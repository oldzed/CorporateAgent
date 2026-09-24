import http.server
import socketserver
import urllib.request
import urllib.error
import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import queue
import json
import hashlib
import time
import sqlite3
import secrets
import os
import role

# ========== 配置区 ==========
LISTEN_PORT = 8080
USER_FILE = "user.json"
DB_FILE = "audit.db"

MAX_THREADS = 200
SOCKET_TIMEOUT = 20
UPSTREAM_TIMEOUT = 15
TUNNEL_IDLE_TIMEOUT = 30
MAX_BODY_SIZE = 10 * 1024 * 1024
FORWARD_CHUNK = 64 * 1024
GUI_LOG_MAX_LINES = 5000

PING_INTERVAL = 5
PING_TIMEOUT = 15
CLEANUP_INTERVAL = 5
BODY_CAPTURE_LIMIT = 64 * 1024

FLOW_TAB_MAX_ROWS = 1000

# ---- Clash 上游代理 ----
CLASH_HOST = "127.0.0.1"
CLASH_PORT = 7897
CLASH_TEST_TIMEOUT = 3
# ============================

log_queue = queue.Queue()
log_widget = None
session_tree = None
session_filter_online = None
flow_tree = None
flow_cond_label = None

# 拦截页（启动时加载到内存）
_block_page_bytes = b"<html><body><h1>Blocked</h1></body></html>"


def load_block_page(path="block.html"):
    global _block_page_bytes
    try:
        with open(path, "rb") as f:
            _block_page_bytes = f.read()
    except Exception as e:
        log_queue.put(f"[警告] 加载 {path} 失败: {e}，使用默认拦截页\n")

# ---- 直连/Clash 两种 opener ----
_opener_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_opener_clash = urllib.request.build_opener(
    urllib.request.ProxyHandler({
        "http": f"http://{CLASH_HOST}:{CLASH_PORT}",
        "https": f"http://{CLASH_HOST}:{CLASH_PORT}",
    }))


# ========== 日志 ==========
def write_log(client_ip, method, url, status):
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {client_ip}  {method}  {url}  →  {status}\n"
    log_queue.put(line)


# ========== 用户验证 ==========
def load_users():
    try:
        with open(USER_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("users", [])
    except Exception as e:
        log_queue.put(f"[警告] 读取 {USER_FILE} 失败: {e}\n")
        return []


def verify_user(username, password):
    if not username or not password:
        return False, None, 0
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    for u in load_users():
        if u.get("username") == username and u.get("password_hash") == pwd_hash:
            return True, u.get("role", "user"), int(u.get("proxy", 0))
    return False, None, 0


def get_user_proxy_perm(username):
    for u in load_users():
        if u.get("username") == username:
            return int(u.get("proxy", 0))
    return 0


# ========== 数据库 ==========
def db_conn():
    conn = sqlite3.connect(DB_FILE, timeout=5, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = db_conn()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT UNIQUE NOT NULL,
            username    TEXT NOT NULL,
            role        TEXT,
            client_ip   TEXT NOT NULL,
            login_time  DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
            status      TEXT DEFAULT 'online',
            use_upstream_proxy INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sess_ip     ON sessions(client_ip);
        CREATE INDEX IF NOT EXISTS idx_sess_user   ON sessions(username);
        CREATE INDEX IF NOT EXISTS idx_sess_status ON sessions(status);

        CREATE TABLE IF NOT EXISTS flows (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
            session_id   TEXT,
            client_ip    TEXT,
            username     TEXT,
            role         TEXT,
            method       TEXT,
            scheme       TEXT,
            host         TEXT,
            port         INTEGER,
            url          TEXT,
            status       INTEGER,
            action       TEXT,
            rule_id      TEXT,
            rule_name    TEXT,
            req_size     INTEGER,
            resp_size    INTEGER,
            req_body     BLOB,
            resp_body     BLOB,
            content_type TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_flows_ts      ON flows(timestamp);
        CREATE INDEX IF NOT EXISTS idx_flows_user    ON flows(username);
        CREATE INDEX IF NOT EXISTS idx_flows_host    ON flows(host);
        CREATE INDEX IF NOT EXISTS idx_flows_action  ON flows(action);
        """)
        conn.commit()

        # ---- 兼容老库：sessions 无 use_upstream_proxy 列则补上 ----
        cols = [r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()]
        if "use_upstream_proxy" not in cols:
            conn.execute(
                "ALTER TABLE sessions ADD COLUMN use_upstream_proxy INTEGER DEFAULT 0")
            conn.commit()
            log_queue.put("[迁移] sessions 表已添加 use_upstream_proxy 列\n")

        # ---- 兼容老库：flows 无 session_id 列则补上 ----
        cols = [r[1] for r in conn.execute("PRAGMA table_info(flows)").fetchall()]
        if "session_id" not in cols:
            conn.execute("ALTER TABLE flows ADD COLUMN session_id TEXT")
            conn.commit()
            log_queue.put("[迁移] flows 表已添加 session_id 列\n")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id)")
        conn.commit()

    finally:
        conn.close()


def create_session(username, role, client_ip):
    sid = secrets.token_hex(16)
    conn = db_conn()
    try:
        conn.execute(
            "INSERT INTO sessions (session_id, username, role, client_ip, "
            "login_time, last_seen, status, use_upstream_proxy) "
            "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'online', 0)",
            (sid, username, role, client_ip))
        conn.commit()
        return sid
    finally:
        conn.close()


def get_latest_online_session_by_ip(client_ip):
    conn = db_conn()
    try:
        row = conn.execute(
            "SELECT session_id, username, role, login_time, last_seen, status, "
            "COALESCE(use_upstream_proxy, 0) "
            "FROM sessions WHERE client_ip=? AND status='online' "
            "ORDER BY login_time DESC LIMIT 1",
            (client_ip,)).fetchone()
        if row:
            return {"session_id": row[0], "username": row[1], "role": row[2],
                    "login_time": row[3], "last_seen": row[4],
                    "status": row[5], "use_upstream_proxy": row[6],
                    "client_ip": client_ip}
        return None
    finally:
        conn.close()


def get_session_full(session_id):
    conn = db_conn()
    try:
        row = conn.execute(
            "SELECT session_id, username, role, client_ip, login_time, "
            "last_seen, status, COALESCE(use_upstream_proxy, 0) "
            "FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        if row:
            return {"session_id": row[0], "username": row[1], "role": row[2],
                    "client_ip": row[3], "login_time": row[4],
                    "last_seen": row[5], "status": row[6],
                    "use_upstream_proxy": row[7]}
        return None
    finally:
        conn.close()


def set_session_upstream_proxy(session_id, enabled):
    conn = db_conn()
    try:
        conn.execute(
            "UPDATE sessions SET use_upstream_proxy=? "
            "WHERE session_id=? AND status='online'",
            (1 if enabled else 0, session_id))
        conn.commit()
    finally:
        conn.close()


def touch_session(session_id):
    conn = db_conn()
    try:
        conn.execute(
            "UPDATE sessions SET last_seen=CURRENT_TIMESTAMP "
            "WHERE session_id=? AND status='online'",
            (session_id,))
        conn.commit()
    finally:
        conn.close()


def end_session(session_id, status="offline"):
    conn = db_conn()
    try:
        conn.execute(
            "UPDATE sessions SET status=? WHERE session_id=? AND status='online'",
            (status, session_id))
        conn.commit()
    finally:
        conn.close()


def query_sessions(online_only=False):
    conn = db_conn()
    try:
        if online_only:
            rows = conn.execute(
                "SELECT client_ip, username, role, login_time, last_seen, status "
                "FROM sessions WHERE status='online' ORDER BY login_time DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT client_ip, username, role, login_time, last_seen, status "
                "FROM sessions ORDER BY login_time DESC LIMIT 500"
            ).fetchall()
        return rows
    finally:
        conn.close()


def cleanup_timeout_sessions():
    conn = db_conn()
    try:
        cur = conn.execute(
            "UPDATE sessions SET status='offline' "
            "WHERE status='online' "
            "AND (strftime('%s','now') - strftime('%s', last_seen)) > ?",
            (PING_TIMEOUT,))
        conn.commit()
        if cur.rowcount:
            log_queue.put(f"[清理] {cur.rowcount} 个超时会话已置 offline\n")
    finally:
        conn.close()


def query_flows_by_session(session_id, limit=FLOW_TAB_MAX_ROWS):
    conn = db_conn()
    try:
        rows = conn.execute(
            "SELECT timestamp, method, scheme, host, port, url, status, "
            "action, rule_name, req_size, resp_size, content_type "
            "FROM flows WHERE session_id=? "
            "ORDER BY id DESC LIMIT ?",
            (session_id, limit)).fetchall()
        return rows
    finally:
        conn.close()


def get_session_by_id(session_id):
    return get_session_full(session_id)


# ========== Clash 测试 ==========
def test_clash_alive():
    """向 Clash 发一个 HTTP 请求，判断 Clash 是否可用"""
    try:
        s = socket.create_connection((CLASH_HOST, CLASH_PORT),
                                     timeout=CLASH_TEST_TIMEOUT)
    except Exception:
        return False
    try:
        s.settimeout(CLASH_TEST_TIMEOUT)
        req = (b"GET http://www.gstatic.com/generate_204 HTTP/1.1\r\n"
               b"Host: www.gstatic.com\r\n"
               b"Proxy-Connection: close\r\n\r\n")
        s.sendall(req)
        resp = b""
        while len(resp) < 512:
            try:
                chunk = s.recv(512)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp:
                break
        return b"HTTP/" in resp
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


# ========== 审计队列 ==========
audit_queue = queue.Queue()
audit_stop = threading.Event()
_audit_thread = None


def audit_record(flow: dict):
    audit_queue.put(flow)


def _audit_writer_loop():
    buf = []
    last_flush = time.time()
    while not audit_stop.is_set() or not audit_queue.empty():
        try:
            item = audit_queue.get(timeout=1)
            buf.append(item)
        except queue.Empty:
            pass
        if len(buf) >= 100 or (buf and time.time() - last_flush >= 1):
            _flush_flows(buf)
            buf = []
            last_flush = time.time()
    if buf:
        _flush_flows(buf)


def _flush_flows(rows):
    if not rows:
        return
    conn = db_conn()
    try:
        conn.executemany(
            "INSERT INTO flows (session_id, client_ip, username, role, method, "
            "scheme, host, port, url, status, action, rule_id, rule_name, "
            "req_size, resp_size, req_body, resp_body, content_type) "
            "VALUES (:session_id, :client_ip, :username, :role, :method, :scheme, "
            ":host, :port, :url, :status, :action, :rule_id, :rule_name, "
            ":req_size, :resp_size, :req_body, :resp_body, :content_type)",
            rows)
        conn.commit()
    except Exception as e:
        log_queue.put(f"[审计写库失败] {e}\n")
    finally:
        conn.close()


def start_audit_writer():
    global _audit_thread
    audit_stop.clear()
    _audit_thread = threading.Thread(target=_audit_writer_loop, daemon=True)
    _audit_thread.start()


def stop_audit_writer():
    audit_stop.set()
    if _audit_thread:
        _audit_thread.join(timeout=3)


# ========== 会话清理线程 ==========
_cleanup_stop = threading.Event()
_cleanup_thread = None


def _cleanup_loop():
    while not _cleanup_stop.is_set():
        try:
            cleanup_timeout_sessions()
        except Exception as e:
            log_queue.put(f"[清理异常] {e}\n")
        _cleanup_stop.wait(CLEANUP_INTERVAL)


def start_cleanup():
    global _cleanup_thread
    _cleanup_stop.clear()
    _cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
    _cleanup_thread.start()


def stop_cleanup():
    _cleanup_stop.set()
    if _cleanup_thread:
        _cleanup_thread.join(timeout=2)


# ========== 目标解析 ==========
def parse_target(path):
    if path.startswith("http://"):
        scheme = "http"
    elif path.startswith("https://"):
        scheme = "https"
    else:
        return None, None, None, path
    from urllib.parse import urlparse
    u = urlparse(path)
    host = u.hostname
    port = u.port or (443 if scheme == "https" else 80)
    return host, port, scheme, path


# ========== 代理处理器 ==========
class ProxyHandler(http.server.BaseHTTPRequestHandler):

    timeout = SOCKET_TIMEOUT

    def do_GET(self):     self.handle_request()
    def do_POST(self):    self.handle_request()
    def do_PUT(self):     self.handle_request()
    def do_DELETE(self):  self.handle_request()
    def do_HEAD(self):    self.handle_request()
    def do_OPTIONS(self): self.handle_request()

    def _json_resp(self, code, obj):
        resp = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        try:
            self.wfile.write(resp)
        except Exception:
            pass

    def handle_request(self):
        if self.path == "/__auth__" and self.command == "POST":
            self.handle_auth()
            return
        if self.path == "/__ping__" and self.command == "POST":
            self.handle_ping()
            return
        if self.path == "/__logout__" and self.command == "POST":
            self.handle_logout()
            return
        if self.path == "/__set_proxy__" and self.command == "POST":
            self.handle_set_proxy()
            return

        client_ip = self.client_address[0]
        sess = get_latest_online_session_by_ip(client_ip)
        if sess is None:
            self._send_404()
            return

        touch_session(sess["session_id"])
        self._proxy_http(sess)

    def _send_404(self):
        try:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            pass

    def _send_block(self):
        try:
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(_block_page_bytes)))
            self.send_header("Connection", "close")  # ← 加这行
            self.end_headers()
            self.wfile.write(_block_page_bytes)
        except Exception:
            pass

    # ---------- 认证 ----------
    def handle_auth(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        username = "?"
        try:
            data = json.loads(body)
            username = data.get("username", "?")
            ok, role, proxy_perm = verify_user(
                data.get("username"), data.get("password"))
        except Exception:
            ok, role, proxy_perm = False, None, 0

        client_ip = self.client_address[0]
        if ok:
            sid = create_session(username, role, client_ip)
            resp_data = {"ok": True, "role": role, "session_id": sid,
                         "ping_interval": PING_INTERVAL,
                         "proxy": proxy_perm}
            code = 200
        else:
            resp_data = {"ok": False, "role": None,
                         "reason": "invalid_credentials"}
            code = 401

        resp = json.dumps(resp_data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        try:
            self.wfile.write(resp)
        except Exception:
            pass

        write_log(client_ip, "AUTH", username,
                  f"OK({role})" if ok else "FAIL")

    # ---------- 心跳 ----------
    def handle_ping(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        sid = None
        try:
            data = json.loads(body)
            sid = data.get("session_id")
        except Exception:
            pass

        client_ip = self.client_address[0]
        ok = False
        reason = "invalid_session"

        if sid:
            conn = db_conn()
            try:
                row = conn.execute(
                    "SELECT status, client_ip FROM sessions WHERE session_id=?",
                    (sid,)).fetchone()
                if row:
                    status, sess_ip = row
                    if sess_ip != client_ip:
                        reason = "ip_mismatch"
                    elif status == "kicked":
                        reason = "kicked"
                    elif status == "online":
                        conn.execute(
                            "UPDATE sessions SET last_seen=CURRENT_TIMESTAMP "
                            "WHERE session_id=?", (sid,))
                        conn.commit()
                        ok = True
                        reason = "ok"
                    else:
                        reason = "offline"
            finally:
                conn.close()

        self._json_resp(200, {"ok": ok, "reason": reason})

    # ---------- 登出 ----------
    def handle_logout(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        sid = None
        try:
            data = json.loads(body)
            sid = data.get("session_id")
        except Exception:
            pass

        if sid:
            end_session(sid, "offline")

        self._json_resp(200, {"ok": True})

    # ---------- 外网代理开关 ----------
    def handle_set_proxy(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        sid = None
        enabled = False
        try:
            data = json.loads(body)
            sid = data.get("session_id")
            enabled = bool(data.get("enabled"))
        except Exception:
            pass

        client_ip = self.client_address[0]
        sess = get_session_full(sid) if sid else None
        if not sess or sess["client_ip"] != client_ip or sess["status"] != "online":
            self._json_resp(400, {"ok": False, "reason": "invalid_session"})
            return

        # 二次校验权限（防篡改）
        if get_user_proxy_perm(sess["username"]) != 1:
            self._json_resp(403, {"ok": False, "reason": "no_permission"})
            return

        if enabled:
            if not test_clash_alive():
                write_log(client_ip, "SETPROXY", sess["username"],
                          "ON-FAIL(clash_unreachable)")
                self._json_resp(200, {"ok": False,
                                      "reason": "clash_unreachable"})
                return
            set_session_upstream_proxy(sid, True)
            write_log(client_ip, "SETPROXY", sess["username"], "ON")
            self._json_resp(200, {"ok": True, "enabled": True})
        else:
            set_session_upstream_proxy(sid, False)
            write_log(client_ip, "SETPROXY", sess["username"], "OFF")
            self._json_resp(200, {"ok": True, "enabled": False})

    # ---------- HTTP 代理转发 ----------
    def _proxy_http(self, sess):
        url = self.path
        method = self.command
        client_ip = self.client_address[0]
        host, port, scheme, _ = parse_target(url)
        if scheme is None:
            self._send_404()
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            content_length = 0

        if content_length > MAX_BODY_SIZE:
            self.send_response(413)
            self.end_headers()
            try:
                self.wfile.write(b"413 Payload Too Large")
            except Exception:
                pass
            write_log(client_ip, method, url, 413)
            return

        body = self.rfile.read(content_length) if content_length else None
        req_body_capture = body[:BODY_CAPTURE_LIMIT] if body else None

        # ---- 域名黑名单检查 ----
        action, pattern = role.check(sess["role"], host)
        if action == "block":
            self._send_block()
            write_log(client_ip, method, url, f"BLOCK({pattern})")
            audit_record({
                "session_id": sess["session_id"],
                "client_ip": client_ip, "username": sess["username"],
                "role": sess["role"], "method": method, "scheme": scheme,
                "host": host, "port": port, "url": url,
                "status": 403, "action": "block",
                "rule_id": None, "rule_name": pattern,
                "req_size": content_length, "resp_size": 0,
                "req_body": req_body_capture, "resp_body": None,
                "content_type": "text/html",
            })
            return
        # ------------------------

        use_clash = bool(sess.get("use_upstream_proxy"))
        opener = _opener_clash if use_clash else _opener_direct

        try:
            req = urllib.request.Request(url, data=body, method=method)
            for k, v in self.headers.items():
                if k.lower() not in ('proxy-connection', 'connection',
                                     'host', 'content-length',
                                     'accept-encoding', 'transfer-encoding'):
                    req.add_header(k, v)

            with opener.open(req, timeout=UPSTREAM_TIMEOUT) as resp:
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")
                upstream_len = resp.headers.get("Content-Length")

                self.send_response(status)
                if content_type:
                    self.send_header("Content-Type", content_type)
                if upstream_len is not None:
                    self.send_header("Content-Length", upstream_len)
                else:
                    self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()

                resp_size = 0
                resp_body_capture = bytearray()

                if method == "HEAD":
                    pass
                elif upstream_len is not None:
                    while True:
                        chunk = resp.read(FORWARD_CHUNK)
                        if not chunk:
                            break
                        resp_size += len(chunk)
                        if len(resp_body_capture) < BODY_CAPTURE_LIMIT:
                            take = BODY_CAPTURE_LIMIT - len(resp_body_capture)
                            resp_body_capture.extend(chunk[:take])
                        self.wfile.write(chunk)
                else:
                    while True:
                        chunk = resp.read(FORWARD_CHUNK)
                        if not chunk:
                            break
                        resp_size += len(chunk)
                        if len(resp_body_capture) < BODY_CAPTURE_LIMIT:
                            take = BODY_CAPTURE_LIMIT - len(resp_body_capture)
                            resp_body_capture.extend(chunk[:take])
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.write(b"0\r\n\r\n")

            write_log(client_ip, method, url, status)

            audit_record({
                "session_id": sess["session_id"],
                "client_ip": client_ip,
                "username": sess["username"],
                "role": sess["role"],
                "method": method, "scheme": scheme,
                "host": host, "port": port, "url": url,
                "status": status, "action": "allow",
                "rule_id": None, "rule_name": None,
                "req_size": content_length,
                "resp_size": resp_size,
                "req_body": req_body_capture,
                "resp_body": bytes(resp_body_capture) if resp_body_capture else None,
                "content_type": content_type,
            })

        except urllib.error.HTTPError as e:
            try:
                self.send_response(e.code)
                self.end_headers()
                try:
                    self.wfile.write(e.read())
                except Exception:
                    pass
            except Exception:
                pass
            write_log(client_ip, method, url, e.code)
            audit_record({
                "session_id": sess["session_id"],
                "client_ip": client_ip, "username": sess["username"],
                "role": sess["role"], "method": method, "scheme": scheme,
                "host": host, "port": port, "url": url,
                "status": e.code, "action": "allow",
                "rule_id": None, "rule_name": None,
                "req_size": content_length, "resp_size": 0,
                "req_body": req_body_capture, "resp_body": None,
                "content_type": "",
            })

        except socket.timeout:
            write_log(client_ip, method, url, "TIMEOUT")
        except Exception as e:
            try:
                self.send_response(502)
                self.end_headers()
                try:
                    self.wfile.write(f"502 Bad Gateway: {e}".encode())
                except Exception:
                    pass
            except Exception:
                pass
            write_log(client_ip, method, url, "ERR")

    # ---------- CONNECT 隧道 ----------
    def do_CONNECT(self):
        client_ip = self.client_address[0]

        sess = get_latest_online_session_by_ip(client_ip)
        if sess is None:
            self._send_404()
            return
        touch_session(sess["session_id"])

        use_clash = bool(sess.get("use_upstream_proxy"))
        upstream = None
        try:
            host, port_str = self.path.split(":")
            port = int(port_str)

            # ---- 域名黑名单检查 ----
            action, pattern = role.check(sess["role"], host)
            if action == "block":
                try:
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except Exception:
                    pass
                write_log(client_ip, "CONNECT", self.path, f"BLOCK({pattern})")
                audit_record({
                    "session_id": sess["session_id"],
                    "client_ip": client_ip, "username": sess["username"],
                    "role": sess["role"], "method": "CONNECT", "scheme": "https",
                    "host": host, "port": port, "url": self.path,
                    "status": 403, "action": "block",
                    "rule_id": None, "rule_name": pattern,
                    "req_size": 0, "resp_size": 0,
                    "req_body": None, "resp_body": None,
                    "content_type": "",
                })
                return
            # ------------------------

            if use_clash:
                # 走 Clash：连 Clash，让 Clash 建立隧道
                upstream = socket.create_connection(
                    (CLASH_HOST, CLASH_PORT), timeout=10)
                upstream.settimeout(TUNNEL_IDLE_TIMEOUT)
                upstream.sendall(
                    f"CONNECT {host}:{port} HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n\r\n".encode())
                resp = upstream.recv(4096)
                first_line = resp.split(b"\r\n", 1)[0] if resp else b""
                if b"200" not in first_line:
                    try:
                        self.send_response(502)
                        self.end_headers()
                    except Exception:
                        pass
                    write_log(client_ip, "CONNECT", self.path,
                              f"CLASH-REJECT {first_line[:40]}")
                    return
            else:
                # 直连
                upstream = socket.create_connection((host, port), timeout=10)
                upstream.settimeout(TUNNEL_IDLE_TIMEOUT)

            try:
                self.connection.settimeout(TUNNEL_IDLE_TIMEOUT)
            except Exception:
                pass

            self.send_response(200, "Connection Established")
            self.end_headers()
            write_log(client_ip, "CONNECT", self.path, 200)

            audit_record({
                "session_id": sess["session_id"],
                "client_ip": client_ip, "username": sess["username"],
                "role": sess["role"], "method": "CONNECT", "scheme": "https",
                "host": host, "port": port, "url": self.path,
                "status": 200, "action": "allow",
                "rule_id": None, "rule_name": None,
                "req_size": 0, "resp_size": 0,
                "req_body": None, "resp_body": None,
                "content_type": "",
            })

            self.tunnel(self.connection, upstream)

        except Exception:
            try:
                self.send_response(502)
                self.end_headers()
            except Exception:
                pass
            write_log(client_ip, "CONNECT", self.path, "ERR")
        finally:
            try:
                if upstream is not None:
                    upstream.close()
            except Exception:
                pass
            try:
                self.connection.close()
            except Exception:
                pass

    def tunnel(self, client_sock, upstream_sock):
        def pipe(src, dst):
            try:
                while True:
                    try:
                        data = src.recv(8192)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        s.close()
                    except Exception:
                        pass

        t1 = threading.Thread(target=pipe, args=(client_sock, upstream_sock),
                              daemon=True)
        t2 = threading.Thread(target=pipe, args=(upstream_sock, client_sock),
                              daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def log_message(self, *args):
        pass


# ========== 带并发上限的 TCP 服务器 ==========
class BoundedThreadingTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, max_threads=MAX_THREADS, **kwargs):
        super().__init__(*args, **kwargs)
        self._sem = threading.Semaphore(max_threads)

    def process_request(self, request, client_address):
        self._sem.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self._sem.release()
            raise

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self._sem.release()


# ========== GUI ==========
class ServerGUI:
    def __init__(self):
        global log_widget, session_tree, session_filter_online
        global flow_tree, flow_cond_label
        self.root = tk.Tk()
        self.root.title("代理服务端 - 流量审计")
        self.root.geometry("1000x620")
        self.server = None

        top = tk.Frame(self.root)
        top.pack(fill="x", pady=3)
        tk.Label(top, text=f"监听端口: {LISTEN_PORT}",
                 font=("微软雅黑", 10)).pack(side="left", padx=8)
        tk.Label(top, text=f"Clash: {CLASH_HOST}:{CLASH_PORT}",
                 font=("微软雅黑", 9), fg="gray").pack(side="left", padx=4)
        self.btn = tk.Button(top, text="启动服务", command=self.toggle,
                             width=12, height=1)
        self.btn.pack(side="left", padx=5)
        self.status = tk.Label(top, text="● 已停止", fg="red")
        self.status.pack(side="left", padx=8)

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=5)
        self.nb = nb

        # Tab1 日志
        tab1 = tk.Frame(nb)
        nb.add(tab1, text="访问日志")
        tk.Label(tab1, text="时间 / 客户端 / 方法 / 路径 / 状态",
                 font=("微软雅黑", 9)).pack(pady=3)
        log_widget = scrolledtext.ScrolledText(
            tab1, height=20, font=("Consolas", 9))
        log_widget.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Button(tab1, text="清空日志",
                  command=lambda: log_widget.delete("1.0", "end")
                  ).pack(pady=3)

        # Tab2 会话
        tab2 = tk.Frame(nb)
        nb.add(tab2, text="会话")

        filter_bar = tk.Frame(tab2)
        filter_bar.pack(fill="x", pady=3)
        tk.Label(filter_bar, text="筛选:").pack(side="left", padx=5)
        session_filter_online = tk.StringVar(value="all")
        tk.Radiobutton(filter_bar, text="全部", variable=session_filter_online,
                       value="all", command=self.refresh_sessions
                       ).pack(side="left", padx=3)
        tk.Radiobutton(filter_bar, text="当前在线", variable=session_filter_online,
                       value="online", command=self.refresh_sessions
                       ).pack(side="left", padx=3)
        tk.Button(filter_bar, text="刷新",
                  command=self.refresh_sessions).pack(side="left", padx=8)
        tk.Label(filter_bar, text="（右键会话查看流量 / 断开）",
                 fg="gray").pack(side="left", padx=8)

        cols = ("ip", "username", "role", "login_time", "last_seen", "status")
        session_tree = ttk.Treeview(tab2, columns=cols, show="headings",
                                    height=16)
        for c, t, w in [("ip", "IP", 130), ("username", "用户", 110),
                        ("role", "规则组", 100), ("login_time", "登录时间", 160),
                        ("last_seen", "最后活跃", 160), ("status", "状态", 80)]:
            session_tree.heading(c, text=t)
            session_tree.column(c, width=w, anchor="center")
        session_tree.pack(fill="both", expand=True, padx=5, pady=5)

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="只看当前会话流量",
                              command=self.show_session_flows)
        self.menu.add_separator()
        self.menu.add_command(label="断开该会话", command=self.kick_selected)
        session_tree.bind("<Button-3>", self._popup_menu)

        # Tab3 筛选结果
        tab3 = tk.Frame(nb)
        nb.add(tab3, text="筛选结果")
        self.tab3 = tab3

        cond_bar = tk.Frame(tab3)
        cond_bar.pack(fill="x", pady=3)
        flow_cond_label = tk.Label(
            cond_bar, text="（未选择会话）",
            font=("微软雅黑", 9), anchor="w", fg="gray")
        flow_cond_label.pack(side="left", padx=8, fill="x", expand=True)

        btn_bar = tk.Frame(tab3)
        btn_bar.pack(fill="x")
        tk.Button(btn_bar, text="刷新",
                  command=self.manual_refresh_flows).pack(side="left", padx=8)

        fcols = ("timestamp", "method", "host", "port", "url", "status",
                 "action", "rule_name", "req_size", "resp_size", "content_type")
        flow_tree = ttk.Treeview(tab3, columns=fcols, show="headings", height=18)
        widths = {"timestamp": 150, "method": 70, "host": 170, "port": 55,
                  "url": 320, "status": 60, "action": 60, "rule_name": 90,
                  "req_size": 70, "resp_size": 70, "content_type": 120}
        headers = {"timestamp": "时间", "method": "方法", "host": "主机",
                   "port": "端口", "url": "URL", "status": "状态",
                   "action": "动作", "rule_name": "规则",
                   "req_size": "请求大小", "resp_size": "响应大小",
                   "content_type": "Content-Type"}
        for c in fcols:
            flow_tree.heading(c, text=headers[c])
            flow_tree.column(c, width=widths[c], anchor="center")
        flow_tree.pack(fill="both", expand=True, padx=5, pady=5)

        self.current_flow_session = None

        self.poll_log_queue()
        self.poll_sessions()

    def poll_log_queue(self):
        count = 0
        while not log_queue.empty() and count < 200:
            line = log_queue.get()
            log_widget.insert("end", line)
            count += 1
        if count:
            try:
                total_lines = int(log_widget.index("end-1c").split(".")[0])
                if total_lines > GUI_LOG_MAX_LINES:
                    log_widget.delete("1.0",
                                      f"{total_lines - GUI_LOG_MAX_LINES}.0")
            except Exception:
                pass
            log_widget.see("end")
        self.root.after(200, self.poll_log_queue)

    def poll_sessions(self):
        try:
            self.refresh_sessions()
        except Exception:
            pass
        self.root.after(2000, self.poll_sessions)

    def refresh_sessions(self):
        if session_tree is None:
            return
        online_only = (session_filter_online.get() == "online")
        try:
            rows = query_sessions(online_only=online_only)
        except Exception:
            rows = []
        sel = session_tree.selection()
        sel_ip = None
        if sel:
            vals = session_tree.item(sel[0], "values")
            if vals:
                sel_ip = vals[0]
        for i in session_tree.get_children():
            session_tree.delete(i)
        for r in rows:
            ip, username, role, login_time, last_seen, status = r
            iid = session_tree.insert("", "end",
                                      values=(ip, username, role or "",
                                              login_time, last_seen, status))
            if sel_ip and ip == sel_ip:
                session_tree.selection_set(iid)

    def _popup_menu(self, event):
        row = session_tree.identify_row(event.y)
        if row:
            session_tree.selection_set(row)
            self.menu.post(event.x_root, event.y_root)

    def show_session_flows(self):
        sel = session_tree.selection()
        if not sel:
            return
        vals = session_tree.item(sel[0], "values")
        if not vals:
            return
        ip, username, role, login_time, last_seen, status = vals

        sess = get_latest_online_session_by_ip(ip)
        if sess is None:
            conn = db_conn()
            try:
                row = conn.execute(
                    "SELECT session_id, username, role, client_ip, login_time, "
                    "last_seen, status, COALESCE(use_upstream_proxy, 0) "
                    "FROM sessions "
                    "WHERE client_ip=? AND username=? "
                    "ORDER BY login_time DESC LIMIT 1",
                    (ip, username)).fetchone()
            finally:
                conn.close()
            if not row:
                messagebox.showinfo("提示", "找不到该会话记录")
                return
            sess = {"session_id": row[0], "username": row[1], "role": row[2],
                    "client_ip": row[3], "login_time": row[4],
                    "last_seen": row[5], "status": row[6],
                    "use_upstream_proxy": row[7]}

        self.current_flow_session = sess
        self._update_flow_cond_label()
        self.refresh_flows()
        self.nb.select(self.tab3)

    def _update_flow_cond_label(self):
        s = self.current_flow_session
        if not s:
            flow_cond_label.config(text="（未选择会话）", fg="gray")
            return
        up = "Clash" if s.get("use_upstream_proxy") else "直连"
        text = (f"会话: {s.get('client_ip')} / {s.get('username')} "
                f"/ role={s.get('role')} "
                f"/ login={s.get('login_time')} "
                f"/ status={s.get('status')} "
                f"/ 出网={up} "
                f"/ sid={s.get('session_id')[:8]}...")
        flow_cond_label.config(text=text, fg="black")

    def manual_refresh_flows(self):
        self.refresh_flows()

    def refresh_flows(self):
        if flow_tree is None or self.current_flow_session is None:
            return

        sid = self.current_flow_session["session_id"]
        try:
            rows = query_flows_by_session(sid)
        except Exception as e:
            rows = []
            log_queue.put(f"[筛选流量失败] {e}\n")

        for i in flow_tree.get_children():
            flow_tree.delete(i)
        for r in rows:
            ts, method, scheme, host, port, url, status, action, rule_name, \
                req_size, resp_size, content_type = r
            flow_tree.insert("", "end", values=(
                ts, method, host or "", port or "",
                (url or "")[:200], status, action or "",
                rule_name or "", req_size, resp_size,
                content_type or ""))

    def kick_selected(self):
        sel = session_tree.selection()
        if not sel:
            return
        vals = session_tree.item(sel[0], "values")
        if not vals:
            return
        ip, username, role, login_time, last_seen, status = vals
        if status != "online":
            messagebox.showinfo("提示", "该会话已不在线")
            return
        if not messagebox.askyesno("确认", f"断开 {ip} (用户 {username}) 的会话？"):
            return
        sess = get_latest_online_session_by_ip(ip)
        if sess:
            end_session(sess["session_id"], "kicked")
            log_queue.put(f"[踢人] {ip} 用户 {username} 会话已断开\n")
            self.refresh_sessions()

    def toggle(self):
        if self.server is None:
            self.start()
            self.btn.config(text="停止服务")
            self.status.config(text="● 运行中", fg="green")
        else:
            self.stop()
            self.btn.config(text="启动服务")
            self.status.config(text="● 已停止", fg="red")

    def start(self):
        try:
            init_db()
            load_block_page("block.html")
            role.load_roles("role.json")
            start_audit_writer()
            start_cleanup()
            self.server = BoundedThreadingTCPServer(
                ("0.0.0.0", LISTEN_PORT), ProxyHandler,
                max_threads=MAX_THREADS)
            self.server.daemon_threads = True
            threading.Thread(target=self.server.serve_forever,
                             daemon=True).start()
            log_queue.put(f"[启动] 监听 0.0.0.0:{LISTEN_PORT}\n")
            log_queue.put(f"[启动] Clash 上游: {CLASH_HOST}:{CLASH_PORT}\n")
        except Exception as e:
            log_queue.put(f"[启动失败] {e}\n")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            stop_cleanup()
            stop_audit_writer()
            log_queue.put("[停止] 服务已关闭\n")

    def run(self):
        self.root.mainloop()




if __name__ == "__main__":
    ServerGUI().run()