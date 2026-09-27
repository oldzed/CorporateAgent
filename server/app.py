# -*- coding: utf-8 -*-
"""企业代理审计系统 - Web 管理端（只读 DB，可写 JSON）"""
import os
import re
import json
import base64
import hashlib
import sqlite3
import threading
import urllib.request
import urllib.error
from functools import wraps
import string
from datetime import timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash
)

# ========== 路径与配置 ==========
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_FILE    = os.path.join(BASE_DIR, "audit.db")
USER_FILE  = os.path.join(BASE_DIR, "user.json")
ROLE_FILE  = os.path.join(BASE_DIR, "role.json")
ADMIN_FILE = os.path.join(BASE_DIR, "admin.json")
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
PER_PAGE   = 20

# ========== JSON 读写锁 ==========
_json_lock = threading.Lock()


def _load_secret():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(SECRET_FILE, "wb") as f:
        f.write(key)
    return key


def load_admins():
    try:
        with open(ADMIN_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("admins", [])
    except Exception:
        return []


def load_users():
    try:
        with open(USER_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("users", [])
    except Exception:
        return []


def save_users(users):
    with _json_lock:
        tmp = USER_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"users": users}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, USER_FILE)


def load_roles():
    try:
        with open(ROLE_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("roles", {})
    except Exception:
        return {}


def save_roles(roles):
    with _json_lock:
        tmp = ROLE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"roles": roles}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, ROLE_FILE)


# ========== 数据库（只读） ==========
def db_ro():
    uri = f"file:{DB_FILE}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


# ========== Flask ==========
app = Flask(__name__)
app.secret_key = _load_secret()
app.permanent_session_lifetime = timedelta(hours=2)
app.config["JSON_AS_ASCII"] = False


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_globals():
    return {"session_admin": session.get("admin")}


# ---------- 认证 ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        h = hashlib.sha256(p.encode()).hexdigest()
        for a in load_admins():
            if a.get("username") == u and a.get("password_hash") == h:
                session.permanent = True
                session["admin"] = u
                nxt = request.args.get("next") or url_for("audit")
                return redirect(nxt)
        flash("用户名或密码错误", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- 审计 ----------
@app.route("/")
@login_required
def audit():
    return render_template("audit.html")


@app.route("/api/flows")
@login_required
def api_flows():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    f_start  = _to_sql_time(request.args.get("start", ""))
    f_end    = _to_sql_time(request.args.get("end", ""))
    f_ip     = (request.args.get("ip") or "").strip()
    f_user   = (request.args.get("username") or "").strip()
    f_host   = (request.args.get("host") or "").strip()
    f_act    = (request.args.get("action") or "").strip()
    f_scheme = (request.args.get("scheme") or "").strip()

    where, params = [], []
    if f_start:
        where.append("timestamp >= ?")
        params.append(f_start)
    if f_end:
        where.append("timestamp <= ?")
        params.append(f_end)
    if f_ip:
        where.append("client_ip LIKE ?")
        params.append(f"%{f_ip}%")
    if f_user:
        where.append("username LIKE ?")
        params.append(f"%{f_user}%")
    if f_host:
        where.append("host LIKE ?")
        params.append(f"%{f_host}%")
    if f_act in ("allow", "block"):
        where.append("action = ?")
        params.append(f_act)
    if f_scheme in ("http", "https"):
        where.append("scheme = ?")
        params.append(f_scheme)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = db_ro()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM flows {where_sql}", params).fetchone()[0]
        offset = (page - 1) * PER_PAGE
        rows = conn.execute(
            f"SELECT id, timestamp, client_ip, username, role, method, scheme, "
            f"host, port, url, status, action, rule_name, req_size, resp_size, "
            f"content_type "
            f"FROM flows {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [PER_PAGE, offset]).fetchall()
    finally:
        conn.close()

    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return jsonify({
        "ok": True,
        "page": page,
        "per_page": PER_PAGE,
        "total": total,
        "total_pages": total_pages,
        "rows": [dict(r) for r in rows],
    })


@app.route("/api/flows/<int:fid>")
@login_required
def api_flow_detail(fid):
    conn = db_ro()
    try:
        row = conn.execute(
            "SELECT * FROM flows WHERE id=?", (fid,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"ok": False, "reason": "not_found"}), 404

    d = dict(row)
    for k in ("req_body", "resp_body"):
        v = d.pop(k, None)
        if v is None:
            d[k + "_b64"] = None
            d[k + "_size"] = 0
            d[k + "_text"] = None
            d[k + "_binary"] = False
            d[k + "_mime_hint"] = None
            continue
        if isinstance(v, (bytes, bytearray)):
            data = bytes(v)
        elif isinstance(v, str):
            data = v.encode("utf-8", "replace")
        else:
            data = bytes(v)

        d[k + "_b64"] = base64.b64encode(data).decode("ascii")
        d[k + "_size"] = len(data)

        text = _decode_text(data)
        printable_ratio = _printable_ratio(data[:4096])  # 只看前 4KB
        is_binary = (text is None) or (printable_ratio < 0.90)

        d[k + "_binary"] = is_binary
        d[k + "_mime_hint"] = _detect_mime(data[:16])
        # 二进制时不返回文本，让前端只显示 Hex / 提示
        d[k + "_text"] = None if is_binary else text

    return jsonify({"ok": True, "row": d})


def _to_sql_time(s):
    """前端 datetime-local 'YYYY-MM-DDTHH:MM' -> 'YYYY-MM-DD HH:MM:SS'"""
    s = (s or "").strip()
    if not s:
        return ""
    s = s.replace("T", " ")
    if len(s) == 16:  # 缺秒
        s += ":00"
    return s


def _decode_text(data: bytes):
    """只尝试真正可能失败的编码。全失败说明是二进制。"""
    # 1)  BOM
    if data.startswith(b"\xef\xbb\xbf"):
        try: return data[3:].decode("utf-8")
        except Exception: pass
    if data.startswith(b"\xff\xfe"):
        try: return data[2:].decode("utf-16-le")
        except Exception: pass
    if data.startswith(b"\xfe\xff"):
        try: return data[2:].decode("utf-16-be")
        except Exception: pass

    # 2) UTF-8 严格模式
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass

    # 3) GBK 严格模式
    try:
        return data.decode("gbk")
    except UnicodeDecodeError:
        pass

    # 4) 都不是 → 二进制
    return None

_PRINTABLE = set(bytes(string.printable, "ascii")) | {0x09, 0x0a, 0x0d}

def _printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    # 只统计 ASCII 控制字符：把 < 0x20 且不是 \t\r\n 的当"坏"
    bad  = sum(1 for b in data if b < 0x20 and b not in (0x09, 0x0a, 0x0d))
    return 1.0 - (bad / len(data))


def _detect_mime(head: bytes):
    """根据 magic bytes 猜一猜类型，纯展示用"""
    if head.startswith(b"\x1f\x8b"):                 return "gzip"
    if head.startswith(b"\x50\x4b\x03\x04"):         return "zip"
    if head.startswith(b"\x89PNG"):                  return "png"
    if head.startswith(b"\xff\xd8\xff"):             return "jpeg"
    if head.startswith(b"GIF8"):                     return "gif"
    if head.startswith(b"%PDF"):                     return "pdf"
    if head.startswith(b"\x7b") or head.startswith(b"\x5b"):  return "json?"
    if head.startswith(b"<"):                        return "html/xml?"
    return None
# ---------- 用户管理 ----------
@app.route("/users")
@login_required
def users_page():
    return render_template("users.html")


@app.route("/api/users")
@login_required
def api_users_list():
    users = load_users()
    out = [{
        "username": u.get("username"),
        "role": u.get("role", ""),
        "proxy": int(u.get("proxy", 0)),
    } for u in users]
    return jsonify({"ok": True, "users": out,
                    "roles": list(load_roles().keys())})


@app.route("/api/users", methods=["POST"])
@login_required
def api_users_create():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role_name = (data.get("role") or "").strip()
    proxy = 1 if int(data.get("proxy", 0)) else 0

    if not re.match(r"^[A-Za-z0-9_\-\.@]+$", username):
        return jsonify({"ok": False, "reason": "用户名只能含字母数字 _ - . @"}), 400
    if not password:
        return jsonify({"ok": False, "reason": "密码不能为空"}), 400
    if not role_name or role_name not in load_roles():
        return jsonify({"ok": False, "reason": "规则组不存在"}), 400

    users = load_users()
    if any(u.get("username") == username for u in users):
        return jsonify({"ok": False, "reason": "用户名已存在"}), 400

    users.append({
        "username": username,
        "password_hash": hashlib.sha256(password.encode()).hexdigest(),
        "role": role_name,
        "proxy": str(proxy),
    })
    save_users(users)
    return jsonify({"ok": True})


@app.route("/api/users/<username>", methods=["DELETE"])
@login_required
def api_users_delete(username):
    users = load_users()
    new_users = [u for u in users if u.get("username") != username]
    if len(new_users) == len(users):
        return jsonify({"ok": False, "reason": "用户不存在"}), 404
    save_users(new_users)
    return jsonify({"ok": True})


@app.route("/api/users/<username>", methods=["PUT"])
@login_required
def api_users_update(username):
    data = request.get_json(silent=True) or {}
    users = load_users()
    found = False
    for u in users:
        if u.get("username") == username:
            if "role" in data:
                r = (data["role"] or "").strip()
                if r not in load_roles():
                    return jsonify({"ok": False, "reason": "规则组不存在"}), 400
                u["role"] = r
            if "proxy" in data:
                u["proxy"] = str(1 if int(data["proxy"]) else 0)
            found = True
            break
    if not found:
        return jsonify({"ok": False, "reason": "用户不存在"}), 404
    save_users(users)
    return jsonify({"ok": True})


@app.route("/api/users/<username>/password", methods=["POST"])
@login_required
def api_users_password(username):
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"ok": False, "reason": "密码不能为空"}), 400
    users = load_users()
    found = False
    for u in users:
        if u.get("username") == username:
            u["password_hash"] = hashlib.sha256(password.encode()).hexdigest()
            found = True
            break
    if not found:
        return jsonify({"ok": False, "reason": "用户不存在"}), 404
    save_users(users)
    return jsonify({"ok": True})


# ---------- 规则组管理 ----------
@app.route("/roles")
@login_required
def roles_page():
    return render_template("roles.html")


@app.route("/api/roles")
@login_required
def api_roles_list():
    roles = load_roles()
    users = load_users()
    out = []
    for name, cfg in roles.items():
        cnt = sum(1 for u in users if u.get("role") == name)
        out.append({
            "name": name,
            "blacklist": cfg.get("blacklist", []),
            "user_count": cnt,
        })
    return jsonify({"ok": True, "roles": out})


@app.route("/api/roles", methods=["POST"])
@login_required
def api_roles_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    blacklist = data.get("blacklist") or []

    if not re.match(r"^[A-Za-z0-9_]+$", name):
        return jsonify({"ok": False, "reason": "组名只能含字母数字下划线"}), 400

    roles = load_roles()
    if name in roles:
        return jsonify({"ok": False, "reason": "组名已存在"}), 400

    err = _validate_blacklist(blacklist)
    if err:
        return jsonify({"ok": False, "reason": err}), 400

    roles[name] = {"blacklist": [p for p in blacklist if p.strip()]}
    save_roles(roles)
    return jsonify({"ok": True})


@app.route("/api/roles/<name>", methods=["PUT"])
@login_required
def api_roles_update(name):
    data = request.get_json(silent=True) or {}
    blacklist = data.get("blacklist") or []
    roles = load_roles()
    if name not in roles:
        return jsonify({"ok": False, "reason": "规则组不存在"}), 404

    err = _validate_blacklist(blacklist)
    if err:
        return jsonify({"ok": False, "reason": err}), 400

    roles[name] = {"blacklist": [p for p in blacklist if p.strip()]}
    save_roles(roles)
    return jsonify({"ok": True})


@app.route("/api/roles/<name>", methods=["DELETE"])
@login_required
def api_roles_delete(name):
    roles = load_roles()
    if name not in roles:
        return jsonify({"ok": False, "reason": "规则组不存在"}), 404
    if len(roles) <= 1:
        return jsonify({"ok": False, "reason": "至少保留一个规则组"}), 400

    users = load_users()
    new_users = [u for u in users if u.get("role") != name]
    removed = len(users) - len(new_users)

    del roles[name]
    save_roles(roles)
    save_users(new_users)
    return jsonify({"ok": True, "removed_users": removed})


def _validate_blacklist(patterns):
    for p in patterns:
        if not isinstance(p, str) or not p.strip():
            continue
        try:
            re.compile(p)
        except re.error as e:
            return f"无效正则 {p!r}: {e}"
    return None


# ---------- 触发 proxy 热重载 ----------
@app.route("/admin/reload", methods=["POST"])
@login_required
def admin_reload():
    url = f"http://{PROXY_HOST}:{PROXY_PORT}/__reload__"
    try:
        req = urllib.request.Request(url, data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read().decode("utf-8", "replace")
            data = json.loads(body) if body else {}
        return jsonify({"ok": True, "msg": data.get("msg", "已重载")})
    except urllib.error.HTTPError as e:
        return jsonify({"ok": False, "reason": f"代理返回 {e.code}"}), 502
    except Exception as e:
        return jsonify({"ok": False,
                        "reason": f"代理未运行或重载失败: {e}"}), 502


if __name__ == "__main__":
    print(f"[启动] Web 管理端: http://127.0.0.1:5000")
    print(f"[DB ] 只读: {DB_FILE}")
    print(f"[JSON] user.json: {USER_FILE}")
    print(f"[JSON] role.json: {ROLE_FILE}")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)