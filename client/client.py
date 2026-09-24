import http.server
import socketserver
import socket
import threading
import tkinter as tk
from tkinter import messagebox
import winreg
import ctypes
import atexit
import signal
import sys
import os
import json
import time
import urllib.request
import urllib.error

# ========== 配置区 ==========
DEFAULT_UPSTREAM_HOST = "127.0.0.1"
DEFAULT_UPSTREAM_PORT = 8080
LOCAL_PORT = 8888
PROXY_HOST = "127.0.0.1"
PING_INTERVAL_DEFAULT = 5
# ============================

_upstream_host = DEFAULT_UPSTREAM_HOST
_upstream_port = DEFAULT_UPSTREAM_PORT
_session_id = None
_ping_interval = PING_INTERVAL_DEFAULT

# ========== 客户端本地配置 ==========
CONFIG_DIR = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "CorporateAgent")
CONFIG_FILE = os.path.join(CONFIG_DIR, "client_config.json")


def load_client_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_client_config(cfg: dict):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[配置] 保存失败: {e}")


def get_upstream_proxy():
    return (_upstream_host, _upstream_port)


# ========== 系统代理 ==========
def enable_system_proxy(host=PROXY_HOST, port=LOCAL_PORT):
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_WRITE)
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,
                      "localhost;127.*;10.*;172.16.*;192.168.*;<local>")
    winreg.CloseKey(key)
    refresh_proxy()


def disable_system_proxy():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        refresh_proxy()
        print("[清理] 系统代理已关闭")
    except Exception as e:
        print(f"[清理] 关闭系统代理失败: {e}")


def refresh_proxy():
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
    ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)


atexit.register(disable_system_proxy)


# ========== 服务端通信 ==========
def _post_json(path, payload, timeout=5):
    url = f"http://{_upstream_host}:{_upstream_port}{path}"
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def auth_to_server(username, password):
    try:
        result = _post_json("/__auth__",
                            {"username": username, "password": password})
        return (result.get("ok", False), result.get("role"),
                result.get("session_id"),
                result.get("ping_interval", PING_INTERVAL_DEFAULT),
                result.get("proxy", 0))
    except urllib.error.HTTPError:
        return False, None, None, PING_INTERVAL_DEFAULT, 0
    except Exception as e:
        messagebox.showerror("连接失败", f"无法连接服务端:\n{e}")
        return False, None, None, PING_INTERVAL_DEFAULT, 0


def send_ping():
    global _session_id
    if not _session_id:
        return None
    try:
        return _post_json("/__ping__", {"session_id": _session_id}, timeout=4)
    except Exception:
        return None


def send_logout():
    global _session_id
    if not _session_id:
        return
    try:
        _post_json("/__logout__", {"session_id": _session_id}, timeout=3)
    except Exception:
        pass


def set_proxy_to_server(enabled):
    """请求服务端设置外网代理开关，返回 (ok, reason)"""
    global _session_id
    if not _session_id:
        return False, "no_session"
    try:
        result = _post_json("/__set_proxy__",
                            {"session_id": _session_id, "enabled": enabled},
                            timeout=10)
        return result.get("ok", False), result.get("reason")
    except Exception as e:
        return False, str(e)


# ========== 心跳线程 ==========
def _heartbeat_loop(stop_evt, on_kicked):
    global _session_id, _ping_interval
    while not stop_evt.is_set():
        if stop_evt.wait(_ping_interval):
            break
        result = send_ping()
        if result is None:
            continue
        if not result.get("ok"):
            reason = result.get("reason")
            if reason == "kicked":
                on_kicked("管理员已断开您的会话")
                return
            elif reason in ("offline", "invalid_session", "ip_mismatch"):
                on_kicked(f"会话已失效（{reason}）")
                return


# ========== 转发处理器 ==========
class ForwardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):    self.forward()
    def do_POST(self):   self.forward()
    def do_PUT(self):    self.forward()
    def do_DELETE(self): self.forward()

    def forward(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else None

        try:
            upstream = socket.create_connection(get_upstream_proxy(), timeout=5)
        except Exception:
            self.send_response(502)
            self.end_headers()
            try:
                self.wfile.write(b"502 Upstream Unreachable")
            except:
                pass
            return

        try:
            request_line = f"{self.command} {self.path} {self.request_version}\r\n"
            headers = "".join(f"{k}: {v}\r\n" for k, v in self.headers.items())
            headers = headers.replace("Proxy-Connection: keep-alive\r\n", "")
            raw = (request_line + headers + "\r\n").encode()
            if body:
                raw += body
            upstream.sendall(raw)

            # ---- 读 header ----
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = upstream.recv(4096)
                if not chunk:
                    break
                buf += chunk

            if b"\r\n\r\n" not in buf:
                self.wfile.write(buf)
                return

            header, _, rest = buf.partition(b"\r\n\r\n")

            # 解析 Content-Length / Transfer-Encoding
            resp_len = None
            is_chunked = False
            for line in header.split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                k = k.strip().lower()
                if k == b"content-length":
                    try:
                        resp_len = int(v.strip())
                    except:
                        pass
                elif k == b"transfer-encoding" and b"chunked" in v.lower():
                    is_chunked = True

            # 把 header 写回
            self.wfile.write(header + b"\r\n\r\n")

            if resp_len is not None:
                # 精确读 body
                self.wfile.write(rest)
                remaining = resp_len - len(rest)
                while remaining > 0:
                    chunk = upstream.recv(min(8192, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
            elif is_chunked:
                # chunked：读到 0 块结束
                self.wfile.write(rest)
                while True:
                    chunk = upstream.recv(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    if b"\r\n0\r\n\r\n" in chunk:
                        break
            else:
                # 读到关闭
                self.wfile.write(rest)
                while True:
                    chunk = upstream.recv(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except Exception:
            pass
        finally:
            try:
                upstream.close()
            except:
                pass

    def do_CONNECT(self):
        try:
            upstream = socket.create_connection(get_upstream_proxy(), timeout=5)
        except Exception:
            self.send_response(502)
            self.end_headers()
            try:
                self.wfile.write(b"502 Upstream Unreachable")
            except: pass
            return

        try:
            upstream.sendall(
                f"CONNECT {self.path} HTTP/1.1\r\n"
                f"Host: {self.path}\r\n\r\n".encode())
            resp = upstream.recv(4096)
            if b"200" in resp:
                self.send_response(200, "Connection Established")
                self.end_headers()
                self.tunnel(self.connection, upstream)
            else:
                self.send_response(502)
                self.end_headers()
        except Exception:
            try:
                self.send_response(502)
                self.end_headers()
            except: pass
        finally:
            try: upstream.close()
            except: pass

    def tunnel(self, client_sock, upstream_sock):
        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except: pass
            finally:
                try: dst.close()
                except: pass
        t1 = threading.Thread(target=pipe, args=(client_sock, upstream_sock))
        t2 = threading.Thread(target=pipe, args=(upstream_sock, client_sock))
        t1.start(); t2.start()
        t1.join(); t2.join()

    def log_message(self, *args): pass


# ========== GUI ==========
class ClientGUI:
    def __init__(self):
        global _upstream_host, _upstream_port
        self.root = tk.Tk()
        self.root.title("代理客户端")
        self.root.geometry("420x480")
        self.server = None
        self.role = None
        self.heartbeat_stop = threading.Event()
        self.heartbeat_thread = None
        self.upstream_enabled = False
        self.proxy_perm = 0
        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_ui(self):
        tk.Label(self.root, text="服务端地址 (ip:port)",
                 font=("微软雅黑", 9)).pack(pady=(10, 2))
        self.entry_server = tk.Entry(self.root, width=28, justify="center")
        saved = load_client_config()
        last_server = saved.get("server") or \
                      f"{DEFAULT_UPSTREAM_HOST}:{DEFAULT_UPSTREAM_PORT}"
        self.entry_server.insert(0, last_server)
        self.entry_server.pack(pady=2)

        tk.Label(self.root, text=f"本地监听: {PROXY_HOST}:{LOCAL_PORT}",
                 font=("微软雅黑", 9)).pack(pady=2)

        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        tk.Label(frame, text="账号:").grid(row=0, column=0, padx=5, pady=3)
        self.entry_user = tk.Entry(frame, width=20)
        self.entry_user.grid(row=0, column=1, pady=3)
        tk.Label(frame, text="密码:").grid(row=1, column=0, padx=5, pady=3)
        self.entry_pass = tk.Entry(frame, width=20, show="*")
        self.entry_pass.grid(row=1, column=1, pady=3)

        self.btn = tk.Button(self.root, text="启动", command=self.toggle,
                             width=15, height=2)
        self.btn.pack(pady=8)

        # 外网代理按钮（默认关闭，启动前禁用）
        self.btn_upstream = tk.Button(
            self.root, text="外网代理: 关闭", command=self.toggle_upstream,
            width=20, height=1, state="disabled")
        self.btn_upstream.pack(pady=4)

        self.status = tk.Label(self.root, text="● 已停止", fg="red")
        self.status.pack(pady=2)

    def parse_server(self):
        text = self.entry_server.get().strip()
        if not text:
            messagebox.showwarning("提示", "请输入服务端地址，格式 ip:port")
            return None
        if text.startswith("["):
            try:
                host, rest = text[1:].split("]", 1)
                port = int(rest.lstrip(":"))
            except Exception:
                messagebox.showwarning("提示", "地址格式错误，应为 ip:port")
                return None
        else:
            if ":" not in text:
                messagebox.showwarning("提示", "地址格式错误，应为 ip:port")
                return None
            host, port_str = text.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                messagebox.showwarning("提示", "端口必须是数字")
                return None
        if not (0 < port < 65536):
            messagebox.showwarning("提示", "端口范围应在 1~65535")
            return None
        if not host:
            messagebox.showwarning("提示", "主机地址不能为空")
            return None
        return host, port

    def toggle(self):
        if self.server is None:
            self.start()
        else:
            self.stop()

    def start(self):
        global _upstream_host, _upstream_port, _session_id, _ping_interval

        parsed = self.parse_server()
        if parsed is None:
            return
        host, port = parsed

        username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()
        if not username or not password:
            messagebox.showwarning("提示", "请输入账号和密码")
            return

        _upstream_host, _upstream_port = host, port

        ok, role, sid, ping_interval, proxy_perm = auth_to_server(username, password)
        if not ok:
            messagebox.showerror("验证失败", "账号或密码错误")
            return

        self.role = role
        _session_id = sid
        _ping_interval = ping_interval or PING_INTERVAL_DEFAULT
        self.upstream_enabled = False
        self.proxy_perm = proxy_perm

        save_client_config({"server": f"{host}:{port}"})

        try:
            self.server = socketserver.ThreadingTCPServer(
                (PROXY_HOST, LOCAL_PORT), ForwardHandler)
            self.server.daemon_threads = True
            threading.Thread(target=self.server.serve_forever,
                             daemon=True).start()
        except Exception as e:
            messagebox.showerror("启动失败", f"端口 {LOCAL_PORT} 被占用:\n{e}")
            self.server = None
            send_logout()
            _session_id = None
            return

        enable_system_proxy()

        self.heartbeat_stop.clear()
        self.heartbeat_thread = threading.Thread(
            target=_heartbeat_loop,
            args=(self.heartbeat_stop, self._on_session_dead),
            daemon=True)
        self.heartbeat_thread.start()

        self.btn.config(text="停止")
        if self.proxy_perm:
            self.btn_upstream.config(text="外网代理: 关闭", state="normal")
        else:
            self.btn_upstream.config(text="外网代理: 无权限", state="disabled")
        self.status.config(text=f"● 运行中 ({role}) @ {host}:{port}", fg="green")

    def toggle_upstream(self):
        """外网代理 toggle 按钮"""
        if self.server is None:
            messagebox.showinfo("提示", "请先启动代理")
            return
        if not self.proxy_perm:
            messagebox.showinfo("提示", "当前账号无外网代理权限")
            return

        new_state = not self.upstream_enabled
        self.btn_upstream.config(state="disabled")
        try:
            ok, reason = set_proxy_to_server(new_state)
        finally:
            self.btn_upstream.config(state="normal")

        if not ok:
            if reason == "clash_unreachable":
                messagebox.showerror(
                    "外网代理不可用",
                    "无法连接 Clash 上游代理，请检查 Clash 是否运行。")
            elif reason == "no_permission":
                messagebox.showerror("无权限", "当前账号无外网代理权限。")
            elif reason == "invalid_session":
                messagebox.showerror("会话失效", "会话已失效，请重新启动代理。")
            else:
                messagebox.showerror("切换失败", f"原因：{reason}")
            return

        self.upstream_enabled = new_state
        if new_state:
            self.btn_upstream.config(text="外网代理: 开启")
        else:
            self.btn_upstream.config(text="外网代理: 关闭")

    def _on_session_dead(self, msg):
        self.root.after(0, lambda: self._force_stop(msg))

    def _force_stop(self, msg):
        if self.server is None:
            return
        self.stop(send_logout_req=False)
        messagebox.showwarning("会话已断开", msg)

    def stop(self, send_logout_req=True):
        global _session_id
        self.heartbeat_stop.set()
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)
            self.heartbeat_thread = None

        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None

        disable_system_proxy()

        if send_logout_req and _session_id:
            send_logout()
        _session_id = None

        self.upstream_enabled = False
        self.btn.config(text="启动")
        self.btn_upstream.config(text="外网代理: 关闭", state="disabled")
        self.status.config(text="● 已停止", fg="red")

    def on_close(self):
        self.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ========== 信号 ==========
def signal_handler(sig, frame):
    disable_system_proxy()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


if __name__ == "__main__":
    disable_system_proxy()
    ClientGUI().run()