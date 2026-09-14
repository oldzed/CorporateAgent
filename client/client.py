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
import json
import urllib.request
import urllib.error

# ========== 配置区 ==========
UPSTREAM_HOST = "127.0.0.1"     # 服务端地址
UPSTREAM_PORT = 8080            # 服务端端口
LOCAL_PORT = 8888               # 本地监听端口
PROXY_HOST = "127.0.0.1"
# ============================

UPSTREAM_PROXY = (UPSTREAM_HOST, UPSTREAM_PORT)


# ========== 系统代理管理 ==========
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


# ========== 账号验证 ==========
def auth_to_server(username, password):
    """向服务端请求验证"""
    url = f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}/__auth__"
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            return result.get("ok", False), result.get("role")
    except urllib.error.HTTPError as e:
        return False, None
    except Exception as e:
        messagebox.showerror("连接失败", f"无法连接服务端:\n{e}")
        return False, None


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
            upstream = socket.create_connection(UPSTREAM_PROXY, timeout=5)
        except Exception:
            self.send_response(502)
            self.end_headers()
            try:
                self.wfile.write(b"502 Upstream Unreachable")
            except: pass
            return

        try:
            request_line = f"{self.command} {self.path} {self.request_version}\r\n"
            headers = "".join(f"{k}: {v}\r\n" for k, v in self.headers.items())
            headers = headers.replace("Proxy-Connection: keep-alive\r\n", "")
            raw = (request_line + headers + "\r\n").encode()
            if body:
                raw += body
            upstream.sendall(raw)

            response = b""
            while True:
                chunk = upstream.recv(4096)
                if not chunk: break
                response += chunk
                if b"\r\n\r\n" in response and len(chunk) < 4096:
                    break
            self.wfile.write(response)
        except Exception:
            pass
        finally:
            try: upstream.close()
            except: pass

    def do_CONNECT(self):
        try:
            upstream = socket.create_connection(UPSTREAM_PROXY, timeout=5)
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
                    if not data: break
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
        self.root = tk.Tk()
        self.root.title("代理客户端")
        self.root.geometry("400x320")
        self.server = None
        self.role = None
        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_ui(self):
        tk.Label(self.root, text=f"服务端: {UPSTREAM_HOST}:{UPSTREAM_PORT}",
                 font=("微软雅黑", 9)).pack(pady=5)
        tk.Label(self.root, text=f"本地监听: {PROXY_HOST}:{LOCAL_PORT}",
                 font=("微软雅黑", 9)).pack(pady=2)

        # 账号密码输入
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="账号:").grid(row=0, column=0, padx=5, pady=3)
        self.entry_user = tk.Entry(frame, width=20)
        self.entry_user.grid(row=0, column=1, pady=3)

        tk.Label(frame, text="密码:").grid(row=1, column=0, padx=5, pady=3)
        self.entry_pass = tk.Entry(frame, width=20, show="*")
        self.entry_pass.grid(row=1, column=1, pady=3)

        # 开关按钮
        self.btn = tk.Button(self.root, text="启动", command=self.toggle,
                             width=15, height=2)
        self.btn.pack(pady=10)

        self.status = tk.Label(self.root, text="● 已停止", fg="red")
        self.status.pack()

    def toggle(self):
        if self.server is None:
            self.start()
        else:
            self.stop()

    def start(self):
        username = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()

        if not username or not password:
            messagebox.showwarning("提示", "请输入账号和密码")
            return

        # 向服务端验证
        ok, role = auth_to_server(username, password)
        if not ok:
            messagebox.showerror("验证失败", "账号或密码错误")
            return

        self.role = role

        # 验证通过，开启本地监听 + 系统代理
        try:
            self.server = socketserver.ThreadingTCPServer(
                (PROXY_HOST, LOCAL_PORT), ForwardHandler)
            self.server.daemon_threads = True
            threading.Thread(target=self.server.serve_forever,
                             daemon=True).start()
        except Exception as e:
            messagebox.showerror("启动失败", f"端口 {LOCAL_PORT} 被占用:\n{e}")
            self.server = None
            return

        enable_system_proxy()
        self.btn.config(text="停止")
        self.status.config(text=f"● 运行中 ({role})", fg="green")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        disable_system_proxy()
        self.btn.config(text="启动")
        self.status.config(text="● 已停止", fg="red")

    def on_close(self):
        self.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ========== 信号处理 ==========
def signal_handler(sig, frame):
    disable_system_proxy()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


if __name__ == "__main__":
    disable_system_proxy()   # 启动前清残留
    ClientGUI().run()