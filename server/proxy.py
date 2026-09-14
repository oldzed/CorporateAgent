import http.server
import socketserver
import urllib.request
import urllib.error
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
import queue
import json
import hashlib

# ========== 配置区 ==========
LISTEN_PORT = 8080
USER_FILE = "user.json"
# ============================

log_queue = queue.Queue()
log_widget = None


# ========== 日志 ==========
def write_log(client_ip, method, url, status):
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {client_ip}  {method}  {url}  →  {status}\n"
    log_queue.put(line)
    print(line, end="")


# ========== 用户验证 ==========
def load_users():
    try:
        with open(USER_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("users", [])
    except Exception as e:
        print(f"[警告] 读取 {USER_FILE} 失败: {e}")
        return []


def verify_user(username, password):
    if not username or not password:
        return False, None
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    for u in load_users():
        if u.get("username") == username and u.get("password_hash") == pwd_hash:
            return True, u.get("role", "user")
    return False, None


# ========== 代理处理器 ==========
class ProxyHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):     self.handle_request()
    def do_POST(self):    self.handle_request()
    def do_PUT(self):     self.handle_request()
    def do_DELETE(self):  self.handle_request()
    def do_HEAD(self):    self.handle_request()
    def do_OPTIONS(self): self.handle_request()

    def handle_request(self):
        # ---- 拦截验证请求 ----
        if self.path == "/__auth__" and self.command == "POST":
            self.handle_auth()
            return

        url = self.path
        method = self.command
        client_ip = self.client_address[0]
        print(f"[收到请求] {client_ip}  {method}  {url}")

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else None

        try:
            req = urllib.request.Request(url, data=body, method=method)
            for k, v in self.headers.items():
                if k.lower() not in ('proxy-connection', 'connection',
                                     'host', 'content-length',
                                     'accept-encoding'):
                    req.add_header(k, v)

            with urllib.request.urlopen(req, timeout=15) as resp:
                status = resp.status
                content = resp.read()
                content_type = resp.headers.get("Content-Type", "text/html")

            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            write_log(client_ip, method, url, status)

        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            try: self.wfile.write(e.read())
            except: pass
            write_log(client_ip, method, url, e.code)

        except Exception as e:
            self.send_response(502)
            self.end_headers()
            try: self.wfile.write(f"502 Bad Gateway: {e}".encode())
            except: pass
            write_log(client_ip, method, url, "ERR")

    def handle_auth(self):
        """处理 /__auth__ 验证请求"""
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        username = "?"
        try:
            data = json.loads(body)
            username = data.get("username", "?")
            ok, role = verify_user(data.get("username"), data.get("password"))
        except Exception:
            ok, role = False, None

        resp = json.dumps({"ok": ok, "role": role}).encode()
        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

        write_log(self.client_address[0], "AUTH", username,
                  f"OK({role})" if ok else "FAIL")

    def do_CONNECT(self):
        """HTTPS隧道：记录并放行"""
        client_ip = self.client_address[0]
        print(f"[CONNECT] {client_ip}  {self.path}")
        try:
            host, port = self.path.split(":")
            port = int(port)
            upstream = socket.create_connection((host, port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()
            write_log(client_ip, "CONNECT", self.path, 200)
            self.tunnel(self.connection, upstream)
        except Exception:
            try:
                self.send_response(502)
                self.end_headers()
            except: pass
            write_log(client_ip, "CONNECT", self.path, "ERR")

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
class ServerGUI:
    def __init__(self):
        global log_widget
        self.root = tk.Tk()
        self.root.title("代理服务端 - 流量审计")
        self.root.geometry("800x480")
        self.server = None

        tk.Label(self.root, text=f"监听端口: {LISTEN_PORT}",
                 font=("微软雅黑", 10)).pack(pady=3)

        self.btn = tk.Button(self.root, text="启动服务",
                             command=self.toggle, width=15, height=2)
        self.btn.pack(pady=5)

        self.status = tk.Label(self.root, text="● 已停止", fg="red")
        self.status.pack()

        tk.Label(self.root,
                 text="访问日志（时间 / 客户端 / 方法 / 路径 / 状态）",
                 font=("微软雅黑", 9)).pack(pady=3)

        log_widget = scrolledtext.ScrolledText(
            self.root, height=18, font=("Consolas", 9))
        log_widget.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Button(self.root, text="清空日志",
                  command=lambda: log_widget.delete("1.0", "end")).pack(pady=3)

        self.poll_log_queue()

    def poll_log_queue(self):
        while not log_queue.empty():
            line = log_queue.get()
            log_widget.insert("end", line)
            log_widget.see("end")
        self.root.after(200, self.poll_log_queue)

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
            self.server = socketserver.ThreadingTCPServer(
                ("0.0.0.0", LISTEN_PORT), ProxyHandler)
            self.server.daemon_threads = True
            threading.Thread(target=self.server.serve_forever,
                             daemon=True).start()
            print(f"[启动] 监听 0.0.0.0:{LISTEN_PORT}")
        except Exception as e:
            print(f"[启动失败] {e}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            print("[停止] 服务已关闭")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    ServerGUI().run()