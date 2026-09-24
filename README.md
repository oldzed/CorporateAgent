# 企业代理审计系统

企业代理审计系统（Enterprise Proxy Audit System）是一个基于 Python 的企业内网代理审计工具，采用 **客户端 / 服务端** 架构，提供代理转发、基于角色的内容过滤、访问审计与集中式会话管理能力。

## 架构概览

```
浏览器/应用
    │ 系统代理自动指向 127.0.0.1:8888
    ▼
client/client.py（本地代理，客户端 GUI）
    │ 认证后转发到服务端
    ▼
server/proxy.py（代理服务端，服务端 GUI）
    │ 按角色黑名单过滤，写入审计库
    ├── 直连目标站点
    └── 或经 Clash 上游代理（127.0.0.1:7897）出网
```

- **客户端**：运行在员工机器上，提供 tkinter 图形界面。启动后自动将 Windows 系统代理指向本地 `127.0.0.1:8888`，把流量经认证后转发给服务端。
- **服务端**：运行在服务器/网关，提供图形化审计界面。负责用户认证、会话管理、基于角色的域名黑名单过滤、审计日志落库，并可按会话开启经 Clash 的外网代理。

## 功能特性

- **代理转发**：支持 HTTP 转发与 HTTPS `CONNECT` 隧道。
- **用户认证**：账号密码登录，密码以 SHA-256 哈希存储于 `server/user.json`，登录后生成会话（session）。
- **角色过滤**：按角色对域名做正则黑名单匹配（`server/role.json`），命中返回拦截页（`server/block.html`）。
- **审计日志**：会话与访问流量写入 SQLite 数据库（`server/audit.db`），记录请求/响应大小并抓取报文片段，可在服务端 GUI 按会话回溯。
- **会话管理**：客户端心跳保活、超时自动下线、管理员在 GUI 中一键断开会话。
- **外网代理（Clash）**：具有权限的用户可一键开启/关闭经 Clash 上游代理的出网通道（默认 `127.0.0.1:7897`）。
- **双 GUI**：服务端 GUI 含「访问日志 / 会话 / 筛选结果」三个页签；客户端 GUI 负责登录与启停。

## 目录结构

```
企业代理审计系统/
├── server/
│   ├── proxy.py        # 代理服务端（转发 + 过滤 + 审计 + 会话管理 + GUI）
│   ├── role.py         # 角色黑名单规则加载与匹配
│   ├── role.json       # 角色 → 域名黑名单（正则）
│   ├── user.json       # 用户账号（SHA-256 密码哈希、角色、外网代理权限）
│   ├── block.html      # 拦截提示页
│   ├── _init_.py       # 包标记（空文件）
│   └── audit.db        # 审计数据库（运行后自动生成，已加入 .gitignore）
├── client/
│   ├── client.py       # 客户端（本地代理 + 系统代理设置 + GUI）
│   ├── build.bat       # PyInstaller 打包脚本
│   └── 企业代理审计客户端.spec  # 打包配置
├── LICENSE
└── README.md
```

## 环境要求

- **操作系统**：Windows（客户端依赖 `winreg` / `ctypes` 设置系统代理）
- **Python**：3.8+（项目基于 Python 3.10 开发）
- **依赖**：全部为标准库（`sqlite3`、`tkinter`、`http.server`、`socketserver`、`urllib`、`winreg`、`hashlib` 等），无需额外安装
- **可选**：Clash 上游代理（用于「外网代理」功能，默认 `127.0.0.1:7897`）

## 快速开始

### 1. 准备配置

首次使用前，在 `server/user.json` 中配置账号，在 `server/role.json` 中配置角色黑名单。可用以下命令生成密码的 SHA-256 哈希：

```bash
python -c "import hashlib; print(hashlib.sha256('你的密码'.encode()).hexdigest())"
```

### 2. 启动服务端

```bash
cd server
python proxy.py
```

在弹窗中点击「启动服务」，默认监听 `0.0.0.0:8080`。

### 3. 启动客户端

在员工机器上：

```bash
cd client
python client.py
```

填写服务端地址（`ip:port`）、账号密码，点击「启动」。客户端会：

1. 向服务端认证并建立会话；
2. 在本机 `127.0.0.1:8888` 启动转发代理；
3. 自动将 Windows 系统代理指向该本地端口。

关闭客户端或停止时，会自动注销会话并还原系统代理。

## 配置说明

### 用户配置 `server/user.json`

```json
{
  "users": [
    {
      "username": "alice",
      "password_hash": "<sha256 十六进制>",
      "role": "admin",
      "proxy": 1
    },
    {
      "username": "bob",
      "password_hash": "<sha256 十六进制>",
      "role": "user",
      "proxy": 0
    }
  ]
}
```

| 字段 | 说明 |
| --- | --- |
| `username` | 登录账号 |
| `password_hash` | 密码的 SHA-256 十六进制哈希 |
| `role` | 所属角色，必须与 `role.json` 中的角色名完全一致 |
| `proxy` | 外网代理权限：`1` 可开启，`0` 无权限 |

### 角色过滤配置 `server/role.json`

```json
{
  "roles": {
    "admin": {
      "blacklist": ["bilibili\\.com"]
    },
    "user": {
      "blacklist": [
        "facebook\\.com",
        "twitter\\.com",
        "weibo\\.com",
        "youtube\\.com",
        "bilibili\\.com"
      ]
    }
  }
}
```

`blacklist` 为域名正则列表（大小写不敏感），命中即拦截。正则中的 `.` 等特殊字符需转义。

### 服务端运行参数

在 `server/proxy.py` 顶部配置区调整：`LISTEN_PORT`（监听端口）、`CLASH_HOST` / `CLASH_PORT`（上游代理地址）、`MAX_BODY_SIZE`（请求体上限）、各超时与线程数等。

### 客户端运行参数

在 `client/client.py` 顶部配置区调整：`LOCAL_PORT`（本地代理端口，默认 8888）、`DEFAULT_UPSTREAM_HOST` / `DEFAULT_UPSTREAM_PORT`（默认服务端地址）。

## 审计数据库

`server/audit.db`（SQLite）在服务端首次启动时自动生成，包含两张表：

- `sessions`：会话信息（用户、角色、客户端 IP、登录/活跃时间、状态、外网代理开关）。
- `flows`：访问流量（时间、会话、方法、主机、URL、状态码、放行/拦截、命中规则、请求/响应大小、报文片段、Content-Type）。

可通过服务端 GUI 的「会话」页签右键某会话，在「筛选结果」页签查看该会话的流量明细。

## 打包客户端

在 Windows 下双击 `client/build.bat`（脚本会自动检测并安装 PyInstaller）：

```bash
cd client
build.bat
```

生成的可执行文件位于 `client/dist/企业代理审计客户端.exe`。

## 说明

- `server/audit.db` 为运行时生成，已加入 `.gitignore`，无需手动提交。
- 客户端配置（上次填写的服务端地址）保存在 `%APPDATA%\CorporateAgent\client_config.json`。
- `docs/` 目录中的需求设计文档与实际实现存在偏差，以本 README 与源码为准。
