# 企业代理审计系统

企业代理审计系统（Enterprise Proxy Audit System）是一个基于 Python 的企业内网代理审计工具，提供 HTTP 代理转发、内容过滤与访问审计功能。

## 功能特性

- **代理转发**：基于 HTTP 代理协议转发客户端请求
- **内容过滤**：根据 `rules.json` 中的规则对域名、关键词、文件扩展名进行过滤
- **审计日志**：将访问记录写入 SQLite 数据库（`server/audit.db`），支持追溯
- **GUI 客户端**：基于 tkinter 的图形化配置与管理界面

## 目录结构

```
企业代理审计系统/
├── server/
│   ├── proxy.py          # 代理服务端（过滤+审计）
│   ├── rules.json        # 过滤规则
│   └── audit.db          # 审计日志（运行后生成）
├── client/
│   ├── client.py         # tkinter GUI客户端
│   └── build.bat         # PyInstaller打包脚本
├── docs/
│   ├── 报告.pdf
│   └── 演示视频.mp4
└── README.md
```

## 环境要求

- Python 3.8+
- 依赖：`sqlite3`（标准库）、`tkinter`（标准库）

## 快速开始

### 1. 启动代理服务端

```bash
cd server
python proxy.py
```

### 2. 启动 GUI 客户端

```bash
cd client
python client.py
```

### 3. 打包客户端

在 Windows 下双击运行 `client/build.bat`（需先安装 PyInstaller）：

```bash
pip install pyinstaller
```

## 过滤规则

编辑 `server/rules.json` 配置过滤规则：

```json
{
  "blocked_domains": [],
  "blocked_keywords": [],
  "blocked_extensions": []
}
```

## 说明

- `server/audit.db` 在服务端首次运行时自动生成，已加入 `.gitignore`，无需手动提交。
- `docs/` 目录用于存放项目报告（`报告.pdf`）与演示视频（`演示视频.mp4`），请自行放入相应文件。
