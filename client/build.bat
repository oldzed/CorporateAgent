@echo off
chcp 65001 >nul
REM ============================================
REM  企业代理审计系统 - 客户端打包脚本
REM  依赖：pip install pyinstaller
REM ============================================
cd /d "%~dp0"

pyinstaller --onefile --windowed --name "企业代理审计客户端" client.py

echo.
echo 打包完成，可执行文件位于 dist 目录下。
pause
