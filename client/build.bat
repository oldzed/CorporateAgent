@echo off
chcp 936 >nul
setlocal enabledelayedexpansion

REM ============================================
REM  企业代理审计系统 - 客户端打包脚本
REM  功能：将 client.py 打包为单文件 Windows 可执行程序
REM  依赖：Python 3.8+、PyInstaller
REM ============================================

title 企业代理审计系统 - 客户端打包
cd /d "%~dp0"

REM ---------- 可配置项 ----------
set "APP_NAME=企业代理审计客户端"
set "ENTRY=client.py"
set "ICON=client.ico"
REM ------------------------------

echo ============================================
echo   企业代理审计系统 - 客户端打包
echo ============================================
echo.

REM 1. 检查 Python 环境
echo [1/4] 检查 Python 环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Python，请先安装 Python 3.8+ 并加入 PATH。
    pause
    exit /b 1
)

REM 2. 检查 PyInstaller，缺失则自动安装
echo [2/4] 检查 PyInstaller...
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo 未安装 PyInstaller，正在自动安装...
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo [错误] PyInstaller 安装失败，请手动执行：pip install pyinstaller
        pause
        exit /b 1
    )
)

REM 3. 清理旧的构建产物
echo [3/4] 清理旧的构建产物...
if exist "build"  rd /s /q "build"
if exist "dist"   rd /s /q "dist"
if exist "*.spec" del /q "*.spec" 2>nul

REM 4. 打包（若存在图标文件则一并打包）
set "ICON_ARG="
if exist "%ICON%" set "ICON_ARG=--icon=%ICON%"

echo [4/4] 开始打包（首次打包可能需要几分钟）...
python -m PyInstaller --onefile --windowed --clean --noconfirm --name "%APP_NAME%" !ICON_ARG! "%ENTRY%"
if errorlevel 1 (
    echo [错误] 打包失败，请查看上方错误信息。
    pause
    exit /b 1
)

REM 校验产物
if not exist "dist\%APP_NAME%.exe" (
    echo [错误] 未找到生成的可执行文件：dist\%APP_NAME%.exe
    pause
    exit /b 1
)

echo.
echo ============================================
echo   打包完成！
echo   可执行文件：dist\%APP_NAME%.exe
echo ============================================
echo.
pause
endlocal
