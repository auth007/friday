@echo off
chcp 65001 >nul
echo 🛡️  VulnTrack 漏洞管理平台
echo ================================

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ❌ 未检测到 Python，请先安装 Python 3.8+
    pause
    exit /b 1
)

echo ✅ Python 已就绪

if not exist ".venv" (
    echo.
    echo 📦 创建虚拟环境...
    python -m venv .venv
)

echo 📦 安装依赖...
.venv\Scripts\pip install -r requirements.txt -q

set PORT=5000
set DEBUG=false
set DB_PATH=vulntrack.db

echo.
echo 🚀 启动服务...
echo    地址: http://localhost:%PORT%
echo    默认账号: admin / admin123
echo.
echo 按 Ctrl+C 停止服务
echo ================================

.venv\Scripts\python app.py
pause
