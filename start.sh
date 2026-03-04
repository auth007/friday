#!/bin/bash
set -e

echo "🛡️  Sjzy_Friday 漏洞管理平台"
echo "================================"

if ! command -v python3 &>/dev/null; then
    echo "❌ 未检测到 Python3"; exit 1
fi
echo "✅ Python: $(python3 --version)"

VENV_DIR=".venv"

# 如果 venv 不完整则重建
if [ ! -f "$VENV_DIR/bin/python" ] || [ ! -f "$VENV_DIR/bin/pip" ]; then
    echo "📦 创建虚拟环境..."
    rm -rf "$VENV_DIR"

    # 尝试方式1：标准 venv
    python3 -m venv "$VENV_DIR" 2>/dev/null

    # pip 还是没有？说明系统缺 ensurepip，装 python3-venv/python3-full
    if [ ! -f "$VENV_DIR/bin/pip" ]; then
        echo "⚠️  pip 缺失，尝试安装 python3-full..."
        apt-get install -y python3-full python3-pip -qq 2>/dev/null || \
        apt-get install -y python3-venv          -qq 2>/dev/null || true
        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR" 2>/dev/null || true
    fi

    # 还是没有 pip？用 get-pip.py 引导
    if [ ! -f "$VENV_DIR/bin/pip" ] && [ -f "$VENV_DIR/bin/python" ]; then
        echo "⚠️  用 get-pip.py 引导安装 pip..."
        curl -fsSL https://bootstrap.pypa.io/get-pip.py | "$VENV_DIR/bin/python" 2>/dev/null || \
        wget -qO- https://bootstrap.pypa.io/get-pip.py | "$VENV_DIR/bin/python" 2>/dev/null || true
    fi

    # 终极兜底：--without-pip 建 venv，再手动装
    if [ ! -f "$VENV_DIR/bin/pip" ]; then
        echo "⚠️  尝试 --without-pip 模式..."
        rm -rf "$VENV_DIR"
        python3 -m venv --without-pip "$VENV_DIR" 2>/dev/null || true
        if [ -f "$VENV_DIR/bin/python" ]; then
            curl -fsSL https://bootstrap.pypa.io/get-pip.py | "$VENV_DIR/bin/python" || \
            wget -qO- https://bootstrap.pypa.io/get-pip.py  | "$VENV_DIR/bin/python" || true
        fi
    fi
fi

# 最终检查
if [ ! -f "$VENV_DIR/bin/pip" ]; then
    echo ""
    echo "❌ 无法创建虚拟环境，尝试直接用系统 pip..."
    # 系统级安装兜底（Debian/Ubuntu externally-managed 环境加 --break-system-packages）
    python3 -m pip install -r requirements.txt -q 2>/dev/null || \
    python3 -m pip install -r requirements.txt -q --break-system-packages || {
        echo "❌ 所有方式均失败，请手动运行："
        echo "   apt install python3-full python3-pip"
        echo "   然后重新执行 ./start.sh"
        exit 1
    }
    VENV_PYTHON="python3"
    VENV_GUNICORN="gunicorn"
else
    echo "📦 安装依赖..."
    "$VENV_DIR/bin/pip" install -r requirements.txt -q
    VENV_PYTHON="$VENV_DIR/bin/python"
    VENV_GUNICORN="$VENV_DIR/bin/gunicorn"
fi

export PORT=${PORT:-5000}
export DEBUG=${DEBUG:-false}
export DB_PATH=${DB_PATH:-sjzy_friday.db}
WORKERS=${WORKERS:-4}

echo ""
echo "🚀 启动服务 (gunicorn × ${WORKERS} workers)"
echo "   地址:     http://0.0.0.0:$PORT"
echo "   数据库:   $DB_PATH"
echo "   默认账号: admin / admin123"
echo "   飞书登录: ${FEISHU_APP_ID:+已配置}${FEISHU_APP_ID:-未配置}"
echo ""
echo "停止: Ctrl+C  |  后台运行: systemctl start sjzy-friday"
echo "================================"

exec $VENV_GUNICORN \
    --workers "$WORKERS" \
    --bind "0.0.0.0:$PORT" \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    app:app
