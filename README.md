# 🛡️ Friday - 漏洞管理平台

> 基于 Python Flask + SQLite 的轻量级企业漏洞管理系统

## 快速启动

### Linux / macOS
```bash
chmod +x start.sh
./start.sh
```

### Windows
```
双击 start.bat
```

### 手动安装
```bash
pip install -r requirements.txt
python app.py
```

访问 http://localhost:5000

## 默认账号

| 账号  | 密码     | 角色     | 说明              |
|-------|----------|----------|-------------------|
| admin | admin123 | 管理员   | 全部权限          |
| alice | alice    | 普通用户 | 查看、提交、编辑  |
| bob   | bob      | 只读用户 | 仅查看            |
| carol | carol    | 项目限制 | 仅可查看 Project1 |

## 功能特性

- **鉴权系统**：管理员 / 普通用户角色，细粒度权限（查看、提交、编辑、删除）
- **项目管理**：创建项目、设置成员、按项目限制用户访问范围
- **漏洞管理**：完整的漏洞生命周期（提交 → 修复中 → 已修复 → 关闭）
- **仪表盘**：统计图表、按项目筛选、趋势分析
- **通知系统**：支持多个飞书机器人 Webhook + 邮件通知
- **数据持久化**：SQLite 轻量数据库，无需额外部署

## 环境变量配置

```bash
PORT=5000          # 服务端口（默认 5000）
DB_PATH=vulntrack.db  # 数据库路径
DEBUG=false        # 调试模式

# 邮件通知（可选）
SMTP_HOST=smtp.qq.com
SMTP_PORT=465
SMTP_USER=xxx@qq.com
SMTP_PASS=授权码
SMTP_FROM=xxx@qq.com
```

## 技术栈

- **后端**：Python 3.8+ / Flask
- **数据库**：SQLite（WAL模式）
- **前端**：纯 HTML + CSS + JavaScript（无框架依赖）
- **通知**：飞书 Webhook API / SMTP 邮件

## 项目结构

```
vulntrack/
├── app.py          # 后端主程序
├── static/
│   └── index.html  # 前端单页应用
├── requirements.txt
├── start.sh        # Linux/macOS 启动
├── start.bat       # Windows 启动
└── vulntrack.db    # SQLite 数据库（首次运行后生成）
```
