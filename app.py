#!/usr/bin/env python3
"""Sjzy_Friday - 漏洞管理平台"""
import os
import re
import json
import hashlib
import secrets
import sqlite3
import smtplib
import threading
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, request, jsonify, send_from_directory, g, redirect, make_response

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=os.path.join(_BASE_DIR, 'static'))
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DB_PATH           = os.environ.get('DB_PATH', os.path.join(_BASE_DIR, 'sjzy_friday.db'))
FEISHU_APP_ID     = os.environ.get('FEISHU_APP_ID', '')
FEISHU_APP_SECRET = os.environ.get('FEISHU_APP_SECRET', '')
SITE_URL          = os.environ.get('SITE_URL', 'http://localhost:5000')


# ══════════ 安全工具 ══════════

def esc(s):
    """HTML 实体转义，防 XSS"""
    if s is None:
        return ''
    return (str(s).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))

_VALID_COLOR    = re.compile(r'^#[0-9a-fA-F]{6}$')
_ALLOWED_SEV    = {'严重', '高危', '中危', '低危'}
_ALLOWED_STATUS = {'待修复', '修复中', '已修复', '已关闭'}
_ALLOWED_ROLE   = {'admin', 'user'}

def validate_color(c):
    return c if _VALID_COLOR.match(c or '') else '#58a6ff'

def validate_severity(s):
    return s if s in _ALLOWED_SEV else None

def validate_status(s):
    return s if s in _ALLOWED_STATUS else None

def validate_role(r):
    return r if r in _ALLOWED_ROLE else 'user'

def cap(s, n=1000):
    return None if s is None else str(s)[:n]

def safe_int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ══════════ DATABASE ══════════

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA synchronous = NORMAL")   # WAL模式下安全且更快
        g.db.execute("PRAGMA cache_size = -32000")    # 32MB 查询缓存
        g.db.execute("PRAGMA busy_timeout = 5000")    # 写锁等待5秒，避免并发报错
        g.db.execute("PRAGMA wal_autocheckpoint = 1000")
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL DEFAULT '',
            feishu_open_id TEXT UNIQUE,
            feishu_union_id TEXT,
            feishu_name TEXT,
            feishu_avatar TEXT,
            auth_type TEXT NOT NULL DEFAULT 'local',
            role TEXT NOT NULL DEFAULT 'user',
            perm_view INTEGER NOT NULL DEFAULT 1,
            perm_submit INTEGER NOT NULL DEFAULT 1,
            perm_edit INTEGER NOT NULL DEFAULT 0,
            perm_delete INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS user_project_access (
            user_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, project_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            color TEXT NOT NULL DEFAULT '#58a6ff',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS project_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss REAL NOT NULL DEFAULT 0,
            project_id INTEGER,
            assignee TEXT,
            component TEXT NOT NULL,
            description TEXT NOT NULL,
            poc TEXT,
            fix_suggestion TEXT,
            status TEXT NOT NULL DEFAULT '待修复',
            submitter_id INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            fixed_at TEXT,
            closed_at TEXT,
            notify_on_close INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (submitter_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS vuln_notify_targets (
            vuln_id INTEGER NOT NULL,
            notify_source_id INTEGER NOT NULL,
            PRIMARY KEY (vuln_id, notify_source_id),
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
            FOREIGN KEY (notify_source_id) REFERENCES notify_sources(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notify_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            note TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS feishu_oauth_state (
            state TEXT PRIMARY KEY,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            redirect_vuln_id INTEGER
        );
        """)
        db.commit()

        # 兼容旧库迁移
        cols = {r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()}
        for col, sql in [
            ("feishu_open_id",  "ALTER TABLE users ADD COLUMN feishu_open_id TEXT"),
            ("feishu_union_id", "ALTER TABLE users ADD COLUMN feishu_union_id TEXT"),
            ("feishu_name",     "ALTER TABLE users ADD COLUMN feishu_name TEXT"),
            ("feishu_avatar",   "ALTER TABLE users ADD COLUMN feishu_avatar TEXT"),
            ("auth_type",       "ALTER TABLE users ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'local'"),
        ]:
            if col not in cols:
                try:
                    db.execute(sql); db.commit()
                except Exception:
                    pass

        # 首次初始化演示数据
        if db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c'] == 0:
            _seed_demo_data(db)

        db.execute("DELETE FROM feishu_oauth_state WHERE created_at < datetime('now','-10 minutes')")
        db.commit()


def _seed_demo_data(db):
    ph = _hash_pw('admin123')
    db.execute("INSERT INTO users (username,email,password_hash,role,perm_view,perm_submit,perm_edit,perm_delete) VALUES ('admin','admin@sjzy.local',?,'admin',1,1,1,1)", [ph])
    db.execute("INSERT INTO users (username,email,password_hash,role,perm_view,perm_submit,perm_edit,perm_delete) VALUES ('alice','alice@example.com',?,'user',1,1,1,0)", [_hash_pw('alice')])
    db.execute("INSERT INTO users (username,email,password_hash,role,perm_view,perm_submit,perm_edit,perm_delete) VALUES ('bob','bob@example.com',?,'user',1,0,0,0)", [_hash_pw('bob')])
    db.execute("INSERT INTO users (username,email,password_hash,role,perm_view,perm_submit,perm_edit,perm_delete) VALUES ('carol','carol@example.com',?,'user',1,1,0,0)", [_hash_pw('carol')])
    db.execute("INSERT INTO projects (name,description,color) VALUES ('Core Platform','核心业务平台安全','#58a6ff')")
    db.execute("INSERT INTO projects (name,description,color) VALUES ('Mobile App','移动端应用安全','#3fb950')")
    db.execute("INSERT INTO projects (name,description,color) VALUES ('API Gateway','API网关及中间件','#f78166')")
    db.execute("INSERT INTO project_members (project_id,name) VALUES (1,'张三')")
    db.execute("INSERT INTO project_members (project_id,name) VALUES (1,'李四')")
    db.execute("INSERT INTO project_members (project_id,name) VALUES (2,'王五')")
    db.execute("INSERT INTO project_members (project_id,name) VALUES (2,'赵六')")
    db.execute("INSERT INTO project_members (project_id,name) VALUES (3,'陈七')")
    carol_id = db.execute("SELECT id FROM users WHERE username='carol'").fetchone()['id']
    db.execute("INSERT INTO user_project_access (user_id,project_id) VALUES (?,1)", [carol_id])
    for v in [
        ('SF-2024-001','SQL注入漏洞 - 登录接口','高危',7.5,1,'张三','auth-service v2.3','登录接口存在SQL注入漏洞，攻击者可绕过身份验证',"curl -X POST /api/login -d 'user=admin OR 1=1--'",'使用参数化查询','已修复',1),
        ('SF-2024-002','XSS漏洞 - 用户评论模块','中危',6.1,1,'李四','comment-service','用户评论未做XSS过滤，可执行恶意脚本','<script>alert(1)</script>','对用户输入进行HTML实体编码','待修复',1),
        ('SF-2024-003','文件上传漏洞 - 头像上传','严重',9.0,2,'王五','user-center','头像上传未校验文件类型，可上传webshell',None,'校验文件MIME类型，存储到OSS','修复中',2),
        ('SF-2024-004','API鉴权缺失 - 订单接口','高危',8.2,3,'陈七','order-api v1.2','API接口缺少鉴权，未授权用户可访问任意订单','curl /api/orders/12345','添加JWT鉴权中间件','待修复',1),
        ('SF-2024-005','弱密码策略 - 用户注册','低危',4.3,1,'张三','auth-service','用户注册未强制复杂密码',None,'强制密码复杂度要求','已关闭',1),
    ]:
        db.execute("INSERT INTO vulnerabilities (vuln_id,title,severity,cvss,project_id,assignee,component,description,poc,fix_suggestion,status,submitter_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", v)
    db.commit()


def _hash_pw(pw):
    salt = os.environ.get('PASSWORD_SALT', 'sjzy_friday_2024')
    return hashlib.sha256((salt + pw).encode()).hexdigest()


# ══════════ AUTH ══════════

def _make_session(db, user_id):
    token   = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    db.execute("INSERT OR REPLACE INTO sessions (token,user_id,expires_at) VALUES (?,?,?)",
               [token, user_id, expires])
    db.commit()
    return token


def get_current_user():
    token = request.cookies.get('session_token') or request.headers.get('X-Session-Token')
    if not token or not re.fullmatch(r'[0-9a-f]{64}', token):
        return None
    row = get_db().execute("""
        SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
        WHERE s.token=? AND s.expires_at>datetime('now') AND u.is_active=1
    """, [token]).fetchone()
    return dict(row) if row else None


def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        u = get_current_user()
        if not u:
            return jsonify({'error': '未登录', 'code': 401}), 401
        g.user = u
        return f(*a, **kw)
    return d


def view_required(f):
    """登录 + 必须有 perm_view 权限"""
    @wraps(f)
    def d(*a, **kw):
        u = get_current_user()
        if not u:
            return jsonify({'error': '未登录', 'code': 401}), 401
        if not u['perm_view'] and u['role'] != 'admin':
            return jsonify({'error': '无查看权限', 'code': 403}), 403
        g.user = u
        return f(*a, **kw)
    return d


def admin_required(f):
    @wraps(f)
    def d(*a, **kw):
        u = get_current_user()
        if not u:
            return jsonify({'error': '未登录', 'code': 401}), 401
        if u['role'] != 'admin':
            return jsonify({'error': '需要管理员权限', 'code': 403}), 403
        g.user = u
        return f(*a, **kw)
    return d


def _user_project_ids(user):
    """返回用户可访问的项目 ID 列表，空列表代表无限制"""
    if user['role'] == 'admin':
        return None  # None = 无限制
    rows = get_db().execute(
        "SELECT project_id FROM user_project_access WHERE user_id=?", [user['id']]).fetchall()
    return [r['project_id'] for r in rows]  # 空列表 = 无限制（全部项目）


def _check_project_access(user, project_id):
    ids = _user_project_ids(user)
    if ids is None or not ids:
        return True
    return safe_int(project_id, -1) in ids


def fmt_user(u):
    return {
        'id':           u['id'],
        'username':     u['username'],
        'email':        u.get('email', ''),
        'role':         u['role'],
        'auth_type':    u.get('auth_type', 'local'),
        'feishu_name':  u.get('feishu_name') or '',
        'feishu_avatar':u.get('feishu_avatar') or '',
        'display_name': u.get('feishu_name') or u['username'],
        'perms': {
            'view':   bool(u['perm_view']),
            'submit': bool(u['perm_submit']),
            'edit':   bool(u['perm_edit']),
            'delete': bool(u['perm_delete']),
        }
    }


# ══════════ 安全响应头 ══════════

@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options']  = 'nosniff'
    resp.headers['X-Frame-Options']         = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection']        = '1; mode=block'
    resp.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    return resp


# ══════════ ROUTES ══════════

@app.route('/')
def index():
    return send_from_directory(os.path.join(_BASE_DIR, 'static'), 'index.html')


# ── 本地登录 ──

@app.route('/api/auth/login', methods=['POST'])
def login():
    d  = request.json or {}
    un = cap(d.get('username', '').strip(), 64)
    pw = d.get('password', '')
    if not un or not pw or len(pw) > 128:
        return jsonify({'error': '用户名或密码格式错误'}), 400
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE username=? AND is_active=1 AND auth_type='local'",
                      [un]).fetchone()
    if not user or user['password_hash'] != _hash_pw(pw):
        return jsonify({'error': '用户名或密码错误'}), 401
    token = _make_session(db, user['id'])
    resp  = jsonify({'ok': True, 'user': fmt_user(dict(user))})
    resp.set_cookie('session_token', token, httponly=True, max_age=86400, samesite='Lax')
    return resp


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    token = request.cookies.get('session_token')
    if token and re.fullmatch(r'[0-9a-f]{64}', token):
        try:
            get_db().execute("DELETE FROM sessions WHERE token=?", [token])
            get_db().commit()
        except Exception:
            pass
    resp = jsonify({'ok': True})
    resp.delete_cookie('session_token')
    return resp


@app.route('/api/auth/me')
def me():
    u = get_current_user()
    if not u:
        return jsonify({'error': '未登录'}), 401
    return jsonify(fmt_user(u))


# ── 飞书 OAuth ──

@app.route('/api/auth/feishu/config')
def feishu_config():
    return jsonify({
        'enabled': bool(FEISHU_APP_ID and FEISHU_APP_SECRET),
        'app_id':  FEISHU_APP_ID
    })


@app.route('/api/auth/feishu/url')
def feishu_auth_url():
    if not FEISHU_APP_ID:
        return jsonify({'error': '飞书登录未配置'}), 400
    vuln_id = request.args.get('vuln_id', '')
    state   = secrets.token_urlsafe(24)
    db      = get_db()
    db.execute("DELETE FROM feishu_oauth_state WHERE created_at < datetime('now','-10 minutes')")
    db.execute("INSERT INTO feishu_oauth_state (state,redirect_vuln_id) VALUES (?,?)",
               [state, safe_int(vuln_id)])
    db.commit()
    redirect_uri = urllib.parse.quote(f"{SITE_URL}/api/auth/feishu/callback", safe='')
    url = (f"https://open.feishu.cn/open-apis/authen/v1/authorize"
           f"?app_id={FEISHU_APP_ID}&redirect_uri={redirect_uri}&state={state}"
           f"&scope=contact:user.base:readonly")
    return jsonify({'url': url})


@app.route('/api/auth/feishu/callback')
def feishu_callback():
    code  = request.args.get('code', '')
    state = request.args.get('state', '')
    if not code or not state or len(state) > 64:
        return redirect('/?feishu_error=missing_params')
    db  = get_db()
    row = db.execute(
        "SELECT * FROM feishu_oauth_state WHERE state=? AND created_at > datetime('now','-10 minutes')",
        [state]).fetchone()
    if not row:
        return redirect('/?feishu_error=invalid_state')
    redirect_vuln_id = row['redirect_vuln_id']
    db.execute("DELETE FROM feishu_oauth_state WHERE state=?", [state])
    db.commit()

    try:
        uinfo = _feishu_get_user_info(code)
    except Exception as e:
        print(f"[Feishu OAuth] {e}")
        return redirect('/?feishu_error=oauth_failed')

    open_id = uinfo.get('open_id', '')
    if not open_id:
        return redirect('/?feishu_error=no_openid')

    name    = cap(uinfo.get('name', ''), 100)
    avatar  = cap(uinfo.get('avatar_url', ''), 500)
    email   = cap(uinfo.get('email', '') or uinfo.get('enterprise_email', ''), 200)
    u_id    = uinfo.get('union_id', '')

    existing = db.execute("SELECT * FROM users WHERE feishu_open_id=? AND is_active=1",
                          [open_id]).fetchone()
    if existing:
        db.execute("UPDATE users SET feishu_name=?,feishu_avatar=?,feishu_union_id=? WHERE id=?",
                   [name, avatar, u_id, existing['id']])
        db.commit()
        user_id = existing['id']
    else:
        base = f"fs_{open_id[-8:]}"
        username, sfx = base, 0
        while db.execute("SELECT id FROM users WHERE username=?", [username]).fetchone():
            sfx += 1; username = f"{base}_{sfx}"
        # 飞书用户初次登录：默认全部权限为 0，需管理员手动授权
        db.execute("""INSERT INTO users
            (username,email,feishu_open_id,feishu_union_id,feishu_name,feishu_avatar,
             auth_type,role,perm_view,perm_submit,perm_edit,perm_delete)
            VALUES (?,?,?,?,?,?,'feishu','user',0,0,0,0)""",
            [username, email, open_id, u_id, name, avatar])
        db.commit()
        user_id = db.execute("SELECT id FROM users WHERE feishu_open_id=?", [open_id]).fetchone()['id']

    token  = _make_session(db, user_id)
    target = f"/?vuln_id={redirect_vuln_id}" if redirect_vuln_id else '/'
    resp   = make_response(redirect(target))
    resp.set_cookie('session_token', token, httponly=True, max_age=86400, samesite='Lax')
    return resp


def _feishu_get_user_info(code):
    # 1. app_access_token
    r = _http_post('https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal',
                   {'app_id': FEISHU_APP_ID, 'app_secret': FEISHU_APP_SECRET})
    if r.get('code') != 0:
        raise Exception(f"app_token 失败: {r}")
    app_token = r['app_access_token']

    # 2. user_access_token
    r2 = _http_post('https://open.feishu.cn/open-apis/authen/v1/oidc/access_token',
                    {'grant_type': 'authorization_code', 'code': code},
                    auth=f'Bearer {app_token}')
    if r2.get('code') != 0:
        raise Exception(f"user_token 失败: {r2}")
    user_token = r2['data']['access_token']

    # 3. user_info
    req = urllib.request.Request(
        'https://open.feishu.cn/open-apis/authen/v1/user_info',
        headers={'Authorization': f'Bearer {user_token}'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        r3 = json.loads(resp.read())
    if r3.get('code') != 0:
        raise Exception(f"user_info 失败: {r3}")
    return r3['data']


def _http_post(url, body, auth=None):
    headers = {'Content-Type': 'application/json'}
    if auth:
        headers['Authorization'] = auth
    req = urllib.request.Request(
        url, data=json.dumps(body).encode('utf-8'), headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


# ── PROJECTS ──

@app.route('/api/projects')
@login_required
def list_projects():
    db   = get_db()
    user = g.user
    ids  = _user_project_ids(user)
    if ids is None or not ids:
        projects = db.execute("SELECT * FROM projects WHERE is_active=1 ORDER BY id").fetchall()
    else:
        ph = ','.join('?' * len(ids))
        projects = db.execute(
            f"SELECT * FROM projects WHERE is_active=1 AND id IN ({ph}) ORDER BY id",
            ids).fetchall()
    result = []
    for p in projects:
        members = db.execute("SELECT name FROM project_members WHERE project_id=?", [p['id']]).fetchall()
        cnt     = db.execute("SELECT COUNT(*) as c FROM vulnerabilities WHERE project_id=?", [p['id']]).fetchone()
        result.append({**dict(p), 'members': [m['name'] for m in members], 'vuln_count': cnt['c']})
    return jsonify(result)


@app.route('/api/projects', methods=['POST'])
@admin_required
def create_project():
    d    = request.json or {}
    name = cap(d.get('name', '').strip(), 100)
    if not name:
        return jsonify({'error': '项目名称不能为空'}), 400
    db  = get_db()
    cur = db.execute("INSERT INTO projects (name,description,color) VALUES (?,?,?)",
                     [name, cap(d.get('description', ''), 500), validate_color(d.get('color'))])
    pid = cur.lastrowid
    for m in d.get('members', [])[:50]:
        m = cap(str(m).strip(), 50)
        if m:
            db.execute("INSERT INTO project_members (project_id,name) VALUES (?,?)", [pid, m])
    db.commit()
    return jsonify({'ok': True, 'id': pid})


@app.route('/api/projects/<int:pid>', methods=['PUT'])
@admin_required
def update_project(pid):
    d    = request.json or {}
    name = cap(d.get('name', '').strip(), 100)
    if not name:
        return jsonify({'error': '项目名称不能为空'}), 400
    db = get_db()
    db.execute("UPDATE projects SET name=?,description=?,color=? WHERE id=?",
               [name, cap(d.get('description', ''), 500), validate_color(d.get('color')), pid])
    db.execute("DELETE FROM project_members WHERE project_id=?", [pid])
    for m in d.get('members', [])[:50]:
        m = cap(str(m).strip(), 50)
        if m:
            db.execute("INSERT INTO project_members (project_id,name) VALUES (?,?)", [pid, m])
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/projects/<int:pid>', methods=['DELETE'])
@admin_required
def delete_project(pid):
    db = get_db()
    db.execute("UPDATE projects SET is_active=0 WHERE id=?", [pid])
    db.commit()
    return jsonify({'ok': True})


# ── VULNERABILITIES ──

@app.route('/api/vulns')
@view_required
def list_vulns():
    db, user = get_db(), g.user
    where, params = ["1=1"], []
    ids = _user_project_ids(user)
    if ids:
        ph = ','.join('?' * len(ids))
        where.append(f"v.project_id IN ({ph})")
        params.extend(ids)

    q = cap(request.args.get('q', '').strip(), 200)
    if q:
        where.append("(v.title LIKE ? OR v.component LIKE ? OR v.vuln_id LIKE ?)")
        params.extend([f'%{q}%', f'%{q}%', f'%{q}%'])

    sev = validate_severity(request.args.get('severity', ''))
    if sev:
        where.append("v.severity=?"); params.append(sev)

    sta = validate_status(request.args.get('status', ''))
    if sta:
        where.append("v.status=?"); params.append(sta)

    proj = safe_int(request.args.get('project', ''))
    if proj is not None:
        where.append("v.project_id=?"); params.append(proj)

    w    = ' AND '.join(where)
    rows = db.execute(f"""
        SELECT v.*, p.name as project_name, p.color as project_color, u.username as submitter_name
        FROM vulnerabilities v
        LEFT JOIN projects p ON p.id=v.project_id
        LEFT JOIN users u ON u.id=v.submitter_id
        WHERE {w}
        ORDER BY CASE v.severity WHEN '严重' THEN 1 WHEN '高危' THEN 2
                                 WHEN '中危' THEN 3 WHEN '低危' THEN 4 ELSE 5 END,
                 v.id DESC
    """, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/vulns/<int:vid>')
@view_required
def get_vuln(vid):
    db  = get_db()
    row = db.execute("""
        SELECT v.*, p.name as project_name, p.color as project_color, u.username as submitter_name
        FROM vulnerabilities v
        LEFT JOIN projects p ON p.id=v.project_id
        LEFT JOIN users u ON u.id=v.submitter_id WHERE v.id=?
    """, [vid]).fetchone()
    if not row:
        return jsonify({'error': '漏洞不存在'}), 404
    if not _check_project_access(g.user, row['project_id']):
        return jsonify({'error': '无权访问'}), 403
    result  = dict(row)
    targets = db.execute("""
        SELECT ns.id, ns.name, ns.type FROM vuln_notify_targets vnt
        JOIN notify_sources ns ON ns.id=vnt.notify_source_id WHERE vnt.vuln_id=?
    """, [vid]).fetchall()
    result['notify_targets'] = [dict(t) for t in targets]
    return jsonify(result)


def _next_vuln_id(db, row_id):
    """基于自增 row_id 生成漏洞编号，无竞态条件"""
    year = datetime.now().year
    row = db.execute(
        "SELECT MAX(CAST(SUBSTR(vuln_id, 9) AS INTEGER)) as mx "
        "FROM vulnerabilities WHERE vuln_id LIKE ? AND vuln_id != '__tmp__'",
        [f"SF-{year}-%"]
    ).fetchone()
    n = max((row['mx'] or 0) + 1, row_id)
    return f"SF-{year}-{n:03d}"


@app.route('/api/vulns', methods=['POST'])
@view_required
def create_vuln():
    user = g.user
    if not user['perm_submit']:
        return jsonify({'error': '无提交权限'}), 403
    d     = request.json or {}
    title = cap(d.get('title', '').strip(), 300)
    sev   = validate_severity(d.get('severity', ''))
    comp  = cap(d.get('component', '').strip(), 300)
    desc  = cap(d.get('description', '').strip(), 10000)
    proj  = safe_int(d.get('project_id'))
    if not all([title, sev, comp, desc, proj]):
        return jsonify({'error': '请填写所有必填字段'}), 400
    if not _check_project_access(user, proj):
        return jsonify({'error': '无权向该项目提交漏洞'}), 403
    cvss = max(0.0, min(10.0, float(d.get('cvss', 0) or 0)))
    db   = get_db()
    # 先插入占位符拿到自增 id，再用 id 生成唯一编号回填
    # 彻底解决多进程竞态导致的 UNIQUE constraint 冲突
    cur  = db.execute("""
        INSERT INTO vulnerabilities
            (vuln_id,title,severity,cvss,project_id,assignee,component,description,
             poc,fix_suggestion,status,submitter_id,notify_on_close)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, ['__tmp__', title, sev, cvss, proj, cap(d.get('assignee'), 100),
          comp, desc, cap(d.get('poc'), 10000), cap(d.get('fix_suggestion'), 5000),
          '待修复', user['id'], 1 if d.get('notify_on_close') else 0])
    new_id = cur.lastrowid
    vid = _next_vuln_id(db, new_id)
    db.execute("UPDATE vulnerabilities SET vuln_id=? WHERE id=?", [vid, new_id])
    for src_id in d.get('notify_sources', []):
        sid = safe_int(src_id)
        if sid:
            try:
                db.execute("INSERT INTO vuln_notify_targets (vuln_id,notify_source_id) VALUES (?,?)",
                           [new_id, sid])
            except Exception:
                pass
    db.commit()
    if d.get('notify_sources'):
        snap = dict(db.execute("SELECT * FROM vulnerabilities WHERE id=?", [new_id]).fetchone())
        threading.Thread(target=send_notifications, args=(new_id, 'new', snap), daemon=True).start()
    return jsonify({'ok': True, 'id': new_id, 'vuln_id': vid})


@app.route('/api/vulns/<int:vid>', methods=['PUT'])
@view_required
def update_vuln(vid):
    user = g.user
    if not user['perm_edit'] and user['role'] != 'admin':
        return jsonify({'error': '无编辑权限'}), 403
    d    = request.json or {}
    db   = get_db()
    vuln = db.execute("SELECT * FROM vulnerabilities WHERE id=?", [vid]).fetchone()
    if not vuln:
        return jsonify({'error': '漏洞不存在'}), 404
    if not _check_project_access(user, vuln['project_id']):
        return jsonify({'error': '无权访问'}), 403

    old_status = vuln['status']
    new_status = validate_status(d.get('status', old_status)) or old_status
    now        = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    fixed_at   = vuln['fixed_at'] or (now if new_status == '已修复' else None)
    closed_at  = vuln['closed_at'] or (now if new_status == '已关闭' else None)
    sev  = validate_severity(d.get('severity', vuln['severity'])) or vuln['severity']
    cvss = max(0.0, min(10.0, float(d.get('cvss', vuln['cvss']) or 0)))

    db.execute("""
        UPDATE vulnerabilities SET title=?,severity=?,cvss=?,project_id=?,assignee=?,
            component=?,description=?,poc=?,fix_suggestion=?,status=?,
            updated_at=?,fixed_at=?,closed_at=?,notify_on_close=? WHERE id=?
    """, [cap(d.get('title', vuln['title']), 300), sev, cvss,
          safe_int(d.get('project_id', vuln['project_id'])),
          cap(d.get('assignee', vuln['assignee']), 100),
          cap(d.get('component', vuln['component']), 300),
          cap(d.get('description', vuln['description']), 10000),
          cap(d.get('poc', vuln['poc']), 10000),
          cap(d.get('fix_suggestion', vuln['fix_suggestion']), 5000),
          new_status, now, fixed_at, closed_at,
          1 if d.get('notify_on_close', vuln['notify_on_close']) else 0, vid])
    db.commit()

    if new_status == '已关闭' and old_status != '已关闭' and vuln['notify_on_close']:
        snap = dict(db.execute("SELECT * FROM vulnerabilities WHERE id=?", [vid]).fetchone())
        threading.Thread(target=send_close_notifications, args=(vid, snap), daemon=True).start()
    return jsonify({'ok': True})


@app.route('/api/vulns/<int:vid>', methods=['DELETE'])
@view_required
def delete_vuln(vid):
    user = g.user
    if not user['perm_delete'] and user['role'] != 'admin':
        return jsonify({'error': '无删除权限'}), 403
    db   = get_db()
    vuln = db.execute("SELECT project_id FROM vulnerabilities WHERE id=?", [vid]).fetchone()
    if not vuln:
        return jsonify({'error': '漏洞不存在'}), 404
    if not _check_project_access(user, vuln['project_id']):
        return jsonify({'error': '无权访问'}), 403
    db.execute("DELETE FROM vulnerabilities WHERE id=?", [vid])
    db.commit()
    return jsonify({'ok': True})


# ── DASHBOARD ──

@app.route('/api/dashboard')
@view_required
def dashboard():
    db, user = get_db(), g.user
    where, params = ["1=1"], []
    proj = safe_int(request.args.get('project', ''))
    if proj:
        where.append("project_id=?"); params.append(proj)
    ids = _user_project_ids(user)
    if ids:
        ph = ','.join('?' * len(ids))
        where.append(f"project_id IN ({ph})")
        params.extend(ids)
    w  = ' AND '.join(where)
    def cnt(extra=''):
        return db.execute(f"SELECT COUNT(*) as c FROM vulnerabilities WHERE {w}{extra}", params).fetchone()['c']
    total  = cnt()
    open_  = cnt(" AND status='待修复'")
    fixing = cnt(" AND status='修复中'")
    fixed  = cnt(" AND status='已修复'")
    closed = cnt(" AND status='已关闭'")
    sev_data = {s: db.execute(f"SELECT COUNT(*) as c FROM vulnerabilities WHERE severity=? AND {w}",
                               [s]+params).fetchone()['c'] for s in ['严重','高危','中危','低危']}
    # by_project must also respect user project access restriction
    proj_where = "p.is_active=1"
    proj_params_extra = []
    if ids:
        ph2 = ','.join('?' * len(ids))
        proj_where += f" AND p.id IN ({ph2})"
        proj_params_extra = list(ids)
    proj_rows = db.execute(f"""
        SELECT p.name,p.color,COUNT(v.id) as cnt FROM projects p
        LEFT JOIN vulnerabilities v ON v.project_id=p.id AND {w}
        WHERE {proj_where} GROUP BY p.id ORDER BY cnt DESC LIMIT 8
    """, params + proj_params_extra).fetchall()
    trend = []
    for i in range(7, -1, -1):
        d0 = (datetime.now()-timedelta(weeks=i)).strftime('%Y-%m-%d')
        d1 = (datetime.now()-timedelta(weeks=i-1)).strftime('%Y-%m-%d')
        c  = db.execute(f"SELECT COUNT(*) as c FROM vulnerabilities WHERE date(created_at)>=? AND date(created_at)<? AND {w}",
                         [d0,d1]+params).fetchone()['c']
        trend.append({'week': d0[:7], 'count': c})
    return jsonify({'total':total,'open':open_,'fixing':fixing,'fixed':fixed,'closed':closed,
                    'by_severity':sev_data,'by_project':[dict(r) for r in proj_rows],'trend':trend})


# ── USERS ──

@app.route('/api/users')
@admin_required
def list_users():
    db    = get_db()
    users = db.execute("SELECT * FROM users WHERE is_active=1 ORDER BY id").fetchall()
    result = []
    for u in users:
        access = db.execute("SELECT project_id FROM user_project_access WHERE user_id=?", [u['id']]).fetchall()
        d = fmt_user(dict(u))
        d['proj_access'] = [r['project_id'] for r in access]
        d['created_at']  = u['created_at']
        result.append(d)
    return jsonify(result)


@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    d  = request.json or {}
    un = cap(d.get('username', '').strip(), 64)
    em = cap(d.get('email', '').strip(), 200)
    pw = d.get('password', '123456')
    if not un or not em:
        return jsonify({'error': '用户名和邮箱不能为空'}), 400
    if not re.match(r'^[\w\-\.]{1,64}$', un):
        return jsonify({'error': '用户名格式不合法（只允许字母数字下划线中划线点）'}), 400
    if len(pw) > 128:
        return jsonify({'error': '密码过长'}), 400
    db = get_db()
    try:
        p = d.get('perms', {})
        cur = db.execute("""INSERT INTO users (username,email,password_hash,role,
            perm_view,perm_submit,perm_edit,perm_delete) VALUES (?,?,?,?,?,?,?,?)""",
            [un, em, _hash_pw(pw), validate_role(d.get('role','user')),
             1 if p.get('view',True) else 0, 1 if p.get('submit',True) else 0,
             1 if p.get('edit') else 0, 1 if p.get('delete') else 0])
        uid = cur.lastrowid
        for pid in d.get('proj_access', []):
            if safe_int(pid):
                db.execute("INSERT OR IGNORE INTO user_project_access (user_id,project_id) VALUES (?,?)",
                           [uid, safe_int(pid)])
        db.commit()
        return jsonify({'ok': True, 'id': uid})
    except sqlite3.IntegrityError:
        return jsonify({'error': '用户名或邮箱已存在'}), 409


@app.route('/api/users/<int:uid>', methods=['PUT'])
@admin_required
def update_user(uid):
    d     = request.json or {}
    db    = get_db()
    perms = d.get('perms', {})
    ups, vals = [], []
    if 'role' in d:
        ups.append('role=?'); vals.append(validate_role(d['role']))
    if perms:
        ups.append('perm_view=?,perm_submit=?,perm_edit=?,perm_delete=?')
        vals.extend([1 if perms.get('view') else 0, 1 if perms.get('submit') else 0,
                     1 if perms.get('edit') else 0, 1 if perms.get('delete') else 0])
    if d.get('password'):
        pw = d['password']
        if len(pw) > 128:
            return jsonify({'error': '密码过长'}), 400
        ups.append('password_hash=?'); vals.append(_hash_pw(pw))
    if ups:
        vals.append(uid)
        db.execute(f"UPDATE users SET {', '.join(ups)} WHERE id=?", vals)
    if 'proj_access' in d:
        db.execute("DELETE FROM user_project_access WHERE user_id=?", [uid])
        for pid in d['proj_access']:
            if safe_int(pid):
                db.execute("INSERT OR IGNORE INTO user_project_access (user_id,project_id) VALUES (?,?)",
                           [uid, safe_int(pid)])
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/users/<int:uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid == g.user['id']:
        return jsonify({'error': '不能删除当前登录用户'}), 400
    db = get_db()
    db.execute("UPDATE users SET is_active=0 WHERE id=?", [uid])
    db.execute("DELETE FROM sessions WHERE user_id=?", [uid])
    db.commit()
    return jsonify({'ok': True})


# ── NOTIFY SOURCES ──

@app.route('/api/notify-sources')
@login_required
def list_notify_sources():
    rows = get_db().execute("SELECT * FROM notify_sources ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/notify-sources', methods=['POST'])
@admin_required
def create_notify_source():
    d     = request.json or {}
    name  = cap(d.get('name', '').strip(), 100)
    value = cap(d.get('value', '').strip(), 2000)
    ntype = d.get('type', 'feishu')
    if ntype not in ('feishu', 'email'):
        return jsonify({'error': '类型无效'}), 400
    if not name or not value:
        return jsonify({'error': '名称和地址不能为空'}), 400
    db  = get_db()
    cur = db.execute("INSERT INTO notify_sources (name,type,value,note) VALUES (?,?,?,?)",
                     [name, ntype, value, cap(d.get('note', ''), 500)])
    db.commit()
    return jsonify({'ok': True, 'id': cur.lastrowid})


@app.route('/api/notify-sources/<int:nid>', methods=['PUT'])
@admin_required
def update_notify_source(nid):
    d  = request.json or {}
    db = get_db()
    db.execute("UPDATE notify_sources SET name=?,value=?,note=?,enabled=? WHERE id=?",
               [cap(d.get('name'), 100), cap(d.get('value'), 2000),
                cap(d.get('note', ''), 500), 1 if d.get('enabled', True) else 0, nid])
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/notify-sources/<int:nid>', methods=['DELETE'])
@admin_required
def delete_notify_source(nid):
    db = get_db()
    db.execute("DELETE FROM notify_sources WHERE id=?", [nid])
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/notify-sources/<int:nid>/test', methods=['POST'])
@admin_required
def test_notify_source(nid):
    src = get_db().execute("SELECT * FROM notify_sources WHERE id=?", [nid]).fetchone()
    if not src:
        return jsonify({'error': '通知源不存在'}), 404
    src = dict(src)
    try:
        if src['type'] == 'feishu':
            _send_feishu_card(src['value'], '🔔 Sjzy_Friday 测试通知',
                              '这是一条测试消息，连接正常！', {}, vuln_link=None)
        return jsonify({'ok': True, 'message': '测试通知已发送'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════ 通知逻辑 ══════════

def _send_feishu_card(webhook_url, title, content, vuln_data, vuln_link=None):
    colors  = {'严重':'red','高危':'orange','中危':'yellow','低危':'green'}
    color   = colors.get(vuln_data.get('severity', ''), 'blue')
    elems   = [{"tag":"div","text":{"content":content,"tag":"lark_md"}}]
    if vuln_link:
        elems.append({"tag":"action","actions":[{
            "tag":"button",
            "text":{"tag":"plain_text","content":"🔗 查看漏洞详情（点击飞书授权登录）"},
            "type":"primary","url": vuln_link
        }]})
    elems += [{"tag":"hr"},{"tag":"note","elements":[{"tag":"plain_text","content":"Sjzy_Friday · 漏洞管理平台"}]}]
    msg  = {"msg_type":"interactive","card":{
        "config":{"wide_screen_mode":True},
        "header":{"title":{"content":title,"tag":"plain_text"},"template":color},
        "elements":elems
    }}
    body = json.dumps(msg, ensure_ascii=False).encode('utf-8')
    req  = urllib.request.Request(webhook_url, data=body,
                                  headers={'Content-Type':'application/json; charset=utf-8'})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read()


def _vuln_link(vuln_db_id):
    """生成飞书 OAuth 跳转链接"""
    if not FEISHU_APP_ID:
        return f"{SITE_URL}/?vuln_id={vuln_db_id}"
    state = secrets.token_urlsafe(24)
    with app.app_context():
        db = get_db()
        db.execute("INSERT OR REPLACE INTO feishu_oauth_state (state,redirect_vuln_id) VALUES (?,?)",
                   [state, vuln_db_id])
        db.commit()
    redir = urllib.parse.quote(f"{SITE_URL}/api/auth/feishu/callback", safe='')
    return (f"https://open.feishu.cn/open-apis/authen/v1/authorize"
            f"?app_id={FEISHU_APP_ID}&redirect_uri={redir}&state={state}"
            f"&scope=contact:user.base:readonly")


def send_notifications(vuln_id, event_type, vuln):
    with app.app_context():
        db      = get_db()
        targets = db.execute("""
            SELECT ns.* FROM vuln_notify_targets vnt
            JOIN notify_sources ns ON ns.id=vnt.notify_source_id
            WHERE vnt.vuln_id=? AND ns.enabled=1
        """, [vuln_id]).fetchall()
        v       = vuln if isinstance(vuln, dict) else dict(vuln)
        title   = f"{'🆕 新漏洞' if event_type=='new' else '✅ 漏洞关闭'} · {v.get('title','')}"
        content = (
            f"**{'🆕 新漏洞发现' if event_type=='new' else '✅ 漏洞已关闭'}**\n\n"
            f"**标题：** {v.get('title','')}\n"
            f"**漏洞ID：** {v.get('vuln_id','')}\n"
            f"**严重级别：** {v.get('severity','')}\n"
            f"**CVSS：** {v.get('cvss',0)}\n"
            f"**状态：** {v.get('status','')}\n"
            f"**影响组件：** {v.get('component','')}\n"
            f"**责任人：** {v.get('assignee','未分配')}\n"
        )
        link = _vuln_link(vuln_id)
        for t in [dict(x) for x in targets]:
            try:
                if t['type'] == 'feishu':
                    _send_feishu_card(t['value'], title, content, v, vuln_link=link)
                    print(f"[Feishu] ✓ {t['name']}")
                elif t['type'] == 'email':
                    html = content.replace('\n','<br>') + f'<br><br><a href="{link}">点击查看漏洞详情</a>'
                    _send_email(t['value'], title, html)
                    print(f"[Email] ✓ {t['value']}")
            except Exception as e:
                print(f"[Notify] ✗ {t['name']}: {e}")


def send_close_notifications(vuln_id, vuln):
    send_notifications(vuln_id, 'close', vuln)


def _send_email(to, subject, html):
    host  = os.environ.get('SMTP_HOST', '')
    port  = int(os.environ.get('SMTP_PORT', 465))
    user  = os.environ.get('SMTP_USER', '')
    pw    = os.environ.get('SMTP_PASS', '')
    frm   = os.environ.get('SMTP_FROM', user)
    if not host or not user:
        print(f"[Email] SMTP未配置，跳过: {to}"); return
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = frm
    msg['To']      = to
    msg.attach(MIMEText(html, 'html', 'utf-8'))
    with smtplib.SMTP_SSL(host, port) as s:
        s.login(user, pw)
        s.sendmail(frm, [to], msg.as_string())


# Gunicorn 入口：init_db 在模块加载时执行
init_db()

if __name__ == '__main__':
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    print(f"\n🚀 Sjzy_Friday 漏洞管理平台（开发模式）")
    print(f"   访问地址: http://0.0.0.0:{port}")
    print(f"   默认账号: admin / admin123")
    print(f"   飞书登录: {'已启用 ('+FEISHU_APP_ID+')' if FEISHU_APP_ID else '未配置'}")
    print(f"   生产环境请使用: gunicorn -w 4 -b 0.0.0.0:{port} app:app\n")
    app.run(host='0.0.0.0', port=port, debug=debug)
