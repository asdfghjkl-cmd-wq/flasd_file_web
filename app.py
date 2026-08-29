"""
文件上传服务 - 共享盘/个人盘文件管理(安全加固版,模块化拆分后组装入口)

空间模型:
- 共享盘(默认): UPLOAD_DIR,所有登录用户共享(原行为)。
- 个人盘:        BASE_DIR/private/<用户名>/,仅本人可访问(admin 不受限)。
- URL 区分: 以 /p 开头的路径走个人盘(如 /p/api/files),其余走共享盘;
  页面提供「共享盘/个人盘」切换入口,前端请求自动加 /p 前缀。

模块结构(拆分):
- app_state.py   配置常量、Redis 连接、用户数据层、任务队列系统(全局状态唯一持有者)
- app_paths.py   路径安全/元数据/个人盘工具
- app_tools.py   分割/合成/解压/URL 下载工具
- app_auth.py    认证装饰器、登录/找回/重置路由、邮件
- app_routes.py  文件/任务/tus/分享/回收站等业务路由(register_routes)
- app_admin.py   管理控制台 socket 服务
- app.py         本文件:组装入口(创建 app、中间件、首页、启动逻辑)

主要加固:
1. 用户数据隔离:个人盘按用户名分目录,路径解析强制限定在各自盘根内。
2. 管理控制台:静态 RSA 密钥、握手/认证按源 IP 限流、update/download 传输
   端口增加一次性 token 认证,debug 的 get 命令改为白名单变量。
3. SSRF:解析后固定 IP 直连(防 DNS 重绑定绕过),每跳重定向重新校验。
4. 修复:loginok 管理员标志、call_ze 空 JSON 500、保留目录名越权、
   download 无大小上限、全局用户字典并发读写等。

注意:文件分割(TOOL_CUT/TOOL_ASSEMBLY)属于文件处理工具,并非 HTTP 分卷上传;
大文件 HTTP 断点续传未实现,前端大文件上传请走 tus(/api/tus)。
"""
import os
import sys
import locale
import logging
import secrets
import socket
import atexit
import time
import threading
from string import ascii_letters
from logging.handlers import RotatingFileHandler

from flask import Flask, request, session, redirect, url_for, jsonify
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, CSRFError
import filelock

import app_state as st
from app_state import _user_lock, users, save_user   # noqa: F401  # 确保状态模块先加载

# 防止本文件被二次加载:python app.py 时本模块名为 __main__,
# 而 worker/管理控制台里的 `from app import app` 会以 'app' 名再次加载本文件,
# 导致模块级代码(含启动日志/路由注册)重复执行。提前注册别名让 import 命中缓存。
import sys as _sys
if not _sys.modules.get('app'):
    _sys.modules['app'] = _sys.modules[__name__]

from app_auth import register_auth, login_required
from app_routes import register_routes
from app_admin import is_port_in_use, w


# ==================== 日志 ====================
# 日志文件(不再在启动时截断,保留历史日志;带轮转防止无限增长)
LOG_FILE = os.path.join(st.BASE_DIR, "app.log")
_LOG_FORMATTER = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_log_level = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)
_root_logger = logging.getLogger()
_root_logger.setLevel(_log_level)
for _h in list(_root_logger.handlers):
    _root_logger.removeHandler(_h)
_fh = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
_fh.setFormatter(_LOG_FORMATTER)
_root_logger.addHandler(_fh)
_sh = logging.StreamHandler()
_sh.setFormatter(_LOG_FORMATTER)
_root_logger.addHandler(_sh)


# ==================== 密钥 ====================
def ran_str(length, charset=ascii_letters):
    # secrets 为密码学安全随机;random 可预测,被采样后可能推演出 SECRET_KEY
    return ''.join(secrets.choice(charset) for _ in range(length))

try:
    with open(os.path.join(st.BASE_DIR, "s.key"), "r", encoding="utf-8") as s:
        k = s.read()
except (OSError, UnicodeDecodeError):
    k = ran_str(128)
    with open(os.path.join(st.BASE_DIR, "s.key"), "w", encoding="utf-8") as s:
        s.write(k)


# ==================== Flask 应用 ====================
app = Flask(__name__)
# 额外允许的来源(逗号分隔,如部署到其它域名)
_extra_origins = [o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '').split(',') if o.strip()]
CORS(app, resources={
    r"/*": {
        # 只用精确域名:通配子域 + SameSite=Lax + credentials 会让任一子域 XSS 即可劫持会话
        "origins": [
            "http://127.0.0.1:5000",
            "https://127.0.0.1:5000",
            "https://www.goodlink.website",
            "https://goodlink.website",
        ] + _extra_origins
    }
}, supports_credentials=True)
app.config.update(
    MAX_CONTENT_LENGTH=1024 * 1024 * 1024,
    UPLOAD_FOLDER=st.UPLOAD_DIR,
    SECRET_KEY=os.environ.get('SECRET_KEY', k),
    JSON_AS_ASCII=False, SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_HTTPONLY=True
)
# 显式设置 SESSION_COOKIE_SECURE 优先;未设置时按部署方式推断(模块导入=生产,gunicorn/uwsgi)
_secure_cookie_env = os.environ.get('SESSION_COOKIE_SECURE')
if _secure_cookie_env is not None:
    app.config['SESSION_COOKIE_SECURE'] = _secure_cookie_env == '1'
elif __name__ != '__main__':
    app.config['SESSION_COOKIE_SECURE'] = True

# 新版 Flask 用 app.json.ensure_ascii，旧版用 JSON_AS_ASCII
try:
    app.json.ensure_ascii = False
except AttributeError:
    pass

csrf = CSRFProtect(app)


class ScopePrefixMiddleware:
    """WSGI 层 URL 前缀改写:把 /p 开头的路径剥掉 /p 前缀并标记个人盘 scope,
    使所有现有路由自动同时服务于共享盘(/ )与个人盘(/p)。"""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '')
        if path == st.PERSONAL_URL_PREFIX or path.startswith(st.PERSONAL_URL_PREFIX + '/'):
            environ['PATH_INFO'] = path[len(st.PERSONAL_URL_PREFIX):] or '/'
            environ['dsh.scope'] = 'personal'
        else:
            environ['dsh.scope'] = 'shared'
        return self.wsgi_app(environ, start_response)


app.wsgi_app = ScopePrefixMiddleware(app.wsgi_app)


# 反向代理场景:X-Forwarded-Proto/Host/For 需要可信代理才生效(与 TRUSTED_PROXIES 配合)
_proxy_count = st._env_int('PROXY_COUNT', 0)
if _proxy_count > 0:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_count, x_proto=_proxy_count, x_host=_proxy_count)
    logging.info(f"ProxyFix 已启用(代理层数={_proxy_count})")

@app.before_request
def _set_scope():
    from flask import g
    g.scope = request.environ.get('dsh.scope', 'shared')

logging.info("flask create ok")


# ==================== 全局 HTML 模板 ====================
HTML_FILE = os.path.join(st.BASE_DIR, 'a.html')
HTML_TEMPLATE = ""

def load_html():
    global HTML_TEMPLATE
    try:
        with open(HTML_FILE, "r", encoding="utf-8") as f:
            HTML_TEMPLATE = f.read()
    except Exception as e:
        logging.warning(f"无法加载模板 {HTML_FILE}: {e}")
        HTML_TEMPLATE = "<h1>模板加载失败，请联系管理员</h1>"

load_html()
logging.info("html load ok")

# 后台线程:模板热重载
def background_tasks():
    global HTML_TEMPLATE
    while True:
        time.sleep(300)
        try:
            with open(HTML_FILE, "r", encoding="utf-8") as f:
                new_tpl = f.read()
            if HTML_TEMPLATE != new_tpl:
                # 仅更新原始模板;调试链接由 index() 渲染期追加,避免反复拼接
                HTML_TEMPLATE = new_tpl
                logging.info("模板已热重载")
        except Exception as e:
            logging.warning(f"模板重载异常: {e}")
if not app.debug:
    bg_thread = threading.Thread(target=background_tasks, daemon=True)
    bg_thread.start()


# ==================== 首页 ====================
_index_template_cache = [None, None]   # [tpl, compiled]:单槽缓存,模板变更时替换而非累积

def _index_template():
    """编译并缓存首页模板(避免每个请求重新解析 Jinja;单槽防泄漏)。"""
    tpl = HTML_TEMPLATE
    if app.debug:
        # 调试链接在渲染期追加,避免热重载时反复拼接
        tpl += "<br/>\n<a href=\"/api/new\">new</a>"
    if _index_template_cache[0] != tpl:
        _index_template_cache[0] = tpl
        _index_template_cache[1] = app.jinja_env.from_string(tpl)
    return _index_template_cache[1]

@app.route('/')
@login_required
def index():
    return _index_template().render(username=session.get('user_id', ''))

@app.route("/api/new")
def reload_template():
    if app.debug:
        try:
            load_html()
            logging.info("模板已热重载")
        except Exception as e:
            logging.warning(f"模板重载异常: {e}")
    return redirect("/")


# ==================== 全局错误处理 / 健康检查 / 安全头 ====================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Not found'}), 404
    return "not found<br><a href=\"/\"></a>"

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({'success': False, 'error': 'CSRF验证失败'}), 400

@app.route('/healthz')
def healthz():
    """存活探针(免认证):Redis 可用即视为健康,供负载均衡/监控使用。"""
    try:
        st.r.ping()
        return 'ok', 200
    except Exception as e:
        logging.error(f"healthz 失败: {e}")
        return 'redis down', 503

@app.errorhandler(413)
def handle_too_large(e):
    return jsonify({'success': False, 'error': '请求体超过大小限制'}), 413

@app.after_request
def _security_headers(resp):
    """统一安全响应头;HSTS 建议由反代层配置。"""
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    resp.headers.setdefault('X-XSS-Protection', '0')
    return resp


# ==================== 注册业务路由 ====================
register_auth(app)
register_routes(app, csrf)
logging.info("routes registered ok")


# ==================== 启动逻辑 ====================
if sys.platform.startswith('win'):
    # 只原地调整编码,不要用 sys.stdout = io.TextIOWrapper(...) 重新包装:
    # 旧对象失去引用被 GC 时会关闭底层 buffer,导致 click 打印启动 banner 时
    # fileno() 抛 "I/O operation on closed file"。
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    try:
        locale.setlocale(locale.LC_ALL, 'zh_CN.UTF-8')
    except Exception:
        pass

lock = filelock.SoftFileLock('.admin_lock')


def _start_admin_server():
    """挑选管理端口并启动控制台监听线程(返回端口)。"""
    min_p = st._env_int('ADMIN_PORT_MIN', 6000)
    max_p = st._env_int('ADMIN_PORT_MAX', 6050)
    while True:
        sm = secrets.randbelow(max_p - min_p + 1) + min_p
        if not is_port_in_use(sm):
            break
    st.r.set('man_port', sm)
    logging.info(f"管理端口链接:{socket.gethostbyname(socket.gethostname())}:{sm}")
    s = threading.Thread(target=w, daemon=True, args=(sm, lock))
    s.start()
    return sm


if __name__ == '__main__':
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = st._env_int('PORT', 5000)
    logging.info(f"🌐 启动: http://{HOST}:{PORT} (本机访问 http://{socket.gethostbyname(socket.gethostname())}:{PORT})")
    # 仅当显式允许（ALLOW_DE_LOCK=1）时才由 de.lock 文件开启 debug，
    # 避免残留文件意外打开 get/cr 等调试命令的攻击面
    if os.environ.get('ALLOW_DE_LOCK', '0') == '1' and os.path.exists(os.path.join(st.BASE_DIR, "de.lock")):
        app.debug = True  # 调试链接由 index() 渲染期追加
    _start_admin_server()
    app.run(HOST, PORT, use_reloader=False, use_evalex=False)
else:
    try:
        # 本 worker 抢到了锁，负责启动管理端口
        lock.acquire(timeout=1)
        _start_admin_server()
        atexit.register(lock.release)
    except filelock.Timeout as e:
        logging.info('管理端口已被其它 worker 占用,跳过')
