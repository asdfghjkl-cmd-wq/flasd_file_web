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
- app.py         本文件:create_app 工厂(配置/中间件/错误处理/路由注册)+ 启动逻辑

主要加固:
1. 用户数据隔离:个人盘按用户名分目录,路径解析强制限定在各自盘根内。
2. 管理控制台:静态 RSA 密钥、握手/认证按源 IP 限流、update/download 传输
   端口增加一次性 token 认证,debug 的 get 命令改为白名单变量。
3. SSRF:解析后固定 IP 直连(防 DNS 重绑定绕过),每跳重定向重新校验。
4. 修复:loginok 管理员标志、call_ze 空 JSON 500、保留目录名越权、
   download 无大小上限、全局用户字典并发读写等。

最近变更(按代码审查意见重构):
- create_app 工厂化:配置/CORS/CSRF/中间件/错误处理/安全头/路由注册集中一处,
  测试可传 config 获得隔离实例;app_admin 延迟取 app/load_html 引用经
  app_state 注册表(st.get_app()/st.get_load_html()),不再使用 sys.modules 别名 hack。
- SESSION_COOKIE_SECURE 改为显式 env 开关(测试可经 config 覆盖),不再按 __name__ 推断部署方式。
- 密钥文件原子创建(O_EXCL 防多进程并发生成不同 key),并收紧文件权限。
- 管理端口锁锚定 BASE_DIR 并改用 FileLock(进程崩溃后 OS 自动释放,不会残留死锁);
  __main__ 与 gunicorn worker 统一走同一套抢锁流程。
- 新增 /readyz(Redis + 上传目录可写),/healthz 保持原语义兼容现有监控。
- 新增 500 的 JSON 处理与请求日志(request_id + 方法 + 路径 + 状态码 + 耗时)。
- 模板热重载改为请求时惰性 mtime 检测(替代每 worker 一个 5 分钟轮询线程,
  多 worker 下模板更新天然最终一致)。
- 新增 CSP / Permissions-Policy 响应头;MAX_CONTENT_LENGTH 支持 env 调整。
- /api/new 改名 /api/reload-template(旧路径 302 兼容);404 文案修复。

最近变更(第二轮代码审查意见落地):
- 日志配置收敛为幂等 setup_logging():只管理自己添加的 handler,不再清空宿主进程
  root logger 的既有 handler,避免 import 副作用破坏测试/工具进程。
- 会话密钥创建失败改为 fail-fast(不再静默降级为临时随机密钥,杜绝多 worker 各自
  不同密钥导致会话随机失效且难排查的问题)。
- create_app 的 config 参数提前到 CORS/CSRF 初始化之前应用:测试可覆盖
  ALLOWED_ORIGINS、WTF_CSRF_ENABLED、SESSION_COOKIE_SECURE 等启动期生效配置。
- MAX_CONTENT_LENGTH 默认 1GB -> 256MB(非分片大请求是磁盘/内存消耗面,大文件应走 tus)。
- 500 日志与 JSON 错误响应携带 request_id,便于与请求日志串联排查。
- /api/ 响应增加 Cache-Control: no-store(文件下载走 /download/、/share/,不受影响)。
- 管理端口信息 man_port TTL 1 天 -> 10 分钟,退出时删除本进程写入的值,端口耗尽时
  清除旧值;管理端口启动收敛为 maybe_start_admin_console() 显式入口,
  支持 START_ADMIN_CONSOLE=0 关闭 import 副作用。
- HOST 默认 127.0.0.1(公网部署需显式设置 HOST=0.0.0.0)。

最近变更(第三轮代码审查意见落地):
- 移除 sys.modules['app'] 别名 hack,改由 app_state 注册表持有 app/load_html 引用
  (python app.py 直跑与 gunicorn 导入两条路径均可用,且不再依赖模块加载顺序)。
- 模板编译缓存挂到 current_app.extensions(按实例隔离,测试隔离实例不再与全局
  实例串扰);_index_template/reload_template 改用 current_app.debug;模板热重载
  的 mtime 检查-更新加锁。
- 请求日志增加 scope 字段(区分共享盘/个人盘);500 非 API 响应携带 request_id。
- CORS 默认仅放行本机地址,生产域名统一走 ALLOWED_ORIGINS 环境变量。
- 日志统一 lazy 格式化;本机 IP 获取失败回退回环地址;
  ADMIN_PORT_MIN/MAX 配置非法时显式拒绝;atexit 释放锁前检查持有状态。

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
import uuid
from string import ascii_letters
from logging.handlers import RotatingFileHandler

from flask import Flask, request, session, redirect, jsonify, g, current_app
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, CSRFError
import filelock

import app_state as st
from app_state import _user_lock, users, save_user   # noqa: F401  # 确保状态模块先加载

# 注:app_admin 需要延迟取 app/load_html 引用时,一律经 app_state 注册表
# (st.get_app()/st.get_load_html())获取,不再使用旧的 sys.modules 别名 hack:
# 该 hack 依赖"app.py 是第一个被加载的文件",且 python app.py 直跑(__main__)时
# `from app import app` 会把本文件二次加载,产生第二个实例并重复执行模块级副作用
# (详见 app_state.py 注册表注释)。

from app_auth import register_auth, login_required
from app_routes import register_routes
from app_admin import is_port_in_use, w as start_admin_console


# ==================== 日志 ====================
# 日志文件(不再在启动时截断,保留历史日志;带轮转防止无限增长)
LOG_FILE = os.path.join(st.BASE_DIR, "app.log")
_LOG_FORMATTER = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# 用 handler 上的标记属性识别"本模块添加的 handler",重复调用 setup_logging 时只移除自己的,
# 不再无差别清空宿主进程(如测试框架/其它工具)已有的 root logger handler。
_LOG_HANDLER_TAG = "dsh_app_log"


def setup_logging():
    """配置 root logger:级别 + 轮转文件 + 控制台;重复调用幂等,不干扰既有 handler。"""
    level = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        if getattr(h, _LOG_HANDLER_TAG, False):
            root.removeHandler(h)
    # 多进程(如 gunicorn 多 worker)共写同一文件时,轮转存在竞态(可接受,业界常见);
    # 如需严格轮转,可换 concurrent-log-handler 的 ConcurrentRotatingFileHandler(需新依赖)。
    fh = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(_LOG_FORMATTER)
    setattr(fh, _LOG_HANDLER_TAG, True)
    root.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(_LOG_FORMATTER)
    setattr(sh, _LOG_HANDLER_TAG, True)
    root.addHandler(sh)
    return root


setup_logging()


# ==================== 密钥 ====================
def ran_str(length, charset=ascii_letters):
    # secrets 为密码学安全随机;random 可预测,被采样后可能推演出 SECRET_KEY
    return ''.join(secrets.choice(charset) for _ in range(length))


SECRET_KEY_FILE = os.path.join(st.BASE_DIR, "s.key")


def _load_or_create_secret_key():
    """读取会话密钥;不存在时原子创建并收紧权限。

    O_EXCL 原子创建保证多进程首次同时启动时只有一个成功写入,
    其余进程重读同一份 key(避免各进程各自生成、互相覆盖导致重启后会话全部失效)。
    """
    def _read():
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if not key:
                raise OSError("密钥文件为空")
            return key

    try:
        return _read()
    except FileNotFoundError:
        pass
    except OSError as e:
        logging.warning("读取密钥文件失败,将重新生成: %s", e)

    try:
        fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # Windows 忽略权限位
        key = ran_str(128)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key)
        return key
    except FileExistsError:
        # 其它进程已抢先创建;短暂重试等待其写入完成
        for _ in range(5):
            try:
                return _read()
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(
            f"并发创建密钥后重读仍失败({SECRET_KEY_FILE});请检查文件状态与权限后重启"
        ) from None
    except OSError as e:
        # fail-fast:密钥无法落盘时若改用临时随机密钥,多 worker 下每个进程密钥不同,
        # 会话会在 worker 间随机失效且极难排查;直接暴露错误让启动失败,由部署方修复。
        raise RuntimeError(
            f"无法创建/读取会话密钥文件 {SECRET_KEY_FILE}: {e};"
            "请检查目录权限与磁盘状态后重启"
        ) from e


SECRET_KEY = _load_or_create_secret_key()


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


# ==================== 全局 HTML 模板 ====================
HTML_FILE = os.path.join(st.BASE_DIR, 'a.html')
HTML_TEMPLATE = ""
_tpl_mtime = [0.0]   # [mtime]:上次加载模板时的文件修改时间(惰性热重载)
_tpl_lock = threading.Lock()   # 保护 _tpl_mtime/HTML_TEMPLATE 的检查-更新(多线程热重载)


def load_html():
    global HTML_TEMPLATE
    try:
        with open(HTML_FILE, "r", encoding="utf-8") as f:
            HTML_TEMPLATE = f.read()
        try:
            _tpl_mtime[0] = os.path.getmtime(HTML_FILE)
        except OSError:
            pass
    except Exception as e:
        logging.warning("无法加载模板 %s: %s", HTML_FILE, e)
        HTML_TEMPLATE = "<h1>模板加载失败，请联系管理员</h1>"


def _get_html_template():
    """惰性热重载:请求期按文件 mtime 变化重读模板(每次仅一次 stat,开销极小)。

    替代原"每 worker 一个 5 分钟后台轮询线程":多 worker 各自惰性检测,
    模板更新天然最终一致,且不再浪费线程;文件缺失时回退到当前缓存。
    """
    global HTML_TEMPLATE
    with _tpl_lock:
        try:
            mtime = os.path.getmtime(HTML_FILE)
        except OSError:
            return HTML_TEMPLATE
        if mtime != _tpl_mtime[0]:
            _tpl_mtime[0] = mtime
            try:
                with open(HTML_FILE, "r", encoding="utf-8") as f:
                    HTML_TEMPLATE = f.read()
                logging.info("模板已热重载(mtime=%s)", mtime)
            except OSError as e:
                logging.warning("模板重载异常: %s", e)
    return HTML_TEMPLATE


load_html()
logging.info("html load ok")


def _index_template():
    """编译并缓存首页模板;缓存挂在 current_app.extensions 上,按实例隔离。

    避免模块级单槽缓存被多个 Flask 实例(如测试隔离实例)串扰;
    调试链接在渲染期追加,避免热重载时反复拼接。
    """
    tpl = _get_html_template()
    if current_app.debug:
        tpl += "<br/>\n<a href=\"/api/reload-template\">reload</a>"
    cache = current_app.extensions.setdefault('tpl_index_cache', [None, None])  # [tpl, compiled]
    if cache[0] != tpl:
        cache[0] = tpl
        cache[1] = current_app.jinja_env.from_string(tpl)
    return cache[1]


# ==================== Flask 应用工厂 ====================
def create_app(config=None):
    """应用工厂:组装 Flask 实例(配置/CORS/CSRF/中间件/错误处理/安全头/路由注册)。

    模块级 `app = create_app()` 供 gunicorn(`app:app`)与各模块延迟导入使用;
    测试可传 config(dict)覆盖默认配置,获得隔离实例。
    """
    app = Flask(__name__)
    # 基础配置(config 参数优先,便于测试覆盖启动期生效的项)
    app.config.update(
        # 请求体上限按 env 可调(默认 256MB);大文件请走 tus 分片上传(见 app_routes.py),
        # 过大的非分片请求体是磁盘/内存消耗面,不宜默认放到 GB 级。
        MAX_CONTENT_LENGTH=st._env_int('MAX_CONTENT_LENGTH_MB', 256) * 1024 * 1024,
        UPLOAD_FOLDER=st.UPLOAD_DIR,
        SECRET_KEY=os.environ.get('SECRET_KEY', SECRET_KEY),
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_HTTPONLY=True,
        # CORS 额外允许的来源(逗号分隔,如部署到其它域名);config 可覆盖
        ALLOWED_ORIGINS=os.environ.get('ALLOWED_ORIGINS', ''),
    )
    if config:
        # 必须在 CORS/CSRF 初始化之前应用:这些配置在启动期读取
        # (如 WTF_CSRF_ENABLED、ALLOWED_ORIGINS),晚于此时点传入不生效。
        app.config.update(config)
    # SESSION_COOKIE_SECURE:默认开关是显式 env(SESSION_COOKIE_SECURE=1),
    # 测试可通过 config 显式传入覆盖;不再按 __name__ 推断部署方式——那依赖启动路径、
    # 行为不可预期(如 gunicorn 本地 http 调试时 Secure cookie 会被浏览器拒发,导致登录失效)。
    if 'SESSION_COOKIE_SECURE' not in app.config:
        env_val = os.environ.get('SESSION_COOKIE_SECURE')
        if env_val is None:
            logging.warning("未设置 SESSION_COOKIE_SECURE:生产 HTTPS 部署请显式设置 "
                            "SESSION_COOKIE_SECURE=1,否则会话 cookie 将以明文传输")
            app.config['SESSION_COOKIE_SECURE'] = False
        else:
            app.config['SESSION_COOKIE_SECURE'] = env_val == '1'
    # CORS:只用精确域名(通配子域 + SameSite=Lax + credentials 会让任一子域 XSS 即可劫持会话)。
    # 默认仅放行本机地址;部署到其它域名时通过 ALLOWED_ORIGINS 环境变量配置
    # (逗号分隔,如 ALLOWED_ORIGINS=https://a.example.com,https://b.example.com)。
    _extra_origins = [o.strip() for o in str(app.config.get('ALLOWED_ORIGINS', '')).split(',') if o.strip()]
    CORS(app, resources={
        r"/*": {
            "origins": [
                "http://127.0.0.1:5000",
                "https://127.0.0.1:5000",
            ] + _extra_origins
        }
    }, supports_credentials=True)

    # 新版 Flask 用 app.json.ensure_ascii，旧版用 JSON_AS_ASCII(旧配置项已废弃,不再设置)
    try:
        app.json.ensure_ascii = False
    except AttributeError:
        pass

    csrf = CSRFProtect(app)

    app.wsgi_app = ScopePrefixMiddleware(app.wsgi_app)

    # 反向代理场景:X-Forwarded-Proto/Host/For 需要可信代理才生效(与 TRUSTED_PROXIES 配合)
    _proxy_count = st._env_int('PROXY_COUNT', 0)
    if _proxy_count > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_count, x_proto=_proxy_count, x_host=_proxy_count)
        logging.info("ProxyFix 已启用(代理层数=%s)", _proxy_count)

    @app.before_request
    def _before_request():
        g.scope = request.environ.get('dsh.scope', 'shared')
        g.request_id = uuid.uuid4().hex[:12]
        g.request_start = time.perf_counter()

    # ============ 首页 ============
    @app.route('/')
    @login_required
    def index():
        return _index_template().render(username=session.get('user_id', ''))

    @app.route("/api/reload-template")
    @login_required
    def reload_template():
        if current_app.debug:
            try:
                load_html()
                logging.info("模板已热重载")
            except Exception as e:
                logging.warning("模板重载异常: %s", e)
        return redirect("/")

    # 兼容旧路径(原 /api/new)
    @app.route("/api/new")
    def _legacy_reload_template():
        return redirect("/api/reload-template")

    # ============ 全局错误处理 / 健康检查 / 安全头 ============

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'success': False, 'error': 'Not found'}), 404
        return "页面不存在", 404

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return jsonify({'success': False, 'error': 'CSRF验证失败'}), 400

    @app.errorhandler(413)
    def handle_too_large(e):
        return jsonify({'success': False, 'error': '请求体超过大小限制'}), 413

    @app.errorhandler(500)
    def handle_500(e):
        orig = getattr(e, 'original_exception', None) or e
        rid = getattr(g, 'request_id', '-')
        # 优先记录原始异常(HTTPException 包装场景保留其 traceback),并带 request_id 便于与请求日志串联
        tb = getattr(orig, '__traceback__', None)
        if tb is not None:
            logging.error("未处理异常 request_id=%s: %r", rid, orig,
                          exc_info=(type(orig), orig, tb))
        else:
            logging.error("未处理异常 request_id=%s: %r", rid, orig, exc_info=True)
        if request.path.startswith('/api/'):
            return jsonify({'success': False, 'error': '服务器内部错误',
                            'request_id': rid}), 500
        # 非 API 页面也暴露 request_id,便于用户带着它报障
        return f"服务器内部错误(请求ID:{rid})", 500

    @app.route('/healthz')
    def healthz():
        """存活+Redis 探针(免认证):保持原语义,兼容现有负载均衡/监控配置。"""
        try:
            st.r.ping()
            return 'ok', 200
        except Exception as e:
            logging.error("healthz 失败: %s", e)
            return 'redis down', 503

    @app.route('/readyz')
    def readyz():
        """就绪探针(免认证):Redis 可用且上传目录可写才算就绪,供更严格的上线/摘流判断。"""
        try:
            st.r.ping()
        except Exception as e:
            logging.error("readyz redis 失败: %s", e)
            return 'redis down', 503
        try:
            probe = os.path.join(st.UPLOAD_DIR, f".readyz_{os.getpid()}")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("1")
            os.remove(probe)
        except OSError as e:
            logging.error("readyz 上传目录不可写: %s", e)
            return 'upload dir not writable', 503
        return 'ok', 200

    @app.after_request
    def _request_log(resp):
        """请求日志:request_id + 方法 + 路径 + 状态码 + 耗时;健康检查路径不刷日志。"""
        start = getattr(g, 'request_start', None)
        if start is None:
            return resp
        dur_ms = (time.perf_counter() - start) * 1000
        if request.path not in ('/healthz', '/readyz'):
            logging.info("req %s scope=%s %s %s -> %d %.1fms",
                         getattr(g, 'request_id', '-'),
                         getattr(g, 'scope', 'shared'),
                         request.method, request.path, resp.status_code, dur_ms)
        return resp

    @app.after_request
    def _security_headers(resp):
        """统一安全响应头;HSTS 建议由反代层配置。"""
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
        resp.headers.setdefault('Referrer-Policy', 'same-origin')
        resp.headers.setdefault('X-XSS-Protection', '0')
        resp.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        # API 响应禁止浏览器缓存(会话/文件列表等敏感数据);
        # 文件下载走 /download/ 与 /share/,不经过 /api/,不受影响。
        if request.path.startswith('/api/'):
            resp.headers.setdefault('Cache-Control', 'no-store')
        # CSP:a.html 含内联脚本/样式与 javascript: 链接,故保留 'unsafe-inline';
        # frame-ancestors 'none' 与 X-Frame-Options 双保险防点击劫持。
        resp.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
            "connect-src 'self' ws: wss:; frame-ancestors 'none'"
        )
        return resp

    # ============ 注册业务路由 ============
    register_auth(app)
    register_routes(app, csrf)
    logging.info("routes registered ok")
    return app


# ==================== 组装应用 ====================
app = create_app()
# 注册表:供 app_admin 等延迟取引用(替代旧的 sys.modules hack,见 app_state.py)
st.set_app(app)
st.set_load_html(load_html)
logging.info("flask create ok")


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

def _local_ip():
    """本机对外 IP;主机名解析失败(无网/无 DNS)时回退回环地址。"""
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return '127.0.0.1'


# 管理端口互斥锁:锚定 BASE_DIR,避免相对路径依赖 CWD 导致多进程各自为政;
# 使用硬锁 FileLock:进程退出/崩溃后由 OS 自动释放,不会像 SoftFileLock 那样
# 因锁文件残留而永久锁死。
admin_lock = filelock.FileLock(os.path.join(st.BASE_DIR, '.admin_lock'))


# 记录本进程实际启动的管理端口,退出时据此清理 Redis 中的 man_port(只删自己写的值)
_started_admin_port = [None]


def _start_admin_server():
    """挑选管理端口并启动控制台监听线程(返回端口;范围内端口耗尽返回 None)。"""
    min_p = st._env_int('ADMIN_PORT_MIN', 6000)
    max_p = st._env_int('ADMIN_PORT_MAX', 6050)
    if max_p < min_p:
        # 环境变量配错(MAX < MIN)时 randbelow 会抛 ValueError 且信息晦涩,启动前显式拒绝
        logging.error("ADMIN_PORT_MAX(%s) < ADMIN_PORT_MIN(%s),放弃启动管理控制台", max_p, min_p)
        return None
    port = None
    for _ in range(50):   # 随机尝试有限次数,防止范围内端口全被占用时无限循环
        sm = secrets.randbelow(max_p - min_p + 1) + min_p
        if not is_port_in_use(sm):
            port = sm
            break
    if port is None:
        logging.error("管理端口范围 %s-%s 全部被占用,放弃启动管理控制台", min_p, max_p)
        try:
            st.r.delete('man_port')   # 清除可能残留的旧值,避免误导客户端
        except Exception:
            pass
        return None
    _started_admin_port[0] = port
    # TTL 10 分钟:进程退出后旧值最多残留 10 分钟,配合退出时的显式删除(见
    # _cleanup_man_port),避免旧端口值误导客户端长达一天。
    st.r.set('man_port', port, ex=600)
    logging.info("管理端口链接:%s:%s", _local_ip(), port)
    threading.Thread(target=start_admin_console, daemon=True, args=(port, admin_lock)).start()
    return port


def _cleanup_man_port():
    """退出时尽力删除 Redis 中由本进程写入的管理端口值(避免误删其它进程新写入的值)。"""
    try:
        if _started_admin_port[0] is not None and \
                st.r.get('man_port') == str(_started_admin_port[0]):
            st.r.delete('man_port')
    except Exception:
        pass


def _try_start_admin_server():
    """统一的管理端口启动入口:先抢锁,抢到才启动,保证多进程/多 worker 只启动一个。

    __main__ 直跑与 gunicorn worker 导入走同一条路径,行为一致。
    """
    try:
        admin_lock.acquire(timeout=1)
    except filelock.Timeout:
        logging.info('管理端口已被其它进程占用,跳过')
        return False
    try:
        _start_admin_server()
    except Exception:
        admin_lock.release()
        raise
    # 释放前检查持有状态:filelock 在未持有时调用 release() 会抛 NotLocked
    atexit.register(lambda: admin_lock.release() if admin_lock.is_locked else None)
    atexit.register(_cleanup_man_port)
    return True


def maybe_start_admin_console():
    """显式管理端口启动入口(幂等)。

    控制开关 START_ADMIN_CONSOLE(默认 '1' 保持旧行为;测试/工具导入时设 0 可跳过,
    从而移除 import 副作用)。推荐生产形态:gunicorn post_fork hook 中调用本函数,
    import 路径不再自动启动(届时可把默认值改为 '0')。
    注意:gunicorn preload 模式下不要在 master 进程 fork 之前调用本函数,
    socket 与线程会被 fork 继承,行为不可预期。
    """
    if os.environ.get('START_ADMIN_CONSOLE', '1') != '1':
        logging.info('START_ADMIN_CONSOLE != 1,跳过管理控制台启动')
        return False
    return _try_start_admin_server()


if __name__ == '__main__':
    HOST = os.environ.get('HOST', '127.0.0.1')
    PORT = st._env_int('PORT', 5000)
    logging.info("🌐 启动: http://%s:%s (本机访问 http://%s:%s)", HOST, PORT, _local_ip(), PORT)
    # 仅当显式允许（ALLOW_DE_LOCK=1）时才由 de.lock 文件开启 debug，
    # 避免残留文件意外打开 get/cr 等调试命令的攻击面
    if os.environ.get('ALLOW_DE_LOCK', '0') == '1' and os.path.exists(os.path.join(st.BASE_DIR, "de.lock")):
        app.debug = True  # 调试链接由 index() 渲染期追加
    maybe_start_admin_console()
    app.run(HOST, PORT, use_reloader=False, use_evalex=False)
else:
    # gunicorn/uwsgi 等生产导入路径:抢锁成功的进程负责启动管理端口。
    # 默认行为与旧版一致;可用 START_ADMIN_CONSOLE=0 关闭 import 副作用,
    # 或改用 gunicorn post_fork hook 调用 maybe_start_admin_console()。
    maybe_start_admin_console()
