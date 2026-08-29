"""
文件上传服务 - 共享盘/个人盘文件管理(安全加固版,模块化拆分后组装入口)

空间模型:
- 共享盘(默认): UPLOAD_DIR,所有登录用户共享(原行为)。
- 个人盘:        BASE_DIR/private/<用户名>/,仅本人可访问(admin 不受限)。
- URL 区分: 以 /p 开头的路径走个人盘(如 /p/api/files),其余走共享盘;
  页面提供「共享盘/个人盘」切换入口,前端请求自动加 /p 前缀。

模块结构(拆分):
- app_state.py     配置常量、Redis 连接、用户数据层、任务队列系统(全局状态唯一持有者)
- app_paths.py     路径安全/元数据/个人盘工具
- app_tools.py     分割/合成/解压/URL 下载工具
- app_auth.py      认证装饰器、登录/找回/重置路由、邮件
- app_routes.py    文件/任务/tus/分享/回收站等业务路由(register_routes)
- app_admin.py     管理控制台 socket 服务
- app_middleware.py WSGI 中间件(URL 前缀改写 / 可信代理剥头 / debug 源码护栏)
- app_template.py  全局 HTML 模板加载与请求期热重载
- app.py           本文件:create_app 工厂(配置/中间件/错误处理/路由注册)+ 启动逻辑

主要加固:
1. 用户数据隔离:个人盘按用户名分目录,路径解析强制限定在各自盘根内。
2. 管理控制台:静态 RSA 密钥、握手/认证按源 IP 限流、update/download 传输
   端口增加一次性 token 认证,debug 的 get 命令改为白名单变量。
3. SSRF:解析后固定 IP 直连(防 DNS 重绑定绕过),每跳重定向重新校验。
4. 会话/部署:密钥文件原子创建(O_EXCL 防多进程并发)、SESSION_COOKIE_SECURE
   显式 env 开关、CORS 默认仅放行本机地址(端口随 PORT,SITE_URL/ALLOWED_ORIGINS
   扩展)、CSP(script-src 'self'+nonce,见 _security_headers)/Permissions-Policy
   安全头、/healthz(liveness,仅查存活)与 /readyz(readiness,Redis+磁盘可写)
   探针语义分离。
5. 管理端口:FileLock 互斥(进程崩溃后 OS 自动释放)、man_port TTL 10 分钟
   (后台守护线程每 5 分钟续期,服务运行期间键不失效;退出时清理自己写的值)、
   maybe_start_admin_console() 显式入口(START_ADMIN_CONSOLE 默认 0,import 路径
   无副作用;需管理控制台时显式开启或走 gunicorn post_fork hook)。
6. 模板热重载:请求期惰性 mtime 检测(多 worker 天然最终一致),编译缓存按实例隔离。
7. debug 源码护栏:WSGI 最外层中间件,debug 模式下仅本机回环地址可见 traceback,
   非本机客户端一律脱敏 500(完整堆栈只进服务端日志)。

变更历史见 CHANGELOG.md。

注意:文件分割(TOOL_CUT/TOOL_ASSEMBLY)属于文件处理工具,并非 HTTP 分卷上传;
大文件 HTTP 断点续传未实现,前端大文件上传请走 tus(/api/tus)。
"""

from __future__ import annotations

import os
import sys
import locale
import logging
import secrets
import socket
import ipaddress
import re
import atexit
import time
import threading
import uuid
import weakref
from datetime import timedelta
from string import ascii_letters, digits

from flask import (Flask, request, session, redirect, url_for, jsonify, g,
                   current_app, Response)
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
import filelock

import app_state as st

# 注:app_admin 需要延迟取 app/load_html 引用时,一律经 app_state 注册表
# (st.get_app()/st.get_load_html())获取,不再使用旧的 sys.modules 别名 hack:
# 该 hack 依赖"app.py 是第一个被加载的文件",且 python app.py 直跑(__main__)时
# `from app import app` 会把本文件二次加载,产生第二个实例并重复执行模块级副作用
# (详见 app_state.py 注册表注释)。

from app_auth import register_auth, login_required
from app_routes import register_routes
from app_admin import is_port_in_use, serve_admin_console
# WSGI 中间件与模板热重载已拆分到独立模块(app_middleware / app_template),
# 这里仅导入供 create_app 组装;保持模块级名字可见,兼容既有引用方式。
# 注:_get_html_template 仅在 app_template 内部被调用,此处导入仅为兼容
# 既有 `from app import _get_html_template` 的引用方式,非遗漏。
from app_middleware import (ScopePrefixMiddleware, TrustedProxyScrubMiddleware,
                            DebugTracebackGuard)
from app_template import load_html, _get_html_template, _index_template


# ==================== 日志 ====================
# 日志文件(不再在启动时截断,保留历史日志;带轮转防止无限增长)
LOG_FILE: str = os.path.join(st.BASE_DIR, "app.log")
_LOG_FORMATTER = logging.Formatter(
    # 带 filename:lineno:多模块排障时能直接定位日志出处(如 app_routes.py:318)
    "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# 用 handler 上的标记属性识别"本模块添加的 handler",重复调用 setup_logging 时只移除自己的,
# 不再无差别清空宿主进程(如测试框架/其它工具)已有的 root logger handler。
_LOG_HANDLER_TAG = "dsh_app_log"
# 不写请求日志的路径(健康检查/探针,避免刷屏)
_NO_LOG_PATHS = ('/healthz', '/readyz')
# 请求日志的级别判断走缓存实例(避免热路径每次 getLogger();打日志仍走
# logging.info/error 等模块级函数,不改变调用方/测试的 monkeypatch 语义)。
_root_logger = logging.getLogger()

try:
    # 多进程(如 gunicorn 多 worker)共写同一日志文件时,RotatingFileHandler 的
    # 轮转存在竞态(两个进程同时 rename/重建文件,可能丢日志或产生损坏文件)。
    # 装了 concurrent-log-handler 则自动用其并发安全版(同一日志文件轮转加锁);
    # 未安装时回退标准 RotatingFileHandler(竞态可接受,业界常见,不强制新依赖)。
    from concurrent_log_handler import ConcurrentRotatingFileHandler as _FileHandler
except ImportError:
    from logging.handlers import RotatingFileHandler as _FileHandler


def setup_logging() -> logging.Logger:
    """配置 root logger:级别 + 轮转文件 + 控制台;重复调用幂等,不干扰既有 handler。

    LOG_SET_ROOT_LEVEL=0 时不再修改宿主进程(root logger)的级别,只设置本模块
    添加的 handler 级别——注意 logger 级别是更上游的过滤:宿主级别若高于本配置,
    自家 handler 也收不到更低级别的日志,这是尊重宿主既有配置的预期行为。

    延迟到 create_app 内调用(消除 import 期副作用):DISABLE_AUTO_APP=1 的工具/
    测试进程导入本模块时不再创建 handler、不再写 app.log。
    """
    level = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)
    root = logging.getLogger()
    if os.environ.get('LOG_SET_ROOT_LEVEL', '1') == '1':
        root.setLevel(level)
    for h in list(root.handlers):
        if getattr(h, _LOG_HANDLER_TAG, False):
            root.removeHandler(h)
            try:
                # 文件 handler 持有自开的日志文件 fd,remove 后必须 close 防 fd 泄漏
                # (测试/多实例反复 create_app 场景);StreamHandler 的 stream 是共享的
                # sys.stderr/sys.stdout,不能 close,否则会破坏宿主进程的输出流。
                if isinstance(h, logging.FileHandler):
                    h.close()
            except Exception:
                pass
    try:
        fh = _FileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    except OSError as e:
        # 日志是辅助设施:目录只读/磁盘故障时降级为仅控制台输出,
        # 不能让整个 Web 服务因写不了日志而启动失败。
        logging.warning("日志文件创建失败,本次仅控制台输出: %s", e)
    else:
        fh.setLevel(level)
        fh.setFormatter(_LOG_FORMATTER)
        setattr(fh, _LOG_HANDLER_TAG, True)
        root.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(level)
    sh.setFormatter(_LOG_FORMATTER)
    setattr(sh, _LOG_HANDLER_TAG, True)
    root.addHandler(sh)
    return root


# ==================== 密钥 ====================
# 会话密钥最小长度:短密钥(误写/截断/迁移遗留)会静默削弱会话签名,低于此值拒绝
_SECRET_KEY_MIN_LEN = 32
# 密钥文件并发重建时(FileExistsError)的重读重试参数,见 _load_or_create_secret_key
_KEY_READ_RETRIES = 5
_KEY_READ_RETRY_DELAY = 0.1


def ran_str(length: int, charset: str = ascii_letters + digits) -> str:
    # secrets 为密码学安全随机;random 可预测,被采样后可能推演出 SECRET_KEY
    return ''.join(secrets.choice(charset) for _ in range(length))


SECRET_KEY_FILE: str = os.path.join(st.BASE_DIR, "s.key")


def _load_or_create_secret_key() -> str:
    """读取会话密钥;不存在时原子创建并收紧权限。

    O_EXCL 原子创建保证多进程首次同时启动时只有一个成功写入,
    其余进程重读同一份 key(避免各进程各自生成、互相覆盖导致重启后会话全部失效)。
    """
    def _read():
        try:
            with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
                key = f.read().strip()
        except UnicodeDecodeError as e:
            # 密钥文件不是合法 UTF-8(误写/二进制损坏/编码错乱):同样视为文件损坏。
            # 转成 OSError 走下方既有「重读重试→fail-fast」路径——UnicodeDecodeError
            # 是 ValueError 子类而非 OSError,原实现会绕过所有错误分支,以晦涩的
            # 解码 traceback 直接冒泡到启动栈。
            raise OSError(f"密钥文件不是合法 UTF-8 文本: {e}") from e
        if not key:
            raise OSError("密钥文件为空")
        # 强度校验:短密钥(误写/截断/迁移遗留)会静默削弱会话签名,
        # 宁可启动失败暴露问题,也不接受弱密钥。不足 _SECRET_KEY_MIN_LEN 字符
        # 视为文件损坏:文件已存在时下方 O_EXCL 无法重建,重读重试仍失败则
        # fail-fast,由部署方删除/修复文件后重启(见 FileExistsError 分支指引)。
        if len(key) < _SECRET_KEY_MIN_LEN:
            raise OSError(f"密钥文件内容过短({len(key)}<{_SECRET_KEY_MIN_LEN}),拒绝使用弱密钥")
        return key

    try:
        return _read()
    except FileNotFoundError:
        pass
    except OSError as e:
        # 注意:仅"文件不存在"(上一分支)才会走下方 O_EXCL 新建;文件存在但
        # 损坏/不可读时,O_EXCL 因文件已存在而必然失败,最终 fail-fast
        # (见 FileExistsError / 末位 OSError 分支),不会静默重建弱密钥。
        logging.warning("读取密钥文件失败: %s", e)

    try:
        fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # POSIX 生效;Windows 忽略权限位,见 _harden_key_file_windows
        key = ran_str(128)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key)
        _harden_key_file_windows()  # best-effort:Windows 下收紧 ACL,失败仅告警
        return key
    except FileExistsError:
        # 其它进程已抢先创建;短暂重试等待其写入完成。
        # 若重读仍失败(如文件损坏/过短且被多进程同时重建),同样 fail-fast:
        # 弱密钥或状态不明的密钥文件不该被静默采用。
        for _ in range(_KEY_READ_RETRIES):
            try:
                return _read()
            except OSError:
                time.sleep(_KEY_READ_RETRY_DELAY)
        raise RuntimeError(
            f"密钥文件无法使用且重读仍失败({SECRET_KEY_FILE});"
            "请检查文件状态与权限(损坏/过短/并发未写完);"
            "若为损坏/过短内容,可删除该文件后重启以自动重新生成"
            "(注意:删除后既有会话将全部失效)"
        ) from None
    except OSError as e:
        # fail-fast:密钥无法落盘时若改用临时随机密钥,多 worker 下每个进程密钥不同,
        # 会话会在 worker 间随机失效且极难排查;直接暴露错误让启动失败,由部署方修复。
        raise RuntimeError(
            f"无法创建/读取会话密钥文件 {SECRET_KEY_FILE}: {e};"
            "请检查目录权限与磁盘状态后重启"
        ) from e


def _harden_key_file_windows() -> None:
    """Windows 上 os.open 的 0o600 权限位被忽略,s.key 会继承目录 ACL(明文泄露面)。

    best-effort 用 icacls 收紧为仅当前用户可读写(/inheritance:r 去掉继承的 ACE,
    /grant:r 替换已有权限);任何失败只告警不阻断启动——部署方仍应手动收紧。
    """
    if not sys.platform.startswith('win'):
        return
    try:
        import subprocess
        user = os.environ.get('USERNAME') or os.getlogin()
        r = subprocess.run(
            ['icacls', SECRET_KEY_FILE, '/inheritance:r', '/grant:r', f'{user}:(R,W)'],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            logging.warning("s.key ACL 收紧失败(icacls rc=%s): %s",
                            r.returncode, (r.stderr or r.stdout).strip())
            return
        logging.info("s.key ACL 已收紧为仅当前用户(%s)可访问", user)
    except Exception as e:
        logging.warning("无法自动收紧 s.key ACL(建议手动 icacls %s /inheritance:r /grant:r %s:(R,W)): %s",
                        SECRET_KEY_FILE, os.environ.get('USERNAME') or os.getlogin(), e)


# 注意:不再在模块级生成/读取会话密钥(原 `SECRET_KEY = _load_or_create_secret_key()`),
# 该文件读写移到 create_app 内惰性执行,消除 import 期副作用(测试/工具进程导入本模块
# 时不再触碰磁盘与 s.key)。多进程首次同时启动的 O_EXCL 原子创建语义不变。


# ==================== 健康探针(带结果缓存 + 并发合并) ====================
# 成功结果在短窗口内直接复用(降频 Redis RTT 与磁盘 IO)。
# max(1, ...) 保持 int:该变量是"秒级整数下限"(对比下方失败缓存的 0.2~2.0 float
# clamp,语义不同),避免 max(1.0, int) 把类型悄悄变成 float。
_PROBE_CACHE_SECONDS = max(1, st.env_int('PROBE_CACHE_SECONDS', 5))
# 失败结果也做极短缓存:Redis 故障时若每个探针请求(LB/K8s 常多源并发)都发起一次
# 1s 超时的 ping,会在已故障的 Redis 上堆积大量挂起连接,反而加剧资源消耗;
# 失败缓存(默认 1s)远小于探针周期(1~3s),恢复后状态延迟反映不超过该窗口。
_PROBE_FAIL_CACHE_SECONDS = max(0.2, min(2.0, st.env_int('PROBE_FAIL_CACHE_SECONDS', 1)))
# 探针状态(ok/at)与合并锁挂在 current_app.extensions 上,按实例隔离
# (与 _index_template 的编译缓存同策略):多 Flask 实例(如测试隔离实例)不串扰;
# 无请求上下文时不可调用(探针仅在请求路由内使用)。
# 测试需要跨实例重置缓存:用弱引用集合记录已创建实例(不阻碍 GC),
# 经 _reset_probe_cache() 统一清空各实例 extensions 中的探针状态。
_probe_apps: weakref.WeakSet = weakref.WeakSet()


def _register_probe_app(app: Flask) -> None:
    _probe_apps.add(app)


def _reset_probe_cache(app: Flask | None = None) -> None:
    """重置健康探针结果缓存(测试/诊断用);不传 app 时重置所有已注册实例。

    探针状态按实例隔离挂在各实例 extensions 上(见 _probe_healthy),模块级没有
    单一状态可清;这里遍历弱引用注册表清掉 probe_state/probe_lock,
    下次探针请求重新 ping。无请求上下文时也可安全调用。
    """
    targets = (app,) if app is not None else tuple(_probe_apps)
    for _a in targets:
        _a.extensions.pop('probe_state', None)
        _a.extensions.pop('probe_lock', None)


def _probe_healthy() -> bool:
    """Redis 就绪探针(结果缓存 + 并发合并):窗口内直接复用结果,否则持锁单飞一次 ping。

    仅服务 /readyz(readiness);/healthz(liveness)只反映进程存活,不依赖 Redis——
    依赖检查放 readiness 是标准语义:liveness 探针在依赖抖动时触发容器重启,会把
    瞬时故障放大成滚动重启(见 _register_probes 的 healthz 注释)。

    锁外快路径:缓存窗口内的请求直接返回,不排队等锁——K8s/LB 多源并发打探针时
    (Redis ping 超时可达 1s),未命中的请求才持锁单飞一次;锁内"检查-更新"
    天然合并并发请求(后到的探针等锁后,其结果已落在缓存窗口内,直接复用而不再 ping),
    也保证 ok/at 的更新原子可见。
    """
    now = time.monotonic()
    ext = current_app.extensions
    state = ext.setdefault('probe_state', {'ok': False, 'at': 0.0})
    window = _PROBE_CACHE_SECONDS if state['ok'] else _PROBE_FAIL_CACHE_SECONDS
    if now - state['at'] < window:
        return state['ok']
    lock = ext.setdefault('probe_lock', threading.Lock())
    with lock:
        # 双检:等锁期间其它请求可能已完成 ping,缓存已落在窗口内
        window = _PROBE_CACHE_SECONDS if state['ok'] else _PROBE_FAIL_CACHE_SECONDS
        if time.monotonic() - state['at'] < window:
            return state['ok']
        ok = st.ping_redis()
        state.update(ok=ok, at=time.monotonic())
        return ok


# ==================== 应用工厂辅助(模块级) ====================
# 原 create_app 内部的闭包/局部逻辑拆分为独立函数:工厂只做编排,
# 便于逐块单测,也避免单个函数过长。

def _resolve_secret_key() -> str:
    """SECRET_KEY 双来源:显式环境变量优先,否则用 s.key 文件(见 _load_or_create_secret_key)。

    注意:来源切换(设置/移除 env)会使密钥变化,已签发的会话将全部失效;
    部署时应固定一种来源,不要交替使用。
    """
    _secret_key = os.environ.get('SECRET_KEY')
    if _secret_key:
        if len(_secret_key) < _SECRET_KEY_MIN_LEN:
            # 显式配置的弱密钥同样拒绝:会话签名密钥过短会显著削弱安全性,
            # fail-fast 让部署者立刻发现,而不是上线后靠撞库才暴露。
            raise RuntimeError(
                f"SECRET_KEY 环境变量长度不足({len(_secret_key)}<{_SECRET_KEY_MIN_LEN}),"
                "会话签名密钥过弱;请更换为至少 32 字符的强随机值"
            )
        logging.info("SECRET_KEY 使用环境变量(忽略密钥文件 %s)", SECRET_KEY_FILE)
        return _secret_key
    logging.info("SECRET_KEY 使用密钥文件 %s", SECRET_KEY_FILE)
    # 惰性加载:仅在真正创建应用时才读写 s.key(消除 import 期副作用)
    return _load_or_create_secret_key()


_ORIGIN_PAT = re.compile(r'^https?://[^/\s]+$')


def _resolve_allowed_origins(app_config: dict, site_url: str, default_port: int) -> list[str]:
    """解析 CORS 放行来源(启动期 fail-fast 校验)。

    默认仅放行本机地址,端口跟随 PORT(由调用方传入:取自 app.config['PORT'],
    与 create_app 的 config 覆盖保持一致,不再单独读 env,避免测试/多实例下
    两处端口来源不一致导致 CORS origins 算错);SITE_URL 与 ALLOWED_ORIGINS
    作为扩展来源。只用精确域名:通配子域 + SameSite=Lax + credentials 会让任一
    子域 XSS 即可劫持会话;浏览器 Origin 头永远不带路径,配置带路径
    (如 https://a.com/files)会因来源不匹配被 CORS 拦截且极难排查,故启动期拒绝。
    """
    _default_port = default_port
    # 同时放行 127.0.0.1 与 localhost:浏览器中二者是不同 Origin,
    # 只放行 127.0.0.1 时,用户经 http://localhost:PORT 访问会触发 CORS 拦截。
    # 端口为协议默认值(80/443)时省略端口号:浏览器序列化 Origin 对默认端口
    # 不带端口号(如 http://127.0.0.1),带 :80/:443 的来源与之不匹配会被 CORS 拦截。
    origins = []
    for _scheme in ('http', 'https'):
        _default_scheme_port = 443 if _scheme == 'https' else 80
        _suffix = '' if _default_port == _default_scheme_port else f':{_default_port}'
        for _host in ('127.0.0.1', 'localhost'):
            origins.append(f"{_scheme}://{_host}{_suffix}")
    if site_url:
        if not _ORIGIN_PAT.match(site_url):
            raise RuntimeError(
                f"SITE_URL 格式非法: {site_url!r};应为 https://域名[:端口](不含路径),"
                "否则浏览器 Origin 与之不匹配,跨域请求会被 CORS 拦截"
            )
        origins.append(site_url)
    for _o in str(app_config.get('ALLOWED_ORIGINS', '')).split(','):
        _o = _o.strip()
        if not _o:
            continue
        if _o == '*':
            # 通配符 + credentials 是自相矛盾的配置:浏览器按 CORS 规范直接拒绝
            # 带凭证的 '*' 请求(credentials 模式下不得使用通配来源),表现是
            # "登录后所有跨域请求被 CORS 拦截",极难排查;且一旦后续代码误用
            # 通配符就是越权面。fail-fast,要求列出具体来源。
            raise RuntimeError(
                "ALLOWED_ORIGINS 不支持 '*' 通配符(与 supports_credentials=True 冲突,"
                "浏览器会拒绝带凭证的跨域请求);请列出具体来源,"
                "例如 ALLOWED_ORIGINS=https://a.example.com,https://b.example.com"
            )
        if not _ORIGIN_PAT.match(_o):
            raise RuntimeError(
                f"ALLOWED_ORIGINS 中的来源格式非法: {_o!r};"
                "应为 scheme://host[:port](不含路径)"
            )
        origins.append(_o)
    # 去重:SITE_URL 可能与默认本机来源重复(如 SITE_URL=http://127.0.0.1:5000),
    # 重复项对 CORS 无意义;dict.fromkeys 保持首次出现顺序
    return list(dict.fromkeys(origins))


def _apply_secure_cookie_config(app: Flask, config: dict | None, site_url: str, proxy_count: int) -> None:
    """SESSION_COOKIE_SECURE 默认值:
    - config 参数显式传入(测试)或 env 显式设置:以显式值为准;
    - 两者均未设置时,仅当 SITE_URL 为 https 才自动开启 Secure,把"HTTPS 部署漏配"
      从告警变成自动防护;其余形态保持关闭并给出告警(显式 SESSION_COOKIE_SECURE=1 永远可覆盖)。

    注意:不能仅凭 PROXY_COUNT>0 就推断 HTTPS——PROXY_COUNT 只说明存在反代,不能推断
    浏览器实际访问协议;http 反代下自动开 Secure 会让浏览器不发送会话 cookie,
    表现为"登录成功立刻被登出"且极难排查,故该形态要求部署方显式设置。
    另外不能用 `'SESSION_COOKIE_SECURE' not in app.config` 判断——Flask 的
    DEFAULT_CONFIG 本身就带 SESSION_COOKIE_SECURE=False,该判断恒为 False,
    会导致整个推断分支成为死代码;必须判断调用方(config 参数)是否显式给出。
    """
    if config is None or 'SESSION_COOKIE_SECURE' not in config:
        env_val = os.environ.get('SESSION_COOKIE_SECURE')
        if env_val is None:
            if site_url.startswith('https://'):
                app.config['SESSION_COOKIE_SECURE'] = True
                logging.info("SESSION_COOKIE_SECURE 自动开启(SITE_URL=https,判定为 HTTPS 部署形态)")
            else:
                if proxy_count > 0:
                    logging.warning("PROXY_COUNT>0 但 SITE_URL 非 https:无法推断浏览器访问协议,"
                                    "SESSION_COOKIE_SECURE 保持关闭;HTTPS 反代部署请显式设置 "
                                    "SESSION_COOKIE_SECURE=1,否则会话 cookie 将以明文传输")
                else:
                    logging.warning("未设置 SESSION_COOKIE_SECURE:生产 HTTPS 部署请显式设置 "
                                    "SESSION_COOKIE_SECURE=1,否则会话 cookie 将以明文传输")
                app.config['SESSION_COOKIE_SECURE'] = False
        else:
            # 宽松解析常见真值('1'/'true'/'yes'/'on'),避免拼写差异被静默当 False
            app.config['SESSION_COOKIE_SECURE'] = env_val.strip().lower() in ('1', 'true', 'yes', 'on')


def _before_request() -> None:
    g.scope = request.environ.get('dsh.scope', st.SCOPE_SHARED)
    g.request_id = uuid.uuid4().hex[:12]
    g.request_start = time.perf_counter()
    # CSP nonce:仅首页页面(共享盘/个人盘;ScopePrefixMiddleware 已剥 /p 前缀,
    # 故 request.path 都是 '/')渲染 a.html,需要注入内联 <script> 的 nonce。
    # API/下载/分享等响应无内联脚本,不给 nonce,CSP 落到更严格的 'self'(见 _security_headers)。
    if request.path == '/':
        g.csp_nonce = secrets.token_urlsafe(16)


def _register_home_routes(app: Flask) -> None:
    """首页 + 模板重载路由(含兼容旧路径 /api/new)。"""

    @app.route('/')
    @login_required
    def index():
        _tpl = _index_template()
        # csp_nonce 由 _before_request 生成(仅 '/' 页面);模板里 <script nonce="{{ csp_nonce }}">,
        # 与 _security_headers 下发的 CSP script-src 'nonce-...' 一一对应。
        # or '' 兜底:若未来路由变化导致本函数在非首页上下文被调用,g.csp_nonce
        # 为 None 时模板会渲染出字面 "None",与 _security_headers 中"无 nonce 则
        # script-src 'self'"的严格策略不一致,提前挡掉这种隐性降级。
        _vars = {'username': session.get('user_id', ''),
                 'csp_nonce': getattr(g, 'csp_nonce', None) or ''}
        if current_app.debug:
            # generate_csrf() 读写 session,url_for 依赖请求上下文;个人盘下
            # 中间件设置了 SCRIPT_NAME,url_for 自动带 /p 前缀
            _vars.update(_action=url_for('reload_template'), _csrf=generate_csrf())
        return _tpl.render(**_vars)

    @app.route("/api/reload-template", methods=["POST"])
    @login_required
    def reload_template():
        if not current_app.debug:
            # 非 debug 不提供手动重载:模板变更由 TEMPLATE_AUTO_RELOAD 自动生效;
            # 返回 404 而非旧的无意义 302(生产环境被访问时不会白跳一次)。
            return jsonify({'success': False, 'error': 'Not found'}), 404
        if load_html():
            logging.info("模板已热重载")
        else:
            logging.warning("模板重载失败(load_html 内部已记录原因)")
        # 用 url_for 回首页:个人盘(/p)下自动带前缀,不会把用户踢回共享盘
        return redirect(url_for("index"))

    # 兼容旧路径(原 /api/new):直接复用同一逻辑
    # (不能 redirect——302 会把 POST 变成 GET,落到仅 POST 的 reload-template 上变 405)。
    @app.route("/api/new", methods=["POST"])
    @login_required
    def _legacy_reload_template():
        return reload_template()


def _register_error_handlers(app: Flask) -> None:
    """全局错误处理:统一 JSON(API)/文本(页面)响应。"""

    @app.errorhandler(404)
    def not_found(e):
        if st.is_api_request(request):
            return jsonify({'success': False, 'error': 'Not found'}), 404
        return "页面不存在", 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        """405 统一 JSON(API)/文本(页面),并附 Allow 头告知可用方法。"""
        allow = getattr(e, 'valid_methods', None)
        headers = {'Allow': ', '.join(sorted(allow))} if allow else {}
        if st.is_api_request(request):
            return jsonify({'success': False, 'error': 'Method not allowed'}), 405, headers
        return "方法不允许", 405, headers

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        # 403:CSRF token 缺失/无效属于"客户端凭证错误"(区别于 401 未登录、400 请求格式错误);
        # 页面表单(如 debug 的 reload 表单)提交失败时返回文本,不抛裸 JSON。
        if st.is_api_request(request):
            return jsonify({'success': False, 'error': 'CSRF验证失败'}), 403
        return "CSRF验证失败", 403

    @app.errorhandler(413)
    def handle_too_large(e):
        # 与 400/415/429 同策略:页面请求返回文本,不抛裸 JSON
        # (大文件上传未走 tus 时,页面表单提交也可能触发 413,返回 JSON 会显示一串
        #  原始 JSON 文本,体验差且与其它错误处理器的响应形态不一致)。
        if st.is_api_request(request):
            return jsonify({'success': False, 'error': '请求体超过大小限制'}), 413
        return "请求体超过大小限制", 413

    @app.errorhandler(400)
    @app.errorhandler(415)
    @app.errorhandler(429)
    def handle_client_error(e):
        """400/415/429 统一 JSON(API)/文本(页面);描述取 HTTPException 自带文案。"""
        desc = getattr(e, 'description', None) or '请求错误'
        if st.is_api_request(request):
            return jsonify({'success': False, 'error': desc}), e.code
        return desc, e.code

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
        if st.is_api_request(request):
            return jsonify({'success': False, 'error': '服务器内部错误',
                            'request_id': rid}), 500
        # 非 API 页面也暴露 request_id,便于用户带着它报障
        return f"服务器内部错误(请求ID:{rid})", 500


def _register_probes(app: Flask) -> None:
    """存活/就绪探针(均免认证,兼容现有负载均衡/监控配置)。

    liveness(/healthz)与 readiness(/readyz)语义分离:healthz 只反映进程存活,
    不依赖 Redis/磁盘——若 liveness 在依赖故障时返回 503,K8s 会反复重启容器,
    把瞬时抖动放大成滚动重启;依赖检查统一由 readyz 承担。
    """

    @app.route('/healthz')
    def healthz():
        """存活探针(liveness):进程能响应请求即存活,恒 200。
        依赖可用性见 /readyz(readiness),不要在这里叠加 Redis/磁盘检查。"""
        return 'ok', 200

    @app.route('/readyz')
    def readyz():
        """就绪探针(readiness):Redis 可用且上传目录可写才算就绪,供更严格的上线/摘流判断。

        失败日志用 WARNING:LB/K8s 探针高频(1~3s)打点,ERROR 会淹没真实故障日志。
        注意结果缓存:ok 结果缓存 _PROBE_CACHE_SECONDS 秒(默认 5s),Redis 故障后
        /readyz 最坏延迟该窗口才反映为 503;故障结果缓存约 1s(见 _probe_healthy),
        恢复后状态延迟反映不超过约 1s——部署监控请容忍该最坏检测延迟。
        """
        if not _probe_healthy():
            logging.warning("readyz 未就绪: redis 不可用(失败结果缓存 %ss,见 _probe_healthy)",
                            _PROBE_FAIL_CACHE_SECONDS)
            return 'redis down', 503
        try:
            probe = os.path.join(st.UPLOAD_DIR, f".readyz_{os.getpid()}")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("1")
        except OSError as e:
            logging.warning("readyz 未就绪: 上传目录不可写: %s", e)
            return 'upload dir not writable', 503
        try:
            os.remove(probe)
        except OSError:
            # 删除失败(杀软/权限抖动)不代表目录不可写,不应把"就绪"误判为"未就绪"
            logging.warning("readyz 探针文件删除失败(不影响就绪): %s", probe)
        return 'ok', 200


def _request_log(resp: Response) -> Response:
    """请求日志:request_id + 方法 + 路径 + 状态码 + 耗时;健康检查路径不刷日志。

    分级:5xx 用 ERROR(便于告警检索);401/403 认证/授权失败已在业务侧单独
    打点(如 app_auth 的 "login failure" warning),404 是爬虫/扫描器噪音,
    CORS 预检 OPTIONS 无业务信息量——这四类统一下沉到 DEBUG,避免刷屏淹没 5xx;
    其余 INFO。REQUEST_LOG=0 可整体关闭(压测/高吞吐部署)。
    """
    start = getattr(g, 'request_start', None)
    if start is None:
        return resp
    # 路径归一化:健康检查尾斜杠变体(/healthz/、/readyz/)同样不刷日志,避免扫描噪音
    if (not current_app.config.get('REQUEST_LOG', True)
            or request.path.rstrip('/') in _NO_LOG_PATHS):
        return resp
    # 分级策略见函数 docstring(5xx ERROR / 认证类与噪音下沉 DEBUG)
    if resp.status_code >= 500:
        _level = logging.ERROR
    elif (request.method == 'OPTIONS'
            or resp.status_code in (401, 403, 404)):
        _level = logging.DEBUG
    else:
        _level = logging.INFO
    # 级别未启用时直接返回:不为不会输出的日志做字符串格式化(压测/高吞吐收益明显)。
    # 级别判断走模块级缓存实例(见 _root_logger);实际打日志仍用 logging.info 等
    # 模块级函数,不改变调用方/测试的 monkeypatch 语义。
    if not _root_logger.isEnabledFor(_level):
        return resp
    dur_ms = (time.perf_counter() - start) * 1000
    # client=来源 IP:ProxyFix 已把 remote_addr 修正为可信代理链上的客户端地址,
    # 不要读原始 X-Forwarded-For 头(直连场景下客户端可伪造)。
    line = (f"req {getattr(g, 'request_id', '-')} "
            f"scope={getattr(g, 'scope', st.SCOPE_SHARED)} "
            f"{request.method} {request.path} client={request.remote_addr or '-'} "
            f"-> {resp.status_code} {dur_ms:.1f}ms")
    if _level == logging.ERROR:
        logging.error(line)
    elif _level == logging.DEBUG:
        logging.debug(line)
    else:
        logging.info(line)
    return resp


def _security_headers(resp: Response) -> Response:
    """统一安全响应头;HSTS 建议由反代层配置,例如:
    `Strict-Transport-Security: max-age=31536000; includeSubDomains`。"""
    # X-Request-Id:把请求 ID 暴露给客户端,用户报障时可直接携带,便于与请求日志串联
    _rid = getattr(g, 'request_id', None)
    if _rid:
        resp.headers.setdefault('X-Request-Id', _rid)
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')  # 与 CSP frame-ancestors 'none' 语义一致
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    # X-XSS-Protection 显式置 0:现代浏览器(Chrome 78+/Firefox)已移除该头;旧版
    # 浏览器的"过滤"本身可被构造为 XSS(过滤逻辑可被绕过并反射执行),故禁用。
    resp.headers.setdefault('X-XSS-Protection', '0')
    # HSTS 由应用直接下发(SITE_URL=https 时自动开启,见 create_app 的 HSTS_MAX_AGE),
    # 反代层仍建议叠加更大 max-age 的配置,应用层兜底保证 https 部署不会漏掉 HSTS。
    hsts = current_app.config.get('HSTS_MAX_AGE', 0)
    if hsts:
        resp.headers.setdefault('Strict-Transport-Security',
                                f'max-age={hsts}; includeSubDomains')
    resp.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    resp.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    # CORP 同源:禁止其他站点经 <img>/fetch 等跨源方式读取本应用资源
    # (与 COOP 配套,收窄跨源数据外带面;本应用无合法跨源资源消费方)
    resp.headers.setdefault('Cross-Origin-Resource-Policy', 'same-origin')
    # API 与首页响应禁止浏览器缓存(会话/文件列表/用户名等敏感数据);
    # 未登录渲染的页面(登录/找回/重置)同样 no-store:reset 链接含一次性 token,
    # 页面与 URL 落缓存会延长 token 暴露面,且这些页面由中间缓存缓存无收益。
    # 文件下载走 /download/ 与 /share/,不经过 /api/,不受影响。
    # 错误响应(4xx/5xx,可能携带 request_id/错误详情)同样禁止缓存:
    # 避免浏览器/中间缓存把带 request_id 的错误页存起来,后续报障时对不上日志。
    _no_store_pages = ('/', '/login', '/forgot', '/reset')
    if st.is_api_request(request) or request.path in _no_store_pages or resp.status_code >= 400:
        resp.headers.setdefault('Cache-Control', 'no-store')
    # CSP:script-src 已收紧为 'self' + nonce(仅首页页面,见 _before_request 的
    # g.csp_nonce),不再放行 'unsafe-inline'——a.html 的静态与 JS 生成内联事件
    # 处理器已全部迁移为 data-csp-action 事件委托(见 a.html script 头注释)。
    # 非页面响应(API/下载/分享/登录模板)无 nonce,CSP 落到更严格的 'self':
    # 分享的 HTML 文件被直接浏览时,其内联脚本同样被阻止(防恶意分享内容)。
    # style-src 保留 'unsafe-inline':CSS 无脚本执行能力(XSS 主防线在 script-src),
    # 且登录模板/内联 style 属性/JS 生成的进度条宽度等依赖内联样式,收紧收益低。
    # frame-ancestors 'none' 与 X-Frame-Options 双保险防点击劫持;
    # form-action 'self' 限制表单只能提交到同源(form-action 不回退到 default-src,
    # 不设置时表单可被诱导提交到任意源)。
    # connect-src 收紧为 'self':当前页面/服务无 WebSocket 使用者(管理控制台是
    # 浏览器外的自定义 socket 客户端,不受页面 CSP 约束);若未来需要浏览器 WS,
    # 请按实际源显式放行(如 ws://127.0.0.1:*),勿使用裸 ws: 通配——它会放行
    # 任意 WebSocket 端点,架空 'self' 对数据外带的防护。
    # base-uri 'self':禁止 <base> 标签改写页面资源基址(防资源基址劫持式注入);
    # object-src 'none':default-src 已兜底,显式置 none 进一步禁绝插件/旧式对象注入。
    _nonce = getattr(g, 'csp_nonce', None)
    _script_src = f"script-src 'self' 'nonce-{_nonce}'" if _nonce else "script-src 'self'"
    csp = (
        f"default-src 'self'; {_script_src}; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
        "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; "
        "base-uri 'self'; object-src 'none'"
    )
    resp.headers.setdefault('Content-Security-Policy', csp)
    return resp


# ==================== Flask 应用工厂 ====================
def create_app(config: dict | None = None) -> Flask:
    """应用工厂:组装 Flask 实例(配置/CORS/CSRF/中间件/错误处理/安全头/路由注册)。

    模块级 `app = create_app()` 供 gunicorn(`app:app`)与各模块延迟导入使用;
    测试可传 config(dict)覆盖默认配置,获得隔离实例。
    """
    # 日志初始化收敛到工厂内:消除 import 期副作用(DISABLE_AUTO_APP=1 的工具/测试
    # 进程导入本模块时不再创建 handler、不再写 app.log);setup_logging 幂等,
    # 多实例重复调用只替换自己的 handler。
    setup_logging()
    app = Flask(__name__)
    # 基础配置(config 参数优先,便于测试覆盖启动期生效的项)
    app.config.update(
        # 服务端口(供 CORS 默认本机来源计算;dev 直跑/gunicorn 实际监听仍各自
        # 读 PORT 环境变量,这里统一配置源避免两处不一致)
        PORT=st.env_int('PORT', 5000),
        # 请求体上限按 env 可调(默认 256MB);大文件请走 tus 分片上传(见 app_routes.py),
        # 过大的非分片请求体是磁盘/内存消耗面,不宜默认放到 GB 级。
        MAX_CONTENT_LENGTH=st.env_int('MAX_CONTENT_LENGTH_MB', 256) * 1024 * 1024,
        UPLOAD_FOLDER=st.UPLOAD_DIR,
        SECRET_KEY=_resolve_secret_key(),
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_HTTPONLY=True,
        # 持久会话时长(登录后 session.permanent=True,见 app_auth.py):
        # 默认 7 天(替代 Flask 默认 31 天),SESSION_DAYS 环境变量可配;
        # 滑动过期:每次请求自动续期(SESSION_REFRESH_EACH_REQUEST 默认开启)。
        PERMANENT_SESSION_LIFETIME=timedelta(days=st.env_int('SESSION_DAYS', 7)),
        # 请求日志开关:REQUEST_LOG=0 关闭每请求 INFO 打点(压测/高吞吐部署用);config 可覆盖
        REQUEST_LOG=os.environ.get('REQUEST_LOG', '1') == '1',
        # CORS 额外允许的来源(逗号分隔,如部署到其它域名);config 可覆盖
        ALLOWED_ORIGINS=os.environ.get('ALLOWED_ORIGINS', ''),
        # 显式声明 CSRF token 有效期:会话 7 天且滑动续期,Flask-WTF 默认不限时
        # 与长会话匹配;写死 None 防止未来版本默认行为变化导致长会话中表单提交失败。
        WTF_CSRF_TIME_LIMIT=None,
    )
    if config:
        # 必须在 CORS/CSRF 初始化之前应用:这些配置在启动期读取
        # (如 WTF_CSRF_ENABLED、ALLOWED_ORIGINS),晚于此时点传入不生效。
        app.config.update(config)
    # ============ 部署形态 ============
    # 集中解析 SITE_URL / PROXY_COUNT,供 CORS 与 SESSION_COOKIE_SECURE 共用
    # (同一来源只在启动期解析一次,避免两处重复读取产生不一致)。
    # config 显式传入的 SITE_URL 优先(测试实例可控),否则读环境变量。
    site_url = str((config or {}).get('SITE_URL') or os.environ.get('SITE_URL', '')).strip().rstrip('/')
    proxy_count = st.env_int('PROXY_COUNT', 0)
    # CORS:只用精确域名(格式校验见 _resolve_allowed_origins),启动期 fail-fast。
    _origins = _resolve_allowed_origins(app.config, site_url, app.config.get('PORT', 5000))
    CORS(app, resources={
        r"/*": {"origins": _origins}
    }, supports_credentials=True)
    # 跨站前端部署形态提示:SameSite=Lax 下浏览器跨站 XHR/fetch 不携带会话 cookie,
    # 配置了非本机来源(跨站前端)时会表现为"登录成功立刻失效"且极难排查。
    # 启动期给出告警;跨站前端需要 SESSION_COOKIE_SAMESITE=None 且 SESSION_COOKIE_SECURE=1。
    # 仅统计真·外部来源:默认生成的 http/https 本机来源(_resolve_allowed_origins
    # 会同时放行 127.0.0.1 与 localhost 的两种协议形态)不算跨站,避免默认部署误报。
    _local_origin_re = re.compile(r'^https?://(127\.0\.0\.1|localhost)(:\d+)?$')
    _external_origins = [o for o in _origins if not _local_origin_re.match(o)]
    if (_external_origins
            and 'SESSION_COOKIE_SAMESITE' not in (config or {})
            and os.environ.get('SESSION_COOKIE_SAMESITE') is None):
        logging.warning(
            "ALLOWED_ORIGINS/SITE_URL 含非本机来源(%s),但 SESSION_COOKIE_SAMESITE 未显式配置;"
            "当前 SameSite=Lax 会阻止跨站 XHR/fetch 携带会话 cookie,跨站前端将无法保持登录;"
            "如需跨站前端,请显式设置 SESSION_COOKIE_SAMESITE=None 且 SESSION_COOKIE_SECURE=1",
            ", ".join(_external_origins))
    # SESSION_COOKIE_SECURE:默认开关是显式 env(SESSION_COOKIE_SECURE=1),
    # 测试可通过 config 显式传入覆盖;两者均未设置时按部署形态自动推断(见辅助函数)。
    _apply_secure_cookie_config(app, config, site_url, proxy_count)
    # HSTS:仅当明确是 https 部署形态(SITE_URL=https)时由应用直接下发,不依赖反代配置
    # (反代层常被遗漏);http 形态下发 HSTS 反而会让浏览器拒绝后续 http 访问,故不设置(0=关闭)。
    app.config['HSTS_MAX_AGE'] = 31536000 if site_url.startswith('https://') else 0
    # Flask>=3.0 始终提供 app.json(替代已废弃的 JSON_AS_ASCII 配置项)
    app.json.ensure_ascii = False

    csrf = CSRFProtect(app)

    app.wsgi_app = ScopePrefixMiddleware(app.wsgi_app)
    # 反向代理场景:X-Forwarded-Proto/Host/For 只有在「直连方属于可信代理」时才被采纳。
    # werkzeug 的 ProxyFix 不校验直连方身份,直接信任会让任意客户端伪造这些头
    # (篡改 remote_addr 绕过 IP 限流、伪造 scheme/host 影响 url_for 生成),
    # 因此在外层包 TrustedProxyScrubMiddleware:直连方不在 TRUSTED_PROXIES 时
    # 先清空 XFF 族头,ProxyFix 拿不到伪造头即退化为"不解析"(见中间件注释)。
    if proxy_count > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxy_count, x_proto=proxy_count, x_host=proxy_count)
        app.wsgi_app = TrustedProxyScrubMiddleware(app.wsgi_app, st.TRUSTED_PROXIES)
        logging.info("ProxyFix 已启用(代理层数=%s,可信直连方=%s)",
                     proxy_count, sorted(st.TRUSTED_PROXIES) or '(未配置:忽略一切 X-Forwarded-* 头)')

    app.before_request(_before_request)

    # ============ 首页 / 错误处理 / 探针 / 安全头 ============
    _register_home_routes(app)
    _register_error_handlers(app)
    _register_probes(app)
    app.after_request(_request_log)
    app.after_request(_security_headers)

    # ============ 注册业务路由 ============
    register_auth(app)
    register_routes(app, csrf)
    # debug 源码护栏挂在 WSGI 链最外层(见 DebugTracebackGuard 注释):
    # debug 模式下未处理异常会 propagate 到 WSGI 服务器,这里在到达 dev server
    # 之前拦截,非本机客户端一律得到脱敏 500,完整堆栈只进服务端日志。
    app.wsgi_app = DebugTracebackGuard(app.wsgi_app, lambda: bool(app.debug))
    logging.info("routes registered ok")
    _register_probe_app(app)
    return app


# ==================== 组装应用 ====================
# 模块级 app 引用(gunicorn `app:app` 与 __main__ 依赖);DISABLE_AUTO_APP=1 时为 None
app: Flask | None

def _apply_debug_lock(app_: Flask) -> bool:
    """统一 debug 开关判定:ALLOW_DE_LOCK=1 且 BASE_DIR/de.lock 存在时开启。

    __main__ 直跑与 gunicorn import 路径共用本函数,消除"同一 de.lock 在两种
    部署形态下行为不一致"的问题。de.lock 本身是调试触发标志,生产环境不应保留
    该文件;ALLOW_DE_LOCK 也必须在显式调试时才临时设置(详见模块 docstring 的
    安全说明与 de.lock 残留文件风险)。
    """
    if (os.environ.get('ALLOW_DE_LOCK', '0') == '1'
            and os.path.exists(os.path.join(st.BASE_DIR, "de.lock"))):
        app_.debug = True
        logging.warning("de.lock 存在且 ALLOW_DE_LOCK=1:已开启 debug 模式"
                        "(仅限调试期;生产请移除 de.lock 并取消该环境变量)")
        return True
    return False


def _bootstrap_app() -> None:
    """创建全局应用并登记注册表(gunicorn `app:app` 与 __main__ 依赖模块级 app)。"""
    global app
    app = create_app()
    # 模板加载从 import 期移到这里:消除"import 本模块即读盘"的副作用
    # (DISABLE_AUTO_APP=1 的工具/测试进程不再触碰 a.html;手动 create_app 的
    #  测试实例可按需调用 load_html() 或走请求期热重载)。
    load_html()
    logging.info("html load ok")
    # 注册表:供 app_admin 等延迟取引用(替代旧的 sys.modules hack,见 app_state.py)
    st.set_app(app)
    st.set_load_html(load_html)
    logging.info("flask create ok")


# 模块级副作用收敛:默认自动组装以兼容 gunicorn(app:app)与既有启动方式;
# 工具/测试进程设 DISABLE_AUTO_APP=1 可跳过 create_app/模板加载等 import 副作用,
# 仅按需手动调用 create_app(config=...) 获得隔离实例。
if os.environ.get('DISABLE_AUTO_APP', '0') != '1':
    _bootstrap_app()
else:
    app = None
    logging.info("DISABLE_AUTO_APP=1,跳过全局应用组装")


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

_local_ip_cache: str | None = None


def _local_ip() -> str:
    """本机对外 IP:多网卡(含 VPN/虚拟机网卡)时取第一个非回环 IPv4,
    避免 gethostbyname 随机返回某张网卡地址误导启动日志;解析失败回退回环地址。
    VPN/多网卡环境下探测可能选中虚拟网卡,可用 ADVERTISE_IP 环境变量显式覆盖。
    结果按进程缓存:启动横幅/管理端口日志多次调用时不再重复 getaddrinfo 扫描
    (ADVERTISE_IP 与网卡地址在运行期不变,缓存安全)。"""
    global _local_ip_cache
    if _local_ip_cache is not None:
        return _local_ip_cache
    _override = os.environ.get('ADVERTISE_IP', '').strip()
    if _override:
        _local_ip_cache = _override
        return _local_ip_cache
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ipaddress.IPv4Address(ip).is_loopback:
                _local_ip_cache = ip
                return ip
    except OSError:
        pass
    _local_ip_cache = '127.0.0.1'
    return _local_ip_cache


# 管理端口互斥锁:锚定 BASE_DIR,避免相对路径依赖 CWD 导致多进程各自为政;
# 使用硬锁 FileLock:进程退出/崩溃后由 OS 自动释放,不会像 SoftFileLock 那样
# 因锁文件残留而永久锁死。
admin_lock: filelock.FileLock = filelock.FileLock(os.path.join(st.BASE_DIR, '.admin_lock'))


# 记录本进程实际启动的管理端口,退出时据此清理 Redis 中的 man_port(只删自己写的值)
_started_admin_port: int | None = None


def _man_port_key() -> str:
    """Redis 中记录本实例管理端口地址的键。

    默认 'man_port'(兼容既有管理控制台客户端);多台机器共享同一 Redis 时,
    各实例写同一个键会互相覆盖(客户端拿到的是最后写入者的端口),可通过
    MAN_PORT_KEY=man_port:<实例标识> 做实例隔离(客户端需按同样的键名发现)。
    """
    return os.environ.get('MAN_PORT_KEY', 'man_port')


_MAN_PORT_TTL = 600  # 与 _start_admin_server 写入 ex 保持一致
_MAN_PORT_RENEW_INTERVAL = 300  # TTL 的一半,留足网络抖动/调度延迟余量


def _renew_man_port_loop(key: str, port: int, ttl: int = _MAN_PORT_TTL,
                         stop_event: threading.Event | None = None) -> None:
    """后台守护线程:定期续期 Redis 中本进程的管理端口键。

    原实现只写入一次 ex=600:服务运行超过 10 分钟后键自然过期,客户端断线重连
    或新客户端启动时将无法发现管理端口(而服务仍活着)。续期前校验值仍是自己写的,
    多实例共享同一 Redis 且键名相同(MAN_PORT_KEY 未做实例隔离)时不误续别人写入的值;
    续期失败(Redis 瞬时不可用)不退出,下个周期自动重试。
    stop_event 用于测试/优雅退出场景显式停止循环;不传时按 daemon 线程随进程退出。
    用 Event.wait(timeout) 替代 time.sleep:语义等价(每周期唤醒续期),但 stop_event
    被 set 时立即退出,不再干等最多一个续期周期(测试/优雅退出场景友好)。
    """
    stop = stop_event if stop_event is not None else threading.Event()
    while not stop.wait(_MAN_PORT_RENEW_INTERVAL):
        try:
            if st.r.get(key) == str(port):
                st.r.expire(key, ttl)
        except Exception as e:
            logging.debug("man_port 续期失败(key=%s),下周期重试: %r", key, e, exc_info=True)


def _start_admin_server() -> int | None:
    """挑选管理端口并启动控制台监听线程(返回端口;范围内端口耗尽返回 None)。"""
    global _started_admin_port
    min_p = st.env_int('ADMIN_PORT_MIN', 6000)
    max_p = st.env_int('ADMIN_PORT_MAX', 6050)
    if max_p < min_p:
        # 环境变量配错(MAX < MIN)时 randbelow 会抛 ValueError 且信息晦涩,启动前显式拒绝
        logging.error("ADMIN_PORT_MAX(%s) < ADMIN_PORT_MIN(%s),放弃启动管理控制台", max_p, min_p)
        return None
    port = None
    # range 左闭右开:需要 max_p + 1 才能覆盖到配置的 ADMIN_PORT_MAX
    for ax in range(min_p, max_p + 1):
        if not is_port_in_use(ax):
            port = ax
            break

    if port is None:
        logging.error("管理端口范围 %s-%s 全部被占用,放弃启动管理控制台", min_p, max_p)
        # 不再主动删除 man_port:本进程从未成功写入(端口耗尽),删除极可能误伤
        # 其它进程刚写入的值;旧值由 TTL(600s)自然过期,残留误导窗口很短。
        return None
    # TTL 10 分钟:进程退出后旧值最多残留 10 分钟,配合退出时的显式删除(见
    # _cleanup_man_port),避免旧端口值误导客户端长达一天。
    # 约束:单机多进程由 admin_lock 保证唯一写入者;但多台机器共享同一 Redis 时
    # 各实例会用同一个键互相覆盖(客户端拿到的是别人的端口),
    # 可用 MAN_PORT_KEY=man_port:<实例标识> 隔离(见 _man_port_key)。
    # 先写 Redis 再登记全局端口:set 失败抛异常时(由 maybe_start_admin_console
    # 捕获,Redis 不可用场景)不残留"已登记但从未生效"的 _started_admin_port,
    # 退出清理逻辑(_cleanup_man_port)始终基于真实写入状态判断。
    st.r.set(_man_port_key(), port, ex=_MAN_PORT_TTL)
    _started_admin_port = port
    logging.info("管理端口链接:%s:%s", _local_ip(), port)
    # 把 man_port 键名传给监听线程:bind 失败时(TOCTOU)线程据此清理自己写的键;
    # 线程显式命名,便于进程内定位(gunicorn 多 worker 场景排查归属)。
    threading.Thread(target=serve_admin_console, name='admin-console-listen', daemon=True,
                     args=(port, admin_lock, _man_port_key())).start()
    # man_port 续期守护线程:服务长跑时键不会在 TTL 后过期(见 _renew_man_port_loop)
    threading.Thread(target=_renew_man_port_loop, name='man-port-renew', daemon=True,
                     args=(_man_port_key(), port)).start()
    return port


def _cleanup_man_port() -> None:
    """退出时尽力删除 Redis 中由本进程写入的管理端口值(避免误删其它进程新写入的值)。"""
    try:
        _key = _man_port_key()
        if _started_admin_port is not None and st.r.get(_key) == str(_started_admin_port):
            st.r.delete(_key)
    except Exception as e:
        # 退出路径不阻断进程,但失败要可查(如 Redis 已不可达、值格式异常)
        logging.debug("退出时清理 man_port 失败(不影响退出): %r", e, exc_info=True)


def _try_start_admin_server() -> bool:
    """统一的管理端口启动入口:先抢锁,抢到才启动,保证多进程/多 worker 只启动一个。

    __main__ 直跑与 gunicorn worker 导入走同一条路径,行为一致。
    锁生命周期:启动成功后保持持有到进程退出(atexit 释放,期间其它进程无法抢锁);
    启动抛异常时在 finally 中立即释放,避免锁被无用持有(后续可被其它进程重试)。
    """
    try:
        admin_lock.acquire(timeout=1)
    except filelock.Timeout:
        logging.info('管理端口已被其它进程占用,跳过')
        return False
    _ok = False
    try:
        port = _start_admin_server()
        if port is None:
            # 端口范围全部被占用:视为未启动成功,释放锁返回 False。
            # 原实现此路径不抛异常,锁会被本进程空持到退出,期间端口一旦
            # 空闲,其它进程也因抢不到锁而无法启动管理控制台。
            return False
        atexit.register(_release_admin_lock)
        atexit.register(_cleanup_man_port)
        _ok = True
        return True
    finally:
        if not _ok and admin_lock.is_locked:
            try:
                admin_lock.release()
            except Exception as e:
                # 释放失败只记录:锁文件残留由 filelock 硬锁的 OS 级释放兜底
                logging.debug("启动失败后释放管理端口锁异常(不影响): %r", e, exc_info=True)


def _release_admin_lock() -> None:
    """退出时释放管理端口互斥锁(仅在仍持有时;filelock 未持有 release 会抛 NotLocked)。"""
    try:
        if admin_lock.is_locked:
            admin_lock.release()
    except Exception as e:
        logging.debug("退出时释放管理端口锁失败(不影响退出): %r", e, exc_info=True)


def maybe_start_admin_console() -> bool:
    """显式管理端口启动入口(幂等)。

    控制开关 START_ADMIN_CONSOLE(默认 '0':默认不启动,消除 import 路径副作用;
    需要管理控制台时显式设置 START_ADMIN_CONSOLE=1)。推荐生产形态:
    gunicorn post_fork hook 中调用本函数(先设 START_ADMIN_CONSOLE=1),
    import 路径默认不再自动启动管理端口。
    注意:gunicorn preload 模式下不要在 master 进程 fork 之前调用本函数,
    socket 与线程会被 fork 继承,行为不可预期。
    更一般地:本应用(含 app_state 的模块级 Redis 连接、任务线程与 load_redis
    线程)不建议配合 gunicorn --preload 使用——master import 时会建立 Redis
    连接并启动线程,fork 后所有 worker 继承同一 TCP 连接与线程副本,连接响应
    会互相抢读、锁状态不可预期;如需 preload,请先完成 app_state 的惰性化改造
    或改在 post_fork 中初始化。
    """
    if os.environ.get('START_ADMIN_CONSOLE', '0') != '1':
        logging.info('START_ADMIN_CONSOLE 未启用(默认关闭管理控制台);'
                     '如需启用请设置 START_ADMIN_CONSOLE=1,'
                     '生产推荐在 gunicorn post_fork hook 中显式调用 maybe_start_admin_console()')
        return False
    if admin_lock.is_locked:
        # 本进程已持有锁(幂等重入,如 __main__ 与 import 路径先后触发):
        # 直接返回"已启动",避免走 acquire 超时路径打出误导日志("已被其它进程占用"——其实是自己)。
        return True
    try:
        return _try_start_admin_server()
    except Exception:
        # 管理控制台是可选组件:启动失败(如 Redis 不可用导致 man_port 写入失败)
        # 只记录日志,不能让异常一路抛到 __main__ 使整个 Web 服务启动失败。
        logging.exception("管理控制台启动失败,忽略(不影响主服务)")
        return False


if __name__ == '__main__':
    HOST = os.environ.get('HOST', '127.0.0.1')
    PORT = st.env_int('PORT', 5000)
    if app is None:
        # DISABLE_AUTO_APP=1 时模块级未组装全局应用,无法直跑
        logging.error("DISABLE_AUTO_APP=1 时无法直接运行服务器;请移除该环境变量后重启")
        sys.exit(1)
    logging.info("🌐 启动: http://%s:%s (本机访问 http://%s:%s)", HOST, PORT, _local_ip(), PORT)
    if not os.environ.get('ADVERTISE_IP'):
        # _local_ip 在容器/NAT/多网卡环境下可能选中错误网卡(见其 docstring),
        # 启动横幅上的地址仅供本机/局域网参考,容器部署请用 ADVERTISE_IP 覆盖
        logging.info("提示:容器/NAT/多网卡部署请设置 ADVERTISE_IP 以对外展示正确的访问地址")
    # 仅当显式允许（ALLOW_DE_LOCK=1）时才由 de.lock 文件开启 debug，
    # 避免残留文件意外打开 get/cr 等调试命令的攻击面(判定逻辑见 _apply_debug_lock)
    _apply_debug_lock(app)  # 调试链接由 index() 渲染期追加
    maybe_start_admin_console()
    # threaded=True:上传/下载/URL 下载是 IO 阻塞型,单线程下一个大请求会串行
    # 阻塞所有其它请求(生产走 gunicorn,此参数仅影响 dev 直跑体验)
    app.run(HOST, PORT, use_reloader=False, use_evalex=False, threaded=True)
else:
    # gunicorn/uwsgi 等生产导入路径:START_ADMIN_CONSOLE 默认关闭('0'),
    # import 路径不再产生启动管理端口的副作用(无线程/无 Redis 写/无端口占用);
    # 需要管理控制台时:显式 START_ADMIN_CONSOLE=1(保持旧版自动启动行为,兼容既有部署),
    # 或推荐在 gunicorn post_fork hook 中调用 maybe_start_admin_console()——把启动
    # 时机从"import 时刻"推迟到"worker fork 之后",避免 socket/线程被 fork 继承
    # (详见 maybe_start_admin_console 注释):
    #   def post_fork(server, worker):
    #       import app
    #       app.maybe_start_admin_console()
    # DISABLE_AUTO_APP=1(工具/测试导入)时不自动启动管理端口。
    if app is not None:
        # 与 __main__ 直跑路径共用同一 debug 判定(见 _apply_debug_lock)
        _apply_debug_lock(app)
        maybe_start_admin_console()
