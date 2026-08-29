"""
WSGI 中间件层(从 app.py 拆分):URL 前缀改写 / 可信代理剥头 / debug 源码护栏。

拆分动机:app.py 只保留「应用工厂 + 启动编排」,中间件按职责独立成模块,
与 app_state / app_paths / app_tools / app_auth / app_routes / app_admin 的
模块化拆分风格一致。本模块不持有应用级可变状态,仅依赖 app_state 常量。
"""

from __future__ import annotations

import sys
import logging
from typing import Any, Callable

from flask import Response

import app_state as st


class ScopePrefixMiddleware:
    """WSGI 层 URL 前缀改写:把 /p 开头的路径剥掉 /p 前缀并标记个人盘 scope,
    使所有现有路由自动同时服务于共享盘(/ )与个人盘(/p)。"""

    def __init__(self, wsgi_app: Callable) -> None:
        self.wsgi_app = wsgi_app

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        path = environ.get('PATH_INFO', '')
        if path == st.PERSONAL_URL_PREFIX or path.startswith(st.PERSONAL_URL_PREFIX + '/'):
            environ['PATH_INFO'] = path[len(st.PERSONAL_URL_PREFIX):] or '/'
            # 与上游已有 SCRIPT_NAME 拼接而非覆盖:反代子路径挂载(SCRIPT_NAME 非空)
            # 时直接覆盖会丢失子路径,url_for() 生成错误前缀;拼接保持两种部署形态都
            # 正确(werkzeug 规范 SCRIPT_NAME 无尾斜杠,如 '/sub' + '/p' = '/sub/p')。
            _script = (environ.get('SCRIPT_NAME') or '').rstrip('/')
            environ['SCRIPT_NAME'] = _script + st.PERSONAL_URL_PREFIX
            environ['dsh.scope'] = st.SCOPE_PERSONAL
        else:
            environ['dsh.scope'] = st.SCOPE_SHARED
        return self.wsgi_app(environ, start_response)


class TrustedProxyScrubMiddleware:
    """可信代理剥头中间件:仅当直连方(REMOTE_ADDR)属于 TRUSTED_PROXIES 时,
    才保留 X-Forwarded-For/Proto/Host 头交给下层(ProxyFix)处理;否则全部剥离。

    背景:werkzeug 的 ProxyFix 只按 x_for 数量解析头,不校验直连方身份。若应用
    直连公网且误配 PROXY_COUNT,攻击者可在任意请求里伪造 X-Forwarded-For 篡改
    request.remote_addr(绕过登录/找回密码的 IP 限流、污染审计日志),或伪造
    X-Forwarded-Proto/Host 影响 url_for 生成的 scheme/域名(钓鱼面)。
    本中间件把 ProxyFix 的信任面收紧为「仅可信代理直连」,与 app_auth._client_ip
    的 TRUSTED_PROXIES 语义保持一致(白名单收敛在 app_state)。
    """
    _FORWARDED_HEADERS = (
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED_PROTO',
        'HTTP_X_FORWARDED_HOST',
    )

    def __init__(self, wsgi_app: Callable, trusted: frozenset | set) -> None:
        self.wsgi_app = wsgi_app
        self.trusted = frozenset(trusted)

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        # REMOTE_ADDR 在此处(ProxyFix 外层)仍是 socket 层真实直连方,不可伪造
        if (environ.get('REMOTE_ADDR') or '') not in self.trusted:
            for _h in self._FORWARDED_HEADERS:
                environ.pop(_h, None)
        return self.wsgi_app(environ, start_response)


class DebugTracebackGuard:
    """debug 模式源码护栏:Flask 在 debug 下把未处理异常直接 re-raise(PROPAGATE_EXCEPTIONS
    默认随 debug 开启)给 WSGI 服务器——python app.py 直跑时是 werkzeug dev server,
    会给请求方渲染带源码/局部变量的 traceback 页面。若 de.lock 开了 debug 且端口可被
    非本机访问,任何客户端触发 500 都能看到源码,这是真实的源码泄露面。

    本中间件挂在 WSGI 链最外层(位于 ProxyFix/剥头中间件之外,REMOTE_ADDR 为 socket 层
    真实直连方,不可伪造):
    - debug 开启且直连方是本机回环地址:放行异常,保留本机调试体验(dev server 渲染 traceback);
    - 其余情况(非 debug,或 debug 但非本机):吞掉异常,返回脱敏 500,完整堆栈只进服务端日志
      (Flask 的 propagate 分支不记日志,这里补记,否则非本机 500 连日志都没有)。

    注意:局域网内经其它网卡 IP 调试同样视为非本机(泄露面相同),请收紧部署网络;
    如需扩大放行范围,请显式维护地址清单,勿用通配。
    """
    _LOCAL_ADDRS = frozenset({'127.0.0.1', '::1', '[::1]'})

    def __init__(self, wsgi_app: Callable, is_debug: Callable[[], bool]) -> None:
        self.wsgi_app = wsgi_app
        self.is_debug = is_debug

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        try:
            return self.wsgi_app(environ, start_response)
        except Exception:
            if self.is_debug() and (environ.get('REMOTE_ADDR') or '') in self._LOCAL_ADDRS:
                raise
            # 非 debug(理论上到不了这里,防御)或 debug 下非本机:响应脱敏,细节只进日志
            logging.exception("未处理异常(非本机客户端,响应已脱敏): %r",
                              sys.exc_info()[1])
            resp = Response('服务器内部错误', status=500, mimetype='text/plain')
            return resp(environ, start_response)
