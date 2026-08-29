"""
全局 HTML 模板加载/热重载(从 app.py 拆分)。

职责:读取 a.html 首页模板、请求期惰性 mtime 热重载(时间窗节流 + 双检锁)、
按实例缓存 Jinja 编译结果。模块级全局变量仅限本模块内使用,避免 app.py 的
工厂逻辑与模板状态耦合。

热重载开关与节流:生产可设 TEMPLATE_AUTO_RELOAD=0 彻底关闭(省掉每请求的 stat);
开启时模板变更最多延迟 TPL_RELOAD_INTERVAL 秒生效。
"""

from __future__ import annotations

import os
import time
import threading
import logging

from flask import current_app
from jinja2 import Template

import app_state as st


# ==================== 全局 HTML 模板 ====================
HTML_FILE: str = os.path.join(st.BASE_DIR, 'a.html')
HTML_TEMPLATE: str = ""
_tpl_mtime: int = 0   # 上次加载模板时的纳秒级 mtime(os.stat().st_mtime_ns,惰性热重载)
_tpl_last_check: float = 0.0   # 上次执行 mtime 检查的时间(monotonic,时间窗节流用)
_tpl_lock = threading.Lock()   # 保护 _tpl_mtime/HTML_TEMPLATE 的检查-更新(多线程热重载)
# 热重载开关与节流间隔:生产可设 TEMPLATE_AUTO_RELOAD=0 彻底关闭(省掉每请求的 stat);
# 开启时模板变更最多延迟 TPL_RELOAD_INTERVAL 秒生效。
TPL_AUTO_RELOAD = os.environ.get('TEMPLATE_AUTO_RELOAD', '1') == '1'
TPL_RELOAD_INTERVAL = max(0.1, st.env_int('TEMPLATE_RELOAD_INTERVAL', 1))


def load_html() -> bool:
    """重新读取模板文件(手动/自动热重载共用入口);返回是否成功。

    返回 bool 供调用方区分"已重载/加载失败":load_html 内部已捕获异常并回退
    错误页,若不返回状态,外层只能无条件打印"重载成功",故障时误导运维。
    """
    global HTML_TEMPLATE, _tpl_mtime
    try:
        with open(HTML_FILE, "r", encoding="utf-8") as f:
            HTML_TEMPLATE = f.read()
        try:
            # 纳秒级 mtime:秒级粒度下同一秒内连续两次保存(内容不同)会漏检热重载
            _tpl_mtime = os.stat(HTML_FILE).st_mtime_ns
        except OSError:
            pass
        return True
    except Exception as e:
        logging.warning("无法加载模板 %s: %s", HTML_FILE, e)
        HTML_TEMPLATE = "<h1>模板加载失败，请联系管理员</h1>"
        return False


def _get_html_template() -> str:
    """惰性热重载:请求期按文件 mtime 变化重读模板(时间窗节流,默认 1s 内至多一次 stat)。

    双检锁:无锁 stat 命中缓存则直接返回(高并发热路径不触碰互斥锁),
    仅当 mtime 变化时才拿锁重读,把全局锁争用降到"模板变更时"。
    节流:两次请求间隔不足 TPL_RELOAD_INTERVAL 秒时直接返回缓存,避免全站最热路径
    每个请求都做系统调用;生产可设 TEMPLATE_AUTO_RELOAD=0 彻底关闭热重载。
    替代原"每 worker 一个 5 分钟后台轮询线程":多 worker 各自惰性检测,
    模板更新天然最终一致,且不再浪费线程;文件缺失时回退到当前缓存。
    """
    global HTML_TEMPLATE, _tpl_mtime, _tpl_last_check
    if not TPL_AUTO_RELOAD:
        return HTML_TEMPLATE
    now = time.monotonic()
    if now - _tpl_last_check < TPL_RELOAD_INTERVAL:
        return HTML_TEMPLATE
    try:
        mtime = os.stat(HTML_FILE).st_mtime_ns
    except OSError:
        _tpl_last_check = now
        return HTML_TEMPLATE
    if mtime == _tpl_mtime:
        _tpl_last_check = now
        return HTML_TEMPLATE
    with _tpl_lock:
        # 双检:拿锁后重读 mtime,避免"检查-更新"竞态(并发线程同时重读文件)
        try:
            mtime = os.stat(HTML_FILE).st_mtime_ns
        except OSError:
            return HTML_TEMPLATE
        if mtime == _tpl_mtime:
            return HTML_TEMPLATE
        try:
            with open(HTML_FILE, "r", encoding="utf-8") as f:
                new_tpl = f.read()
        except OSError as e:
            # 读取失败不得推进 _tpl_mtime:否则后续请求 stat 命中同一 mtime 后
            # 不再重读,模板会静默停摆在旧版本(直到文件再次被修改)。
            # 失败时 _tpl_last_check 也不更新,节流窗口过后会自动重试 stat。
            logging.warning("模板重载异常: %s", e)
            return HTML_TEMPLATE
        HTML_TEMPLATE = new_tpl
        _tpl_mtime = mtime
        _tpl_last_check = now
        logging.info("模板已热重载(mtime=%s)", mtime)
    return HTML_TEMPLATE


def _index_template() -> Template:
    """编译并缓存首页模板;缓存挂在 current_app.extensions 上,按实例隔离。

    避免模块级单槽缓存被多个 Flask 实例(如测试隔离实例)串扰;
    缓存键 = 基础模板对象引用 + debug 标志:热重载会替换 HTML_TEMPLATE 字符串对象,
    引用比较 O(1) 即可感知变化,无需对整份模板做 O(n) 字符串比较;
    debug 表单用 Jinja 变量注入(替代原手工 % 拼接),url_for/CSRF token 由
    index() 渲染期传入(二者都需请求上下文,不在这里隐式依赖请求上下文)。
    """
    base = _get_html_template()
    cache = current_app.extensions.setdefault('tpl_index_cache', [None, None, None])  # [base_ref, debug, compiled]
    debug_on = bool(current_app.debug)
    if cache[0] is not base or cache[1] != debug_on:
        if debug_on:
            # reload 是修改状态的操作,端点已收紧为 POST,链接改为表单并带 CSRF token
            tpl = (base
                   + '<br/>\n<form method="post" action="{{ _action }}" style="display:inline">'
                     '<input type="hidden" name="csrf_token" value="{{ _csrf }}">'
                     '<button type="submit">reload</button></form>')
        else:
            tpl = base
        cache[0] = base
        cache[1] = debug_on
        cache[2] = current_app.jinja_env.from_string(tpl)
    return cache[2]
