# -*- coding: utf-8 -*-
"""
认证与账号:登录/登出/找回/重置路由、登录态装饰器、邮件发送。

注册方式:app.py 调用 register_auth(app)。
"""
import os
import re
import time
import logging
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

import requests
from flask import (request, session, jsonify, redirect, url_for, render_template)
from werkzeug.security import check_password_hash, generate_password_hash

import app_state as st


# ==================== 通用辅助 ====================

def _is_api_request():
    return st.is_api_request(request)

def _reject(msg, status=403):
    if _is_api_request():
        return jsonify({'success': False, 'error': msg}), status
    return msg, status

def _safe_next(target):
    """防止开放重定向：只允许站内相对路径"""
    if target and target.startswith('/') and not target.startswith('//'):
        return target
    return url_for('index')

# 仅在直连方属于可信代理时才信任 X-Forwarded-For，防止伪造 IP 绕过限流
# (白名单定义收敛在 app_state.TRUSTED_PROXIES,与 app.py 的 ProxyFix 剥头中间件共用)
TRUSTED_PROXIES = st.TRUSTED_PROXIES

def _client_ip():
    """获取客户端真实 IP：直连方不在可信代理列表时回退到 remote_addr。"""
    ra = request.remote_addr or ''
    if ra in TRUSTED_PROXIES:
        xff = request.headers.get('X-Forwarded-For', '')
        first = xff.split(',')[0].strip() if xff else ''
        if first:
            return first
    return ra

# ==================== 登录态装饰器 ====================

# login_required 的短期用户校验缓存:把「用户存在性 + 会话版本」查询合并并缓存,
# 消除高并发下每个请求的锁内 dict 查询与 Redis 会话版本读取(锁/IO 热点)。
# 缓存 TTL 很短(默认 2s):用户被删除后最多延迟该窗口失效;
# 改密/重置会自增 sess_ver,版本不匹配会强制回源查询,不受缓存影响。
_AUTH_CACHE_TTL = 2.0
_auth_cache: dict = {}   # username -> (sess_ver 或 None(用户不存在), monotonic 时间戳)


def _cached_session_version(username: str):
    """带短期缓存的会话版本查询:命中且未过期直接返回,否则持锁回源。"""
    now = time.monotonic()
    hit = _auth_cache.get(username)
    if hit is not None and now - hit[1] < _AUTH_CACHE_TTL:
        return hit[0]
    with st._user_lock:
        exists = username in st.users
        ver = st._session_version(username) if exists else None
    _auth_cache[username] = (ver, now)
    return ver

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        user = session.get('user_id')
        ver = _cached_session_version(user) if user else None
        if ver is None:
            # user 为空或用户不存在(可能刚被删除)
            if _is_api_request():
                return jsonify({'success': False, 'error': '请先登录'}), 401
            return redirect(url_for('login', next=request.url))
        # 会话版本校验:改密/重置后旧会话立即失效
        if session.get('sess_ver') != ver:
            session.pop('user_id', None)
            session.pop('sess_ver', None)
            if _is_api_request():
                return jsonify({'success': False, 'error': '会话已失效,请重新登录'}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return wrap

def is_allowed(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        with st._user_lock:
            blocked = list(st.blocked_users)
        if session.get('user_id') in blocked:
            return _reject('no admin', 403)
        return f(*args, **kwargs)
    return wrap

def is_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get('user_id') == st.admin:
            return f(*args, **kwargs)
        return _reject('no admin', 403)
    return wrap


# ==================== 邮件 ====================
# 发邮件线程池:Resend API 请求最坏 15s,避免在请求/控制台线程内同步阻塞
_mail_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='mail')

def _send_mail(to_addr, subject, text, html=None):
    """通过 Resend API 发送邮件(DKIM/SPF 由 Resend 处理,免维护 SMTP)"""
    if not st.RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY 未配置")
    payload = {
        "from": st.MAIL_FROM,
        "to": [to_addr],
        "subject": subject,
        "text": text,
    }
    if html:
        payload["html"] = html
    resp = requests.post("https://api.resend.com/emails",
                         headers={"Authorization": "Bearer " + st.RESEND_API_KEY},
                         json=payload, timeout=15)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Resend 发送失败: HTTP {resp.status_code} {resp.text[:200]}")
    return resp.json()


def _send_reset_mail(username, mail):
    """生成一次性重置 token 并发邮件,链接 30 分钟内有效"""
    import secrets
    token = secrets.token_urlsafe(32)
    st.r.set(st.RESET_TOKEN_PREFIX + token, username)
    st.r.expire(st.RESET_TOKEN_PREFIX + token, st.RESET_TOKEN_TTL)
    link = f"{st.SITE_URL}/reset?token={token}"
    subject = "重置密码 - 文件管理系统"
    text = (
        f"你好, {username}:\n\n"
        f"你正在申请重置密码。请在 30 分钟内打开以下链接完成重置:\n\n"
        f"{link}\n\n"
        f"如果这不是你的操作,请忽略本邮件,你的密码不会被修改。\n"
        f"-- {st.SITE_URL}"
    )
    html = (
        f"<p>你好, <b>{username}</b>:</p>"
        f"<p>你正在申请重置密码,请在 30 分钟内点击以下链接完成重置:</p>"
        f'<p><a href="{link}">{link}</a></p>'
        f"<p>如果这不是你的操作,请忽略本邮件,你的密码不会被修改。</p>"
    )
    _send_mail(mail, subject, text, html)


# ==================== 路由注册 ====================

def register_auth(app):
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        reset_ok = request.args.get('reset')
        if request.method == 'POST':
            ip = _client_ip() or 'unknown'
            fail_key = f'login_fail:{ip}'
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            # IP 限流(5 次)+ 账号限流(20 次):防止分布式 IP 轮换绕过;
            # 账号阈值放宽,避免攻击者故意输错把受害者账号锁死(单点爆破由 IP 限流挡住)
            acct_key = f'login_fail_u:{username.lower()}' if username else ''
            if int(st.r.get(fail_key) or 0) >= st.LOGIN_FAIL_LIMIT or (acct_key and int(st.r.get(acct_key) or 0) >= st.LOGIN_FAIL_ACCT_LIMIT):
                error = '尝试次数过多，请10分钟后再试'
                return render_template('login.html', error=error)
            with st._user_lock:
                stored = st.users.get(username, '')
                is_blocked = username in st.blocked_users
            if stored and check_password_hash(stored, password):
                if is_blocked:
                    # 被封禁用户禁止登录(原实现登录成功但业务层一律 403,状态不一致;
                    # 封禁状态只能由真实存在的账号触发,不会扩大用户名枚举面)
                    error = '账号已被封禁,请联系管理员'
                    logging.warning(f"blocked user login attempt: {username} from {_client_ip()}")
                    # 直接渲染并返回:不再落入下方"用户名或密码错误"覆盖 error,
                    # 也不会计入失败限流计数(封禁状态与凭据正确性无关)
                    return render_template('login.html', error=error, reset_ok=reset_ok)
                else:
                    session.clear()   # 防 session 固定攻击：登录前废弃旧会话
                    # 持久会话:过期时长取 app.config['PERMANENT_SESSION_LIFETIME']
                    # (默认 7 天,SESSION_DAYS 环境变量可配),滑动续期;
                    # 原默认临时会话"关闭浏览器即失效"没有明确服务端过期,改后更可控。
                    session.permanent = True
                    session['user_id'] = username
                    session['sess_ver'] = st._session_version(username)
                    st.r.delete(fail_key)
                    if acct_key:
                        st.r.delete(acct_key)
                    logging.info(f"user login ok: {username} from {_client_ip()}")
                    return redirect(_safe_next(request.args.get('next')))
            error = '用户名或密码错误'
            st.r.incr(fail_key)
            st.r.expire(fail_key, st.LOGIN_FAIL_WINDOW)
            if acct_key:
                st.r.incr(acct_key)
                st.r.expire(acct_key, st.LOGIN_FAIL_WINDOW)
            logging.warning(f"user login failure.from {_client_ip()} user:{username}")
        return render_template('login.html', error=error, reset_ok=reset_ok)

    @app.route('/logout')
    def logout():
        session.clear()
        logging.info("user logout")
        return redirect(url_for('login'))

    @app.route('/forgot', methods=['GET', 'POST'])
    def forgot():
        """忘记密码:输入用户名或绑定邮箱,发送重置链接(不暴露账号是否存在)"""
        error = None
        if request.method == 'POST':
            ip = _client_ip() or 'unknown'
            fail_key = f'forgot_fail:{ip}'
            if int(st.r.get(fail_key) or 0) >= st.LOGIN_FAIL_LIMIT:
                error = '尝试次数过多,请10分钟后再试'
                return render_template('forgot.html', error=error, msg=None, sent=False)
            # 无论账号是否存在都计数,同时防枚举与防轰炸
            st.r.incr(fail_key)
            st.r.expire(fail_key, st.LOGIN_FAIL_WINDOW)
            account = request.form.get('account', '').strip()
            with st._user_lock:
                username = account if account in st.users else None
                mail = st.user_emails.get(username, '') if username else ''
                if not mail:
                    # 支持直接用绑定邮箱反查用户名
                    for uname, umail in list(st.user_emails.items()):
                        if umail.lower() == account.lower():
                            username, mail = uname, umail
                            break
            if username and mail and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', mail):
                if not st.SITE_URL:
                    # 重置链接依赖 SITE_URL 拼接,未配置时邮件里的链接不可用;
                    # 仍返回统一"已发送"提示(不向请求方暴露配置错误),错误只进日志
                    logging.error("重置邮件未发送:SITE_URL 未配置,无法生成有效重置链接")
                else:
                    # 异步发送:Resend API 最坏阻塞 15s,不该卡住请求线程
                    try:
                        fut = _mail_pool.submit(_send_reset_mail, username, mail)
                        fut.add_done_callback(
                            lambda f: logging.error(f"重置邮件发送失败: {f.exception()}") if f.exception() else None
                        )
                    except Exception as e:
                        logging.error(f"重置邮件线程启动失败: user={username} err={e}")
            # 统一提示,避免用户枚举
            msg = "如果该账号存在且绑定了邮箱,重置链接已发送,请查收(30分钟内有效)。"
            return render_template('forgot.html', error=None, msg=msg, sent=True)
        return render_template('forgot.html', error=None, msg=None, sent=False)

    @app.route('/reset', methods=['GET', 'POST'])
    def reset():
        """重置密码:GET 校验 token 并显示表单,POST 校验后更新密码(一次性 token)"""
        error = None
        if request.method == 'POST':
            token = request.form.get('token', '')
            password = request.form.get('password', '')
            confirm = request.form.get('confirm', '')
            if len(password) < 8:
                error = '密码至少 8 位'
            elif password != confirm:
                error = '两次输入的密码不一致'
            else:
                username = st.r.get(st.RESET_TOKEN_PREFIX + token)
                if not username:
                    error = '链接无效或已过期,请重新申请'
                else:
                    with st._user_lock:
                        exists = username in st.users
                        if exists:
                            st.users[username] = generate_password_hash(password)
                            # 改内存与落库在同一把锁内完成,防止 load_redis 快照覆盖丢失更新
                            st.save_user()
                    if not exists:
                        # 防"账号复活"漏洞:deluser 只清个人盘/分享/会话版本,不清理未消费的
                        # 重置 token;残留 token 若仍可重置,会重建已删除账号。此处废弃 token 并拒绝。
                        st.r.delete(st.RESET_TOKEN_PREFIX + token)
                        error = '账号不存在或已被删除,请重新注册'
                    else:
                        # 会话版本自增:该用户所有旧会话(含被窃取的)立即失效
                        st.r.incr(f'sess_ver:{username}')
                        st.r.delete(st.RESET_TOKEN_PREFIX + token)   # 一次性:用完即失效
                        logging.info(f"password reset ok: {username}")
                        return redirect(url_for('login', reset=1))
            return render_template('reset.html', error=error, token=token)
        token = request.args.get('token', '')
        if not st.r.get(st.RESET_TOKEN_PREFIX + token):
            return render_template('reset.html', error='链接无效或已过期,请重新申请', token='')
        return render_template('reset.html', error=None, token=token)

    @app.route("/api/loginok")
    def loginok():
        name = ""
        lo = False
        la = False
        if "user_id" in session:
            lo = True
            name = session.get("user_id")
            la = session.get("user_id") == st.admin
            with st._user_lock:
                blocked = list(st.blocked_users)
            if session.get("user_id") in blocked:
                la = False
        return jsonify({"login": lo, "admin": la, "name": name})

    @app.route('/check')
    def admin_or_no_user():
        with st._user_lock:
            valid = ('user_id' in session) and (session.get('user_id') in st.users)
        if not valid:
            return 'Non-user', 401
        else:
            if session.get('user_id') == st.admin:
                return 'admin', 200
            else:
                return 'user', 403
