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
    return (request.is_json or
            request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
            request.path.startswith('/api/'))

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
TRUSTED_PROXIES = {p.strip() for p in os.environ.get('TRUSTED_PROXIES', '').split(',') if p.strip()}

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

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        with st._user_lock:
            user = session.get('user_id')
            valid = (user is not None) and (user in st.users)
        if not valid:
            if _is_api_request():
                return jsonify({'success': False, 'error': '请先登录'}), 401
            return redirect(url_for('login', next=request.url))
        # 会话版本校验:改密/重置后旧会话立即失效
        if session.get('sess_ver') != st._session_version(user):
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
            if stored and check_password_hash(stored, password):
                session.clear()   # 防 session 固定攻击：登录前废弃旧会话
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
                        st.users[username] = generate_password_hash(password)
                        # 改内存与落库在同一把锁内完成,防止 load_redis 快照覆盖丢失更新
                        st.save_user()
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
