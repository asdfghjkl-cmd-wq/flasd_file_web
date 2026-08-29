"""
文件上传服务 - 共享盘/个人盘文件管理(安全加固版)

空间模型:
- 共享盘(默认): UPLOAD_DIR,所有登录用户共享(原行为)。
- 个人盘:        BASE_DIR/private/<用户名>/,仅本人可访问(admin 不受限)。
- URL 区分: 以 /p 开头的路径走个人盘(如 /p/api/files),其余走共享盘;
  页面提供「共享盘/个人盘」切换入口,前端请求自动加 /p 前缀。

主要加固:
1. 用户数据隔离:个人盘按用户名分目录,路径解析强制限定在各自盘根内。
2. 管理控制台:静态 RSA 密钥、握手/认证按源 IP 限流、update/download 传输
   端口增加一次性 token 认证,debug 的 get 命令改为白名单变量。
3. SSRF:解析后固定 IP 直连(防 DNS 重绑定绕过),每跳重定向重新校验。
4. 修复:loginok 管理员标志、call_ze 空 JSON 500、保留目录名越权、
   download 无大小上限、全局用户字典并发读写等。

注意:文件分割(TOOL_CUT/TOOL_ASSEMBLY)属于文件处理工具,并非 HTTP 分卷上传;
大文件 HTTP 断点续传未实现,前端大文件上传请走 /file/upload。
"""


import subprocess

import psutil,ipaddress
import filelock
from file_rw import recv_file,send_file

def is_port_in_use(port):
    for conn in psutil.net_connections():
        if conn.laddr.port == port and conn.status == "LISTEN": # type: ignore
            return True
    return False

import hashlib
import atexit
import hmac

from py7zr import SevenZipFile
from py7zr.callbacks import ExtractCallback

import zipfile, requests,pyzipper
import shlex
from threading import Thread,Event,RLock
from queue import Queue
from urllib.parse import urlparse, urljoin
import logging
from logging.handlers import RotatingFileHandler
import select
import socket
import struct
from string import ascii_lowercase, ascii_letters
from flask import (Flask, request, jsonify, render_template_string,
                   make_response, send_from_directory, session, redirect, url_for, abort, g)
import random
from flask_cors import CORS
import os, sys, json, traceback, shutil, re, uuid, time, io, secrets
from datetime import datetime
from urllib.parse import quote
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_wtf.csrf import CSRFProtect, CSRFError
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
# 禁用不安全的请求警告（针对 verify=False）
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import redis


def _env_int(name, default):
    """读取整数型环境变量,非法值回退默认值(避免配置写错导致进程起不来)。"""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == '':
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        print(f"[WARN] 环境变量 {name} 不是合法整数({raw!r}),使用默认值 {default}", flush=True)
        return default

# 从环境变量读取 Redis 地址，方便部署
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = _env_int('REDIS_PORT', 6379)
REDIS_DB = _env_int('REDIS_DB', 0)
REDIS_PASSWORD  = os.environ.get('REDIS_PASSWORD', None)

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, password=REDIS_PASSWORD,
                decode_responses=True, socket_connect_timeout=5, socket_timeout=5)
try:
    print(r.info('server')['redis_version'],flush=True)
except Exception as e:
    print(f"[FATAL] Redis 连接失败: {e}", flush=True)
    raise SystemExit(f"Redis 连接失败: {e}")
# 加固:Redis 存有密码哈希/任务/管理端口等敏感数据
# 公网无密码默认拒绝启动;确需这样部署时显式设置 ALLOW_INSECURE_REDIS=1
try:
    if not REDIS_PASSWORD and not ipaddress.IPv4Address(REDIS_HOST).is_private():
        if os.environ.get('ALLOW_INSECURE_REDIS', '0') != '1':
            raise SystemExit("Redis 未设置密码且非本地地址,存在泄露风险;请设置 REDIS_PASSWORD,"
                             "或确认网络已隔离后设置 ALLOW_INSECURE_REDIS=1 显式放行")
        logging.warning("Redis 未设置密码且非本地地址,存在泄露风险(已由 ALLOW_INSECURE_REDIS 显式放行)")
except ipaddress.AddressValueError:
    if not REDIS_PASSWORD and not ipaddress.IPv4Address(socket.gethostbyname(REDIS_HOST)).is_private:
        if os.environ.get('ALLOW_INSECURE_REDIS', '0') != '1':
            raise SystemExit("Redis 未设置密码且非本地地址,存在泄露风险;请设置 REDIS_PASSWORD,"
                             "或确认网络已隔离后设置 ALLOW_INSECURE_REDIS=1 显式放行")
        logging.warning("Redis 未设置密码且非本地地址,存在泄露风险(已由 ALLOW_INSECURE_REDIS 显式放行)")

# 全局用户数据并发锁:users/user_list/blocked_users/admin 被请求线程、
# load_redis 线程与管理控制台线程共享,读写必须加锁(RLock 支持嵌套 save_user)
_user_lock = RLock()

# debug open 邮件验证:向管理员绑定邮箱发送一次性验证码(10 分钟有效)
DEBUG_CODE_TTL = 600
DEBUG_CODE_PREFIX = 'debug_code:'

# ==================== 邮件 / 密码找回 ====================
# SMTP 通过环境变量注入(与 REDIS_PASSWORD 同风格);发件人默认 no-reply@www.goodlink.website

MAIL_FROM = os.environ.get('MAIL_FROM', 'no-reply@www.relink.website')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
SITE_URL = os.environ.get('SITE_URL', 'https://www.relink.website')
RESET_TOKEN_TTL = 1800        # 重置链接 30 分钟有效
RESET_TOKEN_PREFIX = 'reset_token:'

class Cancelled(BaseException):
    """任务取消信号:BaseException 使其能穿透各工具的普通 except 处理。"""
    pass

def get_filename_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.path.split('/')[-1]



class tool:
    class u1:
        @staticmethod
        def call(source_path,chunk_size,output_dir,task_id,cancel_check):
            if os.path.exists(output_dir):
                if os.path.isdir(output_dir):
                        shutil.rmtree(output_dir)
                else:
                    os.remove(output_dir)  # 如果是同名文件则删除
            os.makedirs(output_dir)

            file_count = 0
            with open(source_path, "rb") as src:
                while True:
                    if cancel_check():
                        shutil.rmtree(output_dir)
                        raise Cancelled("cancel")
                    data = src.read(chunk_size)
                    if not data:
                        break
                    file_count += 1

                    # 4位编号便于排序
                    out_name = os.path.join(output_dir, f"{file_count:04d}.data")
                    with  open(out_name, "wb") as chunk:
                        chunk.write(data)

    # 写入元信息
            meta_path = os.path.join(output_dir, "file")
            with open(meta_path, "w", encoding="utf-8") as meta:
                meta.write(f"{os.path.basename(source_path)}\n")
                meta.write(f"{file_count}\n")
                meta.write(f"{chunk_size}\n")
            return True


    class u2:
        def call(dir,tdir,task_id,cancel_check):
            with open(os.path.join(dir,"file"),"r",encoding="utf-8") as fmeta:
                n = os.path.basename(fmeta.readline().rstrip("\n"))
                x = int(fmeta.readline().rstrip("\n"))
            with open(os.path.join(tdir,n),"wb") as bn:
                for nb in range(1,x+1):
                    if cancel_check():
                        os.remove(bn.name)
                        raise Cancelled("cancel")
                    with open(os.path.join(dir,f"{nb:04d}.data"),"rb") as an:
                        bn.write(an.read())
            return True

# ==================== 异步任务系统 ====================


MAX_WORKERS = 3
task_queue = Queue()
def save_user():
    """将用户数据存入 Redis(内部持有 _user_lock,RLock 可重入)"""
    with _user_lock:
        # 存储密码哈希
        if users:
            r.hset("users", mapping=users)   # type: ignore # {"username": "hash"}
        # 存储用户邮箱(用于密码找回)
        r.delete("user_emails")
        if user_emails:
            r.hset("user_emails", mapping=user_emails)
        # 存储用户列表
        r.delete("user_list")
        if user_list:
            r.sadd("user_list", *user_list) # type: ignore
        # 存储黑名单
        r.delete("blocked_users")
        if blocked_users:
            r.sadd("blocked_users", *blocked_users)
        # 存储管理员
        r.set("admin", admin) # type: ignore
    print('save ok', flush=True)

def load_user():
    """从 Redis 加载用户数据(内部持有 _user_lock)"""
    global users, user_list, blocked_users, admin, user_emails

    with _user_lock:
        # 一次性迁移旧黑名单 key（旧 key 为 nigga_list）
        if r.exists("nigga_list"):
            old = list(r.smembers("nigga_list"))
            if old:
                r.sadd("blocked_users", *old)
            r.delete("nigga_list")

        # 默认管理员（环境变量）
        ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', os.environ.get('a', None))
        ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', os.environ.get('p', None))
        ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD) if ADMIN_PASSWORD else None

        # 尝试从 Redis 读取
        redis_users = r.hgetall("users")
        redis_user_list = list(r.smembers("user_list"))
        redis_blocked_users = list(r.smembers("blocked_users"))
        redis_admin = r.get("admin")
        redis_user_emails = r.hgetall("user_emails")

        # 如果 Redis 中有数据就用 Redis 的
        if redis_users:
            users = redis_users
            user_list = redis_user_list
            blocked_users = redis_blocked_users
            admin = redis_admin if redis_admin else ADMIN_USERNAME
            user_emails = redis_user_emails
        else:
            # 首次运行，用环境变量初始化
            # 未配置管理员密码时不要写入 None 哈希，避免后续 check_password_hash 崩溃
            users = {ADMIN_USERNAME: ADMIN_PASSWORD_HASH} if (ADMIN_USERNAME and ADMIN_PASSWORD_HASH) else {}
            user_list = [ADMIN_USERNAME] if ADMIN_USERNAME else []
            blocked_users = []
            admin = ADMIN_USERNAME
            user_emails = {}
            save_user()  # 写入 Redis

    return users, user_list, blocked_users, admin, user_emails

# ==================== 工具 ID 常量 ====================
TOOL_CUT = 1        # 分割文件
TOOL_ASSEMBLY = 2   # 合成文件
TOOL_INFO = 3       # 使用说明（无任务）
TOOL_UNZIP = 4      # 解压
TOOL_DOWNLOAD = 6   # URL 下载
TOOL_COPY = 50      # 复制
TOOL_MOVE = 51      # 移动
TOOL_HASH = 64      # 计算哈希
# 可取消任务的工具集合
tool_list = {TOOL_CUT, TOOL_ASSEMBLY, TOOL_UNZIP, TOOL_DOWNLOAD, TOOL_COPY, TOOL_MOVE, TOOL_HASH}

def worker():
    while True:
        task_id, func, base_args, tool_id = task_queue.get()
        if task_id is None:
            break
        # 更新状态为 running
        r.hset(task_key(task_id), 'status', 'running')

        try:
            with app.app_context():
                if tool_id in tool_list:
                    r.hset(task_key(task_id), 'can_cancel', 'True')
                    if tool_id == TOOL_HASH:
                        ok, result = func(*base_args, task_id=task_id,
                                          cancel_check=lambda: is_cancelled(task_id))
                    else:
                        ok = func(*base_args, task_id=task_id,
                                  cancel_check=lambda: is_cancelled(task_id))
                else:
                    r.hset(task_key(task_id), 'can_cancel', 'False')
                    func(*base_args)
                    ok, result = True, None

            if ok:
                r.hset(task_key(task_id), 'status', 'finished')
                if tool_id == TOOL_HASH:
                    r.hset(task_key(task_id), 'return', result)
            else:
                r.hset(task_key(task_id), 'status', 'failed')
                t = get_task(task_id)
                if not t or t.get('error') == '':
                    r.hset(task_key(task_id), 'error', 'unknown')

        except Cancelled:
            # 任务主动取消(BaseException,穿透普通 except)
            if is_cancelled(task_id):
                r.hset(task_key(task_id), 'status', 'cancelled')
        except Exception as e:
            traceback.print_exc()
            if is_cancelled(task_id):
                r.hset(task_key(task_id), 'status', 'cancelled')
            else:
                r.hset(task_key(task_id), 'status', 'failed')
                r.hset(task_key(task_id), 'error', str(e))
        finally:
            if is_cancelled(task_id):
                r.hset(task_key(task_id), 'status', 'cancelled')
                r.hset(task_key(task_id), 'error', 'User cancelled')
            task_queue.task_done()

for _ in range(MAX_WORKERS):
    t = Thread(target=worker, daemon=True)
    t.start()

# ==================== 初始化 ====================
if sys.platform.startswith('win'):
    import io, locale
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    try: locale.setlocale(locale.LC_ALL, 'zh_CN.UTF-8')
    except: pass

def ran_str(length, charset=ascii_lowercase+'0123456789'):
    # secrets 为密码学安全随机;random 可预测,被采样后可能推演出 SECRET_KEY
    return ''.join(secrets.choice(charset) for _ in range(length))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_FILE = os.path.join(BASE_DIR, 'a.html')
TRASH_DIR = os.path.join(BASE_DIR,'trash')
if not os.path.exists(TRASH_DIR):
    os.makedirs(TRASH_DIR)
try:
    with open(os.path.join(BASE_DIR, "s.key"), "r", encoding="utf-8") as s:
        k = s.read()
except:
    k = ran_str(128, ascii_letters)
    with open(os.path.join(BASE_DIR, "s.key"), "w", encoding="utf-8") as s:
        s.write(k)
# 日志文件（不再在启动时截断，保留历史日志；带轮转防止无限增长）
LOG_FILE = os.path.join(BASE_DIR, "app.log")
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
    UPLOAD_FOLDER=os.path.join(BASE_DIR, 'uploads'),
    SECRET_KEY=os.environ.get('SECRET_KEY', k),
    JSON_AS_ASCII=False,SESSION_COOKIE_SAMESITE='Lax',
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
        if path == PERSONAL_URL_PREFIX or path.startswith(PERSONAL_URL_PREFIX + '/'):
            environ['PATH_INFO'] = path[len(PERSONAL_URL_PREFIX):] or '/'
            environ['dsh.scope'] = 'personal'
        else:
            environ['dsh.scope'] = 'shared'
        return self.wsgi_app(environ, start_response)


app.wsgi_app = ScopePrefixMiddleware(app.wsgi_app)





# 反向代理场景:X-Forwarded-Proto/Host/For 需要可信代理才生效(与 TRUSTED_PROXIES 配合)
_proxy_count = _env_int('PROXY_COUNT', 0)
if _proxy_count > 0:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_count, x_proto=_proxy_count, x_host=_proxy_count)
    logging.info(f"ProxyFix 已启用(代理层数={_proxy_count})")

@app.before_request
def _set_scope():
    g.scope = request.environ.get('dsh.scope', 'shared')

logging.info("flask create ok")

UPLOAD_DIR = os.path.abspath(app.config['UPLOAD_FOLDER'])
META_DIR = os.path.join(UPLOAD_DIR, 'metadata')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(META_DIR, exist_ok=True)

# ==================== 双空间(共享盘/个人盘) ====================
# 共享盘:UPLOAD_DIR(所有用户);个人盘:PRIVATE_ROOT/<用户名>/(仅本人 + admin)
PRIVATE_ROOT = os.path.join(BASE_DIR, 'private')
os.makedirs(PRIVATE_ROOT, exist_ok=True)
PERSONAL_URL_PREFIX = '/p'          # 个人盘 URL 前缀
RESERVED_NAMES = {'metadata', 'chunks'}   # 系统保留目录/文件名
# 下载大小上限(字节),防止下载把磁盘写满;0 表示不限制
DOWNLOAD_MAX_SIZE = _env_int('DOWNLOAD_MAX_SIZE', 10 * 1024**3)
# 管理端口随机范围
ADMIN_PORT_MIN = _env_int('ADMIN_PORT_MIN', 6000)
ADMIN_PORT_MAX = _env_int('ADMIN_PORT_MAX', 6050)
# 管理端口绑定地址(默认仅本机回环;需要远程管理时显式设置 ADMIN_BIND,并配合防火墙/ACL)
ADMIN_BIND = os.environ.get('ADMIN_BIND', '0.0.0.0')
if ADMIN_BIND not in ('127.0.0.1', '::1', 'localhost'):
    logging.warning(f"ADMIN_BIND={ADMIN_BIND} 非回环地址,管理控制台暴露于网络,请确认防火墙/ACL")
# 管理控制台握手限流:同一 IP 每窗口最多连接次数
ADMIN_CONN_LIMIT = _env_int('ADMIN_CONN_LIMIT', 5)
ADMIN_CONN_WINDOW = 10   # 秒


# 任务数据用 Hash 存储，键为 task:<task_id>
TASK_PREFIX = "task:"

def task_key(task_id):
    return TASK_PREFIX + task_id

def save_task(task_id, data):
    """保存任务到 Redis（初始化或更新）"""
    key = task_key(task_id)
    # 需要序列化嵌套结构
    safe = {}
    for k, v in data.items():
        if isinstance(v, (dict, list)):
            safe[k] = json.dumps(v)
        else:
            safe[k] = str(v)
    r.hset(key, mapping=safe)
    # 任务 7 天无更新自动过期，防止无限累积
    r.expire(key, 7 * 24 * 3600)

def get_tasks_bulk(tids):
    """批量读取任务（pipeline 化，避免 N+1）；返回 {tid: 反序列化后的 dict}"""
    if not tids:
        return {}
    pipe = r.pipeline()
    for tid in tids:
        pipe.hgetall(task_key(tid))
    raws = pipe.execute()
    out = {}
    for tid, raw in zip(tids, raws):
        if not raw:
            continue
        if 'progress' in raw:
            try:
                raw['progress'] = json.loads(raw['progress'])
            except Exception:
                pass
        if 'file_info' in raw:
            try:
                raw['file_info'] = json.loads(raw['file_info'])
            except Exception:
                pass
        raw['cancel_flag'] = int(raw.get('cancel_flag', 0))
        out[tid] = raw
    return out

def get_task(task_id):
    """从 Redis 读取任务，并反序列化"""
    return get_tasks_bulk([task_id]).get(task_id)

def delete_task(task_id):
    r.delete(task_key(task_id))

def is_cancelled(task_id):
    """任务执行中检查是否被取消"""
    flag = r.hget(task_key(task_id), 'cancel_flag')
    return flag == '1'

def cancel_task_by_id(task_id):
    """设置取消标记"""
    if not r.exists(task_key(task_id)):
        return False
    status = r.hget(task_key(task_id), 'status')
    if status not in ('running', 'pending'):
        return False
    r.hset(task_key(task_id), 'cancel_flag', '1')
    return True

MAX_PENDING_PER_USER = _env_int('MAX_PENDING_PER_USER', 10)

def _check_pending_limit():
    """每用户排队任务上限：超限返回 429 响应，否则返回 None。"""
    user = session.get('user_id')
    if not user or user == admin:
        return None
    count = 0
    for key in r.scan_iter(match=f"{TASK_PREFIX}*"):
        if r.hget(key, 'owner') == user and r.hget(key, 'status') == 'pending':
            count += 1
            if count >= MAX_PENDING_PER_USER:
                return jsonify({'success': False, 'error': f'排队任务过多(上限 {MAX_PENDING_PER_USER} 个)'}), 429
    return None

def _can_access_task(task):
    """任务归属校验：非管理员只能访问自己创建的任务。"""
    if not task:
        return False
    if session.get('user_id') == admin:
        return True
    return task.get('owner') == session.get('user_id')

def load_redis():
    global user_list,users,blocked_users,admin,user_emails
    while True:
        time.sleep(10)
        try:
            redis_users = r.hgetall("users")
            redis_user_list = list(r.smembers("user_list"))
            redis_blocked_users = list(r.smembers("blocked_users"))
            redis_admin = r.get("admin")
            redis_user_emails = r.hgetall("user_emails")
            ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', os.environ.get('a', None))
            if redis_users:
                with _user_lock:
                    users = redis_users
                    user_list = redis_user_list
                    blocked_users = redis_blocked_users
                    admin = redis_admin if redis_admin else ADMIN_USERNAME
                    # 邮箱数据也要同步,否则多 worker 下忘记密码功能读到陈旧数据
                    if redis_user_emails:
                        user_emails = redis_user_emails
        except Exception as e:
            # Redis 瞬时错误不能让同步线程死掉，记录后下轮重试
            logging.warning(f"load_redis 同步失败: {e}")

def update_task_progress(task_id, total=None, current=None):
    """更新任务进度（下载等场景）"""
    key = task_key(task_id)
    progress_str = r.hget(key, 'progress')
    if progress_str:
        progress = json.loads(progress_str)
    else:
        progress = {'total': 0, 'current': 0}
    if total is not None:
        progress['total'] = total
    if current is not None:
        progress['current'] = current
    r.hset(key, 'progress', json.dumps(progress))
    # 长耗时任务(下载)运行期间持续续期,防止 7 天 TTL 中途过期
    r.expire(key, 7 * 24 * 3600)

users,user_list,blocked_users,admin,user_emails = load_user()
annn = Thread(target=load_redis,daemon=True)
annn.start()
# ==================== 全局 HTML 模板 ====================
HTML_TEMPLATE = ""

def get_hash(path,task_id,cancel_check):
    n = hashlib.sha256()
    with open(path,'rb') as b:
        for chunk in iter(lambda: b.read(1024*1024*10), b''):
            n.update(chunk)
            if cancel_check():
                raise Cancelled("cancel")

    return True,str(n.hexdigest())



def load_html():
    global HTML_TEMPLATE
    try:
        with open(HTML_FILE, "r", encoding="utf-8") as f:
            HTML_TEMPLATE = f.read()
    except Exception as e:
        print(f"[WARN] 无法加载模板 {HTML_FILE}: {e}")
        HTML_TEMPLATE = "<h1>模板加载失败，请联系管理员</h1>"

load_html()
logging.info("html load ok")

# ==================== 后台线程 ====================
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
                print("[INFO] 模板已热重载")
        except Exception as e:
            print(f"[WARN] 模板重载异常: {e}")

if not app.debug:
    bg_thread = Thread(target=background_tasks, daemon=True)
    bg_thread.start()

# ==================== 工具函数 ====================
def _is_api_request():
    return (request.is_json or
            request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
            request.path.startswith('/api/'))

def _reject(msg, status=403):
    if _is_api_request():
        return jsonify({'success': False, 'error': msg}), status
    return msg, status

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        with _user_lock:
            valid = ('user_id' in session) and (session.get('user_id') in users)
        if not valid:
            if _is_api_request():
                return jsonify({'success': False, 'error': '请先登录'}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return wrap

def is_allowed(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        with _user_lock:
            blocked = list(blocked_users)
        if session.get('user_id') in blocked:
            return _reject('no admin', 403)
        return f(*args, **kwargs)
    return wrap

def is_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get('user_id') == admin:
            return f(*args, **kwargs)
        return _reject('no admin', 403)
    return wrap


def _personal_root(username):
    """个人盘根目录:PRIVATE_ROOT/<用户名>/。"""
    name = clean_filename(username or 'unknown')
    return os.path.join(PRIVATE_ROOT, name)

def _current_root():
    """当前请求的盘根(共享盘或个人盘),在请求上下文内使用。
    个人盘根目录不存在时自动创建(用户首次进入 /p 即生效)。"""
    if getattr(g, 'scope', 'shared') == 'personal':
        root = _personal_root(session.get('user_id'))
        try:
            os.makedirs(root, exist_ok=True)
        except OSError as e:
            logging.error(f"创建个人盘目录失败: {root} ({e})")
        return root
    return UPLOAD_DIR

def _root_for_scope(scope, username):
    """按 scope 与用户名确定盘根(worker 线程等无请求上下文场景)。"""
    if scope == 'personal':
        return _personal_root(username)
    return UPLOAD_DIR

def _task_root(task_id, default=None):
    """从任务记录读取提交时的盘根(worker 线程内路径解析用)。"""
    t = get_task(task_id)
    root = t.get('root') if t else None
    return root or default or UPLOAD_DIR

def safe_path(*parts, root=None):
    # 无参数或仅传入 '.'/'' 时，直接返回盘根
    if not parts or (len(parts) == 1 and parts[0] in ('.', '')):
        return root or UPLOAD_DIR

    base = root or UPLOAD_DIR
    target = os.path.realpath(os.path.abspath(os.path.join(base, *parts)))
    base_abs = os.path.realpath(base)
    # normcase 处理 Windows 大小写不敏感；os.sep 边界比较防 uploads_evil 之类前缀绕过
    if os.path.normcase(target) == os.path.normcase(base_abs):
        return target
    if os.path.normcase(target).startswith(os.path.normcase(base_abs) + os.sep):
        return target
    raise ValueError("路径越权")

def _share_path_check(path):
    """分享链接下载校验:只防穿越,允许读取共享盘与个人盘任意文件(链接本身 24h 过期)。"""
    real = os.path.realpath(path)
    for base in (UPLOAD_DIR, PRIVATE_ROOT):
        base_real = os.path.realpath(base)
        if os.path.normcase(real) == os.path.normcase(base_real):
            return real
        if os.path.normcase(real).startswith(os.path.normcase(base_real) + os.sep):
            return real
    raise ValueError("路径越权")

def clean_filename(filename):
    if not filename: return "未命名文件"
    if isinstance(filename, bytes):
        try: filename = filename.decode('utf-8')
        except:
            try: filename = filename.decode('gbk')
            except: filename = filename.decode('latin-1')
    name, ext = os.path.splitext(filename)
    illegal = r'[\\/*?:"<>|]'
    name = re.sub(illegal, '', name).strip('. ')
    ext = ext.lstrip('.')
    if not name and not ext: return "未命名文件"
    if not name: return f"未命名文件.{ext}"
    if not ext: return name
    return f"{name}.{ext}"

def _reserve_upload_path(folder, filename):
    """以 O_CREAT|O_EXCL 原子占位，避免并发上传同名互相覆盖；返回 (filepath, fileobj)。"""
    name, ext = os.path.splitext(filename)
    counter = 1
    candidate = filename
    while True:
        path = os.path.join(folder, candidate)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            return path, os.fdopen(fd, 'wb')
        except FileExistsError:
            counter += 1
            candidate = f"{name} ({counter}){ext}" if counter <= 1000 else f"{name}_{int(time.time() * 1000) % 1000000}{ext}"
            continue
        except OSError as e:
            raise ValueError(f"无法创建文件: {e}")

def get_file_info(path):
    try:
        stat = os.stat(path)
        return {'size': stat.st_size, 'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
    except: return None

def _meta_base_for(scope=None):
    """元数据根目录:共享盘 META_DIR,个人盘 META_DIR/private/<用户名>/。"""
    s = scope if scope is not None else getattr(g, 'scope', 'shared')
    if s == 'personal':
        return os.path.join(META_DIR, 'private', str(session.get('user_id') or 'unknown'))
    return META_DIR

def _meta_dir_for(rel_path, scope=None):
    meta_base = _meta_base_for(scope)
    rel_dir = os.path.dirname(rel_path)
    if rel_dir:
        return os.path.join(meta_base, rel_dir)
    return meta_base

def save_meta(rel_path, original_name, size, scope=None):
    rel_path = os.path.normpath(rel_path)   # 防御:消除 ../ 等,避免元数据目录错位
    meta_dir = _meta_dir_for(rel_path, scope)
    os.makedirs(meta_dir, exist_ok=True)
    meta_file = os.path.join(meta_dir, os.path.basename(rel_path) + '.json')
    with open(meta_file, 'w', encoding='utf-8') as f:
        json.dump({
            'original_name': original_name,
            'relative_path': rel_path,
            'size': size,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, f, ensure_ascii=False, indent=2)

def get_meta_path(rel_path, scope=None):
    return os.path.join(_meta_dir_for(rel_path, scope), os.path.basename(rel_path) + '.json')

def sze(file,od,password,task_id, root=None):
    root = root or UPLOAD_DIR
    zp = safe_path(file, root=root)
    if not os.path.isfile(zp):
        raise FileNotFoundError(f"not found:{zp}")
    basename = str(os.path.basename(zp))
    a,b = os.path.splitext(basename)
    if not  a:
        a= "extracted"
    target_base = os.path.join(od,a)
    target_dir = target_base
    counter = 1
    while os.path.exists(target_dir):
        target_dir = f"{target_base} ({counter})"
        counter += 1
        if counter > 1000:
            ts = int(time.time() * 1000) % 1000000
            target_dir = f"{target_base}_{ts}"
            break
    target_dir = os.path.realpath(target_dir)
    # 最终检查确保解压目录仍位于当前盘根下
    root_abs = os.path.realpath(root)
    if not target_dir.startswith(root_abs + os.sep) and target_dir != root_abs:
        raise ValueError("解压目标路径越权")
    os.makedirs(target_dir, exist_ok=True)
    try:
        sece(zp,target_dir,file,password,task_id)
        return True,target_dir
    except Exception as e:
        app.logger.error(f"解压失败: {e}")
        if os.path.exists(target_dir) and not os.listdir(target_dir):
            os.rmdir(target_dir)
        return False,target_dir



def _validate_extract_members(members, target_dir, max_total=50 * 1024**3, max_entries=100000):
    """解压前校验：条目数 / Zip Slip / 累计体积上限；返回条目总数。"""
    total = len(members)
    if total > max_entries:
        raise Exception("解压条目数超限")
    acc = 0
    rt = os.path.realpath(target_dir)
    for member in members:
        name = member.filename
        # 拒绝符号链接条目:7z 解压会真实创建 symlink,链接可指向盘外造成越权读写
        if getattr(member, 'is_symlink', False):
            raise Exception(f"不允许符号链接条目: {name}")
        # 防 Zip Slip 检查
        member_path = os.path.realpath(os.path.join(target_dir, name))
        if not member_path.startswith(rt + os.sep) and member_path != rt:
            raise Exception(f"Zip Slip 攻击检测: {name}")
        # file_size 兼容 zipfile/pyzipper，uncompressed 兼容 py7zr
        size = getattr(member, 'file_size', None) or getattr(member, 'uncompressed', None) or 0
        acc += size
        if acc > max_total:
            raise Exception("解压总大小超限")
    return total

def _extract_loop(zf, members, target_dir, task_id, max_total=50 * 1024**3, max_entries=100000):
    """统一的解压循环（zip/pyzipper）：取消检查 + 逐文件解压 + 进度更新。

    注：py7zr 的 extract 在同一个 SevenZipFile 上多次调用不可靠（CRC 错误），
    7z 请走 sece 的 extractall + 回调方案。
    """
    total = _validate_extract_members(members, target_dir, max_total, max_entries)
    for idx, member in enumerate(members):
        # 每次解压一个文件前检查取消
        if is_cancelled(task_id):  # 直接使用 Redis 检查，因为此处拿不到 cancel_check 闭包
            # 清理已解压的部分
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
            raise Cancelled("解压被取消")
        name = member.filename
        # 目录条目只建目录,不执行 extract(py7zr 的 FileInfo 用 is_directory 标记)
        if name.endswith('/') or getattr(member, 'is_directory', False):
            os.makedirs(os.path.realpath(os.path.join(target_dir, name)), exist_ok=True)
        else:
            zf.extract(member, target_dir)
        # 更新任务进度
        update_task_progress(task_id, total=total, current=idx+1)
    return total

class _SevenZipExtractCallback(ExtractCallback):
    """py7zr 解压进度回调。

    注意：py7zr 的回调在独立的 reporter 线程执行，回调内抛异常无法中断
    解压（异常会被吞掉），因此这里只更新进度，取消改由 _CancelReader 实现。
    """

    def __init__(self, task_id, total):
        self.task_id = task_id
        self.total = total
        self.current = 0

    def report_start_preparation(self):
        pass

    def report_start(self, file_path, processing_bytes):
        self.current += 1
        update_task_progress(self.task_id, total=self.total, current=self.current)

    def report_update(self, decompressed_bytes):
        pass

    def report_end(self, file_path, wrote_bytes):
        pass

    def report_warning(self, message):
        app.logger.warning(f"7z 解压警告: {message}")

    def report_postprocess(self):
        pass


class _CancelReader(io.RawIOBase):
    """包装 7z 文件句柄：每次 read 前检查取消，命中则抛 Cancelled 中断解压。

    py7zr 的 extractall 无法通过回调中断（回调在 reporter 线程执行，异常被吞），
    用文件读取钩子可以真正中止底层解压（Cancelled 为 BaseException，可穿透 py7zr 内部异常处理）。
    """

    def __init__(self, fp, cancel_fn):
        super().__init__()
        self._fp = fp
        self._cancel = cancel_fn

    def readable(self):
        return True

    def seekable(self):
        return True

    def read(self, n=-1):
        if self._cancel():
            raise Cancelled("解压被取消")
        return self._fp.read(n)

    def readinto(self, b):
        if self._cancel():
            raise Cancelled("解压被取消")
        data = self._fp.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def seek(self, offset, whence=0):
        return self._fp.seek(offset, whence)

    def tell(self):
        return self._fp.tell()

    def close(self):
        try:
            if not self.closed:
                self._fp.close()
        finally:
            super().close()


def sece(zp,target_dir,file,password,task_id):
    try:
        with open(zp, "rb") as raw:
            reader = _CancelReader(raw, lambda: is_cancelled(task_id))
            with SevenZipFile(reader, mode="r", password=password) as zf:
                members = zf.list()
                total = _validate_extract_members(members, target_dir)
                # py7zr 需单次 extractall（多次 extract 会 CRC 失败）
                zf.extractall(target_dir, callback=_SevenZipExtractCallback(task_id, total))
        app.logger.info(f"解压完成: {file} -> {target_dir}")
    except Cancelled:
        # 取消：清理已解压的部分，与原 _extract_loop 行为一致
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
        raise
    except Exception as e:
        save_task(task_id, {'error': str(e)})
        raise e
        




def zipe(file: str, dir,password,task_id, root=None):
    """解压 ZIP 文件，并防止 Zip Slip 攻击"""
    root = root or UPLOAD_DIR
    zip_path = safe_path(file, root=root)
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(f"文件不存在: {file}")
    basename = os.path.basename(zip_path)
    if basename.lower().endswith('.zip'):
        dir_name = basename[:-4]
    else:
        dir_name = basename
    if not dir_name:
        dir_name = "extracted"
    # dir 已经是 safe_path 的结果，保证在 UPLOAD_DIR 内
    target_base = os.path.join(dir, dir_name)
    target_dir = target_base
    counter = 1
    while os.path.exists(target_dir):
        target_dir = f"{target_base} ({counter})"
        counter += 1
        if counter > 1000:
            ts = int(time.time() * 1000) % 1000000
            target_dir = f"{target_base}_{ts}"
            break
    target_dir = os.path.realpath(target_dir)
    # 最终检查确保解压目录仍位于当前盘根下
    root_abs = os.path.realpath(root)
    if not target_dir.startswith(root_abs + os.sep) and target_dir != root_abs:
        raise ValueError("解压目标路径越权")
    os.makedirs(target_dir, exist_ok=True)
    try:
        if password == "":
            zce(zip_path,target_dir,file,task_id)
        else:zece(zip_path,target_dir,file,password.encode(),task_id)
        return True
    except Exception as e:
        app.logger.error(f"解压失败: {e}")
        if os.path.exists(target_dir) and not os.listdir(target_dir):
            os.rmdir(target_dir)
        raise e

def zce(zip_path, target_dir, file, task_id):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            _extract_loop(zf, zf.infolist(), target_dir, task_id)
        app.logger.info(f"解压完成: {file} -> {target_dir}")
    except Exception as e:
        save_task(task_id, {'error': str(e)})
        raise e

def zece(zip_path,target_dir,file,password,task_id):
    try:
        with pyzipper.AESZipFile(zip_path, 'r') as zf:
            zf.setpassword(password)
            _extract_loop(zf, zf.infolist(), target_dir, task_id)
        app.logger.info(f"解压完成: {file} -> {target_dir}")
    except Exception as e:
        save_task(task_id, {'error': str(e)})
        raise e

def _is_blocked_ip(ip_str):
    """SSRF 防护：判断 IP 是否为内网/回环/链路本地/保留/组播等禁止访问的地址"""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)

def _check_url_host(url):
    """SSRF 校验单个 URL：scheme 合法、有 host、解析出的地址均非内网/私网/回环等禁访地址。"""
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"不支持的协议: {parsed.scheme}")
    host = parsed.hostname
    if not host:
        raise ValueError("URL 缺少主机名")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError(f"无法解析主机: {host}")
    if any(_is_blocked_ip(info[4][0]) for info in infos):
        raise ValueError(f"禁止下载内网/私网地址: {host}")
    return parsed

# TLS 校验可配置（默认关闭以兼容自签名内网场景，建议生产开启）
DOWNLOAD_VERIFY_TLS = os.environ.get('DOWNLOAD_VERIFY_TLS', '0') == '1'
DOWNLOAD_MAX_REDIRECTS = 5

def _pin_host(url):
    """解析并固定 IP:返回 (pinned_url, host_header)。

    先按 _check_url_host 校验解析出的所有地址均为公网,再取第一个公网 IP 直连,
    并携带原始 Host 头。请求阶段不再查 DNS,彻底杜绝 DNS 重绑定(T-O-A)绕过。
    注意:HTTPS 走 IP 直连时 SNI/证书校验会失效,请配合 DOWNLOAD_VERIFY_TLS=0 使用;
    若需要严格 TLS 校验,应改用受控 DNS(内网 DNS 或固定 hosts)。"""
    parsed = _check_url_host(url)
    default_port = 443 if parsed.scheme == 'https' else 80
    port = parsed.port or default_port
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"无法解析主机: {parsed.hostname}")
    ips = [info[4][0] for info in infos if not _is_blocked_ip(info[4][0])]
    if not ips:
        raise ValueError(f"禁止下载内网/私网地址: {parsed.hostname}")
    ip = ips[0]
    host_header = parsed.hostname
    if parsed.port:
        host_header += f":{parsed.port}"
    netloc = f"[{ip}]" if ':' in ip else ip
    if port != default_port:
        netloc += f":{port}"
    # 注意:ParseResult 只有 netloc 是字段,hostname/port 是派生属性,不能 _replace
    pinned = parsed._replace(netloc=netloc).geturl()
    return pinned, host_header

def download(url, dir, task_id, cancel_check):
    filepath = None
    try:
        # 逐跳 SSRF 校验 + 固定 IP 直连(防 DNS 重绑定):requests 默认跟随重定向,
        # 只查首跳会被重定向绕过,故手动逐跳处理,每一跳都重新校验并重新固定 IP
        current = url
        with requests.Session() as s:
            for _ in range(DOWNLOAD_MAX_REDIRECTS + 1):
                pinned, host_header = _pin_host(current)
                resp = s.get(pinned, headers={'Host': host_header}, stream=True,
                             timeout=(10, 30), verify=DOWNLOAD_VERIFY_TLS,
                             allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get('Location')
                    resp.close()
                    if not loc:
                        raise ValueError("重定向响应缺少 Location")
                    current = urljoin(current, loc)
                    continue
                resp.raise_for_status()
                break
            else:
                raise ValueError("重定向次数超限")
            try:
                total = int(resp.headers.get('content-length') or 0)
            except (TypeError, ValueError):
                total = 0
            if total < 0:
                total = 0
            if DOWNLOAD_MAX_SIZE and total > DOWNLOAD_MAX_SIZE:
                resp.close()
                raise ValueError(f"文件过大(超过 {DOWNLOAD_MAX_SIZE} 字节)")
            filename = clean_filename(get_filename_from_url(current))
            filepath = os.path.join(dir, filename)   # dir 是调用方算好的盘根(绝对路径)
            update_task_progress(task_id, total=total, current=0)
            last_cancel_check = time.time()
            last_progress_update = time.time()

            with open(filepath, 'wb') as f:
                downloaded = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    now = time.time()
                    # 取消检查节流：每 0.2 秒一次，避免每 8KB 一次高频 Redis 请求
                    if now - last_cancel_check >= 0.2:
                        last_cancel_check = now
                        if cancel_check():
                            resp.close()
                            raise Exception("下载被取消")
                    if chunk:
                        if DOWNLOAD_MAX_SIZE and downloaded + len(chunk) > DOWNLOAD_MAX_SIZE:
                            resp.close()
                            raise ValueError(f"下载超过大小上限 {DOWNLOAD_MAX_SIZE} 字节")
                        f.write(chunk)
                        downloaded += len(chunk)
                        # 进度更新节流：每 0.5 秒一次
                        if now - last_progress_update >= 0.5:
                            update_task_progress(task_id, current=downloaded)
                            last_progress_update = now
                # 收尾时更新最终进度
                update_task_progress(task_id, current=downloaded)
        return True
    except Exception as e:
        logging.error(f"下载错误: {e}")
        save_task(task_id,{'error':str(e)})
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        raise

# ==================== 模板 ====================
LOGIN_TEMPLATE = '''
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>登录</title>
<style>body{font-family:sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px}
h2{margin-bottom:20px;color:#2c3e50;text-align:center}
input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:10px;background:#3498db;color:#fff;border:none;border-radius:4px;cursor:pointer}
.error{background:#f8d7da;color:#721c24;padding:10px;border-radius:4px;margin-bottom:15px}
.info{background:#d4edda;color:#155724;padding:10px;border-radius:4px;margin-bottom:15px}
.mute{margin-top:12px;text-align:center;font-size:13px;color:#666}
a{color:#3498db;text-decoration:none}</style></head>
<body><div class="login"><h2>登录</h2>
{% if reset_ok %}<div class="info">密码已重置,请用新密码登录</div>{% endif %}
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<input name="username" placeholder="用户名" required autofocus>
<input type="password" name="password" placeholder="密码" required>
<button type="submit">登录</button></form>
<div class="mute"><a href="{{ url_for('forgot') }}">忘记密码?</a></div>
</div></body></html>
'''

FORGOT_TEMPLATE = '''
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>找回密码</title>
<style>body{font-family:sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px}
h2{margin-bottom:20px;color:#2c3e50;text-align:center}
input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:10px;background:#3498db;color:#fff;border:none;border-radius:4px;cursor:pointer}
.error{background:#f8d7da;color:#721c24;padding:10px;border-radius:4px;margin-bottom:15px}
.info{background:#d4edda;color:#155724;padding:10px;border-radius:4px;margin-bottom:15px}
.mute{margin-top:12px;text-align:center;font-size:13px;color:#666}
a{color:#3498db;text-decoration:none}</style></head>
<body><div class="login"><h2>找回密码</h2>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
{% if msg %}<div class="info">{{ msg }}</div>{% endif %}
{% if not sent %}
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<input name="account" placeholder="用户名 或 注册邮箱" required autofocus>
<button type="submit">发送重置链接</button></form>
{% endif %}
<div class="mute"><a href="{{ url_for('login') }}">返回登录</a></div>
</div></body></html>
'''

RESET_TEMPLATE = '''
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>重置密码</title>
<style>body{font-family:sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px}
h2{margin-bottom:20px;color:#2c3e50;text-align:center}
input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:10px;background:#3498db;color:#fff;border:none;border-radius:4px;cursor:pointer}
.error{background:#f8d7da;color:#721c24;padding:10px;border-radius:4px;margin-bottom:15px}
.mute{margin-top:12px;text-align:center;font-size:13px;color:#666}
a{color:#3498db;text-decoration:none}</style></head>
<body><div class="login"><h2>重置密码</h2>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<input type="hidden" name="token" value="{{ token }}">
<input type="password" name="password" placeholder="新密码(至少8位)" required minlength="8" autofocus>
<input type="password" name="confirm" placeholder="确认新密码" required minlength="8">
<button type="submit">重置密码</button></form>
<div class="mute"><a href="{{ url_for('login') }}">返回登录</a></div>
</div></body></html>
'''


# ==================== 路由 ====================
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    logging.info(f"user logining.from {request.remote_addr}")
    error = None
    reset_ok = request.args.get('reset')
    if request.method == 'POST':
        ip = _client_ip() or 'unknown'
        fail_key = f'login_fail:{ip}'
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        # IP 限流 + 账号限流:防止分布式 IP 轮换绕过
        acct_key = f'login_fail_u:{username.lower()}' if username else ''
        if int(r.get(fail_key) or 0) >= 5 or (acct_key and int(r.get(acct_key) or 0) >= 5):
            error = '尝试次数过多，请10分钟后再试'
            return render_template_string(LOGIN_TEMPLATE, error=error)
        with _user_lock:
            stored = users.get(username, '')
        if stored and check_password_hash(stored, password):
            session.clear()   # 防 session 固定攻击：登录前废弃旧会话
            session['user_id'] = username
            r.delete(fail_key)
            if acct_key:
                r.delete(acct_key)
            return redirect(_safe_next(request.args.get('next')))
        error = '用户名或密码错误'
        r.incr(fail_key)
        r.expire(fail_key, 600)
        if acct_key:
            r.incr(acct_key)
            r.expire(acct_key, 600)
        logging.warning(f"user login failure.from {request.remote_addr} user:{username}")
    return render_template_string(LOGIN_TEMPLATE, error=error, reset_ok=reset_ok)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    logging.info("user logout")
    return redirect(url_for('login'))

def _send_mail(to_addr, subject, text, html=None):
    """通过 Resend API 发送邮件(DKIM/SPF 由 Resend 处理,免维护 SMTP)"""
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY 未配置")
    payload = {
        "from": MAIL_FROM,
        "to": [to_addr],
        "subject": subject,
        "text": text,
    }
    if html:
        payload["html"] = html
    resp = requests.post("https://api.resend.com/emails",
                         headers={"Authorization": "Bearer " + RESEND_API_KEY},
                         json=payload, timeout=15)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Resend 发送失败: HTTP {resp.status_code} {resp.text[:200]}")
    return resp.json()


def _send_reset_mail(username, mail):
    """生成一次性重置 token 并发邮件,链接 30 分钟内有效"""
    token = secrets.token_urlsafe(32)
    r.set(RESET_TOKEN_PREFIX + token, username)
    r.expire(RESET_TOKEN_PREFIX + token, RESET_TOKEN_TTL)
    link = f"{SITE_URL}/reset?token={token}"
    subject = "重置密码 - 文件管理系统"
    text = (
        f"你好, {username}:\n\n"
        f"你正在申请重置密码。请在 30 分钟内打开以下链接完成重置:\n\n"
        f"{link}\n\n"
        f"如果这不是你的操作,请忽略本邮件,你的密码不会被修改。\n"
        f"-- {SITE_URL}"
    )
    html = (
        f"<p>你好, <b>{username}</b>:</p>"
        f"<p>你正在申请重置密码,请在 30 分钟内点击以下链接完成重置:</p>"
        f'<p><a href="{link}">{link}</a></p>'
        f"<p>如果这不是你的操作,请忽略本邮件,你的密码不会被修改。</p>"
    )
    _send_mail(mail, subject, text, html)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    """忘记密码:输入用户名或绑定邮箱,发送重置链接(不暴露账号是否存在)"""
    error = None
    if request.method == 'POST':
        ip = _client_ip() or 'unknown'
        fail_key = f'forgot_fail:{ip}'
        if int(r.get(fail_key) or 0) >= 5:
            error = '尝试次数过多,请10分钟后再试'
            return render_template_string(FORGOT_TEMPLATE, error=error, msg=None, sent=False)
        # 无论账号是否存在都计数,同时防枚举与防轰炸
        r.incr(fail_key)
        r.expire(fail_key, 600)
        account = request.form.get('account', '').strip()
        with _user_lock:
            username = account if account in users else None
            mail = user_emails.get(username, '') if username else ''
            if not mail:
                # 支持直接用绑定邮箱反查用户名
                for uname, umail in list(user_emails.items()):
                    if umail.lower() == account.lower():
                        username, mail = uname, umail
                        break
        if username and mail and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', mail):
            # 异步发送:Resend API 最坏阻塞 15s,不该卡住请求线程
            try:
                Thread(target=_send_reset_mail, args=(username, mail), daemon=True).start()
            except Exception as e:
                logging.error(f"重置邮件线程启动失败: user={username} err={e}")
        # 统一提示,避免用户枚举
        msg = "如果该账号存在且绑定了邮箱,重置链接已发送,请查收(30分钟内有效)。"
        return render_template_string(FORGOT_TEMPLATE, error=None, msg=msg, sent=True)
    return render_template_string(FORGOT_TEMPLATE, error=None, msg=None, sent=False)


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
            username = r.get(RESET_TOKEN_PREFIX + token)
            if not username:
                error = '链接无效或已过期,请重新申请'
            else:
                with _user_lock:
                    users[username] = generate_password_hash(password)
                save_user()
                r.delete(RESET_TOKEN_PREFIX + token)   # 一次性:用完即失效
                logging.info(f"password reset ok: {username}")
                return redirect(url_for('login', reset=1))
        return render_template_string(RESET_TEMPLATE, error=error, token=token)
    token = request.args.get('token', '')
    if not r.get(RESET_TOKEN_PREFIX + token):
        return render_template_string(RESET_TEMPLATE, error='链接无效或已过期,请重新申请', token='')
    return render_template_string(RESET_TEMPLATE, error=None, token=token)


@app.route("/api/loginok")
def loginok():
    name = ""
    lo = False
    la =False
    if "user_id" in session:
        lo = True
        name = session.get("user_id")
        la = session.get("user_id") == admin
        with _user_lock:
            blocked = list(blocked_users)
        if session.get("user_id") in blocked:
            la = False
    return jsonify({"login":lo,"admin":la,"name":name})

@app.route('/check')
def admin_or_no_user():
    with _user_lock:
        valid = ('user_id' in session) and (session.get('user_id') in users)
    if not valid:return 'Non-user',401
    else:
        if session.get('user_id') == admin:
            return 'admin',200
        else:return 'user',403

@app.route("/api/gdl")
@login_required
@is_allowed
def get_download_list():
    keys = r.scan_iter(match=f"{TASK_PREFIX}*")
    tids = []
    for key in keys:
        if isinstance(key, bytes):
            tid = key.decode().split(':', 1)[-1]
        else:
            tid = key.split(':', 1)[-1]
        tids.append(tid)
    all_tasks = get_tasks_bulk(tids)  # pipeline 批量读，避免逐 key N+1
    running_downloads = []
    is_owner_view = session.get('user_id') != admin
    for tid, task in all_tasks.items():
        if str(task.get('tool_id')) == str(TOOL_DOWNLOAD) and task.get('status') == 'running':
            # 非管理员只能看到自己的下载任务
            if is_owner_view and task.get('owner') != session.get('user_id'):
                continue
            running_downloads.append(tid)
    return jsonify(running_downloads), 200
            
@app.route("/api/dl")
@login_required
@is_allowed
def get_task_list_all():
    # 获取 Redis 中所有任务
    keys = r.scan_iter(match=f"{TASK_PREFIX}*")
    tasks = {}
    allowed_types = (str, int, float, bool, list, dict)
    tids = []
    for key in keys:
        # key 格式为 task:uuid
        if isinstance(key, bytes):
            tid = key.decode().split(':', 1)[-1]
        else:
            tid = key.split(':', 1)[-1]
        tids.append(tid)
    all_tasks = get_tasks_bulk(tids)  # pipeline 批量读，避免 N+1
    is_owner_view = session.get('user_id') != admin
    for tid, task in all_tasks.items():
        # 非管理员只能看到自己的任务
        if is_owner_view and task.get('owner') != session.get('user_id'):
            continue
        # 过滤不可序列化字段，保持与原 /api/dl 一致
        filtered = {}
        for k, v in task.items():
            if isinstance(v, allowed_types) or v is None:
                filtered[k] = v
        tasks[tid] = filtered
    return jsonify(tasks)

@app.route('/file/hash',methods=['POST'])
@login_required
@is_allowed
def call_hash():
    limit_resp = _check_pending_limit()
    if limit_resp:
        return limit_resp
    a = request.json
    try:
        ah = a.get('path',"")
        sp = safe_path(ah, root=_current_root())
        
    except Exception as d:
        logging.error(str(d))
        n = jsonify({'success':False})
        n.status_code = 400
        return n
    func = get_hash

    task_id = str(uuid.uuid4())
    tool_id = TOOL_HASH
    
    save_task(task_id,{
                'status': 'pending',
                'error': '',
                'tool_id': tool_id,
                'progress': {'total': 0, 'current': 0},
                'file_info':{'src':sp},
                'owner': session.get('user_id', ''),
                'root': _current_root(),
                'path': os.path.dirname(os.path.abspath(sp))
            })
    arg_list = (sp,)
    task_queue.put((task_id, func, arg_list, tool_id))
    return jsonify({'success':True,'task_id':task_id})
    




_index_template_cache = {}

def _index_template():
    """编译并缓存首页模板(避免每个请求重新解析 Jinja)。"""
    tpl = HTML_TEMPLATE
    if app.debug:
        # 调试链接在渲染期追加,避免热重载时反复拼接
        tpl += "<br/>\n<a href=\"/api/new\">new</a>"
    if tpl not in _index_template_cache:
        _index_template_cache[tpl] = app.jinja_env.from_string(tpl)
    return _index_template_cache[tpl]

@app.route('/')
@login_required
def index():
    return _index_template().render(username=session.get('user_id',''))

@app.route('/api/task/<task_id>', methods=['GET'])
@is_allowed
@login_required
def get_task_status(task_id):

    task = get_task(task_id)
    if not task:
        return jsonify({'success': False, 'error': '无效任务ID'}), 404
    if not _can_access_task(task):
        return jsonify({'success': False, 'error': '无权访问该任务'}), 403

    a = {}
    # 注意：bytes/bytearray 无法被 jsonify 序列化，会直接 500
    n = [str, int, list, dict, bool, float]
    for aa,x in task.items():
        if type(x) in n:
            a[aa] = x
    a['success'] =True

    return jsonify(a)


@app.route('/api/task/<task_id>/cancel', methods=['POST'])
@login_required
@is_allowed
def cancel_task(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({'success': False, 'error': '无效任务ID'}), 404
    if not _can_access_task(task):
        return jsonify({'success': False, 'error': '无权操作该任务'}), 403
    success = cancel_task_by_id(task_id)
    if not success:
        return jsonify({'success': False, 'error': '任务无法取消'}), 400
    return jsonify({'success': True})

@app.route('/api/task/<task_id>/delete', methods=['POST'])
@login_required
@is_allowed
def webdelete_task(task_id):
    task = get_task(task_id)          # 直接获取任务对象
    if not task:
        return jsonify({'success': False, 'error': '无效任务ID'}), 404
    if not _can_access_task(task):
        return jsonify({'success': False, 'error': '无权操作该任务'}), 403
    status = task.get('status', '')
    if status == 'running':
        return jsonify({'success': False, 'error': '任务正在运行，无法删除'}), 403
    elif status == 'pending':
        return jsonify({'success': False, 'error': '任务仍在队列中，无法删除'}), 403
    else:
        delete_task(task_id)
        return jsonify({'success': True})
    

@app.route("/file/move", methods=['POST'])
@is_allowed
@login_required
def call_move():
    limit_resp = _check_pending_limit()
    if limit_resp:
        return limit_resp
    try:
        data = request.get_json()
        if not data:
            abort(400)
        source = data["source"]
        target = data["target"]
    
    except (KeyError, TypeError):
        abort(400)
    func = move_file

    task_id = str(uuid.uuid4())
    tool_id = TOOL_MOVE

    save_task(task_id,{
            'status': 'pending',
            'error': '',
            'tool_id': tool_id,
            'progress': {'total': 0, 'current': 0},

            'file_info':{'src':source,'dst':resolve_target_path(safe_path(source, root=_current_root()), target)},
            'owner': session.get('user_id', ''),
            'root': _current_root(),
            'path': os.path.dirname(os.path.abspath(source))
        })
    arg_list = (source,target)
    task_queue.put((task_id, func, arg_list, tool_id))
    return jsonify({'success':True,'task_id':task_id})

def move_file(source, target, task_id, cancel_check):
    try:
        root = _task_root(task_id)
        src = safe_path(source, root=root)
        dst = resolve_target_path(src, target, root=root)
    except ValueError as e:
        save_task(task_id, {'error': str(e)})
        return False
    # 同盘且目标不存在的单文件优先原子 rename(瞬间完成);否则回退复制+删除(支持取消)
    if os.path.isfile(src) and not os.path.exists(dst):
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(src, dst)
            return True
        except OSError:
            pass
    # 复制成功后删除源
    if copy_file(source, target, task_id, cancel_check):
        if os.path.isdir(src):
            shutil.rmtree(src)
        else:
            os.remove(src)
        return True
    return False

        
@app.route("/file/copy", methods=['POST'])
@is_allowed
@login_required
def call_copy():
    limit_resp = _check_pending_limit()
    if limit_resp:
        return limit_resp
    try:
        data = request.get_json()
        if not data:
            abort(400)
        source = data["source"]
        target = data["target"]
    
    except (KeyError, TypeError):
        abort(400)
    func = copy_file

    task_id = str(uuid.uuid4())
    tool_id = TOOL_COPY

    save_task(task_id,{
            'status': 'pending',
            'error': '',
            'tool_id': tool_id,
            'progress': {'total': 0, 'current': 0},

            'file_info':{'src':source,'dst':target},
            'owner': session.get('user_id', ''),
            'root': _current_root(),
            'path': os.path.dirname(os.path.abspath(source))
        })
    arg_list = (source,target)
    task_queue.put((task_id, func, arg_list, tool_id))
    return jsonify({'success':True,'task_id':task_id})




def _copy_chunked(src, dst, cancel_check):
    """分块复制单个文件,每 1MB 检查一次取消;取消抛 Cancelled 由调用方清理。"""
    with open(src, 'rb') as f_in, open(dst, 'wb') as f_out:
        while True:
            if cancel_check():
                raise Cancelled("复制被取消")
            chunk = f_in.read(1024 * 1024)  # 1MB 块
            if not chunk:
                break
            f_out.write(chunk)


def copy_file(source, target, task_id, cancel_check):
    try:
        root = _task_root(task_id)
        src = safe_path(source, root=root)
        dst = resolve_target_path(src, target, root=root)
    except ValueError as e:
        save_task(task_id, {'error': str(e)})
        return False

    if not os.path.exists(src):
        save_task(task_id, {'error': '源路径不存在'})
        return False

    try:
        if os.path.isfile(src):
            # 确保目标目录存在
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                _copy_chunked(src, dst, cancel_check)
            except Cancelled:
                # 取消时删除未完成的目标文件
                if os.path.exists(dst):
                    os.remove(dst)
                raise
        elif os.path.isdir(src):
            # 递归复制目录:遍历目录树,每个文件走同一分块复制逻辑(可取消)
            for root, dirs, files in os.walk(src):
                if cancel_check():
                    # 清理已复制的内容
                    if os.path.exists(dst):
                        shutil.rmtree(dst, ignore_errors=True)
                    raise Cancelled("复制被取消")
                rel_path = os.path.relpath(root, src)
                dest_root = os.path.join(dst, rel_path)
                os.makedirs(dest_root, exist_ok=True)
                for file in files:
                    if cancel_check():
                        if os.path.exists(dst):
                            shutil.rmtree(dst, ignore_errors=True)
                        raise Cancelled("复制被取消")
                    src_file = os.path.join(root, file)
                    dst_file = os.path.join(dest_root, file)
                    try:
                        _copy_chunked(src_file, dst_file, cancel_check)
                    except Cancelled:
                        if os.path.exists(dst):
                            shutil.rmtree(dst, ignore_errors=True)
                        raise
        else:
            save_task(task_id, {'error': '源路径类型未知'})
            return False
        return True
    except Exception as e:
        traceback.print_exc()
        save_task(task_id, {'error': str(e)})
        return False

    
@app.route('/file/zipex',methods=['POST'])
@login_required
@is_allowed
def call_ze():
    limit_resp = _check_pending_limit()
    if limit_resp:
        return limit_resp
    try:
        a = request.get_json(silent=True) or {}
        f = a['path']
        user_dir = a.get('outpath', '')
        if user_dir == "":
            user_dir = os.path.dirname(safe_path(f, root=_current_root()))
        password = a.get('password','')
    
        sp = resolve_target_path(safe_path(f, root=_current_root()), user_dir)
    except (KeyError, TypeError, ValueError) as e:
        logging.error(str(e))
        abort(400)
    func = zip_ex

    task_id = str(uuid.uuid4())
    tool_id = TOOL_UNZIP
    save_task(task_id, {
                'status': 'pending',
                'error': '',
                'tool_id': tool_id,
                'progress': {'total': 0, 'current': 0},
                                                'file_info':{'src':f,'dst':sp},
                'owner': session.get('user_id', ''),
                'root': _current_root(),
                'path': os.path.dirname(os.path.abspath(f))
            })
    arg_list = (f,sp,password)
    task_queue.put((task_id, func, arg_list, tool_id))
    return jsonify({'success':True,'task_id':task_id})
    

def zip_ex(f,sp,password,task_id,cancel_check):
   


    f =safe_path(f, root=_task_root(task_id))
    if not os.path.exists(f):
        
        return False
    

    _,n = os.path.splitext(f)
    try:
        if n == ".zip":
            a = zipe(f,sp,password,task_id, root=_task_root(task_id))
        elif n == '.7z':
            # sze 返回 (是否成功, 解压目录) 元组,不能整体当布尔用
            ok, _ = sze(f,sp,password,task_id, root=_task_root(task_id))
            a = ok

        else:
            save_task(task_id,{'error':'not found'})
            return False
        if not a:
            task = get_task(task_id)
            if not task or task.get('error') == '':
                save_task(task_id, {'error': 'error'})
            return False

        return True
    except Exception as e:
        traceback.print_exc()
        logging.error(str(e))
        save_task(task_id,{'error':e})
        return False


def resolve_target_path(src_abs: str, target: str, root: str = None) -> str:
    """
    将目标路径 target 解析为绝对路径。
    如果 target 是相对路径，则相对于 src_abs 的目录解析；
    如果 target 是绝对路径，则直接使用（但会检查是否在当前盘根内）。
    root 缺省时按 src_abs 前缀自动推断所属盘根(个人盘取 <用户名> 这一层,
    防止 ../ 跨用户)。
    """
    if not target:
        raise ValueError("目标路径不能为空")
    src_dir = os.path.dirname(src_abs)
    if os.path.isabs(target):
        target_abs = os.path.abspath(target)
    else:
        target_abs = os.path.abspath(os.path.join(src_dir, target))

    if root is None:
        # 按 src_abs 前缀推断盘根
        src_real = os.path.realpath(src_abs)
        priv_real = os.path.realpath(PRIVATE_ROOT)
        if os.path.normcase(src_real).startswith(os.path.normcase(priv_real) + os.sep):
            rest = src_real[len(priv_real):].lstrip(os.sep)
            user_part = rest.split(os.sep, 1)[0] if rest else ''
            root = os.path.join(priv_real, user_part) if user_part else priv_real
        else:
            root = UPLOAD_DIR

    target_abs = os.path.realpath(target_abs)
    root_abs = os.path.realpath(root)
    # normcase + os.sep 边界比较，防前缀绕过与大小写绕过
    if os.path.normcase(target_abs) == os.path.normcase(root_abs):
        return target_abs
    if os.path.normcase(target_abs).startswith(os.path.normcase(root_abs) + os.sep):
        return target_abs
    raise ValueError(f"目标路径越权;{target_abs};{root_abs};{sys.platform}")


@app.route('/api/disk_usage')
@is_allowed
@login_required
def get_du():
    a,b,c = shutil.disk_usage(UPLOAD_DIR)
    return jsonify({'total':a,"used":b,"free":c})


@app.route("/api/toolcall", methods=['POST'])
@is_allowed
@login_required
def call_tool():
    
    limit_resp = _check_pending_limit()
    if limit_resp:
        return limit_resp
    try:
        a = request.json
        a=dict(a)
        logging.info(f"call_tool {a}")
        tool_id = a.get("tool")
        args_raw = a.get("args", "").strip()



        def clean_arg(s):
            s = s.replace('\\', '/').strip().strip("'\"")
            if s.lower().startswith('uploads/'):
                s = s[len('uploads/'):]
            elif s.lower() == 'uploads':
                s = ''
            if s == '.':
                s = ''
            return s

        clean = clean_arg(args_raw)

        user_dir = a.get('path', '')
        
        root = _current_root()
        safe_dir = safe_path(user_dir, root=root) if user_dir else root
        if tool_id == TOOL_ASSEMBLY:   # 合成文件
            func = tool.u2.call
            arg_list = (safe_path(clean, root=root), safe_dir)
        elif tool_id == TOOL_CUT: # 分割文件
            m = re.search(r'-c\s+(\S+)\s+-f\s+(.+)', args_raw.strip())
            if not m:
                return jsonify({'success': False, 'error': '参数格式错误'}), 400
            try:
                chunk_size = int(m.group(1))
            except ValueError:
                return jsonify({'success': False, 'error': '块大小必须为整数'}), 400
            if not (1 <= chunk_size <= 1024 ** 3):
                return jsonify({'success': False, 'error': '块大小超出允许范围(1~1GB)'}), 400
            file_path = m.group(2)
            fp_clean = clean_arg(file_path)
            func = tool.u1.call
            arg_list = (safe_path(fp_clean, root=root), chunk_size,
                        os.path.join(safe_dir,os.path.basename(fp_clean)+"_cut"))
        elif tool_id == TOOL_INFO:
            return jsonify({'success': True, 'message': '使用Assembly以合成文件\n使用cut以分割文件,用法 -c 分割块大小 -f 文件(从根目录起)'}), 201
        
        elif tool_id == TOOL_DOWNLOAD:
            if session.get('user_id') == admin:
                func = download
                arg_list = (clean,safe_dir)  
            else:return jsonify({'success': False, 'error': 'no admin'}), 403

        else:
            return jsonify({'success': False, 'error': '未知工具'}), 404

        task_id = str(uuid.uuid4())
        save_task(task_id,{
                'status': 'pending',
                'error': '',
                'tool_id': tool_id,
                'progress': {'total': 0, 'current': 0},
                'owner': session.get('user_id', ''),
                'root': root,
                'path': a.get("path")
            })
        task_queue.put((task_id, func, arg_list, tool_id))
        return jsonify({'success': True, 'task_id': task_id}), 202

    except Exception as e:
        traceback.print_exc()
        logging.error(str(e))
        return jsonify({'success': False, 'error': '服务器内部错误'}), 500

@app.route('/file/upload', methods=['POST'])
@is_allowed
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': '没有选择文件'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': '文件名为空'}), 400
    original = file.filename
    folder = request.form.get('folder', '').strip()
    if clean_filename(original) in RESERVED_NAMES:
        return jsonify({'success': False, 'error': '名称被系统保留'}), 400
    if any(part in RESERVED_NAMES for part in folder.replace('\\', '/').split('/') if part):
        return jsonify({'success': False, 'error': '目录名被系统保留'}), 400
    try:
        target_dir = safe_path(folder, root=_current_root()) if folder else _current_root()
    except ValueError as e:
        return jsonify({'success': False, 'error': f'目录非法: {str(e)}'}), 400
    os.makedirs(target_dir, exist_ok=True)
    filename = clean_filename(original)
    try:
        filepath, out = _reserve_upload_path(target_dir, filename)
    except ValueError as e:
        return jsonify({'success': False, 'error': f'保存失败: {str(e)}'}), 500
    try:
        with out:
            file.save(out)
        size = os.path.getsize(filepath)
        # 相对当前盘根计算(个人盘不能相对 UPLOAD_DIR,否则元数据路径错位)
        rel = os.path.relpath(filepath, _current_root())
        save_meta(rel, original, size, scope=getattr(g, 'scope', 'shared'))
        return jsonify({'success': True, 'data': {'original': original, 'saved': os.path.basename(filepath), 'size': size}})
    except Exception as e:
        traceback.print_exc()
        try:
            os.remove(filepath)
        except OSError:
            pass
        return jsonify({'success': False, 'error': f'保存失败: {str(e)}'}), 500

@app.route("/api/new")
def sssss():
    if app.debug:
        try:
            load_html()
            print("[INFO] 模板已热重载")
        except Exception as e:
            print(f"[WARN] 模板重载异常: {e}")
        return redirect("/")
    else:
        return redirect("/")








@app.route('/api/files')
@login_required
@is_allowed
def list_files():
    rel_path = request.args.get('path', '').strip()
    try:
        target_dir = safe_path(rel_path, root=_current_root()) if rel_path else _current_root()
    except ValueError:
        return jsonify({'success': False, 'error': '非法路径'}), 400
    if not os.path.isdir(target_dir):
        return jsonify({'success': False, 'error': '路径不存在'}), 404
    items = []

    try:
        for name in os.listdir(target_dir):
            if name.startswith('.') or name == 'metadata' or name == 'chunks': continue
            full = os.path.join(target_dir, name)
            is_dir = os.path.isdir(full)
            ext = os.path.splitext(full)[1] if os.path.isfile(full) else ""
            is_archive = ext in ('.zip', '.7z')   # 与 zip_ex 实际支持的格式一致

            info = {} if is_dir else (get_file_info(full) or {})
            items.append({
                'name': name,   # JSON 返回原始名，HTML 转义交给前端
                'type': 'directory' if is_dir else 'file',
                'size': info.get('size', 0),
                'modified': info.get('modified', ''),
                'type_file': ext,
                'type_zip': is_archive
            })
        items.sort(key=lambda x: (0 if x['type']=='directory' else 1, x['name'].lower()))
    except Exception as e:
        logging.error(str(e))
        return jsonify({'success': False, 'error': "see log"}), 500

    return jsonify({'success': True, 'data': items})

@app.route('/api/folders', methods=['POST'])
@is_allowed
@login_required
def create_folder():
    data = request.get_json(silent=True)
    if not data: return jsonify({'success': False, 'error': '无效数据'}), 400
    parent = data.get('path', '').strip()
    name = data.get('name', '').strip()
    if not name: return jsonify({'success': False, 'error': '名称不能为空'}), 400
    if re.search(r'[\\/*?:"<>|]', name):
        return jsonify({'success': False, 'error': '名称包含非法字符'}), 400
    if name in RESERVED_NAMES:
        return jsonify({'success': False, 'error': '名称被系统保留'}), 400
    try:
        parent_dir = safe_path(parent, root=_current_root()) if parent else _current_root()
    except ValueError:
        return jsonify({'success': False, 'error': '父目录非法'}), 400
    new_dir = os.path.join(parent_dir, name)
    if os.path.exists(new_dir):
        return jsonify({'success': False, 'error': '文件夹已存在'}), 409
    try:
        os.makedirs(new_dir)
        return jsonify({'success': True})
    except Exception as e:
        logging.error(str(e))
        return jsonify({'success': False, 'error': "see log"}), 500


@app.route('/api/delete/<path:item_path>', methods=['DELETE'])
@is_allowed
@login_required
def delete_item(item_path):
    try:
        root = _current_root()
        full = safe_path(item_path, root=root)
    except ValueError:
        return jsonify({'success': False, 'error': '路径非法'}), 400
    if not os.path.exists(full):
        return jsonify({'success': False, 'error': '路径不存在'}), 404

    # 在 move 之前记录文件/目录类型，否则 move 后原路径已不存在，判断会失真
    was_file = os.path.isfile(full)

    # 生成唯一ID
    item_id = uuid.uuid4().hex
    trash_dest = os.path.join(TRASH_DIR, item_id)

    try:
        # 移动文件/文件夹到回收站
        shutil.move(full, trash_dest)

        # 记录原始路径（相对路径）、类型、删除时间、所属盘与归属
        scope = getattr(g, 'scope', 'shared')
        rel_path = os.path.relpath(full, root)
        meta = {
            'original_path': rel_path,
            'is_dir': not was_file,
            'delete_time': int(time.time()),
            'scope': scope,
            'owner': session.get('user_id', '')
        }
        r.setex(f"trash:{item_id}", 86400 * 10, json.dumps(meta))  # 10天过期（与 TTL 一致）

        # 删除原有元数据（可选，如果需要恢复元数据请保留）
        # 这里保留原有元数据删除逻辑，因为恢复时会重新生成
        if was_file:
            meta_file = get_meta_path(rel_path, scope=scope)
            if os.path.exists(meta_file):
                os.remove(meta_file)
                meta_dir = os.path.dirname(meta_file)
                if meta_dir != _meta_base_for(scope) and not os.listdir(meta_dir):
                    os.rmdir(meta_dir)
        else:
            meta_dir = _meta_dir_for(rel_path, scope)
            if os.path.exists(meta_dir):
                shutil.rmtree(meta_dir)

        return jsonify({'success': True})
    except Exception as e:
        logging.error(str(e))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/share/share_put', methods=['POST'])
@is_allowed
@login_required
def share_put():
    data = request.json
    file = data.get('file')
    try:
        full = safe_path(file, root=_current_root())
    except ValueError:
        return jsonify({'success': False, 'error': '路径非法'}), 400
    if not os.path.isfile(full):
        return jsonify({'success': False, 'error': '文件不存在'}), 404
    u = str(uuid.uuid4())
    r.setex(f"share:{u}", 86400, full)   # 24小时过期
    host = request.host_url
    return jsonify({'link': host + "share/share_get/" + u})

@app.route('/share/share_get/<path:uuid>')
def down(uuid):
    file_path = r.get(f"share:{uuid}")
    if not file_path:
        abort(404)
    try:
        full = _share_path_check(file_path)
    except ValueError as e:
        abort(404)
    if not os.path.isfile(full): abort(404)
    
    dirname = os.path.dirname(full)
    filename = os.path.basename(full)
    resp = make_response(send_from_directory(dirname, filename, as_attachment=True))
    resp.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(filename)}"
    return resp


@app.route('/api/clear-all', methods=['DELETE'])
@login_required
@is_allowed
@is_admin
def clear_all():
    try:
        for name in os.listdir(UPLOAD_DIR):
            if name == 'metadata' or name == 'chunks': continue
            path = os.path.join(UPLOAD_DIR, name)
            if os.path.isfile(path): os.remove(path)
            else: shutil.rmtree(path)
        if os.path.exists(META_DIR):
            shutil.rmtree(META_DIR)
            os.makedirs(META_DIR, exist_ok=True)
        # 个人盘一并清空(admin 权限)
        for name in os.listdir(PRIVATE_ROOT):
            path = os.path.join(PRIVATE_ROOT, name)
            if os.path.isfile(path): os.remove(path)
            else: shutil.rmtree(path)
        return jsonify({'success': True})
    except Exception as e:
        logging.error(str(e))
        return jsonify({'success': False, 'error':""}), 500

@app.route('/download/<path:file_path>')
@login_required
@is_allowed
def web_download_file(file_path):
    try:
        full = safe_path(file_path, root=_current_root())
    except ValueError:
        abort(404)
    if not os.path.isfile(full): abort(404)
    dirname = os.path.dirname(full)
    filename = os.path.basename(full)
    resp = make_response(send_from_directory(dirname, filename, as_attachment=True))
    resp.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(filename)}"
    return resp


def trash_autoclear():
    n = []
    for name in os.listdir(TRASH_DIR):
        k = r.get(f'trash:{name}')
        if not k:
            trash_path = os.path.join(TRASH_DIR, name)
            if os.path.exists(trash_path):
                if os.path.isdir(trash_path):
                    shutil.rmtree(trash_path)
                else:
                    os.remove(trash_path)
            r.delete(f'trash:{name}')  # 同步清理失效的 Redis 记录
            n.append(name)
    return n
def while_trash_autodelete():
    while True:
        time.sleep(10)
        trash_autoclear()
Thread(target=while_trash_autodelete,daemon=True).start(
)
#---------trash--------------
@app.route('/api/trash/list', methods=['GET'])
@is_allowed
@login_required
def trash_list():
    items = []
    keys = r.scan_iter(match="trash:*")
    is_admin_view = session.get('user_id') == admin
    for key in keys:
        item_id = key.split(':', 1)[-1]
        meta_json = r.get(key)
        if not meta_json:
            continue
        meta = json.loads(meta_json)
        # 非管理员只能看到自己的回收站条目
        if not is_admin_view and meta.get('owner') != session.get('user_id'):
            continue
        trash_path = os.path.join(TRASH_DIR, item_id)
        if not os.path.exists(trash_path):
            r.delete(key)  # 清理无效记录
            continue
        # 获取文件信息
        stat = os.stat(trash_path)
        items.append({
            'id': item_id,
            'original_path': meta['original_path'],
            'is_dir': meta['is_dir'],
            'size': stat.st_size if not meta['is_dir'] else 0,
            'delete_time': meta['delete_time'],
            'name': os.path.basename(meta['original_path'])
        })
    # 按删除时间倒序
    items.sort(key=lambda x: x['delete_time'], reverse=True)
    return jsonify({'success': True, 'data': items})
@app.route('/api/trash/restore/<item_id>', methods=['POST'])
@is_allowed
@login_required
def trash_restore(item_id):
    meta_json = r.get(f"trash:{item_id}")
    if not meta_json:
        return jsonify({'success': False, 'error': '记录不存在'}), 404
    meta = json.loads(meta_json)
    trash_path = os.path.join(TRASH_DIR, item_id)
    if not os.path.exists(trash_path):
        r.delete(f"trash:{item_id}")
        return jsonify({'success': False, 'error': '文件已丢失'}), 404

    original_rel = meta['original_path']
    scope = meta.get('scope', 'shared')
    owner = meta.get('owner') or session.get('user_id')
    # 回收站条目只能由本人或 admin 恢复(个人盘与共享盘一致)
    if owner != session.get('user_id') and session.get('user_id') != admin:
        return jsonify({'success': False, 'error': '无权恢复该文件'}), 403
    root = _root_for_scope(scope, owner)
    target_full = safe_path(original_rel, root=root)  # 验证路径安全

    # 如果原路径已存在，则自动重命名（加“_恢复”后缀）
    if os.path.exists(target_full):
        base, ext = os.path.splitext(target_full)
        counter = 1
        while os.path.exists(f"{base}_恢复{counter}{ext}"):
            counter += 1
        target_full = f"{base}_恢复{counter}{ext}"
        # 更新原始路径（用于后续元数据,相对所属盘根;个人盘不能相对 UPLOAD_DIR）
        original_rel = os.path.relpath(target_full, root)

    try:
        # 移动回原位置
        shutil.move(trash_path, target_full)
        # 删除 Redis 记录
        r.delete(f"trash:{item_id}")
        # 重新生成元数据（如果是文件）
        if not meta['is_dir']:
            save_meta(original_rel, os.path.basename(target_full), os.path.getsize(target_full), scope=scope)
        return jsonify({'success': True})
    except Exception as e:
        logging.error(str(e))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/trash/delete/<item_id>', methods=['DELETE'])
@is_allowed
@login_required
def trash_delete(item_id):
    # 只能删除自己(或 admin)的回收站条目,防止越权永久删除他人文件
    meta_json = r.get(f"trash:{item_id}")
    if not meta_json:
        if session.get('user_id') != admin:
            return jsonify({'success': False, 'error': '记录不存在'}), 404
    else:
        meta = json.loads(meta_json)
        if meta.get('owner') != session.get('user_id') and session.get('user_id') != admin:
            return jsonify({'success': False, 'error': '无权删除该回收站条目'}), 403
    # 同步删除磁盘实体，避免文件残留到下一次自动清理
    trash_path = os.path.join(TRASH_DIR, item_id)
    if os.path.exists(trash_path):
        if os.path.isdir(trash_path):
            shutil.rmtree(trash_path, ignore_errors=True)
        else:
            os.remove(trash_path)
    r.delete(f"trash:{item_id}")
    return jsonify({'success': True})
@app.route('/api/trash/clear', methods=['DELETE'])
@is_allowed
@login_required
def trash_clear():
    keys = r.scan_iter(match="trash:*")
    for key in keys:
        item_id = key.split(':', 1)[-1]
        trash_path = os.path.join(TRASH_DIR, item_id)
        if os.path.exists(trash_path):
            if os.path.isdir(trash_path):
                shutil.rmtree(trash_path)
            else:
                os.remove(trash_path)
        r.delete(key)
    return jsonify({'success': True})


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Not found'}), 404
    return "not found<br><a href=\"/\"></a>"

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({'success': False, 'error': 'CSRF验证失败'}), 400

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

# ==================== 服务器控制台（调试用） ====================

def generate_tree(path_str, sock, key=None, n=0):
    if n > 10:
        return ''
    tree_str = ""
    path = Path(path_str).resolve()
    if not path.exists():
        return f"路径不存在: {path_str}\n"

    try:
        if path.is_file():
            send_plain(sock, '    |' * n + '-' * 4 + path.name + '\n', key)
        elif path.is_dir():
            if n == 0:
                send_plain(sock, str(path) + '\\\n', key)
            else:
                send_plain(sock, '    |' * n + '-' * 4 + path.name + '\\\n', key)
            for child in sorted(path.iterdir()):
                tree_str += generate_tree(str(child), sock, key, n + 1)
    except PermissionError:
        send_plain(sock, '    |' * n + '-' * 4 + f"[权限不足] {path.name}\n", key)
    except Exception as e:
        send_plain(sock, '    |' * n + '-' * 4 + f"[错误: {e}]\n", key)

    return tree_str

def create_file(filename):
    with open(filename, 'a'):
        os.utime(filename, None)




# ==================== 服务器控制台（修复版） ====================

# 服务端静态 RSA 密钥:启动时生成一次。每连接重新生成 3072 位密钥(约数百毫秒~数秒)
# 会被连接洪水打成 CPU DoS,必须复用。
_ADMIN_RSA_PRIVATE_KEY = RSA.generate(3072)


def _admin_conn_throttle(ip):
    """同一 IP 每窗口(ADMIN_CONN_WINDOW 秒)最多 ADMIN_CONN_LIMIT 次连接,超限拒绝。"""
    key = f'admin_conn:{ip}'
    n = r.incr(key)
    if n == 1:
        r.expire(key, ADMIN_CONN_WINDOW)
    return n <= ADMIN_CONN_LIMIT


def _pick_transfer_port():
    """挑选空闲端口并生成一次性传输 token。
    注:选端口与 bind 之间存在 TOCTOU,但传输端口有 token 认证兜底。"""
    while True:
        sm = random.randint(ADMIN_PORT_MIN, ADMIN_PORT_MAX)
        if not is_port_in_use(sm):
            break
    return sm, secrets.token_urlsafe(16)


def recv_exact(sock, n):
    """精确接收 n 字节数据"""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# 管理连接的 AES-256 会话密钥改为每连接局部持有（见 _handle_admin_conn），
# 不再使用全局变量，避免多连接并发时串话。

def send_enc_frame(sock, key, plaintext: bytes):
    """发送 AES-256-GCM 加密帧：长度(4字节大端) + nonce(12) + 密文 + tag(16)"""
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    payload = nonce + ct + tag
    sock.sendall(struct.pack('>I', len(payload)) + payload)

def recv_enc_frame(sock, key, max_len=64 * 1024 * 1024):
    """接收并解密 AES-256-GCM 加密帧，返回明文字节串；连接关闭返回 None"""
    raw_len = recv_exact(sock, 4)
    if raw_len is None:
        return None
    length = struct.unpack('>I', raw_len)[0]
    if length < 28:   # nonce(12) + tag(16) 是最小帧
        raise ValueError("非法加密帧长度")
    if length > max_len:   # 上限保护：防止未认证对端申请超大长度耗尽内存
        raise ValueError(f"加密帧长度超限: {length}")
    payload = recv_exact(sock, length)
    if payload is None:
        return None
    nonce, body = payload[:12], payload[12:]
    ct, tag = body[:-16], body[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def send_plain(sock, msg: str, key=None):
    """发送回复（走 AES-256-GCM 加密通道），末尾加换行符"""
    if key is not None:
        send_enc_frame(sock, key, (msg + '\0').encode())
    else:
        # 握手完成前的兜底明文（仅认证阶段可能用到）
        sock.sendall((msg + '\0').encode())

def stdin_shell(popen:subprocess.Popen,sock:socket.socket,key,event:Event):
    """终端输入线程：读取加密帧写入子进程 stdin；
    收到 EOT(\\4) 时关闭 stdin 让子进程自然退出；客户端断开时终止子进程；
    event 置位后通过超时轮询退出（Windows 的 select 仅支持 socket，此处检测的正是 socket，可用）。"""
    while not event.is_set():
        if not select.select([sock], [], [], 0.2)[0]:
            continue
        aaa = recv_enc_frame(sock, key)
        if aaa is None:
            # 客户端断开：终止子进程，避免命令循环永久阻塞
            try:
                popen.terminate()
            except Exception:
                pass
            break
        if aaa == b'\4':
            # 终端结束：关闭 stdin 让子进程自然退出（EOF）
            try:
                popen.stdin.close()
            except Exception:
                pass
            break
        try:
            popen.stdin.write(aaa.decode())
            popen.stdin.flush()
        except (ValueError, OSError):
            # 子进程已退出导致 stdin 关闭
            break


def w(port, lock: filelock.FileLock):
    """管理控制台监听：每连接一线程处理，认证后带空闲超时。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ADMIN_BIND, port))
    s.listen(5)
    time.sleep(1)

    # 初始化命令白名单（仅在首次写入）
    if not r.smembers('command'):
        for _cmd in ('ping', 'python', 'python3', 'ls', 'echo'):
            r.sadd('command', _cmd)

    print('等待管理连接...', flush=True)
    while True:
        try:
            sf, client_addr = s.accept()
        except OSError:
            # 偶发 EINTR/资源问题，短暂退避后继续
            time.sleep(0.2)
            continue
        print(f"新连接来自 {client_addr}", flush=True)
        # 每连接一个线程，挂起/闲置的连接不再阻塞后续连接
        t = Thread(target=_handle_admin_conn, args=(sf, client_addr), daemon=True)
        t.start()


def _handle_admin_conn(sock, client_addr):
    """单个管理连接的完整生命周期：握手 -> 认证 -> 命令循环。"""
    session_key = None
    # 认证失败限流键前缀（Redis 存储，1 小时过期）
    AUTH_FAIL_PREFIX = 'admin_fail:'

    try:
        # 握手前按源 IP 限流:连接洪水不再能触发每连接一次的 RSA 公钥生成/加密运算
        if not _admin_conn_throttle(client_addr[0]):
            print(f"管理连接过频,拒绝 {client_addr}", flush=True)
            try:
                sock.close()
            except Exception:
                pass
            return
        sock.settimeout(30)   # 握手阶段超时，防止客户端挂起占用连接
        # 1. 发送公钥（长度前缀 + 公钥数据）
        private_key = _ADMIN_RSA_PRIVATE_KEY   # 静态密钥:避免每连接生成 3072 位密钥
        public_key = private_key.publickey()
        pub_bytes = public_key.export_key()
        sock.sendall(struct.pack('>I', len(pub_bytes)))
        sock.sendall(pub_bytes)

        # 2. 接收 RSA-OAEP 加密的 32 字节会话密钥，之后所有流量走 AES-256-GCM
        raw_len = recv_exact(sock, 4)
        if raw_len is None:
            raise ConnectionError("客户端未发送会话密钥")
        enc_len = struct.unpack('>I', raw_len)[0]
        if enc_len > 1024:   # RSA-3072 密文固定 384 字节,上限保护防超大长度
            raise ValueError("会话密钥长度非法")
        enc_key = recv_exact(sock, enc_len)
        if enc_key is None:
            raise ConnectionError("会话密钥数据不完整")
        session_key = PKCS1_OAEP.new(private_key).decrypt(enc_key)
        if len(session_key) != 32:
            raise ValueError("会话密钥长度非法")

        # 3. 接收 AES-GCM 加密的认证信息
        encrypted_auth = recv_enc_frame(sock, session_key)
        if encrypted_auth is None:
            raise ConnectionError("客户端未发送认证信息")
        auth_str = encrypted_auth.decode()
        nm = auth_str.split(',')
        # 失败限流:按源 IP 为键(客户端自报 ID 可被换号绕过,不可信),失败 >=5 次锁定 1 小时
        fail_key = AUTH_FAIL_PREFIX + str(client_addr[0])
        fail_cnt = int(r.get(fail_key) or 0)
        if fail_cnt >= 5:
            # 打印不含明文密码（nm[1] 为密码，禁止输出）
            print(f"认证已锁定: user={nm[0] if len(nm) > 0 else '?'} client={nm[2] if len(nm) > 2 else '?'}", flush=True)
            send_plain(sock, "n", session_key)
            send_enc_frame(sock, session_key, b'\4')
            time.sleep(1)   # 失败节流，抑制 CPU DoS
            return
        with _user_lock:
            stored_hash = users.get(nm[0], '')
            is_admin_name = (nm[0] == admin)
        if is_admin_name and stored_hash and check_password_hash(stored_hash, nm[1]):
            r.delete(fail_key)   # 成功后清零计数
            send_plain(sock, "y", session_key)
            send_enc_frame(sock, session_key, b'\4')
            print('认证成功', flush=True)
        else:
            r.incr(fail_key)
            r.expire(fail_key, 3600)
            # 打印不含明文密码（nm[1] 为密码，禁止输出）
            print(f"认证失败: user={nm[0] if len(nm) > 0 else '?'} client={nm[2] if len(nm) > 2 else '?'}", flush=True)
            send_plain(sock, "n", session_key)
            send_enc_frame(sock, session_key, b'\4')
            time.sleep(1)   # 失败节流，抑制 CPU DoS
            return
    except Exception as e:
        traceback.print_exc()
        try:
            send_plain(sock, "er", session_key)
        except Exception:
            pass
        time.sleep(1)   # 握手失败节流，防止 RSA 生成/建连被刷
        try:
            sock.close()
        except Exception:
            pass
        return

    # 认证完成：空闲超时 300 秒，挂起/闲置的连接不会永久占用控制台
    sock.settimeout(300)
    try:
        _admin_command_loop(sock, session_key)
    except socket.timeout:
        print(f"管理连接空闲超时,断开 {client_addr}", flush=True)
    except Exception as e:
        traceback.print_exc()
        try:
            send_plain(sock, f"error: {e}\n", session_key)
        except Exception:
            pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print(f"管理连接关闭 {client_addr}", flush=True)


def _admin_command_loop(sock, session_key):
    """已认证连接的命令循环（每连接一个线程内运行）。"""
    global admin
    process = None
    while True:
        try:
            sock.sendall(b'c')

            # 接收加密的命令（AES-256-GCM 帧）；空闲 300 秒触发 socket.timeout
            encrypted_cmd = recv_enc_frame(sock, session_key)
            if encrypted_cmd is None:
                break
            cmd = encrypted_cmd.decode()

            try:
                logging.info(f"exec: {cmd.split(' ')[0:2]} from {sock.getpeername()}")
            except OSError:
                logging.info(f"exec: {cmd.split(' ')[0:2]}")

            if cmd == "</c>":
                send_plain(sock, "bye", session_key)
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                break
            if cmd in ("exit",):
                keys = r.scan_iter(match=f"{TASK_PREFIX}*")
                for key in keys:
                    cancel_task_by_id(key)
                os._exit(0)
            elif cmd.lower() == 'gettask':
                keys = r.scan_iter(match=f"{TASK_PREFIX}*")
                tasks = {}
                for key in keys:
                    # key 格式为 task:uuid
                    if isinstance(key, bytes):
                        tid = key.decode().split(':', 1)[-1]
                    else:
                        tid = key.split(':', 1)[-1]
                    task = get_task(tid)  # 已经反序列化 progress/file_info
                    if task:
                        # 过滤不可序列化字段，保持与原 /api/dl 一致
                        filtered = {}
                        for k, v in task.items():
                            filtered[k] = v
                        tasks[tid] = filtered
                send_plain(sock=sock, msg=str(tasks), key=session_key)
            elif cmd.lower() == 'cleartask':
                keys = r.scan_iter(match=f"{TASK_PREFIX}*")
                for key in keys:
                    if isinstance(key, bytes):
                        tid = key.decode().split(':', 1)[-1]
                    else:
                        tid = key.split(':', 1)[-1]
                    task = get_task(tid)
                    if task and task.get('status') not in ('running', 'pending'):
                        delete_task(tid)
                        send_plain(sock, f'remove task {tid}\n', session_key)
            elif cmd.lower().startswith("ls"):
                path_part = cmd.replace("ls", "", 1).strip()
                if path_part.startswith('-'):
                    nn = cmd.split(' ')
                    sxs = nn[1]
                    try:
                        path_part = nn[2]
                    except IndexError:
                        path_part = ''
                    for s in sxs:
                        if s == 'l':
                            try:
                                lp = safe_path(path_part) if path_part else UPLOAD_DIR
                            except ValueError:
                                send_plain(sock, 'path not allowed', session_key)
                                break
                            for n in os.listdir(lp):
                                send_plain(sock, n + '\n', session_key)
                            break
                else:
                    try:
                        lp = safe_path(path_part) if path_part else UPLOAD_DIR
                    except ValueError:
                        send_plain(sock, 'path not allowed', session_key)
                        continue
                    generate_tree(lp, sock, session_key)

            elif cmd.lower().startswith('del '):
                rel = cmd[4:].strip()
                try:
                    ss = safe_path(rel)
                except ValueError:
                    send_plain(sock, 'path not allowed', session_key)
                    continue
                if os.path.basename(ss) == 'app.py':
                    send_plain(sock, 'not can remove', session_key)
                elif os.path.isfile(ss):
                    shutil.move(ss, TRASH_DIR)
                    send_plain(sock, 'move to trash ok', session_key)
                else:
                    send_plain(sock, 'file not found', session_key)

            elif cmd.lower().startswith('cat '):
                rel = cmd[4:].strip()
                try:
                    ss = safe_path(rel)
                except ValueError:
                    send_plain(sock, 'path not allowed', session_key)
                    continue
                if not os.path.isfile(ss):
                    send_plain(sock, 'file not found', session_key)
                    continue
                with open(ss, 'rb') as nn:
                    while True:
                        t = nn.read(1024)
                        if not t:
                            break
                        send_plain(sock, t.decode('utf-8', 'replace'), session_key)
            elif cmd == "load":
                load_html()
                send_plain(sock, "load ok", session_key)
            elif cmd.lower().startswith('debug '):
                ddd = cmd.lower().replace("debug ", "").strip()
                if ddd == "open":
                    # 邮件验证:向管理员绑定邮箱发送一次性验证码
                    admin_mail = user_emails.get(admin, '')
                    if not admin_mail or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', admin_mail):
                        send_plain(sock, "debug open refused: 管理员未绑定邮箱,请先用 setmail 绑定", session_key)
                    else:
                        code = f"{secrets.randbelow(1000000):06d}"
                        r.set(DEBUG_CODE_PREFIX + code, admin, ex=DEBUG_CODE_TTL)
                        try:
                            _send_mail(admin_mail, "开启调试模式验证码",
                                       f"你的调试模式验证码是: {code}\n{DEBUG_CODE_TTL // 60} 分钟内有效,请勿泄露。\n-- {SITE_URL}",
                                       f"<p>你的调试模式验证码是: <b>{code}</b></p>"
                                       f"<p>{DEBUG_CODE_TTL // 60} 分钟内有效,请勿泄露。</p>")
                            send_plain(sock, f"验证码已发送至 {admin_mail}({DEBUG_CODE_TTL // 60}分钟内有效),请用 debug open <验证码> 完成验证", session_key)
                        except Exception as e:
                            logging.error(f"debug 验证码邮件发送失败: {e}")
                            r.delete(DEBUG_CODE_PREFIX + code)
                            send_plain(sock, "验证码邮件发送失败,请稍后再试", session_key)
                elif ddd.startswith("open "):
                    parts = ddd.split(None, 1)
                    code = parts[1] if len(parts) == 2 else ''
                    if code and r.get(DEBUG_CODE_PREFIX + code):
                        r.delete(DEBUG_CODE_PREFIX + code)   # 一次性:用完即失效
                        create_file(os.path.join(BASE_DIR, "de.lock"))
                        app.debug = True
                        logging.warning(f"[audit] debug mode OPEN (by {sock.getpeername()})")
                        send_plain(sock, "debug mode open ok", session_key)
                    else:
                        # 验证码错误/过期:节流 + 日志(不输出验证码明文)
                        print(f"debug open 验证码错误: client={sock.getpeername()}", flush=True)
                        time.sleep(1)
                        send_plain(sock, "debug open refused: 验证码错误或已过期", session_key)
                elif ddd == "close":
                    if os.path.exists(os.path.join(BASE_DIR, "de.lock")):
                        os.remove(os.path.join(BASE_DIR, "de.lock"))
                    app.debug = False
                    send_plain(sock, "debug mode close ok", session_key)
                else:
                    send_plain(sock, f"debug mode {'open' if app.debug else 'close'}", session_key)

            elif cmd.lower().startswith("adduser "):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 4:
                    username, password, mail = parts[1], parts[2], parts[3]
                    with _user_lock:
                        exists = username in users
                    if exists:
                        send_plain(sock, '用户已存在', session_key)
                    elif len(password) < 8:
                        send_plain(sock, '密码至少 8 位', session_key)
                    elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', mail):
                        send_plain(sock, '邮箱格式不正确', session_key)
                    else:
                        with _user_lock:
                            users[username] = generate_password_hash(password)
                            user_list.append(username)
                            user_emails[username] = mail
                        send_plain(sock, f"用户 *** 已添加(邮箱 {mail})", session_key)
                        logging.warning(f"[audit] adduser: {username} (by {sock.getpeername()})")
                        save_user()
                else:
                    send_plain(sock, 'usage: adduser <user> <password> <mail@Example.com>', session_key)

            elif cmd.lower().startswith("setmail "):
                # 为已存在用户绑定/更新邮箱(密码找回用);adduser 会拒绝重名,故单独提供
                parts = [p for p in cmd.split() if p]
                if len(parts) == 3:
                    username, mail = parts[1], parts[2]
                    with _user_lock:
                        exists = username in users
                    if not exists:
                        send_plain(sock, '用户不存在', session_key)
                    elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', mail):
                        send_plain(sock, '邮箱格式不正确', session_key)
                    else:
                        with _user_lock:
                            user_emails[username] = mail
                        send_plain(sock, f"邮箱已更新: {username} -> {mail}", session_key)
                        save_user()
                else:
                    send_plain(sock, 'usage: setmail <user> <mail@Example.com>', session_key)

            elif cmd.lower().startswith("deluser "):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 2:
                    username = parts[1]
                    with _user_lock:
                        if username in users and username in user_list:
                            del users[username]
                            user_list.remove(username)
                            user_emails.pop(username, None)
                            deleted = True
                        elif username in users and username in blocked_users:
                            del users[username]
                            blocked_users.remove(username)
                            user_emails.pop(username, None)
                            deleted = True
                        else:
                            deleted = False
                    if deleted:
                        send_plain(sock, f"用户 *** 已删除", session_key)
                        logging.warning(f"[audit] deluser: {username} (by {sock.getpeername()})")
                        save_user()
                    else:
                        send_plain(sock, "用户不存在", session_key)

            elif cmd.lower() == ("listuser"):
                with _user_lock:
                    info = ["当前用户列表:"]
                    for user in users.keys():
                        role = ""
                        if user in blocked_users:
                            role += " forbid"
                        else:
                            if user not in user_list:
                                user_list.append(user)
                            role += " authorized"
                        if user == admin:
                            role += " admin"
                        email = user_emails.get(user, '')
                        info.append(f"--{user} {role}  {email}")
                send_plain(sock, "\n".join(info), session_key)
                save_user()

            elif cmd.lower().startswith("addnigga "):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 2:
                    username = parts[1]
                    with _user_lock:
                        exists = username in users
                        in_block = username in blocked_users
                    if not exists:
                        send_plain(sock, f"*** 不存在", session_key)
                    elif not in_block:
                        with _user_lock:
                            blocked_users.append(username)
                            if username in user_list:
                                user_list.remove(username)
                        send_plain(sock, f"用户 *** 已移入黑名单", session_key)
                        save_user()

            elif cmd.lower().startswith("delnigga "):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 2:
                    username = parts[1]
                    with _user_lock:
                        exists = username in users
                        in_block = username in blocked_users
                    if not exists:
                        send_plain(sock, f"*** 不存在", session_key)
                    elif in_block:
                        with _user_lock:
                            blocked_users.remove(username)
                            if username not in user_list:
                                user_list.append(username)
                        send_plain(sock, f"用户 *** 已移出黑名单", session_key)
                        save_user()

            elif cmd.lower().startswith("setadmin "):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 2:
                    username = parts[1]
                    with _user_lock:
                        exists = username in users
                        in_list = username in user_list
                    if not exists:
                        send_plain(sock, f"*** 不存在", session_key)
                    elif in_list:
                        with _user_lock:
                            admin = username
                        send_plain(sock, f"用户 *** 已设为管理员", session_key)
                        logging.warning(f"[audit] setadmin: {username} (by {sock.getpeername()})")
                        save_user()

            elif app.debug and cmd.lower().startswith("get "):
                parts = cmd.split()
                if len(parts) < 2:
                    send_plain(sock, "usage: get <var>", session_key)
                    continue
                name = parts[1]
                # 白名单:只允许读取非敏感调试变量(users/user_emails 含密码哈希,禁止输出)
                if name not in ('admin', 'user_list', 'blocked_users',
                                'MAX_WORKERS', 'MAX_PENDING_PER_USER', 'DOWNLOAD_MAX_SIZE',
                                'UPLOAD_DIR', 'PRIVATE_ROOT', 'app'):
                    send_plain(sock, f"变量 {name} 不允许读取", session_key)
                    continue
                val = globals().get(name)
                if isinstance(val, (dict, list, set)):
                    send_plain(sock, f"{type(val).__name__}(len={len(val)})", session_key)
                else:
                    send_plain(sock, str(val), session_key)

            elif cmd.lower() == 'clearlog':
                open(LOG_FILE, 'w', encoding='utf-8').close()
                send_plain(sock, 'log clear', session_key)
                err_file = os.path.join(BASE_DIR, 'error')
                if os.path.exists(err_file):
                    os.remove(err_file)
                send_plain(sock, 'Error stack is clear', session_key)
            elif cmd.lower() == 'update':
                ns = recv_enc_frame(sock, session_key)
                ns = ns.decode()
                # 校验是合法 IPv4 且不是 0.0.0.0/组播，避免绑定所有接口导致未授权访问
                if ipaddress.IPv4Address(ns).is_unspecified or ipaddress.IPv4Address(ns).is_multicast:
                    send_plain(sock, 'bad ip', session_key)
                    continue
                sm, tok = _pick_transfer_port()
                a = Thread(target=update_file, args=(ns, sm, tok), daemon=True)
                a.start()
                # 一次性 token 与端口一起经加密通道下发,传输连接必须先出示 token
                logging.warning(f"[audit] update 传输端口开启: {ns}:{sm} (by {sock.getpeername()})")
                send_plain(sock, f"{sm}:{tok}", session_key)
            elif cmd.lower() == 'download':
                ns = recv_enc_frame(sock, session_key)
                ns = ns.decode()
                if ipaddress.IPv4Address(ns).is_unspecified or ipaddress.IPv4Address(ns).is_multicast:
                    send_plain(sock, 'bad ip', session_key)
                    continue
                sm, tok = _pick_transfer_port()
                a = Thread(target=download_file, args=(ns, sm, tok), daemon=True)
                a.start()
                # 一次性 token 与端口一起经加密通道下发,传输连接必须先出示 token
                logging.warning(f"[audit] download 传输端口开启: {ns}:{sm} (by {sock.getpeername()})")
                send_plain(sock, f"{sm}:{tok}", session_key)

            elif cmd.startswith('run '):
                rest = cmd[4:].strip()
                stdin_on = False
                if rest.startswith('term '):
                    stdin_on = True
                    rest = rest[5:].strip()
                try:
                    tokens = shlex.split(rest)
                except ValueError:
                    send_plain(sock, '参数解析失败', session_key)
                    continue
                if not tokens:
                    send_plain(sock, 'can\'t exec', session_key)
                    continue
                exe = shutil.which(tokens[0])
                if tokens[0] not in r.smembers('command') or exe is None:
                    send_plain(sock, 'can\'t exec', session_key)
                else:
                    # 通知客户端已进入终端模式（客户端据此决定是否启动 stdin 输入线程）
                    send_plain(sock, '\x02TERM', session_key)
                    # 不再使用 shell=True，避免 `run ping; rm -rf` 之类注入绕过白名单
                    # PYTHONUNBUFFERED=1 让 python 子进程行缓冲/无缓冲，保证实时输出
                    env = dict(os.environ)
                    env['PYTHONUNBUFFERED'] = '1'
                    stop_event = Event()

                    process = subprocess.Popen([exe] + tokens[1:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, cwd=UPLOAD_DIR, text=True, env=env)
                    stdin_thread = None
                    if stdin_on:
                        print('term', flush=True)
                        stdin_thread = Thread(target=stdin_shell, name='command', args=(process, sock, session_key, stop_event), daemon=True)
                        stdin_thread.start()
                    # 用底层 fd 的 os.read：管道一有数据就返回（不攒满 4096），保证实时回显。
                    # 非阻塞 + 轮询；子进程退出时读尽剩余输出后结束。
                    def stdout_forward(p, s):
                        fd = p.stdout.fileno()
                        try:
                            os.set_blocking(fd, False)
                        except OSError:
                            pass
                        while True:
                            try:
                                chunk = os.read(fd, 4096)
                            except BlockingIOError:
                                chunk = b''
                            except OSError:
                                break
                            if chunk:
                                # 字节透传：不在服务端解码，交给客户端按 utf-8/gbk 智能解码
                                send_enc_frame(s, session_key, chunk)
                            elif p.poll() is not None:
                                # 子进程已退出：读尽剩余输出
                                while True:
                                    try:
                                        tail = os.read(fd, 4096)
                                    except (BlockingIOError, OSError):
                                        tail = b''
                                    if not tail:
                                        break
                                    send_enc_frame(s, session_key, tail)
                                break
                            else:
                                time.sleep(0.05)
                    reader = Thread(target=stdout_forward, args=(process, sock), daemon=True)
                    reader.start()
                    process.wait()
                    reader.join(timeout=2)   # 子进程退出后 stdout EOF，reader 会自行结束
                    if stdin_thread is not None:
                        stop_event.set()    # 停止 stdin 输入线程，避免其截获下一条命令
                        stdin_thread.join(timeout=1)
                    return_code = process.returncode
                    send_plain(sock, f"Process finished with return code {return_code}", session_key)
            elif cmd.lower() == 'export':
                raise Exception('export')
            elif cmd.lower() == 'runlist':
                send_plain(sock, str(r.smembers('command')), session_key)
            elif cmd.startswith('cr ') and app.debug:
                cmd_name = cmd.replace("cr ", '', 1).strip()
                if cmd_name and ' ' not in cmd_name and shutil.which(cmd_name):
                    r.sadd('command', cmd_name)
                    r.smembers('command')
                    send_plain(sock, f'command {cmd_name} added', session_key)
                else:
                    send_plain(sock, 'can\'t add command', session_key)
            else:
                send_plain(sock, "未知命令", session_key)

        except socket.timeout:
            # 空闲超时：交由 _handle_admin_conn 统一断开
            raise
        except Exception as e:
            traceback.print_exc()
            try:
                # 只写堆栈，不 dump locals —— locals 含明文密码(nm)/会话密钥/命令文本，禁止落盘
                with open(os.path.join(BASE_DIR, 'error'), 'w', encoding='utf-8') as d:
                    d.write(traceback.format_exc())
            except Exception as en:
                try:
                    send_plain(sock, f"error: {en}\n", session_key)
                except Exception:
                    break
            if process is not None and process.poll() is None:
                process.terminate()
            logging.error(f"命令执行错误: {e}")
            try:
                send_plain(sock, f"error: {e}\n", session_key)
            except Exception:
                break
        finally:
            try:
                send_enc_frame(sock, session_key, b'\4')
            except Exception:
                break
def _recv_token(con, token, timeout=10):
    """传输连接认证:接收长度(4)+token 字节并恒定时间比对。失败/超时返回 False。"""
    try:
        con.settimeout(timeout)
        raw_len = recv_exact(con, 4)
        if raw_len is None:
            return False
        length = struct.unpack('>I', raw_len)[0]
        if length > 512:
            return False
        data = recv_exact(con, length)
        if data is None:
            return False
        con.settimeout(None)
        return hmac.compare_digest(data.decode('utf-8', 'replace'), token)
    except (socket.timeout, OSError):
        return False

def update_file(ip,port,token):
    n = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    n.settimeout(30)   # 客户端拿了端口不来连时,线程不会永久挂起
    n.bind((ip,port))
    n.listen(1)
    try:
        con,addr = n.accept()
    except socket.timeout:
        print('update accept timeout', flush=True)
        n.close()
        return
    try:
        if not _recv_token(con, token):
            print('update token mismatch', flush=True)
            return
        if not recv_file(con, save_dir=UPLOAD_DIR, max_size=1024 * 1024 * 1024):
            print('error', flush=True)
    finally:
        con.close()
        n.close()

def download_file(ip,port,token):
    n = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    n.settimeout(30)   # 同 update_file:防线程永久挂起
    n.bind((ip,port))
    n.listen(1)
    try:
        con,addr = n.accept()
    except socket.timeout:
        print('download accept timeout', flush=True)
        n.close()
        return
    try:
        if not _recv_token(con, token):
            print('download token mismatch', flush=True)
            return
        # 客户端发送：struct.pack('!I', len(name)) + name.encode()
        raw_len = con.recv(4)
        if len(raw_len) < 4:
            return
        name_len = struct.unpack('!I', raw_len)[0]
        if name_len > 4096:
            print('download name too long', flush=True)
            return
        name = b''
        while len(name) < name_len:
            chunk = con.recv(name_len - len(name))
            if not chunk:
                break
            name += chunk
        file_rel = name.decode()
        try:
            file_path = safe_path(file_rel)  # 仅允许 UPLOAD_DIR 内文件，防任意读取
        except ValueError:
            print('download path not allowed', flush=True)
        else:
            if not os.path.isfile(file_path):
                print('download file not found', flush=True)
            elif not send_file(con, file_path):
                print('error', flush=True)
    finally:
        con.close()
        n.close()

lock = filelock.SoftFileLock('.admin_lock')





if __name__ == '__main__':
    print(f"🌐 启动：http://0.0.0.0:5000\n访问http://{socket.gethostbyname(socket.gethostname())}:5000", flush=True)
    # 仅当显式允许（ALLOW_DE_LOCK=1）时才由 de.lock 文件开启 debug，
    # 避免残留文件意外打开 get/cr 等调试命令的攻击面
    if os.environ.get('ALLOW_DE_LOCK', '0') == '1' and os.path.exists(os.path.join(BASE_DIR, "de.lock")):
        app.debug = True  # 调试链接由 index() 渲染期追加
    while True:
        sm = random.randint(ADMIN_PORT_MIN, ADMIN_PORT_MAX)
        if not is_port_in_use(sm):
            break
    
    r.set('man_port',sm)
    print(f"管理端口链接:{socket.gethostbyname(socket.gethostname())}:{sm}",flush=True)
    logging.info(f"管理端口链接:{socket.gethostbyname(socket.gethostname())}:{sm}")
    s = Thread(target=w, daemon=True,args=(sm, lock))
    s.start()
    app.run("0.0.0.0", 5000, use_reloader=False,use_evalex=False)
else:
    try:
        # 本 worker 抢到了锁，负责启动管理端口
        lock.acquire(timeout=1)
        while True:
            sm = random.randint(ADMIN_PORT_MIN, ADMIN_PORT_MAX)
            if not is_port_in_use(sm):
                break
        print(f"管理端口链接: {socket.gethostbyname(socket.gethostname())}:{sm}", flush=True)
        logging.info(f"管理端口链接: {socket.gethostbyname(socket.gethostname())}:{sm}")
        r.set('man_port',sm)
        s = Thread(target=w, daemon=True, args=(sm,lock))
        s.start()
        atexit.register(lock.release)

            
        
    except filelock.Timeout as e:print('no lock')