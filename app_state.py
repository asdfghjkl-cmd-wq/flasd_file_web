# -*- coding: utf-8 -*-
"""
全局状态与数据层:配置常量、Redis 连接、用户数据、任务队列系统。

本模块是唯一"持有全局可变状态"的地方,被 app_paths / app_tools / app_auth /
app_routes / app_admin 共享。约定:
- 其它模块统一 `import app_state as st`,经 `st.xxx` 读取(admin 等会被重绑定,
  直接 `from app_state import admin` 会拿到旧值);
- users / user_list / blocked_users / user_emails 等容器只做原地修改
  (load_redis 在锁内 clear + update),保证共享引用始终有效。
本模块不 import app(避免循环导入);worker 线程在真正取到任务时才延迟导入 app。
"""
import os
import sys
import re
import json
import time
import logging
import uuid
import socket
import ipaddress
from threading import Thread, RLock
from queue import Queue

import redis
from werkzeug.security import generate_password_hash
from flask import jsonify, session


def env_int(name, default):
    """读取整数型环境变量,非法值回退默认值(避免配置写错导致进程起不来)。"""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == '':
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        logging.warning(f"环境变量 {name} 不是合法整数({raw!r}),使用默认值 {default}")
        return default


# 兼容别名:历史模块(app_admin/app_routes 等)仍用旧下划线名,新代码请用 env_int
_env_int = env_int


# ==================== Redis 连接 ====================
# 从环境变量读取 Redis 地址，方便部署
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = _env_int('REDIS_PORT', 6379)
REDIS_DB = _env_int('REDIS_DB', 0)
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, password=REDIS_PASSWORD,
                decode_responses=True, socket_connect_timeout=5, socket_timeout=5)
# Redis 启动检查:默认 fail-fast(部署早期就发现问题);
# 测试/无 Redis 环境可设 REDIS_SKIP_CHECK=1 跳过(连接对象惰性,不实际连接)。
if os.environ.get('REDIS_SKIP_CHECK', '0') != '1':
    try:
        logging.info(f"Redis 版本: {r.info('server')['redis_version']}")
    except Exception as e:
        print(f"[FATAL] Redis 连接失败: {e}", flush=True)
        logging.error(f"Redis 连接失败: {e}")
        raise SystemExit(f"Redis 连接失败: {e}")

# 健康检查专用连接:短超时(1s),避免 Redis 故障时模块级连接 socket_timeout(5s)
# 拖慢 /healthz /readyz,导致 LB/K8s 探针窗口(通常 1~3s)内误判失败。
_probe_redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB,
                           password=REDIS_PASSWORD, decode_responses=True,
                           socket_connect_timeout=1, socket_timeout=1)


def ping_redis() -> bool:
    """探针用 ping:短超时连接,失败仅返回 False(不抛异常,便于探针快速响应)。"""
    try:
        _probe_redis.ping()
        return True
    except Exception:
        return False
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


class Cancelled(BaseException):
    """任务取消信号:BaseException 使其能穿透各工具的普通 except 处理。"""
    pass


# ==================== 目录与常量 ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRASH_DIR = os.path.join(BASE_DIR, 'trash')
if not os.path.exists(TRASH_DIR):
    os.makedirs(TRASH_DIR)
# 共享盘根(与 app.config['UPLOAD_FOLDER'] 保持一致,app.py 创建 Flask 时引用本值)
UPLOAD_DIR = os.path.abspath(os.path.join(BASE_DIR, 'uploads'))
META_DIR = os.path.join(UPLOAD_DIR, 'metadata')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(META_DIR, exist_ok=True)

# ==================== 双空间(共享盘/个人盘) ====================
# 共享盘:UPLOAD_DIR(所有用户);个人盘:PRIVATE_ROOT/<用户名>/(仅本人 + admin)
PRIVATE_ROOT = os.path.join(BASE_DIR, 'private')
os.makedirs(PRIVATE_ROOT, exist_ok=True)
PERSONAL_URL_PREFIX = '/p'          # 个人盘 URL 前缀
# 双空间 scope 标记:WSGI 中间件写入 environ['dsh.scope'],路由经 g.scope 读取;
# 具名常量避免魔法字符串拼写错误(值不变,兼容 app_routes 中的字面量比较与持久化 meta)
SCOPE_SHARED = 'shared'
SCOPE_PERSONAL = 'personal'
RESERVED_NAMES = {'metadata', 'chunks'}   # 系统保留目录/文件名
# 用户名规范:仅字母/数字/_/-,1~32 位(个人盘目录依此命名,防跨用户目录冲突)
USERNAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
# 下载大小上限(字节),防止下载把磁盘写满;0 表示不限制
DOWNLOAD_MAX_SIZE = _env_int('DOWNLOAD_MAX_SIZE', 10 * 1024**3)
# 分享链接有效期(秒)
SHARE_TTL = 86400
# 分享链接下载限流:同一 IP 每分钟最多次数
SHARE_RATE_LIMIT = 60
# 回收站保留时间(秒,与 trash:<id> 的 Redis TTL 一致)
TRASH_TTL = 86400 * 10
# 登录/找回限流:同一 IP 每窗口最多失败次数;账号维度阈值放宽防误锁
LOGIN_FAIL_LIMIT = 5
LOGIN_FAIL_ACCT_LIMIT = 20
LOGIN_FAIL_WINDOW = 600

# ==================== 邮件 / 密码找回 ====================
# SMTP 通过环境变量注入(与 REDIS_PASSWORD 同风格)
MAIL_FROM = os.environ.get('MAIL_FROM', 'no-reply@www.relink.website')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
SITE_URL = os.environ.get('SITE_URL', 'https://www.relink.website')
RESET_TOKEN_TTL = 1800        # 重置链接 30 分钟有效
RESET_TOKEN_PREFIX = 'reset_token:'

# ==================== 可信反向代理 ====================
# 可信代理白名单(直连方 IP,逗号分隔):仅在直连方属于本集合时才采纳
# X-Forwarded-For/Proto/Host 头(app_auth._client_ip 与 app.py 的 ProxyFix
# 剥头中间件共用,定义收敛在本处避免两份语义漂移)。
TRUSTED_PROXIES = frozenset(
    p.strip() for p in os.environ.get('TRUSTED_PROXIES', '').split(',') if p.strip()
)


def is_api_request(request) -> bool:
    """统一 API 判定(错误处理/安全头/认证共享):JSON 请求、XHR 或 /api/ 路径。

    原来 app.py 仅按 path 前缀判断、app_auth 额外看 is_json/X-Requested-With,
    两套并存会导致同一请求在错误处理与认证处返回不同响应格式;统一后
    JSON/XHR 请求一律按 API 语义处理(JSON 错误体),页面请求返回文本。
    """
    return (request.is_json or
            request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
            request.path.startswith('/api/'))

# ==================== 用户数据存取 ====================

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
    logging.debug('save ok')

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

# 声明全局(load_user/load_redis 会重绑定这些名字)
users = {}
user_list = []
blocked_users = []
admin = None
user_emails = {}


def load_redis():
    """后台同步线程:每 10s 用 Redis 最新快照刷新内存状态。
    容器(users 等)在锁内原地更新,保证共享引用始终有效且不与写路径冲突;
    admin 为标量,经 st.admin 读取的模块总能拿到最新值。

    多 worker 部署注意:每个 worker 进程持有自己的内存副本,本进程内的修改
    (save_user 等)实时写 Redis 并同步自己的内存;其它 worker 最长延迟一个
    同步周期(默认 10s,见下方 time.sleep)才能看到变更——即"删除用户/改密/
    封禁"后,打到未同步 worker 的旧会话在最坏 10s 内仍可通过 login_required
    校验。单 worker 部署无此窗口;多 worker 部署若要求更严格,请缩短同步间隔
    或把登录/权限热路径改为 Redis 直查。"""
    global admin
    while True:
        time.sleep(10)
        try:
            with _user_lock:
                # 锁内重读,避免"改内存-落库"与"快照覆盖"之间的丢更新竞态
                redis_users = r.hgetall("users")
                redis_user_list = list(r.smembers("user_list"))
                redis_blocked_users = list(r.smembers("blocked_users"))
                redis_admin = r.get("admin")
                redis_user_emails = r.hgetall("user_emails")
                ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', os.environ.get('a', None))
                if redis_users:
                    users.clear()
                    users.update(redis_users)
                    user_list[:] = redis_user_list
                    blocked_users[:] = redis_blocked_users
                    admin = redis_admin if redis_admin else ADMIN_USERNAME
                    # 邮箱数据也要同步,否则多 worker 下忘记密码功能读到陈旧数据
                    if redis_user_emails:
                        user_emails.clear()
                        user_emails.update(redis_user_emails)
        except Exception as e:
            # Redis 瞬时错误不能让同步线程死掉，记录后下轮重试
            logging.warning(f"load_redis 同步失败: {e}")

def _session_version(username):
    """用户会话版本号:改密/重置密码时自增,使该用户旧会话(含被窃取的)全部失效。"""
    try:
        return int(r.get(f'sess_ver:{username}') or 0)
    except (TypeError, ValueError):
        return 0


# ==================== 任务系统 ====================
MAX_WORKERS = 3
task_queue = Queue()

# 工具 ID 常量
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
    # 按归属建立索引,供任务列表/排队限流快速查询(索引 TTL 略长于任务)
    owner = data.get('owner')
    if owner:
        r.sadd(f'user_tasks:{owner}', task_id)
        r.expire(f'user_tasks:{owner}', 8 * 24 * 3600)

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
        try:
            raw['cancel_flag'] = int(raw.get('cancel_flag', 0))
        except (TypeError, ValueError):
            raw['cancel_flag'] = 0
        out[tid] = raw
    return out

def get_task(task_id):
    """从 Redis 读取任务，并反序列化"""
    return get_tasks_bulk([task_id]).get(task_id)

def delete_task(task_id):
    t = get_task(task_id)
    if t and t.get('owner'):
        r.srem(f'user_tasks:{t["owner"]}', task_id)
    r.delete(task_key(task_id))


def _all_task_ids():
    """返回全部任务 id(scan_iter + bytes 解码)。"""
    tids = []
    for key in r.scan_iter(match=f"{TASK_PREFIX}*"):
        if isinstance(key, bytes):
            tids.append(key.decode().split(':', 1)[-1])
        else:
            tids.append(key.split(':', 1)[-1])
    return tids


def _task_ids_for_view(is_owner_view):
    """任务 id 集合:普通用户走 user_tasks 索引(为空时回退全量),管理员全量。"""
    if is_owner_view:
        tids = list(r.smembers(f'user_tasks:{session.get("user_id")}'))
        if not tids:
            return _all_task_ids()
        return tids
    return _all_task_ids()

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
    # 优先走按用户索引;索引为空(旧数据)时回退全量扫描
    tids = list(r.smembers(f'user_tasks:{user}')) or _all_task_ids()
    count = 0
    for tid in tids:
        if r.hget(task_key(tid), 'status') == 'pending':
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

# 进度更新 Lua 脚本:在 Redis 内原子完成"读-改-写",并发更新不互相覆盖;
# total/current 传空串表示不更新该字段;同时续期(与 7 天 TTL 一致)
_PROGRESS_UPDATE_LUA = """
local key = KEYS[1]
local total = ARGV[1]
local current = ARGV[2]
local raw = redis.call('HGET', key, 'progress')
local t = {}
if raw then
    local ok, dec = pcall(cjson.decode, raw)
    if ok and type(dec) == 'table' then t = dec end
end
if total ~= '' then t['total'] = tonumber(total) end
if current ~= '' then t['current'] = tonumber(current) end
redis.call('HSET', key, 'progress', cjson.encode(t))
redis.call('EXPIRE', key, 7 * 24 * 3600)
return 1
"""

def update_task_progress(task_id, total=None, current=None):
    """更新任务进度（下载等场景）:原子 Lua 更新,避免多线程 RMW 互相覆盖;
    长耗时任务(下载)运行期间持续续期,防止 7 天 TTL 中途过期。"""
    r.eval(_PROGRESS_UPDATE_LUA, 1, task_key(task_id),
           '' if total is None else str(total),
           '' if current is None else str(current))


def worker():
    """后台任务执行线程:从队列取任务执行,更新 Redis 状态。

    注意:当前工具函数(get_hash/u1/u2/copy/move/zip_ex/download)均为纯文件与
    Redis 操作,不需要 Flask 请求上下文;因此这里不再 import app / 使用
    app_context(避免触发 app.py 以 'app' 模块名二次加载导致启动日志重复)。
    若未来工具需要 Flask 上下文,再在此处延迟导入并包一层 with app.app_context()。
    """
    while True:
        task_id, func, base_args, tool_id = task_queue.get()
        if task_id is None:
            break
        # 更新状态为 running
        r.hset(task_key(task_id), 'status', 'running')

        try:
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
            import traceback
            traceback.print_exc()
            if is_cancelled(task_id):
                r.hset(task_key(task_id), 'status', 'cancelled')
            else:
                r.hset(task_key(task_id), 'status', 'failed')
                r.hset(task_key(task_id), 'error', str(e))
        finally:
            if is_cancelled(task_id):
                # 只在任务未完成时覆盖为 cancelled,避免与正常完成瞬间的竞态
                if r.hget(task_key(task_id), 'status') in ('running', 'pending'):
                    r.hset(task_key(task_id), 'status', 'cancelled')
                    r.hset(task_key(task_id), 'error', 'User cancelled')
            task_queue.task_done()


# ==================== 启动后台线程 ====================
for _ in range(MAX_WORKERS):
    t = Thread(target=worker, daemon=True)
    t.start()

users, user_list, blocked_users, admin, user_emails = load_user()
annn = Thread(target=load_redis, daemon=True)
annn.start()


# ==================== app 引用注册表 ====================
# 替代 app.py 旧有的 sys.modules['app'] hack:python app.py 直跑时本模块名为
# __main__,app_admin 若延迟 `from app import app` 会把本文件以 'app' 名字再加载
# 一遍,产生第二个模块对象(日志/密钥/模板等模块级代码重复执行,且拿到与运行
# 实例不同的第二个 Flask app)。改为:app.py 在模块级创建实例后写入本注册表,
# app_admin 等需要延迟取引用的地方经 get_app()/get_load_html() 获取,与运行
# 实例恒为同一对象,且不再依赖"app.py 是第一个被加载的文件"。
_app_ref = None
_load_html_ref = None


def set_app(app):
    """注册运行中的 Flask 实例引用(由 app.py 模块级创建后写入)。"""
    global _app_ref
    _app_ref = app


def get_app():
    """取运行中的 Flask 实例引用;尚未创建时返回 None。"""
    return _app_ref


def set_load_html(fn):
    """注册 load_html 函数引用(模板热重载用,见 app_admin 'load' 命令)。"""
    global _load_html_ref
    _load_html_ref = fn


def get_load_html():
    """取 load_html 函数引用;尚未注册时返回 None。"""
    return _load_html_ref
