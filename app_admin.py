# -*- coding: utf-8 -*-
"""
管理控制台:自定义加密 socket 协议(握手→认证→命令循环)与文件传输端点。

- 只监听 ADMIN_BIND(默认 127.0.0.1),认证失败按源 IP 锁定;
- update/download 传输端口带一次性 token 认证;
- 全局可变状态一律经 app_state(st.xxx)访问;app.debug 在函数内延迟导入。
"""
import os
import re
import hmac
import time
import logging
import socket
import struct
import secrets
import shlex
import shutil
import select
import subprocess
import uuid
import ipaddress
from pathlib import Path
from threading import Thread, Event, BoundedSemaphore

import psutil
import filelock
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

import app_state as st
from app_paths import safe_path, _purge_user
from app_auth import _send_mail
from file_rw import recv_file, send_file


def is_port_in_use(port):
    for conn in psutil.net_connections():
        if conn.laddr.port == port and conn.status == "LISTEN":  # type: ignore
            return True
    return False


# ==================== 常量 ====================
# 管理控制台:认证失败锁定阈值与时长、空闲超时、握手超时
ADMIN_AUTH_FAIL_LIMIT = 5
ADMIN_AUTH_LOCKOUT = 3600
ADMIN_IDLE_TIMEOUT = 300
ADMIN_HANDSHAKE_TIMEOUT = 30
# 管理端口随机范围
ADMIN_PORT_MIN = st._env_int('ADMIN_PORT_MIN', 6000)
ADMIN_PORT_MAX = st._env_int('ADMIN_PORT_MAX', 6050)
# 管理端口绑定地址(默认仅本机回环;需要远程管理时显式设置 ADMIN_BIND,并配合防火墙/ACL)
ADMIN_BIND = os.environ.get('ADMIN_BIND', '127.0.0.1')
if ADMIN_BIND not in ('127.0.0.1', '::1', 'localhost'):
    logging.warning(f"ADMIN_BIND={ADMIN_BIND} 非回环地址,管理控制台暴露于网络,请确认防火墙/ACL")
# 管理控制台握手限流:同一 IP 每窗口最多连接次数
ADMIN_CONN_LIMIT = st._env_int('ADMIN_CONN_LIMIT', 5)
ADMIN_CONN_WINDOW = 10   # 秒
# 管理传输连接(update/download)认证后的空闲超时:防对端认证后挂死不释放线程
TRANSFER_IDLE_TIMEOUT = st._env_int('TRANSFER_IDLE_TIMEOUT', 600)

# debug open 邮件验证:向管理员绑定邮箱发送一次性验证码(10 分钟有效)
DEBUG_CODE_TTL = 600
DEBUG_CODE_PREFIX = 'debug_code:'


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


# 服务端静态 RSA 密钥:启动时生成一次。每连接重新生成 3072 位密钥(约数百毫秒~数秒)
# 会被连接洪水打成 CPU DoS,必须复用。
_ADMIN_RSA_PRIVATE_KEY = RSA.generate(3072)
# 管理控制台并发连接上限:多 IP 连接洪水也打不穿线程池(握手限流只按单 IP)
ADMIN_MAX_CONNS = st._env_int('ADMIN_MAX_CONNS', 8)
_admin_conn_sem = BoundedSemaphore(ADMIN_MAX_CONNS)


def _admin_conn_throttle(ip):
    """同一 IP 每窗口(ADMIN_CONN_WINDOW 秒)最多 ADMIN_CONN_LIMIT 次连接,超限拒绝。"""
    key = f'admin_conn:{ip}'
    n = st.r.incr(key)
    if n == 1:
        st.r.expire(key, ADMIN_CONN_WINDOW)
    return n <= ADMIN_CONN_LIMIT


def _pick_transfer_port():
    """挑选空闲端口并生成一次性传输 token。
    注:选端口与 bind 之间存在 TOCTOU,但传输端口有 token 认证兜底。"""
    while True:
        sm = secrets.randbelow(ADMIN_PORT_MAX - ADMIN_PORT_MIN + 1) + ADMIN_PORT_MIN
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

def stdin_shell(popen: subprocess.Popen, sock: socket.socket, key, event: Event):
    """终端输入线程：读取加密帧写入子进程 stdin；
    收到 EOT(\4) 时关闭 stdin 让子进程自然退出；客户端断开时终止子进程；
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
    if not st.r.smembers('command'):
        for _cmd in ('ping', 'python', 'python3', 'ls', 'echo'):
            st.r.sadd('command', _cmd)

    logging.info('管理控制台监听中...')
    while True:
        try:
            sf, client_addr = s.accept()
        except OSError:
            # 偶发 EINTR/资源问题，短暂退避后继续
            time.sleep(0.2)
            continue
        logging.info(f"新连接来自 {client_addr}")
        # 每连接一个线程，挂起/闲置的连接不再阻塞后续连接
        t = Thread(target=_handle_admin_conn, args=(sf, client_addr), daemon=True)
        t.start()


def _handle_admin_conn(sock, client_addr):
    """单个管理连接的入口:受并发上限约束后转内部处理。"""
    if not _admin_conn_sem.acquire(timeout=10):
        try:
            sock.close()
        except Exception:
            pass
        return
    try:
        _handle_admin_conn_inner(sock, client_addr)
    finally:
        _admin_conn_sem.release()


def _handle_admin_conn_inner(sock, client_addr):
    """单个管理连接的完整生命周期：握手 -> 认证 -> 命令循环。"""
    session_key = None
    # 认证失败限流键前缀（Redis 存储，1 小时过期）
    AUTH_FAIL_PREFIX = 'admin_fail:'

    try:
        # 握手前按源 IP 限流:连接洪水不再能触发每连接一次的 RSA 公钥生成/加密运算
        if not _admin_conn_throttle(client_addr[0]):
            logging.warning(f"管理连接过频,拒绝 {client_addr}")
            try:
                sock.close()
            except Exception:
                pass
            return
        sock.settimeout(ADMIN_HANDSHAKE_TIMEOUT)   # 握手阶段超时，防止客户端挂起占用连接
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
        fail_cnt = int(st.r.get(fail_key) or 0)
        if fail_cnt >= ADMIN_AUTH_FAIL_LIMIT:
            # 打印不含明文密码（nm[1] 为密码，禁止输出）
            logging.warning(f"认证已锁定: user={nm[0] if len(nm) > 0 else '?'} client={nm[2] if len(nm) > 2 else '?'}")
            send_plain(sock, "n", session_key)
            send_enc_frame(sock, session_key, b'\4')
            time.sleep(1)   # 失败节流，抑制 CPU DoS
            return
        with st._user_lock:
            stored_hash = st.users.get(nm[0], '')
            is_admin_name = (nm[0] == st.admin)
        if is_admin_name and stored_hash and check_password_hash(stored_hash, nm[1]):
            st.r.delete(fail_key)   # 成功后清零计数
            send_plain(sock, "y", session_key)
            send_enc_frame(sock, session_key, b'\4')
            logging.info('认证成功')
        else:
            st.r.incr(fail_key)
            st.r.expire(fail_key, ADMIN_AUTH_LOCKOUT)
            # 打印不含明文密码（nm[1] 为密码，禁止输出）
            logging.warning(f"认证失败: user={nm[0] if len(nm) > 0 else '?'} client={nm[2] if len(nm) > 2 else '?'}")
            send_plain(sock, "n", session_key)
            send_enc_frame(sock, session_key, b'\4')
            time.sleep(1)   # 失败节流，抑制 CPU DoS
            return
    except Exception as e:
        import traceback
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
    sock.settimeout(ADMIN_IDLE_TIMEOUT)
    try:
        _admin_command_loop(sock, session_key)
    except socket.timeout:
        logging.info(f"管理连接空闲超时,断开 {client_addr}")
    except Exception as e:
        import traceback
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
        logging.debug(f"管理连接关闭 {client_addr}")


def _admin_command_loop(sock, session_key):
    """已认证连接的命令循环（每连接一个线程内运行）。"""
    from app import app   # 延迟导入:命令执行时 app 必然已创建,避免模块循环
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
                keys = st.r.scan_iter(match=f"{st.TASK_PREFIX}*")
                for key in keys:
                    st.cancel_task_by_id(key)
                os._exit(0)
            elif cmd.lower() == 'gettask':
                keys = st.r.scan_iter(match=f"{st.TASK_PREFIX}*")
                tasks = {}
                for key in keys:
                    # key 格式为 task:uuid
                    if isinstance(key, bytes):
                        tid = key.decode().split(':', 1)[-1]
                    else:
                        tid = key.split(':', 1)[-1]
                    task = st.get_task(tid)  # 已经反序列化 progress/file_info
                    if task:
                        # 过滤不可序列化字段，保持与原 /api/dl 一致
                        filtered = {}
                        for k, v in task.items():
                            filtered[k] = v
                        tasks[tid] = filtered
                send_plain(sock=sock, msg=str(tasks), key=session_key)
            elif cmd.lower() == 'cleartask':
                keys = st.r.scan_iter(match=f"{st.TASK_PREFIX}*")
                for key in keys:
                    if isinstance(key, bytes):
                        tid = key.decode().split(':', 1)[-1]
                    else:
                        tid = key.split(':', 1)[-1]
                    task = st.get_task(tid)
                    if task and task.get('status') not in ('running', 'pending'):
                        st.delete_task(tid)
                        send_plain(sock, f'remove task {tid}\n', session_key)
            elif cmd.lower().startswith('passwd'):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 3:
                    username,passwd = parts[1],parts[2]
                    with st._user_lock:
                        exists = username in users
                    if not exists:
                        send_plain(sock, '用户不存在', session_key)
                    else:
                        with _user_lock:
                            st.users[username] = generate_password_hash(passwd)
                            send_plain(sock, f"用户 *** 密码已更改", session_key)
                            logging.warning(f"[audit] passwd: {username} (by {sock.getpeername()})")
                            st.save_user()
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
                                lp = safe_path(path_part) if path_part else st.UPLOAD_DIR
                            except ValueError:
                                send_plain(sock, 'path not allowed', session_key)
                                break
                            for n in os.listdir(lp):
                                send_plain(sock, n + '\n', session_key)
                            break
                else:
                    try:
                        lp = safe_path(path_part) if path_part else st.UPLOAD_DIR
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
                    shutil.move(ss, st.TRASH_DIR)
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
                from app import load_html
                load_html()
                send_plain(sock, "load ok", session_key)
            elif cmd.lower().startswith('debug '):
                ddd = cmd.lower().replace("debug ", "").strip()
                if ddd == "open":
                    # 邮件验证:向管理员绑定邮箱发送一次性验证码
                    admin_mail = st.user_emails.get(st.admin, '')
                    if not admin_mail or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', admin_mail):
                        send_plain(sock, "debug open refused: 管理员未绑定邮箱,请先用 setmail 绑定", session_key)
                    else:
                        code = f"{secrets.randbelow(1000000):06d}"
                        st.r.set(DEBUG_CODE_PREFIX + code, st.admin, ex=DEBUG_CODE_TTL)
                        try:
                            _send_mail(admin_mail, "开启调试模式验证码",
                                       f"你的调试模式验证码是: {code}\n{DEBUG_CODE_TTL // 60} 分钟内有效,请勿泄露。\n-- {st.SITE_URL}",
                                       f"<p>你的调试模式验证码是: <b>{code}</b></p>"
                                       f"<p>{DEBUG_CODE_TTL // 60} 分钟内有效,请勿泄露。</p>")
                            send_plain(sock, f"验证码已发送至 {admin_mail}({DEBUG_CODE_TTL // 60}分钟内有效),请用 debug open <验证码> 完成验证", session_key)
                        except Exception as e:
                            logging.error(f"debug 验证码邮件发送失败: {e}")
                            st.r.delete(DEBUG_CODE_PREFIX + code)
                            send_plain(sock, "验证码邮件发送失败,请稍后再试", session_key)
                elif ddd.startswith("open "):
                    parts = ddd.split(None, 1)
                    code = parts[1] if len(parts) == 2 else ''
                    # 验证码尝试限流:同一来源 IP 连续失败 10 次,锁 10 分钟
                    try:
                        peer_ip = sock.getpeername()[0]
                    except OSError:
                        peer_ip = 'unknown'
                    attempt_key = f'debug_open_fail:{peer_ip}'
                    if int(st.r.get(attempt_key) or 0) >= 10:
                        send_plain(sock, "验证码尝试次数过多,请10分钟后再试", session_key)
                        continue
                    if code and st.r.get(DEBUG_CODE_PREFIX + code):
                        st.r.delete(DEBUG_CODE_PREFIX + code)   # 一次性:用完即失效
                        st.r.delete(attempt_key)
                        create_file(os.path.join(st.BASE_DIR, "de.lock"))
                        app.debug = True
                        logging.warning(f"[audit] debug mode OPEN (by {sock.getpeername()})")
                        send_plain(sock, "debug mode open ok", session_key)
                    else:
                        # 验证码错误/过期:计数 + 节流 + 日志(不输出验证码明文)
                        st.r.incr(attempt_key)
                        st.r.expire(attempt_key, 600)
                        logging.warning(f"debug open 验证码错误: client={sock.getpeername()}")
                        time.sleep(1)
                        send_plain(sock, "debug open refused: 验证码错误或已过期", session_key)
                elif ddd == "close":
                    if os.path.exists(os.path.join(st.BASE_DIR, "de.lock")):
                        os.remove(os.path.join(st.BASE_DIR, "de.lock"))
                    app.debug = False
                    send_plain(sock, "debug mode close ok", session_key)
                else:
                    send_plain(sock, f"debug mode {'open' if app.debug else 'close'}", session_key)

            elif cmd.lower().startswith("adduser "):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 4:
                    username, password, mail = parts[1], parts[2], parts[3]
                    with st._user_lock:
                        exists = username in st.users
                    if exists:
                        send_plain(sock, '用户已存在', session_key)
                    elif not st.USERNAME_RE.match(username):
                        send_plain(sock, '用户名仅允许字母/数字/_- ,长度 1~32', session_key)
                    elif len(password) < 8:
                        send_plain(sock, '密码至少 8 位', session_key)
                    elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', mail):
                        send_plain(sock, '邮箱格式不正确', session_key)
                    else:
                        with st._user_lock:
                            st.users[username] = generate_password_hash(password)
                            st.user_list.append(username)
                            st.user_emails[username] = mail
                            st.save_user()   # 与内存修改同一把锁内落库,防 load_redis 覆盖丢失
                        send_plain(sock, f"用户 *** 已添加(邮箱 {mail})", session_key)
                        logging.warning(f"[audit] adduser: {username} (by {sock.getpeername()})")
                else:
                    send_plain(sock, 'usage: adduser <user> <password> <mail@Example.com>', session_key)

            elif cmd.lower().startswith("setmail "):
                # 为已存在用户绑定/更新邮箱(密码找回用);adduser 会拒绝重名,故单独提供
                parts = [p for p in cmd.split() if p]
                if len(parts) == 3:
                    username, mail = parts[1], parts[2]
                    with st._user_lock:
                        exists = username in st.users
                    if not exists:
                        send_plain(sock, '用户不存在', session_key)
                    elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', mail):
                        send_plain(sock, '邮箱格式不正确', session_key)
                    else:
                        with st._user_lock:
                            st.user_emails[username] = mail
                            st.save_user()   # 锁内落库,防 load_redis 覆盖丢失
                        send_plain(sock, f"邮箱已更新: {username} -> {mail}", session_key)
                else:
                    send_plain(sock, 'usage: setmail <user> <mail@Example.com>', session_key)

            elif cmd.lower().startswith("deluser "):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 2:
                    username = parts[1]
                    if username == st.admin:
                        send_plain(sock, '不能删除管理员账号', session_key)
                        continue
                    with st._user_lock:
                        if username in st.users and username in st.user_list:
                            del st.users[username]
                            st.user_list.remove(username)
                            st.user_emails.pop(username, None)
                            deleted = True
                        elif username in st.users and username in st.blocked_users:
                            del st.users[username]
                            st.blocked_users.remove(username)
                            st.user_emails.pop(username, None)
                            deleted = True
                        else:
                            deleted = False
                        if deleted:
                            st.save_user()   # 锁内落库,防 load_redis 快照覆盖把已删用户"复活"
                    if deleted:
                        # 锁外清理:个人盘/分享链接/会话,避免长操作占锁
                        _purge_user(username)
                        send_plain(sock, f"用户 *** 已删除", session_key)
                        logging.warning(f"[audit] deluser: {username} (by {sock.getpeername()})")
                    else:
                        send_plain(sock, "用户不存在", session_key)

            elif cmd.lower().startswith(("listuser")):
                with st._user_lock:
                    info = ["当前用户列表:"]
                    for user in st.users.keys():
                        role = ""
                        if user in st.blocked_users:
                            role += " forbid"
                        else:
                            # 只读展示,不在列表操作中写数据(避免副作用)
                            role += " authorized"
                        if user == st.admin:
                            role += " admin"
                        email = st.user_emails.get(user, '')
                        info.append(f"--{user} {role}  {email}")
                send_plain(sock, "\n".join(info), session_key)

            # 兼容旧命令 addnigga/delnigga;新命令名为 block/unblock
            elif cmd.lower().startswith(("addnigga ", "block ")):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 2:
                    username = parts[1]
                    with st._user_lock:
                        exists = username in st.users
                        in_block = username in st.blocked_users
                    if not exists:
                        send_plain(sock, f"*** 不存在", session_key)
                    elif not in_block:
                        with st._user_lock:
                            st.blocked_users.append(username)
                            if username in st.user_list:
                                st.user_list.remove(username)
                            st.save_user()   # 锁内落库
                        send_plain(sock, f"用户 *** 已移入黑名单", session_key)

            elif cmd.lower().startswith(("delnigga ", "unblock ")):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 2:
                    username = parts[1]
                    with st._user_lock:
                        exists = username in st.users
                        in_block = username in st.blocked_users
                    if not exists:
                        send_plain(sock, f"*** 不存在", session_key)
                    elif in_block:
                        with st._user_lock:
                            st.blocked_users.remove(username)
                            if username not in st.user_list:
                                st.user_list.append(username)
                            st.save_user()   # 锁内落库
                        send_plain(sock, f"用户 *** 已移出黑名单", session_key)

            elif cmd.lower().startswith("setadmin "):
                parts = [p for p in cmd.split() if p]
                if len(parts) == 2:
                    username = parts[1]
                    with st._user_lock:
                        exists = username in st.users
                        in_list = username in st.user_list
                    if not exists:
                        send_plain(sock, f"*** 不存在", session_key)
                    elif in_list:
                        with st._user_lock:
                            st.admin = username
                            st.save_user()   # 锁内落库
                        send_plain(sock, f"用户 *** 已设为管理员", session_key)
                        logging.warning(f"[audit] setadmin: {username} (by {sock.getpeername()})")

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
                if name == 'app':
                    val = app
                else:
                    val = getattr(st, name, None)
                if isinstance(val, (dict, list, set)):
                    send_plain(sock, f"{type(val).__name__}(len={len(val)})", session_key)
                else:
                    send_plain(sock, str(val), session_key)

            elif cmd.lower() == 'clearlog':
                open(os.path.join(st.BASE_DIR, 'app.log'), 'w', encoding='utf-8').close()
                send_plain(sock, 'log clear', session_key)
                err_file = os.path.join(st.BASE_DIR, 'error')
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
                if tokens[0] not in st.r.smembers('command') or exe is None:
                    send_plain(sock, 'can\'t exec', session_key)
                else:
                    # 通知客户端已进入终端模式（客户端据此决定是否启动 stdin 输入线程）
                    send_plain(sock, '\x02TERM', session_key)
                    # 不再使用 shell=True，避免 `run ping; rm -rf` 之类注入绕过白名单
                    # PYTHONUNBUFFERED=1 让 python 子进程行缓冲/无缓冲，保证实时输出
                    env = dict(os.environ)
                    env['PYTHONUNBUFFERED'] = '1'
                    stop_event = Event()

                    process = subprocess.Popen([exe] + tokens[1:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, cwd=st.UPLOAD_DIR, text=True, env=env)
                    stdin_thread = None
                    if stdin_on:
                        logging.debug('term')
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
                send_plain(sock, str(st.r.smembers('command')), session_key)
            elif cmd.startswith('cr ') and app.debug:
                cmd_name = cmd.replace("cr ", '', 1).strip()
                if cmd_name and ' ' not in cmd_name and shutil.which(cmd_name):
                    st.r.sadd('command', cmd_name)
                    st.r.smembers('command')
                    send_plain(sock, f'command {cmd_name} added', session_key)
                else:
                    send_plain(sock, 'can\'t add command', session_key)
            else:
                send_plain(sock, "未知命令", session_key)

        except socket.timeout:
            # 空闲超时：交由 _handle_admin_conn 统一断开
            raise
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                # 只写堆栈，不 dump locals —— locals 含明文密码(nm)/会话密钥/命令文本，禁止落盘
                with open(os.path.join(st.BASE_DIR, 'error'), 'w', encoding='utf-8') as d:
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


# ==================== 传输端点(update/download) ====================

def _bind_transfer_socket(sock, ip, port):
    """绑定传输监听端口:客户端指定 IP 绑定失败(如非本机接口)时回退到 ADMIN_BIND。"""
    for addr in (ip, ADMIN_BIND):
        try:
            sock.bind((addr, port))
            return True
        except OSError as e:
            logging.warning(f"绑定 {addr}:{port} 失败: {e}")
    return False


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

def update_file(ip, port, token):
    n = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    n.settimeout(30)   # 客户端拿了端口不来连时,线程不会永久挂起
    if not _bind_transfer_socket(n, ip, port):
        n.close()
        return
    n.listen(1)
    try:
        con, addr = n.accept()
    except socket.timeout:
        logging.warning('update accept timeout')
        n.close()
        return
    try:
        if not _recv_token(con, token):
            logging.warning('update token mismatch')
            return
        # 认证后仍保留空闲超时(_recv_token 内部会清掉超时),防线程永久挂起
        con.settimeout(TRANSFER_IDLE_TIMEOUT)
        # 磁盘余量预检:至少保留 1GB,防大文件写满磁盘
        if shutil.disk_usage(st.UPLOAD_DIR).free < 1024 ** 3:
            logging.error('update 磁盘空间不足,拒绝接收')
            return
        if not recv_file(con, save_dir=st.UPLOAD_DIR, max_size=1024 * 1024 * 1024):
            logging.error('update 接收文件失败')
    finally:
        con.close()
        n.close()

def download_file(ip, port, token):
    n = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    n.settimeout(30)   # 同 update_file:防线程永久挂起
    if not _bind_transfer_socket(n, ip, port):
        n.close()
        return
    n.listen(1)
    try:
        con, addr = n.accept()
    except socket.timeout:
        logging.warning('download accept timeout')
        n.close()
        return
    try:
        if not _recv_token(con, token):
            logging.warning('download token mismatch')
            return
        # 认证后仍保留空闲超时(_recv_token 内部会清掉超时),防线程永久挂起
        con.settimeout(TRANSFER_IDLE_TIMEOUT)
        # 客户端发送：struct.pack('!I', len(name)) + name.encode()
        raw_len = con.recv(4)
        if len(raw_len) < 4:
            return
        name_len = struct.unpack('!I', raw_len)[0]
        if name_len > 4096:
            logging.warning('download name too long')
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
            logging.warning('download path not allowed')
        else:
            if not os.path.isfile(file_path):
                logging.warning('download file not found')
            elif not send_file(con, file_path):
                logging.error('download 发送文件失败')
    finally:
        con.close()
        n.close()
