import os,sys
import socket
import struct
from time import sleep
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from file_rw import recv_file, send_file
from threading import Thread,Event
import select
try:
    import msvcrt          # Windows 下用 kbhit 做可打断的 stdin 轮询
    _HAS_KBHIT = True
except ImportError:
    _HAS_KBHIT = False
import stun
_,b,_=stun.get_ip_info(stun_host="stun1.l.google.com",stun_port=19302)
def recv_exact(sock, n):
    """精确接收 n 字节数据"""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_enc_frame(sock, key, plaintext: bytes):
    """发送 AES-256-GCM 加密帧：长度(4字节大端) + nonce(12) + 密文 + tag(16)"""
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    payload = nonce + ct + tag
    sock.sendall(struct.pack('>I', len(payload)) + payload)

def recv_enc_frame(sock, key):
    """接收并解密 AES-256-GCM 加密帧，返回明文字节串；连接关闭返回 None"""
    raw_len = recv_exact(sock, 4)
    if raw_len is None:
        return None
    length = struct.unpack('>I', raw_len)[0]
    payload = recv_exact(sock, length)
    if payload is None:
        return None
    if length < 28:   # nonce(12) + tag(16) 是最小帧
        raise ValueError("非法加密帧长度")
    nonce, body = payload[:12], payload[12:]
    ct, tag = body[:-16], body[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def recv_reply(sock, key, echo=True):
    """读取回复，直到收到 \4 结束帧；echo=True 时边收边打印，实现实时输出"""
    out = b''
    while True:
        frame = recv_enc_frame(sock, key)
        if frame is None:
            break
        if frame == b'\4':
            break
        out += frame
        if echo:
            _echo(frame)
    return out

def _echo(frame):
    """打印一帧内容（去掉 \0 结尾）；优先 utf-8，失败按本地代码页(gbk)解码"""
    data = frame.replace(b'\0', b'')
    if not data:
        return
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        text = data.decode('gbk', errors='replace')
    if text:
        print(text, end='', flush=True)

def stdin_u(sock:socket.socket,e:Event,key):
    """终端输入线程：读取本地 stdin 并加密发送；输入 exit 或 Ctrl-D 时发送 EOT 结束终端。
    Windows 用 msvcrt.kbhit、Unix 用 select 轮询，以便停止事件能及时打断阻塞。"""
    buf = ''
    while not e.is_set():
        if _HAS_KBHIT:
            if not msvcrt.kbhit():
                time.sleep(0.05)
                continue
        else:
            if not select.select([sys.stdin], [], [], 0.2)[0]:
                continue
        n = sys.stdin.read(1)
        if not n:
            break
        buf += n
        if buf.endswith('exit\n') or '\x04' in buf:
            send_enc_frame(sock, key, b'\4')
            break
        send_enc_frame(sock, key, n.encode())

def bash(sock:socket.socket,key):
    a = Event()
    t= Thread(target=stdin_u,args=(sock,a,key))
    t.start()
    recv_reply(sock,key)
    a.set()


def _send_token(sock, token):
    """发送传输连接认证 token:长度(4)+token 字节。"""
    data = token.encode()
    sock.sendall(struct.pack('!I', len(data)) + data)


def update(host, port, token):
    aa = input('path:')
    if os.path.isfile(aa):
        a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        a.connect((host, port))
        _send_token(a, token)
        send_file(a, aa)

def download(h, p, token):
    aa = input('path:')
    a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a.connect((h, p))
    _send_token(a, token)
    a.sendall(struct.pack('!I', len(aa)) + aa.encode())
    save_dir = os.path.dirname(aa) if os.path.dirname(aa) else '.'
    recv_file(a, save_dir, display=True)

def login():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    aa = input("address:")
    if ':' in aa:
        xx = aa.split(':')
        aa = xx[0].strip()
        bb = xx[1].strip()
    else:
        bb = input('post:')

    if bb.isdecimal():
        bb = int(bb)
    else:
        exit()
    sock.connect((aa, bb))

    # 1. 接收公钥长度 + 公钥数据
    raw_len = recv_exact(sock, 4)
    pub_len = struct.unpack('>I', raw_len)[0]
    pub_bytes = recv_exact(sock, pub_len)
    public_key = RSA.import_key(pub_bytes)

    # 2. 生成 32 字节随机会话密钥，用 RSA-OAEP 加密后发送（仅此一次非对称运算）
    session_key = os.urandom(32)
    cipher = PKCS1_OAEP.new(public_key)
    enc = cipher.encrypt(session_key)
    sock.sendall(struct.pack('>I', len(enc)) + enc)

    # 3. 认证信息走 AES-256-GCM 加密帧
    n = input('user:')
    p = input('password:')
    if n == "" and p == "":
        p = n = 'admin'
    send_enc_frame(sock, session_key, f'{n},{p},{b}'.encode())

    # 4. 接收认证结果（AES-GCM 帧，直到 \4 结束）
    sock.settimeout(10)
    try:
        response = recv_reply(sock, session_key, echo=False)
    except Exception:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        login()
    print('认证结果:', response.decode())
    sock.settimeout(None)   # 回复以 \4 帧结束，无需再用超时判断响应结束
    return sock, session_key, aa, bb

sock, session_key, aa, bb = login()
# 后续命令全部走 AES-256-GCM 加密帧
abibi = time.time()
while True:
    ma = sock.recv(10)
    if ma == b'b':
        bash(sock,session_key)
    cmd = input(f'{aa}:{bb} {int((time.time()-abibi)*1000)}ms> ')
    abibi = time.time()
    if cmd == 'quit':
        cmd = '</c>'
        send_enc_frame(sock, session_key, cmd.encode())
        recv_reply(sock, session_key)   # 已实时打印
        exit(0)
    if cmd == "":
        cmd = "k"

    send_enc_frame(sock, session_key, cmd.encode())
    if cmd.startswith('run term'):
        # 先收确认帧：服务端真正进入终端模式（发 \x02TERM）才启动 stdin 输入线程；
        # 否则（如命令不在白名单）按普通回复处理，避免后台 stdin 线程污染后续命令。
        stop = Event()
        first = recv_enc_frame(sock, session_key)
        if first is not None and first.startswith(b'\x02TERM'):
            t = Thread(target=stdin_u, args=(sock, stop, session_key), daemon=True)
            t.start()
        elif first is not None:
            _echo(first)
        while True:
            frame = recv_enc_frame(sock, session_key)
            if frame is None or frame == b'\4':
                break
            _echo(frame)
        stop.set()
        continue
    resp = recv_reply(sock, session_key)   # 边收边打印
    text = resp.replace(b'\0', b'').decode('utf-8', errors='replace').strip()
    if cmd == 'update' or cmd == 'download':
        # 服务端回复 "端口:一次性token",传输连接须先出示 token
        try:
            port_str, tok = text.split(':', 1)
            n = int(port_str)
            if cmd == 'update':
                send_enc_frame(sock,session_key,b.encode())
                update(aa, n, tok)
            else:
                send_enc_frame(sock,session_key,b.encode())
                download(aa, n, tok)
        except (ValueError, TypeError):
            pass
    print()
