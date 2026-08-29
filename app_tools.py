# -*- coding: utf-8 -*-
"""
文件处理工具:分割/合成、哈希、解压(zip/7z,防 Zip Slip)、URL 下载(防 SSRF)。

日志统一走标准 logging(传播到 app.py 配置的 root logger,行为与原 app.logger 一致)。
"""
import os
import io
import re
import time
import logging
import shutil
import hashlib
import socket
import struct
import ipaddress
import zipfile
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

import requests
import pyzipper
from py7zr import SevenZipFile
from py7zr.callbacks import ExtractCallback

# 禁用不安全的请求警告（针对 verify=False）
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import app_state as st
from app_paths import safe_path, clean_filename


def get_filename_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.path.split('/')[-1]


class tool:
    class u1:
        @staticmethod
        def call(source_path, chunk_size, output_dir, task_id, cancel_check):
            if os.path.exists(output_dir):
                if os.path.isdir(output_dir):
                    shutil.rmtree(output_dir)
                else:
                    os.remove(output_dir)  # 如果是同名文件则删除
            os.makedirs(output_dir)

            file_count = 0
            out = None
            try:
                with open(source_path, "rb") as src:
                    while True:
                        if cancel_check():
                            raise st.Cancelled("cancel")
                        # 每个输出文件累计写满 chunk_size;分块读写,避免整块进内存
                        if out is None:
                            file_count += 1
                            out_name = os.path.join(output_dir, f"{file_count:04d}.data")
                            out = open(out_name, "wb")
                            written = 0
                        data = src.read(min(chunk_size - written, 1024 * 1024))
                        if not data:
                            break
                        out.write(data)
                        written += len(data)
                        if written >= chunk_size:
                            out.close()
                            out = None
            except st.Cancelled:
                if out is not None:
                    out.close()
                shutil.rmtree(output_dir)
                raise
            finally:
                if out is not None:
                    out.close()

            # 写入元信息
            meta_path = os.path.join(output_dir, "file")
            with open(meta_path, "w", encoding="utf-8") as meta:
                meta.write(f"{os.path.basename(source_path)}\n")
                meta.write(f"{file_count}\n")
                meta.write(f"{chunk_size}\n")
            return True

    class u2:
        @staticmethod
        def call(dir, tdir, task_id, cancel_check):
            with open(os.path.join(dir, "file"), "r", encoding="utf-8") as fmeta:
                n = os.path.basename(fmeta.readline().rstrip("\n"))
                x = int(fmeta.readline().rstrip("\n"))
            with open(os.path.join(tdir, n), "wb") as bn:
                for nb in range(1, x + 1):
                    if cancel_check():
                        os.remove(bn.name)
                        raise st.Cancelled("cancel")
                    with open(os.path.join(dir, f"{nb:04d}.data"), "rb") as an:
                        # 分块拷贝,避免整块(最大64MB)读入内存
                        while True:
                            chunk = an.read(1024 * 1024)
                            if not chunk:
                                break
                            bn.write(chunk)
            return True


def get_hash(path, task_id, cancel_check):
    n = hashlib.sha256()
    with open(path, 'rb') as b:
        for chunk in iter(lambda: b.read(1024 * 1024 * 10), b''):
            n.update(chunk)
            if cancel_check():
                raise st.Cancelled("cancel")
    return True, str(n.hexdigest())


# ==================== 解压(zip/7z) ====================

def sze(file, od, password, task_id, root=None):
    root = root or st.UPLOAD_DIR
    zp = safe_path(file, root=root)
    if not os.path.isfile(zp):
        raise FileNotFoundError(f"not found:{zp}")
    basename = str(os.path.basename(zp))
    a, b = os.path.splitext(basename)
    if not a:
        a = "extracted"
    target_base = os.path.join(od, a)
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
        sece(zp, target_dir, file, password, task_id)
        return True, target_dir
    except Exception as e:
        logging.error(f"解压失败: {e}")
        if os.path.exists(target_dir) and not os.listdir(target_dir):
            os.rmdir(target_dir)
        return False, target_dir


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
    # 与磁盘剩余空间比对(至少保留 512MB 余量),避免解压写满磁盘
    if acc > shutil.disk_usage(target_dir).free - 512 * 1024 ** 2:
        raise Exception("磁盘空间不足,无法解压")
    return total

def _extract_loop(zf, members, target_dir, task_id, max_total=50 * 1024**3, max_entries=100000):
    """统一的解压循环（zip/pyzipper）：取消检查 + 逐文件解压 + 进度更新。

    注：py7zr 的 extract 在同一个 SevenZipFile 上多次调用不可靠（CRC 错误），
    7z 请走 sece 的 extractall + 回调方案。
    """
    total = _validate_extract_members(members, target_dir, max_total, max_entries)
    for idx, member in enumerate(members):
        # 每次解压一个文件前检查取消
        if st.is_cancelled(task_id):  # 直接使用 Redis 检查，因为此处拿不到 cancel_check 闭包
            # 清理已解压的部分
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
            raise st.Cancelled("解压被取消")
        name = member.filename
        # 目录条目只建目录,不执行 extract(py7zr 的 FileInfo 用 is_directory 标记)
        if name.endswith('/') or getattr(member, 'is_directory', False):
            os.makedirs(os.path.realpath(os.path.join(target_dir, name)), exist_ok=True)
        else:
            zf.extract(member, target_dir)
        # 更新任务进度
        st.update_task_progress(task_id, total=total, current=idx + 1)
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
        st.update_task_progress(self.task_id, total=self.total, current=self.current)

    def report_update(self, decompressed_bytes):
        pass

    def report_end(self, file_path, wrote_bytes):
        pass

    def report_warning(self, message):
        logging.warning(f"7z 解压警告: {message}")

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
            raise st.Cancelled("解压被取消")
        return self._fp.read(n)

    def readinto(self, b):
        if self._cancel():
            raise st.Cancelled("解压被取消")
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


def sece(zp, target_dir, file, password, task_id):
    try:
        with open(zp, "rb") as raw:
            reader = _CancelReader(raw, lambda: st.is_cancelled(task_id))
            with SevenZipFile(reader, mode="r", password=password) as zf:
                members = zf.list()
                total = _validate_extract_members(members, target_dir)
                # py7zr 需单次 extractall（多次 extract 会 CRC 失败）
                zf.extractall(target_dir, callback=_SevenZipExtractCallback(task_id, total))
        logging.info(f"解压完成: {file} -> {target_dir}")
    except st.Cancelled:
        # 取消：清理已解压的部分，与原 _extract_loop 行为一致
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
        raise
    except Exception as e:
        st.save_task(task_id, {'error': str(e)})
        raise e


def zipe(file: str, dir, password, task_id, root=None):
    """解压 ZIP 文件，并防止 Zip Slip 攻击"""
    root = root or st.UPLOAD_DIR
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
            zce(zip_path, target_dir, file, task_id)
        else:
            zece(zip_path, target_dir, file, password.encode(), task_id)
        return True
    except Exception as e:
        logging.error(f"解压失败: {e}")
        if os.path.exists(target_dir) and not os.listdir(target_dir):
            os.rmdir(target_dir)
        raise e

def zce(zip_path, target_dir, file, task_id):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            _extract_loop(zf, zf.infolist(), target_dir, task_id)
        logging.info(f"解压完成: {file} -> {target_dir}")
    except Exception as e:
        st.save_task(task_id, {'error': str(e)})
        raise e

def zece(zip_path, target_dir, file, password, task_id):
    try:
        with pyzipper.AESZipFile(zip_path, 'r') as zf:
            zf.setpassword(password)
            _extract_loop(zf, zf.infolist(), target_dir, task_id)
        logging.info(f"解压完成: {file} -> {target_dir}")
    except Exception as e:
        st.save_task(task_id, {'error': str(e)})
        raise e


# ==================== URL 下载(防 SSRF) ====================

# DNS 解析线程池:getaddrinfo 阻塞且无超时,丢到池子里限时,防 worker 线程被卡死
_dns_pool = ThreadPoolExecutor(max_workers=4)

def _resolve_host(host, port=None, socktype=None):
    """带超时的 getaddrinfo 封装;超时抛 ValueError。"""
    kw = {}
    if socktype is not None:
        kw['type'] = socktype
    fut = _dns_pool.submit(socket.getaddrinfo, host, port, **kw)
    try:
        return fut.result(timeout=5)
    except TimeoutError:
        raise ValueError(f"DNS 解析超时: {host}")

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
        infos = _resolve_host(host, None)
    except socket.gaierror:
        raise ValueError(f"无法解析主机: {host}")
    if any(_is_blocked_ip(info[4][0]) for info in infos):
        raise ValueError(f"禁止下载内网/私网地址: {host}")
    return parsed

# TLS 校验默认关闭以兼容"固定 IP 直连"模式:该模式下 https 的证书域名与 IP 对不上,
# 严格校验必然失败,故需 DOWNLOAD_VERIFY_TLS=0 或改用受控 DNS + 域名直连。
# 生产建议:确认内网环境可校验后显式设置 DOWNLOAD_VERIFY_TLS=1,并只信任受控 DNS。
DOWNLOAD_VERIFY_TLS = os.environ.get('DOWNLOAD_VERIFY_TLS', '0') == '1'
if not DOWNLOAD_VERIFY_TLS:
    logging.warning("DOWNLOAD_VERIFY_TLS 未开启:https 下载不做证书校验,存在中间人风险;"
                    "请确认网络环境后显式设置(生产建议 DOWNLOAD_VERIFY_TLS=1)")
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
        infos = _resolve_host(parsed.hostname, port, socket.SOCK_STREAM)
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
            if st.DOWNLOAD_MAX_SIZE and total > st.DOWNLOAD_MAX_SIZE:
                resp.close()
                raise ValueError(f"文件过大(超过 {st.DOWNLOAD_MAX_SIZE} 字节)")
            filename = clean_filename(get_filename_from_url(current))
            filepath = os.path.join(dir, filename)   # dir 是调用方算好的盘根(绝对路径)
            st.update_task_progress(task_id, total=total, current=0)
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
                        if st.DOWNLOAD_MAX_SIZE and downloaded + len(chunk) > st.DOWNLOAD_MAX_SIZE:
                            resp.close()
                            raise ValueError(f"下载超过大小上限 {st.DOWNLOAD_MAX_SIZE} 字节")
                        f.write(chunk)
                        downloaded += len(chunk)
                        # 进度更新节流：每 0.5 秒一次
                        if now - last_progress_update >= 0.5:
                            st.update_task_progress(task_id, current=downloaded)
                            last_progress_update = now
                # 收尾时更新最终进度
                st.update_task_progress(task_id, current=downloaded)
        return True
    except Exception as e:
        logging.error(f"下载错误: {e}")
        st.save_task(task_id, {'error': str(e)})
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        raise
