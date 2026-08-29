# -*- coding: utf-8 -*-
"""
路径与文件安全工具:盘根解析、路径越权防护、文件名清洗、元数据、个人盘目录。

只依赖 app_state(经 st.xxx 访问常量与任务数据),不依赖 Flask app。
"""
import os
import re
import json
import time
import shutil
import logging
import uuid
from datetime import datetime

from flask import g, session

import app_state as st


def _user_dirname(username):
    """个人盘目录名:统一规范化入口。
    adduser 已按 USERNAME_RE 校验新用户名;此处兜底历史脏数据(非法字符/超长)。"""
    name = clean_filename(username or 'unknown')
    return (name[:64] or 'unknown')

def _personal_root(username):
    """个人盘根目录:PRIVATE_ROOT/<用户名>/。"""
    return os.path.join(st.PRIVATE_ROOT, _user_dirname(username))

def _purge_user(username):
    """deluser 后的清理:删除个人盘数据与分享链接,并使该用户全部会话立即失效。
    注意:个人盘数据为物理删除;如需要可恢复窗口,可改为移入回收站。"""
    # 1) 个人盘目录
    priv = _personal_root(username)
    if os.path.isdir(priv):
        try:
            shutil.rmtree(priv, ignore_errors=True)
            logging.warning(f"[audit] deluser: 已删除个人盘 {priv}")
        except Exception as e:
            logging.error(f"删除用户 {username} 个人盘失败: {e}")
    # 2) 分享链接(新格式记录 owner,按归属删除)
    for key in st.r.scan_iter(match="share:*"):
        try:
            meta = json.loads(st.r.get(key))
        except (TypeError, ValueError):
            meta = None
        if isinstance(meta, dict) and meta.get('owner') == username:
            st.r.delete(key)
    # 3) 会话失效:版本号自增,该用户旧会话(含被窃取的)全部失效
    st.r.incr(f'sess_ver:{username}')

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
    return st.UPLOAD_DIR

def _root_for_scope(scope, username):
    """按 scope 与用户名确定盘根(worker 线程等无请求上下文场景)。"""
    if scope == 'personal':
        return _personal_root(username)
    return st.UPLOAD_DIR

def _task_root(task_id, default=None):
    """从任务记录读取提交时的盘根(worker 线程内路径解析用)。"""
    t = st.get_task(task_id)
    root = t.get('root') if t else None
    return root or default or st.UPLOAD_DIR

def safe_path(*parts, root=None):
    # 无参数或仅传入 '.'/'' 时，直接返回盘根
    if not parts or (len(parts) == 1 and parts[0] in ('.', '')):
        return root or st.UPLOAD_DIR

    base = root or st.UPLOAD_DIR
    target = os.path.realpath(os.path.abspath(os.path.join(base, *parts)))
    base_abs = os.path.realpath(base)
    # normcase 处理 Windows 大小写不敏感；os.sep 边界比较防 uploads_evil 之类前缀绕过
    if os.path.normcase(target) == os.path.normcase(base_abs):
        return target
    if os.path.normcase(target).startswith(os.path.normcase(base_abs) + os.sep):
        return target
    raise ValueError("路径越权")

def _share_path_check(path):
    """分享链接下载校验:只防穿越,允许读取共享盘与个人盘任意文件(链接本身 24h 过期)。
    注:新格式分享链接已不经过本函数(按归属盘根拼接),仅兼容旧格式记录。"""
    real = os.path.realpath(path)
    for base in (st.UPLOAD_DIR, st.PRIVATE_ROOT):
        base_real = os.path.realpath(base)
        if os.path.normcase(real) == os.path.normcase(base_real):
            return real
        if os.path.normcase(real).startswith(os.path.normcase(base_real) + os.sep):
            return real
    raise ValueError("路径越权")

def clean_filename(filename):
    if not filename: return "未命名文件"
    if isinstance(filename, bytes):
        try:
            filename = filename.decode('utf-8')
        except UnicodeDecodeError:
            try:
                filename = filename.decode('gbk')
            except UnicodeDecodeError:
                filename = filename.decode('latin-1')
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
    except OSError:
        return None

def _meta_base_for(scope=None, username=None):
    """元数据根目录:共享盘 META_DIR,个人盘 META_DIR/private/<用户名>/。"""
    s = scope if scope is not None else getattr(g, 'scope', 'shared')
    if s == 'personal':
        # 显式传入 username(后台/无会话上下文场景),缺省用当前会话用户
        u = username or session.get('user_id')
        return os.path.join(st.META_DIR, 'private', _user_dirname(u))
    return st.META_DIR

def _meta_dir_for(rel_path, scope=None, username=None):
    meta_base = _meta_base_for(scope, username)
    rel_dir = os.path.dirname(rel_path)
    if rel_dir:
        return os.path.join(meta_base, rel_dir)
    return meta_base

def save_meta(rel_path, original_name, size, scope=None, username=None):
    rel_path = os.path.normpath(rel_path)   # 防御:消除 ../ 等,避免元数据目录错位
    meta_dir = _meta_dir_for(rel_path, scope, username)
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
        priv_real = os.path.realpath(st.PRIVATE_ROOT)
        if os.path.normcase(src_real).startswith(os.path.normcase(priv_real) + os.sep):
            rest = src_real[len(priv_real):].lstrip(os.sep)
            user_part = rest.split(os.sep, 1)[0] if rest else ''
            root = os.path.join(priv_real, user_part) if user_part else priv_real
        else:
            root = st.UPLOAD_DIR

    target_abs = os.path.realpath(target_abs)
    root_abs = os.path.realpath(root)
    # normcase + os.sep 边界比较，防前缀绕过与大小写绕过
    if os.path.normcase(target_abs) == os.path.normcase(root_abs):
        return target_abs
    if os.path.normcase(target_abs).startswith(os.path.normcase(root_abs) + os.sep):
        return target_abs
    raise ValueError("目标路径越权")


def _ensure_distinct_target(src, dst):
    """防止复制/移动目标与源重叠,返回错误消息(无问题返回 None):
    - 文件:目标与源相同会让复制操作截断源文件;
    - 目录:目标位于源内部会造成无限递归复制,直至写满磁盘。"""
    src_real = os.path.realpath(src)
    dst_real = os.path.realpath(dst)
    if os.path.normcase(dst_real) == os.path.normcase(src_real):
        return '目标不能与源路径相同'
    if os.path.isdir(src_real) and os.path.normcase(dst_real).startswith(os.path.normcase(src_real) + os.sep):
        return '目标不能位于源目录内部'
    return None
