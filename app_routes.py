# -*- coding: utf-8 -*-
"""
业务路由:文件列表/上传(tus)/任务/复制移动/解压/分享/回收站/下载。

注册方式:app.py 调用 register_routes(app, csrf)。
"""
import os
import re
import json
import time
import uuid
import base64
import shutil
import logging
import traceback
from datetime import datetime
from urllib.parse import quote
from threading import Thread, RLock

from flask import (request, jsonify, make_response, send_from_directory,
                   session, redirect, url_for, abort, g)

import app_state as st
from app_paths import (safe_path, clean_filename, _reserve_upload_path,
                       _current_root, _root_for_scope, _task_root,
                       _share_path_check, _meta_base_for, _meta_dir_for,
                       save_meta, get_meta_path, resolve_target_path,
                       _ensure_distinct_target)
from app_tools import tool, get_hash, download, zipe, sze
from app_auth import login_required, is_allowed, is_admin, _client_ip


# ==================== 任务状态 ====================

@login_required
@is_allowed
def get_download_list():
    is_owner_view = session.get('user_id') != st.admin
    tids = st._task_ids_for_view(is_owner_view)
    all_tasks = st.get_tasks_bulk(tids)  # pipeline 批量读，避免逐 key N+1
    running_downloads = []
    for tid, task in all_tasks.items():
        if str(task.get('tool_id')) == str(st.TOOL_DOWNLOAD) and task.get('status') == 'running':
            # 非管理员只能看到自己的下载任务
            if is_owner_view and task.get('owner') != session.get('user_id'):
                continue
            running_downloads.append(tid)
    return jsonify(running_downloads), 200


@login_required
@is_allowed
def get_task_list_all():
    # 获取 Redis 中所有任务
    tasks = {}
    allowed_types = (str, int, float, bool, list, dict)
    is_owner_view = session.get('user_id') != st.admin
    tids = st._task_ids_for_view(is_owner_view)
    all_tasks = st.get_tasks_bulk(tids)  # pipeline 批量读，避免 N+1
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


@login_required
@is_allowed
def call_hash():
    limit_resp = st._check_pending_limit()
    if limit_resp:
        return limit_resp
    a = request.json
    try:
        ah = a.get('path', "")
        sp = safe_path(ah, root=_current_root())
    except Exception as d:
        logging.error(str(d))
        n = jsonify({'success': False})
        n.status_code = 400
        return n
    func = get_hash

    task_id = str(uuid.uuid4())
    tool_id = st.TOOL_HASH

    st.save_task(task_id, {
        'status': 'pending',
        'error': '',
        'tool_id': tool_id,
        'progress': {'total': 0, 'current': 0},
        'file_info': {'src': sp},
        'owner': session.get('user_id', ''),
        'root': _current_root(),
        'path': os.path.dirname(os.path.abspath(sp))
    })
    arg_list = (sp,)
    st.task_queue.put((task_id, func, arg_list, tool_id))
    return jsonify({'success': True, 'task_id': task_id})


@login_required
@is_allowed
def get_task_status(task_id):
    task = st.get_task(task_id)
    if not task:
        return jsonify({'success': False, 'error': '无效任务ID'}), 404
    if not st._can_access_task(task):
        return jsonify({'success': False, 'error': '无权访问该任务'}), 403

    a = {}
    # 注意：bytes/bytearray 无法被 jsonify 序列化，会直接 500
    n = [str, int, list, dict, bool, float]
    for aa, x in task.items():
        if type(x) in n:
            a[aa] = x
    a['success'] = True

    return jsonify(a)


@login_required
@is_allowed
def cancel_task(task_id):
    task = st.get_task(task_id)
    if not task:
        return jsonify({'success': False, 'error': '无效任务ID'}), 404
    if not st._can_access_task(task):
        return jsonify({'success': False, 'error': '无权操作该任务'}), 403
    success = st.cancel_task_by_id(task_id)
    if not success:
        return jsonify({'success': False, 'error': '任务无法取消'}), 400
    return jsonify({'success': True})


@login_required
@is_allowed
def webdelete_task(task_id):
    task = st.get_task(task_id)          # 直接获取任务对象
    if not task:
        return jsonify({'success': False, 'error': '无效任务ID'}), 404
    if not st._can_access_task(task):
        return jsonify({'success': False, 'error': '无权操作该任务'}), 403
    status = task.get('status', '')
    if status == 'running':
        return jsonify({'success': False, 'error': '任务正在运行，无法删除'}), 403
    elif status == 'pending':
        return jsonify({'success': False, 'error': '任务仍在队列中，无法删除'}), 403
    else:
        st.delete_task(task_id)
        return jsonify({'success': True})


# ==================== 移动 / 复制 ====================

def move_file(source, target, task_id, cancel_check):
    try:
        root = _task_root(task_id)
        src = safe_path(source, root=root)
        dst = resolve_target_path(src, target, root=root)
    except ValueError as e:
        st.save_task(task_id, {'error': str(e)})
        return False
    # 防目录移入自身/目标与源相同(无限递归或自覆盖)
    overlap = _ensure_distinct_target(src, dst)
    if overlap:
        st.save_task(task_id, {'error': overlap})
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


def _copy_chunked(src, dst, cancel_check):
    """分块复制单个文件,每 1MB 检查一次取消;取消抛 Cancelled 由调用方清理。"""
    with open(src, 'rb') as f_in, open(dst, 'wb') as f_out:
        while True:
            if cancel_check():
                raise st.Cancelled("复制被取消")
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
        st.save_task(task_id, {'error': str(e)})
        return False

    # 防目录复制进自身/目标与源相同(无限递归或截断源文件)
    overlap = _ensure_distinct_target(src, dst)
    if overlap:
        st.save_task(task_id, {'error': overlap})
        return False

    if not os.path.exists(src):
        st.save_task(task_id, {'error': '源路径不存在'})
        return False

    try:
        if os.path.isfile(src):
            # 确保目标目录存在
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                _copy_chunked(src, dst, cancel_check)
            except st.Cancelled:
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
                    raise st.Cancelled("复制被取消")
                rel_path = os.path.relpath(root, src)
                dest_root = os.path.join(dst, rel_path)
                os.makedirs(dest_root, exist_ok=True)
                for file in files:
                    if cancel_check():
                        if os.path.exists(dst):
                            shutil.rmtree(dst, ignore_errors=True)
                        raise st.Cancelled("复制被取消")
                    src_file = os.path.join(root, file)
                    dst_file = os.path.join(dest_root, file)
                    try:
                        _copy_chunked(src_file, dst_file, cancel_check)
                    except st.Cancelled:
                        if os.path.exists(dst):
                            shutil.rmtree(dst, ignore_errors=True)
                        raise
        else:
            st.save_task(task_id, {'error': '源路径类型未知'})
            return False
        return True
    except Exception as e:
        traceback.print_exc()
        st.save_task(task_id, {'error': str(e)})
        return False


# ==================== 解压 ====================

def zip_ex(f, sp, password, task_id, cancel_check):
    f = safe_path(f, root=_task_root(task_id))
    if not os.path.exists(f):
        st.save_task(task_id, {'error': '文件不存在'})
        return False

    _, n = os.path.splitext(f)
    try:
        if n == ".zip":
            a = zipe(f, sp, password, task_id, root=_task_root(task_id))
        elif n == '.7z':
            # sze 返回 (是否成功, 解压目录) 元组,不能整体当布尔用
            ok, _ = sze(f, sp, password, task_id, root=_task_root(task_id))
            a = ok
        else:
            st.save_task(task_id, {'error': 'not found'})
            return False
        if not a:
            task = st.get_task(task_id)
            if not task or task.get('error') == '':
                st.save_task(task_id, {'error': 'error'})
            return False

        return True
    except Exception as e:
        traceback.print_exc()
        logging.error(str(e))
        st.save_task(task_id, {'error': e})
        return False


# ==================== 工具调用 / 上传 ====================

@login_required
@is_allowed
def call_tool():
    limit_resp = st._check_pending_limit()
    if limit_resp:
        return limit_resp
    try:
        a = request.get_json(silent=True)
        if not isinstance(a, dict):
            return jsonify({'success': False, 'error': '无效请求数据'}), 400
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
        if tool_id == st.TOOL_ASSEMBLY:   # 合成文件
            func = tool.u2.call
            arg_list = (safe_path(clean, root=root), safe_dir)
        elif tool_id == st.TOOL_CUT:  # 分割文件
            m = re.search(r'-c\s+(\S+)\s+-f\s+(.+)', args_raw.strip())
            if not m:
                return jsonify({'success': False, 'error': '参数格式错误'}), 400
            try:
                chunk_size = int(m.group(1))
            except ValueError:
                return jsonify({'success': False, 'error': '块大小必须为整数'}), 400
            if not (1 <= chunk_size <= 64 * 1024 ** 2):
                return jsonify({'success': False, 'error': '块大小超出允许范围(1~64MB)'}), 400
            file_path = m.group(2)
            fp_clean = clean_arg(file_path)
            func = tool.u1.call
            arg_list = (safe_path(fp_clean, root=root), chunk_size,
                        os.path.join(safe_dir, os.path.basename(fp_clean) + "_cut"))
        elif tool_id == st.TOOL_INFO:
            return jsonify({'success': True, 'message': '使用Assembly以合成文件\n使用cut以分割文件,用法 -c 分割块大小 -f 文件(从根目录起)'}), 201

        elif tool_id == st.TOOL_DOWNLOAD:
            if session.get('user_id') == st.admin:
                func = download
                arg_list = (clean, safe_dir)
            else:
                return jsonify({'success': False, 'error': 'no admin'}), 403

        else:
            return jsonify({'success': False, 'error': '未知工具'}), 404

        task_id = str(uuid.uuid4())
        st.save_task(task_id, {
            'status': 'pending',
            'error': '',
            'tool_id': tool_id,
            'progress': {'total': 0, 'current': 0},
            'owner': session.get('user_id', ''),
            'root': root,
            'path': a.get("path")
        })
        st.task_queue.put((task_id, func, arg_list, tool_id))
        return jsonify({'success': True, 'task_id': task_id}), 202

    except Exception as e:
        traceback.print_exc()
        logging.error(str(e))
        return jsonify({'success': False, 'error': '服务器内部错误'}), 500


@login_required
@is_allowed
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': '没有选择文件'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': '文件名为空'}), 400
    original = file.filename
    folder = request.form.get('folder', '').strip()
    if clean_filename(original) in st.RESERVED_NAMES:
        return jsonify({'success': False, 'error': '名称被系统保留'}), 400
    if any(part in st.RESERVED_NAMES for part in folder.replace('\\', '/').split('/') if part):
        return jsonify({'success': False, 'error': '目录名被系统保留'}), 400
    try:
        target_dir = safe_path(folder, root=_current_root()) if folder else _current_root()
    except ValueError as e:
        return jsonify({'success': False, 'error': f'目录非法: {str(e)}'}), 400
    os.makedirs(target_dir, exist_ok=True)
    # 磁盘余量预检:至少保留 1GB 安全余量,防并发上传灌满磁盘
    if shutil.disk_usage(target_dir).free < (request.content_length or 0) + 1024 ** 3:
        return jsonify({'success': False, 'error': '磁盘空间不足,请稍后再试'}), 507
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


# ==================== tus 分块上传 ====================

def _tus_tmp_base(scope):
    """tus 临时目录:与目标盘同盘(. 开头,文件列表自动隐藏)。
    临时文件与最终落盘位置同文件系统,保证 os.replace 原子完成,
    磁盘余量检查口径也与目标盘一致。"""
    base = st.UPLOAD_DIR if scope != 'personal' else st.PRIVATE_ROOT
    d = os.path.join(base, '.tus_tmp')
    os.makedirs(d, exist_ok=True)
    return d

# 单次上传总量上限(字节,环境变量可调)
TUS_MAX_UPLOAD_SIZE = st._env_int('TUS_MAX_UPLOAD_SIZE', 10 * 1024**3)
# 上传无活动过期时间(秒):期间没有 PATCH 即视为放弃
TUS_UPLOAD_TTL = st._env_int('TUS_UPLOAD_TTL', 24 * 3600)
TUS_PREFIX = 'tus:'
# 单次 PATCH 分片上限(独立于全局 MAX_CONTENT_LENGTH,默认同为 1GB);并发写锁防同进程双 PATCH 交错
TUS_MAX_PATCH_SIZE = st._env_int('TUS_MAX_PATCH_SIZE', 1024 * 1024 * 1024)
_tus_write_lock = RLock()


def _tus_key(upload_id):
    return TUS_PREFIX + upload_id


def _tus_tmp_path(upload_id, tmp_dir=None):
    return os.path.join(tmp_dir or _tus_tmp_base('shared'), upload_id)


def _tus_meta(upload_id):
    raw = st.r.get(_tus_key(upload_id))
    if not raw:
        return None
    try:
        meta = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return meta if isinstance(meta, dict) else None


def _parse_tus_metadata(header):
    """解析 Upload-Metadata 头:逗号分隔的 'key base64url(value)' 对。"""
    out = {}
    if not header:
        return out
    for pair in header.split(','):
        pair = pair.strip()
        if not pair:
            continue
        parts = pair.split(' ', 1)
        key = parts[0].strip()
        val = ''
        if len(parts) == 2:
            s = parts[1].strip()
            try:
                val = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', 'replace')
            except (ValueError, TypeError):
                val = ''
        out[key] = val
    return out


def _tus_response(body='', status=204, **headers):
    """统一 tus 响应:tus 规范要求响应携带 Tus-Resumable 头。"""
    resp = make_response(body, status)
    resp.headers['Tus-Resumable'] = '1.0.0'
    for k, v in headers.items():
        resp.headers[k] = v
    return resp


def _tus_finish(upload_id, meta):
    """上传完成:原子移动到目标目录并写元数据;失败返回 False(丢弃本次上传)。"""
    target_dir = meta.get('target_dir') or st.UPLOAD_DIR
    filename = meta.get('filename') or '未命名文件'
    tmp = _tus_tmp_path(upload_id, meta.get('tmp_dir'))
    final_path = None
    try:
        os.makedirs(target_dir, exist_ok=True)
        # 目标文件名冲突时生成唯一名:O_EXCL 占位后原子替换占位
        name, ext = os.path.splitext(filename)
        counter = 1
        candidate = filename
        while True:
            cand = os.path.join(target_dir, candidate)
            try:
                fd = os.open(cand, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                final_path = cand
                break
            except FileExistsError:
                counter += 1
                candidate = f"{name} ({counter}){ext}" if counter <= 1000 else f"{name}_{int(time.time() * 1000) % 1000000}{ext}"
        try:
            os.replace(tmp, final_path)
        except OSError:
            # 跨文件系统回退为复制+删除(非原子,罕见场景)
            shutil.move(tmp, final_path)
        size = os.path.getsize(final_path)
        scope = meta.get('scope', 'shared')
        root = _root_for_scope(scope, meta.get('owner'))
        rel = os.path.relpath(final_path, root)
        save_meta(rel, filename, size, scope=scope, username=meta.get('owner'))
        return True
    except Exception as e:
        logging.error(f"tus 完成落盘失败: {e}")
        if final_path and os.path.exists(final_path):
            try:
                os.remove(final_path)
            except OSError:
                pass
        return False
    finally:
        st.r.delete(_tus_key(upload_id))
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


@login_required
@is_allowed
def tus_create():
    """tus creation:POST /api/tus,必须携带 Upload-Length;成功返回 Location。"""
    if request.headers.get('Tus-Resumable') != '1.0.0':
        return _tus_response('unsupported tus version', 412)
    length_str = request.headers.get('Upload-Length', '').strip()
    if not length_str.isdigit():
        return _tus_response('Upload-Length 缺失或非法', 400)
    length = int(length_str)
    if length > TUS_MAX_UPLOAD_SIZE:
        return _tus_response(f'上传超过大小上限 {TUS_MAX_UPLOAD_SIZE} 字节', 413)
    meta = _parse_tus_metadata(request.headers.get('Upload-Metadata', ''))
    filename = clean_filename(meta.get('filename', ''))
    if filename in st.RESERVED_NAMES:
        return _tus_response('名称被系统保留', 400)
    folder = meta.get('path', '').strip().replace('\\', '/')
    if any(part in st.RESERVED_NAMES for part in folder.split('/') if part):
        return _tus_response('目录名被系统保留', 400)
    try:
        target_dir = safe_path(folder, root=_current_root()) if folder else _current_root()
    except ValueError:
        return _tus_response('目标目录非法', 400)
    os.makedirs(target_dir, exist_ok=True)
    scope = getattr(g, 'scope', 'shared')
    tmp_base = _tus_tmp_base(scope)
    # 磁盘余量预检:按临时目录(与目标同盘)口径,至少保留 1GB 安全余量
    if shutil.disk_usage(tmp_base).free < length + 1024 ** 3:
        return _tus_response('磁盘空间不足,请稍后再试', 507)
    upload_id = uuid.uuid4().hex
    tmp = _tus_tmp_path(upload_id, tmp_base)
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except OSError:
        return _tus_response('创建上传失败', 500)
    st.r.set(_tus_key(upload_id), json.dumps({
        'scope': scope,
        'owner': session.get('user_id', ''),
        'filename': filename,
        'target_dir': target_dir,
        'tmp_dir': tmp_base,
        'length': length,
        'created': time.time(),
    }))
    st.r.expire(_tus_key(upload_id), TUS_UPLOAD_TTL)
    location = url_for('tus_upload', upload_id=upload_id)
    if scope == 'personal':
        location = st.PERSONAL_URL_PREFIX + location   # 个人盘补 /p 前缀,避免 scope 漂移
    return _tus_response('', 201, **{'Location': location})


@login_required
@is_allowed
def tus_upload(upload_id):
    """tus upload:PATCH /api/tus/<id>,Content-Type: application/offset+octet-stream。"""
    if request.headers.get('Tus-Resumable') != '1.0.0':
        return _tus_response('unsupported tus version', 412)
    meta = _tus_meta(upload_id)
    if not meta:
        return _tus_response('上传不存在或已过期', 404)
    user = session.get('user_id')
    if meta.get('owner') != user and user != st.admin:
        return _tus_response('无权操作该上传', 403)
    if request.headers.get('Content-Type', '').lower() != 'application/offset+octet-stream':
        return _tus_response('Content-Type 必须为 application/offset+octet-stream', 400)
    tmp = _tus_tmp_path(upload_id, meta.get('tmp_dir'))
    # 读-校验-写整体加锁,防同进程双 PATCH 交错(跨进程由 offset 校验兜底)
    with _tus_write_lock:
        try:
            offset = os.path.getsize(tmp)
        except OSError:
            return _tus_response('上传数据丢失', 404)
        # 顺序校验:客户端声明的 offset 必须与当前一致,不一致返回 409
        if request.headers.get('Upload-Offset') != str(offset):
            return _tus_response('offset 不匹配,请重试', 409)
        # 磁盘余量检查(至少保留 512MB;注意是 MB,勿写成 512*1024**3=512GB)
        if shutil.disk_usage(os.path.dirname(tmp)).free < 512 * 1024 ** 2:
            return _tus_response('磁盘空间不足,请稍后再试', 507)
        try:
            with open(tmp, 'ab') as f:
                written = 0
                while True:
                    chunk = request.stream.read(1024 * 1024)
                    if not chunk:
                        break
                    if written + len(chunk) > TUS_MAX_PATCH_SIZE:
                        return _tus_response('单次分片超过大小限制', 413)
                    if offset + written + len(chunk) > meta['length']:
                        return _tus_response('数据超出声明长度', 413)
                    f.write(chunk)
                    written += len(chunk)
        except OSError as e:
            logging.error(f"tus 写入失败: {e}")
            return _tus_response('写入失败', 500)
        new_offset = offset + written
        st.r.expire(_tus_key(upload_id), TUS_UPLOAD_TTL)
        if new_offset >= meta['length']:
            if not _tus_finish(upload_id, meta):
                return _tus_response('上传完成但落盘失败,请重新上传', 500)
        return _tus_response('', 204, **{'Upload-Offset': str(new_offset)})


@login_required
@is_allowed
def tus_head(upload_id):
    """tus HEAD:查询已上传字节数(断点续传依据)。"""
    meta = _tus_meta(upload_id)
    if not meta:
        return _tus_response('', 404)
    user = session.get('user_id')
    if meta.get('owner') != user and user != st.admin:
        return _tus_response('', 403)
    try:
        offset = os.path.getsize(_tus_tmp_path(upload_id, meta.get('tmp_dir')))
    except OSError:
        return _tus_response('', 404)
    return _tus_response('', 200, **{'Upload-Offset': str(offset), 'Upload-Length': str(meta['length'])})


@login_required
@is_allowed
def tus_terminate(upload_id):
    """tus termination:取消上传并清理临时文件。"""
    meta = _tus_meta(upload_id)
    if not meta:
        return _tus_response('', 404)
    user = session.get('user_id')
    if meta.get('owner') != user and user != st.admin:
        return _tus_response('', 403)
    st.r.delete(_tus_key(upload_id))
    tmp = _tus_tmp_path(upload_id, meta.get('tmp_dir'))
    if os.path.exists(tmp):
        try:
            os.remove(tmp)
        except OSError:
            pass
    return _tus_response('', 204)


def tus_autoclear():
    """清理过期/失效的 tus 临时文件:redis 记录不存在即视为过期,删除磁盘实体。
    共享盘与个人盘的临时目录都扫。"""
    for base in (_tus_tmp_base('shared'), _tus_tmp_base('personal')):
        try:
            for name in os.listdir(base):
                if st.r.exists(_tus_key(name)):
                    continue
                path = os.path.join(base, name)
                try:
                    if os.path.isfile(path):
                        os.remove(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                except OSError:
                    pass
        except OSError as e:
            logging.warning(f"tus 清理异常({base}): {e}")


def while_tus_autodelete():
    while True:
        time.sleep(600)
        tus_autoclear()


# ==================== 文件列表 / 目录 ====================

@login_required
@is_allowed
def list_files():
    rel_path = request.args.get('path', '').strip()
    limit = request.args.get('limit', type=int)
    offset = request.args.get('offset', type=int) or 0
    try:
        target_dir = safe_path(rel_path, root=_current_root()) if rel_path else _current_root()
    except ValueError:
        return jsonify({'success': False, 'error': '非法路径'}), 400
    if not os.path.isdir(target_dir):
        return jsonify({'success': False, 'error': '路径不存在'}), 404
    items = []

    try:
        # scandir 一次目录遍历即拿到类型/stat,比 listdir+isdir+isfile+stat 少 3 次系统调用
        for entry in os.scandir(target_dir):
            name = entry.name
            if name.startswith('.') or name == 'metadata' or name == 'chunks': continue
            try:
                is_dir = entry.is_dir()
            except OSError:
                is_dir = False
            ext = os.path.splitext(name)[1] if not is_dir else ""
            is_archive = ext in ('.zip', '.7z')   # 与 zip_ex 实际支持的格式一致

            if is_dir:
                info = {}
            else:
                try:
                    stat = entry.stat()
                    info = {'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
                except OSError:
                    info = {}
            items.append({
                'name': name,   # JSON 返回原始名，HTML 转义交给前端
                'type': 'directory' if is_dir else 'file',
                'size': info.get('size', 0),
                'modified': info.get('modified', ''),
                'type_file': ext,
                'type_zip': is_archive
            })
        items.sort(key=lambda x: (0 if x['type'] == 'directory' else 1, x['name'].lower()))
        # 可选分页:limit/offset 参数,缺省返回全部(兼容现有前端)
        if offset or limit is not None:
            items = items[offset: offset + limit if limit else None]
    except Exception as e:
        logging.error(str(e))
        return jsonify({'success': False, 'error': "see log"}), 500

    return jsonify({'success': True, 'data': items})


@login_required
@is_allowed
def create_folder():
    data = request.get_json(silent=True)
    if not data: return jsonify({'success': False, 'error': '无效数据'}), 400
    parent = data.get('path', '').strip()
    name = data.get('name', '').strip()
    if not name: return jsonify({'success': False, 'error': '名称不能为空'}), 400
    if name in ('.', '..'):
        return jsonify({'success': False, 'error': '名称不合法'}), 400
    if re.search(r'[\\/*?:"<>|]', name):
        return jsonify({'success': False, 'error': '名称包含非法字符'}), 400
    if name in st.RESERVED_NAMES:
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


@login_required
@is_allowed
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
    trash_dest = os.path.join(st.TRASH_DIR, item_id)

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
        st.r.setex(f"trash:{item_id}", st.TRASH_TTL, json.dumps(meta))  # 10天过期（与 TTL 一致）

        # 删除原有元数据（可选，如果需要恢复元数据请保留）
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


# ==================== 分享 / 下载 ====================

@login_required
@is_allowed
def share_put():
    data = request.get_json(silent=True) or {}
    file = data.get('file')
    try:
        full = safe_path(file, root=_current_root())
    except ValueError:
        return jsonify({'success': False, 'error': '路径非法'}), 400
    if not os.path.isfile(full):
        return jsonify({'success': False, 'error': '文件不存在'}), 404
    scope = getattr(g, 'scope', 'shared')
    owner = session.get('user_id', '')
    root = _root_for_scope(scope, owner)
    rel = os.path.relpath(full, root)
    u = str(uuid.uuid4())
    # 只存相对路径 + 归属,不落盘绝对路径(防泄露服务器目录结构);
    # 下载时按 scope/owner 重新拼盘根并校验,链接无法指向他人盘内文件
    st.r.setex(f"share:{u}", st.SHARE_TTL, json.dumps({
        'scope': scope, 'owner': owner, 'rel_path': rel, 'created': time.time(),
    }))
    host = request.host_url
    return jsonify({'link': host + "share/share_get/" + u})


def down(uuid):
    raw = st.r.get(f"share:{uuid}")
    if not raw:
        abort(404)
    try:
        meta = json.loads(raw)
    except (TypeError, ValueError):
        meta = None
    if isinstance(meta, dict):
        # 新格式:按归属盘根重新拼接相对路径,不信任任何存储的绝对路径
        scope = meta.get('scope', 'shared')
        owner = meta.get('owner', '')
        rel_path = meta.get('rel_path', '')
        if scope == 'personal' and not owner:
            abort(404)
        root = _root_for_scope(scope, owner)
        try:
            full = safe_path(rel_path, root=root)
        except ValueError:
            abort(404)
    else:
        # 旧格式(纯绝对路径字符串):兼容存量链接,仍做越权检查
        try:
            full = _share_path_check(raw)
        except ValueError:
            abort(404)
    if not os.path.isfile(full): abort(404)
    # 分享下载限流:同一 IP 每分钟最多 SHARE_RATE_LIMIT 次,防刷带宽/磁盘 IO
    ip = _client_ip() or 'unknown'
    rl_key = f'share_rl:{ip}'
    if int(st.r.get(rl_key) or 0) >= st.SHARE_RATE_LIMIT:
        abort(429)
    st.r.incr(rl_key)
    st.r.expire(rl_key, 60)
    # 与 URL 下载一致的大小上限,防分享超大文件
    if st.DOWNLOAD_MAX_SIZE and os.path.getsize(full) > st.DOWNLOAD_MAX_SIZE:
        abort(413)

    dirname = os.path.dirname(full)
    filename = os.path.basename(full)
    resp = make_response(send_from_directory(dirname, filename, as_attachment=True))
    resp.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(filename)}"
    return resp


@login_required
@is_allowed
@is_admin
def clear_all():
    try:
        for name in os.listdir(st.UPLOAD_DIR):
            if name == 'metadata' or name == 'chunks': continue
            path = os.path.join(st.UPLOAD_DIR, name)
            if os.path.isfile(path): os.remove(path)
            else: shutil.rmtree(path)
        if os.path.exists(st.META_DIR):
            shutil.rmtree(st.META_DIR)
            os.makedirs(st.META_DIR, exist_ok=True)
        # 个人盘一并清空(admin 权限)
        for name in os.listdir(st.PRIVATE_ROOT):
            path = os.path.join(st.PRIVATE_ROOT, name)
            if os.path.isfile(path): os.remove(path)
            else: shutil.rmtree(path)
        return jsonify({'success': True})
    except Exception as e:
        logging.error(str(e))
        return jsonify({'success': False, 'error': ""}), 500


@login_required
@is_allowed
def web_download_file(file_path):
    try:
        full = safe_path(file_path, root=_current_root())
    except ValueError:
        abort(404)
    if not os.path.isfile(full): abort(404)
    # 与 URL 下载一致的大小上限(0=不限制),防超大文件流式下载刷磁盘 IO
    if st.DOWNLOAD_MAX_SIZE and os.path.getsize(full) > st.DOWNLOAD_MAX_SIZE:
        abort(413)
    dirname = os.path.dirname(full)
    filename = os.path.basename(full)
    resp = make_response(send_from_directory(dirname, filename, as_attachment=True))
    resp.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(filename)}"
    return resp


# ==================== 回收站 ====================
# 回收站恢复/清理的进程内互斥锁(防同进程并发恢复时的目标路径竞态)
_trash_lock = RLock()

def trash_autoclear():
    n = []
    for name in os.listdir(st.TRASH_DIR):
        k = st.r.get(f'trash:{name}')
        if not k:
            trash_path = os.path.join(st.TRASH_DIR, name)
            if os.path.exists(trash_path):
                if os.path.isdir(trash_path):
                    shutil.rmtree(trash_path)
                else:
                    os.remove(trash_path)
            st.r.delete(f'trash:{name}')  # 同步清理失效的 Redis 记录
            n.append(name)
    return n

def while_trash_autodelete():
    while True:
        time.sleep(60)   # 回收站条目有 10 天 TTL,60 秒扫一次足够,避免高频全扫
        trash_autoclear()

@login_required
@is_allowed
def trash_list():
    items = []
    keys = st.r.scan_iter(match="trash:*")
    is_admin_view = session.get('user_id') == st.admin
    for key in keys:
        item_id = key.split(':', 1)[-1]
        meta_json = st.r.get(key)
        if not meta_json:
            continue
        meta = json.loads(meta_json)
        # 非管理员只能看到自己的回收站条目
        if not is_admin_view and meta.get('owner') != session.get('user_id'):
            continue
        trash_path = os.path.join(st.TRASH_DIR, item_id)
        if not os.path.exists(trash_path):
            st.r.delete(key)  # 清理无效记录
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


@login_required
@is_allowed
def trash_restore(item_id):
    meta_json = st.r.get(f"trash:{item_id}")
    if not meta_json:
        return jsonify({'success': False, 'error': '记录不存在'}), 404
    meta = json.loads(meta_json)
    trash_path = os.path.join(st.TRASH_DIR, item_id)
    if not os.path.exists(trash_path):
        st.r.delete(f"trash:{item_id}")
        return jsonify({'success': False, 'error': '文件已丢失'}), 404

    original_rel = meta['original_path']
    scope = meta.get('scope', 'shared')
    owner = meta.get('owner') or session.get('user_id')
    # 回收站条目只能由本人或 admin 恢复(个人盘与共享盘一致)
    if owner != session.get('user_id') and session.get('user_id') != st.admin:
        return jsonify({'success': False, 'error': '无权恢复该文件'}), 403
    root = _root_for_scope(scope, owner)
    target_full = safe_path(original_rel, root=root)  # 验证路径安全

    # 锁内完成"目标已存在→改名"与"移动"两步,消除检查与执行之间的 TOCTOU
    with _trash_lock:
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
            st.r.delete(f"trash:{item_id}")
            # 重新生成元数据（如果是文件）;必须传 username=owner,
            # 否则 admin 恢复他人个人盘文件时元数据会落进 admin 自己的 meta 目录
            if not meta['is_dir']:
                save_meta(original_rel, os.path.basename(target_full), os.path.getsize(target_full),
                          scope=scope, username=owner)
            return jsonify({'success': True})
        except Exception as e:
            logging.error(str(e))
            return jsonify({'success': False, 'error': str(e)}), 500


@login_required
@is_allowed
def trash_delete(item_id):
    # 只能删除自己(或 admin)的回收站条目,防止越权永久删除他人文件
    meta_json = st.r.get(f"trash:{item_id}")
    if not meta_json:
        if session.get('user_id') != st.admin:
            return jsonify({'success': False, 'error': '记录不存在'}), 404
    else:
        meta = json.loads(meta_json)
        if meta.get('owner') != session.get('user_id') and session.get('user_id') != st.admin:
            return jsonify({'success': False, 'error': '无权删除该回收站条目'}), 403
    # 同步删除磁盘实体，避免文件残留到下一次自动清理
    trash_path = os.path.join(st.TRASH_DIR, item_id)
    if os.path.exists(trash_path):
        if os.path.isdir(trash_path):
            shutil.rmtree(trash_path, ignore_errors=True)
        else:
            os.remove(trash_path)
    st.r.delete(f"trash:{item_id}")
    return jsonify({'success': True})


@login_required
@is_allowed
def trash_clear():
    """清空回收站:管理员清全部,普通用户只能清自己的条目(防越权删除他人文件)。"""
    is_admin_view = session.get('user_id') == st.admin
    keys = st.r.scan_iter(match="trash:*")
    for key in keys:
        item_id = key.split(':', 1)[-1]
        meta_json = st.r.get(key)
        if not meta_json:
            st.r.delete(key)
            continue
        try:
            meta = json.loads(meta_json)
        except (TypeError, ValueError):
            st.r.delete(key)
            continue
        if not is_admin_view and meta.get('owner') != session.get('user_id'):
            continue
        trash_path = os.path.join(st.TRASH_DIR, item_id)
        if os.path.exists(trash_path):
            if os.path.isdir(trash_path):
                shutil.rmtree(trash_path)
            else:
                os.remove(trash_path)
        st.r.delete(key)
    return jsonify({'success': True})


# ==================== 路由注册 ====================

def register_routes(app, csrf):
    app.add_url_rule('/api/gdl', 'get_download_list', get_download_list, methods=['GET'])
    app.add_url_rule('/api/dl', 'get_task_list_all', get_task_list_all, methods=['GET'])
    app.add_url_rule('/file/hash', 'call_hash', call_hash, methods=['POST'])
    app.add_url_rule('/api/task/<task_id>', 'get_task_status', get_task_status, methods=['GET'])
    app.add_url_rule('/api/task/<task_id>/cancel', 'cancel_task', cancel_task, methods=['POST'])
    app.add_url_rule('/api/task/<task_id>/delete', 'webdelete_task', webdelete_task, methods=['POST'])
    app.add_url_rule('/file/move', 'call_move', call_move, methods=['POST'])
    app.add_url_rule('/file/copy', 'call_copy', call_copy, methods=['POST'])
    app.add_url_rule('/file/zipex', 'call_ze', call_ze, methods=['POST'])
    app.add_url_rule('/api/disk_usage', 'get_du', get_du, methods=['GET'])
    app.add_url_rule('/api/toolcall', 'call_tool', call_tool, methods=['POST'])
    app.add_url_rule('/file/upload', 'upload_file', upload_file, methods=['POST'])
    app.add_url_rule('/api/tus', 'tus_create', tus_create, methods=['POST'])
    app.add_url_rule('/api/tus/<upload_id>', 'tus_upload', tus_upload, methods=['PATCH'])
    app.add_url_rule('/api/tus/<upload_id>', 'tus_head', tus_head, methods=['HEAD'])
    app.add_url_rule('/api/tus/<upload_id>', 'tus_terminate', tus_terminate, methods=['DELETE'])
    app.add_url_rule('/api/files', 'list_files', list_files, methods=['GET'])
    app.add_url_rule('/api/folders', 'create_folder', create_folder, methods=['POST'])
    app.add_url_rule('/api/delete/<path:item_path>', 'delete_item', delete_item, methods=['DELETE'])
    app.add_url_rule('/share/share_put', 'share_put', share_put, methods=['POST'])
    app.add_url_rule('/share/share_get/<path:uuid>', 'down', down)
    app.add_url_rule('/api/clear-all', 'clear_all', clear_all, methods=['DELETE'])
    app.add_url_rule('/download/<path:file_path>', 'web_download_file', web_download_file)
    app.add_url_rule('/api/trash/list', 'trash_list', trash_list, methods=['GET'])
    app.add_url_rule('/api/trash/restore/<item_id>', 'trash_restore', trash_restore, methods=['POST'])
    app.add_url_rule('/api/trash/delete/<item_id>', 'trash_delete', trash_delete, methods=['DELETE'])
    app.add_url_rule('/api/trash/clear', 'trash_clear', trash_clear, methods=['DELETE'])

    # tus 客户端不会携带 CSRF token;端点已有登录+归属校验,且 SameSite=Lax 挡跨站携带 cookie,故豁免
    for _tus_view in (tus_create, tus_upload, tus_head, tus_terminate):
        csrf.exempt(_tus_view)

    # 后台清理线程
    tus_autoclear()   # 启动时清理一次残留
    Thread(target=while_tus_autodelete, daemon=True).start()
    Thread(target=while_trash_autodelete, daemon=True).start()


# ==================== 由 register_routes 注册的路由函数(装饰器在模块级声明) ====================

@login_required
@is_allowed
def get_du():
    # 按当前盘(共享盘/个人盘)口径统计,个人盘不再显示共享盘容量
    a, b, c = shutil.disk_usage(_current_root())
    return jsonify({'total': a, "used": b, "free": c})


@login_required
@is_allowed
def call_move():
    limit_resp = st._check_pending_limit()
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
    tool_id = st.TOOL_MOVE

    st.save_task(task_id, {
        'status': 'pending',
        'error': '',
        'tool_id': tool_id,
        'progress': {'total': 0, 'current': 0},

        'file_info': {'src': source, 'dst': resolve_target_path(safe_path(source, root=_current_root()), target)},
        'owner': session.get('user_id', ''),
        'root': _current_root(),
        'path': os.path.dirname(os.path.abspath(source))
    })
    arg_list = (source, target)
    st.task_queue.put((task_id, func, arg_list, tool_id))
    return jsonify({'success': True, 'task_id': task_id})


@login_required
@is_allowed
def call_copy():
    limit_resp = st._check_pending_limit()
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
    tool_id = st.TOOL_COPY

    st.save_task(task_id, {
        'status': 'pending',
        'error': '',
        'tool_id': tool_id,
        'progress': {'total': 0, 'current': 0},

        'file_info': {'src': source, 'dst': target},
        'owner': session.get('user_id', ''),
        'root': _current_root(),
        'path': os.path.dirname(os.path.abspath(source))
    })
    arg_list = (source, target)
    st.task_queue.put((task_id, func, arg_list, tool_id))
    return jsonify({'success': True, 'task_id': task_id})


@login_required
@is_allowed
def call_ze():
    limit_resp = st._check_pending_limit()
    if limit_resp:
        return limit_resp
    try:
        a = request.get_json(silent=True) or {}
        f = a['path']
        user_dir = a.get('outpath', '')
        if user_dir == "":
            user_dir = os.path.dirname(safe_path(f, root=_current_root()))
        password = a.get('password', '')

        sp = resolve_target_path(safe_path(f, root=_current_root()), user_dir)
    except (KeyError, TypeError, ValueError) as e:
        logging.error(str(e))
        abort(400)
    func = zip_ex

    task_id = str(uuid.uuid4())
    tool_id = st.TOOL_UNZIP
    st.save_task(task_id, {
        'status': 'pending',
        'error': '',
        'tool_id': tool_id,
        'progress': {'total': 0, 'current': 0},
        'file_info': {'src': f, 'dst': sp},
        'owner': session.get('user_id', ''),
        'root': _current_root(),
        'path': os.path.dirname(os.path.abspath(f))
    })
    arg_list = (f, sp, password)
    st.task_queue.put((task_id, func, arg_list, tool_id))
    return jsonify({'success': True, 'task_id': task_id})
