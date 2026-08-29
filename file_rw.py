import os
import shutil
import struct
import json
import hashlib
import socket
from typing import Optional, Dict, Any


def recv_msg(sock: socket.socket) -> Optional[bytes]:
    """接收一条完整消息：先读4字节长度，再读消息体"""
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    msg_len = struct.unpack('!I', raw_len)[0]
    data = b''
    while len(data) < msg_len:
        chunk = sock.recv(msg_len - len(data))
        if not chunk:
            raise ConnectionError("连接中断")
        data += chunk
    return data


def send_msg(sock: socket.socket, data: bytes) -> None:
    """发送一条消息：先发4字节长度，再发消息体"""
    sock.sendall(struct.pack('!I', len(data)))
    sock.sendall(data)


def recv_json(sock: socket.socket) -> Optional[Dict[str, Any]]:
    data = recv_msg(sock)
    if data is None:
        return None
    return json.loads(data.decode('utf-8'))


def send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    send_msg(sock, json.dumps(obj).encode('utf-8'))


def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(filepath: str, block_size: int = 1024 * 1024) -> str:
    """分块计算文件哈希:避免大文件一次性读入内存(OOM)。"""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def send_file(sock: socket.socket, filepath: str, block_size: int = 1024 * 1024) -> bool:
    """
    发送端：将文件分块发送至对端。
    协议：
      1. 发送元信息 (JSON)
      2. 接收 missing_blocks 列表
      3. 依次发送缺失的数据块（块ID + 数据）
      4. 发送 complete
      5. 等待最终结果
    """
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)
    file_hash = _sha256_file(filepath)
    total_blocks = (file_size + block_size - 1) // block_size + 1

    try:
        meta = {
            "type": "meta",
            "filename": filename,
            "file_size": file_size,
            "block_size": block_size,
            "total_blocks": total_blocks,
            "file_hash": file_hash
        }
        send_json(sock, meta)

        resp = recv_json(sock)
        if resp is None:
            print("未收到 missing_blocks 响应")
            return False
        missing_blocks = resp.get('blocks', [])
        print(f"需要发送 {len(missing_blocks)} 个块")

        with open(filepath, 'rb') as f:
            for block_id in missing_blocks:
                offset = block_id * block_size
                f.seek(offset)
                data = f.read(block_size)
                header = struct.pack('!II', block_id, len(data))

                # 带重试的发送
                for attempt in range(1, 10):
                    try:
                        send_msg(sock, header + data)
                    except Exception:
                        print(f"块 {block_id} 发送失败 (尝试 {attempt})")
                        import time
                        time.sleep(attempt * 2)
                        continue

                    ack = recv_json(sock)
                    if ack is None:
                        continue
                    if ack.get('type') == 'ack':
                        print(f"块 {block_id} 发送成功")
                        break
                    else:
                        print(f"块 {block_id} 被拒绝，重试")
                        import time
                        time.sleep(attempt * 2)
                else:
                    print(f"块 {block_id} 最终失败")
                    return False

        send_json(sock, {"type": "complete"})
        result = recv_json(sock)
        if result is None:
            return False
        if result.get('type') == 'success':
            print("上传成功且校验通过")
            return True
        else:
            print(f"上传失败: {result.get('reason')}")
            return False
    finally:
        sock.close()


def recv_file(sock: socket.socket, save_dir: str = '.', display = False, block_size: int = 1024 * 1024, max_size: int = None) -> bool:
    """
    接收端：从 socket 接收文件，支持断点续传和整体哈希校验。
    注意：block_size 参数仅用于与发送端保持一致，实际接收时使用发送端提供的 block_size。
    """
    try:
        # 1. 接收元信息
        meta = recv_json(sock)
        if meta is None or meta.get('type') != 'meta':
            raise ValueError("期望接收元信息消息")
        filename = os.path.basename(meta['filename'])  # 防路径穿越
        file_size = meta['file_size']
        block_size = meta['block_size']          # 使用发送端指定的块大小
        total_blocks = meta['total_blocks']
        file_hash = meta['file_hash']

        if max_size is not None and file_size > max_size:
            send_json(sock, {"type": "failed", "reason": "file too large"})
            return False
        # 对端参数校验:块大小限幅、块数必须与文件大小自洽,防止恶意申报海量块
        if not (1024 <= block_size <= 64 * 1024 * 1024):
            send_json(sock, {"type": "failed", "reason": "block size invalid"})
            return False
        expected_blocks = (file_size + block_size - 1) // block_size + 1
        if total_blocks != expected_blocks:
            send_json(sock, {"type": "failed", "reason": "invalid block count"})
            return False

        os.makedirs(save_dir, exist_ok=True)
        temp_dir = os.path.join(save_dir, f"{filename}.parts")
        os.makedirs(temp_dir, exist_ok=True)

        # 扫描已接收块
        received_blocks = set()
        for fname in os.listdir(temp_dir):
            if fname.endswith('.block'):
                try:
                    block_id = int(fname.split('.')[0])
                    received_blocks.add(block_id)
                except ValueError:
                    continue

        missing_blocks = [i for i in range(total_blocks) if i not in received_blocks]
        print(f"缺失块: {missing_blocks}")
        send_json(sock, {"type": "missing_blocks", "blocks": missing_blocks})

        # 接收缺失块
        for expected_block_id in missing_blocks:
            msg = recv_msg(sock)
            if msg is None:
                send_json(sock, {"type": "failed", "reason": "connection lost"})
                return False

            if len(msg) < 8:
                send_json(sock, {"type": "nack", "block_id": -1})
                continue

            block_id, data_len = struct.unpack('!II', msg[:8])
            data = msg[8:]
            if len(data) != data_len or block_id != expected_block_id:
                send_json(sock, {"type": "nack", "block_id": block_id})
                continue

            block_path = os.path.join(temp_dir, f"{block_id}.block")
            with open(block_path, 'wb') as f:
                f.write(data)
            send_json(sock, {"type": "ack", "block_id": block_id})
            if display:
                print(f'已接收{block_id},还有{len(missing_blocks)-block_id}')

        # 等待发送端完成通知
        complete_msg = recv_json(sock)
        if complete_msg is None or complete_msg.get('type') != 'complete':
            send_json(sock, {"type": "failed", "reason": "protocol error"})
            return False

        # 合并所有块
        final_path = os.path.join(save_dir, filename)
        with open(final_path, 'wb') as out_f:
            for i in range(total_blocks):
                block_path = os.path.join(temp_dir, f"{i}.block")
                if not os.path.exists(block_path):
                    send_json(sock, {"type": "failed", "reason": "missing blocks"})
                    shutil.rmtree(temp_dir, ignore_errors=True)   # 终局失败,清理残留
                    return False
                with open(block_path, 'rb') as bf:
                    shutil.copyfileobj(bf, out_f)

        # 校验哈希
        hasher = hashlib.sha256()
        with open(final_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        actual_hash = hasher.hexdigest()

        if actual_hash == file_hash:
            # 清理临时目录
            for fname in os.listdir(temp_dir):
                os.remove(os.path.join(temp_dir, fname))
            os.rmdir(temp_dir)
            send_json(sock, {"type": "success"})
            return True
        else:
            # 终局失败:数据已坏,保留 .parts 无意义,清理避免磁盘残留
            shutil.rmtree(temp_dir, ignore_errors=True)
            send_json(sock, {"type": "failed", "reason": "hash mismatch"})
            return False

    except Exception as e:
        print(f"接收文件时发生异常: {e}")
        try:
            send_json(sock, {"type": "failed", "reason": str(e)})
        except:
            pass
        return False