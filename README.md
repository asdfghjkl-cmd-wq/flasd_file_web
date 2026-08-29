# 文件上传服务(共享盘 / 个人盘)

基于 Flask 的文件上传与管理系统,提供「共享盘」与「个人盘」双空间文件管理、异步任务(分割/合成/解压/URL 下载/哈希)、分享链接、回收站与加密管理控制台。

## 功能特性

- **双空间模型**
  - 共享盘(默认):`uploads/`,所有登录用户共享;
  - 个人盘:`private/<用户名>/`,仅本人与管理员可访问,URL 以 `/p` 前缀区分(如 `/p/api/files`),页面提供空间切换入口。
- **文件管理**:tus 分片上传(支持大文件断点续传)、普通上传、文件列表、创建文件夹、删除、复制、移动、下载、磁盘占用查询。
- **文件工具**(异步任务队列,带进度与取消):
  - 文件分割 / 合成(如 `1000.data` 分片);
  - 解压 zip / 加密 zip / 7z(防 Zip Slip 路径穿越);
  - URL 下载(防 SSRF:固定 IP 直连 + 每跳重定向重新校验);
  - 计算哈希。
- **分享链接**:`/share/share_put` 生成,默认 1 天有效,按 IP 限流。
- **回收站**:删除先入回收站(默认保留 10 天),支持恢复 / 彻底删除 / 清空。
- **用户体系**:登录 / 登出 / 找回密码 / 重置密码;登录失败按 IP 与账号双重限流;改密或重置后旧会话立即失效(会话版本号);被封禁用户禁止登录。
- **管理控制台**:自定义加密 socket 协议(握手 → 认证 → 命令循环),管理员远程管理用户、文件、模板与调试开关(见下文)。
- **安全加固**:路径越权防护、CSP(nonce + `script-src 'self'`)、可信代理剥头(防伪造 `X-Forwarded-*` 绕过限流)、debug 源码护栏(非本机客户端不暴露 traceback)、会话密钥文件原子创建、探针语义分离(`/healthz` liveness / `/readyz` readiness)。
- **模板热重载**:`a.html` 变更自动生效(默认 1 秒节流),生产可关闭。

## 环境要求

- Python **>= 3.10**(代码使用 `dict | None`、`list[str]` 等新语法)
- **Redis**(必需):存储用户/密码哈希、任务、限流计数、分享链接、回收站、管理端口发现
- 平台:Windows / Linux 均可;生产推荐 Linux + gunicorn

## 快速开始

```bash
# 1. 安装依赖(推荐用锁定版本保证可复现)
pip install -r requirements.lock
#    或仅安装顶层依赖:pip install -r requirements.txt

# 2. 启动 Redis(默认 localhost:6379,无密码)

# 3. 设置管理员初始账号(首次启动写入 Redis)
#    Windows PowerShell:
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "一个足够强的密码"
#    Linux/macOS:
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='一个足够强的密码'

# 4. 启动(开发模式)
python app.py
# 访问 http://127.0.0.1:5000
```

- 会话密钥自动生成并保存到 `s.key`(少于 32 字符的密钥会被拒绝);也可用 `SECRET_KEY` 环境变量显式指定。
- 首次启动时会连接 Redis 做启动检查,失败则拒绝启动(测试/无 Redis 环境可设 `REDIS_SKIP_CHECK=1` 跳过,但功能仍依赖 Redis)。

### 生产部署(gunicorn)

```bash
# 注意:本应用含模块级 Redis 连接与后台线程,请勿使用 gunicorn --preload
gunicorn -w 4 -b 0.0.0.0:8000 --worker-class gthread --threads 8 app:app
```

管理控制台默认不随 import 自动启动(`START_ADMIN_CONSOLE=0`),推荐在 gunicorn `post_fork` hook 中显式启动:

```python
# gunicorn.conf.py
def post_fork(server, worker):
    import app
    app.maybe_start_admin_console()
```

## 配置(环境变量)

### 基础

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `5000` | 服务端口(dev 直跑与 gunicorn 监听均读此值) |
| `HOST` | `127.0.0.1` | 监听地址(仅 dev 直跑) |
| `SITE_URL` | 空 | 站点对外地址,如 `https://example.com`(不含路径);决定 CORS 默认来源与 HSTS / Secure cookie 自动推断 |
| `ADVERTISE_IP` | 自动探测 | 启动横幅对外展示的 IP(容器/NAT/多网卡场景建议显式设置) |
| `DISABLE_AUTO_APP` | `0` | 设为 `1` 时 import 不自动组装应用(工具/测试进程用) |

### Redis

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `REDIS_HOST` | `localhost` | Redis 地址 |
| `REDIS_PORT` | `6379` | Redis 端口 |
| `REDIS_DB` | `0` | Redis 库号 |
| `REDIS_PASSWORD` | 空 | 密码;公网地址且无密码默认拒绝启动,需显式 `ALLOW_INSECURE_REDIS=1` |
| `REDIS_SKIP_CHECK` | `0` | 跳过启动期 Redis 连通性检查 |
| `ALLOW_INSECURE_REDIS` | `0` | 放行"无密码 + 非本地地址"的 Redis |

### 账号与会话

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_USERNAME`(别名 `a`) | 空 | 初始管理员用户名 |
| `ADMIN_PASSWORD`(别名 `p`) | 空 | 初始管理员密码 |
| `SESSION_DAYS` | `7` | 登录会话有效期(天),滑动续期 |
| `SECRET_KEY` | 自动生成 | 会话签名密钥(至少 32 字符),设置后忽略 `s.key` 文件 |
| `SESSION_COOKIE_SECURE` | 自动推断 | 显式设置 `1` 开启 Secure cookie(HTTPS 部署建议显式设置) |
| `SESSION_COOKIE_SAMESITE` | `Lax` | 跨站前端需要 `None` + Secure |

### 安全 / 反代

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ALLOWED_ORIGINS` | 空 | CORS 额外放行的来源,逗号分隔;不支持 `*` |
| `PROXY_COUNT` | `0` | 可信反代层数;大于 0 时启用 ProxyFix |
| `TRUSTED_PROXIES` | 空 | 可信直连方 IP 白名单,逗号分隔;仅名单内的直连方提交的 `X-Forwarded-*` 头才被采纳 |
| `ALLOW_DE_LOCK` | `0` | 配合 `BASE_DIR/de.lock` 文件开启 debug 模式(仅调试期使用,生产勿留) |
| `DOWNLOAD_VERIFY_TLS` | `0` | URL 下载是否校验 TLS 证书;**默认关闭,生产建议设为 `1`** |

### 上传 / 下载 / 任务

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `MAX_CONTENT_LENGTH_MB` | `256` | 非分片请求体上限(MB);大文件请走 tus |
| `TUS_MAX_UPLOAD_SIZE` | `10GB` | tus 单文件大小上限(字节) |
| `TUS_UPLOAD_TTL` | `24h` | tus 上传会话有效期(秒) |
| `TUS_MAX_PATCH_SIZE` | `1GB` | tus 单次 PATCH 分片上限(字节) |
| `DOWNLOAD_MAX_SIZE` | `10GB` | URL 下载大小上限(字节,0 表示不限制) |
| `MAX_PENDING_PER_USER` | `10` | 每用户排队任务数上限(超限返回 429) |

### 邮件(密码找回 / debug 验证码)

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `MAIL_FROM` | `no-reply@www.relink.website` | 发件地址 |
| `RESEND_API_KEY` | 空 | Resend 邮件服务 API Key;为空时找回密码功能不可用 |

### 模板 / 日志 / 探针

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `TEMPLATE_AUTO_RELOAD` | `1` | 请求期按 mtime 热重载 `a.html`;生产可设 `0` 关闭 |
| `TEMPLATE_RELOAD_INTERVAL` | `1` | 热重载检查节流(秒) |
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `LOG_SET_ROOT_LEVEL` | `1` | 设为 `0` 时不修改宿主进程 root logger 级别 |
| `REQUEST_LOG` | `1` | 设为 `0` 关闭每请求访问日志(压测/高吞吐) |
| `PROBE_CACHE_SECONDS` | `5` | `/readyz` 成功结果缓存(秒) |
| `PROBE_FAIL_CACHE_SECONDS` | `1` | `/readyz` 失败结果缓存(秒) |

### 管理控制台

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `START_ADMIN_CONSOLE` | `0` | 设为 `1` 自动启动管理端口(推荐 gunicorn post_fork 显式调用) |
| `ADMIN_PORT_MIN` / `ADMIN_PORT_MAX` | `6000` / `6050` | 管理端口随机范围 |
| `ADMIN_BIND` | `127.0.0.1` | 管理端口监听地址(非回环时告警,请配合防火墙) |
| `ADMIN_CONN_LIMIT` | `5` | 同一 IP 每 10 秒窗口握手连接上限 |
| `ADMIN_MAX_CONNS` | `8` | 最大并发管理连接 |
| `TRANSFER_IDLE_TIMEOUT` | `600` | update/download 传输连接认证后空闲超时(秒) |
| `MAN_PORT_KEY` | `man_port` | Redis 中管理端口发现键;多机共享 Redis 时用 `man_port:<实例标识>` 隔离 |

## API 概览

所有业务路由同时服务共享盘(无前缀)与个人盘(`/p` 前缀,如 `/p/api/files`);除标注外均需登录。

### 认证 / 页面

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/login` | 登录(表单) |
| GET | `/logout` | 登出 |
| GET/POST | `/forgot` | 忘记密码(发送重置邮件) |
| GET/POST | `/reset` | 重置密码 |
| GET | `/` | 主页面(共享盘/个人盘) |
| POST | `/api/reload-template` | 模板热重载(仅 debug 模式) |
| GET | `/healthz` | 存活探针(liveness,恒 200,免认证) |
| GET | `/readyz` | 就绪探针(readiness:Redis + 上传目录可写,免认证) |

### 文件

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/files` | 文件列表 |
| POST | `/file/upload` | 普通上传 |
| POST | `/api/tus` | tus 创建上传会话 |
| PATCH | `/api/tus/<upload_id>` | tus 上传分片 |
| HEAD | `/api/tus/<upload_id>` | tus 查询进度 |
| DELETE | `/api/tus/<upload_id>` | tus 终止上传 |
| POST | `/api/folders` | 创建文件夹 |
| POST | `/file/move` | 移动 |
| POST | `/file/copy` | 复制 |
| DELETE | `/api/delete/<path:item_path>` | 删除(进回收站) |
| GET | `/download/<path:file_path>` | 下载文件 |
| GET | `/api/disk_usage` | 磁盘占用 |

### 任务 / 工具

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/toolcall` | 工具调用(分割/合成/URL 下载等,参数含 tool id) |
| GET | `/api/gdl` | 运行中的下载任务 id 列表 |
| GET | `/api/dl` | 任务列表 |
| GET | `/api/task/<task_id>` | 任务状态与进度 |
| POST | `/api/task/<task_id>/cancel` | 取消任务 |
| POST | `/api/task/<task_id>/delete` | 删除任务记录 |
| POST | `/file/hash` | 计算文件哈希 |
| POST | `/file/zipex` | 解压(zip/7z) |

### 分享 / 回收站

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/share/share_put` | 生成分享链接 |
| GET | `/share/share_get/<uuid>` | 通过分享链接下载 |
| GET | `/api/trash/list` | 回收站列表 |
| POST | `/api/trash/restore/<item_id>` | 恢复 |
| DELETE | `/api/trash/delete/<item_id>` | 彻底删除 |
| DELETE | `/api/trash/clear` | 清空回收站 |
| DELETE | `/api/clear-all` | 清空共享盘全部文件 |

> 工具 ID:`1` 分割、`2` 合成、`4` 解压、`6` URL 下载、`50` 复制、`51` 移动、`64` 哈希(常量见 `app_state.py`)。

## 管理控制台

加密 socket 管理端,只监听 `ADMIN_BIND`(默认 `127.0.0.1`),支持:

- 用户管理:`adduser <user> <password> <mail>`、`setmail <user> <mail>`、`passwd <user> <newpass>`、`deluser <user>`(删除用户同时清理个人盘数据并使会话失效)
- 文件管理:`ls [路径]`、`cat <文件>`、`del <路径>`(移入回收站)、目录树浏览
- 模板:load(热重载 `a.html`)
- 调试:`debug open`(邮件验证码验证后开启 debug 模式)、`debug close`
- 文件传输:update(上传文件到服务器)、download(拉取服务器文件),传输端口带一次性 token 认证

启用方式:

```bash
export START_ADMIN_CONSOLE=1
python app.py        # 管理端口从 6000-6050 中挑选,日志会打印地址
```

或生产环境在 gunicorn `post_fork` 中调用 `app.maybe_start_admin_console()`(见上文)。客户端为 `console.py`(管理端脚本,需与服务端协议匹配的加密握手,依赖见其头部)。

## 架构与模块

| 文件 | 职责 |
| --- | --- |
| `app.py` | 应用工厂 `create_app()`:配置 / CORS / CSRF / 中间件 / 错误处理 / 安全头 / 路由注册;启动逻辑与管理端口守护 |
| `app_state.py` | 全局唯一状态持有者:配置常量、Redis 连接、用户数据层、任务队列与 worker 线程、应用引用注册表 |
| `app_paths.py` | 路径安全:盘根解析、越权防护、文件名清洗、元数据、个人盘目录、用户清理 |
| `app_tools.py` | 文件工具:分割/合成、哈希、解压(防 Zip Slip)、URL 下载(防 SSRF) |
| `app_auth.py` | 认证:登录/登出/找回/重置、`login_required` 等装饰器、邮件发送、IP 限流 |
| `app_routes.py` | 业务路由:文件/任务/tus/分享/回收站/下载(`register_routes`) |
| `app_admin.py` | 管理控制台:加密 socket 协议、认证、命令循环、文件传输 |
| `app_middleware.py` | WSGI 中间件:`ScopePrefixMiddleware`(/p 前缀)、`TrustedProxyScrubMiddleware`(剥伪造头)、`DebugTracebackGuard`(debug 源码护栏) |
| `app_template.py` | 全局 HTML 模板加载与请求期热重载 |
| `file_rw.py` | socket 消息/文件传输帧协议(管理控制台与客户端共用) |
| `console.py` | 管理控制台客户端脚本 |
| `a.html` | 主页面单文件模板(登录后界面) |
| `templates/` | 登录/找回/重置页面 |
| `tests/` | pytest 测试(`conftest.py` 已关闭模块级副作用) |

数据目录:

- `uploads/` — 共享盘根;`uploads/metadata/` 文件元数据
- `private/<用户名>/` — 个人盘
- `trash/` — 回收站暂存
- `app.log` — 轮转日志(10MB × 5);`s.key` — 会话密钥

## 健康探针

- `/healthz`:liveness,进程能响应即 200,不依赖 Redis/磁盘(避免依赖抖动引发滚动重启);
- `/readyz`:readiness,Redis 可 ping 且上传目录可写才 200,否则 503。注意结果缓存(成功 5s / 失败 1s),监控需容忍该最坏检测延迟。

## 测试

```bash
pip install pytest
python -m pytest tests/ -v
```

`tests/conftest.py` 自动设置 `REDIS_SKIP_CHECK=1` / `DISABLE_AUTO_APP=1` / `START_ADMIN_CONSOLE=0`,import 阶段无副作用;各用例按需手动 `create_app(config=...)` 构建隔离实例。

## 变更历史

见 [CHANGELOG.md](CHANGELOG.md)。
