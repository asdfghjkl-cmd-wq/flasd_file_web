# Changelog

本文件承接原 app.py 模块 docstring 中的「最近变更」历史(变更历史自模块注释
迁移至此,避免模块注释随迭代腐化;当前架构说明见 app.py 模块 docstring)。

## 第十轮(本次,代码审查意见落地)

- 413 错误处理器与其余错误处理器(400/415/429/CSRF)统一形态:页面请求返回
  文本,仅 API/XHR 请求返回 JSON。原实现无条件返回 JSON,页面表单(如大文件
  未走 tus 时)触发 413 会看到一串原始 JSON;同步更新 test_413_too_large
  覆盖两种形态。
- 修复密钥文件解码异常绕过错误处理:`_load_or_create_secret_key` 读取 s.key
  时,非法 UTF-8(误写/二进制损坏)会抛 UnicodeDecodeError(ValueError 子类,
  非 OSError),原实现所有 OSError 分支都捕获不到,以晦涩解码 traceback 直接
  冒泡到启动栈;现转为 OSError 并入既有「重读重试→fail-fast」路径,报错信息
  明确(「密钥文件不是合法 UTF-8 文本」),提示删除后重启重建。
- 首页模板 `csp_nonce` 变量加 `or ''` 兜底:避免路由变化导致 g.csp_nonce 为
  None 时模板渲染字面 "None",与 `_security_headers` 无 nonce 时
  `script-src 'self'` 的严格策略隐性降级不一致。
- `_PROBE_CACHE_SECONDS` 下限由 `max(1.0, ...)` 改为 `max(1, ...)`,保持 int
  类型(该变量是秒级整数下限,与失败缓存的 0.2~2.0 float clamp 语义不同)。
- 删除死代码 `_LOG_HANDLER_KIND`(仅赋值、全项目从不读取)。

## 第九轮(本次,代码审查意见落地)

- 修复模板热重载的静默停摆缺陷:`_get_html_template` 锁内在读文件之前就推进了
  `_tpl_mtime`,若重读失败(文件占用/瞬时 IO 错误),后续请求 stat 命中同一 mtime
  后不再重读,模板会永久停留在旧版直到文件再次修改;改为「先成功读入、再推进
  mtime」,失败时保留旧 mtime 与节流时间,窗口过后自动重试。
- 探针语义拆分:`/healthz` 改为纯 liveness(进程存活恒 200,不再依赖 Redis);
  Redis/磁盘可写检查全部收敛到 `/readyz`(readiness)。原实现 liveness 在 Redis
  故障时返回 503,K8s/LB 会在依赖抖动时反复重启容器,把瞬时故障放大成滚动重启。
  探针失败日志由 ERROR 降为 WARNING(探针 1~3s 高频打点,ERROR 会淹没真实故障)。
- `setup_logging()` 延迟到 `create_app` 内调用:消除 import 期副作用,
  `DISABLE_AUTO_APP=1` 的工具/测试进程导入 app.py 时不再创建 handler、不再写
  app.log。
- 日志轮转并发安全化:`concurrent-log-handler` 条件导入(装了自动用
  ConcurrentRotatingFileHandler 处理多 worker 共写同一日志文件的轮转竞态),
  未安装时回退标准 RotatingFileHandler,不强制新依赖。
- `START_ADMIN_CONSOLE` 默认值改为 `0`:gunicorn/uwsgi 等生产导入路径默认不再
  自动启动管理端口(消除 import 副作用);需要时显式 `START_ADMIN_CONSOLE=1`
  (兼容旧版自动启动)或走推荐的 gunicorn post_fork hook。
- 管理端口相关线程显式命名(`admin-console-listen` / `man-port-renew`),
  `_renew_man_port_loop` 支持 stop_event 显式停止(测试/优雅退出场景)。
- `app_admin.w` 改名 `serve_admin_console`(消除晦涩的单字母导出名)。
- 模块拆分:`app_middleware.py`(ScopePrefix / TrustedProxyScrub /
  DebugTracebackGuard 三个 WSGI 中间件)、`app_template.py`(全局 HTML 模板加载
  与请求期热重载)从 app.py 拆出;app.py 仅保留工厂 + 启动编排,模块级名字
  re-export 保持既有引用方式不变。
- 请求日志级别判断改用模块级缓存的 root logger(省热路径每次 getLogger());
  实际打日志仍走 logging 模块级函数,不改变调用方/测试的 monkeypatch 语义。
- 修复 import 期日志重复输出:`app_tools` 的 DOWNLOAD_VERIFY_TLS 告警改用模块级
  logger(原 `logging.warning` 模块级函数在 root 无 handler 时会自动 basicConfig()
  添加默认 StreamHandler,与 setup_logging 配置的 handler 重复输出)。
- CSP 收紧(script-src 去掉 'unsafe-inline'):
  - 首页 `/`(共享盘/个人盘)响应按请求生成随机 nonce(`g.csp_nonce`,存入
    `_before_request`),`script-src 'self' 'nonce-…'`,a.html 的 `<script>` 标签
    注入同名 nonce;API/下载/分享等无内联脚本的响应落到更严格的 `script-src 'self'`
    (分享的 HTML 被直接浏览时内联脚本同样被阻止,防恶意分享内容)。
  - a.html 全部 32 处内联事件处理器迁移:静态 HTML(14 处 onclick + 1 处
    `javascript:` 链接)与 JS 模板字符串生成的 17 处 onclick 统一改为
    `data-csp-action` + 全局 click 事件委托(参数经 encodeURIComponent 传
    data-csp-p1/p2,委托侧 decodeURIComponent 还原,不再有字符串拼接转义问题)。
  - `style-src` 保留 'unsafe-inline':CSS 无脚本执行能力,且登录模板/内联 style
    属性/JS 生成的进度条等依赖内联样式,收紧收益低(XSS 主防线在 script-src)。

## 第八轮(本次,代码审查意见落地)

- 修复 SESSION_COOKIE_SECURE 自动推断误判:原来 `PROXY_COUNT>0` 即自动开启
  Secure,http 反代部署下浏览器不发送 Secure cookie,表现为"登录成功立刻被登出"
  且极难排查;改为仅 `SITE_URL=https://` 时自动开启,代理+非 https 形态降级为
  显式告警并保持关闭(显式 `SESSION_COOKIE_SECURE=1` 永远可覆盖)。
- 新增 debug 源码护栏 `DebugTracebackGuard`(WSGI 最外层中间件):Flask 在 debug
  下将未处理异常 propagate 到服务器,werkzeug dev server 会向请求方渲染带源码的
  traceback 页面;现在仅本机回环地址(127.0.0.1/::1)可见 traceback,非本机客户端
  一律返回脱敏 500(完整堆栈经 logging.exception 只进服务端日志)。
- 消除残余 import 副作用:`load_html()`(读 a.html)从模块级移入 `_bootstrap_app()`,
  `DISABLE_AUTO_APP=1` 的工具/测试进程不再触碰模板文件。
- 模板热重载改用纳秒级 mtime(`os.stat().st_mtime_ns`):秒级粒度下同一秒内两次
  保存(内容不同)会漏检。
- 探针缓存状态从模块级全局改挂 `current_app.extensions`(按实例隔离,与模板编译
  缓存同策略),多 Flask 实例(测试隔离实例)不再串扰探针结果。
- 请求日志路径归一化(`rstrip('/')`):`/healthz/` 等尾斜杠变体不再刷日志。
- 错误响应(4xx/5xx)统一追加 `Cache-Control: no-store`(避免带 request_id 的错误
  页被浏览器/中间缓存,报障时对不上日志)。
- `maybe_start_admin_console` 幂等化:`admin_lock.is_locked` 时直接返回 True,
  避免重复调用走锁超时路径打出误导日志("已被其它进程占用"——其实是自己)。
- CSRF 校验失败按请求形态区分响应:页面请求返回文本"CSRF验证失败"(不再抛裸
  JSON),API 请求仍返回 JSON。
- HSTS 应用层兜底:`SITE_URL=https://` 时自动下发
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`,不依赖反代配置。
- `env_int` 公开:`app_state._env_int` 改名 `env_int` 并保留 `_env_int = env_int`
  兼容别名(历史模块引用不受影响);`app.py` 内全部改用公开名。
- 杂项:`icacls` 调用去掉无占位 f-string;请求日志格式化统一为 f-string。

## 第七轮(本次,代码审查意见落地)

- 修复 man_port TTL 永不续期:原实现只写入一次 ex=600,服务运行超过 10 分钟后
  Redis 中的管理端口键自然过期,客户端断线重连/新客户端启动将无法发现端口;
  新增后台守护线程 `_renew_man_port_loop` 每 5 分钟续期一次(续期前校验值仍是
  自己写的,多实例共享 Redis 且键名相同时不误续别人的值)。
- 健康探针抗风暴:失败结果不再立即透传,新增失败短缓存(默认 1s,
  `PROBE_FAIL_CACHE_SECONDS` 可调,上限 2s)并加锁合并并发 ping——Redis 故障时
  多探针源(LB/K8s)并发请求不再在已故障的 Redis 上堆积 1s 超时连接;
  同时 ok/at 状态在锁内更新,消除非原子读。
- create_app 拆分:配置解析(`_resolve_secret_key`/`_resolve_allowed_origins`/
  `_apply_secure_cookie_config`)、路由注册(`_register_home_routes`)、错误处理
  (`_register_error_handlers`)、探针(`_register_probes`)、after_request
  (`_request_log`/`_security_headers`)提为模块级函数,工厂只做编排;
  行为与拆分前一致(冒烟测试验证)。
- 密钥加载惰性化:原模块级 `SECRET_KEY = _load_or_create_secret_key()` 移除,
  改在 create_app 内调用——工具/测试进程 import app.py 不再读写 s.key;
  O_EXCL 原子创建与 fail-fast 语义不变。
- Windows 密钥文件权限收紧(仅新创建时):`_harden_key_file_windows()` 用
  icacls 对 s.key 执行 `/inheritance:r /grant:r <user>:(R,W)`,失败仅告警不
  阻断启动;缓解 0o600 在 Windows 上被忽略的问题。
- setup_logging 增加 `LOG_SET_ROOT_LEVEL=0` 开关:默认仍设置 root 级别(兼容
  旧行为),关闭时只设置自家 handler 级别,不再覆盖宿主进程(gunicorn 等)
  的日志级别配置。
- CSRF token 有效期显式化:`WTF_CSRF_TIME_LIMIT=None` 写入基础配置,与 7 天
  滑动会话匹配,防止未来 Flask-WTF 默认值变化导致长会话中表单提交失败。
- `_local_ip()` 支持 `ADVERTISE_IP` 环境变量覆盖(VPN/多网卡环境下探测可能
  选中虚拟网卡,日志展示误导)。

## 第六轮(本次,代码审查意见落地)

- 修复管理端口占用耗尽时的误删:端口全被占用时不再主动删除 Redis `man_port`
  (本进程从未成功写入,删除极可能误伤其它进程刚写入的值),旧值由 TTL(600s)
  自然过期,残留误导窗口很短。
- CSRF 校验失败返回码 400 → 403:token 缺失/无效属于客户端凭证错误
  (区别于 401 未登录、400 请求格式错误),测试断言同步更新。
- 持久会话时长显式化:新增 `PERMANENT_SESSION_LIFETIME`(默认 7 天,
  `SESSION_DAYS` 环境变量可配,替代 Flask 默认 31 天),登录成功处设
  `session.permanent = True` 使其生效(滑动续期);原临时会话无明确服务端过期。
- 请求日志分级:5xx 升为 ERROR(便于告警检索),404 降为 DEBUG(爬虫/扫描器
  噪音不刷 INFO),其余保持 INFO。
- `_local_ip()` 改为遍历网卡取第一个非回环 IPv4,避免多网卡(含 VPN/虚拟机
  网卡)时 gethostbyname 随机返回误导地址;解析失败仍回退回环地址。
- 双空间 scope 引入具名常量 `st.SCOPE_SHARED` / `st.SCOPE_PERSONAL`
  (app.py 全部使用;值不变,兼容 app_routes 字面量比较与持久化 meta)。
- 代码清洁:Flask>=3.0 下 `app.json.ensure_ascii` 去掉旧版兼容分支;
  模块级变量(LOG_FILE/SECRET_KEY_FILE/HTML_FILE/HTML_TEMPLATE/app/admin_lock)
  补类型标注。
- 修复隐藏 NameError:app.py 顶部未 import `url_for`,但 reload_template /
  _legacy_reload_template 视图均使用之——此前被登录保护(401 提前返回)掩盖,
  生产上登录用户访问 /api/new 会 500;补 import 并新增登录态测试覆盖该路径。
- 测试修正:安全头断言 `X-Frame-Options` 由过时的 SAMEORIGIN 改为与实现一致的
  DENY;/api/new 重定向测试补登录态构造(此前未考虑 login_required);
  新增 404 只写 DEBUG 不写 INFO 的分级断言。

## 第五轮(本次,代码审查意见落地)

- CSP 补充 form-action 'self':form-action 不回退到 default-src,不设置时表单
  可被诱导提交到任意源;页面含登录/上传表单,收紧后只能提交到同源。
- 所有响应统一携带 X-Request-Id 响应头(请求 ID 此前只出现在日志与 500 回传),
  用户报障可直接携带,便于与请求日志串联排查。
- 新增 405 错误处理:API 返回 JSON、页面返回文本,并附 Allow 头告知可用方法
  (此前 404/413/CSRF/500 已 JSON 化,405 遗漏)。
- SECRET_KEY 双来源行为文档化并打日志:显式设置 SECRET_KEY 环境变量时优先使用
  并提示忽略 s.key 文件,否则使用密钥文件;提醒部署固定一种来源,切换会导致
  已签发会话全部失效。
- 模板热重载改双检锁:热路径无锁 stat 命中缓存直接返回,仅 mtime 变化时才拿锁
  重读,降低全局锁争用;`_tpl_mtime`/`_started_admin_port` 由 list 容器改为
  global 标量(类型注解更清晰,不再用可变容器装标量)。
- 新增 requirements.lock:锁定顶层依赖与传递闭包版本(当前 venv 解析结果),
  部署可复现;重新生成命令见文件头注释。
- 安全头注释补充 HSTS 反代配置示例与 CSP nonce 迁移 TODO。

## 第四轮(本次,代码审查意见落地)

- 修复管理端口扫描 off-by-one:range(min_p, max_p) 改为 range(min_p, max_p + 1),
  配置的 ADMIN_PORT_MAX 不再被排除在可用范围之外。
- CSP 收紧:connect-src 从 `'self' ws: wss:` 改为 `'self'`(裸 ws:/wss: 会放行任意
  WebSocket 端点,架空 'self' 对数据外带的防护;当前页面无 WS 使用者,管理控制台
  为浏览器外自定义 socket 客户端,不受页面 CSP 约束)。
- CORS 默认 origins 不再硬编码 5000 端口:跟随 PORT 环境变量派生,
  显式设置 SITE_URL 时自动加入其来源,ALLOWED_ORIGINS 继续作为扩展入口。
- 健康检查改用短超时探针连接(st.ping_redis,1s):避免 Redis 故障时模块级连接
  socket_timeout(5s) 拖慢 /healthz /readyz,在 LB/K8s 探针窗口内误判失败。
- 收敛模块 import 副作用:新增 DISABLE_AUTO_APP=1 跳过模块级 create_app/模板加载
  与自动启动管理端口(工具/测试进程按需手动 create_app(config=...));
  app_state 新增 REDIS_SKIP_CHECK=1 跳过 Redis 启动检查(测试/无 Redis 环境)。
- 删除 app.py 中仅靠 import 副作用维持的 noqa 导入(from app_state import
  _user_lock, users, save_user——三个名字在 app.py 均未使用,导入顺序由
  `import app_state as st` 保证)。
- 请求日志新增 REQUEST_LOG=0 开关,可关闭每请求 INFO 打点(压测/高吞吐部署)。
- 类型注解:create_app/_load_or_create_secret_key/ScopePrefixMiddleware 等
  补注解,模块启用 from __future__ import annotations。
- 新增 pytest 测试(tests/):create_app 配置注入、/p 前缀中间件、安全头/CSP、
  探针、密钥原子创建与并发创建、CORS 端口派生、CSRF/413/404/500 错误处理、
  请求日志开关。

## 第三轮代码审查意见落地

- 移除 sys.modules['app'] 别名 hack,改由 app_state 注册表持有 app/load_html 引用
  (python app.py 直跑与 gunicorn 导入两条路径均可用,且不再依赖模块加载顺序)。
- 模板编译缓存挂到 current_app.extensions(按实例隔离,测试隔离实例不再与全局
  实例串扰);_index_template/reload_template 改用 current_app.debug;模板热重载
  的 mtime 检查-更新加锁。
- 请求日志增加 scope 字段(区分共享盘/个人盘);500 非 API 响应携带 request_id。
- CORS 默认仅放行本机地址,生产域名统一走 ALLOWED_ORIGINS 环境变量。
- 日志统一 lazy 格式化;本机 IP 获取失败回退回环地址;
  ADMIN_PORT_MIN/MAX 配置非法时显式拒绝;atexit 释放锁前检查持有状态。

## 第二轮代码审查意见落地

- 日志配置收敛为幂等 setup_logging():只管理自己添加的 handler,不再清空宿主进程
  root logger 的既有 handler,避免 import 副作用破坏测试/工具进程。
- 会话密钥创建失败改为 fail-fast(不再静默降级为临时随机密钥,杜绝多 worker 各自
  不同密钥导致会话随机失效且难排查的问题)。
- create_app 的 config 参数提前到 CORS/CSRF 初始化之前应用:测试可覆盖
  ALLOWED_ORIGINS、WTF_CSRF_ENABLED、SESSION_COOKIE_SECURE 等启动期生效配置。
- MAX_CONTENT_LENGTH 默认 1GB -> 256MB(非分片大请求是磁盘/内存消耗面,大文件应走 tus)。
- 500 日志与 JSON 错误响应携带 request_id,便于与请求日志串联排查。
- /api/ 响应增加 Cache-Control: no-store(文件下载走 /download/、/share/,不受影响)。
- 管理端口信息 man_port TTL 1 天 -> 10 分钟,退出时删除本进程写入的值,端口耗尽时
  清除旧值;管理端口启动收敛为 maybe_start_admin_console() 显式入口,
  支持 START_ADMIN_CONSOLE=0 关闭 import 副作用。
- HOST 默认 127.0.0.1(公网部署需显式设置 HOST=0.0.0.0)。

## 第一轮代码审查意见落地(按代码审查意见重构)

- create_app 工厂化:配置/CORS/CSRF/中间件/错误处理/安全头/路由注册集中一处,
  测试可传 config 获得隔离实例;app_admin 延迟取 app/load_html 引用经
  app_state 注册表(st.get_app()/st.get_load_html()),不再使用 sys.modules 别名 hack。
- SESSION_COOKIE_SECURE 改为显式 env 开关(测试可经 config 覆盖),不再按 __name__ 推断部署方式。
- 密钥文件原子创建(O_EXCL 防多进程并发生成不同 key),并收紧文件权限。
- 管理端口锁锚定 BASE_DIR 并改用 FileLock(进程崩溃后 OS 自动释放,不会残留死锁);
  __main__ 与 gunicorn worker 统一走同一套抢锁流程。
- 新增 /readyz(Redis + 上传目录可写),/healthz 保持原语义兼容现有监控。
- 新增 500 的 JSON 处理与请求日志(request_id + 方法 + 路径 + 状态码 + 耗时)。
- 模板热重载改为请求时惰性 mtime 检测(替代每 worker 一个 5 分钟轮询线程,
  多 worker 下模板更新天然最终一致)。
- 新增 CSP / Permissions-Policy 响应头;MAX_CONTENT_LENGTH 支持 env 调整。
- /api/new 改名 /api/reload-template(旧路径 302 兼容);404 文案修复。
