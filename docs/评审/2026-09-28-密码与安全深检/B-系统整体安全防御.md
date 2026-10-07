# 「飞证」系统整体安全防御 · 独立评审报告（席位 B，2026-09-28）

> 干净上下文只读评审。证据=代码锚（文件:行号）+活服务只读 GET 探针（127.0.0.1:8000/8100，`--noproxy '*'`）+磁盘实况清点。
> 评审语境：竞赛演示档（demo 钥=已声明形态，本报告派生钥一律写公式）+文档化生产演进。
> 净新增承诺：本报告发现均为既往三代理评审（A 席报告+合成摘要）与红队记录之外的新增项，或对"宣称已修"的在位性核验。

---

## ① 总体印象

这套系统的**防御纵深是真实存在且分层清楚的**：认证三域（X-RA-Token / X-Audit-Token / X-Engine-Token）全部恒时比较且域分离；匿名受理面以"RA 签名即准入票据"替代传统登录（`authz/router.py:154-165` 的 ApplyIn 零身份字段+`admission_gate` 门控②验签），是"无口令体系"下正确的准入设计；worker 的并发正确性工程（租约/终态守卫/record_lock 跨进程文件锁/TOCTOU 复查/读后写对拍）经逐行核验**确属已修且在位**；案卷下载端点的输入面防御（hex 正则+artifact 白名单）经实测穿越无效。演示档内自洽度高——demo 钥的随机化批次（FZ_ENGINE_SK/FZ_RA_SK/FZ_RA_OPS_TOKEN/FZ_WRAP_KEY/FZ_AUTHZ_BINDING_KEY）已在 `demo_up.py:172-184` 全部落位，且 `/ra/ops-token-hint` 实测返回 `demo:false` 只指路不回值。

本轮净新增的问题集中在三处：**登记/签发面的认证缺位在 nginx 网络档下是真实的高危面**（P1）；**TRAIL 失败路径的轨迹明文残留与清扫单点触发**（隐私系统自己的磁盘取证面没闭环，P2）；**出证任务的资源门控缺失**（内存竞争史的复燃条件仍在，P2）。另有宣称-实现的收尾微差两处（审计令牌档位、备份档位条件）。无 P0。

---

## ② 做得好的（带代码锚）

1. **认证三域：恒时比较+域分离+单源注入+fail-closed**。
   - `ra/router.py:270-281`（X-RA-Token）、`audit/router.py:214-221`（X-Audit-Token）、`telemetry/router.py:34-47`（X-Engine-Token）全部 `hmac.compare_digest`；engine 面 `not want` 时直接 401（env 缺失≠放行），且 `main.py:29-37` 启动时对 "real 链但无 FZ_ENGINE_TOKEN" 打印显式告警——fail-closed 但让人看见（R3-0.5 教训的制度化）。
   - 401 诊断打印的是 `supplied_len/want_len/want_fp`（长度指纹），不打印值——这个"诊断面不泄密"的细节意识很好（但见 P3-2，want 前缀仍进了日志）。
   - 单源注入：`demo_up.py:172-184` 五钥随机+`%TEMP%` 持久+`gcs_bridge_start.sh:12-13` 桥侧从同源文件读取——"一处定义、三服务同源"落到实处。**实测**：`/ra/ops-token-hint` 返回 `demo:false`（随机注入生效）。
   - 披露纪律自洽：`ra/router.py:337-369` 与 `audit/router.py:317-333` 只披露"本就 repo 公开可推算"的值（env 未设=派生公式 `sm3(b"FZ-KMS|ra-ops").hex()` 族），env 已设=只指路文件——"凭证不贴墙上"的边界画得准。

2. **匿名红线的代码级兑现（不只是文档宣称）**。
   - `/chain/panel`、`/chain/record/{auth_id}` 全文无身份字段（`chain/panel.py:130-261`，实抽 auth_id=136 确认仅证明/政策/链面字段）；面板令状只出哈希+authId，case_no 明确注释"审计自由文本不出未认证面"（`chain/panel.py:148-150`）。
   - RA 实名映射 SM4-GCM wrap 落库（`ra/service.py:141-150`，域钥=`kms_domain_key(b"FZ-KMS|ra-store-wrap")`，env FZ_WRAP_KEY 已随机化）；回执=128bit CSPRNG+令牌经会话钥 ECIES 封发（`authz/service.py:302, 373-384`）；令牌零设备字段（`authz/service.py:333-334` sn_hash 不入令牌）。
   - 受理毒丸防御：会话公钥先过曲线方程校验（`authz/service.py:147-158`，S5 修复——防"非曲线点 ECIES 封发抛异常→毒丸申请占满 worker"的匿名 DoS）。

3. **worker 并发正确性是成体系的，不是单点补丁**。
   - 两步乐观认领（候选选出→条件 UPDATE 抢租约→RETURNING 裁决归属，`worker.py:271-296`）；终态守卫=仅 pending 可入终态的条件 UPDATE，迟到者不得把 approved 翻案（`worker.py:391-420`）；租约 ≥2×verify 超时的推导写进注释（`worker.py:248-254`）；跨重启对账防崩溃窗盲重试（`worker.py:299-323`）；验证窗内撤销根 TOCTOU 复查（`worker.py:456-471`）+recordAuth 读后写对拍（`worker.py:531-547`）+authId 预测错位 fail-closed（`worker.py:548-560`）。这一族防线互相咬合，是"多 worker 水平扩展"宣称的真实底气。

4. **record_lock（特别任务①）核验通过**。
   - `record_lock.py:42-65`：获取（忙等+超时→`RecordAuthLockTimeout`→走瞬时重试轴 `worker.py:335-355`）/释放（`finally` 中仅 acquired 才解锁+必关 fd——异常路径不漏锁）/进程崩溃 OS 自动释放（msvcrt/fcntl 语义）；Windows `msvcrt.locking(LK_NBLCK,1)` 与 POSIX `flock(LOCK_EX|LOCK_NB)` 双形态正确。
   - 锁范围设计正确：verify（分钟级）在锁外，锁内只串行"预测→铸令牌→recordAuth"（`worker.py:482-530`，单笔 tx 亚秒级），90s 超时远大于单 tx 时长；锁内失败上抛自然释放。与 engine 链写原子性的关系清晰：互斥保证预测恒中，组外写入由 `auth_id != predicted` 守卫兜底（fail-closed 拒绝，不按实际值放行——`record_lock.py:3-14` 的定谳逻辑成立，锚定串号比烧授权更糟的判断正确）。
   - 残余小项见 P3-5（缺省锁文件 %TEMP% 的跨用户前提），模块 docstring 已如实声明生产升 pg_advisory_lock 的路径。

5. **案卷下载端点（特别任务②）核验通过**。
   - `prover.py:688-691`：case_id 正则 `[0-9a-f]{8,64}`（纯 hex，路径拼接无穿越可能）+artifact 固定六件白名单（proof.bin/verifier_param.bin/verdict.json/instances.json/expected.json/binding.json）。**实测**：`/prove/case/..%2f..%2fsecrets/proof.bin`→404（路由层不匹配）；`/prove/case/zzzz/no_artifact.bin`→400 bad_case_id。
   - case_id=CSPRNG `token_hex(8)`（64bit，`prover.py:577,706`）——在线枚举不可行（10k req/s 下命中中位约 3900 万年），产物本身零秘密（见证不出设备，`prover.py:1-8` 架构声明与 instances.json 实查一致：纯公开实例字段）。熵低于回执码 128bit 的家族不一致见 P3-4。
   - 行程索引 `/prove/trip/index` 无认证（实查可读）——桥接属 TCB 第①层（`server.py:2-6` 绑定 127.0.0.1 已实测确认，`gcs_bridge_start.sh:23`），本机自读自料，边界内自洽。

6. **验证分发站与浏览器内验证的安全面干净**。
   - `/verify/api/checks` 校验值按磁盘实物实时 sha256（`verify_dist.py:39-50`），**实测与 dist/SHA256SUMS.txt 及磁盘 sha256sum 三方逐位一致**——"永不失真"宣称兑现；`trail_canonical_spec.json` 端点源码钉定路径、不可穿越（`verify_dist.py:53-62`）。
   - `check_dir=False`（`main.py:114-118`）核验为**无安全影响**：仅跳过启动期目录存在性检查（产物未生成分发页仍可访问），Starlette StaticFiles 的路径解析自带穿越防护；/verify/ 页面（git 内）与 /verify/dist（gitignore 二进制）分离挂载、前序匹配正确（`main.py:111-125`）。
   - `wasmVerifyWorker.ts`：worker 内自行 fetch 的 URL 全部由 TrailView 以 `apiBase()`/`bridgeBase()`（localhost 白名单 CORS，`main.py:69-74`/`server.py:31-36`）构造，无用户可控 URL 注入面；验证在浏览器本地 WASI 沙箱内运行、双信号判据（rc=0 且末行含 OK）与 CLI 同判——"零服务端参与"的复验形态没有引入新的信任假设。

7. **出证数据面的新旧两道防线**。
   - 新增 fence×alt_max 交叉比对（`prover.py:604-617`）：链上检查点签名的围栏态高于引擎授权即 409 拒绝出证——"固件围栏被抬高=证书语义矛盾"的守门从无到有；配合 alt_max 引擎绑定对拍（`prover.py:589-599`）+引擎签名绑定随案卷归档 binding.json（`prover.py:514-516`），"证明者不可自报上限"在桥侧、装配面、复验面三层闭环。
   - 合成采样 403 门控（`server.py:96-107`，FZ_ALLOW_SYNTHETIC_SAMPLE 缺省关）+SITL 采样 fail-closed（非 sitl 链路拒绝伪造遥测，`server.py:124-125`）——"真实测试策略"有代码闸门背书。

8. **传输与部署面的纪律**。
   - `chain/client.py:44-46` trust_env=False（链 RPC 禁系统代理）+5s 熔断冷却（`client.py:62-76`）；`nginx_fz.conf`：apply 分区 5r/s burst10 / 常规 50r/s burst100、9443 `ssl_verify_client on`、TLSv1.2+；`gen_certs.py` CA 全扩展（basicConstraints/keyUsage critical）+SAN 双址+私钥 gitignore+CSR 即焚。
   - `_prove_remote` 主机钥 pinning 强制（`prover.py:318-341`）——缺 FZ_PROVE_REMOTE_HOSTKEY 直接拒绝盲连，把"MITM 可截获完整见证"的攻击面在代码层关死，这是上轮评审修复里质量很高的一处。

9. **审计双控的链面硬约束**（`audit/service.py:120-141`）：解锁前验令状链上在案（`warrant_not_on_chain` 拒）+链上/库内一次性（`already_unlocked`）+解锁留痕 onlyRA 上链——"追责行为本身被审计"不是口号，是三重前置条件。

---

## ③ 缺陷与风险（按严重度）

### P1-1 登记/子凭证签发面无认证——网络可达档下=无限自铸准入身份+追责身份自报

- **证据**：`POST /ra/register`（`ra/router.py:218-223`）与 `POST /ra/sub-credentials`（`ra/router.py:226-231`）均无任何认证依赖（对比：revoke/warrant/unlock/collab 全有 `_require_ra_token`）。register 接受任意 `id_number`（仅校验 18 字符，`ra/service.py:92-93`）与自报 `cert_level`，响应直接返回签名材料（`ra/service.py:160-165`）；sub-credentials 只校验预像与承诺一致（`ra/service.py:195` 附近重算 commitment 对拍）——而预像对自注册者完全已知。
- **攻击场景**：演示档三服务绑 127.0.0.1（`demo_up.py:203-204`）→ 仅本机可达，风险被环回抑制。但 `nginx_fz.conf:29-42` 的 443"浏览器档"把**全部** `/ra/*` 代理到后端且仅服务端 TLS（无客户端证书、无令牌）——按该配置部署（即"生产演进"宣称的入口形态），任意网络 peer 可：①自铸任意身份证号的凭证（数量受配额但可无限换 username）；②借 ZK 管线获真实飞行授权令牌；③令状解锁时 RA 解出的是攻击者自报的身份证号（`ra/service.py:357-371` unwrap 所得）——**追责闭环解出攻击者自报身份=问责面被架空**。
- **修法方向**：登记面加身份核验档位（RA ops 令牌/一次性邀请码/对接 KYC 的最小形态），或 nginx 443 对 `/ra/register|/ra/sub-credentials` 单独 limit+来源白名单；最低限度先把边界显式化（见亮点化）。
- **能否转化为亮点**：能。答辩口径 G 区已有"本作品不宣称机构级部署"（部分覆盖此边界），但"登记通道=演示无核验窗口、生产=KYC 到面+RA 运维令牌"应作为一条显式 TCB 边界写进 E 区——"准入身份核验是登记机构的组织职能而非密码职能，本作品交付的是核验之后的零知识化"，主动讲清反而封住"拿假身份证能飞吗"这一必问。

### P2-1 TRAIL 失败路径的轨迹明文残留 + 脱敏清扫单点触发（隐私系统的磁盘取证面未闭环）

- **证据**：AUTH 失败路径做对了——`job.json`（含身份证号/盐/出示私钥见证）即焚+写脱敏 `failure.json`（`prover.py:198-217`；磁盘实查 4 个 `_tmp_*` 目录仅剩 failure.json，内容仅 task_id/错误消息/时间，无任何见证值）。但 **TRAIL 失败路径的 finally 只在成功时删 tmp**（`prover.py:534-538`：`if task.get("status") != "failed": shutil.rmtree(tmp)`）——失败时 `trail_job.json`（含 `rows_hex`=完整 128 样本经纬度轨迹+设备签名，`prover.py:472-497`）整目录滞留；且 TTL 清扫 `_sweep_stale_failures()` **只在 AUTH 失败分支被调用**（`prover.py:217` 唯一调用点），TRAIL 失败不触发清扫，也无启动清扫。另：进程被硬杀（`demo_up.py:86-113` preclean 每次 `taskkill /F` 端口进程）时 finally 不执行，AUTH 的 `job.json` 同样滞留，只能等"下一次 AUTH 失败且已超 24h"才被顺带扫掉。
- **攻击场景**：本机盘面取证/误共享备份/目录同步盘场景下，"轨迹本体永不上链、只存本机"（数据分级文档桥接本地域）的宣称被自己的出证临时目录打折扣；隐私系统仓库里滞留明文见证/轨迹=答辩时可被戳的"自家红线破口"。
- **修法方向**：TRAIL 失败分支对齐 AUTH（删 `trail_job.json`+写脱敏 failure.json）；`_sweep_stale_failures()` 挂到桥启动/`_cases_dir()` 首调/worker 周期，不再依赖"恰好又失败一次"。
- **能否转化为亮点**：能。收口后"隐私系统的磁盘取证面：成功即焚+失败脱敏+启动清扫三重纪律"是一段很好的答辩材料——现在的半吊子态反而是减分项。

### P2-2 出证任务面无并发上限+任务表无回收（内存竞争史的复燃条件仍在）

- **证据**：`_TASKS: dict` 只增不删（`prover.py:71`，全文件无任何清出点——`/prove/task/{id}` 也不出表）；`/prove/start` 与 `/prove/trail/start` 每请求无条件 `threading.Thread` 起出证（`prover.py:730-731, 623-628`），无信号量/去重——每个 AUTH prove 是 12 Rayon 线程、峰值 ~14GB 级的子进程（口径卡 B5）。
- **攻击场景**：演示机上重复点击/脚本连发 `/prove/start`→并发出证进程互相挤压内存→交换死或 OOM 杀，正在跑的任务全灭。TCB① 内属"自伤"，但这是**历史实锤事故族**（性能档案 R1/R2 的内存工程全是为它做的），前端按钮无防抖的条件下演示现场翻车概率不低。
- **修法方向**：全局 `Semaphore(1)`（或按 profile 限 1）+同 case/material 去重（同 plan_hash+nonce 的进行中任务直接复用 task_id）+`_TASKS` 上限/TTL 驱逐。
- **能否转化为亮点**：能。"出证是稀缺算力"的产品语义（排队/复用/限流）本就是性能档案的叙事延伸，代码化后可与 60s 硬门判决行合并讲。

### P2-3 demo_up 真链档的审计台令牌仍是 repo 公开常量——与 CHECKLIST 表述相左

- **证据**：`demo_up.py:167` `env.setdefault("FZ_AUDIT_TOKEN", "fake-audit-token")` **无视链档**无条件注入；而 CHECKLIST 写"真链档见 kms audit_api_token"（`demo_up.py:51`）。实际效果：真链演示档下审计台令牌=repo 文档化的演示常量（派生公式 `sm3(b"FZ-KMS|audit|api-token").hex()`，但被 env 覆盖为常量），`/audit/demo-token` 实测返回 `demo:true` 并回显该常量——立案（logWarrant 上链）、解锁实名、追溯全可用一个公开值操作。披露逻辑本身自洽（env==公开常量即披露，`audit/router.py:330-333`），问题在"上轮随机化批次漏了这一面+文档文本未兑现"。
- **攻击场景**：演示机旁观的评委/观众对 8000 端口（本机任意进程）可全程操纵审计面——演示档内环回+公开常量=已声明形态，危害限于"审计台认证形同装饰"；但这恰是"审计方独立"叙事的支撑面。
- **修法方向**：真链档下 `setdefault` 改 `secrets.token_hex(32)` 并入 `%TEMP%` 持久清单（与 FZ_RA_OPS_TOKEN 同批同纪律）；CHECKLIST 文本随之自然成立。
- **能否转化为亮点**：能——"六个密钥面全部每场一次性随机"比现在的"五个半"干净得多，且改动是三行。

### P2-4 双控第二因素在数据链不可验证时 fail-open + FZC1 旧函仍可解锁

- **证据**：`audit/router.py:413-422` 仅当 `scope_mismatch is True` 才 403，返回 None（授权链任一环缺失，`ra/scope.py:33-44`）即放行——"范围受限双控"对历史/异常数据退化为"有函即可"；且 FZC1 旧函仍走兼容解析（`audit/router.py:407`），FZC1 无令状绑定（`ra/collab.py:68-70` 自证"一张函可解多个令状"），新出具已全量 FZC2（`ra/router.py:456`）但存量 FZC1 对任意在案未解锁令状仍然有效。
- **攻击场景**：持有任一历史 FZC1 函的 RA 操作员（或其凭据的泄露者）可对**另一张**令状解锁实名（仍需审计令牌+令状在案+未解锁三前提，故非独立攻破，属双控强度衰减）。`target_auth_id=None` 的匿名立案令状则天然无范围约束（设计声明内）。
- **修法方向**：FZC1 解析面加窗口期声明（仅限无 target 历史令状/直接停用）；scope=None 时在解锁结果里显式标注 `scope_verified:false` 供审计留痕。
- **能否转化为亮点**：能。FZC2 的"函-令状-凭证三方 AAD"本身就是好素材，补上"旧函停用窗口"声明即完整。

### P3（卫生级）

- **P3-1** 登记面的信息面：`/ra/revocation/snapshot` 公开返回撤销表全量（`ra/router.py:265-267`）——撤销 handle 本属"公示镜像"设计（B3b），但无分页/无缓存下属公开面无界读。登记/签发主缺陷已单列 P1-1。
- **P3-2** 引擎令牌 401 诊断把 `want[:6]` 写进日志（`telemetry/router.py:41-43`）——随机 32hex 下前缀泄露不构成攻击面，但违反自家"日志零敏感值"纪律；改打 `sm3(want)[:8]` 指纹同效。
- **P3-3** 未认证公开面的资源放大：`/ra/revocation/witness` 每调用全表加载+SMT 全树重算（`ra/router.py:242-262`）；`/authz/binding` 同为无节流计算面。nginx 50r/s 兜底，演示域可接受；撤销表低频变，加 3-5s TTL 缓存即可。
- **P3-4** case_id 64bit（`prover.py:577,706`）与回执码 128bit（`authz/service.py:302`）capability 熵不一致；案卷目录（磁盘实查 163 个）无 TTL 归档——proof/instances 属公开材料但长期滞盘。统一 `token_hex(16)`+案卷归档 TTL。
- **P3-5** record_lock 缺省锁文件在 `%TEMP%`（`record_lock.py:32-39`）：Windows 按用户隔离，跨用户多 worker 不互斥（docstring 已声明生产改 FZ_RECORD_AUTH_LOCK/pg_advisory_lock——生产部署清单应把该 env 列为必设项）。
- **P3-6** localhost 面无 Host 校验：DNS rebinding 理论上可让外部页面读到未认证 GET（`/chain/panel`、桥 `/audit`、`/prove/case/*`）——均为零身份/零秘密面，演示域风险低；加 Host ∈ {127.0.0.1, localhost} 中间件一行即可封死。
- **P3-7** `/authz/apply` 受理前的 case 产物存在性检查（`authz/router.py:180-184`）构成"任意 hex 目录是否含三件套"的布尔探针——case_id 64bit 随机下不可行，仅记录在案。
- **P3-8** `_audit_token()` 每请求读 env 而 `_deps` 缓存首值（`audit/router.py:200-207`）——运维热改 env 后两处可能短暂不一致；无攻击收益，一致性卫生。

---

## ④ "宣称 vs 实现"核验表

| # | 宣称（来源） | 判定 | 证据 |
|---|---|---|---|
| 1 | record_auth_lock 跨进程互斥已根修（口径卡 F2） | **属实** | `record_lock.py` 全（异常安全 finally/超时→重试轴/OS 崩溃自释放）+`worker.py:482-531` 锁内预测→铸→链写+`worker.py:548-560` 组外错位 fail-closed；锁范围设计合理（verify 在锁外） |
| 2 | 案卷下载 case_id 正则+artifact 白名单防穿越（合成摘要"已修"批） | **属实** | `prover.py:688-691`+实测 `..%2f`→404、短 id→400；产物白名单六件无路径量 |
| 3 | A2 ECIES 密文篡改拒（红队记录） | **属实（在位）** | `crypto/sm2.py:445-465` 自实现 decrypt 显式比较 C3 校验值（gmssl 原实现不比较的坑已绕开）+`redteam.py:140-158` 攻击形态在案 |
| 4 | A5 时间窗滥用拒（红队记录） | **属实（在位）** | `authz/service.py:245-247` window_too_long（FZ_MAX_TOKEN_WINDOW_S 缺省 6h）+`authz/service.py:254-261` t_epoch 新鲜度门（防回溯洗窗） |
| 5 | A6 接口灌爆 429（红队记录/口径卡 F4） | **属实但层位=部署面** | `nginx_fz.conf:20-22,37-41` limit_req 分区；backend 裸端口 8000 无应用层限流（redteam.py:227 脚本自注"本机环回无 nginx 时=业务层承受"）——宣称应绑定"nginx 前置档" |
| 6 | A8 审计台坏令牌 401（红队记录） | **属实（在位+实测）** | `audit/router.py:214-221` 恒时比较；实探 `GET /audit/warrants` 无令牌=401 |
| 7 | demo_up 补 FZ_RA_OPS_TOKEN/FZ_WRAP_KEY/FZ_AUTHZ_BINDING_KEY 随机注入+%TEMP% 持久（合成摘要已处置） | **属实** | `demo_up.py:182-184, 189-198`；实测 `/ra/ops-token-hint` demo=false 只指路 |
| 8 | 合成采样 403 门控（真实测试策略） | **属实** | `server.py:96-103` env 缺省关；SITL 面 fail-closed（`server.py:124-125`） |
| 9 | binding.json 随案卷归档+下载白名单（合成摘要已处置） | **属实** | `prover.py:514-516` 归档+`prover.py:690` 白名单含 binding.json |
| 10 | failure.json 脱敏+job.json 即焚+TTL 清扫（prover 注释 A-P2-1） | **半属实** | AUTH 路径属实（磁盘实查无 job.json 残留、failure.json 无敏感值）；**TRAIL 失败路径不成立**（P2-1）且清扫单点触发 |
| 11 | 分发站 sha256 实时计算+供应链公示（口径卡 A7） | **属实（实测）** | `/verify/api/checks` 与 dist/SHA256SUMS.txt 与磁盘 sha256sum 三方逐位一致（zkc-linux-amd64/zkc.wasm/manifest） |
| 12 | fence×alt_max 交叉比对（口径卡 A4 行程证书包） | **属实** | `prover.py:604-617` 围栏 cm>授权 cm 即 409 fence_exceeds_auth+围栏态形态校验 |
| 13 | CHECKLIST"真链档令牌见 kms audit_api_token"（demo_up.py:51） | **不属实** | `demo_up.py:167` 无条件 setdefault 公开常量，真链档同样被覆盖（P2-3） |
| 14 | F6 备份可恢复（口径卡 F 区） | **有条件兑现** | `backup_demo.py` 仅 PG 档（pg_dump+FZ_PG_PW_FILE env）；缺省 SQLite 演示形态不可复现该判决行——答辩引用时应标档位 |
| 15 |TrailView `/prove` 前缀已修（A-P0-1） | **属实（顺带核验）** | `TrailView.vue:167` dlUrl 已含 `/prove/case/` |
| 16 | verify 静态挂载 check_dir=False（本轮评审问询点） | **无安全影响** | 仅跳过启动检查；Starlette StaticFiles 自带穿越防护（`main.py:114-125`） |

---

## ⑤ 一句话总评

**这是一套"防御真实存在、边界大多画得诚实"的系统：并发正确性与认证纪律经逐行核验确属兑现，而本轮真正要补的是三件自家叙事内的事——登记面的认证空档要显式化、TRAIL 失败路径的磁盘脱敏要闭环、出证算力要上闸门；补齐这三件加审计令牌最后一钥的随机化，"演示档内自洽、生产宣称可兑现"就不再有已知例外。**
