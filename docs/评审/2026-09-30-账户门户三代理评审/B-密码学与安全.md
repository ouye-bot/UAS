# 「飞证」账户门户与双控层 · 密码学与安全评审（B 席）

> 干净上下文实弹评审（2026-09-30）。范围：`backend/app/accounts/`（models/service/
> kdf/deps/router/admin_router/collab）、前端 auth 面（`gcs/web/src/lib/auth.ts`/
> `keystore.ts`/`material.ts`/AdminView/AuditView 签名面）、令牌退役面、迁移
> b1c2d3e4_0011/ee11ff22_0012/c3d4e5f7_0013。方法论：全量代码实读 + 实弹打真栈
> （http://127.0.0.1:8000，真链档）+ 进程内新库状态机实测；测试子集
> `test_accounts.py + test_collab_dual_control.py` 17/17 通过。实弹脚本与临时
> 账户（revb- 前缀）均在 %TEMP%，未动任何源码/配置/服务。PIII 一律打码。

---

## 一、总评

**账户本体的密码设计是这几批交付里最干净的一层：服务端稳态零口令材料不是话术而是可逐行验证的事实**——登录=SM2 挑战-应答（nonce 一次性+120s TTL），预置账户首登激活用 KDF 核对子一次性恒时比对后即焚（`service.py:194-212`），此后库里没有任何可离线猜测口令的面；私钥/身份资料只以客户端密码 KEK 的 SM4-GCM v3 信封存在，KDF 在 Python/TS 两侧逐字节同构且有 JS 固定向量对拍测试钉死。这些经实弹全部站得住：重放挑战 401、伪造签名 401、跨账户 nonce 401、错角色 401/403 两层语义精确、限速 429 真实生效、Cookie HttpOnly+SameSite=Lax 到位、X-Audit-Token/X-RA-Token 退役彻底（三 router 零残留认证代码）。

**但双控工作流这一批的头号宣称被实弹推翻了**。设计方案 §4（L126-128）白纸黑字："任何单一角色（包括服务器自身被完全攻陷的场景下没有两把钥时）都无法合法完成解锁……双控从'约定'升格为'密码学事实'"。实测：**机构管理员单方会话、不带审计员签名、不带协作函、且故意配错令状的外来凭证，3 个 HTTP 请求即在真链档拿到当事人明文实名（姓名/身份证号/设备号）**——走的正是令牌退役后原样保留的 `POST /ra/warrant/unlock` 残留路由。这不是理论洞，是可当场复演的宣称翻车。

第二族问题是**双控状态机的非原子性**：approve 的幂等宣称（"重复批准不重复执行"）与实现相反——executed 后用垃圾签名重批即把请求打回 execute_failed（结案永不可能）、每次重试重复出函落台账；并发双 approve 产生双执行；approve/reject 竞态能让**已被驳回的请求以 executed 终态收场**。均为进程内新库实测证实。

第三处是**前端跨账户清扫的锚被自己的登出流程拆掉**：logout 先删会话旗标，下一次登录读到 prevUser=null，账户切换清扫整体短路——上一账户的明文身份证号（fzForm）、凭证与密封件在共享浏览器上跨户滞留；而被宣称依赖的 `sweepIfIdentityChanged` 全仓零调用。

总体定性：**认证与密钥层可放心带上台面；双控层"密码学强制"的宣称今天不成立**——堵掉一条残留路由、给状态机加一行原子性、给清扫锚换个挂点，宣称即可回到与实现同一条线上。

---

## 二、密码设计亮点（经实弹核验，挂证据）

1. **服务端稳态零口令材料，且激活核对子是"即焚"而非"留存"**。`accounts/models.py:38-46`：账户表无任何口令列；`service.py:205`（激活核对 `hmac.compare_digest(verifier_hex.lower(), want)` 恒时）+ `service.py:209-210`（`init_verifier_hex=None` 即焚）+ `router.py:126`（activate 入限速桶）。实弹确认：激活态账户与稳态账户的库里都没有口令等价物——"拖库=密封件离线猜测面"的边界陈述与实现一致（且猜测面对象是密码 KEK 信封，不是口令哈希）。
2. **KDF 双语言逐字节对拍锚**。`accounts/kdf.py:22-31` 与 `keystore.ts:43-53` 同一构造（h0=SM3(pass‖salt)；hi=SM3(h_{i-1}‖pass)；取 16B），`test_accounts.py::test_kdf_cross_vectors` 持有 JS 侧固定向量——跨语言 KDF 是迁移 bug 高发区（字节序/编码/迭代边界），这里用测试钉死而非口头宣称，是教科书做法。
3. **密封件双层公钥核对，错配即拒**。服务端注册/激活入口 `_validate_sealed_blob`（`service.py:89-108`：v3 形态+pk 一致性+全字段 hex 形态，fail-closed 不带病入库）；前端解封后再核 `skMatchPub(sk, env.pk) && env.pk === ks.pubkey_hex`（`auth.ts:210-212`）——密封件被调包/截断在两端都出人话错误而非密码学异常。
4. **会话凭据"库泄露不可还原"**。`service.py:239-247`：token=`secrets.token_hex(32)`（256bit），库内只存 `sm3(token)`；Cookie `HttpOnly; SameSite=lax`（`router.py:155-163`，演示 http 档无 Secure=已拍板接受边界）。实弹核验 Set-Cookie 原文：`fz_session=…; HttpOnly; Max-Age=43200; Path=/; SameSite=lax`。401（未登录/失效）与 403（角色不符）两层语义分立且全站一致（`deps.py:42-63`），实弹逐点核对无漂移。
5. **令牌退役是"真退役"**。`audit/router.py` 与 `ra/router.py` 全文已无 `compare_digest`/Bearer 检查代码（仅注释与 `main.py:99` CORS allow-headers 留了一个无害的旧头名）；上一轮的恒时比较面随令牌一起消失，未留下"头还在、只查会话"的半吊子态。审计流内部解锁走 `_ra_unlock` 函数桥（`audit/router.py:186-199`）不经 HTTP——这反衬出问题清单 B-P0-1 里那条 HTTP 残留路由的突兀。
6. **执行失败的结构化诚实面**。`collab.py:340-353`：历史纪元凭证（信封以已轮换域密钥封装）如实映射为"实名解锁在密码学上不可达"的 `unwrap_failed` 人话错误，而非 500 或假成功——纪元轮换的密码学后果被如实传达给批准人，这是很多成熟系统都做不到的诚实。
7. **负例体系覆盖新攻击面**。17/17 通过含：挑战重放拒、坏签拒、跨角色 401/403、限速 429、登出焚会话、双控缺任一签名拒、同令状在途唯一性。实弹复核与测试结论一致（无"测试绿、线上偏"的裂缝）。

---

## 三、问题清单

### B-P0-1 残留路由 `/ra/warrant/unlock`：单管理员完整绕过双控（实弹证实，宣称翻车级）

- **证据**：`ra/router.py:306-326`——端点仅 `require_role("admin")`；`ra/service.py:339-373` `warrant_unlock` 只查①令状链上在案②凭证有通道②密文③unwrap，**无审计员签名、无 FZC2、无 scope 校验、不查本地 unlocked_ts**；全仓前端/脚本零调用（纯残留面）。
- **实弹复现**（真链档，PIII 打码）：
  1. auditor 建令状 `REVB-B1-2fe12d`（wh=`c01b01…02fd`，无目标）；
  2. admin 会话 `POST /ra/warrant/unlock {"warrant_hash_hex": wh, "master_cred_hash_hex": <外来凭证，属另一令状>}` → **200** `{"username":"role***","id_number":"1101***","sn":"FZ-R***"}`。
  单人、跨令状凭证、无协作函、无双签——审计台的 `warrants.unlocked_ts` 甚至不变（该路径不写审计库），案件在审计台上仍是"未解锁"。
- **级别**：P0（本批头号宣称"任何单一角色无法合法完成解锁"（设计方案 §4 L126-128）被可复现推翻；答辩/评委 3 请求即可复演）。
- **威胁模型内可利用性**：admin 会话持有者（内部人员/被钓会话/机构台 XSS）无需任何第二因子。注：链上 `logWarrantUnlock` 有一次性守卫（`IdentityRegistry.sol:84-89` `require(!warrantUnlocks[warrantHash])`）——只防"同令状重复解锁"，对首次单人解锁无约束；已解锁令状重放该路由得到的是未捕获 ChainError → 500（追踪号 5b0cc88a9fc9e8d7 实录），顺带暴露该路径连 ChainError→503/409 的映射都没接（其他路径都有）。
- **修复方向**：直接下线该 HTTP 路由（审计流用的是函数桥，无合法调用方）；若须保留运维面，则强制要求存在同 wh 的 approved/executed collab 请求 + 补 scope_mismatch 校验 + ChainError 映射。同时把设计方案 §4 的宣称与路由表做一次对账。

### B-P1-2 双控状态机非原子：幂等宣称与实现相反；executed 可被打回 execute_failed；驳回可被执行覆盖（进程内实证）

- **证据**：`collab.py:151-184` `approve_and_execute`——docstring L163"幂等：approved/executing/executed 直接返回当前态（重复批准不重复执行）"，实现却是：非 pending 态**跳过签名验证**后无条件 `_spawn_execute`（L172-179）。`_executing` 进程级集合（L36, L217-225）只在"线程还活着"时去重——worker 完成后同请求可再次拉起。
- **实测**（进程内新库，fake 锚，完整授权链构造）：
  - **A（重批回归）**：请求批至 executed 后，`POST approve {"sig_hex":"00"*64}`（垃圾签名）→ **200**，后台再执行→出第二张 FZC2+台账落第二行（1→2 行）→ `already_unlocked` → 请求终态 **execute_failed**，`close` 409"须已执行方可结案"——已闭环案件被永久打回，且无任何新签名。
  - **C（并发双批）**：两名管理员同时对同一 pending 请求 approve → 双双 200（后写者覆盖 admin_sig 溯源），**台账落 2 行=双执行**，终态 execute_failed（第二次解锁撞 already_unlocked）。
  - **D（批/驳竞态）**：approve 与 reject 并发 → 均 200；终态 **executed**——管理员的显式驳回被后台执行覆盖，"驳回=终态"语义失守。
- **级别**：P1（完整性/审计语义；UI 有 busy 守卫但 API 裸露，重试按钮/双击/网络重发均可触发）。
- **修复方向**：状态迁移改条件 UPDATE（`UPDATE collab_requests SET status='approved' WHERE id=? AND status='pending'`，rowcount=0 即 409）或 SELECT…FOR UPDATE；非 pending 态直接返回当前视图不再 spawn；executed/rejected/closed 一律拒批；rejected 与 executed 互斥由数据库保证。

### B-P1-3 前端账户切换清扫被登出流程短路：明文 PIII 跨账户滞留共享浏览器

- **证据**：`auth.ts:229-231`——`const prevUser = cachedUsername(); setSessionFlag(out.username,…); sweepForAccountSwitch(prevUser, out.username)`；而 `auth.ts:79-87` logout 先 `clearSessionFlag()`（删除 fzSession）→ 下一次登录 `cachedUsername()`=null → `sweepForAccountSwitch` 首行 `if (!prevUser…) return false`（`material.ts:117-118`）**直接短路**。被宣称依赖的兜底 `sweepIfIdentityChanged`（`App.vue:60` 注释"本地 fzCred 等身份域由 sweepIfIdentityChanged 在换人时清扫"）**全仓零调用**（grep 仅定义处与该注释）。
- **后果**：A 登出→B 同浏览器登录：A 的 `fzForm`（**明文身份证号**，`auth.ts:157`）/`fzCred`/`fzUserKeypair`（A 的密封件）全部滞留，B 的页面按旧键位读到 A 的身份材料；A 的 `fzIdTag` 与 `fzCred` 同源一致，身份标签清扫也永不触发。密钥本体有密码密封（B 拿不到 A 的 sk），泄露的是 PIII 展示面与身份串号——正是 `ACCOUNT_SWITCH_KEYS`（`material.ts:109-115`）这批键要防的场景，防线的锚却在登出时自毁。
- **级别**：P1（共享浏览器 PIII 跨户泄露；静态证据链完整闭合，无歧义）。
- **修复方向**：logout 改为先取 prevUser 落入独立键（如 `fzLastUser`）再清旗标；或 logout 时同步清 `ACCOUNT_SWITCH_KEYS`；或干脆在 App 挂载时真调一次 `sweepIfIdentityChanged`（函数已存在，一行接线）。顺手把"单一事实源"纪律补完：`sweepIfIdentityChanged` 与 `sweepForAccountSwitch` 共用同一键表。

### B-P2-4 FZC2 在自动执行路径是自我往返仪式；设计文档 §4.5 的"信封 AAD 绑定双签+范围+时效+单次有效"未实现

- **证据**：`collab.py:322-331`——自动执行里 `seal_collab_v2` 出函→`open_collab_v2` 解封（"双向自证"）→真正的解锁直接以 `cred_hex` 走 `AuditService.unlock`；FZC2 码本身不出服务器、不进任何验证环节（仅指纹落库展示）。`ra/collab.py` 实际 AAD=`FZ-COLLAB-v2‖wh`（无双签/范围/时效/单次位）；CollabRequest 无时效字段。安全 enforced 实为：双签验签（工作流门）+ `resolve_cred_for_auth`（范围）——**效果等价但机制与宣称不同物**。附带：每次 retry/re-approve 重复出函+台账落行（实测 2 行），台账"出具"语义被注水。
- **级别**：P2（宣称-实现错位，非可利用洞；但答辩追问"双签怎么进信封的"即穿）。
- **修复方向**：宣称收窄（双控强制=双验签+解析链范围校验，FZC2=出函凭据物）或补实现（req_hash 与 (cred,wh) 入 AAD、出函绑定 request_id、加 expiry）。台账只在函真正交付审计侧时落行。

### B-P2-5 密封件公开下发端点无限速：离线猜测面从"拖库"扩大为"一次 GET"

- **证据**：`router.py:103-110` `GET /auth/keystore/{username}` 无会话要求亦无 `auth_limiter`；实弹未登录拉取 admin 密封件 200（573B）。`keystore_of` 注释自认"公开网络面拿到密封件只有离线猜测面"——设计与"库泄露=猜测面"的已接受边界相比，实现把获取成本降为零泄漏、零限速；配合 prelogin 的用户名枚举（存在 200/不存在 404），构成对指定用户的定向离线字典攻击入口（原生 SM3 迭代链 ≈11ms/候选，上轮 C 席实测口径）。
- **级别**：P2（边界表述诚实性+攻击面收紧；非新密码弱点——KDF 21000 的强度账是已接受边界，此处只报"获取面"的扩大）。
- **修复方向**：keystore 端点挂限速桶（与 challenge 同窗）；文案把"库泄露"改为"能访问 /auth/keystore 的任何人"；用户名枚举可留（演示档）但应在口径卡声明。

### B-P2-6 限速器内存固定窗的部署语义与锁死面

- **证据**：`service.py:53-81`——`AttemptLimiter` 进程内 dict+threading.Lock，代码自注"多进程部署须共享存储"（诚实）。实测补充两点：①各操作独立桶——login 桶打满 429 后 prelogin 仍 200（实弹确认），桶分立是设计而非漏防，但意味着限速保护只覆盖登录签名面；②键=`ip|username`：攻击者可从任意 IP 烧掉受害用户名的桶（5 分钟登录锁死 DoS）；反向地，NAT/反代后多用户共享 ip 桶互踩。`_hits` 无过期回收（仅成功登录 reset login 桶），长期运行缓慢积累。
- **级别**：P2（部署即失效类——uvicorn 单 worker 演示档成立；生产多 worker 需共享存储才能兑现宣称）。
- **修复方向**：迁移 Alembic 化（web_sessions 表加一列即可）或 Redis；键加"仅对失败计数+成功即焚"避免自我锁死；声明"限速=单进程档"。

### B-P2-7 req_hash 绑定的传递性与消息域卫生

- **证据**：`collab.py:47-48`——req_hash=SM3("FZ-COLLAB-REQ|v1|"+wh+"|"+note)，只覆盖（令状哈希，附言）。实际解锁对象=target_auth_id→`resolve_cred_for_auth` 的凭证，靠"令状行创建后不可变"传递绑定；管理员批准签名**不直接承诺** target_auth_id/case_no/cred。approve 与 create 共用同一消息域（同一字符串，两把不同钥验）——当前角色单值（`_ROLES`）+服务端按账户公钥验签使其不可互换，属域卫生而非漏洞。附言为自由文本：审计员理论上可在 note 里写一套、令状 target 是另一套，批准人看到的是两者拼盘。
- **级别**：P2（当前不可利用——DB 行不可变+目标来自令状行；但绑定是"架构惯性"而非"签名承诺"，任何未来允许改令状 target 的功能都会静默击穿它）。
- **修复方向**：req_hash v2 纳入 `target_auth_id+case_no+req_id`（版本化前缀已留）；执行前把本地令状行与链上 scope hash（`SM3(FZ-SCOPE|auth_id|case_no)`，`audit/service.py:95-98` 已锚链）对拍一次，把传递绑定升级为密码学核对。

### B-P3 群（卫生，一句话各）

- **B-P3-8** 挑战 nonce 非原子消费：`login` 读-验-写间无行锁，同 (nonce,sig) 并发双登理论可得双会话（SQLite 写串行收窄窗口；http MITM 边界内才可取到对）。
- **B-P3-9** 用户名枚举：prelogin 404/200+mode 差异、register 409——演示可接受，口径卡声明即可。
- **B-P3-10** 过期 web_sessions/challenges 行不清理（challenge 有 10×TTL 顺手扫，`service.py:184-188`；会话无）——库缓慢膨胀。
- **B-P3-11** `execute_error` 直接落 `f"{type(exc).__name__}: {exc}"[:500]`（`collab.py:247`）——意外异常文本可能带内部细节进 admin UI；建议白名单化。
- **B-P3-12** `register_account` 并发同名撞 unique 约束→未处理 IntegrityError→500（有约束兜底无原子 upsert 话术）。
- **B-P3-13** `main.py:99` CORS allow-headers 残留 `X-Audit-Token`（无害，清了干净）；`audit/service.py:10`/`ra/collab.py:3` 头注仍描述令牌认证（文档卫生）。
- **B-P3-14** `auth.ts:98` 模块级 `pending` 注册材料（sk+密码明文）驻 JS 内存至流程完成/刷新——TCB 已声明语义内，登记完成即焚做得对（`finishRegistrationLocal` L162）。
- **B-P3-15** `/ra/register`、`/ra/sub-credentials` 仍无认证（上轮已记的"环回抑制但边界未显式声明"）——账户化后与"上链注册=资料补全、须 pilot 会话"（`router.py:173`）的叙事并存两条注册路，建议显式声明或封路。

### 旧修复抽查（本轮复核，均落地）

- `fzSessionSkUnlock` 已入单一事实源 `SESSION_CLEANUP_KEYS`（`material.ts:71-75`），logout/sweep 双路径调用 ✅（上轮 C-P1-1 根修到位——但见 B-P1-3 新缺口）。
- `FZ_WRAP_KEY` env 覆盖已改 per-label KDF（`kms/__init__.py:89-104`），域分离在强化档成立 ✅（上轮 C-P2-4 根修到位）。
- 迁移链单头：ee11ff22（merge 双头）→ b1c2d3e4 → c3d4e5f7(head)，`alembic heads` 单行 ✅。
- KDF"OWASP 2023 对齐值"话术仍在（`kdf.py:11`/`keystore.ts:15`）——上轮 C-P2-7 的"话术改诚实算术"建议未采纳，此处按既定边界不再展开，仅提示该句在被追问"对齐哪一行"时仍是雷。

---

## 四、架构层深问（按任务四问逐条作答）

1. **req_hash 绑定是否真的防挪用？**——防"改内容挪用"成立但有前提：请求行创建后 (wh,note,req_hash) 不可变，执行对象由 wh→令状行→target_auth_id→解析链传递确定，而签名恰恰不覆盖后三环（B-P2-7）。防"换令状/换凭证"=成立（换 wh 验签即败；凭证由令状行决定，不经手签名人）。真正的短板不在哈希而在**状态机**（B-P1-2）：内容绑定是密码学强制的，生命周期绑定是竞态的。
2. **批准签名能否被重放到另一请求？**——直接重放：不成立。另一请求需同 (wh,note)；同 wh 的新请求只能在旧请求非 pending 时新建（驳回后可重建，实测允许），但"已批准过"意味着令状已解锁→create 被 `already_unlocked` 拒——常规路径闭合。残余路径恰是 B-P1-2 的 A 例：**同一请求**上重放批准语义（非 pending 态 approve 根本不验签，何须重放签名）；以及 execute_failed 令状未解锁时，同 (wh,note) 新请求可复用旧批准签名——语义上仍是"批准同一件事"，无实质越权。结论：重放面当前无可利用物，但"非 pending 态免验签"把签名防线整个旁路了，修状态机时应一并堵上。
3. **后台执行线程的事务/并发语义？**——三个事实：①独立 `SessionLocal`（正确，HTTP 会话已随响应关闭）+ 兜底异常全落 execute_failed（`collab.py:228-257`，结构化做得好）；②进程级 `_executing` 去重**只防同时**，不防先后（C 例双执行）；③daemon 线程+无持久任务表——进程重启于 approved 态=任务丢失且无 resume 路径（retry 只认 execute_failed；唯一"恢复"是非 pending approve 免验签重触发，属意外的复活通道而非设计）。多进程部署下 _executing 失效=任意双执行。根修：执行状态进库（executing 列+租约时间戳），spawn 前条件 UPDATE 抢占。
4. **限速器内存形态在多进程部署下的失效？**——如 B-P2-6：每 worker 一套独立桶，限额×N；且与 _executing 同属"进程级状态当全局用"的同一族问题。这批代码有两处该族实例，建议一次收敛（共享存储或显式声明单进程档并加启动断言）。
5. **warrant 域与 collab 域的密码学衔接缺口？**——链上令状锚 `SM3(FZ-SCOPE|auth_id|case_no)` 承诺了目标与案号（`audit/service.py:95-106`），但 collab 执行全程不回查这个锚（本地行即真相）；req_hash 只签 (wh,note)；FZC2 的 AAD 只绑 wh 不绑双签/范围/时效（B-P2-4）。三段各自自洽，**衔接靠的是"本地 DB 行不可变"这一非密码学假设**。把链上 scope 对拍接进 `_execute`（一次 `warrant_on_chain` 同族的 view 调用）即可把三段焊成一条密码学链——这是本批最有性价比的一个补强。

---

## 五、一句话结论

**认证与密钥层（零口令材料+KDF 对拍锚+信封核对）是可答辩的扎实资产；但"双控=密码学事实"的宣称今天被一条残留路由和三个竞态实际推翻——先删 `/ra/warrant/unlock`、再给状态机加原子性、然后接回清扫锚，这三件做完，本批宣称才配得上它真正的密码学底子。**
