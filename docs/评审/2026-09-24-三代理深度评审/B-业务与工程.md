# 飞证 · 深度评审报告 B：业务逻辑严谨性 + 前后端/区块链实际应用性 + 工程合规成熟性

- 评审人：B（系统工程评审代理）
- 日期：2026-09-24
- 方式：只读深读全部关键路径源码 + 四合约逐方法审计 + 只读探针（GET /healthz、/chain/panel、/metrics、/engine/anchors）+ feizheng.db 只读查询 + backend pytest（218 passed, 6 deselected）。未发任何链上交易、未写任何业务数据。
- 代码基线：uas 仓 HEAD = 6811857（R2-c），即队长三修之后。

---

## ① 理解综述（≤300 字）

飞证以"实名承诺上链 + 一次性子凭证 + 本机 ZK 出证 + worker 验证 + 链上 recordAuth + 令牌取件 + ARM 联动固件围栏 + 遥测哈希链/检查点锚定 + TRAIL 合规证明 + 令状双控追溯"构建全生命周期。工程完成度真实存在：218 单测、四合约权限矩阵、R2 电路换代、S1 44 断言全真串联都有据可查。但本次评审找到两类队长三修的**同源未爆弹**：一是"电路内数学正确、应用层空转"——撤销集键空间与电路键错位，使"撤销即时"对 AUTH 的强制为空；二是"单测全绿、产品路径断裂"——X-Engine-Token 认证加入后 bridge 从不携带、启动器从不注入，检查点/事件上链在产品路径 100% 401，且两个判决脚本当前必红。另有一批一次性语义/配额/租约竞态/公示面漂移问题，逐条列下。

---

## ② 分级发现

判定标准：P0=宣称的核心安全/业务性质不成立或主路径不可用；P1=功能在真实使用中会坏或可被滥用；P2=语义失真/一致性/可运维性缺陷；P3=改进项。

---

### P0-1 撤销→AUTH 的"电路数学拒绝"是空转的：撤销集键空间与电路键错位，主凭证吊销后旧子凭证仍可走通全程

**证据链（每一环都已读源码核实）：**
1. 撤销写入的树叶 = 主凭证句柄：`backend/app/ra/service.py:259-264`——`revoke()` 只 `Revocation(handle_hex=cred.master_cred_hash_hex)`，树=`smt_root(handles)`；全仓无任何代码把 pk′.x 写入撤销集（grep `holder_pub` 仅存 SubCredential 表）。
2. 电路验证的键 = 出示公钥 x 坐标：`uas/zksvc/vendor/plonkish-7e0e1a7/plonkish/plonkish_sm2_probe/src/smt_weave.rs:1`（"键=子凭证出示公钥 x 坐标 pk′.x"）、`:8`（"键=证明者自己的出示公钥，E8 [sk′]G=pk′ 电路内绑定"）、`:183-184`（pkx_word_cell）。
3. 见证分发同键：`backend/app/ra/router.py:196-212`——`/ra/revocation/witness` 键=`holder_pk_hex[:64]`（pk′.x）。
4. 设计意图自认未接线：`backend/app/ra/smt.py:3-5`——"树键=…B3b 起=子凭证出示公钥 x 坐标 pk′.x——**主凭证吊销经 RA 撤销传播进树，B4 接线**"。该接线在 `ra/service.py` 中不存在。
5. 受理门控只比对根一致性：`backend/app/authz/service.py:197-200`——`rev_root_hex != chain_root` 即拒，只保证"你用的根是当前根"，不检查申请者是否在撤销集内；门控四步全链无任何撤销状态检查。

**为什么是 P0**：SM3 哈希句柄与 EC 坐标 x 是两个不相交的值域，"`pk′.x` ∉ {sm3(C) 句柄集合}"恒真——被电路 soundness 保护（R2 已封 SMT 门编织空洞，`docs/性能档案.md` R2 节）的这条语句，**在应用层是一个永真式**。后果：被吊销飞手在吊销前已签发、未消费的子凭证（配额上限 20 张、单张 24h 有效，`ra/service.py:32-33`）在有效期内仍可完整走通 出证→受理→recordAuth→ARM。这直接推翻 `docs/答辩口径卡.md` B4"被吊销见证负例数学拒绝；撤销即时链级"与 `contracts/src/IdentityRegistry.sol:5-6` 注释"被吊销者下一次申请即被 AUTH 电路数学拒绝"。撤销目前唯一真实生效点=签发期 `cred.status==2` 拒新签（`ra/service.py:201-202`），单测 `test_ra_service.py::test_negative_revoked` 也只测到这一层——**负例体系恰好在最关键的一环缺测**。

**修法（两选一，均不需要动证明系统）**：
- 方案 A（推荐）：`revoke()` 时遍历该主凭证全部未消费 `SubCredential.holder_pub_hex`，把 `pk.x` 一并入 SMT 叶集（与句柄并树），见证/根计算同源不变；工作量 0.5 天。
- 方案 B：电路键改为 `sm3(C)` 句柄（电路内已算出 C），RA 不用改——但需重出电路+重 pin，赛内不划算。
- 无论哪个方案，必须补端到端负例："吊销后旧子凭证 apply → 必拒"，进 check.sh。

---

### P0-2 X-Engine-Token 认证断链：bridge 永不携带该头、启动器从不注入 env，检查点/事件真链上链在产品路径 100% 被拒，且两个判决脚本当前必红

**证据链：**
1. backend 强制认证且 fail-closed 到"未配置即全拒"：`backend/app/telemetry/router.py:34-41`——`want = os.environ.get("FZ_ENGINE_TOKEN", "")`，`not want` 直接 401。
2. bridge 转发面不带认证头：`uas/gcs/bridge/server.py:158-176`——`_post_engine` 请求头仅 `Content-Type`；全仓 grep `X-Engine-Token` 只出现在 telemetry/router.py 与 pytest。
3. 启动器不注入：`uas/scripts/demo_up.py:163-179`（只 setdefault FZ_AUDIT_TOKEN/FZ_ENGINE_SK）、`backend/scripts/scenario_S1_fullchain.py:170-176`、`backend/scripts/sitl_e2e_services.py:129`（`env=os.environ.copy()`）——三处均无 FZ_ENGINE_TOKEN；评审现场 shell 实测 `FZ_ENGINE_TOKEN` 为空。
4. 时间线定谳：加入认证的 commit 3e8898a（2026-09-23 18:48）**晚于** S1 最后全绿（9e5893d）与前端 e2e 最后验证；其后无任何脚本/启动器适配。
5. 后果实证一（脚本必红）：`scenario_S1_fullchain.py:464`（3.1 检查点真链锚定断言 `r.get("ok") is True`）与 `:541`（5.1 recordEvent）、`e2e_frontend_api.py:255-256`（4.10 断言）在 HEAD 上经 bridge 路径必然收到 `ok=False anchor_failed`。
6. 后果实证二（产品数据面）：feizheng.db 只读查询 `checkpoint_anchors=0` 行（对照 warrants=3、chain_events=38）——持久库从未成功落一条检查点锚定。
7. 叠加放大：web 前端没有任何页面调用 `/telemetry/anchor`、`/telemetry/event`、`/telemetry/sitl_sample`（grep 全 src 零命中），所以队长手动测试根本走不到这一步——**这正是"单测 218 绿（test_chain_engine_anchor.py 自带 env+header）、真产品路径已断"的队长三修同型问题**。

**修法**：①`_post_engine` 增加 `X-Engine-Token` 头（env `FZ_ENGINE_TOKEN` 与 backend 同源）；②demo_up/sitl_e2e_services/S1 桥环境三处统一注入（"一处定义、同源注入"纪律，教训㊿+40 的翻版）；③backend 未配置 FZ_ENGINE_TOKEN 时启动即打印显眼告警（fail-closed 但要让人看见）；④重跑 e2e_frontend_api+S1 恢复判决行。工作量 0.5 天。

---

### P1-1 worker 租约(600s)==zkc verify 超时(600s)、无续租、无终态守卫：多 worker 档存在"approved 被翻案为 rejected、ready 回执被翻案为 failed"的竞态

**证据：**
- `backend/app/zk/worker.py:206-208`（`_lease_seconds=600`）与 `:74`（`subprocess.run(..., timeout=600)`）相等；`_claim_pending`（:225-250）认领后处理期间**无任何租约续期**。
- `:262-277` 异常重试路径对 `row.status` 无条件覆写；`:337-345`、`:389-400` 置 rejected/failed 前不复查该行是否已被他人置为 approved。`Receipt` 同理。
- 触发序：worker A 认领→verify 耗时逼近 600s→租约过期被 worker B 认领→A 先 recordAuth 成功、seal_receipt(ready)→B 的 recordAuth 撞 nonce 已烧→走 nonce_conflict 分支把**同一行**改成 rejected、回执改成 failed（B 的 SELECT 发生在认领时，无乐观锁/version 列）。飞手丢掉一个链上已登记、nonce 已烧的有效授权。
- 口径卡 F2 明确宣称"多 worker 水平扩展（双 worker 实弹）"——当前单 worker 演示不触发，但宣称的生产档在此参数下不安全。

**修法**：①终态不可逆守卫：所有终态写改 `UPDATE ... WHERE status='pending'` 并以 rowcount 裁决；②租约 ≥ 2×verify 超时，或处理线程心跳续租；③置 receipt.failed 前查现态。工作量 0.5 天。

---

### P1-2 子凭证配额永不释放 + 失败即永久烧配额：同一主凭证累计签发 20 张后被永久锁死

**证据：**
- `backend/app/ra/service.py:205-213`：配额计数=`consumed==False` 的行数，**无 expires_at 过滤**；而全仓没有任何代码把 `SubCredential.consumed` 置 True（grep 实证，`ra/models.py:67` 定义后成死列）。过期子凭证也永久占坑。
- 失败即烧：受理成功唯一性由 `applications.sub_cred_hash_hex` 唯一索引保证（feizheng.db 实证 `ux_applications_sub_cred_hash`；模型层未声明，来自 alembic 0005）——worker 判 rejected（证明无效/nonce 冲突）后**applications 行仍在**，同一张子凭证重新 apply 必 409 `sub_cred_used`。即每次验证失败永久消耗一张配额。worker 自己的拒绝话术"请换 nonce 重新出证"（worker.py:390-393）其实也换不回这张子凭证。
- 量化：配额 20 = 最多容忍 19 次失败；20 次签发后该用户终身 `quota_exceeded`（429）。演示库 55 张子凭证全部 consumed=0，验证了计数永不释放。

**修法**：①配额口径改为"未过期 ∧ 未消费"计数；②worker approved 时回写 `consumed=True`（rejected 不回写但 applications 唯一索引要放开封存行——或改为只对 approved 建唯一性）；③给"失败子凭证"一个重签豁免。工作量 0.5 天。

---

### P1-3 授权（authId）撤销无任何业务入口：紧急禁飞无法执行，遥测撤销门是死代码

**证据：**
- `contracts/src/FlightAuthRegistry.sol:72-79` `revokeAuth` 存在；全仓唯一调用=`backend/scripts/chain_smoke.py:429`（烟测）。`backend/app` 无消费（grep 实证）。
- 下游消费者因此全为死路：`backend/app/telemetry/service.py:186-187` 的 `auth_revoked` 拒绝分支永远不可达（status 恒 0）；审计追溯 `audit/router.py:120` 读到的 status 也恒 0。
- 结合 P0-1：对"已签发的飞行授权"而言，系统没有任何一条撤销路径（凭证明明可预留窗 6 小时）。以真实无人机监管视角，这是流程设计的实质缺口——监管"叫停某次飞行"在系统内不成立。

**修法**：engine 运维面（X-Engine-Token 域）加 `POST /engine/auths/{id}/revoke` → `revokeAuth`；同时把撤销事件纳入索引器/追溯时间线。工作量 0.5 天。

---

### P2-1 web 飞行屏围栏态硬编码 120m：检查点签名绑定的围栏态与 ARM 实际写入固件的围栏脱钩

`gcs/web/src/views/FlightView.vue:85`——`/telemetry/start` 传死值 `fence_state_hex:"01007800"`（0x0078=120m）；而 ARM 实际围栏=min(令牌 alt_max, 计划高度)（`gcs/bridge/sitl_link.py:349-369`），返回值 `armResult.fence_state_hex` 被前端丢弃。微型类（50m，政策 `policy.py:22`）飞行时，检查点/审计/设备交叉审计所依赖的"围栏态绑定"（`telemetry/checkpoint.py:14-17`、D16）记录的是假围栏。S1/e2e 脚本都正确透传（S1:379-380），**唯独产品 UI 路径失真**。修法：透传 `armResult.value.fence_state_hex`，1 小时。

### P2-2 授权窗结束时刻硬编码 t_epoch+3600：计划的 end_ts 承诺进 plan_hash 却不进令牌窗

`ApplyView.vue:234`——`t_end: (f.binding?.t_epoch ?? 0) + 3600`。飞手填写"今天 10:00-12:00"（默认窗 2 小时，`:69-72`），实际令牌窗=出证时刻起 1 小时；出证 ~2.5 分钟+排队后，用户若按计划"下午起飞"必撞 `window_expired`。计划时间在密码学上被承诺、在业务上被无视——"计划"语义=装饰。feizheng.db 佐证：#17（web 来）窗长 3600s，#10-13（脚本来）7200s。修法：`t_end = clamp(plan.end_ts, t_start+下限, t_start+FZ_MAX_TOKEN_WINDOW_S)`，前端与门控同一口径。2 小时。

### P2-3 政策公示对拍在首个申请时求值一次后终身冻结

`backend/app/authz/router.py:119-137`——`d.chain_policy_published = _policy_published(pr)` 是 **bool**，随 `_DEPS` 进程级缓存。后端启动晚于 publishPolicy/publishPolicy 换版 ⟹ 门控永远 409 `policy_unpublished`；反之先公示后篡改检测依赖重启。与同文件 `_chain_pin`（每次 apply 实时回读）行为不一致。修法：改为每次 apply 调用（函数引用而非求值结果）或 TTL 缓存。1-2 小时。

### P2-4 链不可达无熔断：WSL 僵死窗内每请求实付 10s 超时，登记/受理/吊销全链路慢挂

评审现场实测（WSL 链僵死中，R2-c commit 自述 HCS_E_CONNECTION_TIMEOUT）：`GET /chain/panel` 10s 后才返回（`chain/panel.py:58-97`，ChainClient timeout=10s，`client.py:36`）；真链档下 `/ra/register`、`/ra/revoke`、`/authz/apply`（门控③④链视图 `authz/router.py:54-72`）每个请求都要先撞 10s 超时再 500。无健康探针、无半开熔断、无 `chain_unavailable` 语义码；`_chain_bindings` 只缓存绑定不缓存健康。诚实失败值得肯定，但可用性面应当 fail-fast。修法：进程级链健康位（探测成功才放行链视图，失败快速返回结构化 code）。0.5 天。

### P2-5 "轨迹合规"实为"高度合规"：SITL 路径 lat/lon 恒 0，web 手动采样是随机数

`gcs/bridge/server.py:124`——SITL 真采样 `_chain.push(t_epoch, alt_cm, 0, 0)`，经纬度硬编码 0（`sitl_link.relative_alt_mm` 只读高度，`sitl_link.py:235-240`）；web 手动采样 alt=3000+randInt(6000)、lat/lon 线性伪造（`FlightView.vue:100-102`）。TRAIL 电路本身只约束高度范围+时间无隙（口径卡 B2），所以"轨迹合规证书"的对外名实不符；且 UI 把随机数采样呈现为"飞行记录"（未标注仿真），与 `sitl_sample` "不伪造遥测"的自我声明（server.py:111-112）双标。修法：接 GLOBAL_POSITION_INT 的 lat/lon（0.5 天）或口径收窄+UI 标注"演示仿真数据"（1 小时）。

### P2-6 "令状双控"实为同进程自调用：持审计令牌单人可自建令状并解锁实名

`backend/app/audit/router.py:185-198`——`_ra_unlock` 直接 import `ra.router._svc` 在**同一后端进程内**完成 unwrap+logWarrantUnlock；审计台解锁唯一认证因素=X-Audit-Token（`:214-221`），RA 操作员没有独立确认动作；`collab_code` 是可选项（`:279-298`，直接传 master_cred_hash 亦可）。配合 admin/auditor/RA 演示钥皆出自同一确定性派生（`kms/__init__.py:47-105`），单机演示里"双控"是叙事性的。口径卡 G 与 A7 已诚实声明"非密码学门限"，但文档口径（audit/service.py:1-8"流程双控"）偏强。修法：强制 collab_code（RA 签发物=第二因素），或 RA 侧增加待办确认面。0.5 天。

### P2-7 worker 恢复路径的跨重启盲区 + 0x16 一律误分类为瞬时

`worker.py:294-310` 的 `_recover_landed_auth` 只在**同一次异常处理后**执行；若进程在"交易已落地、回执未读"窗口崩溃，重启后无任何启动对账（无 pending×nonceUsed 扫描），recordAuth 必撞 revert 0x16，重试轴烧满 3 次后拒绝理由还是误导性的 `transient x3: 回执状态非成功: 0x16`（feizheng.db application #16 实证原文），且链上留下孤儿授权（nonce 已烧、token 无主、回执 failed）。同理，revert 类失败（subcred used/token exists）本质永久，却走瞬时重试烧满 3 次。修法：worker 启动时对 status=pending 的申请做 nonceUsed/tokenAuthIds 对账；按回执 status/错误串分类永久轴。0.5 天。

### P3（改进项）

1. **/metrics 标签基数无界**：`fz_requests_total{path="/authz/receipt/<码>"}` 按回执码逐个建标签（评审现场 /metrics 已见 3 个独立码路径，单个码被轮询 45 次）——长跑内存无界+抓取膨胀。应归一化 path 模板。
2. **ReceiptView 死标签**：`ReceiptView.vue:43` 判 `result.status==='pending'` 显示"ZK 验证队列中"，而回执状态域是 `waiting/ready/failed`（`authz/service.py:303-311`），分支永假。
3. **ChainView 显示空案号**：`ChainView.vue:108` 读 `w.case_no`，而 `/chain/panel` 有意不下发该字段（`chain/panel.py:117-119`）——前端契约漂移（与已修的 envelope 双形态同族）。
4. **并发重复申请=500**：并发同 sub_cred/nonce 双 apply，SELECT 查重双双通过后靠唯一索引兜底，后者 IntegrityError 未捕获 → 500（应转 409）。
5. **gcs_audit.db 相对路径**：`bridge/telemetry.py:68` 默认 `gcs_audit.db` 随进程 CWD 漂移（仓库根与 gcs/bridge 各可能生成一份），一次性令牌防重放状态可能被换文件绕过（TCB①范围内，但应绝对路径化）。
6. **bridge 进程实际持有 engine 私钥派生面**：`bridge/telemetry.py:30-35` 修掉了直接调用，但 demo_up `bridge_env=env.copy()`（`scripts/demo_up.py:181`）把 `FZ_ENGINE_SK` 注入 bridge 进程环境——"桥不持政策引擎私钥"的 TCB 表述被部署方式破坏。env 分发应按进程裁剪。
7. **重复登记不吊销旧主凭证**：同 username 再登记创建新 Credential，旧 master_cred_hash 在链上与 RA 库中仍 status=1（`ra/service.py:125-155`）——R2-c 只清了浏览器侧，密码学侧旧身份仍有效。
8. **bridge verify_token 文档漂移**：`bridge/telemetry.py:7-8` 宣称五查含"nonce 未用（本地状态）"，实现无此查（一次性仅靠 token_arms 表）。

---

## ③「空有其表」专项清单（宣称存在、实际只有脚本/烟测在消费）

| # | 功能面 | 宣称处 | 实际消费方 | 证据 | 定性 |
|---|---|---|---|---|---|
| 1 | PolicyRegistry.classRules/getClassRule（限高/资质链上公示） | 口径卡 G"政策与电路指纹：限高/资质规则公示" | **仅 chain_smoke** | `PolicyRegistry.sol:46-60`；backend/app 无 getClassRule 调用；且 `chain_smoke.py:347-349` 已把**生产合约** class 1 写成 requiredLevel=2，与本地政策 `(120,1)`（policy.py:23）及 paramsHash 公示值相悖——公示面与现实相反 | 摆设+已污染 |
| 2 | FlightAuthRegistry.revokeAuth（授权撤销） | 口径卡 G 角色表 Engine 职责列 | 仅烟测 | 见 P1-3 | 摆设 |
| 3 | TelemetryAnchor.verifyHead | 合约"可核验" | 仅烟测 | `TelemetryAnchor.sol:41-43`；app 层用 latest（audit/router.py:130） | 摆设 |
| 4 | burnNonce 独立写面 | 口径卡 C1"四链写面全真链接线" | worker.chain_burn_nonce 无产品调用点 | `worker.py:139-143` 自注"产品调用点=运维/演示位" | 诚实标注的半摆设 |
| 5 | /telemetry/anchor、/telemetry/event、/telemetry/sitl_sample、/prove/trail/start（检查点锚定/事件上链/真采样/TRAIL 出证） | demo_up 清单"遥测面→/telemetry/anchor 真链锚定" | 仅 S1/e2e_frontend_api/S4 脚本；web 前端零调用 | grep gcs/web/src 零命中；且当前经 bridge 全被 401（P0-2） | 脚本专属+当前断裂 |
| 6 | TrailView「生成合规报告」按钮 | 屏④"一键生成合规报告" | 只导出 trail_job.json 文本：checkpoints=[]、alt_max_cm/authId 手填可改 | `TrailView.vue:26-90`（无任何 /prove/trail/start 调用）；真 TRAIL 证明只存在于脚本档 | 按钮是装饰 |
| 7 | mTLS（gen_certs.py+nginx_fz.conf）与限流 | 口径卡 F3/F4"传输安全 mTLS/滥用防护" | 仅"9443 e2e mTLS 档"（需手动 `wsl nginx -c` 起 sidecar） | demo_up 直接 uvicorn 明文 8000/8100；红队 A6 的 429 判决行依赖该 sidecar | 生产档可验，产品路径未接 |
| 8 | /engine/anchors GET | "fake 锚记录查询" | 真链模式恒返回空 | `telemetry/router.py:118-122`；现场实测 `{"records":[],"events":[]}`（mode=real） | 误导面 |
| 9 | checkpoint_anchors 表（SN v2 设备交叉审计数据面） | 数据分级文档"平台库投影" | 0 行（见 P0-2） | feizheng.db 实证 | 断供 |

对照：**真实被业务消费的链面**（给公正结论）——IdentityRegistry 的 registerCommitment/setStatus/setRevocationRoot/warrants/warrantUnlocks（ra/router.py:88-116、audit/router.py:98-101、service.py:87/112/114）、FlightAuthRegistry 的 recordAuth/nonceUsed/usedSubCreds/getAuth/authCount/tokenAuthIds（worker.py:87/117-136/285-310、authz/router.py:54-57/135）、TelemetryAnchor 的 anchorCheckpoint/recordEvent/latest（telemetry/service.py:122-145）。四合约不存在无主写面，EventRecorded 亦真有消费（indexer.py 全量块扫描投影，feizheng.db chain_events=38 行）——这一点值得肯定。

---

## ④ 赛内可落地的务实路线图（按性价比排序）

| 优先 | 事项 | 工作量 | 对应发现 |
|---|---|---|---|
| 1 | 修 P0-2：bridge 带 X-Engine-Token + 三启动器同源注入 + 启动告警；重跑 e2e_frontend_api 与 S1 恢复"判决行仍全绿"的事实 | 0.5 天 | P0-2 |
| 2 | 修 P0-1：revoke() 把未消费子凭证 pk.x 并入撤销树 + "吊销后旧子凭证必拒"端到端负例入 check.sh（答辩口径 B4 从此真正成立） | 0.5-1 天 | P0-1 |
| 3 | worker 终态守卫+租约>2×verify 超时（三条 WHERE 守卫+一个参数） | 0.5 天 | P1-1 |
| 4 | 配额口径修复（consumed 回写+过期过滤） | 0.5 天 | P1-2 |
| 5 | FlightView 围栏态透传 + t_end 用计划 end_ts（clamp 到政策窗） | 3 小时 | P2-1/P2-2 |
| 6 | engine 撤销授权端点（紧急禁飞闭环） | 0.5 天 | P1-3 |
| 7 | `_policy_published` 改 per-apply；链不可达熔断+chain_unavailable 语义码 | 0.5 天 | P2-3/P2-4 |
| 8 | 口径收敛批：TRAIL=高度合规、双控=RA 协作函强制、TrailView 按钮接真出证或改名"导出证明材料" | 0.5 天 | P2-5/P2-6/#6 |
| 9 | P3 清理批（metrics 模板化、409 化、死标签、绝对路径、env 裁剪） | 0.5 天 | P3 |

前 4 项合计约 2-2.5 天即可把"宣称-实现"偏差的全部 P0/P1 清零；其余为答辩前可选加固。

---

## ⑤ 亮点（≤100 字）

透明 SNARK 本机出证、链上 proofDigest 令第三方复验作弊可检出；authId 预分配与 R2-c 恢复序体现了稀缺的"把生产事故写回产品"的工程习惯；诚实边界文档（TCB 分层、判决行可复现纪律）在同类竞赛作品中属第一梯队。
