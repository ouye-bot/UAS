# 飞证系统 · B 席独立评审报告（2026-09-26）

**评审方式**：只读。静态精读 backend/app 全模块、alembic 0001–0009、bridge 全模块、web 全部 views/lib、四合约、判决脚本族与启动器；只读 GET 探针（8000/8100/5174/8545）+ SQLite 只读查询（feizheng.db、gcs/bridge/gcs_audit.db）。未修改任何文件、未运行测试/构建、未触碰在线服务。

---

## ① 理解综述（≤300 字）

飞证以"实名承诺上链→一次性子凭证→本机 ZK 出证→七步门控受理→worker 验证+链上 recordAuth→一次性令牌 ARM 联动固件围栏→遥测哈希链/检查点锚定→TRAIL 证书→令状+协作函双控解锁实名"构成全生命周期。上一轮三代理评审的 R3-0/R3-1/R3-2/R3-3.1/R3-4 及 09-25/26 新批（撤销传播、位序统一、engine-token 同源注入、worker 终态守卫/租约、配额 consumed 口径、政策 per-apply、collab_code 强制、信封 v3、引擎钥源代理、身份清扫、机型只读、verdict mask 自述、WSLInterop 自愈、2D 可视化）**经逐项抽查基本真实落地且质量合格**（feizheng.db 实证：checkpoint_anchors 0→32 行、sub_credentials consumed=1×35、申请窗已取计划 end_ts）。但本轮仍找到两个 P1：R3-1.3 修复自身引入的**政策公示门控死码**、RA 面链不可达兜底路径自身崩溃；另有迁移链双头、撤销验证深度不足等 12 项。评审时点全栈实测下线（探针全拒绝），见 P2-8。

---

## ② 发现清单

判定标准：P1=安全/业务门控失效或宣称的核心防线名存实亡；P2=真实使用中会坏/可被滥用/可运维性断裂；P3=改进项。

### P1-1 政策公示对拍门控已成死码：`is False` 比对可调用对象永假——上轮 P2-3 的修复引入回归，fail-closed 防线静默失效
- **证据**：`backend/app/authz/service.py:184`——`if deps.chain_policy_published is False:`（按 bool 比对）；而 `backend/app/authz/router.py:139`——`d.chain_policy_published = lambda: _policy_published(pr)`（R3-1.3 改 per-apply 时把属性从 bool 换成了 **lambda**）。`lambda is False` 恒为 False ⟹ `policy_unpublished` 409 **永远不会触发**，`_policy_published` 全链无任何调用点。类型注解仍是 `bool | None`（service.py:49）。
- **佐证**：`backend/tests/test_policy_source.py:8-16` 只测纯函数 `chain_policy_published()`，门控级测试注入的是 bool 形态——单测全绿、产品路径死码，正是该团队自己总结的"测试替身语义漂移"家族第 N 次重现。`docs/红队攻击记录.md:27-29` 仍宣称"政策 paramsHash 未公示/被变更 → 受理 409 policy_unpublished"——该防御证据在当前 HEAD 已不成立（红队实测在 R3-1.3 改动之前）。
- **影响**：本地政策表（CLASS_RULES/POLICY_VERSION）被单方变更而未重新 publishPolicy 时，受理照常通过——"政策链源对拍 fail-closed"（答辩卡 C 区/阶段四修复）宣称落空。
- **修法**：gate 归一化——`pol = deps.chain_policy_published; res = pol() if callable(pol) else pol; if res is False: raise`；补一条"注入 callable 返回 False"的门控级测试。**工作量 0.5h**。[静态分析]

### P1-2 RA 面"链不可达"兜底自身崩溃：RaError 不接受第三参数，503 语义码路径抛 TypeError 变 500
- **证据**：`backend/app/ra/service.py:40-41`——`class RaError.__init__(self, code, message="")` 仅两参；`backend/app/ra/router.py:186` 与 `:255`——`return _deny(RaError("chain_unavailable", str(e), 503))` 传了三个位置参数 ⟹ 链不可达时 register/revoke 处理器自身 TypeError ⟹ FastAPI 500。且 `_ERR_STATUS`（ra/router.py:148-156）无 `chain_unavailable` 键，即便修掉参数也会落 400。对照组：authz/router.py:207 用 `AuthzError(..., 503)`（AuthzError 有 status 参数，service.py:30）是正确的。
- **影响**：R3-1.4 熔断（chain/client.py:62-76）在 authz 面给了结构化 503，但登记/吊销面（链写面的另一半）在链僵死窗内是裸 500——"chain_unavailable 语义码"宣称对 RA 面不成立，运维排障拿到的是无语义错误。
- **修法**：RaError 增加 `status=400` 参数、`_deny` 消费之；两处调用同步。**工作量 0.5h**。[静态分析]

### P2-3 alembic 迁移链分叉双头：全新环境 `alembic upgrade head` 必报 Multiple heads，生产档部署流程断裂
- **证据**：`backend/alembic/versions/`——`a1b2c3d4_0007_chain_events.py` 与 `c3d4e5f6_0008_sn_device_audit.py` 的 `down_revision` **都是** `f7a8b9c0`（0006）；此后 0009 挂在 0008 下 ⟹ 双头（a1b2c3d4 与 b7c8d9e0）。live 库实证：feizheng.db `alembic_version` 表 **2 行** `[('b7c8d9e0',), ('a1b2c3d4',)]` [实测探针]——只有靠 `upgrade heads`/手工盖章才可能到达此态。
- **影响**：新环境（含 PG 生产档）按文档惯例执行 `upgrade head` 直接报错；"持久库升级必须在服务启动前"（MEMORY R2-deploy）纪律在干净机上不可执行；两环境表结构可能悄然分叉。
- **修法**：补一个 `alembic merge -m "merge 0007/0008"` 空迁移统一头；部署文档显式 `upgrade heads`。**工作量 1h**。[静态分析+实测探针]

### P2-4 撤销传播的端到端负例缺失 + live 撤销路径零实操：R3-0 承诺的"吊销后旧子凭证必拒入 check.sh"未交付
- **证据**：撤销传播单测在（test_ra_service.py:228-245、witness fail-fast :247+；位序统一红线测试 `smt_host_circuit_root_parity_nondefault_tree`、vendor d098f23 `smt_weave.rs:176-186` LSB-at-leaf 已核）；但 `scenario_S1_fullchain.py`/`e2e_auth_full.py`/`e2e_frontend_api.py` 全文 **grep 零 revoke 步骤**；live feizheng.db `revocations=0`、credentials 101 条全部 status=1 [实测探针]——全系统从未对真实数据执行过一次吊销。
- **影响**：系统第一安全宣称"撤销即时、电路数学拒绝"（答辩卡 B4）的验证深度=单测层；「被吊销者缓存旧见证→stale_rev_root 拒、重取→witness 403 拒、硬闯→root.fold 死」的分层防线未被任何端到端负例串起来验证过。
- **修法**：e2e 增一段：签发子凭证→revoke→旧子凭证 apply（witness 403 / stale root 409 双形态断言）→入 check.sh。**工作量 0.5 天**。[静态分析+实测探针]

### P2-5 吊销对象粒度=单凭证而非人 + pk′.x 键域跨凭证传染：重复登记场景下"该吊销的吊不净、不该伤的会误伤"
- **证据**：①`ra/service.py:269-287` revoke 只并入**该凭证**未消费子凭证的 pk′.x，无"按 username 撤销全部凭证"入口；②pk′=浏览器长期身份钥（material.ts:5 `storedPk`，恢复码找回=同一 sk 回庭，keystore.ts 生命周期⑥），若用户以恢复码恢复旧钥后重新登记（新凭证 B 绑同一 pk′），之后凭证 A 被吊销 ⟹ pk′.x 入撤销集 ⟹ **凭证 B 的子凭证数学不可证**——诚实用户被误伤且签发面不拦（`issue_sub_credential` ra/service.py:178-250 不查撤销集，签发成功、出证必败）；③反面：违规者重新登记即获全新有效凭证（上轮已知 P3"重复登记不吊销旧主凭证"仍开放，register ra/service.py:125-155 无旧凭证处理）。
- **影响**：撤销语义在"人-凭证-钥匙"三层上不对称：追责可逃逸（按凭证吊销）、无辜可误伤（按钥匙封堵），两者同根。
- **修法**：短期——issue_sub_credential 预检 `holder pk′ ∈ 撤销集` 时人话拒绝；revoke 支持 `by_username` 级联撤销该 user 全部凭证；中期=撤销键改 SM3(C) 句柄入电路（赛后）。**工作量 0.5–1 天**。[静态分析]

### P2-6 worker `auth_id_mismatch` 过严：多 worker 并发下把链上已登记的自洽授权整单销毁
- **证据**：`backend/app/zk/worker.py:425-498`——令牌 body 用**预测** authId 铸造（`th=hash(body)`），链上 recordAuth 登记的恰是这个 th；recordAuth 成功后 `auth_id != predicted` 即 `_set_terminal(rejected)`+receipt failed。但 token body/链上 tokenHash/闸门键 `tokenAuthIds[th]` 三者**本自洽**（闸门按 tokenHash 回读，不依赖预测值）——预测错位只是说明并发窗内有另一笔授权落地。
- **影响**：F2"多 worker 水平扩展"宣称下，两个 worker 并发排水时后来者必被 fail-closed 拒绝：nonce 已烧、子凭证 consumed、回执 failed——一次并发即烧掉一张合法授权。安全上过严，业务上即拒绝率放大。
- **修法**：mismatch 分支先查 `tokenAuthIds(th)` 命中即按实际 authId 继续（AuthRecord/verdict 用实际值），仅链无记录才拒。**工作量 2h**。[静态分析]

### P2-7 FlightView 自动驾驶定时器不随页面卸载停止：离开飞行屏后飞机仍被持续指令爬升
- **证据**：`gcs/web/src/views/FlightView.vue:371-374` onBeforeUnmount 只清 `sampleTimer/tick`，`autoPilot`（:352-359 `setInterval` 每 450ms 发 `/sitl/climb` 油门指令）不清理；`window.addEventListener("resize", 匿名)`（:367）同样未移除。用户在 autoFlying 中切屏（如去屏④出 TRAIL 证书）后，bang-bang 控制循环在后台继续驱动飞控。
- **影响**：演示中"去下一屏"是标准动线；后台隐形油门指令与"结束飞行并封链"可同时生效（disarm 后 climb 仍发），观感与安全叙事都差。
- **修法**：onBeforeUnmount 调 `stopAuto()`；resize 改具名函数并 removeEventListener。**工作量 0.5h**。[静态分析]

### P2-8 演示栈可用性仍系于人工保活：评审时点三服务+链全部下线（已知项，落地实用性核心风险）
- **证据**：[实测探针 2026-09-26] `8000/8100/5174` 全部 `WinError 10061 拒绝连接`；WSL 8545 无响应、`ps` 无 fisco-bcos/uvicorn 进程。与 MEMORY ㊿+67"会话托管的后台任务树会被中断连带清杀"及"WSL 保活会话必须常挂"一致。生产部署文档（docs/生产部署与安全演进.md 一·补）宣称 systemd 蓝本就位，但仅覆盖 SITL（scripts/sitl_units_up.sh），backend/bridge/web/worker 无守护蓝本；demo_up preclean（scripts/demo_up.py:105-110）还会 pkill WSL 侧 uvicorn——由 demo_up 拉起的 Windows 桥是 FakeLink（不设 `FZ_GCS_LINK`），而 CHECKLIST（demo_up.py:44-47）承诺"自动真采样 2Hz/固件围栏红条"，真 SITL 体验需另行在 WSL 手工起桥——**启动器能力与测试清单承诺不对齐**。
- **影响**：评委/队长任意时刻走进来可能是全黑或半残栈；"产品路径"与"脚本路径"的桥拓扑漂移是历史头号事故源（团队自己的定性）。
- **修法**：backend/worker/bridge/web 补 systemd/NSSM 守护单元或 `demo_up --daemon`；CHECKLIST 按 FZ_GCS_LINK 实际档位动态打印。**工作量 1 天**。[实测探针]（**已知项**——服务器窗/队长窗挂账相关，但本条是本机演示栈的独立缺口）

### P3-9 TrailView"导出出证任务 JSON"与真出证契约断裂：按导出文件跑 zkc 必被 fail-closed 拒
- **证据**：`gcs/web/src/views/TrailView.vue:48-84` buildSpec——行内 t=绝对 epoch 秒（`be(r.t,4)`）、`t_start=rows[0].t`、`chain_head=fzTrailHead`（遥测链头，>Iiii 口径）；权威契约=桥 `_trail_window_rows`（gcs/bridge/prover.py:337-357）行 t=**相对 500ms 网格**、链头=对行字节重放、装配器 fail-closed 对账（assemble.rs:207）。两口径必不一致 ⟹ 导出的 trail_job.json 直接 `zkc prove` 死于"换链头"。按钮 title"供命令行/第三方复验"交付的是不可执行产物。
- **修法**：导出改为从桥拉取 `/trail/start` 同源的 rows_hex/win_head（或后端加只读预览端点）。**工作量 1–2h**。[静态分析]

### P3-10 /metrics 标签基数无界未修（已知项，确认仍开放）
- **证据**：`backend/app/main.py:45-46`——`inc("fz_requests_total", {"path": request.url.path, ...})` 原样路径（含 `/authz/receipt/<码>`），上轮 B-P3-1 已列，未修。**工作量 1h**（路径模板归一化）。[静态分析]

### P3-11 gcs_audit.db 三份拷贝实证路径漂移：一次性令牌审计态随 CWD 分叉（已知项加深）
- **证据**：[实测探针] `gcs/bridge/gcs_audit.db`=70 arms/25 denials（真身），`backend/gcs_audit.db` 与 `gcs/web/src/gcs_audit.db` 均为空壳——相对路径缺省（gcs/bridge/telemetry.py:93）已实际造成三份文件。防重放 `token_arms` 主键态若落到空壳文件=同令牌可再次 ARM（TCB① 域内，但零成本可绝）。**修法**：缺省改 `Path(__file__).parent / "gcs_audit.db"`，删除两份迷路库。**工作量 0.5h**。[实测探针]

### P3-12 fence.py 模块头令牌语义过时（文档漂移）
- **证据**：`gcs/bridge/fence.py:8-9`"令牌=时间窗授权（窗内可多次起飞语义），本记录=审计行非消费销毁"vs 同文件实现已是方案 A 一次性（sitl_link.py:368-374 token_used 拒）；`fence.py:5`"nonce 未用（本地状态）"宣称实现无此查（verify_token 五查无 nonce 消费项）。答辩逐行读码时是把柄。**工作量 0.5h**。[静态分析]

### P3-13 "紧急禁飞"语义=证据断供而非飞行终止：已签发未 ARM 的令牌在 revokeAuth 后仍可解锁
- **证据**：`telemetry/router.py:131-169` revokeAuth 落链后，遥测面 auth_revoked 生效（telemetry/service.py:186-187，死亡分支已激活——R3-1.5 属实）；但桥 `FlightGate.attempt_arm`（sitl_link.py:350-394）只验签名/窗/计划/一次性，**不查链上授权状态**（离线闸门=设计选择），故"叫停某次飞行"对"尚未 ARM 的令牌"无效，对"已 ARM 在飞"也只是断锚定取证。telemetry/router.py:133-135 docstring 诚实描述了前者，但答辩口径"紧急禁飞闭环"宜主动收窄为"监管叫停=审计断供+围栏参数已随令牌冻结"。**修法**：口径收窄（文档 0.5h）或 ARM 面加可选链上 status 预检（在线档 2h）。[静态分析]

### P3-14 文档卫生批：smt.py 双处残留 64 深度口径 + up.sh 结构杂音
- **证据**：`backend/app/ra/smt.py:85-89` non_membership_witness docstring"64×32B hex / [64×0/1] / d=64（叶层）"vs `DEPTH=32`（上轮 A-P3-1 承诺 P0-1 修复时顺带清理，仍未清）；`scripts/up.sh:32-35`"B0 段完成"输出位于 [3/3] 段之前、编号 [1/2][2/2][3/3] 不一致、自愈 FAIL 不影响退出码。**工作量 0.5h**。[静态分析]

---

## ③ 「实际应用性」核验矩阵

| 宣称 | 实测/静态通路 | 判定 |
|---|---|---|
| S1 全生命周期全真串联 45 断言 | 判决行 2026-09-25 复跑在案（MEMORY）；脚本静态审查无假拍面；**评审时点栈未运行，未复测** | 真（历史实测；今日未回归） |
| AUTH 出证→受理→recordAuth→ARM | 代码链路逐环贯通；live DB 申请 #51-53 于 09-25 approved [探针] | **真** |
| 撤销即时进电路（B4） | 机制真（R3-0.1 位序统一+R3-0.3 传播+parity 红线测试）；e2e 负例缺、live 撤销 0 次（P2-4） | 机制真/验证浅 |
| 政策公示对拍 fail-closed | 门控死码（P1-1），红队记录 §二 证据失效 | **名存实亡** |
| TRAIL 证书第三方可复验 | 桥 /trail/start→真出证→证书卡+三件套下载+复验命令（TrailView.vue:123-227）；导出 JSON 附带断裂（P3-9） | **真**（主通路） |
| 检查点锚定上链产品路径 | engine-token 三处同源注入（demo_up:161/fence→server:181-183/main.py:29-37 告警）+ checkpoint_anchors **0→32 行** [探针] | **真（已修复实证）** |
| 令牌一次一用+固件围栏 | attempt_arm token_used+围栏先写后 ARM+fence_state 透传+围栏红条；TCB① 边界诚实 | **真** |
| 令状双控+SN 交叉审计 | collab_code 强制（audit/router.py:284-299）+信封 v3 版本字节（ra/service.py:141,317 实为 \x01）+device_check 第四态；live 8 令状/5 解锁 [探针] | **真**（demo 钥可推算边界已声明=已知项） |
| mTLS/限流 | gen_certs.py+nginx_fz.conf 在库，e2e mTLS 档历史实测；当前产品路径明文、sidecar 未挂 | 演示档可验/产品未接（已知项） |
| PG/多 worker/备份/metrics | 代码+迁移在；迁移链双头（P2-3）；多 worker authId 竞态烧授权（P2-6）；metrics 标签无界（P3-10） | 部分可用 |
| 今日新改：引擎钥源代理 | demo_up:172-178 桥裁钥+FZ_ENGINE_PUB_PROXY=1→fence.py:30-60 三级钥源→server.py:308-323 代理 /authz/engine/pub——逻辑闭环正确 | 静态正确（未回归实测） |
| 今日新改：身份清扫+机型只读 | App.vue:25 载入锚定+material.ts:57-90 十一键清扫+ApplyView.vue:491 readonly——静态正确；清扫不含 fzForm/fzCred 属刻意（身份本体） | 静态正确（未回归实测） |
| 今日新改：WSLInterop 自愈 | up.sh [3/3] 探针用真实子命令（cmd.exe /c echo）符合教训㊿+77 | 正确（段落位置/编号瑕疵） |
| 09-25：verdict mask 自述 | prove.rs:123,376-379,541 与 vendor 消费方"存在即关"同式+测试钉定（:1013-1020） | **真** |

---

## ④ 落地实用性优化规划

| 优先 | 动作 | 价值 | 工作量 | 验收 |
|---|---|---|---|---|
| 1 | 修 P1-1 门控死码+callable 门控级测试 | 恢复 fail-closed 宣称；防答辩现场被"改政策表"击穿 | 0.5h | 注入 callable→False 的测试红转绿；篡改 CLASS_RULES 后 apply 得 409 policy_unpublished |
| 2 | 修 P1-2 RaError 503 | 链僵死窗登记/吊销面结构化降级 | 0.5h | 停链后 /ra/register 得 {code:chain_unavailable} 503 |
| 3 | alembic merge 统一双头 | 干净机/PG 生产档部署可执行 | 1h | 新库 `alembic upgrade head` 单命令建至 b7c8d9e0 |
| 4 | 撤销端到端负例入 check.sh（P2-4） | 答辩 B4 宣称从"机制真"升"验证真" | 0.5 天 | e2e 新增 3 断言：旧子凭证 apply 403/stale 409/二次签发 403 |
| 5 | worker mismatch 放行（P2-6）+autopilot 清理（P2-7） | 多 worker 拒绝率↓；消演示事故点 | 3h | 双 worker 并发 4 申请全 approved；切屏后无 climb 指令 |
| 6 | 签发面撤销预检+按人级联吊销（P2-5） | 撤销语义"人-凭证-钥匙"自洽 | 0.5–1 天 | 被吊销者再签发被人话拒绝；级联撤销后全凭证不可出证 |
| 7 | 三服务守护化+CHECKLIST 按档打印（P2-8） | 评委任意时刻走进来栈是活的 | 1 天 | 重启宿主后 demo_up/up 一键回到全绿；fake 档清单不出现 SITL 字样 |
| 8 | P3 批：TrailView 导出契约/审计库绝对路径/fence 头口径/紧急禁飞口径/smt+up.sh 文档 | 复验叙事闭环+读码无把柄 | 1 天 | 导出 JSON 可直接跑通 zkc prove；仓内仅一份 gcs_audit.db |

---

## ⑤ 亮点（≤1 句）

判决行可复现、负例一等公民与"把生产事故写回产品"的闭环习惯（engine-token 断链三天内根治并使 checkpoint_anchors 从 0 行到 32 行实证）在这类竞赛系统中属第一梯队的工程真实度。
