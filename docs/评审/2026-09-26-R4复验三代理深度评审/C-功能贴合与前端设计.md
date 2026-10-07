# C 席独立评审报告（2026-09-26 · R4 复验轮）

## ① 理解综述

本系统「飞证」前端七屏+审计台在 R3-2/批B/C 整改后已发生质变：上轮 P0/P1 绝大多数落地为真管线——TrailView 真出证+证书卡、FlightView 链路徽标/2Hz 自动真采样/ARMED 横幅/围栏红条/封链、ApplyView 六段标签+轮询容错+政策上限联动、RecordView 撤销自查、恢复码入口、身份清扫双保险。当前的主要矛盾已从「宣称与屏幕断链」转移到**新代码自身的收口质量**：今日上山的 TrailView 导出件与真出证数据面不同源、ApplyView 半程恢复成功后 UI 卡死、FlightView 对桥接 200+ok:false 拒绝静默吞掉——三类都是「差最后一米」的缺陷，恰好在演示动线上。另有一批上轮修复声称完成但实地核验未通过项（口令红盒、回执码双份、对比度、字重），逐条列证。

*探针备注：评审时对 127.0.0.1:5174/8000/8100 发只读 GET，三个端口均连接被拒（curl exit 7，HTTP 000）——无法区分是队长重启中还是沙箱网络限制，不做运行时断言；本报告全部结论基于源码静态精读，标注 [静态分析]。*

---

## ② 发现清单

### P0（演示翻车 / 宣称断链）

**P0-1 「导出出证任务（JSON）」是一件 zkc 必拒的假 spec，且「第三方复验」命令引用不可得的文件**
- 证据 [静态分析]：`gcs/web/src/views/TrailView.vue:92-104` exportSpec 自组 rows：t 用 **unix 秒** BE4（:62 `be(r.t, 4)`）、chain_head 取 `fzTrailHead`（:76，即 fence.py:23-25 锚链头）。而真出证管线 `gcs/bridge/prover.py:401-436` `/trail/start` **只读 body.alt_max_cm**，rows 由 `prover.py:312-339` `_trail_window_rows` 从桥内 `_chain.samples[:128]`（:418）重打——14B `>IHii`、**段相对 500ms 网格**、链头=GENESIS 重放。fence.py:3-9 注释明写「两条链各自闭环勿混用」。即：导出文件与证书数据面是两套口径，拿去 `zkc prove` 必被装配器 fail-closed 拒绝（链头对不上）。其次，证书卡展示的复验命令 `zkc verify-instances … --expected expected.json`（TrailView.vue:225）中 expected.json 在桥接 `/case/{id}/{artifact}` 白名单（prover.py:455）中不存在（bridge 案卷只落四件，prover.py:388），instances.json 服务端支持却没给下载按钮（:220-222 只有三件）。对外文档宣称「任何第三方可独立复验」（uas/01_设计文档/2026-09-23-作品说明文档.md:28）——评委照 UI 操作即当场失败。同屏附带：`TrailView.vue:176` 「授权编号」是可编辑输入框，但 `/trail/start` 用 `_chain.auth_id`（prover.py:435）根本不消费它——装饰件即占位，触碰「占位即缺陷」红线。
- 改法：① 导出按钮改为导出**真案卷**：done 后把 `instances.json` 加进下载按钮组（服务端已支持，prover.py:455，一行），原 JSON 导出改名「留痕存档（本机格式，非出证输入）」或直接删除 `exportSpec/buildSpec/twoComplement`（约 60 行死代码，TrailView.vue:48-104）；② 复验命令改为与实际可得文件一致（或由 verdict+锚定头现场生成 expected 展示）；③ 授权编号改只读回显（值来自飞行屏 fzTrailAuthId）。工作量 3~4h。预期收益：宣称-屏幕-可操作三层闭合，堵住最可能的现场翻车点。

### P1（高概率踩坑 / 明显失分）

**P1-1 出证中途切页再回来：恢复成功后 UI 永远停在「处理中…」+ 恢复提示条不消失**
- 证据 [静态分析]：`gcs/web/src/views/ApplyView.vue:399-410` onMounted 恢复流程时 `busy=true; resumeRun(f)`；`resumeRun`（:298-319）的 assembling/proving/applying 三个成功分支**从不复位 busy/resuming**（receipt 分支只复位 resuming 不复位 busy）。成功走完 `setStage("ready")` 后：提交按钮仍显示「处理中…」且 disabled（:495-497），顶部恢复条 `v-if="resuming && busy"`（:441）长驻——用户无法再次发起申请，只能刷新。这是 2 分钟出证+切页的常见动线。
- 改法：resumeRun 包 `finally { busy.value = false; resuming.value = false; }`。工作量 10 分钟。

**P1-2 未解锁时点「开始记录」零反应：桥接 200+ok:false 拒绝被当成功吞掉**
- 证据 [静态分析]：`gcs/bridge/server.py:79-82,88-91` 未 ARM 时 `/telemetry/start` 返回 **HTTP 200** `{ok:false,code:"not_armed",…}`；`gcs/web/src/views/FlightView.vue:141-155` 不检查 `r.ok`，直接把该拒绝对象赋给 `chain.value` 并把 `genesis_head_hex`（undefined）写进 localStorage（:152-153）——界面无任何错误（DenyBox 空），只出现一块空 kv。同族：`pushSample`（:172-188）也不检查 `r.ok` 就 `recordSample`（自动采样路径 ：167 反而检查了 `if (r?.ok)`）。
- 改法：两处补 `if (r && r.ok === false) { denyLog.value = { code: r.code, message: 人话(r.code) }; return; }`（not_armed → 「请先解锁起飞——没有授权就不会开启飞行记录」）。工作量 1h。

**P1-3 「任意设备领取飞行令牌」是兑现不了的承诺：会话私钥永远不出原浏览器**
- 证据 [静态分析]：ApplyView.vue:510「凭此码可在任意设备查询进度并**领取飞行令牌**」、ReceiptView.vue:28-30「支持换设备操作」；但令牌是 ECIES 加密给一次性会话钥（ApplyView.vue:361 `sessionStorage.setItem("fzSessionSk", …)`），该钥不展示、不可导出、刷新即失（FlightView.vue:21-23 只从本机存储回填）。异机取件 100% 落入 `decrypt_failed` 红盒。文案-机制断链是上轮 P0 同族问题在新文案上复发。
- 改法（最小）：文案改为「换设备可查询进度；取件请在发起申请的这台设备上完成」，并把异机 decrypt_failed 的人话提示补上；跨设备真取件（取件信封导出/导入）留作路线图，不为此加班。工作量 20 分钟。

**P1-4 队长的手动测试清单与现 UI 完全脱节（全文档级过时）**
- 证据 [静态分析]：`uas/docs/前端手动测试清单.md:14` 「注册承诺」按钮（现 UI 登记在入口页三步向导，RecordView 无注册）；:22 「证明模式演示占位」「提交匿名申请」（现 ApplyView.vue:497 为「提交申请（本机出证）」，占位模式已删）；:35 「取件解密+验签→not_ready 拒绝」被写成**预期结果**，而现在真管线可 ready 取件——照单测试会误报一堆「缺陷」或漏测新功能（恢复码/封链/撤销自查/TRAIL 出证全部不在清单里）。
- 改法：按现 UI 重写清单（含 SITL 档：登记→解锁口令→申请→领取→ARM→自动采样→封链→TRAIL 出证→负例五连：篡改令牌/重放 ARM/超限/随机回执码/撤销自查）。工作量 1h。优先级高的原因：这是队长此刻正在依赖的文档。

**P1-5 政策超限被映射成错误文案「作业高度须为 1..500 米」——把对的拦截配了错的解释**
- 证据 [静态分析]：ApplyView.vue:329-332 超政策上限时 `planErr.value = "alt_range"`，而 PLAN_ERR_TEXT.alt_range=「作业高度须为 1..500 米」（:28）。政策上限 120m 时填 150 → 提示「须为 1..500 米」，与 120 的真实原因矛盾（绑定面返回的 alt_max 就在手上，:358）。附带：policyAltMax 只在**提交后**才显示（binding 在 apply() 内调用），「政策实时公示」晚了一步。
- 改法：新增错误码 `policy_alt`（文案「超过政策上限 {X} m——请降低计划高度」）；并在 alt 输入框 blur 时预取一次 `/authz/binding` 让上限与即时标红（:490 已有）在提交前生效。工作量 40 分钟。

**P1-6 [修复核验未通过] 口令解锁/安全升级仍寄生红色拒绝盒——上轮 P1-2 声称落地，实地仍是 .deny**
- 证据 [静态分析]：ApplyView.vue:454-460（sealed 口令框）、:461-475（legacy 升级+恢复码展示）容器仍是 `class="deny"`（红底 ✕ 语义，ui.css:57-61）——把正常操作渲染成系统报错的问题原样存在；口令框无 @keyup.enter、unlock 成功后 unlockPass 不清空（:142-153）。上轮建议的 `.gate` 卡未实现。
- 改法：新增 `.gate`（--accent-soft 底+左 3px accent 边+「身份钥已锁定」标题），两块迁入；回车提交；成功清空口令。工作量 3h。

### P2（中等）

**P2-1 TRAIL 出证轮询零容错——与 ApplyView 的 pollWithRetry 双标**
- 证据 [静态分析]：TrailView.vue:133-139 裸 `for(;;)` 轮询 `/prove/task`，一次网络抖动=1~5 分钟出证作废（fail 后 stage 清空、证书卡不出现）；ApplyView.vue:222-234 已有 pollWithRetry（5 败+退避）却未复用。
- 改法：把 pollWithRetry 提升到 lib/api.ts 供两屏共用。工作量 0.5h。

**P2-2 「结束飞行并封链」后 ARMED 横幅不复位、爬升/悬停仍可点**
- 证据 [静态分析]：FlightView.vue:208-218 endFlight 调 `/sitl/disarm`（桥内真 disarm，sitl_link.py:293-295）但 `armResult` 不动 → gate-banner 仍显示 ARMED（:418-426）；手动爬升/悬停按钮只看 `armed/sealing`（:468-469），点后吃到 `not_armed` 拒绝（server.py:77-82）——封链后的第一次负反馈是自我矛盾的。
- 改法：endFlight 成功后 `armResult.value=null`（横幅回 DISARMED）或在横幅加第三态「已停桨 · 封链完成」；disarm 后禁用爬升/悬停。工作量 0.5h。

**P2-3 [修复核验-差距量化] --ink-3 调深后仍不达 WCAG AA：4.12:1 < 4.5:1**
- 证据 [静态分析+计算]：tokens.css:15 现值 #6b7f96。线性化：r(107)=0.1470、g(127)=0.2122、b(150)=0.3048，L=0.2126·0.1470+0.7152·0.2122+0.0722·0.3048=0.2050；对白底对比 (1.05)/(0.2050+0.05)=**4.12:1**。而 .note/.desc/label/kv dt 是 12-13px 正文色（ui.css:16,18,63,65），AA 小字需 4.5:1。上轮建议值本身就差 0.4。
- 改法：#64748b（同法计算 L=0.1707 → **4.76:1**），一行改动。工作量 10 分钟。

**P2-4 FlightView resize 监听器泄漏：匿名函数永远移除不掉**
- 证据 [静态分析]：FlightView.vue:367 `window.addEventListener("resize", () => {…})` 匿名注册；onBeforeUnmount（:371-374）只清两个 timer。七屏间反复进出=处理器叠加、组件销毁后仍画已卸载 canvas。
- 改法：具名 `const onResize = () => {…}`，add/remove 对称。工作量 10 分钟。

**P2-5 [修复核验未通过] 出证成功后回执码仍同屏两份**
- 证据 [静态分析]：ApplyView.vue:504（kv 行 HashText 截断一份）+ :506-509（receipt-box 完整码+复制又一份）。上轮 P1-10 的「删 kv 重复行」只做了一半（CTA 加了，重复没删）。
- 改法：删 :504 行。工作量 10 分钟。

**P2-6 申请历史缺失：fzLastReceipt 单值覆盖，旧回执码 UI 无处找回**
- 证据 [静态分析]：ApplyView.vue:287 每次申请覆盖写 `fzLastReceipt`；回执查询（ReceiptView.vue:31-34）只能手输。真实监管场景飞手必然多申请并存；演示中「申请两次」即丢第一次的码。这也是监管叙事里「可追溯我的历史申请」的缺口。
- 改法：追加 `fzReceipts` 列表（code/time/status），在回执查询屏下方加「最近的申请」小卡（点击即查）。工作量 0.5 人天。

**P2-7 说人话纪律残留清单（逐屏）**
- 证据 [静态分析]：ReceiptView.vue:43 `waiting——ZK 验证队列中`（英文态+ZK 术语，ready 态更是裸出英文「ready」）；TrailView.vue:178 「genesis 链头」（FlightView 同物叫「飞行链起始锚」:476，同物两名+英语直出）；RecordView.vue:110 h2 标签「已承诺化」（密码学行话当卖点贴）；FlightView.vue:423 横幅人话行夹生英文 `authId 3`（kv 处同物译作「授权编号」:399）；机型类全程裸数字 0..255（LoginView.vue:226,288；ApplyView.vue:491）——飞手不知道「1 类」是什么。
- 改法：waiting→「排队核验中（零知识验证）」/ready→「已通过」；genesis→统一「起始锚」；「已承诺化」→「已加密登记」；横幅改「授权编号 3」；机型类加映射（0/1/2/3→微型/轻型/小型/中型，与登记文案对齐）。工作量 1.5h。

**P2-8 fake 档演示动线断裂：TRAIL 出证要手点 128 次「注入仿真样本」**
- 证据 [静态分析]：FlightView.vue:467 非 SITL 档仅「注入仿真样本」单发按钮（+1/次），TrailView 出证门槛 128（TrailView.vue:190）；SITL 掉线（WSL 重启）时整个「飞行→证书」演示段不可达，且无任何降级引导。
- 改法：fake/未连接档加「一键补齐演示样本（128）」ghost 按钮：循环调用 /telemetry/sample 带进度提示，按钮文案诚实标注「注入仿真数据」。工作量 1h。

### P3（改进）

**P3-1 fzTokenPayload 漏出身份清扫名单**——material.ts:61-65 IDENTITY_SCOPED_KEYS 无 `fzTokenPayload`，仅 LoginView.vue:138 登记路径手动清；「双保险」的第二道（sweep）扫不到它，换身份后 TrailView.loadAltMax（TrailView.vue:30-37）会读到上一身份令牌的 alt_max。加进数组，10 分钟。

**P3-2 [修复核验未通过] 650/750 非标准字重仍在**——ui.css:13（panel h2 650）、App.vue:98（brand 750）。演示机 win32+微软雅黑只有 400/700，中间值渲染为合成加粗、笔画发虚。统一 600/700，10 分钟。

**P3-3 canvas 与表单的可访问性欠账**——FlightView.vue:452 高度曲线 canvas 无 aria-label/role，空态纯空白（航迹图 ：311-314 至少画了提示文字但读屏不可达）；全站 `<label>` 与 input 是兄弟节点无 for/id 关联（如 ApplyView.vue:478-491），点标签不聚焦。改法：canvas 容器 `role="img"+aria-label`、空态用 HTML 覆盖层；label 包裹或 for/id。合计 2h。

**P3-4 RecordView 两处小失分**——:128 主凭证「有效期至」裸 ISO 直出（子凭证已做人话倒计时 ：134，同屏不一致）；:92 snapshot 拉取失败静默置 null，「吊销名单状态」块整个消失而非显示「名单状态暂不可达」。改法 30 分钟。

**P3-5 DenyBox 不识别换行**——ApplyView.vue:434 组装 `message\n提示：…` 双行语义，但 DenyBox.vue:8 内联渲染、ui.css .deny 无 `white-space: pre-line` → 真实原因与提示挤成一行，恰削弱「真实原因必须保留可见」的整改初衷。加一行 CSS，10 分钟。

---

## ③ 逐屏四态完备性矩阵（现状）

| 屏 | 加载态 | 空态 | 错误态 | 成功态 | 主要缺口 |
|---|---|---|---|---|---|
| 入口登记 | ✓ busy「提交中…」(LoginView:251) | ✓ 零预填(enroll.ts:19) | ✓ step-err(:246)+DenyBox(:255) | ✓ 恢复码卡(:256-262) | busy 不禁用输入；恢复码入口已补（核验通过） |
| 我的记录 | ✗ snapshot 静默(:92) | ✓(:153) | △ deny 有(:120)，snapshot 失败无 UI | ✓ 倒计时+撤销自查(:134,136-144) | 主凭证裸 ISO；snapshot 失败态（P3-4） |
| 起飞申请 | ✓ 段标签+秒表(:513-519) | ✓(:447,:525) | ✓ DenyBox+人话 hint(:428-436) | ✓ CTA(:520-523) | 恢复卡死(P1-1)；超限错文案(P1-5)；红盒(P1-6)；双份码(P2-5) |
| 令牌与飞行 | ✓ busy | ✓(:411；航迹图空态 ：311) | △ 三处 deny 已分位(:389,438,492)，但 ok:false 静默(P1-2) | ✓ 横幅+双图+封链(:418,452-491) | 封链后横幅(P2-2)；resize 泄漏(P2-4)；高度图空态 |
| 留痕与合规证明 | ✓ spin+秒表(:201-207) | ✓(:196-198,:244) | △ deny(:199)；轮询无容错(P2-1) | ✓ 证书卡(:209-227) | 导出假 spec+复验文件缺(P0-1)；装饰 authId(:176) |
| 回执查询 | ✓(:34) | ✓ 空码禁用 | ✓(:37) | △ waiting/ready 英文直出(:42-43) | 文案(P2-7)；历史列表(P2-6) |
| 链上留痕 | ✓(:73) | ✓ 各卡 | ✓ 15s 超时+重试(:41-59,72)（核验通过） | ✓ | fake 术语已改人话(:88)（核验通过）；无最后更新时间 |
| 审计台（对照） | △ 列表无 spinner | ✓ | ✓ 401 人话 | ✓ 时间线 | 令牌已 type=password+「已连接 ✓」（static/index.html:116,172，核验通过） |

---

## ④ 五个瞬间与五个方向

**最掉分的 5 个瞬间**
1. 未解锁点「开始记录」→ 界面毫无反应，还悄悄污染 localStorage（P1-2）。
2. 出证中切页再回，恢复成功却永远「处理中…」（P1-1）。
3. 照 ApplyView 承诺换设备「领取飞行令牌」→ decrypt_failed 红盒（P1-3）。
4. 点「导出出证任务」拿去 zkc 复验 → 必拒，「第三方可复验」当场断裂（P0-1）。
5. 政策上限 120m 填 150，提示却是「须为 1..500 米」（P1-5）。

**最加分的 5 个方向（按投入产出比）**
1. P0-1 三处小改（3~4h）：让最硬的 TRAIL 成果真正「可第三方复验」。
2. P1-1+P1-2+P1-5 三个 10~60 分钟级收口：堵掉演示动线上三处静默/自相矛盾。
3. 飞行屏已地面站化（链路徽标/ARMED 横幅/真采样/双图/封链）——沿此把「封链后状态复位」补完即成完整生命周期叙事。
4. 文案纪律一日清（P2-7+P3-5，约 2h）：waiting/genesis/已承诺化/authId 清零后，七屏再无工程腔。
5. 申请历史小卡（P2-6）：补齐「多申请并存」这一最高频真实需求，且是回执跨设备叙事的诚实起点。

## ⑤ 亮点

在坚持手写令牌与 DenyBox 范式的前提下，本轮把上轮评审的纸面缺陷几乎逐条变成了真管线（TRAIL 出证、封链锚定、撤销自查、恢复码找回、身份清扫），这种「评审-整改-实地复验」闭环本身就是该作品最硬的工程证明。
