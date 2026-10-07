# C 线 · 产品贴合性与前端设计深度评审（2026-09-24）

> 评审人视角：产品评委 + 前端设计专家双重视角。只读评审（源码精读 + 只读 HTTP 探活），
> 未修改任何业务文件。所有发现均给出 file:line 级证据、可直接执行的改法与工作量。
> 评审对象：uas/gcs/web/src（七屏 + lib + 组件 + 样式）、uas/gcs/bridge/server.py、
> backend authz/ra/audit/chain 面板、audit/ui、docs（性能档案/答辩口径卡/说明书 v2/对外文档）。

---

## ① 理解综述（≤300 字）

「飞证」前端以 Vue3 手写 CSS 实现七屏（登录/记录/申请/飞行/留痕/回执/链上），设计令牌
体系（tokens.css）淡雅克制、一致性较好；密码学叙事完整：承诺登记→一次性子凭证→本机
ZK 出证（约 2 分钟）→受理→令牌取件→ARM→遥测哈希链→TRAIL 导出→审计台令状双控。
核心矛盾：**后端能力密度远高于前端消费度**。bridge 的 SITL 真采样/锚定/disarm、backend
的撤销见证自查、性能档案的实测数字、恢复码解封（keystore.ts 已实现）均无前端入口；
而前端把演示最关键的三个高光时刻（TRAIL 证书、ARM 状态、遥测链）做成了「下载 JSON」
「两行文本」「手动点采样」。对外文档宣称与屏幕所见存在 5 处断链，是当前最大风险。

---

## ② 分级发现

### P0 致命（演示翻车 / 宣称与所见断链 / 功能死锁）

**P0-1 「生成合规报告」名不副实——TRAIL 只有输入材料，没有证书产物**
- 证据：`gcs/web/src/views/TrailView.vue:70-82`（exportSpec 仅 Blob 下载 trail_job.json）；
  按钮 label「生成合规报告」（TrailView.vue:113）；对外文档
  `uas/01_设计文档/2026-09-23-作品说明文档.md:28`宣称「轨迹合规证书……任何第三方可独立复验」。
- 为什么致命：评委点击按钮 → 浏览器下载栏闪过一个 JSON → 页面零反馈。按钮承诺「报告」，
  交付的是「出证作业的输入文件」，且需要手动命令行 `zkc prove --spec trail_job.json`
  才能变成证书（docs/前端手动测试清单.md:42 自己也这么写）。演示叙事在最后一米断裂：
  全场最硬的成果（TRAIL n=128 服务器实测 prove 14.77s/verify 0.20s，性能档案 B6 节）
  在产品面上不存在。
- 改法（三件，可直接执行）：
  1. 按钮改名「导出 TRAIL 出证任务（JSON）」，tooltip 写明用途；
  2. 新增「提交出证」按钮：桥接加 `POST /trail/prove`（转发 zksvc，复用 gcs/bridge/server.py
     已有的 `_post_engine` 模式与 prove_router 形态），前端复用 ApplyView 的
     pollTask + 秒表 + 条纹进度组件（约 15s 出证，等待体验可直接抄）；
  3. done 后渲染「TRAIL 合规证书」卡片：`verdict: OK` 大号 StatusTag(ok) + 证明文件
     SM3 摘要（HashText）+「本机 297s / 服务器 14.77s」实测耗时角标 + 「下载判决件三件套」
     与「第三方复验命令」展示行。样式复用 .panel + .kv，零新依赖。
- 工作量：1.5~2 人天（桥接端点 0.5 + 前端 1）。

**P0-2 「采样 +1」手动假遥测——与「真固件硬拦截」宣称正面冲突**
- 证据：`gcs/web/src/views/FlightView.vue:96-113`：`alt = 3000 + randInt(6000)`、
  `lat = 310000000 + samples.length * 13`——遥测数据是浏览器内随机数+序号线性递增编造的；
  桥接真采样面 `gcs/bridge/server.py:107-139`（/telemetry/sitl_sample，取真飞控
  GLOBAL_POSITION_INT）与 `/link_status`（268-275 行）**前端零消费**。
- 实测：本机探活 `GET 127.0.0.1:8100/link_status` 返回 `{"mode":"sitl","conn":null,...}`
  ——链路配置为 SITL 但当前无连接；FlightView 对此完全无感知，评委点「采样 +1」
  得到的是前端伪造数。这与答辩口径卡 A3「固件围栏硬拦截（真遥测 2Hz）」、
  bridge 源码自己写的「不伪造遥测」纪律（server.py:111）直接矛盾。
- 附带：`FlightView.vue:85` `fence_state_hex: "01007800"` 魔法值硬编码（0x78=120m）。
- 改法：
  1. 飞行记录 panel 顶部加链路徽标：onMounted 调 `/link_status`，sitl+conn 正常=绿点
     「SITL 链路在线」，fake=金点「仿真链路」，conn=null=红点「链路未连接」（并禁用采样）；
  2. 采样改为自动循环：ARM 成功后 500ms setInterval 调 `/telemetry/sitl_sample`（真实高度
     回显），fake 档下按钮标注「注入仿真样本」而非「采样 +1」；
  3. 响应里 `fence_breached/last_statustext` 渲染为红色告警条「⚠ 固件围栏触发 @XXXXcm
     （Max Alt fence breached）」——这是 S2 场景最有戏剧性的瞬间，现在是无人看见的返回字段。
- 工作量：1 人天。

**P0-3 令牌时间窗显示 Unix 裸秒，无剩余有效期**
- 证据：`gcs/web/src/views/FlightView.vue:141` `{{ info.tok.t_start }} ~ {{ info.tok.t_end }}`
  ——渲染如 `1789010400 ~ 1789014000`；「令牌时间窗一次一用」是对外文档核心技术卖点
  （作品说明文档:39），但展示层是评委读不懂的 10 位数。
- 改法：加 `fmtTs()`（YYYY-MM-DD HH:mm:ss）+ `remaining` computed（每秒 tick，取自
  ApplyView 已有的 ticker 模式）显示「剩余 58:32」；<5min 变 tag.gold，过期 tag.bad
  「已过期——闸门将拒绝」。同时 ApplyView `:234` `t_end = t_epoch + 3600`（受理固定 1 小时窗）
  与计划单 2 小时窗口（defaultWindow，ApplyView.vue:69-72）脱节，应在计划表单旁加一句
  「实际授权窗=验证通过起 1 小时」的人话说明。
- 工作量：0.5 人天。

**P0-4 密钥库 none 态死锁：提交按钮永久灰死且无解释**
- 证据：`gcs/web/src/views/ApplyView.vue:421`
  `:disabled="busy || !hasMaterial || keystoreState !== 'unlocked'"`；模板仅处理
  `sealed`（382-388）与 `legacy`（389-403）两个态，`keystoreState === 'none'`
  （fzUserKeypair 丢失/被清，而 fzCred 仍在——例如「清浏览器缓存」只清了一半，
  或跨浏览器复制了 fzCred）无任何 UI 分支。
- 后果：守卫（router.ts:26 只查 fzCred）放行进入申请屏 → 按钮灰死 → 用户无提示可循。
  队长手动测试刚报过三个缺陷，这是同类「等而不知情」的第四例。
- 改法：补一个 `v-if="keystoreState === 'none'"` 的 DenyBox：「本机密钥库缺失——
  请返回入口页重新登记，或凭恢复码找回」+ 路由按钮 `go('/login')`。顺带在按钮旁
  加 title 提示未解锁原因。工作量：2h。

**P0-5 恢复码「找回身份」入口全站缺失——宣称有、实现有、UI 没有**
- 证据：LoginView.vue:205「清空浏览器数据后，凭恢复码可找回身份」；对外文档
  （作品说明文档:22）「忘记口令可凭恢复码找回，密钥不出设备」；keystore.ts:97
  `openWithRecoveryCode` 完整实现且被 keystore 9 项测试覆盖——但 grep 全 src/ 无任何
  调用它的组件（仅 ApplyView 升级路径间接用 sealKeystore）。
- 后果：评委问「恢复码怎么用」→ 现场无法演示 → 密码学叙事的关键一环（双因子信封）
  只能靠口述。宣称-实现-产品三层中断了一层。
- 改法：LoginView「进入」卡（hasLocal 分支）加 `<details>`「凭恢复码找回密钥库」：
  输入恢复码 + 新口令×2 → `openWithRecoveryCode` 解封 sk → `sealKeystore(sk, pk, 新口令, 恢复码)`
  重密封写回 → 提示「密钥库已恢复」。注意校验恢复码 24 字符 6 段形态后再调 KDF
  （SM3 60000 次迭代约 1s，加 busy 态防双击）。
- 工作量：0.5 人天。

### P1 严重（高概率踩坑 / 明显失分）

**P1-1 出证/回执轮询零容错：一次网络抖动 = 2 分钟白等 + 烧掉一张一次性子凭证**
- 证据：`gcs/web/src/views/ApplyView.vue:196-214` pollTask/pollReceipt 均为 `for(;;)`
  无重试包裹；`:329-333` catch 后 `clearFlow()` 直接销毁流程快照。桥接/后端任一次
  fetch 瞬断 → fail → 快照清除 → 重新 apply 从头出证，且旧子凭证已绑定 nonce 消耗
  （子凭证一次性是门控硬约束），重试成本=重新签发子凭证+再等 2 分钟。
- 改法：轮询体包 try/catch，连续失败计数 ≥5 才 throw（指数退避 2s→4s→8s）；fail 时
  保留 FlowState 并给「继续等待 / 放弃本次申请」双按钮而非静默清除。工作量：0.5 人天。

**P1-2 口令解锁交互寄生在红色错误盒（.deny）里**
- 证据：`gcs/web/src/views/ApplyView.vue:382-403`：keystoreState sealed/legacy 的
  口令输入框、升级流程全部放在 `class="deny"`（红底、✕ 前缀、红字）容器内——把
  正常操作渲染成系统报错，视觉语义错误，且 DenyBox 纪律「真实拒绝原样呈现」被稀释。
- 改法：新增 `.gate` 样式卡（`--accent-soft` 底 + 左侧 3px accent 边 + 🔒 图标 +
  「身份钥已锁定」标题），口令框回车即提交（@keyup.enter），unlock 成功后
  `unlockPass.value = ""`（当前口令残留输入框，:128-139 未清空）。工作量：3h。

**P1-3 政策数据被丢弃：binding 返回的 alt_max/required_level 没进 UI**
- 证据：`gcs/web/src/views/ApplyView.vue:299-301` `await api("/authz/binding?...")`
  返回值未接收；backend `app/authz/router.py:239-248` 明确返回 `alt_max`（政策高度上限）
  与 `required_level`。前端高度输入框 `max="500"` 硬编码（:416）。
- 改法：接收返回值存 `bindingInfo` ref；高度 label 动态显示「政策上限 {alt_max}m」，
  input :max 绑定之；超限输入即时标红（不必等提交后端拒）。这是「政策实时公示」
  卖点的零成本展示位。工作量：2h。

**P1-4 飞手无法自查撤销状态（后端端点现成）**
- 证据：`gcs/web/src/views/RecordView.vue:94-101` 只展示全局 snapshot（版本/根/数量）；
  backend `app/ra/router.py:196-213` 已有 `GET /ra/revocation/witness?holder_pk_hex=`
  （非成员见证+根，正是出证电路消费的同源数据）——前端零调用。被吊销飞手只能等
  出证失败后才从 DENY_HINT 反推原因（ApplyView.vue:367-370）。
- 改法：RecordView 撤销名单块加「检查我的状态」按钮 → 调 witness → 成功显示
  StatusTag(ok)「不在吊销名单（非成员见证已核）」+ HashText 见证值；被吊销显示
  StatusTag(bad)「已列入吊销名单——申请将被数学拒绝」。演示负例闭环（吊销→自查→
  申请被拒）一站打通。工作量：0.5 人天。

**P1-5 登记页文案自相矛盾：「无需设置密码」vs「请设置访问口令」**
- 证据：`gcs/web/src/views/LoginView.vue:271` foot「登记会在本机生成您的专属密钥，
  无需设置密码——密钥即身份」；同屏 step3 `:180`「访问口令（≥8 位，用于加密本机私钥）」
  及 :89-96 的口令校验。文件头注释 `:2`「无口令体系（密钥即身份）」是 P1-A 密钥库
  改版前的旧口径残留。
- 改法：foot 改为「密钥即身份：此处口令不用于登录，仅在本机加密您的私钥文件」。
  工作量：10 分钟。评委逐字读登记页的概率极高，这类硬伤性价比最低。

**P1-6 子凭证/主凭证有效期无倒计时、无过期态**
- 证据：`gcs/web/src/views/RecordView.vue:86,92` `{{ cred.expires_at }}` /
  `{{ sub.expires_at }}` 原始字符串直出。子凭证 24h 有效（测试清单：15），过期后
  出证必败，但 UI 对「已过期」零感知——与 P0-4 同族的「不知道自己为什么被拒」。
- 改法：computed `subRemain`（毫秒差→「剩余 23:41:08」），<2h 显示 tag.gold、
  过期显示 tag.bad「已过期——请重签」并禁用跳转申请的引导。工作量：2h。

**P1-7 飞行无终点：无 DISARM/封链/锚定操作，生命周期戛然而止**
- 证据：FlightView 只有「开始记录/采样 +1」；bridge `server.py:178-227`
  `/telemetry/anchor`（检查点真链锚定+anchored_seq 续传）与 `/sitl/disarm`（:259-265）
  前端零消费。飞行结束后：链不封口、检查点不上链、闸门不复位——评委看到的飞行
  生命周期没有句号，而「检查点锚定上链」是 ChainView/审计台时间线的上游数据源。
- 改法：飞行记录 panel 加「结束飞行并封链」按钮：顺序调 `/telemetry/anchor`
  （显示「已锚定 n 个检查点（anchored_seq=x）」）→ `/sitl/disarm` → ARM 横幅复位
  DISARMED + 遥测循环停止。这同时是「ARM→飞→锚→trail 证书」叙事的关键转场。
  工作量：0.5 人天。

**P1-8 ARM 状态无地面站观感**
- 证据：`gcs/web/src/views/FlightView.vue:157-160`：解锁成功仅 kv 两行「闸门：已解锁
  （审计行已记）」。ARM/SAFE 大状态是所有真实地面站（Mission Planner/QGC）的第一视觉，
  也是本系统「令牌→固件」硬绑定的高光时刻，现在是一行小字。
- 改法：解锁 panel 顶部加状态横幅：大号 mono 字「DISARMED / ARMED」+ 左边框色
  （灰/绿）+ ARMED 时套 `fz-pulse` 呼吸动画（tokens.css:99 已有，目前只用在顶栏小圆点）
  + 副行 authId + 围栏「min(令牌 alt_max, 计划高度)=XXm」。工作量：3h。

**P1-9 错误提示位置与操作分离**
- 证据：FlightView 三段操作（取件/解锁/记录）共享一个 `deny` ref，但 DenyBox 只渲染在
  第一个 panel（:130）。ARM 或采样失败时，错误出现在页面最上方「取件」卡内，
  用户视点在下方——又一个「发生了但看不见」。
- 改法：deny 改为三处独立（各 panel 自己的 deny ref），或全局 toast（右上角 fixed，
  5s 自动消失，复用 fz-enter 动画）。工作量：2h。

**P1-10 ready 高光时刻无 CTA，回执码同屏重复显示两份**
- 证据：`gcs/web/src/views/ApplyView.vue:428` kv 行「回执码」HashText 截断一份，
  `:430-435` receipt-box 完整码+复制按钮又一份；出证成功（ready）后唯一引导是
  `:444-446` 一行 12px note「到令牌与飞行取件解锁」——全场最值得庆祝的时刻
  （2 分钟等待的终点）没有任何行动按钮。
- 改法：删 kv 里重复行；ready 态渲染成功卡（StatusTag ok「授权已就绪」+ receipt-box
  + 主按钮「前往取件 →」router.push('/flight')）。工作量：1h。

### P2 中等

| # | 发现 | 证据 | 改法 | 工作量 |
|---|------|------|------|--------|
| P2-1 | ChainView 链不可达时无限白挂：实测 `GET /chain/panel` 阻塞无响应，前端只有「读取中…」无超时无重试 | ChainView.vue:36-44,55；backend/chain/panel.py `_chain_face` 直连 RPC | onMounted 加 AbortController 8s 超时；错误态加「重试」按钮 | 1h |
| P2-2 | 内部术语直出：「当前为无链模式（fake）」——fake 是部署环境变量名 | ChainView.vue:70-72 | 改「演示模式（链下登记在案，链状态面不可用）」 | 0.5h |
| P2-3 | 「退出」不退：logout 仅 push('/login')，内存明文私钥 cachedSk 与 sessionStorage 会话钥均不清理，与 title「本机身份保留」的隐私承诺不符 | App.vue:37-39；keystore.ts:137 cachedSk | logout 调 cacheSk(null) + sessionStorage.clear() | 0.5h |
| P2-4 | 半程恢复无提示条：onMounted 恢复 FlowState 时静默续跑（注释说「提示条」但模板无），用户不知道正在恢复 | ApplyView.vue:341-354 | 顶部加 note 条「检测到未完成的申请（出证中），正在恢复进度…」；另 :346-353 的 if/else-if 两分支代码完全相同，合并为一行 | 0.5h |
| P2-5 | 无 favicon/描述/theme-color：投影时标签页灰白图标，console 必现 favicon 404 | gcs/web/index.html | 加内联 SVG favicon（飞证 logo 可复用 App.vue icons.craft 路径）+ `<meta name="theme-color" content="#f6f8fb">` | 0.5h |
| P2-6 | 审计台连接无成功反馈、令牌明文显示：点「连接」成功后 header 无变化，token input 非 type=password | audit/static/index.html:116-117,167-183 | 成功后输入框变绿框+右侧 tag「已连接 · n 条令状」；type 改 password | 1h |
| P2-7 | TrailView 高度上限（厘米）暴露手填且单位与飞行屏不一致：令牌 alt_max（米）已有却不带出；用户填错=出证必败 | TrailView.vue:9,102-103 vs FlightView.vue:141 | altMax 改为取件后从令牌带出的只读值（alt_max*100），删除输入框 | 1h |
| P2-8 | 大量内联样式与「令牌驱动」纪律相悖：`style="margin-top:14px; border-top..."` 十余处 | RecordView.vue:72,88,94；ApplyView.vue:420,437；FlightView.vue:127,157,170 等 | 收敛进 ui.css：加 `.panel-sub`（上分隔块）、`.mt-12/.mt-16` 间距工具类 | 2h |
| P2-9 | 文档与 UI 脱节：前端手动测试清单.md 描述的仍是旧版 UI（「证明模式演示占位」「注册承诺」按钮，现 UI 已无）；答辩卡 D3「web 负例按钮」已不存在（FlightView arm(tamper) 有参数无入口，:50）；F9「八屏」实际七屏 | docs/前端手动测试清单.md 全文；答辩口径卡 D3/F9 | 重写测试清单对齐现 UI；tamper 负例做成「令牌防篡改自检（演示）」ghost 按钮放 ARM 旁 | 清单 1h / 按钮 2h |
| P2-10 | HashText 复制失败静默、成功反馈弱：仅行内「已复制」文字，原生 title 提示延迟 >1s | HashText.vue:15-27 | hover 时 border 变实线+cursor 提示；失败时显示「复制失败」红字 | 0.5h |
| P2-11 | 采样明细表裸展示工程值：t=Unix 秒、alt(cm)、lat(1e7) 原样直出 | TrailView.vue:127-136 | 表头改「时间 HH:mm:ss / 高度 m / 纬度°/经度°」并格式化；评委才能看出「这是条航迹」 | 1h |

### P3 改进（视觉/可访问性细项）

| # | 发现 | 证据 | 改法 |
|---|------|------|------|
| P3-1 | --ink-3（#8496ab）对白底对比度 3.03:1，低于 WCAG AA 4.5:1，却大面积用于 12px 的 note/desc/label/空态文案 | tokens.css:15；ui.css:16,18,63 | 加深至 #6b7f96（≈4.6:1），--ink-3 保持用于装饰性场景另立 --ink-4 |
| P3-2 | 中文粗体 650/750 为非标准字重：微软雅黑仅 400/700，中间值由浏览器合成发虚 | tokens.css 使用处（font-weight:650/750 遍布各屏） | 统一改 600/700 两档 |
| P3-3 | 「链上留痕」与「留痕与合规证明」共用同一 trail 图标 | router.ts:18,20（icon:"trail" 两处） | chain 屏改用「链条」图标（三节环 path） |
| P3-4 | grid2 全站 6 处固定对半分，左列常只有一个按钮大片留白（RecordView 左列 vs 右列 kv 密度失衡） | RecordView.vue:70；ApplyView.vue:404；FlightView.vue:123 等 | 引入 `grid2--wide`（1.2fr/0.8fr）变体；RecordView 左列补撤销自查卡（见 P1-4）填实 |
| P3-5 | 键盘焦点态只有输入框有：按钮/卡片/nav/HashText 无 :focus-visible 样式，Tab 导航不可见 | ui.css:25-27 仅覆盖 input/select/textarea | 全局补 `:focus-visible { outline:2px solid var(--accent); outline-offset:2px }` |
| P3-6 | StatusTag 注释宣称支持 neutral，类型与样式均无 | StatusTag.vue:2-3；ui.css:47-55 无 .tag.neutral（默认态即 neutral，但类型未列） | 类型收窄或补全，二选一 |
| P3-7 | kv 150px 固定标签列窄屏挤压；会话私钥 128hex 输入框单行溢出 | ui.css:64；FlightView.vue:126 | @media 窄屏 kv 改单列堆叠；私钥框加 overflow 滚动或折叠显示（👁 展开） |
| P3-8 | 演示机分辨率未设防：main max-width 1120px 在 4K 投影下两侧大量空白、字号偏小 | App.vue:126 | 投影场景加 `@media (min-width:1600px){ html{font-size:112.5%} .main{max-width:1280px} }` |

### 演示走查：最掉分的 5 个视觉瞬间（评委 10 分钟视角）

1. **出证等待 2 分钟**：右列只有一条 6px 装饰性条纹无限滚动（进度永远 100% 宽，
   ApplyView.vue:456-461，与代码注释「诚实进度」自相矛盾）+ 红色盒里的口令框。
   改法：真 6 段分段进度（binding→…→ready 各段节点点亮+各段已用时+按性能档案
   实测值标 ETA「本段预计 ~90s」）。
2. **「采样 +1」手动点击**（P0-2）：地面站最像玩具的一刻。
3. **令牌时间窗 Unix 裸秒**（P0-3）：核心卖点读不懂。
4. **「生成合规报告」点完没反应**（P0-1）：下载栏一闪，页面静止。
5. **「当前为无链模式（fake）」**（P2-2）：内部环境变量名直出给评委。

### 最加分的 5 个改进方向（按投入产出比）

1. **TRAIL 证书卡**（P0-1）：把最硬的实测成果（14.77s/verify 0.2s/篡改 exit 2）变成屏幕上的 verdict=OK 大卡片——答辩卡的 A4 判决行产品化。
2. **ARM 状态横幅 + 自动遥测 + 围栏告警条**（P0-2/P1-7/P1-8）：飞行屏从「表单页」变「地面站」，S2 场景的围栏触发瞬间可视化。
3. **出证分段真进度 + ETA**（上文 1）：把「约 2 分钟」的煎熬变成「见证 8s ✓ → 证明 92s…」的确定性叙事。
4. **撤销自查一键**（P1-4）：端点现成，把「撤销名单进电路」卖点做成飞手可亲手验证的交互。
5. **ready 成功卡 + 前往取件 CTA**（P1-10）：两分钟等待的终点要有仪式感。

---

## ③ 高价值新功能清单（按赛内可实现性排序）

| 序 | 功能 | 依托的现成能力 | 工作量 | 演示价值 |
|----|------|----------------|--------|----------|
| 1 | 撤销状态自查（飞手） | `GET /ra/revocation/witness`（ra/router.py:196）已实现 | 0.5 人天 | 「撤销进电路」卖点可交互化；负例闭环起点 |
| 2 | TRAIL 出证闭环 + 证书卡 | zksvc CLI + 性能档案实测数字；ApplyView 轮询组件可复用 | 2 人天 | 补齐对外文档最大宣称「第三方可复验证书」 |
| 3 | 令牌剩余有效期倒计时 + 授权窗人话 | 令牌字段已在手 | 0.5 人天 | 一次一用卖点可读化 |
| 4 | SITL 链路状态徽标 + 自动真采样 + 围栏告警条 | `/link_status`、`/telemetry/sitl_sample`（bridge 现成） | 1 人天 | S2 场景可视化，消解「假数据」风险 |
| 5 | 恢复码找回身份入口 | `openWithRecoveryCode` 已实现+已测试 | 0.5 人天 | 双因子信封宣称现场可演示 |
| 6 | 结束飞行封链（锚定+DISARM） | `/telemetry/anchor`、`/sitl/disarm`（bridge 现成） | 0.5 人天 | 生命周期闭环 + ChainView/审计台数据源打通 |
| 7 | 令牌防篡改自检按钮（负例演示） | FlightView.arm(tamper) 参数已实现无入口（:50） | 2h | D1 负例一等公民回归产品面 |
| 8 | 撤销管理操作台（RA 侧 web 屏） | `POST /ra/revoke` 已有（ra/router.py:234） | 1 人天 | 监管角色可视化：吊销→自查→申请被拒三连 |
| 9 | 2D 航迹图（canvas 折线+围栏线） | fzTrailRows 本地在手；答辩卡 E7 已把「2D 航迹图+遥测曲线」定为 3D 替代方案 | 1 人天 | TRAIL 证书的直观佐证，「航线不可见」对照面 |
| 10 | 审计台统计概览条 | `/audit/warrants` 列表现成，前端汇总即可 | 0.5 人天 | 治理面从「操作台」升级「驾驶舱」 |
| 11 | 本机历史申请列表（回执码簿） | fzLastReceipt 单值即可扩展为列表 | 0.5 人天 | 高频真实需求；跨设备取件叙事的起点 |
| 12 | 性能判决行屏显（链状态卡加 prove/verify 实测耗时） | worker 判决件含耗时；性能档案口径 | 1 人天 | 「数据可信度」展示，答辩即视化（可选） |

---

## ④ 逐屏状态完备性矩阵（加载 / 空 / 错误 / 成功）

| 屏 | 加载态 | 空态 | 错误态 | 成功态 | 缺口 |
|----|--------|------|--------|--------|------|
| LoginView | ✓ busy「提交中…」 | ✓ 零预填 | ✓ step-err + DenyBox | ✓ done + 恢复码卡 | 口令强度函数（enroll.ts:61）写了没用；busy 时输入框未禁用；恢复码找回入口缺失（P0-5） |
| RecordView | ✗ snapshot 拉取无 loading | ✓「尚无凭证」note | △ deny 有，但 snapshot 失败被静默吞掉（:50-51 catch 置 null 无 UI） | ✓ kv 展示 | snapshot 加载/失败态；子凭证过期态与倒计时（P1-6）；撤销自查（P1-4） |
| ApplyView | ✓ stage+秒表+条纹 | ✓ 缺材料 deny + 右列 note | ✓ DenyBox+DENY_HINT 人话映射 | △ 仅 StatusTag+一行 note，无 CTA | none 态死锁（P0-4）；恢复提示条（P2-4）；进度条为装饰非分段（P2-1 相关）；政策上限未联动（P1-3） |
| FlightView | ✓ busy | ✓「取件后此处显示…」note | ✗ 错误显示在顶部取件卡，与操作位置分离（P1-9） | △ kv 两行，无地面站观感（P1-8） | 链路状态、令牌倒计时（P0-3）、结束飞行（P1-7）、空态下按钮禁用原因无提示 |
| TrailView | —（无异步） | ✓ ready computed+「样本不足」gold tag | △ export 的 catch 仅 String(e)（:79-81，非结构化） | ✗ 下载即结束，无证书反馈（P0-1） | 全部依赖 P0-1 改造；明细表工程值直出（P2-11） |
| ReceiptView | ✓「查询中…」 | ✓（按钮 code 空禁用） | ✓ DenyBox | △ 状态 tag + 密文截断 | ready 后无「去取件」引导；pending 态文案「pending——ZK 验证队列中」英文态直出 |
| ChainView | ✓「读取中…」 | ✓ 各卡「暂无…」 | ✓ deny 文本，但无超时无重试（P2-1） | ✓ | 无自动刷新/最后更新时间；「fake」术语（P2-2）；与 trail 屏图标重复（P3-3） |
| 审计台（对照） | △ 列表加载无 spinner | ✓ 空列表文案 | ✓ 401 人话+flash | ✓ 时间线动画良好 | 连接成功无反馈、令牌明文（P2-6）；无统计概览（功能清单#10） |

---

## ⑤ 亮点（≤100 字）

设计令牌体系完整（tokens.css 一处定义、审计台同源复刻）、prefers-reduced-motion 与
CSPRNG 纪律到位；DenyBox「真实拒绝原样呈现」+DENY_HINT 人话映射是诚实工程观的
好范式；失配检测前移（material.ts）把密码学报错翻译成了可操作指引；审计台时间线
与引导步骤是全站信息设计最佳屏，值得反向输出给飞手端。

---

## 附：验证方式备查

- 源码精读：uas/gcs/web/src 全部 23 文件（七屏/components/lib/styles/App/router/main）。
- 只读探活：`GET localhost:5174`（dev server 正常）；`GET 127.0.0.1:8100/link_status`
  → `{"mode":"sitl","conn":null}`（链路配置 SITL 但未连接，前端无感知——P0-2 实锤）；
  `GET 127.0.0.1:8100/audit`（正常）；`GET 127.0.0.1:8000/authz/healthz`（正常）；
  `GET 127.0.0.1:8000/chain/panel`（阻塞无响应——P2-1 实锤）；audit/ui HTML 已拉取核对。
- 对比度计算：#8496ab vs #ffffff ≈ 3.03:1（WCAG AA 小字需 4.5:1）。
