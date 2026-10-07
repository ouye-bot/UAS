# 「飞证」C 席评审报告：口令、凭据与密钥全生命周期

> 干净上下文只读评审（2026-09-28）。席位 C。评审范围：keystore.ts / 恢复码 / 口令流 /
> material.ts 身份清扫 / token.ts 取件链路 / backend KMS 域派生 / FZC2 协作函 /
> 密钥暴露面普查 / wasm 验证面。全部发现为对 2026-09-28 三代理评审 B 报告的
> **净新增**或**后续核验**；报告不含任何真实口令/密钥明文值（探针只输出耗时与位数）。

---

## 一、总体印象

**浏览器密钥库是这个作品里"文档-测试-实现"三条线对齐得最好的子系统**：零明文私钥红线
经穷举核验属实、双 KEK+AAD 绑槽位与文档逐字相符、恢复码 120bit 构造教科书级、红测试
钉定到位。后端 KMS 的域分离矩阵主件健康，上一轮 B 席的 P0-2（KDF 轮数文档失真）、
P1-4（demo_up 三面未随机）、P1-5（桥接公钥回落模糊态）三项**均已真实修复**（本轮逐条
核验，见第四节）。

主要问题集中在三处：**①"解锁态"的宣称反转**——`密钥库安全说明`⑤ 与 keystore.ts 头注
仍宣称"刷新即清零"，而实现已改为 sessionStorage 跨刷新存活，且该明文私钥键不在任何
身份清扫/重登记清理清单里，跨身份滞留；**②恢复叙事的核心场景不可达**——"清空浏览器/
换设备凭恢复码找回"在实现上不成立（信封密文在本机，清空即失，全仓无信封导出/导入）；
**③域分离的 env 覆盖设计缺陷**——`FZ_WRAP_KEY` 一把环境钥顶掉所有对称域标签，使
RA 实名映射钥与协作函钥在 env 档恒为同钥，标签域分离名存实亡。另有 KDF"OWASP 对齐"
话术经实测探针核算不成立（差一个数量级），以及若干清单漂移类卫生缺陷。

---

## 二、做得好的（带代码锚）

1. **"localStorage 零明文私钥"红线穷举核验通过（特别任务①）**。对 web src 全部
   `localStorage.setItem` 写入点（12 处：api.ts×2、keystore.ts×1、material.ts×2、
   plan.ts×1、ApplyView×4、FlightView×5、LoginView×2、RecordView×1）逐一核对：
   唯一钥材料写入点是 `storeKeystore`（`gcs/web/src/lib/keystore.ts:151-154`），落盘
   串为 `{v:2, pk, enc, rec}`——无 sk。红测试钉定双保险：
   `gcs/web/tests/lib/keystore.test.ts:36-43`（序列化串 `not.toContain(SK)`+双密文
   独立盐断言）；v1 明文遗留检测 `isLegacyKeystore`（keystore.ts:131-135）+
   ApplyView 升级 gate（ApplyView.vue:476-490）覆写明文 v1 信封。
2. **恢复码构造严谨**。32 字符去易混字母表 ×24 字符 = 2^120（探针核验
   `log2(32^24)=120.0`）；`randInt32` 拒绝采样无模偏置（keystore.ts:114-123），随机源
   `crypto.getRandomValues` 与 `randHex` 同纪律（api.ts:94-98）；一次性展示+确认放行
   （LoginView.vue:257-263 checkbox 门控按钮）与文档"仅显示这一次"一致。
3. **双 KEK + AAD 绑槽位 + 双槽独立盐/nonce**。`seal()` 每槽独立 `randHex(16)` 盐 +
   `randHex(12)` nonce（keystore.ts:69-75）；AAD=`FZ-KEYSTORE-v2|pass` /
   `FZ-KEYSTORE-v2|recovery`（keystore.ts:17-18,92）——密文互换挪用必 tag 失败；
   `unseal` 失败统一抛"口令/恢复码错误或密文被篡改"（keystore.ts:82-85），与
   密钥库说明安全点 4"不区分口令错与密文坏"逐字相符。
4. **令牌取件链路跨语言同构+验签纪律**。`canonicalTokenBody` 复刻 Python
   `sort_keys+ensure_ascii` 形态（token.ts:30-41）；裸摘要以字节数组入 SM2 方程
   防 double-encode（token.ts:69-73）；`checkTokenFields` 七字段+窗口+plan_hash+nonce
   形态五查（token.ts:80-95）与后端 `build_token`（authz/service.py:336-357）字段一一
   对应；引擎公钥每次现取不缓存并说明理由（FlightView.vue:132-134）。
5. **恒时比较全覆盖 + 桥接公钥 fail-closed（上轮 P1-5 后续核验✅）**。
   `X-Engine-Token`/审计令牌/RA 运维令牌三面均 `hmac.compare_digest`
   （telemetry/router.py:38、audit/router.py:218、ra/router.py:280）；
   `gcs/bridge/telemetry.py:46-56` 取不到公示钥时**拒绝**而非静默回落确定性派生钥。
6. **KMS 域分离矩阵主件健康**（矩阵详表见第五节）：SM2 六域+对称域标签互异；
   device 域带 `FZ-KMS|device|<serial>` 前缀天然防撞串；链交易钥族
   （`FZ-CHAIN-SMOKE|*`）与凭证签名钥族（`FZ-KMS|*`）分族——"链钥轮换不影响凭证
   验证公钥"的注释宣称（kms/__init__.py:48-49）结构上成立。
7. **FZC2 协作函三方绑定**。`(cred‖warrant)` 双入 GCM AAD（ra/collab.py:78-110），
   换令状/换凭证任一即认证失败；消费侧 `scope_mismatch` 数据链校验
   （audit/router.py:405-415 + ra/scope.py，"不可验证≠放行误判"口径清晰）——
   "双控"从流程性升级为范围受限，与口径卡 C+2 的诚实降格互补。
8. **出证失败现场即焚**。`gcs/bridge/prover.py:196-227`：成功 rmtree 整目录、失败
   `job.json`（含身份证号/盐/出示私钥见证）unlink、`failure.json` 脱敏+24h TTL 清扫；
   红测试 `test_bridge_core.py:376-421` 钉定。
9. **wasm 验证面零秘密**。`wasmVerifyWorker.ts` 仅 fetch 公开复验材料
   （zkc.wasm/spec/instances/proof/vp/expected），WASI 预打开文件全是验证输入，
   无任何钥面——"浏览器内验证=零服务端参与"的宣称与实现一致。
10. **git 卫生**。`.gitignore` 覆盖 `.env/*.key/*.pem/backend/certs/backups`；
    仓内 64-hex 字面量扫描仅命中官方向量与 manifest 常数（sm3 初始向量等），无钥材料
    入库。后端路由无 receipt_code/collab_code 落日志点。

---

## 三、缺陷与风险（按严重度）

### P1-1 解锁态明文私钥跨身份滞留 + "刷新即清零"宣称反转

- **证据**：`keystore.ts:172-177`（`cacheSk` 把明文 sk 写入
  `sessionStorage["fzSessionSkUnlock"]`）；`material.ts:87-88`（身份清扫只清
  `fzSessionSk`/`fzApplyFlow`，**不清** `fzSessionSkUnlock`）；`LoginView.vue:150-151`
  （重新登记同样只清 `fzSessionSk`）；唯一正确路径是 App.logout 的 `clearCachedSk()`
  （App.vue:51）。而 `keystore.ts:9` 头注"明文私钥仅存在于调用方内存变量（模块缓存），
  **刷新即失**"与 `docs/密钥库安全说明.md:22`"页面刷新/关闭 = 内存清零，需重新输入口令"
  均与实现矛盾——sessionStorage 跨 F5 存活。
- **攻击/事故场景**：共享浏览器，A 解锁后退出（logout 有焚），但若走"重新登记"路径
  （不经 logout）：B 登记成功后 `storeKeystore` 把模块缓存置 null（keystore.ts:153），
  `getCachedSk()` 回落读到 **A 的明文 sk**（keystore.ts:163）→ ApplyView 显示"已解锁"
  （ApplyView.vue:139），B 出证时 `holder_sk_hex` 提交的是 A 的私钥（ApplyView.vue:370-382）。
  下游电路按 pk(sk) 绑定会 fail-closed（证明失败而非错签），但这是"跨身份明文钥滞留 +
  解锁态假阳性"的红线精神违背，答辩演示一旦触发即是难看的事故现场。
- **修法方向**：`sweepIfIdentityChanged` 与 `register()` 清理清单补
  `fzSessionSkUnlock`（或统一改调 `clearCachedSk()`）；文档⑤与头注改为与实现一致的
  "sessionStorage 存活至关窗"；或干脆移除 sessionStorage 缓存、回归纯内存+刷新重解锁。
- **亮点化**：补第 10 项红测试"身份切换后 `getCachedSk()` 必为 null"——把"换人=密钥态
  全清"做成像零明文红线一样的钉定资产。

### P1-2 恢复叙事核心场景不可达："清空浏览器/换设备凭恢复码找回"不成立

- **证据**：`docs/密钥库安全说明.md:24`（"⑥ 恢复 清空浏览器/换设备：粘贴恢复码 →
  KEK2 解封 → 同一私钥回庭"）；UI 两处同文案（LoginView.vue:260,322"清空浏览器数据后，
  凭恢复码可找回身份"）。实现上恢复码只是 KEK2 的口令，**私钥只存在于本机
  `rec`/`enc` 密文里**；清空浏览器数据=信封消失；全仓无信封导出/导入 UI
  （grep 导出/导入/备份/下载零命中，恢复入口 `recoverKeystore` 在新设备必然命中
  "本机无可恢复的加密密钥库"，LoginView.vue:62）。
- **场景**：评委照 UI 文案实测"清浏览器→贴恢复码"→失败；或真用户换手机后按文档操作
  →身份永久丢失且事前以为有救。宣称给了用户不存在的安全保障。
- **修法方向**：二选一。A（一行）：文案收窄为"忘记口令时（本机密钥库还在）凭恢复码
  重置"；B（半天，推荐）：信封导出/导入——`fzUserKeypair` JSON 下载为文件+恢复页
  粘贴导入后走既有 `openWithRecoveryCode`，密文不出用户之手，零新增信任面。
- **亮点化**：做成"恢复码（人脑记）+ 信封文件（U 盘）"双件套跨设备找回，反而补全
  生命周期的第⑦步叙事，且与"恢复码永不落服务器"红线零冲突。

### P1-3 UI 隐私宣称与登记通道实现矛盾："身份证号不出本机/不向服务器提交明文"

- **证据**：UI 三处宣称（LoginView.vue:272"身份证号不出本机，只提交加密摘要"、
  LoginView.vue:220/282 与 enroll.ts:34"仅在本机参与承诺计算，不向服务器提交明文"）；
  实现上 `register()` 把完整表单（含 `id_number` 明文）POST 给 `/ra/register`
  （LoginView.vue:130-133），后端确以明文入参计算承诺并落 RA 库实名映射密文
  （backend/app/ra/service.py:81-92,110-145）。
- **定性**：架构本身没问题——RA 持实名映射密文是口径卡 E2 声明过的组织级 TCB 边界；
  **错的是 UI 文案**，隐私叙事的核心页面上挂着一句 devtools 一开即穿的假话。
- **修法**：文案改为"身份证号不上链、不进授权与审计面——仅登记机构以加密信封留存"。
- **亮点化**：改为在 UI 上画出身份证号的五域流向小图（本机→RA 密文→链上仅承诺），
  把诚实边界变成展示面。

### P2-4 `FZ_WRAP_KEY` 环境覆盖击穿对称域分离：两域恒共钥

- **证据**：`kms_domain_key(label)` 的 env 优先逻辑**忽略 label**
  （kms/__init__.py:89-96：设了 `FZ_WRAP_KEY` 则任何标签都返回同一把钥）。使用点
  两域：RA 实名映射 wrap `FZ-KMS|ra-store-wrap`（authz/service.py:394,404 →
  ra/service.py:64-68 的 `id_store_cipher`）与协作函 `FZ-KMS|collab-code`
  （ra/collab.py:27）。demo_up.py:183 随机注入 `FZ_WRAP_KEY` 后，**这两域在强化档
  （恰恰是修过 P1-4 之后的常态档）恒为同钥**；不设 env 的纯缺省档反而分域。
- **场景**：协作函钥面泄露（RA 运维通道被冒充，见 P1-4 前的威胁模型）⟹ 攻击者可解
  RA 库**全量**实名映射密文——"RA 库可见方=仅登记机构"（数据分级文档:13）的爆炸半径
  被跨域耦合放大；同时两域共享 nonce 池（GCM 96bit 随机 nonce），加密学上无近忧
  （生日界 2^48 量级），问题是**钥治理**而非 GCM 安全。
- **修法**：per-domain env（`FZ_WRAP_KEY_RA_STORE`/`FZ_WRAP_KEY_COLLAB`），或主钥
  +标签再派生：`sm3_bytes(FZ_WRAP_KEY_master + label)[:16]`——后者 env 数量不膨胀。
- **亮点化**：正好接上生产文档的"根钥离线+期间钥分层"路线（生产部署与安全演进.md:15），
  把"域钥=KDF(根钥, 域标签)"讲成密钥分层的第一层实现。

### P2-5 demo 随机钥 %TEMP% 明文持久、无清理、与"会话级"宣称失真

- **证据**：`scripts/demo_up.py:185-198` 把六把随机钥明文写 `%TEMP%`
  （fz_engine_sk/fz_engine_token/fz_ra_sk/fz_ra_ops_token/fz_wrap_key/
  fz_authz_binding_key）；实测七钥文件在盘（含 fz_pg_pw.txt 自 09-22 起驻留）；
  `demo_down.py` 无任何删除逻辑；`docs/数据分级与生命周期.md:16` 宣称 KMS 面
  "演示=**会话级**"。ACL 为用户私有（icacls 核验：SYSTEM/Admins/当前用户），演示机
  单用户形态尚可，但文件跨会话无限期累积。
- **场景**：演示机长期使用后钥面沉淀；换机/交件/录屏共享屏幕时 %TEMP% 未清=六把
  演示钥+库口令随盘走；"每场一次性随机"的注释意图（demo_up.py:173-175）被持久化
  抵消——下一场不删文件就沿用旧钥。
- **修法**：demo_down 增加 %TEMP% 六文件删除；demo_up 启动时发现现存文件打印
  "上次演示钥残留——已轮换"；生产演进文档把"钥文件落盘"边界补成文。
- **亮点化**："会话级承诺"做实为产品纪律：启动即焚上一场、退出即焚本场。

### P2-6 `fzLastCaseId` 漏出重登记清理清单——"换人即被身份清扫"宣称一键之差

- **证据**：`IDENTITY_SCOPED_KEYS` 含 `fzLastCaseId`（material.ts:61-66），但
  `register()` 的手工清理清单（LoginView.vue:137-151）恰缺它，且末尾
  `storeIdentityTag()`（LoginView.vue:156）重置清扫锚 ⟹ 后续
  `sweepIfIdentityChanged` 永不触发。`ChainView.vue:100-101` 注释宣称
  "fzLastCaseId=身份域键，换人即被身份清扫——不会误关联他人"不成立。
- **场景**：A 出证过（fzLastCaseId=A 案卷）→ 同浏览器重新登记为 B → B 的链上留痕页
  在匹配 authId 时把 A 的案卷号当"本机案卷"（ChainView.vue:104-110），下载面指向
  A 的案卷。UI 级串号，无钥面泄露。
- **修法（根因级）**：LoginView 清单与 `IDENTITY_SCOPED_KEYS` 单源化——从 material.ts
  导出常量复用，消灭第二份手抄清单（两份清单漂移是结构性的，这次漏一个，下次漏别的）。

### P2-7 KDF"OWASP 2023 对齐"话术数学上不成立 + 口令下限无强度门控

- **证据与探针**：`keystore.ts:15`（21000 轮）+`密钥库安全说明.md:35`（"OWASP 2023
  口令哈希指南对齐值"）。OWASP 2023 口令存储备忘单：PBKDF2-HMAC-SHA256=600,000 迭代
  （≈120 万次压缩）、PBKDF2-HMAC-SHA512=210,000 迭代（≈42 万次压缩）；本构造 21000
  迭代=21000 次 SM3 压缩——对最弱档仍弱 ~20×，"21000"疑为 210,000 的十倍误读。
  实测探针（backend venv）：SM3 迭代链原生单核（hashlib 口径）≈0.54μs/轮 →
  **21000 轮 ≈ 11.4ms/候选**，较 UI 体感的"纯 JS 3.5s"便宜 ~300×——离线攻击者的
  真实成本是原生的，不是 JS 的。口令面：`LoginView.vue:119` 只查长度 ≥8；
  `passphraseStrength`（enroll.ts:61-72）**定义+单测俱在但零 UI 消费**（强度条不存在），
  而密钥库说明安全点 1 宣称"口令熵（**强度条引导**）"。
- **场景**：攻击者拿到 localStorage 密文离线试口令（该威胁模型是文档自己诚实声明过的），
  8 位纯小写口令在单张高端 GPU（折算 SHA-256 类吞吐）上约 5 天量级可破；
  8 位混合字符则数年——防线的实际下限=用户手滑程度，而 UI 恰恰不给引导。
- **修法（按性价比）**：①把 `passphraseStrength` 接进 UI 并对 KEK 口令强制 ≥"中"
  （≥2 档）——函数已有、零新代码；②轮数提至 ≥100k + WebWorker 异步解锁（文档已有
  "60000+ 演进"承诺，建议直接 100k：原生成本升到 ~54ms/候选，5×）；③话术从
  "OWASP 对齐值"改为"自建构造的诚实轮数取舍+演进表"（国密无 PBKDF2 标准的自建
  构造本身是加分的诚实点，别让一句对齐话术把它变减分）。
- **紧迫性评估（特别任务②）**：威胁模型陈述本身诚实（离线爆破面白纸黑字），失真的
  是"对齐"二字与强度引导缺位。对**答辩**紧迫性高（B 席已预言"KDF 多少轮"是追问链
  雷区，现在文档-代码虽对齐、追问"对齐的哪一行"即穿）；对**实际演示风险**低
  （演示口令是答辩队自设的）。建议赛前完成 ①+③（半小时），②可留演进。

### P2-8 登记重试路径可封空私钥+复用旧身份公钥

- **证据**：`generateKeypairAndRecovery` 兜底守卫 `raw.v===2 && recoveryCode.value`
  （LoginView.vue:37-46）无法区分"本流程刚封的信封"与"**上一身份**的 v2 信封"。
  首次 `/ra/register` 失败后 `recoveryCode.value` 已置值 ⟹ 重试命中兜底分支返回
  `{sk:"", pk:旧公钥}` ⟹ 新身份以旧公钥登记上链，且
  `sealKeystore(kp.sk="", ...)` 封空私钥（`sealKeystore` 不校验 sk 非空，keystore.ts:89-93；
  此后 `cacheSk("")` 恒 falsy，UI 显示已解锁但 apply 报"身份钥未解锁"，死循环变砖）。
- **场景**：重新登记 + 首次提交遇网络错误 + 重试 = 身份变砖；共享浏览器上更糟——
  新登记身份绑定的是**别人**的公钥。
- **修法**：`sealKeystore` 首行加 sk 形态校验（64 hex，一行）；兜底守卫改为流程内
  显式标志位（如 `thisRunSealed`）而非全局 v2 检测。

### P3（卫生与边界）

- **P3-9** `fzTokenPayload`（明文令牌 body|sig）长期驻留 localStorage
  （FlightView.vue:148），数据分级五域表"用户本地"行（数据分级文档:14）未列此项。
  令牌含 authId/nonce/窗——过期后即公开信息，量级低，补表即可。
- **P3-10** ECIES 会话私钥取件后不清零：`pickup` 成功后 `fzSessionSk` 仍驻
  sessionStorage 至关窗/退出（FlightView.vue:25-27,135；无 removeItem 调用点）。
  "sessionStorage 关窗即焚"声明属实（数据分级文档:14），但 ApplyView 注释
  "一次性"（ApplyView.vue:365）仅指每申请一把、非用后即焚。另
  FlightView.vue:26 的 `localStorage.getItem("fzSessionSk")` 回落读是历史残留
  **死代码**（全仓无对应写入点）——建议删除，防未来手滑写回 localStorage 复活明文落盘面。
- **P3-11** 环境名漂移：同一把 admin 链钥在 `scripts/publish_pin.py:55` 读
  `FZ_CHAIN_ADMIN_TX_SK`、`scripts/chain_smoke.py:140` 读 `FZ_CHAIN_ADMIN_SK`——
  单边注入即部署钥与公示钥分裂（演示确定性派生下二者同源所以今天无症状）。
- **P3-12** FZC1 旧函兼容路径仍可解封"同凭证"的任意令状（audit/router.py:407 +
  scope 校验补偿）；协作函无时效绑定（AAD 无时间分量）、无一次性消费位——同令状
  重复解锁均留痕、范围受限，演示可接受；建议 FZC3 预留 expiry+nonce 字节。
- **P3-13** `sm4gcm.ts:8` 头注"仅实现解密（加密在服务端）"与同文件
  `sm4GcmEncrypt`（:211-229）矛盾——keystore 引入加密面后头注未更。
- **P3-14** 前端 GCM tag 比较为早退循环（sm4gcm.ts:198-200），与后端恒时比较
  （crypto/sm4.py:143）不对称；JS 面实际可利用性趋零，记录在案保持口径一致。
- **P3-15** 解锁口令用后即清（ApplyView.vue:150 "unlockPass 清空"）是好细节；但
  `passphrase2/upgradePass/recNewPass` 驻留 Vue ref——属 TCB 已声明的 JS 字符串
  语义边界（密钥库说明三），不计缺陷。

---

## 四、"宣称 vs 实现"核验表

| # | 宣称 | 出处 | 实现核验 | 裁定 |
|---|------|------|----------|------|
| 1 | localStorage 零明文私钥 | keystore.ts:1、密钥库说明③ | 12 处 setItem 穷举+红测试钉定 | ✅ 属实 |
| 2 | 页面刷新/关闭=内存清零，需重新输口令 | 密钥库说明:22、keystore.ts:9 | sessionStorage 跨刷新存活 | ❌ 失真（P1-1） |
| 3 | 恢复码 120bit·去易混·仅展示一次 | 密钥库说明:14 | 探针 120.0bit+展示门控 | ✅ 属实 |
| 4 | 清空浏览器/换设备凭恢复码找回 | 密钥库说明:24、LoginView:260,322 | 信封在本机、无导出导入 | ❌ 不可达（P1-2） |
| 5 | KDF 21000=OWASP 2023 对齐值 | keystore.ts:15、密钥库说明:35 | 对最弱档仍弱 ~20×；原生 11.4ms/候选 | ⚠️ 话术失真（P2-7） |
| 6 | 强度条引导口令熵 | 密钥库说明:34 | `passphraseStrength` 零 UI 消费 | ❌ 失真（P2-7） |
| 7 | 双 KEK 任一解封+AAD 绑槽位 | 密钥库说明:16-18,41-42 | keystore.ts:17-18,69-75,92 | ✅ 属实 |
| 8 | 篡改必败不泄细节 | 密钥库说明:43-44 | KeystoreError 统一话术+红测试 | ✅ 属实 |
| 9 | 会话私钥 sessionStorage 关窗即焚 | 数据分级:14、生产文档:16 | ApplyView:367/FlightView:26 | ✅ 属实（用后不清=P3-10） |
| 10 | KMS demo=会话级、进程内持有 | 数据分级:16 | %TEMP% 六钥持久无清理 | ⚠️ 失真（P2-5） |
| 11 | 引擎令牌恒时比较 | 口径卡 C+4 | 三 router compare_digest | ✅ 属实 |
| 12 | RA 库可见方=仅登记机构 | 数据分级:13 | env 档 wrap 钥与协作函共钥 | ⚠️ 部分（P2-4） |
| 13 | 身份证号不出本机/不提交明文 | LoginView:272,220、enroll:34 | POST /ra/register 明文 id_number | ❌ 失真（P1-3） |
| 14 | 换人即被身份清扫 | material.ts:79、ChainView:100 | fzLastCaseId 漏清单+锚重置 | ⚠️ 一键之差（P2-6） |
| 15 | 【上轮 P0-2】KDF 轮数文档对齐 | B 报告 | 21000 三处一致（ts:15/说明:16,35/头注:6-7） | ✅ 已修 |
| 16 | 【上轮 P1-4】demo_up 三面随机化 | B 报告 | demo_up.py:182-184 补齐 | ✅ 已修 |
| 17 | 【上轮 P1-5】桥接公钥回落 fail-closed | B 报告 | bridge/telemetry.py:46-56 改拒绝 | ✅ 已修 |
| 18 | wasm 验证面零秘密 | 口径卡 A7 | wasmVerifyWorker 仅公开材料 | ✅ 属实 |

---

## 五、密钥域分离矩阵

SM2 域（`_derive_priv(label) = SM3(label) mod (n-2) + 1`；env 优先）：

| 域 | 派生标签 / env | 消费面 | 输出长度/用途匹配 | 撞串评估 |
|---|---|---|---|---|
| RA 凭证签名 | `FZ-KMS\|ra-signing` / FZ_RA_SK | 子凭证签发/验签（ra_pub_hex_of） | 32B 标量→SM2 ✓ | 与他域前缀互异 ✓ |
| 引擎令牌签名 | `FZ-KMS\|engine-signing` / FZ_ENGINE_SK | 令牌 sign_digest（裸摘要） | ✓ | ✓ |
| 链交易-RA | `FZ-CHAIN-SMOKE\|ra` / FZ_CHAIN_RA_TX_SK | onlyRA 写面 | ✓ | 分族命名防混 ✓ |
| 链交易-engine | `FZ-CHAIN-SMOKE\|engine` / FZ_CHAIN_ENGINE_TX_SK | onlyEngine 四写面 | ✓ | ✓ |
| 链交易-auditor | `FZ-CHAIN-SMOKE\|auditor` / FZ_CHAIN_AUDITOR_TX_SK | logWarrant | ✓ | ✓ |
| 链交易-admin | `FZ-CHAIN-SMOKE\|admin` / FZ_CHAIN_ADMIN_TX_SK | onlyAdmin（publish_pin.py:55） | ✓ | ✓（env 名漂移 P3-11） |
| 设备钥 | `FZ-KMS\|device\|<serial>` / FZ_DEVICE_SK | 检查点签名（device_key.py:35-43） | ✓ | 前缀防撞 ✓ |

对称/令牌域（`kms_domain_key(label)=SM3(label)[:16]`；`FZ_WRAP_KEY` env 优先）：

| 域 | 派生标签 / env | 消费面 | AAD | 裁定 |
|---|---|---|---|---|
| RA 实名映射 wrap | `FZ-KMS\|ra-store-wrap` / **FZ_WRAP_KEY** | id_store_cipher/wrap_secret | `FZ-WRAP` | env 档与下行共钥 ⚠️（P2-4） |
| 协作函 | `FZ-KMS\|collab-code` / **FZ_WRAP_KEY** | FZC1/FZC2 信封 | `FZ-COLLAB-v1/v2`+warrant_hash(v2) | 同上 ⚠️（P2-4）；v2 AAD 绑定 ✓ |
| 绑定挑战 HMAC | `FZ-KMS\|authz-binding` / FZ_AUTHZ_BINDING_KEY | 绑定挑战 HMAC-SM3 | —（HMAC 自带域） | ✓（P3-3 已收口 KMS 端口） |
| 审计台 API 令牌 | `FZ-KMS\|audit\|api-token` / FZ_AUDIT_TOKEN | audit 面 Bearer | — | ✓（demo 缺省 fake-audit-token 已声明） |
| RA 运维令牌 | `FZ-KMS\|ra-ops` / FZ_RA_OPS_TOKEN | RA 运维面 Bearer | — | ✓ 恒时比较在调用侧 |

浏览器域：KEK1/KEK2（口令/恢复码→SM4-128，AAD 绑 v2 槽位）与后端域完全隔离；
ECIES 会话钥一次性生成不落盘（sessionStorage 声明面）；计划盐 128bit CSPRNG。
**全局唯一性结论**：全部标签字节串互异、不可能撞串；唯一的域分离破坏点在
env 覆盖语义（P2-4），不在标签设计。

---

## 六、一句话总评

密钥库本体（密封/解封/恢复码/红测试）是可放心带上台面的资产，真正的欠账都在
**宣称面的最后一公里**——把"刷新即清零""换设备可恢复""OWASP 对齐""身份证号不出
本机"四句话改到与代码同一条线上，再堵上 `fzSessionSkUnlock` 清扫与 `FZ_WRAP_KEY`
共钥两个真窟窿，这个席位就没有能让评委追击的硬伤了。
