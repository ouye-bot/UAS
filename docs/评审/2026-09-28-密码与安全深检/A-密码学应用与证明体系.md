# 「飞证」A 席评审报告：密码学应用与证明体系（2026-09-28）

> 评审人：安全评审子代理·席位 A（密码学应用与证明体系）。干净上下文、只读评审。
> 相对 `docs/评审/2026-09-28-三代理深度评审/B-密码学专家评审报告.md`（下称"B 报"）
> 的增量纪律：只报净新增发现或"宣称已修但不属实"的核验，B 报已定谳项仅在核验表
> 引用。本轮实测手段：仓内代码实读、两枚只读 Python 探针（venv 解释器，纯数学/
> 编码行为）、活服务只读 GET（/authz/engine/pub、/verify/api/checks）、
> `publish_pin.py --check`（零副作用回读档）、`sha256sum -c`（dist 目录）。全文
> 不含任何口令/私钥明文值；演示域派生钥只写公式（如 `sm3(b"FZ-KMS|…")`）。

---

## 一、总体印象

这套系统的密码学内核**经得起逐行读**：原语层是"官方向量逐字节锚定才启用引擎、
失败回落纯实现"的双引擎纪律，且补齐了 gmssl 的真实缺陷；证明体系的语句绑定面
（实例 0 = e、实例 19-24 逐位核对）在 Python 门控与 Rust 验证器两侧**独立重导出、
同式对拍**，B 报点名的 S5[严重1] 组合攻击封堵经三代码锚核验**属实**；SMT 撤销
空洞修复（weave_proto_gates 全量翻译）在当前 vendor 快照（4201a82）中**完整在位**；
B 报五项 P0/P1 修复中有四项半**兑现且可复核**（binding.json、KDF 对齐、demo_up
六钥随机、桥接公钥 fail-closed、令牌原始字节验签）。本轮净新增的三个主要问题都
不在"密码用得对不对"，而在**绑定链的最后一级扣环**：子凭证一次性语义键在客户端
自报哈希上（P1-1）、引擎 TRAIL 绑定为未锚定的链头背书且两链编码分叉（P1-2）、
装配面验签公钥由证明者自带（P1-3）。三者共同形态是团队自己命名的"接缝"——
每一侧组件都正确，接缝处缺一道服务器/宿主侧的重算或回查。另有一枚实测探针证实
的功能性缺陷（通道②信封 SN 字段恒丢，P2-2）。

---

## 二、做得好的地方（逐条带代码锚与为什么好）

1. **原语层双引擎纪律 + gmssl 缺陷补齐，且每处都有"为什么不用现成库"的实证理由。**
   SM2 验签走 OpenSSL EVP 主径（`backend/app/crypto/sm2.py:250-321`），启用前
   三重差分锚（自签自验/篡改拒绝/错钥拒绝，`sm2.py:324-335`）全过才选通；SM3/
   SM4-GCM 同款（`sm3.py:23-32` GB/T A.1 锚、`sm4.py:294-319` RFC 8998+GB/T
   C.5 三组向量 encrypt/decrypt 双路径）。三处"库不可信"补齐均注明源码级证据：
   gmssl 随机数用 Python random（`sm2.py:422-427` 换 secrets）、gmssl ECIES
   解密不比 C3（`sm2.py:445-466` 自实现补齐）、gmssl `_sm3_z` 不收自定义 ID
   （`sm2.py:123-137`）。附加侧信道卫生：标量盲化点乘（`sm2.py:84-100`，解密
   路径 `[d]C1` 这种重复采样高危面也盖到了）、GCM tag 恒时比较（`sm4.py:143`）、
   引擎令牌/RA 运维令牌 `hmac.compare_digest`（`telemetry/router.py:38`、
   `ra/router.py:280`）。**为什么好**：这不是"用了国密"，是"用对了国密"，且每
   个决定带可复现的实测依据，答辩追问链条完整。

2. **实例 0 = e 的语句摘要钉——组合攻击封堵真实闭环（特别任务①核验通过）。**
   三锚齐全：①受理面从提交报文独立算 e 并落库（`backend/app/authz/service.py:
   277-283`，e = `digest_e_bytes(M_A′) mod n`）；②worker 把 `row.e_hex` 原样
   写进 expected（`backend/app/zk/worker.py:431`）；③zkc verify-instances 在
   后端验证**之前**逐位比对实例 0，非空即核对、不等即拒（`zksvc/src/prove.rs:
   940-953`）。数学口径两侧一致（探针实测：`fold_words = Σ dg[k]·2^{32k} ==
   int(词序倒转摘要, BE)`，`credential.py:118-129` 的 `_reverse_words` 与电路
   `fold_digest_fp` 同式）。"电路证明自签凭证 + 受理提交真子凭证"的攻击者在
   实例 0 处必撞：e(自签) ≠ e(提交的 RA 签名报文)。**为什么好**：攻击面分析
   准确（攻击者控制的是"提交哪份报文"与"证明哪份报文"两个自由度，此钉把两者
   焊死），且核对先于昂贵的后端验证（fail-fast）。

3. **SMT 撤销闭环五层防线全部在位（特别任务②核验通过）。**
   `weave_proto_gates` 全量翻译在当前 pin 快照 `zksvc/vendor/plonkish-4201a82/
   plonkish/plonkish_sm2_probe/src/sm3_lookup_weave.rs:561-648`：把 BlockCircuit
   逐组 4 约束（split1/split3/add/const）+ 8 lookup 通道按列映射翻译进 Builder，
   `assert_eq!(groups, plan.advice.len())` 与 `assert_eq!(constraints,
   groups*4)` 双断言防漏翻；AUTH 装配消费点 `sm2_full_statement_assemble.rs:
   1997`。叠加：撤销传播（主凭证吊销把未消费子凭证 pk′.x 并入叶集，
   `ra/service.py:303-326`）、签发面预检（holder_revoked 403，`ra/service.py:
   210-215`）、worker 验证窗 TOCTOU 链上复查（`zk/worker.py:460-471`）、链级
   纪元单调（`contracts/src/IdentityRegistry.sol:51-57`，`epoch ==
   revEpoch+1`）、启动对账自愈（`ra/align.py:20-40`）。**为什么好**：这是
   "漏洞→恶意见证实测→根修→红线测试→多层纵深"的完整闭环，且本轮核验确认
   修复在**当前生效的 vendor 快照**里而非历史层。

4. **fold 双口径历史雷区已单源化并显式命名。** `trail_host.rs:75-92` 把
   `fold_words_be`（词序折叠，实例钉口径）与 `fold_be_integer`（BE 整数，
   gmssl 裸摘要签名口径）定义为两个具名约定并注明"不可混用"；Python 侧
   `authz/service.py:102-110` 的 `_fe_be32_hex_from_bytes32` 与 Rust
   `fold_words_be` 逐字对齐（注释保留了"曾误写为 BE 整数口径⟹实例 23 全拒"
   的教训）。实测对拍：检查点签名（Python `sign_digest(sm3(msg))` ↔ Rust
   `fold_be_integer(sm3(msg))`，`device_key.py:46-47` ↔ `trail_host.rs:121-131`）
   与 TRAIL 绑定签名（`telemetry/router.py:206-208` ↔ `assemble.rs:229-252`）
   两侧口径一致。**为什么好**：跨语言双实现的折叠约定是这类系统最容易"各自
   对各自错"的地方，他们把它变成了带测试锚的显式契约。

5. **受理门控的编排质量高。** 七查序（`authz/service.py:129-308`）：
   ①会话钥格式**加曲线方程校验**（:152-158，注释明说防"非曲线点 ECIES 抛
   异常→毒丸申请无限重试占满 worker"的匿名 DoS——这是把密码学失败模式当
   可用性攻击面想的稀缺意识）→②子凭证验签→③nonce 链查重→③′子凭证链级
   查重→③″政策公示对拍（callable/bool 形态归一，:183-186，修掉了"恒不等于
   False⟹防线死码"的静默失效）→④电路 pin 链上对拍（:191-194）→⑤实例
   19-24 逐位核对+窗上限 clamp（`FZ_MAX_TOKEN_WINDOW_S`，:243-247）+时间锚
   新鲜度 ±slack（:254-261）+库级双兜底查重。廉价先于昂贵、每查有独立拒绝码、
   全部 fail-closed（政策未公示 409、pin 未发布=None 渐进、链不可达 503
   结构化）。**为什么好**：门控不是检查项堆砌，是带攻击模型的排序。

6. **供应链面经实测核验为真。** dist 三件 sha256 逐字节对上（`sha256sum -c`
   3/3 OK）；`/verify/api/checks` 实时计算的哈希与磁盘实物一致（无硬编码数字
   失真面）；`publish_pin.py --check` 实测回读：本地指纹
   `SM3(4201a82|a5714181…)` 的摘要 `17a90dc1…` 与链上 circuitPin **逐位一致**
   ——口径卡 A7 的"pin 指纹 17a90dc1…与链上一致"宣称在本机当前部署复现成立。
   verify-instances 不消费 vendor 树（`backend/app/verify_dist.py:8-11`）的单
   二进制复验形态也使分发站产品理由成立。

7. **B 报五项修复核验四项半属实**（详见第四节核验表）：binding.json 已随案卷
   发放并进下载白名单（`gcs/bridge/prover.py:514-519,690`）、KDF 21000 三面对
   齐（`keystore.ts:15` + `docs/密钥库安全说明.md:16-17,35-36`）、demo_up 六钥
   全随机（`scripts/demo_up.py:172-184`）、桥接公钥代理 fail-closed
   （`gcs/bridge/telemetry.py:44-63`）、令牌验签改原始字节（`telemetry.py:
   69-85`）。修复不是改注释，是改行为并带测试/断言。

---

## 三、缺陷与风险（按严重度排序）

### P1-1 子凭证一次性语义键在客户端自报哈希上——`sub_cred_hash_hex` 未与 `sm3(M_A′)` 绑定【净新增·高危·可利用】

**证据链**（全路径无一处校验哈希=报文摘要）：
- 受理面：`authz/router.py:160`（`sub_cred_hash_hex` 为客户端字段，仅注明用途）；
  `authz/service.py:177`（链级查重键）、`:266-273`（库级查重键）、`:288`（入库）
  ——三处全部消费客户端值，无 `== sm3_bytes(msg)` 复算；
- 上链面：`zk/worker.py:506→127` 把该值原样送 `recordAuth`，`worker.py:537`
  读后写对拍也是"链上 vs 原值"自洽；
- 签发面本有正确值：`ra/service.py:247` 存的 `sub_cred_hash_hex = sm3(msg).hex()`，
  但受理面从不与 RA 库内行或现算值比对；
- 链面：`contracts/src/FlightAuthRegistry.sol:54` 的 `usedSubCreds` 唯一性强
  制只对被喂入的键生效。

**攻击场景**：合法持有一张有效子凭证 (msg, sig) 的飞手，提交 N 份申请，每份
用**同一 (msg, sig)** 配不同随机 `sub_cred_hash_hex` + 新 nonce/plan_hash/窗：
门②验签过（签名真）、门③ nonce 新、门③′链级查重过（键每次不同）、门④⑤过
（每窗新鲜出证即可）→ recordAuth 每次落不同 subCredHash，链上"子凭证唯一性"
（口径卡 C3"subCredHash 唯一（二次 revert）"）与配额/消费机制（`worker.py:
595-600` 按 hash 找 SubCredential 行回写消费——找不到行，静默跳过）全部空转。
一张 24h 子凭证可铸造无上限授权。**红队 D3 与 e2e 负例全部用同一 hash 复放**，
所以两层防线都在负例中如实触发——被测形态与绕过形态不同。

**连带削弱**：协作函范围校验 `ra/scope.py:28-38` 靠 `SubCredential.sub_cred_hash
== Application.sub_cred_hash` 关联授权→凭证，伪造 hash 时返回 None =
"不可验证"（调用方按放行处理）——F 席根修的范围约束对这类记录失效。

**修法方向**（一行级）：`admission_gate` 内 `sub_cred_hash = sm3_bytes(msg).hex()`
服务端现算，与提交值不一致即 409（或直接覆盖入库值）；worker 无需改动即恢复
消费回写与 scope 关联。

**亮点化思考**：门控②的原则本来是"公开提交自证"（签名兼准入票据）——把"哈希
=服务器派生"补进去正好凑齐完整原则：**凡用作唯一性键/关联键的值，必须服务器
从已验签材料重算，不接受客户端转述**。答辩可主动讲这个原则及本例教训。

---

### P1-2 引擎 TRAIL 绑定为"未锚定链头"背书，且锚定链与语句链是两条不同编码的哈希链【净新增·宣称与实现不符】

**证据链**：
- 绑定端点只查"授权在案+政策 alt_max"，对 `chain_head_hex` 无任何链上锚定回查
  （`telemetry/router.py:186-208`：任意 64hex head + 有效 X-Engine-Token 即得
  引擎签名）；链上现成的 `TelemetryAnchor.verifyHead/anchoredHeads`
  （`TelemetryAnchor.sol:21,41-43`）全仓无消费方；
- **两条链编码不同**：锚定面 `fence.py:25` 用 `struct.pack(">Iiii",…)`（16B，
  alt 4B）；TRAIL 语句面 `prover.py:384-411` 用 `>IHii`（14B，alt 2B）——同一
  份采样序列在两条链下的头**必然不同**。TRAIL 证书实例 0 的头来自证明者域内
  14B 重放（`_trail_window_rows`），永远不等于飞行时经 `/engine/anchor` 锚到
  链上的 16B 头；
- 宣称面失真：`zksvc/src/profile.rs:108` 称 chain_head 为"链上 TelemetryAnchor
  公示，实例源"；`docs/证明体系安全注记.md` §四称"记录真实性由链头钉覆盖"——
  实现中该头从未上链，"钉"的是证明者自算值。团队在别处知情：`fence.py:5-7`
  （"两条链各自闭环勿混用"）、`scenario_S4_trail.py:126`（"真实部署=链上锚定
  值"——承认现在不是）。

**影响**：第三方拿到 TRAIL 合规证书后，实例 0 的头无法关联到任何链上锚定记录
——"锚定"语义断裂，飞行时锚定链的全部链上证据对这张证书**零约束力**。R4-P0-1
根修的核心权威（引擎签名）实际为证明者域内任意 head 背书。不构成越权放大
（alt_max 仍由政策权威供给，见 P1-3 的边界），但"第三方可复验合规证书"这一
核心卖点的证据链被抽掉一环。

**修法方向**（成本低、收益高）：`trail_binding` 端点签发前链上回查一次
`anchoredHeads(auth_id, ·)`（或 latest）确认 head 在案——一次 view call；
中期统一两链编码（或锚定窗口头本身），并在 S4 增"证书头 ∈ 链上锚定集"断言。
**亮点化**：修后可宣称"引擎只对链上锚定过的飞行记录出具高度绑定"——比现在
的口径强一档。

---

### P1-3 TRAIL 装配面三查对"证明者域内改 spec"不可防：验签公钥是 spec 自带字段【净新增·宣称需收窄】

**证据**：`zksvc/src/profile.rs:135`（`engine_pub_hex` 是 `TrailBindingInput`
字段——随 spec 由证明者供给）；`assemble.rs:228-252` 验签基准即该字段，装配
器无钉定比对、无权威注入。恶意证明者在证明者域内改 spec 的完整绕过路径：
自组 (sk_e′, pk_e′) → 对 `FZ-TRAIL-BIND|auth_id|65500|head` 自签 → 填入
`binding.engine_pub_hex = pk_e′`——三查（alt_max/auth_id/chain_head 一致性）
与签名验签全绿，出 verify-OK 证书。`docs/证明体系安全注记.md` §四"安全依赖
引擎钥在证明者域外"的表述不成立——**钥在域外，但公钥引用在域内**。团队部分
知情（`assemble.rs:580-581` 测试注释"自签公钥仅自洽不自证"），但注记正文未
收窄，且"上限不可自报"（`profile.rs:117-119`）对恶意证明者是假的。

**缓解在位（如实列出）**：诚实桥接流程中 alt_max 由 backend 权威签发并与请求
对拍（`prover.py:583-599`）；binding.json 已随案卷发放（B 报 P0-1 修复属实，
`prover.py:511-519`）+ fence×alt_max 交叉比对（`prover.py:604-617`）。但全仓
grep 证实：**没有任何脚本/分发页/测试**把 binding.json 的 `engine_pub_hex`
与 `/authz/engine/pub` 对拍（`verify_static/index.html` 只讲 verify-instances；
S4 场景无此断言）——第三方复核层"数据齐备但无工具无文档步骤"。

**修法方向**：①短期：装配器支持宿主侧权威注入钉定（如 env
`FZ_ENGINE_PUB_HEX`，不匹配即拒——诚实部署一行配置即堵死）；②把第三方复核
（binding.json 公钥对拍 + 离线验签 + 与实例 0 比对）写进 S4 断言与 `/verify/`
页步骤；③赛后挂账的"alt_max 入公开实例"是终局解（安全注记已自认 belt-and-
braces）。**亮点化**：答辩口径应改为"装配三查防配置错，权威锚靠第三方按协议
对拍公示钥——工具如下"，比含糊的"不可自报"更可防守。

---

### P2-1 worker 把 expected.json 写进证明者可写的案卷目录——本地竞态可替换期望值【净新增】

**证据**：`zk/worker.py:55-57` `expected_path = case_dir/expected.json` 后直接
起 zkc 消费；而 case 目录由桥接/证明者进程写入（`prover.py:184-189`）。能监听
目录变更的本地进程可在"worker 写入→zkc 读取"窗内覆盖 expected.json，使实例
核对对攻击者选的期望进行——伪造证明配自选期望即可过最后一道验证（受理门控
与 DB 绑定全部被绕过）。演示拓扑中 bridge 与 worker 同机，攻击者若控制桥接
进程即持有此能力。

**为什么只是 P2**：需要本地文件系统竞速（非远程可利用）；且桥接进程本就在
TCB 边界讨论范围内。但"验证器最后一道的信任输入写在不可信目录"是明确的卫生
缺陷。

**修法**：expected 写 worker 私有临时目录（`tempfile`），或 zkc 增加
`--expected-stdin` 从管道读。一处改动消除整类竞态。

---

### P2-2 通道②信封 v3 版本字节从未写入、解锁判断恒假——SN 字段恒丢（实测证实）【净新增·功能性/宣称失真】

**证据**：写入面 `ra/service.py:141-150` 用 `b"" + username|id_number|sn|handle`
（注释却称"版本字节 0x01 + 四段"）；解析面 `ra/service.py:360-364`
`if plain[:1] == b"":`——对非空明文**恒为 False**，v3 信封恒走旧 3 段分支：
`sn_b = b""`，`_handle` 实际吃进 `sn|handle` 串。同文件的
`_open_store_envelope`（:387-394，按 `len(parts)==4` 正确解析）是死代码，
warrant_unlock 未复用。**探针实测**（venv 直调 wrap/unwrap+解析逻辑）：v3 信封
解析输出 `sn=''`、尾部 `SN-001|<handle>` 被并入 handle 位。

**影响**：令状解锁返回的 sn 恒为空——"解锁后设备交叉审计的数据源"（通道②
v3 的立项理由，`ra/service.py:140` 注释、口径卡 C4 链路）在实现上断裂。
username/id_number 仍正确，非机密性/完整性漏洞，但属"宣称的数据面不存在"。

**修法**：写入 `b"\x01" + …` 且判断 `plain[:1] == b"\x01"`；或直接改调
`_open_store_envelope`（顺带消掉死代码）。存量密文（无版本字节）按 4 段/3 段
长度判别兼容即可。

---

### P3（卫生与低危）

- **P3-1 info 磁盘缓存内容无认证**：`prove.rs:784-836` 缓存键全公开可算、命中
  即信、仅反序列化失败自愈——有验证方磁盘写权限者可投毒电路结构 info，配合
  自备 vp/proof 使 verify-instances 通过（语义门 expected 仍在服务侧，第三方
  场景 expected 随案卷投递时暴露面更大）。修法：缓存键纳入内容 SM3 或落盘
  前后带 MAC；列 P3 因需本地写权限。
- **P3-2 畸形 hex 入参 → 500**：`authz/service.py:160,170` 及 `:177` 的
  `bytes.fromhex` 在奇数位/非法 hex 时抛 ValueError，router 只捕
  AuthzError/ChainError（`authz/router.py:202-207`）⟹ 应为 400 的输入得到 500
  裸奔。修法：ApplyIn 增 hex 形态校验或门控内包一层。
- **P3-3 注释/文档陈旧三处**：`credential.py:8-10` 模块 docstring 仍是 51B 旧
  布局（实现为 55B v3，函数 docstring 正确）；`ra/smt.py:47` 注释"前 64bit"
  实取 32 位（DEPTH=32）；`zksvc/src/assemble.rs:8-11`/`profile.rs:7-9` 头注
  AUTH 结构锚 104,543/11,448/536 与口径卡 B1"现行 census ~38.2K/10,380/546"
  两代并存（**未定谳**孰为现行——验证法：跑 zksvc auth 族 census/cargo test
  对账；口径卡 B1 自述 104,287→44,383→~38.2K 演进，头注停在 09-23 R2 代）。
- **P3-4 口径卡 vendor 数字两代并存**：B3/C2 仍写"b381127 / aggregate
  d979770e…"，而当前 pin 实测为 `SM3(4201a82|a5714181…)`（`--check` 链上一
  致）。属 W-2 换代后未回写——与 B 报 P1-7 同族的"文档数字 grep 代码"缺巡检。
- **P3-5 内存/会话明文面残留**：`sm2.py:103` `_pub_cache` 以明文私钥 hex 为键
  （B 报 P2 残留，未清）；`keystore.ts:176` sessionStorage 明文 sk 缓存仍在且
  `密钥库安全说明.md` 未补该边界（B 报 P1-3 未处理，唯一未兑现项）。

**演示可接受边界（不再计分，与 B 报一致）**：r≡2 常量（C+1）、RA/授权合谋
去匿名（E2）、pk′ 出示层可链接（C3）、设备钥=桥接模拟（E1）、检查点验签不进
电路（B6-d8′）、`/ra/ops-token-hint` 缺省档返回可推算令牌（诚实标注 demo 语义）。

---

## 四、"宣称 vs 实现"核验表（红先绿后）

| # | 宣称 | 宣称出处 | 核验结论 | 关键证据 |
|---|------|---------|---------|---------|
| 1 | 实例 0 e_hex 封死"电路自签凭证+受理提交真凭证"组合攻击 | 安全注记/service.py:278 注释 | **属实**（特别任务①通过） | service.py:277-283 → worker.py:431 → prove.rs:940-953 三锚闭环；fold 口径探针实测一致 |
| 2 | SMT 撤销空洞修复（weave_proto_gates 全量翻译）在当前代码完整 | 口径卡 B4 | **属实**（特别任务②通过） | vendor 4201a82 `sm3_lookup_weave.rs:561-648`（4 约束×64 组+8 lookup 通道+组数 assert）；调用点 `sm2_full_statement_assemble.rs:1997` |
| 3 | TRAIL alt_max 引擎绑定三层，"上限不可自报" | 安全注记 §四/profile.rs:117 | **部分失真**（特别任务③） | 装配三查在位但公钥 spec 自带⟳P1-3；binding.json 已发放（B 报 P0-1 修复属实）但无第三方对拍工具；head 无锚定回查⟳P1-2 |
| 4 | B 报 P0-1：binding.json 随案卷发放 | B 报 | **已修属实** | prover.py:514-519 写入、:690 下载白名单、行程索引 artifacts 列表 |
| 5 | B 报 P0-2：KDF 轮数宣称-实现对齐 | B 报 | **已修属实** | keystore.ts:15 = 21_000，头注/文档三面统一（21000），并留 60000+ 演进项 |
| 6 | B 报 P1-4：demo_up 缺省钥全随机 | B 报 | **已修属实** | scripts/demo_up.py:172-184 六钥 token_hex/token_bytes 注入+落盘指引 |
| 7 | B 报 P1-5：桥接公钥回落改 fail-closed | B 报 | **已修属实** | gcs/bridge/telemetry.py:44-63（代理模式 backend 不可达即 RuntimeError 拒 ARM） |
| 8 | B 报 P1-6：令牌验签对原始字节 | B 报 | **已修属实** | telemetry.py:69-85（split_token 返回 body_raw，e=sm3(body_raw)） |
| 9 | B 报 P1-3：sessionStorage 明文 sk 边界 | B 报 | **未修未声明** | keystore.ts:176 仍在；密钥库安全说明.md 无 sessionStorage 字样 |
| 10 | 电路指纹链上公示 fail-closed（C2/A7） | 口径卡 | **属实（实测）** | publish_pin --check：本地 `17a90dc1…` 与链上逐位一致；门④ service.py:191-194 |
| 11 | 撤销即时分层防线（传播/预检/TOCTOU/纪元单调/对账） | 口径卡 B4 | **属实** | ra/service.py:303-326/:210-215、worker.py:460-471、IdentityRegistry.sol:51-57、align.py:20-40 |
| 12 | 检查点/绑定签名 fold 口径两侧一致（D4：改 1 字节验签必败） | 口径卡 D4 | **属实** | device_key.py:46-47 ↔ trail_host.rs:121-131（fold_be_integer）；telemetry/router.py:206-208 ↔ assemble.rs:229-252 |
| 13 | 一次性令牌+同会话重解锁例外 | 口径卡 E4 | **属实** | sitl_link.py:484-509（token_used 拒二次；重解锁仅 `is_armed ∧ fc 未 armed` 窄门） |
| 14 | D3 子凭证一次性（库级+链级双拒） | 口径卡 D3 | **部分失真** | 防线真实但对"换 hash 变体"全空转⟳P1-1 |
| 15 | 通道② 信封 v3（SN₁ 设备交叉审计数据源） | ra/service.py:140/口径卡 C4 | **失真（实测）** | 版本字节未写+判断恒假⟳P2-2，sn 恒空 |
| 16 | 分发站 sha256 与指纹一致性声明 | 口径卡 A7/verify_dist.py | **属实（实测）** | dist sha256sum -c 3/3 OK；/verify/api/checks 实时值与磁盘一致；pin 链上一致 |

---

## 五、一句话总评

密码学内核与证明绑定面（e_hex 钉、SMT 全量翻译、fold 双口径、pin 供应链）是
参赛作品中罕见地经得起"逐行+探针"复核的，B 报修复兑现率高；本轮把三个"最后
一级扣环"（一次性键的服务器重算、TRAIL 头的锚定回查、装配验签钥的权威钉定，
外加一枚 SN 字段丢失的实测 bug）补上后，这套系统的宣称面才能真正追平它已经
做到位的实现面。
