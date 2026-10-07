# A · 密码技术安全性与创新性 / 整体性能优化规划 —— 深度评审报告

- 评审人：三代理评审 · A 席（密码工程 + 性能）
- 日期：2026-09-24；方式：只读深读源码 + 定向单测 + 纯计算验证（未改任何业务文件、未跑 e2e、未碰服务与链）
- 路径基准：下文 `uas/` = `C:\Users\联想\Desktop\Meeting\uas\`；`vendor/` = `uas/zksvc/vendor/plonkish-7e0e1a7/plonkish/plonkish_sm2_probe/src/`；`bkd/` = `uas/zksvc/vendor/plonkish-7e0e1a7/plonkish/plonkish_backend/src/`
- 判据纪律：每条发现均以实际读到的代码行为证据；两处 P0 用可复现脚本/单测形态验证后才下结论。

---

## ① 理解综述（≤300 字）

飞证 = 国密全栈（SM2/SM3/SM4）+ 自研透明 SNARK（Basefold+HyperPlonk 改，reps=16/log_rate=1，setup 种子公开常数、无 trusted setup 属实）+ FISCO BCOS 留痕。AUTH 语句六件套（SM2 验签体 16,554 约束零接触复用、C=SM3(salt‖cert‖class‖id‖sn_h) 布尔单块、θ 范围门、exp≥T、ctx_tag/pred_id 绑定钉、深度 32 SM3-SMT 非成员）；TRAIL 逐样本高度/时间/链头钉。电路为自研 Builder 的 plonkish 形态（环=复制等值、查表=logUp 族），R2 刚封堵 SMT 撤销"约束/lookup 空洞"并清偿 1,609 死列。性能基线：AUTH 本机 prove 97.59s/verify 3.74s（结构 104,543/11,448/536，σ 4,133 列、环 1,029,439）；TRAIL 服务器 14.77s。工程纪律（判决行、PinDrift、负例一等公民、先红后绿）明显高于竞赛均值；但撤销语句的**键域错位**与两处宣称溢出是硬伤。

---

## ② 分级发现

### P0（致命——宣称与实现存在结构性断裂）

**P0-1 撤销"即时生效"的语句键域错位：SMT 非成员检查对被吊销主凭证恒真。**
- 证据：
  - 电路语句键 = pk′.x（`vendor/smt_weave.rs:1-26` 深度 32、键=pk′.x；`smt_weave.rs:176-179` `key_bits_of` 取 key_be[..4]；`uas/zksvc/src/assemble.rs:365-379` smt_siblings/smt_root 装配）；
  - 撤销集写入键 = master_cred_hash=SM3(C)（`uas/backend/app/ra/service.py:259-264`：`Revocation(handle_hex=cred.master_cred_hash_hex…)`、`root=smt_root(handles)`）；
  - 见证分发键 = pk′.x（`uas/backend/app/ra/router.py:203-205`：`key=bytes.fromhex(holder_pk_hex[:64])`，对 handles=master_cred_hash 集合算非成员）。
- 为什么致命：pk′.x（随机椭圆点坐标）与 master_cred_hash（摘要值）属于不相交值域，"pk′.x ∉ 吊销集"对任意飞手**恒真**——64 组 SM3 链在数据上是常数 DEFAULT 链的忠实重算，撤销语义对"已签发未消费的子凭证"完全不设防。链上公示根、门控④比对、电路 root.fold 全部在正确地验证一个空洞谓词。`contracts/src/IdentityRegistry.sol:4` 的宣称"被吊销者下一次申请即被 AUTH 电路数学拒绝"与 `docs/答辩口径卡.md` B4 在真实数据流不成立；红队记录与 `vendor/sm2_auth_assemble.rs:512`（`auth_smt_forged_root_vacuity_red`）封堵的是"恶意证明者重写见证"，不是键域错位。成员句柄负例（`sm2_auth_assemble.rs:479` 起）用 handle 当 key 的测试形态自洽，恰掩盖了生产形态。
- 实际残余防线（缓解非根治）：RA 签发期 `cred.status==2` 拒新签发（`ra/service.py:201-202`）+ 子凭证 TTL≤24h/配额 20（`ra/service.py:32-33`）。被吊销者已持有的子凭证在 TTL 内仍可正常出证拿令牌。
- 修法（二选一，推荐 a）：
  a) 数据层传播：`revoke` 时把该主凭证名下全部未消费 SubCredential 的 `holder_pub_hex`（pk′.x）作为句柄并入吊销集再推根（`ra/service.py:revoke` 约 +10 行）；witness 端点不变；新增 e2e 负例"吊销后旧子凭证出证必拒"。
  b) 语句层换键：SMT 键改为电路内已计算的 handle=SM3(C)（C 已在 (S7) 电路内，但需再串一条 SM3，+64 组代价，赛中不划算）。
- 工作量：a ≈ 0.5–1 天（含 e2e 负例与根重发）；b ≈ 3–5 天。

**P0-2 host↔电路 SMT 位序镜像：撤销集一旦含真实键，诚实证明者将无法出证（与 P0-1 联动的正确性地雷）。**
- 证据：
  - host 树（`uas/backend/app/ra/smt.py:46-56` `_path_bits`/`_leaf_pos`、`:103-125` `verify_non_membership`）：位置 pos=handle 前 32bit 的整数，**叶层消费 LSB（handle bit31）、根层消费 MSB（handle bit0）**（d=32 首轮 bit=`leaf_pos>>0&1`）；
  - 电路链（`vendor/smt_weave.rs:66-98` `smt_blocks`/`assemble_chain` + `:176-179`）：**块 0=叶层消费 MSB（`(v>>(31-i))&1`，i=0 为 bit0）**——恰好镜像。
- 为什么致命：本评审用 backend venv 纯计算复现：同一 handle/兄弟列表下，host 根 `3e356f75…` ≠ 电路序链根 `4035cafe…`（DIVERGE）。当前全链 e2e 仍绿，只因空树 DEFAULT 链 cur==sib 对称、位序不可见；即便按 P0-1a 修了数据层，只要证明者路径近邻出现非默认兄弟（真实撤销集下必然存在），诚实见证的电路链根≠host 根 ⟹ root.fold 违约 ⟹ 好人被拒。
- 修法：统一方向（推荐改 `smt_weave.rs::key_bits_of`/`smt_blocks` 为 LSB-at-leaf，与 smt.py 一致；或反向改 smt.py，二选一）→ 更新黄金向量 → vendor 换代 repin。DEFAULT 链对称，空树根不变。
- 工作量：0.5 天（含差分对拍与 repin 仪式，仪式本身 R2 已演练过）。

### P1（严重——宣称溢出 / 语义死链）

**P1-1 "D18 逐次不可链接"宣称溢出：apk 公开实例 ⟹ pk′=apk−pk_I 任何人可恢复，授权服务跨申请可关联同一设备身份。**
- 证据：E10 六实例钉 12..17=C₁/C₂/apk（`vendor/sm2_full_statement_assemble.rs:1346-1369`：`set_instance(12+k…)` 含 `w.apk.0/.1`），实例 3=pk_I（`sm2_verify_assemble.rs:299` P_A.x 钉=实例 3）；apk=pk′+pk_I（`vendor/sm2_auth_assemble.rs:88-90` `witness_from_auth`）；pk′=浏览器长期身份钥跨申请复用（`uas/gcs/web/src/views/ApplyView.vue:307-318` `holder_sk_hex: getCachedSk()`、`material.ts:5` 绑定 `storedPk()`）。
- 为什么严重：谁拿到 instances.json（受理面/worker/判决件目录），做一次域内点减法即得该飞手设备公钥——RA 侧登记的是同一把 `user_pub_hex`（`ra/service.py:106-107`），两信任主体无需合谋即可以 pk′ 为join键关联"申请↔登记"。`docs/答辩口径卡.md` C3 标题写"逐次不可链接（D18）"，判据却只给了"链上 11 元组无 sn/身份 + subCredHash 唯一"——链面证据为真，标题宣称溢出；E2 诚实边界只声明了"设备层可链接"，而 apk 面是**身份层**链接。
- 修法：短期（0.5 天）把 C3 口径收窄为"授权记录层不可链接（链上零身份/subCredHash 逐次全新），出示公钥层可链接——一次性出示钥/盲签=R4"；长期 R4：每申请一次性 sk′（需改 keystore/签发流，赛后）。

**P1-2 ElGamal 盲化因子 r 恒为常量 2：C₂ 可被任何人去盲，承诺机制名存实亡。**
- 证据：`vendor/sm2_auth_assemble.rs:86` `r: [2, 0, 0, 0]`（注释自认"r 字段占位 2 不进报文"）；E9 消费 `w.r`（`sm2_full_statement_assemble.rs:1121-1130` r_bits 种子、C₁=r·G 循环 `:1153`、C₂=Id·G+r·apk `:1284-1302`）；同文件测试 `:3296` 却断言"第二见证 ElGamal r 必须不同"——实现与自家测试意图自相矛盾。
- 为什么严重：r 公开恒定 ⟹ Id·G=C₂−2·apk 人人可算。id′ 每次全新（`ra/service.py:216`）故**无新增跨申请链接**（主链接仍是 P1-1 的 apk），但 (C₁,C₂) 的 Pedersen 型盲化完全失效、语句里 257 步 ×2 条 EC 循环在保护一个常数，且答辩若被追问"r 哪来的随机性"无从落地。
- 修法：装配/spec 增加 `r_hex` 输入面，桥接 CSPRNG 生成 r∈[1,n−1]（`uas/gcs/bridge/prover.py` + `uas/zksvc/src/assemble.rs` + 装配三面小改，黄金向量换代）；或文档明确 C₁/C₂ 仅语句绑定非匿名机制并删注释。0.5 天（前者）。

### P2（中等——论证缺口 / 漂移风险）

**P2-1 D18 Phase 3 掩蔽（协议层 HVZK）缺形式化论证，仅实验级支撑。**
- 证据：掩蔽实现完整且 FS 序正确（承诺先于 β/γ/α/y/ρ：`bkd/backend/hyperplonk.rs:236-255,284-318,379-397`；验证方 λ 去掩 `bkd/backend/hyperplonk/verifier.rs:32-101`；熵源纪律 OsRng `:244-247`）。但 ZK 论证=小档实验对拍 `phase3_sumcheck_msgs_linear_residual`（`hyperplonk.rs:662-774`，k=3）与跨证明新鲜度门（`:594-659`）。缺：m→sumcheck 轮消息函数族的覆盖性/秩论证（k=12 时消息坐标 ~60 个、m 熵 4,096 值，直觉充分但无成文理由）。
- 修法：写一页安全注记（模拟器构造=witness-0+fresh m，逐轮消息分布重合的条件与验证），或补 k=8 档统计检验入 check.sh。0.5 天。

**P2-2 reps=16/log_rate=1 无成文具体安全预算。**
- 证据：参数类型级钉定（`uas/zksvc/src/profile.rs:22-23`、`uas/zksvc/src/prove.rs:39-57`）；透明性属实（编码表/公共盐链由调用方种子派生、种子为公开常数 `prove.rs:64`，`bkd/pcs/multilinear/basefold.rs:302-335`）；且 #27 修复记录在案（`basefold.rs:3539-3542`：reps>1 验证断言曾与 prover 矛盾）。缺：Basefold knowledge-soundness 在 (ρ=1/2, t=16, |F|≈2^254) 下的具体界与文档化（答辩卡/性能档案均无）。
- 修法：按 Basefold 论文定理给参数化估计写入性能档案新节+论文附录。0.5 天，纯文档。

**P2-3 KMS demo 缺省钥=公开可推算（SM3(公开 label) 直接当私钥）。**
- 证据：`uas/backend/app/kms/__init__.py:28-33` `d=SM3(label)%(n−2)+1`；RA/engine/链/审计/api-token 全域同法（`:25,43,53,58-69,99-116,125-131`）。文档说"演示确定性/非生产凭据"（`:4-7`），但没点破**任何人都能重推 RA/引擎签名私钥**——评委现场若追问"你的 RA 钥现在安全吗"，现状是可被冒充签发。
- 修法：缺省改为首启 CSPRNG 生成+`FZ_WRAPPED_SK` 封存落盘（keystore 已有 SM4-GCM 同构件）；最低成本=demo_up 启动横幅+答辩口径一句"演示钥公开可推算，生产 env/HSM"。0.5 天。

**P2-4 受理门控与 worker 的 required_level/policy_version 双实现漂移。**
- 证据：gate 用 `get_rule(class_id)`（`uas/backend/app/authz/service.py:192-196`）并逐位核对实例 22；worker 却是 `required_level = get_rule(row.class_id)[1] if row.class_id in (0,1) else 0`（`uas/backend/app/zk/worker.py:317`）。当前 `CLASS_RULES` 只有 {0,1}（`uas/backend/app/authz/policy.py:21-24`），else 分支是死代码；一旦扩表（小型/中型），worker 期望 θ=0 ≠ 实例 22 ⟹ 白白跑完 22s 验证后假拒。同族：gate 落库 `policy_version=""`（`service.py:284`）、worker 兜底硬编码 `"policy-2026-09-v1"`（`worker.py:324`）。
- 修法：worker 直接 `get_rule`+消费库内 policy_version；删两处特判。0.5 天。

### P3（改进）

- **P3-1** `ra/smt.py:6-8,46-49,85-100` 文档自相矛盾："路径=键前 64bit/64 兄弟"与实际 32bit/32 兄弟（`DEPTH=32`、`range(DEPTH)`）；P0-1 修复时顺手清理。1h。
- **P3-2** `MASK_OFF` 环境旗标可静默关闭全部 ZK 掩蔽（`bkd/backend/hyperplonk.rs:243-254`），verdict.json 不记录掩蔽态——运维踩到即全局可链接且不可检。修：verdict 增加 `mask=on/off` 字段 + 置位时 stderr 黄条。1h。
- **P3-3** 绑定挑战 HMAC 密钥=公开常量（`uas/backend/app/authz/service.py:113` `SM3(b"FZ-KMS|binding-secret")`）⟹ HMAC 退化为纯 SM3。当前安全模型无损（挑战本就回传+服务端重导出核对），但结构误导读者。1h。
- **P3-4** `uas/zksvc/src/prove.rs:63-66` "固定种子=证明字节级复现锚"注释与 D18 OsRng 掩蔽矛盾（性能档案 R1 已自证"证明本就不逐字节复现"）——过时注释会在答辩逐行读码时变成把柄。0.5h。
- **P3-5** `uas/backend/app/authz/router.py:201` `session.get(type(app_row).__mro__[0], app_row.id)` 无效兜取（结果仅 noqa）——清理。0.5h。

### 宣称核实速览（B1~B5/D18/透明证明）

| 宣称 | 判定 |
|---|---|
| B1 电路结构/性能数字 | **属实**（结构锚 104,543/11,448/536 与 `uas/zksvc/src/assemble.rs:8-11` 一致；R2 端到端判决行自洽） |
| B3 SM3 查表化 58.9× | **属实但口径=约束数比**；wall-clock 实测 122.17s→49.36s（`vendor/sm3_lookup_weave.rs:26-31` 判决行），论文表述应并列表述两者 |
| B4 撤销即时进电路 | **机制在、语义断**（P0-1/P0-2）：电路对"键∈正确域"的强制性是真的，对"被吊销的凭证"是空的 |
| B5 内存工程（−46.2%/103.9×） | **属实**（R1 归因表+消费面审计闭环，`docs/性能档案.md` R1 节，四件改动有代码对应） |
| D18 逐次不可链接 | **链面真、身份面溢出**（P1-1）；证明字节不可链接属实（OsRng 盐/掩蔽+`phase3_mask_freshness_fixed_seed_two_proofs` 门） |
| 透明证明（无可信设置） | **属实**：setup 全由公开常数种子派生（`prove.rs:64` + `basefold.rs:302-335`），无陷门；但缺 soundness 预算文档（P2-2） |
| 透明 SNARK 创新定位 | 查表 SM3 电路=成熟技术（4-bit limb+lookup，国际 halo2/zkWasm 同族先例）的**高质量工程移植+自研织入框架**（环合并/影子行/weave_proto_gates 抽象是自己的）；SMT 入电路=标准构造集成；Basefold+HyperPlonk 选型本身非首创。竞赛国内线属第一梯队；"国际水平"表述宜限定为"同类语句的完整生产化"而非算法创新 |

---

## ③ 性能与安全路线图

### 3.1 基线与逐段归因复核（仍成立的骨架）

AUTH 本机 97.59s 的构成（R1 探针比例 + R2 结构变动折算 [推得]）：sumcheck ≈44s（约束数 104,543 × 2^12 行，主导项）≈45%；见证掩蔽+组承诺 ≈28%；batch_open ≈26s（29,600 对，R2 后 +512 通道的对冲已体现在 97.59s）；evals ≈10s；permutation_z ≈7s。隐性性能债四件：4,133 σ 列（≈1.6GB σ 承诺载荷）、1,029,439 环（出度 1 的"一次消费"wire 占大头）、assert.zero 族 6,497 列（跨 gadget 无共享的通用门列）、lookup m/h 列 1,072（536×2，全部承诺+掩蔽+开口）。TRAIL 侧：本机 297s 是测试 harness 形态伪影，权威口径=服务器 14.77s；其 m/h=2,048 列占承诺列数 ~20%，是 TRAIL 侧最大可压缩项。

### 3.2 赛内可落地（按 收益/工作量/风险 排序）

| # | 动作 | 量化预期 | 依据/风险 |
|---|---|---|---|
| 1 | 服务器窗 R2 复测 + 服务器 RAYON 扫参（8/12/16） | 把"≈27s [推得]"变 [实测]；RAYON 4→12 服务器档约 −5~15%（本机扫参 4→12 提速 28% 类推） | `docs/性能档案.md` R2 ③②声明待办；零风险，0.5 天 |
| 2 | **(S7) 承诺块布尔 SM3 查表化**：`plan_z_parts_single` 的 C=SM3(salt‖…) 单块（≈60K 约束，B2 solo 基线 60,212/1,315 列）改为 LUT 组（weave 机制现成，+1 组=+34 列+8 通道） | 约束 104.5K→≈45K ⟹ sumcheck ≈44s→≈19s [推得，按约束线性]；advice −~1.2K 列 ⟹ commit/open −3~5s、内存 −0.5~0.8GB；**prove 97.6→≈70~75s（−23~28%）** | 本评审对 104.5K 的家族分解（验签 16,554+EC 六循环 ~20K+布尔 C 块 ~60K+杂项）与总量闭合；工作量 2–3 天；风险中（同一 vendor 换代+repin 仪式 R2 已演练） |
| 3 | lookup 通道合并（与 #2 同批换代）：全表族 XOR3/MAJ/CH 合一条宽通道（联合表逐行一致保持 soundness）、SPLIT1/SPLIT3 合一 → 8→5 通道/组 | lookups 536→≈340，m/h −400 列：AUTH −1~2s；TRAIL −768 列 ≈ prove −10~15% [推得] | 表域不匹配故不能全并（XOR2/SPLIT/RANGE 是稀疏表，合并进宽元组仍逐行绑定，安全）；1–2 天 |
| 4 | 安全收口三件（P0-1 数据层 + P0-2 位序 + P2-4 漂移） | 撤销语义真实化；防"好人被拒"展示事故 | 见 P0/P2；合计 2 天，先于任何出证演示 |
| 5 | 口径收口（P1-1/P2-2/P2-3 文档面） | 答辩无懈可击化 | 1 天 |

赛内**放弃**项及理由：v3b 全量列压缩（11.6K→7.7K，−19s [推得] 但需跨 gadget 布局重排 3–5 天、赛期回归风险大——留给赛后）；行域共享（同上，且动 σ 结构）；SMT 深度减半（32→16 改变语句键域=语义变更+收益 <7% 列数，违反"不改语句"红线）；reps/log_rate 降参（安全红线）；分布式/硬件 prover（远期）。

### 3.3 赛后路线（择要）

① wire→线性约束替换出度 1 的复制环（环 1.03M 预计 −30~50%，σ 列与 preprocess 同步缩）；② v3b 全量列压缩+行域共享；③ sumcheck 轮内并行/向量化与 batch_open 懒重编码（消费面审计已证码字开口期必需、bh 可弃）；④ 掩蔽列流式驻留（sumcheck 后弃明文副本，−1.7GB）；⑤ R4 一次性出示钥/盲签（连根解决 P1-1）；⑥ SMT 撤销键语义的电路级终态（键=SM3(C) 入电路）。

---

## ④ 亮点（≤100 字）

判决行纪律、PinDrift 供应链守卫、负例一等公民与"先红后绿"复盘是真功夫；R2 用普查仪器自己挖出并封堵 SMT 空洞（vacuity 红线测试）是全系统最像专业 ZK 团队的一幕。透明 SNARK 选型与内存归因-消费面审计方法学扎实，值得在答辩中前置展示。
