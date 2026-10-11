# SM2-OPAQUE 归约论证（修订版 v2——对照独立评审十条清单逐项修订，2026-10-11）

> **版本状态**：本文件=docs/SM2-OPAQUE归约论证.md（v1，提交 be93674，评审 **NO-GO**
> 留档）的**修订版**，按评审修订清单十条逐项对应修订，供复评。v1 原样保留作 NO-GO
> 历史依据。诚实红线延续：论证写不到位的环节继续如实标『归约缺口』（§10），本修订的
> 目标=宣称与证据精确对齐，不以含糊其辞过关。
>
> **文献核对声明**：本修订已于 2026-10-11 联网核对三项规范原文（rfc-editor.org）：
> RFC 9807『The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE)
> Protocol』（2025-07，IRTF/CFRG）、RFC 9380『Hashing to Elliptic Curves』、RFC 9497
> 『Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups』（2023-12，
> Davidson–Faz-Hernández–Sullivan–Wood）。文内引文与节号为核对后原文。

## 修订对照表（评审发现 10 条 → 修订动作 → 所在章节）

| # | 评审发现（v1 病灶） | 修订动作 | 所在章节 |
|---|---|---|---|
| 1 | 规范本体错：OPAQUE=RFC 9807 被全篇混指为 RFC 9380（hash-to-curve 规范） | 两文献职责分账成文，全篇引用逐处更正（OPAQUE 协议/信封/AKE→9807；H2C/SSWU/hash_to_field→9380；OPRF 套件→9497） | §1.1，全文引用点（§0/§2/§3/§4/§5/§8） |
| 2 | Z 选取四准则丢二改二（写成『g(Z) 非平方且 g(-b/(Z·a)) 非平方』——丢 c2/c3，把 c4 的『g(B/(Z·A)) 为平方』改自造变元） | RFC 9380 §6.6.2 四准则原文重写；SM2 曲线上满足四准则的具体 Z 值**求解钉定 Z=−9**，附全锚点验证+P-256 交叉验证+淘汰轨迹 | §3.2（复现脚本附录 A） |
| 3 | hash_to_field L 参数钉 64B（实拆 2×32B）⟹ mod-p 统计偏差 ≈2^−32 | L=48B/元素（双元素 96B）按 RFC 9380 §5 公式；统计距离 2^−32→2^−128 修正账 | §3.3 |
| 4 | RO 构成缺 Q0+Q1 求和步（只有单点 map） | RFC 9380 §3 六步全序成文（u=hash_to_field(msg,2)→Q0→Q1→R=Q0+Q1→clear_cofactor） | §3.4 |
| 5 | OMDL 非严格：GGM 骨架示意、无博弈级定理与归约器构造 | 升级为游戏跳跃式归约：实验定义→引理 1（RO 编程完美模拟）/引理 2（adaptive→静态挑战集 self-reducibility，含预算等价）→GGM 计数定理+逐跳损失账+假设命名分账（One-More 族/JKK14/TCRSTW21/RFC 9497）+Cheon 加速注记 | §2.4 |
| 6 | invalid-curve 点校验缺席（非恒时乘法器遇非曲线点可被逐位提取 k），应升格为 Evaluate 前置条件并引仓内 _kg_blinded | 升格为协议规范本身的安全前置条件（规范条目 O-1~O-3，非测试项），引 `backend/app/crypto/sm2.py:98-113` `_kg_blinded`，并如实划清『盲化≠替代校验』边界 | §2.3（测试面联动 §9） |
| 7 | D5 低估 AKE 前向保密 essential——无 PFS 现状代入则复合体不满足 RFC 9807 定理前提 | 方案 A（SM2 临时-临时 ECDH 增补，设计草图+六项新增证明义务清单）与方案 B（诚实收缩宣称+精确措辞）**两案都成文**；利弊分析后**推荐方案 B** | §8（§0.2 宣称同步收口） |
| 8 | D6 漏 masked_response 防 enumeration 掩码机制分析；mode-B（服务端持 Protect(rwd)）KCI/内部人新面无分析 | masked_response 机制+防枚举论证成文；mode-A/mode-B 新面逐项分析+形态推荐 | §5.4/§5.5 |
| 9 | KEK 链双公式矛盾+双重 Harden 次序不唯一；迁移主体写反（应客户端域）；旧 blob 删除语义未钉死；/auth/keystore 无鉴权无限流 | rwd→KEK 派生链钉定单公式唯一序（§5.3）；迁移主体纠正为客户端域；旧密封层删除语义+不可逆点钉死；/auth/keystore 写成实施前置注记（不改代码） | §5.3/§7.2/§7.3 |
| 10 | k_oprf 同泄退化情形未入缺口清单 G | 新增 G9 入清单+条件性致命分析+缓解边界 | §10 |

---

## 0. 背景与精确宣称对账

### 0.1 残余面（v1 结论维持——评审公允记录确认）

现行「服务端零口令材料」的精确含义：服务器不存口令哈希/明文，但**存口令派生的密封
件**——私钥/身份资料以密码 KEK（PBKDF2-HMAC-SM3(pass, salt, 600k) 派生 16B KEK）
经 SM4-GCM 密封（v4 信封）存于 `accounts.sealed_blob`。该形态的残余面：**拖库离线
字典攻击**——攻击者拿库（sealed_blob+salt）后可对候选口令逐个离线执行 KEK 派生+
GCM 解封试错（GCM tag 即口令正确性 oracle），600k 轮只提高单次成本，不改变离线可
枚举的结构。

OPAQUE（**RFC 9807**）的结构性消灭原理：口令→随机化口令串的派生需**服务端 OPRF
私钥 k_oprf** 参与盲化求值；拖库者拿走 credential file 却拿不到 k_oprf，任何离线
候选都无法验证——字典攻击被迫转为在线（每候选一次交互，受限速/审计面覆盖）。

### 0.2 精确宣称（本修订钉定——与 §8 方案 B 联动）

**达成宣称**（每条挂证据）：
1. 拖库面（仅得 DB，未得 k_oprf）⟹ 离线口令验证 oracle 消失，字典攻击被迫在线化
   ——证据：§2.4 归约（GGM 计数定理+引理+损失账）。
2. KCI 型性质：服务器侧妥协（DB+信封，无 k_oprf）不足以冒充客户端——客户端私钥
   在信封内、需 rwd 解封，rwd 需在线过 OPRF 门（对应 RFC 9807 §10.2 对 KCI 的
   语义「Even upon compromise of the server, the attacker cannot impersonate the
   client to the server without first running an exhaustive dictionary attack」——
   本方案中该字典攻击=在线形态）。
3. 响应不可区分（防 username 注册状态枚举）——证据：§5.4 masked_response 分析
   （RFC 9807 §6.3.1/§10.9 机制对齐）。

**不宣称**（诚实收缩——收口 v1 的 aPAKE 级含糊）：
> 本复合体安全等级=「OPRF 核心加固的口令门+信封保护+SM2 挑战-应答认证」，**不是
> RFC 9807 全义 aPAKE 等级**：因 AKE 层（现役 SM2 挑战-应答）无协议内前向保密，
> 不满足 RFC 9807 §10.2 明示的 AKE essential 要求（"Another essential requirement
> from AKE protocols for use in OPAQUE is to provide forward secrecy (against
> active attackers)"；且无 KE3 型钥确认时 "forward secrecy is only achieved
> against eavesdroppers, which is insufficient for OPAQUE security"）。该等级的
> 达成=§8 方案 A 演进项（义务清单在案，未实施未证明前不宣称）。

v1 病灶对应：v1 §3 D5 行「现状已如此，OPAQUE 不恶化」即为评审所指『结构性消灭宣称
在 AKE 维度未对账』——本节按 essential 重述，G3 同步重述（§10）。

## 1. 文献分账与符号

### 1.1 三文献职责分账（修订第 1 条——全篇引用基准）

| 文献 | 管辖范围 | 本文档引用点 |
|---|---|---|
| **RFC 9807**（OPAQUE aPAKE，2025-07） | 协议结构：OPRF 依赖（§2.1）、KSF/Stretch（§2.3）、信封与 credential protection（§4、§4.1.1–4.1.3）、注册（§5，RegistrationRecord=§5.1）、在线 AKE（§6，CredentialResponse=§6.3.1、masked_response 掩码=§6.3.2.2、fake record=§6.3.2.2）、AKE 安全要求（§10.2）、key stretching 讨论（§10.8）、客户端枚举（§10.9） | §0/§4/§5/§8 |
| **RFC 9380**（hash-to-curve） | H2C 全部：hash_to_field 与 L（§5）、expand_message_xmd（§5.3.1）、DST 纪律（§3.1）、SSWU 与 Z 四准则（§6.6.2）、hash_to_curve 复合（§3） | §3 |
| **RFC 9497**（OPRFs Using Prime-Order Groups，2023-12） | OPRF 协议形态与套件：modeOPRF/VOPRF/POPRF（0x00/0x01/0x02）、Blind/BlindEvaluate/Finalize/Evaluate/DeriveKeyPair、P256-SHA256 套件、安全注记（One-More Gap CDH） | §2 |

v1 病灶对应：v1 全篇以 RFC 9380 指称 OPAQUE（「OPAQUE（RFC 9380）」「RFC 9380
§4.3 credential protection」「RFC 9380 用 base mode」等均为错引——credential
protection 在 RFC 9807 §4，base mode 对齐对象是 RFC 9497 modeOPRF）；仅 §2.2 SSWU
引 9380 是对的。修订后凡 OPAQUE 协议语义一律引 9807，凡 H2C 一律引 9380。

### 1.2 符号

F_p 素域；E: y²=x³+ax+b over F_p；G（大写斜体）=E 的 F_p-有理点群；主子群阶 n
（素数），cofactor h=1；Z_n*=[1,n−1]；[k]P 标量乘；RO 随机 oracle；ROM/GGM/AGM
（随机预言机/通用群/代数群模型）；Extract/Expand=HKDF-SM3（extract/expand 双层，
G5 在案）；CSPRNG=secrets（RFC 4086 口径）。

## 2. OPRF 在 SM2 群的实例化

### 2.1 群选择与域参数（v1 结论维持——评审实算确认）

SM2（GM/T 0003.5-2012）：256-bit 素域 prime curve，p=2^256−2^224−2^96+2^64−1
（hex `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF`，
p mod 4=3），a=−3（mod p），b≠0（`0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F5
15AB8F92DDBCBD414D940E93`），基点阶 n 素数、cofactor h=1。OPRF/VOPRF 群要求=
素数阶群——SM2 主群天然满足，无需 cofactor 清除语义（clear_cofactor=恒等，§3.4）。
DDH 假设强度：与 NIST P-256 同级（128-bit 语义）。以上硬事实经评审数值实算确认
（公允记录在案）。

### 2.2 OPRF 构造（base mode=RFC 9497 modeOPRF=0x00）

函数命名对齐 RFC 9497/RFC 9807 §2.1 API：

- **Blind**（客户端）：`r ←$ Z_n*`；`α = [r]·H2C(oprf_input)`（H2C=§3 完整构造；
  oprf_input 域分离=`"FZ-OPAQUE-OPRF|v1"‖0x00‖username‖0x00‖password`——base mode
  无 POPRF info 通道，username 绑定走输入前缀，承接 v1 D9 意图，防跨账户 rwd 拼
  接）；存 blind=r。
- **BlindEvaluate**（服务端）：**先执行 §2.3 点校验前置条件 O-1**，然后
  `β = [k]·α`（k=k_oprf ∈ Z_n*）。
- **Finalize**（客户端）：`Y = [r⁻¹]·β`；`oprf_output = Extract-SM3("", 
  "FZ-OPAQUE-Finalize|v1"‖Y.x‖Y.y)`（64B 坐标域串+域分离，RFC 9497 Finalize 的
  「长度前缀+transcript 哈希」语义同构）。
- **Evaluate**（服务端直算，自持 k 与输入时）：`[k]·H2C(oprf_input)`（同样受 §2.3
  前置条件约束）。
- 正确性：[r⁻¹][k][r]·H2C = [k]·H2C ✓（标量乘交换律，平凡验证）。

与 v1 的差异：v1 在 Blind 输入侧再做一次 Harden（`Harden_in`）——RFC 9807 的 KSF
（Stretch）只在 **Finalize 之后的 oprf_output 上施加一次**（§5.2.3/§6.3.2.3 同序），
输入侧不再二次慢哈希；本修订随 §5.3 单链钉定一并更正（同时消灭评审所指『双重
Harden 次序不唯一』）。

### 2.3 invalid-curve 点校验=Evaluate 的安全前置条件（修订第 6 条——规范条目，非测试项）

**规范条目（实施批必须落进协议代码路径，不是 crypto_audit 测试项）**：

- **O-1（服务端）**：BlindEvaluate/Evaluate 在标量乘之前，必须对输入 α/β 执行完整
  曲线点校验：坐标 ∈ F_p、满足 y²=x³+ax+b（mod p）、非无穷远点编码。校验失败=
  结构化拒绝（400 族），**绝不进入标量乘路径**。
- **O-2（客户端）**：Finalize 前对 β 执行同款校验（恶意服务端可回非曲线点探测客户端
  blind 侧信道——对偶面）。
- **O-3（标量乘纪律）**：k_oprf 的标量乘走仓内既有盲化路径
  `backend/app/crypto/sm2.py:98-113` `_kg_blinded`（随机分裂 d=d1+d2 (mod n) 双乘
  +点加，每次调用 _kg 位模式与 k 去相关——SP9 9.19 时序侧信道防线，仓内已验证与
  非盲化输出逐字节一致）。

**为什么是前置条件（威胁机理）**：软件档标量乘非恒时（G6 在案）。对**合法曲线点**，
_kg_blinded 已使位模式与 k 去相关（G6 残余=合法点上的时延泄漏，由 §9 统计断言钉
基线）；但对**非曲线点** P'，乘法器实际工作在另一条曲线上（无效曲线攻击族）——
低阶子群/异曲线点的响应 [k]·P' 直接泄漏 k mod (小阶)或逐位信息，**盲化双乘不改变
无效点的群结构泄漏**（d1+d2 分裂仍满足 [d1]P'+[d2]P'=[k]P' 的可区分代数关系）。
因此校验是安全前置条件——缺了它，§2.4 的归约前提（攻击者询问均落在合法群内）不
成立。v1 把「α/β 非曲线点」只列在 §7 模糊注入测试项，评审判定『缺席应升格』成立，
本条即为升格。

### 2.4 安全归约：博弈序列、显式引理与损失账（修订第 5 条）

#### 2.4.1 假设命名分账（诚实对账）

- OPAQUE 论文（Jarecki-Krawczyk-Xu, Eurocrypt 2018）对 2HashDH OPRF 用 **OMDL**
  （one-more discrete log，Bellare–Neven 命名传统）陈述。
- **RFC 9497**（本方案对齐的 OPRF 规范）Security Considerations 原文：其 OPRF/VOPRF
  的 pseudorandomness 与 input secrecy（及 verifiability）「are based on the
  **One-More Gap Computational Diffie-Hellman** assumption」（引 JKK14）；Gap 变体=
  附 DDH oracle（VOPRF 的 DLEQ 验证面所需；base mode 无 DLEQ，不需要 Gap oracle）。
- Tyagi–Celi–Ristenpart–Sullivan–Tessaro–Wood（2021）：One-More Gap CDH 与 One-More
  Gap SDHI 在 **AGM（代数群模型）中归约到 q-DL**（RFC 9497 同引）。
- 本文档采用**非 Gap 的 One-More 计数型假设**（定义 2）陈述+GGM 内无条件计数定理；
  假设陈述为本文自写、依上述命名传统——完整文献级形式化对齐归入 G7。

#### 2.4.2 实验定义

- **定义 1（OPRF-UF_q，不可伪造）**：A 自适应询问 Evaluate ≤ q 次、H2C（RO）任意
  次；A 输出 (x*, Y*)，x* 未询问过；A 胜 ⟺ Y*=[k]·H2C(x*)。
- **定义 2（OMDH_q，One-More Diffie-Hellman，非 Gap 计数型）**：挑战者 k←$ Z_n*，
  给 A (G, G, Q=[k]G) 与 oracle O_k: X↦[k]X（预算 q 次——O_k 即去哈希的裸
  Evaluate）；A 胜 ⟺ 输出 (X*, Y*) 使 Y*=[k]X* 且 X* ∉ 已询问集合。
- **定义 3（OMDL_q，对偶记账）**：给 A (G, Q=[k]G) 与 DL_G oracle（输入 Y 返回
  y: Y=[y]G，预算 q 次）；A 胜 ⟺ 输出 k。与 OMDH 同为「多解一个」计数族的两种
  记账，GGM 内均由计数定理覆盖（Bellare–Neven/JKK 命名传统）。
- **OPRF-IND_q**：挑战阶段 A 提交未询问 x*，收到 Y←{[k]·H2C(x*), 均匀群元素}，
  猜 b——GGM 内与 UF 同一定理覆盖（§2.4.5）。

#### 2.4.3 引理 1（RO 编程完美模拟——adaptive 询问到静态目标的转换）

设 H2C 为可编程 RO，Q=[k]G 为**静态挑战**。模拟器 M 对 A 的第 i 次 adaptive
Evaluate 询问 x_i：采样 ρ_i←$ Z_n*，**编程 H2C(x_i):=[ρ_i]G**，应答 Y_i=[ρ_i]Q。
则：
1. Y_i = [ρ_i k]G = [k]([ρ_i]G) = [k]·H2C(x_i)——与真实 Evaluate 逐点相等；
2. A 视图分布与真实实验的统计距离 ≤ H2C 输出分布与「G\{O} 均匀」的统计差
   （§3.5 桥，2^−128 级）+ρ_i 与真实 H2C 值耦合的可探测度（GGM/ROM 内为零——
   ρ_i 信息论隐藏于编程）；
3. **adaptive 序列已被转换为对单一静态目标 Q 的标量倍序列**，且模拟器全知 ρ_i
   （后续提取的锚点）。

#### 2.4.4 引理 2（预算等价 self-reducibility——静态挑战集形态）

(i) **OPRF-UF_q ⇒ OMDH_q，损失 0**：以 A 直接作 OMDH 攻击者——A 的 Evaluate(x)
询问转发为 O_k(H2C(x))（1:1 预算），A 的胜输出 (x*, Y*) 即 OMDH 的
(X*=H2C(x*), Y*)，X* 新鲜性由 x* 新鲜性+H2C 无碰撞传递。
(ii) **OMDH_q ⇒ OPRF-UF_q，损失 0（ROM 内，经引理 1）**：M 编程 H2C 使 A 的每个
询问都被静态目标 Q 服务；A 输出 q_e+1 个合法对 ⟹ 在代数模型中其中至少一个含
「未服务」的新鲜项（one-more 计数本体），M 以其全知的 ρ 把该对翻译回 OMDH 胜出。
(iii) oracle 型与**静态目标集型**（q+1 个静态目标 X_1..X_{q+1}、oracle 至多服务
q 个、须补出第 q+1 个）优势等价——同一计数实验的两种记账（标准 self-reducibility，
损失 0）。**本引理即评审清单要求的「adaptive Evaluate 询问到静态挑战集」显式化。**

#### 2.4.5 定理（GGM 计数界）与损失账

**定理**：GGM+ROM 中，任何 q_e 次 Evaluate、q_H 次 H2C 询问的 PPT 攻击者：
Adv^{OPRF-UF} + Adv^{OPRF-IND} ≤ (q_e+q_H+3)²/n。
证明骨架（Shoup 句柄代数）：群元素=形式分数句柄（变元 k、ρ_1..ρ_{q_e}、σ_1..σ_{q_H}
上 Z_n 系数有理式）；模拟逐步；「两个不同形式分数同值」的碰撞事件单步概率 ≤ t/n
（t=当前句柄数）；A 的伪造目标 k·σ*（σ* 新鲜）∉ span{1, k, ρ_i, kρ_i}，只能经
碰撞事件产出；q_e+q_H+3 次句柄生成 ⟹ 并界如上。∎（骨架级——完整展开=JKX18 附录
层级，残余缺口见 G1。）

**逐跳损失账**：

| 跳 | 变更 | 损失项 | 量级 |
|---|---|---|---|
| G0→G1 | H2C（§3 具体构造）→ 理想 RO（§3.5 indifferentiability 桥） | Δ_H2C | ≤2^−128 统计 + RO 区分计算项（§3.5） |
| G1→G2 | GGM 句柄模拟 | 碰撞界 | (q_e+q_H+3)²/n |
| G2→OMDH/OMDL | 引理 1+引理 2 | **0**（完美模拟+等价记账） | — |
| GGM 外 | 计数定理→标准模型假设 | OMDH/OMDL 假设项（§2.4.1 分账） | 计算性，negl |

数值面：n≈2^256；q_e+q_H ≤ 2^20 ⟹ 界 ≥ 2^−216 级——128-bit 安全预算内余量充足。

**Cheon 型加速注记（RFC 9497 同款风险提示）**：攻击者获得 Q 次合法 Evaluate 响应
时，静态 DH（=k）求解可加速 log2(Q)/2 位（Boneh–Goli 04/Cheon 06，RFC 9497 原文
引用同款）——Evaluate 限流不只是业务纪律，也是假设强度纪律（§9 落限流断言）。

**v1 病灶对应**：v1 §1.3 只有「论证骨架（generic group model）」示意段+自认 G1；
本节给出实验定义、引理 1/2（含 adaptive→静态与预算账）、定理级计数界、逐跳损失表
与假设命名分账。G1 相应缩减（§10）：剩余缺口=GGM/ROM 模型启发式本身+无第三方独立
复现，不再是「无博弈级定理」。

#### 2.4.6 malicious-server 面（v1 结论维持）

base mode 下恶意服务器可对任意 x 返回假值（客户端无 verifiable 通道——G8）。本方
案威胁模型=服务器诚实但可被拖库（自托管），rwd 伪造非目标面；第三方托管须升级
VOPRF（RFC 9497 modeVOPRF=0x01，DLEQ 证明）——演进注记维持。

### 2.5 SM2 群平移合法性（v1 结论维持）

OMDH/OMDL/GGM 论证群无关（只依赖素数阶循环群抽象）；SM2 与 P-256 的域参数差异在
GGM 下不可见。SM2 特有结构核查维持 v1：签名 Z 值路径/nonce 结构（sm2.py 签名实现）
与 OPRF 标量乘零共享；SM2 曲线无超越 256-bit 通用界的已知攻击；cofactor=1 无
small-subgroup 面。**新增**：§2.3 点校验前置把「非曲线点」从平移论证的假设前提改
为协议强制，平移论证的适用域=合法群内。

## 3. SM2 HashToCurve 构造（全部引 RFC 9380——修订第 2/3/4 条）

### 3.1 现状（v1 结论维持）

RFC 9380 定义了 P-256/P-384/P-521（SSWU）等套件，**不含 SM2**；国标亦无 SM2
hash-to-curve 套件。自构造+一般性定理覆盖（G2：标准互操作缺口，如实）。

### 3.2 选定 Simplified SWU（RFC 9380 §6.6.2）+ SM2 的 Z 钉定

**适用性**：SSWU 适用于 a≠0 且 b≠0 的 Weierstrass 曲线；SM2 a=−3 ✓、b≠0 ✓
（RFC 9380 对 A=−3 有直落曲线的套件先例：P-256/P-384/P-521 均直接用 SSWU，无需
3-isogeny 链——那是 A=0/B=0 曲线 §6.6.3 的待遇）。v1 此结论评审确认成立。

**Z 的四准则（RFC 9380 §6.6.2 原文，逐字）**——Z 为满足以下全部条件的 F 元素：

1. "Z is non-square in F"
2. "Z != -1 in F"
3. "the polynomial g(x) - Z is irreducible over F, and"
4. "g(B / (Z * A)) is square in F"

其中 g(x)=x³+A·x+B（A=a=−3，B=b）。

**各准则的技术角色（本修订论证）**：
- c1（Z 非平方）：SSWU 分支全定义性的代数核心。映射以
  `x1 = (−B/A)·(1 + inv0(Z²·u⁴ + Z·u²))`、`x2 = Z·u²·x1` 两候选求点（RFC 9380
  §6.6.2 操作步骤原文），恒等式 **g(x2)=Z³·u⁶·g(x1)** 成立（本修订对 SM2+Z=−9
  以 10 组随机 u 数值验证 ✓）；u 非例外时 u⁶ 为平方 ⟹ χ(g2)=χ(Z)·χ(g1)=−χ(g1)
  ⟹ gx1/gx2 恰一为平方 ⟹ 两分支必一命中。
- c2（Z≠−1）：RFC 列为准测；Z=−1 时 t=Z²u⁴+Zu² 退化为 u⁴−u² 结构，映射分支退化
  （角色推理 RFC 未附文——如实照办+数值执行，不越权解读）。
- c3（g(x)−Z 不可约）：SSWU 正确性/分布论证的代数前提（RFC §6.6.2 列示；Brier
  et al. 2010/Wahby–Boneh 分析所依）。
- c4（g(B/(Z·A)) 为平方）：**例外情形锚**。RFC 9380 §6.6.2 原文："The exceptional
  cases are values of u such that Z²·u⁴ + Z·u² == 0. This includes u == 0" 且
  "Implementations must detect this case and set x1 = B / (Z * A), which
  guarantees that g(x1) is square by the condition on Z given above"——c4 正是
  该保证（u=0 或 Zu²=−1 时直取 x1=B/(Z·A) 仍得合法点）。

**v1 病灶对照**：v1 写「Z 的选取：最小正整数 Z s.t. g(Z)=Z³+aZ+b 为非平方且
g(-b/(Z·a)) 非平方」——四准则丢 c2/c3 两条，且把 c4（g(**B/(Z·A)**) 为**平方**）
改写成自造变元 −b/(Z·a) 的非平方（正确变元 B/(Z·A)=−B/(3Z)，与 −b/(Z·a)=b/(3Z)
差一符号）。按 v1 钉出的 Z 非 RFC 口径 SSWU 常量——本节即为修正。

**SM2 的 Z 求解与验证（修订第 2 条核心交付）**：

- 搜索约定：|Z| 递增、负值优先（RFC 9380 既有套件 Z 全为负小整数先例：
  P-256=−10、P-384=−12、P-521=−4、secp256k1=−11；BLS12-381 G1=+11 为例外如实记）。
- 判定方法：c1/c2 用 Euler 判据 pow(Z,(p−1)/2,p)；c3 对三次式⟺「无 F_p 根」⟺
  gcd(x^p−x, g(x)−Z)=1（多项式模幂+多项式 gcd 实现，**三重验证**：与暴力逐点求根、
  与 sympy GF(p) 因式分解在 6 个素域 360 组随机三次式上全部一致；见附录 A）；
  c4 直接 Euler 判据。
- **P-256 交叉验证（检查器 256-bit 尺度端到端可信）**：同一检查器对 P-256
  |Z|≤12 唯一通过 **Z=−10，与 RFC 9380 套件发布值一致**；淘汰轨迹逐条可复核：
  −1（c2）、−2/−4/−5/−8/−9（c3 可约）、−3/−6（c1 平方）、−7（c4 非平方）。
- **SM2 淘汰轨迹（|Z|≤8 负值域）**：−1（c2）；−2/−3/−5/−6/−7/−8（c3：g(x)−Z 可约
  有根）；−4（c4：g(B/(Z·A)) 非平方）⟹ **钉定 Z=−9**。
- **Z=−9 验证锚点**（全部 256-bit 值逐字可复核，复现脚本=附录 A）：
  - Z=−9 ≡ `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFF6` (mod p)；
  - c1 ✓：pow(−9,(p−1)/2,p)=p−1（非平方）；
  - c2 ✓：−9≢−1 (mod p)；
  - c3 ✓：g(x)−Z=x³−3x+(b+9) 在 F_p 无根（gcd(x^p−x, g(x)−Z)=1）；x^p mod (g(x)−Z)
    的独立双路径一致（多项式模幂 vs 3×3 伴随矩阵幂，**逐字相等**）：
    `0x8c9b89bfd1217964cbbb138058b0a0daa3b7f144a2f84220a2f180e8ccd6f67b`、
    `0xa9c084b3c7fe741cb3c962235b7488198cf94416992a3679f24adff4ad1576b7`、
    `0x39b23b1f976f434d9a22763fd3a7af92ae24075d2e83def02e873f8b999484c2`；
  - c4 ✓：x0=B/(Z·A)=`0x993812c2e964b7a31f4f35452d9b7222aa35051b7294938ac5d7953b4eb9a1b9`，
    g(x0)=`0x415bc055b574f716255dc77649a3c4025b1d89280c892d901229a8831df50f44`，
    Euler 残差=1（平方）；
  - SSWU 恒等式 g(x2)=Z³u⁶g(x1) + 「gx1/gx2 恰一平方」：10 组随机 u 数值验证 ✓。
- **诚实注记**：SM2 无 RFC/国标 SSWU 套件 ⟹ 无「RFC RECOMMENDED Z」可对照
  （RFC 附录 H.2 脚本只对既列曲线输出）；Z=−9 为本修订按上述确定性约定自注册钉定，
  四准则为 RFC §6.6.2 的规范性验收条件（满足即正确性成立），G2 维持。实施批以
  附录 A 脚本重跑+SSWU test vector 钉入 crypto_audit（§9）。

### 3.3 hash_to_field 的 L 参数与统计距离（修订第 3 条）

- **L 公式（RFC 9380 §5）**：L = ceil((ceil(log2 p) + k)/8)，k=目标安全位摘要。
  SM2：ceil(log2 p)=256，k=128 ⟹ **L=48 B/元素**；hash_to_field(msg, 2) 的
  len_in_bytes=**96 B**。每元素：48B 大端整数 mod p（拒绝采样不需要——SSWU 全域
  覆盖，v1 结论维持）。
- **统计距离账**：均匀 384-bit 串 mod p 的偏差 ≤ p/2^384 < 2^256/2^384 = **2^−128**
  （RFC 9380 §5 原文口径 "bias at most 2^-k"）✓ 达标。
- **v1 病灶定量对照**：v1 钉 64B 拆 2×32B ⟹ 每元素均匀源仅 2^256；p=2^256−r
  其中 r=2^256−p=**2^224+2^96−2^64+1**（hex `0x100000000000000000000000000000000
  FFFFFFFF0000000000000001`）⟹ mod-p 统计距离 = r/2^256 ≈ **2^−32** ≫ 2^−128 目标
  ——评审判定「H2C≈RO 桥假设在所钉参数下不成立」成立。本修订以 96B 双 48B 消灭该
  病灶，§3.5 的桥界随之闭合。

### 3.4 hash_to_curve RO 构成——完整步序（修订第 4 条）

RFC 9380 §3 原文复合步序（逐步照录，SM3-XMD 实例化）：

```
hash_to_curve(msg):
1. u  = hash_to_field(msg, 2)          # u0,u1 ∈ F_p；expand_message_xmd，96B
2. Q0 = map_to_curve(u0)               # SSWU（§3.2：x1/x2 分支+例外锚 B/(Z·A)）
3. Q1 = map_to_curve(u1)               # 同上
4. R  = Q0 + Q1                        # 群加（v1 缺失的求和步——本条补全）
5. P  = clear_cofactor(R)              # h=1 ⟹ 恒等（§2.1）
6. return P                            # sgn0(y)=sgn0(u) 符号纪律（RFC §6.6.2 原文）
```

**expand_message_xmd（RFC 9380 §5.3.1）实例化合规账**：H=SM3，输出 b=256 bit：
- b ≥ 2k=256 ✓（恰好达线）；SM3 块长 s=64B，b/8=32 ≤ 64 ✓；
- ell=ceil(96/32)=3 ≤ 255 ✓；len_in_bytes=96 ≤ 65535 ✓；
- DST=`"FZ-OPAQUE-V1-"‖suite_id`，suite_id 自注册命名 `SM2_P256_XMD:SM3_SSWU_RO_`
  （仿 RFC 9380 套件命名族；长度 ≥16B ✓、≤255 ✓——自注册≠标准化，G2）；
- msg_prime/Z_pad/l_i_b_str 结构照 RFC §5.3.1 原文实现（b_0/b_i 链）。

**v1 病灶对照**：v1 只有单点 map（无 u 双采样、无 Q0+Q1、无显式 RO 复合段）——
indifferentiability 定理的适用对象本应是「本 §3.4 复合构造」，单点 map 不构成
H2C≈RO 桥。本条补全后 §3.5 论证有所指。

### 3.5 indifferentiability 论证（v1 结论维持+所指修正）

SSWU map 与 clear_cofactor 复合对素数阶曲线 indifferentiable from random oracle
（Brier–Coron–Icart–Kang–Lyubashevsky–Mantin 2010 + RFC 9380 §3 的工程化重述）；
h=1 时 clear_cofactor 恒等，安全论证不依赖 SM2 专属证明（定理直接覆盖，比 OMDL
的 GGM 启发式强一档——v1 结论维持）。**所指修正**：定理对象=§3.4 六步复合构造
（含 Q0+Q1 与双 u），参数=§3.3 的 L=48B（2^−128 统计差入桥界）。桥界记 Δ_H2C，
入 §2.4.5 损失账 G0→G1 跳。

## 4. 与 RFC 9807/9380 的逐条偏离清单（修订——全部重锚定到正确文献）

| # | 规范条目（正确文献） | 本方案 | 性质 | 等级 |
|---|---|---|---|---|
| D1 | 群=NIST P-256 等（RFC 9497 套件族） | SM2 prime-order group（h=1） | 平移（同语义素数阶群，GGM 下不可分） | 低 |
| D2 | H2C=RFC 9380 套件（P256_XMD:SHA-256_SSWU_RO_ 等） | SSWU(A=−3)+SM3-XMD 自构造套件，Z=−9 钉定（§3.2） | 自构造——定理覆盖但无 RFC 对照套件/互操作基线 | 中（G2） |
| D3 | RFC 9380 xmd/HKDF 族基线为 SHA 系 | HMAC-SM3 同构（extract/expand 双层） | HKDF-SM3 无 RFC 基线（工业先例在案） | 低 |
| D4 | KSF/Stretch：RFC 9807 §2.3（建议 Argon2id 等记忆困难函数；**术语=Stretch/KSF**，§10.8 讨论） | Stretch=PBKDF2-HMAC-SM3 600k（v4 同域参数——国密无 Argon2），**仅施加一次、Finalize 后**（§5.3 钉定） | 慢哈希弱于记忆困难型（GPU/ASIC 并行面），如实 | 中（G4） |
| D5 | AKE：RFC 9807 §10.2 要求 KCI+**前向保密（essential）**+KE3 钥确认 | 现役 SM2 挑战-应答保留；**宣称按 §0.2 收缩**，PFS 升级=§8 方案 A | essential 未满足——不宣称 aPAKE 级（诚实收缩） | 中（G3，§8 两案） |
| D6 | credential protection：Envelope（RFC 9807 §4.1.1–4.1.3）+masking_key/masked_response（§6.3.1、§6.3.2.2）+fake record | 机制全对齐+key commitment 保留；envelope 载荷=现行 v4 信封内容（私钥/身份资料）；**masked_response 防枚举分析成文（§5.4）** | 形态适配（载荷语义替换），机制对齐 | 低 |
| D7 | OPRF mode=base（RFC 9497 modeOPRF=0x00；RFC 9807 §2.1 依赖即此形态） | base mode | 对齐（单 server 自托管）；第三方托管须 modeVOPRF | 低 |
| D8 | clear_cofactor（RFC 9380 §3 第 5 步） | 恒等（h=1） | 对齐（简化） | 无 |
| D9 | identifiers/域分离（RFC 9807 protocol inputs 域串纪律） | oprf_input 前缀绑 username（§2.2）；DST/ info 域分离全套 | 设计选择（同 RFC 纪律） | 低 |
| D10 | CSPRNG | secrets（RFC 4086 口径）；SM2 内部 k=secrets（gmssl random 弃用已根修，sm2.py docstring 在案） | 对齐 | 无 |

v1 病灶对应：D6 行原文只写「保留 key commitment」——masked_response 机制缺失（§5.4
补）；D4/D5/D6 行文献号全部重锚（9380→9807/9497）。

## 5. 协议流程（注册态/登录态）

### 5.1 注册态（新建账户；与现行 /ra/register+激活面嫁接——v1 骨架维持）

```
Client(浏览器)                                   Server(backend)
  oprf_input = 域串(username, pwd)                 （§2.2）
  blind: r ←$ CSPRNG; α=[r]·H2C(oprf_input)
  ──────────── α, username ──────────────────────>
                                     O-1 点校验（§2.3）
                                     β = BlindEvaluate(k_oprf, α)
  <──────────── β, 注册面应答 ──────────────────
  Y=[r⁻¹]β; oprf_output=Extract(…Y…)
  stretched=Stretch(oprf_output)                  （§5.3 单链）
  rwd=Extract("", oprf_output‖stretched)
  KEK=Expand(rwd, envelope_nonce‖"FZ-OPAQUE-EnvelopeKey|v1", 16B)
  钥对生成+密封: v5' 信封=SM4GCM(KEK)(sk‖profile)
  <──── envelope 上传（register/activate 面）────
                                     存 accounts.sealed_blob + OPRF record
```

嫁接点维持 v1：v4 信封的 KEK 源换代（PBKDF2(pass,salt) → rwd 派生），信封形态/
GCM/AAD 纪律不变；登记承诺/RA 签发链路零变化。

### 5.2 登录态（含 RFC 9807 §6 CredentialResponse 形态）

```
  prelogin: mode=opaque（无密封件明文下发！——/auth/keystore 公开拉取面在此收口，§7.3）
  α = Blind(oprf_input)
  ──── α ────────────────────────────────────>
                        O-1 校验; β=BlindEvaluate(k_oprf,α); 挑战 nonce（SM2 AKE 保留）
  <─── β, masking_nonce, masked_response ─────
  rwd 派生（§5.3 单链）→ masking_key → 解掩码取 envelope
  → KEK → 解封 → SM2 sign(FZ-AUTH-LOGIN|nonce) → 会话（零变化）
```

### 5.3 rwd→KEK 派生链（修订第 9 条——单公式钉定，消灭 v1 双公式矛盾）

**唯一规范链（次序钉定，与 RFC 9807 §5.2.3/§6.3.2.3 同序）**：

```
oprf_output  = Extract-SM3("", "FZ-OPAQUE-Finalize|v1"‖Y.x‖Y.y)     # ①Finalize 提取
stretched    = PBKDF2-HMAC-SM3(oprf_output, salt=accounts.salt, 600_000)
                                                          # ②Stretch/KSF——全链仅此一次
rwd          = Extract-SM3("", oprf_output ‖ stretched)   # ③randomized_password 对位
masking_key  = Expand-SM3(rwd, "FZ-OPAQUE-MaskingKey|v1", 32B)     # ④掩码钥（§5.4）
KEK          = Expand-SM3(rwd, envelope_nonce ‖ "FZ-OPAQUE-EnvelopeKey|v1", 16B)
                                                          # ⑤信封钥（RFC 9807 §4.1.2 对位）
```

- 域分离：①③④⑤ 四个 info/salt 串互异且带 `FZ-OPAQUE` 前缀——同根 rwd 的四域
  钥互不可替代。
- **v1 病灶对照**：v1 §4.1 写 `KEK = HKDF-SM3-Extract/Expand(rwd, "FZ-OPAQUE-KEK|v1"‖salt)`
  （直连式），v1 §4.3 又写 `KEK = HKDF-SM3(Extract(rwd),…) 再经 Harden 迭代
  （PBKDF2 600k 以 rwd 替代 pass）`（二次慢哈希式）——双公式矛盾+双重 Harden 次序
  不唯一，评审判定成立。本条为**唯一**公式：Stretch 在 ② 施加一次；KEK 直接由 rwd
  Expand（⑤），其后再无任何慢哈希/再派生步骤。实施批若改链，必须整体替换本条并
  重走评审。

### 5.4 masked_response 防 enumeration 分析（修订第 8 条之一）

**机制（RFC 9807 §6.3.1/§6.3.2.2 原文）**：CredentialResponse =
evaluated_message ‖ masking_nonce ‖ masked_response；masking_key 由 rwd 派生
（§5.3 ④）；pad = Expand(masking_key, masking_nonce‖"MaskedResponse", Npk+Nn+Nm)；
**masked_response = pad ⊕ (server_public_key ‖ envelope)**。未注册用户：服务端
"fake the existence of the record"（伪造 evaluated_message+随机 envelope 应答，
§6.3.2.2）。

**防枚举论证**：攻击者（无口令）对任意 username 观测 CredentialResponse——
- 已注册用户：rwd 未知（§2.4 归约：离线不可验证）⟹ masking_key 未知 ⟹ pad 伪随机
  ⟹ masked_response=伪随机 pad⊕明文 ⟹ 伪随机；
- 未注册用户：fabricated 应答同样伪随机；
⟹ 两侧响应分布在 (i) masking pad 的 KDF 伪随机性（HKDF-SM3 假设——G5 关联）与
(ii) OPRF 输出不可区分（§2.4）下计算不可区分 ⟹ **无 username 注册状态 oracle**。
配合：固定响应长度（编码定长）+恒定时延断言（§9）。**实施义务**：fake-record 路径
必须实现（缺它则未注册用户响应可区分——§9 枚举负例钉定）。**v1 病灶对照**：v1 D6
无本机制——评审判定「sole purpose 是防 client enumeration 的掩码机制缺失」成立，
本条补全。

### 5.5 envelope 形态：mode-A（客户端域解封）vs mode-B（服务端持 Protect(rwd)）新面分析（修订第 8 条之二）

先钉术语：RFC 9807 本体形态=**服务端存 envelope，经 masked_response 下发**（即 v1
所称 mode-B——RFC 9807 §4 credential storage 服务端持存+§6 掩码下发；v1 所称
「mode-A 客户端解封」实为 v4-现状嫁接的偏离形态）。

| 面 | mode-A（密封件客户端域解封，v4 嫁接形态） | mode-B（RFC 9807 默认：服务端持存+掩码下发） |
|---|---|---|
| 离线字典 | 无 k_oprf ⟹ 在线（§2.4） | 同左——拖库多拿 envelope 本体但无 k_oprf 不可用，**面等价** |
| KCI/冒充 | 信封保护客户端私钥+OPRF 门（§0.2-2） | 同左 |
| 传输/端点面 | envelope 经 /auth/keystore 类端点下发 ⟹ 端点鉴权/限流缺口直接暴露（§7.3） | envelope 入 masked_response ⟹ **独立 keystore 端点面消灭** |
| 内部人面 | 服务端运维接触不到 envelope（在 DB 但无 k_oprf 仍在线——同泄面 G9 两模式同） | 同左；**新增**：服务端静态持有 envelope+OPRF record 的关联记录面（记录型内部人可见账户密封件清单——无 k_oprf 不可解） |
| 枚举面 | fake-record 义务同 §5.4 | fake-record 义务同 §5.4（机制本体即为此设计——对齐度更高） |
| 迁移面 | v4→v5' 客户端域重封路径最短（§7） | 需一次服务端持存改造+掩码通道 |

**分析结论**：mode-B 与 RFC 9807 规范对齐度最高（masked_response 语义完整成立、
keystore 端点面消灭、fake-record 义务同源）；mode-A 的唯一优势=对 v4 现状嫁接面
最小。**推荐 mode-B**（规范对齐优先）；mode-A 仅在 §7 迁移过渡窗内作为兼容轨道存
在。v1 的「二选一在实施批定」收口为：默认 mode-B，偏离须附等效面分析。两模式的
**KCI/内部人新面如上逐项在案**——v1 病灶（无分析）消除。

## 6. k_oprf 入 KMS 生产注册表（v1 结论维持+provider 对接）

`app/kms/__init__.py:36-47` PRODUCTION_REQUIRED_KEYS 增第 11 钥
`("FZ_OPRF_SK", "OPRF 拖库面防护服务钥（SM2 scalar，rwd 派生根）", "sk32")`：

- **拒启语义**：production 档缺 FZ_OPRF_SK=拒绝以派生钥启动（派生钥=SM3(公开常量)
  任何人可推算 ⟹ OPAQUE 防护归零，必须拒——v1 结论维持）。
- **轮换联动**：k_oprf 轮换 ⟹ 存量 rwd 全部失效 ⟹ 所有 v5' 信封需客户端重跑注册
  序——双钥过渡窗（k_old 只读 Evaluate 至迁移完成，新注册用 k_new），迁移序见 §7。
- **provider 对接**（1.4 抽象层）：OPRF Evaluate=[k]·H2C 标量乘——HSM 到位后 k_oprf
  入 HSM 钥槽（私钥不出硬件面），Evaluate 走 PKCS#11 标量乘原语；G6/G9 同步收窄。

## 7. v4 存量惰性重封迁移（修订第 9 条之二——主体纠正+删除语义+前置注记）

### 7.1 流程（先例=v3→v4 惰性重封全套：停发/cutoff/production 扫库告警/回滚窗）

1. **停发**：新注册/重置一律 OPAQUE 形态（v5'+rwd 派生）；未启用档维持 v4（配置
   开关双轨——同 v3 惯例）。
2. **惰性重封——主体=客户端域（v1 写反，本条纠正）**：存量 v4 账户登录时，**客户端
   **以其已提交的登录口令执行：旧路径 KEK=PBKDF2(pass,salt) **在客户端域**解封 v4
   信封 → 同口令走 §5.1 OPAQUE 注册序得 rwd → v5' 重封 → 上传落库。**一次明口令
   在客户端域的重放**（同一输入，无需二次索要）。服务端域**没有也不需要明口令**——
   v1 写「服务端以旧路径（口令 KEK）解封一次」为主体的表述**写反**（服务端只存密
   封件、无口令材料；v3→v4 先例实为客户端回传重封——MEMORY 在案可复核）。
3. **截止开关**：FZ_OPAQUE_CUTOFF_TS（Unix 秒；0=不启用）到点后 v4 存量登录拒绝
   （403 引导重置）+production 启动扫库告警（同 v3 惯例代码路径）。
4. **回滚窗**：重封失败=保持 v4 态（不 burn 旧密封层）。

### 7.2 旧 blob 删除语义（钉死）

- **不可逆点=删除事务**：客户端 v5' 上传落库与 OPAQUE record 建立**确认成功**后，
  **同一事务**删除旧 sealed_blob/旧 init_verifier 密封层。删除前任何崩溃 ⟹ 状态
  仍为 v4（回滚窗语义可重试）；删除提交后 ⟹ v4 路径对该账户永久失效（不可逆，
  不可恢复——故前置条件 7.3 必须先于首个删除事务就位）。
- 迁移完成判据：账户级=删除事务提交；系统级=FZ_OPAQUE_CUTOFF_TS 到点+production
  扫库存量计数=0。

### 7.3 实施前置注记（不改代码——钉入实施批义务清单）

**/auth/keystore 现状无鉴权、无限流**（任意人可拉任意 username 的密封件=离线枚举
面本体）——本修订将其列为 **OPAQUE 实施批的前置条件**（非测试项、非后续演进）：

1. 该端点（或其替代通道）必须加**会话鉴权**（仅本账户已认证会话可拉）或改为
   masked_response 通道（§5.4/§5.5 mode-B 下自然消灭）；
2. 必须加**限流**；
3. 已迁移账户旧 blob 已删（§7.2）⟹ 该账户枚举面消失——**顺序**：7.3-1/2 就位之前，
   不得发生任何删除事务（否则迁移窗口内枚举面公开存活）。

v1 病灶对应：「旧密封层作废」未钉死删除语义+keystore 缺口未入前置——本节补全。

## 8. AKE 前向保密处置（修订第 7 条——两案成文，推荐 B）

### 8.1 RFC 9807 的 AKE 要求（原文核对）

RFC 9807 §10.2：OPAQUE 是把「具备 KCI 安全与前向保密的 AKE 协议」编译成安全
aPAKE 的方案——"transforming any AKE protocol (with Key Compromise Impersonation
(KCI) security and forward secrecy…) into a secure aPAKE protocol"；"Another
essential requirement from AKE protocols for use in OPAQUE is to provide forward
secrecy (against active attackers)"（**essential 措辞原文**）；且无 KE3 型钥确认时
"forward secrecy is only achieved against eavesdroppers, which is insufficient
for OPAQUE security"。

### 8.2 现役 AKE 的精确性质

SM2 挑战-应答（服务端下发一次性 nonce，客户端签 `FZ-AUTH-LOGIN|nonce`，服务端验
签建会话）：认证性 ✓；KCI 对抗面=拖库者（无 k_oprf）不能冒充客户端（客户端私钥
信封保护，rwd 需在线过 OPRF 门）✓；**无协议内 PFS**：应用层挑战-应答不派生会话钥
——应用层不贡献前向保密，传输面 PFS 完全取决于承载 TLS 的部署形态，不符合 RFC
9807 对 AKE **自身**提供 FS 的 essential 语义 ⟹ 复合体不满足 RFC 9807 定理前提，
实得=「口令门 OPRF 加固+信封保护认证」非 aPAKE 级（§0.2 已如实收缩）。

### 8.3 方案 A：SM2 挑战-应答上增补带 PFS 的临时钥交换

**设计草图**（3 消息，ephemeral-ephemeral ECDH 融入现役序）：

```
C→S: gC=[c]G                       # c ←$ CSPRNG 临时标量；gC 走点校验（O-1 同款）
S→C: gS=[s]G, Sig_S("FZ-AUTH-LOGIN-PFS|v1"‖H(gC‖gS‖nonce‖username))
                                   # 服务端长期签名钥签 transcript（抗 UKS/降级）
C→S: Sig_U(transcript)             # 现役客户端签名保留+transcript binding
K  = HKDF-SM3(Extract([c]gS), info="FZ-AUTH-SESSION|v1"‖H(transcript), 32B)
```

PFS 语义：被动记录者无 c/s ⟹ 记录后移与私钥泄露不回放历史会话（active 面由
transcript 双签名+nonce 一次性覆盖至 KE3 型钥确认语义——服务端最终响应即钥确认）。

**新增证明义务清单（本批零代码零证明——如实：义务≠证明，未闭合前不宣称）**：
1. gC/gS 双向 invalid-curve/点校验+小子群面（h=1 群内校验即够，O-1 平移）；
2. KCI/UKS 在 transcript-bound 双签名下的重证（SM2 签名串内嵌 H(transcript) 的
   绑定语义形式化）；
3. 临时钥与长期钥/rwd/KEK 的密钥域分离（key schedule 分层——HKDF info 域隔离的
   可证性）；
4. replay/downgrade（版本常量+nonce+transcript 三重绑定的负例面）；
5. 恒时面扩展（ECDH 标量乘入 _kg_blinded 路径+§9 统计断言扩项）；
6. 与 OPAQUE 导出钥的域分离（RFC 9807 export 语义）。

### 8.4 方案 B：诚实收缩宣称（推荐）

- 保持现役 SM2 挑战-应答 AKE 原样；
- 宣称精确措辞=**§0.2 全文**（达成三条/不宣称一条），关键句：「AKE 层无协议内前向
  保密，不满足 RFC 9807 §10.2 对 AKE 的 essential 前向保密要求，故不宣称 RFC 9807
  全义 aPAKE 等级；OPRF 核心的抗离线字典宣称以 §2.4 归约为限」；
- G3 按 essential 重述（§10）：缺口=协议内 PFS 缺失（现状如实，非本设计引入）；
  升级路径=§8.3 方案 A（义务清单在案，作为独立演进项——不阻塞本方案复评）；
- 答辩口径联动：E11 行『激活核对子』表述不动，『SM2-OPAQUE 已论证、宣称以修订版
  §0.2 为准』一句在案（MEMORY 由宿主批维护——本文档只钉宣称源头）。

### 8.5 利弊分析与推荐

| | 方案 A（增补 PFS） | 方案 B（收缩宣称） |
|---|---|---|
| 宣称上限 | 可对齐 RFC 9807 全义 aPAKE | 明确低于 aPAKE（OPRF 加固口令门） |
| 本批可闭合性 | **不可**——六项证明义务在零代码批无法闭合；宣称先行=下一轮 NO-GO 风险 | **可**——宣称与既有证据即时精确对齐 |
| 实施代价 | 协议序+密钥调度+恒时面+测试全链改动 | 零改动 |
| 复评风险 | 证明悬空 ⟹ 高 | 宣称-证据一致 ⟹ 低 |
| 与诚实红线 | 相容（若义务全闭合后宣称） | 相容（本修订即示范） |

**推荐：方案 B。** 理由：复评判据=宣称与证据一致；本批为纯文档批，方案 A 的六项
证明义务无法闭合，以其入档则 AKE 维度宣称仍悬空（与 v1 被判 NO-GO 同构）；方案 B
立即可闭合、不消灭 A（A 全文在案供实施批/赛后演进），且与评审重启条件「G3 按
essential 重述对账 §0 宣称」直接对应。

## 9. 恒时性与模糊注入测试计划（v1 骨架+修订扩项）

1. **OPRF Evaluate 恒时性**：标量乘路径（[k]·H2C）不分支于 k 位；软件档现状=既有
   缺口如实（G6）；crypto_audit 加「Evaluate 时延分布」统计断言（错误/正确中位比
   阈值 1.3×，同既有方法论）。
2. **Stretch 恒轮**：600k 轮计数器外泄面=零分支（PBKDF2 构造内建）。
3. **O-1/O-2 前置校验负例族（升格）**：α/β 非曲线点、无穷远点编码、超长 hex、非
   hex、空串、符号注入（-x）、坐标 ≥p ⟹ 全部结构化拒绝（400 族）零崩溃，且断言
   **未进入标量乘路径**（§2.3 前置条件的执行断言——从 v1 的纯模糊注入升格为安全
   条件验证）；blind 域外（≥n）归约/拒绝语义钉定。
4. **枚举隐私负例（新增）**：已注册/未注册用户 CredentialResponse 长度恒定、时延
   分布 1.3× 阈值内、fake-record 路径在案（§5.4 义务）；masked_response 篡改 ⟹
   解掩码必败（GCM/MAC 面复用 v4/v5 篡改负例族）。
5. **模糊注入（四口）**：Evaluate/Blind/Finalize/元数据解析四口注入族（v1 骨架
   维持）+rwd 派生输入错位（DST/username 错配）⟹ 解封必败。
6. **互操作测试向量（新增锚点）**：Z=−9 四准则复现（附录 A 脚本输出逐字钉定）；
   expand_message_xmd(SM3) 向量；固定 pwd→(α, β, rwd) 十六进制向量；跨引擎对拍
   同 KDF 纪律。
7. **G9 演练负例（新增）**：缺 FZ_OPRF_SK 拒启断言（production 档）；（演示档）
   拿 k_oprf+DB 的离线枚举成功路径=演示退化面存在性（§10 G9 的可证伪呈现）。
8. **Evaluate 限流断言（新增——Cheon 注记落地）**：单位时间 Evaluate 配额与审计
   事件（§2.4.5 注记）。

## 10. 归约缺口清单（诚实红线——逐条可质证；修订后 G1 缩减、G3 重述、新增 G9）

| # | 缺口 | 等级 | 处置 |
|---|---|---|---|
| G1 | 归约=GGM/ROM 模型（启发式模型本身）；**缩减**：博弈序列+引理 1/2+计数定理+损失账已给（§2.4），剩余=模型启发式+SM2-OPAQUE 无公开第三方独立复现；假设陈述为本文自写（依 One-More 族命名传统，分账在案） | 低-中（v1 为中-高） | 方法论同族平移（RFC 9497/JKK14/TCRSTW21 结构）；实施批可采购形式化/第三方密评 |
| G2 | SM2 hash-to-curve 无 RFC/国标套件（SSWU(−3)+SM3-XMD 自构造；Z=−9 自注册钉定——四准则为 RFC 规范性验收条件，无 RFC RECOMMENDED 对照值） | 中 | DST/套件命名自注册；实施批出 test vector（§9-6）并可投递标准化通道（可选） |
| G3 | **重述（essential 对账）**：AKE=SM2 挑战-应答，**无协议内前向保密**——不满足 RFC 9807 §10.2 essential ⟹ 复合体不宣称 aPAKE 级（§0.2）；PFS 升级=§8.3 方案 A（义务清单在案，独立演进项） | 中 | 宣称已收缩对齐；A 为演进路径 |
| G4 | Stretch=PBKDF2-HMAC-SM3 600k 非记忆困难型（GPU/ASIC 并行面保留） | 中 | 国密无 Argon2；迭代数 env 可调（对齐 FZ_KDF_ITERATIONS 纪律） |
| G5 | HKDF-SM3 无 RFC 基线（§5.4 枚举论证的 pad 伪随机性同悬此假设） | 低 | 工业实践先例；extract/expand 构造自证 |
| G6 | 软件档 OPRF Evaluate 在**合法点**上非恒时（gmssl 标量乘现状）——无效点面已由 §2.3 前置条件消灭（边界澄清） | 中 | 软件档如实标注；HSM provider 对接时硬件原语消灭（§9-1 断言钉现状基线） |
| G7 | 无形式化验证（ProVerif/Tamarin 对 OPAQUE 嫁接面；含 §2.4.1 假设陈述的文献级形式化对齐） | 低 | 实施批可选采购/赛后项 |
| G8 | base mode 无 verifiable 通道（恶意 server 可伪造 rwd 拒绝服务/锁定——自托管威胁模型下非目标面） | 低 | 第三方托管场景升级 modeVOPRF（RFC 9497） |
| G9 | **新增（修订第 10 条）——k_oprf 与 DB 同泄退化**：k_oprf 与 DB 同时被拿（部署纪律破坏：k_oprf 备份进 DB 所在环境/双域同时被攻破/KMS 与 DB 同域妥协）⟹ 攻击者可**离线**计算 [k]·H2C(候选口令) ⟹ rwd 可离线验证 ⟹ **离线字典原样回归**（OPAQUE 门结构性失效，且无声警报） | 中（条件性致命——仅同泄触发；KMS/DB 域分离完好时不触发） | ①KMS 拒启语义（缺 FZ_OPRF_SK 不启动，防公开派生钥顶替归零）；②k_oprf 双钥轮换使同泄材料失效窗有界（§6）；③HSM 演进=k_oprf 不出硬件（同泄面收窄为硬件攻破面）；④部署纪律文档强制+production 扫库告警扩项（k_oprf 存放域检查——实施批注记）；⑤**残余如实**：部署方违规同泄无技术强制，此面不可归零只能收窄 |

## 11. 实施边界与复评请求

- 本批交付=本修订文档（零代码零实施——v1 与本文件均不触任何代码/答辩口径卡/
  MEMORY；宿主另有工作流在跑，逐文件 git add 本文件独立提交防互扰）。
- 实施批顺序（⑫，若复评放行）：§3.2 Z=−9+H2C test vector 钉定 → §2.3 O-1~O-3
  前置条件落码 → §5.3 单链 → §5.4 fake-record+掩码 → §6 第 11 钥+拒启 → §7.3
  keystore 鉴权限流（先于 §7.2 首个删除事务）→ §7 迁移+CUTOFF → §9 测试全项。
- **复评请求**：按修订对照表十条逐项复核；重点裁决项=§8 两案取舍（本修订推荐 B，
  A 在案）；§0.2 宣称措辞是否与证据对齐；§2.4 归约面是否达复评标准；§3.2 Z=−9
  锚点可复现性（附录 A）。

## 附录 A：Z=−9 验证脚本骨架（文档内容——不落库执行，实施批以 crypto_audit 复现钉定）

```python
p = 2**256 - 2**224 - 2**96 + 2**64 - 1
A = (-3) % p
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Z = -9
# c1: pow(Z % p, (p-1)//2, p) == p-1                     # 非平方
# c2: Z % p != p - 1                                     # 非 -1
# c3: gcd(x^p - x, x^3 + A*x + (B - Z)) over F_p == 1    # g(x)-Z 不可约（三次式<=>无根）
#     x^p mod c 实现：多项式模幂（x^d = -A x^(d-2) - (B-Z) x^(d-3) 逐步归约）
#     独立交叉验证：3x3 伴随矩阵幂 M=[[0,0,-c],[1,0,-A],[0,1,0]], x^p = M^p·(1,0,0)
#     本修订双路径输出逐字相等（三系数 hex 见 §3.2 锚点）
# c4: g(B/(Z*A)) 为平方：x0 = B * pow(Z*A % p, -1, p) % p
#     euler(x0³+A·x0+B) == 1
# 交叉验证锚：同一检查器对 P-256（p=2^256-2^224+2^192+2^96-1, a=-3, b=0x5AC635D8…604B）
#     |Z|<=12 唯一通过 Z=-10 = RFC 9380 套件发布值；淘汰轨迹逐条可复核
# SSWU 恒等式：随机 u：t=Z²u⁴+Zu²; x1=(-B/A)(1+inv0(t)); x2=Z u² x1
#     g(x2) == Z³u⁶·g(x1) 且 gx1/gx2 恰一平方（10 组验证通过）
# 例外锚：u=0 或 u²=-1/Z ⟹ t=0 ⟹ x1=B/(Z*A)，g(x1) 平方由 c4 保证（RFC §6.6.2 原文语义）
```

（验证计算环境：本修订于 2026-10-11 以 Python 3.13 大整数算术实算；c3 判定器经
暴力逐点求根+sympy GF(p) 因式分解双 oracle 在 6 素域 360 组随机三次式上验证一致；
P-256 交叉验证为 256-bit 尺度端到端锚。）
