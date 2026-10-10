# SM2-OPAQUE 归约论证（⑫OPAQUE/PAKE 前置门——只写文档不做实施，2026-10-11）

> 性质：**前置论证文档**——⑫OPAQUE/PAKE 演进项（答辩口径卡 E 段/演进清单在案）的实施前置门。
> 本批**零代码零实施**：交付=归约论证+偏离清单+嫁接设计+迁移方案+测试计划。
> 诚实红线：论证写不到位的环节**如实标注「归约缺口」**（§8），评审员逐条质证在预期内。
> 现行锚：`app/accounts/kdf.py`（v4 信封 KEK=PBKDF2-HMAC-SM3 600,000 轮，
> KDF_ITERATIONS_DEFAULT=600_000@:30——OWASP 2023 档）、`app/accounts/envelope.py`
> （v4 信封形态 AAD_V4）、`app/kms/__init__.py:36-47`（production 10 钥注册表）、
> `app/crypto/sm2.py`（SM2 原语：sign@164/encrypt@441/decrypt@464——自实现补齐
> GB/T 完整校验，见函数 docstring 对 gmssl 缺陷的实证注释）。

## 0. 背景与残余面（为什么是 OPAQUE）

现行「服务端零口令材料」的精确含义：服务器不存口令哈希/明文，但**存口令派生
的密封件**——私钥/身份资料以密码 KEK（PBKDF2-HMAC-SM3(pass, salt, 600k) 派生
16B KEK）经 SM4-GCM 密封（v4 信封）存于 `accounts.sealed_blob`。该形态的残余面：

- **拖库离线字典攻击**：攻击者拿库（sealed_blob+salt）后，可对候选口令逐个
  离线执行 KEK 派生+GCM 解封试错（GCM tag 即口令正确性 oracle）——600k 轮
  只提高单次成本，**不改变离线可枚举的结构**。口令熵不足时（人类口令分布）
  该面即现实威胁。
- OPAQUE（RFC 9380）的结构性消灭原理：口令→rwd 的派生需**服务端 OPRF 私钥
  k_oprf**参与（盲化求值）；拖库者拿走 credential file 却**拿不到 k_oprf**，
  任何离线 rwd 候选都无法验证——字典攻击被迫转为**在线**（每个候选一次与
  服务端的交互，受限速/审计面覆盖）。这就是本论证要达成的目标形态。

## 1. OPRF 在 SM2 群的实例化（件①）

### 1.1 群选择与域参数

SM2（GM/T 0003.5-2012）：256-bit 素域 prime curve，y²=x³+ax+b over F_p，
p=2^256−2^224−2^96+2^64−1，a=−3（mod p），b≠0，基点阶 **n 为素数、
cofactor h=1**。OPRF/VOPRF 的群要求=**素数阶群**（DDH/OMDL 语义面）——
SM2 主群 cofactor=1 天然满足，**无需 cofactor 清除步骤**（相对 Curve25519
Edwards 形态的 ristretto 包装，SM2 实例化反而更直接：直接用主群）。
DDH 假设强度：SM2 与 NIST P-256 同为 256-bit 素曲线，index-calculus 界相同
（同安全级别，128-bit 语义）。

### 1.2 OPRF 构造（base mode，非 verifiable——选择理由见 §3 偏离 D7）

密钥：k ∈ [1, n−1]（k_oprf），对应公钥 K=[k]G。
- **Evaluate(sk, x)**（服务器）：y = [k]·H₂C(x)（H₂C=§2 的 hash-to-curve）
- **Blind(pwd, r)**（客户端）：α = [r]·H₂C(Harden_in(pwd))，存 blind=r
- **Finalize(pwd, r, β)**：y = Finalize(H₂C(Harden_in(pwd)), r, β) = β·[r]⁻¹
  （β 的仿射坐标 xy 作 KDF 输入域），rwd = Harden(Extract(y))（§4）
- 正确性：[r]⁻¹·[k·r]·H₂C = [k]·H₂C ✓（加法群标量乘交换律，平凡验证）

### 1.3 安全归约：OMDL（one-more discrete log）自写论证

**目标**：任何 PPT 攻击者 A 以 q 次 Evaluate 询问后，输出 q+1 个 H₂C 输入的
[k]·H₂C(xᵢ) 且不能解出对应 DL——其优势可归约为求解「q+1 次 DL 挑战」。

**论证骨架（generic group model，GGM）**：
1. GGM 下攻击者只能做群操作与 oracle 询问，群元素=不透明句柄（隐藏整数
   表示）——这是 Shoup 1997 以来的标准建模。**如实假设级标注**：GGM 是
   启发式模型（非标准假设归约），与 P-256 VOPRF（Jarecki-Krawczyk-Xu，
   CCS 2016/JOE 版）的归约**方法论同族**——本论证=该归约在素数阶群上的
   平移（SM2 群与 P-256 群在 GGM 下无区分），非独立新证明（§8 缺口 G1）。
2. Evaluate oracle 的实现方式（ challenger 以 k·H₂C(x) 应答）与「k+1 目标」
   的 self-reducibility：OPRF 输出 βᵢ=[k]αᵢ。攻击者要「more than one-more」，
   必须在 q 次受控询问外自行合成 [k]·H₂C(x*)——GGM 中任何合成项的「k 次
   数」都是句柄代数树上可追踪的整数系数；q 次询问最多给 q 个含 k 的新鲜
   基础项，第 q+1 个含 k 的独立项需要解 DL（否则只能线性组合已见项，其
   [k] 系数由已询问的 αᵢ 张成——选择 x*∉{αᵢ} 即失败）。归约器 B 收到
   OMDL 挑战 (G, [k]G, x₁..x_{q+1}) 后把 A 的 Evaluate 询问用挑战对答，
   A 输出 q+1 个合法 yᵢ ⟹ B 以其解 DL（self-reducibility 标准步）。
3. **omdl 假设陈述（SM2 群实例）**：给定 (SM2 群, G, [k]G, H₂C(x₁..x_{q+1}))
   与 q 次 [k]·H₂C(xᵢ) 询问 oracle，构造 [k]·H₂C(xⱼ)（任一新 xⱼ）的概率
   ≤ 1/n + negl(λ)。n≈2^256 ⟹ 概率界 ~2^-256 级。
4. **malicious-server 面（rwd 可伪造性）**：base mode 下恶意服务器可对
   任意 x 返回 [k]·H₂C(x) 或**假值**——客户端无法验证 β 合法。OPAQUE 场景
   的威胁模型=服务器是**诚实但被拖库**的一方（自托管），rwd 伪造不构成
   攻击目标（服务器本就持有 k）——因此 base mode 足够（RFC 9380 同款
   选择）。若未来引入**第三方托管 OPRF**（PEP 分离部署），必须升级
   VOPRF（可验证：附 NIZK 证明 k·α=k·H₂C(x) 的 DDH 元组证明）——列
   §3 偏离 D7 与演进注意。

### 1.4 SM2 群与 P-256 群的平移合法性论证

OMDL/GGM 论证是**群无关**的（generic group 只依赖「素数阶循环群」抽象）；
SM2 与 P-256 的差异（域参数、曲线方程系数）在 GGM 下不可见。SM2 特有结构
对 OPRF 面的影响核查：
- SM2 签名的 Z 值路径/nonce 结构（app/crypto/sm2.py:164 签名实现）与 OPRF
  标量乘**零共享**（OPRF 不使用签名原语）——签名侧已知分析不迁移；
- SM2 曲线无已知的超越 256-bit 通用界的攻击（index calculus 同族界）；
- cofactor=1：无 small-subgroup/limb-leak 面（对比 X25519 的 cofactor 处理）。

## 2. SM2 HashToCurve 构造选定与论证（件②）

### 2.1 现状：SM2 无 RFC hash-to-curve 套件

RFC 9380 定义了 P-256/P-384/P-521（SSWU for a=−3）/Curve25519（elligator 2）
等套件，**不含 SM2**；国内亦无国家标准化的 SM2 hash-to-curve（GB/T 32918.5
不含此内容）。这是**自构造+引一般性定理**的场景（§8 缺口 G2：标准互操作
缺口，如实）。

### 2.2 选定：Simplified SWU（SSWU）for a=−3，适配 SM2

RFC 9380 §6.6.2/6.6.3 的 SSWU 适用于 **a≠0 且 b≠0** 的 Weierstrass 曲线，
并对 a=−3 有专门简化式（map_to_curve_simple_swu_ −3 分支）。SM2：a=−3 ✓
b≠0 ✓ ⟹ **SSWU(-3) 公式直接适配**（无需 3-isogeny 链——那是 Curve25519
ell2 路径的待遇）。构造：

1. **Expand-Messages 层**：`expand_message_xmd(H=SM3, DST="FZ-OPAQUE-H2C-"
   ‖suite-id, len_in_bytes=64)`——DST 域分离纪律同 RFC 9380 §3.1（suite-id
   自注册：`SM2_P256_SSWU_SM3_` 命名族，**自注册≠标准化**（§8 G2））。
2. **hash_to_field**：64B 拆两个 32B 域元素（u∈F_p²），按 SM2 素数 p 做
   mod-p 归约（拒绝采样不需要——SSWU 全域覆盖）。
3. **map_to_curve_simple_swu(u)**：SSWU(-3) 分支公式（tv1..tv4 中间域），
   输出 (x,y)；Z 的选取：最小正整数 Z s.t. g(Z)=Z³+aZ+b 为非平方且
   g(-b/(Z·a)) 非平方——对 SM2 的具体 Z 值=**实施时数值搜索并钉入常量**
   （本批不实施，搜索算法与验收条件在此成文：对 i=1..p-1 逐个验证两条件
   +映射可逆性测试向量，实施批以 test vector 形式钉定）。
4. **clear_cofactor**：恒等（h=1，§1.1）。
5. **isogeny**：不需要（SSWU 直接落在目标曲线）。

### 2.3 论证

SSWU 的 indifferentiability 由 hash-to-curve 通用定理给出（Brier-Coron-
Icart-Kang-Lyubashevsky-Mantin 2010「Efficient Indifferentiable Hashing into
Ordinary Elliptic Curves」+RFC 9380 §4 的工程化重述）：SSWU map 与
clear_cofactor 复合在 h=1 时对任意素数阶曲线 indifferentiable from random
oracle（up to 2^-… 统计界，与曲线参数无关，只依赖「map 是非退化有限覆盖」
性质——SSWU 对任意 a≠0,b≠0 曲线成立）。**即：该构造的安全性论证不依赖
SM2 专属证明，是定理直接覆盖**——这比 OMDL（GGM 启发式）更强一档。

## 3. 与 RFC 9380 的逐条偏离清单（件③）

| # | RFC 9380 条目 | 本方案 | 性质 | 等级 |
|---|---|---|---|---|
| D1 | 群=NIST P-256/ristretto（附录套件） | SM2 prime-order group（h=1） | 平移（同语义素数阶群，GGM 下不可分） | 低 |
| D2 | hash-to-curve=RFC 套件（P256_SSWU_SHA256 等） | SSWU(-3)+SM3 xmd 自构造套件（§2） | **自构造**——定理覆盖但无 RFC 对照套件/互操作基线 | 中（G2） |
| D3 | Expand=HKDF-SHA256 提取层（extract/expand 双层） | HMAC-SM3 同构双层（extract+expand） | HKDF-SM3 无 RFC 基线（工业实践先例在案） | 低 |
| D4 | Harden：RFC 建议 Argon2id 等记忆困难函数 | PBKDF2-HMAC-SM3 600k（与 v4 KEK 同域参数——国密无 Argon2） | 慢哈希强度弱于记忆困难型（GPU/ASIC 并行面），如实 | 中 |
| D5 | AKE：RFC 允许任意 AKE，推荐强 KCI/UKS 性质（3-DH 族） | 保留现行 SM2 挑战-应答（nonce 一次性+链级 burn） | **现状已如此，OPAQUE 不恶化**——但 AKE 强性质（前向保密/PFS）弱于 3-DH，如实列缺口（G3） | 中（G3） |
| D6 | Envelope：RFC 9380 §4.3 credential protection（secret/audit 口径+key commitment） | 保留 key commitment 机制；envelope 载荷=现行 v4 信封内容（私钥/身份资料） | 形态适配（载荷语义替换），机制对齐 | 低 |
| D7 | OPRF mode：base mode（RFC 9380 用 base） | base mode | 对齐（单 server 自托管）；第三方托管须 VOPRF（演进注记） | 低 |
| D8 | clear_cofactor | 恒等（h=1） | 对齐（简化） | 无 |
| D9 | identifiers（RFC 9380 §4.1 verifiable 通道的身份串接） | base mode 无 verifiable 通道；Harden 输入附 username 作 domain separation（防跨账户 rwd 拼接） | 设计选择（RFC 同款建议） | 低 |
| D10 | CSPRNG | secrets（RFC 4086 口径一致）；SM2 内部 k=secrets（gmssl random 弃用已根修——sm2.py docstring 在案） | 对齐 | 无 |

## 4. 协议流程（件④——注册态/登录态）

### 4.1 注册态（新建账户；与现行 `/ra/register`+激活面嫁接）

```
Client(浏览器)                                   Server(backend)
  pwd ──Harden_in──> x = H2C-in候选
  blind: r ∈ CSPRNG; α=[r]·H2C(x)
  ──────────────── α, username ────────────────>
                                    β = Evaluate(k_oprf, α)   [OPRF]
  <──────────────── β, salt, envelope 流程 ───────
  rwd = Finalize(x, r, β) = Harden(Extract(unblind(β)))
  KEK = HKDF-SM3-Extract/Expand(rwd, "FZ-OPAQUE-KEK|v1"‖salt)
  钥对生成+密封: v5' 信封 = SM4GCM(KEK)(sk‖profile)
  <──── envelope 上传（register/activate 面）────
                                    存 accounts.sealed_blob
                                    存 OPRF record（username→元数据）
```

与现行嫁接点：**v4 信封的 KEK 源换代**（PBKDF2(pass,salt) → rwd 派生），
信封形态/GCM/AAD 纪律不变；登记承诺/RA 签发链路零变化。

### 4.2 登录态（含现行 SM2 挑战-应答 AKE 保留）

```
  prelogin: mode=opaque（prelogin 元数据：无 sealed_blob 下发！——现行
  /auth/keystore 公开密封件下发的面在此收口）
  blind: α=[r]·H2C(Harden_in(pwd))
  ──── α ────────────────────────────────────>
                        β=Evaluate(k_oprf,α); 挑战 nonce（SM2 AKE 保留）
  <─── β, nonce ──────────────────────────────
  rwd = Finalize(...)  → KEK
  现状登录序：keystore 解封（KEK=KEK(rwd)）→ SM2 sign(FZ-AUTH-LOGIN|nonce)
  ──── sig ──────────────────────────────────>
                        验签→会话（零变化）
```

要点：**envelope 下发窗收口**——现行 `/auth/keystore/{u}` 任意人可拉密封件
（离线枚举面本体）；OPAQUE 化后密封件仅在 β→rwd 派生成功后下发（或不下发
——envelope 改由服务端持 Protect(rwd) 形态，RFC 9380 server-side credential
file 模式，二选一在实施批定）。SM2 挑战-应答 AKE 完整保留（§3 D5）。

### 4.3 rwd→KEK 派生

`KEK = HKDF-SM3(Extract(rwd), salt=nonce_reg, info="FZ-OPAQUE-KEK|v1", 16B)`，
再经 Harden 迭代（PBKDF2-HMAC-SM3 600k 以 rwd 替代 pass——双因子：OPRF 私钥
盲化层+慢哈希层，RFC 9380 的 rwd Harden 同构）。

## 5. k_oprf 入 KMS 生产注册表（件⑤）

`app/kms/__init__.py:36-47` PRODUCTION_REQUIRED_KEYS 增第 11 钥：

```python
("FZ_OPRF_SK", "OPRF 拖库面防护服务钥（SM2 scalar，rwd 派生根）", "sk32"),
```

- **拒启语义自然延伸**：production 档缺 FZ_OPRF_SK=拒绝以派生钥启动（同 10 钥
  纪律——派生钥=SM3(公开常量)，任何人可推算 ⟹ OPAQUE 防护归零，必须拒）。
- **轮换联动**（scripts/rotate_kms_keys.py 同表扩展）：k_oprf 轮换 ⟹ 存量
  rwd 全部失效 ⟹ **所有 v5' 信封需客户端重跑注册序**（重密封）——比 FZ_WRAP_KEY
  轮换（重登记）更重：方案=**双钥过渡窗**（k_old 保留只读 Evaluate 至全部
  账户迁移完成，新注册用 k_new），迁移序见 §6。
- **provider 对接**（1.4 抽象层）：OPRF Evaluate=[k]·H₂C 标量乘——HSM 到位后
  归入「私钥不出硬件」面（k_oprf 入 HSM 钥槽，Evaluate 走 PKCS#11 标量乘
  原语；1.4 类 docstring 钥槽策略同源）。

## 6. v4 存量惰性重封迁移方案（件⑥）

先例=v3→v4 惰性重封（拍板③：注册停发 v3+FZ_V3_CUTOFF_TS 截止+production
存量告警+登录惰性升级 v3→v4 同口令重封——全部在案复用）：

1. **停发**：新注册/重置一律 OPAQUE 形态（v5' 信封+rwd 派生）；OPAQUE 未启用
   档（部署方不选）维持 v4 现状（**配置开关与现状兼容双轨**——同 v3 惯例）。
2. **惰性重封**：存量 v4 账户登录时——服务端以**旧路径**（口令 KEK）解封一次
   +客户端执行一次 OPAQUE 注册序（盲化面走旧口令）→新 v5' 信封落库+OPAQUE
   record 建→旧 init_verifier/sealed_blob 密封层作废。**一次明口令在客户端
   域的重放**（用户已提交登录口令=同一输入，无需二次索要）。
3. **截止开关**：FZ_OPAQUE_CUTOFF_TS（Unix 秒；0=不启用——同 FZ_V3_CUTOFF_TS
   语义）。到点后 v4 存量登录拒绝（403 引导机构重置）+production 启动扫库
   告警（存量计数+处置指引——同 v3 惯例代码路径）。
4. **回滚窗**：重封失败=保持 v4 态（不 burn 旧密封层——解封成功即证旧路径完
   好）；OPAQUE 形态异常回退=部署级开关（FZ_OPAQUE_ENABLED，缺省 off——
   演进项不激活现状）。

## 7. 恒时性与模糊注入测试计划（件⑦，入 crypto_audit）

1. **OPRF Evaluate 恒时性**：标量乘路径（[k]·H₂C）不分支于 k 位（底层
   gmssl _kg 的现状恒时性=既有缺口如实——provider/HSM 对接时由硬件原语
   兜底；软件档在 crypto_audit 加「Evaluate 时延分布」统计断言（与既有
   SM2 恒时性 KEK 派生 0.997×/验签 1.032× 同方法论：错误/正确中位比阈值
   1.3×）。
2. **Harden 迭代恒轮**：600k 轮计数器外泄面=零分支（PBKDF2 构造内建）。
3. **模糊注入**（crypto_audit 新增 OPAQUE 段，对 Evaluate/Blind/Finalize/
   元数据解析四口）：
   - α/β 非曲线点、无穷远点编码、超长 hex、非 hex、空串、符号注入（-x）
     ⟹ 全部结构化拒绝（400 族）零崩溃；
   - blind 元素域外（≥n）归约/拒绝语义钉定；
   - envelope 长度/首字节/AAD 篡改（复用 v4/v5 篡改负例族）；
   - rwd 派生输入错位（DST/username 错配）⟹ 解封必败（GCM tag）。
4. **互操作测试向量**：H₂C 的 SSWU test vector（固定 pwd→固定 α/β/rwd 十六
   进制）入 crypto_audit 锚定（跨引擎对拍同 KDF 纪律）。

## 8. 归约缺口清单（诚实红线——逐条可质证）

| # | 缺口 | 等级 | 处置 |
|---|---|---|---|
| G1 | OMDL 归约=GGM 启发式（非标准模型归约）；SM2-OPAQUE 无公开第三方安全证明/独立复现 | 中 | 方法论同族平移（P-256 VOPRF）；实施批可采购形式化/第三方密评 |
| G2 | SM2 hash-to-curve 无 RFC/国标套件（SSWU(-3)+SM3-xmd 自构造——定理覆盖但互操作/对照基线缺） | 中 | DST/套件命名自注册；实施批出 test vector 并投递标准化通道（可选） |
| G3 | AKE=SM2 挑战-应答（无 PFS，弱于 RFC 推荐 3-DH） | 中 | **现状已如此非新增**；OPAQUE 不改变 AKE 面；PFS 升级=独立演进项 |
| G4 | Harden=PBKDF2 600k 非记忆困难型（GPU/ASIC 并行面保留） | 中 | 国密无 Argon2；Harden 迭代数 env 可调（对齐 FZ_KDF_ITERATIONS 纪律） |
| G5 | HKDF-SM3 无 RFC 基线 | 低 | 工业实践先例；extract/expand 构造自证 |
| G6 | 软件档 OPRF Evaluate 非恒时（gmssl 标量乘现状）——侧信道残余 | 中 | 软件档如实标注；HSM provider 对接时由硬件原语消灭（§7.1 断言先入 crypto_audit 钉现状基线） |
| G7 | 无形式化验证（ProVerif/Tamarin 对 OPAQUE 嫁接面） | 低 | 实施批可选采购/赛后项 |
| G8 | base mode 无 verifiable 通道（恶意 server 可伪造 rwd 拒绝服务/锁定——自托管威胁模型下非目标面） | 低 | 第三方托管场景升级 VOPRF（§1.3 注记） |

## 9. 实施边界与验收预告（本批零代码）

- 本批交付=本文档（零代码零实施零指纹变化——纯文档批，doc_consistency 门禁）。
- 实施批（⑫，前置门已过）：§2 H₂C test vector+Z 钉定→§5 第 11 钥+拒启延伸
  →§4 注册/登录嫁接→§6 迁移+CUTOFF→§7 crypto_audit 三件（恒时分布/模糊注
  入/互操作向量）→provider/HSM 对接（1.4 抽象层消费）。
- 验收预告（实施批）：拖库模拟负例（拿库+离线枚举 oracle 消失=只能在线）+
  迁移全链（v4→OPAQUE 惰性重封实弹）+crypto_audit 新段全绿。
