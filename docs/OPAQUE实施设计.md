# OPAQUE 实施设计（⑫O-1 定稿——后续全部编码的合同）

> **依据（唯一协议基准）**：`docs/SM2-OPAQUE归约论证-修订版.md`（复评 **GO**，提交
> 8a10595；瑕疵 a~g 已按 GO 附件约束⑩随手更正，提交 4d1245b——更正均为非阻塞注记
> 级，承重论证零变化）。本文=该归约的**实施设计定稿**：把归约的规范性内容钉定到
> 字节/字段/端点/测试粒度，作为 O-2~O-7 全部编码批的合同。**实施照单施工，偏离
> 即违约**；改 §5.3 派生链等承重公式=整体替换+重走评审（归约 §5.3 原文纪律）。
>
> **基线锚**（本设计引用的代码事实均于 2026-10-12 读仓核实）：
> `backend/app/accounts/envelope.py:29`（ENVELOPE_V_CURRENT=4）、
> `backend/app/accounts/service.py:246`（_SEALED_BLOB_VERSIONS=(3,4)）、
> `backend/app/accounts/router.py:116-123`（/auth/keystore 无鉴权无限流现状）、
> `backend/app/accounts/service.py:506-521`（FZ_V3_CUTOFF_TS 先例）、
> `backend/app/accounts/service.py:619-635`（production 存量扫库告警先例）、
> `backend/app/crypto/sm2.py:98-114`（_kg_blinded）、
> `backend/app/kms/__init__.py:36-47`（PRODUCTION_REQUIRED_KEYS 十钥）、
> `backend/app/authz/service.py:591-612`（authz 域 0x05 门限信封 v5——与 accounts
> 域信封**不同列不同命名空间**，见 §1.1）、`backend/alembic/versions` 头=0027。

---

## 0. 实施约束十条落点总表（验收销号门）

GO 附件十条实施约束逐条落点（O-7 大考与各阶段独立审查员按本表逐条销号）：

| # | 约束（GO 附件原文） | 归约依据 | 本设计落点 | 实现载体（O-2~O-6） |
|---|---|---|---|---|
| ① | AKE 锁方案 B：零改动保留现役 SM2 挑战-应答，对外措辞锁死 §0.2 | §0.2/§8.2/§8.4 | 本设计 **§2.3/§8** | **负约束**：AKE 代码零改动（`service.py:524-560` login、`router.py:211-277` challenge/login 路由原样）；措辞=§8.2 禁用表述清单 |
| ② | keystore 鉴权+限流先于首个删除事务（红线） | §7.3 | 本设计 **§5.5** | O-3 落 `router.py:116` keystore_route 限流+410 门；**部署/合入序：O-3 先于 O-4**；§5.5 断言入 crypto_audit |
| ③ | mode-B（fake-record）为缺省形态 | §5.4/§5.5 | 本设计 **§6** | O-3 evaluate 端点 fake-record 路径+masked_response；偏离须附等效面分析（归约 §5.5 原文） |
| ④ | Z=−9 以附录 A 脚本重跑+SSWU/xmd test vector 入 crypto_audit，复评锚点作预期值 | §3.2+附录 A | 本设计 **§3.3/§9.1** | O-2 crypto_audit C9-1/C9-2/C9-3（预期值=归约 §3.2 六组 hex 逐字） |
| ⑤ | O-1/O-2/O-3 点校验落协议代码路径（非测试项），标量乘走 _kg_blinded | §2.3 | 本设计 **§2.4/§7.2** | O-2 服务端 evaluate 前置校验（400 族 fail-closed）+客户端 Finalize 前校验；标量乘=`sm2.py:98` _kg_blinded |
| ⑥ | §5.3 rwd→KEK 单链为唯一公式 | §5.3 | 本设计 **§1.4**（五步逐字转录+禁改注记） | O-2 `app/crypto/kdf.py` 增 HKDF-SM3 extract/expand；O-3 信封签发/解封仅此一链 |
| ⑦ | Evaluate 限流+审计事件（Cheon log2(Q)/2 纪律） | §2.4.5/§9-8 | 本设计 **§6.6** | O-3 evaluate_limiter（AttemptLimiter 复用）+台账事件；crypto_audit C9-7 |
| ⑧ | KMS 第 11 钥 FZ_OPRF_SK+production 拒启，轮换=全量 rwd 失效+双钥过渡窗 | §6/§10-G9 | 本设计 **§4** | O-2 `kms/__init__.py:36` 表增行+oprf_key()/oprf_key_old()；test_kms_production_guard 增例 |
| ⑨ | L=48B/96B+xmd 参数按 §3.3/§3.4（b≥2k 恰好达线，边界测试钉死） | §3.3/§3.4 | 本设计 **§3.1/§9.1** | O-2 常量模块+边界断言（b=256=2k、ell=3、96B）入 C9-2 |
| ⑩ | 瑕疵 a~g 随实施批顺手更正 | 复评 GO 报告瑕疵清单 | **已完成**（4d1245b，单独小提交）+O-6 核对表引用 | 归约文档头部更正记录段（七处逐条在案） |

---

## 1. 信封 v6 布局（约束⑥载体；对应任务书交付①）

### 1.1 版本命名与共存判别

**拍板：新信封版本号=6（不是归约行文中的「v5'」）**。理由：仓内「v5 信封」已被
authz 门限份额信封占用（`app/authz/service.py:596` `_V5_TAG=0x05`，MEMORY「存量
v5 信封」条同义）——accounts 域若再用 v5 号会造成文档/台账代际混排；v6 无歧义。
归约「v5'」系行文占位（其 §5.5 表格内的 mode 描述不受影响），本拍板属命名落位，
非协议偏离（记入 §1.5 钉定表 D-1）。

版本判别（`_SEALED_BLOB_VERSIONS` 扩为 (3,4,6)，`service.py:246`）：

| 形态 | 命名空间/列 | 首判别 | KDF 槽标记 | 解封派生 |
|---|---|---|---|---|
| v3（legacy） | accounts.sealed_blob（Text JSON） | `"v":3` | （无 kdf 槽） | SM3 迭代链 21000（`kdf.py:71` _legacy_v3） |
| v4（现行） | accounts.sealed_blob（Text JSON） | `"v":4` | `enc.kdf=="pbkdf2-sm3"`+iter | PBKDF2-HMAC-SM3(pass, salt, iter, 16B) |
| **v6（本批）** | accounts.sealed_blob（Text JSON） | `"v":6` | `enc.kdf=="opaque-rwd-v1"` | **§1.4 单链**（rwd 派生——口令不经任何直连 KDF） |
| authz v5（**非同域，仅防混名**） | authz 实名映射 blob（Bytes） | 首字节 `0x05` | —（门限 ECIES 路径） | 三份额域 2-of-3 合成（`authz/service.py:615` unwrap_any） |

判别纪律沿用 `envelope.py:64` unseal_envelope 的 fail-closed 口径：**未知版本/缺
槽=显式拒绝，不许静默兼容**（crypto_audit C2 同款负例锚平移到 v6）。

### 1.2 v6 字段表（字节级——定长纪律为 §6.3 masked_response 的 Nm 锚）

```json
{"v":6,
 "pk":"<128 hex——账户 SM2 公钥（x||y，64B）>",
 "enc":{"kdf":"opaque-rwd-v1",
        "env_nonce":"<24 hex——12B，KEK 派生 info 输入（§1.4 ⑤）>",
        "nonce":"<24 hex——12B，SM4-GCM IV>",
        "ct":"<64 hex——32B，SM4-GCM 密文（载荷=sk 32B，同 v4）>",
        "tag":"<32 hex——16B，GCM 认证标签>"}}
```

| 字段 | 字节宽 | 说明 |
|---|---|---|
| `v` | 1 整数 | 恒 6；形态门首判 |
| `pk` | 64B（128 hex） | 与 accounts.pubkey_hex 一致（入库门校验——`service.py:271` 同款） |
| `enc.kdf` | 13B ASCII | 恒 `"opaque-rwd-v1"`；形态门 fail-closed（v4 槽标记同构） |
| `enc.env_nonce` | 12B | KEK=Expand-SM3(rwd, env_nonce‖"FZ-OPAQUE-EnvelopeKey|v1", 16B) |
| `enc.nonce` | 12B | SM4-GCM IV |
| `enc.ct` | 32B（64 hex） | 恒 32B（载荷=sk_hex 解码）——**定长**；非 64 hex=形态拒绝 |
| `enc.tag` | 16B（32 hex） | GCM-128 |

- **AAD**：`AAD_V6 = b"FZ-OPAQUE-ENV-v6|rwd"`（v4=`FZ-KEYSTORE-v4|pass` 同构——
  KEK 源语义入 AAD；钉定值，见 §1.5 D-2）。
- **定长不变式**：全字段定宽 ⟹ v6 JSON 串字节长度恒定（实施批以常量断言钉死：
  同参数两次 seal 的 blob 长度逐字节相等位宽——长度漂移即 C9-5 枚举面红）。
- **与 v4 的结构差**：v6 无 `enc.salt`/`enc.iter` 槽——v4 的 iter 落盘是为「env
  调档不影响存量解封回放」；v6 的 KEK 源=rwd（非口令直连），salt/iter 属 rwd 派生
  参数、**信封解封前就要用**（先 rwd→masking_key→解掩码才见信封）⟹ 自描述无意义，
  改由服务端账面存储并在登录响应下发（§1.3/§6.2）。此为 v4 纪律的**有依据换代**，
  见 §1.5 D-3。

### 1.3 服务端存储面（accounts 域新增列——alembic 0028）

| 列 | 类型 | 语义 |
|---|---|---|
| `opaque_masking_key_hex` | String(64) NULL | 32B masking_key（§1.4 ④ 客户端派生、注册时上传；mode-B 掩码用）——NULL=无 OPAQUE 记录（v4 存量） |
| `opaque_kdf_salt_hex` | String(32) NULL | 16B Stretch 盐（§1.4 ② salt=accounts.salt 的落点）——客户端生成、注册/激活时上传（**D-8**——密封先于账户存在） |
| `opaque_kdf_iter` | Integer NULL | Stretch 轮数（缺省 600000，env FZ_KDF_ITERATIONS 档；G4 的 env 可调纪律落点）——客户端上传（**D-8**） |
| `opaque_key_id` | String(16) NULL | **k_oprf 钥指纹**=SM3(该钥公钥)前 8 hex（§4.3 轮换判别）——NULL=无记录 |

迁移 0028（头=0027 d0e1f2a3 之后）：四列全 NULL 缺省——存量 v4 行零回填、零语义
变化；演示档升级脚本照常 `alembic upgrade head`。

### 1.4 rwd→KEK 派生链（约束⑥——归约 §5.3 唯一公式逐字转录，禁改）

```
oprf_output  = Extract-SM3("", "FZ-OPAQUE-Finalize|v1"‖Y.x‖Y.y)     # ①Finalize 提取
stretched    = PBKDF2-HMAC-SM3(oprf_output, salt=opaque_kdf_salt_hex, opaque_kdf_iter)   # ②Stretch——全链仅此一次
rwd          = Extract-SM3("", oprf_output ‖ stretched)             # ③randomized_password 对位
masking_key  = Expand-SM3(rwd, "FZ-OPAQUE-MaskingKey|v1", 32B)      # ④掩码钥（§6）
KEK          = Expand-SM3(rwd, env_nonce ‖ "FZ-OPAQUE-EnvelopeKey|v1", 16B)   # ⑤信封钥
```

- ①~⑤ 与归约 §5.3 逐字一致（变量名按 §1.2/§1.3 落位：salt=服务端账面
  `opaque_kdf_salt_hex`、iter=`opaque_kdf_iter` 缺省 600000）。
- 资料密封槽（sealed_profile v6）独立域：
  `KEK_profile = Expand-SM3(rwd, profile_env_nonce ‖ "FZ-OPAQUE-ProfileKey|v1", 16B)`，
  AAD=`b"FZ-OPAQUE-PROFILE-v6|rwd"`，形态同 §1.2（`"v":6,"slot":"profile",…`）。
  独立 info 域=资料槽与信封槽同根不同钥（D6 载荷语义替换的槽位延伸，§1.5 D-4）。
- **改链=整体替换本节+重走评审**（归约 §5.3 原文纪律照录）。
- HKDF-SM3（Extract/Expand）为**新建原语**：`app/crypto/kdf.py` 增
  `hkdf_sm3_extract(salt, ikm)`/`hkdf_sm3_expand(prk, info, len)`——构造=RFC 5869
  标准双层，HMAC=既有 `app/crypto/hmac_sm3.py`；官方向量测试入 `tests/test_crypto_kdf.py`
  （只增）。参数位对齐归约记式：①③ 两处 `Extract-SM3("", 域串‖材料)` 的第一参
  =HKDF **盐位**（本链恒空串）、域串‖材料落 **IKM 位**；④⑤ 的
  `Expand-SM3(rwd, 域串, len)` 的 PRK=rwd、域串落 **info 位**。

### 1.5 对归约文档的钉定与澄清表（设计级决定——逐条给出理由，非偏离）

| # | 钉定 | 理由 |
|---|---|---|
| D-1 | 新信封命名 **v6**（归约行文 v5'） | §1.1——authz v5 已占用命名；零协议语义 |
| D-2 | AAD 常量 `FZ-OPAQUE-ENV-v6|rwd` / `FZ-OPAQUE-PROFILE-v6|rwd` | 归约未钉 AAD 字面；沿 v4「KEK 源入 AAD」工艺 |
| D-3 | v6 信封不带 salt/iter 槽；salt/iter 服务端账面+响应下发 | §1.2 论证——解封前消费的参数无法自描述 |
| D-4 | 资料槽独立 ProfileKey 域 | 同根域分离；归约 D6「载荷语义替换」授权范围内 |
| D-5 | salt/iter/env_nonce 均为**公开参数**（不入密） | KDF 盐与 nonce 非 secret——RFC 9807 同口径（masking_nonce 明文传输） |
| D-6 | masking_key 由**客户端派生、注册时上传**、服务端账面存储 | RFC 9807 §4 credential file 存 masking_key 的对位；§1.4 ④ 归约原文「由 rwd 派生」的双方各自可派（客户端解掩码/服务端掩码） |
| D-7 | masked_response 的 server_public_key 槽=engine_pub_hex()（公开验签钥） | 方案 B 无 OPAQUE-AKE 服务器钥——槽位取定长公开材料作身份锚；D6「载荷语义替换」授权范围（§6.3） |
| D-8 | **盐/迭代数客户端生成、注册/激活时上传、服务端账面存储**（O-3 实施期钉定——§1.3 初稿「服务端生成」更正） | 协议时序约束：客户端须在密封（v6 信封签发）前派生 rwd（§1.4 ②），而账户行此时尚不存在——服务端无法预先生成盐；登录时经 evaluate 响应回传账面值（§2.1 五键），D-6 masking_key 同款处理 |
| D-9 | 改密门细化（§5.6）：**v6 账户（记录在账）须 v6'+新 masking_key 原子换新**（防「新 rwd 信封+旧掩码钥」永不可解错配）；v4 存量（无记录）保留 v4→v4 现役语义（不得携带 masking_key）；盐/迭代不轮换 | §5.1 门在改密场景的精确化——v4→v6 的形态切换属 O-4 迁移通道语义，改密不越通道 |
| D-10 | Stretch（§1.4 ②）输出宽度=**32B** | 归约 §5.3 未钉长度处；取 SM3 摘要宽（32B）作 ③Extract 的输入域——客户端唯一消费方（服务端零 rwd 派生），JS↔PY 对拍锚钉死 |
| D-11 | **迁移体携带与注册同构的 D-8 四件套**（sealed_blob+masking_key_hex+kdf_salt_hex+kdf_iter——§5.1-3 初稿回传体列表漏盐/迭代两件，O-4 实施期更正） | 惰性重封的客户端注册序（会话内 §2.2）生成盐/迭代并用于密封——服务端落账四列缺一不可（登录响应回传面依赖）；客户端链本体=app/accounts/client.py（运营件，scripts/script_auth 种子动线与 O-5 JS 共用对拍参照） |

---

## 2. OPRF 消息流（对应任务书交付②；约束①⑤载体）

### 2.1 端点形态：单端点双态复用

新增 `POST /auth/opaque/evaluate`（RFC 9807 CredentialRequest/RegistrationRequest
的统一对位端点）：

- 请求：`{"username": str, "alpha_hex": "<128 hex>"}`（α=盲化元素 64B）。
- 响应（**恒五键、恒定长**——注册态/登录态/未注册三态同形，§6.1）：
  `{"evaluated_message": "<128 hex β>", "masking_nonce": "<64 hex 32B>",`
  `"masked_response": "<定长 hex>", "kdf_salt_hex": "<32 hex 16B>", "kdf_iter": <int>}`
- 注册态客户端只消费 `evaluated_message`；登录态客户端五键全消费。恒形理由：
  任何「按态分形」的响应即注册状态 oracle（§6 防枚举的第一前提）。

### 2.2 注册态时序（归约 §5.1 嫁接面逐条落位）

```
Client(浏览器)                                 Server(backend)
  oprf_input="FZ-OPAQUE-OPRF|v1"‖0x00‖username‖0x00‖password   （归约 §2.2 域串，逐字）
  r ←$ Z_n*（secrets/webcrypto CSPRNG；禁 Math.random）
  α=[r]·H2C(oprf_input)                        （§3 构造；O-2 客户端侧）
  ── POST /auth/opaque/evaluate {username, alpha_hex} ──>
                                 O-1 点校验（§2.4）；限流（§6.6）
                                 β=[k_oprf]·α（_kg_blinded 路径，O-3）
  <──── β, masking_nonce*, masked_response*, kdf_salt_hex*, kdf_iter* ────
  （*注册态忽略——恒形占位）
  Y=[r⁻¹]·β；O-2 校验 Y∈曲线
  oprf_output/rwd/masking_key  （§1.4 ①③④）
  生成钥对（既有 sm-crypto generateKeyPairHex）+ v6 信封密封（§1.2；盐/迭代客户端
  生成——D-8）
  ── POST /auth/register {username, pubkey_hex, sealed_blob(v6), masking_key_hex, kdf_salt_hex, kdf_iter} ──>
                                 形态门（v6+kdf 标记+公钥绑定）
                                 账面落 opaque_key_id（当前钥指纹）+掩码钥/盐/迭代（D-8）
                                 存 accounts.sealed_blob(v6)（一事务）
  <──── 201 ────
```

- 服务端**零口令派生材料**：账面只有 β 计算的副产物 α（不落盘）、masking_key
  （rwd 的派生钥——非 rwd 本体、非 KEK，拖库面分析见 §6.5）、salt/iter（公开）。
- 嫁接点零变化（归约 §5.1 原文）：信封形态/GCM/AAD 纪律换代不换面；登记承诺/RA
  签发链路零触碰。
- 预置机构账户激活态（pending_activation）：同 evaluate（真实 β——激活序要封
  v6），`/auth/activate` 门序（时效/激活码/核对子，`service.py:427-498`）零变化，
  仅 `ActivateIn` 增 `masking_key_hex`+v6 形态门。

### 2.3 登录态时序（归约 §5.2；**AKE=方案 B 零改动**——约束①）

```
Client                                         Server
  prelogin（现状零变化；v6 账户 mode=challenge）
  α=Blind(oprf_input)                          （同 §2.2）
  ── POST /auth/opaque/evaluate ──>
                                 O-1 校验；β=[k]·α；
                                 masking_nonce←$32B；
                                 pad=Expand(masking_key, masking_nonce‖"MaskedResponse", …)（§6.3）
                                 masked_response=pad⊕(server_pub‖envelope)
  <──── β, masking_nonce, masked_response, kdf_salt_hex, kdf_iter ────
  O-2 校验 β；Y=[r⁻¹]β；rwd（§1.4 ①②③——salt/iter 取响应值）
  masking_key'=Expand(rwd,…,32B)（客户端自派，§1.4 ④）
  解掩码取 envelope → KEK（§1.4 ⑤）→ SM4-GCM 解封 → sk
  pubkey_from_priv(sk)==响应 pk 自校（客户端侧；服务端入库门已有）
  ── 以下现役 AKE 原样（方案 B——零代码改动） ──
  ── POST /auth/challenge/{username} ──>        一次性 nonce（service.py:382）
  sig=SM2Sign("FZ-AUTH-LOGIN|"+nonce)           （auth.ts:407 同口径）
  ── POST /auth/login {username, nonce_hex, sig_hex} ──>
                                 验签→会话（service.py:524 login 零改动）
```

- 错口令语义：rwd 错 ⟹ masking_key' 错 ⟹ 解掩码得乱码 ⟹ v6 形态门/GCM 败 ⟹
  **客户端本地**人话判词（「密码错误」）；服务端全程零口令知识、无新失败 oracle
  （与 v4 GCM 失败同 UX）。服务端可见的唯一新面=evaluate 请求（受限流/审计覆盖，
  §6.6）。
- v4 存量账户登录：**不走 evaluate**（无 OPAQUE 记录——pre-auth evaluate 对其
  返回 fake 形态，§6.1），走现役 keystore 拉取+解封+挑战-应答；登录成功后触发
  §5.1 惰性重封（会话内 evaluate 取真实 β）。

### 2.4 O-1/O-2 点校验前置条件（约束⑤——规范条目落代码路径，非测试项）

- **O-1（服务端，evaluate 入口第一道门**，先于限流后的任何标量乘）：
  `alpha_hex` 必须 128 hex、解码 64B、x=p[0:32]∈[0,p)、y=p[32:64]∈[0,p)、
  y²≡x³+ax+b (mod p)、且 (x,y)≠无穷远（128hex x||y 编码下无穷远无表示——长度
  门即拒）。校验失败=`AccountError("opaque_invalid_point",…,400)` 结构化拒绝，
  **绝不进入标量乘路径**（路径断言见 §9.1 C9-6）。复用 `_point_on_curve`
  （`sm2.py:67`）+新增坐标域检查（现函数未查 x<p——O-2 批补全，两调用方共享）。
- **O-2（客户端，Finalize 前）**：β 同款校验（128hex/域内/曲线方程）——恶意/
  被劫持服务端回非曲线点的对偶面；JS 侧 `sm2group.ts` 提供同一谓词，JS↔PY 对拍
  锚钉死（负例同族）。
- **O-3（标量乘纪律）**：服务端 β=[k]α 一律走 `_kg_blinded`（`sm2.py:98`，
  d=d1+d2 随机分裂双乘）——构造 `CryptSM2(private_key=k_hex,…)` 后调既有路径；
  禁直接调 gmssl `_kg`（审查红线：evaluate 路径 grep 无裸 `_kg(` 调用）。
- 威胁机理照归约 §2.3（无效曲线点逐位提取 k、盲化不消除无效点泄漏）——**校验是
  归约 §2.4 的前提成立条件**，不是防御纵深选项。

---

## 3. HashToCurve 参数钉定（对应任务书交付③；约束④⑨载体）

### 3.1 常量表（实现=单一常量模块，禁散落；归约 §2.1/§3.2/§3.3/§3.4 逐字转录）

| 参数 | 值 | 来源 |
|---|---|---|
| p | `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF` | SM2 域参数（default_ecc_table，禁手抄） |
| a | −3 (mod p) | 归约 §2.1 |
| b | `0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93` | 同上 |
| n（群阶） | default_ecc_table["n"] | 素数、cofactor h=1（clear_cofactor=恒等） |
| **Z（SSWU）** | **−9** | 归约 §3.2 钉定（四准则全过+|Z|≤12 正负全域唯一——瑕疵 g 强化在案） |
| L（hash_to_field） | **48 B/元素；双元素 len_in_bytes=96 B** | 归约 §3.3（ceil((256+128)/8)） |
| xmd 哈希 H | SM3（b=256 bit，s=64B 块） | 归约 §3.4 合规账 |
| DST | `"FZ-OPAQUE-V1-" ‖ "SM2_P256_XMD:SM3_SSWU_RO_"` | 归约 §3.4 套件自注册命名（≥16B/≤255） |
| xmd 结构 | msg_prime/Z_pad/l_i_b_str/b_0/b_i 链 | RFC 9380 §5.3.1 原文（归约 §3.4「照原文实现」） |
| sgn0 | sgn0(y)=sgn0(u) 符号纪律 | RFC 9380 §6.6.2（归约 §3.4 第 6 步） |
| 例外锚 | u=0 或 Zu²=−1 ⟹ t=0 ⟹ x1=B/(Z·A) | RFC §6.6.2 原文+归约 §3.2 c4 |
| inv0 | 逆元不存在（输入=0）时返回 0（RFC inv0 语义） | SSWU 步骤 `1+inv0(…)` 的容错分支 |

### 3.2 构造全序（六步——归约 §3.4 逐字；实现序=测试序）

```
hash_to_curve(msg):
  u  = hash_to_field(msg, 2)     # xmd-SM3，96B → u0,u1
  Q0 = map_to_curve_sswu(u0)     # x1=(−B/A)(1+inv0(t)) / x2=Z·u²·x1，t=Z²u⁴+Zu²
  Q1 = map_to_curve_sswu(u1)
  R  = Q0 + Q1                   # 群加
  P  = clear_cofactor(R)         # h=1 ⟹ 恒等（保留调用点作规范形状）
  return P
```

### 3.3 附录 A 锚点值（crypto_audit C9-1 预期值——归约 §3.2 hex 逐字照录，禁改写）

| 锚点 | 预期值（256-bit hex） |
|---|---|
| Z mod p | `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFF6` |
| c1：pow(Z,(p−1)/2,p) | p−1（非平方） |
| c3：x^p mod (g(x)−Z) 三系数（多项式模幂与 3×3 伴随矩阵幂**双路径逐字相等**） | `0x8c9b89bfd1217964cbbb138058b0a0daa3b7f144a2f84220a2f180e8ccd6f67b`、`0xa9c084b3c7fe741cb3c962235b7488198cf94416992a3679f24adff4ad1576b7`、`0x39b23b1f976f434d9a22763fd3a7af92ae24075d2e83def02e873f8b999484c2` |
| x0=B/(Z·A) | `0x993812c2e964b7a31f4f35452d9b7222aa35051b7294938ac5d7953b4eb9a1b9` |
| g(x0) | `0x415bc055b574f716255dc77649a3c4025b1d89280c892d901229a8831df50f44`（Euler 残差=1） |
| P-256 交叉验证 | 同一判定器 \|Z\|≤12 唯一通过 Z=−10=RFC 9380 发布值；淘汰轨迹：−1(c2)、−2/−4/−5/−8/−9(c3)、−3/−6(c1)、−7(c4) |
| SM2 淘汰轨迹 | −1(c2)；−2/−3/−5/−6/−7/−8(c3)；−4(c4)；**−9 通过**；+1~+12 全灭（全域唯一性——瑕疵 g 强化实测） |
| SSWU 恒等式 | g(x2)=Z³u⁶g(x1) 且 gx1/gx2 恰一平方——30 组随机 u 抽样断言（复评实测口径） |

### 3.4 边界钉死（约束⑨「边界测试钉死」的落点清单）

- `b≥2k`：SM3 b=256 与 2k=256 **恰好达线**——断言 `_XMD_B == 2*_SECURITY_K`（不
  留冗余余量的形态断言；参数漂移即红）。
- `s=64`、`ell=ceil(96/32)=3≤255`、`len_in_bytes=96≤65535`、DST 长度域——四项
  xmd 合规账逐项断言（归约 §3.4 账面→测试四行）。
- L=48：`hash_to_field(msg,2)` 输出恒 96B；单元素大端 mod p。
- 统计距离口径：48B 源下 mod-p 偏差 <2^−128（归约 §3.3 修正账——注记入常量模块
  docstring，测试不做统计断言[账面为解析事实]）。

---

## 4. k_oprf 入 KMS 生产注册表第 11 钥（对应任务书交付④；约束⑧载体）

### 4.1 注册表增行（`app/kms/__init__.py:36` PRODUCTION_REQUIRED_KEYS）

```python
("FZ_OPRF_SK", "OPRF 拖库面防护服务钥（SM2 scalar，rwd 派生根）", "sk32"),
```

（归约 §6 原文行转录。首位空缺顺延为第 11 钥；`scripts/rotate_kms_keys.py` 同表
同源自动纳管。）

### 4.2 取钥与拒启语义

- `oprf_key() -> str`：env `FZ_OPRF_SK`（64 hex，域校验 [1,n−2] 同 `_assert_priv`）
  优先；缺省=演示档 SM3 域派生 `_derive_priv(b"FZ-KMS|oprf")`（幂等锚——**非生产
  凭据**，纪律同 KMS 既有十钥）。
- **production 拒启**：`assert_no_demo_keys_in_production()`（`kms/__init__.py:50`）
  经注册表遍历自动覆盖 FZ_OPRF_SK——缺 env 即 RuntimeError 人话列缺（**拒绝以
  公开派生钥启动：派生钥人人可算 ⟹ OPAQUE 防护归零**——归约 §6 原文语义）。
- G9 同泄缓解边界照归约 §10：KMS 拒启①/轮换②/HSM 演进③/部署纪律④/残余⑤
  （部署方违规同泄无技术强制）——实施批在 `生产部署与安全演进.md` 补部署域分离
  强制条（O-6 文档面）。

### 4.3 轮换=全量 rwd 失效+双钥过渡窗（归约 §6 原文落地）

- 仪式：`FZ_OPRF_SK_OLD`←现值；`FZ_OPRF_SK`←新随机值（rotate 脚本出 env 行+指纹）。
- **key_id 判别**：每账户 `opaque_key_id`=SM3(该钥公钥)前 8 hex；evaluate 时按
  记录 key_id 匹配 {current, old} 指纹取钥——
  - 匹配 current：正常；
  - 匹配 old：**只读 Evaluate**（过渡窗存量登录可解）；该账户下一次注册序事件
    （改密/重置/重封）即改绑 current 指纹（惰性轮换——与新注册同通道）；
  - 皆不匹配：记录作废（401 引导重置——k 已不可得，rwd 永不可派）。
- 过渡窗收口判据（v3→v4 先例同构）：production 启动扫库告警
  `count(opaque_key_id==old 指纹)>0`（`v3_envelope_stock_report` 同款工艺，
  `service.py:619`）；清零后移除 FZ_OPRF_SK_OLD（k_old 销毁 ⟹ 未轮换账户 rwd
  **全量失效**=必须重置/重注册——归约 §6「存量 rwd 全部失效」的精确语义，
  窗长=部署方运营决策，代码面只保证「窗内有界+清零可见」）。
- provider 演进注记（归约 §6 原文）：HSM 到位后 k_oprf 入槽，Evaluate 走 PKCS#11
  标量乘原语——S5 provider 抽象（`app/crypto/provider.py`）扩展点，本批不实现。

---

## 5. 迁移方案：v4 存量惰性重封（对应任务书交付⑤；约束②红线）

### 5.1 触发点与流程（主体=客户端域——归约 §7.1-2 纠正后的原文形态）

- **停发**：`FZ_OPAQUE_ENABLED`（缺省 on；=0 为双轨回退开关）——on 时
  `/auth/register`、`/auth/activate`、`/auth/password/change` 形态门只收 v6
  （v4 blob=422 引导刷新，`service.py:322` v3 停发同款）。
- **惰性重封触发点=v4 账户登录成功后（会话内一次性）**：
  1. v4 账户按现役路径登录（§2.3 尾段——keystore 拉取+PBKDF2 解封+挑战-应答）；
  2. 登录成功、口令仍在内存的同一会话内：**同口令**走 §2.2 注册序（真实 β——
     携会话的 evaluate，§6.1）得 rwd→v6 重封+masking_key 派生；
  3. `POST /auth/opaque/migrate`（**会话鉴权**；体=v6 sealed_blob+masking_key_hex
     +可选 v6 sealed_profile）：服务端校验 v6 形态+公钥绑定一致后
     **同一事务**写入 {sealed_blob=v6, opaque_masking_key_hex, opaque_kdf_salt_hex,
     opaque_kdf_iter, opaque_key_id}——该 UPDATE 即 §5.4 的「删除事务」（旧 v4
     blob 被**同事务原子覆盖**，无窗口期双形态并存）。
- 服务端域**没有也不需要明口令**（归约 §7.1-2 原文）。一次明口令在客户端域重放
  （同输入，无需二次索要——与 v3→v4 惰性升级 UX 同感，`auth.ts:262` 先例）。

### 5.2 截止开关 FZ_OPAQUE_CUTOFF_TS（归约 §7.1-3；FZ_V3_CUTOFF_TS 同构）

- env `FZ_OPAQUE_CUTOFF_TS`（Unix 秒；0/缺省=不启用——**缺省不启**，与
  `service.py:506` v3 先例逐字同构，显式非法值抛错 fail-visible）。
- 到点后：v4 存量登录拒绝（403「旧版密钥封装已过截止期——请联系机构重置凭证」，
  在挑战消费之前裁决不烧 nonce）；production 启动扫库告警（存量 v4 计数>0 人话
  文案——§5.3 系统级收口判据）。

### 5.3 双轨兼容与完成判据

- 双轨：`FZ_OPAQUE_ENABLED=0` 全量回退 v4 现役（evaluate 端点 503 关闭态）；
  on 态下 v4 存量/新 v6 两形态并存至各自收口。
- 完成判据（归约 §7.2 原文）：账户级=删除事务（§5.1-3 UPDATE）提交；系统级=
  FZ_OPAQUE_CUTOFF_TS 到点+production 扫库存量计数=0。

### 5.4 旧 blob 删除语义（归约 §7.2 钉死——不可逆点）

- **不可逆点=migrate 事务提交**：提交前任何崩溃 ⟹ 账户仍 v4（可重试——回滚窗
  语义：重封失败保持 v4 态，不 burn 旧密封层）；提交后 ⟹ v4 路径对该账户永久
  失效（blob 已换代，PBKDF2 链不再可用——不可恢复）。
- 故**前置条件（§5.5）必须先于首个删除事务就位**——红线。

### 5.5 keystore 前置序（约束②红线——归约 §7.3 逐条落位）

现状（`router.py:116-123` keystore_route：**无鉴权、无限流**，任意人可拉任意
username 密封件=离线枚举面本体）处置，**O-3 先于 O-4 部署/合入，硬序**：

1. **限流先行（O-3 第一提交）**：keystore_route 挂 `auth_limiter`（键
   `keystore|ip|username`，10 发/300s 同族桶——`service.py:193` 同款落库共享窗）；
2. **通道收口（O-3 第二提交）**：v6 账户（opaque 记录在账）请求=410
   「已迁移 OPAQUE 通道——密封件经登录掩码响应下发」；仅 v4 过渡存量保留拉取
   （登录鸡-蛋：v4 解封需先取件，无法前置会话鉴权——诚实残余：v4 过渡窗内该
   账户类枚举面存活至 CUTOFF，跨账户批量拉取受 1 的限流压制。归约 §7.3-1 的
   「会话鉴权」选项落于 §5.1-3 的 migrate 端点（会话内）；「masked_response 通道」
   选项=v6 形态本体——两选项的落位均在案）；
3. **顺序红线**：2 落地之前不得发生任何 §5.4 删除事务（否则迁移窗口内枚举面
   公开存活）——O-4 的 migrate 路径在代码内前置断言 keystore 收口常量在位
   （模块级 import 校验，评审可 grep）。

### 5.6 改密/重置与 v6 的交互（O-4/O-6 交互注记）

- 自助改密（会话内）：新口令→真实 β（会话 evaluate）→rwd'→v6' 重封+新
  masking_key→`/auth/password/change` 扩展体（v6' blob+profile 槽 v6'+masking_key），
  原子换新（`router.py:159` 现役原子语义保持）；salt 不轮换（rwd 已随口令换根）、
  key_id 改绑当前钥指纹。
- 离线重置（种子脚本）：回到 pending_activation（`service.py:680` 零变化）——
  下次激活即以新口令封 v6（自然轮换点，§4.3 改绑窗口的收敛通道）。

---

## 6. 防枚举：mode-B fake-record+masked_response（对应任务书交付⑥；约束③⑦载体）

### 6.1 fake-record 路径（缺省形态——RFC 9807 §6.3.2.2 原文形态，瑕疵 d 已注记）

evaluate 真实求值的**唯一条件集**（其余一律 fake）：
（a）账户存在且 OPAQUE 记录在账；或（b）`status=="pending_activation"`（激活序
需真实 β）；或（c）请求携**本账户有效会话且会话属主==请求 username**（§5.1 惰性
重封/§5.6 改密的会话内真实 β）。其余（不存在账户/v4 存量 pre-auth）：

- `masking_key`←$32B 随机；`envelope` 槽=**定长全零字节**（长度=真实 v6 信封字节
  数——RFC 原文 "consisting only of zeros"；线上伪随机性由 pad 保证）；
- RFC fake-record 的随机 `client_public_key` 槽在本适配中并入 §6.3 的
  server_public_key 槽（fake 与 real 同填 engine_pub——槽值恒定公开，分布差异
  只来自 pad⊕(真 envelope) vs pad⊕(全零)，伪随机 pad 下不可分）；
- `evaluated_message`=β=[k]α（与真实路径同构——无记录可查即可算，分布同）；
- `kdf_salt_hex`←$16B 随机、`kdf_iter`=当前档——五键恒形。

### 6.2 响应字节账（定长——不可区分的载体）

| 域 | 长度 | fake 形态 |
|---|---|---|
| evaluated_message | 64B（128 hex） | [k]α 同构 |
| masking_nonce | 32B（64 hex） | ←$32B |
| masked_response | **Npk+Nm 定长**（server_pub 64B ‖ envelope 定长） | pad⊕全零 |
| kdf_salt_hex | 16B（32 hex） | ←$16B |
| kdf_iter | 整数 | 当前档 |

### 6.3 masked_response 构造（§5.4 记式逐字+消费口径钉定）

```
pad = Expand-SM3(masking_key, masking_nonce ‖ "MaskedResponse", Npk+Nn+Nm)
masked_response = pad[:Npk+Nm] ⊕ (server_public_key ‖ envelope)
```

- `Npk`=64B；`Nn`=32B（masking_nonce 长——RFC 9807 §6.3.1 记账对齐）；`Nm`=v6
  信封 JSON 定长字节（§1.2 定长不变式）。§5.4 记式的 Nn 项按记式保留在 pad 输出
  长度内，**异或消费取前 Npk+Nm 字节**（钉定消费口径——两实现不得自行解释，
  JS↔PY 对拍锚钉死）。
- `server_public_key` 槽位映射（D6 形态适配，方案 B 下无 OPAQUE-AKE 服务器钥）：
  =`engine_pub_hex()`（`kms/__init__.py:182`，64B 公开验签钥——服务端身份锚，
  定长公开材料；对位注记入 O-3 代码 docstring 与 §1.5 D-7）。
- masking_key 服务端取账面（§1.3 列）；fake 用随机——两侧 pad 皆伪随机（G5
  HKDF-SM3 假设挂账如实——归约 §5.4/§10-G5 原文）。

### 6.4 防枚举论证的引用关系

计算不可区分性论证=归约 §5.4 原文（两侧响应在 KDF 伪随机性+OPRF 输出不可区分下
不可分）；本设计的义务=**机制在位且分布等价可测**（§9.1 C9-5：三态响应长度恒定
+统计不可区分+时延 1.3× 阈内）。

### 6.5 keystore 端点面与 mode-B 的关系

mode-B 下 v6 信封仅经 masked_response 下发 ⟹ 独立 keystore 端点面对 v6 账户
消灭（§5.5-2 的 410 门）；拖库者拿 masking_key+envelope 无 k_oprf 仍在线
（归约 §5.5 表格「面等价」行——离线字典不可能性不受 masking_key 入账影响）。

### 6.6 Evaluate 限流+审计事件（约束⑦——Cheon log2(Q)/2 纪律落地）

- `evaluate_limiter = AttemptLimiter(max_attempts=10, window_s=300)`（复用
  `service.py:154` 落库共享桶——多副本同窗重启不清零）；键
  `opaque|ip|username`；429 人话判词同族。
- **审计事件**（AccountAdminLog append-only，action 常量钉定）：
  `opaque_invalid_point`（O-1 拒绝——主动攻击指示器逐笔留痕）、
  `opaque_rate_limited`（429——Cheon 配额耗尽留痕）。正常 evaluate 不入台账
  （高频面；配额纪律由限流桶承载）。
- Cheon 注记（归约 §2.4.5 原文）：Q 次合法响应 ⟹ 静态 DH 求解加速
  log2(Q)/2 位——限流把 Q 压到窗 10/300s（Q≈10⁴/日 ⟹ ~6.6 bit，可忽略）；
  断言=429 路径存在+台账行在（C9-7）。

---

## 7. 前端盲化技术选型（对应任务书交付⑦；O-5 实现基准）

### 7.1 候选与裁决

| 候选 | 形态 | 裁决 |
|---|---|---|
| **A. 纯 JS BigInt SM2 群运算** | 浏览器自持 Blind/Finalize（Fp 四则+点加/倍+标量乘+SSWU+xmd，新 TS 模块 ~300 行） | **选定** |
| B. 服务端两消息形态（浏览器零群运算——把盲化/去盲交服务端消息拆解，或客户端直接上送口令派生量） | 服务端代算 | **否决**（安全归零，见下） |
| C. WASM（Rust sm2 编译入前端） | 复用 zksvc 侧 Rust | 备选不采（工具链新面+体积，冻结期不引） |

**B 否决的安全论证**：mode-B 下信封存于服务端 ⟹ 若服务端获得任何**口令确定性
派生量**（oprf_input/H2C(oprf_input)/可直接验证的中间量），则运行时服务端（或
运行时妥协者）可对该账户信封**离线**逐候选执行 rwd 派生+GCM 试错（服务端自持
k_oprf，Evaluate 对任意候选自算）——归约 §0.2-1「拖库⟹在线化」的结构性收益在
该形态下对**服务端自身**坍塌为完全离线攻击。盲化的协议目的（归约 §2.2：服务端
只见 α=[r]·H2C(input)，r 均匀 ⟹ 与口令信息论无关）不可由服务端代算达成——
**客户端域群运算是 §0.2 宣称成立的必要条件，非性能取舍**。归约 §5.1/§5.2 时序
图中 Blind/Finalize 均钉在 Client 列——B 亦为归约偏离。

### 7.2 选定 A 的实现契约（O-5 基准）

- 模块划分：`gcs/web/src/lib/sm2group.ts`（Fp BigInt 四则+仿射点加/倍+标量乘
  （倍加法）+曲线点谓词=O-2 客户端校验）、`lib/opaque.ts`（Blind/Finalize/xmd-SM3
  展开/SSWU/域串常量——与后端常量模块逐字同源）；`keystore.ts` 增 v6 seal/open
  （§1.2 同构）；`auth.ts` 流程接线（§2.2/§2.3 时序）。
- 复用面：`sm-crypto`（钥对生成/挑战-应答签名——零改动）、`hash-wasm`
  （SM3/PBKDF2——xmd 与 HKDF-SM3 建于其上；HMAC-SM3 若 hash-wasm 无导出则在
  createSM3 上自实现 ~30 行——O-5 实测定，两径皆须 JS↔PY 对拍锚）。
- **对拍锚纪律**（deriveKekV4 先例，`tests/test_accounts.py:147`）：固定
  (username,password,salt,env_nonce) 黄金向量下，JS 与 PY 的
  {α, β, Y, oprf_output, rwd, masking_key, KEK, v6 blob, masked_response} 十件
  逐字节相等——pytest 内以 node 子进程实跑 TS 产出对拍（同 existing 工艺），
  入 `tests/test_accounts_opaque.py`。
- 恒时性注记：客户端标量乘处理**会话一次性随机 r**（用后即焚），浏览器 JS 非恒时
  实现的时序面攻击者=同源页面上下文（XSS 面大于此）——如实注记为客户端档残余
  （G6 客户端侧对应物，不涉 §0.2 宣称）；服务端侧恒时纪律不受影响（O-3 走
  _kg_blinded+§9.1 C9-7 断言）。
- 性能预算：登录冷路径增量=1 次标量乘+SSWU 两次 map+xmd 3 调用 ≪ 既有 PBKDF2
  600k 轮（~0.36s）——用户无感；演示档 UX 零变化红线（O-5 验收项）。

---

## 8. 宣称口径（对应任务书交付⑧；约束①——对外措辞锁死）

### 8.1 达成宣称（归约 §0.2 三条逐字，每条挂证据锚）

1. **拖库面**（仅得 DB，未得 k_oprf）⟹ 离线口令验证 oracle 消失，字典攻击被迫
   在线化——证据：归约 §2.4 归约（GGM 计数定理+引理+损失账）+本设计 §2（机制）。
2. **KCI 型性质**：服务器侧妥协（DB+信封，无 k_oprf）不足以冒充客户端——证据：
   归约 §0.2-2（RFC 9807 §10.2 语义对位，本方案中该字典攻击=在线形态）。
3. **响应不可区分**（防 username 注册状态枚举）——证据：本设计 §6+归约 §5.4
   （RFC 9807 §6.3.1/§10.9 机制对齐）。

### 8.2 不宣称（诚实收缩——逐字锁死）

> 本复合体安全等级=「OPRF 核心加固的口令门+信封保护+SM2 挑战-应答认证」，**不是
> RFC 9807 全义 aPAKE 等级**：因 AKE 层（现役 SM2 挑战-应答）无协议内前向保密，
> 不满足 RFC 9807 §10.2 明示的 AKE essential 要求（另一 essential 措辞与
> "forward secrecy is only achieved against eavesdroppers…" 句见归约 §0.2/§8.1，
> 锚已随瑕疵 a 更正）。该等级的达成=归约 §8.3 方案 A 演进项（六项义务清单在案，
> 未实施未证明前不宣称）。

### 8.3 禁用表述清单（全站对外文档扫描面——O-7 面③执行，此处钉死判词）

| 禁用表述 | 禁用理由 | 合规替代表述 |
|---|---|---|
| 「aPAKE 等级」「满足 RFC 9807」 | §0.2 不宣称条款——AKE essential 未满足 | 「OPRF 核心加固的口令门（方案 B 收缩宣称）」 |
| 「前向保密 / PFS」（协议内语义） | 现役 AKE 无协议内 PFS；传输面 PFS 属 TLS 部署形态 | 「无协议内前向保密；PFS=方案 A 演进项（义务清单在案）」 |
| 「完全抵抗拖库」「杜绝离线攻击」 | 绝对化宣称禁令（doc_consistency 同族） | 「离线字典 oracle 消失，攻击被迫在线化（受限速/审计覆盖）」 |
| 「KCI 安全（全义）」 | RFC 9807 KCI 语义依附 aPAKE 编译定理 | 「服务器侧妥协不足以冒充客户端（KCI 型性质，§0.2-2 语义）」 |
| 「OPRF 恒时」 | G6：软件档合法点上非恒时（_kg_blinded 去相关+无效点面已由 O-1 消灭） | 「标量乘走盲化路径；恒时性=统计断言钉基线（G6 在案）」 |

- 扫描范围：作品说明/框架规划/口径卡/README/性能档案/演示动线——`doc_consistency`
  增禁用短语行（O-6 文档批挂入 FORBIDDEN 表，元引述豁免沿用）。
- 残余面引用纪律：任何对外 OPAQUE 宣称段落须带 G 清单指针（G2/G3/G4/G5/G6/G9
  中相关项）——归约 §10 为常设限定面。

---

## 9. 测试计划（对应任务书交付⑨；约束④⑨销号载体）

### 9.1 crypto_audit 增例清单（新模块 **C9 OPAQUE 协议矩阵**——87 项基线只增）

| # | 增例 | 断言要点（阈值/预期值） |
|---|---|---|
| C9-1 | Z=−9 四准则复现（附录 A 脚本内联重跑） | §3.3 锚点表六组 hex **逐字**；c3 双路径（多项式模幂 vs 伴随矩阵幂）逐字相等；P-256 交叉唯一 −10+淘汰轨迹分类逐条 |
| C9-2 | xmd-SM3 test vector+边界四行 | 固定 msg→u0/u1 黄金 hex（实施批生成后钉死）；b=2k 恰好达线/ell=3/96B/DST 长度域断言 |
| C9-3 | SSWU test vector | 固定 u→(x,y) 黄金锚+恒等式 30 组抽样+例外锚 u=0→x1=B/(Z·A)+sgn0 纪律 |
| C9-4 | 注册/登录端到端回环（函数级） | §2.2/§2.3 全链绿；错口令=解掩码后形态/GCM 败（服务端零失败差异） |
| C9-5 | 枚举不可区分 | 三态（v6/未注册/待激活）响应五键长度恒定；masked_response 分布统计（卡方/频次，公平面）；已注册 vs 未注册 evaluate 时延中位比 <1.3× |
| C9-6 | O-1/O-2 负例族+路径断言 | 非曲线点/坐标≥p/无穷远编码尝试/超长/非 hex/空串/符号注入 → 全 400 族零崩溃；**断言未进入标量乘路径**（路径哨兵计数=0） |
| C9-7 | Evaluate 恒时/分布+限流 | 合法点上正确/错位输入时延中位比 <1.3×（C7 同法）；429+台账行（Cheon 纪律） |
| C9-8 | 模糊注入四口 | evaluate/blind/finalize/v6 blob 解析 ≥500 轮畸形输入：全拒+零崩溃零逃逸（C8 同法） |
| C9-9 | keystore 前置序 | v6 账户 keystore 请求=410；限流桶在位（429）；migrate 模块前置断言在位 |
| C9-10 | KMS 第 11 钥拒启 | production 缺 FZ_OPRF_SK→RuntimeError 人话列缺（test_kms_production_guard 增例联动） |
| C9-11 | 轮换双钥过渡窗 | key_id 指纹匹配 old 只读 evaluate 绿；新注册绑 current；皆不匹配=401 引导重置 |
| C9-12 | 迁移序 | v4 登录→会话 migrate 原子 UPDATE→v4 路径永久 403/410；CUTOFF 后 v4 拒登 403；回滚窗（migrate 失败零状态残留） |

### 9.2 后端 pytest 增例（先红后绿——负例先行）

- `tests/test_crypto_opaque.py`（O-2）：向量对拍（C9-1/2/3 同源）+原语负例
  （非曲线点/域外标量 r≥n 拒绝/inv0 分支）；HKDF-SM3 官方向量
  （`tests/test_crypto_kdf.py` 增例）。
- `tests/test_accounts_opaque.py`（O-3/O-4）：evaluate 三态恒形+fake-record 不可
  区分（长度/统计）、O-1 路径哨兵、限流+审计行、migrate 原子性（失败回滚零残留）、
  CUTOFF 开关、改密联动（v6' 重封+旧口令败）、JS↔PY 十件对拍锚。
- `tests/test_kms_production_guard.py`（O-2 增例）：FZ_OPRF_SK 行+拒启+FZ_OPRF_SK_OLD
  过渡窗。
- 回归红线：既有 `test_accounts.py`（v3/v4 全套）/`test_password_change.py`/
  authz 组零破坏（v4 用户照常登录）；全量 pytest 567 基线只增不减。

### 9.3 e2e 动线清单（O-6；演示口令面=固定 auditor123/admin123 纪律不变）

- `scripts/e2e_opaque.py`（新）：①飞手注册（浏览器生成钥对+OPAQUE 封 v6）→
  资料签发→登录→错口令（客户端判词+服务端零差异）→429 限流→会话态改密→再登录；
  ②种子 admin（auditor123）激活→登录→改密→再登录；③v4→v6 惰性重封（预置 v4
  形态账户登录→自动迁移→二次登录走 OPAQUE 通道+keystore 410）→CUTOFF 档
  （env 注入）拒登 403；④evaluate 限流族（11 连发 429）。
- `e2e_auth_full`/`e2e_browser_ui`：登录段照常全绿（40 基线锚迁移合规——体验
  零变化）；`demo_up` 横幅数字换代（O-6）。

### 9.4 实弹环境纪律（教训⑦⑧对齐）

栈重启按 MEMORY 教训⑦⑧（FZ_ZK_CASES_DIR 权威值+七件套 env+FZ_CHAIN_ANCHOR=real）；
本批新增 env 三枚（FZ_OPRF_SK/FZ_OPRF_SK_OLD/FZ_OPAQUE_ENABLED——demo 档缺省可跑，
production 档拒启语义照 §4.2）+CUTOFF 两枚（FZ_OPAQUE_CUTOFF_TS；.local_env 同
口径）。

---

## 10. 实施边界与里程碑映射

- **里程碑**（工作流 O-2~O-7，本设计=O-1 合同）：O-2 密码原语层（§3/§4/§2.4+
  C9-1/2/3 向量先行）→ O-3 后端协议（§1/§2/§5.5/§6——**§5.5 红线先于 O-4**）→
  O-4 存量迁移（§5）→ O-5 前端适配（§7——按本合同选型 A 实现）→ O-6 测试收官
  与文档换代（§9+口径卡 E11 行换代+MEMORY 收官条+瑕疵 a~g 核对表引用 4d1245b）→
  O-7 认证面大考（§0 销号表逐条+§8.3 全站扫描）。
- **指纹声明**：本批纯 accounts 域+KMS 注册表+前端——**零电路/零 vendor/零合约
  触碰** ⟹ 指纹三面全同 SM3(4201a82|b05df9d8…) 零换代（publish_pin 无需重公示）；
  O-7 面①复核。
- **冻结面**：现役登录 UX 零变化（演示口令/动线/界面零新增必填项）；AKE 代码
  零改动（约束①负约束——审查员对照 `git diff` 核 `service.py:524-560`/
  `router.py:211-277` 不在场）。
- **遗留如实**：方案 A（PFS）六项义务在案留赛后（归约 §8.3）；G1~G9 缺口清单
  为常设限定面（归约 §10）；HSM provider 对接=演进注记（§4.3）。
