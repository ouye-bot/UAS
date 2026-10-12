# 交付验收报告 · ⑫OPAQUE 认证面 scoped 大考（O-7）

> 验收对象：⑫OPAQUE 登录协议实施六批（O-1 设计定稿 e1bc5d1 → O-2 原语 add4a14
> → O-3 协议 6c353f8 → O-4 迁移 510b4a3 → O-5 前端 6bcb637 → O-6 收官 cad4295）。
> 验收人：实施工程师本批（O-7——非独立第三方；独立审查=各批 vitest/pytest 负例
> +设计合同对照）。日期 2026-10-13。基线：cad4295 工作树（本报告产出零代码改动）。
> **环境红项（如实前置）**：本机 fisco 节点自 10-11 起 SecureInitializer cert 故障
> ——链上公示/重公示仪式与真链档 e2e 全家受其阻（详见面①/面⑥遗留）。

## 面① 全量门禁

| 门禁 | 命令 | 结果 | 判定 |
|---|---|---|---|
| pytest 全量（门禁粒度） | `python -m pytest -q -m "not slow"` | **609 passed + 5 failed / 6 deselected**（383.0s） | 609 绿 + 5 个**链环境依赖**失败（见下） |
| 失败 5 项根因 | 同上重跑+错误提取 | 5 项全为 production 档启动测试（test_cookie_secure_production_auto / test_production_injected_keys_start / test_production_all_set_starts / test_v3_envelope_sunset production 两项），错误=`httpcore.ConnectTimeout` → **POST http://127.0.0.1:8545（链 RPC）超时** | **非本批回归**：同树 cad4295 前次全量 614 passed 0 failed（O-6 实测录 289.7s）；其间零代码改动（git status 干净）；差异=链 RPC 8545 当前挂起（fisco cert 故障延续，直连探针 3s 无响应）。5 项测试均落在 FZ_CHAIN_ANCHOR=real 的链读路径（R3-1.4 熔断窗在错误栈可见） |
| 复跑定位 | `pytest <5 项> -q`（杀残留 preview 进程后×2） | 仍 5 failed（同因 8545 挂起，与并发/残留进程无关——已 taskkill 残留 preview PID 14828 复跑同果） | 环境红项坐实 |
| cargo（zksvc lib） | `cargo test --lib`（zksvc/） | **45 passed, 0 failed, 1 ignored**（411.3s） | ✅ 与基线 45+1 一致 |
| crypto_audit | `python scripts/crypto_audit.py --quick` | **98/99**（C9 全 14 例绿：C9-01~10 原语锚+C9-11~14 协议面；唯一失败 C3-15） | 87 基线只增 ✓；**C3-15 如实红项**：manifest b05df9d8 领先链上公示一代（期望链上 01140a45=上一代），重公示仪式待 fisco 恢复——O-2 起在案，本批零链触碰 |
| 指纹对拍（不触电路） | `git diff HEAD --stat -- zksvc/ vendor/ contracts/`（空）+MANIFEST 读回 | **零电路零指纹触碰**；本地指纹=SM3(4201a82\|b05df9d8…) 与黄金向量/pin 常量三源一致 | ✅ 零漂移（链上滞后一代=C3-15 同源环境项） |
| ruff 双绿 | `ruff check app tests` / `format --check app tests` | All checks passed! / 140 files already formatted | ✅ |

## 面② 认证动线实弹

- **API 全动线**：`python scripts/e2e_opaque_auth.py` → **41 项断言 [OK]**（O-6 实测复跑于本报告前，282s 面内 55.6s 的 crypto_audit 同机）：注册 v6 201 → 种子激活（auditor123）200 → OPAQUE 登录 200（解封 sk=注册 sk）→ 错口令连发 200×10（服务端零口令知识）+第 11 发 429 → v4 存量惰性迁移（注册 422 降级拒/keystore 200/migrate 200/keystore 410/OPAQUE 登录 200）→ 改密 v6'+掩码钥原子换新（旧口令客户端败/新口令 200）→ CUTOFF 403/v6 照常。
- **浏览器全动线**：`python scripts/e2e_browser_ui.py` → **40 项断言 [OK]、零 pageerror（67s）**：⓪.4a 建 v6 账户（浏览器钥对+OPAQUE 材料）→⓪.4b 资料上链→⓪.6 错密码负例人话提示→⓪.7 正例挑战-应答→工作台，及 ①~⑨ 全屏回归。演示档体验零变化：auditor123/admin123 照常登录、界面零新增必填项（e2e 断言即证）。

## 面③ 宣称-实现对账（归约 §0.2 三条+禁用表述）

| §0.2 宣称 | 证据锚 |
|---|---|
| ①拖库面离线 oracle 消失、字典攻击被迫在线化 | 归约 §2.4 OMDL 归约（GO 复评达实施依据门槛）；实施侧：k_oprf 仅存 KMS（FZ_OPRF_SK，production 拒启语义 app/kms/__init__.py:50）+评估走在线掩码通道——离线持有 DB+信封无 k_oprf 不可验证任何候选（test_accounts_opaque 错口令客户端败=零服务端差异佐证无新 oracle） |
| ②KCI 型：服务器妥协不足以冒充客户端 | 信封 KEK=rwd（需在线 evaluate 取盐/迭代+盲化通道）；测试=错口令 OPAQUE 解封失败（e2e_opaque_auth ⑦ 旧口令败） |
| ③响应不可区分（防枚举） | crypto_audit C9-11：三态 60 样本四键长度恒定+masked_response 零重合；实施=§6.1 fake-record（定长全零 envelope+随机 masking_key） |
| **不宣称**：非 RFC 9807 全义 aPAKE（现役 SM2 挑战-应答无协议内 PFS——方案 A 义务清单留赛后） | 口径卡 E11 行换代文字锁定；归约 §0.2/§8.4 原文 |

**禁用表述全站扫描**：`aPAKE`/`PFS`/`前向保密` 正面使用=零（口径卡 E11 仅否定式「非…aPAKE」「无协议内前向保密」；性能档案/MEMORY/归约文档仅历史评审记录与否定/演进语境——grep 负向过滤后零命中）；作品说明文档零 OPAQUE 表述（未对外新增宣称）；前端源码零 aPAKE/PFS 字样。E11 行已换代为方案 B 三达成/一不宣称锁 §0.2。

## 面④ 安全负例全家

| 负例 | 实测锚 |
|---|---|
| 离线猜不可行性 | 归约 §2.4 归约（GO 复评）+实施零 oracle 佐证（错口令服务端零差异——e2e ⑤ 前 10 发全 200） |
| 枚举不可区分 | crypto_audit C9-11（三态 60 样本长度恒定+masked_response 零重合） |
| 重放 | test_accounts_opaque test_v6_challenge_replay_rejected（同 nonce 二次=401 bad_challenge） |
| 非曲线点/坐标域外 | crypto_audit C9-12（600 轮全拒）+C9-06 哨兵（未进标量乘路径）+test_crypto_opaque 负例族 |
| 限流 | e2e ⑤ 恰第 11 发 429+crypto_audit C9-13（429 恰第 11 发）+台账 opaque_rate_limited |
| 惰性重封后 v4 形态不再接受 | test_accounts_opaque migrate 后 keystore 410+register 422（v6_change_required） |

## 面⑤ 迁移验收

- **全链**：O-4 tests（test_accounts_opaque migrate 全链：migrate 200→keystore 410→OPAQUE 登录 200→台账一行）+crypto_audit C9-14 同构复核 ✓。
- **截止开关**：FZ_OPAQUE_CUTOFF_TS 到点后 v4 登录 403 v4_cutoff（挑战不烧 nonce——撤截止同 nonce 可登）+v6 照常（e2e_opaque_auth ⑧ 实弹）+fail-visible 非法 env 抛错。
- **回滚窗**：失败零部分状态（行原样 v4+四列 NULL）→重试收敛（O-4 实测）。
- **keystore 前置序（约束②红线）**：O-3 先行 commit 6c353f8<本批 510b4a3（commit 序可证）+crypto_audit C9-13（410 门+429 桶在位）+migrate 运行时断言（换新后 keystore 必 410 否则回滚拒发——service.migrate_to_opaque §5.5-3）。

## 面⑥ 交付物核对

| 交付物 | 状态 |
|---|---|
| 设计文档 docs/OPAQUE实施设计.md（e1bc5d1，含 §0 约束十条落点总表+D-1~D-11 钉定） | ✅ 在库 |
| 归约 GO 引用 | ✅ 修订版（复评 GO）为唯一协议依据——两文档头部互引 |
| 约束十条销号表 | ✅ 设计 §0 总表逐条落点+本报告面②~⑤逐条证据；E11 行=宣称口径换代落地 |
| 实施六批提交链 | ✅ e1bc5d1→add4a14→6c353f8→510b4a3→6bcb637→cad4295（git log 逐笔在案） |
| 测试资产 | ✅ pytest +42（613→614 收官 +1）/vitest +10（179）/crypto_audit +14（C9 10+EXT 4）/e2e_opaque_auth 新 41/浏览器 40 |

## 遗留（如实）

1. **C3-15 链上重公示**：manifest b05df9d8 领先链上公示一代——重公示仪式待 fisco 节点恢复（cert 故障在案）；恢复后随真链档复跑全套。
2. **真链档 e2e 全家**（e2e_workflows 99/auth_full 30/fleet 33/cross_org 29）本机未实跑（同因 fisco）——账户面影响=零（script_login 与浏览器注册激活登录已分别实弹）。
3. **production 档启动测试 5 项**：依赖链 RPC 8545 可达——fisco 恢复即转绿（错误=ConnectTimeout 至 8545，本批零链触碰）。
4. 前端 profile 槽 v6 换代、HSM provider 对接、方案 A（PFS）六项义务——赛后项（设计 §10 遗留如实）。
