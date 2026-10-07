# A 席独立评审报告 · 密码技术安全性与创新性 / 整体性能优化规划（2026-09-26）

路径基准：`uas/` = `C:\Users\联想\Desktop\Meeting\uas\`；`vendor/` = `uas/zksvc/vendor/plonkish-d098f23/plonkish/plonkish_sm2_probe/src/`（vendor 只读）。方式：只读深读源码+文档+SQLite 只读探针+端口只读 GET 探针（未改任何文件、未跑测试/构建、未动服务）。

## ① 理解综述（≤300 字）

飞证=国密全栈+自研透明 SNARK（SM2 域 Basefold+HyperPlonk，reps=16/log_rate=1，种子公开常数派生，透明性属实）+FISCO 四合约。AUTH 语句 25 实例面（e/r/s、C₁/C₂/apk、ctx_tag/pred_id/T/θ/rev_root fold/class_id）逐位核对闭环；上轮 P0-1（撤销键域）/P0-2（SMT 位序）修复质量经抽查属实：`ra/service.py:265-287` 传播 pk′.x、`smt_weave.rs:181-184` LSB-at-leaf+非默认树红线测试（:492）、见证端 fail-fast（`ra/router.py:196-205`）。R3-3.1 后 AUTH 44,383 约束/服务器 prove 29.8s。本席新发现一个同构于已修 SMT 空洞的「空转谓词」：**TRAIL 的高度上限由证明者自选且不入验证面**（P0）；另 RA 演示钥随机化不对称、上轮撤销端到端负例未闭环等 10 项。工程纪律真实且高水准，但「接缝空转」病灶在 TRAIL 语句上第三次出现。

## ② 发现清单

### P0（宣称与实现断裂）

**P0-1 TRAIL 语句的高度上限 `alt_max` 与 `t_start` 是证明者自选常量，不进公开实例与验证绑定——「逐点高度≤授权上限」的合规宣称对恶意出证方数学空转。[静态分析+实测探针]**
- 证据：
  - 范围门把 alt_max 烧进约束**常量**：`vendor/trail_weave.rs:226`（`alt_max_e = FpSM2::from(alt_max_cm)`）、`:295`（`rec - Constant(alt_max_e)`）；t_start 同法 `:339`；
  - 实例面仅链头单值：`vendor/trail_weave.rs:344-346`（`instances = vec![vec![head_fold]]`、`num_instances=vec![1]`；`assemble.rs:512` 测试钉 `instances==1`）；
  - 验证面只核实例 0==fold(chain_head)：`uas/zksvc/src/prove.rs:763-789`（TRAIL 分支仅 chain_head_hex 期望）；`uas/backend/app/zk/worker.py` 不涉 TRAIL；判决件 verdict.json 无 alt_max/t_start 字段（`prove.rs` VerdictFile 结构）；
  - 出证入口 alt_max_cm 由请求体自报：`uas/gcs/bridge/prover.py:30-33,401-418`；全系统无任何「alt_max_cm==授权令牌 altMaxM×100」的服务端对拍（链上 `FlightAuthRegistry.getAuth[3]` 有 altMaxM 但无人消费对 TRAIL）。
- 影响：飞过限高的飞手可用自报 `alt_max_cm=65535`（655.35m）对自己已锚定的真实链头出一张 verify-OK 的「高度合规证书」，第三方无法从证明/实例/vp/判决件分辨——`docs/答辩口径卡.md` B2/A4「逐点高度范围」「合规证书」宣称在恶意证明者模型下不成立。时间连续门与链头钉（记录真实性）仍健全；这与已修的 AUTH SMT 撤销空洞（R2）及上轮 P0-1 属同一「空转谓词」病灶，且五个 TRAIL 负例（`trail_weave.rs:519-616`）全部用**固定 alt_max** 构造——恰是「恶意证明者自由构造见证」盲区的同型重现。
- 修法：alt_max（cm）与 t_start 提升为公开实例 1/2（照链头钉机制 z-prep 门 + `q_inst`，+2 约束/+2 实例，性能影响可忽略）；`verify_instances` TRAIL 分支增 expected `alt_max_cm/t_start`；演示/判决脚本与 `altMaxM×100` 链上记录对拍；黄金向量 v5+repin 仪式（已演练 3 次）。附带把负例矩阵补「抬上限」形态。工作量 1 人天。

### P1（严重）

**P1-1 RA 演示签名钥=公开可推算，且 per-run 随机化只做了 ENGINE 未做 RA——demo 档可伪造子凭证签发直通全链。[静态分析]（半已知项：口径卡 C+3 已声明"公开可推算"；本条新发现的是**缓解措施的不对称**）**
- 证据：`uas/backend/app/kms/__init__.py:27-42`（`_derive_priv(SM3("FZ-KMS|ra-signing"))`，FZ_RA_SK env 才有真随机）；`uas/scripts/demo_up.py:159-164` 仅注入随机 `FZ_ENGINE_TOKEN/FZ_ENGINE_SK`，无 `FZ_RA_SK`。红队修复⑩的定谳理由「评委无法自推私钥铸令牌」逐字适用于 RA：自推 RA 私钥→伪造 M_A′ 签名→门控②通过（`authz/service.py:171` 用同一派生公钥验签）→开源证明器本地出证→worker verify 通过→令牌+链上 recordAuth。
- 影响：演示/真链档下知道派生式的攻击者可全链冒发；与已实施的 ENGINE 随机化构成同类漏洞的双重标准。
- 修法：demo_up 注入每场随机 `FZ_RA_SK`（`/ra/pubkey` 动态消费、黄金向量测试自带钥，兼容性零障碍）。0.5 人天。

**P1-2 上轮整改 R3-0.4 验收门未闭环：「吊销后旧子凭证申请必拒」端到端负例不存在，撤销链路从未在演示/判决环境全链走过。[静态分析+实测探针]**
- 证据：`uas/scripts/check.sh` 五段无任何撤销项；`uas/backend/scripts/e2e_auth_full.py` 断言枚举 ①-⑪ 无 revoke；现有覆盖=`backend/tests/test_ra_service.py:227`（传播单测）+witness 端 fail-fast 单元面；**演示库 `backend/feizheng.db` revocations 表 0 行 [实测]**——94 用户/50 授权的真实演示库从未执行过吊销，传播+推根+align+门控④的联合路径无实弹判决行。
- 影响：P0-1 修复（已抽查属实）缺端到端证据；若评委现场要求演示「吊销即拒」无现成脚本，且该链路首跑即演出（本系统历史规律：无人走过的接缝必藏雷）。
- 修法：e2e 增一段（revoke→witness fail-fast 拒→/ra/revoke 后旧子凭证 apply 409）入 check.sh。0.5 人天。

### P2（中等）

**P2-1 AUTH 出证失败现场滞留明文见证材料。[实测探针]**
- 证据：`uas/gcs/bridge/prover.py:158-163`（`if status != "failed": rmtree(tmp)`——失败即保留）；`backend/fz-zk-cases/` 下 **28 个 `_tmp_*` 残留目录 [实测]，多个含 `job.json`（id_number_hex 身份证号+holder_sk_hex 出示私钥+salt 明文）[实测]**。注释自称"调试期暂保留"，但无 TTL/清理机制=事实永久滞留——隐私系统的磁盘取证面与「身份证号全程不出设备」叙事冲突。
- 修法：失败现场脱敏（保留 zkc stderr 剥离 spec）或限时清理+落盘前提示。0.5 人天。

**P2-2 演示库迁移链双头。[实测探针]**
- 证据：`backend/feizheng.db` alembic_version=**两行** `('b7c8d9e0',0009)`+`('a1b2c3d4',0007)`，而 0008=`c3d4e5f6` 未在版本表（`alembic/versions/` 链 0007→0008→0009 线性）——下次对该库 `alembic upgrade` 必报多头/断链；违反自订纪律㊿+31（迁移验收须 `alembic current` 走查）。
- 修法：stamp 单头+持久库走查纳入 check.sh。0.25 人天。

**P2-3 撤销 TOCTOU 分钟级窗口：受理核根后、recordAuth 前的吊销不拦截。[静态分析]**
- 证据：门控④仅受理时点比对 rev_root（`authz/service.py:200-202`）；worker verify→recordAuth 全程不再复查（`zk/worker.py:386-470`）。吊销发生在该窗口内则旧根证明仍被 approved——「撤销即时」存在分钟级残余窗口（纪元根语义=受理时点快照，宜显式声明）。
- 修法：worker recordAuth 前一次 `revRoot==row.rev_root_hex` 链上复查（+5 行）。0.25 人天。

**P2-4 演示栈评审时点整体离线。[实测探针 2026-09-26]**
- 证据：8000/8100/5174/8545 四端口全部无监听（Windows netstat+WSL `ss` 仅 PG 5432）——尽管交接位声明"在线跑"。教训㊿+67（会话托管后台树连带清杀）第三次复现；演示可用性单点。
- 修法：S5 已有 systemd/schtasks 蓝本落 demo_up 常驻化+演示前 readiness 探针（真实子命令探活，㊿+77）。0.5 人天。

### P3（改进）

- **P3-1** `backend/app/authz/policy.py:56-66` 死 helper `ctx_tag_of/pred_id_of` 域前缀（"FZ-CTX|"/"FZ-PRED|"）与活映射（`authz/service.py:111-131` HMAC-SM3、`profile.rs:36` "FZ-ZKSVC-PRED-ID\x01"）不一致，docstring 却自称"电路实例 19/20 域"——误接即跨语言断链陷阱。删除或改注。0.5h。
- **P3-2** `zksvc/src/prove.rs:752-756` canonical spec 解析 `FZ_AUTH_CANONICAL_SPEC` 恒遮蔽 `FZ_TRAIL_CANONICAL_SPEC`——同进程双档验证必假拒（fail-closed 可用性）；建议按 spec.profile 感知解析。1h。
- **P3-3** TRAIL 检查点 `fence_state` 内 FENCE_ALT_MAX 与 spec `alt_max_cm` 无装配面交叉核对（`assemble.rs:235-254` 只验签不比对）——P0-1 修复时顺带钉入。2h。
- **P3-4** `zksvc/src/assemble.rs:400` 生产库路径 `std::env::set_var("SM3_LUT","1")`——库函数全局 env 突变（工单#3 纪律存量违例点）；当前与 pin 口径一致无实害，宜迁构造参数。1h。
- **P3-5** `/prove/case/{id}/{artifact}` 无认证下载 proof/instances（`prover.py:446-462`）——capability URL（64bit 熵 case_id）依赖机密性；apk 链接面暴露半径宜随"一次性出示钥=R4"一并收敛。已知项关联，仅登记。

**已知项核对（不冒充新发现）**：r≡2 常量仍在 `vendor/sm2_auth_assemble.rs:86`（口径卡 C+1 已声明，CSPRNG 实装维持挂账）；apk/pk′ 层可链接（C3 口径已收窄，R4）；服务器窗复测（工单#4，本报告路线图保留）；一次性出示钥（R4）。L2b 核实结论：EC 窗口化已按框架 A7 于 B3 随带完成于**验签体**（16,554 约束），E8/E9 六循环（~20K）未窗口化——无"TRAIL/EC 查表化 L2b 未完"欠账，性能路线按此定标。

## ③ 性能优化路线图（赛内可落地，按收益排序）

现状基线 [实测]：AUTH 44,383 约束/advice 10,360/lookups 544/rings 1,045,006；服务器 12C prove 29.8s/verify 1.3s/proof 24.16MB；本机 19.8GB S1 门 RAYON=6 出证 100-126s。TRAIL 532 约束/lookups 1,024；服务器 14.77s（09-21 二进制）；本机 43-57s。约束家族构成：EC 六循环 ~20K+验签体 16.5K+杂项 ~7K+SMT 门 256（布尔 C 块已被 R3-3.1 查表化出局）。

| # | 动作 | 量化预期 | 依据 | 风险 | 工作量 |
|---|---|---|---|---|---|
| 1 | **P0-1 修复**：TRAIL alt_max/t_start 入实例钉+验证对拍（随批黄金向量 v5+repin） | 安全修复；+2 实例/+2 约束，prove 影响可忽略 | 本报告 P0-1；z 门机制现成（trail_weave.rs:153-171） | 低（repin 仪式已演练 3 次） | 1 人天 |
| 2 | **P1-2 撤销 e2e 负例入 check.sh** + 演示库对齐仪式实弹 | 撤销宣称获端到端判决行 | 本报告 P1-2 | 低 | 0.5 人天 |
| 3 | **canonical 电路 info/预处理的指纹键控磁盘缓存**（worker verify 与出证共用） | worker verify 22-30s→**预计 ≤8s**；每次出证省 setup+preprocess ~6.4s 与 vp 22MB 写读（约 −6%） | R1 相位数据：assemble 7.9s/preprocess 6.1s/verify 1.3s——大头是逐进程重复装配 | 低（种子确定性、结构恒同；指纹键控防漂移） | 1-1.5 人天 |
| 4 | **演示机 pagefile 扩容+重启**（S3 挂账，需队长）→ S1 内存门 RAYON 6→12 | AUTH 出证 100-126s→**约 70-85s（−30~40%）**、TRAIL 43-57s→约 30-40s [推得，按 R1 扫参曲线 4→12 提速 28% 类推] | 性能档案 RAYON 扫参节；R3-3.1 部署收口批"RAYON=6 封顶"的成因即内存 | 零代码风险；需重启窗 | 0.5 人天 |
| 5 | **服务器窗复测**（工单#4，需队长开机）：TRAIL 当前二进制四元组+AUTH 29.8s 复核+服务器 RAYON 扫参 | 档案推算值全部实测化；服务器 RAYON 8/12/16 择优（预期再 −5~10% [推得]） | 性能档案 R2 ③声明+R3-3.3 尾项 | 低 | 0.5-1 人天 |
| 6 | /chain/panel 链面 RPC 加 3-5s TTL 缓存+并发化 | 面板首屏 500ms 级→毫秒级回源 | panel.py 每请求新建 ChainClient+串行 RPC | 低 | 0.5 人天 |
| 7 | SMT 内节点双块→单块 bare-compress 语义（64→32 LUT 组；可裁） | advice −~1,100、lookups 544→~288、prove **−8~12%** [推得] | B3b-d7 每内节点=数据块+padding 块（smt_weave.rs:141-166），padding 压缩对 64B 定长消息是常量函数 | 中（语句哈希语义变更：smt.py+根值换代+align 仪式+repin） | 2-3 人天 |
| 8 | E8/E9 六 EC 循环窗口化（同 L2b 方法推广）——**建议赛后** | 约束 −12~15K、prove **−15~25%** [推得] | 验签体 16.5K=窗口化后先例；六循环 ~20K/257 步未窗口化 | 中高（电路手术+全量回归+repin） | 3-5 人天 |
| 9 | 维持搁置确认：R3-3.2 lookup 通道合并（maj/ch 不同域联合强制=语义错误，㊿+50）；v3b 列压缩（跨 gadget 重排 3-5 天）；SMT 深度/键域变更（违反语句红线） | — | 上轮评审+MEMORY 定谳 | — | — |

## ④ 创新性定级与答辩风险点

**定级**：算法层 **B+**——透明 SNARK 选型（Basefold+HyperPlonk@SM2 域）为自有论文资产、无可信设置属实，但 Basefold/HyperPlonk 本身非首创，SM3 查表化/halo2 同族 4-bit limb lookup 为成熟技术的自研移植；SM2 域原生+全语句生产化有实质贡献。工程层 **A-**——SMT 非成员进电路、weave_proto_gates/环审计/auth_census 普查器、掩蔽机制+FS 序、实例驱动验证（服务端零秘密）为自研且质量高；国密全栈+真链+SITL 物理闭环的系统整合竞赛国内线第一梯队。综合：竞赛维度头部；"国际水平"表述宜限定为"同类语句的完整生产化"。

**答辩风险点（按杀伤力排序）**：
1. **TRAIL"合规证书"被追问"第三方如何验证高度≤授权上限"即翻车**（P0-1）——修复或把口径主动收窄为"记录完整性+时间连续性证书"二选一，修优于收。
2. "撤销即时"若被要求现场演示——无现成端到端脚本（P1-2），且演示库从未跑过吊销。
3. r=2 常量 ElGamal（已知已声明）——追问"(C₁,C₂) 两条 EC 循环保护什么"时按 C+1 口径答，勿展开"盲化"字眼。
4. reps=16/log_rate=1 严格界——答辩口径卡未引，被追问时指向 `docs/证明体系安全注记.md` §二/§三（D27 权威），勿现场推。
5. KMS 演示钥——ENGINE 已随机化而 RA 未（P1-1），修复前勿主动讲"评委无法自推私钥"这句话，RA 钥同样可推。
6. 演示可用性——当前栈离线（P2-4），彩排窗前必须 demo_up 常驻化+探针预检。

## ⑤ 亮点

auth_census 结构普查+恶意见证红线测试的"自挖自堵"方法学，配 PinDrift 供应链守卫与全链负例一等公民，是全系统最接近专业 ZK 团队实证纪律的一幕。
