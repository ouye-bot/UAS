# 互认集 census 实测与 A/B 对拍（2.2 二期评审材料②数据档）

- **实验性质**：全部实验在 vendor 快照实验分支 **`exp/2.2-mutual-smt-census`**（git worktree 自 62134a6 拉出）完成，**不并入现役**——现役 pin/指纹/黄金向量逐字不动（§四 git 状态证明）。实验分支内为使 prove 跑通做的实验性 repin（152 文件）只存在于分支，不回并。
- **实现面**：`mutual_weave.rs`（新，~470 行=现役 smt_weave.rs 深度 32 机械复制改深度 6）+`sm2_full_statement_assemble.rs` 接线（容量 26→27/组序 69..81/pack 推进/织入三段/实例 ordinal 26 钉）+`lib.rs` mod 声明+`tests/mutual_census.rs`（census 测试）。复用现役 SM3 查表门工艺全套（weave_core/lane 带/mux lane 化/EMPTY 常量锚/根钉折叠——R2 加固实弹检验工艺平移）。

## 一、census 实测 [实测，release tests/mutual_census.rs 9.08s]

| 项 | 现役判决行 | 实验分支 | Δ 实测 |
|---|---|---|---|
| constraints | 19,434 | 19,473 | **+39** |
| advice 列 | 8,410 | 8,640 | **+230** |
| lookups（查表列） | 195 | 229 | **+34**（12 组成员链的查表列——SM3 压缩强制走 lookup，非 constraints 口径） |
| 公开实例 | 26 | 27 | **+1**（互认集根，ordinal 26） |

约束增量构成：mux 12 块×2=24+路径位 bool 6+recomb 1+根折叠 1=32+选择器/环杂项 ≈+39 ✓ 与织入面同构对账；advice +230=12 组 pack INPUT 带列+cur/sib/bit lane 列+影子列 64+EMPTY 预处理列+路径位格列。

**对照复评 §2.2 估算**：任务书口径「+3~5k 约束 [推得]」→ 实测**纯成员叶子 +39 约束**（另有 +34 查表列/+230 advice 的真实资源开销）——约束数口径严重高估；但复评 NO-GO 的代价主体（pk_RA 根手术 +1~2.3k/换代级联/增益恒真）不在本实测范围，**不推翻 NO-GO**（材料① §三/§六）。

## 二、proof/prove A/B 对拍 [实测，安静窗 Load 0，canonical spec 生产构型 mask=on]

同窗双发（B=现役 master 62134a6 树 zkc；A=实验分支 zkc；同机同构 RAYON 缺省）：

| 项 | 现役 B | 实验 A | Δ | Δ% |
|---|---|---|---|---|
| proof 尺寸 | 16,063,712B | 16,865,192B | **+801,480B** | +5.0% |
| prove 时长 | 15.49s | 16.52s | **+1.03s** | +6.6% |
| verify 时长 | 0.47s | 0.49s | +0.02s | +4.3% |
| verdict | OK | OK | 双绿（prove+盘上回读 verify 闭环） | — |
| 指纹 | SM3(4201a82\|b05df9d8…) | SM3(4201a82\|2ec0a2d7…) | 分支换代（实验面） | — |

verdict.json 原始件：`%TEMP%/exp22_ab/{base,exp}/verdict.json`（proof.bin/verifier_param.bin/instances.json 同目录）。

## 三、实验实录（根因链与教训）

1. **实例 ordinal 家行错位（本实验唯一 prove 级 FAIL 的根因）**：首版织入把 fold 约束激活行/影子播种行传 `rm[23]`（现役 SMT 根实例 23 的家行），而互认集根钉=set_instance(26)——实例 ordinal k 的家行=`row_mapping()[k]`（先例锚：装配面注释「rm[24]=实例 24 家点——θ 门同构模式」+「q_inst@row_mapping()[ordinal]」）⟹ fold 约束@实例 23 家行读 q_inst=rev_root fold 值 vs mutual 影子折叠——sumcheck 开口对账 `Unmatched between sum_check output and query evaluation` FAIL（装配 sanity 未炸=两 fold 约束同行使错误形态特殊——**教训：新增实例钉的家行必须随 ordinal 走，rm 表达式与 set_instance ordinal 同源派生**）。根修=row_rev: rm[26] 后双绿。
2. **实验 repin 两次**：6c887163（首次，织入实现后）→ 2ec0a2d7（家行根修后）——分支内 MANIFEST 只服务 PinDrift 准入门让 prove 可跑，无公示语义。
3. census 测试的实例计数口径：`info.num_instances` 是**每实例列行数向量**（len=1 列），实例值总数=`iter().sum()`=27——「实例 26→27」为数量口径，钉值 ordinal=26（0-based）。
4. 负载纪律：A/B 双发前确认 LoadPercentage=0（2.1 批遗留的 auth_window_forgeries 超长测试进程已停——其 3h+ 未完与本征 4h+ 级时长在 2.1 TaskResult 留档）。

## 四、现役零触碰证明 [git 实证]

- 主树（master）工作区在 2.2 批全程仅新增 docs/ 三件评审材料，vendor 快照/MANIFEST/黄金向量/zksvc 源**零改动**：`git status --porcelain` 无 vendor/MANIFEST/黄金向量条目（终态复查输出见提交报告）。
- 主树 HEAD 指纹面：MANIFEST aggregate=`b05df9d8…`（2.1 批现值）逐字未动；黄金向量 `zk_pin_fingerprint=SM3(4201a82|b05df9d8…)` 逐字未动。
- 实验改动全部在 `exp/2.2-mutual-smt-census` 分支（worktree 检出于独立目录），分支提交后**不合并**：`git log master..exp/2.2-mutual-smt-census` 即实验提交集，master 历史零新增 vendor 提交。

## 五、结论（重评弹药口径）

1. **互认集成员叶子真实成本 [实测]**：+39 约束/+34 查表列/+230 advice/+1 实例；连带 proof +5.0%/prove +6.6%/verify +4.3%。
2. **「+3~5k 约束」口径定谳**：对「纯互认集成员叶子」高估约两个数量级（估算≠定谳实锤）；该口径在复评语境下混合了 pk_RA 根手术（+1~2.3k 另测）与叶子成本——重评时按本档拆分对账。
3. **二期实施剩余大头**（本实测未覆盖，维持复评口径待 T1 触发后另测）：pk_RA 根手术（Z_A 折叠失效+apk 改接）、host/链面/受理门/e2e/换代级联。
