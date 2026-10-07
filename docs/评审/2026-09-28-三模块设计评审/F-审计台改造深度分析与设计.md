> 本设计文档由干净上下文设计代理生成（2026-09-28），只读评审+设计方案，未实施。原样归档。

# 「飞证」审计台改造深度分析与设计规划（2026-09-28，只读评审+设计）

## 一、业务链严谨性审计（违规发生→留痕闭环逐步核对）

| 步骤 | 数据从哪来 | 谁授权 | 凭什么可信 | 留痕在哪 | 断点/含糊 |
|---|---|---|---|---|---|
| ① 违规发生 | 固件围栏硬拦截（SITL STATUSTEXT）→桥→`POST /engine/event`（telemetry/router.py:107） | engine 交易钥（合约 onlyEngine，TelemetryAnchor.sol:36） | 固件权威上报+链写 onlyEngine | `EventRecorded` 上链；索引器 10s 增量回填 `chain_events`（indexer.py:23-72、main.py:79） | 无硬断点；但 `chain_events` 全局无消费端点——只有令状 trace 内按 authId 读（audit/router.py:144-170） |
| ② 发现违规 | （现状）审计员人肉开 /chain/panel 翻记录 | — | — | — | **断点①**：审计台无违规事件列表，authId 靠猜（index.html:135 占位“例：33（见违规事件的授权编号）”但页面无处可看违规） |
| ③ 立案（令状上链） | 案号+依据文本+目标 authId（index.html:132-136） | X-Audit-Token（audit/router.py:214-221）→合约 onlyAuditor `logWarrant`（IdentityRegistry.sol:73-77） | 依据文本服务端自动 SM3（router.py:279-281）；令状哈希=SM3(域‖案号‖scope)（service.py:56-58）；append-only | WarrantLogged 事件+warrants 表（audit/models.py:18-35） | 三个含糊：**(a)** `target_auth_id` 不校验存在性（service.py:74-88，笔误可立案）；**(b)** `legal_basis_text` 哈希后即丢弃（router.py:267-268）——事后无法自证“当时依据是什么文本”，可信度表述只有哈希没有原文回显；**(c)** 令状上链 tx 哈希未落库，时间线只写“已留痕”无锚点 |
| ④ RA 出函 | RA 操作员 POST /ra/collab-code+X-RA-Token（ra/router.py:331-345） | X-RA-Token 恒时比较（ra/router.py:270-281） | SM4-GCM FZC1 码（collab.py:35-41） | **无**——出具行为零台账，RA 库不记谁何时为何凭证出过函 | **断点②（最重）**：函**不绑定令状**（AAD 仅版本域，collab.py:20）；无时效、可复用（一函可解多个令状）；且“核验在案后出具”纯靠人工——接口不验任何在案性 |
| ⑤ 解锁实名 | 审计台粘贴 FZC 码（index.html:231-233） | 双令牌缺一不可：审计端门禁+`open_collab` 还原 cred→`warrant_unlock`（audit/router.py:298-325→ra/service.py:339-374） | 链上在案核验双查（service.py:112+ra/service.py:349）+一次性 `logWarrantUnlock` onlyRA（IdentityRegistry.sol:84-89） | WarrantUnlockLogged+warrants 表解锁行 | **含糊（与④同根）**：解锁实名与令状 `target_auth_id` **无一致性校验**——B 案令状粘 A 案凭证的函也能解（unlock/warrant_unlock 全链路无 target 比对）。“scope_hash”只是哈希派生物，不构成技术约束。另 UI 残留死输入“高级：直接输入主凭证校验值”（index.html:237-239）——该路径已退役（router.py:302-311 必返 400 missing_collab_code），宣称-实现不一致 |
| ⑥ 追溯时间线 | trace=链上回读 getAuth 11 元组+latest 检查点+chain_events+device_check（audit/router.py:103-171、service.py:132-147） | X-Audit-Token | 链上回读单一事实源（B7-d3） | raw JSON 折叠 | **断点③**：no_evidence 第四态无 UI 表达——时间线仅判 match/mismatch，no_evidence/insufficient 落入 else 分支被误标“待实名解锁后核对”（index.html:281-283 vs device_check.py:56-64），而 no_evidence=“授权已消费但零检查点（可疑）”恰是借机逃逸的警示态；违规事件节点只显块号不显 tx_hash（index.html:277，数据里就有） |
| ⑦ 留痕自证 | chain_fingerprint=区块高（audit/router.py:173-174） | — | 链 | 链 | 区块高未在 UI 显著呈现（仅 raw JSON 内） |

## 二、全流程手动测试断点清单与指引闭环

以“新审计员+RA 操作员只看页面提示”走查：

| 步骤 | 需要的凭据/输入 | 现状 | 断链判定 |
|---|---|---|---|
| 打开审计台 | 后端地址 | 同源直出 /audit/ui/（main.py:96+，no-cache） | ✓ |
| 登录审计台 | 审计令牌 | “演示令牌？”按钮+披露判定（index.html:117、router.py:244-260，W-9） | ✓ 闭环 |
| 找 authId 立案 | 目标授权编号 | 无违规视图；panel 有记录但无违规标注 | ✗ → 见三-A |
| RA 登录 | RA 操作员令牌 | **页面零指引**。实际位置：demo_up 随机化后持久 `%TEMP%\fz_ra_ops_token.txt`（demo_up.py:182、193）；未设 env 时缺省=SM3("FZ-KMS\|ra-ops")（kms/__init__.py:125-131）；手测清单只有一行 curl 注记（前端手动测试清单.md:96-97） | ✗ → 见三-C |
| RA 找凭证哈希出函 | master_cred_hash_hex | **人类无法从任何页面获得**——e2e 脚本是从登记步骤顺拿的（e2e_frontend_api.py:377）；映射链 authId→AuthRecord→Application.sub_cred_hash→SubCredential.credential_id→Credential 只存在库内（authz/models.py:74-83、ra/models.py:57-68） | ✗✗ 最大断点 → 见三-B |
| 解锁 | FZC 码粘贴 | 有 textarea+程序说明（index.html:231-236） | ✓（但函本身有缺陷，见一④） |
| 追溯核对 | 设备核对/事件 | 时间线自动，但 no_evidence 误标 | ✗（见一⑥） |

## 三、改造设计提案

**A. 违规事件待办+一键立案**（断点①）
- API：`GET /audit/violations`（X-Audit-Token）——`chain_events`（event_type=1）按 authId 聚合，左联 `AuthRecord/Application`（class_id/状态/时间窗）+`CheckpointAnchor` 计数+`Warrants` 归并出“未立案/已立案”态。全部零身份字段，复用已有索引器数据，不新增链交互。
- UI：左栏“登记令状”面板上方新增「违规事件待办」面板（当前单屏两栏 400px+1fr 结构不动，左栏纵向堆叠）：每行“⚠ 授权 #N · 围栏违规 · 块 B · 未立案 → [立案]”。点立案=**带出 authId 预填表单**（含建议案号 CASE-YYYY-NNN），**不自动提交**——立案依据必须人工填写，这是监管权威性的一部分。
- 严谨性：待办只聚合不裁决；是否违规仍由审计员判断（no_evidence 型“零事件授权”不进此列表，避免假阳性，另一路由令状列表覆盖）。

**B. RA 协作窗（独立页 /ra/ui）**（断点②，核心）
- **位置论证**：独立页而非审计台同页 tab。理由：审计台页明文宣称“任一方单独无法完成解锁”（index.html:235），同页出函+粘贴解锁=单浏览器单人闭环，视觉上自证双控失守；独立工作台（不同 URL/不同令牌/不同机构名头）让“机构分权”叙事成立，工程上也与 `/audit/ui` 后端直出模式同构（B7-d2 治理面不入 Vue 栈先例）。注意两者同源 8000，无需动 CORS（main.py:76 白名单仅 X-Audit-Token，RA 窗同源不受影响）。
- 页面三区：①令牌指引区（见 C）；②「待协作令状」列表：`GET /ra/collab/pending`（X-RA-Token）返回未解锁令状（案号/target_auth_id/在案状态/依据哈希）——RA 核验“在案+案由”后出函，正是 index.html:235 宣称程序的界面化；③出具区：选令状→服务端解析 authId→cred 映射→`POST /ra/collab-code` 增 `warrant_hash_hex` 入参→**FZC2**：AAD 绑定 `warrant_hash‖cred_hash`（版本字节分派先例=信封 v3，MEMORY ㊿+61），并写 RA 库 `collab_issued` 台账（令状/凭证/指纹/时刻）。审计端 `open_collab(code, warrant_hash)` 校验绑定——解锁接口已知 wh，天然携带，无 UI 改动负担。FZC1 兼容期保留解析但审计台标注“旧式未绑定函”。可选时效（如 24h）一并入 AAD 明文。
- 不破坏双控：出函仍 X-RA-Token 门禁、解锁仍需令状在案+一次性上链留痕；新增的只是“函与令状绑定+出具台账”，权限分离只收紧不放松。RA 窗全程不显实名（解锁动作只发生在审计台）。

**C. 凭据指引闭环**（断点④）
- /ra/ui 顶部仿 W-9 披露纪律：`GET /ra/ops-token-hint` 返回 `{demo, source, path}` **不回令牌值**——env 未设（缺省派生值 repo 可推算）才可像审计台一样披露；demo_up 随机化档则指路 `%TEMP%\fz_ra_ops_token.txt`（demo_up.py:193）+一键复制读取命令。不做“凭证贴墙”端点。
- 审计台 header 加一行“协作函由登记机构出具→打开协作窗 /ra/ui”（跨窗链接，两个页面互指，形成指引环）。demo_up 启动尾打印双窗 URL+令牌文件路径。

**D. 严谨性修复（随批）**：①unlock/warrant_unlock 增 `target_auth_id↔cred` 一致性校验（走 AuthRecord→Application→SubCredential→Credential 链，不符=403 `scope_mismatch`）——把“双控”升级为“双控且范围受限于令状”；②create_warrant 校验 authId 存在性（AuthRecord 缺失时 UI 警示确认）；③`legal_basis_text` 落 warrants 表（迁移+立案卡回显原文+哈希双锚）；④删 UI 死输入（index.html:237-239）；⑤时间线补 no_evidence 黄/红警示节点与事件 tx_hash 渲染。

## 四、权威信服力细节清单

**低成本高收益**：案号格式校验（正则+示例，非硬拒可确认）；立案成功卡展示令状哈希全文+依据哈希+复制按钮（“登记行为已上链”给锚点）；时间线每节点双锚（块号+tx）；解锁后显示“解锁行为已上链·区块 N”（需 `_real_chain_call` 回传 receipt 中的 txHash/块高，改动一处映射）；chain_fingerprint（区块高）置于时间线页脚作“回读时点”声明；no_evidence 客观警示文案（device_check.py:62 的 reason 已备好，纯 UI 消费）。
**过度设计（不建议）**：令状撤销面（合约无此语义，append-only+“更正须新令状”反而是卖点）；时间线逐节点 Merkle 证明展示；getPastLogs 全量重放；多审计员账号体系（KMS 密钥即身份已自洽）；实名脱敏（审计场景完整呈现是合法披露，脱敏反显心虚）。

## 五、实现改动面与优先级

- **P0（全流程可手动测试+指引闭环，~1 天）**：`backend/app/audit/static/index.html`（删死输入+RA 窗指引链接）；新建 `backend/app/ra/static/index.html`+`backend/app/ra/router.py` 增 `/ra/collab/pending`、`/ra/ops-token-hint`；`scripts/demo_up.py` 打印双窗与令牌文件路径；`docs/前端手动测试清单.md` 审计台节重写为“双窗剧本”。
- **P1（待办+一键立案+函绑定+范围校验，~2 天）**：`audit/router.py`+`audit/service.py`（/audit/violations、target↔cred 校验、authId 存在性、legal_basis_text 落库）；`ra/collab.py`（FZC2 绑定+时效）；`ra/router.py` collab-code 增 warrant 入参+台账；`alembic` 新迁移（warrants.legal_basis_text、collab_issued 表）；index.html 违规待办面板+一键立案；e2e_frontend_api.py 8.x 段增断言（scope_mismatch 负例、FZC2 绑定、违规列表）。
- **P2（权威感细节，~0.5 天）**：第四节清单+no_evidence/tx 渲染+解锁 tx 留痕。

## 六、开放问题（需队长拍板）

1. 双控演示口径：同机双浏览器双开是否可接受（建议：可，答辩话术“双控=机构分权与令牌分域，非物理隔离”）；2. FZC2 上线后 FZC1 兼容期长度（建议仅解析不新发）；3. 协作函时效/一次性是否要上链表达（建议仅 RA 库台账——上链须合约变更，触发独立设计纪律）；4. `scope_mismatch` 拒绝是否允许 RA 换签重出（建议：允许，出函台账留痕即可，无需新令状）；5. 令状列表解锁后回显 `master_cred_hash_hex`（service.py:207）在 UI 是否屏蔽（伪名沟通口径问题，非安全问题）；6. 违规待办中同一 authId 多事件多令状的归并粒度（建议按 authId 聚合、已立案标灰不禁新立案——新违规可另案）。