# 飞证 · UAS

**无人机低空合规飞行隐私保护与审计系统** —— 第 12 届全国密码技术竞赛作品。

飞证让守法飞手的身份与轨迹默认隐身：起飞前以**零知识证明**证明"我有合规资质"而不暴露"我是谁"；飞行后可生成**零披露的轨迹合规证书**，任何第三方无需安装额外信任即可独立复验；只有固件围栏真实触发、走完审计令状与**双控协同**，才能按案解出实名。监管获得可问责性，公众获得数据最小化。

## 核心特性

- **国密全栈**：SM2 挑战-应答登录（服务端零口令、零私钥材料）/ SM3 / SM4-GCM / HMAC-SM3；官方向量三语言（Python/Rust/TS）单一事实源对拍。
- **自研透明 SNARK**：HyperPlonk 多项式 IOP + Basefold 承诺，在 SM2 域上原生实例化（零可信设置）；SM3 查表化电路、EC 固定基窗口化、撤销稀疏默克尔树全量入电路；公开种子 setup、证明器电路指纹上链 fail-closed（PinDrift 守卫）。
- **两大证明电路**：
  - **AUTH**（准入匿名，约 19.6K 约束）：证明 RA 签发的子凭证有效、资质/机型/未吊销/在有效期满足政策——不披露身份明文；
  - **TRAIL**（轨迹合规，n=128 采样）：逐点高度合规 + 时间无空隙 + 链头钉定，轨迹样本零披露。
- **隐私纵深**：出示钥一次性（每张子凭证全新钥对，跨申请不可链接）/ 链上零身份字段 / 实名仅存登记机构加密信封 / 一次性飞行令牌（一次授权一次解锁）。
- **双控密码学强制**：解锁实名需审计员与机构管理员两把独立 SM2 钥对同一请求哈希签名——缺一不解锁，范围焊死在请求内。
- **全链真实闭环**：真 SITL 飞控（固件围栏硬拦截）→ 真出证 → 真链锚定（FISCO BCOS 国密四节点 PBFT）→ 真审计追溯；第三方复验双形态：Linux 二进制（4.9s）/ 浏览器 WASM（零服务端参与）。

## 架构总览

```
┌──────────────────────────  Windows / 部署机  ──────────────────────────┐
│  Vue 门户(:5174)   FastAPI backend(:8000)   worker(证明验证)           │
│      │                    │ 受理门控五步        │                       │
│      │                    │                     │ verify-instances      │
│  三工作台（飞手/审计/机构）│ recordAuth/nonce   ▼                       │
│      │                    ▼                     判决件归档              │
└──────┼────────────────────┼─────────────────────┬───────────────────────┘
       │                    │ 链上写面             │
       ▼                    ▼                     ▼
┌────────────── WSL2（常驻基础设施）─────────────────────────────────────┐
│  FISCO BCOS 国密四节点(PBFT)   ArduPilot SITL(SERIAL0:5760)            │
│            ▲                            ▲                             │
│            └── 证据链/公示面            飞行桥(:8100，闸门+围栏+遥测)   │
└────────────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
├── backend/            # FastAPI 应用（accounts/authz/ra/audit/chain/zk）、迁移、e2e 脚本
├── gcs/bridge/         # 飞行桥：MAVLink 闸门、围栏、遥测链、TRAIL 出证编排
├── gcs/web/            # Vue 三工作台（飞手/审计/机构）
├── zksvc/              # Rust 证明器（zkc CLI）+ vendor 钉定快照（HyperPlonk+Basefold）
├── contracts/          # Solidity 四合约（IdentityRegistry/PolicyRegistry/FlightAuthRegistry/TelemetryAnchor）
├── scripts/            # demo_up/demo_reset、链节点/SITL 拉起、部署模板
├── docs/               # 性能档案（全部实测判决行）、答辩口径卡、设计方案
└── alembic/            # 数据库迁移
```

## 快速开始

### 环境要求

- Windows 10/11 + WSL2（Ubuntu，systemd 启用）——承载联盟链与 SITL
- Python 3.13（`backend/.venv`）、Node 22、Rust stable（zksvc 构建）
- FISCO BCOS 国密四节点（`scripts/chain_nodes_up.sh` 拉起）
- ArduPilot SITL（`scripts/sitl_units_up.sh` 拉起，可选——无飞控亦可走完除飞行外的全部流程）

### 部署配置

1. 复制部署路径模板并按本机修改（该文件已被 .gitignore，不会上传）：

   ```bash
   cp .local_env.example .local_env
   # 编辑 FZ_UAS_WSL / FZ_TMP_WSL 为本机实际路径
   ```

2. 安装依赖并构建：

   ```bash
   cd backend && python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
   cd ../gcs/web && npm install && npm run build
   cd ../zksvc && cargo build --release
   ```

### 启动与初始化

```bash
python backend/scripts/seed_accounts.py    # 预置机构账户（口令写入 %TEMP%，线下交付）
python backend/scripts/demo_reset.py --yes --down  # 演示库纯净重置（清库→迁移→播种）
python scripts/demo_up.py                  # 一键拉起 backend/bridge/web（真链自动探活）
```

- 门户：`http://localhost:5174`（飞手注册 / 三角色登录）
- 审计台/机构台：登录后按角色自动进入
- **演示档预置口令**：`auditor / auditor123`、`admin / admin123`（首登激活）——仅适用于本地演示环境；生产部署必须通过 `FZ_SEED_AUDITOR_PASSWORD` / `FZ_SEED_ADMIN_PASSWORD` 注入随机口令。

### 五套验证门禁（backend/ 下执行）

```bash
python -m pytest tests/ -q                                  # 后端全量 278
python -m pytest ../gcs/bridge/test_bridge_core.py -q       # 飞行桥 32
./.venv/Scripts/python.exe scripts/e2e_browser_ui.py        # 浏览器级 29（自起隔离夹具）
FZ_SEED_AUDITOR_PASSWORD=... FZ_SEED_ADMIN_PASSWORD=...   ./.venv/Scripts/python.exe scripts/e2e_frontend_api.py    # 接口级实弹 62（真链+真出证）
./.venv/Scripts/python.exe scripts/e2e_roles_live.py   --auditor-pw .. --admin-pw ..                             # 三角色全职责 30
```

全真串联判决行：`scripts/scenario_S1_fullchain.py`（46 项断言：登记→出证→ARM 真 SITL→合规飞行→越围栏取证→TRAIL 证书→令状双控→追溯，中途零替身）。

## 关键安全机制（负例一等公民）

| 攻击面 | 防线 |
|---|---|
| 令牌重放/篡改 | 一次性令牌（token_used 拒二次 ARM）、验签+计划绑定+窗口校验 |
| 子凭证/nonce 重放 | 库级+链级双拒（sub_cred_used / nonce_used 链上烧毁） |
| 单席越权解锁 | 双控双签名缺一不可；批准即绑定"查什么" |
| 电路替换/降级 | 电路指纹链上公示 fail-closed（pin_mismatch 409）；单字节漂移 prove 即拒 |
| 撤销逃逸 | 三层防线：按人吊销→子凭证出示钥传播并入→签发面预检；验证后 TOCTOU 复查 |
| 出示钥链接 | 每张子凭证一次性全新钥对（出示公钥层跨申请不可链接） |
| 服务端造假 | proofDigest 上链+判决件归档+第三方独立复验——"跳过验证直接发令牌"可被任何第三方戳穿 |

## 文档

- [docs/性能档案.md](docs/性能档案.md) —— 全部性能与电路判决行（含实测命令）
- [docs/答辩口径卡.md](docs/答辩口径卡.md) —— 宣称→判决行→可复现命令三点一线
- [docs/证明体系安全注记.md](docs/证明体系安全注记.md) —— 零知识掩蔽与参数安全预算
- [docs/SMT深度16规划与安全论证.md](docs/SMT深度16规划与安全论证.md) —— 撤销树参数决策记录
- [docs/三大测试体系设计方案.md](docs/三大测试体系设计方案.md) —— 密码/安全防御链/性能三大测试设计
- [docs/三大测试汇总报告.md](docs/三大测试汇总报告.md) —— 三套件全量成绩单（密码审计 82/防御链 55+回归 9/性能 46，报告 JSON 可溯）

## 诚实边界（先于提问）

- 演示形态：SITL 仿真 + 设备钥由桥接模拟（TCB 声明，真机 SE/TCM 路线成文）；
- RA（登记机构）与授权服务为两信任主体，合谋即破匿名——组织级 TCB 声明；
- 一证多机（SN 绑定端到端）**⑥代已交付**（服务端权威 sn_hash+令牌域+桥第 6 查）；跨申请不可链接已交付（一次性出示钥）；
- 限速器已落库共享（`rate_limit_buckets` 表跨进程共享窗）；演示档口令为固定演示值；
- 证明时长本机分钟级（服务器窗 25s≤60s 硬门）；本档不宣称生产就绪——生产化路线见 docs/生产部署与安全演进.md。

## License

版权所有，许可条款待定（参见仓库公告）。
