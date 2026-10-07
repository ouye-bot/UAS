# 并发 4 档扫描操作手册（perf_suite 自动生成——主会话在重启窗口执行）

## 关键事实（本轮代码定位 [实测-代码]）
- 串行闸 env `FZ_PROVE_MAX_CONCURRENT` 由 **桥进程** 读取：
  `gcs/bridge/prover.py` L79 `_PROVE_MAX = int(os.environ.get("FZ_PROVE_MAX_CONCURRENT", "1"))`。
  **重启 backend 无效——必须重启桥（8100）**（"重启 backend 才生效"的假设不成立，特此勘误）。
- 闸语义=**拒绝式**：超闸的新 `/prove/start` 即刻 `429 prove_busy`，不入队（本构建
  任务状态机 assembling→proving→done/failed，无 queued 态）。并发 N 档的"排队时延"
  须由压测端堆叠 N+ 个在途任务后，以「提交→status 离开 assembling」+「429 缺席窗」统计。

## 自动执行（一键）
```bash
bash backend/scripts/reports/perf-concurrency4-scan.sh
```
脚本流程：`FZ_PROVE_MAX_CONCURRENT=4` 注入三服务重启 → 探活 →
`python scripts/perf_suite.py --concurrency 1 --runs 5` → 无 env 重启恢复缺省闸=1。
**执行前提：无真实飞行演示在途**（重启会清桥任务表；worker 未决回执随 backend 重启保留）。

## 手动步骤
1. `python backend/scripts/sitl_e2e_services.py down`（全杀纪律——多实例残留教训）
2. 以 `FZ_PROVE_MAX_CONCURRENT=4` 注入后 `python backend/scripts/sitl_e2e_services.py up`
   （真链档需 `FZ_CHAIN_ANCHOR=real` 与演示 env 同窗注入——以 demo_up 的 env 面为准）
3. `cd backend && python scripts/perf_suite.py --concurrency 1 --runs 5`
4. 无 env 重启恢复缺省闸=1（步骤 1~2 重跑一遍不带 env）

## 出证预算
- 每档消耗 = 预热 1 + 实测 runs 张；2 档+4 档连扫请分窗执行，单窗总消耗 ≤6 张纪律不变。
- 报告 env.prove_max_concurrent 记录执行进程的 env 值——与桥注入值核对一致方可归因。
