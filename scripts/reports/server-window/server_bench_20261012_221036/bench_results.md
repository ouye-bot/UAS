# ⑦代服务器窗复测结果（server_bench.py 自动生成）

- 测量时间：2026-10-12 22:12:00
- 命令：`python3 scripts/server_bench.py full`（RAYON=12，N=3 取中位）
- 构建复现性门：PASS——SM3(4201a82|b05df9d8e2d5f39fb4d92b19d47379c86c0d40159e9fd39a1c9c77455b9b4985)
- 机器画像：Alibaba Cloud Linux 4.0.6 (OpenAnolis Edition)｜Intel(R) Xeon(R) 6982P-C｜逻辑核 12｜内存 46.02GiB｜磁盘空闲 183.12GiB｜rustc 1.98.0-nightly (31a9463c6 2026-05-25)

## 服务器窗 · ⑦代四元组（对照④代 2026-09-27：AUTH 25.14/0.68、TRAIL 15.10/0.21）

| 语句 | setup | preprocess | prove | 回读 verify | total | proof |
|---|---|---|---|---|---|---|
| **AUTH** | 0.174s | 1.443s | **14.514s** | 0.531s | 19.904s | 16,063,712B |
| **TRAIL** | 0.225s | 1.339s | **4.175s** | 0.066s | 7.82s | 6,157,272B |

## ≤60s 演示硬门判定

- AUTH prove 中位 **14.514s** → **PASS**
  （硬门 60s，余量 4.13×；④代口径 25.14s/近 2.4×）
- TRAIL prove/verify 中位 **4.175s / 0.066s**
  （无硬门；④代 15.10s/0.21s，本机 12.3s@10-07）

## 性能档案 现行口径总表 · 回填块（测后复制进 docs/性能档案.md 并随正式入档批次改写）

```
| 服务器窗 AUTH prove | 14.514s（≤60s 硬门余量 4.13×） | [实测 2026-10-12，⑦代电路——服务器窗复测（12C/46.02G，rustc 1.98.0-nightly (31a9463c6 2026-05-25)，RAYON=12）] |
| TRAIL 服务器 prove / verify | 4.175s / 0.066s | [实测 2026-10-12，⑦代口径] |
```

## 逐次明细

### AUTH（tests/auth_canonical_spec.json，黄金向量 v7 口径，实例 26 逐位核对过）

| run | setup | preprocess | prove | verify | total | proof | pcs |
|---|---|---|---|---|---|---|---|
| 1 | 0.187 | 1.474 | 14.421 | 0.533 | 19.872 | 16,063,712B | il=1/dd=0/st=0 |
| 2 | 0.174 | 1.443 | 14.514 | 0.531 | 19.904 | 16,063,712B | il=1/dd=0/st=0 |
| 3 | 0.152 | 1.418 | 14.614 | 0.529 | 19.957 | 16,063,712B | il=1/dd=0/st=0 |

### TRAIL（tests/trail_canonical_spec.json，实例 8）

| run | setup | preprocess | prove | verify | total | proof | pcs |
|---|---|---|---|---|---|---|---|
| 1 | 0.223 | 1.339 | 4.161 | 0.066 | 7.812 | 6,157,272B | il=1/dd=0/st=0 |
| 2 | 0.225 | 1.334 | 4.176 | 0.066 | 7.82 | 6,157,272B | il=1/dd=0/st=0 |
| 3 | 0.225 | 1.34 | 4.175 | 0.066 | 7.843 | 6,157,272B | il=1/dd=0/st=0 |

## 诚实声明

- 证明字节跨次不复现（mask=on OsRng 每证新鲜）——对拍锚=尺寸+指纹+公开实例三元，proof_sm3 仅记录不比对。
- 逐次明细与中位数全部落盘 bench_results.json；判决行引用时注明机器画像与工具链。
