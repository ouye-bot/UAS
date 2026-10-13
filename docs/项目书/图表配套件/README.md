# 图表配套件索引

本目录存放作品设计报告正文（`../作品设计报告正文.txt`）中全部图表位的配套产出文件。

## Python 数据图（脚本 + 300dpi PNG）

| 脚本 | 成图 PNG | 正文图表位 | 数据源 |
|---|---|---|---|
| `py/fig15_circuit_evolution.py` | `png/图15_电路规模演进图.png` | 2.3 节 图 15 | 性能档案.md:28（各代电路普查实测值 104,287→19,434） |
| `py/fig16_cross_system_comparison.py` | `png/图16_同语句跨系统对比图.png` | 2.3 节 图 16 | 性能档案.md:28 + REPORT-plonky2-auth.md:50-51/61-63（同语句 Plonky2 实测对比） |
| `py/fig18_performance_benchmark.py` | `png/图18_性能对比图.png` | 3.3 节 图 18 | 性能档案.md:30/35（服务器窗 14.514s/0.531s/4.175s + 承诺线 30/5/20） |

### 复现命令

```bash
cd py
python fig15_circuit_evolution.py   # → ../png/图15_电路规模演进图.png
python fig16_cross_system_comparison.py  # → ../png/图16_同语句跨系统对比图.png
python fig18_performance_benchmark.py    # → ../png/图18_性能对比图.png
```

需 matplotlib ≥3.5 且系统中文字体（SimHei 或 Microsoft YaHei）可用。输出 300dpi PNG。

## drawio XML 源文件

| 文件 | 正文图表位 | 说明 |
|---|---|---|
| `drawio/图1_系统总体架构图.drawio` | 1.2 节 图 1 | 五层架构（应用/服务/密码/电路/链），四类合约按监管角色划分 |
| `drawio/图5_门限解锁时序图.drawio` | 2.1.5 节 图 5 | 三取二门限 + 双人协同 + 四关校验时序 |
| `drawio/图6_跨域吊销传播图.drawio` | 2.1.6 节 图 6 | 跨域吊销经聚合撤销树即时传播 |

可用 draw.io（https://app.diagrams.net）打开编辑，或用 `xml.etree.ElementTree` 验证 XML 合法性。

## 前端页面截图

| 文件 | 正文图表位 | 说明 |
|---|---|---|
| `screenshots/06_登录页.png` | 2.2 节运行环境展示 | 飞证系统登录页 |
| `screenshots/08_飞手工作台.png` | 2.2 节 图 8 | 飞手工作台：六段刻度轨+令牌取件+链上留痕+证书卡 |
| `screenshots/09_管理员工作台.png` | 2.2 节 图 9 | 机构管理员工作台：待办+四板块+机构域标识 |
| `screenshots/10_审计台.png` | 2.2 节 图 10 | 审计台：违规收件箱+令状立案+调证流程 |
| `screenshots/11_治理公示页.png` | 2.2 节 图 11 | 治理公示页：互认名册+撤销锚+聚合状态+治理参数 |
| `screenshots/14_门限解锁留痕.png` | 2.2 节 图 14 | 门限解锁留痕：逐域四关判定+份额合成 |

由 Playwright Chromium（headless，1600×900）对 http://localhost:5174 实运行截取。

## 未列入本批的图表位

正文共 19 个图位＋8 个表位。以下图位由正文文字直接承载、无需独立配图文件：

- 图 3~图 7 协议时序图的 drawio 源文件中，图 1（架构图）已覆盖总体拓扑
- 表 1（功能清单）、表 2（承诺对照）、表 3（场景覆盖）、表 4（技术指标总表）、表 7（测试规模总表）为正文表格内容稿，排版时由文字处理器生成

## 装配注意事项

1. 成图 PNG 替换正文「占位待配」标记后，标记字样随备查块一并删除。
2. drawio 源文件可用 draw.io 打开编辑后导出为 SVG/PNG 嵌入排版稿。
3. Python 脚本可用 `python <脚本名>` 重新生成 PNG（数据硬编码自性能档案总表）。
4. 截图在终稿装配前应重新截取以获取最新界面状态。
