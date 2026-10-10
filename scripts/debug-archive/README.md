# debug-archive（一次性调试脚本归档 · ⑨站 2026-10-10）

本目录=历史一次性调试/探针脚本归档（git mv 移动不删——`git log --follow` 可溯全史）。

- 归档件**不保证可直接运行**：部分件内硬编码的 `scripts/...` 路径随归档失效
  （例：sitl_udp_pair_test.py 引用同目录 sitl_udp_recv_test.py 的旧位置），
  考古复用时请按现状自校路径。
- 引用面定谳=归档前逐件全仓 grep（py/sh/md/ts/vue/rs/cmd/bat/json/toml）；
  后续新发现的漏检引用按「指针改指 debug-archive 新路径或改指现行替代件」根修。
- 现行基础设施/活跃件清单见 scripts/ 顶层与 docs/MEMORY.md ⑨站条目。
