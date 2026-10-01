#!/usr/bin/env bash
# 四合约国密 solc 编译入口（幂等）。WSL 侧编译逻辑在 compile_wsl.sh（落盘脚本，
# 规避 wsl.exe 参数转义层）；本脚本负责路径转换、调用与 manifest 生成。
# 产物：build/<name>.{bin,abi,runtime.bin} + build_manifest.md sha256 对账。
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
# 中文路径经 wsl.exe 参数传递会损坏编码——靠 wsl 的 Windows cwd 自动继承（勿传路径参数）
wsl -u root bash compile_wsl.sh

cd "$DIR"
python - <<'PYEOF'
import hashlib
import subprocess
from pathlib import Path

build = Path("build")
ver = subprocess.run(
    ["wsl", "-u", "root", "/home/ouye/.fisco/solc/0.4.25/sm3/solc", "--version"],
    capture_output=True, text=True,
).stdout.strip().splitlines()
lines = [
    "# 合约编译产物 manifest（B1 起）",
    "",
    "- 编译器：FISCO solc 国密版（WSL /home/ouye/.fisco/solc/0.4.25/sm3/solc）",
    f"- 版本：{ver[-1] if ver else 'unknown'}",
    "- 命令：`solc --bin --abi --overwrite -o build src/<C>.sol`（逐合约显式）；runtime=`--bin-runtime`",
    "- 目标链：FISCO BCOS 2.9.0 国密四节点（sm_crypto=true）",
    "",
    "| 文件 | sha256 |",
    "|---|---|",
]
for p in sorted(build.iterdir()):
    if p.suffix in (".bin", ".abi") or p.name.endswith(".runtime.bin"):
        lines.append(f"| {p.name} | {hashlib.sha256(p.read_bytes()).hexdigest()} |")
lines.append("")
lines.append("## 部署对账（chain_smoke --deploy 回填）")
lines.append("")
lines.append("| 合约 | 部署地址 | 部署块 | runtime sha256（前 16） |")
lines.append("|---|---|---|---|")
lines.append("|（待部署） | | | |")
Path("build_manifest.md").write_text("\n".join(lines), encoding="utf-8")
print("manifest 已生成")
PYEOF
