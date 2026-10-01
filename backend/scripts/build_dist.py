"""验证分发站产物构建（2026-09-28 分发批）——可复现的 dist 重建。

用法（在 uas 仓根或 backend/ 下）：
  # 从 WSL 尖峰副本（默认形态：zkc 由 ~/spike/zksvc native 构建）
  python scripts/build_dist.py --zkc '\\\\wsl$\\Ubuntu\\home\\ouye\\spike\\zksvc\\target\\release\\zkc'
  # 或任意已构建的 Linux 二进制路径 + wasm 产物
  python scripts/build_dist.py --zkc <path> --wasm <path>

产物（backend/dist/，gitignore——二进制不进 git）：
  zkc-linux-amd64 / zkc.wasm / zksvc-build-manifest.json / SHA256SUMS.txt

供应链口径：manifest 恒取 zksvc/build_manifest.json（官方钉定源——与链上公示
指纹同源）；SHA256SUMS 由本脚本按实物重算。zkc 构建配方（WSL）：
  systemd-run --uid=ouye（rustup RUSTUP_TOOLCHAIN=nightly-x86_64-unknown-linux-gnu
  覆盖 rust-toolchain.toml 的 windows 钉）cargo build --release -j 2 --offline
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
DIST = BACKEND / "dist"


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zkc", required=True, help="Linux zkc 二进制路径（默认形态=WSL 尖峰副本产物）")
    ap.add_argument("--wasm", default=None, help="zkc.wasm 路径（缺省=保留现有 wasm 产物）")
    args = ap.parse_args()

    zkc = Path(args.zkc)
    if not zkc.is_file():
        print(f"[FAIL] zkc 不存在: {zkc}")
        return 1
    if not zkc.read_bytes()[:4] == b"\x7fELF":
        print("[FAIL] 非 ELF 二进制（Linux x86-64 形态检查）")
        return 1

    DIST.mkdir(parents=True, exist_ok=True)
    shutil.copy2(zkc, DIST / "zkc-linux-amd64")
    if args.wasm:
        wasm = Path(args.wasm)
        if not wasm.is_file():
            print(f"[FAIL] wasm 不存在: {wasm}")
            return 1
        shutil.copy2(wasm, DIST / "zkc.wasm")
    elif not (DIST / "zkc.wasm").is_file():
        print("[WARN] zkc.wasm 缺失（--wasm 未给且无存量）——页面将标「未生成」")
    # manifest 恒取官方钉定源（链上公示同源——分发面零手抄）
    shutil.copy2(BACKEND.parent / "zksvc" / "build_manifest.json", DIST / "zksvc-build-manifest.json")

    names = ["zkc-linux-amd64"]
    if (DIST / "zkc.wasm").is_file():
        names.append("zkc.wasm")
    names.append("zksvc-build-manifest.json")
    lines = []
    for n in names:
        d = _sha256(DIST / n)
        lines.append(f"{d}  {n}")
        print(f"[dist] {d}  {n}")
    (DIST / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"[dist] 完成（{DIST}）——页面 /verify/ 实时校验值自动换代")
    return 0


if __name__ == "__main__":
    sys.exit(main())
