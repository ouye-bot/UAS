"""验证分发站产物构建（2026-09-28 分发批；2026-10-15 代同步门禁硬化）——可复现的 dist 重建。

用法（在 uas 仓根或 backend/ 下）：
  # 从 WSL 尖峰副本（默认形态：zkc 由 ~/spike/zksvc native 构建）
  python scripts/build_dist.py --zkc '\\\\wsl$\\Ubuntu\\home\\ouye\\spike\\zksvc\\target\\release\\zkc'
  # 或任意已构建的 Linux 二进制路径 + wasm 产物
  python scripts/build_dist.py --zkc <path> --wasm <path>

产物（backend/dist/，gitignore——二进制不进仓）：
  zkc-linux-amd64 / zkc.wasm / zksvc-build-manifest.json / SHA256SUMS.txt

供应链口径：manifest 恒取 zksvc/build_manifest.json（官方钉定源——与链上公示
指纹同源）；SHA256SUMS 由本脚本按实物重算。zkc 构建配方（WSL，2026-10-15
实弹实证）：
  ①主仓 zksvc 同步到 WSL 本地盘（rsync -a 排除 target/probe_baseline/
    artifacts-*/内嵌 .log——/mnt/c 9p 上直接构建极慢且 target 必须排除；
    vendor-reg 必须整树同步且不得短于主仓——native 档 libmimalloc-sys 的
    cc 链缺文件=编译期 E2 崩，2026-10-15 实弹教训）；
  ②.cargo/config.toml 必须取 config-offline-full.toml（全量 35 行含
    [source.crates-io] 块——短版缺块=cc 等 registry 依赖离线必败，性能档案
    既有教训）；发行版 /usr/bin/cargo 不识 rustup target——构建必须走
    /home/ouye/.cargo/bin（systemd-run 需 --setenv=PATH 显式给）；
  ③wasm 档：cargo build --target wasm32-wasip1 --release --offline -j 2
    （RUSTUP_TOOLCHAIN=nightly-x86_64-unknown-linux-gnu 覆盖 rust-toolchain.toml
    的 windows 钉）；native 档：cargo build --release --offline -j 2。
  ④**分发前代门禁（本脚本内建，无豁免旗标）**：zkc（ELF）与 zkc.wasm 双
    产物逐一过门——必须含现役代标记（FZ-TRAIL-BIND2| 七字段报文域+
    FZ_ENGINE_PUB_HEX 运行时验签基准）且不含旧代模板，违者拒绝分发
    exit 1（2026-10-15 队长手测实弹教训：分发面 wasm 停 9/28 旧代、引擎
    绑定验签恒败，代差必须在分发口与 CI 双处红，不靠手测抓。ELF 同判的
    理由：第三方下载 zkc-linux-amd64 离线复验与浏览器 wasm 是同一验证面，
    只门 wasm 会把代差从 ELF 面再放进来一次）。
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
DIST = BACKEND / "dist"

# 现役代标记（与 zksvc/src/assemble.rs 装配面/后端 verify_dist.py 重签面同代）：
# BIND2=七字段报文域（auth_id/alt_max_cm/chain_head/围栏 4 界）；FZ_ENGINE_PUB_HEX=
# 引擎公钥运行时参数（浏览器 wasm 验签基准，2026-10-13~14 批）。旧代 wasm 只有
# FZ-TRAIL-BIND|四字段模板——字节级可判（BIND2 串不包含 "BIND|"，双向可断）。
_CURRENT_MARKERS = (b"FZ-TRAIL-BIND2|", b"FZ_ENGINE_PUB_HEX")
_STALE_MARKER = b"FZ-TRAIL-BIND|"


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def generation_gate(artifact: Path, kind: str) -> None:
    """分发口代门禁（zkc ELF 与 zkc.wasm 同判）：缺现役代标记或含旧代模板
    =拒绝分发（fail-closed，无豁免旗标——真要豁免只有改本脚本一条路，git
    可见）。两产物是同一验证面的两种载体（浏览器 wasm/离线 ELF），字节级
    代标记同源（assemble.rs 报文域模板+ENV 常量名都编进二进制）。"""
    data = artifact.read_bytes()
    stale = _STALE_MARKER in data
    missing = [m.decode() for m in _CURRENT_MARKERS if m not in data]
    if stale or missing:
        print(f"[FAIL] {kind} 代差门禁：{artifact}")
        if stale:
            print("       含旧代 binding 模板 FZ-TRAIL-BIND|（无围栏字段代）")
            print("       ——现役引擎 BIND2 七字段签名必验败")
        if missing:
            print(f"       缺现役代标记：{missing}（运行时引擎钥/现役报文域不在位）")
        print("       该产物是旧代构建——请从现役 zksvc 源重建（配方见头注），不得分发。")
        raise SystemExit(1)
    print(f"[gate] {kind} 代门禁通过：含 BIND2 报文域+FZ_ENGINE_PUB_HEX 基准，无旧代模板")


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
    # 入口 zkc（无论新旧）先过代门禁：ELF 与 wasm 是同一验证面的两种载体
    generation_gate(zkc, "zkc-linux-amd64")

    wasm_target = DIST / "zkc.wasm"
    if args.wasm:
        wasm = Path(args.wasm)
        if not wasm.is_file():
            print(f"[FAIL] wasm 不存在: {wasm}")
            return 1
        generation_gate(wasm, "zkc.wasm")
    elif wasm_target.is_file():
        # 存量 wasm 也过门禁：分发的每一件都必须与现役代同步（否则删除重建）
        generation_gate(wasm_target, "zkc.wasm（存量）")
    else:
        print("[WARN] zkc.wasm 缺失（--wasm 未给且无存量）——页面将标「未生成」")

    DIST.mkdir(parents=True, exist_ok=True)
    shutil.copy2(zkc, DIST / "zkc-linux-amd64")
    if args.wasm:
        shutil.copy2(wasm, wasm_target)
    # manifest 恒取官方钉定源（链上公示同源——分发面零手抄）
    shutil.copy2(BACKEND.parent / "zksvc" / "build_manifest.json", DIST / "zksvc-build-manifest.json")

    names = ["zkc-linux-amd64"]
    if wasm_target.is_file():
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
