# -*- coding: utf-8 -*-
"""vendor 重钉流程（R1 2026-09-21 固化为脚本——教训㊿+6 全流程内建）。

用法：python scripts/repin_vendor.py <共享仓路径> <commit短sha>
步骤：①git -c core.autocrlf=false archive → zksvc/vendor/plonkish-<sha>/
     ②重算 vendor/MANIFEST.json（逐文件 SM3+aggregate，路径相对快照根）
     ③build_manifest.json 换代（pinned/snapshot_dir/aggregate/file_count）
     ④zksvc/Cargo.toml vendor 路径换代  ⑤旧快照目录删除（换钉成功后）
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

UAS = Path(__file__).resolve().parents[1]
ZKSVC = UAS / "zksvc"
VENDOR = ZKSVC / "vendor"


def sm3(data: bytes) -> str:
    sys.path.insert(0, str(UAS / "backend"))
    from app.crypto.sm3 import sm3_bytes

    return sm3_bytes(data).hex()


def main() -> int:
    repo = Path(sys.argv[1]).resolve()
    short = sys.argv[2]
    snap = VENDOR / f"plonkish-{short}"
    if snap.exists():
        print(f"快照已存在：{snap}")
        return 1
    full = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", short], capture_output=True, text=True, check=True
    ).stdout.strip()

    # ① archive（CRLF 教训⑪：autocrlf=false）
    snap.mkdir(parents=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "core.autocrlf=false", "archive", full, "plonkish"],
        stdout=open(snap / "_archive.tar", "wb"),
        check=True,
    )
    import tarfile

    with tarfile.open(snap / "_archive.tar") as tf:
        tf.extractall(snap)
    (snap / "_archive.tar").unlink()

    # ② MANIFEST（逐文件 SM3，声明序=排序遍历；聚合=逐文件 sm3 hex 串流式进 SM3，
    # 与 Rust pin_fingerprint 聚合式逐字同构）
    files = []
    st_data = bytearray()
    for p in sorted(snap.rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            rel = p.relative_to(snap).as_posix()
            data = p.read_bytes()
            h = sm3(data)
            files.append({"path": rel, "bytes": len(data), "sm3": h})
            st_data.extend(h.encode("ascii"))
    agg_hex = sm3(bytes(st_data))
    manifest = {
        "pin_commit": short,
        "file_count": len(files),
        "aggregate_sm3": agg_hex,
        "files": files,
    }
    (VENDOR / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=1), encoding="utf-8", newline=""
    )

    # ③ build_manifest 换代
    bm_path = ZKSVC / "build_manifest.json"
    bm = json.loads(bm_path.read_text(encoding="utf-8"))
    old_dir = bm["snapshot_dir"]
    bm.update(
        {
            "pinned_commit_short": short,
            "pinned_commit_full": full,
            "snapshot_dir": f"zksvc/vendor/plonkish-{short}",
            "aggregate_sm3": agg_hex,
            "file_count": len(files),
        }
    )
    bm_path.write_text(
        json.dumps(bm, indent=1, ensure_ascii=False), encoding="utf-8", newline=""
    )

    # ④ Cargo.toml 路径换代
    cargo = ZKSVC / "Cargo.toml"
    text = cargo.read_text(encoding="utf-8")
    old_snap_name = Path(old_dir).name
    if old_snap_name in text:
        text = text.replace(old_snap_name, f"plonkish-{short}")
        cargo.write_text(text, encoding="utf-8", newline="")
    else:
        print(f"[WARN] Cargo.toml 未找到旧快照名 {old_snap_name}——手工核对")

    # ⑤ 旧快照删除
    old_path = UAS / old_dir
    if old_path.exists() and old_snap_name != f"plonkish-{short}":
        import shutil

        shutil.rmtree(old_path)
    print(f"re-pin 完成：plonkish-{short} files={len(files)} aggregate={agg_hex[:16]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
