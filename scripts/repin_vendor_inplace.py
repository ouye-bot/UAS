# -*- coding: utf-8 -*-
"""vendor MANIFEST 就地重钉（⑦代换代仪式用，2026-10-06）。

与 scripts/repin_vendor.py ② 步同式（单一事实源对齐——快照不重打，就地
重算逐文件 SM3+aggregate；pin_commit 保持原快照 sha）：
  ① 逐文件 SM3（排序遍历=声明序，与 Rust pin_fingerprint 复算序一致）
  ② aggregate = 逐文件 sm3 hex 串流式进 SM3
  ③ MANIFEST.json 原格式重写（indent=1，LF）
用法：python scripts/repin_vendor_inplace.py
"""
import hashlib
import json
import sys
from pathlib import Path

UAS = Path(__file__).resolve().parents[1]
VENDOR = UAS / "zksvc" / "vendor"


def sm3(data: bytes) -> str:
    sys.path.insert(0, str(UAS / "backend"))
    from app.crypto.sm3 import sm3_bytes

    return sm3_bytes(data).hex()


def main() -> int:
    snap = VENDOR / "plonkish-4201a82"
    man_path = VENDOR / "MANIFEST.json"
    old = json.loads(man_path.read_text(encoding="utf-8"))
    files = []
    st = bytearray()
    for p in sorted(snap.rglob("*")):
        # 源面口径=原 archive 快照（148 文件）：尊重快照 .gitignore
        #（target/、*.output、auth_dead_cols.txt=生成产物不入指纹）。
        if (
            p.is_file()
            and ".git" not in p.parts
            and "target" not in p.parts
            and p.name != "auth_dead_cols.txt"
            and p.suffix != ".output"
        ):
            rel = p.relative_to(snap).as_posix()
            data = p.read_bytes()
            h = sm3(data)
            files.append({"path": rel, "bytes": len(data), "sm3": h})
            st.extend(h.encode("ascii"))
    manifest = {
        "pin_commit": old["pin_commit"],
        "file_count": len(files),
        "aggregate_sm3": sm3(bytes(st)),
        "files": files,
    }
    man_path.write_text(
        json.dumps(manifest, indent=1), encoding="utf-8", newline=""
    )
    print(f"[repin] files={len(files)} aggregate={manifest['aggregate_sm3']}")
    print(f"[repin] pin 串 = SM3({manifest['pin_commit']}|{manifest['aggregate_sm3']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
