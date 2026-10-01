#!/usr/bin/env python
"""B0 密码引擎微基准——输出性能档案判决行（标 [实测]+日期+机器）。

运行：cd uas && backend/.venv/Scripts/python.exe scripts/bench_b0.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from statistics import median

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.crypto import sm2, sm3, sm4
from app.crypto.sm2 import generate_keypair, sign, verify
from app.crypto.sm4 import SM4GCM

N_HASH = 2000
N_SIGN = 20
N_VERIFY = 50
N_GCM = 200
PAYLOAD = b"f" * 1024  # 1KB


def bench(fn, n: int) -> float:
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1000)
    return median(ts)


def main() -> None:
    print(f"SM3 引擎={sm3.engine_name()}  1KB×{N_HASH} 中位 {bench(lambda: sm3.sm3_bytes(PAYLOAD), N_HASH):.3f} ms/op")
    priv, pub = generate_keypair()
    msg = b"bench"
    sig = sign(priv, msg)
    assert verify(pub, msg, sig)
    print(f"SM2 sign  ×{N_SIGN} 中位 {bench(lambda: sign(priv, msg), N_SIGN):.3f} ms/op")
    print(
        f"SM2 verify（引擎={sm2.engine_name()}）×{N_VERIFY} 中位 "
        f"{bench(lambda: verify(pub, msg, sig), N_VERIFY):.3f} ms/op"
    )
    g = SM4GCM(b"k" * 16)
    print(
        f"SM4-GCM（引擎={sm4.engine_name()}）1KB 加密 ×{N_GCM} 中位 "
        f"{bench(lambda: g.encrypt(b'n' * 12, PAYLOAD, b''), N_GCM):.3f} ms/op"
    )


if __name__ == "__main__":
    main()
