"""PBKDF2-HMAC-SM3（RFC 8018）。用例：密码派生（账户 KEK/激活核对子）。

双引擎（2026-10-04 密码底座升档，与 sm3.py 同一引擎门）：OpenSM3 可用
（经 GB/T 锚向量验证，见 sm3.py:_select_engine）时走 hashlib C 实现——
600k 轮实测 ~0.36s（纯 Python 回落引擎约 260× 慢）；回落路径语义逐字节
同构（官方向量 tests/test_crypto_kdf.py 双路径全量守卫）。
"""

from __future__ import annotations

import hashlib

from app.crypto.hmac_sm3 import hmac_sm3
from app.crypto.sm3 import _ENGINE


def _pbkdf2_pure(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    out = bytearray()
    block_index = 1
    while len(out) < dklen:
        u = hmac_sm3(password, salt + block_index.to_bytes(4, "big"))
        acc = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = hmac_sm3(password, u)
            acc ^= int.from_bytes(u, "big")
        out.extend(acc.to_bytes(32, "big"))
        block_index += 1
    return bytes(out[:dklen])


def pbkdf2_hmac_sm3(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    if iterations < 1:
        raise ValueError("iterations 必须 ≥ 1")
    if dklen < 1:
        raise ValueError("dklen 必须 ≥ 1")
    if _ENGINE == "openssl":
        # OpenSSL 引擎档：hashlib C 路径（同 RFC 8018——官方向量双路径对拍）
        return hashlib.pbkdf2_hmac("sm3", password, salt, iterations, dklen)
    return _pbkdf2_pure(password, salt, iterations, dklen)
