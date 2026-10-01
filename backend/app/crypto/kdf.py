"""PBKDF2-HMAC-SM3（RFC 8018）。用例：密码派生（机构托管密钥库/用户备份密码）。"""

from __future__ import annotations

from app.crypto.hmac_sm3 import hmac_sm3


def pbkdf2_hmac_sm3(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    if iterations < 1:
        raise ValueError("iterations 必须 ≥ 1")
    if dklen < 1:
        raise ValueError("dklen 必须 ≥ 1")
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
