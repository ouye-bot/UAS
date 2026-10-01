"""HMAC-SM3（RFC 2104，块长 64B）。gmssl 3.2.2 无此原语，自实现。"""

from __future__ import annotations

from app.crypto.sm3 import sm3_bytes

_BLOCK = 64  # SM3 块长


def hmac_sm3(key: bytes, msg: bytes) -> bytes:
    """RFC 2104：H(K^opad || H(K^ipad || text))。key 超过块长先 SM3。"""
    if len(key) > _BLOCK:
        key = sm3_bytes(key)
    key = key.ljust(_BLOCK, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = sm3_bytes(ipad + msg)
    return sm3_bytes(opad + inner)
