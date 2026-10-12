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


# ---- HKDF-SM3（RFC 5869 标准 extract/expand 双层——⑫O-2 批：OPAQUE rwd 派生链） ----
# G5 缺口如实（归约修订版 §10）：HKDF-SM3 无 RFC 基线——构造=RFC 5869 伪代码逐字
# 平移（HMAC 换 hmac_sm3），「构造自证」=tests/test_crypto_kdf.py 直呼参考组合对拍。

_HKDF_HASH_LEN = 32  # SM3 输出 32B（=RFC 5869 HashLen）


def hkdf_sm3_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 §2.2 Extract：PRK = HMAC-SM3(salt, IKM)；盐缺省=HashLen 零串。

    OPAQUE rwd 链位（设计 §1.4，归约 §5.3 记式逐字对齐）：①Finalize 提取与
    ③randomized_password 两处 Extract 的第一参恒空串（盐位）——域串落 IKM 位。"""
    if not salt:
        salt = b"\x00" * _HKDF_HASH_LEN
    return hmac_sm3(salt, ikm)


def hkdf_sm3_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3 Expand：OKM=T(1)‖T(2)…，T(i)=HMAC-SM3(PRK, T(i−1)‖info‖i)。

    OPAQUE rwd 链位：④masking_key（info="FZ-OPAQUE-MaskingKey|v1"，32B）与
    ⑤KEK（info=env_nonce‖"FZ-OPAQUE-EnvelopeKey|v1"，16B）。"""
    if length < 1:
        raise ValueError("length 必须 ≥ 1")
    if length > 255 * _HKDF_HASH_LEN:
        raise ValueError(f"length 超出 HKDF 上限（255×{_HKDF_HASH_LEN}B）")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sm3(prk, t + info + counter.to_bytes(1, "big"))
        okm += t
        counter += 1
    return okm[:length]
