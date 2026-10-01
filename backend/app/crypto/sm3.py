"""SM3 封装——全系统唯一哈希入口（SP-1 全栈国密红线）。

引擎选择（0C 根修，2026-09-04）：优先 OpenSSL C 实现（hashlib.new("sm3")），
且仅当其通过 GB/T 32905-2016 A.1 锚向量逐字节验证后才启用；不可用或验证
失败自动回落 gmssl 纯 Python。两引擎对调用方完全透明：bytes 进、32B 出。

杠杆实测（0C 测量）：单次摘要 ~250µs（gmssl）→ ~1.2µs（OpenSSL，~200×）；
PBKDF2-HMAC-SM3 80k 迭代官方向量 431.49s → 秒级。回落引擎正确性由
tests/test_crypto_kdf.py 慢层（check_full.sh/nightly）全量向量守卫。
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Callable
from typing import Any

# GB/T 32905-2016 A.1："abc" 的标准摘要（引擎验证锚；与 tests/test_crypto_sm3.py 同源）
_GBT_ANCHOR = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def _select_engine(new_fn: Callable[[str], Any] | None = None) -> str:
    """选定 SM3 引擎：OpenSSL 仅在锚向量通过时启用，否则回落 gmssl。"""
    if new_fn is None:
        new_fn = hashlib.new
    with contextlib.suppress(Exception):
        d = new_fn("sm3")
        d.update(b"abc")
        if d.digest().hex() == _GBT_ANCHOR:
            return "openssl"
    return "gmssl"


_ENGINE = _select_engine()


def engine_name() -> str:
    """当前 SM3 引擎（"openssl" | "gmssl"）；供测试与运维自省。"""
    return _ENGINE


def _sm3_gmssl(data: bytes) -> bytes:
    from gmssl import sm3 as _gmssl  # 延迟导入：仅回落路径需要

    return bytes.fromhex(_gmssl.sm3_hash(list(data)))


def sm3_bytes(data: bytes) -> bytes:
    """SM3 摘要：bytes 进，32 字节出（引擎透明）。"""
    if _ENGINE == "openssl":
        return hashlib.new("sm3", data).digest()
    return _sm3_gmssl(data)


def sm3_hex(data: bytes) -> str:
    """SM3 摘要：bytes 进，64 位小写 hex 出（引擎透明）。"""
    if _ENGINE == "openssl":
        return hashlib.new("sm3", data).hexdigest()
    return _sm3_gmssl(data).hex()
