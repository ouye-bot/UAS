"""SM3 封装测试。向量源：GB/T 32905-2016 附录 A.1（官方唯一示例向量）。"""

import pytest

from app.crypto import sm3
from app.crypto.sm3 import engine_name, sm3_bytes, sm3_hex

# GB/T 32905-2016 A.1："abc"
_ABC_MSG = b"abc"
_ABC_DIGEST = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def test_gbt32905_abc_vector():
    assert sm3_hex(_ABC_MSG) == _ABC_DIGEST


def test_sm3_bytes_returns_32_bytes():
    out = sm3_bytes(b"")
    assert isinstance(out, bytes) and len(out) == 32


def test_sm3_hex_is_64_lowercase():
    h = sm3_hex(b"x" * 1000)  # 多块输入
    assert len(h) == 64 and h == h.lower()
    assert sm3_hex(b"x" * 1000) == h  # 确定性


def test_sm3_boundary_lengths_differ():
    # 55/56/64/65 字节跨填充边界，输出应互不相同
    digests = {sm3_hex(b"a" * n) for n in (55, 56, 64, 65)}
    assert len(digests) == 4


# ---- 引擎契约（0C 根修：OpenSSL 快径 + 锚验证失败自动回落 gmssl；引擎对调用方透明）----


def test_engine_is_openssl_when_available():
    """可用且过 GB/T 锚时必须选 OpenSSL——PBKDF2 80k 迭代 431s→秒级的根源（0C 实测）。"""
    import hashlib

    if "sm3" not in hashlib.algorithms_available:
        pytest.skip("本环境 OpenSSL 无 sm3：回落 gmssl 即正确行为")
    assert engine_name() == "openssl"


def test_engine_invariance_bytes_and_hex(monkeypatch):
    """引擎不变量：默认引擎与强制 gmssl 回落结果逐字节一致（含填充边界与多块）。"""
    samples = [b"", b"abc", b"x" * 63, b"y" * 64, b"z" * 65, bytes(range(256)) * 3]
    for s in samples:
        expected = sm3_bytes(s)
        monkeypatch.setattr(sm3, "_ENGINE", "gmssl")
        try:
            assert sm3_bytes(s) == expected, s[:16]
            assert sm3_hex(s) == expected.hex(), s[:16]
        finally:
            monkeypatch.undo()


def test_selector_falls_back_on_openssl_anchor_mismatch():
    """选择器防御：OpenSSL 存在但锚向量不符（伪 sm3/算法替换）⟹ 必须回落 gmssl。"""

    class _FakeDigest:
        def update(self, data):
            pass

        def digest(self):
            return b"\x00" * 32  # 任何非 GB/T 锚值

    assert sm3._select_engine(new_fn=lambda name: _FakeDigest()) == "gmssl"


def test_selector_falls_back_on_openssl_absent():
    """选择器防御：hashlib.new 拒绝 sm3（无此算法）⟹ 回落 gmssl。"""

    def _raise(name):
        raise ValueError("unsupported hash type")

    assert sm3._select_engine(new_fn=_raise) == "gmssl"
