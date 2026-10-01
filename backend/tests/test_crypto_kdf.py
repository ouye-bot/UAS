"""PBKDF2-HMAC-SM3 测试。

向量源：GmSSL C 官方测试套件 tests/pbkdf2test_sm3.h（60 条，本会话读入；
此处取 6 条覆盖 RFC 7914 官方例/伪随机/空口令/全零口令/Utf8/长迭代）。
"""

import pytest

from app.crypto.kdf import pbkdf2_hmac_sm3

VECTORS = [
    # (password_hex, salt_hex, iterations, dklen, expected_hex, 出处)
    (
        b"passwd",
        b"salt",
        1,
        64,
        "30530b86537c85ea33fbe26ee0adea8d8bd91d283b87936f400e83ad2364ef2632cd8662313657c0e6138ffeda2c4e6805869cbd8030188858d8a675ac762523",
        "RFC 7914 #1",
    ),
    (
        b"Password",
        b"NaCl",
        80000,
        64,
        "6064dd50568a7cd0fab52aea443fd71c6f45044fd0aede5928568be7948a34699d2bfce8a435110f551cc0e1814602c03c11ecb7f951fec50602850a5102cb88",
        "RFC 7914 #2（慢例）",
    ),
    (
        bytes.fromhex("7130577430643470"),
        bytes.fromhex("798acc7c76739d75"),
        4096,
        16,
        "67676e93c77d10cb6c3783285df0cf63",
        "伪随机 #3",
    ),
    (
        b"",
        bytes.fromhex("1a71e2118c9fbcc9"),
        4096,
        32,
        "20fdb4331ef976d15d8dc1af90d139424dba907d15e890c9b1fd7be9720c9f68",
        "空口令 #51",
    ),
    (
        bytes.fromhex("d0a3d1bed38acc83"),
        bytes.fromhex("8dfae85c9f2072ae"),
        4096,
        16,
        "1e1c52ab28aefa2910283d4e73b1a0ef",
        "Utf8 #27",
    ),
    (
        # 原文为 130 个 ASCII '0' 字符的 hex 串 → 65 字节 0x00（超 HMAC 块长，
        # 专项覆盖"长钥先哈希"路径；计划期曾误抄为 64 字节，已对源勘误）
        bytes(65),
        bytes.fromhex("9de9b71eeb9d9a34"),
        4096,
        16,
        "b6b45b3dfbd87e35dab8c4ce6bc3458a",
        "全零口令 #60（special case：65B 长钥）",
    ),
]


@pytest.mark.parametrize("pw,salt,iters,dklen,expect,src", VECTORS)
def test_pbkdf2_official_vectors(pw, salt, iters, dklen, expect, src):
    assert pbkdf2_hmac_sm3(pw, salt, iters, dklen).hex() == expect, src


@pytest.mark.slow
@pytest.mark.parametrize("pw,salt,iters,dklen,expect,src", VECTORS)
def test_pbkdf2_official_vectors_gmssl_fallback(pw, salt, iters, dklen, expect, src, monkeypatch):
    """慢层守卫（0C 分层）：强制 gmssl 回落引擎跑全量官方向量。

    生产引擎（OpenSSL）在默认门禁全量验证；回落引擎纯 Python 慢 ~260×，
    若不设守卫则只在 OpenSSL 缺失环境才被触发=回落路径腐化盲区。
    默认门禁跳过本组；scripts/check_full.sh（nightly/发布前）全量验证。
    """
    from app.crypto import sm3 as sm3_mod

    monkeypatch.setattr(sm3_mod, "_ENGINE", "gmssl")
    assert pbkdf2_hmac_sm3(pw, salt, iters, dklen).hex() == expect, src


def test_dklen_partial_block():
    """dklen 非整块（42B）时按 RFC 8018 截断。用 #4（42B/4096）对拍。"""
    out = pbkdf2_hmac_sm3(
        bytes.fromhex("5a30673349567272"), bytes.fromhex("84bbd18de5ec10ff"), 4096, 42
    )
    assert (
        out.hex()
        == "fdf1106ffa3b9277df853d26b339f52f35baec64eb571a663108869dd8a9a9853ce2a3af98420f104309"
    )


def test_iterations_must_be_positive():
    with pytest.raises(ValueError):
        pbkdf2_hmac_sm3(b"pw", b"salt", 0, 32)
