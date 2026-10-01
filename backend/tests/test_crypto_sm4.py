"""SM4-GCM 测试。

向量源（官方测试套件，本会话自 GmSSL C 库 tests/ 读入）：
- GB/T 32907-2016 附录 A（SM4 核心标准向量）：sm4_ecbtest.c:53-67
- RFC 8998 A.1（SM4-GCM 64B 全字段）：sm4_gcmtest.c test_sm4_gcm
- GB/T 36624-2018 C.5 例 1/例 2：sm4_gcmtest.c test_sm4_gcm_gbt36624_1/2
"""

import os

import pytest

from app.crypto.sm4 import SM4GCM, PureSM4GCM, SM4GCMError, engine_name

# --- GB/T 32907-2016 附录 A：SM4 核心标准向量 ---
GBT_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
GBT_PT = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
GBT_CT = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")

# --- RFC 8998 A.1 ---
RFC_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
RFC_IV = bytes.fromhex("00001234567800000000ABCD")
RFC_AAD = bytes.fromhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
RFC_PT = bytes.fromhex(
    "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
    "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
)
RFC_CT = bytes.fromhex(
    "17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735"
    "D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D"
)
RFC_TAG = bytes.fromhex("83DE3541E4C2B58177E065A9BF7B62EC")

# --- GB/T 36624-2018 C.5 例 1（空明文/空 AAD） ---
GBT36624_KEY = bytes(16)
GBT36624_IV = bytes(12)
GBT36624_1_TAG = bytes.fromhex("232F0CFE308B49EA6FC88229B5DC858D")
# --- 例 2（16 字节零明文） ---
GBT36624_2_PT = bytes(16)
GBT36624_2_CT = bytes.fromhex("7DE2AA7F1110188218063BE1BFEB6D89")
GBT36624_2_TAG = bytes.fromhex("B851B5F39493752BE508F1BB4482C557")


def _engines() -> list[type]:
    """双引擎矩阵：选通引擎 + 纯参考引擎（官方向量在两者上都必须逐字节命中）。"""
    return [SM4GCM, PureSM4GCM]


class TestEngineSelection:
    def test_engine_name_introspection(self):
        assert engine_name() in {"openssl", "pure"}

    def test_selected_engine_official_vectors(self):
        """选通引擎（默认 openssl，锚向量验证失败自动回落 pure）必须命中官方向量。"""
        g = SM4GCM(RFC_KEY)
        ct, tag = g.encrypt(RFC_IV, RFC_PT, RFC_AAD)
        assert (ct, tag) == (RFC_CT, RFC_TAG)

    def test_cross_engine_byte_agreement(self):
        """跨引擎一致性（最强正确性锚）：两实现对同一输入产出逐字节相同密文+tag。"""
        import os

        key, nonce = os.urandom(16), os.urandom(12)
        pt, aad = os.urandom(4096), os.urandom(24)
        results = {e.__name__: e(key).encrypt(nonce, pt, aad) for e in _engines()}
        assert len(set(results.values())) == 1, f"跨引擎不一致: {results.keys()}"

    def test_both_engines_reject_tampered_tag(self):
        bad = bytes([RFC_TAG[0] ^ 0x01]) + RFC_TAG[1:]
        for e in _engines():
            with pytest.raises(SM4GCMError):
                e(RFC_KEY).decrypt(RFC_IV, RFC_CT, bad, RFC_AAD)


class TestRawBlock:
    def test_gbt32907_standard_vector(self):
        """裸块原语（纯参考引擎面）必须精确命中 GB/T 32907 标准向量。"""
        g = PureSM4GCM(GBT_KEY)
        assert g._raw_block(GBT_PT) == GBT_CT

    def test_raw_block_inverse(self):
        g = PureSM4GCM(GBT_KEY)
        assert g._raw_block_dec(GBT_CT) == GBT_PT


class TestGCMOfficialVectors:
    """三组官方向量双引擎逐字节命中（选通引擎 + 纯参考引擎）。"""

    @pytest.mark.parametrize("eng", _engines(), ids=lambda e: e.__name__)
    def test_rfc8998_a1(self, eng):
        g = eng(RFC_KEY)
        ct, tag = g.encrypt(RFC_IV, RFC_PT, RFC_AAD)
        assert ct == RFC_CT and tag == RFC_TAG
        assert g.decrypt(RFC_IV, RFC_CT, RFC_TAG, RFC_AAD) == RFC_PT

    @pytest.mark.parametrize("eng", _engines(), ids=lambda e: e.__name__)
    def test_gbt36624_c5_case1_empty(self, eng):
        g = eng(GBT36624_KEY)
        ct, tag = g.encrypt(GBT36624_IV, b"", b"")
        assert ct == b"" and tag == GBT36624_1_TAG

    @pytest.mark.parametrize("eng", _engines(), ids=lambda e: e.__name__)
    def test_gbt36624_c5_case2(self, eng):
        g = eng(GBT36624_KEY)
        ct, tag = g.encrypt(GBT36624_IV, GBT36624_2_PT, b"")
        assert ct == GBT36624_2_CT and tag == GBT36624_2_TAG


class TestGCMNegative:
    @pytest.mark.parametrize("eng", _engines(), ids=lambda e: e.__name__)
    def test_tampered_tag_rejected(self, eng):
        g = eng(RFC_KEY)
        bad = bytes([RFC_TAG[0] ^ 0x01]) + RFC_TAG[1:]
        with pytest.raises(SM4GCMError):
            g.decrypt(RFC_IV, RFC_CT, bad, RFC_AAD)

    @pytest.mark.parametrize("eng", _engines(), ids=lambda e: e.__name__)
    def test_tampered_ciphertext_rejected(self, eng):
        g = eng(RFC_KEY)
        bad = bytes([RFC_CT[0] ^ 0x01]) + RFC_CT[1:]
        with pytest.raises(SM4GCMError):
            g.decrypt(RFC_IV, bad, RFC_TAG, RFC_AAD)

    @pytest.mark.parametrize("eng", _engines(), ids=lambda e: e.__name__)
    def test_tampered_aad_rejected(self, eng):
        g = eng(RFC_KEY)
        bad = bytes([RFC_AAD[0] ^ 0x01]) + RFC_AAD[1:]
        with pytest.raises(SM4GCMError):
            g.decrypt(RFC_IV, RFC_CT, RFC_TAG, bad)

    @pytest.mark.parametrize("eng", _engines(), ids=lambda e: e.__name__)
    def test_wrong_nonce_rejected(self, eng):
        g = eng(RFC_KEY)
        with pytest.raises(SM4GCMError):
            g.decrypt(bytes(12), RFC_CT, RFC_TAG, RFC_AAD)


class TestGCMProperties:
    def test_randomized_roundtrip(self):
        for _ in range(20):
            g = SM4GCM(os.urandom(16))
            pt, aad = os.urandom(os.urandom(1)[0] * 3), os.urandom(os.urandom(1)[0])
            nonce = os.urandom(12)
            ct, tag = g.encrypt(nonce, pt, aad)
            assert g.decrypt(nonce, ct, tag, aad) == pt

    def test_key_length_enforced(self):
        with pytest.raises(ValueError):
            SM4GCM(b"short")

    def test_nonce_length_enforced(self):
        g = SM4GCM(GBT_KEY)
        with pytest.raises(ValueError):
            g.encrypt(b"short-nonce", b"x")
