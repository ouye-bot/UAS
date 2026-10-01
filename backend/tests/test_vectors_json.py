"""向量单一事实源对拍：JSON 事实源 × Python 实现 全原语逐字节核对。

这是三语言对拍的 Python 面（Rust=zksvc/tests/sm3_vectors.rs，
TS=gcs/web/tests/*.test.ts）。JSON 结构被三语言共享——任何字段改动须三语言同批同步。
"""

import json
from pathlib import Path

import pytest

from app.crypto.hmac_sm3 import hmac_sm3
from app.crypto.kdf import pbkdf2_hmac_sm3
from app.crypto.sm2 import verify, verify_digest
from app.crypto.sm3 import sm3_bytes
from app.crypto.sm4 import SM4GCM, PureSM4GCM

_VEC = Path(__file__).resolve().parent.parent / "app" / "crypto" / "vectors"


def _load(name: str) -> dict:
    with open(_VEC / name, encoding="utf-8") as f:
        return json.load(f)


class TestSM3Official:
    def test_vectors_file_sm3_matches_implementation(self):
        data = _load("sm3_official.json")
        for v in data["vectors"] + data["extra_consistency"]:
            assert sm3_bytes(bytes.fromhex(v["msg_hex"])).hex() == v["digest_hex"], v["name"]

    def test_a1_anchor_literal(self):
        # 锚字面量双保险：JSON 与测试文件双处持有 A.1（防 JSON 被误改）
        assert (
            sm3_bytes(b"abc").hex()
            == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        )


class TestSM2Official:
    def test_verify_digest_five_tuple(self):
        data = _load("sm2_official.json")
        for v in data["verify_digest_vectors"]:
            ok = verify_digest(v["pub_hex"], bytes.fromhex(v["e_hex"]), v["sig_hex"])
            assert ok is True, v["name"]
            bad = "0" + v["sig_hex"][1:]
            ok_bad = verify_digest(v["pub_hex"], bytes.fromhex(v["e_hex"]), bad)
            assert ok_bad is False, v["name"]

    def test_ts_parity_fixture(self):
        fx = _load("sm2_official.json")["ts_parity_fixture"]
        msg = bytes.fromhex(fx["msg_hex"])
        assert msg == b"YZT-SM2-PARITY-VECTOR"  # hex 转写自检
        assert verify(fx["pub_hex"], msg, fx["sig_hex"]) is True
        assert verify(fx["pub_hex"], msg + b"x", fx["sig_hex"]) is False


class TestSM4Official:
    @pytest.mark.parametrize("eng", [SM4GCM, PureSM4GCM], ids=lambda e: e.__name__)
    def test_gcm_vectors_both_engines(self, eng):
        data = _load("sm4_official.json")
        for v in data["gcm_vectors"]:
            g = eng(bytes.fromhex(v["key_hex"]))
            ct, tag = g.encrypt(
                bytes.fromhex(v["iv_hex"]), bytes.fromhex(v["pt_hex"]), bytes.fromhex(v["aad_hex"])
            )
            assert ct.hex().upper() == v["ct_hex"], (eng.__name__, v["name"])
            assert tag.hex().upper() == v["tag_hex"], (eng.__name__, v["name"])


class TestHMACKdfSmoke:
    """HMAC/PBKDF2 向量在 test_crypto_hmac/kdf.py 内联持有（GmSSL 官方套件），
    此处仅 smoke 证明 JSON 事实源体系外另有独立内联锚（双保险分层）。"""

    def test_hmac_rfc2104_structure(self):
        tag = hmac_sm3(b"k" * 64, b"m")
        assert len(tag) == 32

    def test_pbkdf2_rfc7914_1(self):
        assert pbkdf2_hmac_sm3(b"passwd", b"salt", 1, 64).hex().startswith("30530b86537c85ea")
