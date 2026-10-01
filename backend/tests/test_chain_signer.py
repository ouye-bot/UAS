"""TxSigner 测试：国密交易签名（v=公钥、摘要=SM3(rlp)（GM 链口径）、裸摘要签名）。

对拍三层验证之第一、二层：
① 自研裸摘要签名 → gmssl CryptSM2.verify 直接过（e=digest 无 ZA，节点
   sm2Sign/SM2Signature.cpp 对源；Z 路径仅用于消息级签名，混用即假绿）；
② digest = SM3(rlp(十字段))（GM 链 crypto::Hash 分派为 sm3，CryptoInterface.h
   对源锚定——2026-09-01 真链两轮实证：keccak 摘要被 InvalidSignature 拒收）；
③ 真链 sendRawTransaction 接受 = 第三层，见 tests/test_chain_integration.py。
"""

import pytest
from gmssl.sm2 import CryptSM2

from app.chain.rlp import rlp_encode_fields
from app.chain.signer import TxSigner, UnsignedTx, unsigned_rlp
from app.crypto.sm2 import sign as sm2_msg_sign
from app.crypto.sm2 import sign_digest, verify_digest
from app.crypto.sm3 import sm3_bytes


def _digest() -> bytes:
    return sm3_bytes(unsigned_rlp(_unsigned()))


# 已知测试私钥（非生产）：全仓统一测试账户，生产密钥经 KMS 托管仪式生成（设计 §6）
PRIV = "39f3ee4b8ad2f4a3f1f6cba5a6e5a4d9c3b2a1907e6d5c4b3a29180f7e6d5c4b"


def _unsigned() -> UnsignedTx:
    return UnsignedTx(
        randomid=123456789,
        gas_price=30000000,
        gas_limit=30000000,
        block_limit=500,
        to=bytes.fromhex("11" * 20),
        value=0,
        data=bytes.fromhex("dead"),
        fisco_chain_id=1,
        group_id=1,
        extra_data=b"",
    )


def test_unsigned_rlp_field_shape():
    tx = _unsigned()
    manual = rlp_encode_fields(
        [
            tx.randomid,
            tx.gas_price,
            tx.gas_limit,
            tx.block_limit,
            tx.to,
            tx.value,
            tx.data,
            tx.fisco_chain_id,
            tx.group_id,
            tx.extra_data,
        ]
    )
    assert unsigned_rlp(tx) == manual


def test_v_is_full_public_key():
    signer = TxSigner(PRIV)
    v, _r, _s = signer.sign_vrs(_digest())
    assert v == int(signer.public_key_hex, 16)
    assert len(signer.public_key_hex) == 128


def test_signature_verifies_with_gmssl_raw_digest():
    """第一层对拍：自研裸摘要签名可被 python-sdk 同款 gmssl CryptSM2.verify 验签
    （节点口径：e=digest 直接入方程、无 ZA——Signer_GM.sign → CryptSM2.sign）。"""
    signer = TxSigner(PRIV)
    digest = _digest()
    v, r, s = signer.sign_vrs(digest)
    rs = f"{r:064x}{s:064x}"
    crypt = CryptSM2(public_key=signer.public_key_hex, private_key=PRIV)
    assert crypt.verify(rs, digest)
    # 篡改摘要必须失败
    evil = bytes([digest[0] ^ 1]) + digest[1:]
    assert not crypt.verify(rs, evil)
    # 与自实现 verify_digest 互为 differential（同口径双实现）
    assert verify_digest(signer.public_key_hex, digest, rs)
    assert v > 0


def test_raw_digest_and_z_path_are_distinct_primitives():
    """裸摘要与 Z 路径是两个原语：Z 路径签名对裸摘要验签必败（差一层 SM3(ZA‖·)）。

    2026-09-01 真链 InvalidSignature 的单元级复现：TxSigner 若误用 Z 路径
    sign()，本测试即红——防止两条通路将来被混用回退。
    """
    signer = TxSigner(PRIV)
    digest = _digest()
    z_sig = sm2_msg_sign(PRIV, digest)  # 把 digest 当"消息"走 Z 路径
    assert not verify_digest(signer.public_key_hex, digest, z_sig)
    raw_sig = sign_digest(PRIV, digest)  # 裸摘要
    assert verify_digest(signer.public_key_hex, digest, raw_sig)


def test_raw_rlp_shape():
    signer = TxSigner(PRIV)
    raw = signer.sign_tx(_unsigned())
    assert raw[0] in (0xF8, 0xF9)  # 十四字段列表体 >55B
    assert len(raw) > 160  # 十字段 ~70B + v(公钥≤65B) + r/s 各 ≤33B


def test_address_format():
    signer = TxSigner(PRIV)
    assert len(signer.address) == 42 and signer.address.startswith("0x")


def test_same_unsigned_diff_raw():
    """同 tx 两次签名 raw 不同（k 随机 secrets）但 unsigned_rlp 确定相同。"""
    signer = TxSigner(PRIV)
    assert unsigned_rlp(_unsigned()) == unsigned_rlp(_unsigned())
    assert signer.sign_tx(_unsigned()) != signer.sign_tx(_unsigned())


def test_to_must_be_20b_or_empty():
    with pytest.raises(ValueError):
        UnsignedTx(
            randomid=1,
            gas_price=1,
            gas_limit=1,
            block_limit=1,
            to=b"\x11" * 19,
            value=0,
            data=b"",
            fisco_chain_id=1,
            group_id=1,
            extra_data=b"",
        )
