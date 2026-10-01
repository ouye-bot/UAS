"""M_A 模块测试：报文构造+词序口径签验自洽+黄金向量钉定（B3 电路对拍单一事实源）。

M_A（框架 §5.1，与旧系统 pred_credential M′ 同构）：
  M_A = Z_A(ra)(32) ‖ x(id′·G)(32) ‖ C(32) ‖ pk′.x(32) ‖ pk′.y(32) ‖ exp_u BE(4) ‖ par(1)
  C = SM3(salt(16) ‖ id_number(18) ‖ cert_level(1) ‖ sn_h(16))   # 51B 单块
  sn_h = SM3(序列号)[0..16]
电路口径 e：SM3(M_A) 词序小端折叠（词 7..0 倒序拼接）→ sign_digest/verify_digest。
"""

import json
from pathlib import Path

from app.crypto.sm2 import generate_keypair, verify_digest
from app.crypto.sm3 import sm3_bytes
from app.ra.credential import (
    build_message,
    commitment_c,
    digest_e_bytes,
    sign_credential,
    sn_hash,
    verify_credential,
)

_VEC = Path(__file__).resolve().parents[2] / "zksvc" / "tests" / "auth_golden_vector.json"

# 固定样例（黄金向量源——与电路对拍共享；非生产凭据）
V_SALT = bytes.fromhex("00" * 16)
V_ID = b"11010119900307999X"  # 18B 形态样例（格式锚，非真实证件号）
V_CERT = 3
V_SN = b"UAS-SN-2026-0001"
V_EXP = 1900000000


def test_sn_hash_16b():
    assert len(sn_hash(V_SN)) == 16
    assert sn_hash(V_SN) == sm3_bytes(V_SN)[:16]


def test_commitment_c_55b_single_block():
    """C 布局 v3（B4-d1）：55B 恰满单块；class 居字节 20（词 5 MSB）。"""
    c = commitment_c(V_SALT, V_ID, V_CERT, V_SN, 1)
    assert len(c) == 32
    assert c == sm3_bytes(V_SALT + V_CERT.to_bytes(4, "big") + b"" + V_ID + sn_hash(V_SN))
    # class 改变 ⟹ C 改变（机型进承诺的因果锚）
    assert c != commitment_c(V_SALT, V_ID, V_CERT, V_SN, 0)


def test_commitment_c_input_validation():
    import pytest

    from app.ra.credential import CredentialError

    with pytest.raises(CredentialError):
        commitment_c(bytes(15), V_ID, V_CERT, V_SN)  # salt 长度
    with pytest.raises(CredentialError):
        commitment_c(V_SALT, b"123", V_CERT, V_SN)  # 身份号长度
    with pytest.raises(CredentialError):
        commitment_c(V_SALT, V_ID, 0, V_SN)  # 资质等级域
    with pytest.raises(CredentialError):
        commitment_c(V_SALT, V_ID, V_CERT, b"")  # 序列号空


def test_build_message_165b_layout():
    _, ra_pub = generate_keypair()
    _, holder_pub = generate_keypair()
    id_prime = sm3_bytes(b"id-prime-demo")
    msg = build_message(ra_pub, id_prime, V_SALT, V_ID, V_CERT, V_SN, holder_pub, V_EXP, 1)
    assert len(msg) == 165
    # 字段偏移锚：Z_A[0:32] x(id·G)[32:64] C[64:96] pk.x[96:128] pk.y[128:160] exp[160:164] par[164]
    assert msg[64:96] == commitment_c(V_SALT, V_ID, V_CERT, V_SN, 1)
    assert msg[96:128] == bytes.fromhex(holder_pub[:64])
    assert msg[128:160] == bytes.fromhex(holder_pub[64:])
    assert msg[160:164] == V_EXP.to_bytes(4, "big")
    assert msg[164] & 0x02  # par=0x02|lsb(y(id·G))


def test_word_order_reverse_is_involutive():
    import app.ra.credential as cred

    d = sm3_bytes(b"any-32b-digest-precision-probe")
    assert cred._reverse_words(cred._reverse_words(d)) == d
    msg = build_message(*_mk_args())  # 参数固定复用（每次 generate_keypair 会漂移）
    e = digest_e_bytes(msg)
    assert cred._reverse_words(e) == sm3_bytes(msg)


def _mk_args():
    _, ra_pub = generate_keypair()
    _, holder_pub = generate_keypair()
    return (
        ra_pub,
        sm3_bytes(b"id-prime-demo"),
        V_SALT,
        V_ID,
        V_CERT,
        V_SN,
        holder_pub,
        V_EXP,
    )


def test_sign_verify_circuit_word_order():
    ra_priv, ra_pub = generate_keypair()
    _, holder_pub = generate_keypair()
    msg = build_message(
        ra_pub, sm3_bytes(b"wordorder"), V_SALT, V_ID, V_CERT, V_SN, holder_pub, V_EXP
    )
    e = digest_e_bytes(msg)
    sig = sign_credential(ra_priv, msg)
    assert verify_credential(ra_pub, msg, sig) is True  # 同口径验签
    assert verify_digest(ra_pub, e, sig) is True  # 与裸摘要通道一致（电路口径同 e）
    assert verify_credential(ra_pub, msg + b"x", sig) is False
    _, other_pub = generate_keypair()
    assert verify_credential(other_pub, msg, sig) is False


def test_golden_vector_file_roundtrip():
    data = json.loads(_VEC.read_text())
    msg = bytes.fromhex(data["message_hex"])
    assert len(msg) == 165
    rebuilt = build_message(
        data["ra_pub_hex"],
        bytes.fromhex(data["id_prime_hex"]),
        bytes.fromhex(data["salt_hex"]),
        data["id_number"].encode(),
        data["cert_level"],
        data["sn"].encode(),
        data["holder_pub_hex"],
        data["exp_u"],
        data["class_id"],
    )
    assert rebuilt == msg
    assert digest_e_bytes(msg).hex() == data["e_bytes_hex"]
    assert verify_credential(data["ra_pub_hex"], msg, data["sig_hex"]) is True
