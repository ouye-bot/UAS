"""1.4 provider 抽象层单测：分派 fail-closed/软件档影子对拍等价/HSM 骨架
零冒充不可达/production 拒启语义不放松。

等价判据（红线「逐字节零漂移」的准确形态）：
- 确定性原语（SM4-GCM 同 key/nonce/pt/aad）：provider 与现状实现**逐字节**
  相等（ct/tag）；
- 含随机 k 的 SM2 签名/ECIES：逐字节相同不成立（每次签名/加密随机化）——
  等价=**互验互换**（provider 签→现状验签过；现状签→provider 验签过；
  现状加密→provider 解密回明文；provider 加密→现状解密回明文）；
- CSPRNG：类型/长度/非重复（分布性不属对拍面）。
"""

from __future__ import annotations

import pytest

from app.crypto import provider as prov
from app.crypto.sm2 import decrypt as sm2_decrypt
from app.crypto.sm2 import encrypt as sm2_encrypt
from app.crypto.sm2 import generate_keypair
from app.crypto.sm2 import sign as sm2_sign
from app.crypto.sm2 import verify as sm2_verify
from app.crypto.sm4 import SM4GCM
from app.kms import assert_no_demo_keys_in_production


@pytest.fixture()
def software():
    return prov.get_provider()


# ---------------------------------------------------------------- 分派


def test_dispatch_defaults_to_software(monkeypatch):
    monkeypatch.delenv("FZ_CRYPTO_PROVIDER", raising=False)
    p = prov.get_provider()
    assert p.name == "software"
    assert isinstance(p, prov.SoftwareCryptoProvider)


def test_dispatch_explicit_software(monkeypatch):
    monkeypatch.setenv("FZ_CRYPTO_PROVIDER", "software")
    assert prov.get_provider().name == "software"


def test_dispatch_unknown_name_rejected(monkeypatch):
    monkeypatch.setenv("FZ_CRYPTO_PROVIDER", "tpm")
    with pytest.raises(RuntimeError, match="fail-closed|未知"):
        prov.get_provider()


# ---------------------------------------------------------------- ③ HSM 零冒充


def test_hsm_unconfigured_unreachable(monkeypatch):
    """显式选 hsm 但未配置 PKCS#11 模块→分派拒（骨架不可达——零替身路径）。"""
    monkeypatch.setenv("FZ_CRYPTO_PROVIDER", "hsm")
    monkeypatch.delenv("FZ_HSM_PKCS11_MODULE", raising=False)
    with pytest.raises(prov.HsmNotConfigured):
        prov.get_provider()


def test_hsm_configured_skeleton_raises_not_implents(monkeypatch):
    """配置在案→可构造骨架，但每原语显式 HsmNotImplemented（零冒充——绝不
    返回假数据）。"""
    monkeypatch.setenv("FZ_CRYPTO_PROVIDER", "hsm")
    monkeypatch.setenv("FZ_HSM_PKCS11_MODULE", "/usr/lib/softhsm.so")
    p = prov.get_provider()
    assert p.name == "hsm"
    with pytest.raises(prov.HsmNotImplemented):
        p.sign_sm2("aa" * 32, b"m")
    with pytest.raises(prov.HsmNotImplemented):
        p.ecies_decrypt("aa" * 32, b"ct")
    with pytest.raises(prov.HsmNotImplemented):
        p.seal_sm4_gcm(b"k" * 16, b"n" * 12, b"pt", b"aad")
    with pytest.raises(prov.HsmNotImplemented):
        p.random_bytes(16)


# ---------------------------------------------------------------- ② 影子对拍


def test_software_sign_cross_verify(software):
    """SM2 签名互验互换（随机 k——逐字节对拍不适用，等价=双引擎互验）。"""
    sk, pk = generate_keypair()
    msg = b"provider-shadow-sign"
    sig_p = software.sign_sm2(sk, msg)
    assert sm2_verify(pk, msg, sig_p)  # provider 签→现状验
    sig_ref = sm2_sign(sk, msg)
    assert software.verify_sm2(pk, msg, sig_ref)  # 现状签→provider 验
    assert sm2_verify(pk, msg, sig_ref)


def test_software_ecies_cross_decrypt(software):
    """ECIES 互解互换（随机 k——等价=双引擎互解回同一明文）。"""
    sk, pk = generate_keypair()
    pt = b"provider-shadow-ecies"
    ct_ref = sm2_encrypt(pk, pt)
    assert software.ecies_decrypt(sk, ct_ref) == pt  # 现状加密→provider 解
    ct_p = software.ecies_encrypt(pk, pt)
    assert sm2_decrypt(sk, ct_p) == pt  # provider 加密→现状解


def test_software_seal_bytewise_identical(software):
    """SM4-GCM 确定性原语：同 key/nonce/pt/aad→provider 与现状 **ct/tag 逐
    字节相等**（零漂移直接判据）+open 互换+篡改拒。"""
    key = bytes(range(16))
    nonce = bytes(range(12))
    pt = b"seal-bytewise-plaintext"
    aad = b"FZ-PROVIDER-AAD"
    ct_ref, tag_ref = SM4GCM(key).encrypt(nonce, pt, aad)
    ct_p, tag_p = software.seal_sm4_gcm(key, nonce, pt, aad)
    assert (ct_p, tag_p) == (ct_ref, tag_ref)  # 逐字节零漂移
    assert software.open_sm4_gcm(key, nonce, ct_ref, tag_ref, aad) == pt
    assert SM4GCM(key).decrypt(nonce, ct_p, tag_p, aad) == pt
    with pytest.raises(Exception):  # noqa: B017 —— 篡改 ct=认证标签拒
        software.open_sm4_gcm(key, nonce, b"x" + ct_p[1:], tag_p, aad)


def test_software_random_bytes(software):
    a = software.random_bytes(32)
    b = software.random_bytes(32)
    assert isinstance(a, bytes) and len(a) == 32
    assert a != b  # CSPRNG 非重复
    assert software.random_bytes(0) == b""


def test_provider_satisfies_protocol(software):
    """软件档实现满足 CryptoProvider 协议（runtime_checkable 结构判定）。"""
    assert isinstance(software, prov.CryptoProvider)


# ---------------------------------------------------------------- 红线


def test_production_demo_key_gate_untouched(monkeypatch):
    """provider 引入不放松 KMS 拒启语义：production 档缺 FZ_*_SK 仍拒启
    （assert_no_demo_keys_in_production 原样）。"""
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    monkeypatch.delenv("FZ_RA_SK", raising=False)
    monkeypatch.delenv("FZ_WRAP_KEY", raising=False)
    with pytest.raises(RuntimeError, match="拒绝以演示派生钥启动"):
        assert_no_demo_keys_in_production()
    # 分派与拒启解耦：production 档 provider 分派仍按 FZ_CRYPTO_PROVIDER 工作
    monkeypatch.delenv("FZ_CRYPTO_PROVIDER", raising=False)
    assert prov.get_provider().name == "software"
