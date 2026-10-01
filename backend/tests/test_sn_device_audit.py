"""SN v2 实施——设备交叉审计测试（红→绿）。

- 设备核对核心：SN₁ 派生预期设备公钥 vs 检查点签名——match/mismatch/insufficient
- 锚定持久化：anchor_checkpoint 落 CheckpointAnchor 行（device_sig/fence/pub）
- 通道②信封含 SN₁：register→unlock 回传 sn；旧 3 段信封兼容
"""

from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.authz.models import AuthRecord
from app.crypto.sm2 import generate_keypair, pubkey_from_priv, sign_digest
from app.crypto.sm3 import sm3_bytes
from app.kms import _derive_priv
from app.ra.models import Base
from app.telemetry.checkpoint import checkpoint_message
from app.telemetry.models import CheckpointAnchor

SN = "SN-AIRCRAFT-001"


def _device_priv(sn: str) -> str:
    return _derive_priv(b"FZ-KMS|device|" + sn.encode())


def _expected_pub(sn: str) -> str:
    return pubkey_from_priv(_device_priv(sn))


def _fence() -> bytes:
    return bytes([1]) + (50).to_bytes(2, "big") + b"\x00"


# ---- 设备核对核心（纯函数，app/audit/device_check.device_consistency）----


def test_device_check_match():
    from app.audit.device_check import device_consistency

    head = sm3_bytes(b"h1")
    sig = sign_digest(_device_priv(SN), sm3_bytes(checkpoint_message(7, 1, head, _fence())))
    rows = [
        {
            "auth_id": 7,
            "seq": 1,
            "chain_head_hex": head.hex(),
            "fence_state_hex": _fence().hex(),
            "device_sig_hex": sig,
            "device_pub_hex": _expected_pub(SN),
        }
    ]
    out = device_consistency(rows, registered_sn=SN)
    assert out["verdict"] == "match" and out["checked"] == 1


def test_device_check_mismatch():
    """借机飞行：检查点由其他设备钥签署 → mismatch（违规升级）。"""
    from app.audit.device_check import device_consistency
    from app.crypto.sm2 import pubkey_from_priv

    other_sk = generate_keypair()[0]
    other_pub = pubkey_from_priv(other_sk)
    head = sm3_bytes(b"h1")
    sig = sign_digest(other_sk, sm3_bytes(checkpoint_message(7, 1, head, _fence())))
    rows = [
        {
            "auth_id": 7,
            "seq": 1,
            "chain_head_hex": head.hex(),
            "fence_state_hex": _fence().hex(),
            "device_sig_hex": sig,
            "device_pub_hex": other_pub,
        }
    ]
    out = device_consistency(rows, registered_sn=SN)
    assert out["verdict"] == "mismatch"


def test_device_check_insufficient():
    from app.audit.device_check import device_consistency

    out = device_consistency([], registered_sn=SN)
    assert out["verdict"] == "insufficient" and out["checked"] == 0


# ---- 锚定持久化（checkpoint_anchors 表）----


def test_anchor_persists_checkpoint_row(tmp_path):
    from app.telemetry.service import anchor_checkpoint

    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    session = sessionmaker(bind=eng)()
    session.add(
        AuthRecord(
            auth_id=5,
            application_id=1,
            token_hash_hex="00" * 32,
            proof_digest_hex="11" * 32,
            verdict_path="x",
            tx_hash="t",
        )
    )
    session.commit()

    class Deps:
        def anchor_on_chain(self, aid, seq, head, sig):
            return "0xfake"

        def auth_status(self, session, aid):
            return 0

    sk, pub = generate_keypair()
    head = sm3_bytes(b"hh")
    sig = sign_digest(sk, sm3_bytes(checkpoint_message(5, 1, head, _fence())))
    out = anchor_checkpoint(
        Deps(),
        session,
        auth_id=5,
        seq=1,
        chain_head_hex=head.hex(),
        fence_state_hex=_fence().hex(),
        sig_hex=sig,
        device_pub_hex=pub,
    )
    assert out["tx"] == "0xfake"
    row = session.scalars(select(CheckpointAnchor)).first()
    assert row is not None and row.auth_id == 5 and row.seq == 1
    assert row.device_sig_hex == sig and row.fence_state_hex == _fence().hex()
    assert row.device_pub_hex == pub


# ---- 通道②信封含 SN₁（register 存 / unlock 解出）----


def _ra_with_sn_envelope(tmp_path):
    from app.kms import ra_signing_keypair
    from app.ra.router import _FakeChain
    from app.ra.service import ChainAnchor, RaDeps, RaService

    eng = create_engine(f"sqlite:///{tmp_path}/env.db")
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng, expire_on_commit=False)()
    priv, pub = ra_signing_keypair()
    ra = RaService(
        s, RaDeps(ra_priv_hex=priv, ra_pub_hex=pub, anchor=ChainAnchor(call=_FakeChain()))
    )
    holder_pk = generate_keypair()[1]
    reg = ra.register(
        username="snenv",
        id_number="110101199001011234",
        cert_level=3,
        sn=SN,
        user_pub_hex=holder_pk,
        class_id=1,
    )
    ra._d.anchor.warrant_on_chain = lambda wh: True
    return ra, s, reg["master_cred_hash_hex"]


def test_envelope_stores_sn_and_unlock_returns_it(tmp_path):
    """register 信封含 SN₁ 明文段 → warrant_unlock 解出回传 sn。"""
    ra, s, mch = _ra_with_sn_envelope(tmp_path)
    out = ra.warrant_unlock(warrant_hash_hex="ab" * 32, master_cred_hash_hex=mch)
    assert out.get("sn") == SN, f"解锁未回传 SN₁: {out}"


def test_legacy_envelope_fallback(tmp_path):
    """旧 3 段信封（无 SN）兼容：解封不炸，sn 缺省为空。"""
    from app.authz.service import unwrap_secret, wrap_secret
    from app.ra.service import _open_store_envelope

    legacy_plain = b"legacy-u|110101199001011234|\xab" * 1
    legacy_plain = b"legacy-u|110101199001011234|\xab\x01\x02"
    sealed = wrap_secret(legacy_plain)
    plain = unwrap_secret(sealed)
    d = _open_store_envelope(plain)
    assert d["username"] == "legacy-u" and d["sn"] == ""
    del sealed


def test_store_envelope_malformed_rejected():
    """GCM 已认证但形态不合规（段数不对）→ 拒析（不静默吞）。"""
    import pytest as _pytest

    from app.ra.service import _open_store_envelope

    with _pytest.raises(ValueError):
        _open_store_envelope(b"only-one-segment")


def test_store_envelope_version_byte_literal_is_explicit_escape():
    """源码卫生守卫（2026-09-28 深检教训）：版本字节字面量必须显式 b"\x01"
    转义形态，禁止原始 0x01 控制字节嵌源码——原始字节会被文本工具渲染成
    空串（两席"sn 恒空"误诊根源）且易被编辑器/linter 静默清理。"""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app" / "ra" / "service.py").read_bytes()
    assert src.count(b'b"\x01"') == 0, "ra/service.py 存在原始 0x01 字面量——改为显式转义"


def test_kms_env_wrap_key_domain_separated(monkeypatch):
    """KMS 强化档域分离（深检 C-P2 根修正例）：FZ_WRAP_KEY 设定下不同 label
    派生不同钥（此前 env 主钥直返=实名映射钥与协作函钥同钥）。"""
    from app.kms import kms_domain_key

    monkeypatch.setenv("FZ_WRAP_KEY", "ab" * 16)
    k1 = kms_domain_key(b"label-one")
    k2 = kms_domain_key(b"label-two")
    assert k1 != k2 and len(k1) == 16 and len(k2) == 16
    assert k1 == kms_domain_key(b"label-one")  # 确定性
