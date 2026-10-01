"""SN v2 批 2——追溯设备一致性核对节点测试。

- 解锁后的令状追溯：checkpoint_anchors 行 + SN₁ 派生公钥验签 → 设备一致/不一致
- 未解锁/无登记 SN → insufficient（诚实缺省）
- 旧版登记（信封无 SN）→ insufficient+reason
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.audit.device_check import _device_priv
from app.audit.models import Warrant
from app.audit.service import AuditDeps, AuditService
from app.crypto.sm2 import generate_keypair, pubkey_from_priv, sign_digest
from app.crypto.sm3 import sm3_bytes
from app.ra.models import Base, Credential
from app.telemetry.checkpoint import checkpoint_message
from app.telemetry.models import CheckpointAnchor

SN = "SN-AIRCRAFT-001"
MCH = "bb" * 32
AUTH_ID = 5


@pytest.fixture()
def svc_with_trace(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/trace.db")
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng, expire_on_commit=False)()

    # 登记凭证（信封 v3：含 SN₁ 明文段）
    envelope = b"u|110101199001011234|" + SN.encode() + b"|hdl"
    import datetime as _dt

    from app.ra.models import User

    s.add(User(id=1, username="snenv", pub_key_hex=generate_keypair()[1]))
    s.add(
        Credential(
            user_id=1,
            commitment_hex="11" * 32,
            master_cred_hash_hex=MCH,
            sn_hash_hex=MCH[:32],
            id_cipher=b"x",
            id_store_cipher=wrap(envelope),
            cert_level=3,
            class_id=1,
            expires_at=_dt.datetime(2099, 1, 1),
        )
    )
    # 已解锁令状（目标 authId=5）
    import datetime as _dt

    s.add(
        Warrant(
            warrant_hash_hex="cc" * 32,
            case_no="T-1",
            scope_hash_hex="22" * 32,
            legal_basis_hash_hex="33" * 32,
            target_auth_id=AUTH_ID,
            unlocked_ts=_dt.datetime(2026, 9, 23, 12, 0, 0),
            unlocked_master_cred_hash_hex=MCH,
        )
    )
    s.commit()
    deps = AuditDeps(
        anchor=type(
            "A",
            (),
            {
                "trace_auth": staticmethod(
                    lambda aid: {
                        "auth_record": {"status": 0, "proof_digest": "dd" * 32},
                        "checkpoints": [],
                        "events": [],
                    }
                ),
                "warrant_on_chain": staticmethod(lambda wh: True),
                "warrant_unlocked_on_chain": staticmethod(lambda wh: False),
                "call": staticmethod(lambda fn, args: None),
                "chain_fingerprint": staticmethod(lambda: "block=1"),
            },
        )(),
        ra_unlock=lambda wh, cred: {},
    )
    yield AuditService(s, deps), s
    s.close()


def wrap(plain: bytes) -> bytes:
    from app.authz.service import wrap_secret

    return wrap_secret(plain)


def _seed_checkpoint(s, sig_ok: bool, seq: int = 1) -> None:

    head = sm3_bytes(b"head")
    fence = bytes([1]) + (50).to_bytes(2, "big") + b"\x00"
    good_priv = _device_priv(SN)
    good_pub = pubkey_from_priv(good_priv)
    sig = (
        sign_digest(good_priv, sm3_bytes(checkpoint_message(AUTH_ID, seq, head, fence)))
        if sig_ok
        else "ff" * 64
    )
    s.add(
        CheckpointAnchor(
            auth_id=AUTH_ID,
            seq=seq,
            chain_head_hex=head.hex(),
            fence_state_hex=fence.hex(),
            device_sig_hex=sig,
            device_pub_hex=good_pub,
            tx_hash="0xt",
        )
    )
    s.commit()


def test_trace_device_check_match(svc_with_trace):
    svc, s = svc_with_trace
    _seed_checkpoint(s, sig_ok=True)
    out = svc.trace(warrant_hash_hex="cc" * 32)
    dc = out["chain_trace"]["device_check"]
    assert dc["verdict"] == "match" and dc["checked"] >= 1


def test_trace_device_check_mismatch(svc_with_trace):
    svc, s = svc_with_trace
    _seed_checkpoint(s, sig_ok=False)
    out = svc.trace(warrant_hash_hex="cc" * 32)
    assert out["chain_trace"]["device_check"]["verdict"] == "mismatch"
