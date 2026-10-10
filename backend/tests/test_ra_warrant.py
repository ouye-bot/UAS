"""B4-T6 测试（A3 通道②）：RA 域钥 wrap 实名映射+令状协作解锁。

- register 落库双通道（通道① ECIES 用户自持+通道② RA 域钥 wrap）
- 有令状在案 ⟹ 解锁成功（返回实名映射+解锁留痕）
- 无令状/错令状 ⟹ 拒绝（流程双控第一关——负例一等公民）
- wrap 完整性：GCM 认证（篡改负例）
"""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz.service import unwrap_any
from app.crypto.sm2 import generate_keypair
from app.kms import ra_signing_keypair
from app.ra.models import Base, Credential
from app.ra.service import ChainAnchor, RaDeps, RaError, RaService


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    from app.audit.models import Base as AuditBase  # collab_issued（④站第③关判定源）

    AuditBase.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


_USER_PK = generate_keypair()[1]


def _register_ok(svc, username="u1"):
    return svc.register(
        username=username,
        id_number="110101199001011234",
        cert_level=3,
        sn="FZ-SN-W1",
        user_pub_hex=_USER_PK,
    )


def _svc(session, warrants: set[bytes] | None = None):
    wset = warrants or set()
    anchor = ChainAnchor(
        call=lambda fn, args: None,
        warrant_on_chain=lambda wh: wh in wset,
    )
    _priv, pub = ra_signing_keypair()

    def _collab_approved(request_sha: str) -> bool:
        """双控批文在案（④站第③关）——真模型真查本 session（v5 门限适配）。"""
        from sqlalchemy import select

        from app.audit.models import CollabIssued

        row = session.scalar(select(CollabIssued).limit(1))
        return row is not None

    return RaService(
        session,
        RaDeps(
            ra_priv_hex=_priv,
            ra_pub_hex=pub,
            anchor=anchor,
            threshold_hooks={
                "request_registered": lambda sha, wh, ch: True,  # unlock 内已自动登记
                "warrant_on_chain": lambda wh_hex: bytes.fromhex(wh_hex) in wset,
                "collab_approved": _collab_approved,
            },
        ),
    )


def test_register_dual_channel_wrap(session):
    svc = _svc(session)
    out = _register_ok(svc)
    cred = session.query(Credential).one()
    assert cred.id_store_cipher is not None and len(cred.id_store_cipher) > 28
    # wrap 完整性（④站 v5 门限信封）：外层 0x05 分派+门限解 →内层 v3 四段不变
    wh0 = secrets.token_bytes(32)
    plain = unwrap_any(
        bytes(cred.id_store_cipher),
        share_hooks={
            "request_registered": lambda sha, w, c: True,
            "warrant_on_chain": lambda w_hex: bytes.fromhex(w_hex) == wh0,
            "collab_approved": lambda sha: True,
        },
        unlock_ctx={
            "warrant_hash_hex": wh0.hex(),
            "cred_hash_hex": out["master_cred_hash_hex"],
            "request_sha256_hex": "cd" * 32,
        },
    )
    assert plain[:1] == b"", "内层信封版本字节"
    username, id_number, sn_b, handle = plain[1:].split(b"|", 3)
    assert username == b"u1" and id_number == b"110101199001011234"
    assert sn_b == b"FZ-SN-W1"
    assert handle.hex() == out["master_cred_hash_hex"]


def test_warrant_unlock_success(session):
    svc = _svc(session)
    out = _register_ok(svc)
    wh = secrets.token_bytes(32)
    # ④站第③关前提：双控出函行（真模型真行——v5 门限解锁的批文语义）
    from datetime import datetime as _dt

    from app.audit.models import CollabIssued

    session.add(
        CollabIssued(
            warrant_hash_hex=wh.hex(),
            master_cred_hash_hex=out["master_cred_hash_hex"],
            code_fingerprint_hex="ab" * 8,
            issued_at=_dt.utcnow(),
        )
    )
    session.commit()
    svc2 = _svc(session, warrants={wh})
    res = svc2.warrant_unlock(
        warrant_hash_hex=wh.hex(), master_cred_hash_hex=out["master_cred_hash_hex"]
    )
    assert res["username"] == "u1"
    assert res["id_number"] == "110101199001011234"


def test_warrant_unlock_without_warrant_rejected(session):
    svc = _svc(session)  # 链上无任何令状
    out = _register_ok(svc)
    with pytest.raises(RaError) as ei:
        svc.warrant_unlock(
            warrant_hash_hex=secrets.token_bytes(32).hex(),
            master_cred_hash_hex=out["master_cred_hash_hex"],
        )
    assert ei.value.code == "warrant_not_found"


def test_warrant_unlock_tampered_cipher_rejected(session):
    svc = _svc(session)
    out = _register_ok(svc)
    cred = session.query(Credential).one()
    blob = bytearray(bytes(cred.id_store_cipher))
    blob[-1] ^= 0x01  # GCM tag 篡改
    cred.id_store_cipher = bytes(blob)
    session.commit()
    wh = secrets.token_bytes(32)
    svc2 = _svc(session, warrants={wh})
    with pytest.raises(RaError) as ei:
        svc2.warrant_unlock(
            warrant_hash_hex=wh.hex(), master_cred_hash_hex=out["master_cred_hash_hex"]
        )
    assert ei.value.code == "unwrap_failed"
