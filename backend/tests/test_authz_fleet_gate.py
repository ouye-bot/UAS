"""3.1 段②受理门按 credKind 分派校验路径（先红后绿钉面）。

分派语义（任务书②原文）：个人=现行单链语义零变化（零新增链读零新增校验）；
机队=org 域链+设备序号绑定——机队路径加链面 kind 对拍（IdentityRegistry
getCred.credKind==2，DB/链漂移 fail-closed）+归属域结构校验。实例面 26 项
逐位同构（cert_level 槽=机构运营资质/sn 槽=设备 SN——server_sn_hash_hex
同构复用，⑥代 SN 绑定工艺）。AuthzDeps.chain_cred_kind：真链注入 getCred
读数；None=无链面跳过（fake/CI——与 chain_pin 渐进可用同范式）。
"""

from __future__ import annotations

import json as _json
import os as _os
import secrets
import tempfile
import time as _time_mod

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz import service
from app.authz.policy import POLICY_VERSION, get_rule
from app.authz.service import (
    _fe_be32_hex_from_bytes32,
    _fe_be32_hex_from_digest,
    _fe_be32_hex_from_u64,
    binding_challenge,
)
from app.crypto.sm3 import sm3_bytes
from app.ra.models import Base, Credential
from app.ra.service import ChainAnchor, RaDeps, RaService

_NOW = int(_time_mod.time())
DEV_SN = "FZ-SN-FLEET-GATE-01"
DEV_NO = "FZ-DEV-GATE-0000A1"  # 18 字符（登记号形态校验）


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng, expire_on_commit=False)()


class KindDeps(service.AuthzDeps):
    """链面替身+chain_cred_kind 注入与调用计数（个人零链读断言的数据源）。"""

    def __init__(self, onchain_kind: int | None):
        super().__init__()
        self.chain_nonce_used = lambda _n: False
        self.chain_rev_root = lambda: (1, "00" * 32)
        self.pin_fingerprint = lambda: "SM3(test|pin)"
        self.kind_calls = 0
        self._onchain_kind = onchain_kind
        self.chain_cred_kind = self._counted_kind

    def _counted_kind(self, handle: bytes) -> int | None:
        self.kind_calls += 1
        return self._onchain_kind


def _kms_svc(session) -> RaService:
    """RA 钥=KMS 权威（受理门验签 ra_pub_hex_of 同源——真实仪式零替身）。"""
    from app.kms import ra_signing_keypair

    priv, pub = ra_signing_keypair()
    return RaService(
        session,
        RaDeps(ra_priv_hex=priv, ra_pub_hex=pub, anchor=ChainAnchor(call=lambda f, a: None)),
    )


def _fleet_credential(session, class_id: int = 1):
    """真实机队仪式：登记设备（kind=2）+签发子凭证——返回受理申请 kwargs。"""
    svc = _kms_svc(session)
    dev = svc.register_fleet_devices(
        operator_org_id="org-a",
        devices=[{"device_no": DEV_NO, "sn": DEV_SN, "cert_level": 3, "class_id": class_id}],
    )["devices"][0]
    from app.crypto.sm2 import generate_keypair

    holder_sk, holder_pk = generate_keypair()
    sub = svc.issue_fleet_sub_credentials(
        operator_org_id="org-a",
        items=[
            {
                "master_cred_hash_hex": dev["master_cred_hash_hex"],
                "salt_hex": dev["salt_hex"],
                "holder_pub_hex": holder_pk,
            }
        ],
    )["items"][0]
    return dev, sub, holder_pk


def _case(plan_hash_hex: str, nonce_hex: str, serial: bytes, class_id: int) -> dict:
    d = _os.path.join(tempfile.mkdtemp(prefix="fzfleetcase"), plan_hash_hex[:16])
    _os.makedirs(d, exist_ok=True)
    inst = ["0" * 64] * 26
    inst[25] = _fe_be32_hex_from_bytes32(sm3_bytes(serial))
    challenge = binding_challenge(plan_hash_hex, nonce_hex)
    inst[19] = _fe_be32_hex_from_digest(sm3_bytes(bytes.fromhex(challenge)))
    pred_str = plan_hash_hex + "|" + nonce_hex + "|" + POLICY_VERSION
    inst[20] = _fe_be32_hex_from_digest(
        sm3_bytes(b"FZ-ZKSVC-PRED-ID" + b"\x01" + pred_str.encode())
    )
    inst[21] = _fe_be32_hex_from_u64(_NOW)
    inst[22] = _fe_be32_hex_from_u64(get_rule(class_id)[1])
    inst[23] = _fe_be32_hex_from_bytes32(bytes.fromhex("00" * 32))
    inst[24] = _fe_be32_hex_from_u64(class_id)
    with open(_os.path.join(d, "proof.bin"), "wb") as f:
        f.write(b"proof")
    with open(_os.path.join(d, "instances.json"), "w", encoding="utf-8") as f:
        f.write(_json.dumps({"instances": inst}))
    with open(_os.path.join(d, "verifier_param.bin"), "wb") as f:
        f.write(b"vp")
    return {"proof": _os.path.join(d, "proof.bin"), "instances": _os.path.join(d, "instances.json")}


def _apply_kwargs(dev: dict, sub: dict, holder_pk: str) -> dict:
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    case = _case(plan_hash_hex, nonce_hex, DEV_SN.encode(), dev["class_id"])
    return dict(
        session_pk_hex=holder_pk,
        sub_cred_message_hex=sub["message_hex"],
        sub_sig_hex=sub["sig_hex"],
        sub_cred_hash_hex=sub["sub_cred_hash_hex"],
        nonce_hex=nonce_hex,
        plan_hash_hex=plan_hash_hex,
        class_id=dev["class_id"],
        proof_path=str(case["proof"]),
        spec_path=str(case["instances"]),
        rev_root_hex="00" * 32,
        t_start=_NOW,
        t_end=_NOW + 3600,
    )


def test_gate_fleet_kind2_chain_match_admitted(session):
    """机队凭证+链面 kind=2 一致 → 受理过（机队路径分派实证）。"""
    dev, sub, holder_pk = _fleet_credential(session)
    row = service.admission_gate(
        session, KindDeps(onchain_kind=2), **_apply_kwargs(dev, sub, holder_pk)
    )
    assert row.status == "pending"
    assert row.sub_cred_hash_hex == sub["sub_cred_hash_hex"]


def test_gate_fleet_kind_mismatch_rejected(session):
    """kind 语义错配拒（负例一等公民）：DB 机队（cred_kind=2）∧链面 kind=1
    （漂移/篡改形态）→ 409 kind_mismatch fail-closed。"""
    dev, sub, holder_pk = _fleet_credential(session)
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(
            session, KindDeps(onchain_kind=1), **_apply_kwargs(dev, sub, holder_pk)
        )
    assert ei.value.code == "kind_mismatch"
    assert ei.value.status == 409


def test_gate_personal_zero_chain_kind_reads(session):
    """个人凭证单链语义零变化：cred_kind=1 受理过且 chain_cred_kind **零调用**
    （不新增链读——现行门控序逐字保持）。"""
    from app.kms import ra_signing_keypair

    priv, pub = ra_signing_keypair()
    svc = RaService(
        session,
        RaDeps(ra_priv_hex=priv, ra_pub_hex=pub, anchor=ChainAnchor(call=lambda f, a: None)),
    )
    holder_sk, holder_pk_ = __import__(
        "app.crypto.sm2", fromlist=["generate_keypair"]
    ).generate_keypair()
    per = svc.register(
        username="pilot-gate-" + secrets.token_hex(4),
        id_number="11010119900307999X",
        cert_level=3,
        sn=DEV_SN,
        user_pub_hex=holder_pk_,
        class_id=1,
    )
    sub = svc.issue_sub_credential(
        master_cred_hash_hex=per["master_cred_hash_hex"],
        salt_hex=per["salt_hex"],
        id_number="11010119900307999X",
        cert_level=3,
        sn=DEV_SN,
        holder_pub_hex=holder_pk_,
    )
    kw = _apply_kwargs({"class_id": 1}, sub, holder_pk_)
    deps = KindDeps(onchain_kind=1)  # 链面即使回 1 也不该被问——个人零链读
    row = service.admission_gate(session, deps, **kw)
    assert row.status == "pending"
    assert deps.kind_calls == 0, "个人路径零新增链读（单链语义零变化）"


def test_gate_fleet_kind_unavailable_skipped(session):
    """chain_cred_kind 缺省（None——fake/CI 无链面）→ 机队凭证受理过
    （渐进可用范式同 chain_pin，production 档恒注入真链读数）。"""
    dev, sub, holder_pk = _fleet_credential(session)
    row = service.admission_gate(
        session, KindDeps(onchain_kind=None), **_apply_kwargs(dev, sub, holder_pk)
    )
    assert row.status == "pending"


def test_gate_fleet_org_unresolved_rejected(session):
    """机队行归属域缺失=结构不变式破坏 → 409 fleet_org_unresolved（fail-closed
    ——owner_org_id 列为机队域权威，机队行恒有域）。"""
    dev, sub, holder_pk = _fleet_credential(session)
    cred = session.scalar(
        __import__("sqlalchemy", fromlist=["select"])
        .select(Credential)
        .where(Credential.master_cred_hash_hex == dev["master_cred_hash_hex"])
    )
    cred.owner_org_id = None
    session.commit()
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(
            session, KindDeps(onchain_kind=2), **_apply_kwargs(dev, sub, holder_pk)
        )
    assert ei.value.code == "fleet_org_unresolved"
