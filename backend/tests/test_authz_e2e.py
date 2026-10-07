"""B4-T5 e2e（API 级）：匿名申请→门控→回执取件全链（RA API 测试同款 DB 模式）。

B4 验收门 clause ①"e2e 申请→令牌→回执解密全链绿"（API 面；worker 排水面在
test_authz_worker；真链/真证明形态归演示体系/服务器窗——分层诚实声明）。
"""

from __future__ import annotations

import json
import secrets
import time as _time_mod

import pytest
from fastapi.testclient import TestClient

import app.db as db_mod
from app.crypto.sm2 import generate_keypair as _gen_kp
from app.crypto.sm3 import sm3_bytes
from app.kms import ra_signing_keypair
from app.main import create_app
from app.ra import router as ra_router
from app.ra.credential import build_message, sign_credential
from app.ra.models import Base

_NOW = int(_time_mod.time())

_VALID_PK = _gen_kp()[1]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    db_file = tmp_path / "authz_e2e.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = db_mod.sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    ra_router._reset_deps_cache()
    # authz 门控 deps 替身（pin/rev_root——真链面在演示窗）
    from app.authz import router as authz_router
    from app.authz.service import AuthzDeps

    class _D(AuthzDeps):
        def __init__(self):
            super().__init__()
            self.pin_fingerprint = lambda: "SM3(test|pin)"
            self.chain_rev_root = lambda: (1, "00" * 32)

    authz_router._deps = lambda: _D()
    with TestClient(create_app()) as c:
        yield c
    ra_router._reset_deps_cache()


def _apply_body():
    _sk, ra_pub = ra_signing_keypair()
    msg = build_message(
        ra_pub,
        secrets.token_bytes(32),
        secrets.token_bytes(16),
        b"110101199001011234",
        3,
        b"FZ-SN-E2E",
        _VALID_PK,
        1900000000,
    )
    _p, _pub = ra_signing_keypair()
    # SN 绑定换代（2026-10-06）：服务端溯源链播种（app DB——受理门/worker
    # 铸令牌共用 sub_cred_hash→credentials.serial_hex 解析面）。
    from conftest import seed_sn_chain

    with db_mod.SessionLocal() as _s:
        seed_sn_chain(_s, msg, b"FZ-SN-E2E")
    plan_hash_hex = "cd" * 32
    nonce_hex = secrets.token_bytes(16).hex()
    # 造真实出证产物目录（instances 由服务端同源折算函数生成——一致性校验可通过）
    import os as _os

    from app.authz.policy import POLICY_VERSION, get_rule
    from app.authz.service import (
        _fe_be32_hex_from_bytes32,
        _fe_be32_hex_from_digest,
        _fe_be32_hex_from_u64,
        binding_challenge,
    )

    case_id = secrets.token_hex(8)
    zk_dir = _os.environ.get("FZ_ZK_CASES_DIR", "/tmp/fz-zk-cases")
    d = _os.path.join(zk_dir, case_id)
    _os.makedirs(d, exist_ok=True)
    inst = ["0" * 64] * 26
    inst[25] = _fe_be32_hex_from_bytes32(sm3_bytes(b"FZ-SN-E2E"))  # SN 绑定换代：实例 25
    inst[19] = _fe_be32_hex_from_digest(
        sm3_bytes(bytes.fromhex(binding_challenge(plan_hash_hex, nonce_hex)))
    )
    pred_domain = b"FZ-ZKSVC-PRED-ID" + b"\x01"
    inst[20] = _fe_be32_hex_from_digest(
        sm3_bytes(pred_domain + (plan_hash_hex + "|" + nonce_hex + "|" + POLICY_VERSION).encode())
    )
    inst[21] = _fe_be32_hex_from_u64(_NOW)
    inst[22] = _fe_be32_hex_from_u64(get_rule(0)[1])
    inst[23] = _fe_be32_hex_from_bytes32(bytes(32))
    inst[24] = _fe_be32_hex_from_u64(0)
    with open(_os.path.join(d, "proof.bin"), "wb") as f:
        f.write(b"proof")
    with open(_os.path.join(d, "instances.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"instances": inst}))
    with open(_os.path.join(d, "verifier_param.bin"), "wb") as f:
        f.write(b"vp")
    return {
        "session_pk_hex": _VALID_PK,
        "sub_cred_message_hex": msg.hex(),
        "sub_sig_hex": sign_credential(_p, msg),
        "sub_cred_hash_hex": sm3_bytes(msg).hex(),  # 签发面同式（A-P1-1 夹具换代）
        "nonce_hex": nonce_hex,
        "plan_hash_hex": plan_hash_hex,
        "class_id": 0,
        "case_id": case_id,
        "t_start": _NOW,
        "t_end": _NOW + 3600,
        "rev_root_hex": "00" * 32,
    }


def test_apply_receipt_pickup_flow(client):
    body = _apply_body()
    resp = client.post("/authz/apply", json=body)
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["status"] == "pending"
    code = data["receipt_code"]
    assert len(code) == 32  # 128bit 回执码

    # 响应面零身份断言（匿名红线）
    flat = resp.text
    for leak in ("username", "id_number", "user_id", "commitment"):
        assert leak not in flat

    # 取件 waiting；404 负例
    r2 = client.get(f"/authz/receipt/{code}")
    assert r2.status_code == 200 and r2.json()["data"]["status"] == "waiting"
    r3 = client.get("/authz/receipt/" + "ff" * 16)
    assert r3.status_code == 404


def test_apply_bad_signature_rejected(client):
    body = _apply_body()
    body["sub_sig_hex"] = "0" + secrets.token_hex(63)
    resp = client.post("/authz/apply", json=body)
    assert resp.status_code == 400
    assert resp.json()["code"] == "bad_sub_signature"


def test_apply_replay_and_case_binding_semantics(client):
    """重放/案卷绑定语义（批 4-1 换代）：同 case_id 同材料=幂等受理（原申请
    原回执直接返回）；同子凭证换案卷=409 sub_cred_used（一次性判决不放松）。"""
    body = _apply_body()
    r1 = client.post("/authz/apply", json=body)
    assert r1.status_code == 200, r1.text
    d1 = r1.json()["data"]
    # 同 body 原样重发（同 case_id 同材料）——幂等：200+同一申请+同一回执码
    r2 = client.post("/authz/apply", json=body)
    assert r2.status_code == 200, r2.text
    d2 = r2.json()["data"]
    assert d2["application_id"] == d1["application_id"]
    assert d2["receipt_code"] == d1["receipt_code"]
    # 库内只此一行（不重复入队）
    from sqlalchemy import func, select

    from app.authz.models import Application as _A
    from app.db import SessionLocal as _SL

    _s = _SL()
    try:
        n = _s.scalar(select(func.count()).select_from(_A))
    finally:
        _s.close()
    assert n == 1

    # 换案卷（新 case_id）重放同一子凭证——一次性判决原样保留（不因幂等放松）
    other_case = secrets.token_hex(8)
    _mk_case_dir(other_case, body["plan_hash_hex"], body["nonce_hex"])
    body2 = dict(body, case_id=other_case)
    resp = client.post("/authz/apply", json=body2)
    assert resp.status_code == 409
    assert resp.json()["code"] == "sub_cred_used"


def _mk_case_dir(case_id: str, plan_hash_hex: str, nonce_hex: str) -> None:
    """造出证产物目录（与 _apply_body 同源折算——案卷绑定语义测试用）。"""
    import os as _os

    from app.authz.policy import POLICY_VERSION as _PV
    from app.authz.policy import get_rule
    from app.authz.service import (
        _fe_be32_hex_from_bytes32,
        _fe_be32_hex_from_digest,
        _fe_be32_hex_from_u64,
        binding_challenge,
    )

    d = _os.path.join(_os.environ.get("FZ_ZK_CASES_DIR", "/tmp/fz-zk-cases"), case_id)
    _os.makedirs(d, exist_ok=True)
    inst = ["0" * 64] * 26
    inst[25] = _fe_be32_hex_from_bytes32(sm3_bytes(b"FZ-SN-E2E"))  # SN 绑定换代：实例 25
    inst[19] = _fe_be32_hex_from_digest(
        sm3_bytes(bytes.fromhex(binding_challenge(plan_hash_hex, nonce_hex)))
    )
    pred_domain = b"FZ-ZKSVC-PRED-ID" + b"\x01"
    inst[20] = _fe_be32_hex_from_digest(
        sm3_bytes(pred_domain + (plan_hash_hex + "|" + nonce_hex + "|" + _PV).encode())
    )
    inst[21] = _fe_be32_hex_from_u64(_NOW)
    inst[22] = _fe_be32_hex_from_u64(get_rule(0)[1])
    inst[23] = _fe_be32_hex_from_bytes32(bytes(32))
    inst[24] = _fe_be32_hex_from_u64(0)
    with open(_os.path.join(d, "proof.bin"), "wb") as f:
        f.write(b"proof")
    with open(_os.path.join(d, "instances.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"instances": inst}))
    with open(_os.path.join(d, "verifier_param.bin"), "wb") as f:
        f.write(b"vp")
