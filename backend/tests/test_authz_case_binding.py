"""批 4 授权面测试：出证案卷服务端权威归属 + 链锚档位显式化。

覆盖面（批 4-1/4-3）：
- 案卷绑定门：抢注拒（409 case_taken）/幂等过（同 case_id 同材料=原申请原
  回执）/材料不一致拒（409 case_taken）/路径穿越仍拒（hex 白名单 400）
- 库级唯一约束兜底（applications.case_id 唯一索引——0017）
- 跨案卷一次性判决保留：同子凭证换 case_id=409 sub_cred_used（不放松）
- 档位显式化：/authz/apply 受理响应与回执 JSON 顶层 mode=fake/real
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
    db_file = tmp_path / "case_binding.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = db_mod.sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    ra_router._reset_deps_cache()
    from app.authz import router as authz_router
    from app.authz.service import AuthzDeps

    class _D(AuthzDeps):
        def __init__(self):
            super().__init__()
            self.pin_fingerprint = lambda: "SM3(test|pin)"
            self.chain_rev_root = lambda: (1, "00" * 32)

    _real_deps = authz_router._deps  # 用例后还原（不向后续测试模块泄漏替身）
    authz_router._deps = lambda: _D()
    with TestClient(create_app()) as c:
        yield c
    authz_router._deps = _real_deps
    ra_router._reset_deps_cache()


def _sub_credential(session_pk_hex: str = _VALID_PK):
    _sk, ra_pub = ra_signing_keypair()
    msg = build_message(
        ra_pub,
        secrets.token_bytes(32),
        secrets.token_bytes(16),
        b"110101199001011234",
        3,
        b"FZ-SN-CASE-BIND",
        session_pk_hex,
        1900000000,
    )
    _p, _pub = ra_signing_keypair()
    # SN 绑定换代（2026-10-06）：服务端溯源链播种（app DB 同 e2e 模式）。
    import app.db as db_mod

    from conftest import seed_sn_chain

    with db_mod.SessionLocal() as _s:
        seed_sn_chain(_s, msg, b"FZ-SN-CASE-BIND")
    return msg, sign_credential(_p, msg)


def _mk_case(case_id: str, plan_hash_hex: str, nonce_hex: str) -> None:
    import os as _os

    from app.authz.policy import POLICY_VERSION, get_rule
    from app.authz.service import (
        _fe_be32_hex_from_bytes32,
        _fe_be32_hex_from_digest,
        _fe_be32_hex_from_u64,
        binding_challenge,
    )

    d = _os.path.join(_os.environ["FZ_ZK_CASES_DIR"], case_id)
    _os.makedirs(d, exist_ok=True)
    inst = ["0" * 64] * 26
    inst[25] = _fe_be32_hex_from_bytes32(sm3_bytes(b"FZ-SN-CASE-BIND"))  # SN 绑定换代：实例 25
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


def _apply_body(case_id: str | None = None, session_pk_hex: str = _VALID_PK) -> dict:
    msg, sig = _sub_credential(session_pk_hex)
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    cid = case_id or secrets.token_hex(8)
    _mk_case(cid, plan_hash_hex, nonce_hex)
    return {
        "session_pk_hex": session_pk_hex,
        "sub_cred_message_hex": msg.hex(),
        "sub_sig_hex": sig,
        "sub_cred_hash_hex": sm3_bytes(msg).hex(),  # 签发面同式（A-P1-1）
        "nonce_hex": nonce_hex,
        "plan_hash_hex": plan_hash_hex,
        "class_id": 0,
        "case_id": cid,
        "t_start": _NOW,
        "t_end": _NOW + 3600,
        "rev_root_hex": "00" * 32,
    }


# ---- 批 4-1：案卷绑定门 ----


def test_case_hijack_rejected(client):
    """抢注拒：首个申请绑定案卷后，携同 case_id 的他人材料=409 case_taken。"""
    body = _apply_body()
    assert client.post("/authz/apply", json=body).status_code == 200
    attacker = _apply_body(case_id=body["case_id"])  # 同案卷、全新材料
    resp = client.post("/authz/apply", json=attacker)
    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "case_taken"
    assert "已归属" in resp.json()["message"]


def test_case_idempotent_replay_passes(client):
    """幂等过：同 case_id 同材料重发=200 且原申请原回执（不重复入队）。"""
    body = _apply_body()
    d1 = client.post("/authz/apply", json=body).json()["data"]
    d2 = client.post("/authz/apply", json=body).json()["data"]
    assert d2["application_id"] == d1["application_id"]
    assert d2["receipt_code"] == d1["receipt_code"]


def test_case_material_mismatch_rejected(client):
    """材料不一致拒：同 case_id、同子凭证但换 nonce（会话钥）=409 case_taken，
    且原绑定申请不被改写。"""
    body = _apply_body()
    r1 = client.post("/authz/apply", json=body)
    assert r1.status_code == 200
    d1 = r1.json()["data"]
    # 同子凭证材料 + 同案卷，但换 nonce（=材料不一致形态；合法签名另签一张报文）
    msg, sig = _sub_credential()
    body2 = dict(body)
    body2["nonce_hex"] = secrets.token_bytes(16).hex()
    body2["sub_cred_message_hex"] = msg.hex()
    body2["sub_sig_hex"] = sig
    body2["sub_cred_hash_hex"] = sm3_bytes(msg).hex()
    _mk_case(body["case_id"], body["plan_hash_hex"], body2["nonce_hex"])  # 实例同源
    resp = client.post("/authz/apply", json=body2)
    assert resp.status_code == 409
    assert resp.json()["code"] == "case_taken"
    # 原归属不受扰（幂等重放仍返回原申请）
    d3 = client.post("/authz/apply", json=body).json()["data"]
    assert d3["application_id"] == d1["application_id"]


def test_case_traversal_still_rejected(client):
    """穿越仍拒：case_id 非 hex（路径分隔/外字符）=400 bad_case_id
    （hex 白名单保留——案卷目录寻址不因绑定语义放宽）。"""
    for bad in ("zz" * 8, "ab/cd/ef", "ab\\cd\\ef", "ab//abcd", "0x0xzzqq"):
        body = _apply_body(case_id=bad)
        resp = client.post("/authz/apply", json=body)
        assert resp.status_code == 400, f"{bad!r}: {resp.text}"
        assert resp.json()["code"] == "bad_case_id"


def test_case_unique_row_and_cross_case_subcred_used(client):
    """一次性判决不放松：同子凭证换案卷（新 case_id 新目录）=409 sub_cred_used；
    库内 case_id 每案卷至多一行。"""
    body = _apply_body()
    assert client.post("/authz/apply", json=body).status_code == 200
    other = secrets.token_hex(8)
    _mk_case(other, body["plan_hash_hex"], body["nonce_hex"])
    resp = client.post("/authz/apply", json=dict(body, case_id=other))
    assert resp.status_code == 409
    assert resp.json()["code"] == "sub_cred_used"


# ---- 批 4-3：档位显式化 ----


def test_apply_and_receipt_mode_fake(client):
    """fake 档：受理响应与回执 JSON 顶层 mode="fake"（缺省链锚档自述）。"""
    body = _apply_body()
    resp = client.post("/authz/apply", json=body)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["mode"] == "fake"
    r = client.get(f"/authz/receipt/{data['receipt_code']}")
    assert r.status_code == 200
    assert r.json()["data"]["mode"] == "fake"


def test_apply_mode_real(monkeypatch, client):
    """real 档：受理响应顶层 mode="real"（读 FZ_CHAIN_ANCHOR——门控链面由
    测试替身注入，此处只验档位字段显式化）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    resp = client.post("/authz/apply", json=_apply_body())
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["mode"] == "real"
