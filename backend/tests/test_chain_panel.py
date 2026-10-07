"""/chain/panel 链面 TTL 缓存测试（R4 第二批 A-路线#6）。

- 同键窗内：链 RPC 零重复（缓存命中）
- TTL 过期/检查点集变化：重新回读
- 记录/令状面不经缓存（每请求实时——proofDigest 对账面不受影响）
- /chain/record/{auth_id} 详情端点（W-8 飞手视角）：归档摘要+expected 回读+
  链上对账正反+404+零身份红线
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.chain.panel as panel
from app.authz.models import Application, AuthRecord
from app.main import create_app
from app.ra.models import Base


class _FakeViews:
    """链视图替身：计数 RPC 调用。"""

    def __init__(self):
        self.calls = 0

    def call_fn(self, fn, args):
        self.calls += 1
        if fn == "revEpoch":
            return [1]
        if fn == "revRoot":
            return [bytes(32)]
        return [(0, bytes(32), 0)]


class _FakeClient:
    def __init__(self):
        self.calls = 0

    def block_number(self):
        self.calls += 1
        return 5448


class _FakeFlightAuth:
    """FlightAuthRegistry 替身：getAuth 12 元组按 proof_digest 回读
    （call_fn 真实形态=12 值平铺列表——与 worker 读后写对拍消费同式；
    授权包配额制 2026-10-06：末位 remaining）。"""

    def __init__(self, proof_digest_hex: str):
        self._digest = bytes.fromhex(proof_digest_hex)
        self.calls = 0

    def call_fn(self, fn, args):
        assert fn == "getAuth", f"record_detail 只应调 getAuth，实际 {fn}"
        self.calls += 1
        return [
            bytes.fromhex("ab" * 32),  # [0] tokenHash
            bytes(16),  # [1] nonce
            1,  # [2] classId
            120,  # [3] altMaxM
            1790000000,  # [4] tStart
            1790003600,  # [5] tEnd
            bytes.fromhex("cd" * 32),  # [6] subCredHash
            self._digest,  # [7] proofDigest
            0,  # [8] status
            0,  # [9] revokeReason
            1790000100,  # [10] ts
            1,  # [11] remaining（授权包配额）
        ]


def _reset_cache(monkeypatch, views, client):
    monkeypatch.setattr(panel, "_face_cache", {"key": None, "at": 0.0, "data": None})
    monkeypatch.setattr(panel, "_face_bindings", {"IdentityRegistry": views, "client": client})
    monkeypatch.setattr(
        panel,
        "_binding_cached",
        lambda name: views,  # TelemetryAnchor 同替身
    )
    monkeypatch.setattr(
        panel, "_addresses", lambda: {"IdentityRegistry": {}, "TelemetryAnchor": {}}
    )


def test_chain_face_ttl_cache(monkeypatch):
    views, client = _FakeViews(), _FakeClient()
    _reset_cache(monkeypatch, views, client)

    f1 = panel._chain_face([1, 2])
    assert f1["block_height"] == 5448 and len(f1["checkpoints"]) == 2
    base_calls = views.calls  # revEpoch+revRoot+2×latest

    # 同键窗内：缓存命中（零新增 RPC）
    f2 = panel._chain_face([1, 2])
    assert f2 == f1 and views.calls == base_calls and client.calls == 1

    # 检查点集变化：键失效重读
    panel._chain_face([1, 2, 3])
    assert views.calls > base_calls

    # TTL 过期：键相同也重读（at 置负——模拟时间流逝）
    panel._face_cache["at"] = -1e9
    panel._chain_face([1, 2, 3])
    assert client.calls == 3


# ---------------- /chain/record/{auth_id} 详情端点（W-8） ----------------

_PROOF_DIGEST = "11" * 32
_EXPECTED = {
    "e_hex": "22" * 32,
    "challenge_hex": "33" * 32,
    "pred_id": "44" * 32,
    "t_epoch": 1790000000,
    "required_level": 3,
    "class_id": 0,
    "smt_root_hex": "55" * 32,
}


@pytest.fixture()
def detail_client(tmp_path, monkeypatch):
    """隔离库+一行授权记录+归档判决件（含 W-8 expected/verify_s 字段）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/panel_detail.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)
    vpath = tmp_path / "app-1.verdict.json"
    vpath.write_text(
        json.dumps(
            {
                "application_id": 1,
                "auth_id": 9001,
                "proof_digest": _PROOF_DIGEST,
                "token_hash": "ab" * 32,
                "tx": "0xdeadbeef",
                "verify_s": 4.1,
                "expected": _EXPECTED,
                "verify_log": "zkc verify-instances: OK\n补充行",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    s = TestSession()
    try:
        app_row = Application(
            session_pk_hex="00" * 32,
            sub_sig_hex="00" * 32,
            sub_cred_hash_hex="77" * 32,
            nonce_hex="88" * 16,
            plan_hash_hex="99" * 32,
            class_id=0,
            policy_version="v-demo",
            rev_root_hex="55" * 32,
            e_hex="22" * 32,
            t_start=1790000000,
            t_end=1790003600,
            status="approved",
        )
        s.add(app_row)
        s.flush()
        s.add(
            AuthRecord(
                auth_id=9001,
                application_id=app_row.id,
                token_hash_hex="ab" * 32,
                proof_digest_hex=_PROOF_DIGEST,
                verdict_path=str(vpath),
                tx_hash="0xdeadbeef",
            )
        )
        s.commit()
    finally:
        s.close()
    monkeypatch.setattr(panel, "SessionLocal", TestSession)
    client = TestClient(create_app())
    client.test_session_factory = TestSession
    return client


def test_record_detail_fake_mode_archived_expected(detail_client):
    r = detail_client.get("/chain/record/9001")
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["auth_id"] == 9001 and d["status"] == "approved"
    assert d["proof_digest_hex"] == _PROOF_DIGEST
    assert d["alt_max_m"] == 50  # class 0=微型 政策单源（米）
    assert d["archived"] is True
    assert d["expected"] == _EXPECTED  # 复验材料=验证时消费的同一期望绑定
    assert d["expected_source"] == "archived"
    assert d["verify_s"] == 4.1
    assert "OK" in (d["verify_tail"] or "")
    assert d["chain"] is None  # fake 档诚实无链面


def test_record_detail_zero_identity_surface(detail_client):
    """零身份红线：详情响应序列化文本不含任何身份/设备字段名。"""
    text = detail_client.get("/chain/record/9001").text
    for banned in (
        "username",
        "id_number",
        "idNumber",
        "user_pub",
        "sn",
        "serial",
        "case_no",
        "sub_sig",
        "session_pk",
        "master_cred",
    ):
        assert banned not in text, f"详情端点泄漏身份面字段 {banned}"


def test_record_detail_not_found(detail_client):
    r = detail_client.get("/chain/record/424242")
    assert r.status_code == 404 and r.json()["code"] == "not_found"


def test_record_detail_expected_rebuilt_for_legacy_archive(detail_client):
    """历史归档（W-8 增量前）无 expected 字段：按 worker 同构式确定性重建。"""
    s = detail_client.test_session_factory()
    try:
        from app.authz.models import AuthRecord as AR

        row = s.query(AR).filter(AR.auth_id == 9001).one()
        vpath = row.verdict_path
    finally:
        s.close()
    legacy = json.loads(open(vpath, encoding="utf-8").read())
    del legacy["expected"]
    open(vpath, "w", encoding="utf-8").write(json.dumps(legacy, ensure_ascii=False))

    d = detail_client.get("/chain/record/9001").json()["data"]
    assert d["expected_source"] == "rebuilt"
    # 行字段直取部分与验证时同值；派生部分（challenge/pred_id）与 worker 同函数对拍
    from app.authz.service import binding_challenge, binding_pred_id

    e = d["expected"]
    assert e["e_hex"] == _EXPECTED["e_hex"]
    assert e["t_epoch"] == _EXPECTED["t_epoch"]
    assert e["class_id"] == _EXPECTED["class_id"]
    assert e["smt_root_hex"] == _EXPECTED["smt_root_hex"]
    assert e["challenge_hex"] == binding_challenge("99" * 32, "88" * 16)
    assert e["pred_id"] == binding_pred_id("99" * 32, "88" * 16, "v-demo")


def test_record_detail_chain_match_and_mismatch(detail_client, monkeypatch):
    """真链档对账：链上 proofDigest 与归档一致→match=True；漂移→match=False。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    fa = _FakeFlightAuth(_PROOF_DIGEST)
    monkeypatch.setattr(panel, "_binding_cached", lambda name: fa)

    d1 = detail_client.get("/chain/record/9001").json()["data"]
    assert d1["chain"]["match"] is True
    assert d1["chain"]["proof_digest_hex"] == _PROOF_DIGEST

    # 链上漂移（如本地归档被篡改后对账）：match=False 必须如实呈现
    fa2 = _FakeFlightAuth("ee" * 32)
    monkeypatch.setattr(panel, "_binding_cached", lambda name: fa2)
    d2 = detail_client.get("/chain/record/9001").json()["data"]
    assert d2["chain"]["match"] is False
