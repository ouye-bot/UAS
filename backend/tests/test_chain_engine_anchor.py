"""阶段一真链写面测试：engine 锚定/事件端点（D-Ⅰ-7）+ worker 真链分支（D-Ⅰ-2）。

覆盖面（负例一等公民）：
- /engine/anchor：好签名过（fake 锚记录在案）/坏签名拒/坏 fence_state 拒/
  authId 不在案拒/seq 重放 409（fake latest_seq 单调模拟合约语义）
- /engine/event：正路径/eventType 越界拒/authId 不在案拒
- worker 真链 recordAuth：calldata 与 B1 烟测 args 逐项同构+AuthRecorded 事件
  解出 authId+无事件 fail-closed+revert 传播
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz.models import AuthRecord
from app.crypto.sm2 import generate_keypair
from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.main import create_app
from app.ra.models import Base
from app.telemetry.models import CheckpointAnchor  # noqa: F401 确保表注册


def _cp_sig(sk: str, auth_id: int, seq: int, head: bytes, fence: bytes) -> str:
    from app.crypto.sm2 import sign_digest
    from app.telemetry.checkpoint import checkpoint_message

    return sign_digest(sk, sm3_bytes(checkpoint_message(auth_id, seq, head, fence)))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/tel_test.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)

    import app.telemetry.router as tr

    tr._reset_fake_state()

    def _sess():
        s = TestSession()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    os.environ.setdefault("FZ_ENGINE_TOKEN", "test-engine-token")
    app = create_app()
    app.dependency_overrides[get_session] = _sess
    with TestClient(app) as c:
        c.headers.update({"X-Engine-Token": "test-engine-token"})
        yield c, TestSession


def _seed_auth(TestSession, auth_id: int = 7) -> None:
    s = TestSession()
    s.add(
        AuthRecord(
            auth_id=auth_id,
            application_id=1,
            token_hash_hex="00" * 32,
            proof_digest_hex="11" * 32,
            verdict_path="x",
            tx_hash="fake",
        )
    )
    s.commit()
    s.close()


def _seed_checkpoint(TestSession, auth_id: int = 7, seq: int = 1) -> None:
    """锚定对拍（2026-09-28）：检查点投影播种——绑定端点要求授权至少一次锚定。"""
    s = TestSession()
    s.add(
        CheckpointAnchor(
            auth_id=auth_id,
            seq=seq,
            chain_head_hex="cc" * 32,
            fence_state_hex="01007800",
            device_sig_hex="dd" * 64,
            device_pub_hex=("ee" * 64),
            tx_hash="0x" + "ff" * 32,
        )
    )
    s.commit()
    s.close()


def _anchor_body(sk: str, pub: str, auth_id: int, seq: int, head: bytes, fence: bytes) -> dict:
    return {
        "auth_id": auth_id,
        "seq": seq,
        "chain_head_hex": head.hex(),
        "fence_state_hex": fence.hex(),
        "sig_hex": _cp_sig(sk, auth_id, seq, head, fence),
        "device_pub_hex": pub,
    }


_FENCE = bytes([1]) + (50).to_bytes(2, "big") + b"\x00"


def test_anchor_good_sig_accepted(client):
    c, TS = client
    _seed_auth(TS)
    sk, pub = generate_keypair()
    r = c.post("/engine/anchor", json=_anchor_body(sk, pub, 7, 1, sm3_bytes(b"head-1"), _FENCE))
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["data"]["seq"] == 1


def test_anchor_bad_signature_rejected(client):
    c, TS = client
    _seed_auth(TS)
    sk, pub = generate_keypair()
    other = generate_keypair()[0]
    body = _anchor_body(sk, pub, 7, 1, sm3_bytes(b"head-2"), _FENCE)
    body["sig_hex"] = _cp_sig(other, 7, 1, sm3_bytes(b"head-2"), _FENCE)  # 他钥签名
    r = c.post("/engine/anchor", json=body)
    assert r.status_code == 403 and r.json()["code"] == "bad_checkpoint_sig"


def test_anchor_fence_tamper_rejected(client):
    """fence_state 改 1 字节=签名报文变=拒（D16 围栏状态绑定）。"""
    c, TS = client
    _seed_auth(TS)
    sk, pub = generate_keypair()
    body = _anchor_body(sk, pub, 7, 1, sm3_bytes(b"head-3"), _FENCE)
    body["fence_state_hex"] = (bytes([1]) + (120).to_bytes(2, "big") + b"\x00").hex()
    r = c.post("/engine/anchor", json=body)
    assert r.status_code == 403 and r.json()["code"] == "bad_checkpoint_sig"


def test_anchor_unknown_auth_rejected(client):
    c, _TS = client
    sk, pub = generate_keypair()
    r = c.post("/engine/anchor", json=_anchor_body(sk, pub, 99, 1, sm3_bytes(b"head-4"), _FENCE))
    assert r.status_code == 403 and r.json()["code"] == "auth_not_found"


def test_anchor_seq_replay_conflict(client):
    """同 seq 重锚=409（fake latest_seq 单调——模拟合约 seq==c.seq+1 语义）。"""
    c, TS = client
    _seed_auth(TS)
    sk, pub = generate_keypair()
    r1 = c.post("/engine/anchor", json=_anchor_body(sk, pub, 7, 1, sm3_bytes(b"a"), _FENCE))
    assert r1.status_code == 200
    r2 = c.post("/engine/anchor", json=_anchor_body(sk, pub, 7, 1, sm3_bytes(b"b"), _FENCE))
    assert r2.status_code == 409 and r2.json()["code"] == "seq_conflict"
    # seq=2 顺序推进可通过
    r3 = c.post("/engine/anchor", json=_anchor_body(sk, pub, 7, 2, sm3_bytes(b"c"), _FENCE))
    assert r3.status_code == 200


def test_event_ok_and_negatives(client):
    c, TS = client
    _seed_auth(TS)
    r = c.post(
        "/engine/event",
        json={"auth_id": 7, "event_type": 1, "event_hash_hex": sm3_bytes(b"ev").hex()},
    )
    assert r.status_code == 200 and r.json()["ok"] is True
    r2 = c.post(
        "/engine/event",
        json={"auth_id": 7, "event_type": 9, "event_hash_hex": sm3_bytes(b"ev").hex()},
    )
    assert r2.status_code == 400 and r2.json()["code"] == "bad_event_type"
    r3 = c.post(
        "/engine/event",
        json={"auth_id": 42, "event_type": 1, "event_hash_hex": sm3_bytes(b"ev").hex()},
    )
    assert r3.status_code == 403 and r3.json()["code"] == "auth_not_found"


# ---- worker 真链 recordAuth（MockTransport 对拍 calldata+事件解析）----


class _RecordingTransport:
    """httpx MockTransport：记录请求，回放预置回执。"""

    def __init__(self, receipt: dict | None = None):
        self.calls: list[dict] = []
        self._receipt = receipt

    def __call__(self, request):
        import httpx

        self.calls.append(json.loads(request.content.decode()))
        payload = self.calls[-1]
        if payload["method"] == "sendRawTransaction":
            body: dict = {"jsonrpc": "2.0", "id": 1, "result": "0x" + "ab" * 32}
        elif payload["method"] == "getTransactionReceipt":
            if self._receipt is None:
                body = {"jsonrpc": "2.0", "id": 1, "result": None}
            else:
                body = {"jsonrpc": "2.0", "id": 1, "result": dict(self._receipt)}
        elif payload["method"] == "getBlockNumber":
            body = {"jsonrpc": "2.0", "id": 1, "result": hex(4700)}
        else:
            body = {"jsonrpc": "2.0", "id": 1, "result": "0x"}
        return httpx.Response(200, json=body)


def _auth_recorded_receipt() -> dict:
    """AuthRecorded 事件回执（indexed authId=5 在 topic1）。"""
    from app.chain.abi import sig_hash

    topic0 = (
        "0x"
        + sig_hash(
            "AuthRecorded(uint256,bytes32,bytes16,uint8,uint16,uint40,uint40,bytes32,bytes32,address,uint64)",
            gm=True,
        ).hex()
    )
    return {
        "status": "0x0",
        "transactionHash": "0x" + "cd" * 32,
        "logs": [
            {
                "address": "0x233610b9b4733f2306c9392bacf61d488b90ac48",
                "topics": [topic0, "0x" + (5).to_bytes(32, "big").hex()],
                "data": "0x",
            }
        ],
    }


class _RealChainWorkerDeps:
    """真链分支 deps（FZ_CHAIN_ANCHOR=real+注入 transport Client）。"""

    def __init__(self, transport):
        import httpx

        from app.zk import worker as w

        os.environ["FZ_CHAIN_ANCHOR"] = "real"
        self._w = w
        deps = w.WorkerDeps()
        deps._chain_http = httpx.Client(transport=httpx.MockTransport(transport))
        self.deps = deps

    def close(self):
        os.environ["FZ_CHAIN_ANCHOR"] = "fake"
        self.deps._chain_http.close()

    def __enter__(self):
        return self.deps

    def __exit__(self, *exc):
        self.close()


_RECORD_AUTH_KW = dict(
    token_hash_hex="aa" * 32,
    nonce_hex="bb" * 16,
    class_id=1,
    alt_max=120,
    t_start=1700000000,
    t_end=1700003600,
    sub_cred_hash_hex="cc" * 32,
    proof_digest_hex="dd" * 32,
)


def test_worker_real_record_auth_roundtrip():
    """真链 recordAuth：calldata 同构+AuthRecorded 事件解出 authId=5。"""
    tr = _RecordingTransport(receipt=_auth_recorded_receipt())
    with _RealChainWorkerDeps(tr) as deps:
        auth_id, tx = deps.chain_record_auth(**_RECORD_AUTH_KW)
        # calldata 对拍：binding 编码产物逐参数断言（abi 定宽 32B 槽——与 B1 烟测
        # args 同构）；raw 交易为 RLP 签名件，接线完整性=calldata 完整嵌入其中。
        from app.chain.abi import fn_selector

        expected = deps._fa_binding.encode_calldata(
            "recordAuth",
            [
                bytes.fromhex("aa" * 32),
                bytes.fromhex("bb" * 16),
                1,
                120,
                1700000000,
                1700003600,
                bytes.fromhex("cc" * 32),
                bytes.fromhex("dd" * 32),
            ],
        )
        sel = fn_selector(
            "recordAuth(bytes32,bytes16,uint8,uint16,uint40,uint40,bytes32,bytes32)", gm=True
        )
        assert expected[: len(sel)] == sel, "selector 前缀一致"
        data = expected[len(sel) :]
        w32 = lambda i: data[i * 32 : (i + 1) * 32]  # noqa: E731
        assert w32(0) == bytes.fromhex("aa" * 32)  # tokenHash
        assert w32(1)[:16] == bytes.fromhex("bb" * 16)  # nonce（bytes16 右填充）
        assert w32(2)[-1] == 1  # classId uint8
        assert w32(3)[-2:] == (120).to_bytes(2, "big")  # altMaxM uint16（meters）
        assert w32(4)[-5:] == (1700000000).to_bytes(5, "big")  # tStart uint40
        assert w32(5)[-5:] == (1700003600).to_bytes(5, "big")  # tEnd uint40
        assert w32(6) == bytes.fromhex("cc" * 32)  # subCredHash
        assert w32(7) == bytes.fromhex("dd" * 32)  # proofDigest
        send = next(c for c in tr.calls if c["method"] == "sendRawTransaction")
        raw = bytes.fromhex(send["params"][1].removeprefix("0x"))
        assert expected in raw, "calldata 完整嵌入签名交易（RLP payload）"
    assert auth_id == 5 and tx == "0x" + "cd" * 32


def test_worker_real_burn_nonce_calldata():
    """burnNonce 独立写面（D-Ⅰ-3 完备性）：calldata=selector+bytes16 槽。"""
    tr = _RecordingTransport(
        receipt={"status": "0x0", "transactionHash": "0x" + "ff" * 32, "logs": []}
    )
    with _RealChainWorkerDeps(tr) as deps:
        tx = deps.chain_burn_nonce(nonce_hex="bb" * 16)
    assert tx == "0x" + "ff" * 32
    from app.chain.abi import fn_selector

    expected = deps._fa_binding.encode_calldata("burnNonce", [bytes.fromhex("bb" * 16)])
    sel = fn_selector("burnNonce(bytes16)", gm=True)
    assert expected[: len(sel)] == sel and expected[len(sel) :][:16] == bytes.fromhex("bb" * 16)


def test_worker_real_record_auth_no_event_fails_closed():
    """回执无 AuthRecorded 事件=fail-closed 异常（禁吞）。"""
    tr = _RecordingTransport(
        receipt={"status": "0x0", "transactionHash": "0x" + "ee" * 32, "logs": []}
    )
    with _RealChainWorkerDeps(tr) as deps:
        with pytest.raises(RuntimeError) as ei:
            deps.chain_record_auth(**_RECORD_AUTH_KW)
    assert "AuthRecorded" in str(ei.value)


def test_worker_real_record_auth_revert_propagates():
    """链 revert（status!=0x0）=异常传播（fail-closed）。"""
    from app.chain.client import ChainError

    tr = _RecordingTransport(receipt={"status": "0x16"})
    with _RealChainWorkerDeps(tr) as deps:
        with pytest.raises(ChainError):
            deps.chain_record_auth(**_RECORD_AUTH_KW)


# ---- R4 复验 P0-1：TRAIL 出证绑定（引擎签 alt_max+链头+authId） ----


def _seed_application(TS, application_id: int = 1, class_id: int = 0):
    from app.authz.models import Application

    s = TS()
    s.add(
        Application(
            id=application_id,
            session_pk_hex="22" * 64,
            sub_sig_hex="33" * 128,
            sub_cred_hash_hex="44" * 32,
            nonce_hex="55" * 16,
            plan_hash_hex="66" * 32,
            class_id=class_id,
            policy_version="policy-2026-09-v1",
            rev_root_hex="00" * 32,
            status="approved",
        )
    )
    s.commit()
    s.close()


def test_trail_binding_issues_engine_sig(client):
    c, TS = client
    _seed_auth(TS)
    _seed_application(TS, class_id=0)
    _seed_checkpoint(TS, auth_id=7)  # 锚定对拍：绑定要求至少一次链上锚定
    head = "ab" * 32
    r = c.get("/engine/trail/binding", params={"auth_id": 7, "chain_head_hex": head})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["alt_max_cm"] == 5000, "微型 50m × 100（TRAIL 电路 cm 口径）"
    from app.kms import engine_pub_hex

    msg = f"FZ-TRAIL-BIND|7|5000|{head}".encode()
    from app.crypto.sm2 import verify_digest

    assert verify_digest(engine_pub_hex(), sm3_bytes(msg), d["sig_hex"])
    # 锚定证据（信封随 binding.json 发放）：内容+独立引擎签名可离线验
    ev = d["anchor_evidence"]
    assert ev["seq"] == 1 and ev["chain_head_hex"] == "cc" * 32
    evid_msg = f"FZ-ANCHOR-EVID|7|{ev['seq']}|{ev['chain_head_hex']}".encode()
    assert verify_digest(engine_pub_hex(), sm3_bytes(evid_msg), d["anchor_evidence_sig_hex"])


def test_trail_binding_requires_anchored_checkpoint(client):
    """零锚定授权拒绝绑定（锚定对拍硬规则——从未留痕的授权不出轨迹证书）。"""
    c, TS = client
    _seed_auth(TS)
    _seed_application(TS, class_id=0)
    r = c.get("/engine/trail/binding", params={"auth_id": 7, "chain_head_hex": "ab" * 32})
    assert r.status_code == 409
    assert "no_anchored_checkpoint" in r.text


def test_trail_binding_bad_head_rejected(client):
    c, _ = client
    r = c.get(
        "/engine/trail/binding",
        params={"auth_id": 7, "chain_head_hex": "ab" * 31},
    )
    assert r.status_code == 400


def test_trail_binding_unknown_auth_404(client):
    c, TS = client
    _seed_application(TS)
    head = "ab" * 32
    r = c.get(
        "/engine/trail/binding",
        params={"auth_id": 999, "chain_head_hex": head},
    )
    assert r.status_code == 404
