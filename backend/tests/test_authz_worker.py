"""B4-T3/T4 测试：验证 worker 排水+令牌签发+回执封发解密。

- 诚实证明（zkc verify 替身 exit 0）→approved+令牌+ECIES 回执+取件解密闭环
- 伪造证明（exit 2）→rejected+回执 failed
- 令牌字段断言（A2：plan_hash 在场；B4-d7：零 sn_hash——设备信息零暴露）
- 判决件归档（proofDigest/token_hash/verdict 路径）
"""

from __future__ import annotations

import json
import secrets
import time as _time_mod
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz import service
from app.authz.models import AuthRecord, Receipt
from app.crypto.sm2 import decrypt as ecies_decrypt
from app.crypto.sm2 import generate_keypair
from app.crypto.sm2 import generate_keypair as _gen_kp
from app.kms import engine_signing_keypair, ra_signing_keypair
from app.ra.credential import build_message, sign_credential
from app.ra.models import Base
from app.zk import worker as w

_NOW = int(_time_mod.time())

_VALID_PK = _gen_kp()[1]


@pytest.fixture()
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


class GateDeps(service.AuthzDeps):
    def __init__(self):
        super().__init__()
        self.pin_fingerprint = lambda: "SM3(test|pin)"
        self.chain_rev_root = lambda: (1, "00" * 32)


class OkWorker(w.WorkerDeps):
    """zkc 替身：exit 0+链上替身 authId=7（预分配一致）。"""

    def zkc_verify(self, case_dir, expected):
        return (0, "verify ok (stub)")

    def next_auth_id(self, **kw):
        return 7

    def chain_record_auth(self, **kw):
        return (7, "0xtx1")


class MismatchWorker(OkWorker):
    """authId 预测错位（多 worker 并发形态）→ fail-closed 拒绝。"""

    def chain_record_auth(self, **kw):
        return (8, "0xtx-clash")


class FailWorker(OkWorker):
    def zkc_verify(self, case_dir, expected):
        return (2, "InvalidSnark: sumcheck mismatch (stub)")


def _enqueued(session, session_sk, session_pk, deps=None, nonce_hex="11" * 16):
    _sk, ra_pub = ra_signing_keypair()
    msg = build_message(
        ra_pub,
        secrets.token_bytes(32),
        secrets.token_bytes(16),
        b"110101199001011234",
        3,
        b"FZ-SN-W",
        session_pk,
        1900000000,
    )
    _p, _pub = ra_signing_keypair()
    # 出证产物目录（instances 由服务端同源折算函数生成——gate 已过；本组测试专注验证后段）
    import json as _json
    import os as _os
    import tempfile as _tf

    from app.authz.policy import POLICY_VERSION
    from app.authz.service import (
        _fe_be32_hex_from_bytes32,
        _fe_be32_hex_from_digest,
        _fe_be32_hex_from_u64,
        binding_challenge,
    )
    from app.crypto.sm3 import sm3_bytes as _sm3

    d = _os.path.join(_tf.mkdtemp(prefix="fzcase"), "case")
    _os.makedirs(d)
    inst = ["0" * 64] * 25
    inst[19] = _fe_be32_hex_from_digest(
        _sm3(bytes.fromhex(binding_challenge("ab" * 32, nonce_hex)))
    )
    pred_str = "ab" * 32 + "|" + nonce_hex + "|" + POLICY_VERSION
    inst[20] = _fe_be32_hex_from_digest(_sm3((b"FZ-ZKSVC-PRED-ID" + b"\x01") + pred_str.encode()))
    inst[21] = _fe_be32_hex_from_u64(_NOW)
    inst[22] = _fe_be32_hex_from_u64(1)  # class 1 轻型 required=1
    inst[23] = _fe_be32_hex_from_bytes32(bytes(32))
    inst[24] = _fe_be32_hex_from_u64(1)
    with open(_os.path.join(d, "proof.bin"), "wb") as f:
        f.write(b"\x11" * 64)
    with open(_os.path.join(d, "instances.json"), "w", encoding="utf-8") as f:
        f.write(_json.dumps({"instances": inst}))
    with open(_os.path.join(d, "verifier_param.bin"), "wb") as f:
        f.write(b"vp")
    row = service.admission_gate(
        session,
        deps or GateDeps(),
        session_pk_hex=session_pk,
        sub_cred_message_hex=msg.hex(),
        sub_sig_hex=sign_credential(_p, msg),
        sub_cred_hash_hex=_sm3(msg).hex(),  # 签发面同式（A-P1-1 夹具换代）
        nonce_hex=nonce_hex,
        plan_hash_hex="ab" * 32,
        class_id=1,
        proof_path=_os.path.join(d, "proof.bin"),
        spec_path=_os.path.join(d, "instances.json"),
        rev_root_hex="00" * 32,
        t_start=_NOW,
        t_end=_NOW + 3600,
    )
    return row


def test_worker_approve_full_chain(session, tmp_path):
    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()

    stats = w.process_pending(session, OkWorker())
    assert stats == {"processed": 1, "approved": 1, "rejected": 0, "retried": 0}
    session.refresh(row)
    assert row.status == "approved" and row.auth_id == 7
    from sqlalchemy import select as _sel

    rec = session.scalar(_sel(AuthRecord).where(AuthRecord.application_id == row.id))
    assert rec is not None and rec.proof_digest_hex
    assert Path(rec.verdict_path).exists()

    # 取件+解密闭环（会话钥 ECIES）
    r = session.get(Receipt, row.receipt_id)
    assert r.status == "ready"
    out = service.receipt_of(session, r.code_hex)
    payload = ecies_decrypt(sk, bytes.fromhex(out["token_cipher_hex"]))
    body, sig = payload.rsplit(b"|", 1)
    tok = json.loads(body)
    # A2：plan_hash 在场；B4-d7：零设备字段
    assert tok["plan_hash"] == "ab" * 32
    assert tok["alt_max"] == 120  # class 1 轻型条例数值
    assert tok["authId"] == 7
    assert "sn_hash" not in tok and "sn" not in tok
    # 令牌签名可验（engine 公钥）
    from app.crypto.sm2 import verify_digest
    from app.crypto.sm3 import sm3_bytes

    _esk, epub = engine_signing_keypair()
    assert verify_digest(epub, sm3_bytes(body), sig.decode())


def test_worker_reject_bad_proof(session, tmp_path):
    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()

    stats = w.process_pending(session, FailWorker())
    assert stats["rejected"] == 1
    session.refresh(row)
    assert row.status == "rejected" and "exit 2" in row.reject_reason
    r = session.get(Receipt, row.receipt_id)
    assert r.status == "failed"


def test_worker_reject_auth_id_mismatch(session, tmp_path):
    """authId 预测错位=fail-closed 拒绝（阶段一根修的守卫：多 worker 并发形态）。"""
    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()
    stats = w.process_pending(session, MismatchWorker())
    assert stats["rejected"] == 1 and stats["approved"] == 0
    session.refresh(row)
    assert row.status == "rejected" and "auth_id_mismatch" in row.reject_reason
    r = session.get(Receipt, row.receipt_id)
    assert r.status == "failed"


def test_receipt_bad_session_key_decrypt_fails(session, tmp_path):
    """坏会话钥解密失败负例（B4 验收门：非取件钥拿不到令牌明文）。"""

    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()
    w.process_pending(session, OkWorker())
    r = session.get(Receipt, row.receipt_id)
    out = service.receipt_of(session, r.code_hex)
    # 用错的会话私钥解密：ECIES 必败（C3 MAC 不符——令牌密文不可读）
    other_sk = generate_keypair()[0]
    with pytest.raises(Exception) as ei:
        ecies_decrypt(other_sk, bytes.fromhex(out["token_cipher_hex"]))
    assert ei.value.__class__.__name__ in ("SM2Error", "ValueError", "Exception")


def test_gate_chain_sub_used_rejects(session):
    """链级子凭证查重先于库查重——数据库换代/多实例场景不漏（阶段四）。"""
    import pytest

    from app.authz.service import AuthzError

    sk, pk = generate_keypair()
    deps = GateDeps()
    deps.chain_sub_used = lambda cred: True  # 链上已用（攻击形态）
    with pytest.raises(AuthzError) as ei:
        _enqueued(session, sk, pk, deps=deps)
    assert ei.value.code == "sub_cred_used"


class ReadbackBinding:
    """getAuth 回读替身：echo 闸门写入的记录（match）或全零（mismatch）。"""

    def __init__(self, match: bool):
        self.match = match
        self.captured = None

    def call_fn(self, fn, args):
        k = self.captured
        if self.match:
            return [
                bytes.fromhex(k["token_hash_hex"]),
                bytes.fromhex(k["nonce_hex"]),
                k["class_id"],
                k["alt_max"],
                k["t_start"],
                k["t_end"],
                bytes.fromhex(k["sub_cred_hash_hex"]),
                bytes.fromhex(k["proof_digest_hex"]),
                0,
                0,
                0,
            ]
        return [b"\x00" * 32] * 8 + [0, 0, 0]


class ReadbackWorker(OkWorker):
    """真链档替身：recordAuth 捕获参数→getAuth 按 match 回读；chain_rev_root_now
    按 root_now 回读（缺省与申请行一致——TOCTOU 复查面）。"""

    def __init__(self, match: bool, root_now: str | None = None):
        super().__init__()
        self.binding = ReadbackBinding(match)
        self._root_now = root_now

    def _flight_auth_binding(self):
        return self.binding

    def chain_rev_root_now(self):
        return (1, self._root_now if self._root_now is not None else "00" * 32)

    def chain_record_auth(self, **kw):
        self.binding.captured = kw
        return (7, "0xtx")


def test_worker_readback_mismatch_rejects(session, tmp_path, monkeypatch):
    """读后写对拍不一致 → 拒绝 chain_readback_mismatch（非重试轴）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    row = _enqueued(session, *generate_keypair())
    stats = w.process_pending(session, ReadbackWorker(match=False))
    assert stats["rejected"] == 1 and stats["approved"] == 0
    session.refresh(row)
    assert row.status == "rejected" and "chain_readback_mismatch" in row.reject_reason


def test_worker_readback_match_approves(session, tmp_path, monkeypatch):
    """回读一致 → 正常批准（读后写不引入误伤）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    row = _enqueued(session, *generate_keypair())
    stats = w.process_pending(session, ReadbackWorker(match=True))
    session.refresh(row)
    assert stats["approved"] == 1 and row.status == "approved" and row.locked_by is None


def test_worker_rev_root_moved_rejects(session, tmp_path, monkeypatch):
    """撤销 TOCTOU（R4 第二批 A-P2-3）：验证窗内撤销根更迭 → recordAuth 前
    复查拦截（终态拒绝，nonce 不烧——申请人刷新见证重新出证）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    row = _enqueued(session, *generate_keypair())
    stats = w.process_pending(session, ReadbackWorker(match=True, root_now="ff" * 32))
    assert stats["rejected"] == 1 and stats["approved"] == 0
    session.refresh(row)
    assert row.status == "rejected" and "rev_root_moved" in row.reject_reason
    r = session.get(Receipt, row.receipt_id)
    assert r.status == "failed"


# ---- R4 第二批 B-P2-6：authId 预测竞态根修（临界区互斥）----

import threading  # noqa: E402


class SeqChainWorker(w.WorkerDeps):
    """链序替身：authId 顺序分配（100+n）。next_auth_id 处 barrier 强制
    「双 worker 同时读计数」的确定性竞窗（无锁时两预测同值，后来者必错位）；
    有锁时后到者被临界区挡在 barrier 外——barrier 超时放行（单读者形态，
    预测恒中）。"""

    def __init__(self):
        super().__init__()
        self._n = 100
        self._read_barrier = threading.Barrier(2, timeout=3)

    def zkc_verify(self, case_dir, expected):
        return (0, "verify ok (stub)")

    def next_auth_id(self, **kw):
        import threading as _th

        try:
            self._read_barrier.wait()
        except _th.BrokenBarrierError:
            pass  # 有锁形态：对方被临界区挡住——单读者直接放行
        return self._n + 1

    def chain_record_auth(self, **kw):
        self._n += 1
        return (self._n, "0xseq")


def test_record_auth_lock_mutual_exclusion(tmp_path, monkeypatch):
    """锁单测：两线程临界区零重叠（进出事件严格串行）。"""
    import threading

    from app.zk.record_lock import record_auth_lock

    monkeypatch.setenv("FZ_RECORD_AUTH_LOCK", str(tmp_path / "lock"))
    events: list[tuple[str, str]] = []
    barrier = threading.Barrier(2)

    def worker(name: str) -> None:
        barrier.wait()  # 两线程同时冲锁
        with record_auth_lock():
            events.append(("enter", name))
            _time_mod.sleep(0.12)
            events.append(("exit", name))

    ts = [threading.Thread(target=worker, args=(n,)) for n in "AB"]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=10)
    assert len(events) == 4
    # 严格串行：任一 enter 之后、同名 exit 之前不得出现另一名的 enter
    first, second = events[0][1], "AB".replace(events[0][1], "")
    assert events == [
        ("enter", first),
        ("exit", first),
        ("enter", second),
        ("exit", second),
    ], f"临界区重叠: {events}"


def test_worker_concurrent_record_auth_both_approved(tmp_path, monkeypatch):
    """双 worker 并发排水：两申请全 approved 且 authId 连续不烧授权
    （B-P2-6 验收线——无锁时后来者 auth_id_mismatch 必烧一张授权）。
    并发形态=预分认领+直驱 _process_one（_claim_pending 的 limit 批会让快线程
    独吞两行——竞窗被吞吐差掩盖，历史首版假绿根因）。"""
    from sqlalchemy import create_engine as _ce

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("FZ_RECORD_AUTH_LOCK", str(tmp_path / "lock"))
    eng = _ce(f"sqlite:///{tmp_path / 'concurrent.db'}", connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    maker = sessionmaker(bind=eng, expire_on_commit=False)

    s0 = maker()
    rows = [
        _enqueued(s0, *generate_keypair(), nonce_hex=secrets.token_bytes(16).hex())
        for _ in range(2)
    ]
    for i, r in enumerate(rows):
        r.locked_by = f"w{i + 1}"  # 预分认领——两 worker 各持一行同时处理
    s0.commit()
    s0.close()

    shared_chain = SeqChainWorker()
    results: dict[str, dict] = {}
    barrier = threading.Barrier(2)

    def drive(name: str, row_id: int) -> None:
        s = maker()
        try:
            row = s.get(type(rows[0]), row_id)
            barrier.wait(timeout=10)  # 两 worker 同时进入处理
            st = {"processed": 0, "approved": 0, "rejected": 0, "retried": 0}
            results[name] = w._process_one(s, shared_chain, row, st)
        finally:
            s.close()

    ts = [threading.Thread(target=drive, args=(f"w{i + 1}", r.id)) for i, r in enumerate(rows)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=30)

    total = {"approved": 0, "rejected": 0}
    for _name, st in results.items():
        total["approved"] += st["approved"]
        total["rejected"] += st["rejected"]
    assert total == {"approved": 2, "rejected": 0}, f"并发排水烧授权: {results}"
    # authId 连续且与链上一致（预测恒中——串号防线）
    s1 = maker()
    from sqlalchemy import select as _sel

    recs = s1.scalars(_sel(AuthRecord).order_by(AuthRecord.auth_id)).all()
    assert [r.auth_id for r in recs] == [101, 102]
    s1.close()
