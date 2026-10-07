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


class CapturingWorker(OkWorker):
    """捕获 expected 的替身（绑定挑战同源断言位）。"""

    def __init__(self):
        super().__init__()
        self.seen: dict | None = None

    def zkc_verify(self, case_dir, expected):
        self.seen = dict(expected)
        return (0, "verify ok (stub)")


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
    from conftest import seed_sn_chain

    seed_sn_chain(session, msg, b"FZ-SN-W")
    inst = ["0" * 64] * 26
    inst[25] = _fe_be32_hex_from_bytes32(_sm3(b"FZ-SN-W"))  # SN 绑定换代：实例 25
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
    # A2：plan_hash 在场；⑥代 SN 绑定（2026-10-06）：serial 原文仍零明文入令牌
    # （零设备明文口径保持），sn_hash=服务端权威 SM3(serial) 全 32B 入载荷
    # （engine 签名域覆盖——桥第 6 查消费同一字段）。
    assert tok["plan_hash"] == "ab" * 32
    assert tok["alt_max"] == 120  # class 1 轻型条例数值
    assert tok["authId"] == 7
    assert "sn" not in tok
    from app.crypto.sm3 import sm3_bytes as _sm3b

    assert tok["sn_hash"] == _sm3b(b"FZ-SN-W").hex(), "sn_hash=服务端权威 SM3(serial)"
    # 令牌签名可验（engine 公钥）
    from app.crypto.sm2 import verify_digest
    from app.crypto.sm3 import sm3_bytes

    _esk, epub = engine_signing_keypair()
    assert verify_digest(epub, sm3_bytes(body), sig.decode())


def test_worker_verdict_expected_carries_exp_u(session, tmp_path):
    """S6 闭环归档（2026-10-04）：判决件 expected.exp_u 在场——第三方拿到判决件
    即可自行核对「凭证有效期覆盖授权窗」（exp_u ≥ t_end；t_end 经链上
    recordAuth/getAuth 记录同源可得）。exp_u 源=受理面从已验签 M_A′[160:164]
    解出落库（applications.exp_u）。"""
    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()
    stats = w.process_pending(session, OkWorker())
    assert stats["approved"] == 1
    vpath = Path(tmp_path) / "verdicts" / f"app-{row.id}.verdict.json"
    verdict = json.loads(vpath.read_text(encoding="utf-8"))
    assert verdict["expected"]["exp_u"] == 1900000000  # _enqueued 夹具的签发效期


def test_worker_verdict_carries_anchor_mode(session, tmp_path):
    """批 4-3 档位显式化：判决件顶层自述链锚档（mode=fake/real）——第三方核对
    「这份授权登记是否落真链」不必猜档（fake 档 tx="fake" 形态同源可辨）。"""
    import os as _os

    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()
    assert w.process_pending(session, OkWorker())["approved"] == 1
    vpath = Path(tmp_path) / "verdicts" / f"app-{row.id}.verdict.json"
    verdict = json.loads(vpath.read_text(encoding="utf-8"))
    want = "fake" if _os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake" else "real"
    assert verdict["mode"] == want


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


def test_gate_stores_pinned_binding_challenge(session):
    """2026-10-07 prove 窗根修：受理门把⑤钉实例 19 用的同一 challenge_hex 落库
    （applications.challenge_hex）——复验与验证同源的唯一权威源。"""
    from app.authz.service import binding_challenge

    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk, nonce_hex="33" * 16)
    assert row.challenge_hex == binding_challenge("ab" * 32, "33" * 16), (
        "受理行必须携带门⑤现算并钉实例的挑战快照"
    )


def test_worker_consumes_stored_challenge_under_key_drift(session, tmp_path, monkeypatch):
    """钥漂移根修回归（e2e_auth_full ⑥ 实弹）：challenge_hex 是钥控 HMAC 值——
    受理（门⑤）与复验（worker）两进程 FZ_AUTHZ_BINDING_KEY 漂移时，worker 按
    env 重建必得不同挑战 ⟹ 实例 19 假拒（proof 本身有效）。现 worker 消费受理
    落库值：漂移场景下 expected.challenge_hex 仍=门⑤钉定值，复验不假拒。"""
    from app.authz.service import binding_challenge

    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()
    pinned = row.challenge_hex
    assert pinned == binding_challenge("ab" * 32, "11" * 16)
    # 模拟 worker 进程 env 钥漂移（部署方换钥/未注入——真案卷假拒的实弹形态）
    monkeypatch.setenv("FZ_AUTHZ_BINDING_KEY", secrets.token_hex(32))
    drifted = binding_challenge("ab" * 32, "11" * 16)
    assert drifted != pinned, "夹具预检：换钥后重建值必须不同（漂移成立）"

    worker = CapturingWorker()
    stats = w.process_pending(session, worker)
    assert stats["approved"] == 1, "钥漂移不得再假拒真案卷"
    assert worker.seen["challenge_hex"] == pinned, (
        "worker 必须消费受理落库的钉定挑战，不得按本进程 env 重建"
    )


def test_worker_legacy_row_challenge_fallback_recompute(session, tmp_path):
    """历史行（0024 迁移前，challenge_hex=""）回落旧重建式——语义=改动前唯一
    路径，迁移桥不放松任何核对（新行恒走落库值）。"""
    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()
    row.challenge_hex = ""  # 历史行形态
    session.commit()

    from app.authz.service import binding_challenge

    worker = CapturingWorker()
    stats = w.process_pending(session, worker)
    assert stats["approved"] == 1
    assert worker.seen["challenge_hex"] == binding_challenge("ab" * 32, "11" * 16)


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
    """getAuth 回读替身：echo 闸门写入的记录（match）或全零（mismatch）。

    12 元组（授权包配额制 2026-10-06：末位 remaining——worker 读后写对拍
    含配额一致性 rec[11]==登记架次数）。"""

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
                int(k.get("sorties", 1)),
            ]
        return [b"\x00" * 32] * 8 + [0, 0, 0, 0]


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


# ---- 授权包配额制（2026-10-06 多架次拍板）：worker 透传与配额落库 ----


def test_worker_sorties_passthrough_and_quota_ledger(session, tmp_path, monkeypatch):
    """sorties 透传链写 + 配额账本落库：申请行 sorties=3 → recordAuth kw 带
    sorties=3；approved 后 auth_records.remaining=3（消费回报递减起点）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    row = _enqueued(session, *generate_keypair())
    row.sorties = 3
    session.commit()
    worker = ReadbackWorker(match=True)
    stats = w.process_pending(session, worker)
    assert stats["approved"] == 1
    assert worker.binding.captured["sorties"] == 3, "recordAuth 配额参数透传"
    from sqlalchemy import select

    from app.authz.models import AuthRecord

    rec = session.scalar(select(AuthRecord).where(AuthRecord.application_id == row.id))
    assert rec is not None and rec.sorties == 3 and rec.remaining == 3


def test_worker_sorties_default_one(session, tmp_path, monkeypatch):
    """缺省配额 1 等价：申请未申报 sorties → recordAuth kw sorties=1，
    auth_records.remaining=1（与令牌一次性历史语义逐字等价）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    row = _enqueued(session, *generate_keypair())
    assert row.sorties == 1, "admission_gate 缺省配额=1"
    worker = ReadbackWorker(match=True)
    stats = w.process_pending(session, worker)
    assert stats["approved"] == 1
    assert worker.binding.captured["sorties"] == 1
    from sqlalchemy import select

    from app.authz.models import AuthRecord

    rec = session.scalar(select(AuthRecord).where(AuthRecord.application_id == row.id))
    assert rec is not None and rec.sorties == 1 and rec.remaining == 1


def test_gate_sorties_out_of_range_rejected(session):
    """配额形检（fail-closed）：0/6 越界=400 bad_sorties（1~5 合法域）。
    形检位于门控序最前——先于全部材料/链面检查。"""
    import pytest

    from app.authz.service import AuthzError, admission_gate

    for bad in (0, 6):
        _sk, pk = generate_keypair()
        with pytest.raises(AuthzError) as ei:
            admission_gate(
                session,
                GateDeps(),
                session_pk_hex=pk,
                sub_cred_message_hex="",
                sub_sig_hex="",
                sub_cred_hash_hex="ff" * 32,
                nonce_hex="22" * 16,
                plan_hash_hex="ab" * 32,
                class_id=1,
                proof_path="x",
                spec_path="x",
                rev_root_hex="00" * 32,
                sorties=bad,
            )
        assert ei.value.code == "bad_sorties"


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


def test_worker_canonical_sanitized_for_forbid_gate(tmp_path, monkeypatch):
    """2026-10-06 prove 窗根修回归：FORBID=1 下 worker 须用「脱敏 canonical 副本
    +env 钥」拼 zkc 环境——真案卷复验不再被装配禁令误拒（e2e_auth_full ⑥ 实弹
    抓出的批 4 漏洞：禁令=spec 文件出现明文钥即拒，env 在场不豁免）。"""
    import json as _json
    import os as _os

    import app.zk.worker as w

    zksvc = tmp_path / "zksvc"
    exe = zksvc / "target" / "release" / "zkc.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")  # 存在性哨（真 zkc 不跑——subprocess 打桩）
    canonical = zksvc / "tests" / "auth_canonical_spec.json"
    canonical.parent.mkdir(parents=True)
    canonical.write_text(_json.dumps({
        "profile": "auth", "reps": 16, "log_rate": 1,
        "binding": {"challenge_hex": "ff" * 32},
        "input": {"kind": "auth", "holder_sk_hex": "ab" * 32,
                  "holder_pk_hex": "cd" * 64, "sig_hex": "ef" * 64},
    }), encoding="utf-8")
    (tmp_path / "instances.json").write_text("{}", encoding="utf-8")

    captured: dict = {}

    def _fake_run(cmd, **k):
        captured.update(k.get("env") or {})
        _san = (k.get("env") or {}).get("FZ_AUTH_CANONICAL_SPEC", "")
        if _san:  # 调用时点快照（finally 焚毁后不可读）
            with open(_san, encoding="utf-8") as _f:
                captured["_san_content"] = _f.read()

        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()

    monkeypatch.setattr(w.subprocess, "run", _fake_run)
    monkeypatch.setenv("FZ_ZK_FORBID_SPEC_KEY", "1")

    wd = w.WorkerDeps()
    wd.zksvc_dir = str(zksvc)
    rc, _ = wd.zkc_verify(str(tmp_path), {"instances": ["11"] * 26})
    assert rc == 0
    san = captured.get("FZ_AUTH_CANONICAL_SPEC", "")
    assert san and san != str(canonical), "必须指向脱敏副本而非仓内原件"
    assert captured.get("FZ_ZK_HOLDER_SK_HEX") == "ab" * 32, "夹具钥必须走 env"
    assert _json.loads(captured["_san_content"])["input"]["holder_sk_hex"] == "",         "副本必须零私钥字节"
    assert not _os.path.exists(san), "脱敏副本须用毕即焚"
