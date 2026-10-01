"""P0-2 worker 队列语义测试：认领互斥/租约回收/瞬时重试/终态拒绝。

- 认领互斥：W1 认领后 W2 同轮必须拿不到同一申请（防双处理）
- 租约回收：locked_at 超过租约的孤儿申请可被其他 worker 接手（kill -9 场景）
- 瞬时重试：链写异常→attempts+1+释放租约+保持 pending；连续超限→rejected+回执 failed
- 终态拒绝：zkc verify 失败=最终 rejected（attempts 不动，非重试轴）
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz.models import Application, Receipt
from app.crypto.sm2 import generate_keypair
from app.ra.models import Base
from app.zk import worker as w

_NOW = 1790000000


@pytest.fixture()
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _enqueue_one(session) -> Application:
    """入队一条合法申请（复用 test_authz_worker 的 _enqueued 全形态）。"""
    from test_authz_worker import _enqueued

    sk, pk = generate_keypair()
    row = _enqueued(session, sk, pk)
    session.commit()
    return row


def test_claim_exclusive(session):
    """W1 认领后 W2 同轮必须拿空（现轮询代码无认领→红）。"""
    _enqueue_one(session)
    r1 = w._claim_pending(session, "w1", limit=4)
    r2 = w._claim_pending(session, "w2", limit=4)
    assert len(r1) == 1 and r1[0].locked_by == "w1"
    assert r2 == [], "W2 拿到 W1 已认领的申请（双处理风险）"


def test_claim_lease_expiry_reclaim(session, monkeypatch):
    """孤儿申请（租约过期）可被其他 worker 接手。"""
    import datetime as dt

    _enqueue_one(session)
    r1 = w._claim_pending(session, "w1", limit=4)
    assert len(r1) == 1
    # 模拟 w1 崩溃：租约时间回拨到过期
    row = session.get(Application, r1[0].id)
    row.locked_at = dt.datetime.utcnow() - dt.timedelta(seconds=w._lease_seconds() + 1)
    session.commit()
    r2 = w._claim_pending(session, "w2", limit=4)
    assert len(r2) == 1 and r2[0].locked_by == "w2", "过期租约未被回收"


class FlakyChainWorker(w.WorkerDeps):
    """链写每次都炸（模拟链抖动）。"""

    def zkc_verify(self, case_dir, expected):
        return (0, "verify ok (stub)")

    def next_auth_id(self, **kw):
        return 7

    def chain_record_auth(self, **kw):
        raise RuntimeError("链抖动（模拟）")


class OkChainWorker(w.WorkerDeps):
    def zkc_verify(self, case_dir, expected):
        return (0, "verify ok (stub)")

    def next_auth_id(self, **kw):
        return 7

    def chain_record_auth(self, **kw):
        return (7, "0xtx-ok")


def test_transient_retry_then_fail(session, monkeypatch):
    """链写异常→attempts+1+释放租约+保持 pending；超限→rejected+回执 failed。"""
    monkeypatch.setattr(w, "_max_attempts", lambda: 2)
    row = _enqueue_one(session)
    # 第一轮：链炸 → 重试态
    stats1 = w.process_pending(session, FlakyChainWorker())
    session.refresh(row)
    assert stats1["retried"] == 1 and stats1["rejected"] == 0
    assert row.status == "pending" and row.attempts == 1
    assert row.locked_by is None, "重试态未释放租约（其他 worker 无法接手）"
    r = session.get(Receipt, row.receipt_id)
    assert r.status == "waiting", "重试态回执不应终态化"
    # 第二轮：仍炸 → 超限终态
    stats2 = w.process_pending(session, FlakyChainWorker())
    session.refresh(row)
    assert stats2["rejected"] == 1
    assert row.status == "rejected" and "transient" in (row.reject_reason or "")
    r = session.get(Receipt, row.receipt_id)
    assert r.status == "failed"


def test_verify_reject_is_final(session):
    """zkc verify 失败=最终 rejected（非重试轴——证明无效不是临时错误）。"""
    from test_authz_worker import FailWorker  # noqa: F401  确认可导入

    row = _enqueue_one(session)

    class RejectWorker(OkChainWorker):
        def zkc_verify(self, case_dir, expected):
            return (2, "InvalidSnark: sumcheck mismatch (stub)")

    stats = w.process_pending(session, RejectWorker())
    session.refresh(row)
    assert stats["rejected"] == 1 and stats["retried"] == 0
    assert row.status == "rejected" and "exit 2" in row.reject_reason
    assert row.attempts == 0, "终态拒绝不应消耗重试计数"


def test_approve_releases_lease(session):
    """批准终态清空租约字段（表整洁——pending 池只含未决）。"""
    row = _enqueue_one(session)
    w.process_pending(session, OkChainWorker())
    session.refresh(row)
    assert row.status == "approved" and row.locked_by is None and row.locked_at is None
