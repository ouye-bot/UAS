"""worker 租约心跳测试（2026-10-04 worker 扩展前置批）。

- 缺省租约 1200s→90s（心跳承担 R3-1.1 的 ≥2×verify 语义）
- _renew_leases：只续本 worker 名下 pending 行；终态/被接管=0 行（心跳自停判据）
- 心跳存续 ⟹ 长 verify 期间租约不过期；心跳停止 ⟹ 接管窗 ~90s
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz.models import Application
from app.crypto.sm2 import generate_keypair
from app.ra.models import Base
from app.zk import worker as w


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _enqueued(session):
    from test_authz_worker import _enqueued as _e

    sk, pk = generate_keypair()
    row = _e(session, sk, pk)
    session.commit()
    return row


def test_default_lease_90s(monkeypatch):
    monkeypatch.delenv("FZ_WORKER_LEASE_S", raising=False)
    assert w._lease_seconds() == 90, "接管窗 1200s→90s（心跳批缺省）"
    monkeypatch.setenv("FZ_WORKER_LEASE_HEARTBEAT_S", "60")
    assert w._lease_heartbeat_interval_s() == 60
    assert w._lease_heartbeat_interval_s() < w._lease_seconds(), "心跳周期须小于租约"


def test_renew_leases_only_own_pending(session):
    row = _enqueued(session)
    w._claim_pending(session, "w1", limit=4)
    assert w._renew_leases(session, "w1", [row.id]) == 1
    first = session.get(Application, row.id).locked_at
    assert w._renew_leases(session, "w1", [row.id]) == 1
    second = session.get(Application, row.id).locked_at
    assert second >= first, "续期推进 locked_at"
    # 他人名下=0（不碰别人租约）
    assert w._renew_leases(session, "w2", [row.id]) == 0
    # 终态=0（心跳使命结束判据）
    r = session.get(Application, row.id)
    r.status = "approved"
    session.commit()
    assert w._renew_leases(session, "w1", [row.id]) == 0


def test_heartbeat_keeps_lease_alive_against_takeover(session, monkeypatch):
    """长 verify 场景：认领后 3 个心跳周期（模拟 3 分钟 verify），租约仍新——
    其他 worker 不可接手；心跳停止且过窗 ⟹ 可接手（接管窗验证）。"""
    monkeypatch.delenv("FZ_WORKER_LEASE_S", raising=False)
    row = _enqueued(session)
    claimed = w._claim_pending(session, "w1", limit=4)
    assert len(claimed) == 1
    for _ in range(3):
        assert w._renew_leases(session, "w1", [row.id]) == 1
        # 人工把时钟推进到「距上次心跳 60s」（< 租约 90s）
        r = session.get(Application, row.id)
        r.locked_at = dt.datetime.utcnow() - dt.timedelta(seconds=60)
        session.commit()
        assert w._claim_pending(session, "w2", limit=4) == [], "心跳存续=不可接手"
    # 心跳停止：locked_at 静止，过租约窗 ⟹ w2 接手（接管窗 ~90s 语义）
    r = session.get(Application, row.id)
    r.locked_at = dt.datetime.utcnow() - dt.timedelta(seconds=w._lease_seconds() + 1)
    session.commit()
    taken = w._claim_pending(session, "w2", limit=4)
    assert len(taken) == 1 and taken[0].locked_by == "w2", "心跳停止过窗=接手"
