"""批 4-7 挑战过期清理卫生件测试：正确清理 + 单条索引范围批量 DELETE。

旧形态=逐行载入（SELECT 全表）+逐行 DELETE——每请求全表扫；现形态=单条
DELETE ... WHERE created_ts < cutoff（ix_auth_challenges_created_ts·0017 承载）。
「不再全表扫」以语句计数断言钉定：issue_challenge 期间触达 auth_challenges 的
语句必须恰为一条 DELETE、零 SELECT。
"""

from __future__ import annotations

import datetime as dt
import secrets

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.accounts import service as svc
from app.accounts.models import Account, AuthChallenge
from app.ra.models import Base


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _account(session, username: str) -> None:
    session.add(
        Account(
            username=username,
            role="pilot",
            status="active",
            pubkey_hex="ab" * 64,
            sealed_blob="{}",
        )
    )
    session.commit()


def _seed_stale(session, username: str, age_s: int) -> str:
    nonce = secrets.token_hex(32)
    row = AuthChallenge(nonce_hex=nonce, username=username)
    row.created_ts = dt.datetime.utcnow() - dt.timedelta(seconds=age_s)
    session.add(row)
    session.commit()
    return nonce


def test_expired_challenges_purged_and_fresh_kept(session):
    """正确性：过期行（>TTL×10）清、TTL 内行与新挑战保留。"""
    _account(session, "u1")
    stale1 = _seed_stale(session, "u1", 100_000)
    stale2 = _seed_stale(session, "u1", 1_300)
    fresh = _seed_stale(session, "u1", 60)
    nonce = svc.issue_challenge(session, "u1")
    rows = session.execute(select(AuthChallenge)).scalars().all()
    nonces = {r.nonce_hex for r in rows}
    assert nonce in nonces and fresh in nonces
    assert stale1 not in nonces and stale2 not in nonces
    assert len(nonces) == 2


def test_cleanup_is_single_indexed_delete_no_scan(session):
    """不再全表扫：issue_challenge 期间触达 auth_challenges 的语句=恰一条
    DELETE（索引范围批量删）、零 SELECT（旧形态=SELECT 全表+N 条逐行 DELETE）。"""
    _account(session, "u2")
    _seed_stale(session, "u2", 100_000)
    _seed_stale(session, "u2", 100_000)
    stmts: list[str] = []

    def _track(_conn, _cursor, statement, _params, _ctx, _many):
        stmts.append(" ".join(statement.lower().split()))

    eng = session.get_bind()
    event.listen(eng, "before_cursor_execute", _track)
    try:
        svc.issue_challenge(session, "u2")
    finally:
        event.remove(eng, "before_cursor_execute", _track)
    touched = [s for s in stmts if "auth_challenges" in s]
    deletes = [s for s in touched if s.startswith("delete")]
    selects = [s for s in touched if s.startswith("select")]
    assert len(deletes) == 1, touched
    assert deletes[0].startswith("delete from auth_challenges")
    assert not selects, f"仍存在对 auth_challenges 的查询（全表扫未根除）: {selects}"
