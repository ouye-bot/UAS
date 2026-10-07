"""登录尝试限速落库测试（批 2-2.5①：rate_limit_buckets 多进程失效面）。

覆盖面：
- 行为不变：429 恰第 11 发触发（窗内 10 发过、第 11 发拒、429 不再累计）
- 多会话共享语义：两个独立 Session（=两个副本）同键累计——合计 10 发后
  任一会话的第 11 发=429（落库前各记各账的缺陷面）
- 窗满自动重开；reset（登录成功路径）清桶
- HTTP 面：/auth/challenge 429 恰第 11 发（与 test_accounts 判决行互证）
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.accounts.models import RateLimitBucket
from app.accounts.service import AccountError, auth_limiter
from app.db import get_session
from app.main import create_app
from app.ra.models import Base


@pytest.fixture()
def limiter_db(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/rate_limit_test.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)
    yield TestSession


def test_429_exactly_on_11th_call(limiter_db):
    """行为不变判决行：窗内恰第 11 发=429；429 不再累计（窗满后仍 429）。"""
    S = limiter_db
    s1 = S()
    try:
        k = "challenge|1.2.3.4|u_rl"
        for _i in range(1, 11):
            auth_limiter.check(k, s1)  # 前 10 发全过
        assert s1.query(RateLimitBucket).filter_by(bucket_key=k).one().hits == 10
        with pytest.raises(AccountError) as ei:
            auth_limiter.check(k, s1)  # 恰第 11 发
        assert ei.value.status == 429 and ei.value.code == "rate_limited"
        # 429 不累计：计数仍 10；再打仍 429
        assert s1.query(RateLimitBucket).filter_by(bucket_key=k).one().hits == 10
        with pytest.raises(AccountError):
            auth_limiter.check("challenge|1.2.3.4|u_rl", s1)
    finally:
        s1.close()


def test_two_sessions_share_bucket(limiter_db):
    """多会话共享语义（落库根修的核心判据）：两个独立 Session 同键累计——
    A 会话 6 发 + B 会话 4 发=合计 10 发 → 任一侧第 11 发=429。"""
    S = limiter_db
    key = "login|9.9.9.9|u_share"
    sa, sb = S(), S()
    try:
        for _ in range(6):
            auth_limiter.check(key, sa)
        for _ in range(4):
            auth_limiter.check(key, sb)
        # 两侧行同源（同窗同计数——非各记各账）
        row_a = sa.query(RateLimitBucket).filter_by(bucket_key=key).one()
        assert row_a.hits == 10
        for sess in (sa, sb):
            with pytest.raises(AccountError) as ei:
                auth_limiter.check(key, sess)
            assert ei.value.status == 429
    finally:
        sa.close()
        sb.close()


def test_window_rollover_and_reset(limiter_db, monkeypatch):
    """窗满自动重开（窗口起点前移→计数归 1）；reset（登录成功路径）清桶。"""
    S = limiter_db
    key = "prelogin|5.5.5.5|u_win"
    s = S()
    try:
        for _ in range(10):
            auth_limiter.check(key, s)
        # 人为把窗起点拨回 6 分钟前——下一发重开新窗
        row = s.query(RateLimitBucket).filter_by(bucket_key=key).one()
        row.window_start = dt.datetime.utcnow() - dt.timedelta(seconds=auth_limiter._win + 60)
        s.commit()
        auth_limiter.check(key, s)
        assert s.query(RateLimitBucket).filter_by(bucket_key=key).one().hits == 1
        # reset 清桶
        auth_limiter.reset(key, s)
        assert s.query(RateLimitBucket).filter_by(bucket_key=key).first() is None
        # 清桶后重计（不 429）
        auth_limiter.check(key, s)
    finally:
        s.close()


def test_http_challenge_429_verdict(tmp_path, monkeypatch):
    """HTTP 面（限速经请求会话落库）：/auth/challenge 429 恰第 11 发——
    与 test_accounts 判决行互证（每用例独立库，无进程态串扰）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/rl_http.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)

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

    app = create_app()
    app.dependency_overrides[get_session] = _sess
    with TestClient(app) as c:
        from app.accounts.models import Account

        gen = _sess()
        s = next(gen)
        try:
            s.add(Account(username="u_http_rl", role="pilot", status="pending_profile",
                          pubkey_hex="ab" * 64))
            s.commit()
        finally:
            gen.close()
        codes = [c.post("/auth/challenge/u_http_rl").status_code for _ in range(11)]
        assert codes[:10] == [200] * 10
        assert codes[10] == 429
