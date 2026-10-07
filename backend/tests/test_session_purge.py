"""WebSession 过期回收测试（2026-10-04 worker 扩展前置批）。

启动钩 purge_expired_sessions：只删 expires_ts 已过的行；有效期内的
（含未来的）一律保留——登出/会话校验语义不变。
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.accounts.models import WebSession
from app.accounts.service import purge_expired_sessions
from app.ra.models import Base


def _session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def test_purge_expired_keeps_valid():
    s = _session()
    now = dt.datetime.utcnow()
    s.add(
        WebSession(
            token_hash_hex="a" * 64,
            username="u1",
            role="pilot",
            created_ts=now - dt.timedelta(hours=3),
            expires_ts=now - dt.timedelta(hours=1),
        )
    )  # 过期
    s.add(
        WebSession(
            token_hash_hex="b" * 64,
            username="u2",
            role="pilot",
            created_ts=now,
            expires_ts=now + dt.timedelta(hours=1),
        )
    )  # 有效
    s.add(
        WebSession(
            token_hash_hex="c" * 64,
            username="u3",
            role="admin",
            created_ts=now,
            expires_ts=now + dt.timedelta(days=7),
        )
    )  # 有效
    s.commit()
    n = purge_expired_sessions(s)
    assert n == 1, "只回收过期行"
    left = {r.token_hash_hex[0] for r in s.execute(select(WebSession)).scalars()}
    assert left == {"b", "c"}, "有效会话保留"
    assert purge_expired_sessions(s) == 0, "幂等"
