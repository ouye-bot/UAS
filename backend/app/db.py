"""DB 基座（B2：SQLite 演示形态——B2-d1 诚实分账；SQLAlchemy 同构可升 PG）。"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# S5：FZ_DB_URL 优先（生产=PostgreSQL：postgresql+psycopg://…；演示=缺省 SQLite
# 文件）。SQLAlchemy/alembic 已抽象——切换不改业务代码。
_DB_URL = os.environ.get("FZ_DB_URL", "")
_DB_PATH = Path(__file__).resolve().parent.parent / "feizheng.db"
_engine = create_engine(_DB_URL or f"sqlite:///{_DB_PATH}", echo=False, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)


def db_url() -> str:
    """当前生效连接串（alembic env.py 消费——P0-1 修复：曾写死 SQLite 路径无视
    FZ_DB_URL，导致"引擎切换、迁移不切"的半切换态）。"""
    return _DB_URL or f"sqlite:///{_DB_PATH}"


def get_session() -> Iterator[Session]:
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
