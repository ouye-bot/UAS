"""P1-C3 事件索引器测试：链上 EventRecorded→chain_events 投影（可注入核心）。

- 正例：块内锚定合约交易的事件解码落库（authId/eventType/eventHash/block/tx）
- 游标：起始=已有 max(block)+1；重复扫描幂等（不重复插入）
- 过滤：非锚定合约地址的交易不产生事件行
"""

from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.authz.models import AuthRecord  # noqa: F401 ——元数据注册顺序
from app.ra.models import Base
from app.telemetry.indexer import index_events

ANCHOR = "0x" + "55" * 20


def _session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _blocks():
    return {
        100: [{"hash": "0xtx1", "to": ANCHOR}],
        101: [{"hash": "0xtx2", "to": "0x" + "99" * 20}],  # 非锚定合约
        102: [{"hash": "0xtx3", "to": ANCHOR}],
    }


def _decode(tx_hash: str) -> list[dict]:
    if tx_hash == "0xtx1":
        return [{"event": "EventRecorded", "authId": 7, "eventType": 1, "eventHash": b"\x01" * 32}]
    if tx_hash == "0xtx3":
        return [{"event": "EventRecorded", "authId": 7, "eventType": 2, "eventHash": b"\x02" * 32}]
    return []


def test_index_and_cursor():
    s = _session()
    blocks = _blocks()
    n = index_events(
        s,
        fetch_block_txs=lambda b: blocks.get(b, []),
        decode_tx=_decode,
        start=100,
        end=102,
        anchor_address=ANCHOR,
    )
    assert n == 2, "两条锚定合约事件落库"
    rows = s.scalars(select(ChainEventRow)).all()
    assert sorted((r.block, r.event_type) for r in rows) == [(100, 1), (102, 2)]
    # 幂等：同区间重扫不重复
    n2 = index_events(
        s,
        fetch_block_txs=lambda b: blocks.get(b, []),
        decode_tx=_decode,
        start=100,
        end=102,
        anchor_address=ANCHOR,
    )
    assert n2 == 0 and len(s.scalars(select(ChainEventRow)).all()) == 2


def test_cursor_start_from_max_block():
    s = _session()
    blocks = _blocks()
    index_events(
        s,
        fetch_block_txs=lambda b: blocks.get(b, []),
        decode_tx=_decode,
        start=100,
        end=100,
        anchor_address=ANCHOR,
    )
    nxt = next_cursor(s)
    assert nxt == 101, "游标=已索引最大块+1"


from app.telemetry.indexer import next_cursor  # noqa: E402
from app.telemetry.models import ChainEvent as ChainEventRow  # noqa: E402


def test_seen_set_windowed_near_cursor(monkeypatch):
    """seen 集合近窗（2026-10-04 内存线性涨根治）：只回看游标前
    FZ_INDEXER_SEEN_BACK_BLOCKS 块。去重键含 block——跨块本就不可能同键，
    seen 集合只在「同块重扫」时生效（增量索引游标只前进，重扫仅发生在游标
    附近=必在窗内）⟹ 近窗对一切可达路径语义零变化，内存不再随 chain_events
    线性涨。"""
    monkeypatch.setenv("FZ_INDEXER_SEEN_BACK_BLOCKS", "10")
    from app.telemetry.indexer import _seen_back_blocks

    assert _seen_back_blocks() == 10
    s = _session()
    blocks = {100: [{"hash": "0xtx1", "to": ANCHOR}]}
    index_events(
        s,
        fetch_block_txs=lambda b: blocks.get(b, []),
        decode_tx=_decode,
        start=100,
        end=100,
        anchor_address=ANCHOR,
    )
    # 窗内同块重扫：幂等（去重仍生效——窗必覆盖游标附近的重扫面）
    n2 = index_events(
        s,
        fetch_block_txs=lambda b: blocks.get(b, []),
        decode_tx=_decode,
        start=100,
        end=100,
        anchor_address=ANCHOR,
    )
    assert n2 == 0 and len(s.scalars(select(ChainEventRow)).all()) == 1
    monkeypatch.delenv("FZ_INDEXER_SEEN_BACK_BLOCKS")
    assert _seen_back_blocks() == 10000, "缺省近窗宽=10000 块"
