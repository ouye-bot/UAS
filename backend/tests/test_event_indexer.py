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


def test_scan_bounds_seeds_from_legacy_when_no_cursor_row(monkeypatch):
    """无持久化游标行时按旧语义种子（事件行 max+1；空表=部署块）。"""
    from app.telemetry.indexer import scan_bounds

    s = _session()
    monkeypatch.setattr("app.telemetry.indexer._deploy_block", lambda: 100)
    assert scan_bounds(s, head=1200, max_blocks=500) == (100, 599), "空库种子=部署块"
    index_events(
        s,
        fetch_block_txs=lambda b: {100: [{"hash": "0xtx1", "to": ANCHOR}]}.get(b, []),
        decode_tx=_decode,
        start=100,
        end=100,
        anchor_address=ANCHOR,
    )
    assert scan_bounds(s, head=1200, max_blocks=500) == (101, 600), "有行种子=max(block)+1"


def test_cursor_crosses_eventless_stall():
    """停摆缺陷回归（2026-10-12 验收批实测）：事件稀疏段>单轮扫描窗时，
    旧游标（=max(block)+1）永远无法跨越空窗 ⟹ 索引器永久停摆。根修后
    游标=持久化扫描位——扫描过即推进，第二轮必须够到空窗之后的合约事件。"""
    from app.telemetry.indexer import advance_cursor, scan_bounds

    s = _session()
    blocks = {100: [{"hash": "0xtx1", "to": ANCHOR}], 700: [{"hash": "0xtx3", "to": ANCHOR}]}
    fetch = lambda b: blocks.get(b, [])  # noqa: E731
    index_events(
        s, fetch_block_txs=fetch, decode_tx=_decode, start=100, end=100, anchor_address=ANCHOR
    )
    # 旧形态：next_cursor 恒=101——扫描窗 500 永远到不了 700 ⟹ 停摆
    # 新形态：第一轮扫 [101,600]（空窗）后游标推进到 600，第二轮够到 700
    b1 = scan_bounds(s, head=1200, max_blocks=500)
    assert b1 == (101, 600)
    n1 = index_events(
        s, fetch_block_txs=fetch, decode_tx=_decode, start=b1[0], end=b1[1], anchor_address=ANCHOR
    )
    advance_cursor(s, b1[1])
    assert n1 == 0, "空窗无事件"
    b2 = scan_bounds(s, head=1200, max_blocks=500)
    assert b2 == (601, 1100), "游标已跨越空窗（旧形态此处恒=101——停摆定谳）"
    n2 = index_events(
        s, fetch_block_txs=fetch, decode_tx=_decode, start=b2[0], end=b2[1], anchor_address=ANCHOR
    )
    advance_cursor(s, b2[1])
    assert n2 == 1, "空窗后事件第二轮必达"
    rows = s.scalars(select(ChainEventRow)).all()
    assert sorted(r.block for r in rows) == [100, 700]


def test_advance_cursor_monotonic_upsert():
    """游标单行 upsert 且只前进（乱序调用不回退）。"""
    from app.telemetry.indexer import advance_cursor, scan_bounds

    s = _session()
    advance_cursor(s, 500)
    advance_cursor(s, 400)  # 乱序回拨调用
    b = scan_bounds(s, head=2000, max_blocks=500)
    assert b == (501, 1000), "游标单调只前进"
    from app.telemetry.models import IndexerCursor

    assert len(s.scalars(select(IndexerCursor)).all()) == 1, "单行形态"
