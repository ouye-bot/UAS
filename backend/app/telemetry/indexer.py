"""事件索引器（P1-C3）：链上 EventRecorded→chain_events 投影。

核心 index_events 可注入（fetch_block_txs/decode_tx 替身位）；服务侧
run_indexer_once 用真实链客户端（块扫描过滤锚定合约 to 地址→receipt 解码）。
幂等：同（tx,block,auth,eventType,eventHash）不重复插入；游标=max(block)+1。
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.telemetry.models import ChainEvent


def index_events(
    session: Session,
    *,
    fetch_block_txs: Callable[[int], list[dict]],
    decode_tx: Callable[[str], list[dict]],
    start: int,
    end: int,
    anchor_address: str,
) -> int:
    """扫描 [start, end] 块区间，落库锚定合约事件。返回新插入行数。"""
    inserted = 0
    seen_rows = session.execute(
        select(
            ChainEvent.tx_hash,
            ChainEvent.block,
            ChainEvent.auth_id,
            ChainEvent.event_type,
            ChainEvent.event_hash_hex,
        )
    ).all()
    seen_keys = {(tx, int(block), int(aid), int(et), eh) for tx, block, aid, et, eh in seen_rows}
    for block in range(start, end + 1):
        for tx in fetch_block_txs(block):
            if str(tx.get("to", "")).lower() != anchor_address.lower():
                continue
            for ev in decode_tx(tx["hash"]):
                if ev.get("event") != "EventRecorded":
                    continue
                key = (
                    tx["hash"],
                    block,
                    int(ev["authId"]),
                    int(ev["eventType"]),
                    bytes(ev["eventHash"]).hex(),
                )
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                session.add(
                    ChainEvent(
                        auth_id=int(ev["authId"]),
                        event_type=int(ev["eventType"]),
                        event_hash_hex=bytes(ev["eventHash"]).hex(),
                        block=block,
                        tx_hash=tx["hash"],
                    )
                )
                inserted += 1
    session.commit()
    return inserted


def next_cursor(session: Session) -> int:
    """游标=已索引最大块+1；空表=合约部署块（TelemetryAnchor.address.block）。"""
    from sqlalchemy import func

    from app.telemetry.models import ChainEvent as CE

    max_b = session.scalar(select(func.max(CE.block)))
    return int(max_b or 0) + 1 if max_b is not None else _deploy_block()


def _deploy_block() -> int:
    addr = json.loads(
        (Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json").read_text()
    )
    return int(addr["TelemetryAnchor"]["block"])


def run_indexer_once(session: Session, *, max_blocks: int = 500) -> int:
    """服务侧一轮增量索引（真实链客户端）。"""
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_ra_tx_key

    addresses = json.loads(
        (Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json").read_text()
    )
    signer = TxSigner(chain_ra_tx_key())
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=signer.address,
    )
    anchor = load_binding("TelemetryAnchor", client, addresses["TelemetryAnchor"]["address"])

    def fetch_block_txs(block: int) -> list[dict]:
        blk = client.get_block_by_number(block, include_txs=True)
        if not blk:
            return []
        txs = blk.get("transactions") or []
        return [{"hash": t.get("hash", ""), "to": t.get("to", "")} for t in txs]

    def decode_tx(tx_hash: str) -> list[dict]:
        receipt = client.get_tx_receipt(tx_hash)
        if not receipt:
            return []
        return anchor.decode_logs(receipt)

    start = next_cursor(session)
    end = min(start + max_blocks - 1, client.block_number())
    if end < start:
        return 0
    return index_events(
        session,
        fetch_block_txs=fetch_block_txs,
        decode_tx=decode_tx,
        start=start,
        end=end,
        anchor_address=addresses["TelemetryAnchor"]["address"],
    )


def start_background_indexer(interval_s: float = 10.0) -> None:
    """真链档守护线程（create_app 挂载——幂等，进程内只起一次）。"""
    global _indexer_started
    if _indexer_started:
        return
    _indexer_started = True

    def loop() -> None:
        from app.db import SessionLocal

        while True:
            s = SessionLocal()
            try:
                run_indexer_once(s)
            except Exception as e:  # noqa: BLE001  链抖动/未就绪——下一轮重试
                print(f"[indexer] 增量索引失败（下轮重试）: {e}", flush=True)
            finally:
                s.close()
            time.sleep(interval_s)

    threading.Thread(target=loop, daemon=True, name="fz-event-indexer").start()


_indexer_started = False
