"""撤销纪元根对账（P0-5）：本地吊销集 SMT 根 vs 链公示根的自愈仪式。

问题形态（阶段一定谳）：链上 revRoot 初始 0x00*32 / 烟测随机根残留，与 RA 镜像
空树根不同源 ⟹ 受理门控④全拒。本模块把脚本仪式（scripts/align_rev_root.py）
核心上移为服务能力：真链档 RA deps 初始化时对账一次，不一致即推链（epoch+1
单调合法），一致即零交易幂等——RA 启动自愈，不再依赖人工。

边界：本地吊销集为权威（推链方向固定 本地→链）；链不可达不阻塞服务启动
（首次锚定写面失败会诚实暴露）。
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable

from app.crypto.sm3 import sm3_bytes  # noqa: F401  （空树根口径与 smt_root 同源见证）


def align_rev_root_core(
    *,
    handles: list[bytes],
    epoch_fn: Callable[[], int],
    root_fn: Callable[[], bytes],
    push_fn: Callable[[int, bytes], None],
) -> dict:
    """对账核心（注入面——测试替身位）。

    handles=本地吊销集句柄；epoch_fn/root_fn=链上公示读取；push_fn=推链动作。
    返回 {"aligned": 最终一致, "pushed": 是否发生推链, "epoch": 现行纪元}。
    """
    from app.ra.smt import smt_root

    local_root = smt_root(handles)
    chain_root = bytes(root_fn())
    if chain_root == local_root:
        return {"aligned": True, "pushed": False, "epoch": int(epoch_fn())}
    new_epoch = int(epoch_fn()) + 1
    push_fn(new_epoch, local_root)
    return {"aligned": True, "pushed": True, "epoch": new_epoch}


def startup_align() -> dict:
    """服务侧对账（真链档 RA deps 初始化钩子消费——真实链客户端+RA 库）。"""
    from sqlalchemy import select

    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.db import SessionLocal
    from app.kms import chain_ra_tx_key
    from app.ra.models import Revocation

    s = SessionLocal()
    try:
        handles = [bytes.fromhex(r.handle_hex) for r in s.scalars(select(Revocation)).all()]
    finally:
        s.close()
    addresses = _chain_addresses()
    signer = TxSigner(chain_ra_tx_key())
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=signer.address,
    )
    ir = load_binding("IdentityRegistry", client, addresses["IdentityRegistry"]["address"])

    def push_fn(epoch: int, root: bytes) -> None:
        ir.send_fn(signer, "setRevocationRoot", [epoch, root])

    return align_rev_root_core(
        handles=handles,
        epoch_fn=lambda: int(ir.call_fn("revEpoch", [])[0]),
        root_fn=lambda: bytes(ir.call_fn("revRoot", [])[0]),
        push_fn=push_fn,
    )


def _chain_addresses() -> dict:
    import json
    from pathlib import Path

    p = Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
    return json.loads(p.read_text())


def startup_align_guard() -> dict:
    """create_app 启动守卫（2026-10-01 批）：真链档启动即自检+台账一行。

    与 RA deps 懒挂钩（app/ra/router._startup_align——首个 RA 请求前兜底）互补：
    本守卫兜「进程启动即」（main.create_app，FZ_CHAIN_ANCHOR=real 时调用）。
    两处共享 startup_align 核心，皆幂等（一致=零交易，二次启动不再推链）。
    台账=打印+结构化日志（fz.startup——JSON 形态入 stdout 日志流）；
    异常上抛由调用方 WARNING 落账不阻塞启动（受理面 stale_rev_root 仍是兜底）。
    """
    out = startup_align()
    log = logging.getLogger("fz.startup")
    if out.get("pushed"):
        line = (
            f"撤销纪元根漂移已自愈：推链 epoch={out['epoch']}"
            "（本地吊销镜像为权威——链上公示根已同步）"
        )
        print(f"[FZ-STARTUP][align] {line}", flush=True)
        log.warning(line)
    else:
        line = f"撤销纪元根一致（epoch={out.get('epoch')}——幂等零交易）"
        print(f"[FZ-STARTUP][align] {line}", flush=True)
        log.info(line)
    return out
