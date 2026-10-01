# -*- coding: utf-8 -*-
"""撤销纪元根对齐仪式（P0-5 后=运维兜底位；服务启动已自动对账——app/ra/align.py）。

保留场景：人工运维/部署清单校验/服务外显式对账。核心逻辑单源=app/ra/align.py。

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/align_rev_root.py
退出码：0=一致或对齐成功；1=失败。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.chain.client import ChainClient  # noqa: E402
from app.chain.contracts import load_binding  # noqa: E402
from app.chain.signer import TxSigner  # noqa: E402
from app.kms import chain_ra_tx_key  # noqa: E402
from app.ra.align import align_rev_root_core  # noqa: E402
from app.ra.models import Revocation  # noqa: E402

RPC = os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545")
ADDR_PATH = Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json"


def main() -> int:
    from sqlalchemy import select

    from app.db import SessionLocal

    s = SessionLocal()
    try:
        handles = [bytes.fromhex(r.handle_hex) for r in s.scalars(select(Revocation)).all()]
    finally:
        s.close()
    print(f"[align] 本地吊销集 {len(handles)} 条")

    ra = TxSigner(chain_ra_tx_key())
    client = ChainClient(rpc_url=RPC, from_addr=ra.address)
    addresses = json.loads(ADDR_PATH.read_text())
    ir = load_binding("IdentityRegistry", client, addresses["IdentityRegistry"]["address"])
    chain_epoch = int(ir.call_fn("revEpoch", [])[0])
    chain_root = ir.call_fn("revRoot", [])[0]
    chain_root_hex = bytes(chain_root).hex() if not isinstance(chain_root, str) else chain_root.removeprefix("0x")
    print(f"[align] 链上 epoch={chain_epoch} root={chain_root_hex[:24]}…")

    out = align_rev_root_core(
        handles=handles,
        epoch_fn=lambda: int(ir.call_fn("revEpoch", [])[0]),
        root_fn=lambda: bytes(ir.call_fn("revRoot", [])[0]),
        push_fn=lambda epoch, root: ir.send_fn(ra, "setRevocationRoot", [epoch, root]),
    )
    if not out["aligned"]:
        print("[FAIL] 对账后仍未一致")
        return 1
    if out["pushed"]:
        back = bytes(ir.call_fn("revRoot", [])[0]).hex()
        print(f"[align] 已对齐 epoch={out['epoch']} 回读={back[:24]}…（门控④即刻同源）")
    else:
        print("[align] 已一致（幂等——零交易）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
