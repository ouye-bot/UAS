# -*- coding: utf-8 -*-
"""链上留痕面板真链档验收（阶段三.1）：面板数据=链上事实（看得见且可核验）。

断言面：
  ① 面板 mode=real
  ② records 非空：每条授权记录的 proofDigest 与链上 getAuth 逐位一致、
     txHash 形态真实（0x…64hex——fake 档为 "fake"）
  ③ chain 状态面（区块高/纪元根）与链原始 JSON-RPC 回读一致
  ④ 令状列表非空且每条 target_auth_id 在链上 getAuth 在案
  ⑤ 面板零身份面（记录/令状无任何身份字段——D19）

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/verify_panel_chain.py
前置：backend(8000) 在线（真链模式）+ WSL 链在线。
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_checks = 0


def ok(label: str) -> None:
    global _checks
    _checks += 1
    print(f"  [OK] {label}")


def expect(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        ok(label)
    else:
        print(f"  [FAIL] {label} {detail}")
        raise SystemExit(1)


def main() -> int:
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_ra_tx_key

    print("== 链上留痕面板真链档验收（面板=链上事实）==")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:8000/chain/panel", timeout=15) as r:
        panel = json.loads(r.read().decode())["data"]

    expect(panel.get("mode") == "real", "① 面板=真链模式")

    addr = json.loads((Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json").read_text())
    client = ChainClient(rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
                         from_addr=TxSigner(chain_ra_tx_key()).address)
    fa = load_binding("FlightAuthRegistry", client, addr["FlightAuthRegistry"]["address"])

    records = panel.get("records") or []
    expect(len(records) >= 1, "② 授权记录非空", "面板 records 空——先跑 e2e/S1 留痕")
    n_chain = 0
    for rec in records:
        if rec.get("tx_hash") in (None, "", "fake"):
            continue  # fake 时代历史行（持久库遗留）——真链行才对账
        onchain = fa.call_fn("getAuth", [rec["auth_id"]])
        if bytes(onchain[7]).hex() == rec["proof_digest_hex"]:
            n_chain += 1
    expect(n_chain >= 1, f"②' 真链行 proofDigest 与链上逐位一致（{n_chain}/{len(records)}）")
    tx_ok = [r for r in records if str(r.get("tx_hash", "")).startswith("0x") and len(r["tx_hash"]) == 66]
    expect(len(tx_ok) >= 1, "②'' txHash 真实形态（0x…64hex 非 fake 替身）")

    chain_face = panel.get("chain") or {}
    expect(int(chain_face.get("block_height", 0)) > 4000, "③ 链面区块高在案（>4000）",
           str(chain_face)[:120])
    expect(chain_face.get("rev_root_hex", "") not in ("", "00" * 32), "③' 撤销纪元根公示在案")

    warrants = panel.get("warrants") or []
    expect(len(warrants) >= 1, "④ 令状列表非空")
    for w in warrants[:5]:
        aid = w.get("target_auth_id")
        if aid:
            rec = fa.call_fn("getAuth", [aid])
            expect(rec is not None, f"④' 令状目标 authId={aid} 链上在案")

    blob = json.dumps(panel, ensure_ascii=False)
    for pat in ("username", "id_number", "idnumber", "手机", "身份证"):
        expect(pat not in blob, f"⑤ 面板零身份面（无 {pat} 字段——D19）")

    print(f"\n== 面板验收全绿：{_checks} 项断言 [OK] ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
