# -*- coding: utf-8 -*-
"""电路指纹链上公示仪式（阶段一 D-Ⅰ-5，A8 承诺兑现）。

把本地 vendor MANIFEST 指纹（SM3(pin_commit|aggregate_sm3) 的摘要）发布到
PolicyRegistry.circuitPin——发布后受理门控④真链模式 fail-closed 强制比对
（authz/router._chain_pin 回读≠本地⟹受理全拒）。

仪式语义：admin 钥一次性发布；重复发布=覆盖（换电路/换 vendor 后重跑）。
烟测已改幂等保护（已公示不随机重设）——先发布后跑烟测安全。

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/publish_pin.py [--check]
  --check：只回读比对不发布（零副作用自检）。
退出码：0=发布/比对一致；1=任何失败（fail-closed）。
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
from app.crypto.sm3 import sm3_bytes  # noqa: E402

RPC = os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545")
ADDR_PATH = Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json"


def local_pin_digest() -> tuple[str, bytes]:
    """本地指纹串与摘要（authz/service.pin_fingerprint 同式——单一事实源）。"""
    root = os.environ.get("FZ_ZKSVC_DIR")
    if not root:
        raise SystemExit("[FAIL] FZ_ZKSVC_DIR 未配置")
    with open(f"{root}/vendor/MANIFEST.json", encoding="utf-8") as f:
        man = json.load(f)
    pin_str = f"SM3({man['pin_commit']}|{man['aggregate_sm3']})"
    return pin_str, sm3_bytes(pin_str.encode())


def main() -> int:
    check_only = "--check" in sys.argv
    pin_str, digest = local_pin_digest()
    print(f"[pin] 本地指纹串: {pin_str}")
    print(f"[pin] 摘要(bytes32): {digest.hex()}")

    # admin 钥（B1 部署者=烟测域 admin——pinCircuit onlyAdmin）
    from app.kms import _derive_priv

    admin = TxSigner(
        os.environ.get("FZ_CHAIN_ADMIN_TX_SK") or _derive_priv(b"FZ-CHAIN-SMOKE|admin")
    )
    client = ChainClient(rpc_url=RPC, from_addr=admin.address)
    addresses = json.loads(ADDR_PATH.read_text())
    pr = load_binding("PolicyRegistry", client, addresses["PolicyRegistry"]["address"])

    on_chain = bytes(pr.call_fn("circuitPin", [])[0])
    if check_only:
        if on_chain == digest:
            print("[pin] 链上已一致（幂等）")
            return 0
        print(f"[FAIL] 链上值不一致: {on_chain.hex()}（--check 模式不发布）")
        return 1
    if on_chain == digest:
        print("[pin] 链上已一致（幂等——无需发布）")
    else:
        receipt = pr.send_fn(admin, "pinCircuit", [digest])
        if str(receipt.get("status", "")) != "0x0":
            print(f"[FAIL] pinCircuit 回执异常: {str(receipt)[:200]}")
            return 1
        back = bytes(pr.call_fn("circuitPin", [])[0])
        if back != digest:
            print(f"[FAIL] 发布后回读不一致: {back.hex()}")
            return 1
        print(f"[pin] 发布成功 tx={receipt.get('transactionHash', '?')}（受理门控④即刻强制）")

    # 政策表 paramsHash 同步公示（阶段四：政策链源 fail-closed 的另一半）
    from app.authz.policy import policy_params_hash

    ph = bytes.fromhex(policy_params_hash())
    on_ph = bytes(pr.call_fn("getPolicy", ["policy-2026-09-v1"])[0])
    if on_ph == ph:
        print("[pin] 政策表已一致（幂等）")
    else:
        receipt2 = pr.send_fn(admin, "publishPolicy", ["policy-2026-09-v1", ph])
        print(f"[pin] 政策表已公示 tx={receipt2.get('transactionHash', '?')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
