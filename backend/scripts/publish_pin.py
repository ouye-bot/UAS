"""电路指纹链上公示仪式（阶段一 D-Ⅰ-5，A8 承诺兑现；批 3.2 升格多签+时间锁）。

把本地 vendor MANIFEST 指纹（SM3(pin_commit|aggregate_sm3) 的摘要）发布到
PolicyRegistry.circuitPin——发布后受理门控④真链模式 fail-closed 强制比对
（authz/router._chain_pin 回读≠本地⟹受理全拒）。

仪式语义（批 3.2：治理面经 AdminGovernor 多签+时间锁——admin 单钥直调退役）：
  propose（admin 提案，calldata 哈希承诺）→ confirm（RA 第二票，2/3 达法定
  人数即锁定 eta）→ 时间锁延迟到期 execute（calldata 逐位对拍）→ 回读对拍
  （本地指纹==链上 circuitPin）。重复发布=覆盖（换电路/换 vendor 后重跑）。
烟测已改幂等保护（已公示不随机重设）——先发布后跑烟测安全。
治理面标注：政策/指纹公示与角色授予均属治理面——运行时 API 不承载，唯
本仪式脚本驱动（app/chain/governor.py 单源）。

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/publish_pin.py [--check]
  --check：只回读比对不发布（零副作用自检）。
  环境变量：FZ_ZKSVC_DIR（vendor MANIFEST 所在）；FZ_CHAIN_ADMIN_TX_SK/
  FZ_CHAIN_RA_TX_SK（.local_env 注入——admin/RA 为 governor 两 owner）。
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
from app.chain.governor import load_governor, run_proposal  # noqa: E402
from app.chain.signer import TxSigner  # noqa: E402
from app.crypto.sm3 import sm3_bytes  # noqa: E402
from app.kms import chain_admin_tx_key, chain_ra_tx_key  # noqa: E402

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

    # 链上交易钥（批 3.2：env 注入=.local_env 随机钥——admin/RA 为 governor 两
    # owner；指纹打印供与部署脚本 chain_smoke --deploy 输出逐位对拍）
    admin = TxSigner(chain_admin_tx_key())
    ra = TxSigner(chain_ra_tx_key())
    print(f"[pin] 钥指纹: admin={admin.address} ra={ra.address}")
    client = ChainClient(rpc_url=RPC, from_addr=admin.address)
    addresses = json.loads(ADDR_PATH.read_text())
    pr = load_binding("PolicyRegistry", client, addresses["PolicyRegistry"]["address"])
    gov = load_governor(client, addresses)

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
        print("[pin] 治理仪式启动：propose(admin)→confirm(RA)→延迟到期 execute")
        receipt = run_proposal(gov, admin, ra, pr, "pinCircuit", [digest],
                               "circuit pin: vendor MANIFEST fingerprint")
        gov_events = [ev["event"] for ev in gov.decode_logs(receipt)]
        pr_events = [ev["event"] for ev in pr.decode_logs(receipt)]
        if "Executed" not in gov_events or "CircuitPinned" not in pr_events:
            print(f"[FAIL] 仪式事件缺失: gov={gov_events} pr={pr_events}")
            return 1
        back = bytes(pr.call_fn("circuitPin", [])[0])
        if back != digest:
            print(f"[FAIL] 发布后回读不一致: {back.hex()}")
            return 1
        print(
            f"[pin] 发布成功 tx={receipt.get('transactionHash', '?')}"
            f"（事件 {gov_events + pr_events}；受理门控④即刻强制）"
        )

    # 政策表 paramsHash 同步公示（阶段四：政策链源 fail-closed 的另一半）——
    # 同经 governor 三步仪式（治理面不留单钥路径）
    from app.authz.policy import policy_params_hash

    ph = bytes.fromhex(policy_params_hash())
    on_ph, on_ts = pr.call_fn("getPolicy", ["policy-2026-09-v1"])
    if bytes(on_ph) == ph:
        print("[pin] 政策表已一致（幂等）")
    elif int(on_ts) != 0:
        print(
            f"[FAIL] 链上已公示同版本不同参 policy-2026-09-v1: {bytes(on_ph).hex()}"
            f"——本地政策表与公示分叉，fail-closed（先核对政策表再人工处置）"
        )
        return 1
    else:
        receipt2 = run_proposal(gov, admin, ra, pr, "publishPolicy",
                                ["policy-2026-09-v1", ph], "policy table paramsHash")
        print(f"[pin] 政策表已公示 tx={receipt2.get('transactionHash', '?')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
