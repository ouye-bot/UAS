"""AdminGovernor 多签+时间锁治理仪式助手（批 3.2，单一事实源）。

治理面语义（chain_smoke --deploy 与 publish_pin 仪式共用本模块）：
- 四业务合约的 onlyAdmin 面（政策/指纹公示+角色授予）链上 admin=AdminGovernor
  （部署时 transferAdmin 移交）。任何治理写入必须三步：
  propose（owner 提案，calldata 哈希承诺）→ confirm（owner 各一票不可重复，
  admin+RA 两票达 required=2 即锁定 eta=now+delay）→ 延迟到期 execute
  （calldata 逐位对拍提案哈希）。
- 运行时 API 不承载治理面：backend 无任何经 governor 的写调用（读面零变化）；
  治理仪式的唯一驱动方=scripts（publish_pin/chain_smoke）。
- 国密口径：FISCO 2.x GM 链 EVM 层 keccak256=SM3（见 abi.sig_hash 同纪律），
  calldataHash 用 sm3_bytes(calldata) 同构计算——与合约内 keccak256 对拍一致。
- 部署构造参数编码（address[3],uint8,uint32）：ABI 静态元组逐字拼接（abi.py
  不含数组类型——故显式编码，保持最小面）。
"""

from __future__ import annotations

import time

from app.chain.contracts import ContractBinding, load_binding
from app.chain.signer import TxSigner
from app.crypto.sm3 import sm3_bytes

GOVERNOR_NAME = "AdminGovernor"
_REQUIRED = 2  # owners=[admin,RA,auditor]，2/3 到法定人数


def governor_delay_s() -> int:
    """时间锁延迟（秒）——FZ_GOVERNOR_DELAY_S 语义。缺省 10s 保测试性；
    🔴 生产环境必须调大（建议 ≥86400），留足观察与 cancel 撤销窗。"""
    import os

    return int(os.environ.get("FZ_GOVERNOR_DELAY_S", "10"))


def load_governor(client, addresses: dict) -> ContractBinding:
    """从地址簿装载 governor binding（地址簿由部署脚本写入）。"""
    entry = addresses.get(GOVERNOR_NAME)
    if not entry:
        raise SystemExit(f"[gov] 地址簿缺 {GOVERNOR_NAME}——先跑部署仪式")
    return load_binding(GOVERNOR_NAME, client, entry["address"])


def ctor_args(
    owner_addresses: list[str], required: int = _REQUIRED, delay_s: int | None = None
) -> bytes:
    """构造参数 (address[3],uint8,uint32) 的 ABI 静态编码（逐 32B 字）。"""
    if len(owner_addresses) != 3:
        raise ValueError("owners 须三钥（admin/RA/auditor）")
    delay = governor_delay_s() if delay_s is None else delay_s
    words = []
    for a in owner_addresses:
        raw = bytes.fromhex(str(a).removeprefix("0x"))
        if len(raw) != 20:
            raise ValueError(f"owner 地址须 20B: {a}")
        words.append(b"\x00" * 12 + raw)
    words.append(required.to_bytes(32, "big"))
    words.append(delay.to_bytes(32, "big"))
    return b"".join(words)


def eta_unix_seconds(eta_raw: int) -> float:
    """链上 eta → Unix 秒。FISCO BCOS 2.x block.timestamp=毫秒（真链 2026-10-05
    实测 13 位）——>1e12 判毫秒除 1000，秒口径直返（跨链口径鲁棒）。"""
    return eta_raw / 1000.0 if eta_raw > 10**12 else float(eta_raw)


def run_proposal(
    gov: ContractBinding,
    proposer: TxSigner,
    confirmer: TxSigner,
    target: ContractBinding,
    fn: str,
    args: list,
    description: str = "",
    timeout_s: float = 120.0,
) -> dict:
    """治理三步仪式：propose→双 confirm→延迟到期 execute，返回 execute 回执。

    - proposer/confirmer 必须为不同 owner（required=2——owner 各一票，
      propose 不计票：admin confirm + RA confirm 两票达法定人数）；
    - confirm 后回读 getProposal 断言 Queued 态+票数达标+eta 已锁（fail-closed）；
    - execute 回执内断言 Executed 事件（目标合约业务事件随回执原样可解析）。
    """
    if proposer.address.lower() == confirmer.address.lower():
        raise ValueError("proposer 与 confirmer 须为不同 owner（2/3 多签语义）")
    call_data = target.encode_calldata(fn, args)
    chash = sm3_bytes(call_data)  # GM 链 EVM 层哈希=SM3（与合约 keccak256 同构）
    r1 = gov.send_fn(proposer, "propose", [target.address, chash, description])
    proposed = [ev for ev in gov.decode_logs(r1) if ev["event"] == "Proposed"]
    if len(proposed) != 1:
        raise RuntimeError(f"Proposed 事件缺失/重复: {len(proposed)}")
    pid = int(proposed[0]["proposalId"])
    gov.send_fn(proposer, "confirm", [pid])
    gov.send_fn(confirmer, "confirm", [pid])
    tp, _tch, _tdesc, eta, confirmations, status = gov.call_fn("getProposal", [pid])
    if int(confirmations) < 2 or int(status) != 1 or int(eta) == 0:
        raise RuntimeError(
            f"提案 {pid} 未达法定人数/未锁定 eta（confirmations={confirmations} status={status}）"
        )
    # 链时=单机本机时（单宿主 WSL），+1.5s 余量
    wait_s = eta_unix_seconds(int(eta)) - time.time() + 1.5
    if wait_s > 0:
        time.sleep(min(wait_s, timeout_s))
    r3 = gov.send_fn(proposer, "execute", [target.address, 0, call_data])
    executed = [ev for ev in gov.decode_logs(r3) if ev["event"] == "Executed"]
    if len(executed) != 1:
        raise RuntimeError(f"Executed 事件缺失/重复: {len(executed)}")
    return r3
