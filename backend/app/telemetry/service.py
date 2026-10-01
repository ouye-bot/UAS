"""遥测锚定服务（阶段一 D-Ⅰ-7）：检查点/事件上链的业务序。

业务序（fail-closed，全部负例有拒绝码）：
- anchor：①形态校验 →②设备签名验证（含围栏状态绑定 D16）→③authId 链上在案
  且有效 →④seq 单调（合约 require 的宿主预检+真链链级强制）→⑤anchorCheckpoint
- event：①形态校验 →②authId 在案 →③recordEvent（eventType 1..4 合约强制）

fake 模式（FZ_CHAIN_ANCHOR=fake，CI/离线）：进程内锚记录（测试断言面，
latest_seq 单调模拟合约语义）；真链：TelemetryAnchor binding + engine 交易钥。
认证边界：engine 面=转发权威（B1-d1），本机部署边界+生产 mTLS（S5 演进文档）；
设备签名=数据完整性校验非准入——锚定语义=engine 转发事实+设备背书数据，
第三方离线验真=重算链哈希→重算检查点→链上回读（exit 0/2）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.telemetry.checkpoint import verify_checkpoint


class TelemetryError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 400) -> None:
        self.code = code
        self.message = message
        self.status = status


@dataclass
class TelemetryDeps:
    """链上副作用/查询注入面（真链=ChainBinding 转发，fake=内存记录）。"""

    anchor_on_chain: Any = None  # (auth_id, seq, head_bytes, sig_bytes) -> tx hash str
    event_on_chain: Any = None  # (auth_id, event_type, event_hash_bytes) -> tx hash str
    auth_status: Any = None  # auth_id -> status int（None=不在案）
    # fake 模式 seq 单调面（auth_id -> latest seq）
    latest_seq: dict[int, int] = field(default_factory=dict)
    records: list[dict] = field(default_factory=list)  # fake 锚记录（测试断言面）
    events: list[dict] = field(default_factory=list)  # fake 事件记录


_default_deps: TelemetryDeps | None = None


def get_deps() -> TelemetryDeps:
    global _default_deps
    if _default_deps is None:
        if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
            _default_deps = TelemetryDeps(
                anchor_on_chain=lambda aid, seq, head, sig: _fake_anchor(aid, seq, head, sig),
                event_on_chain=lambda aid, et, eh: _fake_event(aid, et, eh),
                auth_status=lambda session, aid: _db_auth_status(session, aid),
            )
        else:
            _default_deps = _real_chain_deps()
    return _default_deps


def reset_deps() -> None:
    """测试钩子：env 切换后强制重建 deps。"""
    global _default_deps
    _default_deps = None


def _db_auth_status(session: Session, auth_id: int) -> int | None:
    """fake 模式在案校验：库内 AuthRecord（授权登记镜像）。"""
    from app.authz.models import AuthRecord

    row = session.scalar(select(AuthRecord).where(AuthRecord.auth_id == auth_id))
    return None if row is None else 0  # 镜像无撤销面（撤销=链上面，fake 简化）


def _fake_anchor(auth_id: int, seq: int, head: bytes, sig: bytes) -> str:
    d = get_deps()
    if seq != d.latest_seq.get(auth_id, 0) + 1:
        raise TelemetryError(
            "seq_conflict", f"seq={seq} 非单调（期望 {d.latest_seq.get(auth_id, 0) + 1}）", 409
        )
    d.latest_seq[auth_id] = seq
    d.records.append(
        {"auth_id": auth_id, "seq": seq, "chain_head_hex": head.hex(), "sig_hex": sig.hex()}
    )
    return "fake"


def _fake_event(auth_id: int, event_type: int, event_hash: bytes) -> str:
    d = get_deps()
    d.events.append(
        {"auth_id": auth_id, "event_type": event_type, "event_hash_hex": event_hash.hex()}
    )
    return "fake"


def _chain_addresses() -> dict:
    import json
    from pathlib import Path

    p = Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
    return json.loads(p.read_text())


def _real_chain_deps() -> TelemetryDeps:
    from app.chain.client import ChainClient, ChainError
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_engine_tx_key

    engine = TxSigner(chain_engine_tx_key())
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=engine.address,
    )
    addr = _chain_addresses()
    ta = load_binding("TelemetryAnchor", client, addr["TelemetryAnchor"]["address"])
    fa = load_binding("FlightAuthRegistry", client, addr["FlightAuthRegistry"]["address"])

    def anchor_on_chain(auth_id: int, seq: int, head: bytes, sig: bytes) -> str:
        try:
            receipt = ta.send_fn(engine, "anchorCheckpoint", [auth_id, seq, head, sig])
            return str(receipt.get("transactionHash", ""))
        except ChainError as e:
            if "seq not monotonic" in str(e):
                raise TelemetryError("seq_conflict", str(e), 409) from e
            raise

    def event_on_chain(auth_id: int, event_type: int, event_hash: bytes) -> str:
        try:
            receipt = ta.send_fn(engine, "recordEvent", [auth_id, event_type, event_hash])
            return str(receipt.get("transactionHash", ""))
        except ChainError as e:
            if "bad eventType" in str(e):
                raise TelemetryError("bad_event_type", str(e), 400) from e
            raise

    def auth_status(session: Session, auth_id: int) -> int | None:
        try:
            rec = fa.call_fn("getAuth", [auth_id])
            return int(rec[8])  # 11 元组第 9 位 status
        except ChainError:
            return None  # bad authId require revert=不在案

    return TelemetryDeps(
        anchor_on_chain=anchor_on_chain,
        event_on_chain=event_on_chain,
        auth_status=auth_status,
    )


def anchor_checkpoint(
    deps: TelemetryDeps,
    session: Session,
    *,
    auth_id: int,
    seq: int,
    chain_head_hex: str,
    fence_state_hex: str,
    sig_hex: str,
    device_pub_hex: str,
) -> dict:
    """检查点锚定业务序（D-Ⅰ-7）。返回 {auth_id, seq, tx}。"""
    if seq < 1:
        raise TelemetryError("bad_seq", "seq 须从 1 起")
    try:
        head = bytes.fromhex(chain_head_hex)
        fence = bytes.fromhex(fence_state_hex)
        sig_b = bytes.fromhex(sig_hex)
    except ValueError as e:
        raise TelemetryError("bad_input", f"hex 字段非法: {e}") from e
    if len(head) != 32 or len(fence) != 4:
        raise TelemetryError("bad_input", "chain_head 须 32B、fence_state 须 4B")
    spk = device_pub_hex.lower()
    if len(spk) != 128 or not all(c in "0123456789abcdef" for c in spk):
        raise TelemetryError("bad_input", "device_pub 须 128 hex")
    # ① 设备签名（含围栏状态绑定——改 1 字节必败）
    if not verify_checkpoint(spk, auth_id, seq, head, fence, sig_hex):
        raise TelemetryError("bad_checkpoint_sig", "检查点设备签名验证失败", 403)
    # ② authId 在案
    status = deps.auth_status(session, auth_id)
    if status is None:
        raise TelemetryError("auth_not_found", "authId 不在授权注册表（拒绝锚定）", 403)
    if status != 0:
        raise TelemetryError("auth_revoked", "授权已撤销（拒绝锚定）", 403)
    # ③ 上链（seq 单调：fake=latest_seq 预检；真链=合约 require+异常映射 409）
    tx = deps.anchor_on_chain(auth_id, seq, head, sig_b)
    # ④ 持久化检查点（SN v2：设备交叉审计数据面——device_sig/fence 态可追溯）
    from app.telemetry.models import CheckpointAnchor

    session.add(
        CheckpointAnchor(
            auth_id=auth_id,
            seq=seq,
            chain_head_hex=head.hex(),
            fence_state_hex=fence.hex(),
            device_sig_hex=sig_b.hex(),
            device_pub_hex=device_pub_hex.lower(),
            tx_hash=tx,
        )
    )
    session.commit()
    return {"auth_id": auth_id, "seq": seq, "tx": tx}


def record_event(
    deps: TelemetryDeps,
    session: Session,
    *,
    auth_id: int,
    event_type: int,
    event_hash_hex: str,
) -> dict:
    """违规事件上链业务序（eventType：1=固件围栏 2=地面站监测 3=通信中断 4=迫降）。"""
    if not 1 <= event_type <= 4:
        raise TelemetryError("bad_event_type", "eventType 须 1..4")
    try:
        ev_hash = bytes.fromhex(event_hash_hex)
    except ValueError as e:
        raise TelemetryError("bad_input", f"event_hash 非法: {e}") from e
    if len(ev_hash) != 32:
        raise TelemetryError("bad_input", "event_hash 须 32B/64hex")
    status = deps.auth_status(session, auth_id)
    if status is None:
        raise TelemetryError("auth_not_found", "authId 不在授权注册表", 403)
    if status != 0:
        raise TelemetryError("auth_revoked", "授权已撤销", 403)
    tx = deps.event_on_chain(auth_id, event_type, ev_hash)
    return {"auth_id": auth_id, "event_type": event_type, "tx": tx}
