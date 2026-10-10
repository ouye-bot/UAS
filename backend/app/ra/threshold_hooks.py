"""④站份额域三关校验真实现（2026-10-10）。

三关与数据源（全部真实组件——零替身）：
① 解锁请求台账在案：threshold_root/unlock_requests.jsonl（append-only，
   合成方受理面登记 warrant/cred/C₁ 指纹三元组——域与合成方同读此文件，
   域独立判定）；
② 令状链上在案：IdentityRegistry.warrants 链查（WarrantLog——与
   warrant_unlock 流程双控第一关同源）；
③ 双控批文在案：collab_issued 台账（FZC2 出函=双控批准的产物行——
   warrant+cred 命中）。

链不可达=校验 fail-closed 拒绝（不静默放行——份额出借面红线）。
"""

from __future__ import annotations

import json
from pathlib import Path


def _requests_path() -> Path:
    import os

    env = os.environ.get("FZ_THRESHOLD_ROOT_DIR", "")
    root = Path(env) if env else Path(__file__).resolve().parents[2] / "threshold_root"
    return root / "unlock_requests.jsonl"


def register_unlock_request(
    *, request_sha256_hex: str, warrant_hash_hex: str, cred_hash_hex: str
) -> None:
    """合成方受理登记（append-only；域①关的判定源）。"""
    _requests_path().parent.mkdir(parents=True, exist_ok=True)
    import time

    row = {
        "ts": time.time(),
        "request_sha256_hex": request_sha256_hex,
        "warrant_hash_hex": warrant_hash_hex,
        "cred_hash_hex": cred_hash_hex,
    }
    with _requests_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def request_registered(request_sha256_hex: str, warrant_hash_hex: str, cred_hash_hex: str) -> bool:
    if not _requests_path().exists():
        return False
    for line in _requests_path().read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            row.get("request_sha256_hex") == request_sha256_hex
            and row.get("warrant_hash_hex") == warrant_hash_hex
            and row.get("cred_hash_hex") == cred_hash_hex
        ):
            return True
    return False


def warrant_on_chain(warrant_hash_hex: str) -> bool:
    """真链查（IdentityRegistry.warrants——WarrantLog 公示面）。

    fake 档（FZ_CHAIN_ANCHOR=fake）：链查不可用即 fail-closed 拒——份额出借
    面不因演示档放行（诚实口径：门限解锁的实弹验收在真链档）。"""
    import os

    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
        return False
    try:
        import json
        from pathlib import Path

        from app.chain.client import ChainClient
        from app.chain.contracts import load_binding
        from app.chain.signer import TxSigner
        from app.kms import chain_ra_tx_key

        addr = json.loads(
            (Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json").read_text(
                encoding="utf-8"
            )
        )
        signer = TxSigner(chain_ra_tx_key())
        client = ChainClient(
            rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
            from_addr=signer.address,
        )
        ir = load_binding("IdentityRegistry", client, addr["IdentityRegistry"]["address"])
        return bool(ir.call_fn("warrants", [bytes.fromhex(warrant_hash_hex)])[0])
    except Exception:  # noqa: BLE001 —— 链不可达=fail-closed（份额出借面红线）
        return False


def collab_approved(request_sha256_hex: str) -> bool:
    """双控批文在案：collab_issued 台账按 warrant+cred 命中（请求登记时由
    合成方把 warrant/cred 与 request_sha256 绑定登记——本关核对台账三元组
    对应的出函行存在）。"""
    if not _requests_path().exists():
        return False
    warrant = cred = None
    for line in _requests_path().read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("request_sha256_hex") == request_sha256_hex:
            warrant, cred = row.get("warrant_hash_hex"), row.get("cred_hash_hex")
            break
    if not warrant or not cred:
        return False
    try:
        from sqlalchemy import select

        from app.audit.models import CollabIssued
        from app.db import SessionLocal

        s = SessionLocal()
        try:
            row = s.scalar(
                select(CollabIssued).where(
                    CollabIssued.warrant_hash_hex == warrant,
                    CollabIssued.master_cred_hash_hex == cred,
                )
            )
            return row is not None
        finally:
            s.close()
    except Exception:  # noqa: BLE001 —— DB 不可达=fail-closed
        return False
