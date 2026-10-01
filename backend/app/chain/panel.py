"""链上留痕可视化面板（R1-5）：留痕看得见、可核验的产品面答案。

数据源（B7-d3：留痕单一事实源=链，DB 只作登记索引）：
- 链状态面：区块高、撤销纪元/根（IdentityRegistry 公示）
- 授权记录：FlightAuthRegistry.getAuth（authId/proofDigest/状态）+ DB 索引
- 检查点：TelemetryAnchor.latest（链头/围栏状态/时间）
- 令状：warrants 表（hash/case/时间——治理面留痕索引）
零身份面：面板不出现任何实名/身份字段（D19）。
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.authz.models import Application, AuthRecord
from app.db import SessionLocal
from app.ra.models import Base as RaBase  # noqa: F401 —— 确保元数据已注册

router = APIRouter(prefix="/chain", tags=["chain-panel"])

# 链面 TTL 缓存（R4 第二批 A-路线#6）：面板每请求新建 ChainClient+串行 7 笔
# RPC（block/epoch/root+5×latest）——首屏 500ms 级。缓存 3s（env 可调）+
# 进程级 client/binding 复用：面板=展示面可容忍秒级陈旧（记录/令状仍每请求
# 实时取自 DB；proofDigest 对账面不受影响）。
_FACE_TTL_S = float(os.environ.get("FZ_CHAIN_FACE_TTL_S", "3"))
_face_cache: dict = {"key": None, "at": 0.0, "data": None}
_face_lock = threading.Lock()
_face_bindings: dict = {}


def _mode() -> str:
    return os.environ.get("FZ_CHAIN_ANCHOR", "fake")


def _addresses() -> dict:
    p = Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
    return json.loads(p.read_text())


def _recent_records(session, limit: int = 10) -> list[dict]:
    from sqlalchemy.orm import Session as _S  # noqa: F401

    rows = session.execute(
        select(AuthRecord, Application)
        .join(Application, AuthRecord.application_id == Application.id)
        .order_by(AuthRecord.auth_id.desc())
        .limit(limit)
    ).all()
    return [
        {
            "auth_id": rec.auth_id,
            "proof_digest_hex": rec.proof_digest_hex,
            "tx_hash": rec.tx_hash,
            "status": app.status,
            "class_id": app.class_id,
            "created_at": rec.created_at.isoformat() if rec.created_at else None,
        }
        for rec, app in rows
    ]


def _binding_cached(name: str):
    """链 binding 进程级复用（连接+abi 装配只做一次——authz 路由同模式）。"""
    if name not in _face_bindings:
        from app.chain.client import ChainClient
        from app.chain.contracts import load_binding
        from app.chain.signer import TxSigner
        from app.kms import chain_ra_tx_key

        signer = TxSigner(chain_ra_tx_key())
        client = ChainClient(
            rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
            from_addr=signer.address,
        )
        addrs = _addresses()
        _face_bindings["client"] = client
        _face_bindings[name] = load_binding(name, client, addrs[name]["address"])
    return _face_bindings[name]


def _chain_face(auth_ids: list[int]) -> dict:
    """真链状态面回读（IdentityRegistry/TelemetryAnchor 公示面；TTL 缓存）。"""
    key = tuple(auth_ids[-5:])  # 检查点查询集=缓存键（记录面仍每请求实时）
    now = time.monotonic()
    with _face_lock:
        if _face_cache["key"] == key and now - _face_cache["at"] < _FACE_TTL_S:
            return _face_cache["data"]
    _binding_cached("IdentityRegistry")  # 确保连接与 binding 已建（进程级复用）
    client = _face_bindings["client"]
    ir = _face_bindings["IdentityRegistry"]
    face: dict = {
        "block_height": client.block_number(),
        "rev_epoch": int(ir.call_fn("revEpoch", [])[0]),
        "rev_root_hex": bytes(ir.call_fn("revRoot", [])[0]).hex(),
    }
    addrs = _addresses()
    anchor = None
    if "TelemetryAnchor" in addrs:
        anchor = _binding_cached("TelemetryAnchor")
    checkpoints = []
    if anchor is not None:
        for aid in auth_ids[-5:]:
            try:
                latest = anchor.call_fn("latest", [aid])[0]
            except Exception:  # noqa: BLE001 —— 空锚定位返回空元组/回退
                latest = None
            if latest and len(latest) >= 3:
                checkpoints.append(
                    {
                        "auth_id": aid,
                        "seq": int(latest[0]),
                        "chain_head_hex": bytes(latest[1]).hex(),
                        "ts": int(latest[2]),
                    }
                )
    face["checkpoints"] = checkpoints
    with _face_lock:
        _face_cache.update(key=key, at=time.monotonic(), data=face)
    return face


@router.get("/panel")
def panel():
    mode = _mode()
    session = SessionLocal()
    try:
        records = _recent_records(session, 10)
        auth_ids = [r["auth_id"] for r in records]
        from app.audit.models import Warrant

        warrants = (
            session.execute(select(Warrant).order_by(Warrant.id.desc()).limit(5)).scalars().all()
        )
        panel_data = {
            "mode": mode,
            "records": records,
            "warrants": [
                {
                    "warrant_hash_hex": w.warrant_hash_hex,
                    # case_no=审计自由文本——未认证面板只出哈希与 authId（隐私面）
                    "target_auth_id": w.target_auth_id,
                    "created_ts": w.created_ts.isoformat() if w.created_ts else None,
                }
                for w in warrants
            ],
            "counts": {
                "auth_records": len(records),
                "warrants": len(warrants),
            },
        }
        if mode == "fake":
            # 诚实标注：fake 锚无真链状态面（CI/无链环境）
            panel_data["chain"] = None
        else:
            try:
                panel_data["chain"] = _chain_face(auth_ids)
            except Exception as e:  # noqa: BLE001 —— 链不可达时降级为 DB 索引面
                panel_data["chain"] = None
                panel_data["chain_error"] = str(e)[:160]
        return {"ok": True, "data": panel_data}
    finally:
        session.close()


@router.get("/record/{auth_id}")
def record_detail(auth_id: int):
    """单条链上授权记录详情（W-8 飞手视角：这是什么/如何自行核验的数据面）。

    - 归档判决件摘要（D17 持久归档 verdict.json：验证结论尾段+期望绑定
      expected——与 worker 验证时消费的同一 dict，第三方复验与验证同源）；
    - 链上原文对账：真链档回读 getAuth 逐位比对 proofDigest——面板指纹
      =链上原文的机器证明（chain_match）；链不可达=chain_error 降级不假装；
    - 零身份红线：仅证明/链面/政策面字段，无任何身份与设备字段（与 /panel
      同纪律——case_no/用户名/证件号一律不出）。
    """
    session = SessionLocal()
    try:
        row = session.execute(
            select(AuthRecord, Application)
            .join(Application, AuthRecord.application_id == Application.id)
            .where(AuthRecord.auth_id == auth_id)
        ).first()
        if row is None:
            return JSONResponse(status_code=404, content={"ok": False, "code": "not_found"})
        rec, app = row
        from app.authz.policy import get_rule

        alt_max_m, _level = get_rule(app.class_id)  # 政策面单源（米——与令牌/链面 altMaxM 同单位）
        detail: dict = {
            "auth_id": rec.auth_id,
            "status": app.status,
            "class_id": app.class_id,
            "alt_max_m": alt_max_m,
            "t_start": app.t_start,
            "t_end": app.t_end,
            "created_at": rec.created_at.isoformat() if rec.created_at else None,
            "proof_digest_hex": rec.proof_digest_hex,
            "tx_hash": rec.tx_hash,
        }
        # D17 归档判决件摘要（容错：历史归档可能缺 expected/文件可能被运维清理）
        verdict = None
        try:
            if rec.verdict_path and Path(rec.verdict_path).exists():
                verdict = json.loads(Path(rec.verdict_path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 —— 归档件损坏=按无归档呈现（诚实降级）
            verdict = None
        if verdict is not None:
            lines = [ln for ln in (verdict.get("verify_log") or "").splitlines() if ln.strip()]
            detail["verify_tail"] = "\n".join(lines[-3:]) if lines else None
            detail["verify_s"] = verdict.get("verify_s")
        detail["archived"] = verdict is not None
        # 复验期望绑定 expected：优先取归档件（=worker 验证时真实消费的同源 dict，
        # W-8 归档增量）；历史归档无此字段时按 worker `_process_one` 同构式从
        # 申请行确定性重建（binding_challenge/pred_id 与验证侧同一函数——
        # 非事后编造口径）。expected_source 标注来源供前端如实呈现。
        exp = verdict.get("expected") if verdict else None
        if isinstance(exp, dict) and exp:
            detail["expected"], detail["expected_source"] = exp, "archived"
        else:
            from app.authz.policy import POLICY_VERSION
            from app.authz.service import binding_challenge, binding_pred_id

            detail["expected"] = {
                "e_hex": app.e_hex,
                "challenge_hex": binding_challenge(app.plan_hash_hex, app.nonce_hex),
                "pred_id": binding_pred_id(
                    app.plan_hash_hex,
                    app.nonce_hex,
                    app.policy_version or POLICY_VERSION,
                ),
                "t_epoch": app.t_start,
                "required_level": _level,
                "class_id": app.class_id,
                "smt_root_hex": app.rev_root_hex,
            }
            detail["expected_source"] = "rebuilt"
        if _mode() == "fake":
            detail["chain"] = None  # fake 锚无链状态面（与 /panel 同诚实标注）
        else:
            try:
                fa = _binding_cached("FlightAuthRegistry")
                onchain = fa.call_fn("getAuth", [auth_id])
                detail["chain"] = {
                    "proof_digest_hex": bytes(onchain[7]).hex(),
                    "token_hash_hex": bytes(onchain[0]).hex(),
                    "match": bytes(onchain[7]).hex() == rec.proof_digest_hex,
                }
            except Exception as e:  # noqa: BLE001 —— 链不可达=降级（归档面仍可用）
                detail["chain"] = None
                detail["chain_error"] = str(e)[:160]
        return {"ok": True, "data": detail}
    finally:
        session.close()
