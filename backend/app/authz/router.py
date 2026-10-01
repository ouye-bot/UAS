"""授权服务 API（B4）：匿名受理+回执取件。

端点：POST /authz/apply（匿名申请——门控序四步+入队）、
GET /authz/receipt/{code}（取件：waiting/ready+令牌密文/failed）、
GET /authz/healthz。零身份面：请求/响应/存储三层无身份字段。
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.authz.service import AuthzError, admission_gate, receipt_of
from app.chain.client import ChainError
from app.db import get_session

router = APIRouter(prefix="/authz", tags=["authz"])

_DEPS = None


def _local_rev_root() -> tuple[int, str]:
    """fake/演示模式权威根：与 RA 公开镜像同源（同一撤销表同一 SMT 计算）。

    对抗评审修复（B8）：此前 stub 返回 00*32，与 /ra/revocation/snapshot 的
    本地树根不同源——诚实申请人按公示镜像取见证必被门控④全拒。
    """
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.ra.models import Revocation
    from app.ra.smt import smt_root

    s = SessionLocal()
    try:
        handles = [bytes.fromhex(r.handle_hex) for r in s.scalars(select(Revocation)).all()]
        return (0, smt_root(handles).hex())
    finally:
        s.close()


def _chain_rev_root() -> tuple[int, str]:
    """真链模式权威根：IdentityRegistry.revEpoch/revRoot 回读（B2 公示面）。"""
    ir = _chain_binding("IdentityRegistry")
    epoch = int(ir.call_fn("revEpoch", [])[0])
    root = ir.call_fn("revRoot", [])[0]
    return (epoch, root.hex() if hasattr(root, "hex") else str(root))


def _chain_nonce_used(nonce: bytes) -> bool:
    """真链 nonce 烧毁视图（阶段一 D-Ⅰ-4：门控③链级权威层——库级查重兜底已在）。"""
    fa = _chain_binding("FlightAuthRegistry")
    return bool(fa.call_fn("nonceUsed", [nonce])[0])


def _chain_pin() -> bytes | None:
    """真链电路指纹公示回读（阶段一 D-Ⅰ-5，A8 承诺兑现）。

    PolicyRegistry.circuitPin（bytes32）：未发布（0x00*32）=None 跳过（渐进可用
    ——发布仪式见 scripts/publish_pin.py）；已发布=fail-closed 强制与本地
    MANIFEST 指纹摘要比对（比对面=sm3(本地指纹串)，发布与回读同构闭环）。
    """
    pr = _chain_binding("PolicyRegistry")
    pin = pr.call_fn("circuitPin", [])[0]
    if isinstance(pin, bytes) and pin == b"\x00" * 32:
        return None
    return pin


_chain_bindings: dict[str, object] = {}


def _chain_binding(name: str):
    """链 binding 进程内缓存（受理热路径复用连接；测试 env 切换由进程隔离）。"""
    if name not in _chain_bindings:
        import json
        from pathlib import Path

        from app.chain.client import ChainClient
        from app.chain.contracts import load_binding
        from app.chain.signer import TxSigner
        from app.kms import chain_ra_tx_key

        addr = json.loads(
            (
                Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
            ).read_text()
        )
        signer = TxSigner(chain_ra_tx_key())
        client = ChainClient(
            rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
            from_addr=signer.address,
        )
        _chain_bindings[name] = load_binding(name, client, addr[name]["address"])
    return _chain_bindings[name]


def _policy_published(pr) -> bool:
    """扫描 PolicyRegistry 已发布版本的 paramsHash，任一匹配本地政策表即通过。

    版本上限 64（防异常长循环）；链不可达由调用方（受理门控）按错误处理。
    """
    from app.authz.policy import chain_policy_published

    hashes = []
    for i in range(64):
        try:
            version = pr.call_fn("policyVersions", [i])[0]
            hashes.append(pr.call_fn("getPolicy", [version])[0])
        except Exception:  # noqa: BLE001  越界/链抖动=以已收集版本判定
            break
    return chain_policy_published(hashes)


def _deps():
    global _DEPS
    if _DEPS is None:
        from app.authz.service import AuthzDeps

        d = AuthzDeps()
        # 撤销纪元根权威（门控④比对源）：fake=与 RA 镜像同源本地根；真链=链上公示。
        if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
            d.chain_rev_root = _local_rev_root
        else:
            d.chain_rev_root = _chain_rev_root
            d.chain_nonce_used = _chain_nonce_used
            d.chain_pin = _chain_pin
            # 阶段四：链级子凭证查重 + 政策公示对拍（fail-closed）
            fa = _chain_binding("FlightAuthRegistry")
            pr = _chain_binding("PolicyRegistry")
            d.chain_sub_used = lambda cred_bytes: bool(fa.call_fn("usedSubCreds", [cred_bytes])[0])
            # R3-1.3（评审 P2-3）：政策公示对拍改 per-apply 实时求值（此前进程级
            # 缓存一次求值终身冻结——先登记后公示 ⟹ 永远 409；公示后换版 ⟹ 检测失效）
            d.chain_policy_published = lambda: _policy_published(pr)
        _DEPS = d
    return _DEPS


def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"ok": True, "data": data})


def _deny(exc: AuthzError) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "code": exc.code, "message": exc.message}, status_code=exc.status
    )


class ApplyIn(BaseModel):
    """匿名申请体（零身份字段——D19：子凭证签名公开提交兼作准入票据）。"""

    session_pk_hex: str = Field(..., description="一次性会话公钥 128hex（取件加密目标）")
    sub_cred_message_hex: str = Field(..., description="子凭证报文 M_A′ 330hex")
    sub_sig_hex: str = Field(..., description="子凭证签名 128hex（公开提交）")
    sub_cred_hash_hex: str = Field(..., description="子凭证哈希 64hex（链上唯一性键）")
    nonce_hex: str = Field(..., description="一次性 nonce 32hex（链上烧毁键）")
    plan_hash_hex: str = Field(..., description="飞行计划哈希 64hex（T6 绑定）")
    class_id: int = Field(..., ge=0, le=255, description="机型类（公开——Remote ID 本就广播）")
    rev_root_hex: str = Field(..., description="撤销纪元根 64hex（链上当前纪元）")
    case_id: str = Field(..., min_length=8, max_length=64, description="出证任务号（桥接产物目录）")
    t_start: int = Field(..., ge=1, description="授权窗起点（=出证绑定 t_epoch）")
    t_end: int = Field(..., ge=1, description="授权窗终点")


@router.post("/apply")
def apply(body: ApplyIn, session: Session = Depends(get_session)):

    zk_dir = os.environ.get("FZ_ZK_CASES_DIR", "/tmp/fz-zk-cases")
    case_id = body.case_id.lower()
    if not all(c in "0123456789abcdef" for c in case_id):
        return _deny(AuthzError("bad_case_id", "case_id 须 hex", 400))
    case_dir = os.path.join(zk_dir, case_id)
    proof_path = os.path.join(case_dir, "proof.bin")
    spec_path = os.path.join(case_dir, "instances.json")
    for need in (proof_path, spec_path, os.path.join(case_dir, "verifier_param.bin")):
        if not os.path.exists(need):
            return _deny(
                AuthzError("case_incomplete", f"出证产物缺失: {os.path.basename(need)}", 400)
            )
    try:
        app_row = admission_gate(
            session,
            _deps(),
            session_pk_hex=body.session_pk_hex,
            sub_cred_message_hex=body.sub_cred_message_hex,
            sub_sig_hex=body.sub_sig_hex,
            sub_cred_hash_hex=body.sub_cred_hash_hex,
            nonce_hex=body.nonce_hex,
            plan_hash_hex=body.plan_hash_hex,
            class_id=body.class_id,
            proof_path=proof_path,
            spec_path=spec_path,
            rev_root_hex=body.rev_root_hex,
            t_start=body.t_start,
            t_end=body.t_end,
        )
    except AuthzError as e:
        return _deny(e)
    except ChainError as e:
        # R3-1.3（评审 P2-4）：链不可达=结构化快速失败（熔断窗内 <200ms），
        # 不再 500 裸奔
        return _deny(AuthzError("chain_unavailable", str(e), 503))
    from app.authz.models import Receipt

    r = session.get(Receipt, app_row.receipt_id)
    return _ok(
        {
            "application_id": app_row.id,
            "receipt_code": r.code_hex,
            "status": app_row.status,
        }
    )


@router.get("/engine/pub")
def engine_pub():
    """引擎验签公钥（公开面——飞手浏览器令牌验签基准）。

    R3-B2（评审 TCB 一致性）：公钥改由 backend 供给、桥接代理——桥进程
    不再持有 FZ_ENGINE_SK（政策引擎签名私钥），TCB 表述与部署对齐。"""
    from app.kms import engine_pub_hex

    return _ok({"engine_pub_hex": engine_pub_hex()})


@router.get("/policy/class/{class_id}")
def policy_class(class_id: int):
    """机型政策公示查询（公开面——C-P1-5：政策上限在申请页提交前即知，
    而非提交被拒后才知道；数据=本地政策表 CLASS_RULES，公示对拍仍由门控
    per-apply 执行）。未开放类 404 fail-closed。"""
    from app.authz import policy

    try:
        alt_max_m, required_level = policy.get_rule(class_id)
    except policy.PolicyError as e:
        return JSONResponse(
            status_code=404,
            content={"code": "unsupported_class", "message": str(e), "data": None},
        )
    return _ok(
        {
            "class_id": class_id,
            "alt_max_m": alt_max_m,
            "required_level": required_level,
        }
    )


@router.get("/binding")
def get_binding(
    class_id: int,
    plan_hash_hex: str,
    nonce_hex: str,
    session: Session = Depends(get_session),
):
    """申请绑定面（R1-1b）：政策查表+确定性挑战（HMAC，免存储/不可伪造）+pred_id 串。

    飞手侧实时出证消费——电路实例 19/20/21/22 由此钉定；受理时服务端独立重导出核对。
    """
    import time as _time

    from app.authz.policy import POLICY_VERSION, PolicyError, get_rule
    from app.authz.service import binding_challenge

    if len(plan_hash_hex) != 64 or len(nonce_hex) != 32:
        return _deny(AuthzError("bad_input", "plan_hash 须 64hex、nonce 须 32hex", 400))
    try:
        alt_max, required_level = get_rule(class_id)
    except PolicyError as e:
        return _deny(AuthzError(e.code, e.message, 403))
    challenge = bytes.fromhex(binding_challenge(plan_hash_hex, nonce_hex))
    t_epoch = int(_time.time())
    pred_id = f"{plan_hash_hex}|{nonce_hex}|{POLICY_VERSION}"
    return _ok(
        {
            "challenge_hex": challenge.hex(),
            "pred_id": pred_id,
            "policy_version": POLICY_VERSION,
            "t_epoch": t_epoch,
            "required_level": required_level,
            "alt_max": alt_max,
        }
    )


@router.get("/receipt/{code}")
def receipt(code: str, session: Session = Depends(get_session)):
    try:
        return _ok(receipt_of(session, code))
    except AuthzError as e:
        return _deny(e)


@router.get("/healthz")
def authz_healthz():
    return _ok({"status": "up"})
