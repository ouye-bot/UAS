"""RA API（B2；2026-10-04 撤销业务线硬化 B1/B4/B6/B7）——统一信封
{code, data, message}（HTTP 状态码随负例语义）。

端点：POST /ra/register、POST /ra/sub-credentials、GET /ra/revocation/snapshot、
POST /ra/revoke、POST /ra/revoke/by-username（均 admin 会话+SM2 签名+理由必填；
by-username 配 GET /ra/revoke/by-username/preview 两步式预览——前端签名须覆盖
该用户全部有效凭证句柄串）、POST /ra/restore/request（admin 发起）、
POST /ra/restore/{id}/countersign（auditor 复核——双控恢复）、
GET /ra/restore/requests（admin+auditor 双面——审计员复核前看待复核列表）、
GET /ra/healthz。
链上副作用：FZ_CHAIN_ANCHOR=fake 时落内存记录（测试断言），默认真链
（B1 接入层直调 IdentityRegistry；授权联动直调 FlightAuthRegistry——engine 钥）。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.accounts.deps import require_role
from app.chain.client import ChainError
from app.db import get_session
from app.ra.models import Revocation
from app.ra.service import ChainAnchor, RaDeps, RaError, RaService

router = APIRouter(prefix="/ra", tags=["ra"])

_deps_cache: dict[str, Any] = {}


class _FakeChain:
    """fake 链锚（FZ_CHAIN_ANCHOR=fake：记录调用供测试断言，零链副作用）。"""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []

    def __call__(self, fn: str, args: list) -> None:
        self.calls.append((fn, list(args)))


def _chain_rev_epoch() -> int:
    """链上撤销纪元权威（B2 教训：链上全局状态单权威——本地纪元漂移到
    require(epoch==revEpoch+1) 必 revert。R4 第二批实弹定谳：真链 revEpoch=43
    vs 本地 0，首个真链吊销即 0x16——API 层 RaDeps 此前漏注入 chain_rev_epoch）。"""
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_ra_tx_key

    signer = TxSigner(chain_ra_tx_key())
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=signer.address,
    )
    ir = load_binding("IdentityRegistry", client, _identity_address())
    return int(ir.call_fn("revEpoch", [])[0])


def _ra_deps() -> RaDeps:
    if "deps" not in _deps_cache:
        from app.kms import ra_signing_keypair
        from app.ra.service import AUTH_REVOKE_REASON_LINKAGE

        priv, pub = ra_signing_keypair()
        if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
            anchor: ChainAnchor = ChainAnchor(call=_FakeChain())
            fake_call = anchor.call

            def _fake_auth_revoke(aid: int) -> dict:
                """fake 档授权轴联动：无真链副作用，经 fake anchor 留痕供断言。"""
                fake_call("revoke_auth", [int(aid), AUTH_REVOKE_REASON_LINKAGE])
                return {"ok": True, "detail": "fake 档：revokeAuth 留痕（无真链副作用）"}

            _deps_cache["deps"] = RaDeps(
                ra_priv_hex=priv, ra_pub_hex=pub, anchor=anchor, auth_revoke=_fake_auth_revoke
            )
        else:
            anchor = ChainAnchor(call=_real_chain_call, warrant_on_chain=_real_warrant_on_chain)
            _deps_cache["deps"] = RaDeps(
                ra_priv_hex=priv,
                ra_pub_hex=pub,
                anchor=anchor,
                chain_rev_epoch=_chain_rev_epoch,
                auth_revoke=_real_auth_revoke,
            )
            _startup_align()
    return _deps_cache["deps"]


def _real_auth_revoke(auth_id: int) -> dict:
    """真链授权轴联动（B4）：FlightAuthRegistry.revokeAuth(authId, reason=2)，
    engine 交易钥（KMS 派生，与 worker recordAuth 同域）。已撤销态如实跳过
    （合约 require status==0，盲发必 revert）——返回 ok=False+明细。"""
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_engine_tx_key
    from app.ra.service import AUTH_REVOKE_REASON_LINKAGE

    signer = TxSigner(chain_engine_tx_key())
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=signer.address,
    )
    p = Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
    addr = json.loads(p.read_text())["FlightAuthRegistry"]["address"]
    fa = load_binding("FlightAuthRegistry", client, addr)
    status = int(fa.call_fn("getAuth", [auth_id])[8])  # 11 元组第 9 位 status（0=有效）
    if status != 0:
        return {"ok": False, "detail": f"链上已是撤销态（status={status}）——如实跳过"}
    fa.send_fn(signer, "revokeAuth", [auth_id, AUTH_REVOKE_REASON_LINKAGE])
    return {"ok": True, "detail": "revokeAuth 已上链（reason=2 凭证吊销联动）"}


def _startup_align() -> None:
    """真链档启动对账（P0-5）：撤销根漂移自愈——不一致即推链，异常不阻塞启动。"""
    try:
        from app.ra.align import startup_align

        out = startup_align()
        if out.get("pushed"):
            print(f"[ra] 撤销根已对齐（推链 epoch={out['epoch']}）", flush=True)
    except Exception as e:  # noqa: BLE001  链不可达不阻塞——首次锚定写面诚实暴露
        print(f"[ra] ⚠ 撤销根对账失败（不阻塞启动）: {e}", flush=True)


def _reset_deps_cache() -> None:
    """测试钩子：env 切换后强制重建 deps。"""
    _deps_cache.pop("deps", None)


def _real_warrant_on_chain(wh: bytes) -> bool:
    """真链令状在案查询（B7 接线：IdentityRegistry.warrants 回读）。"""
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_ra_tx_key

    # call 必须带有效 from（FISCO 2.x 零地址 from 静默返回空——旧系统 MEMORY 事实#1）
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=TxSigner(chain_ra_tx_key()).address,
    )
    # 阶段二修复：address 实参缺失（设计即接口雷㊿+23 同型——真链解锁首跑暴露）
    ir = load_binding("IdentityRegistry", client, _identity_address())
    return bool(ir.call_fn("warrants", [wh])[0])


def _real_chain_call(fn: str, args: list) -> None:
    """真链锚：B1 接入层直调 IdentityRegistry（registerCommitment/setStatus/setRevocationRoot）。

    bytesN 参数规范化（阶段一修复：service 层传 "0x…" hex str，abi_encode 须
    bytes——HTTP 面真链 register 首跑即炸的根因；audit/router b32 同模式）。
    """
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_ra_tx_key

    b32 = lambda v: (  # noqa: E731
        bytes.fromhex(str(v).removeprefix("0x")) if isinstance(v, str) else v
    )
    ra = TxSigner(chain_ra_tx_key())
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"), from_addr=ra.address
    )
    binding = load_binding("IdentityRegistry", client, _identity_address())
    fn_map = {
        "register_commitment": "registerCommitment",
        "set_status": "setStatus",
        "set_revocation_root": "setRevocationRoot",
        "log_warrant_unlock": "logWarrantUnlock",  # B7：解锁留痕（onlyRA）
    }
    args = [b32(a) for a in args]
    receipt = binding.send_fn(ra, fn_map[fn], args)
    if str(receipt.get("status", "0x0")) != "0x0":  # pragma: no cover send_fn 已内置断言
        raise RuntimeError(f"链上 {fn_map[fn]} 回执异常")


def _identity_address() -> str:
    p = Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
    return json.loads(p.read_text())["IdentityRegistry"]["address"]


class RegisterIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    id_number: str = Field(min_length=18, max_length=18)
    cert_level: int = Field(ge=1, le=4)
    sn: str = Field(min_length=1, max_length=64)
    user_pub_hex: str = Field(min_length=128, max_length=128)
    class_id: int = Field(default=0, ge=0, le=255)  # 机型类（B4/A4：进 C 原像）


class SubCredIn(BaseModel):
    master_cred_hash_hex: str = Field(min_length=64, max_length=64)
    salt_hex: str = Field(min_length=32, max_length=32)
    id_number: str = Field(min_length=18, max_length=18)
    cert_level: int = Field(ge=1, le=4)
    sn: str = Field(min_length=1, max_length=64)
    holder_pub_hex: str = Field(min_length=128, max_length=128)


class RevokeIn(BaseModel):
    """B1 升格：理由必填（≥4 字，服务层强制——信封语义拒而非 422 裸奔）+
    admin SM2 签名（FZ-REVOKE|v1|{handles 排序}|{reason}|{epoch}）+目标纪元。"""

    master_cred_hash_hex: str = Field(min_length=64, max_length=64)
    reason: str = Field(default="", max_length=500)
    sig_hex: str = Field(default="", max_length=512)
    epoch: int = Field(default=0, ge=0)


class RevokeByUsernameIn(BaseModel):
    """按人级联吊销（R4 第二批 B-P2-5）——机构管理员运维面（账户批：角色守卫门禁）。
    B1 升格：理由必填+admin SM2 签名+目标纪元（同 /ra/revoke 消息域）。"""

    username: str = Field(min_length=1, max_length=64)
    reason: str = Field(default="", max_length=500)
    sig_hex: str = Field(default="", max_length=512)
    epoch: int = Field(default=0, ge=0)


class RestoreRequestIn(BaseModel):
    """B6 双控恢复·admin 发起：签名域 FZ-RESTORE|v1|{handle}|{reason}。"""

    handle_hex: str = Field(min_length=64, max_length=64)
    reason: str = Field(default="", max_length=500)
    sig_hex: str = Field(default="", max_length=512)


class RestoreCountersignIn(BaseModel):
    """B6 双控恢复·auditor 复核：签名域 FZ-RESTORE-COUNTERSIGN|v1|{handle}|{reason}
    （handle/reason 取自请求行——复核即绑定同一内容，换内容=验签失败）。"""

    sig_hex: str = Field(default="", max_length=512)


_ERR_STATUS = {
    "bad_preimage": 403,
    "cred_revoked": 403,
    "revoked": 403,
    "holder_revoked": 403,
    "cred_expired": 409,
    "quota_exceeded": 429,
    "not_found": 404,
    "bad_input": 400,
    "chain_unavailable": 503,
    "id_revoked_before": 409,
}


def _ok(data: Any) -> JSONResponse:
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": data})


def _deny(exc: RaError) -> JSONResponse:
    # B-P1-2：语义映射优先（revoked=403/quota=429 等既有语义），无映射时用
    # 错误实例携带的显式 status（chain_unavailable=503——__init__ 缺参曾使
    # 该路径抛 TypeError 变裸 500），最终缺省 400
    status = _ERR_STATUS.get(exc.code) or getattr(exc, "status", None) or 400
    return JSONResponse(
        status_code=status,
        content={"code": exc.code, "message": str(exc), "data": None},
    )


def _svc(session: Session) -> RaService:
    return RaService(session, _ra_deps())


def _admin_pub(session: Session, username: str) -> str:
    """动作签名人（会话主体）当前公钥——accounts 表单一事实源（collab 双控同源）。"""
    from app.accounts.service import get_account

    acc = get_account(session, username)
    if not acc.pubkey_hex:
        raise RaError("no_key", "签名人账户未生成密钥（未激活）", 409)
    return acc.pubkey_hex


def _register_impl(body: RegisterIn, session: Session = Depends(get_session)):
    try:
        return _ok(_svc(session).register(**body.model_dump()))
    except RaError as exc:
        return _deny(exc)


@router.post("/register")
def register(body: RegisterIn, session: Session = Depends(get_session)):
    try:
        return _register_impl(body, session)
    except ChainError as e:
        return _deny(RaError("chain_unavailable", str(e), 503))


@router.post("/sub-credentials")
def sub_credentials(body: SubCredIn, session: Session = Depends(get_session)):
    try:
        return _ok(_svc(session).issue_sub_credential(**body.model_dump()))
    except RaError as exc:
        return _deny(exc)


@router.get("/pubkey")
def ra_pubkey():
    """RA 签名公钥（公开面——飞手侧出证组装消费）。"""
    from app.kms import ra_pub_hex_of

    return _ok({"ra_pub_hex": ra_pub_hex_of()})


@router.get("/revocation/witness")
def revocation_witness(holder_pk_hex: str, session: Session = Depends(get_session)):
    """撤销非成员见证分发（公开镜像——匿名获取；B3b 深度 32，键=pk′.x）。"""
    from app.ra.smt import cached_tree

    if len(holder_pk_hex) != 128 or not all(c in "0123456789abcdef" for c in holder_pk_hex.lower()):
        return _deny(RaError("bad_input", "公钥须 128 hex（x‖y）"))
    key = bytes.fromhex(holder_pk_hex.lower()[:64])  # 键=pk′.x（32B）
    handles = [bytes.fromhex(r.handle_hex) for r in session.scalars(select(Revocation)).all()]
    if key in handles:
        # R3-0.3 fail-fast：成员键无非成员见证——诚实拒绝而非让申请烧完出证
        # 后死于 root.fold（三代理评审 P0-1 配套面）。
        return _deny(RaError("revoked", "该出示公钥已列入撤销名单——申请将被数学拒绝"))
    # 批 4-7：增量树缓存（集合差分维护——插入/撤销只重算脏路径；根与全量
    # 重算逐字节一致，test_ra_smt 钉定）。
    tree = cached_tree(handles)
    w = tree.non_membership_witness(key)
    # 纪元取 max(叶纪元, 台账纪元)——B6 恢复（摘叶不落叶行）后公示纪元仍单调
    from sqlalchemy import func

    from app.ra.models import RevocationLedger

    led_epoch = session.scalar(select(func.max(RevocationLedger.epoch))) or 0
    return _ok(
        {
            "siblings_hex": w["siblings"],
            "root_hex": tree.root().hex(),
            "epoch": max(
                max((r.epoch for r in session.scalars(select(Revocation)).all()), default=0),
                int(led_epoch),
            ),
        }
    )


@router.get("/revocation/snapshot")
def revocation_snapshot(session: Session = Depends(get_session)):
    return _ok(_svc(session).snapshot())


@router.post("/revoke")
def revoke(
    body: RevokeIn,
    session: Session = Depends(get_session),
    p=Depends(require_role("admin")),
):
    """按凭证吊销（B1 升格）：admin 会话+理由≥4 字+SM2 签名+纪元绑定。"""
    try:
        return _ok(
            _svc(session).revoke(
                master_cred_hash_hex=body.master_cred_hash_hex,
                reason=body.reason,
                admin_sig_hex=body.sig_hex,
                epoch=body.epoch,
                admin_username=p.username,
                admin_pub_hex=_admin_pub(session, p.username),
            )
        )
    except RaError as exc:
        return _deny(exc)
    except ChainError as e:
        return _deny(RaError("chain_unavailable", str(e), 503))


@router.post("/revoke/by-username")
def revoke_by_username(
    body: RevokeByUsernameIn,
    session: Session = Depends(get_session),
    p=Depends(require_role("admin")),
):
    """按人级联吊销（R4 第二批 B-P2-5；B1 升格）：该用户全部有效凭证一次撤销
    （同纪元同根一次推链）+授权轴联动（B4）+黑名单（B7）——封「按凭证吊销可
    逃逸」（重新登记即获新有效凭证）。"""
    try:
        return _ok(
            _svc(session).revoke_by_username(
                username=body.username,
                reason=body.reason,
                admin_sig_hex=body.sig_hex,
                epoch=body.epoch,
                admin_username=p.username,
                admin_pub_hex=_admin_pub(session, p.username),
            )
        )
    except RaError as exc:
        return _deny(exc)
    except ChainError as e:
        return _deny(RaError("chain_unavailable", str(e), 503))


@router.post("/restore/request")
def restore_request(
    body: RestoreRequestIn,
    session: Session = Depends(get_session),
    p=Depends(require_role("admin")),
):
    """B6 双控恢复·第一签（admin 发起）：pending 请求落库，不执行任何恢复。"""
    try:
        return _ok(
            _svc(session).restore_request(
                handle_hex=body.handle_hex,
                reason=body.reason,
                admin_username=p.username,
                admin_sig_hex=body.sig_hex,
            )
        )
    except RaError as exc:
        return _deny(exc)


@router.post("/restore/{request_id}/countersign")
def restore_countersign(
    request_id: int,
    body: RestoreCountersignIn,
    session: Session = Depends(get_session),
    p=Depends(require_role("auditor")),
):
    """B6 双控恢复·第二签（auditor 复核）：双签齐→执行（SMT 摘叶+setStatus(1)
    +新纪元根推链+台账）。admin 到不了本端点（403 角色守卫）——发起人不得
    自行复核。"""
    try:
        return _ok(
            _svc(session).restore_countersign(
                request_id=request_id,
                auditor_username=p.username,
                countersign_sig_hex=body.sig_hex,
            )
        )
    except RaError as exc:
        return _deny(exc)


@router.get("/restore/requests")
def restore_requests(
    session: Session = Depends(get_session), _p=Depends(require_role("admin", "auditor"))
):
    """双控恢复请求列表（admin+auditor 双面——机构台可视化面+审计员复核前置：
    复核人须先看到待复核列表（句柄/理由/发起人）才能拼 FZ-RESTORE-COUNTERSIGN
    消息签名；pilot 恒 403）。"""
    return _ok({"items": _svc(session).restore_requests_list()})


@router.get("/revoke/by-username/preview")
def revoke_by_username_preview(
    username: str,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """按人吊销·两步式第一拍（只读预览，B1 升格配套）：FZ-REVOKE 签名消息须
    覆盖该用户全部有效凭证句柄串——前端无法预知句柄集，先经本端点取句柄与
    目标纪元（公示纪元+1），本地拼消息签名后再调 POST /ra/revoke/by-username。
    只读不落库；用户不存在 404/无有效凭证 409（与正式端点同判）。"""
    try:
        return _ok(_svc(session).revoke_preview_by_username(username=username))
    except RaError as exc:
        return _deny(exc)


class CollabIn(BaseModel):
    warrant_hash_hex: str = Field(min_length=64, max_length=64)
    # 目标授权编号为空的令状（匿名立案位）：RA 显式提供凭证（仍与令状绑定）
    master_cred_hash_hex: str | None = Field(default=None, min_length=64, max_length=64)


@router.get("/collab/pending")
def collab_pending(session: Session = Depends(get_session), _p=Depends(require_role("admin"))):
    """待协作令状列表（F 席改造：机构管理员的核验工作面）——未解锁令状。"""
    from sqlalchemy import select

    from app.audit.models import Warrant

    rows = (
        session.execute(
            select(Warrant)
            .where(Warrant.unlocked_ts.is_(None))
            .order_by(Warrant.created_ts.desc())
            .limit(20)
        )
        .scalars()
        .all()
    )
    return _ok(
        [
            {
                "warrant_hash_hex": w.warrant_hash_hex,
                "case_no": w.case_no,
                "target_auth_id": w.target_auth_id,
                "legal_basis_text": w.legal_basis_text,
                "created_ts": w.created_ts.isoformat() if w.created_ts else None,
            }
            for w in rows
        ]
    )


@router.post("/collab-code")
def collab_code(
    body: CollabIn,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """随案协作函出具（P1 阶段三；2026-09-28 F 席根修）：
    - 必须针对在案且未解锁的令状出具（FZC2：函-令状-凭证三方 AAD 绑定，
      一函一令状——旧 FZC1 不绑定令状的缺陷封堵，FZC1 仅解析不再新发）；
    - 范围校验：令状目标授权编号 ↔ 凭证 不一致=409 scope_mismatch；
    - 出具写台账（collab_issued）——出具行为自身可追溯。"""
    from sqlalchemy import select

    from app.audit.models import CollabIssued, Warrant
    from app.ra.collab import collab_fingerprint, seal_collab_v2
    from app.ra.scope import resolve_cred_for_auth

    w_row = session.execute(
        select(Warrant).where(Warrant.warrant_hash_hex == body.warrant_hash_hex)
    ).scalar_one_or_none()
    if w_row is None:
        return JSONResponse(
            status_code=404,
            content={"code": "warrant_not_found", "message": "令状不在案（哈希不匹配）"},
        )
    if w_row.unlocked_ts is not None:
        return JSONResponse(
            status_code=409,
            content={"code": "already_unlocked", "message": "该令状已解锁实名——无需再出函"},
        )
    # 凭证由服务端从授权链解析（auth_id→Application→SubCredential→Credential）
    # ——RA 操作员永不手输哈希（F 席✗✗断点根修：此前人类无法从任何页面获得
    # 凭证哈希，出函只能靠脚本）。映射不可得=409 诚实拒绝。
    if w_row.target_auth_id is not None:
        # 目标授权在案：凭证由服务端从授权链解析（RA 永不手输哈希——
        # F 席✗✗断点根修：此前人类无法从任何页面获得凭证哈希）
        cred_hex = resolve_cred_for_auth(session, w_row.target_auth_id)
        if not cred_hex:
            return JSONResponse(
                status_code=409,
                content={
                    "code": "cred_unresolved",
                    "message": "该授权编号的凭证映射不可得（登记链缺失）——无法出函",
                },
            )
    else:
        cred_hex = body.master_cred_hash_hex
        if not cred_hex:
            return JSONResponse(
                status_code=400,
                content={
                    "code": "cred_required",
                    "message": "该令状未指定目标授权——请同时提供凭证哈希（FZC2 仍与令状绑定）",
                },
            )
    code = seal_collab_v2(cred_hex, body.warrant_hash_hex)
    session.add(
        CollabIssued(
            warrant_hash_hex=body.warrant_hash_hex,
            master_cred_hash_hex=cred_hex,
            code_fingerprint_hex=collab_fingerprint(code),
        )
    )
    session.commit()
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "",
            "data": {"code": code, "fingerprint": collab_fingerprint(code)},
        },
    )


@router.get("/healthz")
def ra_healthz():
    return {"service": "ra", "ok": True}
