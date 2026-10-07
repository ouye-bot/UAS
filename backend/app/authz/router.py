"""授权服务 API（B4）：匿名受理+回执取件。

端点：POST /authz/apply（匿名申请——门控序四步+入队）、
GET /authz/receipt/{code}（取件：waiting/ready+令牌密文/failed）、
GET /authz/healthz。零身份面：请求/响应/存储三层无身份字段。
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, Request
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
    from app.ra.smt import cached_tree

    s = SessionLocal()
    try:
        handles = [bytes.fromhex(r.handle_hex) for r in s.scalars(select(Revocation)).all()]
        # 批 4-7：增量树缓存（集合差分维护——撤销集不变时零重算；根与全量
        # 重算逐字节一致，test_ra_smt 钉定）。
        return (0, cached_tree(handles).root().hex())
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


def _anchor_mode() -> str:
    """链锚档位显式化（批 4-3）：读 FZ_CHAIN_ANCHOR——非 "fake" 即按 real
    口径报（与本仓各处 `== "fake"` 判定同口径，不引入第三种档位名）。"""
    return "fake" if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake" else "real"


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
    # 授权包配额制（2026-10-06 多架次拍板）：本授权覆盖架次数 1~5，缺省 1=
    # 与令牌一次性历史语义逐字等价（既有 e2e 全绿为证）
    sorties: int = Field(default=1, ge=1, le=5, description="架次配额（1~5，缺省 1）")


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
            case_id=case_id,  # 批 4-1：案卷唯一归属绑定/幂等/case_taken 判决
            sorties=body.sorties,  # 授权包配额制：worker recordAuth 透传上链
        )
    except AuthzError as e:
        return _deny(e)
    except ChainError as e:
        # R3-1.3（评审 P2-4）：链不可达=结构化快速失败（熔断窗内 <200ms），
        # 不再 500 裸奔
        return _deny(AuthzError("chain_unavailable", str(e), 503))
    from app.authz.models import Receipt

    r = session.get(Receipt, app_row.receipt_id)
    # 批 4-3 档位显式化：受理响应顶层携带链锚档（real/fake）——消费方不必
    # 猜「这份授权登记是否落了真链」。
    return _ok(
        {
            "application_id": app_row.id,
            "receipt_code": r.code_hex,
            "status": app_row.status,
            "sorties": app_row.sorties,
            "mode": _anchor_mode(),
        }
    )


@router.get("/engine/pub")
def engine_pub():
    """引擎验签公钥（公开面——飞手浏览器令牌验签基准）。

    R3-B2（评审 TCB 一致性）：公钥改由 backend 供给、桥接代理——桥进程
    不再持有 FZ_ENGINE_SK（政策引擎签名私钥），TCB 表述与部署对齐。"""
    from app.kms import engine_pub_hex

    return _ok({"engine_pub_hex": engine_pub_hex()})


def _credential_revoked_for_auth(session, auth_id: int) -> bool:
    """B4 兜底第二道：按 authId 反解其凭证轴（AuthRecord→Application→
    SubCredential pk′.x→Credential），凭证已吊销（status=2）或出示公钥已入
    撤销集 ⟹ True。链面 status 之外的本地权威镜像（RA 撤销集）——授权轴
    撤销（revokeAuth）漏网的凭证级吊销在此现形。数据链任一环缺失（历史/
    演示数据）=False（诚实不可判——链面 status 仍兜底）。"""
    from sqlalchemy import select

    from app.authz.models import Application, AuthRecord
    from app.ra.models import Credential, Revocation, SubCredential

    rec = session.scalar(select(AuthRecord).where(AuthRecord.auth_id == auth_id))
    if rec is None:
        return False
    app_row = session.get(Application, rec.application_id)
    if app_row is None:
        return False
    sub = (
        session.execute(
            select(SubCredential).where(
                SubCredential.sub_cred_hash_hex == app_row.sub_cred_hash_hex
            )
        )
        .scalars()
        .first()
    )
    if sub is None:
        return False
    if (
        session.scalar(
            select(Revocation.id).where(Revocation.handle_hex == sub.holder_pub_hex.lower()[:64])
        )
        is not None
    ):
        return True
    cred = session.get(Credential, sub.credential_id)
    return cred is not None and cred.status == 2


@router.get("/status")
def auth_status(
    auth_id: int,
    token_hash_hex: str = "",
    session: Session = Depends(get_session),
):
    """ARM 预检面（批1-1.1/1.5）：链上授权状态回读+令牌消费核查。

    桥端 attempt_arm 在令牌五查全过、写围栏前调用——签发后撤销（链上
    status 非 0）的授权在此现形。real 档：复用 _chain_binding("FlightAuthRegistry")
    回读 getAuth 的 status（0=有效/非 0=已撤销）+ IdentityRegistry.revEpoch
    （撤销纪元公示）。链不可达=503 信封（桥端 fail-closed 拒绝解锁）；
    授权不在链上（合约 require "bad authId"）=404 auth_not_found（同样
    fail-closed）。fake 档（FZ_CHAIN_ANCHOR 缺省 fake）：链面跳过，如实
    返回 mode=fake（演示假链档桥端放行但留痕）。

    token_consumed：一次性令牌**消费**标志（S1 全流程实弹根修 2026-10-06：
    签发≠消费——recordAuth 在取件前落 token_hash，若以"在案"当"已用"则
    正常首次 ARM 必被误拒〔S1 2.2 实弹抓出〕。现语义=auth_records.
    token_consumed_ts 非空，仅由桥 ARM 成功后的 /authz/consume 回报置位；
    删本地账本重放时服务端已消费=终拒）。
    授权包配额制（2026-10-06 多架次拍板）：响应增 remaining/sorties——
    remaining=剩余架次（真链档=链上 getAuth[11] 权威回读；fake 档=auth_records
    镜像），sorties=登记配额总数（库镜像）。供桥端/前端显示「剩余架次」与
    新架次放行判定；记录不在案（历史行/演示数据）=null（消费判词退回
    token_consumed 原语义，兼容不破）。"""
    from sqlalchemy import select

    from app.authz.models import AuthRecord

    token_consumed = False
    th = token_hash_hex.strip().lower()
    if len(th) == 64 and all(c in "0123456789abcdef" for c in th):
        token_consumed = (
            session.scalar(
                select(AuthRecord.token_consumed_ts).where(AuthRecord.token_hash_hex == th)
            )
            is not None
        )
    # 配额镜像（库面——真链档仅作 sorties 总数与 fake 档 remaining 源）。
    # 令牌哈希在场且形态合法时须成对匹配（与 /authz/consume 同键口径）；
    # 仅 auth_id 查询（回执面/测试）退化为按 authId 定位。
    th_valid = len(th) == 64 and all(c in "0123456789abcdef" for c in th)
    q = select(AuthRecord).where(AuthRecord.auth_id == auth_id)
    if th_valid:
        q = q.where(AuthRecord.token_hash_hex == th)
    quota_row = session.scalar(q)
    mirror_sorties = int(quota_row.sorties) if quota_row is not None else None
    mirror_remaining = int(quota_row.remaining) if quota_row is not None else None
    # B4 兜底第二道：凭证轴吊销镜像（RA 撤销集+凭证状态）随三形态恒回——
    # 桥端即使链面放行（fake 档/链抖动窗），credential_revoked=True 亦可拒。
    cred_revoked = _credential_revoked_for_auth(session, auth_id)
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
        return _ok(
            {
                "mode": "fake",
                "status": None,
                "rev_epoch": None,
                "token_consumed": token_consumed,
                "credential_revoked": cred_revoked,
                # 授权包配额制：fake 档 remaining=库镜像（消费回报递减的权威面）
                "remaining": mirror_remaining,
                "sorties": mirror_sorties,
            }
        )
    try:
        fa = _chain_binding("FlightAuthRegistry")
        rec = fa.call_fn("getAuth", [auth_id])
        status = int(rec[8])  # 11 元组第 9 位 status（0=有效 1=撤销）
        remaining = int(rec[11])  # 12 元组第 12 位 remaining（配额制链上权威值）
        ir = _chain_binding("IdentityRegistry")
        rev_epoch = int(ir.call_fn("revEpoch", [])[0])
    except ChainError as e:
        if "bad authId" in str(e):
            return JSONResponse(
                {
                    "ok": False,
                    "code": "auth_not_found",
                    "message": f"authId {auth_id} 不在授权注册表（令牌声称的授权无链上记录）",
                },
                status_code=404,
            )
        return JSONResponse(
            {
                "ok": False,
                "code": "chain_unavailable",
                "message": f"授权链不可达——按 fail-closed 策略应拒绝解锁: {str(e)[:150]}",
            },
            status_code=503,
        )
    except Exception as e:  # noqa: BLE001 —— binding 装配失败（abi/地址缺失等）同 503
        return JSONResponse(
            {
                "ok": False,
                "code": "chain_unavailable",
                "message": f"授权链绑定不可用——按 fail-closed 策略应拒绝解锁: {str(e)[:150]}",
            },
            status_code=503,
        )
    return _ok(
        {
            "mode": "real",
            "status": status,
            "rev_epoch": rev_epoch,
            "token_consumed": token_consumed,
            "credential_revoked": cred_revoked,
            # 授权包配额制：真链档 remaining=链上权威回读；sorties=库镜像总数
            "remaining": remaining,
            "sorties": mirror_sorties,
        }
    )


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
        # 批 4-3 档位显式化：回执 JSON 顶层携带链锚档（real/fake）。
        return _ok({**receipt_of(session, code), "mode": _anchor_mode()})
    except AuthzError as e:
        return _deny(e)


@router.get("/healthz")
def authz_healthz():
    return _ok({"status": "up"})


class ConsumeIn(BaseModel):
    auth_id: int
    token_hash_hex: str = Field(min_length=64, max_length=64)


@router.post("/consume")
def authz_consume(body: ConsumeIn, request: Request, session: Session = Depends(get_session)):
    """消费回报（S1 全流程实弹根修 2026-10-06；授权包配额制换代同日）。

    桥在 ARM 成功后回报——服务端消费账本不可删（桥本地 SQLite 可删重放，
    此处终拒）。X-Engine-Token 恒时比较（与遥测引擎面同式）。

    配额语义（2026-10-06 多架次拍板）：幂等语义从「令牌一次性 first 置位」
    上移为「remaining 递减」——每次回报 remaining-=1（真链档同步 engine 链写
    consumeSortie，链上值为权威并回写镜像）；remaining==0 时才置
    token_consumed_ts 终态（即最后一次架次的回报才终态）。remaining==0 再报
    =409 quota_exhausted（配额耗尽，fail-closed——桥端视作已入账终态弃重试）。
    响应增 remaining（递减后剩余架次）；consumed=本次回报后配额归零。
    首次回报 first=True 且 remaining=K-1（K=登记配额；缺省 1 时首报即终态，
    与令牌一次性历史语义逐字等价）。
    """
    import hmac as _hmac

    supplied = request.headers.get("X-Engine-Token", "")
    want = os.environ.get("FZ_ENGINE_TOKEN", "")
    if not supplied or not want or not _hmac.compare_digest(supplied, want):
        return JSONResponse(
            status_code=401,
            content={"ok": False, "code": "unauthorized", "message": "引擎转发面令牌缺失或不符"},
        )
    import datetime as _dt

    from app.authz.models import AuthRecord

    row = (
        session.query(AuthRecord)
        .filter(
            AuthRecord.auth_id == body.auth_id,
            AuthRecord.token_hash_hex == body.token_hash_hex.strip().lower(),
        )
        .one_or_none()
    )
    if row is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "code": "auth_not_found", "message": "授权记录不在案（token_hash 不匹配）"},
        )
    if int(row.remaining or 0) <= 0:
        return JSONResponse(
            status_code=409,
            content={
                "ok": False,
                "code": "quota_exhausted",
                "message": "授权包配额已耗尽（remaining=0）——本授权全部架次已消费",
            },
        )
    first = int(row.remaining or 0) == int(row.sorties or 1)
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") != "fake":
        # 真链档：engine 链写 consumeSortie——链上 remaining 为权威，回写镜像。
        # 链写失败/回执异常=503（桥端待回报队列下拍重试，fail-closed 不吞）；
        # 合约 revert（quota exhausted/auth revoked）=409（与镜像终态一致）。
        from app.chain.client import ChainError
        from app.zk.worker import WorkerDeps

        try:
            remaining = WorkerDeps().chain_consume_sortie(auth_id=int(body.auth_id))
        except ChainError as e:
            text = str(e)
            if "quota exhausted" in text or "auth revoked" in text:
                return JSONResponse(
                    status_code=409,
                    content={"ok": False, "code": "quota_exhausted",
                             "message": f"链上配额拒绝递减: {text[:120]}"},
                )
            return JSONResponse(
                status_code=503,
                content={"ok": False, "code": "chain_unavailable",
                         "message": f"配额链写不可达——桥端稍后重试: {text[:120]}"},
            )
        except Exception as e:  # noqa: BLE001 —— 回执事件缺失等：对账收口再 503
            # 交易可能已落地而事件解出失败（R2-c 同族形态）：remainingOf 回读
            # 对账——回读成功=以链上权威值继续（revert 态 remaining 原样/清零
            # 亦为真值）；回读失败=链不可用 503（桥端待回报队列重试）。
            try:
                from app.zk.worker import WorkerDeps as _WD

                fa = _WD()._flight_auth_binding()
                remaining = int(fa.call_fn("remainingOf", [int(body.auth_id)])[0])
            except Exception:  # noqa: BLE001
                return JSONResponse(
                    status_code=503,
                    content={"ok": False, "code": "chain_unavailable",
                             "message": f"配额链写回执异常——桥端稍后重试: {str(e)[:120]}"},
                )
        row.remaining = int(remaining)
    else:
        row.remaining = int(row.remaining or 0) - 1
    consumed = int(row.remaining) <= 0
    if consumed:
        row.remaining = 0
        row.token_consumed_ts = row.token_consumed_ts or _dt.datetime.utcnow()
    session.commit()
    return _ok({"first": first, "consumed": consumed, "remaining": int(row.remaining)})
