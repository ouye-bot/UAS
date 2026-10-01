"""双控协作请求服务（2026-09-29 账户批 B3；批二异步化）：审计发函→机构批准
→自动执行（后台）→审计结案。

密码学语义（设计方案 §4——双控从流程约束升格为密码学强制）：
- 请求内容哈希 req_hash = SM3("FZ-COLLAB-REQ|v1|令状哈希|附言")；
- 审计员钥签 req_hash（发函）；管理员钥签同一 req_hash（批准）；
- 服务端对两把钥各自 SM2 验签——缺任一签名请求到不了 executed；
- 批准即绑定"查什么"：挪用（换令状/换凭证）=验签失败/FZC2 AAD 失败。

批二改动（队长实测反馈）：
- approve 即返回（approved）——执行放后台线程（真链推链耗时不再卡死浏览器
  请求，NetworkError 根治）；状态轮询：pending→approved→executed|execute_failed；
- 执行失败结构化落库（execute_error）——历史纪元凭证（信封密钥已轮换，
  GCM 解封不可能）如实呈现"该立案的实名解锁密码学上不可达"而非 500；
- executed 后审计员确认结案（closed）——请求生命周期四拍完整：
  待批准→已批准·待执行→已执行·待结案→已结案。
"""

from __future__ import annotations

import datetime as dt
import threading

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.accounts.models import Account, CollabRequest
from app.audit.models import CollabIssued, Warrant
from app.crypto.sm2 import verify as sm2_verify
from app.crypto.sm3 import sm3_bytes

REQ_MSG_PREFIX = "FZ-COLLAB-REQ|v1|"
REJECT_MSG_PREFIX = "FZ-COLLAB-REJECT|v1|"

# 在途执行线程登记（同请求不重复拉起；进程级——演示单实例形态）
_executing: set[int] = set()
_exec_lock = threading.Lock()


class CollabError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 400) -> None:
        super().__init__(message or code)
        self.code = code
        self.status = status


def req_hash_of(warrant_hash_hex: str, note: str) -> str:
    return sm3_bytes((REQ_MSG_PREFIX + warrant_hash_hex + "|" + note).encode()).hex()


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


def _verify_action_sig(pubkey_hex: str | None, msg: str, sig_hex: str) -> None:
    if not pubkey_hex:
        raise CollabError("no_key", "签名人账户未生成密钥（未激活）", 409)
    if not sm2_verify(pubkey_hex, msg.encode(), sig_hex):
        raise CollabError("bad_sig", "签名验证失败——操作内容与签名不匹配", 401)


def create_request(
    session: Session,
    *,
    auditor: Account,
    warrant_hash_hex: str,
    note: str,
    sig_hex: str,
) -> CollabRequest:
    """审计发函：令状在案+未解锁+审计员签名验证→pending 请求（一令状一在途）。"""
    if auditor.role != "auditor":
        raise CollabError("forbidden", "仅审计员可发起协同解锁请求", 403)
    if not note.strip():
        raise CollabError("note_required", "请填写调查理由（批准人将据此判断）")
    wh = warrant_hash_hex.lower()
    w_row = session.execute(
        select(Warrant).where(Warrant.warrant_hash_hex == wh)
    ).scalar_one_or_none()
    if w_row is None:
        raise CollabError("warrant_not_found", "令状未登记（本地索引无此哈希）", 404)
    if w_row.unlocked_ts is not None:
        raise CollabError("already_unlocked", "该令状已解锁实名——无需再发起", 409)
    dup = session.execute(
        select(CollabRequest).where(
            CollabRequest.warrant_hash_hex == wh,
            CollabRequest.status == "pending",
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise CollabError("request_pending", "该令状已有在途协作请求——等待机构管理员处理", 409)
    rh = req_hash_of(wh, note.strip())
    _verify_action_sig(auditor.pubkey_hex, REQ_MSG_PREFIX + wh + "|" + note.strip(), sig_hex)
    row = CollabRequest(
        warrant_hash_hex=wh,
        case_no=w_row.case_no,
        target_auth_id=w_row.target_auth_id,
        legal_basis_text=w_row.legal_basis_text,
        note=note.strip(),
        req_hash_hex=rh,
        status="pending",
        auditor_username=auditor.username,
        auditor_sig_hex=sig_hex,
    )
    session.add(row)
    session.commit()
    return row


def request_view(session: Session, r: CollabRequest) -> dict:
    """请求视图（两台共用）：附上双方公钥指纹——批准人核对"谁签的"。

    指纹按**签名时点**的公钥纪元取（2026-09-30 公钥历史批）：换钥后历史
    请求行的指纹不漂移——指纹与行内签名恒同纪元（append-only 史保证可回取）。"""
    from app.accounts.service import pubkey_at

    auditor_pk = pubkey_at(session, r.auditor_username, r.created_ts)
    admin_pk = (
        pubkey_at(session, r.admin_username, r.decided_ts or r.created_ts)
        if r.admin_username
        else None
    )
    from app.crypto.sm3 import sm3_bytes as _sm3

    return {
        "id": r.id,
        "warrant_hash_hex": r.warrant_hash_hex,
        "case_no": r.case_no,
        "target_auth_id": r.target_auth_id,
        "legal_basis_text": r.legal_basis_text,
        "note": r.note,
        "req_hash_hex": r.req_hash_hex,
        "status": r.status,
        "auditor_username": r.auditor_username,
        "auditor_fp": (auditor_pk or "")[:16],
        "admin_username": r.admin_username,
        "admin_fp": (admin_pk or "")[:16] if admin_pk else None,
        "reject_reason": r.reject_reason,
        "execute_error": r.execute_error,
        "fzc2_fingerprint_hex": r.fzc2_fingerprint_hex,
        "created_ts": r.created_ts.isoformat() if r.created_ts else None,
        "decided_ts": r.decided_ts.isoformat() if r.decided_ts else None,
        "executed_ts": r.executed_ts.isoformat() if r.executed_ts else None,
        "req_fp": _sm3(r.req_hash_hex.encode()).hex()[:16],
    }


def list_requests(session: Session, status: str | None = None) -> list[dict]:
    q = select(CollabRequest).order_by(CollabRequest.id.desc()).limit(100)
    if status:
        q = q.where(CollabRequest.status == status)
    return [request_view(session, r) for r in session.scalars(q).all()]


def verify_request_sigs(session: Session, request_id: int) -> dict:
    """历史签名复验（公钥纪元史的直接消费面）：按**签名时点**的公钥复验
    双控两签。换钥（密码重置→重新激活）后旧签名仍验得过——双控不可抵赖
    的可演示判词：任一方事后称"这不是我签的"，以其当时纪元公钥当场复核。

    返回各签 {ok, epoch}；无纪元可回取（如签名早于账户注册——理论不可达）
    = ok:false + epoch:None（诚实形态，不臆造通过）。"""
    from app.accounts.service import pubkey_at, pubkey_epoch_at

    r = session.get(CollabRequest, request_id)
    if r is None:
        raise CollabError("request_not_found", "协作请求不存在", 404)
    msg = REQ_MSG_PREFIX + r.warrant_hash_hex + "|" + r.note

    def _one(username: str, sig_hex: str | None, ts) -> dict:
        if not sig_hex:
            return {"ok": False, "epoch": None, "reason": "no_sig"}
        pk = pubkey_at(session, username, ts)
        if not pk:
            return {"ok": False, "epoch": None, "reason": "no_epoch_key"}
        ok = sm2_verify(pk, msg.encode(), sig_hex)
        return {
            "ok": ok,
            "epoch": pubkey_epoch_at(session, username, ts),
            "reason": None if ok else "bad_sig",
        }

    return {
        "id": r.id,
        "req_hash_hex": r.req_hash_hex,
        "auditor": _one(r.auditor_username, r.auditor_sig_hex, r.created_ts),
        "admin": (
            _one(r.admin_username, r.admin_sig_hex, r.decided_ts or r.created_ts)
            if r.admin_username
            else {"ok": None, "epoch": None, "reason": "not_decided"}
        ),
    }


def approve_and_execute(
    session: Session,
    *,
    admin: Account,
    request_id: int,
    sig_hex: str,
    wait_s: float | None = None,
) -> dict:
    """批准（即返回）+自动执行（后台线程）。

    wait_s：None=HTTP 面（批准即返回 approved 视图，执行异步）；
    >0=测试/脚本面（阻塞等待终态，超时返回当前态）。
    幂等：approved/executing/executed 直接返回当前态（重复批准不重复执行）。
    """
    if admin.role != "admin":
        raise CollabError("forbidden", "仅机构管理员可批准", 403)
    r = session.get(CollabRequest, request_id)
    if r is None:
        raise CollabError("request_not_found", "协作请求不存在", 404)
    # 状态原子迁移（2026-09-30 评审 P1：ORM 读-改-写三步非原子——垃圾签名重批
    # 可把 executed 打回 execute_failed/并发双执行/approve-reject 竞态。条件
    # UPDATE 让数据库仲裁：仅 pending 可迁 approved，输家拿到 409 而非错态。）
    _verify_action_sig(admin.pubkey_hex, REQ_MSG_PREFIX + r.warrant_hash_hex + "|" + r.note, sig_hex)
    rowcount = session.query(CollabRequest).filter(
        CollabRequest.id == request_id, CollabRequest.status == "pending"
    ).update(
        {
            "status": "approved",
            "admin_username": admin.username,
            "admin_sig_hex": sig_hex,
            "decided_ts": _utcnow(),
        },
        synchronize_session=False,
    )
    session.commit()
    if rowcount == 0:
        session.expire(r)
        raise CollabError("bad_state", f"请求状态为 {r.status}——不可批准（仅待批准态可批）", 409)
    session.expire(r)  # 条件 UPDATE 绕过会话缓存——读视图前强制刷新
    thread = _spawn_execute(request_id)
    if wait_s and thread:
        thread.join(timeout=wait_s)
        session.expire_all()
        r = session.get(CollabRequest, request_id)
    return request_view(session, r)


def retry_execute(session: Session, *, admin: Account, request_id: int) -> dict:
    """执行失败重试（admin）：execute_failed → 后台再执行。"""
    if admin.role != "admin":
        raise CollabError("forbidden", "仅机构管理员可重试执行", 403)
    r = session.get(CollabRequest, request_id)
    if r is None:
        raise CollabError("request_not_found", "协作请求不存在", 404)
    if r.status != "execute_failed":
        raise CollabError("bad_state", f"请求状态为 {r.status}——仅执行失败态可重试", 409)
    r.status = "approved"
    r.execute_error = None
    session.commit()
    _spawn_execute(request_id)
    return request_view(session, r)


def close_request(session: Session, *, auditor: Account, request_id: int) -> dict:
    """审计员结案（executed→closed）：解锁实名已核实，案件闭环。"""
    if auditor.role != "auditor":
        raise CollabError("forbidden", "仅审计员可结案", 403)
    r = session.get(CollabRequest, request_id)
    if r is None:
        raise CollabError("request_not_found", "协作请求不存在", 404)
    rowcount = session.query(CollabRequest).filter(
        CollabRequest.id == request_id, CollabRequest.status == "executed"
    ).update({"status": "closed"}, synchronize_session=False)
    session.commit()
    if rowcount == 0:
        session.expire(r)
        raise CollabError("bad_state", f"请求状态为 {r.status}——须已执行（executed）方可结案", 409)
    session.expire(r)
    return request_view(session, r)


def recover_interrupted() -> int:
    """启动恢复（2026-09-30 评审 P1-6 根修）：后台执行线程在进程内存——服务
    重启即丢，approved 态残留会让机构台永久谎报"执行中"（僵尸卡）。启动时
    扫描 approved 残留 → execute_failed（人话原因，管理员可重试）。"""
    from app.db import SessionLocal

    s = SessionLocal()
    try:
        rows = s.scalars(
            select(CollabRequest).where(CollabRequest.status == "approved")
        ).all()
        for r in rows:
            r.status = "execute_failed"
            r.execute_error = "服务重启——后台执行被中断，请重试执行"
        s.commit()
        return len(rows)
    finally:
        s.close()


def _spawn_execute(request_id: int) -> threading.Thread | None:
    """拉起后台执行线程（独立会话——请求会话已随 HTTP 返回关闭）。"""
    with _exec_lock:
        if request_id in _executing:
            return None
        _executing.add(request_id)
    t = threading.Thread(target=_execute_worker, args=(request_id,), daemon=True)
    t.start()
    return t


def _execute_worker(request_id: int) -> None:
    from app.db import SessionLocal

    try:
        s = SessionLocal()
        try:
            r = s.get(CollabRequest, request_id)
            if r is None:
                return
            _execute(s, r=r)
        finally:
            s.close()
    except Exception as exc:  # noqa: BLE001  后台线程兜底：任何失败都落 execute_failed
        try:
            s = SessionLocal()
            try:
                r = s.get(CollabRequest, request_id)
                if r is not None:
                    r.status = "execute_failed"
                    r.execute_error = f"{type(exc).__name__}: {exc}"[:500]
                    s.commit()
            finally:
                s.close()
        except Exception:  # noqa: BLE001  落库自身失败=日志面（演示形态）
            import logging

            logging.getLogger("fz.collab").error(f"execute_failed 落库失败 req={request_id}")
    finally:
        with _exec_lock:
            _executing.discard(request_id)


def reject_request(
    session: Session,
    *,
    admin: Account,
    request_id: int,
    reason: str,
    sig_hex: str,
) -> dict:
    """驳回（自然业务路径）：理由必填+管理员签名→终态 rejected。"""
    if admin.role != "admin":
        raise CollabError("forbidden", "仅机构管理员可驳回", 403)
    r = session.get(CollabRequest, request_id)
    if r is None:
        raise CollabError("request_not_found", "协作请求不存在", 404)
    if r.status != "pending":
        raise CollabError("bad_state", f"请求状态为 {r.status}——不可驳回", 409)
    if not reason.strip():
        raise CollabError("reason_required", "驳回须填写理由（审计员将据此补充材料或重新立案）")
    _verify_action_sig(
        admin.pubkey_hex,
        REJECT_MSG_PREFIX + r.warrant_hash_hex + "|" + r.note + "|" + reason.strip(),
        sig_hex,
    )
    rowcount = session.query(CollabRequest).filter(
        CollabRequest.id == request_id, CollabRequest.status == "pending"
    ).update(
        {
            "status": "rejected",
            "admin_username": admin.username,
            "admin_sig_hex": sig_hex,
            "reject_reason": reason.strip(),
            "decided_ts": _utcnow(),
        },
        synchronize_session=False,
    )
    session.commit()
    if rowcount == 0:
        session.expire(r)
        raise CollabError("bad_state", f"请求状态为 {r.status}——不可驳回（仅待批准态可驳）", 409)
    session.expire(r)
    return request_view(session, r)


def _execute(session: Session, *, r: CollabRequest) -> dict:
    """执行（approved→executed）：原路复用 RA 出函与审计解锁——不自造捷径。
    失败一律 CollabError（后台线程落 execute_failed）——含历史纪元凭证的
    RaError 映射（GCM 解封不可能=密码学上不可达，如实呈现）。"""
    # ① RA 出函（FZC2 函-令状-凭证三方绑定+出具台账）——复用 ra/router 原逻辑
    from app.ra.collab import collab_fingerprint, open_collab_v2, seal_collab_v2
    from app.ra.scope import resolve_cred_for_auth
    from app.ra.service import RaError
    from app.audit.service import AuditError, AuditService
    from app.audit.router import _deps as audit_deps

    w_row = session.execute(
        select(Warrant).where(Warrant.warrant_hash_hex == r.warrant_hash_hex)
    ).scalar_one_or_none()
    if w_row is None:
        raise CollabError("warrant_not_found", "令状不在案", 404)
    if r.target_auth_id is not None:
        cred_hex = resolve_cred_for_auth(session, r.target_auth_id)
        if not cred_hex:
            raise CollabError(
                "cred_unresolved",
                "该授权编号的凭证映射不可得（登记链缺失）——无法出函",
                409,
            )
    else:
        raise CollabError(
            "cred_required",
            "该令状未指定目标授权编号——自动执行不可达，请走带凭证的重新立案",
            409,
        )
    code = seal_collab_v2(cred_hex, r.warrant_hash_hex)
    session.add(
        CollabIssued(
            warrant_hash_hex=r.warrant_hash_hex,
            master_cred_hash_hex=cred_hex,
            code_fingerprint_hex=collab_fingerprint(code),
        )
    )
    session.commit()
    r.fzc2_fingerprint_hex = collab_fingerprint(code)
    # ② 审计侧解锁（open FZC2→scope 校验→AuditService.unlock 链上留痕）——原路
    cred_back = open_collab_v2(code, r.warrant_hash_hex)  # 双向自证：封出即解
    if cred_back != cred_hex:
        raise CollabError("fzc2_roundtrip_failed", "协作函自证失败（封解不一致）——已中止", 500)
    svc = AuditService(session, audit_deps())
    try:
        out = svc.unlock(warrant_hash_hex=r.warrant_hash_hex, master_cred_hash_hex=cred_hex)
    except AuditError as exc:
        session.commit()
        raise CollabError(exc.code, str(exc), 409) from exc
    except RaError as exc:
        # 历史纪元凭证（信封以已轮换密钥封装）——解封在密码学上不可达：
        # 如实呈现而非 500（2026-09-29 队长实测 approve 报错根因定谳）
        session.commit()
        if exc.code == "unwrap_failed":
            raise CollabError(
                "unwrap_failed",
                "该凭证信封以已轮换的域密钥封装——实名解锁在密码学上不可达"
                "（历史纪元数据）。请针对当前纪元的授权重新立案调查",
                409,
            ) from exc
        raise CollabError(exc.code, str(exc), getattr(exc, "status", 409) or 409) from exc
    rowcount = session.query(CollabRequest).filter(
        CollabRequest.id == r.id, CollabRequest.status == "approved"
    ).update({"status": "executed", "executed_ts": _utcnow()}, synchronize_session=False)
    session.commit()
    if rowcount == 0:
        raise CollabError("bad_state", "请求在执行完成前已离开 approved 态——结果丢弃", 409)
    session.expire(r)
    view = request_view(session, r)
    view["unlocked"] = out
    return view
