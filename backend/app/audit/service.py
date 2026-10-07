"""审计台服务（B7）：令状生命周期——创建上链→协作解锁→解锁留痕→追溯视图。

追溯链路（验收门「事件→个人全链留痕」）：
  违规事件（TelemetryAnchor.recordEvent，链上）
    → 审计台创建令状（IdentityRegistry.logWarrant，onlyAuditor 上链）
    → RA 协作解锁（A3 通道②：链上在案核验→unwrap 实名映射）
    → 解锁留痕（IdentityRegistry.logWarrantUnlock，onlyRA 上链一次性）
    → 追溯视图=令状+解锁面+链上留痕回读（getAuth/检查点/事件 by authId）。

认证：X-Audit-Token（KMS 审计域派生——无密码体系，密钥即身份）。
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.audit.models import Warrant
from app.chain.client import ChainError
from app.crypto.sm3 import sm3_bytes


class AuditError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ChainAuditAnchor:
    """链上副作用/查询回调（fn∈{log_warrant, log_warrant_unlock}）。"""

    call: Callable[[str, list], None]
    warrant_on_chain: Callable[[bytes], bool]
    warrant_unlocked_on_chain: Callable[[bytes], bool]
    # 追溯视图留痕回读（authId→授权记录/检查点/事件；真链实现走 ChainClient）
    trace_auth: Callable[[int], dict] = lambda _aid: {}
    chain_fingerprint: Callable[[], str] = lambda: ""


@dataclass
class AuditDeps:
    anchor: ChainAuditAnchor
    # RA 协作解锁（A3 通道②消费——服务级复用，非 HTTP 自调）
    ra_unlock: Callable[[str, str], dict]
    now: Callable[[], dt.datetime] = dt.datetime.utcnow


_WARRANT_DOMAIN = b"FZ-WARRANT|"


def warrant_hash_of(case_no: str, scope: bytes) -> bytes:
    """令状哈希：SM3(域‖案号‖scope)——案号+范围唯一确定令状。"""
    return sm3_bytes(_WARRANT_DOMAIN + case_no.encode() + b"|" + scope)


class AuditService:
    def __init__(self, session: Session, deps: AuditDeps) -> None:
        self._s = session
        self._d = deps

    def create_warrant(
        self,
        *,
        case_no: str,
        legal_basis_hash_hex: str,
        target_auth_id: int | None = None,
        note: str = "",
        legal_basis_text: str | None = None,
    ) -> dict:
        if not case_no or len(case_no) > 128:
            raise AuditError("bad_input", "案号须 1..128 字符")
        lb = bytes.fromhex(legal_basis_hash_hex)
        if len(lb) != 32:
            raise AuditError("bad_input", "法律依据哈希须 32B/64hex")
        # 目标授权存在性（F 席严谨性：笔误 authId 可立案=立案面不严肃）。
        # auth_id 为空=未指定目标（允许——匿名立案演进位）。
        if target_auth_id is not None:
            from sqlalchemy import select

            from app.authz.models import AuthRecord

            if (
                self._s.scalar(select(AuthRecord).where(AuthRecord.auth_id == target_auth_id))
                is None
            ):
                raise AuditError(
                    "warrant_target_unknown",
                    f"目标授权编号 #{target_auth_id} 不存在（无此授权记录）",
                )
        scope = sm3_bytes(
            b"FZ-SCOPE|" + str(target_auth_id or 0).encode() + b"|" + case_no.encode()
        )
        wh = warrant_hash_of(case_no, scope)
        from sqlalchemy import select

        if self._s.scalar(select(Warrant).where(Warrant.warrant_hash_hex == wh.hex())):
            raise AuditError("warrant_exists", "同案号+范围的令状已登记（append-only）")
        if self._d.anchor.warrant_on_chain(wh):
            raise AuditError("warrant_exists", "链上已有此令状哈希（案号冲突）")
        # 上链（onlyAuditor）——WarrantLogged 事件即「审计行为本身被审计」锚
        self._d.anchor.call("log_warrant", [wh, scope])
        row = Warrant(
            warrant_hash_hex=wh.hex(),
            case_no=case_no,
            scope_hash_hex=scope.hex(),
            legal_basis_hash_hex=legal_basis_hash_hex,
            legal_basis_text=(legal_basis_text or None),
            target_auth_id=target_auth_id,
            note=note,
        )
        self._s.add(row)
        self._s.commit()
        return self._warrant_view(row)

    def unlock(self, *, warrant_hash_hex: str, master_cred_hash_hex: str) -> dict:
        wh = bytes.fromhex(warrant_hash_hex)
        if len(wh) != 32:
            raise AuditError("bad_input", "令状哈希须 32B/64hex")
        from sqlalchemy import select

        row = self._s.scalar(select(Warrant).where(Warrant.warrant_hash_hex == wh.hex()))
        if row is None:
            raise AuditError("warrant_not_found", "令状未登记（本地索引无此哈希）")
        # 链核验失败诚实降级（2026-09-28 审计台 500 定谳）：ChainError 非
        # AuditError，此前直穿 500；且"本地有、链上无"=登记时链不可达的幽灵
        # 令状，需给针对性文案而非泛化错误。
        try:
            on_chain = self._d.anchor.warrant_on_chain(wh)
            already_on_chain = self._d.anchor.warrant_unlocked_on_chain(wh)
        except ChainError as e:
            raise AuditError(
                "chain_unreachable",
                f"链不可达——无法核验令状登记状态，请确认链在线后重试：{e}",
            ) from e
        if not on_chain:
            raise AuditError(
                "warrant_not_on_chain",
                "链上无此令状记录——该令状登记时链不可达（幽灵令状），请删除后重新登记立案",
            )
        if row.unlocked_ts is not None or already_on_chain:
            raise AuditError("already_unlocked", "该令状已解锁（一次性——追加更正须新令状）")
        # RA 协作解锁（A3 通道②：unwrap 实名映射+链上解锁留痕 logWarrantUnlock）
        result = self._d.ra_unlock(warrant_hash_hex, master_cred_hash_hex)
        row.unlocked_ts = self._d.now()
        row.unlocked_master_cred_hash_hex = master_cred_hash_hex
        row.unlocked_username = result["username"]
        row.unlocked_id_number = result["id_number"]
        row.unlocked_sn = result.get("sn")  # SN v2：设备交叉审计数据源
        self._s.commit()
        return self._warrant_view(row)

    def list_warrants(self) -> list[dict]:
        from sqlalchemy import select

        rows = self._s.scalars(select(Warrant).order_by(Warrant.id)).all()
        return [self._warrant_view(r) for r in rows]

    def trace(self, *, warrant_hash_hex: str) -> dict:
        from sqlalchemy import select as _select

        row = self._s.scalar(_select(Warrant).where(Warrant.warrant_hash_hex == warrant_hash_hex))
        if row is None:
            raise AuditError("warrant_not_found", "令状未登记")
        out: dict[str, Any] = {"warrant": self._warrant_view(row)}
        if row.target_auth_id is not None:
            out["chain_trace"] = self._d.anchor.trace_auth(row.target_auth_id)
            # 设备一致性核对（SN v2）：解锁后以登记 SN₁ 派生公钥验检查点签名
            if row.unlocked_ts and row.unlocked_master_cred_hash_hex:
                out["chain_trace"]["device_check"] = self._device_check(
                    row.unlocked_master_cred_hash_hex, row.target_auth_id
                )
        out["chain_fingerprint"] = self._d.anchor.chain_fingerprint()
        out["closure"] = self._closure_view(row)
        return out

    def _closure_view(self, w: Warrant) -> dict | None:
        """结案完整面（0018 A6，前端渲染契约）：该令状最近一次结案的
        结论/说明/双控签名+结案签名/实名哈希/案卷指纹——未结案=None
        （诚实缺省）。台账行+请求行并读（台账=终局锚，请求行=双控面）。"""
        from sqlalchemy import select as _sel

        from app.accounts.models import CaseLedger, CollabRequest

        row = self._s.scalar(
            _sel(CaseLedger)
            .where(CaseLedger.warrant_hash_hex == w.warrant_hash_hex)
            .order_by(CaseLedger.id.desc())
            .limit(1)
        )
        if row is None:
            return None
        req = self._s.scalar(
            _sel(CollabRequest).where(CollabRequest.req_hash_hex == row.req_hash_hex)
        )
        return {
            "req_id": req.id if req else None,
            "req_hash_hex": row.req_hash_hex,
            "case_no": row.case_no,
            "action": row.action,
            "conclusion": row.conclusion,
            "conclusion_text": row.conclusion_text,
            "auditor_username": req.auditor_username if req else row.operator,
            "auditor_sig_hex": req.auditor_sig_hex if req else None,
            "admin_username": req.admin_username if req else None,
            "admin_sig_hex": req.admin_sig_hex if req else None,
            "conclusion_sig_hex": row.sig_hex,
            "fzc2_fingerprint_hex": req.fzc2_fingerprint_hex if req else None,
            "closed_by": row.operator,
            "identity_hash_hex": row.identity_hash_hex,
            "case_archive_fp_hex": row.case_archive_fp_hex,
            "closed_ts": row.closed_ts.isoformat() if row.closed_ts else None,
        }

    def _device_check(self, master_cred_hash_hex: str, auth_id: int) -> dict:
        """核对检查点设备签名与登记 SN₁ 派生公钥（审计台时间线节点数据源）。"""
        from sqlalchemy import select as _sel2

        from app.audit.device_check import device_consistency
        from app.authz.models import AuthRecord
        from app.authz.service import unwrap_secret
        from app.ra.models import Credential
        from app.telemetry.models import CheckpointAnchor

        cred = self._s.scalar(
            _sel2(Credential).where(Credential.master_cred_hash_hex == master_cred_hash_hex)
        )
        if cred is None or cred.id_store_cipher is None:
            return {"verdict": "insufficient", "reason": "登记材料缺通道②密文（旧版）"}
        try:
            plain = unwrap_secret(bytes(cred.id_store_cipher))
            sn = _open_envelope_sn(plain)
        except Exception as e:  # noqa: BLE001
            return {"verdict": "insufficient", "reason": f"信封解封失败: {e}"}
        if not sn:
            return {"verdict": "insufficient", "reason": "旧版登记信封无 SN（重新登记可补）"}
        rows = self._s.scalars(
            _sel2(CheckpointAnchor).where(CheckpointAnchor.auth_id == auth_id)
        ).all()
        rows_d = [
            {
                "auth_id": r.auth_id,
                "seq": r.seq,
                "chain_head_hex": r.chain_head_hex,
                "fence_state_hex": r.fence_state_hex,
                "device_sig_hex": r.device_sig_hex,
                "device_pub_hex": r.device_pub_hex,
            }
            for r in rows
        ]
        # consumed：授权已消费（approved 存证）→ 零检查点即 no_evidence 可疑态
        consumed = (
            self._s.scalar(_sel2(AuthRecord).where(AuthRecord.auth_id == auth_id)) is not None
        )
        out = device_consistency(rows_d, registered_sn=sn, consumed=consumed)
        if sn:
            from app.crypto.sm3 import sm3_bytes as _sm3b

            out["registered_sn_fingerprint"] = _sm3b(sn.encode()).hex()[:16]
        return out

    def _warrant_view(self, r: Warrant) -> dict:
        return {
            "warrant_hash_hex": r.warrant_hash_hex,
            "case_no": r.case_no,
            "scope_hash_hex": r.scope_hash_hex,
            "legal_basis_hash_hex": r.legal_basis_hash_hex,
            "legal_basis_text": r.legal_basis_text,
            "target_auth_id": r.target_auth_id,
            "note": r.note,
            "created_ts": r.created_ts.isoformat() if r.created_ts else None,
            "unlocked": {
                "ts": r.unlocked_ts.isoformat() if r.unlocked_ts else None,
                "master_cred_hash_hex": r.unlocked_master_cred_hash_hex,
                "username": r.unlocked_username,
                "id_number": r.unlocked_id_number,
            },
        }


def _open_envelope_sn(plain: bytes) -> str:
    """通道②信封解析 SN₁（v3 四段含 SN；旧三段缺省空）。"""
    parts = plain.split(b"|", 3)
    if len(parts) >= 3:
        return parts[2].decode()
    return ""
