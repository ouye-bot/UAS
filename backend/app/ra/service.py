"""RA 仪式服务层（B2；2026-10-04 撤销业务线硬化 B1/B4/B6/B7）。

- register：实名→salt CSPRNG→C→M_A 主凭证签发→原像 ECIES(pk_user) 回传
  →masterCredHash=SM3(C) 上链 registerCommitment（chain_anchor 回调注入）；
  B7：SM3(id_number) 落列+黑名单判重（被吊销证件号重登记=409 禁入）
- issue_sub_credential：原像知识认证（重算 C 比对——B2-d4）→fresh id′/exp′(≤24h)
  →M_A′ 签发；配额=单主凭证未消费子凭证 <20；负例三拒（过期/超配额/吊销）
- revoke：B1 升格——reason≥4 字+admin SM2 签名（FZ-REVOKE|v1 域）+纪元绑定；
  句柄入吊销集→链上 setStatus(2)+setRevocationRoot(epoch+1)→纪元根=SMT(吊销集)
  （D14 即时生效语义）；B4：成功后联动授权轴（revokeAuth）；动作入 append-only
  台账（revocation_ledger）；B7：证件号哈希入黑名单
- restore（B6 双控恢复）：admin 发起（FZ-RESTORE|v1 签）→auditor 复核
  （FZ-RESTORE-COUNTERSIGN|v1 签）→双签齐执行：SMT 摘叶+setStatus(1)+新纪元根
- snapshot：公开镜像（epoch/root/revoked handles）——用户端本地建树取见证（零交互=匿名）；
  B1：每叶增 reason/revoked_at/revoked_by（理由本为公示而写，无需脱敏）

链上副作用经 chain_anchor(fn, args) 回调（测试注入 fake；真链版 scripts/smoke_ra_chain.py
与 API 层直连 B1 接入层）。
"""

from __future__ import annotations

import datetime as dt
import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.sm2 import encrypt as sm2_ecies_encrypt
from app.crypto.sm2 import verify as sm2_verify
from app.crypto.sm3 import sm3_bytes
from app.ra.credential import build_message, commitment_c, sign_credential
from app.ra.models import (
    Credential,
    RestoreRequest,
    Revocation,
    RevocationLedger,
    RevokedIdBlacklist,
    SubCredential,
    User,
)
from app.ra.smt import smt_root

SUB_CRED_QUOTA = 20  # 单主凭证未消费子凭证上限（框架 §7.1 配额）
SUB_CRED_TTL_HOURS = 24
CRED_DEFAULT_DAYS = 365

# ---- 签名消息域（B1/B6：撤销与恢复动作的可追责密码学绑定）----
REVOKE_MSG_PREFIX = "FZ-REVOKE|v1|"
RESTORE_MSG_PREFIX = "FZ-RESTORE|v1|"
RESTORE_COUNTERSIGN_MSG_PREFIX = "FZ-RESTORE-COUNTERSIGN|v1|"
REASON_MIN = 4  # 理由≥4 字（公示面最小信息量——无理由强制撤销封堵）
# B4 联动撤销的链上 reason 码（FlightAuthRegistry.revokeAuth(uint256,uint8)）：
# 2=凭证吊销联动（1 预留监管紧急禁飞）
AUTH_REVOKE_REASON_LINKAGE = 2


def revoke_msg(handles: list[str], reason: str, epoch: int) -> str:
    """撤销签名消息：FZ-REVOKE|v1|{handles 排序拼接}|{reason}|{epoch}。

    handles=本次撤销的主凭证句柄（lowercase hex，字典序排序后 "|" 拼接）；
    epoch=本次撤销推进到的新纪元（=当前纪元+1，签名绑定纪元=防重放/防跨纪元挪用）。"""
    return REVOKE_MSG_PREFIX + "|".join(sorted(h.lower() for h in handles)) + f"|{reason}|{epoch}"


def restore_msg(handle_hex: str, reason: str) -> str:
    return RESTORE_MSG_PREFIX + f"{handle_hex.lower()}|{reason}"


def restore_countersign_msg(handle_hex: str, reason: str) -> str:
    return RESTORE_COUNTERSIGN_MSG_PREFIX + f"{handle_hex.lower()}|{reason}"


def _norm_handle(handle_hex: str) -> str:
    h = (handle_hex or "").strip().lower()
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise RaError("bad_input", "句柄须 64 hex（SM3）")
    return h


def _check_reason(reason: str) -> str:
    r = (reason or "").strip()
    if len(r) < REASON_MIN:
        raise RaError("reason_required", f"撤销/恢复理由须 ≥{REASON_MIN} 字（公示面必填）")
    return r


class RaError(Exception):
    """RA 仪式拒绝（code 语义见模块 docstring）"""

    def __init__(self, code: str, message: str = "", status: int = 400) -> None:
        super().__init__(message or code)
        self.code = code
        self.status = status


@dataclass
class ChainAnchor:
    """链上副作用回调（fn∈{register_commitment, set_status, set_revocation_root,
    log_warrant_unlock, revoke_auth}）+令状在案查询（B4-A3：IdentityRegistry WarrantLog）。"""

    call: Callable[[str, list], None]
    warrant_on_chain: Callable[[bytes], bool] = lambda _wh: False


@dataclass
class RaDeps:
    ra_priv_hex: str
    ra_pub_hex: str
    anchor: ChainAnchor
    # 纪元权威=链上（D14 公示面）：真链环境注入 revEpoch 查询；None=本地纪元（fake 测试）
    chain_rev_epoch: Callable[[], int] | None = None
    # B4 授权轴联动：authId→链上 revokeAuth（engine 交易钥）。None=不联动
    # （服务层单测默认）；fake 档经 anchor.call("revoke_auth",…) 留痕供断言；
    # 真链档由 API 层注入 FlightAuthRegistry 路径。返回 {"ok": bool, "detail": str}。
    auth_revoke: Callable[[int], dict] | None = None


def _ra_store_wrap(plaintext: bytes) -> bytes:
    """RA 域钥 SM4-GCM wrap（A3 通道②——B4）。域钥 KMS 派生，零落盘。"""
    from app.authz.service import wrap_secret

    return wrap_secret(plaintext)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


class RaService:
    def __init__(self, session: Session, deps: RaDeps) -> None:
        self._s = session
        self._d = deps

    # ---- 注册仪式 ----
    def register(
        self,
        *,
        username: str,
        id_number: str,
        cert_level: int,
        sn: str,
        user_pub_hex: str,
        class_id: int = 0,
        expires_at: dt.datetime | None = None,
    ) -> dict:
        if len(id_number) != 18:
            raise RaError("bad_input", "身份证号须 18 字符")
        if not 1 <= cert_level <= 4:
            raise RaError("bad_input", "资质等级 1..4")
        # 信封字段注入封堵（红队评审高危 #2）：username/sn 走 "|" 拼接信封——
        # 竖线与空值在此拒绝；username 限可打印安全字符集
        for fname, val in (("username", username), ("sn", sn)):
            if not val or "|" in val:
                raise RaError("bad_input", f"{fname} 含非法字符（竖线）或为空")
            if fname == "username" and not re.fullmatch(r"[A-Za-z0-9._\-]{1,64}", val):
                raise RaError("bad_input", "username 仅限字母/数字/._-（1..64）")
        if not 0 <= class_id <= 255:
            raise RaError("bad_input", "机型类须 u8")
        if len(sn.encode()) < 1 or len(sn.encode()) > 64:
            raise RaError("bad_input", "序列号 1..64 字节")
        if len(user_pub_hex) != 128:
            raise RaError("bad_input", "用户公钥 128 hex")
        # B7 重注册禁入：SM3(请求证件号) 命中吊销黑名单=拒绝（被吊销者同证件号
        # 重登记即满血复活的逃逸面封堵）。零判空放松——命中即 409 人话拒绝。
        id_hash_hex = sm3_bytes(id_number.encode()).hex()
        if (
            self._s.scalar(
                select(RevokedIdBlacklist).where(
                    RevokedIdBlacklist.id_number_hash_hex == id_hash_hex
                )
            )
            is not None
        ):
            raise RaError(
                "id_revoked_before",
                "该证件号项下凭证曾被吊销——禁止重新登记，如有疑问请联系机构",
                409,
            )
        salt = secrets.token_bytes(16)  # CSPRNG 加盐（D10 生死线）
        c = commitment_c(salt, id_number.encode(), cert_level, sn.encode(), class_id)
        handle = sm3_bytes(c)
        exp = expires_at or (_utcnow() + dt.timedelta(days=CRED_DEFAULT_DAYS))
        exp_u = int(exp.timestamp()) & 0xFFFFFFFF
        msg = build_message(
            self._d.ra_pub_hex,
            secrets.token_bytes(32),
            salt,
            id_number.encode(),
            cert_level,
            sn.encode(),
            user_pub_hex,
            exp_u,
            class_id,
        )
        sig = sign_credential(self._d.ra_priv_hex, msg)
        user = self._s.scalar(select(User).where(User.username == username))
        if user is None:
            user = User(username=username, pub_key_hex=user_pub_hex)
            self._s.add(user)
            self._s.flush()
        cred = Credential(
            user_id=user.id,
            commitment_hex=c.hex(),
            master_cred_hash_hex=handle.hex(),
            sn_hash_hex=c.hex()[:32],
            # SN 绑定换代（2026-10-06）：序列号原文入库——服务端自算
            # SM3(serial) 全 32B 的权威源（受理门控实例 25 校验+令牌载荷）。
            serial_hex=sn.encode().hex(),
            # B7：SM3(id_number)——RA 组织级 TCB 域内哈希列（见 models 注释）；
            # 吊销时写入黑名单供重登记判重
            id_number_hash_hex=id_hash_hex,
            id_cipher=sm2_ecies_encrypt(
                user_pub_hex, salt + id_number.encode() + bytes([cert_level])
            ),
            # A3 通道②（B4-d5）：RA 域钥 wrap 实名映射（令状通道——与通道①并存）
            # 通道②信封 v3（SN v2）：版本字节 0x01 + 四段——解锁后设备交叉审计的数据源
            id_store_cipher=_ra_store_wrap(
                b"\x01"
                + username.encode()
                + b"|"
                + id_number.encode()
                + b"|"
                + sn.encode()
                + b"|"
                + handle
            ),
            cert_level=cert_level,
            class_id=class_id,
            expires_at=exp,
            status=1,
        )
        self._s.add(cred)
        self._s.flush()
        # 链上登记（主凭证哈希+状态留痕——D18：链上仅此存主凭证）
        self._d.anchor.call("register_commitment", ["0x" + handle.hex(), 1])
        return {
            "commitment_hex": c.hex(),
            "master_cred_hash_hex": handle.hex(),
            "message_hex": msg.hex(),
            "sig_hex": sig,
            "expires_at": exp.isoformat(),
            "preimage_cipher_hex": sm2_ecies_encrypt(user_pub_hex, salt).hex(),
            "salt_hex": salt.hex(),  # 注册响应一次性回传（用户端与 ECIES 密文双通道自持）
        }

    def _load_cred(self, master_cred_hash_hex: str) -> Credential:
        cred = self._s.scalar(
            select(Credential).where(Credential.master_cred_hash_hex == master_cred_hash_hex)
        )
        if cred is None:
            raise RaError("not_found", "主凭证不存在")
        return cred

    # ---- 子凭证仪式（原像知识认证——B2-d4）----
    def issue_sub_credential(
        self,
        *,
        master_cred_hash_hex: str,
        salt_hex: str,
        id_number: str,
        cert_level: int,
        sn: str,
        holder_pub_hex: str,
    ) -> dict:
        if not sn or "|" in sn:
            raise RaError("bad_input", "sn 含非法字符（竖线）或为空")
        cred = self._load_cred(master_cred_hash_hex)
        # 原像知识认证：重算 C 须逐字节命中库内承诺
        try:
            c = commitment_c(
                bytes.fromhex(salt_hex), id_number.encode(), cert_level, sn.encode(), cred.class_id
            )
        except Exception as exc:  # noqa: BLE001
            raise RaError("bad_preimage", f"原像非法: {exc}") from exc
        if c.hex() != cred.commitment_hex:
            raise RaError("bad_preimage", "承诺不匹配（原像知识认证失败）")
        # 负例三连（验收门）——本凭证自身状态优先报（被吊销者重申=cred_revoked
        # 更精确；holder_revoked 留给跨凭证键传染形态：新凭证+旧出示钥）
        if cred.status == 2:
            raise RaError("cred_revoked", "主凭证已吊销，拒新签发")
        if cred.expires_at <= _utcnow():
            raise RaError("cred_expired", "主凭证已过期")
        # R4 第二批 B-P2-5：签发面撤销预检——出示公钥 pk′.x 已入撤销集（原凭证
        # 吊销时传播并入）仍签发新子凭证 ⟹ 签发成功但出证必死于 SMT root.fold
        # （数学不可证的诚实误伤）。签发面人话拒绝，指引用户重置身份钥重新登记。
        _pkx = holder_pub_hex.lower()[:64]
        if self._s.scalar(select(Revocation).where(Revocation.handle_hex == _pkx)) is not None:
            raise RaError(
                "holder_revoked",
                "该出示公钥已并入撤销名单（原凭证吊销传播）——请重置身份钥后重新登记",
            )
        # R3-1.2（评审 P1-2）：配额口径=未消费 ∧ 未过期——过期子凭证自动让位；
        # approved 消费回写（worker）+ rejected 放行重申（部分唯一索引 0009）
        # 三件合起来才构成完整配额生命周期，缺一即"20 次后终身锁死"。
        unconsumed = len(
            self._s.scalars(
                select(SubCredential).where(
                    SubCredential.credential_id == cred.id,
                    SubCredential.consumed.is_(False),
                    SubCredential.expires_at > _utcnow(),
                )
            ).all()
        )
        if unconsumed >= SUB_CRED_QUOTA:
            raise RaError("quota_exceeded", f"未过期且未消费的子凭证已达上限 {SUB_CRED_QUOTA}")
        exp = min(_utcnow() + dt.timedelta(hours=SUB_CRED_TTL_HOURS), cred.expires_at)
        exp_u = int(exp.timestamp()) & 0xFFFFFFFF
        id_prime = secrets.token_bytes(32)  # fresh 身份标量（跨申请不可链接）
        msg = build_message(
            self._d.ra_pub_hex,
            id_prime,
            bytes.fromhex(salt_hex),
            id_number.encode(),
            cert_level,
            sn.encode(),
            holder_pub_hex,
            exp_u,
            cred.class_id,
        )
        sig = sign_credential(self._d.ra_priv_hex, msg)
        sub = SubCredential(
            credential_id=cred.id,
            sub_cred_hash_hex=sm3_bytes(msg).hex(),
            message_hex=msg.hex(),
            sig_hex=sig,
            holder_pub_hex=holder_pub_hex,
            expires_at=exp,
        )
        self._s.add(sub)
        self._s.flush()
        return {
            "sub_cred_hash_hex": sub.sub_cred_hash_hex,
            "message_hex": msg.hex(),
            "sig_hex": sig,
            "expires_at": exp.isoformat(),
            "id_prime_hex": id_prime.hex(),  # 出示随机化身份（用户端见证自持）
        }

    # ---- 吊销（D14：即时生效；B1 升格：签名+台账+黑名单；B4：联动授权轴）----
    def _verify_admin_sig(
        self,
        *,
        msg: str,
        sig_hex: str,
        admin_pub_hex: str,
        expected_epoch: int | None = None,
        given_epoch: int | None = None,
    ) -> None:
        """admin 动作签名验签（复用 accounts 挑战-应答同族 SM2 验签范式）：
        纪元不符先拒（人话），再 SM2 验签（fail-closed——无签名/坏签名同拒）。
        恢复域消息无纪元字段——两 epoch 实参缺省即跳过比对。"""
        if expected_epoch is not None and given_epoch != expected_epoch:
            raise RaError(
                "bad_epoch",
                f"纪元不符：本次撤销将推进到 epoch={expected_epoch}（请以公示镜像当前纪元+1 签名）",
            )
        if not admin_pub_hex or not sig_hex:
            raise RaError("bad_sig", "缺少管理员签名——撤销须 admin SM2 签名留痕", 401)
        if not sm2_verify(admin_pub_hex, msg.encode(), sig_hex):
            raise RaError("bad_sig", "管理员签名验证失败——操作内容与签名不匹配", 401)

    def _base_epoch(self) -> int:
        if self._d.chain_rev_epoch is not None:
            return self._d.chain_rev_epoch()  # 链上纪元权威（防本地/链上漂移）
        # 本地基线=max(叶纪元, 台账纪元)——B6 恢复推链后新纪元不得回退
        from sqlalchemy import func

        led = self._s.scalar(select(func.max(RevocationLedger.epoch))) or 0
        revoked0 = self._s.scalars(select(Revocation)).all()
        return max(max((r.epoch for r in revoked0), default=0), int(led))

    def _link_authz_axis(self, creds: list[Credential]) -> tuple[list[int], list[dict]]:
        """B4 吊销联动授权轴：解析该（些）凭证名下全部在案且未过期未撤销的
        authId（沿 scope.py 四环解析反向：Credential→SubCredential→Application
        .auth_id），逐个经 deps.auth_revoke 链上 revokeAuth。fake 档如实留痕，
        真链档已撤销（status≠0）由注入面如实跳过并标注。返回 (联动成功清单,
        跳过/失败明细)。"""
        auth_ids: list[int] = []
        now_ts = int(time.time())  # t_end 口径=墙钟 epoch（authz/service 授权窗同源）
        for cred in creds:
            sub_hashes = self._s.scalars(
                select(SubCredential.sub_cred_hash_hex).where(
                    SubCredential.credential_id == cred.id
                )
            ).all()
            if not sub_hashes:
                continue
            from app.authz.models import Application

            rows = self._s.scalars(
                select(Application).where(
                    Application.sub_cred_hash_hex.in_(sub_hashes),
                    Application.auth_id.is_not(None),
                )
            ).all()
            for app in rows:
                if int(app.auth_id) not in auth_ids:
                    # 未过期过滤：授权窗 t_end 与子凭证有效期任一在案口径过期即跳过
                    if app.t_end and int(app.t_end) <= now_ts:
                        continue
                    sub = self._s.scalar(
                        select(SubCredential).where(
                            SubCredential.sub_cred_hash_hex == app.sub_cred_hash_hex
                        )
                    )
                    if sub is not None and sub.expires_at <= _utcnow():
                        continue
                    auth_ids.append(int(app.auth_id))
        if not auth_ids:
            return [], []
        linked: list[int] = []
        errors: list[dict] = []
        for aid in sorted(auth_ids):
            if self._d.auth_revoke is None:
                errors.append({"auth_id": aid, "ok": False, "detail": "联动未接线（deps 缺省）"})
                continue
            try:
                r = self._d.auth_revoke(aid)
            except Exception as e:  # noqa: BLE001  单授权联动失败不回滚凭证轴主行为
                errors.append({"auth_id": aid, "ok": False, "detail": f"{type(e).__name__}: {e}"})
                continue
            (linked if r.get("ok") else errors).append(
                aid if r.get("ok") else {"auth_id": aid, **r}
            )
        return linked, errors

    def revoke(
        self,
        *,
        master_cred_hash_hex: str,
        reason: str,
        admin_username: str,
        admin_pub_hex: str,
        admin_sig_hex: str,
        epoch: int,
    ) -> dict:
        """按凭证吊销（B1 升格）：理由必填≥4 字+admin SM2 签名（FZ-REVOKE|v1
        域，绑定句柄集与新纪元）+动作入 append-only 台账+证件号黑名单（B7）。"""
        cred = self._load_cred(master_cred_hash_hex)
        if cred.status == 2:
            raise RaError("bad_input", "已吊销")
        r = reason.strip()
        if len(r) < REASON_MIN:
            raise RaError("reason_required", f"撤销理由须 ≥{REASON_MIN} 字（公示面必填）")
        self._verify_admin_sig(
            msg=revoke_msg([cred.master_cred_hash_hex], r, epoch),
            sig_hex=admin_sig_hex,
            admin_pub_hex=admin_pub_hex,
            expected_epoch=self._base_epoch() + 1,
            given_epoch=epoch,
        )
        return self._revoke_credentials([cred], r, admin_username, admin_sig_hex)

    def revoke_preview_by_username(self, *, username: str) -> dict:
        """按人吊销·两步式第一拍（只读）：FZ-REVOKE 签名消息须覆盖该用户全部
        有效凭证句柄串（revoke_msg），而前端无法预知句柄集——本预览只读返回
        句柄（字典序，与 revoke_msg 排序口径一致）+目标纪元（=当前纪元+1，
        与 _verify_admin_sig 的 expected_epoch 同源）。不落库不推链；负例同
        revoke_by_username（用户不存在 404/无有效凭证 bad_input，与正式端点
        同判同码）。"""
        user = self._s.scalar(select(User).where(User.username == username))
        if user is None:
            raise RaError("not_found", "用户不存在", 404)
        creds = self._s.scalars(
            select(Credential).where(Credential.user_id == user.id, Credential.status == 1)
        ).all()
        if not creds:
            raise RaError("bad_input", "该用户无有效凭证（无可吊销项）")
        return {
            "username": username,
            "handles": sorted(c.master_cred_hash_hex.lower() for c in creds),
            "epoch": self._base_epoch() + 1,
        }

    def revoke_by_username(
        self,
        *,
        username: str,
        reason: str,
        admin_username: str,
        admin_pub_hex: str,
        admin_sig_hex: str,
        epoch: int,
    ) -> dict:
        """按人级联吊销（R4 第二批 B-P2-5；B1 升格同 revoke）：该用户全部有效
        凭证一次撤销——单凭证吊销的逃逸面对侧（重新登记即获新有效凭证）。同纪元
        同根一次推链；每凭证独立 setStatus。撤销语义在「人-凭证-钥匙」三层对齐：
        按人（本入口）/按凭证（revoke）/按钥匙（传播并入+签发面预检）。"""
        user = self._s.scalar(select(User).where(User.username == username))
        if user is None:
            raise RaError("not_found", "用户不存在")
        creds = self._s.scalars(
            select(Credential).where(Credential.user_id == user.id, Credential.status == 1)
        ).all()
        if not creds:
            raise RaError("bad_input", "该用户无有效凭证（无可吊销项）")
        r = reason.strip()
        if len(r) < REASON_MIN:
            raise RaError("reason_required", f"撤销理由须 ≥{REASON_MIN} 字（公示面必填）")
        handles = [c.master_cred_hash_hex for c in creds]
        self._verify_admin_sig(
            msg=revoke_msg(handles, r, epoch),
            sig_hex=admin_sig_hex,
            admin_pub_hex=admin_pub_hex,
            expected_epoch=self._base_epoch() + 1,
            given_epoch=epoch,
        )
        out = self._revoke_credentials(list(creds), r, admin_username, admin_sig_hex)
        out["revoked_credentials"] = len(creds)
        return out

    def _revoke_credentials(
        self, creds: list[Credential], reason: str, admin_username: str, admin_sig_hex: str
    ) -> dict:
        """吊销共用体：状态置 2+句柄入集（记执行者）+未消费子凭证 pk′.x 传播并入
        （R3-0.3）+证件号哈希入黑名单（B7）→纪元 +1 →SMT 根 →链上 setStatus（每
        凭证）+setRevocationRoot（一次）→B4 授权轴联动→append-only 台账一行。"""
        for cred in creds:
            cred.status = 2
        epoch = self._base_epoch() + 1
        sub_keys = 0
        for cred in creds:
            self._s.add(
                Revocation(
                    handle_hex=cred.master_cred_hash_hex,
                    epoch=epoch,
                    reason=reason,
                    revoked_by=admin_username,
                )
            )
            # B7 重注册禁入：该证件号哈希入黑名单（列缺省=0019 前历史行，如实
            # 无哈希可入——不回填臆造，见 models 注释）。
            if cred.id_number_hash_hex:
                dup = self._s.scalar(
                    select(RevokedIdBlacklist).where(
                        RevokedIdBlacklist.id_number_hash_hex == cred.id_number_hash_hex
                    )
                )
                if dup is None:
                    self._s.add(
                        RevokedIdBlacklist(
                            id_number_hash_hex=cred.id_number_hash_hex,
                            reason=reason[:200],
                        )
                    )
            # R3-0.3 撤销传播（2026-09-24，三代理评审 P0-1）：电路/见证键=子凭证
            # 出示公钥 x 坐标 pk′.x，与句柄域 SM3(C) 不相交——不同步并入则
            # 「pk′.x∉撤销集」对被吊销者恒真（撤销即时宣称空转）。把该主凭证
            # 全部未消费子凭证的 pk′.x 一并写入叶集（同纪元同根一次推链）。
            subs = self._s.scalars(
                select(SubCredential).where(
                    SubCredential.credential_id == cred.id,
                    SubCredential.consumed == False,  # noqa: E712
                )
            ).all()
            seen = {cred.master_cred_hash_hex}
            for sc in subs:
                pkx = sc.holder_pub_hex.lower()[:64]
                if pkx in seen:
                    continue
                seen.add(pkx)
                sub_keys += 1
                self._s.add(
                    Revocation(
                        handle_hex=pkx,
                        epoch=epoch,
                        reason=f"sub-cred:{sc.sub_cred_hash_hex[:16]}",
                        revoked_by=admin_username,
                    )
                )
        self._s.flush()
        handles = [bytes.fromhex(r.handle_hex) for r in self._s.scalars(select(Revocation)).all()]
        root = smt_root(handles)
        for cred in creds:
            self._d.anchor.call("set_status", ["0x" + cred.master_cred_hash_hex, 2])
        self._d.anchor.call("set_revocation_root", [epoch, "0x" + root.hex()])
        # B4：凭证轴落定后联动授权轴（失败不回滚主行为——明细如实入台账/响应）
        linked, link_errors = self._link_authz_axis(creds)
        action = "revoke" if len(creds) == 1 else "revoke_by_username"
        ledger = RevocationLedger(
            action=action,
            actor=admin_username,
            subject_hex=creds[0].master_cred_hash_hex,
            reason=reason,
            sig_hex=admin_sig_hex,
            epoch=epoch,
            detail=json.dumps(
                {
                    "handles": [c.master_cred_hash_hex for c in creds],
                    "revoked_sub_keys": sub_keys,
                    "linked_auth_ids": linked,
                    "link_skipped": link_errors,
                },
                ensure_ascii=False,
            ),
        )
        self._s.add(ledger)
        self._s.flush()
        out = {
            "epoch": epoch,
            "root_hex": root.hex(),
            "ledger_id": ledger.id,
            "revoked_handles_hex": [c.master_cred_hash_hex for c in creds],
            "linked_auth_ids": linked,
        }
        if link_errors:
            out["link_skipped"] = link_errors
        if len(creds) > 1:
            out["revoked_sub_keys"] = sub_keys
        return out

    # ---- 公开镜像（撤销见证源——零交互=匿名获取）----
    def warrant_unlock(self, *, warrant_hash_hex: str, master_cred_hash_hex: str) -> dict:
        """令状协作解锁（A3 通道②/B4-d5）。

        流程双控（队友六问 A7 定性——非密码学门限）：①链上 WarrantLog 在案核验
        ②unwrap 实名映射 ③解锁留痕（logWarrant 二次上链=解锁行为可审计）。
        无令状=拒绝（负例一等公民）。
        """
        wh = bytes.fromhex(warrant_hash_hex)
        if len(wh) != 32:
            raise RaError("bad_input", "令状哈希须 32B/64hex")
        if not self._d.anchor.warrant_on_chain(wh):
            raise RaError("warrant_not_found", "链上无此令状记录（拒绝解锁——流程双控第一关）")
        cred = self._load_cred(master_cred_hash_hex)
        if cred.id_store_cipher is None:
            raise RaError("no_store_cipher", "该凭证无通道②密文（B4 前注册）")
        from app.authz.service import unwrap_secret

        try:
            plain = unwrap_secret(bytes(cred.id_store_cipher))
        except Exception as e:  # GCM 认证失败归一（SM4GCMError 族）
            raise RaError("unwrap_failed", f"通道② 解密失败: {e}") from e
        # 信封解析单源（2026-09-28 深检收尾：v3=0x01 前缀+四段含 SN₁；旧式
        # 三段 sn 诚实缺省——含历史信封。分派逻辑此前内联双份，与
        # _open_store_envelope 漂移面收敛）。
        d = _open_store_envelope(plain)
        # 解锁留痕（链上 logWarrant——审计面：解锁行为本身可审计）
        self._d.anchor.call(
            "log_warrant_unlock", ["0x" + warrant_hash_hex, "0x" + master_cred_hash_hex]
        )
        return {
            "username": d["username"],
            "id_number": d["id_number"],
            "sn": d["sn"],
            "master_cred_hash_hex": master_cred_hash_hex,
        }

    def snapshot(self) -> dict:
        """公开镜像（B1 升格：每叶附 reason/revoked_at/revoked_by——理由本为
        公示而写，无需脱敏；revoked_handles_hex 保留=既有消费面兼容）。
        纪元取 max(叶纪元, 台账纪元)——恢复（B6 摘叶不落叶行）后公示纪元仍单调。"""
        from sqlalchemy import func

        revoked = self._s.scalars(select(Revocation)).all()
        handles = [bytes.fromhex(r.handle_hex) for r in revoked]
        led_epoch = self._s.scalar(select(func.max(RevocationLedger.epoch))) or 0
        epoch = max(max((r.epoch for r in revoked), default=0), int(led_epoch))
        return {
            "epoch": epoch,
            "root_hex": smt_root(handles).hex(),
            "revoked_handles_hex": [r.handle_hex for r in revoked],
            "revoked": [
                {
                    "handle_hex": r.handle_hex,
                    "reason": r.reason,
                    "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                    "epoch": r.epoch,
                    "revoked_by": r.revoked_by,
                }
                for r in revoked
            ],
        }

    # ---- B6 双控恢复（撤销不可逆性的唯一例外口——双人各执一钥）----
    def restore_request(
        self, *, handle_hex: str, reason: str, admin_username: str, admin_sig_hex: str
    ) -> dict:
        """admin 发起恢复：目标句柄须在撤销集+理由≥4 字+admin SM2 签名
        （FZ-RESTORE|v1|{handle}|{reason}）→pending 请求（一句柄一在途）。
        单签不执行——执行只在 countersign 双签齐后发生。"""
        h = _norm_handle(handle_hex)
        r = _check_reason(reason)
        self._verify_admin_sig(
            msg=restore_msg(h, r),
            sig_hex=admin_sig_hex,
            admin_pub_hex=self._account_pub(admin_username),
        )
        if self._s.scalar(select(Revocation).where(Revocation.handle_hex == h)) is None:
            raise RaError("not_revoked", "该句柄不在撤销集——无恢复对象（已生效/未吊销）", 409)
        # 仅主凭证句柄可恢复（撤销集还含 pk′.x 子钥传播叶——摘子钥叶=解锁他人
        # 出示钥，越出「凭证恢复」语义；持有者重置身份钥即可换新，无需恢复）
        if (
            self._s.scalar(
                select(Credential.id).where(Credential.master_cred_hash_hex == h)
            )
            is None
        ):
            raise RaError("not_restorable", "仅主凭证句柄可恢复（子钥传播叶不可恢复）", 409)
        dup = self._s.scalar(
            select(RestoreRequest).where(
                RestoreRequest.handle_hex == h, RestoreRequest.status == "pending"
            )
        )
        if dup is not None:
            raise RaError(
                "restore_pending", f"该句柄已有在途恢复请求（id={dup.id}）——等待复核", 409
            )
        row = RestoreRequest(
            handle_hex=h, reason=r, requested_by=admin_username, admin_sig_hex=admin_sig_hex
        )
        self._s.add(row)
        self._s.commit()
        return self.restore_view(row)

    def restore_countersign(
        self, *, request_id: int, auditor_username: str, countersign_sig_hex: str
    ) -> dict:
        """auditor 复核：SM2 签同内容不同消息域（FZ-RESTORE-COUNTERSIGN|v1）
        +重验 admin 原签——双签齐才执行：SMT 摘叶+合约 setStatus(handle,1)+
        新纪元根推链（复用 _revoke_credentials 的推链范式）+台账+公示根更新
        （公示面即 DB 镜像，摘叶后 snapshot 自动收敛）。负例：单签不执行/
        非对应角色拒（路由层角色守卫）/已生效句柄拒。"""
        from app.accounts.models import Account

        row = self._s.get(RestoreRequest, request_id)
        if row is None:
            raise RaError("not_found", "恢复请求不存在", 404)
        if row.status != "pending":
            raise RaError("bad_state", f"请求状态为 {row.status}——仅待复核态可复核", 409)
        if row.requested_by == auditor_username:
            raise RaError("self_countersign", "发起人不得自行复核——双控须两人", 403)
        admin_pub = self._account_pub(row.requested_by)
        auditor = self._s.scalar(select(Account).where(Account.username == auditor_username))
        if auditor is None or not auditor.pubkey_hex:
            raise RaError("no_key", "复核人账户未生成密钥（未激活）", 409)
        msg = restore_countersign_msg(row.handle_hex, row.reason)
        if not countersign_sig_hex or not sm2_verify(
            auditor.pubkey_hex, msg.encode(), countersign_sig_hex
        ):
            raise RaError("bad_sig", "复核签名验证失败——操作内容与签名不匹配", 401)
        if not admin_pub or not sm2_verify(
            admin_pub, restore_msg(row.handle_hex, row.reason).encode(), row.admin_sig_hex
        ):
            raise RaError("bad_sig", "发起签名复验失败——请求完整性不可确认", 401)
        # 执行（链面先行——失败则整体不落库，请求留在 pending 可重试）
        rev = self._s.scalar(select(Revocation).where(Revocation.handle_hex == row.handle_hex))
        if rev is None:
            row.status = "executed"
            row.execute_error = "句柄已不在撤销集（并发恢复）——幂等终态"
            row.countersign_by = auditor_username
            row.countersign_sig_hex = countersign_sig_hex
            row.executed_ts = _utcnow()
            self._s.commit()
            return self.restore_view(row)
        try:
            self._s.delete(rev)
            self._s.flush()
            cred = self._s.scalar(
                select(Credential).where(Credential.master_cred_hash_hex == row.handle_hex)
            )
            if cred is not None:
                cred.status = 1
            epoch = self._base_epoch() + 1
            handles = [
                bytes.fromhex(r.handle_hex) for r in self._s.scalars(select(Revocation)).all()
            ]
            root = smt_root(handles)
            if cred is not None:
                self._d.anchor.call("set_status", ["0x" + row.handle_hex, 1])
            self._d.anchor.call("set_revocation_root", [epoch, "0x" + root.hex()])
        except Exception as e:  # noqa: BLE001  链面失败：整体回滚，请求留 pending
            self._s.rollback()
            row.execute_error = f"{type(e).__name__}: {e}"[:500]
            self._s.commit()
            raise RaError("chain_unavailable", f"恢复推链失败（请求保留可重试）: {e}", 503) from e
        row.countersign_by = auditor_username
        row.countersign_sig_hex = countersign_sig_hex
        row.status = "executed"
        row.executed_ts = _utcnow()
        self._s.add(
            RevocationLedger(
                action="restore",
                actor=auditor_username,
                subject_hex=row.handle_hex,
                reason=row.reason,
                sig_hex=row.admin_sig_hex,
                epoch=epoch,
                detail=json.dumps(
                    {
                        "requested_by": row.requested_by,
                        "countersign_by": auditor_username,
                        "countersign_sig_hex": countersign_sig_hex,
                        "restored_root_hex": root.hex(),
                    },
                    ensure_ascii=False,
                ),
            )
        )
        self._s.commit()
        return self.restore_view(row)

    def restore_view(self, r: RestoreRequest) -> dict:
        return {
            "id": r.id,
            "handle_hex": r.handle_hex,
            "reason": r.reason,
            "status": r.status,
            "requested_by": r.requested_by,
            "countersign_by": r.countersign_by,
            "execute_error": r.execute_error,
            "created_ts": r.created_ts.isoformat() if r.created_ts else None,
            "executed_ts": r.executed_ts.isoformat() if r.executed_ts else None,
        }

    def restore_requests_list(self) -> list[dict]:
        rows = self._s.scalars(
            select(RestoreRequest).order_by(RestoreRequest.id.desc()).limit(50)
        ).all()
        return [self.restore_view(r) for r in rows]

    def _account_pub(self, username: str) -> str:
        """动作签名人当前公钥（accounts 表——collab 双控同源）。"""
        from app.accounts.models import Account

        acc = self._s.scalar(select(Account).where(Account.username == username))
        if acc is None or not acc.pubkey_hex:
            raise RaError("no_key", "签名人账户未生成密钥（未激活）", 409)
        return acc.pubkey_hex


def _open_store_envelope(plain: bytes) -> dict:
    """通道②信封解封后的字段解析（单一事实源——解锁路径与测试共用）。

    v3：0x01 前缀+四段（含 SN₁）；旧式：三段（sn 诚实缺省）。
    字面量纪律（2026-09-28 深检教训）：版本字节必须显式 b"\\x01" 转义——
    原始控制字节嵌源码会被文本工具渲染成空串（两席"sn 恒空"误诊的根源）
    且易被编辑器/linter 当垃圾清理。"""
    if plain[:1] == b"\x01":
        username, id_number, sn, _handle = plain[1:].split(b"|", 3)
        return {
            "username": username.decode(),
            "id_number": id_number.decode(),
            "sn": sn.decode(),
        }
    parts = plain.split(b"|", 2)
    if len(parts) == 3:
        username, id_number, _handle = parts
        return {
            "username": username.decode(),
            "id_number": id_number.decode(),
            "sn": "",
        }
    raise ValueError("store envelope malformed（GCM 已认证仍不合规——拒析）")
