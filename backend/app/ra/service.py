"""RA 仪式服务层（B2）。

- register：实名→salt CSPRNG→C→M_A 主凭证签发→原像 ECIES(pk_user) 回传
  →masterCredHash=SM3(C) 上链 registerCommitment（chain_anchor 回调注入）
- issue_sub_credential：原像知识认证（重算 C 比对——B2-d4）→fresh id′/exp′(≤24h)
  →M_A′ 签发；配额=单主凭证未消费子凭证 <20；负例三拒（过期/超配额/吊销）
- revoke：句柄入吊销集→链上 setStatus(2)+setRevocationRoot(epoch+1)
  →纪元根=SMT(吊销集)（D14 即时生效语义）
- snapshot：公开镜像（epoch/root/revoked handles）——用户端本地建树取见证（零交互=匿名）

链上副作用经 chain_anchor(fn, args) 回调（测试注入 fake；真链版 scripts/smoke_ra_chain.py
与 API 层直连 B1 接入层）。
"""

from __future__ import annotations

import datetime as dt
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.sm2 import encrypt as sm2_ecies_encrypt
from app.crypto.sm3 import sm3_bytes
from app.ra.credential import build_message, commitment_c, sign_credential
from app.ra.models import Credential, Revocation, SubCredential, User
from app.ra.smt import smt_root

SUB_CRED_QUOTA = 20  # 单主凭证未消费子凭证上限（框架 §7.1 配额）
SUB_CRED_TTL_HOURS = 24
CRED_DEFAULT_DAYS = 365


class RaError(Exception):
    """RA 仪式拒绝（code 语义见模块 docstring）"""

    def __init__(self, code: str, message: str = "", status: int = 400) -> None:
        super().__init__(message or code)
        self.code = code
        self.status = status


@dataclass
class ChainAnchor:
    """链上副作用回调（fn∈{register_commitment, set_status, set_revocation_root,
    log_warrant_unlock}）+令状在案查询（B4-A3：IdentityRegistry WarrantLog）。"""

    call: Callable[[str, list], None]
    warrant_on_chain: Callable[[bytes], bool] = lambda _wh: False


@dataclass
class RaDeps:
    ra_priv_hex: str
    ra_pub_hex: str
    anchor: ChainAnchor
    # 纪元权威=链上（D14 公示面）：真链环境注入 revEpoch 查询；None=本地纪元（fake 测试）
    chain_rev_epoch: Callable[[], int] | None = None


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

    # ---- 吊销（D14：即时生效）----
    def revoke(self, *, master_cred_hash_hex: str, reason: str = "") -> dict:
        cred = self._load_cred(master_cred_hash_hex)
        if cred.status == 2:
            raise RaError("bad_input", "已吊销")
        return self._revoke_credentials([cred], reason)

    def revoke_by_username(self, *, username: str, reason: str = "") -> dict:
        """按人级联吊销（R4 第二批 B-P2-5）：该用户全部有效凭证一次撤销——
        单凭证吊销的逃逸面对侧（违规者重新登记即获全新有效凭证）。同纪元同根
        一次推链；每凭证独立 setStatus。撤销语义在「人-凭证-钥匙」三层对齐：
        按人（本入口）/按凭证（revoke）/按钥匙（传播并入+签发面预检）。"""
        user = self._s.scalar(select(User).where(User.username == username))
        if user is None:
            raise RaError("not_found", "用户不存在")
        creds = self._s.scalars(
            select(Credential).where(Credential.user_id == user.id, Credential.status == 1)
        ).all()
        if not creds:
            raise RaError("bad_input", "该用户无有效凭证（无可吊销项）")
        out = self._revoke_credentials(list(creds), reason)
        out["revoked_credentials"] = len(creds)
        return out

    def _revoke_credentials(self, creds: list[Credential], reason: str) -> dict:
        """吊销共用体：状态置 2+句柄入集+未消费子凭证 pk′.x 传播并入（R3-0.3）
        →纪元 +1 →SMT 根 →链上 setStatus（每凭证）+setRevocationRoot（一次）。"""
        for cred in creds:
            cred.status = 2
        if self._d.chain_rev_epoch is not None:
            base_epoch = self._d.chain_rev_epoch()  # 链上纪元权威（防本地/链上漂移）
        else:
            revoked0 = self._s.scalars(select(Revocation)).all()
            base_epoch = max((r.epoch for r in revoked0), default=0)
        epoch = base_epoch + 1
        sub_keys = 0
        for cred in creds:
            self._s.add(
                Revocation(handle_hex=cred.master_cred_hash_hex, epoch=epoch, reason=reason)
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
                    )
                )
        self._s.flush()
        handles = [bytes.fromhex(r.handle_hex) for r in self._s.scalars(select(Revocation)).all()]
        root = smt_root(handles)
        for cred in creds:
            self._d.anchor.call("set_status", ["0x" + cred.master_cred_hash_hex, 2])
        self._d.anchor.call("set_revocation_root", [epoch, "0x" + root.hex()])
        out = {"epoch": epoch, "root_hex": root.hex()}
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
        revoked = self._s.scalars(select(Revocation)).all()
        handles = [bytes.fromhex(r.handle_hex) for r in revoked]
        epoch = max((r.epoch for r in revoked), default=0)
        return {
            "epoch": epoch,
            "root_hex": smt_root(handles).hex(),
            "revoked_handles_hex": [r.handle_hex for r in revoked],
        }


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
