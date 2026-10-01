"""账户体系数据模型（2026-09-29 账户门户批）。

设计要点（docs/评审/2026-09-29-账户门户与三角色工作台/设计方案.md §2）：
- accounts：三角色账户（pilot/auditor/admin）。服务端**零密码材料**——
  既无明文也无哈希：登录=SM2 挑战-应答签名（挑战 nonce 一次性）。
  私钥以密码 KEK（SM3 迭代链+SM4-GCM）密封后仅存密封件；身份资料
  （含证件号）同样客户端密封后上传——服务器零明文 PIII（与导出件纪律同源）。
- auth_challenges：一次性登录挑战（TTL+单次消费——重放=拒绝）。
- web_sessions：会话表（Cookie 存随机 token；库内只存 SM3(token)——
  库泄露不可还原会话凭据）。
- collab_requests：双控协作请求队列（审计发函→机构批准→自动执行；
  双 SM2 签名各自验证——缺一不解锁，见 router 语义）。
- account_pubkey_history：公钥纪元史（append-only——2026-09-30 密码重置收紧
  批）。每次激活/注册追加一行；密码重置只关闭当前纪元（retired_ts），**从不
  删除**——换钥后历史签名仍可按"签名时点的公钥"复验（双控不可抵赖的根基）。
- account_admin_log：账户管理动作台账（append-only）：密码重置等敏感动作
  逐笔留痕（operator=离线种子脚本——在线面已无重置入口）。
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import BigInteger, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.ra.models import Base

SESSION_TTL_HOURS = 12
CHALLENGE_TTL_SECONDS = 120


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16))  # pilot / auditor / admin
    # pending_profile=飞手已建账户待补资料；pending_activation=预置机构账户
    # 待首登激活（init_verifier 一次性核对）；active=挑战-应答稳态
    status: Mapped[str] = mapped_column(String(24), default="pending_profile")
    pubkey_hex: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # 密码 KEK 密封的私钥信封（v3 JSON：pk+enc{salt,nonce,ct,tag}）——零明文
    sealed_blob: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 密码 KEK 密封的身份资料（{cred,form} JSON——证件号只在密文内）
    sealed_profile: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 非敏感展示列：主凭证哈希（链上承诺句柄——本就是公示面）
    cred_hash_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 预置账户首登激活核对子（派生自初始密码；激活成功即焚——稳态零密码材料）
    init_verifier_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)
    init_kdf_salt_hex: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    last_login_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"

    nonce_hex: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    created_ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    consumed_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class WebSession(Base):
    __tablename__ = "web_sessions"

    # Cookie 携带随机 token；库内只存 SM3(token)——不可逆向
    token_hash_hex: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(16))
    created_ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    expires_ts: Mapped[dt.datetime] = mapped_column(DateTime)


class CollabRequest(Base):
    """双控协作请求（2026-09-29 账户批 B3）：审计立案发函→机构批准→自动执行。

    双签名语义：auditor_sig=审计员钥签 req_hash；admin_sig=管理员钥签同一
    req_hash——两签服务端各自 SM2 验签，缺一请求到不了 executed。范围
    （令状哈希）与依据原文进 req_hash——批准即绑定"查什么"，挪用即验签失败。
    """

    __tablename__ = "collab_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    warrant_hash_hex: Mapped[str] = mapped_column(String(64), index=True)
    case_no: Mapped[str] = mapped_column(String(128))
    target_auth_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # 依据原文+调查理由快照（立案时令状已锚原文——此处随请求再留一份给批准人看全貌）
    legal_basis_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    req_hash_hex: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/approved/rejected/executed
    auditor_username: Mapped[str] = mapped_column(String(64))
    auditor_sig_hex: Mapped[str] = mapped_column(String(256))
    admin_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    admin_sig_hex: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reject_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 自动执行失败原因（execute_failed 态展示——结构化可诊断，不再 500 直穿）
    execute_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fzc2_fingerprint_hex: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    decided_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    executed_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class AccountPubkeyHistory(Base):
    """公钥纪元史（append-only）：一行=某账户的一个公钥纪元。

    纪元边界：注册/首登激活追加（epoch 单调 +1）；密码重置只把当前活动行
    （retired_ts IS NULL）打上 retired_ts——行永不删除/改写。历史签名复验=
    按签名时点 ts 取 activated_ts<=ts<retired_ts（或活动行）的公钥验签。
    """

    __tablename__ = "account_pubkey_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    epoch: Mapped[int] = mapped_column(Integer)  # 账户内单调递增（1 起）
    pubkey_hex: Mapped[str] = mapped_column(String(128))
    activated_ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    retired_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class AccountAdminLog(Base):
    """账户管理动作台账（append-only）：密码重置等敏感动作逐笔留痕。

    在线面无重置入口（2026-09-30 收紧：互不可重置+自重置禁止——单管理员
    重置审计员=接管审计面，双控独立性不可容忍）；唯一合法路径=离线种子
    脚本（operator 如实标注）。
    """

    __tablename__ = "account_admin_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    action: Mapped[str] = mapped_column(String(48))  # password_reset / reseed_pending
    username: Mapped[str] = mapped_column(String(64), index=True)
    operator: Mapped[str] = mapped_column(String(64))  # 动作发起者（offline_seed_script）
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)  # 结构化补充（如被关闭的纪元号）
