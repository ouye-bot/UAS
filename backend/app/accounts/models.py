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
    # 预置账户首登激活核对子（派生自初始密码；激活成功即焚——稳态零密码材料）。
    # 批 2-2.2：核对子改独立派生域（PBKDF2 info="FZ-ACTIVATE-VERIFY|v1"）——
    # 不再是 KEK 等价物；init_verifier_ver 标记格式（"v1"=独立域；NULL=旧种子
    # KEK 等价格式——兼容读取，激活即焚=换代）。
    init_verifier_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)
    init_verifier_ver: Mapped[str | None] = mapped_column(String(8), nullable=True)
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
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/approved/executing/rejected/executed/execute_failed
    # 执行租约（批 2-2.5③ 多副本失效面）：approved→executing 条件 UPDATE 时
    # 落领取人+租约到期；执行线程心跳续租；重启恢复只回收 approved 与
    # executing 中租约已过期者（活租约=他副本在途，不误杀）。
    locked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_until: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
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
    # ---- 结案升格（0018）：结案=案件终局动作，须有结论+签名+时间戳的密码学重量 ----
    # 结论枚举（verified=属实 / mistaken=误报 / inconclusive=无法查证）；
    # 属实（verified）时 conclusion_text 服务端强制必填（终局判词不留白）。
    conclusion: Mapped[str | None] = mapped_column(String(16), nullable=True)
    conclusion_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 审计员钥签 FZ-COLLAB-CLOSE|v1|{req_hash}|{conclusion}|{conclusion_text}
    conclusion_sig_hex: Mapped[str | None] = mapped_column(String(256), nullable=True)
    closed_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    # 案卷指纹（A6）：SM3(令状哈希|req_hash|双签名|函指纹|实名哈希|结论|closed_ts)
    case_archive_fp_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)


class CaseLedger(Base):
    """案件台账（append-only，0018 结案升格）：一行=一次案件终局动作。

    结案此前仅条件 UPDATE status 列——零结论/零签名/零时间戳/零台账（对比：
    驳回都强制理由+签名）。本表让案件终局逐笔留痕：req_hash+结论+审计员签名
    +实名哈希+案卷指纹——collab_requests 行之外的独立复核锚（台账行永不
    删除/改写）。"""
    __tablename__ = "case_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    req_hash_hex: Mapped[str] = mapped_column(String(64), index=True)
    warrant_hash_hex: Mapped[str] = mapped_column(String(64), index=True)
    case_no: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(32))  # close（结案；演进位：reopen 等）
    conclusion: Mapped[str] = mapped_column(String(16))  # verified / mistaken / inconclusive
    conclusion_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    sig_hex: Mapped[str] = mapped_column(String(256))  # 审计员结案签名
    operator: Mapped[str] = mapped_column(String(64))  # 结案审计员用户名
    identity_hash_hex: Mapped[str] = mapped_column(String(64))  # SM3(实名 username|id_number)
    case_archive_fp_hex: Mapped[str] = mapped_column(String(64))  # 案卷指纹（A6）
    closed_ts: Mapped[dt.datetime] = mapped_column(DateTime)


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


class RateLimitBucket(Base):
    """登录尝试限速桶（批 2-2.5① 多进程失效面）：/auth/* 尝试窗落库——
    此前为进程内存固定窗（多副本部署各记各账、重启清零）。key=限速键
    （如 "login|ip|username"），固定窗（window_start 起 window_s 秒）内
    计数；跨进程共享语义=同库同窗。"""

    __tablename__ = "rate_limit_buckets"

    bucket_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    window_start: Mapped[dt.datetime] = mapped_column(DateTime)
    hits: Mapped[int] = mapped_column(Integer, default=0)
