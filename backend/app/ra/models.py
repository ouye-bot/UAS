"""RA 数据模型（B2）——实名映射红线：id_number 永不明文存储（ECIES 密文/承诺）。

- users：平台账户（用户公钥=ECIES 回传目标）
- credentials：主凭证（C+句柄+exp+状态镜像；原像零明文——ECIES 密文镜像+用户自持）
- sub_credentials：一次性子凭证（配额计数域）
- revocations：吊销句柄集合（SMT 叶源；树每次全量重算——演示规模）
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    pub_key_hex: Mapped[str] = mapped_column(String(128))  # 用户 SM2 公钥（ECIES 目标）
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    commitment_hex: Mapped[str] = mapped_column(String(64), unique=True)  # C
    # 句柄=SM3(C)，链上 IdentityRegistry 键
    master_cred_hash_hex: Mapped[str] = mapped_column(String(64), unique=True)
    sn_hash_hex: Mapped[str] = mapped_column(String(32))  # sn_h（子凭证 sn 绑定校验）
    # SN 绑定换代（2026-10-06）：序列号原文 hex（1..=55B 单块填充域）。服务端
    # 权威 sn_hash=SM3(serial) 全 32B 的溯源源（sub_cred_hash→sub_credentials→
    # credentials 链；零客户端自报）。历史行为 NULL——受理面 fail-closed 人话拒绝。
    serial_hex: Mapped[str | None] = mapped_column(String(110), nullable=True)
    # B7 重注册禁入：SM3(id_number) hex。RA 本为组织级 TCB（承诺/ECIES 原像密文/
    # 通道② 实名映射已在库内同域），哈希列不新增任何暴露面；消费点=吊销时写
    # revoked_id_blacklist（同证件号重登记禁入）。0019 前的历史行如实为 NULL
    # （吊销时无哈希可入黑名单——诚实缺口，不回填臆造）。
    id_cipher: Mapped[bytes] = mapped_column(LargeBinary)  # ECIES(salt‖id‖cert) 原像密文
    # A3 通道②（B4）：RA 域钥 SM4-GCM wrap 的实名映射（令状批准后 RA 可解——
    # 与通道① ECIES 用户自持并存；流程双控定性：解锁留痕可审计）
    id_store_cipher: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    cert_level: Mapped[int] = mapped_column(Integer)  # 资质等级（RA 签发面语义；出示面经 C 隐藏）
    id_number_hash_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 机型类（B4/A4：进 C 原像——电路等值钉）
    class_id: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)
    status: Mapped[int] = mapped_column(Integer, default=1)  # 1=有效 2=吊销 3=冻结（链上镜像）
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class SubCredential(Base):
    __tablename__ = "sub_credentials"
    __table_args__ = (UniqueConstraint("sub_cred_hash_hex", name="uq_sub_cred_hash"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[int] = mapped_column(ForeignKey("credentials.id"))
    sub_cred_hash_hex: Mapped[str] = mapped_column(String(64), unique=True)
    message_hex: Mapped[str] = mapped_column(String(330))  # M_A′ 165B hex
    sig_hex: Mapped[str] = mapped_column(String(128))  # RA 签名 r‖s（电路口径）
    holder_pub_hex: Mapped[str] = mapped_column(String(128))  # pk′（用户端生成，RA 只见公钥）
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)
    consumed: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class Revocation(Base):
    __tablename__ = "revocations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    handle_hex: Mapped[str] = mapped_column(String(64), unique=True)
    epoch: Mapped[int] = mapped_column(BigInteger)
    reason: Mapped[str] = mapped_column(String(200), default="")
    revoked_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    # B1 撤销升格：执行者（机构管理员账户名）——「谁撤销」随叶落库（子凭证键
    # 传播叶同样记执行者；empty=0019 前历史行）。
    revoked_by: Mapped[str] = mapped_column(String(64), default="")


class RestoreRequest(Base):
    """B6 双控恢复请求：admin 发起（SM2 签 FZ-RESTORE|v1）→auditor 复核
    （SM2 签 FZ-RESTORE-COUNTERSIGN|v1）→双签齐才执行（SMT 摘叶+setStatus(1)
    +新纪元根推链）。单签不执行——恢复是撤销不可逆性的例外口，须双人各执一钥。"""

    __tablename__ = "restore_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    handle_hex: Mapped[str] = mapped_column(String(64), index=True)  # 待恢复主凭证句柄
    reason: Mapped[str] = mapped_column(Text)  # ≥4 字（两签消息域共用同一理由）
    requested_by: Mapped[str] = mapped_column(String(64))  # 发起 admin 账户名
    admin_sig_hex: Mapped[str] = mapped_column(String(256))
    countersign_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    countersign_sig_hex: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/executed
    execute_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    executed_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class RevokedIdBlacklist(Base):
    """B7 证件号级吊销黑名单：revoke 成功时该人全部凭证的 SM3(id_number) 入列；
    register 入口判重命中=409 拒绝重登记（逃逸面封堵）。恢复（B6）不动黑名单
    ——凭证恢复使原凭证复效，无需重登记；名单清除另行走机构决定面。"""

    __tablename__ = "revoked_id_blacklist"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    id_number_hash_hex: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    reason: Mapped[str] = mapped_column(String(200), default="")
    revoked_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class RevocationLedger(Base):
    """B1 撤销动作 append-only 台账：每次吊销/恢复/授权联动一行——谁/何时/
    对谁/何理由/何签名/何纪元/联动结果。无删除/改写出口（模型级无可变列写面
    ——路由层亦不提供 UPDATE 端点）。"""

    __tablename__ = "revocation_ledger"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    # revoke / revoke_by_username / authz_link / restore
    action: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(64), default="")  # 执行者账户名
    subject_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)  # 主句柄
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)  # 按人撤销时
    reason: Mapped[str] = mapped_column(Text, default="")
    sig_hex: Mapped[str | None] = mapped_column(String(256), nullable=True)  # admin 签名
    epoch: Mapped[int] = mapped_column(BigInteger)
    # 结构化补充 JSON：handles/revoked_sub_keys/linked_auth_ids/link_errors/
    # countersign_by 等
    detail: Mapped[str] = mapped_column(Text, default="")
