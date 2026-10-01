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
    id_cipher: Mapped[bytes] = mapped_column(LargeBinary)  # ECIES(salt‖id‖cert) 原像密文
    # A3 通道②（B4）：RA 域钥 SM4-GCM wrap 的实名映射（令状批准后 RA 可解——
    # 与通道① ECIES 用户自持并存；流程双控定性：解锁留痕可审计）
    id_store_cipher: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    cert_level: Mapped[int] = mapped_column(Integer)  # 资质等级（RA 签发面语义；出示面经 C 隐藏）
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
