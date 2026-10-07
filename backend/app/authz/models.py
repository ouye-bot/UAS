"""授权服务数据模型（B4）——匿名红线：receipts/sessions 表零身份列。

- applications：匿名申请（会话公钥+证明文件+门控状态机）——无 user/凭证关联列
- receipts：回执（128bit 回执码+状态；ECIES 密文令牌的取件凭据）
- auth_records：授权登记镜像（authId/链上回执/判决件路径——链下索引）

模型级零身份断言（B4 验收门）：表列集合不含 username/user_id/id_number/
commitment——tests/test_authz_models.py 钉定。
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    BigInteger,
    DateTime,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.ra.models import Base


class Application(Base):
    __tablename__ = "applications"
    # 出证案卷唯一归属（批 4-1 服务端权威）：case_id=桥端出证任务产物目录号——
    # /authz/apply 首个申请绑定该案卷与其材料；此后携同 case_id 的申请材料
    # 一致=幂等受理、不一致=409 case_taken。唯一索引与 0017 迁移同构
    # （ix_applications_case_id）——历史行 NULL 不参与唯一性。
    __table_args__ = (Index("ix_applications_case_id", "case_id", unique=True),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 匿名通道：会话公钥（一次性——取件加密目标）；零身份列
    session_pk_hex: Mapped[str] = mapped_column(String(128))
    # 子凭证签名（公开提交=受理门控票据——D19 一次性数据）
    sub_sig_hex: Mapped[str] = mapped_column(String(128))
    sub_cred_hash_hex: Mapped[str] = mapped_column(String(64), index=True)
    nonce_hex: Mapped[str] = mapped_column(String(32))
    plan_hash_hex: Mapped[str] = mapped_column(String(64))
    class_id: Mapped[int] = mapped_column(Integer)
    policy_version: Mapped[str] = mapped_column(String(64))
    # 证明与公开实例（验证面消费）
    proof_path: Mapped[str] = mapped_column(Text, default="")
    spec_path: Mapped[str] = mapped_column(Text, default="")
    rev_root_hex: Mapped[str] = mapped_column(String(64))
    # 语句摘要（S5 安全修复[严重1]：实例 0 绑定——worker 传 expected.e_hex；
    # = digest_e_bytes(M_A′)，使「自签凭证+真子凭证受理」组合攻击失效）
    e_hex: Mapped[str] = mapped_column(String(64), default="")
    # 绑定挑战快照（2026-10-07 prove 窗根修）：challenge_hex=HMAC-SM3(服务密钥,
    # plan|nonce) 是**钥控**值——受理门⑤钉实例 19 时用受理进程 env 的钥现算，
    # worker 复验若按 env 重建，两进程 FZ_AUTHZ_BINDING_KEY 漂移即假拒（实测：
    # demo_up 随机钥后端受理、裸 env worker 复验 ⟹ 实例 19 必不一致）。受理时
    # 把**已钉定的**挑战值随申请落库（与 e_hex 同法：复验与验证同源），worker
    # 消费库值不再自算。公开性=绑定面已下发客户端+判决件归档同值，无新增暴露。
    challenge_hex: Mapped[str] = mapped_column(String(64), default="")
    # 授权窗（R1：令牌窗口——t_start=出证绑定 t_epoch）
    t_start: Mapped[int] = mapped_column(Integer, default=0)
    t_end: Mapped[int] = mapped_column(Integer, default=0)
    # 授权包配额（2026-10-06 多架次拍板）：本授权覆盖的架次数（1~5，缺省 1=
    # 与令牌一次性历史语义逐字等价）。worker recordAuth 透传上链。
    sorties: Mapped[int] = mapped_column(Integer, default=1)
    # 子凭证有效期（S6 安全闭环 2026-10-04：受理面从已验签 M_A′[160:164] 解出
    # 落库；核对语义=exp_u ≥ t_end（授权窗整体被凭证覆盖）。判决件
    # expected.exp_u 由此取值——第三方核对覆盖关系不再依赖重建报文）
    exp_u: Mapped[int] = mapped_column(Integer, default=0)
    # 状态机：pending→verifying→approved/rejected
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    reject_reason: Mapped[str] = mapped_column(String(200), default="")
    receipt_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    auth_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    # 队列语义（P0-2）：认领租约+瞬时失败重试——多 worker 防双处理；locked_at
    # 超过租约（FZ_WORKER_LEASE_S）视为孤儿可被接手；终态清空租约字段
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    locked_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class Receipt(Base):
    __tablename__ = "receipts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # 128bit 回执码（CSPRNG——取件凭据；表内零身份列）
    code_hex: Mapped[str] = mapped_column(String(32), unique=True)
    application_id: Mapped[int] = mapped_column(Integer, index=True)
    token_cipher: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="waiting")  # waiting/ready/failed
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class AuthRecord(Base):
    __tablename__ = "auth_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    auth_id: Mapped[int] = mapped_column(BigInteger, unique=True)  # 链上 authId
    application_id: Mapped[int] = mapped_column(Integer)
    token_hash_hex: Mapped[str] = mapped_column(String(64))
    proof_digest_hex: Mapped[str] = mapped_column(String(64))
    verdict_path: Mapped[str] = mapped_column(Text, default="")
    tx_hash: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    # 一次性令牌消费账本（2026-10-06 S1 全流程实弹根修）：签发≠消费——
    # ARM 成功后桥回报消费（服务端不可删），删本地库重放被服务端终拒。
    token_consumed_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    # 授权包配额（2026-10-06 多架次拍板）：sorties=登记配额总数（1~5）；
    # remaining=剩余架次——每次 /authz/consume 回报递减（真链档同步 engine
    # 链写 consumeSortie），remaining==0 置 token_consumed_ts（终态）。
    # 缺省 1=与令牌一次性语义逐字等价（首次回报即终态）。
    sorties: Mapped[int] = mapped_column(Integer, default=1)
    remaining: Mapped[int] = mapped_column(Integer, default=1)
