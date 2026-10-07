"""审计台数据模型（B7）——令状登记面（链是留痕单一事实源，本表只作索引/审计行）。

- warrants：令状登记（哈希/案号/范围/法律依据哈希/目标 authId/解锁审计行）
  append-only：无删除/改写面（令状不可撤销——合约一次性+本表无 UPDATE 出口，
  解锁走专用列一次写入）。
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import BigInteger, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.ra.models import Base


class Warrant(Base):
    __tablename__ = "warrants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    warrant_hash_hex: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_no: Mapped[str] = mapped_column(String(128))
    scope_hash_hex: Mapped[str] = mapped_column(String(64))
    legal_basis_hash_hex: Mapped[str] = mapped_column(String(64))
    # 立案依据原文（2026-09-28 F 席：哈希+原文双锚——事后可自证当时依据）
    legal_basis_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    target_auth_id: Mapped[int] = mapped_column(BigInteger, nullable=True)
    created_ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    # 解锁审计行（一次写入——RA 协作解锁后回填）
    unlocked_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    unlocked_master_cred_hash_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # SN v2：解锁时回传的登记序列号（设备交叉审计数据源）
    unlocked_sn: Mapped[str | None] = mapped_column(String(64), nullable=True)
    unlocked_username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    unlocked_id_number: Mapped[str | None] = mapped_column(String(32), nullable=True)


class DisposalRequest(Base):
    """处置待办（2026-10-04 处置联动 A5/B2）：结案结论=verified（属实）时由
    结案挂钩自动生成——审计定谳的下一棒是机构处置（谁/何时/处置说明逐项留痕）。

    - req_hash_hex 唯一=幂等锚：同案同请求重复挂钩/重复触发不重复建单；
    - 误报（mistaken）/无法查证（inconclusive）不建单——无处置对象；
    - username 取该请求解锁实名（warrants.unlocked_username——unlocked 数据，
      executed 前置保证已回填；不可得时如实存空串，不臆造）。"""

    __tablename__ = "disposal_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    req_hash_hex: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_no: Mapped[str] = mapped_column(String(128))
    username: Mapped[str] = mapped_column(String(128), default="")
    created_ts: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending / done
    resolved_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_ts: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class CollabIssued(Base):
    """RA 协作函出具台账（FZC2 配套）：出具行为可追溯——谁/何时/对哪张令状/哪个凭证。"""

    __tablename__ = "collab_issued"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    warrant_hash_hex: Mapped[str] = mapped_column(String(64), index=True)
    master_cred_hash_hex: Mapped[str] = mapped_column(String(64), index=True)
    code_fingerprint_hex: Mapped[str] = mapped_column(String(16))
    issued_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
