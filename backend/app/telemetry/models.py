"""遥测事件链下投影模型（P1-C3）：链上 EventRecorded→chain_events 索引。

审计追溯时间线的数据源（真链行的可查询投影——链仍为单一事实源，本表=读优化）。
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import BigInteger, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.ra.models import Base


class ChainEvent(Base):
    __tablename__ = "chain_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    auth_id: Mapped[int] = mapped_column(BigInteger, index=True)
    event_type: Mapped[int] = mapped_column(Integer)  # 1=固件围栏 2=地面站 3=通信中断 4=迫降
    event_hash_hex: Mapped[str] = mapped_column(String(64))
    block: Mapped[int] = mapped_column(BigInteger)
    tx_hash: Mapped[str] = mapped_column(String(80))
    logged_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class CheckpointAnchor(Base):
    """检查点锚定持久化（SN v2）：设备交叉审计的数据面。

    链上 latest 只有 (chainHead, seq, ts)——deviceSig/fence_state 仅存于
    事件日志；本表=/engine/anchor 落库的读优化投影（含签名与围栏态），
    供追溯时间线设备一致性核对使用。
    """

    __tablename__ = "checkpoint_anchors"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    auth_id: Mapped[int] = mapped_column(BigInteger, index=True)
    seq: Mapped[int] = mapped_column(Integer)
    chain_head_hex: Mapped[str] = mapped_column(String(64))
    fence_state_hex: Mapped[str] = mapped_column(String(8))
    device_sig_hex: Mapped[str] = mapped_column(String(128))
    device_pub_hex: Mapped[str] = mapped_column(String(128))
    tx_hash: Mapped[str] = mapped_column(String(80), default="")
    logged_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
