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


class IndexerCursor(Base):
    """索引器扫描游标（2026-10-12 验收批根修）：已扫描最大块持久化。

    旧形态游标=max(chain_events.block)+1——事件稀疏段（如合约重部署后首个
    事件距上一事件 >单轮扫描窗 500 块）时游标永远无法跨越空窗 ⟹ 索引器
    永久停摆（实测：游标停在 10628，head 已 11270+，违规事件永不入箱）。
    本行与事件行解耦：扫描过即推进（无论该窗有无事件），旧语义保留为
    无行时的种子回退。单行形态（id=1）——索引器全库唯一。"""

    __tablename__ = "indexer_cursor"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_scanned_block: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow
    )


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
