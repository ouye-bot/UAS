"""0029 索引器扫描游标表（与 app/telemetry/models.py:IndexerCursor 对齐）

indexer_cursor 单行表（id=1 全库唯一）：链上事件索引器已扫描最大块持久化。
旧形态游标=max(chain_events.block)+1 在事件稀疏段（>单轮扫描窗 500 块）时
永远无法跨越空窗，索引器永久停摆——本表与事件行解耦，扫描过即推进；
无行时索引器按旧语义种子回退（app/telemetry/indexer.py），故本迁移只建表
不播种。

此前该表仅由运行时 create_all 兜底建出——从备份恢复库或纯 alembic 建库
场景下表缺失，索引器停摆。本迁移补齐建链缺口。

Revision ID: a9b0c1d2
Revises: e8f9a0b1
Create Date: 2026-10-15
"""

from alembic import op
import sqlalchemy as sa

revision = "a9b0c1d2"
down_revision = "e8f9a0b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "indexer_cursor",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_scanned_block", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("indexer_cursor")
