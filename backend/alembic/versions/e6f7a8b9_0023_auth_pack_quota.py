"""0023 授权包配额制（2026-10-06 多架次拍板）

applications 增 sorties（申请配额 1~5，worker recordAuth 透传上链）；
auth_records 增 sorties/remaining（配额账本——每次消费回报递减，
remaining==0 置 token_consumed_ts 终态；缺省 1 与令牌一次性逐字等价）。

Revision ID: e6f7a8b9
Revises: d5e6f7a8
Create Date: 2026-10-06
"""
from alembic import op
import sqlalchemy as sa

revision = "e6f7a8b9"
down_revision = "d5e6f7a8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "applications",
        sa.Column("sorties", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "auth_records",
        sa.Column("sorties", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "auth_records",
        sa.Column("remaining", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("auth_records", "remaining")
    op.drop_column("auth_records", "sorties")
    op.drop_column("applications", "sorties")
