"""0022 一次性令牌消费账本（S1 全流程实弹根修 2026-10-06）

Revision ID: d5e6f7a8
Revises: c4d5e6f7
Create Date: 2026-10-06
"""
from alembic import op
import sqlalchemy as sa

revision = "d5e6f7a8"
down_revision = "c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "auth_records",
        sa.Column("token_consumed_ts", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("auth_records", "token_consumed_ts")
