"""worker 队列语义列（P0-2）：认领租约+瞬时失败重试

Revision ID: f7a8b9c0
Revises: e5f6a7b8
Create Date: 2026-09-22
"""
from alembic import op
import sqlalchemy as sa

revision = "f7a8b9c0"
down_revision = "e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("applications", sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("applications", sa.Column("locked_by", sa.String(64), nullable=True))
    op.add_column("applications", sa.Column("locked_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("applications", "locked_at")
    op.drop_column("applications", "locked_by")
    op.drop_column("applications", "attempts")
