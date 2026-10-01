"""chain_events 表（P1-C3）：链上事件读优化投影。"""
from alembic import op
import sqlalchemy as sa

revision = "a1b2c3d4"
down_revision = "f7a8b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chain_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("auth_id", sa.BigInteger(), nullable=False, index=True),
        sa.Column("event_type", sa.Integer(), nullable=False),
        sa.Column("event_hash_hex", sa.String(64), nullable=False),
        sa.Column("block", sa.BigInteger(), nullable=False),
        sa.Column("tx_hash", sa.String(80), nullable=False),
        sa.Column("logged_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("chain_events")
