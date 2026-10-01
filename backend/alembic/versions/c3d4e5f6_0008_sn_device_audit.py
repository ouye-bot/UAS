"""SN v2：checkpoint_anchors 表（检查点持久化——设备交叉审计数据面）"""
from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f6"
down_revision = "f7a8b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "checkpoint_anchors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("auth_id", sa.BigInteger(), nullable=False, index=True),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("chain_head_hex", sa.String(64), nullable=False),
        sa.Column("fence_state_hex", sa.String(8), nullable=False),
        sa.Column("device_sig_hex", sa.String(128), nullable=False),
        sa.Column("device_pub_hex", sa.String(128), nullable=False),
        sa.Column("tx_hash", sa.String(80), nullable=False),
        sa.Column("logged_at", sa.DateTime(), nullable=False),
    )
    op.add_column("warrants", sa.Column("unlocked_sn", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("warrants", "unlocked_sn")
    op.drop_table("checkpoint_anchors")
