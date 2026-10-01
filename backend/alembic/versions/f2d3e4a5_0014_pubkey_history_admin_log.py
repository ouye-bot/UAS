"""密码重置收紧批（2026-09-30）：account_pubkey_history + account_admin_log。

公钥纪元史 append-only：注册/激活追加、重置只关闭（retired_ts）——换钥后
历史签名仍可按签名时点公钥复验（双控不可抵赖）。账户管理动作台账：密码
重置逐笔留痕（在线重置端点已下线——唯一路径=离线种子脚本）。
"""
from alembic import op
import sqlalchemy as sa

revision = "f2d3e4a5"
down_revision = "c3d4e5f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "account_pubkey_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, index=True),
        sa.Column("epoch", sa.Integer(), nullable=False),
        sa.Column("pubkey_hex", sa.String(128), nullable=False),
        sa.Column("activated_ts", sa.DateTime(), nullable=False),
        sa.Column("retired_ts", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "account_admin_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("username", sa.String(64), nullable=False, index=True),
        sa.Column("operator", sa.String(64), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("account_admin_log")
    op.drop_table("account_pubkey_history")
