"""S6 安全闭环（2026-10-04）：applications.exp_u——子凭证有效期归档列。

受理面新增「凭证有效期覆盖授权窗」核对（exp_u ≥ t_end，拒绝码
cred_expired_window）：电路 AUTH 语句只证 exp_u ≥ t_epoch（出证时刻），
宿主面此前无任何一处核对凭证效期覆盖整个授权窗。exp_u 从已验签报文
M_A′[160:164] 解出落库——worker 判决件 expected.exp_u 由此取值，第三方
拿到判决件即可自行核对覆盖关系。
"""
from alembic import op
import sqlalchemy as sa

revision = "b5c6d7e8"
down_revision = "f2d3e4a5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "applications",
        sa.Column("exp_u", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("applications", "exp_u")
