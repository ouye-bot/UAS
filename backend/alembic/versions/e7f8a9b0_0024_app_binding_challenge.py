"""0024 申请行绑定挑战快照（2026-10-07 prove 窗根修）

applications 增 challenge_hex：受理门⑤钉实例 19 时现算的钥控挑战
（HMAC-SM3(FZ_AUTHZ_BINDING_KEY, plan|nonce)）随申请落库——worker 复验
消费同一值，不再按各自进程 env 重建（两进程钥漂移曾致真案卷实例 19
假拒，e2e_auth_full ⑥ 实弹）。公开值（绑定面已下发客户端+判决件归档），
无新增暴露面。历史行 server_default=""——worker 空值回落旧重建式。

Revision ID: e7f8a9b0
Revises: e6f7a8b9
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa

revision = "e7f8a9b0"
down_revision = "e6f7a8b9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "applications",
        sa.Column("challenge_hex", sa.String(length=64), nullable=False,
                  server_default=""),
    )


def downgrade() -> None:
    op.drop_column("applications", "challenge_hex")
