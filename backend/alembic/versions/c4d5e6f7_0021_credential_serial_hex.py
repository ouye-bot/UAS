"""SN 绑定换代（2026-10-06）：credentials.serial_hex 原文溯源列

服务端权威 sn_hash=SM3(serial) 全 32B 的溯源源（受理门控实例 25 校验+
令牌 sn_hash 载荷——零客户端自报）。历史行为 NULL：受理面 fail-closed
人话拒绝（sn_unresolved，重新登记后申请）。

Revision ID: c4d5e6f7
Revises: b7d8e9f0
Create Date: 2026-10-06
"""

from alembic import op
import sqlalchemy as sa

revision = "c4d5e6f7"
down_revision = "b7d8e9f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("credentials", sa.Column("serial_hex", sa.String(110), nullable=True))


def downgrade() -> None:
    op.drop_column("credentials", "serial_hex")
