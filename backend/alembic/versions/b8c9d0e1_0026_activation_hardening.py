"""0026 激活面收紧（2026-10-11）：待激活时效+一次性激活码双因子

accounts 增两列：
- pending_since_ts：进入 pending_activation 的时刻（72h 时效窗起点）——
  存量行由本迁移 UPDATE 回填 CURRENT_TIMESTAMP（从迁移时刻起算，从严）。
  注：SQLite 拒绝 ALTER ADD COLUMN 携带非常量 DEFAULT（非空表
  OperationalError——空表侥幸放行），故不用 server_default 而以显式
  UPDATE 回填，语义等价且 SQLite/PostgreSQL 双兼容；
- activation_code_hash：一次性激活码的 SM3 哈希（明码只经种子脚本独立
  交付件出；激活成功即焚）。demo 档双因子关（恒 NULL），production 档
  required 下 NULL=拒绝并指引管理员重置出码。

Revision ID: b8c9d0e1
Revises: a6b7c8d9
Create Date: 2026-10-11
"""
from alembic import op
import sqlalchemy as sa

revision = "b8c9d0e1"
down_revision = "a6b7c8d9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "accounts",
        sa.Column("pending_since_ts", sa.DateTime(), nullable=True),
    )
    # 存量行回填=迁移时刻起算（从严——待激活存量须在 72h 内完成激活，
    # 否则走管理员重置重开窗；active 行该列无消费方，回填无害）
    op.execute("UPDATE accounts SET pending_since_ts = CURRENT_TIMESTAMP")
    op.add_column(
        "accounts",
        sa.Column("activation_code_hash", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("accounts", "activation_code_hash")
    op.drop_column("accounts", "pending_since_ts")
