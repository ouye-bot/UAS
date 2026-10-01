"""sub-credential 重申请放行（R3-1.2，评审 P1-2）：唯一索引改部分索引——
仅 pending/approved 占用子凭证，rejected 行不再永久烧坑（配合 worker
approved 消费回写=配额释放口径完整闭环）。

Revision ID: b7c8d9e0
Revises: c3d4e5f6
Create Date: 2026-09-24
"""

from alembic import op

revision = "b7c8d9e0"
down_revision = "c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ux_applications_sub_cred_hash")
    op.execute(
        "CREATE UNIQUE INDEX ux_applications_sub_cred_active "
        "ON applications (sub_cred_hash_hex) "
        "WHERE status IN ('pending', 'approved')"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ux_applications_sub_cred_active")
    op.execute(
        "CREATE UNIQUE INDEX ux_applications_sub_cred_hash "
        "ON applications (sub_cred_hash_hex)"
    )
