"""stmt e 绑定列 + 子凭证唯一约束（S5 安全修复）

Revision ID: e5f6a7b8
Revises: d8e2f3a4
Create Date: 2026-09-22
"""
from alembic import op
import sqlalchemy as sa

revision = "e5f6a7b8"
down_revision = "d8e2f3a4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("applications", sa.Column("e_hex", sa.String(64), nullable=False, server_default=""))
    # 子凭证一次性=库级强制（TOCTOU 根修：并发双申请唯一索引兜底）——
    # 先清历史重复（保留最小 id），再建唯一索引
    conn = op.get_bind()
    conn.execute(sa.text(
        "DELETE FROM applications WHERE id NOT IN "
        "(SELECT MIN(id) FROM applications GROUP BY sub_cred_hash_hex)"
    ))
    op.create_index("ux_applications_sub_cred_hash", "applications", ["sub_cred_hash_hex"], unique=True)


def downgrade() -> None:
    op.drop_index("ux_applications_sub_cred_hash", table_name="applications")
    op.drop_column("applications", "e_hex")
