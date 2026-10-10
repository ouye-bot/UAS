"""0025 多机构一期：机构域键 org_id（2026-10-10 ⑥站）

accounts/users 增 org_id：机构域账户与用户归属机构（域键=受理/管理域）。
NULL 与历史行 server_default="org-a"——缺省机构域（现网单机构=org-a 惯例）。
域键为管理/公示面归属标注：一期电路 pk_RA 单钥不动（受理门控零变化），
跨域吊销即时生效=共享撤销树单棵（本域吊销直接进本域树）；机构准入/撤销根
公示面=FedRegistry（governor 治理面+逐域署名锚+全局聚合根）。

Revision ID: a6b7c8d9
Revises: e7f8a9b0
Create Date: 2026-10-10
"""
from alembic import op
import sqlalchemy as sa

revision = "a6b7c8d9"
down_revision = "e7f8a9b0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "accounts",
        sa.Column("org_id", sa.String(length=32), nullable=False,
                  server_default="org-a"),
    )
    op.add_column(
        "users",
        sa.Column("org_id", sa.String(length=32), nullable=False,
                  server_default="org-a"),
    )


def downgrade() -> None:
    op.drop_column("users", "org_id")
    op.drop_column("accounts", "org_id")
