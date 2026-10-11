"""0027 机构机队接口实装：credentials 增 cred_kind/owner_org_id/device_no（3.1）

合约 IdentityRegistry credKind=2 预留面激活（合约字节零触碰）：机构管理员以
org 身份批量登记设备（kind=2 机构承诺）+机队设备子凭证批量签发。

- cred_kind Integer NOT NULL server_default="1"：个人飞手=1（历史行回填缺省）、
  机构机队=2——链上 registerCommitment credKind 的 DB 镜像列。
- owner_org_id String(32) NULL：归属机构域权威列（个人行=注册受理域，register
  同步写；机队行=登记操作者域）。历史行 NULL——域解析回落 users.org_id（0025
  既有事实延续）。
- device_no String(18) NULL：机队设备登记号（C 承诺 id_number 槽的机构面填充
  ——承诺原像不可逆，列表/管理面显示源）；个人行 NULL。
- user_id 转 nullable：机队行 user_id=NULL（设备非人，不占 users 实名域）。

Revision ID: d0e1f2a3
Revises: b8c9d0e1
Create Date: 2026-10-11
"""

from alembic import op
import sqlalchemy as sa

revision = "d0e1f2a3"
down_revision = "b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("credentials") as batch:
        batch.add_column(sa.Column("cred_kind", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("owner_org_id", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("device_no", sa.String(length=18), nullable=True))
        batch.alter_column("user_id", existing_type=sa.Integer(), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("credentials") as batch:
        batch.alter_column("user_id", existing_type=sa.Integer(), nullable=False)
        batch.drop_column("device_no")
        batch.drop_column("owner_org_id")
        batch.drop_column("cred_kind")
