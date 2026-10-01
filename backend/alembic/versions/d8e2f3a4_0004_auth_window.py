"""auth records 授权窗列（R1）

Revision ID: d8e2f3a4
Revises: c7d1a2b3
Create Date: 2026-09-21
"""
from alembic import op
import sqlalchemy as sa

revision = "d8e2f3a4"
down_revision = "c7d1a2b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 授权窗列双表（R1 模型 Application.t_start/t_end + AuthRecord 同窗）——
    # 首版漏了 applications（测试 create_all 建表掩盖，持久库 worker 首查即炸
    # "no such column: applications.t_start"——本批收口补全）。
    op.add_column("applications", sa.Column("t_start", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("applications", sa.Column("t_end", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("auth_records", sa.Column("t_start", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("auth_records", sa.Column("t_end", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("auth_records", "t_end")
    op.drop_column("auth_records", "t_start")
    op.drop_column("applications", "t_end")
    op.drop_column("applications", "t_start")
