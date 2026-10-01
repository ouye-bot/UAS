"""audit warrants 表（B7）

Revision ID: c7d1a2b3
Revises: b4a0f001
Create Date: 2026-09-21
"""
from alembic import op
import sqlalchemy as sa

revision = "c7d1a2b3"
down_revision = "b4a0f001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "warrants",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("warrant_hash_hex", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("case_no", sa.String(128), nullable=False),
        sa.Column("scope_hash_hex", sa.String(64), nullable=False),
        sa.Column("legal_basis_hash_hex", sa.String(64), nullable=False),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("target_auth_id", sa.BigInteger(), nullable=True),
        sa.Column("created_ts", sa.DateTime(), nullable=False),
        sa.Column("unlocked_ts", sa.DateTime(), nullable=True),
        sa.Column("unlocked_master_cred_hash_hex", sa.String(64), nullable=True),
        sa.Column("unlocked_username", sa.String(128), nullable=True),
        sa.Column("unlocked_id_number", sa.String(32), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("warrants")
