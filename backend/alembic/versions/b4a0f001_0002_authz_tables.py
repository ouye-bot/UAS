"""B4 authz 三表（applications/receipts/auth_records——零身份列纪律）

Revision ID: b4a0f001
Revises: 30f65e47d9dc
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa

revision = "b4a0f001"
down_revision = "30f65e47d9dc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "applications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("session_pk_hex", sa.String(128), nullable=False),
        sa.Column("sub_sig_hex", sa.String(128), nullable=False),
        sa.Column("sub_cred_hash_hex", sa.String(64), nullable=False, index=True),
        sa.Column("nonce_hex", sa.String(32), nullable=False),
        sa.Column("plan_hash_hex", sa.String(64), nullable=False),
        sa.Column("class_id", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("proof_path", sa.Text(), nullable=False),
        sa.Column("spec_path", sa.Text(), nullable=False),
        sa.Column("rev_root_hex", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, index=True),
        sa.Column("reject_reason", sa.String(200), nullable=False),
        sa.Column("receipt_id", sa.Integer(), nullable=True),
        sa.Column("auth_id", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "receipts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code_hex", sa.String(32), nullable=False, unique=True),
        sa.Column("application_id", sa.Integer(), nullable=False, index=True),
        sa.Column("token_cipher", sa.LargeBinary(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "auth_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("auth_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("application_id", sa.Integer(), nullable=False),
        sa.Column("token_hash_hex", sa.String(64), nullable=False),
        sa.Column("proof_digest_hex", sa.String(64), nullable=False),
        sa.Column("verdict_path", sa.Text(), nullable=False),
        sa.Column("tx_hash", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


    # A3 通道②：credentials 增 wrap 列（与 authz 三表同批）
    op.add_column("credentials", sa.Column("id_store_cipher", sa.LargeBinary(), nullable=True))
    op.add_column("credentials", sa.Column("class_id", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("credentials", "class_id")
    op.drop_column("credentials", "id_store_cipher")
    op.drop_table("auth_records")
    op.drop_table("receipts")
    op.drop_table("applications")
