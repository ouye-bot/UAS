"""账户门户（2026-09-29 账户批 B1）：accounts/auth_challenges/web_sessions/
collab_requests 四表。

- accounts：三角色账户——服务端零口令材料（挑战-应答登录）；私钥/身份资料
  仅存客户端口令 KEK 密封件。
- auth_challenges：一次性登录挑战（TTL+单次消费）。
- web_sessions：库内只存 SM3(token)。
- collab_requests：双控协作请求队列（审计发函→机构批准→自动执行）。
"""
from alembic import op
import sqlalchemy as sa

revision = "b1c2d3e4"
down_revision = "ee11ff22"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "accounts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending_profile"),
        sa.Column("pubkey_hex", sa.String(128), nullable=True),
        sa.Column("sealed_blob", sa.Text(), nullable=True),
        sa.Column("sealed_profile", sa.Text(), nullable=True),
        sa.Column("cred_hash_hex", sa.String(64), nullable=True),
        sa.Column("init_verifier_hex", sa.String(64), nullable=True),
        sa.Column("init_kdf_salt_hex", sa.String(32), nullable=True),
        sa.Column("created_ts", sa.DateTime(), nullable=False),
        sa.Column("last_login_ts", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "auth_challenges",
        sa.Column("nonce_hex", sa.String(64), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, index=True),
        sa.Column("created_ts", sa.DateTime(), nullable=False),
        sa.Column("consumed_ts", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "web_sessions",
        sa.Column("token_hash_hex", sa.String(64), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, index=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("created_ts", sa.DateTime(), nullable=False),
        sa.Column("expires_ts", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "collab_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("warrant_hash_hex", sa.String(64), nullable=False, index=True),
        sa.Column("case_no", sa.String(128), nullable=False),
        sa.Column("target_auth_id", sa.BigInteger(), nullable=True),
        sa.Column("legal_basis_text", sa.Text(), nullable=True),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("req_hash_hex", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("auditor_username", sa.String(64), nullable=False),
        sa.Column("auditor_sig_hex", sa.String(256), nullable=False),
        sa.Column("admin_username", sa.String(64), nullable=True),
        sa.Column("admin_sig_hex", sa.String(256), nullable=True),
        sa.Column("reject_reason", sa.Text(), nullable=True),
        sa.Column("fzc2_fingerprint_hex", sa.String(16), nullable=True),
        sa.Column("created_ts", sa.DateTime(), nullable=False),
        sa.Column("decided_ts", sa.DateTime(), nullable=True),
        sa.Column("executed_ts", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("collab_requests")
    op.drop_table("web_sessions")
    op.drop_table("auth_challenges")
    op.drop_table("accounts")
