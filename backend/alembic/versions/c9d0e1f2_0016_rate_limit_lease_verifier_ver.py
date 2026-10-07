"""批 2 密码底座升档（2026-10-04）：rate_limit_buckets + 执行租约 + 核对子版本。

①  rate_limit_buckets：/auth/* 尝试限速落库（原进程内存固定窗——多副本
   部署各记各账、重启清零；落库后跨副本共享同窗、重启不清零）。
②  collab_requests.locked_by/lease_until：双控执行租约（approved→executing
   条件 UPDATE 认领+心跳续租——多副本恰一胜者，双执行竞窗根除）。
③  accounts.init_verifier_ver：激活核对子格式版本（"v1"=独立派生域
   PBKDF2+FZ-ACTIVATE-VERIFY|v1；NULL=旧种子 KEK 等价格式——兼容读取，
   激活即焚=换代）。
"""
from alembic import op
import sqlalchemy as sa

revision = "c9d0e1f2"
down_revision = "b5c6d7e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_buckets",
        sa.Column("bucket_key", sa.String(128), primary_key=True),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("collab_requests", sa.Column("locked_by", sa.String(64), nullable=True))
    op.add_column("collab_requests", sa.Column("lease_until", sa.DateTime(), nullable=True))
    op.add_column("accounts", sa.Column("init_verifier_ver", sa.String(8), nullable=True))


def downgrade() -> None:
    op.drop_column("accounts", "init_verifier_ver")
    op.drop_column("collab_requests", "lease_until")
    op.drop_column("collab_requests", "locked_by")
    op.drop_table("rate_limit_buckets")
