"""撤销业务线硬化（2026-10-04 B1/B4/B6/B7 批）：

①  revocations.revoked_by：撤销执行者（机构管理员账户名）——「谁撤销」落库。
②  credentials.id_number_hash_hex：SM3(证件号) hex（RA 侧列）。RA 本为组织级
    TCB（原像/实名映射已在库），零新增暴露面；消费点=吊销黑名单（重注册禁入）。
③  restore_requests：双控恢复请求（admin 发起+auditor 复核，双 SM2 签名齐→执行）。
④  revoked_id_blacklist：证件号级吊销黑名单（SM3 哈希）——被吊销者同证件号
    重登记即满血复活的逃逸面封堵。
⑤  revocation_ledger：撤销动作 append-only 台账（谁/何时/对谁/何理由/何签名/
    何纪元/联动了哪些授权）。
"""

import sqlalchemy as sa

from alembic import op

revision = "f0e1d2c3"
down_revision = "a0b1c2d3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "revocations",
        sa.Column("revoked_by", sa.String(64), nullable=False, server_default=""),
    )
    op.add_column("credentials", sa.Column("id_number_hash_hex", sa.String(64), nullable=True))
    op.create_table(
        "restore_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("handle_hex", sa.String(64), nullable=False, index=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column("admin_sig_hex", sa.String(256), nullable=False),
        sa.Column("countersign_by", sa.String(64), nullable=True),
        sa.Column("countersign_sig_hex", sa.String(256), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("execute_error", sa.Text(), nullable=True),
        sa.Column("created_ts", sa.DateTime(), nullable=False),
        sa.Column("executed_ts", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "revoked_id_blacklist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("id_number_hash_hex", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("reason", sa.String(200), nullable=False, server_default=""),
        sa.Column("revoked_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "revocation_ledger",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False, server_default=""),
        sa.Column("subject_hex", sa.String(64), nullable=True),
        sa.Column("username", sa.String(64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("sig_hex", sa.String(256), nullable=True),
        sa.Column("epoch", sa.BigInteger(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_table("revocation_ledger")
    op.drop_table("revoked_id_blacklist")
    op.drop_table("restore_requests")
    op.drop_column("credentials", "id_number_hash_hex")
    op.drop_column("revocations", "revoked_by")
