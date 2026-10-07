"""结案升格批（2026-10-04 台面升格 A1/A6）：结案结论+签名+时间戳+案件台账。

①  collab_requests 结案五列：conclusion（verified=属实/mistaken=误报/
    inconclusive=无法查证）+ conclusion_text（终局说明，属实时服务端强制
    必填）+ conclusion_sig_hex（审计员钥签
    FZ-COLLAB-CLOSE|v1|{req_hash}|{conclusion}|{conclusion_text}）+
    closed_ts + case_archive_fp_hex（案卷指纹）。此前结案仅条件 UPDATE
    status=executed→closed——零结论/零签名/零时间戳（对比：驳回都强制
    理由+签名），案件终局零密码重量。
②  case_ledger（append-only 案件台账）：一行=一次案件终局动作——req_hash/
    令状/案号/action=close/结论/签名/结案人/实名哈希/案卷指纹/结案时间戳，
    collab_requests 行之外的独立复核锚。
"""
from alembic import op
import sqlalchemy as sa

revision = "a2b3c4d5"
down_revision = "a0b1c2d3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("collab_requests", sa.Column("conclusion", sa.String(16), nullable=True))
    op.add_column("collab_requests", sa.Column("conclusion_text", sa.Text(), nullable=True))
    op.add_column("collab_requests", sa.Column("conclusion_sig_hex", sa.String(256), nullable=True))
    op.add_column("collab_requests", sa.Column("closed_ts", sa.DateTime(), nullable=True))
    op.add_column("collab_requests", sa.Column("case_archive_fp_hex", sa.String(64), nullable=True))
    op.create_table(
        "case_ledger",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("req_hash_hex", sa.String(64), nullable=False, index=True),
        sa.Column("warrant_hash_hex", sa.String(64), nullable=False, index=True),
        sa.Column("case_no", sa.String(128), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("conclusion", sa.String(16), nullable=False),
        sa.Column("conclusion_text", sa.Text(), nullable=True),
        sa.Column("sig_hex", sa.String(256), nullable=False),
        sa.Column("operator", sa.String(64), nullable=False),
        sa.Column("identity_hash_hex", sa.String(64), nullable=False),
        sa.Column("case_archive_fp_hex", sa.String(64), nullable=False),
        sa.Column("closed_ts", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("case_ledger")
    op.drop_column("collab_requests", "case_archive_fp_hex")
    op.drop_column("collab_requests", "closed_ts")
    op.drop_column("collab_requests", "conclusion_sig_hex")
    op.drop_column("collab_requests", "conclusion_text")
    op.drop_column("collab_requests", "conclusion")
