"""审计台重构（2026-09-28 F 席）：warrants.legal_basis_text + collab_issued 台账。

- warrants.legal_basis_text：立案依据原文落库（此前只存哈希——事后无法自证
  「当时依据是什么文本」；哈希+原文双锚）。
- collab_issued：RA 协作函出具台账（FZC2 函-令状绑定配套——出具行为从
  零台账变为可追溯：谁/何时/对哪张令状/对哪个凭证）。
"""
from alembic import op
import sqlalchemy as sa

revision = "d9e0f1a2"
down_revision = "b7c8d9e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("warrants", sa.Column("legal_basis_text", sa.Text(), nullable=True))
    op.create_table(
        "collab_issued",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("warrant_hash_hex", sa.String(64), nullable=False, index=True),
        sa.Column("master_cred_hash_hex", sa.String(64), nullable=False, index=True),
        sa.Column("code_fingerprint_hex", sa.String(16), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("collab_issued")
    op.drop_column("warrants", "legal_basis_text")
