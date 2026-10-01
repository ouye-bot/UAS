"""双控批二（2026-09-29）：collab_requests.execute_error——异步执行失败原因列。

approve 异步化（批准即返回+后台执行）配套：执行失败从 500 直穿改为
execute_failed 态+失败原因落库（前端可诊断可重试）。
"""
from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f7"
down_revision = "b1c2d3e4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("collab_requests", sa.Column("execute_error", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("collab_requests", "execute_error")
