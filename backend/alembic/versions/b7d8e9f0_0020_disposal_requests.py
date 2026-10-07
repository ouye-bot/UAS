"""处置待办表（2026-10-04 处置联动 A5/B2）：结案结论=verified（属实）时由
结案挂钩自动生成机构处置待办——审计定谳的下一棒（处置动作逐单留痕）。

- req_hash 唯一=幂等锚：同案同请求重复挂钩/重复触发不重复建单；
- 误报（mistaken）/无法查证（inconclusive）不建单——无处置对象；
- username 取该请求解锁实名（warrants.unlocked_username）；resolved_note/
  resolved_ts 由管理员 resolve 时落定（pending→done 条件 UPDATE）。
"""
from alembic import op
import sqlalchemy as sa

revision = "b7d8e9f0"
down_revision = "b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "disposal_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("req_hash_hex", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("case_no", sa.String(128), nullable=False),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("created_ts", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("resolved_note", sa.Text(), nullable=True),
        sa.Column("resolved_ts", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("disposal_requests")
