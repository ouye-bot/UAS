"""merge 0007/0008 双头（R4 评审 P2-3 根修）：统一迁移链——全新环境
`alembic upgrade head` 单命令可达当前头（此前双头必须 heads/手工盖章，
生产档部署流程在干净机不可执行）。

live 库 alembic_version 本就双行 [('b7c8d9e0',), ('a1b2c3d4',)]——本空迁移
对 live 是无害补齐（两侧父本皆已应用）。
"""
from alembic import op  # noqa: F401  merge 迁移惯例保留 import 形态


revision = "ee11ff22"
down_revision = ("a1b2c3d4", "d9e0f1a2")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
