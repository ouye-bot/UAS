"""merge 0018/0019 双头：统一迁移链——0018（结案升格 A1/A6：collab_requests
结案五列+case_ledger）与 0019（吊销收紧批）同以 0017（a0b1c2d3）为父本并行
落笔，形成双头。本空迁移归并为单头——全新环境 `alembic upgrade head` 单命令
可达当前头（与 0012 merge 惯例同型，两侧父本皆已应用时对库无害补齐）。"""
from alembic import op  # noqa: F401  merge 迁移惯例保留 import 形态


revision = "b3c4d5e6"
down_revision = ("a2b3c4d5", "f0e1d2c3")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
