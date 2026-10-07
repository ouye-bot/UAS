"""批 4 授权面与服务工程（2026-10-04）：案卷唯一归属 + 挑战过期索引。

①  applications.case_id + 唯一索引（ix_applications_case_id）：出证案卷号
    服务端权威归属——/authz/apply 首个申请绑定 case_id 与其材料，此后携同
    case_id 的申请材料一致=幂等受理、不一致=409 case_taken（堵「客户端给定
    case_id 指向任意已存在案卷目录触发验证与授权登记」的抢注面）。历史行
    NULL 不参与唯一性（SQLite/PG 唯一索引均放行多 NULL）。
②  auth_challenges.created_ts 索引（ix_auth_challenges_created_ts）：过期
    挑战清理从全表扫+逐行 DELETE 改索引范围单条批量 DELETE。
"""
from alembic import op
import sqlalchemy as sa

revision = "a0b1c2d3"
down_revision = "c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("applications", sa.Column("case_id", sa.String(64), nullable=True))
    op.create_index("ix_applications_case_id", "applications", ["case_id"], unique=True)
    op.create_index("ix_auth_challenges_created_ts", "auth_challenges", ["created_ts"])


def downgrade() -> None:
    op.drop_index("ix_auth_challenges_created_ts", table_name="auth_challenges")
    op.drop_index("ix_applications_case_id", table_name="applications")
    op.drop_column("applications", "case_id")
