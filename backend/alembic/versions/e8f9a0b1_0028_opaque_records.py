"""0028 ⑫OPAQUE 记录四列（O-3 批——设计合同 §1.3）

accounts 增 OPRF 记录面（mode-B——RFC 9807 credential file 对位）：
- opaque_masking_key_hex String(64) NULL：掩码钥（客户端 §1.4 ④派生上传，D-6）
  ——mode-B masked_response 掩码面+keystore 410 判别键；NULL=v4 存量形态。
- opaque_kdf_salt_hex String(32) NULL / opaque_kdf_iter Integer NULL：
  Stretch 盐/迭代（客户端生成上传，D-8——密封先于账户存在；登录经 evaluate
  响应回传账面值）。
- opaque_key_id String(16) NULL：k_oprf 钥指纹（SM3(该钥公钥)前 8 hex——§4.3
  轮换双钥过渡窗判别键）。

全列 nullable 无缺省——存量 v4 行零回填零语义变化（登录/keystore 既有路径
不读这些列）。

Revision ID: e8f9a0b1
Revises: d0e1f2a3
Create Date: 2026-10-12
"""

from alembic import op
import sqlalchemy as sa

revision = "e8f9a0b1"
down_revision = "d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("accounts") as batch:
        batch.add_column(sa.Column("opaque_masking_key_hex", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("opaque_kdf_salt_hex", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("opaque_kdf_iter", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("opaque_key_id", sa.String(length=16), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("accounts") as batch:
        batch.drop_column("opaque_key_id")
        batch.drop_column("opaque_kdf_iter")
        batch.drop_column("opaque_kdf_salt_hex")
        batch.drop_column("opaque_masking_key_hex")
