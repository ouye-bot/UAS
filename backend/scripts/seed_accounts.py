"""预置机构账户种子（审计员/管理员）——2026-09-29 账户批 B1。

口令来源纪律（红线）：
- env FZ_SEED_AUDITOR_PASSWORD / FZ_SEED_ADMIN_PASSWORD 优先（部署方注入）；
- 未注入则 CSPRNG 生成 16 位随机口令——**只写入 %TEMP%\\fz_accounts_seed.txt**
  （与 fz_audit_token.txt 同纪律：文件不进仓、不入文档，部署者线下交付）。
- 库内仅存 KDF 核对子（首登激活一次性比对后即焚）——无明文无哈希可逆面。

用法：python scripts/seed_accounts.py [--auditor 审计员用户名] [--admin 管理员用户名]
缺省用户名：auditor / admin。
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.accounts.models import Account  # noqa: E402
from app.accounts.service import reset_institutional_account  # noqa: E402
from app.accounts.service import seed_institutional_account  # noqa: E402
from app.ra.models import Base  # noqa: E402


def _ensure_tables() -> None:
    from app.db import _engine  # noqa: F401  确认引擎可建

    Base.metadata.create_all(_engine)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--auditor", default="auditor")
    ap.add_argument("--admin", default="admin")
    ap.add_argument("--reset", action="store_true",
                    help="重置已激活机构账户密码（焚毁旧钥+清会话——下次登录重新激活）")
    ap.add_argument("--auditor-pw", help="指定审计员密码（默认随机）")
    ap.add_argument("--admin-pw", help="指定管理员密码（默认随机）")
    args = ap.parse_args()

    _ensure_tables()

    from app.db import SessionLocal

    out_lines: list[str] = []
    s = SessionLocal()
    try:
        for username, role, env_key, pw_flag in (
            (args.auditor, "auditor", "FZ_SEED_AUDITOR_PASSWORD", args.auditor_pw),
            (args.admin, "admin", "FZ_SEED_ADMIN_PASSWORD", args.admin_pw),
        ):
            existing = (
                s.query(Account).filter(Account.username == username).one_or_none()
            )
            if existing is not None and existing.status == "active":
                if not args.reset:
                    out_lines.append(f"{username}（{role}）：已激活——跳过（不触碰已激活账户）")
                    continue
                pw = pw_flag or os.environ.get(env_key) or secrets.token_urlsafe(12)
                reset_institutional_account(s, username, pw)
                out_lines.append(f"{username}（{role}）：已重置——新密码 {pw}（下次登录重新激活）")
                continue
            pw = pw_flag or os.environ.get(env_key) or secrets.token_urlsafe(12)
            seed_institutional_account(s, username, role, pw)
            out_lines.append(f"{username}（{role}）：初始密码 {pw}")
    finally:
        s.close()

    text = "\n".join(out_lines) + "\n"
    print(text, end="")
    target = Path(tempfile.gettempdir()) / "fz_accounts_seed.txt"
    target.write_text(text, encoding="utf-8")
    print(f"\n[seed] 初始密码已写入 {target}（不进仓不入文档——线下交付后可删除）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
