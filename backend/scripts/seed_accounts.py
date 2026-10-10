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
from app.accounts.service import (
    activation_code_required,  # noqa: E402
    issue_activation_code,  # noqa: E402
    reset_institutional_account,  # noqa: E402
    seed_institutional_account,  # noqa: E402
)
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
    ap.add_argument("--no-org-b", action="store_true",
                    help="跳过第二机构 demo 种子（⑥站多机构：auditor-b/admin-b@org-b）")
    ap.add_argument("--auditor-b-pw", default="auditorb123",
                    help="第二机构审计员初始密码（固定缺省=演示拍板纪律同 org-a）")
    ap.add_argument("--admin-b-pw", default="adminb123",
                    help="第二机构管理员初始密码（固定缺省=演示拍板纪律同 org-a）")
    args = ap.parse_args()

    _ensure_tables()

    from app.db import SessionLocal

    out_lines: list[str] = []
    code_lines: list[str] = []

    def _maybe_issue_code(session, username: str, role_name: str, lines: list[str]) -> None:
        """双因子档位开启时为待激活账户出一次性码（demo 档缺省关=零出码）。"""
        if not activation_code_required():
            return
        row = session.query(Account).filter(Account.username == username).one_or_none()
        if row is None or row.status != "pending_activation":
            return
        code = issue_activation_code(session, row)
        session.commit()
        lines.append(f"{username}（{role_name}）：激活码 {code}")
        code_lines.append(f"{username}：{code}")

    s = SessionLocal()
    try:
        seeds = [
            (args.auditor, "auditor", "org-a", "FZ_SEED_AUDITOR_PASSWORD", args.auditor_pw),
            (args.admin, "admin", "org-a", "FZ_SEED_ADMIN_PASSWORD", args.admin_pw),
        ]
        if not args.no_org_b:
            # ⑥站多机构一期：第二机构 demo 域种子（固定口令=拍板 7 同纪律——
            # 每次种子显式传入，不随机；口令不入库不入文档，本文件例外面=%TEMP% seed）
            seeds.append(("auditor-b", "auditor", "org-b", None, args.auditor_b_pw))
            seeds.append(("admin-b", "admin", "org-b", None, args.admin_b_pw))
        def _pw_of(env_key: str | None, pw_flag: str | None) -> str:
            return (
                pw_flag
                or (os.environ.get(env_key) if env_key else None)
                or secrets.token_urlsafe(12)
            )

        for username, role, org_id, env_key, pw_flag in seeds:
            existing = (
                s.query(Account).filter(Account.username == username).one_or_none()
            )
            if existing is not None and existing.status == "active":
                if not args.reset:
                    out_lines.append(f"{username}（{role}）：已激活——跳过（不触碰已激活账户）")
                    continue
                pw = _pw_of(env_key, pw_flag)
                reset_institutional_account(s, username, pw)
                out_lines.append(f"{username}（{role}）：已重置——新密码 {pw}（下次登录重新激活）")
                _maybe_issue_code(s, username, role, out_lines)
                continue
            pw = _pw_of(env_key, pw_flag)
            seed_institutional_account(s, username, role, pw, org_id=org_id)
            out_lines.append(f"{username}（{role}）：初始密码 {pw}")
            _maybe_issue_code(s, username, role, out_lines)
    finally:
        s.close()

    text = "\n".join(out_lines) + "\n"
    print(text, end="")
    target = Path(tempfile.gettempdir()) / "fz_accounts_seed.txt"
    target.write_text(text, encoding="utf-8")
    print(f"\n[seed] 初始密码已写入 {target}（不进仓不入文档——线下交付后可删除）")
    if code_lines:
        # 双通道纪律（2026-10-11 批③）：激活码与口令**分文件**交付——单文件
        # 泄露不足以抢注钥对（口令+码须同时得手）。码=一次性，激活成功即焚。
        code_text = "\n".join(code_lines) + "\n"
        code_target = Path(tempfile.gettempdir()) / "fz_activation_codes.txt"
        code_target.write_text(code_text, encoding="utf-8")
        print(f"[seed] 一次性激活码已写入 {code_target}（与口令文件分离交付——"
              "激活成功即焚；泄露=即刻重置出码）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
