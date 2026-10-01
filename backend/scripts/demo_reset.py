# -*- coding: utf-8 -*-
"""演示库重置（2026-09-30 评审 P1-10）：清掉测试残留（案卷/协作请求/测试账户
/会话），回到「干净可演示」态——机构账户以指定密码重新播种。

做什么：
  1. （可选 --down）先停 Windows 侧栈（demo_down——WSL 链/桥不动）
  2. 删除 backend/feizheng.db（本地事务库全部重来；链上历史令状仍在链上，
     本地索引清空=列表干净——新演示用新案号即可）
  3. alembic upgrade head（重建全部表）
  4. seed_accounts --auditor-pw/--admin-pw（默认 auditor123/admin123）
之后人工 `python scripts/demo_up.py` 重启。

纪律：破坏性操作——必须 --yes；绝不触碰 WSL 链节点/桥/SITL。
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
UAS = BACKEND.parent
PY = sys.executable


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true", help="确认重置（破坏性——必填）")
    ap.add_argument("--down", action="store_true", help="先停 Windows 侧栈（推荐）")
    ap.add_argument("--auditor-pw", default="auditor123")
    ap.add_argument("--admin-pw", default="admin123")
    args = ap.parse_args()

    if not args.yes:
        print("破坏性操作：将删除 backend/feizheng.db（全部本地案卷/请求/账户）。")
        print("确认请加 --yes（可加 --down 先停栈）。")
        return 1

    if args.down:
        print("[1/4] 停栈（demo_down——WSL 链/桥不动）…")
        subprocess.run([PY, str(UAS / "scripts" / "demo_down.py")], check=False)

    db = BACKEND / "feizheng.db"
    print(f"[2/4] 删除本地事务库 {db} …")
    for suffix in ("", "-wal", "-shm"):
        f = Path(str(db) + suffix)
        if f.is_file():
            f.unlink()
            print(f"  deleted {f.name}")

    print("[3/4] 重建表结构（alembic upgrade head）…")
    r = subprocess.run([PY, "-m", "alembic", "upgrade", "head"], cwd=BACKEND)
    if r.returncode != 0:
        print("[FAIL] 迁移失败")
        return 1

    print("[4/4] 播种机构账户（审计员/管理员）…")
    r = subprocess.run([
        PY, str(BACKEND / "scripts" / "seed_accounts.py"),
        "--auditor-pw", args.auditor_pw, "--admin-pw", args.admin_pw,
    ])
    if r.returncode != 0:
        print("[FAIL] 播种失败")
        return 1

    print("\n== 重置完成 ==")
    print("下一步：python scripts/demo_up.py 重启栈；")
    print(f"账户：auditor / {args.auditor_pw}，admin / {args.admin_pw}（首登激活）。")
    print("建议预飞：飞手注册→申请→飞行越围栏→审计立案→双控→结案 全动线一遍。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
