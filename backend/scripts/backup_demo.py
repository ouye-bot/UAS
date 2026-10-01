"""演示环境备份与恢复演练（P1-B2）。

- backup：WSL 内 pg_dump fz 库 → uas/backups/（gitignored）+ 判决件目录快照
- --restore-drill：最新备份恢复到 fz_restore 库→行数对账（applications/
  auth_records/chain_events）→对账通过即清理演练库——"没演练过的不叫备份"

用法：cd uas/backend && python scripts/backup_demo.py [--restore-drill]
退出码：0=成功；1=任何失败。
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
BACKUP_DIR = UAS / "backups"
CASES = UAS / "backend" / "fz-zk-cases"
PG_PW_FILE = (
    Path(__file__).resolve().parents[1]
    / "certs"
    / ".."
    / ".."
    / ".."
    / (
        # 占位——实际口令文件路径由调用方 env 提供（不入库）
        "backups"
    )
)


def wsl(cmd: str) -> str:
    r = subprocess.run(["wsl", "-u", "root", "bash", "-c", cmd], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[FAIL] wsl: {cmd}\n{r.stdout}{r.stderr}")
        raise SystemExit(1)
    return (r.stdout + r.stderr).strip()


def _pw() -> str:
    import os

    pw_file = os.environ.get("FZ_PG_PW_FILE")
    if not pw_file or not Path(pw_file).exists():
        print("[FAIL] FZ_PG_PW_FILE 未设置或不存在（口令文件不入库）")
        raise SystemExit(1)
    return Path(pw_file).read_text().strip()


def _wsl_path(p: Path) -> str:
    """Windows 路径→WSL /mnt/c 形态（C:/Users/... → /mnt/c/Users/...）。"""
    posix = str(p).replace("\\", "/")
    if posix[1:3] == ":/":
        return "/mnt/" + posix[0].lower() + posix[2:]
    return posix


def backup() -> Path:
    pw = _pw()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dump = BACKUP_DIR / f"fz_{stamp}.sql"
    wsl(f"PGPASSWORD='{pw}' pg_dump -h 127.0.0.1 -U fz -d fz > '{_wsl_path(dump)}'")
    if dump.stat().st_size < 1000:
        print(f"[FAIL] 备份过小: {dump.stat().st_size}B")
        raise SystemExit(1)
    print(f"[backup] 库备份 {dump.name} ({dump.stat().st_size:,}B)")
    # 判决件快照（法律证据级材料——与库备份同频）
    if CASES.exists():
        snap = BACKUP_DIR / f"verdicts_{stamp}"
        subprocess.run(
            ["robocopy", str(CASES / "verdicts"), str(snap), "/E", "/NFL", "/NDL"],
            capture_output=True,
        )
        print(f"[backup] 判决件快照 {snap.name}")
    return dump


def restore_drill(dump: Path) -> int:
    """恢复演练（脚本文件化 restore_drill.sh——㊽ wsl.exe 多层传参损坏规避）。"""
    pw = _pw()
    inner = UAS / "backend" / "scripts" / "restore_drill.sh"
    env_pre = f"export PGPASSWORD='{pw}'; export DUMP_PATH='{_wsl_path(dump)}';"
    out = wsl(f"{env_pre} bash {_wsl_path(inner)}")
    rst, src = {}, {}
    for line in out.splitlines():
        for tag, bucket in (("RST:", rst), ("SRC:", src)):
            if line.startswith(tag):
                _, t, v = line.split(":", 2)
                bucket[t] = v
    ok = rst == src and rst != {}
    print(f"[drill] 行数对账（源={src} 恢复={rst}）→ {'一致' if ok else '不一致'}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--restore-drill", action="store_true")
    args = ap.parse_args()
    dump = backup()
    if args.restore_drill:
        return restore_drill(dump)
    return 0


if __name__ == "__main__":
    sys.exit(main())
