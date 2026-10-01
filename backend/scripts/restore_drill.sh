#!/bin/bash
# P1-B2 恢复演练（由 scripts/backup_demo.py 调用——wsl.exe 多层传参损坏规避，㊽）。
# env：PGPASSWORD（fz 用户口令）+ DUMP_PATH（/mnt/c 形态的备份文件路径）。
set -e
export PGPASSWORD="$PGPASSWORD"
sudo -u postgres psql -qc 'DROP DATABASE IF EXISTS fz_restore;'
sudo -u postgres psql -qc 'CREATE DATABASE fz_restore OWNER fz;'
psql -h 127.0.0.1 -U fz -d fz_restore -q < "$DUMP_PATH"
for t in applications auth_records chain_events warrants; do
  echo "RST:$t:$(psql -h 127.0.0.1 -U fz -d fz_restore -tAc "SELECT count(1) FROM $t" | tr -d ' ')"
  echo "SRC:$t:$(psql -h 127.0.0.1 -U fz -d fz -tAc "SELECT count(1) FROM $t" | tr -d ' ')"
done
sudo -u postgres psql -qc 'DROP DATABASE IF EXISTS fz_restore;'
