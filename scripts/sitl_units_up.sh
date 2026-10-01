# 本机部署路径（.local_env 不入库——模板见 .local_env.example）
_l="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.local_env"
[ -f "$_l" ] && . "$_l"
UAS_WSL="${FZ_UAS_WSL:-/mnt/c/uas}"
#!/usr/bin/env bash
# SITL + 中继 systemd 单元拉起（幂等——先杀净再起）
set -x
systemctl stop fz-sitl fz-relay 2>/dev/null
systemctl reset-failed fz-sitl fz-relay 2>/dev/null
pkill -9 -x arducopter 2>/dev/null
pkill -9 -f fz_relay.py 2>/dev/null
sleep 2
echo "残留检查: arducopter=$(pgrep -cx arducopter) relay=$(pgrep -cf fz_relay.py)"
cp '${UAS_WSL}/scripts/sitl_relay.py' /root/fz_relay.py
systemd-run --unit=fz-sitl --working-directory=/root /home/ouye/ardupilot/build/sitl/bin/arducopter --model + --speedup 1 -I0
systemd-run --unit=fz-relay /usr/bin/python3 /root/fz_relay.py
sleep 12
echo "fz-sitl: $(systemctl is-active fz-sitl)"
echo "fz-relay: $(systemctl is-active fz-relay)"
journalctl -u fz-relay --no-pager -n 4 | grep RELAY | tail -2
echo SCRIPT_DONE
