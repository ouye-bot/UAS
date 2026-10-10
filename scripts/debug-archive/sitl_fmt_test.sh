#!/usr/bin/env bash
# SERIAL0 设备串格式矩阵测试（WSL 侧执行）
systemctl stop fz-sitl 2>/dev/null; systemctl reset-failed 2>/dev/null
pkill -x arducopter 2>/dev/null; sleep 1
for fmt in udpbind:127.0.0.1:14550 udpin:127.0.0.1:14550 udp:127.0.0.1:14550 tcpbind:127.0.0.1:5760; do
  echo "=== format: $fmt ==="
  timeout 6 /home/ouye/ardupilot/build/sitl/bin/arducopter -w --model + --speedup 1 -I0 --serial0="$fmt" 2>&1 | grep -iE 'SERIAL0 on|PANIC|Invalid|bind port 14550|Waiting' | head -3
  pkill -x arducopter 2>/dev/null
  sleep 1
done
echo ALL_DONE
