#!/usr/bin/env bash
# 对 systemd 单元的健康测试：WSL 内部客户端 + 流请求 + GPS 计数
systemctl stop fz-sitl fz-relay 2>/dev/null; systemctl reset-failed 2>/dev/null
pkill -9 -x arducopter 2>/dev/null; pkill -9 -f fz_relay.py 2>/dev/null; sleep 1
systemd-run --unit=fz-sitl --working-directory=/root /home/ouye/ardupilot/build/sitl/bin/arducopter --model + --speedup 1 -I0
systemd-run --unit=fz-relay /usr/bin/python3 /root/fz_relay.py
sleep 3
python3 << 'PYEOF'
from pymavlink import mavutil
import time
from collections import Counter

m = mavutil.mavlink_connection('tcp:127.0.0.1:5760', source_system=255)
print('CLIENT: hb =', m.wait_heartbeat(timeout=30) is not None, flush=True)
m.mav.request_data_stream_send(m.target_system, m.target_component, 0, 10, 1)
c = Counter()
t0 = time.time()
fix = None
while time.time() - t0 < 90:
    try:
        x = m.recv_msg()
    except Exception as e:
        print('CLIENT: recv exc', type(e).__name__, flush=True)
        break
    if x is None:
        continue
    c[x.get_type()] += 1
    if x.get_type() == 'GPS_RAW_INT':
        fix = x.fix_type
print('CLIENT: count90s =', sum(c.values()), dict(c.most_common(6)), 'gps_fix =', fix, flush=True)
PYEOF
echo "SITL_STATE: $(systemctl is-active fz-sitl)"
systemctl stop fz-sitl fz-relay 2>/dev/null
echo ALL_DONE
