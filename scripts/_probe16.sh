cd /home/ouye
nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitl8.log 2>&1 < /dev/null &
sleep 6
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
m.wait_heartbeat(timeout=60)
m.mav.request_data_stream_send(m.target_system, m.target_component, 0, 10, 1)

def set_param(name, val):
    for _ in range(3):
        m.mav.param_set_send(m.target_system, m.target_component, name.encode(), float(val), 2)
        t0 = time.time()
        while time.time()-t0 < 4:
            msg = m.recv_match(blocking=True, timeout=1)
            if msg and msg.get_type() == "PARAM_VALUE" and msg.param_id.rstrip(chr(0)) == name:
                return msg.param_value
    return None

set_param("FENCE_ALT_MAX", 30)
set_param("FENCE_ENABLE", 1)
set_param("FENCE_TYPE", 3)
set_param("DISARM_DELAY", 0)
print("FENCE_SET(30m)", flush=True)

t0 = time.time()
while time.time()-t0 < 120:
    msg = m.recv_match(blocking=True, timeout=3)
    if msg and msg.get_type() == "GPS_RAW_INT" and msg.fix_type >= 3:
        print("GPS_LOCK", flush=True)
        break

# 等 EKF GPS 消费
for i in range(4):
    m.mav.command_long_send(m.target_system, m.target_component, 400, 0, 1, 0, 0, 0, 0, 0, 0)
    t1 = time.time()
    armed = False
    while time.time()-t1 < 10:
        msg = m.recv_match(blocking=True, timeout=2)
        if msg and msg.get_type() == "COMMAND_ACK" and msg.command == 400:
            if msg.result == 0:
                armed = True
            break
        if msg and msg.get_type() == "STATUSTEXT" and "EKF" in msg.text and "GPS" in msg.text:
            break
    if armed:
        print("ARMED", flush=True)
        break
    time.sleep(8)
if not armed:
    print("ARM_FAIL", flush=True)
    raise SystemExit(2)

# 起飞到 45m（越 30m 围栏）——GUIDED 起飞
m.mav.set_mode_send(m.target_system, 1, 15)  # GUIDED=15
m.mav.command_long_send(m.target_system, m.target_component, 22, 0, 0, 0, 0, 0, 0, 0, 45.0)  # MAV_CMD_NAV_TAKEOFF=22
t0 = time.time()
breached = False
max_alt = 0
while time.time()-t0 < 90:
    msg = m.recv_match(blocking=True, timeout=2)
    if msg is None: continue
    t = msg.get_type()
    if t == "GLOBAL_POSITION_INT":
        alt_mm = msg.relative_alt
        max_alt = max(max_alt, alt_mm/1000.0)
        if alt_mm > 40000 and not breached:
            print(f"BREACH_ZONE alt={alt_mm/1000.0:.1f}m", flush=True)
    elif t == "STATUSTEXT" and ("Fence" in msg.text or "fence" in msg.text or "EKF" in msg.text):
        print("STATUS:", msg.text, flush=True)
        breached = True
    elif t == "COMMAND_ACK" and msg.command == 22:
        print("TAKEOFF_ACK", msg.result, flush=True)
print(f"MAX_ALT={max_alt:.1f}m (fence=30m)", flush=True)
PYEOF
exit 0
