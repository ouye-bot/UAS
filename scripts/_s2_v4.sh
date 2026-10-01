cd /home/ouye
setsid nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitlE.log 2>&1 < /dev/null &
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
set_param("DISARM_DELAY", 0)
set_param("FENCE_ALT_MAX", 30); set_param("FENCE_ENABLE", 1); set_param("FENCE_TYPE", 3)
print("FENCE_SET_30m", flush=True)
t0 = time.time()
while time.time()-t0 < 90:
    msg = m.recv_match(blocking=True, timeout=3)
    if msg and msg.get_type() == "GPS_RAW_INT" and msg.fix_type >= 3:
        print("GPS_LOCK", flush=True); break
m.mav.set_mode_send(m.target_system, 1, 15)
time.sleep(1)
armed = False
for i in range(10):
    m.mav.command_long_send(m.target_system, m.target_component, 400, 0, 1, 0, 0, 0, 0, 0, 0)
    t1 = time.time()
    while time.time()-t1 < 10:
        msg = m.recv_match(blocking=True, timeout=2)
        if msg is None: continue
        if msg.get_type() == "COMMAND_ACK" and msg.command == 400:
            print("ARM_ACK", msg.result, flush=True)
            if msg.result == 0: armed = True
            break
        if msg.get_type() == "STATUSTEXT":
            print("STATUS:", msg.text, flush=True)
    if armed: break
    time.sleep(8)
if not armed:
    print("ARM_FAIL", flush=True); raise SystemExit(2)
# GUIDED 速度爬升：SET_POSITION_TARGET_LOCAL_NED vz=-3m/s 持续 25s（3m/s×25≈45m>30m 围栏）
print("CLIMB_START", flush=True)
t0 = time.time(); max_alt = 0.0; breach = False
while time.time()-t0 < 25:
    m.mav.set_position_target_local_ned_send(
        0, m.target_system, m.target_component, 1,  # FRAME_LOCAL_NED=1
        0b0000111111111000,  # 仅 vx/vy/vz 生效（type_mask）
        0, 0, 0, 0, 0, -3.0, 0, 0, 0, 0, 0)
    msg = m.recv_match(blocking=True, timeout=0.3)
    if msg and msg.get_type() == "GLOBAL_POSITION_INT":
        max_alt = max(max_alt, msg.relative_alt/1000.0)
    if msg and msg.get_type() == "STATUSTEXT" and "ence" in msg.text:
        breach = True
        print("BREACH:", msg.text, flush=True)
# 再观察 20s（围栏拦截行为：悬停/制动）
t1 = time.time()
while time.time()-t1 < 20:
    msg = m.recv_match(blocking=True, timeout=1)
    if msg and msg.get_type() == "GLOBAL_POSITION_INT":
        max_alt = max(max_alt, msg.relative_alt/1000.0)
    if msg and msg.get_type() == "STATUSTEXT" and "ence" in msg.text:
        breach = True
print(f"RESULT MAX_ALT={max_alt:.1f}m FENCE_BREACH={breach}", flush=True)
PYEOF
exit 0
