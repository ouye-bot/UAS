cd /home/ouye
setsid nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitlI.log 2>&1 < /dev/null &
sleep 6
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
m.wait_heartbeat(timeout=60)
m.mav.request_data_stream_send(1, 1, 0, 10, 1)
def set_param(name, val):
    for _ in range(3):
        m.mav.param_set_send(1, 1, name.encode(), float(val), 2)
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
armed = False
for i in range(10):
    m.mav.command_long_send(1, 1, 400, 0, 1, 0, 0, 0, 0, 0, 0)
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
# RC Override：油门 ch3=1900（全推）持续爬升——真实飞手形态
print("CLIMB_RC_START", flush=True)
t0 = time.time(); max_alt = 0.0; breach = False
while time.time()-t0 < 40:
    m.mav.rc_channels_override_send(1, 1, 0, 0, 1900, 1500, 1500, 1500, 1500, 1500)
    msg = m.recv_match(blocking=True, timeout=0.2)
    if msg and msg.get_type() == "GLOBAL_POSITION_INT":
        max_alt = max(max_alt, msg.relative_alt/1000.0)
    if msg and msg.get_type() == "STATUSTEXT" and "ence" in msg.text:
        breach = True
        print("BREACH:", msg.text, flush=True)
print(f"after climb MAX_ALT={max_alt:.1f}m", flush=True)
# 悬停观察围栏拦截
for _ in range(100):
    m.mav.rc_channels_override_send(1, 1, 0, 0, 1500, 1500, 1500, 1500, 1500, 1500)
    msg = m.recv_match(blocking=True, timeout=0.2)
    if msg and msg.get_type() == "GLOBAL_POSITION_INT":
        max_alt = max(max_alt, msg.relative_alt/1000.0)
    if msg and msg.get_type() == "STATUSTEXT" and "ence" in msg.text:
        breach = True
        print("BREACH:", msg.text, flush=True)
# 收尾：停止 override+落地
m.mav.rc_channels_override_send(1, 1, 0, 0, 0, 0, 0, 0, 0, 0)
print(f"RESULT MAX_ALT={max_alt:.1f}m FENCE_BREACH={breach}", flush=True)
raise SystemExit(0 if breach else 3)
PYEOF
exit 0
