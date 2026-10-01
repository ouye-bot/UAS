cd /home/ouye
setsid nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitlB.log 2>&1 < /dev/null &
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
set_param("FENCE_ALT_MAX", 30); set_param("FENCE_ENABLE", 1); set_param("FENCE_TYPE", 3)
print("FENCE_SET", flush=True)
t0 = time.time()
while time.time()-t0 < 100:
    msg = m.recv_match(blocking=True, timeout=3)
    if msg and msg.get_type() == "GPS_RAW_INT" and msg.fix_type >= 3:
        print("GPS_LOCK", flush=True); break
armed = False
for i in range(8):
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
time.sleep(2)
m.mav.set_mode_send(m.target_system, 1, 15)
m.mav.command_long_send(m.target_system, m.target_component, 22, 0, 0, 0, 0, 0, 0, 0, 45.0)
t0 = time.time(); max_alt = 0.0; breach_seen = False
while time.time()-t0 < 75:
    msg = m.recv_match(blocking=True, timeout=2)
    if msg is None: continue
    t = msg.get_type()
    if t == "GLOBAL_POSITION_INT":
        max_alt = max(max_alt, msg.relative_alt/1000.0)
    elif t == "STATUSTEXT" and "ence" in msg.text:
        print("STATUS:", msg.text, flush=True); breach_seen = True
print(f"MAX_ALT={max_alt:.1f}m BREACH_TEXT={breach_seen}", flush=True)
PYEOF
exit 0
