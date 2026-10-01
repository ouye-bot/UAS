cd /home/ouye
setsid nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitlG.log 2>&1 < /dev/null &
sleep 6
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
m.wait_heartbeat(timeout=60)
# 🔴 强制真实目标（SITL 心跳首包可能来自 sysid0 占位——0 目标=模式切换被静默拒）
m.target_system = 1
m.target_component = 1
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
print("FENCE_SET", flush=True)
t0 = time.time()
while time.time()-t0 < 90:
    msg = m.recv_match(blocking=True, timeout=3)
    if msg and msg.get_type() == "GPS_RAW_INT" and msg.fix_type >= 3:
        print("GPS_LOCK", flush=True); break
mode_ok = False
for _ in range(4):
    m.mav.set_mode_send(1, 1, 15)
    t1 = time.time()
    while time.time()-t1 < 5:
        msg = m.recv_match(blocking=True, timeout=2)
        if msg and msg.get_type() == "HEARTBEAT" and msg.get_srcSystem() == 1:
            print("MODE_NOW", msg.custom_mode, flush=True)
            if msg.custom_mode == 15: mode_ok = True
    if mode_ok: break
print("GUIDED_OK" if mode_ok else "GUIDED_FAIL", flush=True)
if not mode_ok: raise SystemExit(2)
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
print("CLIMB_START", flush=True)
t0 = time.time(); max_alt = 0.0; breach = False
while time.time()-t0 < 25:
    m.mav.set_position_target_local_ned_send(
        0, 1, 1, 1, 0b0000111111111000, 0, 0, 0, 0, 0, -3.0, 0, 0, 0, 0, 0)
    msg = m.recv_match(blocking=True, timeout=0.3)
    if msg and msg.get_type() == "GLOBAL_POSITION_INT":
        max_alt = max(max_alt, msg.relative_alt/1000.0)
    if msg and msg.get_type() == "STATUSTEXT" and "ence" in msg.text:
        breach = True; print("BREACH:", msg.text, flush=True)
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
