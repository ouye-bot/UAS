cd /home/ouye
nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitl6.log 2>&1 < /dev/null &
sleep 6
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
m.wait_heartbeat(timeout=60)
print("HB_OK", flush=True)

# 请求数据流（30Hz 关键流）
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

print("FENCE_ALT_MAX ->", set_param("FENCE_ALT_MAX", 30), flush=True)
print("FENCE_ENABLE ->", set_param("FENCE_ENABLE", 1), flush=True)
print("FENCE_TYPE ->", set_param("FENCE_TYPE", 3), flush=True)

# 等 GPS 锁
t0 = time.time()
fix = 0
while time.time()-t0 < 90:
    msg = m.recv_match(blocking=True, timeout=3)
    if msg and msg.get_type() == "GPS_RAW_INT":
        fix = msg.fix_type
        if fix >= 3:
            print("GPS_LOCK fix=", fix, flush=True)
            break
    if msg and msg.get_type() == "HEARTBEAT" and msg.type == 0:
        pass
print("GPS final fix=", fix, flush=True)

# 解锁
m.mav.command_long_send(m.target_system, m.target_component, 400, 0, 1, 0, 0, 0, 0, 0, 0)
t0 = time.time()
while time.time()-t0 < 12:
    msg = m.recv_match(blocking=True, timeout=3)
    if msg and msg.get_type() == "COMMAND_ACK" and msg.command == 400:
        print("ARM_ACK result=", msg.result, "(0=OK)", flush=True)
        break
PYEOF
exit 0
