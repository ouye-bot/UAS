cd /home/ouye
nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitl5.log 2>&1 < /dev/null &
sleep 6
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255)
m.wait_heartbeat(timeout=60)
print("HB_OK", flush=True)

def set_param(name, val):
    m.mav.param_set_send(m.target_system, m.target_component, name.encode(), val, 2)  # 2=REAL32? MAV_PARAM_TYPE_REAL32=2
    t0 = time.time()
    while time.time()-t0 < 6:
        msg = m.recv_match(blocking=True, timeout=2)
        if msg and msg.get_type() == "PARAM_VALUE" and msg.param_id.rstrip(chr(0)) == name:
            return msg.param_value
    return None

v = set_param("FENCE_ALT_MAX", 30.0)
print("SET FENCE_ALT_MAX ->", v, flush=True)
v2 = set_param("FENCE_ENABLE", 1.0)
print("SET FENCE_ENABLE ->", v2, flush=True)
# 解锁
m.mav.command_long_send(m.target_system, m.target_component,
    400, 0, 1, 0, 0, 0, 0, 0, 0)  # MAV_CMD_COMPONENT_ARM_DISARM=400
t0 = time.time()
while time.time()-t0 < 10:
    msg = m.recv_match(blocking=True, timeout=3)
    if msg and msg.get_type() == "COMMAND_ACK" and msg.command == 400:
        print("ARM_ACK result=", msg.result, flush=True)
        break
PYEOF
exit 0
