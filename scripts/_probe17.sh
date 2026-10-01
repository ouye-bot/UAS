cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
m.wait_heartbeat(timeout=30)
m.mav.request_data_stream_send(m.target_system, m.target_component, 0, 10, 1)
# 先解围栏 ARM（对照实验：确认非围栏因素）
def set_param(name, val):
    for _ in range(3):
        m.mav.param_set_send(m.target_system, m.target_component, name.encode(), float(val), 2)
        t0 = time.time()
        while time.time()-t0 < 4:
            msg = m.recv_match(blocking=True, timeout=1)
            if msg and msg.get_type() == "PARAM_VALUE" and msg.param_id.rstrip(chr(0)) == name:
                return msg.param_value
    return None
set_param("FENCE_ENABLE", 0)
for i in range(6):
    m.mav.command_long_send(m.target_system, m.target_component, 400, 0, 1, 0, 0, 0, 0, 0, 0)
    t1 = time.time()
    while time.time()-t1 < 8:
        msg = m.recv_match(blocking=True, timeout=2)
        if msg and msg.get_type() == "COMMAND_ACK" and msg.command == 400:
            print("NOFENCE_ARM_ACK", msg.result, flush=True)
            if msg.result == 0: raise SystemExit
            break
        if msg and msg.get_type() == "STATUSTEXT":
            print("STATUS:", msg.text, flush=True)
    time.sleep(6)
PYEOF
exit 0
