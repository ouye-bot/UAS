cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255)
hb = m.wait_heartbeat(timeout=40)
print("HB_OK")
t0 = time.time()
while time.time() - t0 < 25:
    m.mav.param_request_read_send(m.target_system, m.target_component, b"FENCE_ALT_MAX", -1)
    msg = m.recv_match(blocking=True, timeout=5)
    if msg is None:
        continue
    if msg.get_type() == "PARAM_VALUE":
        print("PARAM", msg.param_id.rstrip(chr(0)), "=", round(msg.param_value, 2))
        break
else:
    print("PARAM_TIMEOUT")
PYEOF
