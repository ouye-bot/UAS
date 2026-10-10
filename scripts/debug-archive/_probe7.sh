cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255)
m.wait_heartbeat(timeout=25)
print("HB_OK")
for attempt in range(4):
    m.mav.param_request_read_send(m.target_system, m.target_component, b"FENCE_ALT_MAX", -1)
    t0 = time.time()
    while time.time() - t0 < 5:
        msg = m.recv_match(blocking=True, timeout=2)
        if msg is None:
            break
        if msg.get_type() == "PARAM_VALUE" and "FENCE" in msg.param_id:
            print("PARAM", msg.param_id.rstrip(chr(0)), "=", round(msg.param_value, 2))
            attempt = 99
            break
    if attempt == 99:
        break
PYEOF
