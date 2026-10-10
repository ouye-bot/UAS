cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255, input=False)
m.wait_heartbeat(timeout=25)
print("HB_OK sys=", m.target_system)
for _ in range(3):
    m.mav.param_request_read_send(m.target_system, m.target_component, b"FENCE_ALT_MAX", -1)
    msg = m.recv_match(type="PARAM_VALUE", blocking=True, timeout=5)
    if msg is not None:
        print("PARAM", msg.param_id.rstrip(chr(0)), "=", round(msg.param_value, 2))
        break
    time.sleep(0.5)
else:
    print("STILL_TIMEOUT")
PYEOF
