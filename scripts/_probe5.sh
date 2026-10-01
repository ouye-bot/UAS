cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
# SERIAL0 = TCP 5760（主接口）——改走 TCP
m = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255)
m.wait_heartbeat(timeout=20)
print("HB_TCP_OK")
m.mav.param_request_read_send(m.target_system, m.target_component, b"FENCE_ALT_MAX", -1)
msg = m.recv_match(type="PARAM_VALUE", blocking=True, timeout=6)
print("PARAM", msg.param_id.rstrip(chr(0)) if msg else "TIMEOUT", "=", round(msg.param_value,2) if msg else "")
PYEOF
