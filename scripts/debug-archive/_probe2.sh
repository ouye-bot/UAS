cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("udpout:127.0.0.1:14551", source_system=255)
m.wait_heartbeat(timeout=20)
print("HB on 14551 OK")
for p in ("FENCE_ENABLE", "FENCE_ALT_MAX"):
    m.mav.param_request_read_send(m.target_system, m.target_component, p.encode(), -1)
    msg = m.recv_match(type="PARAM_VALUE", blocking=True, timeout=6)
    if msg is not None:
        print("PARAM", msg.param_id.rstrip(chr(0)), "=", round(msg.param_value, 2))
    else:
        print("PARAM", p, "TIMEOUT")
PYEOF
