cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("udpout:127.0.0.1:14551", source_system=255)
m.wait_heartbeat(timeout=20)
m.mav.param_request_list_send(m.target_system, m.target_component)
count = 0
t0 = time.time()
while time.time() - t0 < 10 and count < 3:
    msg = m.recv_match(type="PARAM_VALUE", blocking=True, timeout=3)
    if msg is None:
        break
    pid = msg.param_id.rstrip(chr(0))
    if pid.startswith("FENCE"):
        print("FENCE_PARAM", pid, "=", round(msg.param_value, 2))
        count += 1
print("LIST_DONE")
PYEOF
