cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("udpout:127.0.0.1:14551", source_system=255)
m.wait_heartbeat(timeout=20)
# param fetch 用 request + 消费全部消息流
m.mav.param_request_read_send(m.target_system, m.target_component, b"FENCE_ALT_MAX", -1)
t0 = time.time()
while time.time() - t0 < 8:
    msg = m.recv_match(blocking=True, timeout=2)
    if msg is None:
        continue
    t = msg.get_type()
    if t == "PARAM_VALUE":
        print("GOT", msg.param_id.rstrip(chr(0)), "=", round(msg.param_value, 2))
        break
else:
    print("NO_PARAM_MSG")
PYEOF
