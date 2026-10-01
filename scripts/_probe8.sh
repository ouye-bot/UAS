cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255, autoreconnect=True)
# 等待心跳并立即常驻消费
hb = m.wait_heartbeat(timeout=30)
print("HB_OK")
t0 = time.time()
got = False
while time.time() - t0 < 15 and not got:
    m.mav.param_request_read_send(m.target_system, m.target_component, b"FENCE_ALT_MAX", -1)
    msg = m.recv_match(blocking=True, timeout=3)
    if msg is None:
        continue
    if msg.get_type() == "PARAM_VALUE":
        pid = msg.param_id.rstrip(chr(0))
        print("PARAM", pid, "=", round(msg.param_value, 2))
        got = True
PYEOF
