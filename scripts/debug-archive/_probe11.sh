cd /home/ouye
python3 - << "PYEOF" &
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255)
m.wait_heartbeat(timeout=60)
print("HB_OK", flush=True)
t0 = time.time()
while time.time()-t0 < 30:
    m.mav.param_request_read_send(m.target_system, m.target_component, b"FENCE_ALT_MAX", -1)
    msg = m.recv_match(blocking=True, timeout=5)
    if msg and msg.get_type() == "PARAM_VALUE":
        print("PARAM", msg.param_id.rstrip(chr(0)), round(msg.param_value, 2), flush=True)
        break
PYEOF
BGPID=$!
sleep 32
cat /tmp/probe_out.txt 2>/dev/null
wait $BGPID
exit 0
