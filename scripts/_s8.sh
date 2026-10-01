cd /home/ouye
nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitl4.log 2>&1 < /dev/null &
sleep 6
cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255)
hb = m.wait_heartbeat(timeout=60)
print("HB_OK", flush=True)
t0 = time.time()
while time.time()-t0 < 30:
    m.mav.param_request_read_send(m.target_system, m.target_component, b"FENCE_ALT_MAX", -1)
    msg = m.recv_match(blocking=True, timeout=5)
    if msg and msg.get_type() == "PARAM_VALUE":
        print("PARAM", msg.param_id.rstrip(chr(0)), round(msg.param_value,2), flush=True)
        break
PYEOF
exit 0
