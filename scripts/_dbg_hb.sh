cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
for i in range(5):
    msg = m.recv_match(type="HEARTBEAT", blocking=True, timeout=5)
    if msg:
        print("HB src=", msg.get_srcSystem(), "comp=", msg.get_srcComponent(), "custom=", msg.custom_mode, "type=", msg.type, "autopilot=", msg.autopilot)
PYEOF
exit 0
