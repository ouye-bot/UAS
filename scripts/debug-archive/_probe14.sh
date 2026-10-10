cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
m.wait_heartbeat(timeout=60)
# 读 RC 输入与 EKF 状态
m.mav.request_data_stream_send(m.target_system, m.target_component, 0, 10, 1)
t0 = time.time()
while time.time()-t0 < 15:
    msg = m.recv_match(blocking=True, timeout=2)
    if msg is None: continue
    t = msg.get_type()
    if t == "STATUSTEXT":
        print("STATUS:", msg.text, flush=True)
    elif t == "SYS_STATUS":
        print("ARMING:", hex(msg.onboard_control_sensors_health), flush=True)
    elif t == "HEARTBEAT" and msg.type != 0:
        print("MODE:", msg.custom_mode, "ARMED:", msg.base_mode & 128, flush=True)
PYEOF
exit 0
