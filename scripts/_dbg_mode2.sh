cd /home/ouye
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
m.wait_heartbeat(timeout=30)
print("MODE_BEFORE", [h.custom_mode for h in [m.recv_match(type="HEARTBEAT", blocking=True, timeout=2)]], flush=True)
# 连发 SET_MODE×3（无 ACK 的消息——用重复+心跳验证）
for _ in range(5):
    m.mav.set_mode_send(1, 1, 1, 15)
    time.sleep(0.4)
t0 = time.time()
ok = False
while time.time()-t0 < 8:
    msg = m.recv_match(type="HEARTBEAT", blocking=True, timeout=2)
    if msg:
        print("MODE", msg.custom_mode, flush=True)
        if msg.custom_mode == 15:
            ok = True
            break
print("GUIDED_OK" if ok else "GUIDED_FAIL", flush=True)
PYEOF
exit 0
