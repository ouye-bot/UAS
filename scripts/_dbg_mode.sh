cd /home/ouye
setsid nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitlH.log 2>&1 < /dev/null &
sleep 6
python3 - << "PYEOF"
import time
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5770", source_system=255, source_component=191)
for i in range(5):
    msg = m.recv_match(type="HEARTBEAT", blocking=True, timeout=6)
    if msg:
        print("HB src=", msg.get_srcSystem(), "comp=", msg.get_srcComponent(), "custom=", msg.custom_mode, "autopilot=", msg.autopilot, flush=True)
# 关键修正：用心跳真实源作为目标
m.target_system = msg.get_srcSystem()
m.target_component = msg.get_srcComponent()
print("TARGET", m.target_system, m.target_component, flush=True)
m.mav.set_mode_send(m.target_system, m.target_component, 1, 15)
t1 = time.time()
while time.time()-t1 < 6:
    msg = m.recv_match(type="HEARTBEAT", blocking=True, timeout=2)
    if msg and msg.custom_mode == 15:
        print("GUIDED_OK", flush=True)
        break
PYEOF
exit 0
