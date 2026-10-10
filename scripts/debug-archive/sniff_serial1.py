"""SERIAL1 对照实验：嗅探器自身发 SET_MODE(ALT_HOLD)——分离 FC 拒绝 vs 桥发送路径问题。"""
import time
from pymavlink import mavutil

m = mavutil.mavlink_connection("tcp:127.0.0.1:5762", source_system=250)
m.wait_heartbeat(timeout=15)
print("sniff: heartbeat ok, mode=", m.flightmode, flush=True)
t0 = time.time()
sent = False
while time.time() - t0 < 30:
    msg = m.recv_match(blocking=True, timeout=1)
    if msg is not None:
        mt = msg.get_type()
        if mt == "HEARTBEAT":
            print(f'{time.time()-t0:.1f}s HB mode={m.flightmode} armed={bool(msg.base_mode & 0x80)}', flush=True)
        elif mt == "STATUSTEXT":
            print(f'{time.time()-t0:.1f}s STATUSTEXT: {msg.text}', flush=True)
        elif mt == "COMMAND_ACK":
            print(f'{time.time()-t0:.1f}s ACK cmd={msg.command} result={msg.result}', flush=True)
    if not sent and time.time() - t0 > 3:
        m.mav.set_mode_send(1, 1, 1, 2)  # ALT_HOLD
        print("sniff: >>> sent SET_MODE ALT_HOLD (base=1 custom=2)", flush=True)
        sent = True
