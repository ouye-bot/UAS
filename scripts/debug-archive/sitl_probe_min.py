# -*- coding: utf-8 -*-
"""MAVLink 通路最小实验：起单元→Windows udpin 收 60s→按类型计数。"""
import subprocess
import time
from collections import Counter

import socket
import struct

from pymavlink import mavutil


def wsl_root(cmd):
    return subprocess.run(["wsl", "-u", "root", "bash", "-c", cmd],
                          capture_output=True, text=True).stdout


wsl_root("systemctl stop fz-sitl fz-relay 2>/dev/null; systemctl reset-failed 2>/dev/null; pkill -x arducopter 2>/dev/null; true")
wsl_root("systemd-run --unit=fz-sitl --working-directory=/root "
         "/home/ouye/ardupilot/build/sitl/bin/arducopter -w --model + --speedup 1 -I0")
wsl_root("systemd-run --unit=fz-relay /usr/bin/python3 /root/fz_relay.py")
time.sleep(8)

m = mavutil.mavlink_connection("udpin:127.0.0.1:14550", source_system=255)
SIO_UDP_CONNRESET = getattr(socket, "SIO_UDP_CONNRESET", -1744830452)
try:
    m.port.ioctl(SIO_UDP_CONNRESET, struct.pack("I", 0))
except Exception as e:
    print("ioctl:", e)
hb = m.wait_heartbeat(timeout=45)
print("bridge hb:", hb is not None)
m.mav.request_data_stream_send(m.target_system, m.target_component, 0, 10, 1)
counts = Counter()
t0 = time.time()
gps_fix = None
while time.time() - t0 < 60:
    try:
        msg = m.recv_msg()
    except Exception as e:
        print("recv exc:", type(e).__name__)
        continue
    if msg is None:
        continue
    counts[msg.get_type()] += 1
    if msg.get_type() == "GPS_RAW_INT":
        gps_fix = msg.fix_type
print("types:", dict(counts.most_common(12)))
print("gps_fix_last:", gps_fix)
wsl_root("systemctl stop fz-sitl fz-relay 2>/dev/null; true")
