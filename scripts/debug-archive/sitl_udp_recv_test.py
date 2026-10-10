# -*- coding: utf-8 -*-
"""裸 UDP 互通实验：WSL 侧收包器（Windows 侧由探测脚本发送）。"""
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 14551))
s.settimeout(20)
print("WSL RX BOUND 14551", flush=True)
got = 0
for i in range(5):
    try:
        d, a = s.recvfrom(256)
        got += 1
        print(f"WSL_GOT #{got} from {a}", flush=True)
    except Exception:
        print("WSL_TIMEOUT", flush=True)
        break
print(f"TOTAL={got}", flush=True)
