# -*- coding: utf-8 -*-
"""裸 UDP 互通实验（驱动）：Windows 发 5 包到 127.0.0.1:14551（WSL 收）。"""
import os
import socket
import subprocess
import time

UAS_WSL = os.environ.get("FZ_UAS_WSL", "/mnt/c/uas")  # 部署路径（env 可覆盖）

rx = subprocess.Popen(
    ["wsl", "bash", "-c",
     "timeout 30 python3 {UAS_WSL}/scripts/sitl_udp_recv_test.py"],
    stdout=subprocess.PIPE, text=True,
)
time.sleep(4)

tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(5):
    tx.sendto(bytes([1, 2, 3]), ("127.0.0.1", 14551))
    time.sleep(0.4)
tx.close()
print("TX: 5 datagrams sent to 127.0.0.1:14551")
out, _ = rx.communicate(timeout=35)
