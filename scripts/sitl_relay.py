# -*- coding: utf-8 -*-
"""SITL MAVLink 中继（WSL 侧运行，systemd 单元 fz-relay）——S2 真接线的连接层。

为什么需要（2026-09-22 实测定谳）：ArduPilot SERIAL0 TCP 每进程只接受一次连接
（烧掉即永拒），且 WSL mirrored 网络下 Windows→WSL 的 TCP accept 即 EOF——
Windows 桥接无法直连。B5 实证 WSL 内部 TCP 可靠 ⟹ 本中继独占 SERIAL0 TCP，
双向转发到 Windows 侧 UDP（mirrored 下 WSL→host 127.0.0.1 UDP 为经典路径）。

自愈语义：SITL 侧 TCP 断/卡（EOF）⟹ 断开重连（SITL 单元若重启则新监听也可接）；
UDP 侧无连接不粘会话。外层 systemd Restart=on-failure 兜底。

用法：python3 sitl_relay.py [tcp_conn] [udp_out]
默认：tcp:127.0.0.1:5760 → udpout:127.0.0.1:14550
"""
import sys
import time

from pymavlink import mavutil

TCP_CONN = sys.argv[1] if len(sys.argv) > 1 else "tcp:127.0.0.1:5760"
DOWN_OUT = sys.argv[2] if len(sys.argv) > 2 else "udpout:127.0.0.1:14550"
UP_BIND = sys.argv[3] if len(sys.argv) > 3 else "udpin:0.0.0.0:14551"


def log(msg: str) -> None:
    print(f"RELAY: {msg}", flush=True)


def connect_tcp():
    tcp = None
    for attempt in range(60):
        try:
            tcp = mavutil.mavlink_connection(TCP_CONN, source_system=255)
            if tcp.wait_heartbeat(timeout=30):
                log("SITL 心跳锁定")
                return tcp
            tcp.close()
        except Exception:
            if tcp is not None:
                try:
                    tcp.close()
                except Exception:
                    pass
        log(f"等待 SITL（{attempt + 1}/60）")
        time.sleep(2)
    raise RuntimeError("SITL 连接失败")


def main() -> None:
    # 单 UDP socket 双向复用（v4 定谳）：connected udpout 的下行虽然可达，但桥接
    # 学到的回程地址=下行临时端口，回包又被 connected 过滤丢弃（上行计数 0 实锤）
    # ⟹ 无连接 bind socket 收发一体；桥接侧显式置 destination_addr=本端口。
    udp = mavutil.mavlink_connection(UP_BIND, source_system=255)
    try:
        udp.port.settimeout(0.002)
    except Exception:
        pass
    # 显式播种下行地址（打破"桥等心跳/中继等来包"的死锁——桥端口=14550 固定）
    udp.destination_addr = ("127.0.0.1", 14550)
    while True:  # 外层自愈：SITL 断链即重连
        tcp = connect_tcp()
        tcp_last = time.time()
        n_fwd = 0
        n_up = 0
        try:
            while True:
                try:
                    m = tcp.recv_msg()
                except (TimeoutError, OSError):
                    m = None
                if m is not None:
                    try:
                        udp.mav.send(m)
                        n_fwd += 1
                    except Exception:
                        pass
                    if m.get_type() == "HEARTBEAT":
                        tcp_last = time.time()
                try:
                    m = udp.recv_msg()
                except (TimeoutError, OSError):
                    m = None
                if m is not None:
                    n_up += 1
                    try:
                        tcp.mav.send(m)
                    except Exception:
                        pass
                if n_up and n_up % 10 == 0:
                    log(f"上行累计 {n_up}")
                # SITL 心跳丢 8s ⟹ 视为断链，重连（SITL 单元可能已重启换监听）
                if time.time() - tcp_last > 8:
                    raise RuntimeError("SITL 心跳丢失（>8s）——重连")
                if n_fwd and n_fwd % 5000 == 0:
                    log(f"下行转发 {n_fwd} 上行 {n_up}")
                if n_up and n_up % 20 == 0:
                    log(f"上行累计 {n_up}")
                time.sleep(0.001)
        except Exception as e:
            log(f"链路异常自愈: {type(e).__name__}: {e}")
            try:
                tcp.close()
            except Exception:
                pass
            time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"致命退出: {e}")
        sys.exit(3)
