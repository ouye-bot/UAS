"""飞行闸门+围栏接线（B5-T3 立基；S2 真接线 2026-09-22 按 B5 实测配方升级）。

连接层抽象（SITLLink）：真实面=MAVLink（WSL ArduPilot SITL；默认
udpin:127.0.0.1:14550=scripts/sitl_relay.py 在 WSL 侧独占 SERIAL0 TCP 并双向转发
UDP——SITL TCP 每进程仅接受一次连接且 nohup 后台不过 wsl 会话界（实测 2026-09-22），
故由拉起方全程持有 relay；B5 配方不变：PARAM_SET 须等 PARAM_VALUE 确认（3 重试×4s）、
ARM 须核 COMMAND_ACK、起飞前位置流 request_data_stream(10Hz)、围栏触发=
STATUSTEXT "Max Alt fence breached"、爬升=RC Override 绕开 SET_MODE 拒绝（B5-d3：
真实飞手形态））。测试面=FakeLink（指令记录器——闸门逻辑可无飞控单测）。

闸门语义（TCB 第①层声明：用户理论可绕——固件围栏=第②层硬强制）：
  验签过 → 设围栏（FENCE_ENABLE=1/FENCE_ALT_MAX=alt_max/FENCE_TYPE=高度围栏）
         → 记录 ARM 审计行（A7）→ 发 ARM
  任何拒绝 → 拒绝+审计行（不触围栏不 ARM）

单会话纪律（B5 实测）：SITL 生命周期=启动方全程持有的一个 wsl.exe 进程；
Windows 侧桥接经 localhost TCP 连接（WSL mirrored 网络）。
"""

from __future__ import annotations

import os
import socket
import threading
import time

from telemetry import LocalAudit, TokenError, verify_token

FENCE_BREACH_TEXT = "Max Alt fence breached"


class LinkError(RuntimeError):
    """飞控链路面错误（连接/确认超时/ARM 拒绝——判决面可读回传）。"""


class SITLLink:
    """MAVLink 真实连接（B5 配方：TCP SERIAL0+确认环）。"""

    def __init__(self, conn_str: str | None = None) -> None:
        self.conn_str = conn_str or os.environ.get("FZ_SITL_CONN", "tcp:127.0.0.1:5760")
        self._m = None
        self._lock = threading.Lock()
        self._hb_thread: threading.Thread | None = None
        self.last_statustext: str | None = None
        self.last_attitude: dict | None = None  # ③GCS 化姿态旁路（UI 面）
        self.last_mode: str | None = None  # ③GCS 化飞控模式旁路（UI 面）
        # 飞控侧上锁位旁路（2026-09-27 队长实测四：HEARTBEAT 此前只取 mode 丢
        # armed 位——飞控「地面怠速自动上锁」后桥全盲，爬升 override 静默无效）
        self.last_fc_armed: bool | None = None
        self.last_gpos: dict | None = None  # GLOBAL_POSITION_INT 缓存（drain 刷新）
        # P3 操控架构修正（2026-09-29 实测定谳）：RC override 停止刷新后飞控
        # 回退到模拟 RC——定高模式下表现为恒速下降（1~1.5m/s 直到落地）。
        # 真实 GCS=持续流式刷新 RC。本桥改为 override 状态+10Hz keepalive：
        # rc_throttle_override 设置 _override_val，keepalive 线程持续发送；
        # rc_release/_disarm 置 None 停发（电机已停，无飞行语义）。
        self._override_val: int | None = None
        self._ovr_thread: threading.Thread | None = None
        # P3 遥测真实感：电池/GPS/HUD 缓存（drain 统一分类——MAVLink 现成字段）
        self.last_bat: dict | None = None    # BATTERY_STATUS
        self.last_gps: dict | None = None    # GPS_RAW_INT
        self.last_hud: dict | None = None    # VFR_HUD
        # COMMAND_ACK 捕获（2026-09-28 队长实测：set_flight_mode 的本地
        # recv_match 与 2Hz 采样线程的 drain() 抢同一条连接——ACK 被 drain
        # 吞掉⟹切换误报未确认（模式实际已切，报错自带"当前 ALT_HOLD"），
        # 爬升油门被异常中止=锯齿摆动/无反应）。drain 统一记录，切换方轮询。
        self._last_ack: tuple[int, int, float] | None = None
        self._last_param: tuple[str, float, float] | None = None  # (name, value, ts)
        self.breach_seen = False

    # ── 基础连接 ──

    def connect(self):
        if self._m is None:
            from pymavlink import mavutil

            last = None
            for attempt in range(30):
                try:
                    m = mavutil.mavlink_connection(self.conn_str, source_system=255)
                    if self.conn_str.startswith("udp"):
                        # Windows：先前 send 的 ICMP 不可达会让 recvfrom 抛
                        # WSAECONNRESET——关掉 UDP connreset（标准 ioctl）
                        import struct

                        # 🔴 ValueError 不是 OSError 子类——漏接即穿透成 500
                        #（实测 02:19:27 时间线定谳）。两形态常量都试。
                        last_ioct = None
                        for ctrl in (
                            getattr(socket, "SIO_UDP_CONNRESET", None),
                            -1744830452,
                            2550136844,
                        ):
                            if ctrl is None:
                                continue
                            try:
                                m.port.ioctl(ctrl, struct.pack("I", 0))
                                last_ioct = None
                                break
                            except (OSError, ValueError) as e:
                                last_ioct = e
                        if last_ioct is not None:
                            print(f"[sitl-link] connreset ioctl 失败（韧性层兜底）: {last_ioct}",
                                  flush=True)
                    if m.wait_heartbeat(timeout=60):
                        self._wrap_resilient(m)
                        self._m = m
                        self._start_gc_heartbeat(m)
                        # 遥测流申请（B5 配方：SITL 缺省不推 GPS/姿态流）
                        try:
                            m.mav.request_data_stream_send(
                                m.target_system, m.target_component, 0, 10, 1,
                            )
                        except Exception:
                            pass
                        return self._m
                    m.close()
                    last = LinkError("心跳等待超时（SITL 未起/连接串错）")
                except ConnectionRefusedError as e:
                    last = e
                    # SERIAL0=单连接槽——任何探活/前主断开后需等 SITL 回到监听
                    time.sleep(2)
            raise LinkError(f"MAVLink 连接失败（重试 30 次）: {last}")
        return self._m

    def _wrap_resilient(self, m) -> None:
        """韧化 recv：TCP 对端死亡（SITL 重启/半开连接）时标记死连——下一
        connect() 透明重建（旧码吞成 None 但保留僵尸 _m，桥对重启后的 SITL
        永久失明 [实测]）。"""
        orig = m.recv_msg

        def recv_msg():
            try:
                return orig()
            except (ConnectionResetError, OSError):
                self._m = None  # 死连标记——下次操作透明重连
                time.sleep(0.05)
                return None

        m.recv_msg = recv_msg

    def _start_gc_heartbeat(self, m) -> None:
        # 中继上行地址（端口契约=relay 的 14551 bind；下行源址会被 connected
        # 过滤——显式设定免去址学习）
        up_addr = os.environ.get("FZ_SITL_UPADDR", "127.0.0.1:14551")
        if self.conn_str.startswith("udp") and up_addr:
            host, _, port = up_addr.rpartition(":")
            try:
                # mavudp 对象属性（非裸 socket）
                m.destination_addr = (host, int(port))
            except Exception:
                pass
        """GCS 心跳保活（1Hz——ArduPilot 依 GCS 心跳判链路在位；经 relay 的
        udp 连接套字节流双向可达）。"""
        if getattr(self, "_hb_thread", None) is not None:
            return

        def _loop():
            from pymavlink import mavutil

            while self._m is not None:
                try:
                    self._m.mav.heartbeat_send(
                        mavutil.mavlink.MAV_TYPE_GCS,
                        mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0,
                    )
                except Exception:
                    time.sleep(0.2)
                time.sleep(1.0)

        self._hb_thread = threading.Thread(target=_loop, daemon=True)
        self._hb_thread.start()

    def close(self) -> None:
        if self._m is not None:
            try:
                self._m.close()
            finally:
                self._m = None

    # ── 参数面（B5：PARAM_SET 必须等 PARAM_VALUE 确认——盲发在 SITL 上实测丢参）──

    def set_param(self, name: str, value: float) -> float:
        """参数写入+确认（2026-09-28 单消费者纪律补全）：PARAM_VALUE 确认只能
        经 drain 捕获（_last_param）轮询——此前本地 recv_match 与并发 drain
        （浏览器 1Hz 轮询等）抢同一连接，确认被吞=参数写入超时=ARM 序列 500。"""
        m = self.connect()
        with self._lock:
            for _ in range(3):
                m.mav.param_set_send(
                    m.target_system, m.target_component,
                    name.encode(), float(value), mavutil_type_real32(),
                )
                t_sent = time.time()
                last_sent = t_sent
                deadline = t_sent + 4
                while time.time() < deadline:
                    # 2026-09-30 根修：0.2s 窗在 10Hz 遥测流下永不返回（消息间隔
                    # <窗长=recv_match 永不超时，确认捕获后仍吞流至偶发缝隙
                    # ——实测每参数 4.1s=ARM 45s 的直接构成）。0.05s 短窗+
                    # 逐轮查 _last_param：确认到达即快速返回。
                    # 1.5s 节拍重发（2026-09-30 二段根修：新连接首包 param_set
                    # 被吞——首参数 4.1s 整=重发才中；早重发自愈）。
                    self.drain(0.05)
                    if time.time() - last_sent >= 1.5:
                        m.mav.param_set_send(
                            m.target_system, m.target_component,
                            name.encode(), float(value), mavutil_type_real32(),
                        )
                        last_sent = time.time()
                    if self._last_param is not None:
                        pname, pvalue, ts = self._last_param
                        if pname == name and ts >= t_sent:
                            return pvalue
            raise LinkError(f"参数确认超时: {name}={value}（3×4s 无 PARAM_VALUE——"
                            "确认被并发 drain 吞掉的修复未生效？）")

    def set_param_background(self, name: str, value: float) -> None:
        """尽力写入（后台 daemon 线程——不阻塞调用方关键路径）。
        用于舒适类参数（PILOT_SPEED_UP 等）；安全类参数（围栏）仍同步
        fail-closed 写入。失败仅打警告。

        🔴 锁纪律（2026-09-30 ARM ACK ~10s 根修的教训）：本调用会持 _lock
        跑满 set_param 的 3×4s 超时循环（对无响应参数=12s 连续持锁）——
        **只准在远离 ARM/解锁关键路径的时机发起**（桥启动等空窗期），
        严禁在 attempt_arm 序列内调用（曾致 ARM 等 _lock ~10s）。
        """
        def run():
            try:
                self.set_param(name, value)
                print(f"[param] {name}={value} 已写入", flush=True)
            except LinkError as e:
                print(f"[warn] {name} 后台写入未确认（以缺省值飞行）: {e}", flush=True)
        threading.Thread(target=run, daemon=True).start()

    # ── 指令面 ──

    def arm(self) -> None:
        # 坠机/GCS 失联保护后飞控常处 RTL 等不可解锁模式（实测 "Arm: RTL mode
        # not armable"）——ARM 前先回手动安全模式，否则 8 次重试全部白等。
        if self.last_mode not in (None, "STABILIZE", "ALT_HOLD"):
            self.set_flight_mode(self.COPTER_STABILIZE, "STABILIZE")
        m = self.connect()
        with self._lock:
            for attempt in range(8):
                m.mav.command_long_send(
                    m.target_system, m.target_component,
                    400, 0, 1, 0, 0, 0, 0, 0, 0,  # MAV_CMD_COMPONENT_ARM_DISARM
                )
                t1 = time.time()
                print(f"[arm-timing] arm_send attempt={attempt} t1={t1:.3f}", flush=True)
                arm_resent = False
                while time.time() - t1 < 10:
                    # 2026-09-30 消费者纪律补全：ARM 确认同样经 drain 单点
                    # （本地 recv_match 会吞 PARAM_VALUE——解锁序列里围栏参数
                    # 写入确认被 ARM 等待抢走=下一参数 4s 超时，与 wait_gps
                    # 同族竞态）。ACK 记录进 _last_ack，此处轮询本记录。
                    self.drain(0.05)  # 短窗——同 set_param（0.2 窗吞流失效）
                    if time.time() - t1 >= 4 and not arm_resent:
                        m.mav.command_long_send(
                            m.target_system, m.target_component,
                            400, 0, 1, 0, 0, 0, 0, 0, 0)
                        arm_resent = True
                        print(f"[arm-timing] arm_resent t=+{time.time()-t1:.3f}s", flush=True)
                    ack = self._last_ack
                    if ack is not None and ack[0] == 400 and ack[2] >= t1:
                        if ack[1] == 0:
                            # ③GCS 化加固：ARM 成功即强制 STABILIZE——防
                            # eeprom 残留模式（RTL 等自主模式）令油门
                            # override 无效 [实测 爬升不动根因]。
                            # 2026-09-27 修正：SET_MODE 消息被 ArduPilot 静默
                            # 忽略（嗅探实锤）——须走 command_long 176。
                            m.mav.command_long_send(
                                m.target_system, m.target_component,
                                176, 0, 1, 0, 0, 0, 0, 0, 0)
                            return
                        print(f"[arm-timing] ARM reject result={ack[1]} statustext={getattr(self, 'last_statustext', None)}", flush=True)
                        break  # 拒绝——重试（围栏检查未就绪等瞬态）
                time.sleep(3)  # 重试间隔 8→3s（围栏就绪稳定窗后首发即中）
        raise LinkError("ARM 被拒（8 次尝试均非 result=0）")

    def disarm(self) -> None:
        m = self.connect()
        with self._lock:
            m.mav.command_long_send(
                m.target_system, m.target_component, 400, 0, 0, 0, 0, 0, 0, 0, 0,
            )

    def request_stream(self, rate_hz: int = 10) -> None:
        m = self.connect()
        m.mav.request_data_stream_send(
            m.target_system, m.target_component, 0, rate_hz, 1,
        )

    # 飞行模式常量（Copter custom_mode）：STABILIZE=0 / ALT_HOLD=2
    COPTER_STABILIZE = 0
    COPTER_ALT_HOLD = 2

    def set_flight_mode(self, custom_mode: int, name: str, timeout_s: float = 6.0) -> None:
        """切飞行模式（MAV_CMD_DO_SET_MODE=176 command_long）+ACK/HEARTBEAT 双确认。

        🔴 2026-09-27 嗅探实锤：ArduPilot **静默忽略** MAVLink SET_MODE 消息
        （set_mode_send——无 ACK 无 STATUSTEXT 无效果），只认 command_long 176。
        批5c 的「ARM 后强制 STABILIZE」实为 eeprom 默认模式掩盖的假象；RTL 残留
        之所以每次都要 -w 重启清除，即因模式切换通道从来就没通过。

        定高（ALT_HOLD）语义：油门杆=升降率指令（1500 保持、>1500 爬升、
        <1500 下降）——「悬停」「爬升」「自动飞行」的统一控制基础。

        2026-09-28 队长实测竞态根修：ACK 只能经 drain() 单点消费（2Hz 采样
        线程与切换线程抢同一条连接——本地 recv_match 必然互抢，ACK 被 sampler
        吞掉⟹模式实际已切而误报未确认，油门被异常中止=锯齿摆动/无反应）。
        本实现三重防线：①幂等早退（已在目标模式直接返回）；②确认=candidate
        ACK（drain 记录、时间戳晚于发送、result==0）**或**心跳模式到位（二者
        其一即成——ACK 丢失不误杀）；③ACK result!=0 立即以真实拒绝码报错。
        """
        if self.last_mode == name:
            return  # 幂等早退（重复爬升/悬停不再重发切换指令）
        for _attempt in range(2):
            m = self.connect()
            with self._lock:
                m.mav.command_long_send(
                    m.target_system, m.target_component,
                    176, 0,  # MAV_CMD_DO_SET_MODE
                    1, int(custom_mode), 0, 0, 0, 0, 0)  # p1=CUSTOM_MODE_ENABLED, p2=custom
            t_sent = time.time()
            deadline = t_sent + 5
            rejected: int | None = None
            while time.time() < deadline:
                self.drain(0.3)
                if self._last_ack is not None:
                    cmd, result, ts = self._last_ack
                    if cmd == 176 and ts >= t_sent:
                        if result != 0:
                            rejected = result
                            break
                        # ACK 成功——继续等心跳模式到位（双确认第二腿）
                        if self.last_mode == name:
                            return
                if self.last_mode == name:
                    return  # 心跳模式确认（ACK 被吞也不误杀——模式已实际切换）
            if rejected is not None:
                raise LinkError(f"飞行模式切换被飞控拒绝（ACK result={rejected}）")
            self.drain(0)
        raise LinkError(f"飞行模式切换未确认: {name}（当前 {self.last_mode}）")

    # ── RC Override（B5-d3：SET_MODE target=0 被拒 ACK4——真实飞手形态绕开）──

    def _override_keepalive(self) -> None:
        """10Hz 持续刷新 RC override（真实 GCS 链路形态——2026-09-29 实测定谳：
        override 停止刷新后飞控回退模拟 RC，定高模式下恒速下降直到落地）。
        daemon 线程随进程存活；连接死亡自动重连。"""
        m = None
        while True:
            time.sleep(0.1)
            val = self._override_val
            if val is None:
                continue
            try:
                if m is None:
                    m = self.connect()
                with self._lock:
                    m.mav.rc_channels_override_send(
                        m.target_system, m.target_component,
                        0, 0, val, 1500, 0, 0, 0, 0,
                    )
            except Exception:
                m = None

    def rc_throttle_override(self, pwm: int, channels: int = 4, hold_s: float = 1.0,
                             neutral: int | None = 1500) -> None:
        """油门杆脉冲+回中（2026-09-28 队长实测六根修）：override 状态由
        keepalive 线程 10Hz 持续刷新（真实 GCS 链路形态——停刷即回退模拟 RC，
        定高模式恒速下降）。hold_s 期满回中 neutral(1500)=定高保持；
        neutral=None=不回中（有界爬升循环段间连续）。"""
        self._override_val = pwm  # keepalive 自此刻持续刷新 pwm（含 hold_s 全程）
        if self._ovr_thread is None or not self._ovr_thread.is_alive():
            self._ovr_thread = threading.Thread(
                target=self._override_keepalive, daemon=True)
            self._ovr_thread.start()
        time.sleep(hold_s)
        # 段末：回中（定高保持）或释放
        self._override_val = neutral if neutral is not None else None

    def rc_release(self) -> None:
        self._override_val = None  # keepalive 停发（电机已停/停转路径）
        m = self.connect()
        m.mav.rc_channels_override_send(
            m.target_system, m.target_component, 0, 0, 0, 0, 0, 0, 0, 0,
        )

    # ── 遥测面（真实采样——R1-4：2Hz 真流）──

    def relative_alt_mm(self, timeout: float = 1.0) -> int | None:
        """相对高度（mm）。2026-09-28 竞态根修：改读 drain 缓存（2Hz 采样/
        心跳线程持续刷新）——原直接 recv_match 与 drain 抢连接+阻塞至 3s=
        爬升响应迟滞。缓存缺失时短暂等待首帧。"""
        if self.last_gpos is not None:
            return self.last_gpos["alt_mm"]
        self.drain(timeout)
        return self.last_gpos["alt_mm"] if self.last_gpos else None

    def global_position(self, timeout: float = 1.0) -> dict | None:
        """完整位置面（R3-C1，评审 P2-5）：高度+经纬度一次取。2026-09-28
        竞态根修：改读 drain 缓存（同 relative_alt_mm——缓存缺失时短暂等待）。"""
        if self.last_gpos is not None:
            return dict(self.last_gpos)
        self.drain(timeout)
        return dict(self.last_gpos) if self.last_gpos else None

    # ── STATUSTEXT 面（围栏触发捕获）──

    def _statustext(self, text: str) -> None:
        self.last_statustext = text
        if FENCE_BREACH_TEXT in str(text):
            self.breach_seen = True

    def drain(self, timeout: float = 0.0) -> str | None:
        """收取消息面（围栏触发检测；返回最近 STATUSTEXT）。
        COMMAND_ACK 统一在此记录（_last_ack）——多线程同连接下 ACK 的唯一
        消费点（set_flight_mode 轮询本记录，不再本地 recv_match 抢消息）。

        2026-09-30 截止时间语义（本日 ARM 45s/确认 11s 卡顿的总根因）：旧实现
        `while True` 只在"≥窗口长的静默缝隙"出现时返回——10Hz 遥测流下缝隙
        罕见，**任何带截止时间的调用方（set_param 4s/_confirm_fc_armed 3s）
        都被流吞掉截止权**（实测确认各 4.1s/11s）。现为结构化时长：窗口内
        持续消费，到时即返。"""
        m = self.connect()
        t_end = time.time() + timeout
        first = True
        while True:
            if timeout > 0 and time.time() >= t_end and not first:
                return self.last_statustext
            remaining = max(0.05, t_end - time.time()) if timeout > 0 else 0.0
            msg = m.recv_match(blocking=timeout > 0, timeout=remaining if timeout > 0 else 0.05)
            if msg is None:
                if timeout > 0 and not first and time.time() < t_end:
                    first = False  # 已消费至少一轮后的小空窗——继续到截止
                    continue
                return self.last_statustext
            first = False
            if msg.get_type() == "COMMAND_ACK":
                try:
                    self._last_ack = (int(msg.command), int(msg.result), time.time())
                    # [ack-trace]（2026-09-30 ARM ACK ~10s 根修插桩）：每条 ACK
                    # 到达即打印（cmd/result/progress/precise ts）——与 [arm-timing]
                    # 发送侧打印对拍，定谳 ACK 迟到 vs 捕获丢失。
                    print(f"[ack-trace] cmd={msg.command} result={msg.result} "
                          f"progress={getattr(msg, 'progress', None)} t={time.time():.3f}",
                          flush=True)
                except Exception:
                    pass
                continue
            if msg.get_type() == "PARAM_VALUE":
                try:
                    self._last_param = (
                        msg.param_id.rstrip("\x00"), float(msg.param_value), time.time(),
                    )
                except Exception:
                    pass
                continue
            if msg.get_type() == "HEARTBEAT":
                try:
                    self.last_mode = m.flightmode  # ③GCS 化模式旁路（UI 面）
                    self.last_fc_armed = bool(int(msg.base_mode) & 0x80)
                except Exception:
                    pass
                continue
            if msg.get_type() == "ATTITUDE":
                # ③GCS 化姿态旁路（仅 UI 态势面，不进 14B 链行）。
                self.last_attitude = {
                    "roll": round(float(msg.roll), 4),
                    "pitch": round(float(msg.pitch), 4),
                    "yaw": round(float(msg.yaw), 4),
                }
                continue
            if msg.get_type() == "BATTERY_STATUS":
                try:
                    voltages = [v for v in (msg.voltages or []) if v > 0]
                    self.last_bat = {
                        "voltage_v": round(sum(voltages) / len(voltages) / 1000, 2) if voltages else None,
                        "current_a": round(msg.current_battery / 100, 2) if msg.current_battery >= 0 else None,
                        "remaining_pct": int(msg.battery_remaining) if 0 <= msg.battery_remaining <= 100 else None,
                    }
                except Exception:
                    pass
                continue
            if msg.get_type() == "GPS_RAW_INT":
                try:
                    self.last_gps = {
                        "sats": int(msg.satellites_visible),
                        "fix": int(msg.fix_type),
                    }
                except Exception:
                    pass
                continue
            if msg.get_type() == "VFR_HUD":
                try:
                    self.last_hud = {
                        "speed_ms": round(float(msg.groundspeed), 1),
                        "heading_deg": int(msg.heading) % 360,
                        "throttle_pct": int(msg.throttle),
                        "alt_m": round(float(msg.alt), 1),
                    }
                except Exception:
                    pass
                continue
            if msg.get_type() == "GLOBAL_POSITION_INT":
                # 位置面缓存（2026-09-28：relative_alt_mm/global_position 改读
                # 缓存——原直接 recv_match 与 drain 抢连接+最长 3s 阻塞=爬升
                # 响应迟滞；缓存在 2Hz 采样下恒新鲜）
                try:
                    self.last_gpos = {
                        "alt_mm": int(msg.relative_alt),
                        "lat_1e7": int(msg.lat),
                        "lon_1e7": int(msg.lon),
                    }
                except Exception:
                    pass
                continue
            if msg.get_type() == "STATUSTEXT":
                self._statustext(msg.text)
                continue
            # （2026-09-30 旧 20×窗口硬顶已由结构化截止时间取代——该硬顶正是
            # 0.2 窗=4s/0.5 窗=10s 卡顿的直接构成）
        return self.last_statustext

    def wait_gps_lock(self, timeout_s: float = 100.0) -> bool:
        """等 GPS 锁定——经 drain 单消费者（2026-09-30 队长实测解锁卡 10s+
        根修）：本函数曾直接 recv_match 抢共享连接（PARAM_VALUE 被 GPS 等待
        抢走=围栏参数确认各耗 4s 超时=ARM 卡死），与 set_param/_last_ack 同
        一消费者纪律。锁定判据=drain 已捕获的 last_gps.fix≥3。"""
        m = self.connect()
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            self.drain(0.2)  # 短窗——同 set_param（捕获后靠本轮查 last_gps 返回）
            gps = getattr(self, "last_gps", None)
            if gps is not None and int(gps.get("fix", 0)) >= 3:
                return True
        return False


def mavutil_type_real32() -> int:
    from pymavlink import mavutil

    return mavutil.mavlink.MAV_PARAM_TYPE_REAL32


class FakeLink(SITLLink):
    """测试替身：参数/指令记录器（闸门逻辑单测——无飞控依赖）。"""

    def __init__(self) -> None:
        self.params: dict[str, float] = {}
        self.armed = False
        self.log: list[str] = []
        self.breach_seen = False
        self.last_statustext = None
        self.last_fc_armed: bool | None = None  # 与 SITLLink 同名旁路（gate 消费）

    def connect(self):  # pragma: no cover —— FakeLink 不触真连接
        raise LinkError("FakeLink 无真实连接面（单测用记录器）")

    def set_param(self, name: str, value: float) -> float:
        self.params[name] = value
        self.log.append(f"PARAM {name}={value}")
        return value

    def arm(self) -> None:
        self.armed = True
        self.last_fc_armed = True  # 替身语义：arm 成功=FC 侧上锁位随之置位
        self.log.append("ARM")

    def disarm(self) -> None:
        self.armed = False
        self.last_fc_armed = False
        self.log.append("DISARM")

    def request_stream(self, rate_hz: int = 10) -> None:
        self.log.append(f"STREAM {rate_hz}")

    def set_flight_mode(self, custom_mode: int, name: str, timeout_s: float = 6.0) -> None:
        self.last_mode = name  # 替身：切换即生效
        self.log.append(f"MODE {name}")

    def rc_throttle_override(self, pwm: int, channels: int = 4, hold_s: float = 1.0) -> None:
        self.log.append(f"RC_THROTTLE {pwm}")

    def rc_release(self) -> None:
        self.log.append("RC_RELEASE")

    def relative_alt_mm(self, timeout: float = 3.0) -> int | None:
        return None

    def drain(self, timeout: float = 0.0) -> str | None:
        return self.last_statustext

    def wait_gps_lock(self, timeout_s: float = 100.0) -> bool:
        return True


class FlightGate:
    def __init__(self, link: SITLLink, audit: LocalAudit) -> None:
        self.link = link
        self.audit = audit
        self.fence_state: bytes | None = None
        self.is_armed = False  # 授权态（遥测前置的数据源——阶段一）
        self.session_auth_id: int | None = None  # 当前授权会话（重解锁路径消费）
        self.session_alt_max: int | None = None

    def disarm(self) -> None:
        """停转+释放 RC+复位授权态（server /sitl/disarm 改走此处——armed 单源）。"""
        self.link.disarm()
        self.link.rc_release()
        self.is_armed = False

    def attempt_arm(
        self,
        token_payload: bytes,
        plan_hash_hex: str,
        now: int | None = None,
        plan_altitude_m: int | None = None,
    ) -> dict:
        try:
            tok = verify_token(token_payload, plan_hash_hex=plan_hash_hex, now=now)
        except TokenError as e:
            self.audit.record_denial(e.code, e.message)
            return {"ok": False, "code": e.code, "message": e.message}
        except RuntimeError as e:
            # 引擎公钥不可得等环境级失败（非令牌问题）——诚实拒绝，不 500
            self.audit.record_denial("engine_pub_unavailable", str(e))
            return {"ok": False, "code": "engine_pub_unavailable", "message": str(e)}
        # 计划高度联动（阶段二）：围栏=min(令牌 alt_max, 计划作业高度)——地面站层
        # 约束（TCB 第①层声明：用户理论可改本机计划；固件硬上限仍=政策值）。
        effective_alt = tok["alt_max"]
        if plan_altitude_m is not None and 1 <= int(plan_altitude_m) < effective_alt:
            effective_alt = int(plan_altitude_m)
        prev = self.audit.first_arm(token_payload)
        # ⓪ 一次性令牌（方案 A，队长拍板）：一次授权对应一次解锁——同令牌二次
        # ARM 拒。**例外=同会话飞控重解锁（2026-09-27 队长实测四根修）**：授权门
        # 已被本令牌打开（is_armed=True）而飞控侧因「地面怠速自动上锁」回落
        # （DISARM_DELAY）时，重发 FC ARM 属同一次授权的延续而非二次解锁——
        # 否则飞手被锁死在「必须重新出证（2 分钟+烧一张一次性子凭证）」的死路。
        # 令牌有效期仍由 verify_token 强制（过期窗=授权窗外，照常拒）。
        fc_armed_now = getattr(self.link, "last_fc_armed", None)
        if prev is not None:
            if self.is_armed and fc_armed_now is False:
                try:
                    self.link.arm()
                    self._confirm_fc_armed()
                except LinkError as e:
                    self.audit.record_denial("fc_arm_failed", str(e))
                    return {"ok": False, "code": "fc_arm_failed", "message": str(e)}
                return {
                    "ok": True,
                    "rearmed": True,
                    "auth_id": self.session_auth_id,
                    "alt_max": self.session_alt_max,
                    "fence_state_hex": self.fence_state.hex(),
                    "first_arm": False,
                }
            msg = "该授权已使用（一次授权对应一次解锁）——请重新申请出证"
            self.audit.record_denial("token_used", msg)
            return {"ok": False, "code": "token_used", "message": msg}
        # ① 围栏写入（先围栏后 ARM——顺序即安全语义）。
        # 单位契约（S2 定谳+复审[中9]统一）：政策/令牌/固件 FENCE_ALT_MAX=**meters**
        # （链上 FlightAuthRegistry.altMaxM 同单位）；TRAIL 电路=cm（×100 转换
        # 在出证装配面）。
        _t0 = time.time()
        self.link.set_param("FENCE_ENABLE", 1)
        print(f"[arm-timing] FENCE_ENABLE {time.time()-_t0:.1f}s", flush=True)
        self.link.set_param("FENCE_ALT_MAX", float(effective_alt))
        print(f"[arm-timing] FENCE_ALT_MAX {time.time()-_t0:.1f}s", flush=True)
        self.link.set_param("FENCE_TYPE", 3)  # ALT_MAX 围栏位型（B5 实测形态）
        print(f"[arm-timing] FENCE_TYPE {time.time()-_t0:.1f}s", flush=True)
        self.link.set_param("FENCE_MARGIN", 0)  # breach 判定精确到线（无预刹车余量）
        print(f"[arm-timing] FENCE_MARGIN {time.time()-_t0:.1f}s", flush=True)
        # 围栏触发行为：保持固件缺省（2026-09-29 实测改判——FENCE_ACTION=3
        # 预防性刹车会把飞控变成"阻止越线"，永远不触发 breach 事件=违规取证
        # 演示路径死亡；缺省行为=越线后拦截制动+breach 事件+回落清除，与 S1
        # 5402cm 实测一致。围栏三参数（ENABLE/ALT_MAX/TYPE）仍 fail-closed。）
        # 飞行员爬升速率上限（P1 操控）：缺省 250cm/s 偏保守——400cm/s 运动档。
        # 本构建对该参数无 PARAM_VALUE 响应（2026-09-28 定谳）。写入=仅桥启动
        # 时后台一次（server.py 模块加载处——2026-09-30 ARM ACK ~10s 根修）：
        # 此前本行在每次 attempt_arm 里重复发起，后台 set_param 持 _lock 跑满
        # 3×4s 超时循环（12s），主线程 arm() 的 with _lock 恰好在 2s settle 窗
        # 后等它的尾段 ~10s——插桩实锤 ARM 命令本身 14ms 即 ACK（[ack-trace]），
        # 时延全耗在锁上。语义零变化：该写入在本构建从未成功，爬升速率一直
        # 是固件缺省值。
        self.fence_state = bytes([1]) + int(effective_alt).to_bytes(2, "big") + b"\x00"
        # 围栏就绪稳定窗（2026-09-30 队长实测 ARM 40s 根修）：FENCE_ENABLE 写入
        # 后固件围栏子系统加载需 ~2s——立即 ARM 会被"Fence check failed"拒绝
        # （8s 重试间隔×3 次=40s 卡顿的剩余构成）。稳定窗+短重试间隔。
        time.sleep(2)
        print(f"[arm-timing] settle_done arm_start {time.time()-_t0:.1f}s", flush=True)
        # ② ARM+审计。DISARM_DELAY=0（③GCS 化尾修，队长实测爬升不动根因）：
        # ArduPilot 落地+怠速 10s 自动上锁会在飞手准备期间悄悄锁电机——爬升
        # override 全部无效且无任何报错 [实测]。关闭自动上锁（与围栏参数同一条
        # 可信参数通道；真实 GCS 运营同形态），上锁权保留在 disarm 显式动作。
        try:
            self.link.arm()
            print(f"[arm-timing] arm_done {time.time()-_t0:.1f}s", flush=True)
        except LinkError as e:
            # ARM 被拒（围栏检查未就绪/模式不可解锁等）——诚实拒绝而非 500
            self.audit.record_denial("fc_arm_failed", str(e))
            return {"ok": False, "code": "fc_arm_failed", "message": str(e)}
        try:
            self.link.set_param("DISARM_DELAY", 0)
        except Exception:  # noqa: BLE001 —— 参数写入失败非致命：fc 旁路+重解锁兜底
            pass
        try:
            self._confirm_fc_armed()
        except LinkError as e:
            self.audit.record_denial("fc_arm_failed", str(e))
            return {"ok": False, "code": "fc_arm_failed", "message": str(e)}
        self.is_armed = True
        self.session_auth_id = tok["authId"]
        self.session_alt_max = effective_alt
        at = self.audit.record_arm(token_payload, tok["authId"])
        return {
            "ok": True,
            "auth_id": tok["authId"],
            "alt_max": effective_alt,
            "fence_state_hex": self.fence_state.hex(),
            "first_arm": prev is None,
            "first_arm_at": at,
        }

    def _confirm_fc_armed(self, timeout_s: float = 3.0) -> None:
        """FC 侧解锁确认：等待 HEARTBEAT 的 SAFETY_ARMED=1（COMMAND_ACK 后仍
        可能立即回落上锁——诚实呈现而非假 armed）。超时仍显式 False=拒绝；
        无位面（None，测试替身/心跳未达）=放行不阻断。"""
        import time as _t

        deadline = _t.time() + timeout_s
        fc: bool | None = getattr(self.link, "last_fc_armed", None)
        while fc is not True and _t.time() < deadline:
            self.link.drain(0.2)  # 短窗（drain 已有截止语义——0.5 长窗无益）
            fc = getattr(self.link, "last_fc_armed", None)
        if fc is not True and fc is not None:
            raise LinkError(
                "飞控解锁未成功（已自动回落上锁）——请检查 GPS/飞控状态后重试"
            )
        # fc is True=已确认；fc is None=无位面 → 不阻断
