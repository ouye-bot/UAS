"""遥测哈希链记录器+检查点（B5-T2，D16/P0-1）。

链语义：h_0=SM3(b"FZ-TEL-GENESIS")；h_{i+1}=SM3(h_i‖t_i‖alt_i‖lat_i‖lon_i)
（BE 定长编码 >Iiii，t=unix 秒录制时间轴）。本链=锚定面（60s 检查点设备签
+真链锚定留痕）；TRAIL 语句面（行=14B >IHii、t=段相对 500ms 网格、链头=行
字节重放）在 prover._trail_window_rows 单源计算——两条链各自闭环勿混用
（㊿+36；字段宽/序同构、t 原点不同）。2Hz 采样（SITL 状态流）；
每 60s 检查点=设备钥 SM2 签（authId‖seq‖chain_head‖fence_state）——围栏状态
绑定使"伪造合规记录"需同时伪造设备签名+固件围栏状态。
"""

from __future__ import annotations

import math
import struct

from app.crypto.sm3 import sm3_bytes

GENESIS = b"FZ-TEL-GENESIS"
SAMPLE_HZ = 2
CHECKPOINT_INTERVAL_S = 60

# 合理性门（批1-1.4）：录制器零门=客户端可注任意"遥测"（倒拨时钟/传送跳变/
# 超速爬升）。界=2Hz 采样契约 + SITL speedup=1 物理界。超界样本拒绝入链
# （rejected_count 计数，/telemetry/state 可见）；拒样不毒化后续录制——
# 下一正常样本重开连续窗（缺口如实留存于链行时间轴）。
MAX_DT_S = 2.0        # 样本间隔上界（2Hz 契约内；超界=断链标记）
MAX_VERT_MS = 25.0    # 垂直速度上界 m/s（SITL speedup=1 物理界）
MAX_JUMP_M = 200.0    # 水平跳变上界 m/样本（传送带/坐标注入界）
_M_PER_1E7_DEG = 111_320.0 / 1e7  # 1e-7° 纬向米数（经向×cos(lat)）


class SampleRejected(ValueError):
    """遥测样本合理性门拒绝（超界不入链）。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def sample_hash(prev_head: bytes, t_epoch: int, alt_cm: int, lat_1e7: int, lon_1e7: int) -> bytes:
    """单样本链扩展（GLOBAL_POSITION_INT 口径：alt mm、lat/lon 1e7 deg）。"""
    return sm3_bytes(prev_head + struct.pack(">Iiii", t_epoch, alt_cm, lat_1e7, lon_1e7))


class TelemetryChain:
    def __init__(self, auth_id: int, serial_priv_hex: str, fence_state: bytes) -> None:
        self.auth_id = auth_id
        self.head = sm3_bytes(GENESIS)
        self.genesis_head = self.head  # 起始锚留档（head 随样本推进——state 回放用）
        self.n = 0
        self.samples: list[tuple[int, int, int, int]] = []  # (t, alt, lat, lon)
        self.priv = serial_priv_hex
        self.fence_state = fence_state  # 4B：enable‖alt_max BE16‖rsv
        self.cp_seq = 0
        self.last_cp_t = 0.0
        self.checkpoints: list[dict] = []
        self.anchored_seq = 0  # 已真链锚定的最大 seq（阶段一：转发面断点续锚）
        # 合理性门状态（批1-1.4）：rejected_count 上报 /telemetry/state；
        # last_wall=服务端采样墙钟（unix 浮点秒——2Hz 同秒双拍下速度/间隔
        # 判定须浮点粒度，整数 t_epoch 只做倒拨门）；_resync=拒样后重开窗。
        self.rejected_count = 0
        self.last_wall: float | None = None
        self.last_reject: dict | None = None
        self._resync = False

    def _reject(self, code: str, message: str) -> None:
        self.rejected_count += 1
        self._resync = True
        self.last_reject = {"code": code, "message": message}
        raise SampleRejected(code, message)

    def push(
        self,
        t_epoch: int,
        alt_cm: int,
        lat_1e7: int,
        lon_1e7: int,
        wall: float | None = None,
    ) -> bytes:
        """样本入链（合理性门——批1-1.4）。

        wall=服务端采样墙钟（time.time() 浮点秒）——服务端时间轴单源（客户端
        给定 t_epoch 忽略作哈希时间轴外的输入；链行 t=服务端折算）。倒拨门/
        水平跳变门对直构链（wall=None，单测/回放装配）恒生效；间隔/速度门
        仅在服务端墙钟在位时判定（整数秒粒度在 2Hz 下同秒双拍，不可判速度）。
        """
        t_epoch = int(t_epoch)
        if self.samples and not self._resync:
            lt, lalt, llat, llon = self.samples[-1]
            if t_epoch < lt:
                self._reject(
                    "clock_rollback",
                    f"遥测时间倒拨（t={t_epoch} < 上一样本 {lt}）——样本拒绝入链",
                )
            dlat_m = (lat_1e7 - llat) * _M_PER_1E7_DEG
            dlon_m = (lon_1e7 - llon) * _M_PER_1E7_DEG * math.cos(math.radians(lat_1e7 / 1e7))
            dm = math.hypot(dlat_m, dlon_m)
            if dm > MAX_JUMP_M:
                self._reject(
                    "teleport_jump",
                    f"水平跳变 {dm:.0f}m 超界 {MAX_JUMP_M:.0f}m/样本——样本拒绝入链",
                )
            if wall is not None and self.last_wall is not None:
                dtw = wall - self.last_wall
                if dtw <= 0:
                    if (alt_cm, lat_1e7, lon_1e7) != (lalt, llat, llon):
                        self._reject(
                            "zero_dt_motion",
                            f"零间隔状态突变（t={t_epoch}）——样本拒绝入链",
                        )
                else:
                    if dtw > MAX_DT_S:
                        self._reject(
                            "dt_exceeded",
                            f"样本间隔 {dtw:.1f}s 超出 2Hz 契约上界 {MAX_DT_S:.0f}s"
                            "——样本拒绝入链（断链标记，采样已中断）",
                        )
                    vert = abs(alt_cm - lalt) / dtw  # cm/s
                    if vert > MAX_VERT_MS * 100:
                        self._reject(
                            "vert_speed",
                            f"垂直速度 {vert / 100:.1f}m/s 超物理界 {MAX_VERT_MS:.0f}m/s"
                            "——样本拒绝入链",
                        )
        if wall is not None:
            self.last_wall = wall
        self._resync = False
        self.head = sample_hash(self.head, t_epoch, alt_cm, lat_1e7, lon_1e7)
        self.samples.append((t_epoch, alt_cm, lat_1e7, lon_1e7))
        self.n += 1
        return self.head

    def maybe_checkpoint(self, now: float, signer) -> dict | None:
        """到期产检查点（设备钥签名+围栏状态绑定——返回 None=未到期）。"""
        if self.n == 0 or now - self.last_cp_t < CHECKPOINT_INTERVAL_S:
            return None
        self.cp_seq += 1
        self.last_cp_t = now
        from device_key import sign_checkpoint

        sig = sign_checkpoint(self.priv, self.auth_id, self.cp_seq, self.head, self.fence_state)
        cp = {
            "auth_id": self.auth_id,
            "seq": self.cp_seq,
            "chain_head_hex": self.head.hex(),
            "fence_state_hex": self.fence_state.hex(),
            "sig_hex": sig,
            "n_samples": self.n,
        }
        self.checkpoints.append(cp)
        return cp

    def breach_event(self, t_epoch: int, alt_cm: int, source: int) -> dict:
        """违规取证（围栏触发 source=1/地面站监测 source=2——D16 固件事件为权威）。"""
        return {
            "auth_id": self.auth_id,
            "event_type": source,
            "event_hash_hex": sm3_bytes(
                self.head + struct.pack(">Ii", t_epoch, alt_cm)
            ).hex(),
            "t_epoch": t_epoch,
            "alt_cm": alt_cm,
        }
