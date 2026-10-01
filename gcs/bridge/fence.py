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

import struct

from app.crypto.sm3 import sm3_bytes

GENESIS = b"FZ-TEL-GENESIS"
SAMPLE_HZ = 2
CHECKPOINT_INTERVAL_S = 60


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

    def push(self, t_epoch: int, alt_cm: int, lat_1e7: int, lon_1e7: int) -> bytes:
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
