"""检查点报文规范（D-Ⅰ-6 单源化——backend 端点验签与 bridge 签名共用）。

报文（B5-d4）：b"FZ-CHK|" ‖ authId(u64 BE) ‖ seq(u32 BE) ‖ chain_head(32B)
‖ fence_state(4B：FENCE_ENABLE(1)‖FENCE_ALT_MAX BE u16‖保留(1))。
签名=设备身份钥 SM2（SITL=桥接模拟设备钥 TCB 声明，真机=SE/TCM——D16）。
"""

from __future__ import annotations

from app.crypto.sm2 import verify_digest
from app.crypto.sm3 import sm3_bytes


def checkpoint_message(auth_id: int, seq: int, chain_head: bytes, fence_state: bytes) -> bytes:
    return (
        b"FZ-CHK|" + auth_id.to_bytes(8, "big") + seq.to_bytes(4, "big") + chain_head + fence_state
    )


def verify_checkpoint(
    pub_hex: str, auth_id: int, seq: int, chain_head: bytes, fence_state: bytes, sig_hex: str
) -> bool:
    """设备签名验证（含围栏状态绑定——改 1 字节必败，B5 测试钉定）。"""
    return verify_digest(
        pub_hex, sm3_bytes(checkpoint_message(auth_id, seq, chain_head, fence_state)), sig_hex
    )
