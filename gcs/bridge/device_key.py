"""设备侧身份钥（B5-T1，D16/TCB 第③层）。

演示形态：bridge 进程模拟设备钥（KMS 域派生——确定性演示锚非生产凭据）；
真机部署=伴飞计算机+SE/TCM 芯片（落地路线成文，TCB 声明第③层）。
签名语义：遥测哈希链链头+检查点报文（authId‖seq‖chain_head‖fence_state）。

检查点报文规范单源（阶段一 D-Ⅰ-6）：backend/app/telemetry/checkpoint.py 为
权威定义（backend 端点验签与 bridge 签名同源）——本模块再导出保持兼容。
"""

from __future__ import annotations

import os

from app.crypto.sm2 import pubkey_from_priv, sign_digest
from app.crypto.sm3 import sm3_bytes
from app.telemetry.checkpoint import checkpoint_message, verify_checkpoint

__all__ = [
    "checkpoint_message",
    "device_keypair",
    "device_serial",
    "sign_checkpoint",
    "verify_checkpoint",
]


def device_serial() -> str:
    """本机序列号单源（SN 绑定换代 2026-10-06）：env FZ_DEVICE_SERIAL 优先，
    缺省演示锚 FZ-SN-DEV-01——与 device_keypair 的钥派生同一读数源（桥第 6
    查 SM3(本机 SN)==token.sn_hash 与设备钥同源）。"""
    return os.environ.get("FZ_DEVICE_SERIAL", "FZ-SN-DEV-01")


def _derive_priv(label: bytes) -> str:
    from gmssl.sm2 import default_ecc_table

    n = int(default_ecc_table["n"], 16)
    d = int.from_bytes(sm3_bytes(label), "big") % (n - 2) + 1
    return format(d, "064x")


def device_keypair(serial: str) -> tuple[str, str]:
    """(priv_hex, pub_hex)——env FZ_DEVICE_SK 优先；缺省按序列号确定性派生。"""
    sk = os.environ.get("FZ_DEVICE_SK")
    if sk:
        if len(sk) != 64:
            raise ValueError("FZ_DEVICE_SK 须 64 hex")
        return sk, pubkey_from_priv(sk)
    priv = _derive_priv(b"FZ-KMS|device|" + serial.encode())
    return priv, pubkey_from_priv(priv)


def sign_checkpoint(priv_hex: str, auth_id: int, seq: int, chain_head: bytes, fence_state: bytes) -> str:
    return sign_digest(priv_hex, sm3_bytes(checkpoint_message(auth_id, seq, chain_head, fence_state)))
