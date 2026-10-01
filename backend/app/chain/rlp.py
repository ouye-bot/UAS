"""RLP 编码（FISCO BCOS 2.x 交易用，编码规则同以太坊）。

交易为平铺字段列表（无嵌套），故只暴露 rlp_encode_fields。
"""

from __future__ import annotations


def _wrap(payload: bytes, short_offset: int, long_offset: int) -> bytes:
    """按串/列表规则加长度头：≤55B 单字节头，否则多字节大端长度。"""
    n = len(payload)
    if n <= 55:
        return bytes([short_offset + n]) + payload
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([long_offset + len(length_bytes)]) + length_bytes + payload


def encode_item(item: int | bytes) -> bytes:
    """单对象编码（以太坊 RLP 口径，测试锚定用）。"""
    if isinstance(item, int):
        if item < 0:
            raise ValueError("RLP 不支持负整数")
        # 大端去前导零；0 → b""（空串 0x80）
        item = item.to_bytes((item.bit_length() + 7) // 8, "big")
    if len(item) == 1 and item[0] < 0x80:
        return item
    return _wrap(item, 0x80, 0xB7)


def rlp_encode_fields(items: list[int | bytes]) -> bytes:
    """平铺字段列表 → RLP 字节串（FISCO tx 十字段+签名三元组）。"""
    body = b"".join(encode_item(i) for i in items)
    return _wrap(body, 0xC0, 0xF7)
