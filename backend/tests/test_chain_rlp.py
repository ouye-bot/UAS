"""RLP 编码测试：以太坊 RLP 官方向量锚定（FISCO 2.x 交易编码同规则）。

单对象向量测 encode_item（官方口径）；rlp_encode_fields 是「字段列表→列表」，
按 FISCO 交易口径另测。
"""

import pytest

from app.chain.rlp import encode_item, rlp_encode_fields

ITEM_VECTORS = [
    # (输入, 期望 hex, 说明) — 以太坊 RLP 官方向量
    (b"dog", "83646f67", "3B 短串"),
    (b"", "80", "空串"),
    (0, "80", "int 0 → 空串"),
    (15, "0f", "单字节 int <0x80 原样"),
    (127, "7f", "0x7f 边界"),
    (128, "8180", "0x80 起为串编码"),
    (1024, "820400", "两字节 int"),
    (bytes(55), "b7" + "00" * 55, "55B 短串上边界 0x80+55=0xb7"),
    (bytes(56), "b838" + "00" * 56, "56B → 长串 1 字节长度头"),
    (b"\x05" * 1024, "b90400" + "05" * 1024, "长串 2 字节长度头"),
]


@pytest.mark.parametrize("item,expected,note", ITEM_VECTORS, ids=[v[2] for v in ITEM_VECTORS])
def test_item_vectors(item, expected, note):
    assert encode_item(item).hex() == expected, note


def test_list_of_two_strings():
    """[cat, dog] 列表：官方向量 c8..."""
    assert rlp_encode_fields([b"cat", b"dog"]).hex() == "c88363617483646f67"


def test_tx_shape_prefix_and_body():
    """十字段形态：头部 0xf8（长列表）+ 长度，字段体大端序。"""
    items = [0, b"", b"\x01" * 32, b"\x11" * 20, 30000000, b"\xde\xad", 1, 1, b""]
    out = rlp_encode_fields(items)
    assert out[0] == 0xF8  # 列表体 >55B → 0xf7+1
    body = out[2:]
    assert body[0] == 0x80 and body[1] == 0x80
    assert body[2] == 0xA0 and body[3:35] == b"\x01" * 32
    assert body[35] == 0x94 and body[36:56] == b"\x11" * 20
    assert body[56] == 0x84 and body[57:61] == (30000000).to_bytes(4, "big")  # 0x80+4 头
    assert body[61] == 0x82 and body[62:64] == b"\xde\xad"
    assert body[64] == 0x01 and body[65] == 0x01 and body[66] == 0x80


def test_negative_rejected():
    with pytest.raises(ValueError):
        rlp_encode_fields([-1])
