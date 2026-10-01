"""keccak + ABI 编码器测试。

向量锚定：keccak256("") 为以太坊官方空串摘要；
selector 取 trasfer/balanceOf 等社区公认值；ABI head/tail 规则按 Solidity 文档。
"""

import pytest

from app.chain.abi import abi_decode, abi_encode, fn_selector, keccak256, sig_hash


def test_keccak256_empty():
    assert (
        keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_keccak256_abc():
    assert (
        keccak256(b"abc").hex()
        == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )


def test_fn_selector_known():
    assert fn_selector("transfer(address,uint256)").hex() == "a9059cbb"
    assert fn_selector("balanceOf(address)").hex() == "70a08231"


def test_fn_selector_gm_anchored_by_bin():
    """国密链选择器 = SM3[:4]：与 solc 国密版编译产物 bin 常量逐项对拍（2026-09-01）。"""
    assert fn_selector("registerOrg(bytes32,bytes32)", gm=True).hex() == "09b13439"
    assert fn_selector("revokeOrg(bytes32)", gm=True).hex() == "dc5277ef"
    assert fn_selector("setCredStatus(bytes32,uint8)", gm=True).hex() == "17546cb0"
    # 事件 topic0 同口径：SM3("OrgRegistered(...)") 前缀与 bin emit 常量命中
    assert (
        sig_hash("OrgRegistered(bytes32,bytes32,address,uint64)", gm=True).hex()[:16]
        == "99561a608dad7a8d"
    )


def test_abi_encode_uint256():
    assert abi_encode(["uint256"], [1]) == (1).to_bytes(32, "big")


def test_abi_encode_uint256_overflow():
    with pytest.raises(ValueError):
        abi_encode(["uint256"], [2**256])


def test_abi_encode_bool_address_bytes32():
    out = abi_encode(["bool", "address", "bytes32"], [True, "0x" + "11" * 20, b"\x01" * 32])
    assert out[0:32] == (1).to_bytes(32, "big")
    assert out[32:64] == b"\x00" * 12 + b"\x11" * 20  # 左填充 20B 地址
    assert out[64:96] == b"\x01" * 32


def test_abi_encode_dynamic_string():
    data = abi_encode(["string"], ["hello"])
    assert data == (32).to_bytes(32, "big") + (5).to_bytes(32, "big") + b"hello" + bytes(27)


def test_abi_encode_dynamic_bytes():
    data = abi_encode(["bytes"], [b"\xab" * 40])
    assert data[0:32] == (32).to_bytes(32, "big")
    assert data[32:64] == (40).to_bytes(32, "big")
    assert data[64:104] == b"\xab" * 40
    assert data[104:128] == bytes(24)  # 右填充到 32 的倍数


def test_abi_encode_mixed_head_tail():
    data = abi_encode(["uint256", "string", "bytes32"], [7, "ab", b"\x01" * 32])
    assert data[0:32] == (7).to_bytes(32, "big")
    assert data[32:64] == (96).to_bytes(32, "big")  # 3×32 静态头后偏移
    assert data[64:96] == b"\x01" * 32
    assert data[96:128] == (2).to_bytes(32, "big")
    assert data[128:130] == b"ab" and data[130:160] == bytes(30)


def test_abi_encode_two_dynamic():
    data = abi_encode(["string", "string"], ["abc", "de"])
    assert data[0:32] == (64).to_bytes(32, "big")
    assert data[32:64] == (64 + 64).to_bytes(32, "big")  # 第一段长 32+32
    assert data[64:96] == (3).to_bytes(32, "big") and data[96:99] == b"abc"
    assert data[128:160] == (2).to_bytes(32, "big") and data[160:162] == b"de"


def test_unknown_type_rejected():
    with pytest.raises(ValueError):
        abi_encode(["uint8[]"], [[1, 2]])


def test_abi_encode_uint_subtypes():
    """uint8/uint64 同 32B 大端编码（Solidity ABI 规范：全部左对齐 32 字）。"""
    assert abi_encode(["uint8"], [7])[31] == 7
    assert abi_encode(["uint64"], [1000])[31] == 0xE8 and abi_encode(["uint64"], [1000])[30] == 3


def test_abi_decode_static_roundtrip():
    types = ["uint8", "uint64", "bytes32", "address", "bool"]
    values = [3, 999, b"\x02" * 32, "0x" + "ab" * 20, True]
    data = abi_encode(types, values)
    assert abi_decode(types, data) == values


def test_abi_decode_string_bytes_roundtrip():
    data = abi_encode(["string", "bytes"], ["hello", b"\x01\x02\x03"])
    assert abi_decode(["string", "bytes"], data) == ["hello", b"\x01\x02\x03"]


def test_abi_decode_mixed():
    data = abi_encode(["bytes32", "string", "uint64"], [b"\x03" * 32, "中文值", 42])
    assert abi_decode(["bytes32", "string", "uint64"], data) == [b"\x03" * 32, "中文值", 42]
