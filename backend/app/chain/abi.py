"""ABI 编码器（FISCO BCOS 合约调用用，Solidity ABI 规范最小集）。

支持六类型：uint256 / address / bool / bytes32 / string / bytes。
静态类型直接编 32B；动态类型（string/bytes）head=偏移、tail=长度+数据+右填充。
selector = 哈希(签名串) 前 4 字节：以太坊通用链用 keccak256，FISCO 2.x 国密链
EVM 层哈希（选择器/事件 topic0/存储定位）整体换 SM3——编译产物 bin 常量对拍
实证（2026-09-01：SM3("registerOrg(bytes32,bytes32)")[:4]=09b13439 与 bin 逐项
命中，keccak 版不被节点 EVM 接受即 revert 0x16）。
"""

from __future__ import annotations

from Crypto.Hash import keccak

from app.crypto.sm3 import sm3_bytes

_UINT256_MAX = 2**256 - 1


def keccak256(data: bytes) -> bytes:
    """原始 Keccak-256（以太坊/FISCO 口径，非 NIST SHA3 padding）。"""
    return keccak.new(data=data, digest_bits=256).digest()


def sig_hash(signature: str, *, gm: bool = False) -> bytes:
    """签名串 → 32B 全量哈希（keccak256；国密链换 SM3）。"""
    return sm3_bytes(signature.encode()) if gm else keccak256(signature.encode())


def fn_selector(signature: str, *, gm: bool = False) -> bytes:
    """函数签名 → 4 字节 selector（gm=True 供 FISCO 国密链）。"""
    return sig_hash(signature, gm=gm)[:4]


def _word(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _encode_static(typ: str, value) -> bytes:
    if typ.startswith("uint"):
        if not isinstance(value, int) or value < 0 or value > _UINT256_MAX:
            raise ValueError(f"{typ} 越界/类型错误: {value!r}")
        return _word(value)
    if typ == "bool":
        return _word(1 if value else 0)
    if typ == "address":
        hexstr = value.hex() if isinstance(value, bytes) else str(value).removeprefix("0x")
        raw = bytes.fromhex(hexstr)
        if len(raw) != 20:
            raise ValueError(f"地址须 20 字节: {value!r}")
        return b"\x00" * 12 + raw
    if typ.startswith("bytes") and typ != "bytes":  # 定长 bytesN（N=1..32）
        n = int(typ[5:])
        if not isinstance(value, (bytes, bytearray)) or len(value) != n:
            raise ValueError(f"{typ} 须 {n} 字节: {value!r}")
        return bytes(value) + bytes(32 - n)  # 右填充
    raise ValueError(f"未知类型: {typ}")


def _encode_tail(typ: str, value) -> bytes:
    data = value if isinstance(value, bytes) else str(value).encode()
    padded = data + bytes((-len(data)) % 32)
    return _word(len(data)) + padded


def abi_decode(types: list[str], data: bytes) -> list:
    """最小解码集：静态类型逐 32B 字 + string/bytes 偏移寻址（head/tail 对称）。"""
    out: list = []
    dynamic = [t in ("string", "bytes") for t in types]
    for i, (t, d) in enumerate(zip(types, dynamic, strict=True)):
        if d:
            offset = int.from_bytes(data[i * 32 : (i + 1) * 32], "big")
            length = int.from_bytes(data[offset : offset + 32], "big")
            raw = data[offset + 32 : offset + 32 + length]
            out.append(raw.decode() if t == "string" else raw)
        elif t.startswith("uint"):
            out.append(int.from_bytes(data[i * 32 : (i + 1) * 32], "big"))
        elif t == "bool":
            out.append(data[i * 32 + 31] != 0)
        elif t == "address":
            out.append("0x" + data[i * 32 + 12 : (i + 1) * 32].hex())
        elif t.startswith("bytes") and t != "bytes":  # 定长 bytesN 截断填充
            n = int(t[5:])
            out.append(data[i * 32 : i * 32 + n])
        else:
            raise ValueError(f"未知类型: {t}")
    return out


def abi_encode(types: list[str], values: list) -> bytes:
    """head/tail 两段式编码（参数个数须与类型一致）。"""
    if len(types) != len(values):
        raise ValueError("类型与值数量不一致")
    is_dynamic = [t in ("string", "bytes") for t in types]
    statics = [
        _encode_static(t, v) if not d else b""
        for t, v, d in zip(types, values, is_dynamic, strict=True)
    ]
    head_size = (
        sum(max(len(s), 32) for s in statics) if any(is_dynamic) else sum(len(s) for s in statics)
    )
    head: list[bytes] = []
    tails: list[bytes] = []
    tail_offset = head_size
    for (t, v, d), s in zip(zip(types, values, is_dynamic, strict=True), statics, strict=True):
        if d:
            head.append(_word(tail_offset))
            tail = _encode_tail(t, v)
            tails.append(tail)
            tail_offset += len(tail)
        else:
            head.append(s)
    return b"".join(head) + b"".join(tails)
