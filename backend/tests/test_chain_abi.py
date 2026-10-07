"""链 ABI 层测试（B1）：四合约接口契约锚+bytesN 编码向量+国密选择器形态。

接口契约=框架 §六接口集（合约漏写任一函数即红——源码↔ABI 单一事实源）。
"""

import json
from pathlib import Path

import pytest

from app.chain.abi import abi_decode, abi_encode, fn_selector

BUILD = Path(__file__).resolve().parents[2] / "contracts" / "build"
CONTRACTS = ("IdentityRegistry", "PolicyRegistry", "FlightAuthRegistry", "TelemetryAnchor")

# 框架 §六接口→源码必须存在的函数集（接口契约锚）；transferAdmin=批 3.2
# 治理面移交（admin→AdminGovernor 多签+时间锁）
REQUIRED_FNS = {
    "IdentityRegistry": {
        "registerCommitment",
        "setStatus",
        "setRevocationRoot",
        "logWarrant",
        "isRevoked",
        "transferAdmin",
    },
    "PolicyRegistry": {
        "publishPolicy",
        "pinCircuit",
        "setClassRule",
        "getClassRule",
        "transferAdmin",
    },
    "FlightAuthRegistry": {
        "recordAuth",
        "burnNonce",
        "revokeAuth",
        "consumeSortie",
        "remainingOf",
        "nonceUsed",
        "transferAdmin",
    },
    "TelemetryAnchor": {"anchorCheckpoint", "recordEvent", "verifyHead", "transferAdmin"},
}


@pytest.mark.parametrize("name", CONTRACTS)
def test_abi_exists_and_required_fns(name):
    abi = json.loads((BUILD / f"{name}.abi").read_text())
    fns = {e["name"] for e in abi if e["type"] == "function"}
    missing = REQUIRED_FNS[name] - fns
    assert not missing, f"{name} ABI 缺接口: {missing}"


def test_governor_abi_surface():
    """AdminGovernor 接口契约锚（批 3.2）：多签+时间锁治理面函数与生命周期事件。"""
    abi = json.loads((BUILD / "AdminGovernor.abi").read_text())
    fns = {e["name"] for e in abi if e["type"] == "function"}
    assert {
        "propose",
        "confirm",
        "execute",
        "cancel",
        "getProposal",
        "proposalOfCall",
        "isOwner",
        "owners",
        "required",
        "delay",
    } <= fns
    events = {e["name"] for e in abi if e["type"] == "event"}
    assert {"Proposed", "Confirmed", "Executed", "Cancelled"} <= events


def test_gm_selector_shape():
    # 国密链选择器=SM3(签名)[:4]（旧系统 2026-09-01 真链实证口径）
    sel = fn_selector("anchorCheckpoint(uint256,uint32,bytes32,bytes)", gm=True)
    assert len(sel) == 4
    assert fn_selector("anchorCheckpoint(uint256,uint32,bytes32,bytes)", gm=True) == sel


def test_bytes16_roundtrip():
    # bytes16 定长（nonce/snHash）：编码=右填充 32B；解码截回 16B
    v = bytes.fromhex("11" * 16)
    enc = abi_encode(["bytes16"], [v])
    assert enc == v + bytes(16)
    assert abi_decode(["bytes16"], enc) == [v]


def test_bytes8_bytes32_roundtrip():
    assert abi_decode(["bytes8"], abi_encode(["bytes8"], [bytes(8)])) == [bytes(8)]
    assert abi_decode(["bytes32"], abi_encode(["bytes32"], [bytes(32)])) == [bytes(32)]


def test_bytes16_wrong_length_rejected():
    with pytest.raises(ValueError, match="bytes16 须 16 字节"):
        abi_encode(["bytes16"], [bytes(15)])
