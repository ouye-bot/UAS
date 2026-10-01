"""合约绑定层：abi 驱动的 calldata 编码 / call / 发交易 / 事件解析。

abi 文件为构建期产物（chain/contracts/build/，solc sm3 版编译），
运行时零 solc 依赖。事件解析按 Solidity ABI：topic0=事件签名哈希（国密链
为 SM3，见 abi.sig_hash），indexed 参数入 topics（32B 字），其余参数按类型
abi_decode(data)。哈希口径随 ChainClient.gm 自动切换。
"""

from __future__ import annotations

import json
from pathlib import Path

from app.chain.abi import abi_decode, abi_encode, fn_selector, sig_hash
from app.chain.client import ChainClient, ChainError
from app.chain.signer import TxSigner, UnsignedTx

_BUILD_DIR = Path(__file__).resolve().parents[3] / "contracts" / "build"

_DEFAULT_GAS = 30_000_000  # [核查] python-sdk sendRawTransaction 默认 gasPrice=gasLimit


def assert_receipt_ok(receipt: dict) -> dict:
    """回执 status==0x0 强制（SP-10.2 / N3 纪律）。

    wait_receipt 已有同款检查（client.py），本断言使不变量在消费侧本地成立：
    任何"上链成功"凭据（transactionHash）必须以回执 status==0x0 为据——
    失败交易的哈希禁止落库充当锚定凭据（静默假上链零容忍，双保险防
    client 层未来重构/替换绕过校验面）。
    """
    status = receipt.get("status", "")
    if status != "0x0":
        raise ChainError(f"链上执行失败 status={status} tx={receipt.get('transactionHash', '?')}")
    return receipt


def _canonical_type(t: str) -> str:
    return t


class ContractBinding:
    def __init__(self, client: ChainClient, abi: dict, address: str) -> None:
        self.client = client
        self.abi = abi
        self.address = address
        # 国密链 EVM 哈希全换 SM3（bin 选择器常量对拍实证）；兼容无 gm 属性的 client
        self._gm = getattr(client, "gm", True)
        self._fns = {e["name"]: e for e in abi if e["type"] == "function"}
        self._events = {e["name"]: e for e in abi if e["type"] == "event"}
        self._topic0 = {
            name: "0x"
            + sig_hash(
                f"{name}({','.join(_canonical_type(i['type']) for i in e['inputs'])})",
                gm=self._gm,
            ).hex()
            for name, e in self._events.items()
        }

    def _entry(self, fn: str) -> dict:
        if fn not in self._fns:
            raise ValueError(f"abi 无函数 {fn}")
        return self._fns[fn]

    def encode_calldata(self, fn: str, args: list) -> bytes:
        entry = self._entry(fn)
        types = [i["type"] for i in entry["inputs"]]
        if len(types) != len(args):
            raise ValueError(f"{fn} 参数数量不符: 期望 {len(types)} 得 {len(args)}")
        return fn_selector(f"{fn}({','.join(types)})", gm=self._gm) + abi_encode(types, args)

    def call_fn(self, fn: str, args: list) -> list:
        entry = self._entry(fn)
        output = self.client.call(self.address, self.encode_calldata(fn, args))
        raw = bytes.fromhex(output.removeprefix("0x"))
        types = [o["type"] for o in entry["outputs"]]
        return abi_decode(types, raw)

    def send_fn(self, signer: TxSigner, fn: str, args: list) -> dict:
        tx = UnsignedTx(
            randomid=signer.new_randomid(),
            gas_price=_DEFAULT_GAS,
            gas_limit=_DEFAULT_GAS,
            block_limit=self.client.block_limit(),
            to=bytes.fromhex(self.address.removeprefix("0x")),
            value=0,
            data=self.encode_calldata(fn, args),
            # fiscoChainId 与 groupId 同源（链 config chain.id=1）
            fisco_chain_id=self.client.group_id,
            group_id=self.client.group_id,
        )
        txhash = self.client.send_raw_tx(signer.sign_tx(tx))
        return assert_receipt_ok(self.client.wait_receipt(txhash))

    def decode_logs(self, receipt: dict) -> list[dict]:
        out: list[dict] = []
        for log in receipt.get("logs", []):
            topics = log.get("topics", [])
            if not topics:
                continue
            # 只认本合约地址发出的日志（SP-10.4.1）：退役合约同签名事件
            # （旧地址仍在链上可写）不得被误归因到当前绑定合约的投影。
            if str(log.get("address", "")).lower() != self.address.lower():
                continue
            for name, ev in self._events.items():
                if topics[0] != self._topic0.get(name):
                    continue
                indexed = [i for i in ev["inputs"] if i["indexed"]]
                plain = [i for i in ev["inputs"] if not i["indexed"]]
                event: dict = {"event": name, "address": log.get("address")}
                for i, param in enumerate(indexed):
                    raw = bytes.fromhex(topics[i + 1].removeprefix("0x"))
                    event[param["name"]] = self._decode_topic(param["type"], raw)
                data = bytes.fromhex(log.get("data", "0x").removeprefix("0x"))
                values = abi_decode([p["type"] for p in plain], data)
                for param, value in zip(plain, values, strict=True):
                    event[param["name"]] = value
                out.append(event)
        return out

    @staticmethod
    def _decode_topic(typ: str, raw: bytes) -> object:
        if typ == "bytes32":
            return raw
        if typ == "address":
            return "0x" + raw[12:].hex()
        if typ.startswith("uint"):
            return int.from_bytes(raw, "big")
        raise ValueError(f"indexed 类型不支持: {typ}")


def load_binding(name: str, client: ChainClient, address: str) -> ContractBinding:
    """从构建产物加载 abi 并绑定地址。"""
    abi_path = _BUILD_DIR / f"{name}.abi"
    if not abi_path.exists():
        raise FileNotFoundError(f"abi 缺失（先跑合约编译）: {abi_path}")
    abi = json.loads(abi_path.read_text())
    return ContractBinding(client, abi, address)
