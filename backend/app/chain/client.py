"""FISCO BCOS 2.x JSON-RPC 客户端（httpx，免 TLS 证书直连 8545）。

读路径与发交易全走 JSON-RPC：call 参数无块参数（探针实测带 latest 报
INVALID_PARAMS）；block_limit = current + 500（python-sdk deltablocklimit 对源）。
gm=True（默认，本系统目标=国密链）：合约层选择器/事件 topic0 用 SM3——
FISCO 2.x 国密链 EVM 层哈希整体换 SM3（bin 常量对拍实证，2026-09-01）。

🔴 call 的 from 必须是真实账户地址（from_addr 必填）：FISCO 2.x 对
from=零地址的 call 静默返回空 output 且 status 仍 0x0（2026-09-01 真链
四形态对拍实证：from=0x00…0 → output 0x；from=真实账户 → 完整 ABI 回读；
gas/gasPrice/value 格式均无关）。响应 status 非 0x0 视为失败
（python-sdk 同款检查；status 键只在 result 为 dict 时存在）。
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.chain.signer import TxSigner

_DELTABLOCKLIMIT = 500  # [核查] python-sdk bcosclient.py:391


class ChainError(Exception):
    pass


class ChainClient:
    def __init__(
        self,
        rpc_url: str,
        group_id: int = 1,
        timeout: float = 10.0,
        http: httpx.Client | None = None,
        gm: bool = True,
        from_addr: str | None = None,
    ) -> None:
        self._url = rpc_url
        self._group = group_id
        self._breaker_until = 0.0  # R3-1.4 熔断冷却窗截止（monotonic）
        # trust_env=False：链 RPC 是本机/内网直连，绝不可走系统代理
        # （系统代理进程死掉时整条链写面瘫痪——红队期实测教训）
        self._http = http or httpx.Client(timeout=timeout, trust_env=False)
        self.gm = gm
        self._from = from_addr

        # SP-13.2 block_limit TTL 缓存态
        self._bl_cache: int | None = None
        self._bl_cached_at: float = 0.0
        import threading

        self._bl_lock = threading.Lock()

    @property
    def group_id(self) -> int:
        return self._group

    def rpc(self, method: str, params: list) -> Any:
        # R3-1.4 链熔断（评审 P2-4）：连接失败后 5s 冷却窗内直接快速失败，
        # 免得链僵死窗内每请求实付 10s 超时（登记/受理/面板全慢挂）。
        now = time.monotonic()
        if now < self._breaker_until:
            raise ChainError(
                f"chain_unavailable: 链不可达熔断窗（剩余 {self._breaker_until - now:.1f}s）"
            )
        try:
            resp = self._http.post(
                self._url,
                json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
            )
        except httpx.HTTPError as e:
            self._breaker_until = time.monotonic() + 5.0  # R3-1.4 熔断 5s 冷却
            raise ChainError(f"RPC 连接失败: {e}") from e
        if resp.status_code != 200:
            raise ChainError(f"RPC HTTP {resp.status_code}")
        body = resp.json()
        if "error" in body:
            raise ChainError(f"RPC {method}: {body['error'].get('message')}")
        return body.get("result")

    # ---- 链状态 ----

    def client_version(self) -> str:
        return str(self.rpc("getClientVersion", [])["FISCO-BCOS Version"])

    def block_number(self) -> int:
        return int(self.rpc("getBlockNumber", [self._group]), 16)

    def block_limit(self) -> int:
        # SP-13.2：短 TTL 缓存（2s）——热路径每次 send 省 getBlockNumber RPC；
        # FISCO blockLimit 窗口（1000 块）远宽于 TTL，链高滞后 2s 无碍入块
        now = time.monotonic()
        with self._bl_lock:
            if self._bl_cache is not None and now - self._bl_cached_at < 2.0:
                return self._bl_cache
            limit = self.block_number() + _DELTABLOCKLIMIT
            self._bl_cache = limit
            self._bl_cached_at = now
            return limit

    # ---- 交易 ----

    def send_raw_tx(self, raw: bytes, signer: TxSigner | None = None) -> str:
        del signer  # 预留：多签账户场景显式传签名者
        return str(self.rpc("sendRawTransaction", [self._group, "0x" + raw.hex()]))

    def get_tx_receipt(self, tx_hash: str) -> dict | None:
        return self.rpc("getTransactionReceipt", [self._group, tx_hash])

    def get_block_by_number(self, n: int, include_txs: bool = False) -> dict | None:
        return self.rpc("getBlockByNumber", [self._group, hex(n), include_txs])

    def wait_receipt(self, tx_hash: str, timeout_s: float = 15.0, poll_s: float = 0.2) -> dict:
        """SP-13.2 自适应轮询：首 poll=poll_s（默认 0.2s——共识正常时首轮即中），
        此后 ×1.5 指数退避至 1s cap（链慢时防打爆 RPC）。"""
        deadline = time.monotonic() + timeout_s
        interval = poll_s
        while time.monotonic() < deadline:
            receipt = self.get_tx_receipt(tx_hash)
            if receipt is not None:
                status = receipt.get("status", "")
                if status != "0x0":
                    raise ChainError(f"回执状态非成功: {status}")
                return receipt
            time.sleep(interval)
            interval = min(interval * 1.5, 1.0)
        raise ChainError(f"等待回执超时: {tx_hash}")

    def call(self, to: str, data: bytes) -> str:
        if not self._from:
            raise ChainError(
                "call 需要 from_addr（ChainClient(rpc, from_addr=账户地址)）："
                "FISCO 2.x 零地址 from 静默返回空 output 且 status 仍 0x0"
            )
        result = self.rpc(
            "call",
            [
                self._group,
                {
                    "from": self._from,
                    "to": to,
                    "gas": hex(30_000_000),
                    "gasPrice": hex(1),
                    "value": "0x0",
                    "data": "0x" + data.hex(),
                },
            ],
        )
        if isinstance(result, dict):
            status = result.get("status", "0x0")
            if status != "0x0":
                raise ChainError(f"call 失败: status={status}")
            return str(result.get("output", "0x"))
        return str(result)
