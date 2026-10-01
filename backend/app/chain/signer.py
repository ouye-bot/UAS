"""国密交易签名器（FISCO BCOS 2.x 国密链，格式对源 python-sdk 四文件锚定）。

- 交易体 RLP 十字段：randomid/gasPrice/gasLimit/blockLimit/to(20B,空=部署)/
  value/data/fiscoChainId/groupId/extraData。
- 签名摘要 = SM3(Z_A ‖ SM3(rlp(十字段)))——节点验证方程全链条对源锚定：
  ① Transaction::hash(WithoutSignature) = crypto::Hash(rlp)，GM 链分派为 sm3
    （CryptoInterface.h）；② SM2::verify 内部 e = SM3(Z_A ‖ 传入哈希) 再入 SM2
    方程（libdevcrypto/sm2/sm2.cpp，ZA 默认 ID "1234567812345678"）。
  2026-09-01 真链三轮实证：keccak 摘要 / 裸 SM3 / 裸 keccak 均被 InvalidSignature
  拒收，唯此双层 SM3+ZA 口径与节点方程逐项对应（keccak 仅用于 ABI/EVM 层）。
- SM2 签名 = 裸摘要口径（e=摘要直接入方程，无 ZA——节点同口径验签；
  python-sdk Signer_GM.sign → CryptSM2.sign 对源锚定。Z 路径仅用于消息级签名）。
- v = 512-bit 完整公钥 int（国密验签不可恢复公钥，节点自 v 取公钥验签）。
- 随机性红线：randomid 用 secrets（python-sdk 用 random.randint，此处不沿用）。
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from app.chain.rlp import rlp_encode_fields
from app.crypto.sm2 import _digest_z, pubkey_from_priv
from app.crypto.sm2 import sign_digest as sm2_sign_digest
from app.crypto.sm3 import sm3_bytes


@dataclass(frozen=True)
class UnsignedTx:
    randomid: int
    gas_price: int
    gas_limit: int
    block_limit: int
    to: bytes  # 20B；部署交易 = b""
    value: int
    data: bytes
    fisco_chain_id: int
    group_id: int
    extra_data: bytes = b""

    def __post_init__(self) -> None:
        if len(self.to) not in (0, 20):
            raise ValueError("to 须 20 字节（部署交易留空）")

    def rlp_fields(self) -> list[int | bytes]:
        return [
            self.randomid,
            self.gas_price,
            self.gas_limit,
            self.block_limit,
            self.to,
            self.value,
            self.data,
            self.fisco_chain_id,
            self.group_id,
            self.extra_data,
        ]


def unsigned_rlp(tx: UnsignedTx) -> bytes:
    """待签名 RLP（测试与冒烟复用）。"""
    return rlp_encode_fields(tx.rlp_fields())


class TxSigner:
    def __init__(self, priv_hex: str) -> None:
        if len(priv_hex) != 64:
            raise ValueError("私钥须 64 hex")
        self._priv = priv_hex
        self._pub = pubkey_from_priv(priv_hex)

    @property
    def public_key_hex(self) -> str:
        """128 hex（x||y，不含 04 前缀）——python-sdk CryptSM2 同口径。"""
        return self._pub

    @property
    def address(self) -> str:
        """0x+40hex = SM3(pub 64B)[-20:]（国密口径；链上回执 from 冒烟终审）。"""
        return "0x" + sm3_bytes(bytes.fromhex(self._pub))[-20:].hex()

    def sign_vrs(self, digest: bytes) -> tuple[int, int, int]:
        """摘要 → (v, r, s)：v=完整公钥 int（FISCO 国密交易核心特征）。

        签名走裸摘要原语（e=digest 直接入 SM2 方程，无 ZA）——节点 sm2Sign
        对传入哈希直接签名验签（SM2Signature.cpp 对源）。
        """
        sig = sm2_sign_digest(self._priv, digest)  # r||s 128 hex，secrets k
        r = int(sig[:64], 16)
        s = int(sig[64:], 16)
        v = int(self._pub, 16)
        return v, r, s

    def sign_tx(self, tx: UnsignedTx) -> bytes:
        """签名并序列化 → raw tx bytes（sendRawTransaction 的 hex 参数）。

        摘要 = SM3(Z_A ‖ SM3(rlp(十字段)))：外层 SM3+ZA 为节点 SM2::verify
        内部流程（sm2.cpp），内层 SM3 为 GM 链 crypto::Hash 对交易 RLP 的
        分派（CryptoInterface.h）。对源锚定，2026-09-01 真链实证。
        """
        txhash = sm3_bytes(unsigned_rlp(tx))  # 节点 hash(WithoutSignature)
        e = _digest_z(self._pub, txhash)  # 节点 SM2::verify 内层 SM3(Z_A ‖ txhash)
        v, r, s = self.sign_vrs(e)
        return rlp_encode_fields(tx.rlp_fields() + [v, r, s])

    def new_randomid(self) -> int:
        """CSPRNG randomid（python-sdk 用 random.randint，红线不沿用）。"""
        return secrets.randbelow(10**9)
