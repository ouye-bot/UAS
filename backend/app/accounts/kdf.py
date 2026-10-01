"""SM3 迭代链 KDF——前端 keystore.ts deriveKek 的服务端镜像（逐字节同构）。

用途：①预置机构账户初始密码核对子的生成/核对（seed_accounts.py 生成、
首登激活核对）——核对子=KEK 本身（密码派生值），激活后即焚；②与前端
KDF 的交叉对拍锚（test_accounts.py 持有 JS 侧算出的固定向量）。

构造（与 gcs/web/src/lib/keystore.ts 同一公开可审计自建构造）：
    h0 = SM3(pass ‖ salt)
    h_i = SM3(h_{i-1} ‖ pass)   （i=1..N-1）
    KEK = h_{N-1}[0:16]         （hex 32 字符）
迭代数=21000（OWASP 2023 对齐值，与前端 KDF_ITERATIONS 同源）。
"""

from __future__ import annotations

from app.crypto.sm3 import sm3_bytes

KDF_ITERATIONS = 21_000
KEK_LEN = 16


def derive_kek(passphrase: str, salt_hex: str, iterations: int = KDF_ITERATIONS) -> str:
    """与前端 deriveKek 输出逐字节一致（hex 32 字符）。"""
    if iterations < 1:
        raise ValueError("KDF 迭代数须 ≥1")
    pass_bytes = passphrase.encode()
    salt = bytes.fromhex(salt_hex)
    h = sm3_bytes(pass_bytes + salt)
    for _ in range(1, iterations):
        h = sm3_bytes(h + pass_bytes)
    return h[:KEK_LEN].hex()
