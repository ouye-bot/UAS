"""密码 KDF（批 2 密码底座升档）：PBKDF2-HMAC-SM3（RFC 8018，标准构造）。

v4 口径（keystore 信封 v3→v4）：
    KEK = PBKDF2-HMAC-SM3(pass, salt, N, 16B)
    N = FZ_KDF_ITERATIONS（缺省 600000，OWASP 2023 PBKDF2 档——env 可调，
    缺省即高档；实现走 app.crypto.kdf 双引擎，OpenSM3 档 600k≈0.36s）。
标准 HMAC 构造替代旧自建 SM3 迭代链（不抗内存困难、非标准构造——审计
定谳：同仓 app/crypto/kdf.py 的 RFC 8018 实现此前未用于本处）。

独立派生域（激活核对子与 KEK 解耦——批 2-2.2）：
    verifier = PBKDF2-HMAC-SM3(pass, "FZ-ACTIVATE-VERIFY|v1"‖salt2, N, 16B)
info 前缀入盐域=域分离：库泄露拿到的核对子不是可用 KEK（与正文密封件
同级离线猜测面），不再是 KEK 等价物。

legacy：旧 v3 SM3 迭代链（h0=SM3(pass‖salt); h_i=SM3(h_{i-1}‖pass);
KEK=h_{N-1}[0:16]，N=21000）完整保留为 _legacy_v3 不删——存量 v3 密封件
解封（envelope 版本分派）与旧种子核对子兼容读取（激活即换代）。

前端镜像：gcs/web/src/lib/keystore.ts deriveKekV4/_legacyV3/deriveActivationVerifier
（同一 RFC 8018 参数+同一 info 域）——JS↔Python 对拍锚见 test_accounts。
"""

from __future__ import annotations

import os

from app.crypto.kdf import pbkdf2_hmac_sm3
from app.crypto.sm3 import sm3_bytes

KDF_ITERATIONS_DEFAULT = 600_000  # OWASP 2023 PBKDF2 口径（env FZ_KDF_ITERATIONS 可调）
KDF_LEGACY_V3_ITERATIONS = 21_000  # 旧 v3 自建链固定值（兼容面专用，不再升档）
KEK_LEN = 16
KDF_NAME_V4 = "pbkdf2-sm3"  # v4 信封 enc.kdf 标记（与前端 keystore.ts 同源）
_ACTIVATION_INFO = b"FZ-ACTIVATE-VERIFY|v1"  # 激活核对子独立派生域（域分离锚）


def kdf_iterations() -> int:
    """当前生效迭代数（env FZ_KDF_ITERATIONS 优先；缺省=OWASP 2023 高档）。"""
    raw = (os.environ.get("FZ_KDF_ITERATIONS") or "").strip()
    n = int(raw) if raw else KDF_ITERATIONS_DEFAULT
    if n < 1:
        raise ValueError("FZ_KDF_ITERATIONS 须 ≥1")
    return n


def derive_kek(passphrase: str, salt_hex: str, iterations: int | None = None) -> str:
    """v4 KEK（hex 32 字符=16B）——与前端 deriveKekV4 输出逐字节一致。

    iterations=None 时读 env 档（生产缺省 600000）；显式传入用于 v4 信封
    内记录迭代数的解封回放（envelope 按信封内 iter 复算）。"""
    n = iterations if iterations is not None else kdf_iterations()
    if n < 1:
        raise ValueError("KDF 迭代数须 ≥1")
    return pbkdf2_hmac_sm3(
        passphrase.encode(), bytes.fromhex(salt_hex), n, KEK_LEN
    ).hex()


def derive_activation_verifier(
    passphrase: str, salt_hex: str, iterations: int | None = None
) -> str:
    """激活核对子（v1 域）：与 KEK 派生域分离（info 前缀入盐）——库泄露
    只得到离线猜测面，核对子本体不是可用 KEK。输出 32 hex（16B）——
    与 KEK 等长不等于同域：域由 _ACTIVATION_INFO 分离。"""
    n = iterations if iterations is not None else kdf_iterations()
    if n < 1:
        raise ValueError("KDF 迭代数须 ≥1")
    return pbkdf2_hmac_sm3(
        passphrase.encode(), _ACTIVATION_INFO + bytes.fromhex(salt_hex), n, KEK_LEN
    ).hex()


def _legacy_v3(passphrase: str, salt_hex: str, iterations: int = KDF_LEGACY_V3_ITERATIONS) -> str:
    """旧 v3 SM3 迭代链（前端 keystore.ts v3 口径逐字节同构）——存量 v3
    密封件解封与旧种子核对子兼容读取专用；新密封件一律走 v4（derive_kek）。"""
    if iterations < 1:
        raise ValueError("KDF 迭代数须 ≥1")
    pass_bytes = passphrase.encode()
    salt = bytes.fromhex(salt_hex)
    h = sm3_bytes(pass_bytes + salt)
    for _ in range(1, iterations):
        h = sm3_bytes(h + pass_bytes)
    return h[:KEK_LEN].hex()
