"""账户密封信封 v3/v4（服务端镜像 keystore.ts——单一事实源）。

版本分派（批 2-2.1）：
    v3（legacy）：{"v":3,"pk":...,"enc":{salt,nonce,ct,tag}}
                  KEK=_legacy_v3 SM3 迭代链 21000；AAD="FZ-KEYSTORE-v3|pass"
    v4（现行）： {"v":4,"pk":...,"enc":{salt,nonce,ct,tag,kdf,iter}}
                  KEK=PBKDF2-HMAC-SM3(pass,salt,iter,16B)；AAD="FZ-KEYSTORE-v4|pass"
                  kdf 恒="pbkdf2-sm3"（形态门 fail-closed）；iter 随信封落盘
                  ——解封按信封内 iter 复算（env 调档不影响存量可解性）。

迁移语义：v3 存量密封件仍可解（不删旧链）；解封成功后惰性重封 v4
（reseal_v4——同一口令，用户无感；前端登录/解锁路径调用并回传服务端）。
未知版本/缺槽=显式拒绝（不许静默兼容——crypto_audit C2 负例锚）。
"""

from __future__ import annotations

import json
import secrets

from app.accounts.kdf import (
    KDF_LEGACY_V3_ITERATIONS,
    KDF_NAME_V4,
    _legacy_v3,
    derive_kek,
)
from app.crypto.sm4 import SM4GCM

ENVELOPE_V_CURRENT = 4

AAD_V3 = b"FZ-KEYSTORE-v3|pass"
AAD_V4 = b"FZ-KEYSTORE-v4|pass"


def seal_envelope_v4(
    sk_hex: str, pk_hex: str, passphrase: str, *, iterations: int | None = None
) -> str:
    """v4 密封（keystore.ts sealKeystoreV4 同构）：KEK=PBKDF2-HMAC-SM3。"""
    from app.accounts.kdf import kdf_iterations

    if not passphrase:
        raise ValueError("密码不可为空")
    n = iterations if iterations is not None else kdf_iterations()
    salt = secrets.token_hex(16)
    nonce = secrets.token_hex(12)
    kek = bytes.fromhex(derive_kek(passphrase, salt, n))
    ct, tag = SM4GCM(kek).encrypt(bytes.fromhex(nonce), bytes.fromhex(sk_hex), AAD_V4)
    return json.dumps(
        {
            "v": ENVELOPE_V_CURRENT,
            "pk": pk_hex,
            "enc": {
                "salt": salt,
                "nonce": nonce,
                "ct": ct.hex(),
                "tag": tag.hex(),
                "kdf": KDF_NAME_V4,
                "iter": n,
            },
        }
    )


def unseal_envelope(blob_text: str, passphrase: str) -> str:
    """版本分派解封：v3 走旧链（legacy 兼容）、v4 走 PBKDF2（按信封内
    iter）。GCM 认证失败/未知版本/坏形态=抛异常（fail-closed）。"""
    try:
        obj = json.loads(blob_text)
    except ValueError as e:
        raise ValueError("密封件不是有效 JSON") from e
    if not isinstance(obj, dict) or obj.get("v") not in (3, 4):
        raise ValueError("密封件形态不符（v3/v4）")
    if not isinstance(obj.get("enc"), dict):
        raise ValueError("密封件缺少密码密封槽")
    enc = obj["enc"]
    v = obj["v"]
    if v == 3:
        kek_hex = _legacy_v3(passphrase, enc["salt"], KDF_LEGACY_V3_ITERATIONS)
        aad = AAD_V3
    else:
        if enc.get("kdf") != KDF_NAME_V4:
            raise ValueError("密封件 KDF 标记不符（v4 须 pbkdf2-sm3）")
        it = enc.get("iter")
        if not isinstance(it, int) or it < 1:
            raise ValueError("密封件 KDF 迭代数非法")
        kek_hex = derive_kek(passphrase, enc["salt"], it)
        aad = AAD_V4
    pt = SM4GCM(bytes.fromhex(kek_hex)).decrypt(
        bytes.fromhex(enc["nonce"]), bytes.fromhex(enc["ct"]), bytes.fromhex(enc["tag"]), aad
    )
    return pt.hex()


def reseal_v4(blob_text: str, passphrase: str, *, iterations: int | None = None) -> str:
    """惰性重封：解封（任意受支持版本）→同口令 v4 重封——存量 v3 账户
    无感升级。解封失败（密码错）原样抛出，不落任何中间态。"""
    sk_hex = unseal_envelope(blob_text, passphrase)
    pk_hex = json.loads(blob_text)["pk"]
    return seal_envelope_v4(sk_hex, pk_hex, passphrase, iterations=iterations)
