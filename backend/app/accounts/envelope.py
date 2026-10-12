"""账户密封信封 v3/v4/v6（服务端镜像 keystore.ts——单一事实源）。

版本分派（批 2-2.1；⑫O-3 批增 v6）：
    v3（legacy）：{"v":3,"pk":...,"enc":{salt,nonce,ct,tag}}
                  KEK=_legacy_v3 SM3 迭代链 21000；AAD="FZ-KEYSTORE-v3|pass"
    v4（现行）： {"v":4,"pk":...,"enc":{salt,nonce,ct,tag,kdf,iter}}
                  KEK=PBKDF2-HMAC-SM3(pass,salt,iter,16B)；AAD="FZ-KEYSTORE-v4|pass"
                  kdf 恒="pbkdf2-sm3"（形态门 fail-closed）；iter 随信封落盘
                  ——解封按信封内 iter 复算（env 调档不影响存量可解性）。
    v6（⑫OPAQUE）：{"v":6,"pk":...,"enc":{kdf,env_nonce,nonce,ct,tag}}
                  KEK=Expand-SM3(rwd, env_nonce‖"FZ-OPAQUE-EnvelopeKey|v1",16B)
                  ——§5.3 单链⑤（rwd 派生——口令不经任何直连 KDF）；AAD=
                  "FZ-OPAQUE-ENV-v6|rwd"；kdf 恒="opaque-rwd-v1"；**定长不变式**
                  （全字段定宽+canonical 序列化⟹信封串字节长恒定——§6.2 masked_
                  response 的 Nm 锚）。服务器无 rwd ⟹ 不可解封（零口令材料红线的
                  正面形态）；本模块的 v6 open 仅服务参考客户端/测试面。
    资料槽 v6：  {"v":6,"slot":"profile","enc":{…}}——KEK=Expand(rwd,
                  profile_env_nonce‖"FZ-OPAQUE-ProfileKey|v1",16)（独立域，D-4）。

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
from app.crypto.kdf import hkdf_sm3_expand
from app.crypto.sm4 import SM4GCM

ENVELOPE_V_CURRENT = 4
ENVELOPE_V_OPAQUE = 6

AAD_V3 = b"FZ-KEYSTORE-v3|pass"
AAD_V4 = b"FZ-KEYSTORE-v4|pass"
KDF_NAME_V6 = "opaque-rwd-v1"  # v6 信封 enc.kdf 标记（形态门 fail-closed）
AAD_V6 = b"FZ-OPAQUE-ENV-v6|rwd"  # 设计 D-2（KEK 源语义入 AAD——v4 同款工艺）
AAD_V6_PROFILE = b"FZ-OPAQUE-PROFILE-v6|rwd"
ENVELOPE_KEY_INFO_V6 = b"FZ-OPAQUE-EnvelopeKey|v1"  # §1.4 ⑤ info 域
PROFILE_KEY_INFO_V6 = b"FZ-OPAQUE-ProfileKey|v1"  # 资料槽独立域（D-4）


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


# ---- v6（⑫OPAQUE——rwd 派生信封；设计 §1.2 字节级字段表照单施工） ----


def canonical_v6(
    pk_hex: str,
    env_nonce_hex: str,
    nonce_hex: str,
    ct_hex: str,
    tag_hex: str,
    *,
    slot: str | None = None,
) -> str:
    """v6 规范形态（定长不变式的载体）：固定键序+compact 分隔符+小写 hex——
    全字段定宽 ⟹ 串字节长恒定（§6.2 masked_response 的 Nm 锚）。"""
    obj: dict = {
        "v": ENVELOPE_V_OPAQUE,
        "pk": pk_hex.lower(),
    }
    if slot is not None:
        obj["slot"] = slot
    obj["enc"] = {
        "kdf": KDF_NAME_V6,
        "env_nonce": env_nonce_hex.lower(),
        "nonce": nonce_hex.lower(),
        "ct": ct_hex.lower(),
        "tag": tag_hex.lower(),
    }
    return json.dumps(obj, separators=(",", ":"))


def standard_v6_envelope_len() -> int:
    """标准 v6 信封字节长（全字段定宽的常量——fake-record 零槽长度锚，§6.1）。"""
    return len(canonical_v6("0" * 128, "0" * 24, "0" * 24, "0" * 64, "0" * 32))


def seal_envelope_v6(
    sk_hex: str,
    pk_hex: str,
    rwd_hex: str,
    *,
    env_nonce_hex: str | None = None,
    nonce_hex: str | None = None,
) -> str:
    """v6 密封（参考客户端/测试面——生产客户端=JS，O-5 逐字节对拍锚定）：
    KEK=Expand-SM3(rwd, env_nonce‖"FZ-OPAQUE-EnvelopeKey|v1",16)（§1.4 ⑤ 唯一单链
    ——改链=整体替换+重走评审）；SM4-GCM AAD 绑定 v6 槽位（D-2）。
    env_nonce_hex/nonce_hex 可钉定（黄金向量面——双端逐字节对拍）。"""
    if not isinstance(rwd_hex, str) or len(rwd_hex) != 64:
        raise ValueError("rwd 须 32B hex")
    env_nonce = env_nonce_hex or secrets.token_hex(12)
    kek = hkdf_sm3_expand(
        bytes.fromhex(rwd_hex), bytes.fromhex(env_nonce) + ENVELOPE_KEY_INFO_V6, 16
    )
    nonce = nonce_hex or secrets.token_hex(12)
    ct, tag = SM4GCM(kek).encrypt(bytes.fromhex(nonce), bytes.fromhex(sk_hex), AAD_V6)
    return canonical_v6(pk_hex, env_nonce, nonce, ct.hex(), tag.hex())


def open_envelope_v6(blob_text: str, rwd_hex: str) -> str:
    """v6 解封（客户端域——rwd 侧；服务器无 rwd 即不可解封=零口令材料红线的
    正面形态；本函数服务参考客户端/测试面）。形态门 fail-closed。"""
    try:
        obj = json.loads(blob_text)
    except ValueError as e:
        raise ValueError("密封件不是有效 JSON") from e
    if (
        not isinstance(obj, dict)
        or obj.get("v") != ENVELOPE_V_OPAQUE
        or isinstance(obj.get("enc"), dict) is False
    ):
        raise ValueError("密封件形态不符（v6）")
    enc = obj["enc"]
    if enc.get("kdf") != KDF_NAME_V6:
        raise ValueError("密封件 KDF 标记不符（v6 须 opaque-rwd-v1）")
    env_nonce, nonce, ct, tag = (
        enc.get("env_nonce"),
        enc.get("nonce"),
        enc.get("ct"),
        enc.get("tag"),
    )
    if not all(
        isinstance(v, str) and len(v) in (24, 24, 64, 32) and len(v) % 2 == 0
        for v in (env_nonce, nonce, ct, tag)
    ):
        raise ValueError("密封槽字段非法（v6 定宽域）")
    kek = hkdf_sm3_expand(
        bytes.fromhex(rwd_hex), bytes.fromhex(env_nonce) + ENVELOPE_KEY_INFO_V6, 16
    )
    pt = SM4GCM(kek).decrypt(bytes.fromhex(nonce), bytes.fromhex(ct), bytes.fromhex(tag), AAD_V6)
    return pt.hex()


def seal_profile_slot_v6(
    payload: bytes, rwd_hex: str, *, profile_env_nonce_hex: str | None = None
) -> str:
    """资料槽 v6 密封（KEK=独立 ProfileKey 域——D-4；载荷={cred,form} 序列化）。
    槽无 pk 槽语义（payload 自持 cred/form）——canonical 的 pk 位以零串占位保定宽
    （形态门按 slot 分派核对）。"""
    if not isinstance(rwd_hex, str) or len(rwd_hex) != 64:
        raise ValueError("rwd 须 32B hex")
    env_nonce = profile_env_nonce_hex or secrets.token_hex(12)
    kek = hkdf_sm3_expand(
        bytes.fromhex(rwd_hex), bytes.fromhex(env_nonce) + PROFILE_KEY_INFO_V6, 16
    )
    nonce = secrets.token_hex(12)
    ct, tag = SM4GCM(kek).encrypt(bytes.fromhex(nonce), payload, AAD_V6_PROFILE)
    return canonical_v6("0" * 128, env_nonce, nonce, ct.hex(), tag.hex(), slot="profile")


def open_profile_slot_v6(blob_text: str, rwd_hex: str) -> bytes:
    """资料槽 v6 解封（参考客户端/测试面）。"""
    obj = json.loads(blob_text)
    if (
        not isinstance(obj, dict)
        or obj.get("v") != ENVELOPE_V_OPAQUE
        or obj.get("slot") != "profile"
    ):
        raise ValueError("资料槽形态不符（v6 profile）")
    enc = obj["enc"]
    if enc.get("kdf") != KDF_NAME_V6:
        raise ValueError("资料槽 KDF 标记不符（v6 须 opaque-rwd-v1）")
    kek = hkdf_sm3_expand(
        bytes.fromhex(rwd_hex), bytes.fromhex(enc["env_nonce"]) + PROFILE_KEY_INFO_V6, 16
    )
    return SM4GCM(kek).decrypt(
        bytes.fromhex(enc["nonce"]),
        bytes.fromhex(enc["ct"]),
        bytes.fromhex(enc["tag"]),
        AAD_V6_PROFILE,
    )
