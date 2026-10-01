"""随案协作函（阶段三）：RA 出具→审计台解封——工程值装进信封。

语义：RA 操作员（持 X-RA-Token）把某凭证的 master_cred_hash 封入协作函；
审计员解锁令状时整段粘贴，服务端解封还原 cred hash——双控语义不变
（令状在案核验+RA 解封），用户不再手输 64 位十六进制。

封装：SM4-GCM（kms_domain_key(b"FZ-KMS|collab-code")，AAD 绑定版本域），
码形 "FZC1.<hex>"——前缀即版本，坏码/篡改=KeystoreError 级结构化拒绝。
"""

from __future__ import annotations

import secrets

from app.crypto.sm3 import sm3_bytes
from app.crypto.sm4 import SM4GCM
from app.kms import kms_domain_key

_PREFIX = "FZC1."
_AAD = b"FZ-COLLAB-v1"
_KEY = None


def _key() -> bytes:
    global _KEY
    if _KEY is None:
        _KEY = kms_domain_key(b"FZ-KMS|collab-code")
    return _KEY


class CollabError(Exception):
    """协作函非法（伪造/篡改/格式错误）——调用方映射 400。"""


def seal_collab(cred_hash_hex: str) -> str:
    if len(cred_hash_hex) != 64:
        raise CollabError("cred hash 须 64 hex")
    nonce = secrets.token_bytes(12)
    g = SM4GCM(_key())
    ct, tag = g.encrypt(nonce, bytes.fromhex(cred_hash_hex), _AAD)
    return _PREFIX + (nonce + ct + tag).hex()


def open_collab(code: str) -> str:
    code = code.strip()
    if not code.startswith(_PREFIX):
        raise CollabError("协作函格式非法")
    try:
        raw = bytes.fromhex(code[len(_PREFIX) :])
    except ValueError as e:
        raise CollabError("协作函格式非法") from e
    if len(raw) < 12 + 16 + 1:
        raise CollabError("协作函内容过短")
    nonce, ct, tag = raw[:12], raw[12:-16], raw[-16:]
    g = SM4GCM(_key())
    try:
        pt = g.decrypt(nonce, ct, tag, _AAD)
    except Exception as e:  # noqa: BLE001  GCM 认证失败=伪造/篡改
        raise CollabError("协作函校验失败（伪造或篡改）") from e
    return pt.hex()


def collab_fingerprint(code: str) -> str:
    """协作函指纹（审计台展示用——不泄露内容）。"""
    return sm3_bytes(code.encode()).hex()[:16]


# ---- FZC2（2026-09-28 F 席根修）：函-令状密码学绑定 ----
# FZC1 的函不绑定令状——一张函可解多个令状；解锁实名与令状目标之间无一致性
# 约束（双控仅为流程性）。FZC2 把 (令状哈希 ‖ 凭证哈希) 双双纳入 GCM AAD：
# 函只能用于其出具时针对的那张令状，且只能还原出那份凭证——「双控且范围
# 受限于令状」。FZC1 保留解析（open_collab 兼容），但新出具一律 FZC2。

_PREFIX_V2 = "FZC2."
_AAD_V2 = b"FZ-COLLAB-v2"


def seal_collab_v2(cred_hash_hex: str, warrant_hash_hex: str) -> str:
    """出具 FZC2：函与 (cred, warrant) 双绑定——换令状/换凭证任一即认证失败。"""
    if len(cred_hash_hex) != 64:
        raise CollabError("cred hash 须 64 hex")
    if len(warrant_hash_hex) != 64:
        raise CollabError("warrant hash 须 64 hex")
    cred = bytes.fromhex(cred_hash_hex)
    wh = bytes.fromhex(warrant_hash_hex)
    nonce = secrets.token_bytes(12)
    g = SM4GCM(_key())
    ct, tag = g.encrypt(nonce, cred, _AAD_V2 + wh)
    return _PREFIX_V2 + (nonce + ct + tag).hex()


def open_collab_v2(code: str, warrant_hash_hex: str) -> str:
    """解封 FZC2：warrant_hash 必须与出具时一致，否则 GCM 认证失败=拒绝。"""
    code = code.strip()
    if not code.startswith(_PREFIX_V2):
        raise CollabError("协作函格式非法（须 FZC2）")
    try:
        wh = bytes.fromhex(warrant_hash_hex)
        raw = bytes.fromhex(code[len(_PREFIX_V2) :])
    except ValueError as e:
        raise CollabError("协作函格式非法") from e
    if len(wh) != 32 or len(raw) < 12 + 16 + 1:
        raise CollabError("协作函内容过短")
    nonce, ct, tag = raw[:12], raw[12:-16], raw[-16:]
    g = SM4GCM(_key())
    try:
        pt = g.decrypt(nonce, ct, tag, _AAD_V2 + wh)
    except Exception as e:  # noqa: BLE001  认证失败=伪造/篡改/函与令状不匹配
        raise CollabError("协作函校验失败（伪造/篡改/与令状不匹配）") from e
    return pt.hex()
