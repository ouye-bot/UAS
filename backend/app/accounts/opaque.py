"""OPAQUE 服务端协议（⑫O-3 批——设计合同 §2/§6；零口令派生材料红线）。

账面=OPRF 记录四列（masking_key/salt/iter/key_id）+v6 信封——服务器永不接触
password/rwd/KEK：masking_key 由客户端派生上传（设计 D-6）、盐/迭代客户端生成
上传（D-8——密封先于账户存在）、服务器仅在 masked_response 掩码面使用 masking_key
（§1.4 ④ 双方可派；拖库者得 masking_key+信封而无 k_oprf 仍在线——归约 §5.5 面等价）。

evaluate 真实求值唯一条件集（§6.1——其余一律 fake）：
  (a) 账户存在且 OPAQUE 记录在账；或
  (b) status==pending_activation（激活序需真实 β）；或
  (c) 请求携本账户有效会话且会话属主==请求 username（§5.1 惰性重封/§5.6 改密）。
fake 形态（RFC 9807 §6.3.2.2 原文——瑕疵 d 注记在案）：随机 masking_key+
定长全零 envelope 槽（长度=canonical v6 信封字节长）——线上伪随机性由 pad 保证。

masked_response（归约 §5.4 记式逐字+消费口径钉定 §6.3）：
    pad = Expand-SM3(masking_key, masking_nonce‖"MaskedResponse", Npk+Nn+Nm)
    masked_response = pad[:Npk+Nm] ⊕ (server_public_key ‖ envelope)
Npk=64B（engine_pub_hex——服务端身份锚，D-7）、Nn=32B（RFC §6.3.1 记账对齐）、
Nm=v6 信封定长字节。
"""

from __future__ import annotations

import secrets

from app.accounts.envelope import standard_v6_envelope_len
from app.accounts.kdf import kdf_iterations
from app.accounts.service import (
    AccountError,
    get_account,
    log_account_action,
    opaque_enabled,
)
from app.crypto.kdf import hkdf_sm3_expand
from app.crypto.oprf import OPRFError, blind_evaluate, parse_point_element

NPK = 64  # server_public_key 槽（64B——engine_pub_hex）
MASKING_NONCE_LEN = 32  # Nn（RFC 9807 §6.3.1 记账对齐）
PAD_LABEL = b"MaskedResponse"  # pad info 串（FZ 适配名——RFC 原文 CredentialResponsePad，瑕疵 d）
MASKING_KEY_LEN = 32  # ④Expand 输出宽（=SM3 HashLen，RFC Nh 同口径）
MASKING_KEY_INFO = b"FZ-OPAQUE-MaskingKey|v1"  # §1.4 ④ info 域（参考客户端同源）
ENVELOPE_KEY_INFO = (
    b"FZ-OPAQUE-EnvelopeKey|v1"  # §1.4 ⑤ info 域（envelope.ENVELOPE_KEY_INFO_V6 别名导出）
)


def server_public_key() -> bytes:
    """masked_response 的 server_public_key 槽（D-7——engine 验签公钥 64B 公开锚）。"""
    from app.kms import engine_pub_hex

    return bytes.fromhex(engine_pub_hex())


def credential_response_pad(masking_key: bytes, masking_nonce: bytes, payload_len: int) -> bytes:
    """§5.4 记式逐字：Expand(masking_key, masking_nonce‖"MaskedResponse", Npk+Nn+Nm)
    ——异或消费取前 Npk+Nm 字节（Nn 项按记式保留在 pad 长度内，§6.3 钉定）。"""
    if len(masking_key) != MASKING_KEY_LEN:
        raise ValueError("masking_key 须 32B")
    if len(masking_nonce) != MASKING_NONCE_LEN:
        raise ValueError("masking_nonce 须 32B")
    pad = hkdf_sm3_expand(
        masking_key, masking_nonce + PAD_LABEL, NPK + MASKING_NONCE_LEN + payload_len
    )
    return pad[: NPK + payload_len]


def mask_credential_response(masking_key: bytes, masking_nonce: bytes, envelope: bytes) -> bytes:
    """masked_response = pad ⊕ (server_public_key ‖ envelope)——定长 Npk+Nm。"""
    pad = credential_response_pad(masking_key, masking_nonce, len(envelope))
    payload = server_public_key() + envelope
    return bytes(a ^ b for a, b in zip(pad, payload, strict=True))


def unmask_credential_response(masking_key: bytes, masking_nonce: bytes, masked: bytes) -> bytes:
    """客户端解掩码（参考客户端/测试面——O-5 JS 同构造对拍锚定）：
    server_pub 前缀不符=解掩码败（错口令的第一道客户端判据——pad 伪随机下
    前缀即 oracle）。"""
    if len(masked) <= NPK:
        raise ValueError("masked_response 长度非法")
    pad = credential_response_pad(masking_key, masking_nonce, len(masked) - NPK)
    payload = bytes(a ^ b for a, b in zip(pad, masked, strict=True))
    if payload[:NPK] != server_public_key():
        raise ValueError("解掩码失败（server_pub 前缀不符——口令错误或信封被篡改）")
    return payload[NPK:]


def build_evaluate_response(
    session, username: str, alpha_hex: str, session_owner: str | None = None
) -> dict:
    """evaluate 恒五键响应（§2.1）——真实/fake 双态同形同长（§6.1/§6.2）。
    O-1 点校验在标量乘之前（fail-closed）；k_oprf 经 KMS 面按记录 key_id 取钥
    （§4.3 轮换判别——皆不匹配=401 记录作废引导重置，设计原文明示语义）。"""
    parse_point_element(alpha_hex)  # O-1——规范前置条件（无效曲线防线）
    row = None
    try:
        row = get_account(session, username)
    except AccountError:
        row = None
    has_record = bool(row is not None and row.opaque_masking_key_hex and row.opaque_key_id)
    real = has_record or (
        row is not None
        and (
            row.status == "pending_activation"
            or (session_owner is not None and session_owner == username)
        )
    )
    masking_nonce = secrets.token_bytes(MASKING_NONCE_LEN)
    if real and has_record:
        k_hex = _resolve_record_key(row.opaque_key_id)
        beta = blind_evaluate(alpha_hex, k_hex)
        masking_key = bytes.fromhex(row.opaque_masking_key_hex)
        envelope = row.sealed_blob.encode()  # canonical 存储（§1.2 定长锚）
        salt_out, iter_out = row.opaque_kdf_salt_hex, int(row.opaque_kdf_iter)
    else:
        # fake（或真实但无记录的 β-only 态——掩码字段随机，客户端流程不消费）
        beta = blind_evaluate(alpha_hex, _current_key_hex())
        masking_key = secrets.token_bytes(MASKING_KEY_LEN)
        envelope = b"\x00" * standard_v6_envelope_len()  # RFC §6.3.2.2 定长全零槽
        salt_out, iter_out = secrets.token_hex(16), kdf_iterations()
    masked = mask_credential_response(masking_key, masking_nonce, envelope)
    return {
        "evaluated_message": beta,
        "masking_nonce": masking_nonce.hex(),
        "masked_response": masked.hex(),
        "kdf_salt_hex": salt_out,
        "kdf_iter": iter_out,
    }


def _current_key_hex() -> str:
    from app.kms import oprf_key

    return oprf_key()


def _resolve_record_key(key_id: str) -> str:
    """按记录指纹取钥（§4.3）：current 优先/old 只读过渡窗/皆不匹配=401 记录作废
    （k 已不可得 ⟹ rwd 永不可派——设计原文明示语义；台账留痕由调用方写入）。"""
    from app.kms import oprf_key_for

    k_hex = oprf_key_for(key_id)
    if k_hex is None:
        raise AccountError(
            "opaque_record_dead",
            "该账户的 OPAQUE 钥代已失效——请联系机构重置凭证",
            401,
        )
    return k_hex


def audit_evaluate_failure(session, *, action: str, username: str, detail: str) -> None:
    """evaluate 异常事件台账（§6.6——append-only 同流；正常 evaluate 不入台账）。"""
    log_account_action(
        session, action=action, username=username, operator="self_attempt", detail=detail
    )


__all__ = [
    "ENVELOPE_KEY_INFO",
    "MASKING_KEY_INFO",
    "MASKING_KEY_LEN",
    "MASKING_NONCE_LEN",
    "NPK",
    "OPRFError",
    "build_evaluate_response",
    "credential_response_pad",
    "mask_credential_response",
    "opaque_enabled",
    "server_public_key",
    "unmask_credential_response",
]
