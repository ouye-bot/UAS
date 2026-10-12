"""OPAQUE 参考客户端（Python——O-5 JS 实现的逐字节对拍参照；⑫O-3 测试面）。

线协议=blind→（POST /auth/opaque/evaluate）→unblind→rwd→解掩码→解封（设计 §2.3）。
本参考把 blind 与 unseal 分离——调用方持 alpha 去 POST、持 (r, 响应体) 回来解封。
注册材料 shortcut 在进程内取服务器同钥直算 evaluate——与线协议盲化回环的等价性
由 test_crypto_opaque.test_oprf_roundtrip_correctness 专测锚定。

§1.4 rwd 单链（唯一公式——设计合同；改链=整体替换+重走评审）：
    oprf_output = Extract("", "FZ-OPAQUE-Finalize|v1"‖Y‖)     # ①
    stretched   = PBKDF2-HMAC-SM3(oprf_output, salt, iter)    # ②（输出 32B——D-10）
    rwd         = Extract("", oprf_output ‖ stretched)        # ③
    masking_key = Expand(rwd, "FZ-OPAQUE-MaskingKey|v1", 32)  # ④
    KEK         = Expand(rwd, env_nonce‖"FZ-OPAQUE-EnvelopeKey|v1", 16)  # ⑤
盐/迭代数客户端生成、注册时上传、服务端账面存储（D-8——密封先于账户存在，
服务端无法预先生成；登录经 evaluate 响应回传账面值）。
"""

from __future__ import annotations

import secrets

from app.accounts.envelope import open_envelope_v6, seal_envelope_v6
from app.accounts.opaque import (
    ENVELOPE_KEY_INFO,
    MASKING_KEY_INFO,
    unmask_credential_response,
)
from app.crypto.kdf import hkdf_sm3_expand, hkdf_sm3_extract, pbkdf2_hmac_sm3
from app.crypto.oprf import (
    blind,
    evaluate,
    oprf_input_bytes,
    oprf_output_from_y,
    unblind,
)

STRETCHED_LEN = 32  # ②Stretch 输出（D-10 钉定——SM3 摘要宽；设计 §1.4 未钉长度处）


def derive_rwd_chain(oprf_output: bytes, salt_hex: str, iterations: int) -> tuple[bytes, bytes]:
    """②③④ 三步（①⑤ 见 oprf.oprf_output_from_y / envelope.seal_envelope_v6）。"""
    stretched = pbkdf2_hmac_sm3(oprf_output, bytes.fromhex(salt_hex), iterations, STRETCHED_LEN)
    rwd = hkdf_sm3_extract(b"", oprf_output + stretched)
    masking_key = hkdf_sm3_expand(rwd, MASKING_KEY_INFO, 32)
    return rwd, masking_key


def kek_from_rwd(rwd: bytes, env_nonce_hex: str) -> bytes:
    """⑤ 信封钥（envelope.seal/open 的 KEK 同源——参考面显式可读）。"""
    return hkdf_sm3_expand(rwd, bytes.fromhex(env_nonce_hex) + ENVELOPE_KEY_INFO, 16)


def ref_seal_v6(
    username: str,
    password: str,
    sk_hex: str,
    pk_hex: str,
    *,
    k_hex: str | None = None,
    salt_hex: str | None = None,
    iterations: int = 600_000,
) -> dict:
    """注册材料四件套（v6 信封+masking_key+盐/迭代——/auth/register·activate 上传体）。"""
    from app.kms import oprf_key

    k = k_hex or oprf_key()
    msg = oprf_input_bytes(username, password)
    y_hex = evaluate(msg, k)  # 进程内同钥 shortcut（等价性锚=盲化回环专测）
    oprf_output = oprf_output_from_y(y_hex)
    salt = salt_hex or secrets.token_hex(16)
    rwd, masking_key = derive_rwd_chain(oprf_output, salt, iterations)
    blob = seal_envelope_v6(sk_hex, pk_hex, rwd.hex())
    return {
        "sealed_blob": blob,
        "masking_key_hex": masking_key.hex(),
        "kdf_salt_hex": salt,
        "kdf_iter": iterations,
    }


def ref_login_blind(username: str, password: str) -> tuple[str, int]:
    """线协议第 1 步：返回 (alpha_hex, r)——调用方持 alpha POST evaluate。"""
    return blind(oprf_input_bytes(username, password))


def ref_login_unseal(r: int, evaluate_response: dict) -> str:
    """线协议第 2 步：unblind→rwd（响应回传盐/迭代）→解掩码→解封，返回 sk_hex。
    错口令=解掩码 server_pub 前缀错/信封形态坏/GCM 认证败——异常即客户端判词源。
    口令不进本步（OPAQUE 性质：解封只需盲化标量+响应+账面 KDF 参数）。"""
    y = unblind(r, evaluate_response["evaluated_message"])
    oprf_output = oprf_output_from_y(y)
    rwd, masking_key = derive_rwd_chain(
        oprf_output, evaluate_response["kdf_salt_hex"], int(evaluate_response["kdf_iter"])
    )
    envelope = unmask_credential_response(
        masking_key,
        bytes.fromhex(evaluate_response["masking_nonce"]),
        bytes.fromhex(evaluate_response["masked_response"]),
    )
    return open_envelope_v6(envelope.decode(), rwd.hex())
