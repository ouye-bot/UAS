"""M_A 凭证密码模块（B2）——RA 签发时签出电路同构凭证（AUTH 语句消费对象）。

凭证 = RA 对 165B 结构化报文 M_A 的 SM2 签名 (r,s)；M_A 与框架 §5.1 逐字段一致，
报文结构与旧系统 pred_credential M′（vendor 电路 host 同构件）逐槽同构——
黄金向量钉定：tests/test_ra_credential.py ↔ zksvc/tests/auth_golden_vector.json（B3
真电路对拍单一事实源）：

    M_A = Z_A(pk_RA)(32) ‖ x(id′_u·G)(32) ‖ C(32)
          ‖ pk′_u.x(32) ‖ pk′_u.y(32) ‖ exp_u BE(4) ‖ par(1)
    C   = SM3( salt(16) ‖ id_number(18) ‖ cert_level(1) ‖ sn_h(16) )   # 51B，SM3 单块
    sn_h = SM3( drone_serial )[0..16]
    par = 0x02 | lsb(y(id′·G))     id′ 标量按 BE 整数解释

🔴 电路 e 口径：e = Σ_{k=0..7} dg[k]·2^{32k}（词序小端折叠）——签名必须走
`sm2.sign_digest` 裸摘要通道，喂入"词 7..0 倒序拼接"的 32B（`digest_e_bytes`）。
验签同口径（SP-19 定谳资产，fork 自旧系统 pred_credential.py，2026-09-19）。
"""

from __future__ import annotations

from app.crypto.sm2 import _G, _c, _za, sign_digest, verify_digest
from app.crypto.sm3 import sm3_bytes

MESSAGE_LEN = 165
SALT_LEN = 16
ID_NUMBER_LEN = 18
SN_HASH_LEN = 16
CERT_MIN, CERT_MAX = 1, 4
U32_MAX = 0xFFFFFFFF


class CredentialError(Exception):
    """M_A 构造/校验失败（输入域错误）。"""


def sn_hash(serial: bytes) -> bytes:
    """sn_h = SM3(无人机序列号)[0..16]（16B 截断——M_A 承诺原像契约）。"""
    if not isinstance(serial, (bytes, bytearray)) or not 1 <= len(serial) <= 64:
        raise CredentialError("序列号须为 1..64 字节")
    return sm3_bytes(bytes(serial))[:SN_HASH_LEN]


def commitment_c(
    salt: bytes,
    id_number: bytes,
    cert_level: int,
    serial: bytes,
    class_id: int = 0,
) -> bytes:
    """C = SM3(salt16 ‖ cert BE4 ‖ class1 ‖ id_number(18) ‖ sn_h(16))——55B 单块加盐承诺。

    加盐是生死线（D10）：身份证号低熵（~10^10 有校验位），无盐=离线穷举面。
    布局 v3（B4-d1/A4，2026-09-20）：cert 居词 4（范围门读数源——B3-d8 保持）+
    class 居字节 20=词 5 MSB（电路 8 位等值钉实例 24 读数源——自报机型套高
    上限攻击的电路封堵）；55B+1pad+8len=64 恰满单块。
    """
    if len(salt) != SALT_LEN:
        raise CredentialError(f"salt 须 {SALT_LEN} 字节")
    if len(id_number) != ID_NUMBER_LEN:
        raise CredentialError(f"身份证号须 {ID_NUMBER_LEN} 字节")
    if isinstance(cert_level, bool) or not isinstance(cert_level, int):
        raise CredentialError("资质等级须整数")
    if not CERT_MIN <= cert_level <= CERT_MAX:
        raise CredentialError(f"资质等级须在 [{CERT_MIN},{CERT_MAX}]")
    if isinstance(class_id, bool) or not isinstance(class_id, int) or not 0 <= class_id <= 255:
        raise CredentialError("机型类须 u8")
    preimage = (
        salt
        + cert_level.to_bytes(4, "big")
        + bytes([class_id])
        + bytes(id_number)
        + sn_hash(serial)
    )
    assert len(preimage) == 55  # SM3 单块（55+1pad+8len=64 恰满）
    return sm3_bytes(preimage)


def _point_mul_g(scalar: int) -> tuple[bytes, bytes]:
    """[k]G → (x_be32, y_be32)。gmssl `_kg` 契约：k int、点 128hex。"""
    xy = _c("0" * 64, _G)._kg(scalar, _G)
    return bytes.fromhex(xy[:64]), bytes.fromhex(xy[64:])


def build_message(
    ra_pub_hex: str,
    id_prime: bytes,
    salt: bytes,
    id_number: bytes,
    cert_level: int,
    serial: bytes,
    holder_pub_hex: str,
    exp_u: int,
    class_id: int = 0,
) -> bytes:
    """165B 报文 M_A（AUTH 电路公开消费对象；Z_A 用 RA 公钥+默认 ID）。"""
    if len(ra_pub_hex) != 128 or len(holder_pub_hex) != 128:
        raise CredentialError("公钥须 128 hex（x‖y）")
    if len(id_prime) != 32:
        raise CredentialError("id′ 须 32 字节")
    if isinstance(exp_u, bool) or not isinstance(exp_u, int) or not 0 <= exp_u <= U32_MAX:
        raise CredentialError("exp_u 须 u32")
    c_bytes = commitment_c(salt, id_number, cert_level, serial, class_id)
    idg_x, idg_y = _point_mul_g(int.from_bytes(id_prime, "big"))
    par = 0x02 | (idg_y[31] & 1)
    msg = (
        _za(ra_pub_hex)
        + idg_x
        + c_bytes
        + bytes.fromhex(holder_pub_hex[:64])
        + bytes.fromhex(holder_pub_hex[64:])
        + exp_u.to_bytes(4, "big")
        + bytes([par])
    )
    assert len(msg) == MESSAGE_LEN
    return msg


def _reverse_words(digest32: bytes) -> bytes:
    """8 个 32 位词倒序拼接（对合）：标准 SM3 摘要 ↔ 电路 fold 口径 BE 整数字节。"""
    if len(digest32) != 32:
        raise CredentialError("摘要须 32 字节")
    return b"".join(digest32[4 * k : 4 * k + 4] for k in range(7, -1, -1))


def digest_e_bytes(message: bytes) -> bytes:
    """电路口径 e 的 32B 大端表示：SM3(M_A) 词序倒转——喂 `sign_digest`/`verify_digest`。"""
    if len(message) != MESSAGE_LEN:
        raise CredentialError(f"报文须 {MESSAGE_LEN} 字节")
    return _reverse_words(sm3_bytes(message))


def sign_credential(ra_priv_hex: str, message: bytes) -> str:
    """裸钥签名（测试/脚本用）；生产走 KMS（ra_signing_keypair 进程内持有）。"""
    return sign_digest(ra_priv_hex, digest_e_bytes(message))


def verify_credential(ra_pub_hex: str, message: bytes, sig_hex: str) -> bool:
    """同口径验签（与电路内 SM2 验签 gadget 消费同一 e——B3 对拍锚）。

    验签面语义：输入非法（长度/格式）一律 False（与 sm2.verify 同哲学，永不抛）；
    构造/签名面（build_message/digest_e_bytes）保持 fail-fast 抛 CredentialError。
    """
    if len(message) != MESSAGE_LEN:
        return False
    try:
        return verify_digest(ra_pub_hex, digest_e_bytes(message), sig_hex)
    except Exception:  # noqa: BLE001  验签面容错=拒绝
        return False
