"""OPRF/HashToCurve 密码原语（⑫O-2 批——SM2-OPAQUE 归约修订版 §2/§3 实施合同）。

唯一协议依据：docs/SM2-OPAQUE归约论证-修订版.md（复评 GO，8a10595；瑕疵 a~g 更正
4d1245b）+ docs/OPAQUE实施设计.md（O-1 定稿，e1bc5d1）§3/§2.4。实施照单施工。

红线（归约 §2.3 规范条目——本模块的代码路径，非测试项）：
- O-1（服务端）：BlindEvaluate 在标量乘**之前**完整校验输入群元素（128 hex/坐标
  ∈ F_p/曲线方程/无穷远无编码）——失败结构化拒绝（OPRFError），绝不进入标量乘
  路径。威胁机理：软件档标量乘对**非曲线点**工作在异曲线上（无效曲线攻击族），
  响应 [k]·P' 直接泄漏 k mod 小阶——盲化双乘不改变无效点的群结构泄漏（归约 §2.3
  原文），校验是 §2.4 归约前提成立条件；
- O-2（客户端）：Finalize 前对 β 同款校验（恶意服务端回非曲线点的对偶面）；
- O-3（标量乘纪律）：一切标量乘走 sm2._kg_blinded（d=d1+d2 随机分裂双乘——
  SP9 9.19 时序侧信道防线；客户端 r 虽为会话一次性随机，同径统一守恒时口径）；
- 随机性一律 secrets（RFC 4086 口径）；曲线常量一律 default_ecc_table（禁手抄）；
- Z=−9 钉定：RFC 9380 §6.6.2 四准则（c1 非平方/c2≠−1/c3 g(x)−Z 不可约/
  c4 g(B/(Z·A)) 平方）在 |Z|≤12 正负全域唯一通过——锚点复现=scripts/crypto_audit
  C9 与 tests/test_crypto_opaque.py（独立判定器），归约 §3.2 附录 A。

测试锚分层（tests/test_crypto_opaque.py）：独立锚=归约附录 A hex 逐字+RFC 9380
K.1 官方 expand_message_xmd(SHA-256) 向量；自洽钉=SM2 套件黄金向量（回归锁）。
"""

from __future__ import annotations

import secrets

from gmssl.sm2 import CryptSM2, default_ecc_table

from app.crypto.kdf import hkdf_sm3_extract
from app.crypto.sm2 import _kg_blinded
from app.crypto.sm3 import sm3_bytes


class OPRFError(Exception):
    """OPRF 原语拒绝（fail-closed）：code 供协议层映射 400 族结构化错误。"""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


# ---------------------------------------------------------------------------
# 常量（设计 §3.1——单一常量模块，禁散落禁手抄）
# ---------------------------------------------------------------------------

_P = int(default_ecc_table["p"], 16)
_A = int(default_ecc_table["a"], 16)  # −3 (mod p)——SSWU 直落适用（a≠0 且 b≠0）
_B = int(default_ecc_table["b"], 16)
_N = int(default_ecc_table["n"], 16)  # 素数、cofactor h=1（clear_cofactor=恒等）
_G_HEX = default_ecc_table["g"]

Z_SSWU = -9  # SSWU 常量（归约 §3.2 钉定——四准则唯一通过值，正负全域）
FIELD_LEN = 48  # hash_to_field 每元素字节（RFC 9380 §5：L=ceil((256+128)/8)）
H2C_COUNT = 2  # hash_to_field 计数（RO 构成——双 u 采样）
SECURITY_K_BITS = 128
SM3_OUT_LEN = 32
SM3_BLOCK_LEN = 64
SUITE_ID = b"SM2_P256_XMD:SM3_SSWU_RO_"  # 套件自注册命名（归约 §3.4；G2 在案）
H2C_DST = b"FZ-OPAQUE-V1-" + SUITE_ID
OPRF_INPUT_PREFIX = b"FZ-OPAQUE-OPRF|v1"  # Blind 输入域串（归约 §2.2——username 绑定）
FINALIZE_PREFIX = b"FZ-OPAQUE-Finalize|v1"  # Finalize 提取域串（归约 §2.2/瑕疵 f 注记）


def oprf_input_bytes(username: str, password: str) -> bytes:
    """oprf_input 域串（归约 §2.2 逐字）：前缀‖0x00‖username‖0x00‖password——
    base mode 无 POPRF info 通道，username 绑定走输入前缀（防跨账户 rwd 拼接）。"""
    return OPRF_INPUT_PREFIX + b"\x00" + username.encode() + b"\x00" + password.encode()


# ---------------------------------------------------------------------------
# expand_message_xmd / hash_to_field（RFC 9380 §5.3.1/§5）
# ---------------------------------------------------------------------------


def _xmd_core(msg: bytes, dst: bytes, len_in_bytes: int, hash_bytes, block_len: int) -> bytes:
    """expand_message_xmd 通用核（RFC 9380 §5.3.1 伪代码逐字）——hash_bytes 参数化
    供 RFC 官方向量锚定（SHA-256 实例=K.1，SM3 实例=本套件自注册）。"""
    out_len = len(hash_bytes(b""))
    ell = -(-len_in_bytes // out_len)
    if len_in_bytes < 1 or ell > 255 or len_in_bytes > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd 参数越界（RFC 9380 §5.3.1 边界）")
    dst_prime = dst + bytes([len(dst)])
    # RFC 9380 §5.3.1 步骤 6 逐字：msg_prime = Z_pad ‖ msg ‖ l_i_b_str ‖ I2OSP(0,1) ‖ DST_prime
    # （l_i_b_str 与 DST_prime 间的单 0x00 字节不可省——K.1 官方向量锚定实测在案）
    msg_prime = b"\x00" * block_len + msg + len_in_bytes.to_bytes(2, "big") + b"\x00" + dst_prime
    b0 = hash_bytes(msg_prime)
    bi = hash_bytes(b0 + b"\x01" + dst_prime)
    out = bytearray(bi)
    for i in range(2, ell + 1):
        bi = hash_bytes(bytes(x ^ y for x, y in zip(b0, bi, strict=True)) + bytes([i]) + dst_prime)
        out += bi
    return bytes(out[:len_in_bytes])


def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """SM3 实例化：b=256 bit（≥2k 恰好达线——设计 §3.4 边界账）、块长 64B、
    len_in_bytes=96 时 ell=3。"""
    return _xmd_core(msg, dst, len_in_bytes, sm3_bytes, SM3_BLOCK_LEN)


def hash_to_field(msg: bytes, count: int = H2C_COUNT) -> list[int]:
    """RFC 9380 §5 hash_to_field：L=48B/元素（均匀 384-bit 串 mod p——统计距离
    <2⁻¹²⁸，归约 §3.3 修正账；v1 病灶 64B/2^−32 已根除）。"""
    if count < 1:
        raise ValueError("count 须 ≥1")
    uniform = expand_message_xmd(msg, H2C_DST, count * FIELD_LEN)
    return [
        int.from_bytes(uniform[i * FIELD_LEN : (i + 1) * FIELD_LEN], "big") % _P
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# SSWU map_to_curve（RFC 9380 §6.6.2——Z=−9）
# ---------------------------------------------------------------------------


def _inv0(x: int) -> int:
    """F_p 逆元（RFC inv0 语义：输入 0 ⟹ 返回 0——SSWU 容错分支）。"""
    x %= _P
    return pow(x, _P - 2, _P) if x else 0


def _is_square(v: int) -> bool:
    v %= _P
    return v == 0 or pow(v, (_P - 1) // 2, _P) == 1


def _fp_sqrt(v: int) -> int:
    """p≡3 (mod 4) 平方根；非平方输入=调用方契约违例（fail-closed）。"""
    r = pow(v % _P, (_P + 1) // 4, _P)
    if r * r % _P != v % _P:
        raise OPRFError("sqrt_not_square", "平方根输入非平方（内部契约违例）")
    return r


def _poly_xp_mod_cubic(a: int, c: int, p: int) -> tuple[int, int, int]:
    """x^p mod (x³+a·x+c)——多项式模幂（x³≡−a·x−c 逐步归约）。
    归约 §3.2 c3 判定核；与 3×3 伴随矩阵幂双路径互证（锚=C9 审计三系数逐字）。"""

    def mulmod(u, v):
        t4 = (u[0] * v[0]) % p
        t3 = (u[0] * v[1] + u[1] * v[0]) % p
        t2 = (u[0] * v[2] + u[1] * v[1] + u[2] * v[0]) % p
        t1 = (u[1] * v[2] + u[2] * v[1]) % p
        t0 = (u[2] * v[2]) % p
        return ((t2 - a * t4) % p, (t1 - c * t4 - a * t3) % p, (t0 - c * t3) % p)

    result, base, e = (0, 0, 1), (0, 1, 0), p
    while e:
        if e & 1:
            result = mulmod(result, base)
        base = mulmod(base, base)
        e >>= 1
    return result  # (x², x, x⁰)


def _sswu_x_candidates(u: int) -> tuple[int, int, int, int, int]:
    """SSWU 候选对与 t（RFC 9380 §6.6.2 步骤；返回 t,x1,g(x1),x2,g(x2)）。

    Z=−9 四准则注释链（Z 满足下列全部条件——本函数正确性的代数前提）：
      c1（非平方）：χ(Z)=−1 ⟹ 恒等式 g(x2)=Z³u⁶·g(x1) 下 χ(g2)=χ(Z)·χ(g1)=−χ(g1)
        ⟹ gx1/gx2 恰一为平方 ⟹ 两分支必一命中（映射全定义性的核心）；
      c2（≠−1）：排除 t=Z²u⁴+Zu² 的分支退化（RFC 列示，角色推理未附文——照办）；
      c3（g(x)−Z 不可约）：gcd(x^p−x, g(x)−Z)=1——分布/正确性论证的代数前提
        （锚=三系数 hex 逐字，C9 审计双路径复现）；
      c4（g(B/(Z·A)) 平方）：例外锚——u=0 或 Z·u²≡−1 时 t=0，直取 x1=B/(Z·A)
        仍得合法点（RFC §6.6.2 原文 "guarantees that g(x1) is square"）。"""
    p = _P
    u %= p
    tv1 = Z_SSWU * u % p * u % p  # Z·u²
    t = (tv1 * tv1 + tv1) % p  # Z²u⁴+Zu²
    x1 = _inv0(t)
    if t == 0:
        # RFC CMOV 语义：x1←c2=−1/Z，再乘 c1=−B/A ⟹ x1=(−B/A)(−1/Z)=B/(Z·A)
        x1 = (-pow(Z_SSWU, p - 2, p)) % p
    else:
        x1 = (x1 + 1) % p
    x1 = x1 * ((-_B) * pow(_A, p - 2, p) % p) % p  # ×c1=−B/A
    gx1 = (pow(x1, 3, p) + _A * x1 + _B) % p
    x2 = tv1 * x1 % p
    gx2 = (pow(x2, 3, p) + _A * x2 + _B) % p
    return t, x1, gx1, x2, gx2


def map_to_curve_sswu(u: int) -> tuple[int, int]:
    """SSWU 映射：gx1 为平方取 x1 分支、否则 x2 分支（恰一平方——c1）；
    y=√g(x) 且 sgn0(y)=sgn0(u)（RFC 符号纪律——u 大端奇偶）。"""
    p = _P
    u %= p
    _t, x1, gx1, x2, gx2 = _sswu_x_candidates(u)
    if _is_square(gx1):
        x, gv = x1, gx1
    else:
        x, gv = x2, gx2
    y = _fp_sqrt(gv)
    if y % 2 != u % 2:
        y = p - y
    return x, y


# ---------------------------------------------------------------------------
# hash_to_curve 六步复合（归约 §3.4——RFC 9380 §3）
# ---------------------------------------------------------------------------


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    """仿射点加（None=无穷远；Q0+Q1 求和步——v1 病灶缺失的 RO 复合步）。"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def hash_to_curve(msg: bytes) -> tuple[int, int]:
    """六步复合：u=hash_to_field(msg,2)→Q0→Q1→R=Q0+Q1→clear_cofactor（h=1 恒等，
    调用形状保留）→P。确定性；无穷远命中≈2⁻²⁵⁶ fail-closed。"""
    u0, u1 = hash_to_field(msg, H2C_COUNT)
    r_pt = _point_add(map_to_curve_sswu(u0), map_to_curve_sswu(u1))
    if r_pt is None:
        raise OPRFError("h2c_infinity", "hash_to_curve 命中无穷远点（概率≈2⁻²⁵⁶）——拒绝")
    return r_pt


def point_to_hex(x: int, y: int) -> str:
    """仿射点 → 128 hex（x‖y，各 64 hex 大端）。"""
    return format(x, "064x") + format(y, "064x")


# ---------------------------------------------------------------------------
# O-1/O-2 群元素校验 + O-3 标量乘纪律
# ---------------------------------------------------------------------------


def parse_point_element(hex128: str) -> tuple[int, int]:
    """OPRF 群元素完整校验（O-1/O-2 前置条件——规范条目，非测试项）：
    128 hex / x,y ∈ [0,p)（坐标域——sm2._point_on_curve 域检查 O-2 批同款）/
    曲线方程；无穷远在 128hex x‖y 编码下无表示（长度门即拒）。
    校验失败=OPRFError（协议层映射 400 族）——绝不进入标量乘路径。"""
    if (
        not isinstance(hex128, str)
        or len(hex128) != 128
        or any(c not in "0123456789abcdefABCDEF" for c in hex128)
    ):
        raise OPRFError("invalid_point", "群元素须 128 hex（x‖y）")
    x = int(hex128[:64], 16)
    y = int(hex128[64:], 16)
    if x >= _P or y >= _P:
        raise OPRFError("invalid_point", "群元素坐标超出 F_p 域")
    if (y * y - (x * x * x + _A * x + _B)) % _P != 0:
        raise OPRFError("invalid_point", "群元素不在 SM2 曲线上（无效曲线拒绝）")
    return x, y


def _validate_scalar(d: int) -> int:
    """标量域校验：∈ Z_n*=[1, n−1]（0/域外/非整数——错域拒 fail-closed）。"""
    if isinstance(d, bool) or not isinstance(d, int):
        raise OPRFError("scalar_format", "标量须整数")
    if not 1 <= d <= _N - 1:
        raise OPRFError("scalar_domain", "标量不在 Z_n* 域（[1, n−1]）")
    return d


def _validate_key_hex(k_hex: str) -> int:
    """OPRF 钥形态门：64 hex 且 ∈ Z_n*（kms 注入面复核——纵深一致）。"""
    if not isinstance(k_hex, str) or len(k_hex) != 64:
        raise OPRFError("key_format", "OPRF 钥须 64 hex")
    try:
        k = int(k_hex, 16)
    except ValueError as e:
        raise OPRFError("key_format", "OPRF 钥须 hex") from e
    if not 1 <= k <= _N - 1:
        raise OPRFError("key_domain", "OPRF 钥不在 Z_n* 域")
    return k


def mul_blinded(scalar: int, point_hex: str) -> str:
    """[scalar]·point——**统一 _kg_blinded 路径**（O-3：随机分裂 d=d1+d2 双乘+点加，
    位模式与标量去相关；客户端 r 乘同径——冷路径 2× 可接受）。"""
    parse_point_element(point_hex)
    d = _validate_scalar(scalar)
    c = CryptSM2(private_key="0" * 64, public_key=_G_HEX, mode=1)
    out = _kg_blinded(c, d, point_hex)
    if not isinstance(out, str) or len(out) > 128:
        shape = len(out) if isinstance(out, str) else type(out).__name__
        raise OPRFError("mul_shape", f"标量乘输出形态异常（{shape}）")
    out = out.zfill(128)
    parse_point_element(out)  # 输出防御校验（gmssl 返回形态漂移即红）
    return out


# ---------------------------------------------------------------------------
# OPRF 三原语（归约 §2.2——命名对齐 RFC 9497/9807 API）
# ---------------------------------------------------------------------------


def blind(msg: bytes) -> tuple[str, int]:
    """客户端 Blind：r ←$ Z_n*（secrets CSPRNG）；α=[r]·H2C(oprf_input)。"""
    r = secrets.randbelow(_N - 1) + 1
    alpha = mul_blinded(r, point_to_hex(*hash_to_curve(msg)))
    return alpha, r


def blind_evaluate(alpha_hex: str, k_hex: str) -> str:
    """服务端 BlindEvaluate：**O-1 点校验先行**（先于标量乘——fail-closed 序），
    然后 β=[k]·α（_kg_blinded 路径）。k_hex 由 KMS 面注入（oprf_key/oprf_key_for）。"""
    parse_point_element(alpha_hex)  # O-1——规范前置条件（无效曲线防线）
    k = _validate_key_hex(k_hex)
    return mul_blinded(k, alpha_hex)


def evaluate(msg: bytes, k_hex: str) -> str:
    """服务端直算 Evaluate（自持 k 与输入——归约 §2.2）：β=[k]·H2C(oprf_input)。
    h2c 输出恒为合法点（校验由 mul_blinded 出口防御兜底）。"""
    k = _validate_key_hex(k_hex)
    return mul_blinded(k, point_to_hex(*hash_to_curve(msg)))


def unblind(r: int, beta_hex: str) -> str:
    """客户端去盲：O-2 校验 β（对偶面——恶意服务端非曲线点）→ Y=[r⁻¹]β。"""
    parse_point_element(beta_hex)
    r_inv = pow(_validate_scalar(r), -1, _N)
    return mul_blinded(r_inv, beta_hex)


def oprf_output_from_y(y_hex: str) -> bytes:
    """①Finalize 提取（设计 §1.4）：oprf_output=Extract("", 域串‖Y.x‖Y.y)——
    64B 坐标域串；域串不含 input（归约 §2.2/瑕疵 f 适配注记——base mode 自托管
    无回退消费方）；域串落 HKDF IKM 位、盐位空。"""
    parse_point_element(y_hex)
    return hkdf_sm3_extract(b"", FINALIZE_PREFIX + bytes.fromhex(y_hex))


def finalize(msg: bytes, r: int, beta_hex: str) -> bytes:
    """客户端 Finalize 完整步：O-2 校验→去盲→提取（unblind+oprf_output_from_y）。"""
    return oprf_output_from_y(unblind(r, beta_hex))
