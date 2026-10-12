"""OPRF/HashToCurve 原语测试（⑫O-2 批——SM2-OPAQUE 归约修订版 §2/§3 合同）。

锚点分层（诚实红线——先红后绿）：
- 独立锚=归约修订版附录 A（Z=−9 四准则全锚点：三系数/x0/g(x0)/P-256 交叉验证
  8a10595 §3.2，逐字照录）+RFC 9380 K.1 官方 expand_message_xmd(SHA-256) 向量
  （rfc-editor 原文，2026-10-12 拉取）——判定器在本文件**独立实现**（与被测模块
  零共享代码路径，复评「从零判定器」方法论同构）；
- 自洽钉=SM2 套件黄金向量（实现生成后钉死——回归锁，独立锚之外的第二层）。
"""

from __future__ import annotations

import hashlib
import secrets

import pytest

from app.crypto.oprf import (
    FIELD_LEN,
    H2C_DST,
    SECURITY_K_BITS,
    SM3_BLOCK_LEN,
    SM3_OUT_LEN,
    SUITE_ID,
    Z_SSWU,
    OPRFError,
    _poly_xp_mod_cubic,
    _sswu_x_candidates,
    _xmd_core,
    blind,
    blind_evaluate,
    expand_message_xmd,
    finalize,
    hash_to_curve,
    hash_to_field,
    map_to_curve_sswu,
    mul_blinded,
    oprf_input_bytes,
    parse_point_element,
    point_to_hex,
)

# ---------------------------------------------------------------------------
# 独立判定器（本文件自实现——附录 A 脚本同构，不 import 被测模块的代数）
# ---------------------------------------------------------------------------


def _poly_mulmod(u, v, a, c, p):
    """(x²,x,x⁰) 系数三元组乘法 mod f=x³+a·x+c（x³≡−a·x−c）。"""
    t4 = (u[0] * v[0]) % p
    t3 = (u[0] * v[1] + u[1] * v[0]) % p
    t2 = (u[0] * v[2] + u[1] * v[1] + u[2] * v[0]) % p
    t1 = (u[1] * v[2] + u[2] * v[1]) % p
    t0 = (u[2] * v[2]) % p
    return ((t2 - a * t4) % p, (t1 - c * t4 - a * t3) % p, (t0 - c * t3) % p)


def _poly_xp_ref(a, c, p):
    """x^p mod f——多项式模幂（独立路径一）。返回 (x²,x,x⁰)。"""
    result, base, e = (0, 0, 1), (0, 1, 0), p
    while e:
        if e & 1:
            result = _poly_mulmod(result, base, a, c, p)
        base = _poly_mulmod(base, base, a, c, p)
        e >>= 1
    return result


def _poly_xp_matrix_ref(a, c, p):
    """x^p = M^p·(1,0,0)——3×3 伴随矩阵幂（独立路径二，M=[[0,0,−c],[1,0,−a],[0,1,0]]）。"""

    def mm(X, Y):
        return [[sum(X[i][k] * Y[k][j] for k in range(3)) % p for j in range(3)] for i in range(3)]

    M = [[0, 0, (-c) % p], [1, 0, (-a) % p], [0, 1, 0]]
    R = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
    e = p
    while e:
        if e & 1:
            R = mm(R, M)
        M = mm(M, M)
        e >>= 1
    return (R[0][0] % p, R[1][0] % p, R[2][0] % p)  # 列 0=升幂（x⁰,x¹,x²）


def _poly_gcd_deg(u, v, p):
    """欧几里得 gcd（升幂系数列表）→ 首项次数；−1=零多项式。"""

    def deg(t):
        return max((i for i, c in enumerate(t) if c % p), default=-1)

    def pmod(u_, v_):
        u_ = u_[:]
        dv = deg(v_)
        inv = pow(v_[dv], -1, p)
        while True:
            du = deg(u_)
            if du < dv:
                return u_
            coef = u_[du] * inv % p
            for i in range(dv + 1):
                u_[du - dv + i] = (u_[du - dv + i] - v_[i] * coef) % p

    while any(v):
        u, v = v, pmod(u, v)
    return deg(u)


def _cubic_irreducible_ref(a, c, p):
    """三次式 x³+a·x+c 不可约 ⟺ 无 F_p 根 ⟺ gcd(x^p−x, f)=1（升幂独立实现）。"""
    r = _poly_xp_ref(a, c, p)
    g = [r[2], (r[1] - 1) % p, r[0]]  # x^p−x mod f（升幂 x⁰,x¹,x²）
    if not any(g):
        return False  # f | x^p−x ⟹ 可约
    return _poly_gcd_deg([c, a, 0, 1], g, p) == 0


def _z_failures_ref(p, a, b, z):
    """RFC 9380 §6.6.2 四准则（c1 非平方/c2≠−1/c3 不可约/c4 g(B/(Z·A)) 平方）——
    返回未满足准则集合（空集=通过）。"""
    fails = set()
    zz = z % p
    if pow(zz, (p - 1) // 2, p) != p - 1:
        fails.add("c1")
    if zz == p - 1:
        fails.add("c2")
    if not _cubic_irreducible_ref(a % p, (b - z) % p, p):
        fails.add("c3")
    x0 = b % p * pow(z * a % p, -1, p) % p
    g0 = (pow(x0, 3, p) + a * x0 + b) % p
    if pow(g0, (p - 1) // 2, p) != 1:
        fails.add("c4")
    return fails


# SM2 / P-256 域参数（测试局部——与被测模块零共享）
P_SM2 = 2**256 - 2**224 - 2**96 + 2**64 - 1
A_SM2 = (-3) % P_SM2
B_SM2 = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
P_P256 = 2**256 - 2**224 + 2**192 + 2**96 - 1
A_P256 = (-3) % P_P256
B_P256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

# 归约修订版 §3.2 锚点（逐字照录——预期值，禁改写）
ANCHOR_XP_COEFFS_ASC = (  # x^p mod (g(x)−Z) 升幂（常量, x, x²）——文档三 hex 逐字
    0x8C9B89BFD1217964CBBB138058B0A0DAA3B7F144A2F84220A2F180E8CCD6F67B,
    0xA9C084B3C7FE741CB3C962235B7488198CF94416992A3679F24ADFF4AD1576B7,
    0x39B23B1F976F434D9A22763FD3A7AF92AE24075D2E83DEF02E873F8B999484C2,
)
ANCHOR_X0 = 0x993812C2E964B7A31F4F35452D9B7222AA35051B7294938AC5D7953B4EB9A1B9
ANCHOR_GX0 = 0x415BC055B574F716255DC77649A3C4025B1D89280C892D901229A8831DF50F44

# RFC 9380 附录 K.1 官方向量（expand_message_xmd, SHA-256, DST=QUUX-V01-CS02-…）
RFC_DST_QUUX = b"QUUX-V01-CS02-with-expander-SHA256-128"
RFC_XMD_VECTORS = [
    (b"", 0x20, "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
    (b"abc", 0x20, "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"),
    (
        b"",
        0x80,
        "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee"
        "0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda85"
        "76c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3"
        "491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
    ),
]

# 演示钥（固定常量——形态合法域内值，非真实凭据；测试专用）
K_DEMO = "3a" * 32
R_DEMO = "17" * 32


# ---------------------------------------------------------------------------
# C9-1 同源：Z=−9 四准则全锚点（独立判定器）
# ---------------------------------------------------------------------------

_ORDER = ("c1", "c2", "c3", "c4")


def _primary_failure(fails: set[str]) -> str:
    """首要淘汰原因=c1<c2<c3<c4 序首个失败项（归约 §3.2 淘汰轨迹的记账约定）。"""
    return min(fails, key=_ORDER.index)


def test_z_criteria_anchor_sm2():
    """SM2 |Z|≤12 正负全域：唯一通过 Z=−9；负值域淘汰轨迹按首要原因逐条
    （归约 §3.2：−1 c2；−2/−3/−5/−6/−7/−8 c3；−4 仅 c4）；正 Z 全灭（瑕疵 g）。"""
    assert _z_failures_ref(P_SM2, A_SM2, B_SM2, -9) == set()
    trajectory = {-1: "c2", -2: "c3", -3: "c3", -4: "c4", -5: "c3", -6: "c3", -7: "c3", -8: "c3"}
    for z, primary in trajectory.items():
        fails = _z_failures_ref(P_SM2, A_SM2, B_SM2, z)
        assert _primary_failure(fails) == primary, f"Z={z} fails={fails}"
        earlier = {_ORDER[i] for i in range(_ORDER.index(primary))}
        assert not (fails & earlier), f"Z={z} 首要原因之前不得有失败项"
    assert _z_failures_ref(P_SM2, A_SM2, B_SM2, -4) == {"c4"}, "−4 仅败 c4（复评实测口径）"
    for z in list(range(1, 13)):
        assert _z_failures_ref(P_SM2, A_SM2, B_SM2, z), f"正 Z=+{z} 必败（全域唯一性）"


def test_z_criteria_anchor_p256_cross():
    """P-256 交叉验证：|Z|≤12 唯一通过 −10=RFC 9380 发布值；淘汰轨迹按首要原因
    （归约 §3.2：−1 c2；−2/−4/−5/−8/−9 c3；−3/−6 c1；−7 恰好只败 c4）。"""
    assert _z_failures_ref(P_P256, A_P256, B_P256, -10) == set()
    trajectory = {
        -1: "c2",
        -2: "c3",
        -3: "c1",
        -4: "c3",
        -5: "c3",
        -6: "c1",
        -7: "c4",
        -8: "c3",
        -9: "c3",
    }
    for z, primary in trajectory.items():
        fails = _z_failures_ref(P_P256, A_P256, B_P256, z)
        assert _primary_failure(fails) == primary, f"Z={z} fails={fails}"
        earlier = {_ORDER[i] for i in range(_ORDER.index(primary))}
        assert not (fails & earlier), f"Z={z} 首要原因之前不得有失败项"
    assert _z_failures_ref(P_P256, A_P256, B_P256, -7) == {"c4"}, "−7 恰好只败 c4（复评口径）"
    for z in range(1, 13):
        assert _z_failures_ref(P_P256, A_P256, B_P256, z), f"正 Z=+{z} 必败"


def test_anchor_three_coefficients_dual_path():
    """三系数双路径逐字相等（多项式模幂 vs 伴随矩阵幂）+文档锚逐字（升幂序）。"""
    c = (B_SM2 - (-9)) % P_SM2
    poly = _poly_xp_ref(A_SM2, c, P_SM2)  # (x²,x,x⁰)
    mat = _poly_xp_matrix_ref(A_SM2, c, P_SM2)  # (x⁰,x,x²)
    assert mat == ANCHOR_XP_COEFFS_ASC
    assert poly == (ANCHOR_XP_COEFFS_ASC[2], ANCHOR_XP_COEFFS_ASC[1], ANCHOR_XP_COEFFS_ASC[0])
    # 被测模块暴露的同名实现（(x²,x,x⁰) 序）必须与独立判定器一致（双实现互证）
    assert _poly_xp_mod_cubic(A_SM2, c, P_SM2) == (
        ANCHOR_XP_COEFFS_ASC[2],
        ANCHOR_XP_COEFFS_ASC[1],
        ANCHOR_XP_COEFFS_ASC[0],
    )


def test_anchor_x0_gx0():
    """例外锚：x0=B/(Z·A)、g(x0) 平方（c4）——文档 hex 逐字。"""
    x0 = B_SM2 % P_SM2 * pow(-9 * A_SM2 % P_SM2, -1, P_SM2) % P_SM2
    g0 = (pow(x0, 3, P_SM2) + A_SM2 * x0 + B_SM2) % P_SM2
    assert x0 == ANCHOR_X0
    assert g0 == ANCHOR_GX0
    assert pow(g0, (P_SM2 - 1) // 2, P_SM2) == 1
    # 模块常量核对
    assert Z_SSWU == -9
    assert Z_SSWU % P_SM2 == 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFF6


# ---------------------------------------------------------------------------
# C9-2 同源：xmd-SM3 官方向量（RFC 9380 K.1，SHA-256 实例化）+SM2 套件边界
# ---------------------------------------------------------------------------


def test_xmd_rfc9380_official_vectors():
    """官方 K.1 向量（SHA-256 实例化——xmd 结构独立锚，多块路径含 0x80）。"""
    for msg, length, expect_hex in RFC_XMD_VECTORS:
        out = _xmd_core(msg, RFC_DST_QUUX, length, lambda b: hashlib.sha256(b).digest(), 64)
        assert out.hex() == expect_hex, f"msg={msg!r} len={length}"


def test_xmd_sm3_suite_shape_and_bounds():
    """SM2 套件 xmd 形状：b≥2k 恰好达线/ell=3/96B/DST 域——边界四行（设计 §3.4）。"""
    assert SM3_OUT_LEN * 8 == 2 * SECURITY_K_BITS  # b≥2k 恰好达线（无冗余余量）
    assert SM3_BLOCK_LEN == 64 and SM3_OUT_LEN == 32
    assert FIELD_LEN == 48
    assert len(SUITE_ID) >= 16 and len(H2C_DST) <= 255
    out = expand_message_xmd(b"abc", H2C_DST, 96)
    assert len(out) == 96
    # 越界 fail-closed：DST>255 / len_in_bytes>65535 / ell>255
    with pytest.raises(ValueError):
        expand_message_xmd(b"abc", b"D" * 256, 96)
    with pytest.raises(ValueError):
        expand_message_xmd(b"abc", H2C_DST, 65536)
    with pytest.raises(ValueError):
        expand_message_xmd(b"abc", H2C_DST, 255 * 32 + 1)


def test_hash_to_field_shape():
    """hash_to_field：双元素 48B/元素 mod p；确定性；不同输入不同分布位。"""
    u = hash_to_field(b"abc", 2)
    assert len(u) == 2
    for v in u:
        assert 0 <= v < P_SM2
    assert u == hash_to_field(b"abc", 2)
    assert u != hash_to_field(b"abd", 2)


# ---------------------------------------------------------------------------
# C9-3 同源：SSWU 映射（恒等式 30 组+例外锚+on-curve+sgn0）
# ---------------------------------------------------------------------------


def _sswu_ref_candidates(u):
    """RFC 9380 §6.6.2 候选对（独立公式实现——x1/x2 与 g 值）。"""
    p = P_SM2
    tv1 = Z_SSWU * u * u % p
    t = (tv1 * tv1 + tv1) % p
    x1 = (1 + (0 if t == 0 else pow(t, p - 2, p))) % p
    if t == 0:
        x1 = (-pow(Z_SSWU, p - 2, p)) % p
    x1 = x1 * (-B_SM2 * pow(A_SM2, p - 2, p)) % p
    gx1 = (pow(x1, 3, p) + A_SM2 * x1 + B_SM2) % p
    x2 = tv1 * x1 % p
    gx2 = (pow(x2, 3, p) + A_SM2 * x2 + B_SM2) % p
    return t, x1, gx1, x2, gx2


def test_sswu_identity_and_exactly_one_square():
    """恒等式 g(x2)=Z³u⁶·g(x1)+恰一平方（30 组随机 u）；例外 u=0 走 c4 锚。"""
    p = P_SM2
    z3u6_hits = 0
    for _ in range(30):
        u = secrets.randbelow(p)
        t, x1, gx1, x2, gx2 = _sswu_ref_candidates(u)
        if t == 0:
            continue  # 例外点恒等式不适用（RFC 以 c4 保证）——随机域命中≈0
        z3u6 = pow(Z_SSWU, 3, p) * pow(u, 6, p) % p
        assert gx2 == z3u6 * gx1 % p
        sq1 = pow(gx1, (p - 1) // 2, p) == 1
        sq2 = pow(gx2, (p - 1) // 2, p) == 1
        assert sq1 != sq2, "恰一平方（SSWU 全定义性核心）"
        z3u6_hits += 1
    assert z3u6_hits == 30
    # 例外锚：u=0 ⟹ x1=B/(Z·A)（模块候选实现）
    t0, x1_0, gx1_0, _x2, _gx2 = _sswu_x_candidates(0)
    assert t0 == 0 and x1_0 == ANCHOR_X0 and gx1_0 == ANCHOR_GX0


def test_map_to_curve_on_curve_and_exception():
    """map 输出恒在曲线上（30 组随机+例外 u=0 与 Zu²=−1）；sgn0(y)=sgn0(u)。"""
    p = P_SM2

    def on_curve(pt):
        x, y = pt
        return (y * y - (x * x * x + A_SM2 * x + B_SM2)) % p == 0

    for u in [0] + [secrets.randbelow(p) for _ in range(29)]:
        x, y = map_to_curve_sswu(u)
        assert on_curve((x, y))
        assert (y - u) % 2 == 0, "sgn0(y)=sgn0(u)（u 偶 ⟹ y 偶）"
    # Zu²≡−1 例外分支（u=pow(inv(Z),2)? —— Zu²=−1 ⟹ u²≡−1/Z）
    u_exc = pow((-pow(Z_SSWU, p - 2, p)) % p, (p + 1) // 4, p)
    assert Z_SSWU * u_exc * u_exc % p == (-1) % p
    x, y = map_to_curve_sswu(u_exc)
    assert on_curve((x, y))


def test_hash_to_curve_deterministic_and_on_curve():
    """六步复合：输出在曲线+确定性+输入域串。"""
    p = P_SM2
    msg = oprf_input_bytes("vector-user", "vector-password")
    pt = hash_to_curve(msg)
    assert (pt[1] * pt[1] - (pt[0] ** 3 + A_SM2 * pt[0] + B_SM2)) % p == 0
    assert pt == hash_to_curve(msg)


# ---------------------------------------------------------------------------
# OPRF 三原语：回环正确性+负例（非曲线点拒/错域拒 fail-closed）
# ---------------------------------------------------------------------------


def test_oprf_roundtrip_correctness():
    """Blind→BlindEvaluate→Finalize ≡ Evaluate 直算提取（正确性恒等式：
    [r⁻¹]·[k]·[r]·P=[k]·P——直算对照**不经去盲**直取提取式）。"""
    from app.crypto.oprf import evaluate as oprf_evaluate
    from app.crypto.oprf import oprf_output_from_y

    msg = oprf_input_bytes("roundtrip-user", "roundtrip-pass")
    alpha, r = blind(msg)
    assert isinstance(r, int) and 1 <= r < P_SM2  # r ∈ Z_n*
    beta = blind_evaluate(alpha, K_DEMO)
    out_blind = finalize(msg, r, beta)
    out_direct = oprf_output_from_y(oprf_evaluate(msg, K_DEMO))
    assert out_blind == out_direct
    assert len(out_blind) == 32  # Extract-SM3 输出 32B


def test_parse_point_element_negatives():
    """O-1/O-2 谓词负例：非 hex/长度/坐标≥p/离曲线——全部结构化拒绝。"""
    good = point_to_hex(*hash_to_curve(oprf_input_bytes("n", "p")))
    x_good, y_good = parse_point_element(good)
    bad_cases = [
        "",
        "ab",
        "zz" * 64,
        "1" * 127,
        "1" * 129,
        "1" * 130,
        point_to_hex(P_SM2, y_good),  # x≥p（坐标域）
        point_to_hex(x_good, P_SM2),  # y≥p
        point_to_hex(x_good, (y_good + 1) % P_SM2),  # 离曲线
    ]
    for bad in bad_cases:
        with pytest.raises(OPRFError):
            parse_point_element(bad)


def test_scalar_domain_negatives():
    """错域拒：r=0/≥n、k=0/≥n/非 hex——fail-closed。"""
    msg = oprf_input_bytes("domain-user", "domain-pass")
    pt_hex = point_to_hex(*hash_to_curve(msg))
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    with pytest.raises(OPRFError):
        mul_blinded(0, pt_hex)
    with pytest.raises(OPRFError):
        mul_blinded(n, pt_hex)
    with pytest.raises(OPRFError):
        blind_evaluate(pt_hex, "00" * 32)
    with pytest.raises(OPRFError):
        blind_evaluate(pt_hex, format(n, "064x"))
    with pytest.raises(OPRFError):
        blind_evaluate(pt_hex, "zz" * 32)
    with pytest.raises(OPRFError):
        finalize(msg, 0, pt_hex)
    with pytest.raises(OPRFError):
        finalize(msg, n, pt_hex)


def test_blind_evaluate_rejects_non_curve_before_mult():
    """O-1 前置：非曲线点进入 evaluate 必拒（先校验后标量乘——fail-closed 序）。"""
    good = point_to_hex(*hash_to_curve(oprf_input_bytes("o", "p")))
    x_g, y_g = parse_point_element(good)
    off = point_to_hex(x_g, (y_g + 1) % P_SM2)
    with pytest.raises(OPRFError):
        blind_evaluate(off, K_DEMO)


# ---------------------------------------------------------------------------
# SM2 套件黄金钉（自洽回归锁——独立锚之上的第二层；实现生成后钉死，漂移即红）
# ---------------------------------------------------------------------------

GOLDEN_XMD_96 = (
    "2d7b607522ed5a75906be92e0b3df13d0ee0bd515f081439eda2233efe65e9529c42a801e5bce009e629e7086b3e07396e2"
    "5b14c50b1fa68a65a182cb0fd1d0064582b916652a613364b2794be933315db7afbc48e0143aa866534ec56c39ec3"
)
GOLDEN_U = (
    "000000000000000000000000000000009f6c0b3f11308d618318de4a53841dd9a505eed483f02205d74add4e6a5d3d23",
    "00000000000000000000000000000000cf6dd1b80cf9207d2c9e57daa9ca93d830ac4aaad27bc4ce715a15ae01251799",
)
GOLDEN_H2C = (
    "60f589fb5942265c25b2963a69e8dbfd5c75b7e7a59e2dcbba6d55003f324de9"
    "2bb48167237ffeff262edd48e80f99c72e955e912a75482a38292dfe8b5fccd2"
)
GOLDEN_SSWU = {
    1: (
        "b8e2fb07009096cb94b7092ebe8202a125bdbc5ffe162b4d283740595eb2fe55"
        "685c894241c17539db345e5bf7357770a831e1d39ce8e9f7c99775790eed4169"
    ),
    2: (
        "8a773b4a812deb13356fd6ab70bbc7b0eacb45cab3ed72be02cad09bad512789"
        "70a436d98d5a3f1d4eb146f03267c023a8355789f922bae2a7530997aa5eaeb8"
    ),
}
GOLDEN_RT_ALPHA = (
    "f7e03e72a588e8fc10131c0ff88581afe58d5575e7e342b6a05b2f26cdef97d83"
    "708f5853656eb27ffea56bfc8e70aa2b93e751724d0899a071d70dc52ab04a7"
)
GOLDEN_RT_BETA = (
    "94fc9dae4e6934b980939f2eedbacd6c616ab1b1d5d1d5ac7a17ed0d47fcd7d9a"
    "70ee9da0f70923b35024a0fc26406b074ccab004c8eaaade363c257651c9ac0"
)
GOLDEN_RT_OUT = "6b0664b3a33c12236efb1a166fd0fa9213e1fc52b9603e004161c98b38167c3c"


def test_golden_sm2_suite_pins():
    """SM2 套件黄金钉：xmd/hash_to_field/h2c/SSWU 固定向量——参数或实现漂移即红。"""
    msg = oprf_input_bytes("vector-user", "vector-password")
    assert expand_message_xmd(b"abc", H2C_DST, 96).hex() == GOLDEN_XMD_96
    u = hash_to_field(msg, 2)
    assert tuple(format(v, "096x") for v in u) == GOLDEN_U
    assert point_to_hex(*hash_to_curve(msg)) == GOLDEN_H2C
    for uu, expect in GOLDEN_SSWU.items():
        assert point_to_hex(*map_to_curve_sswu(uu)) == expect, f"u={uu}"


def test_golden_roundtrip_fixed_rk():
    """固定 r/k 回环黄金（K_DEMO/R_DEMO）：α/β/oprf_output 逐字节钉死。"""
    from app.crypto.oprf import oprf_output_from_y, unblind

    r = int(R_DEMO, 16)
    alpha = mul_blinded(r, GOLDEN_H2C)
    assert alpha == GOLDEN_RT_ALPHA
    beta = blind_evaluate(alpha, K_DEMO)
    assert beta == GOLDEN_RT_BETA
    assert oprf_output_from_y(unblind(r, beta)).hex() == GOLDEN_RT_OUT
