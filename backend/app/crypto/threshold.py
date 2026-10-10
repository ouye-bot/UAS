"""④站 SM2 ECIES 线性门限原语（2-of-3，2026-10-10）。

数学依据（MEMORY §六拍板）：SM2 解密的本质是 [d]C₁（椭圆曲线点乘），而
[d]C₁=Σ[λᵢdᵢ]C₁ 对任意拉格朗日系数 λᵢ 成立（曲线点的标量乘对加法线性）。
Shamir 2-of-3：d=f(0)，f(x)=d+a₁x（mod n）；份额 dᵢ=f(i) 分入三治理角色域。
门限解密时份额域**只回传 [dᵢ]C₁ 点份额**（dᵢ 本身不出域），合成方按任两
份额的拉格朗日系数聚合 Σλᵢ[dᵢ]C₁=[d]C₁ ⟹ 私钥 d 全程不在任何单点重组。

安全语义（诚实口径）：
- 单域失陷不可单独解实名（单份额信息论不定一次多项式）；
- 两域合谋可解（2-of-3 语义——与治理三域多数被攻破同构，答辩口径 C 段）；
- 错域/错份额混入 ⟹ ECIES C3 校验必败（不返回垃圾明文，GB/T 完整校验）。
"""

from __future__ import annotations

import secrets

from app.crypto.sm2 import _N, _P, SM2Error, _c, _point_on_curve, sm3_bytes

# SM2 推荐曲线阶 _N（GB/T 32918，自 sm2 库单一事实源 import——份额/拉格朗日
# 全部 mod n；手抄字面量曾抄成 296bit 致拉格朗日逆元爆炸，教训=域常量禁止
# 二次手抄）。_G 同源（128hex x||y）。
_G = (
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
)


def _inv_mod(a: int, m: int) -> int:
    return pow(a, -1, m)


def shamir_split(d: int, n: int, k: int) -> list[tuple[int, int]]:
    """Shamir k-of-n 分割：f(x)=d+Σaⱼxʲ（mod n），返回 [(i, f(i))] i=1..n。"""
    if not 1 <= k <= n:
        raise ValueError("门限参数非法（须 1≤k≤n）")
    if d <= 0 or d >= _N:
        raise ValueError("根私钥须在 [1, n-1]")
    coeffs = [d] + [secrets.randbelow(_N - 1) + 1 for _ in range(k - 1)]
    shares = []
    for i in range(1, n + 1):
        y = 0
        for j, c in enumerate(coeffs):
            y = (y + c * pow(i, j, _N)) % _N
        shares.append((i, y))
    return shares


def lagrange_coeff(i: int, xs: list[int]) -> int:
    """零点拉格朗日系数 λᵢ=Π(-xⱼ/(xᵢ-xⱼ)) mod n（xs=参与合成的份额下标集）。"""
    acc = 1
    for xj in xs:
        if xj != i:
            acc = acc * (-xj % _N) % _N * _inv_mod((i - xj) % _N, _N) % _N
    return acc


def lagrange_coeff_at(t: int, i: int, xs: list[int]) -> int:
    """点 t 的拉格朗日系数 λᵢ(t)=Π_{j≠i}(t-xⱼ)/(xᵢ-xⱼ) mod n——
    proactive re-share 的换基外推消费面（t=0 时与 lagrange_coeff 同值）。"""
    acc = 1
    for xj in xs:
        if xj != i:
            acc = acc * ((t - xj) % _N) % _N * _inv_mod((i - xj) % _N, _N) % _N
    return acc


def proactive_reshare(old_shares: list[tuple[int, int]], n: int, k: int) -> list[tuple[int, int]]:
    """proactive re-share（⑤站份额刷新核心原语）——**根钥 d 不重组**。

    数学：随机增项多项式 δ(x)=Σ_{j=1..k-1} b_j·xʲ（**无常数项 ⟹ δ(0)=0**），
    新多项式 g=f+δ 满足 g(0)=f(0)=d 恒不变；新份额 g(i)=f(i)+δ(i)。旧份额
    只持 ≥k 份，未持有下标的 f(i) 经拉格朗日标量外推（lagrange_coeff_at）
    补全——全程 [1,n-1] 标量域加乘，d 从不在本函数域出现（与 decrypt 侧
    「d 不在此重组」同纪律：重建 d 需要离散对数级信息，本函数连数值外推
    d 的路径都不走——增项只加在份额点上）。

    安全语义：单纪元内 ≤k-1 份泄露跨纪元不累积（旧份额值对新多项式无效，
    混合合成 ⟹ ECIES C3 必败）；D_pub 侧零变化（存量信封零影响）。
    """
    if not 1 <= k <= n:
        raise ValueError("门限参数非法（须 1≤k≤n）")
    if len(old_shares) < k:
        raise ValueError(f"re-share 须 ≥k={k} 份现存份额（得 {len(old_shares)}）")
    idx = [i for i, _ in old_shares]
    if len(set(idx)) != len(idx):
        raise ValueError("份额下标重复（同域两份不构成独立份额）")
    for i, s in old_shares:
        if not 1 <= i <= n or not 0 < s < _N:
            raise ValueError(f"份额形态非法：下标 {i} 值域越界")
    # 随机增项系数 b_j∈[1,n-1]（j=1..k-1；k=2 即 δ(x)=b·x）
    bs = [secrets.randbelow(_N - 1) + 1 for _ in range(k - 1)]
    out: list[tuple[int, int]] = []
    for i in range(1, n + 1):
        f_i = 0
        for j, s in old_shares:
            f_i = (f_i + lagrange_coeff_at(i, j, idx) * s) % _N
        delta_i = 0
        for p, b in enumerate(bs, start=1):
            delta_i = (delta_i + b * pow(i, p, _N)) % _N
        out.append((i, (f_i + delta_i) % _N))
    return out


def _jac_to_affine(jac: str) -> str:
    """gmssl _add_point 的 Jacobian (x‖y‖z, 192hex) → 仿射 (x‖y, 128hex)；
    z=0=无穷远点 ⟹ 全零 128hex（本模块内作为加法单位元 O）。"""
    if jac is None or len(jac) != 192:
        raise SM2Error("点加返回非法（长度/Jacobian 形态）")
    x, y, z = int(jac[:64], 16), int(jac[64:128], 16), int(jac[128:], 16)
    if z == 0:
        return "0" * 128
    zinv = pow(z, _P - 2, _P)
    zinv2 = zinv * zinv % _P
    x1 = x * zinv2 % _P  # x′=x/z²
    y1 = y * zinv2 % _P * zinv % _P  # y′=y/z³（Jacobian 约定——y 用 z² 版曾错）
    return f"{x1:064x}{y1:064x}"


def point_add(p1_hex: str, p2_hex: str) -> str:
    """仿射点加（无穷远点=全零 128hex）。

    完备分支纪律（AUTH 电路仿射加法完备化同款教训，2026-10-10 ③站复用）：
    等值点走倍点（gmssl _add_point 斜率分母 2y 对 P1==P2 退化为无穷远——
    实测 z=0）；x 同 y 互逆=和为 O；其余走通用 Jacobian 加。"""
    if len(p1_hex) != 128 or len(p2_hex) != 128:
        raise SM2Error("点坐标须 128 hex（仿射 xy）")
    if p1_hex == "0" * 128:
        return p2_hex
    if p2_hex == "0" * 128:
        return p1_hex
    c = _c("", _G)
    if p1_hex == p2_hex:
        return c._kg(2, p1_hex)
    if p1_hex[:64] == p2_hex[:64] and (int(p1_hex[64:], 16) + int(p2_hex[64:], 16)) % _P == 0:
        return "0" * 128
    jac = c._add_point(p1_hex, p2_hex)
    return _jac_to_affine(jac)


def point_mul(scalar: int, p_hex: str) -> str:
    """点标量乘 [s]P（仿射 128hex；s=0 或 P=O ⟹ O）。"""
    if scalar % _N == 0 or p_hex == "0" * 128:
        return "0" * 128
    if len(p_hex) != 128 or not _point_on_curve(p_hex):
        raise SM2Error("点坐标非法（须 128 hex 且在曲线上）")
    c = _c("", _G)
    return c._kg(scalar % _N, p_hex)


def decrypt_share(share_sk_hex: str, c1_hex: str) -> str:
    """份额域出解密份额 [dᵢ]C₁（仿射 128hex）——dᵢ 本身不出域。

    份额须为 [1, n-1] 的标量（shamir_split 产物形态=64hex 内含前导零亦合法）。"""
    d_i = int(share_sk_hex, 16)
    if d_i <= 0 or d_i >= _N:
        raise SM2Error("份额标量须在 [1, n-1]")
    if len(c1_hex) != 128 or not _point_on_curve(c1_hex):
        raise SM2Error("SM2 密文 C1 非法（须 128 hex 且在曲线上）")
    return point_mul(d_i, c1_hex)


def combine_decrypt_shares(shares: list[tuple[int, str]], c1_hex: str) -> str:
    """合成 [d]C₁：Σλᵢ[dᵢ]C₁（拉格朗日系数 mod n；点加串联）。

    shares=[(i, [dᵢ]C₁ hex)]——≥k 个不同下标的份额点。**d 不在此重组**
    （全程点域运算——重建 d 需要离散对数，计算不可行即安全边界）。"""
    if len(shares) < 2:
        raise SM2Error("门限解密须 ≥2 份额（2-of-3 语义——单份额 C3 必败）")
    idx = [i for i, _ in shares]
    if len(set(idx)) != len(idx):
        raise SM2Error("份额下标重复（同域两份不构成独立份额）")
    acc = "0" * 128
    for i, pt in shares:
        lam = lagrange_coeff(i, idx)
        term = point_mul(lam, pt)
        acc = point_add(acc, term)
    if acc == "0" * 128:
        raise SM2Error("份额合成得无穷远点（份额与密文不匹配/域混入）")
    return acc


def _ecies_split(ct: bytes) -> tuple[str, bytes, bytes]:
    if len(ct) < 64 + 32 + 1:
        raise SM2Error("SM2 密文长度非法")
    c1_hex = ct[:64].hex()
    if not _point_on_curve(c1_hex):
        raise SM2Error("SM2 密文 C1 不在曲线上")
    return c1_hex, ct[64:96], ct[96:]


def threshold_decrypt(ct: bytes, shares: list[tuple[int, str]]) -> bytes:
    """门限解密（GB/T 完整校验路径）：合成 [d]C₁ → KDF → 异或 → C3 对拍。

    任何一步失败（份额错/域混/密文篡改）⟹ SM2Error——不返回垃圾明文。"""
    c1_hex, c3, c2 = _ecies_split(ct)
    xy_hex = combine_decrypt_shares(shares, c1_hex)
    x2, y2 = bytes.fromhex(xy_hex[:64]), bytes.fromhex(xy_hex[64:])
    t = _kdf(x2 + y2, len(c2))
    if not any(t):
        raise SM2Error("门限解密失败：KDF 派生密钥全零")
    m = bytes(a ^ b for a, b in zip(c2, t, strict=True))
    if sm3_bytes(x2 + m + y2) != c3:
        raise SM2Error("门限解密失败：C3 校验不通过（份额或密文不匹配）")
    return m


def _kdf(z: bytes, klen: int) -> bytes:
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += sm3_bytes(z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])
