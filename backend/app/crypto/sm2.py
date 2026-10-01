"""SM2 封装：密钥/签名/验签/ECIES。

红线：
- 随机性一律 secrets（gmssl.func.random_hex 基于 random 模块，非 CSPRNG，禁用）；
- 曲线常量一律 default_ecc_table（禁手抄）；
- verify_digest 为 GB/T 32918.5 验证方程的自实现（供 A.2 向量与"给 e 验签"场景），
  与引擎路径 verify 形成 differential 双实现（跨引擎同判测试锚定）。

引擎选择（2026-09-05 根修，复刻 sm3/sm4 先例）：
- 验签是热路径（登录/四要素头/业务 API），测量定谳 [实测]：纯 Python 10.15 ms/op
  为前作宣称值 1.33ms 的 7.5×慢——评审必被追问的性能项；
- OpenSSL EVP 主径（EVP_PKEY_fromdata + EVP_DigestVerify，SM3+SM2 组+distid），
  PoC 实测 0.324 ms/op（31×，反超前作宣称值 4×）；启用前三重差分锚
  （自签自验/篡改拒绝/错钥拒绝）必须全过，否则自动回落纯实现；
- 🔴 EVP_PKEY_fromdata 的 selection 必须为 0x86（PUBLIC_KEY =
  DOMAIN_PARAMETERS|OTHER_PARAMETERS|PUBLIC_KEY，core_dispatch.h 复合宏真值；
  传 1/2 静默失败且无错误队列入栈——RSA 宽容、EC 族严格，排障 3 小时实证）；
  Z 身份必须 pctx set1_id（key 级 distid 参数不参与 EVP 摘要路径）；
- 签名保持纯实现（10ms 冷路径：签发/仪式低频；引擎化见开放项）；
- FZ_SM2_FORCE_PURE=1 强制回落（慢层/诊断）。
"""

from __future__ import annotations

import ctypes
import os
import secrets

from gmssl.sm2 import CryptSM2, default_ecc_table

from app.crypto._ossl import load_libcrypto
from app.crypto.sm3 import sm3_bytes

_N = int(default_ecc_table["n"], 16)
_P = int(default_ecc_table["p"], 16)
_A = int(default_ecc_table["a"], 16)
_B = int(default_ecc_table["b"], 16)
_G = default_ecc_table["g"]  # 128hex x||y


class SM2Error(Exception):
    """SM2 操作失败（解密失败/密钥非法等）。"""


def _assert_priv(priv_hex: str) -> None:
    d = int(priv_hex, 16) if priv_hex else 0
    if not 1 <= d <= _N - 2:
        # SP-19 跨线同步①（共享仓 T6-defect-1 同族）：Keygen 域收窄到 [1, n-2]。
        # d=n-1 使 (1+d)^{-1} 不存在——本侧实测产出的签名恒不过验证（静默废件，
        # 2026-09-13 探针）；vendor 侧（zkc t1 装配）为非终止重采样（论文 40,000+
        # 迭代 trace 实锤）。ingest 咽点拒收 = 双面 fail-fast。
        raise SM2Error("SM2 私钥不在 [1, n-2]（GB/T 32918.2 Keygen 域；n-1 使 (1+d)^-1 不存在）")


def _assert_pub(pub_hex: str) -> None:
    if len(pub_hex) != 128:
        raise SM2Error("SM2 公钥必须 128 hex（x||y）")
    if not _point_on_curve(pub_hex):
        raise SM2Error("SM2 公钥不在曲线上")


def assert_pub(pub_hex: str) -> None:
    """公开校验入口（API 层用）：非 128 hex / 不在曲线 → SM2Error。"""
    _assert_pub(pub_hex)


def _point_on_curve(pub_hex: str) -> bool:
    x = int(pub_hex[:64], 16)
    y = int(pub_hex[64:], 16)
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _c(priv_hex: str, pub_hex: str) -> CryptSM2:
    """构造 gmssl 实例。ECIES 用 C1C3C2 序（mode=1，GB/T 口径）。"""
    return CryptSM2(private_key=priv_hex or "0" * 64, public_key=pub_hex, mode=1)


def generate_keypair() -> tuple[str, str]:
    """生成 (priv_hex64, pub_hex128)。私钥均匀取自 [1, n-1]。"""
    priv = format(secrets.randbelow(_N - 1) + 1, "064x")
    return priv, pubkey_from_priv(priv)


def _kg_blinded(c, d: int, point_hex: str) -> str:  # noqa: ANN001
    """标量盲化点乘（SP9 9.19 时序侧信道防线）：随机分裂 d = d1 + d2 (mod n)，
    计算 [d1]P + [d2]P——每次调用的 _kg 位模式与 d 去相关。

    数学恒等：[d1]P + [d2]P = [d]P（群阶归约）；输出与非盲化路径逐字节一致
    （测试锚定）。代价：2× 标量乘 + 1 点加——解密路径 ~2×（可接受，冷路径）；
    pubkey 推导经 LRU 缓存每钥仅一次。分裂值 ∈ [1, n-1] 且互异（d2=0 概率
    ~2^-256，护栏回退单乘）。gmssl _add_point 契约：P1 仿射(128hex, z 隐 1)、
    P2 需带 z（'1' 尾），返回 Jacobian → _convert_jacb_to_nor 归一。
    """
    d1 = secrets.randbelow(_N - 1) + 1
    d2 = (d - d1) % _N
    if d2 == 0:
        return c._kg(d1, point_hex)
    p1 = c._kg(d1, point_hex)
    p2 = c._kg(d2, point_hex)
    return c._convert_jacb_to_nor(c._add_point(p1, p2 + "1"))


_pub_cache: dict[str, str] = {}  # priv_hex -> pub（LRU 有界；秘密标量乘每钥一次）


def pubkey_from_priv(priv_hex: str) -> str:
    _assert_priv(priv_hex)
    hit = _pub_cache.get(priv_hex)
    if hit is not None:
        return hit
    c = _c(priv_hex, _G)
    pub = _kg_blinded(c, int(priv_hex, 16), _G)
    if len(pub) != 128:
        # 格式不变式（fail-closed）：本域公钥=X‖Y 无 04 前缀恒 128 hex
        # （2026-09-30 误诊纠正：曾疑盲化路径剥前导零——88k 采样零复现；
        # 真因=测试助手对无前缀公钥误 removeprefix("04")，已拔除）
        raise ValueError(f"公钥推导异常（{len(pub)} hex≠128）——拒绝出钥")
    if len(_pub_cache) >= 1024:
        _pub_cache.pop(next(iter(_pub_cache)))  # FIFO 有界（与 EVP pkey 缓存同纪律）
    _pub_cache[priv_hex] = pub
    return pub


_ID_DEFAULT_HEX = "31323334353637383132333435363738"  # 默认用户 ID "1234567812345678"
_ENTL_DEFAULT_HEX = "0080"  # ENTL=128 bit


def _za(pub_hex: str) -> bytes:
    """Z_A = SM3(ENTL || ID || a || b || xG || yG || xA || yA)。

    gmssl._sm3_z 不接受自定义 ID（硬编码默认值），此处自实现同口径；
    默认 ID 全系统统一，改动须同步所有签名方/验签方。
    """
    blob = (
        _ENTL_DEFAULT_HEX
        + _ID_DEFAULT_HEX
        + default_ecc_table["a"]
        + default_ecc_table["b"]
        + _G
        + pub_hex
    )
    return sm3_bytes(bytes.fromhex(blob))


def _digest_z(pub_hex: str, msg: bytes) -> bytes:
    """SM2-withSM3（Z 路径）摘要：e = SM3(Z_A || M)。"""
    return sm3_bytes(_za(pub_hex) + msg)


def sign(priv_hex: str, msg: bytes) -> str:
    """SM2 签名（SM2-withSM3，Z 路径），返回 128hex r||s，K 来自 secrets。

    gmssl.sign(data, K) 是"对摘要直接签名"的原语（内部无哈希），故先自算
    Z 路径摘要再喂入；R/S 触零（概率 ~2^-n）时换 k 重签。
    """
    _assert_priv(priv_hex)
    pub = pubkey_from_priv(priv_hex)
    e = _digest_z(pub, msg)
    c = _c(priv_hex, pub)
    while True:
        k = format(secrets.randbelow(_N - 1) + 1, "064x")
        sig = c.sign(e, k)
        if sig is not None:
            return sig


def sign_digest(priv_hex: str, digest32: bytes) -> str:
    """裸摘要签名：e = digest 直接入 SM2 方程（无 ZA、无内部哈希），返回 128hex r||s。

    与 Z 路径 sign 并存的第二原语：FISCO BCOS 2.x 节点对交易验签即此口径
    （e = keccak(rlp(交易体)) 直接入方程；python-sdk Signer_GM.sign →
    CryptSM2.sign 对源锚定，2026-09-01 真链 InvalidSignature 实证 Z 路径
    不适用于交易签名）。消息级签名（GB/T 32918.3 完整流程）仍用 Z 路径 sign。
    """
    _assert_priv(priv_hex)
    if len(digest32) != 32:
        raise SM2Error("签名摘要须 32 字节")
    c = _c(priv_hex, pubkey_from_priv(priv_hex))
    while True:
        k = format(secrets.randbelow(_N - 1) + 1, "064x")
        sig = c.sign(digest32, k)
        if sig is not None:
            return sig


# --- OpenSSL EVP 验签引擎（Z 路径，GB/T 32918.3 SM2-withSM3 口径） ---

_Z_KEYMGMT_SELECT_PUBLIC = 0x86  # DOMAIN|OTHER|PUBLIC（复合宏展开真值，禁改）
_Z_OSSL_PARAM_UTF8 = 4
_Z_OSSL_PARAM_OCTET = 5
_Z_PKEY_CACHE_CAP = 1024

_evp_lib = None
_pkey_cache: dict[str, int] = {}  # pub_hex -> EVP_PKEY*（进程级有界缓存，不主动 free）


def _evp_symbols():
    """绑定 EVP 验签所需符号（进程级一次）。"""
    global _evp_lib
    if _evp_lib is not None:
        return _evp_lib
    lib = load_libcrypto()
    for fn, rest, args in [
        (
            "EVP_PKEY_CTX_new_from_name",
            ctypes.c_void_p,
            [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p],
        ),
        ("EVP_PKEY_CTX_free", None, [ctypes.c_void_p]),
        ("EVP_PKEY_fromdata_init", ctypes.c_int, [ctypes.c_void_p]),
        (
            "EVP_PKEY_fromdata",
            ctypes.c_int,
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_void_p],
        ),
        ("EVP_MD_CTX_new", ctypes.c_void_p, []),
        ("EVP_MD_CTX_free", None, [ctypes.c_void_p]),
        ("EVP_MD_fetch", ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]),
        ("EVP_MD_free", None, [ctypes.c_void_p]),
        (
            "EVP_DigestVerifyInit",
            ctypes.c_int,
            [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ],
        ),
        ("EVP_PKEY_CTX_set1_id", ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]),
        (
            "EVP_DigestVerify",
            ctypes.c_int,
            [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t],
        ),
    ]:
        f = lib.__getattr__(fn)
        f.restype = rest
        f.argtypes = args
    _evp_lib = lib
    return lib


class _OsslParam(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_char_p),
        ("data_type", ctypes.c_uint),
        ("data", ctypes.c_void_p),
        ("data_size", ctypes.c_size_t),
        ("return_size", ctypes.c_size_t),
    ]


def _evp_pkey_of(pub_hex: str) -> int:
    """公钥 → EVP_PKEY*（每公钥缓存；EVP_PKEY 创建后只读可跨线程共享）。"""
    cached = _pkey_cache.get(pub_hex)
    if cached is not None:
        return cached
    lib = _evp_symbols()
    point = b"\x04" + bytes.fromhex(pub_hex)
    group_buf = ctypes.create_string_buffer(b"sm2")
    pub_buf = ctypes.create_string_buffer(point)
    ctx = lib.EVP_PKEY_CTX_new_from_name(None, b"SM2", None)
    if not ctx:
        raise OSError("SM2 keymgmt 不可用")
    try:
        if lib.EVP_PKEY_fromdata_init(ctx) != 1:
            raise OSError("fromdata_init 失败")
        params = (_OsslParam * 3)(
            _OsslParam(b"group", _Z_OSSL_PARAM_UTF8, ctypes.cast(group_buf, ctypes.c_void_p), 3, 0),
            _OsslParam(
                b"pub", _Z_OSSL_PARAM_OCTET, ctypes.cast(pub_buf, ctypes.c_void_p), len(point), 0
            ),
            _OsslParam(),
        )
        pkey = ctypes.c_void_p()
        if (
            lib.EVP_PKEY_fromdata(ctx, ctypes.byref(pkey), _Z_KEYMGMT_SELECT_PUBLIC, params) != 1
            or not pkey.value
        ):
            raise OSError("EVP_PKEY_fromdata 失败（selection/参数形态）")
    finally:
        lib.EVP_PKEY_CTX_free(ctx)
    if len(_pkey_cache) >= _Z_PKEY_CACHE_CAP:
        _pkey_cache.popitem()  # 有界：淘汰任意项（重建成本 ~0.1ms）
    _pkey_cache[pub_hex] = pkey.value
    return pkey.value


def _evp_verify_z(pub_hex: str, msg: bytes, sig_hex: str) -> bool:
    """EVP Z 路径验签：e = SM3(Z_ID || M)，ID 与 _za 同源（"1234567812345678"）。

    每次调用新鲜 MD_CTX（线程安全）；raw r||s → DER 编码后入 EVP_DigestVerify。
    任何内部异常向上抛出——由 verify() 捕获回落纯实现（参考实现，fail-closed 等价）。
    """
    lib = _evp_symbols()
    pkey = _evp_pkey_of(pub_hex)
    md = lib.EVP_MD_fetch(None, b"SM3", None)
    if not md:
        raise OSError("SM3 fetch 失败")
    mctx = lib.EVP_MD_CTX_new()
    if not mctx:
        raise OSError("MD_CTX 分配失败")
    try:
        pctx = ctypes.c_void_p()
        if lib.EVP_DigestVerifyInit(mctx, ctypes.byref(pctx), md, None, pkey) != 1:
            raise OSError("DigestVerifyInit 失败")
        idbuf = ctypes.create_string_buffer(bytes.fromhex(_ID_DEFAULT_HEX))
        if lib.EVP_PKEY_CTX_set1_id(pctx, idbuf, 16) != 1:
            raise OSError("set1_id 失败")
        raw = bytes.fromhex(sig_hex)
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")

        def _int_der(v: int) -> bytes:
            b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
            if b[0] & 0x80:
                b = b"\x00" + b
            return b"\x02" + bytes([len(b)]) + b

        body = _int_der(r) + _int_der(s)
        der = b"\x30" + bytes([len(body)]) + body
        return lib.EVP_DigestVerify(mctx, der, len(der), msg, len(msg)) == 1
    finally:
        lib.EVP_MD_CTX_free(mctx)
        lib.EVP_MD_free(md)


def _evp_anchor_pass() -> bool:
    """三重差分锚（启用门槛）：自签自验/篡改拒绝/错钥拒绝全过才启用。"""
    priv, pub = generate_keypair()
    msg = b"YZT-SM2-ENGINE-ANCHOR"
    sig = sign(priv, msg)
    if not _evp_verify_z(pub, msg, sig):
        return False
    bad = format(int(sig[:64], 16) ^ 1, "064x") + sig[64:]
    if _evp_verify_z(pub, msg, bad):
        return False
    _, pub2 = generate_keypair()
    return not _evp_verify_z(pub2, msg, sig)


def _select_engine() -> str:
    if os.environ.get("FZ_SM2_FORCE_PURE") == "1":
        return "pure"
    try:
        if _evp_anchor_pass():
            return "openssl"
    except Exception:  # noqa: BLE001  （任何装载/锚失败=回落，不阻塞导入）
        pass
    return "pure"


_ENGINE = _select_engine()


def engine_name() -> str:
    """当前验签引擎（"openssl" | "pure"）；供测试与运维自省。"""
    return _ENGINE


def verify(pub_hex: str, msg: bytes, sig_hex: str) -> bool:
    """SM2-withSM3 验签（Z 路径）——引擎分发入口。

    openssl 主径（EVP，0.324ms/op [实测]）；内部异常回落纯实现
    （verify_digest 是参考实现，回落=同等正确性，fail-closed 等价）。
    """
    try:
        _assert_pub(pub_hex)
    except SM2Error:
        return False
    if len(sig_hex) != 128:
        return False
    if _ENGINE == "openssl":
        try:
            return _evp_verify_z(pub_hex, msg, sig_hex)
        except Exception:  # noqa: BLE001
            pass
    return verify_digest(pub_hex, _digest_z(pub_hex, msg), sig_hex)


def verify_digest(pub_hex: str, digest32: bytes, sig_hex: str) -> bool:
    """自实现验签：给定摘要 e（GB/T 32918.5 验证方程）。

    (x1, y1) = [s]G + [t]P_A，t = (r+s) mod n；当 (e + x1) mod n == r 时有效。
    注意操作数角色：s 打基点 G、t 打公钥 P_A（写反即验签恒败，A.2 实证）。
    gmssl._add_point 返回 Jacobian (x||y||z)，须仿射化后取 x1。
    """
    try:
        _assert_pub(pub_hex)
        if len(digest32) != 32 or len(sig_hex) != 128:
            return False
        r = int(sig_hex[:64], 16)
        s = int(sig_hex[64:], 16)
        if not (1 <= r < _N and 1 <= s < _N):
            return False
        t = (r + s) % _N
        if t == 0:
            return False
        c = _c("", pub_hex)
        p1 = c._kg(s, _G)  # [s]G（仿射 128hex）
        p2 = c._kg(t, pub_hex)  # [t]P_A（仿射 128hex）
        jac = c._add_point(p1, p2)  # Jacobian x||y||z（192hex）
        if jac is None or len(jac) != 192:
            return False
        x, z = int(jac[:64], 16), int(jac[128:], 16)
        if z == 0:  # 和为无穷远点
            return False
        zinv = pow(z, _P - 2, _P)
        x1 = x * zinv % _P * zinv % _P
        e = int.from_bytes(digest32, "big")
        return (e + x1) % _N == r
    except (SM2Error, ValueError, ZeroDivisionError):
        return False


def _kdf(z: bytes, klen: int) -> bytes:
    """SM2 密钥派生函数 KDF（GB/T 32906，SM3 计数器自 1 起）。"""
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += sm3_bytes(z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])


def encrypt(pub_hex: str, plaintext: bytes) -> bytes:
    """SM2 ECIES 加密（C1C3C2 序，GB/T 口径）。

    自实现而非用 gmssl.encrypt：其内部随机 k 取自 func.random_hex
    （Python random，非 CSPRNG，红线禁用）。KDF 全零时按标准换 k 重试。
    """
    _assert_pub(pub_hex)
    if len(plaintext) < 1:
        raise SM2Error("SM2 加密明文不能为空（KDF 不支持 klen=0）")
    c = _c("", pub_hex)
    while True:
        k = secrets.randbelow(_N - 1) + 1
        c1 = c._kg(k, _G)  # [k]G 仿射 128hex
        xy = c._kg(k, pub_hex)  # [k]P_A 仿射 128hex
        x2, y2 = bytes.fromhex(xy[:64]), bytes.fromhex(xy[64:])
        t = _kdf(x2 + y2, len(plaintext))
        if any(t):
            break
    c2 = bytes(a ^ b for a, b in zip(plaintext, t, strict=True))
    c3 = sm3_bytes(x2 + plaintext + y2)
    return bytes.fromhex(c1) + c3 + c2  # C1||C3||C2


def decrypt(priv_hex: str, ct: bytes) -> bytes:
    """SM2 ECIES 解密（C1C3C2 序）。

    自实现而非用 gmssl.decrypt：其算出 C3 校验值 u 后并不比较（密文被
    篡改仍返回垃圾明文，3.2.2 实读源码实证），此处补齐 GB/T 完整校验。
    """
    _assert_priv(priv_hex)
    if len(ct) < 64 + 32 + 1:
        raise SM2Error("SM2 密文长度非法")
    c1_hex, c3, c2 = ct[:64].hex(), ct[64:96], ct[96:]
    if not _point_on_curve(c1_hex):
        raise SM2Error("SM2 密文 C1 不在曲线上")
    c = _c(priv_hex, _G)
    xy = _kg_blinded(c, int(priv_hex, 16), c1_hex)  # [d]C1 盲化（重复采样高危面）
    x2, y2 = bytes.fromhex(xy[:64]), bytes.fromhex(xy[64:])
    t = _kdf(x2 + y2, len(c2))
    if not any(t):
        raise SM2Error("SM2 解密失败：KDF 派生密钥全零")
    m = bytes(a ^ b for a, b in zip(c2, t, strict=True))
    if sm3_bytes(x2 + m + y2) != c3:
        raise SM2Error("SM2 解密失败：C3 校验不通过")
    return m
