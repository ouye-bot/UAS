"""SM4-GCM AEAD——引擎选择（2026-09-04 根修，复刻 sm3.py 0C 先例）。

测量定谳 [实测]：纯 Python 引擎（gmssl 裸块 + 自实现 GHASH/CTR）吞吐仅
0.17 MB/s（64KB 加密 396ms）——1MB 级政务材料加密需 6s，F1/F2/F5 业务路径
生产不可用，与 0C 的 KDF 431s 同类阻断缺陷。

根修：优先 OpenSSL C 实现（libcrypto EVP_CIPHER_fetch("SM4-GCM")，ctypes
零新依赖），且仅当其通过三组官方向量（RFC 8998 A.1 + GB/T 36624-2018 C.5
两例）逐字节验证后才启用；库缺失/能力缺失/验证失败自动回落纯 Python 实现
（保留为参考引擎，慢层守卫）。`FZ_SM4_FORCE_PURE=1` 强制回落（慢层/诊断）。

事实依据（2026-09-01 探针 [实测]，纯引擎）：
- pypi gmssl 3.2.2 的 SM4 核心 = GB/T 32907 合规；
- 🔴 mode 常量反直觉：SM4_ENCRYPT=0, SM4_DECRYPT=1，只用符号常量；
- pycryptodome 无 SM4 [实测 2026-09-04]；OpenSSL 3 的 EVP_get_cipherbyname
  查不到 provider 算法（返回 NULL），必须 EVP_CIPHER_fetch [实测]。
"""

from __future__ import annotations

import contextlib
import ctypes
import hmac as _hmac  # 仅用其 compare_digest 常时比较
import os

from gmssl.sm4 import SM4_DECRYPT, SM4_ENCRYPT, CryptSM4

from app.crypto._ossl import load_libcrypto

_R = 0xE1 << 120  # GCM 域多项式约化常数（SP 800-38D）

# --- 引擎选通锚向量（与 tests/test_crypto_sm4.py 同源，GmSSL C 官方套件） ---
_RFC_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
_RFC_IV = bytes.fromhex("00001234567800000000ABCD")
_RFC_AAD = bytes.fromhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
_RFC_PT = bytes.fromhex(
    "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
    "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
)
_RFC_CT = bytes.fromhex(
    "17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735"
    "D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D"
)
_RFC_TAG = bytes.fromhex("83DE3541E4C2B58177E065A9BF7B62EC")
_GBT_ZKEY = bytes(16)
_GBT_ZIV = bytes(12)
_GBT_C5_1_TAG = bytes.fromhex("232F0CFE308B49EA6FC88229B5DC858D")
_GBT_C5_2_PT = bytes(16)
_GBT_C5_2_CT = bytes.fromhex("7DE2AA7F1110188218063BE1BFEB6D89")
_GBT_C5_2_TAG = bytes.fromhex("B851B5F39493752BE508F1BB4482C557")


class SM4GCMError(Exception):
    """GCM 认证失败（tag 不匹配）。"""


def _gf128_mul(x: int, y: int) -> int:
    """GF(2^128) 乘法（SP 800-38D 算法 1，MSB 序）。"""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


class PureSM4GCM:
    """纯 Python 参考引擎（gmssl 裸块 + 自实现 GHASH/CTR）。

    保留语义：①回落引擎（OpenSSL 不可用/验证失败时自动启用）；
    ②慢层全量向量守卫对象；③裸块原语暴露（GB/T 32907 核心向量锚定面）。
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError("SM4 密钥必须 16 字节")
        self._enc = CryptSM4()
        self._enc.set_key(list(key), SM4_ENCRYPT)  # 注意：ENCRYPT=0
        self._dec = CryptSM4()
        self._dec.set_key(list(key), SM4_DECRYPT)  # 注意：DECRYPT=1
        self._h = int.from_bytes(self._raw_block(bytes(16)), "big")

    # --- 裸块原语（gmssl one_round 适配） ---

    def _raw_block(self, block: bytes) -> bytes:
        return bytes(self._enc.one_round(self._enc.sk, list(block)))

    def _raw_block_dec(self, block: bytes) -> bytes:
        return bytes(self._dec.one_round(self._dec.sk, list(block)))

    # --- GCM 内部 ---

    @staticmethod
    def _inc32(block: bytes) -> bytes:
        n = (int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF
        return block[:12] + n.to_bytes(4, "big")

    def _ctr(self, icb: bytes, data: bytes) -> bytes:
        out = bytearray()
        cb = icb
        for i in range(0, len(data), 16):
            ks = self._raw_block(cb)
            out.extend(a ^ b for a, b in zip(data[i : i + 16], ks, strict=False))
            cb = self._inc32(cb)
        return bytes(out)

    def _ghash(self, aad: bytes, ct: bytes) -> bytes:
        y = 0
        for buf in (aad, ct):
            for i in range(0, len(buf), 16):
                blk = buf[i : i + 16]
                if len(blk) < 16:
                    blk += bytes(16 - len(blk))
                y = _gf128_mul(y ^ int.from_bytes(blk, "big"), self._h)
        lens = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
        return _gf128_mul(y ^ int.from_bytes(lens, "big"), self._h).to_bytes(16, "big")

    # --- AEAD 接口 ---

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        if len(nonce) != 12:
            raise ValueError("GCM nonce 必须 12 字节（96 位 IV）")
        j0 = nonce + b"\x00\x00\x00\x01"
        ct = self._ctr(self._inc32(j0), plaintext)
        s = self._ghash(aad, ct)
        ek_j0 = self._raw_block(j0)
        tag = bytes(a ^ b for a, b in zip(ek_j0, s, strict=True))
        return ct, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        if len(nonce) != 12:
            raise ValueError("GCM nonce 必须 12 字节（96 位 IV）")
        if len(tag) != 16:
            raise SM4GCMError("tag 必须 16 字节")
        j0 = nonce + b"\x00\x00\x00\x01"
        s = self._ghash(aad, ciphertext)
        ek_j0 = self._raw_block(j0)
        expect = bytes(a ^ b for a, b in zip(ek_j0, s, strict=True))
        if not _hmac.compare_digest(expect, tag):  # 常时比较防时序侧信道
            raise SM4GCMError("GCM 认证失败")
        return self._ctr(self._inc32(j0), ciphertext)


# --- OpenSSL EVP 引擎（OpenSSL 3 provider 正道：EVP_CIPHER_fetch） ---

_EVP_CTRL_GCM_SET_IVLEN = 0x9
_EVP_CTRL_GCM_GET_TAG = 0x10
_EVP_CTRL_GCM_SET_TAG = 0x11

_libcrypto = None
_evp_cipher_sm4gcm = None


def _load_libcrypto() -> None:
    """委托共享装载器（app.crypto._ossl）：定位+健康探针（SM3 provider 检查）。"""
    global _libcrypto, _evp_cipher_sm4gcm
    if _libcrypto is not None:
        return
    lib = load_libcrypto()
    lib.EVP_CIPHER_fetch.restype = ctypes.c_void_p
    lib.EVP_CIPHER_fetch.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    cipher = lib.EVP_CIPHER_fetch(None, b"SM4-GCM", None)
    if not cipher:
        raise OSError("libcrypto 无 SM4-GCM provider 能力")
    lib.EVP_CIPHER_free.argtypes = [ctypes.c_void_p]
    _bind_evp_symbols(lib)
    _libcrypto = lib
    # fetched cipher 进程级持有（引用计数不释放——生命周期=进程）
    _evp_cipher_sm4gcm = cipher


def _bind_evp_symbols(lib: ctypes.CDLL) -> None:
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_new.argtypes = []
    lib.EVP_CIPHER_CTX_free.restype = None
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    # Init=(ctx,cipher,impl,key,iv)、Update=(ctx,out,int* outl,in,inl) 均 5 参；
    # Final=(ctx,out,int* outl) 仅 3 参——签名必须逐类绑定（ctypes 按声明强制实参数）
    init_update = (
        "EVP_EncryptInit_ex",
        "EVP_DecryptInit_ex",
        "EVP_EncryptUpdate",
        "EVP_DecryptUpdate",
    )
    for fn in init_update:
        getattr(lib, fn).restype = ctypes.c_int
        getattr(lib, fn).argtypes = [ctypes.c_void_p] * 5
    for fn in ("EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex"):
        getattr(lib, fn).restype = ctypes.c_int
        getattr(lib, fn).argtypes = [ctypes.c_void_p] * 3
    lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
    ]


class EvpSM4GCM:
    """OpenSSL EVP 引擎（C 实现的 CTR+GHASH，吞吐 GB/s 量级）。"""

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError("SM4 密钥必须 16 字节")
        _load_libcrypto()
        self._key = key

    def _new_ctx(self, *, encrypt: bool, nonce: bytes) -> int:
        ctx = _libcrypto.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_CIPHER_CTX_new 失败")
        init = _libcrypto.EVP_EncryptInit_ex if encrypt else _libcrypto.EVP_DecryptInit_ex
        if init(ctx, _evp_cipher_sm4gcm, None, None, None) != 1:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)
            raise RuntimeError("EVP init(cipher) 失败")
        if _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)
            raise RuntimeError("EVP SET_IVLEN 失败")
        if init(ctx, None, None, self._key, nonce) != 1:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)
            raise RuntimeError("EVP init(key,iv) 失败")
        return ctx

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        if len(nonce) != 12:
            raise ValueError("GCM nonce 必须 12 字节（96 位 IV）")
        ctx = self._new_ctx(encrypt=True, nonce=nonce)
        try:
            outl = ctypes.c_int(0)
            if (
                aad
                and _libcrypto.EVP_EncryptUpdate(ctx, None, ctypes.byref(outl), aad, len(aad)) != 1
            ):
                raise RuntimeError("EVP AAD 失败")
            out = ctypes.create_string_buffer(len(plaintext) + 16)
            if (
                _libcrypto.EVP_EncryptUpdate(
                    ctx, out, ctypes.byref(outl), plaintext, len(plaintext)
                )
                != 1
            ):
                raise RuntimeError("EVP encrypt update 失败")
            ct = out.raw[: outl.value]
            fin = ctypes.create_string_buffer(16)
            if _libcrypto.EVP_EncryptFinal_ex(ctx, fin, ctypes.byref(outl)) != 1:
                raise RuntimeError("EVP encrypt final 失败")
            tag = ctypes.create_string_buffer(16)
            if _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_GET_TAG, 16, tag) != 1:
                raise RuntimeError("EVP GET_TAG 失败")
            return ct, tag.raw[:16]
        finally:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        if len(nonce) != 12:
            raise ValueError("GCM nonce 必须 12 字节（96 位 IV）")
        if len(tag) != 16:
            raise SM4GCMError("tag 必须 16 字节")
        ctx = self._new_ctx(encrypt=False, nonce=nonce)
        try:
            outl = ctypes.c_int(0)
            if (
                aad
                and _libcrypto.EVP_DecryptUpdate(ctx, None, ctypes.byref(outl), aad, len(aad)) != 1
            ):
                raise RuntimeError("EVP AAD 失败")
            if (
                _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_TAG, 16, ctypes.c_char_p(tag))
                != 1
            ):
                raise RuntimeError("EVP SET_TAG 失败")
            out = ctypes.create_string_buffer(len(ciphertext) + 16)
            if (
                _libcrypto.EVP_DecryptUpdate(
                    ctx, out, ctypes.byref(outl), ciphertext, len(ciphertext)
                )
                != 1
            ):
                raise RuntimeError("EVP decrypt update 失败")
            pt = out.raw[: outl.value]
            fin = ctypes.create_string_buffer(16)
            if _libcrypto.EVP_DecryptFinal_ex(ctx, fin, ctypes.byref(outl)) != 1:
                raise SM4GCMError("GCM 认证失败")
            return pt
        finally:
            _libcrypto.EVP_CIPHER_CTX_free(ctx)


def _verify_evp_anchors() -> bool:
    """三组官方向量逐字节验证（encrypt+decrypt 双路径）——通过才准启用。"""
    g = EvpSM4GCM(_RFC_KEY)
    ct, tag = g.encrypt(_RFC_IV, _RFC_PT, _RFC_AAD)
    if ct != _RFC_CT or tag != _RFC_TAG:
        return False
    if g.decrypt(_RFC_IV, _RFC_CT, _RFC_TAG, _RFC_AAD) != _RFC_PT:
        return False
    z = EvpSM4GCM(_GBT_ZKEY)
    ct1, tag1 = z.encrypt(_GBT_ZIV, b"", b"")
    if ct1 != b"" or tag1 != _GBT_C5_1_TAG:
        return False
    ct2, tag2 = z.encrypt(_GBT_ZIV, _GBT_C5_2_PT, b"")
    if ct2 != _GBT_C5_2_CT or tag2 != _GBT_C5_2_TAG:
        return False
    return z.decrypt(_GBT_ZIV, _GBT_C5_2_CT, _GBT_C5_2_TAG, b"") == _GBT_C5_2_PT


def _select_engine() -> str:
    """引擎选通：OpenSSL 仅在三组锚向量通过时启用（sm3.py 同款纪律）。"""
    if os.environ.get("FZ_SM4_FORCE_PURE") == "1":
        return "pure"
    with contextlib.suppress(Exception):
        if _verify_evp_anchors():
            return "openssl"
    return "pure"


_ENGINE = _select_engine()

# 公共名：调用方/既有测试零改动（bytes 进出、tag 恒 16B、错误面不变）
SM4GCM: type = EvpSM4GCM if _ENGINE == "openssl" else PureSM4GCM


def engine_name() -> str:
    """当前 SM4-GCM 引擎（"openssl" | "pure"）；供测试与运维自省。"""
    return _ENGINE
