"""libcrypto 共享装载器（sm3/sm4/sm2 引擎选择的公共底座）。

定位顺序：find_library → CONDA_PREFIX → sys.prefix → base_prefix；进程级
缓存（CDLL 只加载一次）。符号绑定由各引擎模块自行完成（职责分离）。
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys

_libcrypto = None
_load_error: str | None = None


def load_libcrypto() -> ctypes.CDLL:
    """进程级单例：返回 libcrypto CDLL；失败抛 OSError（由引擎选通捕获回落）。"""
    global _libcrypto, _load_error
    if _libcrypto is not None:
        return _libcrypto
    if _load_error is not None:
        raise OSError(_load_error)

    candidates: list[str] = []
    found = ctypes.util.find_library("crypto")
    if found:
        candidates.append(found)
    dll_names = (
        "libcrypto-3-x64.dll",
        "libcrypto-1_1-x64.dll",
        "libcrypto-3.dll",
        "libcrypto-1_1.dll",
    )
    for name in dll_names:
        candidates.append(name)
        for base in (os.environ.get("CONDA_PREFIX", ""), sys.prefix, sys.base_prefix):
            if base:
                candidates.append(os.path.join(base, "Library", "bin", name))
                candidates.append(os.path.join(base, "DLLs", name))
                candidates.append(os.path.join(base, name))

    last_err: Exception | None = None
    for cand in candidates:
        try:
            lib = ctypes.CDLL(cand)
            # 健康探针：SM3 摘要能力必须可用（provider 未加载即在此暴露，
            # 杜绝"引擎对象可用但算法缺失"的半装载态——2026-09-05 SM2 排障实证）
            lib.EVP_MD_fetch.restype = ctypes.c_void_p
            lib.EVP_MD_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            md = lib.EVP_MD_fetch(None, b"SM3", None)
            if not md:
                raise OSError(f"{cand} 无 SM3 provider 能力")
            lib.EVP_MD_free.argtypes = [ctypes.c_void_p]
            lib.EVP_MD_free(md)
        except (OSError, AttributeError) as exc:
            last_err = exc
            continue
        _libcrypto = lib
        return lib
    _load_error = f"libcrypto 定位失败（最后错误: {last_err}）"
    raise OSError(_load_error)
