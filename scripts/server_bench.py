#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""server_bench.py —— ⑦代电路服务器窗复测一键测量（性能档案 B1/B2 行前置套件）。

定位：大内存云服务器到位后"半天测完"的单文件执行入口。零第三方依赖
（Python 3.8+ 标准库），测量口径与 docs/性能档案.md「服务器窗 · 新电路四元组
判决行」（2026-09-27，④代 AUTH 25.14s/verify 0.68s、TRAIL 15.10s/0.21s，
12C/46G Alibaba Cloud Linux 4，nightly-2026-05-26，RAYON=12）逐项对齐。

子命令（默认 full）：
  self-check   环境自检：OS/CPU/内存/磁盘/工具链/git 画像打印（本地/服务器皆可跑，零构建）
  fingerprint  构建复现性门（源面）：按 pin_fingerprint.rs 同构式复算 vendor 快照
               指纹，必须等于 SM3(4201a82|b05df9d8…)——不等于即中止（轻量，~2.7MB 哈希）
  sm3-cross    纯 Python SM3 与既有 zkc 二进制（zkc sm3 --file）单文件对拍——
               不重跑重构建，验证指纹门哈希实现可信
  full         服务器主流程：自检 → 指纹门（源面）→ cargo release 构建 →
               AUTH canonical prove ×3 / TRAIL canonical prove ×3（N=3 取中位）→
               判决件指纹门（构建产物面）→ proof 尺寸/实例逐位核对 → 60s 硬门判定 →
               机器画像写入结果文件（JSON+Markdown 双输出，数字位自动填实测）

纪律：本脚本只读既有仓库文件；唯一写入面 = 结果目录与（服务器侧缺省时）
zksvc/.cargo/config.toml（从在册 config-offline-full.toml 复制，属服务器检出
内的新建件）。测量窗内不改任何源码——改码即换代，测量作废。
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ── 口径常量（三源核对，改任一源必须四/五面同步——见 docs/服务器窗复测前置准备.md）──

# 期望指纹：SM3(4201a82|b05df9d8…)——与 backend/scripts/crypto_audit.py
# PIN_LOCAL_EXPECTED、zksvc/build_manifest.json（pin=4201a82，
# aggregate_sm3=b05df9d8…）、zksvc/tests/auth_golden_vector.json
# zk_pin_fingerprint 三源逐字一致（2026-10-11 2.1 批 MANIFEST 151 文件换代态）。
EXPECTED_FINGERPRINT = (
    "SM3(4201a82|b05df9d8e2d5f39fb4d92b19d47379c86c0d40159e9fd39a1c9c77455b9b4985)"
)

AUTH_PROOF_BYTES_GOLDEN = 16_063_712   # ⑦代交织档 [实测 2026-10-06]
AUTH_INSTANCES_GOLDEN = 26             # SN 绑定换代后实例数（黄金向量 expected_instances_hex）
TRAIL_INSTANCES_GOLDEN = 8             # ⑦代 census 钉定断言（现行口径总表 TRAIL 行）

RAYON_THREADS = 12                     # ④代服务器窗口径（同窗最优，R1 扫参 + 09-27 对照）
N_RUNS = 3                             # 各语句实测次数，取中位
GATE_60S = 60.0                        # ≤60s 演示硬门（AUTH prove）

AUTH_SPEC_REL = "tests/auth_canonical_spec.json"
TRAIL_SPEC_REL = "tests/trail_canonical_spec.json"
GOLDEN_VECTOR_REL = "tests/auth_golden_vector.json"
CARGO_CONFIG_TEMPLATE = ".cargo/config-offline-full.toml"
CARGO_CONFIG_LIVE = ".cargo/config.toml"

# 测量口径禁设 env（存在即漂移口径：④代基线 = 部署默认 mask=on/il=1/dd=0/st=0）。
# MASK_OFF 为"存在即关"语义（任何值都算），故必须整键缺席。
FORBIDDEN_ENV = [
    "MASK_OFF",              # 掩蔽关闭=证明可链接，且 prove 时间口径漂移
    "FZ_ZK_SALT_PIN",        # 钉盐差分位=对拍专用世界，非部署口径
    "PCS_INTERLEAVE",        # 缺省即 il=1（apply_pcs_deployment_defaults），显式=漂移
    "PCS_BATCH_DEDUP",
    "PCS_VERIFY_STREAM",
    "FZ_ZK_PACKED_SUMCHECK", # 实验档 packed 通道，56× 反向性能
    "FZ_ZK_FORBID_SPEC_KEY", # canonical spec 自带夹具钥（witness 通道），部署禁令档
    "FZ_DEPLOYMENT",         # production 判定面，测量窗维持缺省 demo 形态
]
REQUIRED_ENV = {
    "FZ_ZK_ALLOW_AUTH": "1",   # AUTH 装配准入门禁
    "FZ_ZK_ALLOW_TRAIL": "1",  # TRAIL 装配准入门禁
}

BASELINE = {  # docs/性能档案.md 现行口径总表 + 「服务器窗 · 新电路四元组判决行」
    "gen": "④代",
    "date": "2026-09-27",
    "machine": "12C/46G Alibaba Cloud Linux 4",
    "toolchain": "nightly-2026-05-26",
    "rayon": 12,
    "auth": {"prove_s": 25.14, "verify_s": 0.68, "total_s": 32.39, "proof_bytes": 22_686_512,
             "setup_s": 0.25, "preprocess_s": 2.85},
    "trail": {"prove_s": 15.10, "verify_s": 0.21, "total_s": 20.38, "proof_bytes": 16_249_632,
              "setup_s": 0.24, "preprocess_s": 2.93},
}

TOOLS = ["rustc", "cargo", "rustup"]


# ── 纯 Python SM3（GB/T 32905-2016）——指纹门独立复算用，与 zkc（sm3 crate 0.4.2）对拍 ──

_SM3_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)
_MASK32 = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _sm3_of_bytes(data: bytes) -> str:
    h = _Sm3()
    h.update(data)
    return h.hexdigest()


def sm3_file(path: Path) -> str:
    h = _Sm3()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class _Sm3:
    """流式 SM3（指纹门逐文件重算用——与 sm3_bytes 同核心，分块喂入）。"""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._len = 0
        self._v = list(_SM3_IV)

    def update(self, data: bytes) -> None:
        self._buf += data
        self._len += len(data)
        off = 0
        while len(self._buf) - off >= 64:
            self._v = _compress(self._v, self._buf[off:off + 64])
            off += 64
        if off:
            del self._buf[:off]

    def hexdigest(self) -> str:
        pad = bytearray(self._buf)
        bit_len = (self._len * 8) & 0xFFFFFFFFFFFFFFFF
        pad.append(0x80)
        while len(pad) % 64 != 56:
            pad.append(0x00)
        pad += bit_len.to_bytes(8, "big")
        v = list(self._v)
        for off in range(0, len(pad), 64):
            v = _compress(v, pad[off:off + 64])
        return "".join(f"{x:08x}" for x in v)


def _compress(v: list, block) -> list:
    b = bytes(block)
    w = [int.from_bytes(b[i * 4:i * 4 + 4], "big") for i in range(16)]
    for j in range(16, 68):
        wj = _p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)) ^ _rotl(w[j - 13], 7) ^ w[j - 6]
        w.append(wj & _MASK32)
    a, bb, c, d, e, f, g, h = v
    for j in range(64):
        tj = 0x79CC4519 if j < 16 else 0x7A879D8A
        ss1 = _rotl(((_rotl(a, 12) + e + _rotl(tj, j % 32)) & _MASK32), 7)
        ss2 = ss1 ^ _rotl(a, 12)
        if j < 16:
            ff = a ^ bb ^ c
            gg = e ^ f ^ g
        else:
            ff = (a & bb) | (a & c) | (bb & c)
            gg = (e & f) | ((~e) & _MASK32 & g)
        wp = w[j] ^ w[j + 4]
        tt1 = (ff + d + ss2 + wp) & _MASK32
        tt2 = (gg + h + ss1 + w[j]) & _MASK32
        d = c
        c = _rotl(bb, 9)
        bb = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = _p0(tt2)
    return [(x ^ y) & _MASK32 for x, y in zip(v, (a, bb, c, d, e, f, g, h))]


# ── 仓库定位（零手抄路径：声明字段相对仓库根——与 prove.rs service_vendor_dir 同构）──

def repo_paths() -> dict:
    script = Path(__file__).resolve()
    root = script.parent.parent          # scripts/server_bench.py → 仓库根
    zksvc = root / "zksvc"
    return {"root": root, "zksvc": zksvc, "vendor_manifest": zksvc / "vendor" / "MANIFEST.json",
            "build_manifest": zksvc / "build_manifest.json", "golden": zksvc / GOLDEN_VECTOR_REL}


def load_build_manifest(zksvc: Path) -> dict:
    bm = json.loads((zksvc / "build_manifest.json").read_text(encoding="utf-8"))
    rel = bm["snapshot_dir"]              # 形如 zksvc/vendor/plonkish-4201a82，相对仓库根
    vendor = zksvc.parent / rel
    return {"bm": bm, "vendor": vendor, "manifest": vendor.parent / "MANIFEST.json"}


# ── 指纹门（pin_fingerprint.rs 同构：存在性+字节数+SM3 逐文件重算，fail-closed）──

def compute_vendor_fingerprint(zksvc: Path, verbose: bool = True) -> str:
    ctx = load_build_manifest(zksvc)
    manifest_path = ctx["manifest"]
    vendor = ctx["vendor"]
    if not manifest_path.is_file():
        raise SystemExit(f"[指纹门][中止] MANIFEST 不可读: {manifest_path}")
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = m["files"]
    if m["file_count"] != len(files):
        raise SystemExit(f"[指纹门][中止] MANIFEST 不自洽: file_count={m['file_count']} ≠ files.len={len(files)}")
    agg = _Sm3()
    total = 0
    for i, fent in enumerate(files):
        p = vendor / fent["path"]
        data = p.read_bytes()  # 不可读即抛异常中止（fail-closed 与 Rust 版同语义）
        if len(data) != fent["bytes"]:
            raise SystemExit(f"[指纹门][中止] 漂移（字节数）: {fent['path']}")
        if _sm3_of_bytes(data) != fent["sm3"]:
            raise SystemExit(f"[指纹门][中止] 漂移（SM3）: {fent['path']}")
        agg.update(fent["sm3"].encode("ascii"))
        total += len(data)
        if verbose and (i + 1) % 50 == 0:
            print(f"  … 逐文件复算 {i + 1}/{len(files)}（累计 {total/1e6:.1f} MB）")
    fp = f"SM3({m['pin_commit']}|{agg.hexdigest()})"
    if verbose:
        print(f"  复算完成：{len(files)} 文件 / {total/1e6:.2f} MB，指纹 {fp}")
    return fp


def fingerprint_gate(zksvc: Path) -> dict:
    """三源核对 + 真树复算。任何一源漂移即中止（防测量有效性翻车）。"""
    print("[指纹门] 三源期望值核对…")
    ctx = load_build_manifest(zksvc)
    bm_aggregate = ctx["bm"].get("aggregate_sm3", "")
    sources = {
        "server_bench 硬编码": EXPECTED_FINGERPRINT,
        "build_manifest.json(aggregate_sm3)": f"SM3({ctx['bm']['pinned_commit_short']}|{bm_aggregate})",
        "golden vector(zk_pin_fingerprint)": json.loads(
            (zksvc / GOLDEN_VECTOR_REL).read_text(encoding="utf-8"))["zk_pin_fingerprint"],
    }
    for name, val in sources.items():
        ok = val == EXPECTED_FINGERPRINT
        print(f"  {'OK ' if ok else 'ERR'} {name}: {val}")
        if not ok:
            raise SystemExit(f"[指纹门][中止] 期望值源 {name} 漂移——测量无效，先对账再上服务器")
    print("[指纹门] 逐文件复算 vendor 快照（pin_fingerprint.rs 同构）…")
    fp = compute_vendor_fingerprint(zksvc)
    if fp != EXPECTED_FINGERPRINT:
        raise SystemExit(f"[指纹门][中止] 复算 {fp} ≠ 期望 {EXPECTED_FINGERPRINT}——"
                         "vendor 快照与判决件不一致（常见：CRLF 污染/传输出错/拿错代际），修好再测")
    print(f"[指纹门] PASS——{fp}")
    return {"pass": True, "expected": EXPECTED_FINGERPRINT, "recomputed": fp,
            "pin_commit": ctx["bm"]["pinned_commit_short"], "file_count": ctx["bm"].get("file_count"),
            "aggregate_sm3": bm_aggregate}


# ── 机器画像（性能档案「机器画像」节同字段）──

def _mem_bytes() -> tuple:
    if platform.system() == "Linux":
        info = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, rest = line.partition(":")
            info[k.strip()] = int(rest.strip().split()[0]) * 1024
        return info.get("MemTotal", 0), info.get("MemAvailable", 0)
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
    st = MEMORYSTATUSEX()
    st.dwLength = ctypes.sizeof(st)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
    return st.ullTotalPhys, st.ullAvailPhys


def _cpu_model() -> str:
    try:
        if platform.system() == "Linux":
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
        elif platform.system() == "Windows":
            out = subprocess.run(["wmic", "cpu", "get", "name"], capture_output=True, text=True,
                                 timeout=15).stdout.strip().splitlines()
            lines = [x.strip() for x in out if x.strip() and x.strip() != "Name"]
            if lines:
                return lines[-1]
    except Exception:
        pass
    return platform.processor() or "unknown"


def _os_pretty() -> str:
    if platform.system() == "Linux":
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if line.startswith("PRETTY_NAME"):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    return f"{platform.system()} {platform.release()}"


def _which_all() -> dict:
    out = {}
    for t in TOOLS:
        p = shutil.which(t)
        out[t] = p
    return out


def _tool_version(cmd: list, timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        first = (r.stdout or r.stderr).strip().splitlines()
        return first[0] if first else "(no output)"
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"(不可用: {e})"


def machine_profile(root: Path) -> dict:
    total, avail = _mem_bytes()
    disk = shutil.disk_usage(root)
    prof = {
        "os": _os_pretty(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": _cpu_model(),
        "cpu_logical": os.cpu_count(),
        "mem_total_gb": round(total / 2**30, 2),
        "mem_avail_gb": round(avail / 2**30, 2),
        "disk_total_gb": round(disk.total / 2**30, 2),
        "disk_free_gb": round(disk.free / 2**30, 2),
        "python": platform.python_version(),
        "rustup_toolchain_env": os.environ.get("RUSTUP_TOOLCHAIN", ""),
        "paths": _which_all(),
        "rustc": None, "cargo": None, "rustup": None,
    }
    if prof["paths"]["rustc"]:
        prof["rustc"] = _tool_version(["rustc", "--version"])
    if prof["paths"]["cargo"]:
        prof["cargo"] = _tool_version(["cargo", "--version"])
    if prof["paths"]["rustup"]:
        prof["rustup"] = _tool_version(["rustup", "show", "active-toolchain"])
    try:
        g = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root,
                           capture_output=True, text=True, timeout=15)
        prof["git_head"] = g.stdout.strip() if g.returncode == 0 else "(not a repo)"
        d = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                           capture_output=True, text=True, timeout=30)
        prof["git_dirty_entries"] = len([x for x in d.stdout.splitlines() if x.strip()]) if d.returncode == 0 else -1
    except (OSError, subprocess.TimeoutExpired):
        prof["git_head"] = "(git 不可用)"
    return prof


def print_profile(prof: dict) -> None:
    print("[自检] 机器画像：")
    print(f"  OS        : {prof['os']}（kernel {prof['kernel']}，{prof['arch']}）")
    print(f"  CPU       : {prof['cpu_model']}（逻辑核 {prof['cpu_logical']}）")
    print(f"  内存      : 总 {prof['mem_total_gb']} GiB / 可用 {prof['mem_avail_gb']} GiB")
    print(f"  磁盘      : 总 {prof['disk_total_gb']} GiB / 空闲 {prof['disk_free_gb']} GiB（仓库所在卷）")
    print(f"  Python    : {prof['python']}")
    print(f"  rustc     : {prof['rustc']}")
    print(f"  cargo     : {prof['cargo']}")
    print(f"  rustup    : {prof['rustup']}")
    print(f"  RUSTUP_TOOLCHAIN env: {prof['rustup_toolchain_env'] or '(未设)'}")
    print(f"  git HEAD  : {prof.get('git_head', '?')}（工作区条目 {prof.get('git_dirty_entries', '?')}）")
    warn = []
    if prof["mem_total_gb"] < 16:
        warn.append(f"内存 {prof['mem_total_gb']}GiB < 16GiB 硬底线——prove 峰值 ~7.5-8GB，构建易 OOM")
    elif prof["mem_total_gb"] < 32:
        warn.append(f"内存 {prof['mem_total_gb']}GiB < 建议值 32GiB——可测，构建并发建议 -j 降档")
    if prof["cpu_logical"] and prof["cpu_logical"] < 12:
        warn.append(f"逻辑核 {prof['cpu_logical']} < 12——RAYON=12 同口径时线程超订，时延偏高须如实标注")
    if prof["disk_free_gb"] < 40:
        warn.append(f"磁盘空闲 {prof['disk_free_gb']}GiB < 建议 40GiB——release 构建+判决件可能写满")
    if not prof["paths"]["cargo"]:
        warn.append("cargo 不在 PATH——full 模式前先装工具链（见前置准备文档 §2）")
    for w in warn:
        print(f"  ⚠ {w}")


# ── 测量执行 ──

def assert_clean_measurement_env() -> None:
    bad = [k for k in FORBIDDEN_ENV if k in os.environ]
    if bad:
        raise SystemExit(f"[口径门][中止] 测量口径禁设 env 在位: {bad}——unset 后重跑（④代口径=部署默认）")
    for k, v in REQUIRED_ENV.items():
        os.environ[k] = v  # 子进程继承（准入门禁）
    print(f"[口径门] PASS——禁设 env 零在位；准入门禁 {REQUIRED_ENV} 由本脚本注入子进程")


def zkc_binary(zksvc: Path) -> Path:
    name = "zkc.exe" if os.name == "nt" else "zkc"
    p = zksvc / "target" / "release" / name
    if not p.is_file():
        raise SystemExit(f"[中止] 未见构建产物 {p}——先跑 full（含构建）或排除 --skip-build")
    return p


def ensure_cargo_config(zksvc: Path, allow_write: bool) -> str:
    live = zksvc / CARGO_CONFIG_LIVE
    if live.is_file():
        return "在册"
    tmpl = zksvc / CARGO_CONFIG_TEMPLATE
    if not tmpl.is_file():
        raise SystemExit(f"[中止] 缺 {tmpl}——离线 vendor 配置模板缺失，拒绝裸构建")
    if not allow_write:
        raise SystemExit(f"[中止] {live} 缺失且本环境未授权写配置——服务器侧重跑（full 模式默认授权）")
    live.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(tmpl, live)
    return f"新建（自 {CARGO_CONFIG_TEMPLATE} 复制——服务器检出内新件，不动源仓）"


def run_build(zksvc: Path, jobs: int, timeout_s: int = 3600) -> dict:
    print(f"[构建] cargo build --release --offline -j {jobs}（cwd=zksvc）…")
    t0 = time.perf_counter()
    r = subprocess.run(["cargo", "build", "--release", "--offline", "-j", str(jobs)],
                       cwd=zksvc, capture_output=True, text=True, timeout=timeout_s)
    dt = time.perf_counter() - t0
    if r.returncode != 0:
        tail = "\n".join((r.stderr or r.stdout).strip().splitlines()[-40:])
        raise SystemExit(f"[构建][中止] exit {r.returncode}，用时 {dt:.0f}s。stderr 尾部：\n{tail}")
    print(f"[构建] PASS——用时 {dt:.0f}s → {zkc_binary(zksvc)}")
    return {"cmd": f"cargo build --release --offline -j {jobs}", "seconds": round(dt, 1),
            "jobs": jobs, "rc": 0}


def run_prove(zksvc: Path, zkc: Path, spec_rel: str, out_dir: Path, label: str,
              timeout_s: int = 1200) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["YZT_ZK_ROOT"] = str(zksvc)  # 服务根显式（双参照系第一优先——prove.rs service_bm_dir）
    env["RAYON_NUM_THREADS"] = str(RAYON_THREADS)
    cmd = [str(zkc), "prove", "--spec", spec_rel, "--out", str(out_dir)]
    t0 = time.perf_counter()
    r = subprocess.run(cmd, cwd=zksvc, env=env, capture_output=True, text=True, timeout=timeout_s)
    wall = time.perf_counter() - t0
    rec: dict = {"label": label, "cmd": " ".join(cmd[1:]), "rc": r.returncode, "wall_s": round(wall, 2)}
    m = re.search(r"zkc prove: OK (\d+)B sm3=([0-9a-f]+) fingerprint=(\S+) pcs=(\S+)",
                  r.stdout or "")
    rec["stdout_tail"] = " | ".join((r.stdout or "").strip().splitlines()[-2:] +
                                    (r.stderr or "").strip().splitlines()[-2:])
    if r.returncode != 0 or not m:
        raise SystemExit(f"[{label}][中止] prove exit {r.returncode}（判决纪律：一切非 OK=FAIL）。\n"
                         f"  stdout: {rec['stdout_tail']}")
    rec["proof_bytes"], rec["proof_sm3"], rec["fingerprint"], rec["pcs"] = (
        int(m.group(1)), m.group(2), m.group(3), m.group(4))
    vd = json.loads((out_dir / "verdict.json").read_text(encoding="utf-8"))
    if vd.get("verdict") != "OK":
        raise SystemExit(f"[{label}][中止] verdict.json verdict={vd.get('verdict')} "
                         f"verify_error={vd.get('verify_error')}")
    for k in ("setup_s", "preprocess_s", "prove_s", "verify_s", "total_s"):
        rec[k] = round(float(vd[k]), 3)
    rec["verdict_fingerprint"] = vd.get("zk_pin_fingerprint")
    rec["proof_sm3_verdict"] = vd.get("proof_sm3")
    inst = json.loads((out_dir / "instances.json").read_text(encoding="utf-8"))["instances"]
    rec["instances_count"] = len(inst)
    rec["mask"] = vd.get("mask")
    return rec


def assert_run_gates(rec: dict, golden_instances: list | None, expect_instances: int,
                     expect_bytes: int | None) -> None:
    if rec["fingerprint"] != EXPECTED_FINGERPRINT or rec["verdict_fingerprint"] != EXPECTED_FINGERPRINT:
        raise SystemExit(f"[判决件指纹门][中止] {rec['label']} 指纹漂移：stdout={rec['fingerprint']} "
                         f"verdict={rec['verdict_fingerprint']} ≠ 期望——构建产物与判决件不一致，测量无效")
    if rec["pcs"] != "il=1/dd=0/st=0":
        raise SystemExit(f"[口径门][中止] {rec['label']} PCS 构型 {rec['pcs']} ≠ il=1/dd=0/st=0"
                         "（④代口径=部署默认交织档）")
    if rec["instances_count"] != expect_instances:
        raise SystemExit(f"[实例门][中止] {rec['label']} 实例数 {rec['instances_count']} ≠ 期望 {expect_instances}")
    if expect_bytes is not None and rec["proof_bytes"] != expect_bytes:
        raise SystemExit(f"[尺寸门][中止] {rec['label']} proof {rec['proof_bytes']}B ≠ 黄金 {expect_bytes}B")
    if golden_instances is not None:
        inst = json.loads((Path(rec["_out_dir"]) / "instances.json").read_text(encoding="utf-8"))["instances"]
        if inst != golden_instances:
            raise SystemExit(f"[实例门][中止] {rec['label']} 公开实例与黄金向量不逐位一致——语句面漂移")


def median_of(recs: list, keys: list) -> dict:
    return {k: round(statistics.median(r[k] for r in recs), 3) for k in keys}


# ── 结果输出（JSON+Markdown 双档；MD 内含性能档案 B1/B2 行回填块）──

def write_results(out_dir: Path, prof: dict, fp_gate: dict, build: dict | None,
                  auth: dict, trail: dict, gate: dict) -> tuple:
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    doc = {
        "schema": "fz-server-bench/1",
        "created": now,
        "purpose": "⑦代电路服务器窗复测——性能档案现行口径总表「服务器窗 AUTH prove」行与"
                   "「TRAIL 服务器 prove / verify」行回填数据源",
        "baseline_4gen": BASELINE,
        "machine_profile": prof,
        "fingerprint_gate": fp_gate,
        "build": build,
        "rayon": RAYON_THREADS,
        "runs_per_statement": N_RUNS,
        "auth": auth,
        "trail": trail,
        "gate_60s": gate,
        "verdict": "PASS" if gate["pass"] else "FAIL(硬门未达——照实入档，勿弃测量)",
    }
    jp = out_dir / "bench_results.json"
    jp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

    def fmt_tuple(stmt: dict) -> str:
        med = stmt["median"]
        return (f"{med['setup_s']}s | {med['preprocess_s']}s | **{med['prove_s']}s** | "
                f"{med['verify_s']}s | {med['total_s']}s | {stmt['runs'][0]['proof_bytes']:,}B")

    ratio = round(GATE_60S / auth["median"]["prove_s"], 2) if auth["median"]["prove_s"] else 0
    md = f"""# ⑦代服务器窗复测结果（server_bench.py 自动生成）

- 测量时间：{now}
- 命令：`python3 scripts/server_bench.py full`（RAYON={RAYON_THREADS}，N={N_RUNS} 取中位）
- 构建复现性门：{'PASS' if fp_gate.get('pass') else 'FAIL'}——{fp_gate.get('recomputed')}
- 机器画像：{prof['os']}｜{prof['cpu_model']}｜逻辑核 {prof['cpu_logical']}｜内存 {prof['mem_total_gb']}GiB｜磁盘空闲 {prof['disk_free_gb']}GiB｜{prof.get('rustc')}

## 服务器窗 · ⑦代四元组（对照④代 2026-09-27：AUTH 25.14/0.68、TRAIL 15.10/0.21）

| 语句 | setup | preprocess | prove | 回读 verify | total | proof |
|---|---|---|---|---|---|---|
| **AUTH** | {fmt_tuple(auth)} |
| **TRAIL** | {fmt_tuple(trail)} |

## ≤60s 演示硬门判定

- AUTH prove 中位 **{auth['median']['prove_s']}s** → **{'PASS' if gate['pass'] else 'FAIL'}**
  （硬门 {GATE_60S:.0f}s，余量 {ratio}×；④代口径 25.14s/近 2.4×）
- TRAIL prove/verify 中位 **{trail['median']['prove_s']}s / {trail['median']['verify_s']}s**
  （无硬门；④代 15.10s/0.21s，本机 12.3s@10-07）

## 性能档案 现行口径总表 · 回填块（测后复制进 docs/性能档案.md 并随正式入档批次改写）

```
| 服务器窗 AUTH prove | {auth['median']['prove_s']}s（≤60s 硬门余量 {ratio}×） | [实测 {now[:10]}，⑦代电路——服务器窗复测（{prof['cpu_logical']}C/{prof['mem_total_gb']}G，{prof.get('rustc')}，RAYON={RAYON_THREADS}）] |
| TRAIL 服务器 prove / verify | {trail['median']['prove_s']}s / {trail['median']['verify_s']}s | [实测 {now[:10]}，⑦代口径] |
```

## 逐次明细

### AUTH（{AUTH_SPEC_REL}，黄金向量 v7 口径，实例 {AUTH_INSTANCES_GOLDEN} 逐位核对过）

| run | setup | preprocess | prove | verify | total | proof | pcs |
|---|---|---|---|---|---|---|---|
""" + "\n".join(
        f"| {i+1} | {r['setup_s']} | {r['preprocess_s']} | {r['prove_s']} | {r['verify_s']} | "
        f"{r['total_s']} | {r['proof_bytes']:,}B | {r['pcs']} |"
        for i, r in enumerate(auth["runs"])) + f"""

### TRAIL（{TRAIL_SPEC_REL}，实例 {TRAIL_INSTANCES_GOLDEN}）

| run | setup | preprocess | prove | verify | total | proof | pcs |
|---|---|---|---|---|---|---|---|
""" + "\n".join(
        f"| {i+1} | {r['setup_s']} | {r['preprocess_s']} | {r['prove_s']} | {r['verify_s']} | "
        f"{r['total_s']} | {r['proof_bytes']:,}B | {r['pcs']} |"
        for i, r in enumerate(trail["runs"])) + f"""

## 诚实声明

- 证明字节跨次不复现（mask=on OsRng 每证新鲜）——对拍锚=尺寸+指纹+公开实例三元，proof_sm3 仅记录不比对。
- 逐次明细与中位数全部落盘 {jp.name}；判决行引用时注明机器画像与工具链。
"""
    mp = out_dir / "bench_results.md"
    mp.write_text(md, encoding="utf-8")
    return jp, mp


# ── 子命令 ──

def cmd_self_check(args) -> int:
    p = repo_paths()
    prof = machine_profile(p["root"])
    print_profile(prof)
    print("[自检] 说明：full 模式尚需 40GiB 级磁盘与离线工具链（nightly-2026-05-26）——见 docs/服务器窗复测前置准备.md")
    return 0


def cmd_fingerprint(args) -> int:
    p = repo_paths()
    print(f"[指纹门] 仓库根: {p['root']}")
    fp_gate = fingerprint_gate(p["zksvc"])
    print("[指纹门] 本地核对完成（源面——与构建无关；服务器上构建后再由判决件二次把关）")
    return 0


def cmd_sm3_cross(args) -> int:
    p = repo_paths()
    zkc = zkc_binary(p["zksvc"])
    ctx = load_build_manifest(p["zksvc"])
    files = json.loads(ctx["manifest"].read_text(encoding="utf-8"))["files"]
    # 取 MANIFEST 中最大的非零文件做对拍（路径含 plonkish/ 前缀，相对 vendor 快照根）
    ent = max((f for f in files if f["bytes"] > 0), key=lambda f: f["bytes"])
    target = ctx["vendor"] / ent["path"]
    print(f"[SM3 对拍] 样本: {target.name}（{ent['bytes']}B，MANIFEST 声明 sm3={ent['sm3'][:16]}…）")
    py_hex = sm3_file(target)
    r = subprocess.run([str(zkc), "sm3", "--file", str(target)], capture_output=True, text=True, timeout=120)
    zkc_hex = r.stdout.strip().splitlines()[-1].strip() if r.returncode == 0 else None
    print(f"  纯 Python : {py_hex}")
    print(f"  zkc 二进制: {zkc_hex}")
    if r.returncode != 0:
        raise SystemExit(f"[SM3 对拍][中止] zkc sm3 exit {r.returncode}: {r.stderr}")
    if py_hex != ent["sm3"] or zkc_hex != ent["sm3"]:
        raise SystemExit("[SM3 对拍][中止] 与 MANIFEST 声明不一致——哈希实现或样本漂移，禁止用于测量")
    print("[SM3 对拍] PASS——纯 Python SM3 ≡ zkc（sm3 crate）≡ MANIFEST 声明，指纹门实现可信")
    return 0


def cmd_full(args) -> int:
    p = repo_paths()
    runs = getattr(args, "runs", None) or N_RUNS
    skip_build = getattr(args, "skip_build", False)
    build_jobs = getattr(args, "build_jobs", None)
    if platform.system() != "Linux" and not getattr(args, "allow_nonlinux", False):
        raise SystemExit("[中止] full 模式为服务器窗设计（含 release 构建=重负载）。"
                         "本机（非 Linux）轻量验证请用 self-check / fingerprint / sm3-cross；"
                         "确要本地构建请显式 --allow-nonlinux")
    t_all = time.perf_counter()
    prof = machine_profile(p["root"])
    print_profile(prof)

    print("[1/6] 测量口径门…")
    assert_clean_measurement_env()

    print("[2/6] 构建复现性门（源面——构建前先证 vendor 快照身份）…")
    fp_gate = fingerprint_gate(p["zksvc"])

    build = None
    if not skip_build:
        print("[3/6] 构建（release offline）…")
        jobs = build_jobs or min(os.cpu_count() or 4, 8)
        ensure_cargo_config(p["zksvc"], allow_write=True)
        build = run_build(p["zksvc"], jobs)
    else:
        print("[3/6] 跳过构建（--skip-build）")
        zkc_binary(p["zksvc"])  # 产物必须在

    zkc = zkc_binary(p["zksvc"])
    golden = json.loads(p["golden"].read_text(encoding="utf-8"))
    golden_instances = golden["expected_instances_hex"]
    results_dir = Path(args.out).resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = results_dir / f"server_bench_{stamp}"

    print(f"[4/6] AUTH canonical prove ×{runs}（RAYON={RAYON_THREADS}）…")
    auth_runs = []
    for i in range(runs):
        out = results_dir / f"auth_run{i+1}"
        rec = run_prove(p["zksvc"], zkc, AUTH_SPEC_REL, out, f"AUTH#{i+1}")
        rec["_out_dir"] = str(out)
        assert_run_gates(rec, golden_instances if i == 0 else None, AUTH_INSTANCES_GOLDEN,
                         AUTH_PROOF_BYTES_GOLDEN if i == 0 else None)
        auth_runs.append(rec)
        print(f"  AUTH#{i+1}: prove {rec['prove_s']}s / verify {rec['verify_s']}s / "
              f"total {rec['total_s']}s / proof {rec['proof_bytes']:,}B")

    print(f"[5/6] TRAIL canonical prove ×{runs}…")
    trail_runs = []
    for i in range(runs):
        out = results_dir / f"trail_run{i+1}"
        rec = run_prove(p["zksvc"], zkc, TRAIL_SPEC_REL, out, f"TRAIL#{i+1}")
        rec["_out_dir"] = str(out)
        assert_run_gates(rec, None, TRAIL_INSTANCES_GOLDEN, None)
        trail_runs.append(rec)
        print(f"  TRAIL#{i+1}: prove {rec['prove_s']}s / verify {rec['verify_s']}s / "
              f"total {rec['total_s']}s / proof {rec['proof_bytes']:,}B")

    tkeys = ["setup_s", "preprocess_s", "prove_s", "verify_s", "total_s"]
    auth = {"spec": AUTH_SPEC_REL, "runs": [{k: v for k, v in r.items() if not k.startswith('_')}
                                            for r in auth_runs],
            "median": median_of(auth_runs, tkeys)}
    trail = {"spec": TRAIL_SPEC_REL, "runs": [{k: v for k, v in r.items() if not k.startswith('_')}
                                              for r in trail_runs],
             "median": median_of(trail_runs, tkeys)}
    ratio = round(GATE_60S / auth["median"]["prove_s"], 2)
    gate = {"threshold_s": GATE_60S, "auth_prove_median_s": auth["median"]["prove_s"],
            "pass": auth["median"]["prove_s"] <= GATE_60S, "margin_x": ratio,
            "baseline_margin_x": round(60 / BASELINE["auth"]["prove_s"], 2)}

    print("[6/6] 结果落盘（JSON+Markdown）…")
    jp, mp = write_results(results_dir, prof, fp_gate, build, auth, trail, gate)
    print(f"  {jp}")
    print(f"  {mp}")
    print(f"[完成] 总用时 {time.perf_counter()-t_all:.0f}s——硬门判定 "
          f"{'PASS' if gate['pass'] else 'FAIL'}（AUTH prove 中位 {auth['median']['prove_s']}s，余量 {ratio}×）")
    print("[回填] 把 bench_results.md「性能档案 现行口径总表 · 回填块」两行带入 docs/性能档案.md"
          "（随正式入档批次，不与本测量窗混提交）")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="⑦代电路服务器窗复测一键测量（性能档案 B1/B2 行前置套件）")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("self-check", help="环境自检（本地/服务器皆可，零构建）")
    sub.add_parser("fingerprint", help="构建复现性门源面复算（轻量）")
    sub.add_parser("sm3-cross", help="纯 Python SM3 与既有 zkc 二进制对拍（不重建）")
    full = sub.add_parser("full", help="服务器主流程：自检→指纹门→构建→AUTH/TRAIL×N→结果")
    full.add_argument("--runs", type=int, default=N_RUNS, help=f"每语句实测次数（默认 {N_RUNS}，取中位）")
    full.add_argument("--skip-build", action="store_true", help="跳过构建（复用既有 target/release 产物）")
    full.add_argument("--build-jobs", type=int, default=None, help="构建并行度（默认 min(逻辑核,8)；OOM 时降档）")
    full.add_argument("--out", default=None, help="结果根目录（默认 <仓库>/server_bench_results）")
    full.add_argument("--allow-nonlinux", action="store_true", help="非 Linux 宿主强制放行（默认拒绝）")
    args = ap.parse_args(argv)
    if args.cmd is None or args.cmd == "full":
        args.out = getattr(args, "out", None) or str(repo_paths()["root"] / "server_bench_results")
        return cmd_full(args)
    if args.cmd == "self-check":
        return cmd_self_check(args)
    if args.cmd == "fingerprint":
        return cmd_fingerprint(args)
    if args.cmd == "sm3-cross":
        return cmd_sm3_cross(args)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
