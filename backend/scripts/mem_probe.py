# -*- coding: utf-8 -*-
"""AUTH/TRAIL prove 内存画像采样器（R1 优化前置探针——零依赖 ctypes 版）。

用法：python scripts/mem_probe.py <zkc路径> <job.json> <输出csv> [tag]
以 200ms 间隔采样目标进程 RSS（WorkingSet）与提交内存（PrivateUsage），落 CSV。
"""
import csv
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import threading
import time


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("PageFaultCount", wt.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def mem_mb(pid):
    pmc = PROCESS_MEMORY_COUNTERS_EX()
    pmc.cb = ctypes.sizeof(pmc)
    h = ctypes.windll.kernel32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFORMATION | VM_READ
    if not h:
        return None, None
    try:
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb)
        if not ok:
            return None, None
        return pmc.WorkingSetSize // (1024 * 1024), pmc.PrivateUsage // (1024 * 1024)
    finally:
        ctypes.windll.kernel32.CloseHandle(h)


def main():
    zkc, job, out_csv = sys.argv[1], sys.argv[2], sys.argv[3]
    tag = sys.argv[4] if len(sys.argv) > 4 else "run"
    env = dict(os.environ)
    env["FZ_ZK_ALLOW_AUTH"] = "1"
    env.setdefault("RUST_MIN_STACK", os.environ.get("PROBE_STACK", "536870912"))
    log = open(job + ".probe.log", "w")
    proc = subprocess.Popen(
        [zkc, "prove", "--spec", job, "--out", job + ".out"],
        stdout=log, stderr=subprocess.STDOUT, env=env,
    )
    rows = []
    t0 = time.time()
    while proc.poll() is None:
        rss, priv = mem_mb(proc.pid)
        if rss is not None:
            rows.append((round(time.time() - t0, 2), rss, priv))
        time.sleep(0.2)
    rc = proc.returncode
    log.close()
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_s", "rss_mb", "commit_mb"])
        w.writerows(rows)
    peak_rss = max((r[1] for r in rows), default=0)
    peak_priv = max((r[2] for r in rows), default=0)
    print(f"tag={tag} rc={rc} 采样点={len(rows)} RSS峰值={peak_rss}MB 提交峰值={peak_priv}MB")


if __name__ == "__main__":
    main()
