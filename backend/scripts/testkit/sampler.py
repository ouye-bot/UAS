"""服务端资源采样器（铁律 8：观测被测服务，不是压测客户端）。

用法：
    from testkit.sampler import ProcessSampler
    s = ProcessSampler(name_patterns=("uvicorn", "zkc", "worker"))  # 进程命令行/名匹配
    s.start(interval_s=1.0)
    ...  被测负载 ...
    curve = s.stop()   # {"t": [..], "cpu_pct": [..], "rss_mb": [..]} + summary
"""
from __future__ import annotations

import os
import threading
import time

import psutil


class ProcessSampler:
    def __init__(self, name_patterns: tuple[str, ...] = ("uvicorn", "python"),
                 exclude_patterns: tuple[str, ...] = ()):
        # exclude_patterns：命令行/名命中即排除（perf_suite 自采防护——
        # 压测客户端自身进程不进被测服务曲线）。
        self.patterns = tuple(p.lower() for p in name_patterns)
        self.excludes = tuple(p.lower() for p in exclude_patterns)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.t: list[float] = []
        self.cpu_pct: list[float] = []
        self.rss_mb: list[float] = []
        self.peak_rss_mb = 0.0

    def _match(self, p: psutil.Process) -> bool:
        try:
            cl = (p.info.get("cmdline") or [])
            name = (p.info.get("name") or "").lower()
            joined = " ".join(cl).lower()
            if p.pid == os.getpid() or any(
                    pat in joined or pat in name for pat in self.excludes):
                return False
            return any(pat in joined or pat in name for pat in self.patterns)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def _targets(self):
        out = []
        for p in psutil.process_iter(attrs=["name", "cmdline"]):
            if self._match(p):
                out.append(p)
        return out

    def _loop(self, interval: float):
        t0 = time.time()
        while not self._stop.is_set():
            cpu = rss = 0.0
            for p in self._targets():
                try:
                    cpu += p.cpu_percent(interval=None)
                    rss += p.memory_info().rss / (1 << 20)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.t.append(round(time.time() - t0, 2))
            self.cpu_pct.append(round(cpu, 1))
            self.rss_mb.append(round(rss, 1))
            self.peak_rss_mb = max(self.peak_rss_mb, rss)
            self._stop.wait(interval)

    def start(self, interval_s: float = 1.0):
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)  # 首采样基线（否则首次读数虚高）
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self._thread = threading.Thread(target=self._loop, args=(interval_s,), daemon=True)
        self._thread.start()

    def stop(self) -> dict:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        avg_rss = round(sum(self.rss_mb) / len(self.rss_mb), 1) if self.rss_mb else 0.0
        return {"samples": len(self.t), "peak_rss_mb": round(self.peak_rss_mb, 1),
                "avg_rss_mb": avg_rss,
                "curve": {"t": self.t, "cpu_pct": self.cpu_pct, "rss_mb": self.rss_mb}}
