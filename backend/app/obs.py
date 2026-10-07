"""可观测性基座（P1-B1）：JSON 日志 + request_id 贯穿 + 零依赖指标注册表。

- request_id：中间件生成（无入站 X-Request-ID 时 CSPRNG），贯穿日志与响应头
- 指标：计数器（fz_requests_total 等）+直方图（fz_verify_seconds 等）——
  GET /metrics 输出 Prometheus 文本格式（外部抓取；本批不自建告警）
- 告警口径（文档）：fz_worker_pending 持续>5min 上涨 / fz_chain_writes_total{ok="0"}
  突增——供部署方配置
"""

from __future__ import annotations

import contextvars
import json
import logging
import secrets
import sys
import threading
import time

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

_lock = threading.Lock()
_counters: dict[str, float] = {}
_histograms: dict[str, list[float]] = {}
_HIST_BUCKETS = (0.01, 0.05, 0.1, 0.5, 1, 5, 15, 30, 60, 120, 300, 600)


class JsonFormatter(logging.Formatter):
    """结构化日志：ts/level/logger/msg + request_id 贯穿字段。"""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        return json.dumps(payload, ensure_ascii=False)


def setup_json_logging() -> None:
    """根日志切 JSON 形态（幂等——重复调用不叠加 handler）。"""
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "_fz_json", False):
            return
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    h._fz_json = True  # type: ignore[attr-defined]
    root.addHandler(h)


def new_request_id(inbound: str | None = None) -> str:
    """rid 生成（2026-10-02 乙5 跨程追踪：入站 X-Request-ID 优先透传——桥/worker
    调 backend 时携带自身 rid，追踪链在服务边界不断裂）。"""
    rid = (inbound or secrets.token_hex(8)).strip()
    if not rid:
        rid = secrets.token_hex(8)
    request_id_var.set(rid)
    return rid


def inc(name: str, labels: dict[str, str] | None = None, value: float = 1) -> None:
    key = _series(name, labels)
    with _lock:
        _counters[key] = _counters.get(key, 0) + value


_HISTOGRAM_CAP = 10_000  # 环窗上限（长时运行内存慢性泄漏防线——2026-10-02 乙5）


def observe(name: str, value: float, labels: dict[str, str] | None = None) -> None:
    key = _series(name, labels)
    with _lock:
        series = _histograms.setdefault(key, [])
        series.append(value)
        if len(series) > _HISTOGRAM_CAP:
            del series[: len(series) - _HISTOGRAM_CAP]  # 保最新样本（丢弃最旧）


def gauge_snapshot() -> dict[str, float]:
    """即时量（抓取时计算——如 pending 深度），由调用方注入。"""
    with _lock:
        out = dict(_counters)
    out.update({k: v for k, v in getattr(gauge_snapshot, "_gauges", {}).items()})
    return out


def set_gauge(name: str, labels: dict[str, str] | None, value: float) -> None:
    with _lock:  # 与 gauge_snapshot 读侧同锁（2026-10-02 乙5：读写竞修复）
        gauges = getattr(gauge_snapshot, "_gauges", {})
        gauges[_series(name, labels)] = value
        gauge_snapshot._gauges = gauges  # type: ignore[attr-defined]


def _series(name: str, labels: dict[str, str] | None) -> str:
    if not labels:
        return name
    inner = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return f"{name}{{{inner}}}"


def _load_worker_gauges() -> dict[str, float]:
    """worker 进程 gauges 共享文件读取（2026-10-02 乙5 归位——worker set_gauge
    写本进程 dict 对 /metrics 不可见；改为文件介质跨进程合并）。"""
    import json as _json
    from pathlib import Path as _Path

    try:
        d = _Path(os.environ.get("FZ_ZK_CASES_DIR", "/tmp/fz-zk-cases")) / "worker_gauges.json"
        if not d.is_file():
            return {}
        obj = _json.loads(d.read_text(encoding="utf-8"))
        # 60s 新鲜度窗——过期视为 worker 离线（不渲染陈旧 gauge）
        if time.time() - float(obj.get("ts", 0)) > 60:
            return {}
        return {k: float(v) for k, v in (obj.get("gauges") or {}).items()}
    except Exception:  # noqa: BLE001
        return {}


def render_metrics() -> str:
    lines: list[str] = []
    with _lock:
        counters = dict(_counters)
        hists = {k: list(v) for k, v in _histograms.items()}
    # worker 进程 gauges 跨进程合并（乙5 归位——60s 新鲜度窗）
    for k, v in _load_worker_gauges().items():
        counters.setdefault(k, v)
    for key, val in sorted(counters.items()):
        lines.append(f"{key} {val}")
    for key, samples in sorted(hists.items()):
        base = key.split("{")[0]
        bucket_key = key.replace(base, base + "_bucket", 1)
        for bound in _HIST_BUCKETS:
            n = sum(1 for s in samples if s <= bound)
            lines.append(f"{_with_label(bucket_key, 'le', str(bound))} {n}")
        lines.append(f"{_with_label(bucket_key, 'le', '+Inf')} {len(samples)}")
        lines.append(f"{_sum_series(key)} {sum(samples)}")
        lines.append(f"{_count_series(key)} {len(samples)}")
    return "\n".join(lines) + "\n"


def _sum_series(key: str) -> str:
    if key.endswith("}"):
        return (
            key[:-1] + ',sum="1"}' if False else f"{key.split('{')[0]}_sum{key[key.index('{') :]}"
        )
    return f"{key}_sum"


def _count_series(key: str) -> str:
    if key.endswith("}"):
        return f"{key.split('{')[0]}_count{key[key.index('{') :]}"
    return f"{key}_count"


def _with_label(key: str, label: str, value: str) -> str:
    if key.endswith("}"):
        return key[:-1] + f',{label}="{value}"}}'
    return f'{key}{{{label}="{value}"}}'
