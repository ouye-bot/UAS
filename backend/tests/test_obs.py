"""P1-B1 可观测性测试：request_id 贯穿+/metrics 指标面。

- 中间件：每请求 X-Request-ID 响应头在场；计数器按 path+code 递增
- /metrics：Prometheus 文本（counter/直方图分桶/sum/count 系列齐全）
- 直方图：observe 后分桶渲染正确
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    import app.obs as obs

    with obs._lock:
        obs._counters.clear()
        obs._histograms.clear()
    with TestClient(create_app()) as c:
        yield c


def test_request_id_header_and_counter(client):
    r1 = client.get("/healthz")
    r2 = client.get("/healthz")
    id1, id2 = r1.headers.get("X-Request-ID"), r2.headers.get("X-Request-ID")
    assert id1 and id2 and id1 != id2
    m = client.get("/metrics").text
    assert 'fz_requests_total{code="200",path="/healthz"} 2' in m


def test_metrics_histogram_rendering(client):
    from app.obs import observe

    observe("fz_verify_seconds", 0.02, {"profile": "auth"})
    observe("fz_verify_seconds", 2.0, {"profile": "auth"})
    m = client.get("/metrics").text
    assert 'fz_verify_seconds_bucket{profile="auth",le="0.05"} 1' in m
    assert 'fz_verify_seconds_bucket{profile="auth",le="30"} 2' in m
    assert 'fz_verify_seconds_bucket{profile="auth",le="+Inf"} 2' in m
    assert 'fz_verify_seconds_count{profile="auth"} 2' in m
    assert 'fz_verify_seconds_sum{profile="auth"} 2.02' in m


def test_request_id_persists_in_log_record(client, caplog):
    import logging

    with caplog.at_level(logging.INFO, logger="fz.http"):
        client.get("/healthz")
    assert any("rid=" in r.getMessage() for r in caplog.records)


def test_worker_gauges_merge_from_share_file(client, monkeypatch, tmp_path):
    """worker gauges 跨进程合并（乙5）：FZ_ZK_CASES_DIR/worker_gauges.json 在场且
    60s 新鲜窗内 ⟹ /metrics 渲染合并其键；过期=worker 离线，陈旧 gauge 不渲染。

    回归钉（2026-10-08）：obs.py 曾漏 import os——_load_worker_gauges 每次
    NameError 被兜底 except 吞掉静默返空，合并路径产品死码（ruff F821 抓出，
    根修后本测试先绿钉死语义）。"""
    import json as _json
    import time as _time

    d = tmp_path / "cases"
    d.mkdir()
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(d))
    fresh = {"ts": _time.time(), "gauges": {"fz_worker_pending": 3.0}}
    (d / "worker_gauges.json").write_text(_json.dumps(fresh), encoding="utf-8")
    m = client.get("/metrics").text
    assert "fz_worker_pending 3.0" in m
    stale = {"ts": _time.time() - 61, "gauges": {"fz_worker_pending": 9.0}}
    (d / "worker_gauges.json").write_text(_json.dumps(stale), encoding="utf-8")
    m2 = client.get("/metrics").text
    assert "fz_worker_pending 9.0" not in m2
