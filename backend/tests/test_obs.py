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
