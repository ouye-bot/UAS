"""create_app 工厂与 healthz 骨架测试（B0 最小服务面）。"""

from fastapi.testclient import TestClient

from app.main import create_app


def test_create_app_factory():
    app = create_app()
    assert app.title == "feizheng-backend"


def test_healthz():
    client = TestClient(create_app())
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "feizheng-backend"}
