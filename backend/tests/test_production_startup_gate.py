"""批 4-2 生产档服务形态断言测试：三形态逐条拒启+信息点名+演示档零影响。

前置：KMS 钥全量注入（批 2-2.3 同款）——使 KMS 断言通过、被测面=本批三条。
覆盖：
- FZ_CHAIN_ANCHOR 未显式配置（缺省 fake 回落）→ 拒启+点名 env 名与"显式 real"指引
- FZ_CHAIN_ANCHOR=fake 显式假链档（遥测 stub 无链上留痕）→ 拒启+点名遥测面
- FZ_DB_URL 未配置（缺省 SQLite 回落）→ 拒启+点名
- demo（环回）档：零 env 照常起（现状保持——断言只动 production）
- 断言函数直呼：demo 档恒通过
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import get_session
from app.deployment import assert_production_services, is_production
from app.kms import PRODUCTION_REQUIRED_KEYS
from app.main import create_app
from app.ra.models import Base


@pytest.fixture()
def _prod_env_base(monkeypatch):
    """清部署/链锚/DB env + 全量注入 KMS 生产钥（哑随机材料——测试专用）。"""
    from scripts.rotate_kms_keys import _material

    monkeypatch.delenv("FZ_DEPLOYMENT", raising=False)
    monkeypatch.delenv("FZ_BIND_ADDR", raising=False)
    monkeypatch.delenv("FZ_HOST", raising=False)
    monkeypatch.delenv("FZ_CHAIN_ANCHOR", raising=False)
    monkeypatch.delenv("FZ_DB_URL", raising=False)
    for name, _desc, kind in PRODUCTION_REQUIRED_KEYS:
        monkeypatch.setenv(name, _material(kind))


def _assert_db(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("FZ_DB_URL", f"sqlite:///{tmp_path}/prod_gate.db")


def test_production_anchor_unset_rejected(_prod_env_base, monkeypatch, tmp_path):
    """形态①：FZ_CHAIN_ANCHOR 未配置（缺省 fake）→ 拒启并点名「须显式 real」。"""
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    _assert_db(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError) as ei:
        create_app()
    msg = str(ei.value)
    assert "FZ_CHAIN_ANCHOR" in msg
    assert "real" in msg
    assert is_production()


def test_production_anchor_fake_telemetry_rejected(_prod_env_base, monkeypatch, tmp_path):
    """形态②：显式 fake 档 → 遥测锚定 stub（无链上留痕）拒启点名。"""
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    _assert_db(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError) as ei:
        create_app()
    msg = str(ei.value)
    assert "fake" in msg and "遥测" in msg
    with pytest.raises(RuntimeError):
        assert_production_services()


def test_production_db_unset_rejected(_prod_env_base, monkeypatch):
    """形态③：FZ_DB_URL 未配置（缺省 SQLite）→ 拒启点名（anchor=real 齐备）。"""
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    with pytest.raises(RuntimeError) as ei:
        create_app()
    msg = str(ei.value)
    assert "FZ_DB_URL" in msg
    assert "SQLite" in msg


def test_production_all_set_starts(tmp_path, _prod_env_base, monkeypatch):
    """三形态齐备 → 可启（healthz 200；真链档索引守护线程链不可达=WARNING 不阻塞）。"""
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    _assert_db(monkeypatch, tmp_path)
    eng = create_engine(f"sqlite:///{tmp_path}/prod_gate.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)

    def _sess():
        s = TestSession()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    app = create_app()
    app.dependency_overrides[get_session] = _sess
    with TestClient(app) as c:
        assert c.get("/healthz").status_code == 200


def test_demo_tier_unaffected(monkeypatch):
    """演示（环回）档：零 env 照常起——断言族只动 production（现状保持）。"""
    monkeypatch.delenv("FZ_CHAIN_ANCHOR", raising=False)
    monkeypatch.delenv("FZ_DB_URL", raising=False)
    assert not is_production()
    assert assert_production_services() is None  # 直呼通过（demo 恒过）
    app = create_app()
    assert app.title == "feizheng-backend"
