"""KMS 生产档启动断言测试（批 2-2.3：演示钥退出默认）。

覆盖面：
- production 档缺任一 FZ_*_SK → create_app 拒启，异常信息逐项点名缺失 env
- production 档全量注入 → 可启（且 kms 访问器返回注入值，非派生值）
- demo（环回）档 → 零 env 可跑（现状保持）
- 非环回绑定地址 → 同 production 判定
- 轮换仪式脚本：材料形态/指纹口径/同表同源（stdout only——零落盘）
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.kms import PRODUCTION_REQUIRED_KEYS, assert_no_demo_keys_in_production
from app.main import create_app
from app.ra.models import Base


@pytest.fixture()
def _clean_kms_env(monkeypatch):
    """清空全部 KMS env + 部署档判定面——用例自设档位。"""
    for name, _desc, _kind in PRODUCTION_REQUIRED_KEYS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("FZ_DEPLOYMENT", raising=False)
    monkeypatch.delenv("FZ_BIND_ADDR", raising=False)
    monkeypatch.delenv("FZ_HOST", raising=False)


def _full_keys(monkeypatch):
    """全量注入合法形态的生产钥（哑随机材料——测试专用，非真实凭据）。"""
    from scripts.rotate_kms_keys import _material

    for name, _desc, kind in PRODUCTION_REQUIRED_KEYS:
        monkeypatch.setenv(name, _material(kind))


def test_production_missing_keys_refuse_startup(_clean_kms_env, monkeypatch):
    """production 档零注入→拒启；异常信息点名缺失 env（人话）。"""
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    with pytest.raises(RuntimeError) as ei:
        create_app()
    msg = str(ei.value)
    assert "拒绝以演示派生钥启动" in msg
    for name, _desc, _kind in PRODUCTION_REQUIRED_KEYS:
        assert name in msg, f"异常信息须点名 {name}"
    # 缺一个时只点那一个
    monkeypatch.setenv("FZ_RA_SK", "ab" * 32)
    with pytest.raises(RuntimeError) as ei2:
        create_app()
    assert "FZ_ENGINE_SK" in str(ei2.value)


def test_production_injected_keys_start(tmp_path, _clean_kms_env, monkeypatch):
    """production 档全量注入→create_app 可启；kms 访问器返回注入值。
    （批 4-2 服务形态断言同闸前置：anchor=real + FZ_DB_URL 显式——
    真链档启动挂索引守护线程，链不可达走 WARNING 不阻塞。）"""
    import os

    from app import kms

    _full_keys(monkeypatch)
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    monkeypatch.setenv("FZ_DB_URL", f"sqlite:///{tmp_path}/kms_prod.db")
    assert_no_demo_keys_in_production()  # 断言函数直呼通过
    eng = create_engine(f"sqlite:///{tmp_path}/kms_prod.db")
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
    # 注入值=生效值（形态门+恒等——非派生值）
    sk, pub = kms.ra_signing_keypair()
    assert sk == os.environ["FZ_RA_SK"] and len(sk) == 64 and len(pub) == 128
    assert kms.chain_ra_tx_key() == os.environ["FZ_CHAIN_RA_TX_SK"]


def test_demo_tier_unaffected(_clean_kms_env):
    """demo（环回）档：零 env 可启可跑——演示现状保持（2.3 只动 production）。"""
    app = create_app()
    assert app.title == "feizheng-backend"


def test_non_loopback_bind_is_production(_clean_kms_env, monkeypatch):
    """绑非环回地址（FZ_BIND_ADDR）=production 判定——缺 env 拒启；
    环回绑定不触发。"""
    monkeypatch.setenv("FZ_BIND_ADDR", "192.168.1.10:8000")
    with pytest.raises(RuntimeError):
        create_app()
    monkeypatch.setenv("FZ_BIND_ADDR", "127.0.0.1:8000")
    assert_no_demo_keys_in_production()  # 环回=demo 档——不拒
    monkeypatch.setenv("FZ_BIND_ADDR", "0.0.0.0:8000")
    with pytest.raises(RuntimeError):
        create_app()  # 全接口绑定按非环回处理（保守=production）


def test_rotate_script_material_and_fingerprint():
    """轮换仪式脚本：材料形态与 kms 访问器形态门一致；指纹=SM3(公钥/材料)
    带外核对口径；与 PRODUCTION_REQUIRED_KEYS 同表同源。"""
    from scripts.rotate_kms_keys import _fingerprint, _material

    for _name, _desc, kind in PRODUCTION_REQUIRED_KEYS:
        v = _material(kind)
        if kind == "sk32":
            assert len(v) == 64
            from app.crypto.sm2 import pubkey_from_priv

            pub = pubkey_from_priv(v)  # 形态门：合法 SM2 私钥
            assert len(pub) == 128
            assert _fingerprint(kind, v) == sm3_bytes(pub.encode()).hex()[:16]
        elif kind == "key16":
            assert len(v) == 32  # 16B
            assert _fingerprint(kind, v) == sm3_bytes(v.encode()).hex()[:16]
        else:
            assert len(v) == 64  # 32B 材料
            assert _fingerprint(kind, v) == sm3_bytes(v.encode()).hex()[:16]
        # CSPRNG：两次生成不重合（确定性派生=本批根除的缺陷面）
        assert _material(kind) != v
