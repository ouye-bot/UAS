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


# ---- 第 11 钥 FZ_OPRF_SK（⑫O-2 批：OPRF 拖库面防护服务钥+轮换双钥过渡窗） ----


def test_oprf_key_in_production_table():
    """FZ_OPRF_SK 在生产注册表（第 11 钥——形态 sk32；拒启语义随表自动生效）。"""
    rows = [name for name, _desc, _kind in PRODUCTION_REQUIRED_KEYS]
    assert rows.count("FZ_OPRF_SK") == 1
    row = next(r for r in PRODUCTION_REQUIRED_KEYS if r[0] == "FZ_OPRF_SK")
    assert row[2] == "sk32"
    assert "OPRF" in row[1]


def test_oprf_key_demo_derived_and_stable(_clean_kms_env):
    """demo 档缺省=SM3 域派生（确定性幂等锚——非生产凭据纪律，B1-d3 同款）。"""
    from app import kms

    k1 = kms.oprf_key()
    assert len(k1) == 64 and all(c in "0123456789abcdef" for c in k1)
    assert k1 == kms.oprf_key()
    assert k1 == kms._derive_priv(b"FZ-KMS|oprf")


def test_oprf_key_env_injection_and_validation(_clean_kms_env, monkeypatch):
    """env 注入优先；非法形态（非 64hex/非 hex/域外 k=0）拒绝——fail-closed。"""
    from app import kms

    monkeypatch.setenv("FZ_OPRF_SK", "ab" * 32)
    assert kms.oprf_key() == "ab" * 32
    monkeypatch.setenv("FZ_OPRF_SK", "zz" * 32)
    with pytest.raises(ValueError):
        kms.oprf_key()
    monkeypatch.setenv("FZ_OPRF_SK", "00" * 32)
    with pytest.raises(ValueError):
        kms.oprf_key()
    monkeypatch.setenv("FZ_OPRF_SK", "ab" * 31)
    with pytest.raises(ValueError):
        kms.oprf_key()


def test_oprf_key_rotation_dual_window(_clean_kms_env, monkeypatch):
    """轮换双钥过渡窗（设计 §4.3）：key_id 指纹判别——current 优先/old 只读/
    皆不匹配=None（记录作废的裁决面归调用方）；old 未注入=过渡窗已收口。"""
    from app import kms

    k_cur, k_old = "ab" * 32, "cd" * 32
    monkeypatch.setenv("FZ_OPRF_SK", k_cur)
    monkeypatch.setenv("FZ_OPRF_SK_OLD", k_old)
    id_cur, id_old = kms.oprf_key_id(k_cur), kms.oprf_key_id(k_old)
    assert id_cur != id_old and len(id_cur) == 8
    assert kms.oprf_key_for(id_cur) == k_cur
    assert kms.oprf_key_for(id_old) == k_old
    assert kms.oprf_key_for("ffffffff") is None
    monkeypatch.delenv("FZ_OPRF_SK_OLD")
    assert kms.oprf_key_for(id_old) is None
    assert kms.oprf_key_for(id_cur) == k_cur


def test_production_missing_oprf_key_refuses(_clean_kms_env, monkeypatch):
    """production 档缺 FZ_OPRF_SK 拒启且点名（拒启语义=派生钥顶替归零防线——
    归约 §6 原文；其余十钥齐备只缺这一枚）。"""
    from scripts.rotate_kms_keys import _material

    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    for name, _d, kind in PRODUCTION_REQUIRED_KEYS:
        if name != "FZ_OPRF_SK":
            monkeypatch.setenv(name, _material(kind))
    with pytest.raises(RuntimeError) as ei:
        create_app()
    assert "FZ_OPRF_SK" in str(ei.value)


# ---- 真链档链上交易钥派生回落 fail-visible（2026-10-15 安全凭据批） ----

_CHAIN_TX_KEY_ENVS = (
    "FZ_CHAIN_RA_TX_SK",
    "FZ_CHAIN_ENGINE_TX_SK",
    "FZ_CHAIN_AUDITOR_TX_SK",
    "FZ_CHAIN_ADMIN_TX_SK",
)


def test_real_chain_anchor_derived_keys_warn(_clean_kms_env, monkeypatch, capsys):
    """真链档（FZ_CHAIN_ANCHOR=real+环回=demo 档不拒启）下链上交易钥未 env
    注入 → 启动打 [FZ-STARTUP][WARN] 逐枚点名。派生回落=SM3(公开常量)
    （kms FZ-CHAIN-SMOKE|* 域）读过 repo 者可自推私钥直发链上交易冒充治理
    owner/审计方——production 档已拒启（assert_no_demo_keys_in_production），
    真链演示档保留 SMOKE 自洽部署动线但必须 fail-visible 让人看见。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    create_app()
    out = capsys.readouterr().out
    assert "[FZ-STARTUP][WARN]" in out and "链上交易钥" in out
    for name in _CHAIN_TX_KEY_ENVS:
        assert name in out, f"WARN 须点名 {name}"


def test_real_chain_anchor_injected_keys_silent(_clean_kms_env, monkeypatch, capsys):
    """四枚链上交易钥 env 注入 → 无链钥 WARN（不误报）；admin 旧名
    FZ_CHAIN_ADMIN_SK 单独注入与 kms 取钥顺序（kms/__init__.py 兼容读）同判
    ——同样视为已注入不告警。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    for name in _CHAIN_TX_KEY_ENVS:
        monkeypatch.setenv(name, "ab" * 32)
    create_app()
    assert "链上交易钥" not in capsys.readouterr().out
    # 旧名兼容：仅 admin 换旧名 FZ_CHAIN_ADMIN_SK（其余三枚保持注入）——
    # 与 kms 取钥顺序（kms/__init__.py 兼容读）同判，同样视为已注入不告警
    monkeypatch.delenv("FZ_CHAIN_ADMIN_TX_SK", raising=False)
    monkeypatch.setenv("FZ_CHAIN_ADMIN_SK", "ab" * 32)
    create_app()
    assert "链上交易钥" not in capsys.readouterr().out
