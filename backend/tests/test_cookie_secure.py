"""会话 Cookie Secure 配置化测试（批 2-2.5②）。

覆盖面：
- 演示档（缺省）：set_cookie 无 Secure（环回 http 可跑——现状保持）
- FZ_COOKIE_SECURE=true：显式开启→set_cookie 带 Secure
- production 档（FZ_DEPLOYMENT=production，KMS 钥全注入）：缺省自动 Secure
- 单元矩阵：FZ_COOKIE_SECURE 各种取值（env 显式值优先）
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.accounts.service import cookie_secure
from app.crypto.sm2 import generate_keypair, sign
from app.db import get_session
from app.main import create_app
from app.ra.models import Base
from tests.accounting import _sealed_blob

PW = "Cookie-Pw-1"


def _client(tmp_path, monkeypatch, **env):
    """建应用+临时库；env kwargs 注入部署档/密钥（monkeypatch 自动还原）。"""
    monkeypatch.delenv("FZ_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("FZ_DEPLOYMENT", raising=False)
    monkeypatch.delenv("FZ_BIND_ADDR", raising=False)
    monkeypatch.delenv("FZ_HOST", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    eng = create_engine(f"sqlite:///{tmp_path}/cookie_test.db")
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
    return TestClient(app)


def _login_capture_setcookie(c: TestClient, username: str) -> str:
    """注册→挑战登录，返回登录响应的 set-cookie 原始行。"""
    sk, pk = generate_keypair()
    r = c.post(
        "/auth/register",
        json={"username": username, "pubkey_hex": pk, "sealed_blob": _sealed_blob(pk, sk, PW)},
    )
    assert r.status_code == 201, r.text
    nonce = c.post(f"/auth/challenge/{username}").json()["data"]["nonce_hex"]
    r2 = c.post(
        "/auth/login",
        json={
            "username": username,
            "nonce_hex": nonce,
            "sig_hex": sign(sk, f"FZ-AUTH-LOGIN|{nonce}".encode()),
        },
    )
    assert r2.status_code == 200, r2.text
    return r2.headers.get("set-cookie", "")


def test_cookie_demo_default_no_secure(tmp_path, monkeypatch):
    """演示档（缺省）：Secure 不位——环回 http 演示可跑（现状保持）。"""
    c = _client(tmp_path, monkeypatch)
    set_cookie = _login_capture_setcookie(c, "pilot_ck1")
    assert "fz_session=" in set_cookie
    assert "HttpOnly" in set_cookie and "SameSite=lax" in set_cookie
    assert "Secure" not in set_cookie, set_cookie


def test_cookie_explicit_env_secure(tmp_path, monkeypatch):
    """FZ_COOKIE_SECURE=true：显式开启→set_cookie 带 Secure。"""
    c = _client(tmp_path, monkeypatch, FZ_COOKIE_SECURE="true")
    set_cookie = _login_capture_setcookie(c, "pilot_ck2")
    assert "Secure" in set_cookie, set_cookie


@pytest.mark.parametrize("raw,expect", [
    ("true", True), ("1", True), ("yes", True), ("on", True), ("TRUE", True),
    ("false", False), ("0", False), ("no", False), ("", False),
])
def test_cookie_secure_unit_matrix(monkeypatch, raw, expect):
    """单元矩阵：env 显式值优先（大小写不敏感；空串=未设定→按部署档）。"""
    monkeypatch.delenv("FZ_DEPLOYMENT", raising=False)
    monkeypatch.delenv("FZ_BIND_ADDR", raising=False)
    monkeypatch.delenv("FZ_HOST", raising=False)
    monkeypatch.setenv("FZ_COOKIE_SECURE", raw)
    assert cookie_secure() is expect


def test_cookie_secure_production_auto(tmp_path, monkeypatch):
    """production 档（KMS 钥全注入+批 4-2 服务形态断言前置：anchor=real/DB 显式
    ——2.3 同款前置扩展）：未设 FZ_COOKIE_SECURE 时自动 Secure（TLS 面缺省收紧）。"""
    from app.kms import PRODUCTION_REQUIRED_KEYS
    from scripts.rotate_kms_keys import _material

    prod_env = {name: _material(kind) for name, _desc, kind in PRODUCTION_REQUIRED_KEYS}
    c = _client(
        tmp_path,
        monkeypatch,
        FZ_DEPLOYMENT="production",
        FZ_CHAIN_ANCHOR="real",
        FZ_DB_URL=f"sqlite:///{tmp_path}/cookie_prod.db",
        **prod_env,
    )
    set_cookie = _login_capture_setcookie(c, "pilot_ck3")
    assert "Secure" in set_cookie, set_cookie
