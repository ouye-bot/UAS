"""拍板③（v3 旧信封停发+截止+production 存量告警）测试：

- 注册停发 v3：/auth/register 收 v3 信封=422（引导刷新），不入库
- v4 注册现行路径不受影响（201 正常入库）
- v3 登录惰性升级：FZ_V3_CUTOFF_TS 未启用/显式 0=现状（登录放行→会话内
  v3→v4 重封回传换库）
- v3 登录截止：截止期已到（now>=FZ_V3_CUTOFF_TS）→存量 v3 信封登录=403
  （处置=机构重置）；拒绝发生在挑战消费之前（nonce 不烧）；v4 账户同一
  截止期下不受影响；未到点（未来截止）=惰性升级窗继续
- 配置错误可见：FZ_V3_CUTOFF_TS 非整数=显式抛错（不许静默当 0）
- production 档启动扫查：存量 v3>0 打印显式告警（数量+账户名掩码+处置指引
  ——不拒启）；无存量不告警；demo 档恒不扫（零影响）
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.accounts.envelope import reseal_v4
from app.accounts.models import Account
from app.accounts.service import (
    mask_username,
    scan_v3_envelope_accounts,
    v3_cutoff_ts,
    v3_envelope_stock_report,
)
from app.crypto.sm2 import generate_keypair, sign
from app.db import get_session
from app.main import create_app
from app.ra.models import Base

PASS = "Test-Pass-8"
_V3_CUTOFF_MSG = "旧版密钥封装已过截止期——请联系机构重置凭证"
_STOCK_MARKER = "存量 v3 密封信封账户"

# 复用既有测试事实源：v3 legacy 信封构造 / production 档 env 基座（KMS 钥注入）
from tests.test_accounts import _sealed_blob_v3_legacy  # noqa: E402
from tests.test_production_startup_gate import _prod_env_base  # noqa: E402,F401


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    monkeypatch.delenv("FZ_V3_CUTOFF_TS", raising=False)  # 截止策略缺省不启用
    eng = create_engine(f"sqlite:///{tmp_path}/v3_sunset_test.db")
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
        yield c


def _sess_of(client):
    """测试库会话（与 test_accounts._sess_of 同款：取依赖覆盖生成器）。"""
    gen = client.app.dependency_overrides[get_session]()
    sess = next(gen)
    return gen, sess


def _seed_v3_account(client, username: str) -> tuple[str, str]:
    """存量 v3 账户（拍板③前注册门兼容口径入库——此处直播行模拟）。"""
    sk, pk = generate_keypair()
    gen, sess = _sess_of(client)
    try:
        sess.add(
            Account(
                username=username,
                role="pilot",
                status="pending_profile",
                pubkey_hex=pk.lower(),
                sealed_blob=_sealed_blob_v3_legacy(pk, sk, PASS),
            )
        )
        sess.commit()
    finally:
        gen.close()
    return sk, pk


def _issue_nonce(c: TestClient, username: str) -> str:
    return c.post(f"/auth/challenge/{username}").json()["data"]["nonce_hex"]


def _login_with_nonce(c: TestClient, username: str, sk: str, nonce: str):
    sig = sign(sk, (f"FZ-AUTH-LOGIN|{nonce}").encode())
    return c.post("/auth/login", json={"username": username, "nonce_hex": nonce, "sig_hex": sig})


def _challenge_login(c: TestClient, username: str, sk: str):
    """完整挑战-应答一次（返回响应对象——由用例自断言状态码）。"""
    return _login_with_nonce(c, username, sk, _issue_nonce(c, username))


# ---- ①注册停发 v3 / ②v4 注册正常 ----
def test_register_rejects_v3_envelope_422(client):
    """拍板③①：注册收 v3 信封=422（人话引导刷新），账户不入库。"""
    sk, pk = generate_keypair()
    r = client.post(
        "/auth/register",
        json={
            "username": "pilot_v3reg",
            "pubkey_hex": pk,
            "sealed_blob": _sealed_blob_v3_legacy(pk, sk, PASS),
        },
    )
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["code"] == "v3_register_rejected"
    assert body["message"] == "注册须使用当前密钥封装格式（v4）——请刷新页面后重试"
    gen, sess = _sess_of(client)
    try:
        assert sess.query(Account).filter_by(username="pilot_v3reg").one_or_none() is None
    finally:
        gen.close()


def test_register_accepts_v4_envelope(client):
    """现行 v4 注册路径不受停发影响（201 入库+信封 v4 落库）。"""
    sk, pk = generate_keypair()
    from app.accounts.envelope import seal_envelope_v4

    r = client.post(
        "/auth/register",
        json={
            "username": "pilot_v4reg",
            "pubkey_hex": pk,
            "sealed_blob": seal_envelope_v4(sk, pk, PASS, iterations=4096),
        },
    )
    assert r.status_code == 201, r.text
    gen, sess = _sess_of(client)
    try:
        row = sess.query(Account).filter_by(username="pilot_v4reg").one()
        assert json.loads(row.sealed_blob)["v"] == 4
    finally:
        gen.close()


# ---- ③v3 登录惰性升级（cutoff=0/未启用） ----
def test_v3_login_lazy_upgrade_with_cutoff_zero(client, monkeypatch):
    """FZ_V3_CUTOFF_TS=0（显式不启用）：存量 v3 登录放行→会话内同口令
    v3→v4 重封回传→库内换 v4（惰性升级现状保持）。"""
    monkeypatch.setenv("FZ_V3_CUTOFF_TS", "0")
    assert v3_cutoff_ts() == 0
    sk, _pk = _seed_v3_account(client, "pilot_lazy0")
    r = _challenge_login(client, "pilot_lazy0", sk)
    assert r.status_code == 200, r.text
    ks = client.get("/auth/keystore/pilot_lazy0").json()["data"]
    assert json.loads(ks["sealed_blob"])["v"] == 3
    up = client.post("/auth/keystore/upgrade", json={"sealed_blob": reseal_v4(ks["sealed_blob"], PASS, iterations=4096)})
    assert up.status_code == 200, up.text
    ks2 = client.get("/auth/keystore/pilot_lazy0").json()["data"]
    assert json.loads(ks2["sealed_blob"])["v"] == 4


# ---- ④cutoff 启用后 v3 登录 403 ----
def test_v3_login_403_after_cutoff_and_nonce_unburned(client, monkeypatch):
    """截止期已到：存量 v3 登录=403（处置指引人话）；拒绝在挑战消费之前
    （同一 nonce 撤截止后仍可登——不烧挑战）；同一截止期下 v4 账户不受影响。"""
    sk_v3, _ = _seed_v3_account(client, "pilot_cut3")
    sk_v4, pk_v4 = generate_keypair()
    from app.accounts.envelope import seal_envelope_v4

    rv = client.post(
        "/auth/register",
        json={
            "username": "pilot_cut4",
            "pubkey_hex": pk_v4,
            "sealed_blob": seal_envelope_v4(sk_v4, pk_v4, PASS, iterations=4096),
        },
    )
    assert rv.status_code == 201, rv.text

    monkeypatch.setenv("FZ_V3_CUTOFF_TS", str(int(time.time()) - 10))  # 已过截止
    nonce = _issue_nonce(client, "pilot_cut3")
    r = _login_with_nonce(client, "pilot_cut3", sk_v3, nonce)
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "v3_cutoff"
    assert r.json()["message"] == _V3_CUTOFF_MSG
    # v4 账户同一截止期下正常登录（截止只打 v3 信封——不伤现行格式）
    r4 = _challenge_login(client, "pilot_cut4", sk_v4)
    assert r4.status_code == 200, r4.text

    # 撤截止（env 移除=不启用）→同一 nonce/签名可登（403 发生在消费前——不烧挑战）
    monkeypatch.delenv("FZ_V3_CUTOFF_TS", raising=False)
    r_again = _login_with_nonce(client, "pilot_cut3", sk_v3, nonce)
    assert r_again.status_code == 200, r_again.text


def test_v3_login_allowed_before_future_cutoff(client, monkeypatch):
    """截止期在未来（未到点）：存量 v3 登录照常放行——惰性升级窗继续。"""
    monkeypatch.setenv("FZ_V3_CUTOFF_TS", str(int(time.time()) + 3600))
    assert v3_cutoff_ts() == int(time.time()) + 3600
    sk, _ = _seed_v3_account(client, "pilot_future")
    r = _challenge_login(client, "pilot_future", sk)
    assert r.status_code == 200, r.text


def test_v3_cutoff_malformed_env_fails_visible(client, monkeypatch):
    """FZ_V3_CUTOFF_TS 非整数=显式抛错（配置错误必须可见——不许静默当 0）。"""
    monkeypatch.setenv("FZ_V3_CUTOFF_TS", "not-a-number")
    with pytest.raises(ValueError, match="FZ_V3_CUTOFF_TS"):
        v3_cutoff_ts()
    sk, _ = _seed_v3_account(client, "pilot_badenv")
    with pytest.raises(ValueError, match="FZ_V3_CUTOFF_TS"):
        _challenge_login(client, "pilot_badenv", sk)


# ---- ⑤⑥production 档存量扫查（启动告警/无存量静默/demo 零影响） ----
def _prod_scan_env(monkeypatch, tmp_path, rows: list[Account]) -> sessionmaker:
    """production env 齐备+临时库播种——返回钉给 app.db.SessionLocal 的工厂。"""
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    dbp = tmp_path / "v3_scan.db"
    monkeypatch.setenv("FZ_DB_URL", f"sqlite:///{dbp}")
    eng = create_engine(f"sqlite:///{dbp}")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)
    s = TestSession()
    try:
        for row in rows:
            s.add(row)
        s.commit()
    finally:
        s.close()
    # 启动扫查走 app.db.SessionLocal（main.py 钩子在 create_app 时取属性）——钉到本例库
    import app.db as _db

    monkeypatch.setattr(_db, "SessionLocal", TestSession)
    return TestSession


def test_production_startup_warns_on_v3_stock(_prod_env_base, monkeypatch, tmp_path, capsys):
    """production+v3 存量：启动打印显式告警（数量+掩码+处置指引，不拒启）；
    账户全名不进日志。"""
    sk, pk = generate_keypair()
    v3_row = Account(
        username="pilot_legacy3",
        role="pilot",
        status="pending_profile",
        pubkey_hex=pk.lower(),
        sealed_blob=_sealed_blob_v3_legacy(pk, sk, PASS),
    )
    _prod_scan_env(monkeypatch, tmp_path, [v3_row])
    app = create_app()  # 不拒启——告警后照常建成
    assert app.title == "feizheng-backend"
    out = capsys.readouterr().out
    assert "[FZ-STARTUP][WARN]" in out
    assert f"{_STOCK_MARKER} 1 个" in out
    assert mask_username("pilot_legacy3") in out  # 掩码在（p***********3）
    assert "pilot_legacy3" not in out  # 全名不进日志
    assert "惰性升级" in out and "重置" in out  # 处置指引双路径齐备
    assert "不阻断启动" in out


def test_production_startup_silent_without_v3_stock(_prod_env_base, monkeypatch, tmp_path, capsys):
    """production 无 v3 存量（v4 账户+未激活空密封件行）：不打印存量告警。"""
    sk, pk = generate_keypair()
    from app.accounts.envelope import seal_envelope_v4

    v4_row = Account(
        username="pilot_modern4",
        role="pilot",
        status="pending_profile",
        pubkey_hex=pk.lower(),
        sealed_blob=seal_envelope_v4(sk, pk, PASS, iterations=4096),
    )
    pending_row = Account(username="aud_waiting", role="auditor", status="pending_activation")
    _prod_scan_env(monkeypatch, tmp_path, [v4_row, pending_row])
    create_app()
    out = capsys.readouterr().out
    assert _STOCK_MARKER not in out  # 无存量=静默（同库 v4/空密封件行不误报）
    assert "pilot_modern4" not in out  # 无存量即无账户名出账


def test_stock_report_demo_tier_and_scan_semantics(monkeypatch, tmp_path):
    """demo（环回）档：库里有 v3 存量也恒不告警（is_production 门）；
    扫查语义=v3 计入、v4/空密封件/坏形态不计入；掩码=首尾保留中间 * 化。"""
    monkeypatch.delenv("FZ_DEPLOYMENT", raising=False)
    monkeypatch.delenv("FZ_BIND_ADDR", raising=False)
    monkeypatch.delenv("FZ_HOST", raising=False)
    eng = create_engine(f"sqlite:///{tmp_path}/scan_sem.db")
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng, expire_on_commit=False)()
    try:
        s.add(
            Account(
                username="pilot_v3x",
                role="pilot",
                status="pending_profile",
                pubkey_hex="ab" * 64,
                sealed_blob=json.dumps({"v": 3, "pk": "ab" * 64, "enc": {"salt": "aa" * 16}}),
            )
        )
        s.add(
            Account(
                username="pilot_v4x",
                role="pilot",
                status="pending_profile",
                pubkey_hex="cd" * 64,
                sealed_blob=json.dumps({"v": 4, "pk": "cd" * 64, "enc": {}}),
            )
        )
        s.add(Account(username="aud_none", role="auditor", status="pending_activation"))
        s.add(
            Account(
                username="pilot_broken",
                role="pilot",
                status="pending_profile",
                sealed_blob="not-json-at-all",
            )
        )
        s.commit()
        assert scan_v3_envelope_accounts(s) == ["pilot_v3x"]
        assert v3_envelope_stock_report(s) is None  # demo 档恒 None
    finally:
        s.close()
    # 掩码语义：首尾保留、中间 * 化；≤2 字符保留首字符
    assert mask_username("pilot_v3up") == "p********p"
    assert mask_username("ab") == "a*"
