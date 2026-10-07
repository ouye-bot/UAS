"""账户门户测试（2026-09-29 账户批；2026-10-04 批 2 密码底座升档）：
注册/激活/挑战-应答登录/会话/角色守卫。

覆盖面：
- KDF 交叉对拍锚（v4=PBKDF2-HMAC-SM3 现行口径 + v3 legacy 兼容口径——
  JS 前端 node+hash-wasm 实测产出，逐字节一致——密封体系根基）
- 飞手注册→资料补全（RA 签发上链）→挑战登录全流程
- 预置机构账户首登激活（核对子一次性，独立派生域）→激活后纯挑战态
- 激活前库内容不含可用 KEK（批 2-2.2 审计断言——核对子≠KEK 等价物）
- 旧种子格式（KEK 等价核对子）兼容读取+激活即换代
- 存量 v3 密封件解封+惰性重封 v4（/auth/keystore/upgrade 回传面）
- 负例：错口令签名拒/挑战重放拒/挑战过期拒/用户名重复拒/坏密封件拒/
  越权 403/未登录 401/限速 429（落库后行为不变）
- 会话：Cookie 形态（HttpOnly+SameSite）/登出即焚
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.accounts.envelope import seal_envelope_v4
from app.accounts.kdf import (
    KDF_LEGACY_V3_ITERATIONS,
    _legacy_v3,
    derive_activation_verifier,
)
from app.crypto.sm2 import generate_keypair, sign
from app.db import get_session
from app.main import create_app
from app.ra.models import Base

PASS = "Test-Pass-8"  # 强度过门槛（字母+数字≥8）——KDF 对拍同款
FORM = {
    "id_number": "110101199001011234",
    "cert_level": 3,
    "sn": "FZ-SN-TEST-01",
    "class_id": 1,
}


def _sealed_blob_js_style(pk: str, sk: str, passphrase: str) -> str:
    """v4 信封（前端 sealKeystoreV4 同构——keystore.ts 批二实现）：
    enc 槽=PBKDF2-HMAC-SM3(pass, salt, iter) KEK + SM4-GCM，AAD 绑定 v4 槽位。
    测试内联实现与 keystore.ts 同一构造（前端侧由 e2e 全流程覆盖）。"""
    import secrets

    from app.crypto.sm4 import SM4GCM

    salt = secrets.token_hex(16)
    nonce = secrets.token_hex(12)
    iterations = 4096  # 测试档迭代数（信封内落盘——生产缺省 600k 由专项锚验证）
    from app.accounts.kdf import derive_kek

    kek = bytes.fromhex(derive_kek(passphrase, salt, iterations))
    ct, tag = SM4GCM(kek).encrypt(bytes.fromhex(nonce), bytes.fromhex(sk), b"FZ-KEYSTORE-v4|pass")
    return json.dumps(
        {
            "v": 4,
            "pk": pk,
            "enc": {
                "salt": salt,
                "nonce": nonce,
                "ct": ct.hex(),
                "tag": tag.hex(),
                "kdf": "pbkdf2-sm3",
                "iter": iterations,
            },
        }
    )


def _sealed_blob_v3_legacy(pk: str, sk: str, passphrase: str) -> str:
    """v3 legacy 信封（存量密封件口径——SM3 迭代链 21000 + v3 AAD）。
    仅供兼容面测试构造存量形态；新密封一律 v4。"""
    import secrets

    from app.crypto.sm4 import SM4GCM

    salt = secrets.token_hex(16)
    nonce = secrets.token_hex(12)
    kek = bytes.fromhex(_legacy_v3(passphrase, salt, KDF_LEGACY_V3_ITERATIONS))
    ct, tag = SM4GCM(kek).encrypt(bytes.fromhex(nonce), bytes.fromhex(sk), b"FZ-KEYSTORE-v3|pass")
    return json.dumps(
        {
            "v": 3,
            "pk": pk,
            "enc": {"salt": salt, "nonce": nonce, "ct": ct.hex(), "tag": tag.hex()},
        }
    )


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/accounts_test.db")
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
    # 限速窗已落库（rate_limit_buckets）——每用例独立临时库，无进程态残留；
    # cookie_secure 读取 env——测试内 monkeypatch 的档位随用例自动还原。


def _register_pilot(c: TestClient, username: str = "pilot_a") -> tuple[str, str]:
    sk, pk = generate_keypair()
    pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀——误剥致 ~1/256 注册随机失败
    r = c.post(
        "/auth/register",
        json={
            "username": username,
            "pubkey_hex": pk_no04,
            "sealed_blob": _sealed_blob_js_style(pk_no04, sk, PASS),
        },
    )
    assert r.status_code == 201, r.text
    return sk, pk_no04


def _login(c: TestClient, username: str, sk: str) -> None:
    nonce = c.post(f"/auth/challenge/{username}").json()["data"]["nonce_hex"]
    sig = sign(sk, (f"FZ-AUTH-LOGIN|{nonce}").encode())
    r = c.post("/auth/login", json={"username": username, "nonce_hex": nonce, "sig_hex": sig})
    assert r.status_code == 200, r.text


# ---- KDF 对拍锚 ----
def test_kdf_cross_vectors():
    """JS 侧派生（node+hash-wasm createSM3/pbkdf2 实测产出）逐字节对拍——密封体系根基。
    v4=现行（PBKDF2-HMAC-SM3，与 Python hashlib/pure 双引擎一致）；v3=legacy（旧
    SM3 迭代链——存量密封件兼容面，值不删不换）。"""
    from app.accounts.kdf import _legacy_v3, derive_kek

    # v4 现行口径
    assert derive_kek("Test-Pass-8", "aabbccdd", 8) == "1277e3342905e4695e67bde5dd3d89dd"
    assert (
        derive_kek("Test-Pass-8", "aabbccdd", 21000) == "0b1e8a811af3d432501681bf8372023b"
    )
    # v3 legacy 口径（保留——旧密封件/旧种子兼容读取的事实源）
    assert _legacy_v3("Test-Pass-8", "aabbccdd", 8) == "b7a19b8f13a8ea0768e16242baaf6d14"
    assert (
        _legacy_v3("Test-Pass-8", "aabbccdd", 21000) == "8c30c8ae0a6067df7085e7230c92096d"
    )


def test_kdf_production_iterations_default_and_env(monkeypatch):
    """生产档迭代数：缺省=600000（OWASP 2023 PBKDF2 档）；FZ_KDF_ITERATIONS
    可调；600k 全参数回环一次（生产工作因子实测走通）。"""
    from app.accounts.envelope import reseal_v4, unseal_envelope
    from app.accounts.kdf import KDF_ITERATIONS_DEFAULT, kdf_iterations

    monkeypatch.delenv("FZ_KDF_ITERATIONS", raising=False)
    assert kdf_iterations() == KDF_ITERATIONS_DEFAULT == 600_000
    monkeypatch.setenv("FZ_KDF_ITERATIONS", "4096")
    assert kdf_iterations() == 4096
    # 600k 生产档实密封实解（一次全工作因子回环）
    monkeypatch.delenv("FZ_KDF_ITERATIONS", raising=False)
    sk, pk = generate_keypair()
    blob = seal_envelope_v4(sk, pk, "Prod-Iter-Check-1")  # 缺省=600k
    assert json.loads(blob)["enc"]["iter"] == 600_000
    assert unseal_envelope(blob, "Prod-Iter-Check-1") == sk
    blob2 = reseal_v4(blob, "Prod-Iter-Check-1", iterations=4096)
    assert unseal_envelope(blob2, "Prod-Iter-Check-1") == sk


# ---- 飞手全流程 ----
def test_pilot_register_profile_login_flow(client):
    sk, pk = _register_pilot(client, "pilot_flow")
    # 未登录取 me=401
    assert client.get("/auth/me").status_code == 401
    # 登录（此时 status=pending_profile 亦可登录——工作台受限由前端表达）
    _login(client, "pilot_flow", sk)
    me = client.get("/auth/me")
    assert me.status_code == 200
    body = me.json()["data"]
    assert body["role"] == "pilot" and body["status"] == "pending_profile"
    assert body["pubkey_hex"] == pk
    # 资料补全→RA 签发（fake 链锚——链副作用记录不炸）；二相回存密封资料
    r = client.post("/auth/profile", json=FORM)
    assert r.status_code == 200, r.text
    out = r.json()["data"]
    assert len(out["master_cred_hash_hex"]) == 64
    me2 = client.get("/auth/me").json()["data"]
    assert me2["status"] == "active" and me2["cred_hash_hex"] == out["master_cred_hash_hex"]
    rk = client.post(
        "/auth/profile/keep",
        json={"sealed_profile": json.dumps({"v": 3, "meta": {"ct": "ab" * 120, "tag": "cd" * 16, "salt": "ef" * 16, "nonce": "12" * 12}})},
    )
    assert rk.status_code == 200, rk.text
    me3 = client.get("/auth/me").json()["data"]
    assert me3["sealed_profile"]


def test_login_challenge_replay_rejected(client):
    sk, _ = _register_pilot(client, "pilot_replay")
    nonce = client.post("/auth/challenge/pilot_replay").json()["data"]["nonce_hex"]
    sig = sign(sk, (f"FZ-AUTH-LOGIN|{nonce}").encode())
    body = {"username": "pilot_replay", "nonce_hex": nonce, "sig_hex": sig}
    assert client.post("/auth/login", json=body).status_code == 200
    r2 = client.post("/auth/login", json=body)
    assert r2.status_code == 401 and r2.json()["code"] == "bad_challenge"


def test_login_wrong_key_rejected(client):
    _register_pilot(client, "pilot_wrong")
    nonce = client.post("/auth/challenge/pilot_wrong").json()["data"]["nonce_hex"]
    sk_other, _ = generate_keypair()
    sig = sign(sk_other, (f"FZ-AUTH-LOGIN|{nonce}").encode())
    r = client.post(
        "/auth/login",
        json={"username": "pilot_wrong", "nonce_hex": nonce, "sig_hex": sig},
    )
    assert r.status_code == 401 and r.json()["code"] == "auth_failed"


def test_register_duplicate_and_bad_blob(client):
    _register_pilot(client, "pilot_dup")
    sk, pk = generate_keypair()
    pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀——误剥致 ~1/256 注册随机失败
    r = client.post(
        "/auth/register",
        json={
            "username": "pilot_dup",
            "pubkey_hex": pk_no04,
            "sealed_blob": _sealed_blob_js_style(pk_no04, sk, PASS),
        },
    )
    assert r.status_code == 409 and r.json()["code"] == "username_taken"
    # 坏密封件：pk 与信封不一致
    r2 = client.post(
        "/auth/register",
        json={
            "username": "pilot_bad",
            "pubkey_hex": pk_no04,
            "sealed_blob": _sealed_blob_js_style("ff" * 64, sk, PASS),
        },
    )
    assert r2.status_code == 400 and r2.json()["code"] == "bad_blob"
    # 非曲线点公钥
    r3 = client.post(
        "/auth/register",
        json={
            "username": "pilot_badpk",
            "pubkey_hex": "11" * 64,
            "sealed_blob": _sealed_blob_js_style("11" * 64, sk, PASS),
        },
    )
    assert r3.status_code == 400 and r3.json()["code"] == "bad_pubkey"


# ---- 预置机构账户：激活→登录→角色守卫 ----
def test_seed_activate_and_role_guard(client):
    from app.accounts.models import Account
    from app.accounts.service import seed_institutional_account

    s = client.app.dependency_overrides[get_session]
    gen = s()
    sess = next(gen)
    try:
        seed_institutional_account(sess, "auditor_t", "auditor", "Init-Pass-9")
        row = sess.query(Account).filter_by(username="auditor_t").one()
        salt = row.init_kdf_salt_hex
        assert row.init_verifier_ver == "v1"  # 独立派生域格式标记
    finally:
        gen.close()

    # 错口令核对子=拒
    sk, pk = generate_keypair()
    pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀——误剥致 ~1/256 注册随机失败
    bad_ver = derive_activation_verifier("Wrong-Pass-1", salt)
    r = client.post(
        "/auth/activate",
        json={
            "username": "auditor_t",
            "verifier_hex": bad_ver,
            "pubkey_hex": pk_no04,
            "sealed_blob": _sealed_blob_js_style(pk_no04, sk, PASS),
        },
    )
    assert r.status_code == 401 and r.json()["code"] == "activation_failed"
    # 正确核对子→激活成功→核对子即焚（含格式标记）
    ver = derive_activation_verifier("Init-Pass-9", salt)
    r2 = client.post(
        "/auth/activate",
        json={
            "username": "auditor_t",
            "verifier_hex": ver,
            "pubkey_hex": pk_no04,
            "sealed_blob": _sealed_blob_js_style(pk_no04, sk, PASS),
        },
    )
    assert r2.status_code == 200, r2.text
    gen = s()
    sess = next(gen)
    try:
        row = sess.query(Account).filter_by(username="auditor_t").one()
        assert row.status == "active" and row.init_verifier_hex is None
        assert row.init_verifier_ver is None and row.init_kdf_salt_hex is None
    finally:
        gen.close()
    # 激活后登录→/auth/whoami 角色正确
    _login(client, "auditor_t", sk)
    who = client.get("/auth/whoami")
    assert who.status_code == 200 and who.json()["data"]["role"] == "auditor"


def test_guard_401_before_login(client):
    """未登录访问业务面=401（审计端点批次切角色前由令牌校验给出同语义）。"""
    assert client.get("/audit/warrants").status_code == 401


def test_rate_limit_429(client):
    sk, _ = _register_pilot(client, "pilot_rl")
    for _ in range(10):
        client.post("/auth/challenge/pilot_rl")
    r = client.post("/auth/challenge/pilot_rl")
    assert r.status_code == 429 and r.json()["code"] == "rate_limited"
    del sk


def test_logout_burns_session(client):
    sk, _ = _register_pilot(client, "pilot_out")
    _login(client, "pilot_out", sk)
    assert client.get("/auth/me").status_code == 200
    assert client.post("/auth/logout").status_code == 200
    assert client.get("/auth/me").status_code == 401


def test_reset_institutional_account(client):
    """机构账户密码重置：激活态→重置→回待激活（新核对子+旧钥焚毁+会话清）；
    新密码激活登录成功；旧密码失效。"""
    from app.accounts.models import Account
    from app.accounts.service import reset_institutional_account, seed_institutional_account

    s = client.app.dependency_overrides[get_session]
    gen = s()
    sess = next(gen)
    try:
        seed_institutional_account(sess, "adm_reset", "admin", "Old-Pass-1")
    finally:
        gen.close()
    sk, _pk = generate_keypair()
    pk_no04 = _pk  # 同上（无 04 前缀）
    # 激活（正确核对子——从库取盐，独立派生域复算）
    gen = s()
    sess = next(gen)
    try:
        salt = sess.query(Account).filter_by(username="adm_reset").one().init_kdf_salt_hex
    finally:
        gen.close()
    r = client.post("/auth/activate", json={
        "username": "adm_reset", "verifier_hex": derive_activation_verifier("Old-Pass-1", salt),
        "pubkey_hex": pk_no04, "sealed_blob": _sealed_blob_js_style(pk_no04, sk, "New-Pass-1")})
    assert r.status_code == 200
    _login(client, "adm_reset", sk)
    assert client.get("/auth/me").status_code == 200  # 会话在
    # 重置
    gen = s()
    sess = next(gen)
    try:
        row = reset_institutional_account(sess, "adm_reset", "Reset-Pass-2")
        assert row.status == "pending_activation" and row.pubkey_hex is None
    finally:
        gen.close()
    # 旧会话已焚毁
    assert client.get("/auth/me").status_code == 401
    # 旧钥登录=不可达（挑战拒绝：未激活）
    nonce_r = client.post("/auth/challenge/adm_reset")
    assert nonce_r.status_code == 409
    # 新密码激活登录
    gen = s()
    sess = next(gen)
    try:
        salt2 = sess.query(Account).filter_by(username="adm_reset").one().init_kdf_salt_hex
    finally:
        gen.close()
    sk2, _pk2 = generate_keypair()
    pk2 = _pk2  # 同上（无 04 前缀）
    r2 = client.post("/auth/activate", json={
        "username": "adm_reset", "verifier_hex": derive_activation_verifier("Reset-Pass-2", salt2),
        "pubkey_hex": pk2, "sealed_blob": _sealed_blob_js_style(pk2, sk2, "Reset-Pass-2")})
    assert r2.status_code == 200
    _login(client, "adm_reset", sk2)
    who = client.get("/auth/whoami").json()["data"]
    assert who["role"] == "admin" and who["status"] == "active"


# ---- 密码重置收紧批（2026-09-30）：在线端点退役+台账+公钥纪元史 append-only ----


def _sess_of(client):
    gen = client.app.dependency_overrides[get_session]()
    sess = next(gen)
    return gen, sess


def test_online_reset_endpoint_retired(client):
    """在线重置端点已下线（互不可重置/自重置禁止）：POST=404——admin 无任何
    在线重置能力；唯一路径=离线种子脚本（负例一等公民）。"""
    from tests.accounting import register_and_login

    register_and_login(client, "adm_online", "admin", "Admin-Pass-9")
    r = client.post(
        "/admin/accounts/auditor/reset-password",
        json={"new_password": "Taken-Over-1"},
    )
    assert r.status_code == 404, r.text  # 路由不存在——非 403/非 401，是彻底退役


def test_reset_writes_admin_log_and_retires_epoch(client):
    """重置=离线脚本路径：台账逐笔留痕+公钥纪元只关闭不删除。"""
    import datetime as dt

    from app.accounts.models import Account, AccountAdminLog, AccountPubkeyHistory
    from app.accounts.service import (
        pubkey_at,
        reset_institutional_account,
        seed_institutional_account,
    )

    gen, sess = _sess_of(client)
    try:
        seed_institutional_account(sess, "aud_log", "auditor", "Init-Pass-1")
        sess.commit()
    finally:
        gen.close()
    # 首登激活（纪元 1 入账）
    gen, sess = _sess_of(client)
    try:
        salt = sess.query(Account).filter_by(username="aud_log").one().init_kdf_salt_hex
    finally:
        gen.close()
    sk, pk = generate_keypair()
    r = client.post("/auth/activate", json={
        "username": "aud_log", "verifier_hex": derive_activation_verifier("Init-Pass-1", salt),
        "pubkey_hex": pk, "sealed_blob": _sealed_blob_js_style(pk, sk, "Init-Pass-1")})
    assert r.status_code == 200, r.text
    # 离线脚本重置
    gen, sess = _sess_of(client)
    try:
        reset_institutional_account(sess, "aud_log", "New-Pass-2")
        sess.commit()
        hist = sess.query(AccountPubkeyHistory).filter_by(username="aud_log").all()
        assert len(hist) == 1 and hist[0].epoch == 1
        assert hist[0].retired_ts is not None  # 只关闭，行保留
        log = sess.query(AccountAdminLog).filter_by(username="aud_log").all()
        assert len(log) == 1 and log[0].action == "password_reset"
        assert log[0].operator == "offline_seed_script"
        assert "closed_epoch=1" in (log[0].detail or "")
        # 重置瞬间之后无活动纪元（新钥未激活）
        assert pubkey_at(sess, "aud_log", dt.datetime.utcnow()) is None
    finally:
        gen.close()


def test_seed_reseed_pending_writes_log(client):
    """待激活态重设核对子（幂等 reseed）也入台账——敏感动作无死角。"""
    from app.accounts.models import AccountAdminLog
    from app.accounts.service import seed_institutional_account

    gen, sess = _sess_of(client)
    try:
        seed_institutional_account(sess, "adm_reseed", "admin", "First-Pass-1")
        seed_institutional_account(sess, "adm_reseed", "admin", "Second-Pass-2")
        sess.commit()
        rows = sess.query(AccountAdminLog).filter_by(username="adm_reseed").all()
        assert len(rows) == 1 and rows[0].action == "reseed_pending"
    finally:
        gen.close()


def test_pubkey_at_epoch_boundaries(client):
    """纪元史时点查询边界：纪元1 全程可取→退休瞬间之后不可取→再激活后
    纪元 2 可取且纪元 1 仍可按历史时点回取（append-only 复验根基）。"""
    import datetime as dt

    from app.accounts.models import Account, AccountPubkeyHistory
    from app.accounts.service import (
        append_pubkey_epoch,
        pubkey_at,
        pubkey_epoch_at,
        retire_active_pubkey_epoch,
    )

    gen, sess = _sess_of(client)
    try:
        t0 = dt.datetime.utcnow()
        sess.add(Account(username="pk_ep", role="pilot", status="active", pubkey_hex="aa" * 64))
        sess.commit()
        append_pubkey_epoch(sess, "pk_ep", "aa" * 64)
        sess.commit()
        t1 = dt.datetime.utcnow()
        assert pubkey_at(sess, "pk_ep", t1) == "aa" * 64
        assert pubkey_epoch_at(sess, "pk_ep", t1) == 1
        assert pubkey_at(sess, "pk_ep", t0) is None  # 早于激活=无纪元
        # 重置（关闭纪元 1）→再激活（纪元 2）
        retired = retire_active_pubkey_epoch(sess, "pk_ep")
        sess.commit()
        t2 = dt.datetime.utcnow()
        assert retired == 1
        assert pubkey_at(sess, "pk_ep", t2) is None  # 退休后无活动钥
        append_pubkey_epoch(sess, "pk_ep", "bb" * 64)
        sess.commit()
        t3 = dt.datetime.utcnow()
        assert pubkey_at(sess, "pk_ep", t3) == "bb" * 64  # 新纪元
        assert pubkey_epoch_at(sess, "pk_ep", t3) == 2
        assert pubkey_at(sess, "pk_ep", t1) == "aa" * 64  # 🔴 历史时点仍回取旧钥
        hist = sess.query(AccountPubkeyHistory).filter_by(username="pk_ep").all()
        assert [(h.epoch, h.retired_ts is not None) for h in hist] == [(1, True), (2, False)]
    finally:
        gen.close()


# ---- 批 2 密码底座升档：核对子解耦 / 旧种子兼容 / 惰性重封 ----


def test_activation_verifier_decoupled_from_kek(client):
    """审计断言（批 2-2.2）：激活前库内核对子不含可用 KEK——
    ①核对子 ≠ KEK 派生值（v4 与 legacy 两口径逐字节不等）；
    ②以库内核对子为 KEK 无法解封任何同口令密封件（GCM 认证失败）；
    ③prelogin 下发独立域口径标记（verifier="v1"）。"""
    import secrets as _secrets

    from app.accounts.kdf import derive_kek
    from app.accounts.models import Account
    from app.accounts.service import seed_institutional_account
    from app.crypto.sm4 import SM4GCM

    gen, sess = _sess_of(client)
    try:
        seed_institutional_account(sess, "aud_dec", "auditor", "Decoupled-Pw-7")
        row = sess.query(Account).filter_by(username="aud_dec").one()
        salt, stored = row.init_kdf_salt_hex, row.init_verifier_hex
    finally:
        gen.close()

    # prelogin 下发独立域标记（客户端据此同域复算）
    pre = client.get("/auth/prelogin/aud_dec").json()["data"]
    assert pre["mode"] == "activation" and pre["verifier"] == "v1"
    assert pre["kdf_salt_hex"] == salt

    # ①库内核对子与两代 KEK 派生值逐字节不等（域分离=拿库拿不到可用 KEK）
    assert stored != derive_kek("Decoupled-Pw-7", salt)  # v4 KEK 域
    assert stored != _legacy_v3("Decoupled-Pw-7", salt)  # v3 legacy KEK 域
    # 同域复算一致（客户端可激活的前提）
    assert stored == derive_activation_verifier("Decoupled-Pw-7", salt)

    # ②用库内核对子当 KEK 解封同口令密封件=GCM 认证失败（不是 KEK 等价物）
    sk, pk = generate_keypair()
    for kek_hex in (derive_kek("Decoupled-Pw-7", salt), _legacy_v3("Decoupled-Pw-7", salt)):
        nonce = _secrets.token_hex(12)
        ct, tag = SM4GCM(bytes.fromhex(kek_hex)).encrypt(
            bytes.fromhex(nonce), bytes.fromhex(sk), b"FZ-KEYSTORE-v4|pass"
        )
        with pytest.raises(Exception):  # noqa: B017, PT011  库内 verifier 当 KEK 必不可解
            SM4GCM(bytes.fromhex(stored)).decrypt(
                bytes.fromhex(nonce), ct, tag, b"FZ-KEYSTORE-v4|pass"
            )


def test_legacy_seed_format_compat_and_upgrade(client):
    """旧种子格式（init_verifier_ver=NULL=旧链 KEK 等价核对子）兼容读取：
    prelogin 下发 legacy_v3 口径→客户端按旧口径复算→激活成功即焚（换代）；
    新域核对子对旧行不误配（401）。"""
    import secrets as _secrets

    from app.accounts.models import Account

    salt = _secrets.token_hex(16)
    gen, sess = _sess_of(client)
    try:
        # 直接构造旧种子行（旧版 seed 脚本落库形态——核对子=旧链 KEK 本体）
        sess.add(
            Account(
                username="aud_old_seed",
                role="auditor",
                status="pending_activation",
                init_kdf_salt_hex=salt,
                init_verifier_hex=_legacy_v3("Old-Seed-Pw-3", salt),
            )
        )
        sess.commit()
    finally:
        gen.close()
    # prelogin 如实下发 legacy 口径（不谎报 v1）
    pre = client.get("/auth/prelogin/aud_old_seed").json()["data"]
    assert pre["verifier"] == "legacy_v3" and pre["rounds"] == KDF_LEGACY_V3_ITERATIONS
    # 新域核对子（客户端若不按 prelogin 分派复算）=拒
    sk, pk = generate_keypair()
    r = client.post("/auth/activate", json={
        "username": "aud_old_seed",
        "verifier_hex": derive_activation_verifier("Old-Seed-Pw-3", salt),
        "pubkey_hex": pk,
        "sealed_blob": _sealed_blob_js_style(pk, sk, "Old-Seed-Pw-3"),
    })
    assert r.status_code == 401 and r.json()["code"] == "activation_failed"
    # 旧口径核对子→激活成功（兼容读取），焚毁即换代
    r2 = client.post("/auth/activate", json={
        "username": "aud_old_seed",
        "verifier_hex": _legacy_v3("Old-Seed-Pw-3", salt, KDF_LEGACY_V3_ITERATIONS),
        "pubkey_hex": pk, "sealed_blob": _sealed_blob_js_style(pk, sk, "Old-Seed-Pw-3")})
    assert r2.status_code == 200, r2.text
    gen, sess = _sess_of(client)
    try:
        row = sess.query(Account).filter_by(username="aud_old_seed").one()
        assert row.status == "active" and row.init_verifier_hex is None
        assert row.init_verifier_ver is None
    finally:
        gen.close()


def test_v3_blob_login_and_lazy_reseal_upgrade(client):
    """存量 v3 密封件（拍板③③面）：注册面已停发 v3（=422 引导刷新，不入库）；
    存量 v3 账户（拍板③前入库——直播行模拟）登录可取，登录会话内
    /auth/keystore/upgrade 以同口令 v4 重封件回传→库内换 v4（无感升级）；
    非属主未登录=401；与登记公钥错配=400 不入库。"""
    from app.accounts.envelope import reseal_v4, unseal_envelope
    from app.accounts.models import Account

    sk, pk = generate_keypair()
    blob_v3 = _sealed_blob_v3_legacy(pk, sk, PASS)
    r = client.post(
        "/auth/register",
        json={
            "username": "pilot_v3up",
            "pubkey_hex": pk,
            "sealed_blob": blob_v3,
        },
    )
    assert r.status_code == 422, r.text  # 拍板③①：注册停发 v3——旧客户端引导刷新
    assert r.json()["code"] == "v3_register_rejected"
    # 存量 v3 账户（历史入库形态）以直播行模拟——登录惰性升级面保留不动
    gen, sess = _sess_of(client)
    try:
        sess.add(
            Account(
                username="pilot_v3up",
                role="pilot",
                status="pending_profile",
                pubkey_hex=pk.lower(),
                sealed_blob=blob_v3,
            )
        )
        sess.commit()
    finally:
        gen.close()
    _login(client, "pilot_v3up", sk)  # 登录（密封件解封在客户端——服务端不触 KDF）
    # 惰性重封：v3→v4 同口令（envelope.reseal_v4 与浏览器侧同构）
    ks = client.get("/auth/keystore/pilot_v3up").json()["data"]
    assert json.loads(ks["sealed_blob"])["v"] == 3
    blob_v4 = reseal_v4(ks["sealed_blob"], PASS, iterations=4096)
    assert json.loads(blob_v4)["v"] == 4 and unseal_envelope(blob_v4, PASS) == sk
    up = client.post("/auth/keystore/upgrade", json={"sealed_blob": blob_v4})
    assert up.status_code == 200, up.text
    ks2 = client.get("/auth/keystore/pilot_v3up").json()["data"]
    assert json.loads(ks2["sealed_blob"])["v"] == 4
    # 未登录=401（属主自换——匿名不可达）
    anon = TestClient(client.app)
    up_anon = anon.post("/auth/keystore/upgrade", json={"sealed_blob": blob_v4})
    assert up_anon.status_code == 401
    # 错配公钥=400（不带病入库）
    sk2, pk2 = generate_keypair()
    bad = seal_envelope_v4(sk2, pk2, PASS, iterations=4096)
    up_bad = client.post("/auth/keystore/upgrade", json={"sealed_blob": bad})
    assert up_bad.status_code == 400 and up_bad.json()["code"] == "bad_blob"
    # 库内仍为本人 v4（坏件未入库）
    gen, sess = _sess_of(client)
    try:
        row = sess.query(Account).filter_by(username="pilot_v3up").one()
        assert json.loads(row.sealed_blob)["v"] == 4
    finally:
        gen.close()
