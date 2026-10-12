"""OPAQUE 后端协议测试（⑫O-3 批——设计合同 §1/§2/§5.5/§6；负例先红后绿）。

覆盖面：
- evaluate 三态恒形（v6 在账/不存在/待激活/v4 存量）+fake-record 不可区分
  （长度恒定+伪随机唯一性——§6.1/§6.2）；
- v6 注册→OPAQUE 登录全动线（真 β/真掩码/错口令客户端败/重放拒/401）；
- 降级尝试拒（gate on 时 v4/v3 注册=422；v4 存量 pre-auth evaluate=fake 无降级 oracle）；
- keystore 硬化（§5.5——限流桶+v6=410；红线：先于任何迁移删除事务）；
- evaluate 限流桶+审计事件（Cheon 纪律——§6.6：opaque_rate_limited/opaque_invalid_point）；
- 改密 v6 重封（masking_key 同步换新——§5.6）+v4 账户改密 v4 语义保留；
- 双轨开关 FZ_OPAQUE_ENABLED=0（v4 现状回归+evaluate 503）。
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.accounts.envelope import (
    canonical_v6,
    seal_envelope_v4,
    standard_v6_envelope_len,
)
from app.accounts.models import Account
from app.accounts.opaque import opaque_enabled
from app.crypto.oprf import oprf_input_bytes, point_to_hex
from app.crypto.sm2 import generate_keypair
from app.db import get_session
from app.main import create_app
from app.ra.models import Base
from tests.opaque_client_ref import (
    ref_login_blind,
    ref_login_unseal,
    ref_seal_v6,
)

PASS = "Opaque-Pw-9x"
P_SM2 = 2**256 - 2**224 - 2**96 + 2**64 - 1


@pytest.fixture()
def oc(tmp_path, monkeypatch):
    """OPAQUE 协议测试夹具：独立临时库+缺省档（gate on）+限速桶隔离。"""
    monkeypatch.delenv("FZ_OPAQUE_ENABLED", raising=False)
    eng = create_engine(f"sqlite:///{tmp_path}/opaque_test.db")
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
        c.TestSession = TestSession
        yield c


def _sess_of(c):
    gen = c.app.dependency_overrides[get_session]()
    return gen, next(gen)


def _register_v6(c: TestClient, username: str, password: str = PASS) -> tuple[str, str]:
    """v6 注册（参考客户端材料）→201；返回 (sk_hex, pk_hex)。"""
    from app.crypto.sm2 import generate_keypair

    sk, pk = generate_keypair()
    body = ref_seal_v6(username, password, sk, pk)
    r = c.post(
        "/auth/register",
        json={"username": username, "pubkey_hex": pk, **body},
    )
    assert r.status_code == 201, r.text
    return sk, pk


def _challenge_login(c: TestClient, username: str, sk_hex: str):
    """现役挑战-应答登录（既有语义——v6 解封后与 v4 同径）。"""
    from app.crypto.sm2 import sign

    nonce = c.post(f"/auth/challenge/{username}").json()["data"]["nonce_hex"]
    return c.post(
        "/auth/login",
        json={
            "username": username,
            "nonce_hex": nonce,
            "sig_hex": sign(sk_hex, f"FZ-AUTH-LOGIN|{nonce}".encode()),
        },
    )


def _opaque_login(c: TestClient, username: str, password: str, expect_sk: str | None):
    """线协议 OPAQUE 登录：blind→evaluate→unseal→挑战-应答。返回解封 sk_hex。"""
    alpha, r_scalar = ref_login_blind(username, password)
    resp = c.post("/auth/opaque/evaluate", json={"username": username, "alpha_hex": alpha})
    assert resp.status_code == 200, resp.text
    sk_hex = ref_login_unseal(r_scalar, resp.json()["data"])
    if expect_sk is not None:
        assert sk_hex == expect_sk
    r = _challenge_login(c, username, sk_hex)
    return sk_hex, r


# ---------------------------------------------------------------------------
# ① evaluate 恒形三态+fake-record 不可区分（§6.1/§6.2）
# ---------------------------------------------------------------------------

RESPONSE_KEYS = (
    "evaluated_message",
    "masking_nonce",
    "masked_response",
    "kdf_salt_hex",
    "kdf_iter",
)
RESPONSE_STR_KEYS = tuple(k for k in RESPONSE_KEYS if k != "kdf_iter")  # 恒长断言面（kdf_iter=int）
_EXPECTED_LEN = {
    "evaluated_message": 128,
    "masking_nonce": 64,
    "kdf_salt_hex": 32,
}


def test_evaluate_constant_shape_four_states(oc):
    """四态（v6 在账/不存在/待激活/v4 存量）响应恒五键恒长（§2.1/§6.2——任何
    分形即注册状态 oracle）。"""
    from app.accounts.service import seed_institutional_account

    _register_v6(oc, "pilot_shape")
    gen, sess = _sess_of(oc)
    try:
        seed_institutional_account(sess, "aud_shape", "auditor", "Seed-Pw-1a")
        sess.add(
            Account(
                username="pilot_v4legacy",
                role="pilot",
                status="active",
                pubkey_hex="11" * 64,
                sealed_blob=seal_envelope_v4("22" * 32, "11" * 64, "V4-Legacy-1"),
            )
        )
        sess.commit()
    finally:
        gen.close()

    shapes = {}
    for username in ("pilot_shape", "ghost_user", "aud_shape", "pilot_v4legacy"):
        alpha, _ = ref_login_blind(username, "Whatever-1a")
        r = oc.post("/auth/opaque/evaluate", json={"username": username, "alpha_hex": alpha})
        assert r.status_code == 200, (username, r.text)
        data = r.json()["data"]
        assert tuple(data.keys()) == RESPONSE_KEYS
        shapes[username] = data
    ref = shapes["ghost_user"]
    for username, data in shapes.items():
        assert data.keys() == ref.keys(), username
        for k in RESPONSE_KEYS:
            if k == "kdf_iter":
                assert isinstance(data[k], int) and data[k] >= 1
            else:
                assert len(data[k]) == len(ref[k]), (username, k)
        for k, ln in _EXPECTED_LEN.items():
            assert len(data[k]) == ln, (username, k)


def test_fake_record_indistinguishable_statistics(oc, monkeypatch):
    """§5.4/§6.1 枚举不可区分：已注册 vs 不存在——五键长度全等+masked_response
    伪随机唯一性（200 样本两态混排零重合；限流桶放大采样面——桶行为专测见下）。"""
    from app.accounts.service import evaluate_limiter

    monkeypatch.setattr(evaluate_limiter, "_max", 100_000)
    _register_v6(oc, "pilot_enum")
    seen = set()
    lens = None
    for i in range(200):
        username = "pilot_enum" if i % 2 == 0 else f"ghost_{i}"
        alpha, _ = ref_login_blind(username, "Whatever-1a")
        r = oc.post("/auth/opaque/evaluate", json={"username": username, "alpha_hex": alpha})
        assert r.status_code == 200
        data = r.json()["data"]
        cur = tuple(len(data[k]) for k in RESPONSE_STR_KEYS)
        lens = cur if lens is None else lens
        assert cur == lens, f"长度漂移@{i}"
        assert data["masked_response"] not in seen, "masked_response 伪随机性破坏（重合）"
        seen.add(data["masked_response"])


def test_fake_envelope_zero_slot_length_anchor():
    """§6.1 fake 形态：零 envelope 槽长度=canonical v6 信封定长（RFC 9380 §6.3.2.2
    原文形态——定长全零+随机 masking_key）。"""
    assert standard_v6_envelope_len() == len(
        canonical_v6("0" * 128, "0" * 24, "0" * 24, "0" * 64, "0" * 32)
    )


# ---------------------------------------------------------------------------
# ② v6 注册→OPAQUE 登录全动线+负例
# ---------------------------------------------------------------------------


def test_v6_register_store_and_opaque_login(oc):
    """注册落账（OPRF 记录四列+规范化 blob）→线协议登录 200（AKE=现役挑战-应答
    零改动——方案 B）。"""
    sk, pk = _register_v6(oc, "pilot_login")
    gen, sess = _sess_of(oc)
    try:
        row = sess.query(Account).filter_by(username="pilot_login").one()
        assert row.opaque_masking_key_hex and len(row.opaque_masking_key_hex) == 64
        assert row.opaque_kdf_salt_hex and len(row.opaque_kdf_salt_hex) == 32
        assert row.opaque_kdf_iter == 600_000
        assert row.opaque_key_id and len(row.opaque_key_id) == 8
        # 规范化存储（compact 再序列化恒等=canonical 形态在库——定长锚的前提）
        assert json.dumps(json.loads(row.sealed_blob), separators=(",", ":")) == row.sealed_blob
        assert json.loads(row.sealed_blob)["enc"]["kdf"] == "opaque-rwd-v1"
    finally:
        gen.close()
    sk_hex, r = _opaque_login(oc, "pilot_login", PASS, sk)
    assert r.status_code == 200, r.text
    assert r.json()["data"]["username"] == "pilot_login"


def test_v6_wrong_password_client_fail_and_401(oc):
    """错口令：解掩码/GCM 客户端败（服务端 evaluate 照常 200——零新失败 oracle，
    判词源=客户端 server_pub 前缀/GCM）；垃圾签名登录=401 auth_failed（现役
    AKE 语义）。"""
    from app.crypto.sm2 import sign

    _register_v6(oc, "pilot_wrongpw")
    alpha, r_scalar = ref_login_blind("pilot_wrongpw", "Wrong-Pw-99")
    resp = oc.post("/auth/opaque/evaluate", json={"username": "pilot_wrongpw", "alpha_hex": alpha})
    assert resp.status_code == 200  # 服务端零口令知识——无错口令差异面
    with pytest.raises(ValueError):
        ref_login_unseal(r_scalar, resp.json()["data"])
    nonce = oc.post("/auth/challenge/pilot_wrongpw").json()["data"]["nonce_hex"]
    r = oc.post(
        "/auth/login",
        json={
            "username": "pilot_wrongpw",
            "nonce_hex": nonce,
            "sig_hex": sign("11" * 32, f"FZ-AUTH-LOGIN|{nonce}".encode()),
        },
    )
    assert r.status_code == 401 and r.json()["code"] == "auth_failed"


def test_v6_challenge_replay_rejected(oc):
    """重放拒：同一挑战 nonce 二次消费=401 bad_challenge（现役语义零改动）。"""
    from app.crypto.sm2 import sign

    sk, _pk = _register_v6(oc, "pilot_replay")
    sk_hex, r = _opaque_login(oc, "pilot_replay", PASS, sk)
    assert r.status_code == 200
    nonce = oc.post("/auth/challenge/pilot_replay").json()["data"]["nonce_hex"]
    sig = sign(sk_hex, f"FZ-AUTH-LOGIN|{nonce}".encode())
    first = oc.post(
        "/auth/login", json={"username": "pilot_replay", "nonce_hex": nonce, "sig_hex": sig}
    )
    second = oc.post(
        "/auth/login", json={"username": "pilot_replay", "nonce_hex": nonce, "sig_hex": sig}
    )
    assert first.status_code == 200
    assert second.status_code == 401 and second.json()["code"] == "bad_challenge"


def test_register_downgrade_attempts_rejected(oc):
    """降级尝试拒（gate on）：v4 blob=422 引导刷新；v6 blob 缺掩码钥=422；
    v3 blob 维持 v3 停发=422。"""
    from app.crypto.sm2 import generate_keypair

    sk, pk = generate_keypair()
    r4 = oc.post(
        "/auth/register",
        json={
            "username": "pilot_dg4",
            "pubkey_hex": pk,
            "sealed_blob": seal_envelope_v4(sk, pk, PASS),
        },
    )
    assert r4.status_code == 422 and r4.json()["code"] == "v6_register_required"
    body = ref_seal_v6("pilot_dg6", PASS, sk, pk)
    r6 = oc.post(
        "/auth/register",
        json={"username": "pilot_dg6", "pubkey_hex": pk, "sealed_blob": body["sealed_blob"]},
    )
    assert r6.status_code == 422 and r6.json()["code"] == "bad_masking_key"
    v3_blob = json.dumps(
        {
            "v": 3,
            "pk": pk,
            "enc": {"salt": "00" * 16, "nonce": "00" * 12, "ct": "00" * 32, "tag": "00" * 16},
        }
    )
    r3 = oc.post(
        "/auth/register",
        json={"username": "pilot_dg3", "pubkey_hex": pk, "sealed_blob": v3_blob},
    )
    assert r3.status_code == 422 and r3.json()["code"] == "v3_register_rejected"


def test_v4_account_preauth_evaluate_is_fake_no_downgrade_oracle(oc):
    """降级面：v4 存量 pre-auth evaluate=fake（无 OPAQUE 登录通道——响应与
    不存在账户不可区分）；v4 照常登录+keystore 照常（200）。"""
    gen, sess = _sess_of(oc)
    try:
        sess.add(
            Account(
                username="pilot_v4keep",
                role="pilot",
                status="active",
                pubkey_hex="33" * 64,
                sealed_blob=seal_envelope_v4("44" * 32, "33" * 64, "V4-Keep-Pw1"),
            )
        )
        sess.commit()
    finally:
        gen.close()
    alpha_v4, _ = ref_login_blind("pilot_v4keep", "x")
    alpha_ghost, _ = ref_login_blind("ghost_none", "x")
    r4 = oc.post("/auth/opaque/evaluate", json={"username": "pilot_v4keep", "alpha_hex": alpha_v4})
    rg = oc.post("/auth/opaque/evaluate", json={"username": "ghost_none", "alpha_hex": alpha_ghost})
    assert r4.status_code == rg.status_code == 200
    d4, dg = r4.json()["data"], rg.json()["data"]
    assert tuple(len(d4[k]) for k in RESPONSE_STR_KEYS) == tuple(
        len(dg[k]) for k in RESPONSE_STR_KEYS
    )


# ---------------------------------------------------------------------------
# ③ keystore 硬化（§5.5——红线：先于任何迁移删除事务）
# ---------------------------------------------------------------------------


def test_keystore_v6_410_and_v4_200(oc):
    """v6 账户 keystore=410（掩码通道取代——独立 keystore 端点面对 v6 消灭）；
    v4 存量照常 200（鸡-蛋过渡面）；不存在=404。"""
    _register_v6(oc, "pilot_ks6")
    gen, sess = _sess_of(oc)
    try:
        sess.add(
            Account(
                username="pilot_ks4",
                role="pilot",
                status="active",
                pubkey_hex="55" * 64,
                sealed_blob=seal_envelope_v4("66" * 32, "55" * 64, "V4-Ks-Pw-1"),
            )
        )
        sess.commit()
    finally:
        gen.close()
    r6 = oc.get("/auth/keystore/pilot_ks6")
    assert r6.status_code == 410 and r6.json()["code"] == "opaque_migrated"
    r4 = oc.get("/auth/keystore/pilot_ks4")
    assert r4.status_code == 200 and json.loads(r4.json()["data"]["sealed_blob"])["v"] == 4
    rg = oc.get("/auth/keystore/ghost_none")
    assert rg.status_code == 404


def test_keystore_rate_limited(oc):
    """限流桶（keystore|ip|username，10 发/300s 同族桶——§5.5-1 先行件）。"""
    _register_v6(oc, "pilot_ksrl")
    codes = [oc.get("/auth/keystore/pilot_ksrl").status_code for _ in range(11)]
    assert codes[:10].count(410) == 10  # v6=410（限流先行计数）
    assert codes[10] == 429 and codes[10] == oc.get("/auth/keystore/pilot_ksrl").status_code


# ---------------------------------------------------------------------------
# ⑤ evaluate 限流桶+审计事件（Cheon 纪律——§6.6）
# ---------------------------------------------------------------------------


def test_evaluate_rate_limit_and_audit(oc):
    """10 发/300s 桶：第 11 发=429+台账 opaque_rate_limited（Cheon 配额耗尽留痕）。"""
    from app.accounts.models import AccountAdminLog

    _register_v6(oc, "pilot_rl")
    codes = []
    for _ in range(11):
        alpha, _ = ref_login_blind("pilot_rl", PASS)
        codes.append(
            oc.post(
                "/auth/opaque/evaluate", json={"username": "pilot_rl", "alpha_hex": alpha}
            ).status_code
        )
    assert codes[:10] == [200] * 10
    assert codes[10] == 429
    gen, sess = _sess_of(oc)
    try:
        rows = (
            sess.query(AccountAdminLog)
            .filter_by(username="pilot_rl", action="opaque_rate_limited")
            .all()
        )
        assert len(rows) == 1
    finally:
        gen.close()


def test_evaluate_invalid_point_rejected_and_audited(oc):
    """O-1 前置：离曲线/坐标域外（x=p 恰在 128hex 内——mod p 方程同判合法）=
    400 opaque_invalid_point+台账一行（主动攻击指示器逐笔留痕——§6.6）；
    长度/字符违规=422（pydantic 层结构化拒绝族——两层皆拒零崩溃）。"""
    from app.accounts.models import AccountAdminLog
    from app.crypto.oprf import hash_to_curve, parse_point_element, point_to_hex

    _register_v6(oc, "pilot_o1")
    good = point_to_hex(*hash_to_curve(oprf_input_bytes("o1", "x")))
    x_g, y_g = parse_point_element(good)
    bad_400 = [
        point_to_hex(x_g, (y_g + 1) % P_SM2),  # 离曲线
        point_to_hex(P_SM2, y_g),  # x≥p（域外——mod p 方程同判合法，128hex 内）
        "zz" * 64,  # 非字符集（合法长度——O-1 层拒）
    ]
    for bad in bad_400:
        r = oc.post("/auth/opaque/evaluate", json={"username": "pilot_o1", "alpha_hex": bad})
        assert r.status_code == 400 and r.json()["code"] == "opaque_invalid_point", bad
    for bad in ("1" * 127, "1" * 129):  # 长度违规——pydantic 结构化拒绝
        r = oc.post("/auth/opaque/evaluate", json={"username": "pilot_o1", "alpha_hex": bad})
        assert r.status_code == 422, bad
    gen, sess = _sess_of(oc)
    try:
        rows = (
            sess.query(AccountAdminLog)
            .filter_by(username="pilot_o1", action="opaque_invalid_point")
            .all()
        )
        assert len(rows) == 3  # 离曲线/域外/非字符集各一笔（422 层不入 O-1 台账）
    finally:
        gen.close()


# ---------------------------------------------------------------------------
# 改密 v6 重封（§5.6）+v4 语义保留
# ---------------------------------------------------------------------------


def test_password_change_v6_reseals_masking_key(oc):
    """v6 改密：v6' blob+新 masking_key 原子换新；盐/迭代不轮换（rwd 已随口令
    换根）；旧口令登录败/新口令登录 200（须持属主会话——改密面 401 门）。"""
    sk, pk = _register_v6(oc, "pilot_pc6")
    _challenge_login(oc, "pilot_pc6", sk)
    gen, sess = _sess_of(oc)
    try:
        row = sess.query(Account).filter_by(username="pilot_pc6").one()
        old_salt, old_iter = row.opaque_kdf_salt_hex, row.opaque_kdf_iter
    finally:
        gen.close()
    body = ref_seal_v6("pilot_pc6", "New-Pw-6ab", sk, pk, salt_hex=old_salt, iterations=old_iter)
    r = oc.post(
        "/auth/password/change",
        json={"sealed_blob": body["sealed_blob"], "masking_key_hex": body["masking_key_hex"]},
    )
    assert r.status_code == 200, r.text
    gen, sess = _sess_of(oc)
    try:
        row = sess.query(Account).filter_by(username="pilot_pc6").one()
        assert json.loads(row.sealed_blob)["v"] == 6
        assert row.opaque_kdf_salt_hex == old_salt  # 盐不轮换
        assert row.opaque_masking_key_hex == body["masking_key_hex"]
    finally:
        gen.close()
    with pytest.raises(ValueError):
        _opaque_login(oc, "pilot_pc6", PASS, None)  # 旧口令=解掩码客户端败（零服务端差异）
    _, r_new = _opaque_login(oc, "pilot_pc6", "New-Pw-6ab", sk)
    assert r_new.status_code == 200


def test_password_change_v6_without_masking_key_rejected(oc):
    """v6 账户改密缺 masking_key=422（防旧掩码钥+新 rwd 信封的静默错配——
    永不可解的半吊子改密面）。"""
    sk, pk = _register_v6(oc, "pilot_pcm")
    _challenge_login(oc, "pilot_pcm", sk)
    body = ref_seal_v6("pilot_pcm", "New-Pw-6cd", sk, pk)
    r = oc.post("/auth/password/change", json={"sealed_blob": body["sealed_blob"]})
    assert r.status_code == 422 and r.json()["code"] == "bad_masking_key"


def test_password_change_v4_account_keeps_v4_semantics(oc):
    """v4 存量（无 OPAQUE 记录）改密=v4→v4 现役语义零破坏（登录照常）。"""
    from app.crypto.sm2 import generate_keypair

    sk, pk = generate_keypair()
    gen, sess = _sess_of(oc)
    try:
        sess.add(
            Account(
                username="pilot_pcv4",
                role="pilot",
                status="active",
                pubkey_hex=pk,
                sealed_blob=seal_envelope_v4(sk, pk, "V4-Old-Pw1"),
            )
        )
        sess.commit()
    finally:
        gen.close()
    _challenge_login(oc, "pilot_pcv4", sk)
    r = oc.post(
        "/auth/password/change",
        json={"sealed_blob": seal_envelope_v4(sk, pk, "V4-New-Pw2")},
    )
    assert r.status_code == 200, r.text
    # 错配公钥=400（不带病入库——现役语义保留；sk↔pk 绑定服务端零知识不可检
    # ——错配落在信封 pk 槽与登记公钥不一致处）
    sk2, pk2 = generate_keypair()
    r_bad = oc.post(
        "/auth/password/change",
        json={"sealed_blob": seal_envelope_v4(sk2, pk2, "V4-New-Pw2")},
    )
    assert r_bad.status_code == 400 and r_bad.json()["code"] == "bad_blob"
    gen, sess = _sess_of(oc)
    try:
        row = sess.query(Account).filter_by(username="pilot_pcv4").one()
        assert json.loads(row.sealed_blob)["v"] == 4
    finally:
        gen.close()


# ---------------------------------------------------------------------------
# 双轨开关（§5.1——FZ_OPAQUE_ENABLED=0=v4 现状回归）
# ---------------------------------------------------------------------------


def test_opaque_disabled_switch(oc, monkeypatch):
    """off 态：v4 注册照常 201/v6 注册=422/evaluate=503 关闭态。"""
    from app.crypto.sm2 import generate_keypair

    monkeypatch.setenv("FZ_OPAQUE_ENABLED", "0")
    assert not opaque_enabled()
    sk, pk = generate_keypair()
    r4 = oc.post(
        "/auth/register",
        json={
            "username": "pilot_off4",
            "pubkey_hex": pk,
            "sealed_blob": seal_envelope_v4(sk, pk, PASS),
        },
    )
    assert r4.status_code == 201, r4.text
    body = ref_seal_v6("pilot_off6", PASS, sk, pk)
    r6 = oc.post(
        "/auth/register",
        json={"username": "pilot_off6", "pubkey_hex": pk, **body},
    )
    assert r6.status_code == 422 and r6.json()["code"] == "opaque_disabled"
    alpha, _ = ref_login_blind("pilot_off4", PASS)
    re_ = oc.post("/auth/opaque/evaluate", json={"username": "pilot_off4", "alpha_hex": alpha})
    assert re_.status_code == 503 and re_.json()["code"] == "opaque_disabled"


# ---------------------------------------------------------------------------
# 待激活态真实 β（§6.1-b）+激活落账
# ---------------------------------------------------------------------------


def test_pending_activation_real_beta_and_v6_activation(oc):
    """待激活账户 evaluate=真实 β（激活序需封 v6）；/auth/activate 以 v6 材料
    落账（记录四列齐）→OPAQUE 登录 200。"""
    from app.accounts.kdf import derive_activation_verifier
    from app.accounts.service import seed_institutional_account

    gen, sess = _sess_of(oc)
    try:
        seed_institutional_account(sess, "aud_act6", "auditor", "Seed-Pw-7a")
    finally:
        gen.close()
    alpha, r_scalar = ref_login_blind("aud_act6", "Seed-Pw-7a")
    r = oc.post("/auth/opaque/evaluate", json={"username": "aud_act6", "alpha_hex": alpha})
    assert r.status_code == 200
    # 真实 β 的可核对性：去盲 Y == [k]·H2C(oprf_input)（§6.1-b 语义锚——注意
    # β 本身是盲化域的 [k]·α，直算对照须经去盲；[k]·[r]·P=[kr]P≠[k]·P）
    from app.crypto.oprf import (
        evaluate as direct_evaluate,
    )
    from app.crypto.oprf import (
        oprf_output_from_y,
        unblind,
    )
    from app.kms import oprf_key

    y = unblind(r_scalar, r.json()["data"]["evaluated_message"])
    expect_y = direct_evaluate(oprf_input_bytes("aud_act6", "Seed-Pw-7a"), oprf_key())
    assert y == expect_y
    assert oprf_output_from_y(y) == oprf_output_from_y(expect_y)
    # 激活：核对子+v6 材料三件
    gen, sess = _sess_of(oc)
    try:
        row = sess.query(Account).filter_by(username="aud_act6").one()
        salt = row.init_kdf_salt_hex
    finally:
        gen.close()
    verifier = derive_activation_verifier("Seed-Pw-7a", salt)
    from app.crypto.sm2 import generate_keypair

    sk, pk = generate_keypair()
    body = ref_seal_v6("aud_act6", "Seed-Pw-7a", sk, pk)
    r_act = oc.post(
        "/auth/activate",
        json={
            "username": "aud_act6",
            "verifier_hex": verifier,
            "pubkey_hex": pk,
            **body,
        },
    )
    assert r_act.status_code == 200, r_act.text
    gen, sess = _sess_of(oc)
    try:
        row = sess.query(Account).filter_by(username="aud_act6").one()
        assert row.opaque_masking_key_hex and row.opaque_key_id
    finally:
        gen.close()
    sk_hex, r_login = _opaque_login(oc, "aud_act6", "Seed-Pw-7a", sk)
    assert r_login.status_code == 200


# ---------------------------------------------------------------------------
# ⑫O-4 存量惰性重封迁移（设计 §5——删除事务/CUTOFF/回滚窗/台账）
# ---------------------------------------------------------------------------


def _seed_v4(c: TestClient, username: str, password: str = "V4-Mig-Pw-1"):
    """v4 存量账户播种（直播行模拟——真实钥对；登录/keystore 全可用）。"""
    from app.accounts.envelope import seal_envelope_v4 as seal4
    from app.crypto.sm2 import generate_keypair

    sk, pk = generate_keypair()
    gen, sess = _sess_of(c)
    try:
        sess.add(
            Account(
                username=username,
                role="pilot",
                status="active",
                pubkey_hex=pk,
                sealed_blob=seal4(sk, pk, password, iterations=4096),
            )
        )
        sess.commit()
    finally:
        gen.close()
    return sk, pk


def test_migrate_v4_to_v6_full_flow(oc):
    """v4 登录（现役路径照常）→会话内 evaluate=真实 β（§6.1-c）→同口令注册序
    →migrate 原子换新（五件落账+台账+钥指纹改绑）→keystore=410/OPAQUE 登录
    200（删除事务提交=v4 路径永久失效——§5.4）。"""
    from app.accounts.models import AccountAdminLog
    from app.crypto.oprf import hash_to_curve, mul_blinded, oprf_input_bytes, unblind
    from app.kms import oprf_key

    sk, pk = _seed_v4(oc, "pilot_mig", "V4-Mig-Pw-1")
    # v4 现役登录（keystore 200→解封→挑战-应答）
    ks = oc.get("/auth/keystore/pilot_mig")
    assert ks.status_code == 200 and json.loads(ks.json()["data"]["sealed_blob"])["v"] == 4
    _challenge_login(oc, "pilot_mig", sk)
    # 会话内 evaluate：真实 β（去盲比对锚——[k]·[r]·P 经去盲=[k]·P）
    alpha, r_scalar = ref_login_blind("pilot_mig", "V4-Mig-Pw-1")
    ev = oc.post("/auth/opaque/evaluate", json={"username": "pilot_mig", "alpha_hex": alpha})
    assert ev.status_code == 200
    y = unblind(r_scalar, ev.json()["data"]["evaluated_message"])
    expect_y = mul_blinded(
        int(oprf_key(), 16),
        point_to_hex(*hash_to_curve(oprf_input_bytes("pilot_mig", "V4-Mig-Pw-1"))),
    )
    assert y == expect_y
    # 同口令注册序 → migrate 回传
    body = ref_seal_v6("pilot_mig", "V4-Mig-Pw-1", sk, pk)
    rm = oc.post(
        "/auth/opaque/migrate",
        json={
            "sealed_blob": body["sealed_blob"],
            "masking_key_hex": body["masking_key_hex"],
            "kdf_salt_hex": body["kdf_salt_hex"],
            "kdf_iter": body["kdf_iter"],
        },
    )
    assert rm.status_code == 200, rm.text
    gen, sess = _sess_of(oc)
    try:
        row = sess.query(Account).filter_by(username="pilot_mig").one()
        assert json.loads(row.sealed_blob)["v"] == 6
        assert row.opaque_masking_key_hex == body["masking_key_hex"]
        assert row.opaque_kdf_salt_hex == body["kdf_salt_hex"] and row.opaque_kdf_iter
        assert row.opaque_key_id and len(row.opaque_key_id) == 8
        logs = (
            sess.query(AccountAdminLog)
            .filter_by(username="pilot_mig", action="opaque_migrate")
            .all()
        )
        assert len(logs) == 1
    finally:
        gen.close()
    # 删除事务提交后：keystore=410（v4 路径永久失效）+OPAQUE 登录 200
    assert oc.get("/auth/keystore/pilot_mig").status_code == 410
    _, r_login = _opaque_login(oc, "pilot_mig", "V4-Mig-Pw-1", sk)
    assert r_login.status_code == 200


def test_migrate_preconditions(oc, monkeypatch):
    """负例族：未登录 401/已迁移 409（幂等回传人话）/v3 形态 409（不越形态）/
    错配公钥 400/缺掩码钥 422/gate off 503。"""
    from app.crypto.sm2 import generate_keypair

    _register_v6(oc, "pilot_mig6")
    sk3, pk3 = generate_keypair()
    gen, sess = _sess_of(oc)
    try:
        sess.add(
            Account(
                username="pilot_mig3",
                role="pilot",
                status="active",
                pubkey_hex=pk3,
                sealed_blob=json.dumps(
                    {
                        "v": 3,
                        "pk": pk3,
                        "enc": {
                            "salt": "00" * 16,
                            "nonce": "00" * 12,
                            "ct": "00" * 32,
                            "tag": "00" * 16,
                        },
                    }
                ),
            )
        )
        sess.commit()
    finally:
        gen.close()
    sk4, pk4 = _seed_v4(oc, "pilot_mig4")
    _challenge_login(oc, "pilot_mig4", sk4)

    def _mig(body):
        return oc.post(
            "/auth/opaque/migrate",
            json={
                "sealed_blob": body["sealed_blob"],
                "masking_key_hex": body.get("masking_key_hex"),
                "kdf_salt_hex": body["kdf_salt_hex"],
                "kdf_iter": body["kdf_iter"],
            },
        )

    # 未登录=401
    anon = TestClient(oc.app)
    body = ref_seal_v6("pilot_mig4", "V4-Mig-Pw-1", sk4, pk4)
    r_anon = anon.post(
        "/auth/opaque/migrate",
        json={
            "sealed_blob": body["sealed_blob"],
            "masking_key_hex": body["masking_key_hex"],
            "kdf_salt_hex": body["kdf_salt_hex"],
            "kdf_iter": body["kdf_iter"],
        },
    )
    assert r_anon.status_code == 401
    # 属主正常迁移=200；重复迁移=409（幂等回传人话）
    rm4 = _mig(body)
    assert rm4.status_code == 200, rm4.text
    r_dup = _mig(body)
    assert r_dup.status_code == 409 and r_dup.json()["code"] == "opaque_migrated"
    # v3 形态=409（迁移不越形态——先走 v3→v4 惰性升级）
    _challenge_login(oc, "pilot_mig3", sk3)
    body3 = ref_seal_v6("pilot_mig3", "Whatever-1a", sk3, pk3)
    r3 = _mig(body3)
    assert r3.status_code == 409 and r3.json()["code"] == "bad_state"
    # 错配公钥=400（blob pk 槽 ≠ 登记公钥）
    sk_x, pk_x = generate_keypair()
    body_x = ref_seal_v6("pilot_mig4", "V4-Mig-Pw-1", sk_x, pk_x)
    r_x = oc.post(
        "/auth/opaque/migrate",
        json={
            "sealed_blob": body_x["sealed_blob"],
            "masking_key_hex": body_x["masking_key_hex"],
            "kdf_salt_hex": body_x["kdf_salt_hex"],
            "kdf_iter": body_x["kdf_iter"],
        },
    )
    # mig4 已迁移=409 先命中——换未迁移账户验证错配 400
    assert r_x.status_code == 409
    sk5, pk5 = _seed_v4(oc, "pilot_mig5")
    _challenge_login(oc, "pilot_mig5", sk5)
    body_x5 = ref_seal_v6("pilot_mig5", "V4-Mig-Pw-1", sk_x, pk_x)
    r_x5 = oc.post(
        "/auth/opaque/migrate",
        json={
            "sealed_blob": body_x5["sealed_blob"],
            "masking_key_hex": body_x5["masking_key_hex"],
            "kdf_salt_hex": body_x5["kdf_salt_hex"],
            "kdf_iter": body_x5["kdf_iter"],
        },
    )
    assert r_x5.status_code == 400 and r_x5.json()["code"] == "bad_blob"
    # 缺掩码钥=422（未迁移账户直达——防旧掩码钥+新 rwd 信封错配）
    body5 = ref_seal_v6("pilot_mig5", "V4-Mig-Pw-1", sk5, pk5)
    r_m = oc.post(
        "/auth/opaque/migrate",
        json={
            "sealed_blob": body5["sealed_blob"],
            "kdf_salt_hex": body5["kdf_salt_hex"],
            "kdf_iter": body5["kdf_iter"],
        },
    )
    assert r_m.status_code == 422, f"resp={r_m.text}"
    assert r_m.json()["code"] == "bad_masking_key", f"resp={r_m.text}"
    # gate off=503
    monkeypatch.setenv("FZ_OPAQUE_ENABLED", "0")
    body5b = ref_seal_v6("pilot_mig5", "V4-Mig-Pw-1", sk5, pk5)
    r_off = oc.post(
        "/auth/opaque/migrate",
        json={
            "sealed_blob": body5b["sealed_blob"],
            "masking_key_hex": body5b["masking_key_hex"],
            "kdf_salt_hex": body5b["kdf_salt_hex"],
            "kdf_iter": body5b["kdf_iter"],
        },
    )
    assert r_off.status_code == 503 and r_off.json()["code"] == "opaque_disabled"


def test_migrate_rollback_window_semantics(oc):
    """回滚窗（§5.4）：换新失败（错配 blob）⟹零部分状态（行原样 v4+四列 NULL）
    →同会话重试合法件=成功（可重试语义）；成功后回滚不可达（v4 永久失效）。"""
    sk, pk = _seed_v4(oc, "pilot_rb")
    _challenge_login(oc, "pilot_rb", sk)
    sk_x, pk_x = generate_keypair()
    body_x = ref_seal_v6("pilot_rb", "V4-Mig-Pw-1", sk_x, pk_x)  # 错配=失败件
    r_bad = oc.post(
        "/auth/opaque/migrate",
        json={
            "sealed_blob": body_x["sealed_blob"],
            "masking_key_hex": body_x["masking_key_hex"],
            "kdf_salt_hex": body_x["kdf_salt_hex"],
            "kdf_iter": body_x["kdf_iter"],
        },
    )
    assert r_bad.status_code == 400
    gen, sess = _sess_of(oc)
    try:
        row = sess.query(Account).filter_by(username="pilot_rb").one()
        assert json.loads(row.sealed_blob)["v"] == 4  # 零部分状态（仍 v4）
        assert row.opaque_masking_key_hex is None  # 四列未动（可重试）
    finally:
        gen.close()
    body = ref_seal_v6("pilot_rb", "V4-Mig-Pw-1", sk, pk)
    r_ok = oc.post(
        "/auth/opaque/migrate",
        json={
            "sealed_blob": body["sealed_blob"],
            "masking_key_hex": body["masking_key_hex"],
            "kdf_salt_hex": body["kdf_salt_hex"],
            "kdf_iter": body["kdf_iter"],
        },
    )
    assert r_ok.status_code == 200  # 重试成功（回滚窗内双轨→收敛）


def test_v4_cutoff_403_and_nonce_unburned(oc, monkeypatch):
    """截止后旧信封拒（403 v4_cutoff——挑战消费前裁决不烧 nonce）；撤截止后
    同一 nonce 可登；v6 账户同截止期不受影响。"""
    import time as _t

    from app.crypto.sm2 import sign

    sk4, _pk4 = _seed_v4(oc, "pilot_cut4b")
    _register_v6(oc, "pilot_cut6")
    monkeypatch.setenv("FZ_OPAQUE_CUTOFF_TS", str(int(_t.time()) - 10))
    nonce = oc.post("/auth/challenge/pilot_cut4b").json()["data"]["nonce_hex"]
    r = oc.post(
        "/auth/login",
        json={
            "username": "pilot_cut4b",
            "nonce_hex": nonce,
            "sig_hex": sign(sk4, f"FZ-AUTH-LOGIN|{nonce}".encode()),
        },
    )
    assert r.status_code == 403 and r.json()["code"] == "v4_cutoff"
    # v6 账户同截止期照常登录（截止只打 v4 形态）
    _, r6 = _opaque_login(oc, "pilot_cut6", PASS, None)
    assert r6.status_code == 200
    # 撤截止→同一 nonce/签名可登（403 发生在消费前——不烧挑战）
    monkeypatch.delenv("FZ_OPAQUE_CUTOFF_TS", raising=False)
    r_again = oc.post(
        "/auth/login",
        json={
            "username": "pilot_cut4b",
            "nonce_hex": nonce,
            "sig_hex": sign(sk4, f"FZ-AUTH-LOGIN|{nonce}".encode()),
        },
    )
    assert r_again.status_code == 200, r_again.text


def test_v4_cutoff_malformed_env_fail_visible(monkeypatch):
    """FZ_OPAQUE_CUTOFF_TS 非整数/负数=显式抛错（fail-visible——v3 同款）。"""
    from app.accounts.service import opaque_cutoff_ts

    monkeypatch.setenv("FZ_OPAQUE_CUTOFF_TS", "not-a-number")
    with pytest.raises(ValueError, match="FZ_OPAQUE_CUTOFF_TS"):
        opaque_cutoff_ts()
    monkeypatch.setenv("FZ_OPAQUE_CUTOFF_TS", "-5")
    with pytest.raises(ValueError, match="FZ_OPAQUE_CUTOFF_TS"):
        opaque_cutoff_ts()
    monkeypatch.delenv("FZ_OPAQUE_CUTOFF_TS", raising=False)
    assert opaque_cutoff_ts() == 0


def test_v4_stock_report_production_scan(tmp_path, monkeypatch):
    """production 扫库告警（§5.2）：存量 v4>0=告警文案（数量+掩码+指引）；
    存量清零=None；demo 档恒 None。"""
    from app.accounts.service import scan_v4_envelope_accounts, v4_envelope_stock_report

    eng = create_engine(f"sqlite:///{tmp_path}/v4_scan.db")
    Base.metadata.create_all(eng)
    TS = sessionmaker(bind=eng, expire_on_commit=False)
    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    monkeypatch.setenv("FZ_DB_URL", f"sqlite:///{tmp_path}/v4_scan.db")
    s = TS()
    try:
        assert v4_envelope_stock_report(s) is None  # 零存量=静默
        sk, pk = generate_keypair()
        s.add(
            Account(
                username="pilot_scan4",
                role="pilot",
                status="active",
                pubkey_hex=pk,
                sealed_blob=seal_envelope_v4(sk, pk, "Scan-Pw-12"),
            )
        )
        s.commit()
        rep = v4_envelope_stock_report(s)
        assert rep and "1 个" in rep and "FZ_OPAQUE_CUTOFF_TS" in rep and "惰性迁移" in rep
        assert len(scan_v4_envelope_accounts(s)) == 1
    finally:
        s.close()
    # demo 档恒 None
    monkeypatch.delenv("FZ_DEPLOYMENT", raising=False)
    s2 = TS()
    try:
        assert v4_envelope_stock_report(s2) is None
    finally:
        s2.close()


def test_seed_accounts_full_flow_live_server(oc):
    """种子账户（auditor123/admin123 固定演示口令）登录全动线实弹：真 HTTP
    服务器（uvicorn 线程）+script_auth.script_login——激活→稳态 OPAQUE 登录
    （v6 keystore 410 分支）→挑战-应答 200；演示档体验零变化（口令/动线不变）。"""
    import threading
    import time as _t

    import uvicorn

    from app.accounts.service import seed_institutional_account
    from scripts.script_auth import script_login

    gen, sess = _sess_of(oc)
    try:
        seed_institutional_account(sess, "auditor_e2e", "auditor", "auditor123")
        seed_institutional_account(sess, "admin_e2e", "admin", "admin123")
    finally:
        gen.close()
    app = oc.app
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = _t.time() + 15
    base = None
    while _t.time() < deadline:
        if server.started:
            base = f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
            break
        _t.sleep(0.05)
    assert base, "uvicorn 未启动"
    try:
        # 首登激活动线（种子→核对子激活→挑战登录）——script_login 全自动
        s_aud = script_login(base, "auditor_e2e", "auditor123")
        me = s_aud.get(f"{base}/auth/whoami", timeout=10)
        assert me.status_code == 200 and me.json()["data"]["role"] == "auditor"
        s_adm = script_login(base, "admin_e2e", "admin123")
        me2 = s_adm.get(f"{base}/auth/whoami", timeout=10)
        assert me2.status_code == 200 and me2.json()["data"]["role"] == "admin"
        # 稳态再登录（v6 账户 keystore=410 → script_auth 走 OPAQUE 掩码通道分支）
        s_aud2 = script_login(base, "auditor_e2e", "auditor123")
        me3 = s_aud2.get(f"{base}/auth/whoami", timeout=10)
        assert me3.status_code == 200
        # 错口令=诚实失败（稳态分支解掩码 ValueError——script_login 诚实透传）
        try:
            script_login(base, "auditor_e2e", "wrong-password-1")
            raise AssertionError("错口令必须失败")
        except (RuntimeError, ValueError):
            pass
    finally:
        server.should_exit = True
        th.join(timeout=5)
