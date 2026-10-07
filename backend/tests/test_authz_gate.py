"""B4-T1/T2 测试：政策引擎+受理门控序（四步廉价检查+负例矩阵）。

覆盖：
- 政策表查表（微/轻两档条例数值+未开放类 fail-closed+paramsHash 稳定性）
- 门控序正例（诚实申请入队+回执码 128bit）
- 门控序负例：坏会话钥/坏子凭证签名/已用 nonce/子凭证重复使用/stale rev_root
- 匿名红线：applications/receipts 表列零身份断言（B4 验收门）
"""

from __future__ import annotations

import secrets
import time as _time_mod

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz import policy, service
from app.authz.models import Application, Receipt
from app.crypto.sm2 import generate_keypair as _gen_kp
from app.kms import ra_signing_keypair
from app.ra.credential import build_message, sign_credential
from app.ra.models import Base

_NOW = int(_time_mod.time())

_VALID_PK = _gen_kp()[1]


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


class FakeDeps(service.AuthzDeps):
    """链面替身：nonce 已用注入+rev_root 恒定。"""

    def __init__(self, nonce_used: set[bytes] | None = None, rev_root: str = "00" * 32):
        super().__init__()
        self._used = nonce_used or set()
        self._rev = rev_root
        self.chain_nonce_used = lambda n: n in self._used
        self.chain_rev_root = lambda: (1, self._rev)
        self.pin_fingerprint = lambda: "SM3(test|pin)"  # 本地指纹替身


def _honest_sub_credential(session_pk_hex: str = "11" * 64, exp_u: int = 1900000000):
    """诚实子凭证材料（黄金向量同构——确定性钥）。

    exp_u 形参（S6 闭环）：缺省 1900000000（2030 远期——既有正例/负例不受扰），
    覆盖率负例传短效期（exp_u<t_end）构造「合法签名+短命凭证」攻击形态。
    """
    _sk, ra_pub = ra_signing_keypair()
    msg = build_message(
        ra_pub,
        secrets.token_bytes(32),
        secrets.token_bytes(16),
        b"110101199001011234",
        3,
        b"FZ-SN-AUTHZ-TEST",
        session_pk_hex,
        exp_u,
    )
    _priv, _pub = ra_signing_keypair()
    sig = sign_credential(_priv, msg)
    return ra_pub, msg, sig


# ---- T1 政策引擎 ----


def test_policy_two_classes_with_regulation_values():
    assert policy.get_rule(0) == (50, 1)  # 微型：真高 50m（条例数值）
    assert policy.get_rule(1) == (120, 1)  # 轻型：真高 120m（条例数值）


def test_policy_unsupported_class_fail_closed():
    for cid in (2, 3, 9, 255):
        with pytest.raises(policy.PolicyError) as ei:
            policy.get_rule(cid)
        assert ei.value.code == "unsupported_class"


def test_policy_params_hash_stable():
    assert policy.policy_params_hash() == policy.policy_params_hash()
    assert len(policy.policy_params_hash()) == 64


# ---- T2 门控序 ----


def _seed_sn_chain(session, msg: bytes):
    """SN 绑定换代（2026-10-06）测试播种：sub_cred_hash→SubCredential→
    Credential.serial_hex 的服务端溯源链（诚实流=RA 签发落库；门控测试直插行）。"""
    import datetime as _dt

    from app.ra.models import Credential, SubCredential, User

    from app.crypto.sm3 import sm3_bytes as _sm3b

    user = User(username="gate-sn-" + secrets.token_hex(6), pub_key_hex="11" * 64)
    session.add(user)
    session.flush()
    cred = Credential(
        user_id=user.id,
        commitment_hex=secrets.token_bytes(32).hex(),
        master_cred_hash_hex=secrets.token_bytes(32).hex(),
        sn_hash_hex="00" * 16,
        serial_hex=b"FZ-SN-AUTHZ-TEST".hex(),
        id_cipher=b"",
        cert_level=3,
        expires_at=_dt.datetime.utcfromtimestamp(1900000000),
    )
    session.add(cred)
    session.flush()
    session.add(
        SubCredential(
            credential_id=cred.id,
            sub_cred_hash_hex=_sm3b(msg).hex(),
            message_hex=msg.hex(),
            sig_hex="00" * 64,
            holder_pub_hex="11" * 64,
            expires_at=_dt.datetime.utcfromtimestamp(1900000000),
        )
    )
    session.commit()


def _apply_kwargs(session, session_pk_hex=_VALID_PK, exp_u: int = 1900000000, **over):
    _ra_pub, msg, sig = _honest_sub_credential(session_pk_hex, exp_u=exp_u)
    if session is not None:
        _seed_sn_chain(session, msg)
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    # 子凭证哈希=服务器签发面同式 sm3(M_A′)（ra/service.py:247）——2026-09-28
    # 安全深检 A-P1-1 后夹具换代：旧夹具随机哈希恰好掩盖了"服务器从不消费"的缺陷
    from app.crypto.sm3 import sm3_bytes as _sm3

    base = dict(
        session_pk_hex=session_pk_hex,
        sub_cred_message_hex=msg.hex(),
        sub_sig_hex=sig,
        sub_cred_hash_hex=_sm3(msg).hex(),
        nonce_hex=nonce_hex,
        plan_hash_hex=plan_hash_hex,
        class_id=0,
        proof_path=str(_make_case(plan_hash_hex, nonce_hex)["proof"]),
        spec_path=str(_make_case(plan_hash_hex, nonce_hex)["instances"]),
        rev_root_hex="00" * 32,
        t_start=_NOW,
        t_end=_NOW + 3600,
    )
    base.update(over)
    return base


def test_gate_honest_application_enqueued(session):
    kw = _apply_kwargs(session)
    row = service.admission_gate(session, FakeDeps(), **kw)
    assert row.status == "pending"
    r = session.get(Receipt, row.receipt_id)
    assert len(r.code_hex) == 32  # 128bit 回执码


# ---- T2 SN 绑定换代（2026-10-06）：实例 26 门控+服务端权威 sn_hash ----


def test_gate_sn_hash_low_instance_count_rejected(session):
    """受理门控实例数下限 26：25 项（旧代产物）= instances_malformed 拒绝。"""
    kw = _apply_kwargs(session)
    import json as _json

    doc = _json.load(open(kw["spec_path"], encoding="utf-8"))
    doc["instances"] = doc["instances"][:25]
    _json.dump(doc, open(kw["spec_path"], "w", encoding="utf-8"))
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "instances_malformed"


def test_gate_sn_hash_instance_mismatch_rejected(session):
    """实例 25 与服务端自算 SM3(serial) 不符（客户端自报/换机形态）=拒绝。"""
    kw = _apply_kwargs(session)
    import json as _json

    doc = _json.load(open(kw["spec_path"], encoding="utf-8"))
    doc["instances"][25] = "11" * 32
    _json.dump(doc, open(kw["spec_path"], "w", encoding="utf-8"))
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "instance_mismatch"


def test_server_sn_hash_authoritative_from_db(session):
    """服务端权威 sn_hash：DB 溯源链（sub_cred_hash→sub_credentials→
    credentials.serial_hex）自算 SM3 全 32B——零客户端自报；历史行缺
    serial_hex=fail-closed 人话拒绝（sn_unresolved）。"""
    from app.crypto.sm3 import sm3_bytes as _sm3b

    kw = _apply_kwargs(session)
    want = _sm3b(b"FZ-SN-AUTHZ-TEST").hex()
    got = service.server_sn_hash_hex(session, kw["sub_cred_hash_hex"])
    assert got == want, "DB 溯源自算 = SM3(serial) 全 32B"
    # 未知子凭证：404 形态拒绝。
    with pytest.raises(service.AuthzError) as ei:
        service.server_sn_hash_hex(session, "ab" * 32)
    assert ei.value.code == "sub_cred_unknown"
    # 历史凭证无 serial 溯源：fail-closed。
    from sqlalchemy import select as _sel

    from app.ra.models import Credential

    cred = session.scalar(_sel(Credential))
    cred.serial_hex = None
    session.commit()
    with pytest.raises(service.AuthzError) as ei:
        service.server_sn_hash_hex(session, kw["sub_cred_hash_hex"])
    assert ei.value.code == "sn_unresolved"


def test_build_token_carries_sn_hash_in_signed_body(session):
    """令牌载荷增 sn_hash——入 body ⟹ engine 签名域覆盖（sign_token 对 body
    原文签名；桥第 6 查消费同一字段）。"""
    import json as _json

    from app.authz.service import sign_token, token_hash

    sn = service.server_sn_hash_hex(session, _apply_kwargs(session)["sub_cred_hash_hex"])
    body = service.build_token(
        auth_id=1,
        plan_hash_hex="ab" * 32,
        alt_max=120,
        t_start=_NOW,
        t_end=_NOW + 3600,
        nonce_hex="ef" * 16,
        policy_version="policy-2026-09-v1",
        sn_hash_hex=sn,
    )
    tok = _json.loads(body)
    assert tok["sn_hash"] == sn, "令牌载荷携带服务端权威 sn_hash"
    sig = sign_token(body)
    assert len(sig) == 128 and len(token_hash(body)) == 64


def test_gate_sub_cred_hash_mismatch_rejected(session):
    """安全深检 A-P1-1 根修正例：同 (msg,sig) 配不同哈希=一张子凭证铸多授权的
    攻击面——门控服务器重算 sm3(M_A′) 对拍，不一致即拒（一次性查重键自此=
    服务器权威值）。"""
    kw = _apply_kwargs(session, sub_cred_hash_hex=secrets.token_bytes(32).hex())
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "sub_cred_hash_mismatch"


def test_gate_sub_cred_hash_case_insensitive(session):
    """大写 hex 哈希同样放行（对拍按字节语义归一）。"""
    kw = _apply_kwargs(session)
    kw["sub_cred_hash_hex"] = kw["sub_cred_hash_hex"].upper()
    row = service.admission_gate(session, FakeDeps(), **kw)
    assert row.status == "pending"


def test_gate_bad_session_key_rejected(session):
    # 凭证用合法钥构造，仅受理面的会话公钥坏（分离被测面）
    kw = _apply_kwargs(session)
    kw["session_pk_hex"] = "zz" * 64
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "bad_session_key"


def test_gate_bad_sub_signature_rejected(session):
    _ra, msg, _sig = _honest_sub_credential()
    bad = "0" + secrets.token_hex(63)
    kw = _apply_kwargs(session, sub_cred_message_hex=msg.hex(), sub_sig_hex=bad)
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "bad_sub_signature"


def test_gate_burned_nonce_rejected(session):
    nonce = secrets.token_bytes(16)
    kw = _apply_kwargs(session, nonce_hex=nonce.hex())
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(nonce_used={nonce}), **kw)
    assert ei.value.code == "nonce_used"


def test_gate_subcred_replay_rejected(session):
    kw = _apply_kwargs(session)
    service.admission_gate(session, FakeDeps(), **kw)
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "sub_cred_used"


def test_gate_stale_t_epoch_backdating_rejected(session):
    # R1 收口对抗自查增面：远古 t_start（证明语句 exp 检查空转+窗口洗白）——即使
    # 实例一致性门被绕过（instances 21 同值），时间锚新鲜度门独立拒绝。
    kw = _apply_kwargs(session, t_start=_NOW - 10 * 365 * 86400, t_end=_NOW - 10 * 365 * 86400 + 3600)
    import json as _json

    from app.authz.service import _fe_be32_hex_from_u64

    doc = _json.load(open(kw["spec_path"], encoding="utf-8"))
    doc["instances"][21] = _fe_be32_hex_from_u64(kw["t_start"])
    _json.dump(doc, open(kw["spec_path"], "w", encoding="utf-8"))
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "stale_t_epoch"


def test_gate_stale_rev_root_rejected(session):
    kw = _apply_kwargs(session, rev_root_hex="aa" * 32)
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "stale_rev_root"


def test_gate_unsupported_class_rejected(session):
    kw = _apply_kwargs(session, class_id=2)
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "unsupported_class"


# ---- S6 安全闭环：凭证有效期必须覆盖整个授权窗 ----


def test_gate_cred_expired_window_rejected(session):
    """S6 闭环负例①（2026-10-04）：exp_u < t_end → 409 cred_expired_window。

    攻击形态：持 exp_u=now+1min 的合法子凭证（RA 签名为真）申请满 6h 授权窗
    ——AUTH 电路只证 exp_u ≥ t_epoch（实例 21=t_start，出证时刻）⟹ 电路为真；
    既有受理门核对窗口自洽与 t_epoch 新鲜度，全文无一处核对凭证有效期覆盖
    授权窗 ⟹ 令牌覆盖凭证死后近 6 小时。宿主面补核对：exp_u ≥ t_end。
    """
    kw = _apply_kwargs(session, exp_u=_NOW + 60, t_end=_NOW + 3600)
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, FakeDeps(), **kw)
    assert ei.value.code == "cred_expired_window"
    assert ei.value.status == 409


def test_gate_cred_window_boundary_exp_equals_t_end_passes(session):
    """S6 闭环负例②（边界）：exp_u == t_end 恰好覆盖 → 放行且 exp_u 落库
    （判决件 expected.exp_u 的归档源——第三方可自行核对覆盖关系）。"""
    kw = _apply_kwargs(session, exp_u=_NOW + 3600, t_end=_NOW + 3600)
    row = service.admission_gate(session, FakeDeps(), **kw)
    assert row.status == "pending"
    assert row.exp_u == _NOW + 3600


# ---- 匿名红线（B4 验收门）----


def test_tables_zero_identity_columns():
    """applications/receipts/auth_records 列集合零身份断言（模型级）。"""
    forbidden = {"username", "user_id", "id_number", "commitment", "holder_pub", "phone"}
    for model in (Application, Receipt):
        cols = {c.name for c in model.__table__.columns}
        leak = cols & forbidden
        assert not leak, f"{model.__tablename__} 身份列泄漏: {leak}"


def test_receipt_fetch_lifecycle(session):
    kw = _apply_kwargs(session)
    row = service.admission_gate(session, FakeDeps(), **kw)
    r = session.get(Receipt, row.receipt_id)
    out = service.receipt_of(session, r.code_hex)
    assert out["status"] == "waiting"
    with pytest.raises(service.AuthzError):
        service.receipt_of(session, "ff" * 16)


def test_gate_pin_mismatch_rejected(session):
    """门控④错 pin 负例（B4 验收门：错 pin 不进 ZK 队列）。"""
    kw = _apply_kwargs(session)

    class PinDeps(FakeDeps):
        def __init__(self):
            super().__init__()
            self.pin_fingerprint = lambda: "SM3(local|aaa)"
            self.chain_pin = lambda: "SM3(chain|bbb)"  # 链上公示≠本地

    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, PinDeps(), **kw)
    assert ei.value.code == "pin_mismatch"
    assert ei.value.status == 409


def _make_case(plan_hash_hex, nonce_hex):
    """造合法出证产物目录（instances 由同源折算函数生成——gate 消费逻辑测试）。"""
    import json as _json
    import os as _os
    import tempfile

    from app.authz.policy import POLICY_VERSION, get_rule
    from app.authz.service import (
        _fe_be32_hex_from_bytes32,
        _fe_be32_hex_from_digest,
        _fe_be32_hex_from_u64,
        binding_challenge,
    )
    from app.crypto.sm3 import sm3_bytes

    d = _os.path.join(tempfile.mkdtemp(prefix="fzcase"), plan_hash_hex[:16])
    _os.makedirs(d, exist_ok=True)
    # SN 绑定换代（2026-10-06）：实例面 25→26——索引 25=sn_hash（SM3(serial)
    # 全 32B BE 折叠；serial 与 _honest_sub_credential 的 build_message 同源）。
    inst = ["0" * 64] * 26
    inst[25] = _fe_be32_hex_from_bytes32(sm3_bytes(b"FZ-SN-AUTHZ-TEST"))  # 词折叠环同 SMT 根（prove 窗定谳）
    challenge = binding_challenge(plan_hash_hex, nonce_hex)
    inst[19] = _fe_be32_hex_from_digest(sm3_bytes(bytes.fromhex(challenge)))
    pred_str = plan_hash_hex + "|" + nonce_hex + "|" + POLICY_VERSION
    pred_domain = b"FZ-ZKSVC-PRED-ID" + b"\x01"
    inst[20] = _fe_be32_hex_from_digest(sm3_bytes(pred_domain + pred_str.encode()))
    inst[21] = _fe_be32_hex_from_u64(_NOW)
    inst[22] = _fe_be32_hex_from_u64(get_rule(0)[1])
    inst[23] = _fe_be32_hex_from_bytes32(bytes.fromhex("00" * 32))
    inst[24] = _fe_be32_hex_from_u64(0)
    with open(_os.path.join(d, "proof.bin"), "wb") as f:
        f.write(b"proof")
    with open(_os.path.join(d, "instances.json"), "w", encoding="utf-8") as f:
        f.write(_json.dumps({"instances": inst}))
    with open(_os.path.join(d, "verifier_param.bin"), "wb") as f:
        f.write(b"vp")
    return {
        "dir": d,
        "proof": _os.path.join(d, "proof.bin"),
        "instances": _os.path.join(d, "instances.json"),
    }


def test_fold_words_be_cross_language_anchor():
    # R1 收口跨语言锚（B6-d10 口径分野回归门）：rev_root 实例 23 的期望值必须
    # 用 fold_words_be（词序折叠）——期望 hex 取自 Rust 侧真实出证产物
    # （zkc prove instances.json[23]，黄金向量根；曾因 Python 侧误用 BE 整数口径
    # 全拒——此测试钉死两口径不再混用）。
    import json as _json
    import os as _os

    from app.authz.service import _fe_be32_hex_from_bytes32

    gv = _json.load(
        open(
            _os.path.join(
                _os.path.dirname(__file__), "..", "..", "zksvc", "tests", "auth_golden_vector.json"
            ),
            encoding="utf-8",
        )
    )
    root = bytes.fromhex(gv["smt_root_hex"])
    assert root != bytes(32)
    assert _fe_be32_hex_from_bytes32(root) == (
        "975ca28e6e11172e1e5ed7422f0fbc4538efd32a5a7d08c940392aa64035cafe"
    ), "fold_words_be 口径漂移（Rust 权威产物对拍失败）"


# ---- B-P1-1 回归根修：政策公示对拍支持 per-apply callable 形态 ----


def test_gate_policy_callable_false_fail_closed(session):
    """注入 callable 且求值=False ⟹ 409 policy_unpublished。

    旧代码按 `deps.chain_policy_published is False` 比对——router 注入的
    per-apply lambda 恒不等于 False ⟹ 防线静默失效（单测全绿、产品死码）。
    """

    class ProxyDeps(FakeDeps):
        def __init__(self):
            super().__init__()
            self.chain_policy_published = lambda: False  # noqa: E731

    kw = _apply_kwargs(session)
    with pytest.raises(service.AuthzError) as ei:
        service.admission_gate(session, ProxyDeps(), **kw)
    assert ei.value.code == "policy_unpublished"


def test_gate_policy_callable_true_passes(session):
    """callable 求值=True ⟹ 正常受理（形态归一不改变通过语义）。"""

    class ProxyDeps(FakeDeps):
        def __init__(self):
            super().__init__()
            self.chain_policy_published = lambda: True  # noqa: E731

    row = service.admission_gate(session, ProxyDeps(), **_apply_kwargs(session))
    assert row.status == "pending"
