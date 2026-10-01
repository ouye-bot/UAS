"""RA 服务层测试：注册/子凭证正例+负例三连（B2 验收门）+吊销纪元根+快照。

链上副作用经 fake anchor 断言（B2-d6）；真链端到端=scripts/smoke_ra_chain.py。
"""

import datetime as dt
import secrets

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crypto.sm2 import generate_keypair
from app.crypto.sm3 import sm3_bytes
from app.ra.credential import verify_credential
from app.ra.models import Base
from app.ra.service import ChainAnchor, RaDeps, RaError, RaService


class FakeAnchor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []

    def __call__(self, fn: str, args: list) -> None:
        self.calls.append((fn, args))


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng, expire_on_commit=False)()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture()
def svc(session):
    ra_priv, ra_pub = generate_keypair()
    fake = FakeAnchor()
    deps = RaDeps(ra_priv_hex=ra_priv, ra_pub_hex=ra_pub, anchor=ChainAnchor(call=fake))
    return RaService(session, deps), fake


def _register(s, username="pilot-1"):
    _, user_pub = generate_keypair()
    return s.register(
        username=username,
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-2026-0001",
        user_pub_hex=user_pub,
    )


def test_register_full_flow(svc):
    s, anchor = svc
    out = s.register(
        username="pilot-a",
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-2026-0001",
        user_pub_hex=generate_keypair()[1],
    )
    assert len(out["message_hex"]) == 330  # 165B
    assert anchor.calls == [("register_commitment", ["0x" + out["master_cred_hash_hex"], 1])]
    # 句柄=SM3(C)
    assert out["master_cred_hash_hex"] == sm3_bytes(bytes.fromhex(out["commitment_hex"])).hex()
    assert len(out["preimage_cipher_hex"]) > 0  # ECIES 原像通道


def test_sub_credential_positive_and_unlinkable(svc):
    s, _ = svc
    reg = _register(s)
    _, holder_pub = generate_keypair()
    out1 = s.issue_sub_credential(
        master_cred_hash_hex=reg["master_cred_hash_hex"],
        salt_hex=reg["salt_hex"],
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-2026-0001",
        holder_pub_hex=holder_pub,
    )
    _, holder_pub2 = generate_keypair()
    out2 = s.issue_sub_credential(
        master_cred_hash_hex=reg["master_cred_hash_hex"],
        salt_hex=reg["salt_hex"],
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-2026-0001",
        holder_pub_hex=holder_pub2,
    )
    # 逐次不可链接：两子凭证 M_A′ 互异+哈希互异+id_prime 互异
    assert out1["message_hex"] != out2["message_hex"]
    assert out1["sub_cred_hash_hex"] != out2["sub_cred_hash_hex"]
    assert out1["id_prime_hex"] != out2["id_prime_hex"]


def test_sub_credential_sig_verifiable(svc):
    s, _ = svc
    # 从 svc 内部取 RA 公钥做验签（deps 可达）
    reg = _register(s, "pilot-b")
    _, holder_pub = generate_keypair()
    out = s.issue_sub_credential(
        master_cred_hash_hex=reg["master_cred_hash_hex"],
        salt_hex=reg["salt_hex"],
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-2026-0001",
        holder_pub_hex=holder_pub,
    )
    ra_pub_hex = s._d.ra_pub_hex  # noqa: SLF001  测试面自省
    assert verify_credential(ra_pub_hex, bytes.fromhex(out["message_hex"]), out["sig_hex"]) is True


def test_sub_credential_bad_preimage(svc):
    s, _ = svc
    reg = _register(s, "pilot-c")
    _, holder_pub = generate_keypair()
    with pytest.raises(RaError, match="原像知识认证失败|承诺不匹配"):
        s.issue_sub_credential(
            master_cred_hash_hex=reg["master_cred_hash_hex"],
            salt_hex="00" * 16,  # 错盐
            id_number="11010119900307999X",
            cert_level=3,
            sn="UAS-SN-2026-0001",
            holder_pub_hex=holder_pub,
        )


def test_negative_expired(svc):
    """负例①：过期主凭证拒新签发。"""
    s, _ = svc
    _, user_pub = generate_keypair()
    reg = s.register(
        username="pilot-exp",
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-2026-0001",
        user_pub_hex=user_pub,
        expires_at=dt.datetime.now(dt.UTC).replace(tzinfo=None) - dt.timedelta(hours=1),
    )
    with pytest.raises(RaError) as ei:
        s.issue_sub_credential(
            master_cred_hash_hex=reg["master_cred_hash_hex"],
            salt_hex=reg["salt_hex"],
            id_number="11010119900307999X",
            cert_level=3,
            sn="UAS-SN-2026-0001",
            holder_pub_hex=generate_keypair()[1],
        )
    assert ei.value.code == "cred_expired"


def test_negative_quota(svc):
    """负例②：超配额（第 21 张）拒。"""
    s, _ = svc
    reg = _register(s, "pilot-quota")
    for i in range(20):
        s.issue_sub_credential(
            master_cred_hash_hex=reg["master_cred_hash_hex"],
            salt_hex=reg["salt_hex"],
            id_number="11010119900307999X",
            cert_level=3,
            sn="UAS-SN-2026-0001",
            holder_pub_hex=generate_keypair()[1],
        )
        del i
    with pytest.raises(RaError) as ei:
        s.issue_sub_credential(
            master_cred_hash_hex=reg["master_cred_hash_hex"],
            salt_hex=reg["salt_hex"],
            id_number="11010119900307999X",
            cert_level=3,
            sn="UAS-SN-2026-0001",
            holder_pub_hex=generate_keypair()[1],
        )
    assert ei.value.code == "quota_exceeded"


def test_negative_revoked(svc):
    """负例③：吊销主凭证拒新签发（D14 即时语义——RA 侧第一道）。"""
    s, anchor = svc
    reg = _register(s, "pilot-rev")
    s.revoke(master_cred_hash_hex=reg["master_cred_hash_hex"], reason="违规飞行")
    # 链上双调用：setStatus(2)+setRevocationRoot(epoch=1)
    fns = [c[0] for c in anchor.calls]
    assert fns == ["register_commitment", "set_status", "set_revocation_root"]
    assert anchor.calls[1][1][1] == 2
    assert anchor.calls[2][1][0] == 1
    with pytest.raises(RaError) as ei:
        s.issue_sub_credential(
            master_cred_hash_hex=reg["master_cred_hash_hex"],
            salt_hex=reg["salt_hex"],
            id_number="11010119900307999X",
            cert_level=3,
            sn="UAS-SN-2026-0001",
            holder_pub_hex=generate_keypair()[1],
        )
    assert ei.value.code == "cred_revoked"


def test_snapshot_matches_smt_and_chain(svc):
    s, anchor = svc
    reg1 = _register(s, "p1")
    reg2 = _register(s, "p2")
    s.revoke(master_cred_hash_hex=reg1["master_cred_hash_hex"], reason="r1")
    s.revoke(master_cred_hash_hex=reg2["master_cred_hash_hex"], reason="r2")
    snap = s.snapshot()
    # 纪元=2（两次吊销各进一纪元）；根=SMT(两个句柄)
    from app.ra.smt import smt_root

    expect_root = smt_root(
        [bytes.fromhex(reg1["master_cred_hash_hex"]), bytes.fromhex(reg2["master_cred_hash_hex"])]
    )
    assert snap["epoch"] == 2
    assert snap["root_hex"] == expect_root.hex()
    # 链上收到两次 set_revocation_root（epoch 1、2）
    roots = [c for c in anchor.calls if c[0] == "set_revocation_root"]
    assert [c[1][0] for c in roots] == [1, 2]


# ---- R3-0.3 撤销传播（评审 P0-1，先红后绿） ----


def test_revocation_propagates_unconsumed_holder_pk(session, svc):
    """revoke 必须把该主凭证全部未消费子凭证的 pk′.x 并入撤销叶集——否则电路
    键（pk′.x）域与句柄域（SM3(C)）不相交，「pk′.x∉撤销集」对被吊销者恒真
    （三代理评审 P0-1：撤销即时宣称空转的根因）。"""
    from sqlalchemy import select

    from app.ra.models import Revocation
    from app.ra.smt import non_membership_witness, verify_non_membership

    s, _ = svc
    reg = _register(s)
    _, holder_pub = generate_keypair()
    s.issue_sub_credential(
        master_cred_hash_hex=reg["master_cred_hash_hex"],
        salt_hex=reg["salt_hex"],
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-2026-0001",
        holder_pub_hex=holder_pub,
    )
    out = s.revoke(master_cred_hash_hex=reg["master_cred_hash_hex"], reason="违规飞行")
    root = bytes.fromhex(out["root_hex"])
    pk_x = bytes.fromhex(holder_pub.lower()[:64])
    handles = [bytes.fromhex(r.handle_hex) for r in session.scalars(select(Revocation)).all()]
    assert pk_x in handles, "被吊销者的 pk′.x 未并入撤销叶集（撤销传播缺失）"
    w = non_membership_witness(pk_x, handles)
    assert not verify_non_membership(pk_x, w, root), (
        "被吊销者 pk′.x 仍可验出非成员——撤销对 AUTH 电路空转（P0-1）"
    )


def test_revocation_witness_endpoint_refuses_member(session, svc):
    """witness 端点对已撤销公钥必须拒绝（fail-fast——不让恶意/不知情申请烧
    2 分钟出证后死于 root.fold）。"""
    from app.ra.router import revocation_witness

    s, _ = svc
    reg = _register(s)
    _, holder_pub = generate_keypair()
    s.issue_sub_credential(
        master_cred_hash_hex=reg["master_cred_hash_hex"],
        salt_hex=reg["salt_hex"],
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-2026-0001",
        holder_pub_hex=holder_pub,
    )
    s.revoke(master_cred_hash_hex=reg["master_cred_hash_hex"], reason="违规飞行")
    resp = revocation_witness(holder_pk_hex=holder_pub.lower(), session=session)
    assert resp.status_code == 403, f"成员键 witness 未拒（状态 {resp.status_code}）"
    assert b"revoked" in resp.body


# ---- R4 第二批 B-P2-5：签发面撤销预检 + 按人级联吊销 ----


def test_issue_sub_credential_holder_revoked_precheck(session, svc):
    """pk′.x 已入撤销集（原凭证吊销传播）后，凭新凭证再来签发必须人话拒绝——
    否则签发成功但出证必死于 SMT root.fold（数学不可证的诚实误伤）。"""
    s, _ = svc
    _, holder_pub = generate_keypair()
    reg_a = s.register(
        username="pilot-holder-" + secrets.token_hex(2),
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-A",
        user_pub_hex=holder_pub,
    )
    _issue_kwargs = {
        "master_cred_hash_hex": reg_a["master_cred_hash_hex"],
        "salt_hex": reg_a["salt_hex"],
        "id_number": "11010119900307999X",
        "cert_level": 3,
        "sn": "UAS-SN-A",
        "holder_pub_hex": holder_pub,
    }
    s.issue_sub_credential(**_issue_kwargs)  # 基线：吊销前可签发
    s.revoke(master_cred_hash_hex=reg_a["master_cred_hash_hex"], reason="撤销键域传染场景")
    # 同一出示钥绑定新主凭证（恢复码找回旧钥重新登记形态）→ 签发面预检拒绝
    reg_b = s.register(
        username="pilot-holder2-" + secrets.token_hex(2),
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-B",
        user_pub_hex=holder_pub,
    )
    with pytest.raises(RaError) as ei:
        s.issue_sub_credential(
            master_cred_hash_hex=reg_b["master_cred_hash_hex"],
            salt_hex=reg_b["salt_hex"],
            id_number="11010119900307999X",
            cert_level=3,
            sn="UAS-SN-B",
            holder_pub_hex=holder_pub,
        )
    assert ei.value.code == "holder_revoked"


def test_revoke_by_username_cascade(session, svc):
    """按人级联：该用户全部有效凭证一次撤销——同纪元同根一次推链，每凭证独立
    setStatus；撤销语义「人-凭证-钥匙」三层对齐（B-P2-5 追责逃逸面封堵）。"""
    from sqlalchemy import select

    from app.ra.models import Credential, Revocation

    s, anchor = svc
    username = "pilot-cascade-" + secrets.token_hex(2)
    _, holder1 = generate_keypair()
    _, holder2 = generate_keypair()
    reg1 = s.register(
        username=username,
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-C1",
        user_pub_hex=holder1,
    )
    reg2 = s.register(
        username=username,
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-C2",
        user_pub_hex=holder2,
    )
    s.issue_sub_credential(
        master_cred_hash_hex=reg1["master_cred_hash_hex"],
        salt_hex=reg1["salt_hex"],
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-C1",
        holder_pub_hex=holder1,
    )
    out = s.revoke_by_username(username=username, reason="按人级联测试")
    assert out["revoked_credentials"] == 2 and out["revoked_sub_keys"] == 1
    # 两凭证均终态（级联后该用户无 status=1 残留）
    assert all(c.status != 1 for c in session.scalars(select(Credential)).all())
    # 句柄+子凭证键全入集，单纪元
    epochs = {r.epoch for r in session.scalars(select(Revocation)).all()}
    assert epochs == {out["epoch"]}
    handles = {r.handle_hex for r in session.scalars(select(Revocation)).all()}
    assert reg1["master_cred_hash_hex"] in handles and reg2["master_cred_hash_hex"] in handles
    assert holder1.lower()[:64] in handles
    # 链面：两笔 setStatus + 一笔 set_revocation_root
    fns = [c[0] for c in anchor.calls]
    assert fns.count("set_status") == 2 and fns.count("set_revocation_root") == 1
    # 空集负例：再级联=bad_input（无有效凭证）
    with pytest.raises(RaError) as ei2:
        s.revoke_by_username(username=username)
    assert ei2.value.code == "bad_input"
    with pytest.raises(RaError) as ei3:
        s.revoke_by_username(username="ghost-" + secrets.token_hex(2))
    assert ei3.value.code == "not_found"


def test_revoke_epoch_chain_authoritative(session):
    """链纪元权威（B2/R4 第二批实弹定谳）：注入 chain_rev_epoch=43 时撤销纪元
    必为 44（本地表空/滞后不得参与纪元推导——require(epoch==revEpoch+1) 契约）。"""
    ra_priv, ra_pub = generate_keypair()
    fake = FakeAnchor()
    deps = RaDeps(
        ra_priv_hex=ra_priv,
        ra_pub_hex=ra_pub,
        anchor=ChainAnchor(call=fake),
        chain_rev_epoch=lambda: 43,
    )
    s = RaService(session, deps)
    reg = _register(s)
    out = s.revoke(master_cred_hash_hex=reg["master_cred_hash_hex"])
    assert out["epoch"] == 44
    roots = [c for c in fake.calls if c[0] == "set_revocation_root"]
    assert roots and roots[-1][1][0] == 44
