"""机构机队接口实装验收（3.1——credKind=2 预留面激活，先红后绿钉面）。

合约面（零触碰）：IdentityRegistry.registerCommitment 已接受 kind=2
（contracts/src/IdentityRegistry.sol:30-35）——本批=服务面把预留接通：
①机构管理员以 org 身份批量登记设备（kind=2 机构承诺）+机队设备子凭证批量签发；
②配额=机构级共享池（FZ_FLEET_POOL_QUOTA 缺省 100——与个人 20/凭证并行独立）；
③撤销走 org 署名推根（⑥站 FedRegistry 分支——机队凭证域权威=owner_org_id 列）。

负例一等公民（每条先红后绿）：
- 跨域机队操作拒：org-b 管理员登记/签发/吊销 org-a 设备 → 403 org_forbidden；
- kind 语义错配拒：机队签发端点对 cred_kind=1 个人凭证 → 409 not_fleet_credential；
- 配额超限拒：共享池（FZ_FLEET_POOL_QUOTA=2）第 3 张 → 429 quota_exceeded。
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.crypto.sm2 import generate_keypair
from app.ra.models import (
    Base,
    Credential,
    Revocation,
    SubCredential,
)
from app.ra.service import (
    ChainAnchor,
    RaDeps,
    RaError,
    RaService,
    revoke_msg,
)


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


def _svc(session, auth_revoke=None) -> RaService:
    ra_priv, ra_pub = generate_keypair()
    return RaService(
        session,
        RaDeps(
            ra_priv_hex=ra_priv,
            ra_pub_hex=ra_pub,
            anchor=ChainAnchor(call=FakeAnchor()),
            auth_revoke=auth_revoke,
        ),
    )


def _reg_personal(s: RaService, username="pilot-f", org_id="org-a") -> dict:
    _, user_pub = generate_keypair()
    return s.register(
        username=username,
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-PERSONAL-1",
        user_pub_hex=user_pub,
        org_id=org_id,
    )


def _fleet_rows(svc: RaService):
    """库内机队凭证行（cred_kind=2）。"""
    return svc._s.scalars(select(Credential).where(Credential.cred_kind == 2)).all()


def _device(no: str = "FZ-DEV-000001A0001", sn: str = "UAS-SN-FLEET-01", cls: int = 1):
    return {"device_no": no, "sn": sn, "cert_level": 3, "class_id": cls}


# ---------------- 段①：机构承诺主凭证（kind=2）+批量登记 ----------------


def test_fleet_register_batch_kind2_and_owner_org(session):
    s = _svc(session)
    out = s.register_fleet_devices(
        operator_org_id="org-b",
        devices=[_device("FZ-DEV-000001A0001"), _device("FZ-DEV-000001A0002", "UAS-SN-FLEET-02")],
    )
    assert len(out["devices"]) == 2
    rows = _fleet_rows(s)
    assert len(rows) == 2
    for r in rows:
        assert r.cred_kind == 2  # 机构机队承诺（链上 credKind=2 镜像）
        assert r.owner_org_id == "org-b"  # 机队域权威列
        assert r.user_id is None  # 设备非人——不占实名域
        # 登记号在列（列表/管理面显示源）
        assert r.device_no in ("FZ-DEV-000001A0001", "FZ-DEV-000001A0002")
    # 链上登记面：register_commitment kind=2（预留面激活实证——FakeAnchor 留痕）
    reg_calls = [c for c in s._d.anchor.call.calls if c[0] == "register_commitment"]
    assert len(reg_calls) == 2
    for _fn, args in reg_calls:
        assert args[1] == 2
    # 每台回传 salt（机构自持原像——签发面原像知识认证输入）+承诺与句柄
    for d, row in zip(out["devices"], rows, strict=True):
        assert len(d["salt_hex"]) == 32
        assert d["master_cred_hash_hex"] == row.master_cred_hash_hex
        assert d["message_hex"] and d["sig_hex"]


def test_fleet_register_personal_path_untouched(session):
    """个人登记零变化（单链语义零变化——cred_kind=1+user_id 恒在）。"""
    s = _svc(session)
    out = _reg_personal(s)
    row = s._s.scalar(
        select(Credential).where(Credential.master_cred_hash_hex == out["master_cred_hash_hex"])
    )
    assert row.cred_kind == 1
    assert row.user_id is not None
    assert row.owner_org_id == "org-a"  # 个人行域列同写（单一权威）


def test_fleet_register_negative_device_no_dup_in_org(session):
    s = _svc(session)
    s.register_fleet_devices(operator_org_id="org-a", devices=[_device()])
    with pytest.raises(RaError) as ei:
        s.register_fleet_devices(operator_org_id="org-a", devices=[_device()])
    assert ei.value.code == "device_exists"


def test_fleet_register_negative_sn_dup_cross_org(session):
    """机队集内 SN 全局判重（物理设备全局唯一——跨域同 SN=绑定歧义）。"""
    s = _svc(session)
    s.register_fleet_devices(operator_org_id="org-a", devices=[_device()])
    with pytest.raises(RaError) as ei:
        s.register_fleet_devices(operator_org_id="org-b", devices=[_device()])
    assert ei.value.code == "device_exists"


def test_fleet_register_negative_unknown_org(session):
    s = _svc(session)
    with pytest.raises(RaError) as ei:
        s.register_fleet_devices(operator_org_id="org-z", devices=[_device()])
    assert ei.value.code == "unknown_org"


def test_fleet_register_negative_device_no_shape(session):
    s = _svc(session)
    with pytest.raises(RaError) as ei:
        s.register_fleet_devices(operator_org_id="org-a", devices=[_device(no="SHORT-7")])
    assert ei.value.code == "bad_input"


# ---------------- 段①：机队子凭证批量签发（机构共享池） ----------------


def _reg_fleet(s: RaService, org="org-a", sn="UAS-SN-FLEET-01", no="FZ-DEV-000001A0001") -> dict:
    out = s.register_fleet_devices(operator_org_id=org, devices=[_device(no=no, sn=sn)])
    return out["devices"][0]


def test_fleet_issue_batch_ok(session):
    s = _svc(session)
    dev = _reg_fleet(s, org="org-b")
    holder_sks = []
    items = []
    for _ in range(2):
        sk, pk = generate_keypair()
        holder_sks.append(sk)
        items.append(
            {
                "master_cred_hash_hex": dev["master_cred_hash_hex"],
                "salt_hex": dev["salt_hex"],
                "holder_pub_hex": pk,
            }
        )
    out = s.issue_fleet_sub_credentials(operator_org_id="org-b", items=items)
    assert len(out["items"]) == 2
    subs = s._s.scalars(select(SubCredential)).all()
    assert len(subs) == 2
    sub_hashes = {x.sub_cred_hash_hex for x in subs}
    for o in out["items"]:
        assert o["sub_cred_hash_hex"] in sub_hashes
        assert o["id_prime_hex"] and o["message_hex"] and o["sig_hex"]


def test_fleet_issue_negative_cross_org(session):
    """跨域机队操作拒（负例一等公民）：org-b 管理员签发 org-a 设备 → 403。"""
    s = _svc(session)
    dev = _reg_fleet(s, org="org-a")
    sk, pk = generate_keypair()
    with pytest.raises(RaError) as ei:
        s.issue_fleet_sub_credentials(
            operator_org_id="org-b",
            items=[
                {
                    "master_cred_hash_hex": dev["master_cred_hash_hex"],
                    "salt_hex": dev["salt_hex"],
                    "holder_pub_hex": pk,
                }
            ],
        )
    assert ei.value.code == "org_forbidden"
    assert ei.value.status == 403


def test_fleet_issue_negative_kind_mismatch(session):
    """kind 语义错配拒（负例一等公民）：机队端点对个人凭证（kind=1）→ 409。"""
    s = _svc(session)
    per = _reg_personal(s)
    sk, pk = generate_keypair()
    with pytest.raises(RaError) as ei:
        s.issue_fleet_sub_credentials(
            operator_org_id="org-a",
            items=[
                {
                    "master_cred_hash_hex": per["master_cred_hash_hex"],
                    "salt_hex": per["salt_hex"],
                    "holder_pub_hex": pk,
                }
            ],
        )
    assert ei.value.code == "not_fleet_credential"


def test_fleet_issue_negative_bad_preimage(session):
    s = _svc(session)
    dev = _reg_fleet(s)
    sk, pk = generate_keypair()
    with pytest.raises(RaError) as ei:
        s.issue_fleet_sub_credentials(
            operator_org_id="org-a",
            items=[
                {
                    "master_cred_hash_hex": dev["master_cred_hash_hex"],
                    "salt_hex": "00" * 16,  # 错原像
                    "holder_pub_hex": pk,
                }
            ],
        )
    assert ei.value.code == "bad_preimage"


def test_fleet_issue_negative_quota_pool_exceeded(session, monkeypatch):
    """配额超限拒（负例一等公民）：机构共享池 FZ_FLEET_POOL_QUOTA=2——同池
    两台设备合计第 3 张拒（共享池语义=机构级累计，非单设备 20）。"""
    monkeypatch.setenv("FZ_FLEET_POOL_QUOTA", "2")
    s = _svc(session)
    d1 = _reg_fleet(s, sn="UAS-SN-FLEET-01", no="FZ-DEV-000001A0001")
    d2 = _reg_fleet(s, sn="UAS-SN-FLEET-02", no="FZ-DEV-000001A0002")
    items = []
    for d in (d1, d2):
        sk, pk = generate_keypair()
        items.append(
            {
                "master_cred_hash_hex": d["master_cred_hash_hex"],
                "salt_hex": d["salt_hex"],
                "holder_pub_hex": pk,
            }
        )
    out = s.issue_fleet_sub_credentials(operator_org_id="org-a", items=items)
    assert len(out["items"]) == 2  # 池内前 2 张放行
    sk3, pk3 = generate_keypair()
    with pytest.raises(RaError) as ei:
        s.issue_fleet_sub_credentials(
            operator_org_id="org-a",
            items=[
                {
                    "master_cred_hash_hex": d1["master_cred_hash_hex"],
                    "salt_hex": d1["salt_hex"],
                    "holder_pub_hex": pk3,
                }
            ],
        )
    assert ei.value.code == "quota_exceeded"
    assert ei.value.status == 429


# ---------------- 段④：撤销走 org 署名推根（owner_org_id 域权威） ----------------


def test_fleet_revoke_cross_org_denied(session):
    """跨域机队吊销拒：org-a 管理员吊销 org-b 设备 → 403（域门先于签名仪式）。"""
    s = _svc(session)
    dev = _reg_fleet(s, org="org-b")
    with pytest.raises(RaError) as ei:
        s.revoke(
            master_cred_hash_hex=dev["master_cred_hash_hex"],
            reason="跨域越权试探",
            admin_username="admin-a",
            admin_pub_hex="ab" * 32,
            admin_sig_hex="cd" * 64,
            epoch=1,
            operator_org_id="org-a",
        )
    assert ei.value.code == "org_forbidden"


def test_fleet_revoke_real_sig_pushes_org_anchor(session):
    """真实签名吊销机队设备：org 署名推根（set_org_rev_root 参数=owner_org_id）。"""
    s = _svc(session)
    dev = _reg_fleet(s, org="org-b")
    admin_sk, admin_pk = generate_keypair()
    handle = dev["master_cred_hash_hex"]
    msg = revoke_msg([handle], "机队设备退役依规吊销", 1)
    from app.crypto.sm2 import sign as sm2_sign

    out = s.revoke(
        master_cred_hash_hex=handle,
        reason="机队设备退役依规吊销",
        admin_username="admin-b",
        admin_pub_hex=admin_pk,
        admin_sig_hex=sm2_sign(admin_sk, msg.encode()),
        epoch=1,
        operator_org_id="org-b",
    )
    assert out["epoch"] == 1
    org_call = [c for c in s._d.anchor.call.calls if c[0] == "set_org_rev_root"]
    assert len(org_call) == 1
    org_b32 = org_call[0][1][0]
    assert isinstance(org_b32, str) and org_b32.startswith("0x")
    assert bytes.fromhex(org_b32[2:]).rstrip(b"\x00") == b"org-b"  # 机构署名锚=owner_org_id
    row = s._s.scalar(select(Credential).where(Credential.master_cred_hash_hex == handle))
    assert row.status == 2


def test_fleet_revoke_propagates_unconsumed_subs(session):
    """机队吊销传播：未消费子凭证 pk′.x 并入撤销集（R3-0.3 同构）。"""
    s = _svc(session)
    dev = _reg_fleet(s, org="org-a")
    sk, pk = generate_keypair()
    s.issue_fleet_sub_credentials(
        operator_org_id="org-a",
        items=[
            {
                "master_cred_hash_hex": dev["master_cred_hash_hex"],
                "salt_hex": dev["salt_hex"],
                "holder_pub_hex": pk,
            }
        ],
    )
    admin_sk, admin_pk = generate_keypair()
    handle = dev["master_cred_hash_hex"]
    from app.crypto.sm2 import sign as sm2_sign

    s.revoke(
        master_cred_hash_hex=handle,
        reason="机队设备退役依规吊销",
        admin_username="admin-a",
        admin_pub_hex=admin_pk,
        admin_sig_hex=sm2_sign(admin_sk, revoke_msg([handle], "机队设备退役依规吊销", 1).encode()),
        epoch=1,
        operator_org_id="org-a",
    )
    leaves = {r.handle_hex for r in s._s.scalars(select(Revocation)).all()}
    assert pk.lower()[:64] in leaves  # 子凭证出示钥已传播并入


def test_fleet_devices_list_scoped_to_org(session):
    s = _svc(session)
    _reg_fleet(s, org="org-a", sn="UAS-SN-FLEET-01", no="FZ-DEV-000001A0001")
    _reg_fleet(s, org="org-b", sn="UAS-SN-FLEET-02", no="FZ-DEV-000001A0002")
    out = s.fleet_devices_list(operator_org_id="org-a")
    assert len(out["items"]) == 1
    assert out["items"][0]["device_no"] == "FZ-DEV-000001A0001"
    assert out["items"][0]["sn"] == "UAS-SN-FLEET-01"
    assert out["items"][0]["cred_kind"] == 2


# ---------------- 审查批根修（2026-10-11 独立审查员 1/6/8 条——先红后绿） ----------------


def test_review1_personal_endpoint_fleet_bypass_denied(session):
    """审查①（高）：个人端点对偶拒绝——匿名路径持 salt 对 kind=2 机队凭证
    用 device_no 当 id_number 槽重算 C 逐字节命中（BYPASS-1）→ 409
    not_personal_credential。同时封共享池配额旁路（个人端点连签绕池）。"""
    s = _svc(session)
    dev = _reg_fleet(s, org="org-a")
    sk, pk = generate_keypair()
    with pytest.raises(RaError) as ei:
        s.issue_sub_credential(
            master_cred_hash_hex=dev["master_cred_hash_hex"],
            salt_hex=dev["salt_hex"],
            id_number=dev["device_no"],  # BYPASS-1：18 字符登记号充 id_number 槽
            cert_level=3,
            sn="UAS-SN-FLEET-01",
            holder_pub_hex=pk,
            operator_org_id=None,  # 匿名路径（域门无操作者可比）
        )
    assert ei.value.code == "not_personal_credential"
    assert ei.value.status == 409


def test_review1_personal_endpoint_pool_quota_bypass_denied(session, monkeypatch):
    """审查①（高）旁路第二形态：同域登录席经个人端点对机队凭证连签 → 池上限
    不可被个人端点击穿（对偶拒绝先于配额——个人配额域不含机队行）。"""
    monkeypatch.setenv("FZ_FLEET_POOL_QUOTA", "2")
    s = _svc(session)
    dev = _reg_fleet(s, org="org-a")
    sk, pk = generate_keypair()
    with pytest.raises(RaError) as ei:
        s.issue_sub_credential(
            master_cred_hash_hex=dev["master_cred_hash_hex"],
            salt_hex=dev["salt_hex"],
            id_number=dev["device_no"],
            cert_level=3,
            sn="UAS-SN-FLEET-01",
            holder_pub_hex=pk,
            operator_org_id="org-a",  # 同域登录席（域门过）
        )
    assert ei.value.code == "not_personal_credential"


def test_review6_batch_register_chain_failure_compensates(session):
    """审查⑥（低）：批量登记链面非原子——第 2 台链写失败时，第 1 台已上链
    承诺必须吊销补偿（setStatus(2)——孤儿承诺不可再签发/消费），异常如实
    上抛（DB 由 get_session 回滚）。"""

    class FailingAnchor:
        def __init__(self) -> None:
            self.calls: list[tuple[str, list]] = []
            self._n = 0

        def __call__(self, fn: str, args: list) -> None:
            self.calls.append((fn, args))
            if fn == "register_commitment":
                self._n += 1
                if self._n == 2:
                    raise RuntimeError("simulated chain failure on 2nd device")

    ra_priv, ra_pub = generate_keypair()
    anchor = FailingAnchor()
    s2 = RaService(
        session, RaDeps(ra_priv_hex=ra_priv, ra_pub_hex=ra_pub, anchor=ChainAnchor(call=anchor))
    )
    with pytest.raises(RuntimeError, match="simulated chain failure"):
        s2.register_fleet_devices(
            operator_org_id="org-a",
            devices=[
                _device(no="FZ-DEV-000001B0001", sn="UAS-SN-RV6-1"),
                _device(no="FZ-DEV-000001B0002", sn="UAS-SN-RV6-2"),
            ],
        )
    # 补偿面：第 1 台的句柄已收到 setStatus(2)（孤儿承诺吊销——不可再签发）
    set_status_calls = [c for c in anchor.calls if c[0] == "set_status"]
    assert len(set_status_calls) == 1
    h1 = set_status_calls[0][1][0]
    assert isinstance(h1, str) and h1.startswith("0x")
    reg_handles = [c[1][0] for c in anchor.calls if c[0] == "register_commitment"]
    assert h1 == reg_handles[0]  # 补偿的正是已上链的第 1 台
    assert set_status_calls[0][1][1] == 2
    # DB 回滚由 get_session 承担（HTTP 面）；直调形态以显式 rollback 等价模拟
    # ——回滚后零机队行残留（未提交事务内的行不落库）。
    session.rollback()
    assert len(s2._s.scalars(select(Credential).where(Credential.cred_kind == 2)).all()) == 0


def test_review8_fleet_issue_unresolved_org_structural(session):
    """审查⑧（观察→钉面）：机队行 owner_org_id 缺失=结构不变式破坏 → 409
    fleet_org_unresolved（与受理门同码——域门判据自身受损时错误码不再靠
    `or DEFAULT_ORG` 兜成跨域 403 语义）。"""
    s = _svc(session)
    dev = _reg_fleet(s, org="org-a")
    cred = s._s.scalar(
        select(Credential).where(Credential.master_cred_hash_hex == dev["master_cred_hash_hex"])
    )
    cred.owner_org_id = None  # 结构破坏注入（唯一写路径恒写列——仅直改库可达）
    session.commit()
    sk, pk = generate_keypair()
    with pytest.raises(RaError) as ei:
        s.issue_fleet_sub_credentials(
            operator_org_id="org-a",
            items=[
                {
                    "master_cred_hash_hex": dev["master_cred_hash_hex"],
                    "salt_hex": dev["salt_hex"],
                    "holder_pub_hex": pk,
                }
            ],
        )
    assert ei.value.code == "fleet_org_unresolved"
    assert ei.value.status == 409
