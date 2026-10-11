"""D4 链上叫停公示（2026-10-12 修整窗口——完整性审计 D 类④根修）。

缺口：监管叫停某授权（凭证吊销联动 revokeAuth）后，Application.status 仍是
approved 且 /chain/panel、/chain/record 只回 DB 状态 ⟹ 公示面恒显「已批准」
——与口径卡 E.5「监管叫停=受理/锚定/解锁三面即时收敛」在公示面相悖；
ChainView 的 revoked 映射是死键（后端从未供给）。

修法：/chain/panel 记录行附 chain_halted（DB 联动台账派生——RevocationLedger
.detail 的 linked_auth_ids + link_skipped 中「链上已是撤销态」项，append-only
台账与链写同事务落地，零额外链读）；/chain/record 真链档附 chain.status
（getAuth 第 9 位原样回传）。先红：旧行无 chain_halted 字段。
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.chain.panel as panel
import app.telemetry.models  # noqa: F401
from app.authz.models import Application, AuthRecord
from app.db import get_session
from app.main import create_app
from app.ra.models import Base, RevocationLedger


@pytest.fixture()
def halt(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/halt.db")
    Base.metadata.create_all(eng)
    import app.authz.models as _am  # noqa: F401

    _am.Base.metadata.create_all(eng)
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
    # panel 读面走 from app.db import SessionLocal 直引——patch 模块名
    # （test_chain_panel.detail_client 同款工艺）
    monkeypatch.setattr(panel, "SessionLocal", TestSession)
    with TestClient(app) as c:
        gen = c.app.dependency_overrides[get_session]()
        s = next(gen)
        try:
            for auth_id in (7001, 7002, 7003):
                app_row = Application(
                    session_pk_hex="11" * 64,
                    sub_sig_hex="00" * 64,
                    sub_cred_hash_hex=f"{auth_id:064x}",
                    nonce_hex="22" * 16,
                    plan_hash_hex="33" * 32,
                    class_id=1,
                    policy_version="test",
                    rev_root_hex="00" * 32,
                    status="approved",
                )
                s.add(app_row)
                s.flush()
                app_row.auth_id = auth_id
                s.add(
                    AuthRecord(
                        auth_id=auth_id,
                        application_id=app_row.id,
                        token_hash_hex="44" * 32,
                        proof_digest_hex="55" * 32,
                    )
                )
            s.add(
                RevocationLedger(
                    action="revoke",
                    actor="admin",
                    subject_hex="ff" * 32,
                    reason="围栏违规成立",
                    sig_hex="00" * 64,
                    epoch=7,
                    detail=json.dumps(
                        {
                            "handles": ["ff" * 32],
                            "linked_auth_ids": [7001],
                            "link_skipped": [
                                {
                                    "auth_id": 7002,
                                    "ok": False,
                                    "detail": "链上已是撤销态（status=2）——如实跳过",
                                },
                            ],
                        },
                        ensure_ascii=False,
                    ),
                )
            )
            s.commit()
        finally:
            gen.close()
        yield c


def test_panel_records_carry_chain_halted(halt):
    """/chain/panel 记录行附 chain_halted：联动叫停（7001）/紧急禁飞先行叫停
    （7002——link_skipped 撤销态）/未叫停（7003=False）。先红：旧行无此字段。"""
    data = halt.get("/chain/panel").json()["data"]
    halted = {r["auth_id"]: r["chain_halted"] for r in data["records"]}
    assert halted[7001] is True, halted
    assert halted[7002] is True, halted
    assert halted[7003] is False, halted


def test_halted_not_persisted_on_application_status(halt):
    """诚实边界钉面：叫停不改写 Application.status（受理面状态与公示叫停态
    分立——本测试锁死「叫停=公示面标注」而非「改库」，防两态混写回归）。"""
    gen = halt.app.dependency_overrides[get_session]()
    s = next(gen)
    try:
        from sqlalchemy import select

        rows = s.scalars(select(Application)).all()
        assert all(r.status == "approved" for r in rows)
    finally:
        gen.close()
