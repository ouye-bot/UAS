"""B3 感知链路人话化：回执 failed 态携带拒绝理由（reject_reason/reject_code）。

被吊销飞手最常见断链的收尾面：worker 把人话判词（rev_root_moved/
nonce_conflict/…）写进 Application.reject_reason，但回执端点此前只吐
status——飞手只看到「验证拒绝」。本面钉定：failed 态响应新增
reject_reason（原文）与 reject_code（前缀稳定码），ready/waiting 形态
零变化（加字段不破既有）。
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz import service
from app.authz.models import Application, Receipt
from app.ra.models import Base


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _failed_pair(session, reason: str) -> Receipt:
    app_row = Application(
        session_pk_hex="11" * 64,
        sub_sig_hex="22" * 64,
        sub_cred_hash_hex="33" * 32,
        nonce_hex="44" * 16,
        plan_hash_hex="55" * 32,
        class_id=1,
        rev_root_hex="00" * 32,
        policy_version="policy-test",
        status="rejected",
        reject_reason=reason,
    )
    receipt = Receipt(code_hex=_code(), application_id=0, status="failed")
    session.add(app_row)
    session.add(receipt)
    session.flush()
    receipt.application_id = app_row.id
    app_row.receipt_id = receipt.id
    session.commit()
    return receipt


_code_n = [0]


def _code() -> str:
    _code_n[0] += 1
    return format(_code_n[0], "032x")


def test_receipt_failed_carries_reject_reason(session):
    """rev_root_moved（验证窗内吊销生效——被吊销主路径）：回执带原文+稳定码。"""
    r = _failed_pair(
        session, "rev_root_moved: 撤销根在验证窗内更迭（吊销已生效）——请刷新见证重新出证"
    )
    out = service.receipt_of(session, r.code_hex)
    assert out["status"] == "failed"
    assert out["reject_code"] == "rev_root_moved"
    assert out["reject_reason"].startswith("rev_root_moved")
    assert "吊销已生效" in out["reject_reason"]


def test_receipt_failed_nonce_conflict_code(session):
    r = _failed_pair(
        session,
        "nonce_conflict: 链上 nonce 已被消耗且非本申请令牌——请换 nonce 重新出证",
    )
    out = service.receipt_of(session, r.code_hex)
    assert out["reject_code"] == "nonce_conflict"


def test_receipt_failed_free_text_falls_back_to_verify_rejected(session):
    """自由文本（zkc 退出日志/transient 尾巴）不伪造业务码——统一归
    verify_rejected，不冒充吊销语义。"""
    for reason in (
        "zkc verify exit 1: some internal log tail",
        "transient x3: chain timeout",
        "",
    ):
        r = _failed_pair(session, reason)
        out = service.receipt_of(session, r.code_hex)
        assert out["reject_code"] == "verify_rejected"
        assert out["reject_reason"] == reason


def test_receipt_waiting_and_ready_shape_unchanged(session):
    """waiting/ready 响应零变化（加字段不破既有消费面）：
    waiting 无 reject 字段；ready 仍只有 token_cipher_hex。"""
    from app.crypto.sm2 import generate_keypair as _gen_kp

    app_row = Application(
        session_pk_hex=_gen_kp()[1],
        sub_sig_hex="22" * 64,
        sub_cred_hash_hex="33" * 32,
        nonce_hex="44" * 16,
        plan_hash_hex="55" * 32,
        class_id=1,
        rev_root_hex="00" * 32,
        policy_version="policy-test",
        status="pending",
    )
    waiting = Receipt(code_hex=_code(), application_id=0, status="waiting")
    session.add(app_row)
    session.add(waiting)
    session.flush()
    waiting.application_id = app_row.id
    app_row.receipt_id = waiting.id
    session.commit()
    out = service.receipt_of(session, waiting.code_hex)
    assert out == {"status": "waiting"}
    service.seal_receipt(session, waiting.id, "{}", "aa" * 32, app_row.session_pk_hex)
    out2 = service.receipt_of(session, waiting.code_hex)
    assert out2["status"] == "ready"
    assert "token_cipher_hex" in out2
    assert "reject_reason" not in out2 and "reject_code" not in out2
