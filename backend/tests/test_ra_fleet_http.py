"""R2 审查①② HTTP 面实弹（独立审查员第二轮——先红后绿钉面）。

根因链（审查员实弹证伪根修⑥注释）：get_session=yield→commit 模式（app/db.py，
无异常即 commit）；fleet_register/fleet_sub_credentials 捕获 ChainError/RaError
后 return _deny(...)（正常响应）⟹ teardown 走 commit 分支 ⟹ 批量中途失败=HTTP
错误响应交付而 DB 部分提交：
- ①登记：链写第 N 台失败 ⟹ 库内残留 kind=2 行（含失败台）——机构收不到 salt
  回执无法签发，登记号/SN 占判重面 ⟹ 重试 409 device_exists 设备卡死；
- ②签发：第 N 张原像错 ⟹ 前 N-1 张已落库但回执丢失——无法出示消费却计入
  共享池配额 24h（幽灵占池）。

修法语义：批量=**全成全败原子**——服务层失败路径显式 session.rollback()（router
吞异常形态下 get_session 不会回滚——「等价模拟」证伪后由服务层承担），链侧孤儿
承诺补偿（根修⑥）保持。本文件=真实 create_app+TestClient+FailingAnchor 的
HTTP 面实弹（非测试内模拟 rollback）。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

os.environ["FZ_CHAIN_ANCHOR"] = "fake"
os.environ["FZ_DB_PATH_OVERRIDE"] = str(Path(__file__).parent / ".test_ra_fleet_http.db")

import app.db as db_mod  # noqa: E402
from app.main import create_app  # noqa: E402
from app.ra import router as ra_router  # noqa: E402
from app.ra.models import Base, Credential, SubCredential  # noqa: E402


class FailingChain:
    """链写失败锚：第 2 台 register_commitment 抛 ChainError（真实失败面形态）。"""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []
        self._n = 0

    def __call__(self, fn: str, args: list) -> None:
        self.calls.append((fn, args))
        if fn == "register_commitment":
            self._n += 1
            if self._n == 2:
                from app.chain.client import ChainError

                raise ChainError("simulated chain failure (R2-①)")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "ra_fleet_http_test.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    ra_router._reset_deps_cache()
    with TestClient(create_app()) as c:
        from tests.accounting import register_and_login

        register_and_login(c, "admin_r2", "admin", "Admin-Pass-1")
        yield c
    ra_router._reset_deps_cache()


def _db_rows(model):
    s = db_mod.SessionLocal()
    try:
        return s.query(model).all()
    finally:
        s.close()


_DEV = {"device_no": "FZ-DEV-R2HTTP00001", "sn": "UAS-SN-R2-1", "cert_level": 3, "class_id": 1}
_DEV2 = {"device_no": "FZ-DEV-R2HTTP00002", "sn": "UAS-SN-R2-2", "cert_level": 3, "class_id": 1}


def test_review_r2_1_http_register_chain_failure_zero_db_rows(client, monkeypatch):
    """审查 R2①（高）：批量登记第 2 台链写失败 → HTTP 503 交付后库内**零** kind=2
    行（全成全败原子——先红=残留 2 行 status=1 有效）。"""
    monkeypatch.setattr(ra_router, "_FakeChain", FailingChain)
    ra_router._reset_deps_cache()
    r = client.post("/ra/fleet/devices", json={"devices": [_DEV, _DEV2]})
    assert r.status_code == 503, r.text[:200]
    assert r.json()["code"] == "chain_unavailable"
    rows = _db_rows(Credential)
    fleet_rows = [x for x in rows if x.cred_kind == 2]
    assert fleet_rows == [], (
        f"HTTP 面部分提交实锤：库内残留 {len(fleet_rows)} 行 kind=2"
        f"（{[x.device_no for x in fleet_rows]}）——登记号/SN 占判重面+回执丢失"
    )


def test_review_r2_2_http_issue_partial_failure_no_ghost_rows(client):
    """审查 R2②（高）：批量签发『2 好+1 坏盐』→ HTTP 403 交付后 sub_credentials
    零幽灵行（先红=2 行 consumed=False 占共享池配额 24h 且回执丢失）；重试全好
    3 张成功（池未被幽灵占用）。"""
    ra_router._reset_deps_cache()
    r = client.post("/ra/fleet/devices", json={"devices": [_DEV, _DEV2]})
    assert r.status_code == 200, r.text[:200]
    devs = r.json()["data"]["devices"]
    sk, pk = __import__("app.crypto.sm2", fromlist=["generate_keypair"]).generate_keypair()
    items = [
        {
            "master_cred_hash_hex": d["master_cred_hash_hex"],
            "salt_hex": d["salt_hex"],
            "holder_pub_hex": pk,
        }
        for d in devs
    ]
    bad = dict(items[0])
    bad["salt_hex"] = "00" * 16  # 第 3 张原像错
    r2 = client.post("/ra/fleet/sub-credentials", json={"items": [*items, bad]})
    assert r2.status_code == 403 and r2.json()["code"] == "bad_preimage", r2.text[:200]
    ghosts = [x for x in _db_rows(SubCredential) if not x.consumed]
    assert ghosts == [], (
        f"幽灵签发实锤：库内残留 {len(ghosts)} 行未消费子凭证（回执随错误响应丢失——"
        "无法出示消费却计入共享池配额 24h）"
    )
    # 重试全好 3 张成功（第 3 张=设备 1 第二张——共享池未被幽灵占用）
    r3 = client.post("/ra/fleet/sub-credentials", json={"items": [*items, dict(items[0])]})
    assert r3.status_code == 200 and len(r3.json()["data"]["items"]) == 3, r3.text[:200]
