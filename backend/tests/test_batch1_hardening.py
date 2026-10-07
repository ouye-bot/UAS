"""批1 飞行强制与取证面硬化（2026-10-04）：/authz/status 预检面 + 演示围栏收窄。

覆盖：
- GET /authz/status 三形态（real-active / real-revoked / chain-unreachable 503 /
  auth_not_found 404 / fake 档如实自报）+ token_consumed 服务端消费账本标志（S1 根修语义：签发≠消费）；
- 演示围栏收窄（1.7+盲审二轮整改 2026-10-04）：FENCE_RECTS=单一演示空域
  （S4 合成场已迁至 SITL 原点近旁——同在南半球）、四界对两场余量 ≥0.5°、
  纬/经界各自同半球（矩形不再横跨赤道）。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.db as db_mod
from app.chain.client import ChainError
from app.main import create_app
from app.ra.models import Base


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    db_file = tmp_path / "b1.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = db_mod.sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    with TestClient(create_app()) as c:
        yield c


def _seed_auth_record(
    token_hash_hex: str, auth_id: int = 7, *, consumed: bool = False, sorties: int = 1
) -> None:
    import datetime as _dt

    from app.authz.models import AuthRecord

    s = db_mod.SessionLocal()
    try:
        s.add(
            AuthRecord(
                auth_id=auth_id,
                application_id=1,
                token_hash_hex=token_hash_hex,
                proof_digest_hex="ee" * 32,
                token_consumed_ts=_dt.datetime.utcnow() if consumed else None,
                # 配额账本（授权包配额制）：consumed 态=配额耗尽（remaining=0）
                sorties=sorties,
                remaining=0 if consumed else sorties,
            )
        )
        s.commit()
    finally:
        s.close()


class _StubBinding:
    """链 binding 替身：getAuth/revEpoch 脚本化（批1-1.1 三形态注入）。"""

    def __init__(self, statuses: dict[int, int], rev_epoch: int = 43, fail: str | None = None):
        self.statuses = statuses
        self.rev_epoch = rev_epoch
        self.fail = fail

    def call_fn(self, fn: str, args: list):
        if self.fail:
            raise ChainError(self.fail)
        if fn == "getAuth":
            aid = int(args[0])
            if aid not in self.statuses:
                raise ChainError("VM exe error: bad authId")  # 合约 require 形态
            # 12 元组（授权包配额制：末位 remaining——链上权威配额值）
            return [b"\x11" * 32, b"\x22" * 16, 0, 50, 1, 2,
                    b"\x33" * 32, b"\x44" * 32, self.statuses[aid], 0, 1790000000, 1]
        if fn == "revEpoch":
            return [self.rev_epoch]
        raise AssertionError(f"stub 未脚本化的调用: {fn}")


# ---- /authz/status：fake 档 ----


def test_authz_status_fake_mode_self_reports(client):
    r = client.get("/authz/status", params={"auth_id": 7, "token_hash_hex": "ab" * 32})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["mode"] == "fake" and d["status"] is None and d["rev_epoch"] is None
    assert d["token_consumed"] is False, "假链档无消费回报=未消费"


def test_authz_status_token_consumed_from_auth_records(client):
    _seed_auth_record("ab" * 32, consumed=True)
    r = client.get("/authz/status", params={"auth_id": 7, "token_hash_hex": "AB" * 32})
    assert r.json()["data"]["token_consumed"] is True, "大小写归一后按消费账本命中"
    r2 = client.get("/authz/status", params={"auth_id": 7, "token_hash_hex": "cd" * 32})
    assert r2.json()["data"]["token_consumed"] is False
    r3 = client.get("/authz/status", params={"auth_id": 7})  # 缺 hash=只查链面
    assert r3.json()["data"]["token_consumed"] is False


# ---- /authz/status：real 档三形态 ----


def test_authz_status_real_active(client, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    from app.authz import router as ar

    monkeypatch.setattr(ar, "_chain_binding", lambda name: _StubBinding({7: 0}))
    r = client.get("/authz/status", params={"auth_id": 7, "token_hash_hex": "ab" * 32})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["mode"] == "real" and d["status"] == 0 and d["rev_epoch"] == 43
    assert d["token_consumed"] is False


def test_authz_status_real_revoked_reports_nonzero(client, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    from app.authz import router as ar

    monkeypatch.setattr(ar, "_chain_binding", lambda name: _StubBinding({7: 1}))
    r = client.get("/authz/status", params={"auth_id": 7})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["mode"] == "real" and d["status"] == 1, "撤销态如实回读（桥端据此拒绝 ARM）"


def test_authz_status_chain_unreachable_503_envelope(client, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    from app.authz import router as ar

    monkeypatch.setattr(
        ar, "_chain_binding", lambda name: _StubBinding({}, fail="RPC 连接失败: conn refused")
    )
    r = client.get("/authz/status", params={"auth_id": 7})
    assert r.status_code == 503, "链不可达=503 信封（桥端 fail-closed 拒绝解锁）"
    body = r.json()
    assert body["ok"] is False and body["code"] == "chain_unavailable"


def test_authz_status_auth_not_found_404(client, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    from app.authz import router as ar

    monkeypatch.setattr(ar, "_chain_binding", lambda name: _StubBinding({}))  # 空=不在案
    r = client.get("/authz/status", params={"auth_id": 99})
    assert r.status_code == 404
    body = r.json()
    assert body["ok"] is False and body["code"] == "auth_not_found"


# ---- 1.7 演示围栏收窄 ----

# ArduPilot SITL 缺省 home（WSL 侧 /home/ouye 起建——南半球负纬度实弹路径）
SITL_HOME = (-353_632_620, 1_491_652_370)
# S4 合成场采样界（scripts/scenario_S4_trail.py：lat -345000000+i*11、
# lon 1500000000+i*7，i<130——2026-10-04 盲审二轮整改：合成场迁至 SITL 原点
# 近旁 -34.5°/150.0°E，同在南半球、相距≈1.1°；旧北半球场 39.900N/116.300E 已废）
S4_FIELD_MAX = (-344_998_581, 1_500_000_903)
MARGIN_1E7 = 5_000_000  # 0.5° 半径余量（1e-7°/unit——5_000_000×1e-7=0.5°，
                        # 换代前误写 500_000=0.05°，与本文件及 policy.py 声明的
                        # 「≥0.5°」口径不符；现按声明语义实钉）


def test_policy_fence_rects_cover_demo_fields_with_margin():
    from app.authz.policy import get_fence

    for cid in (0, 1):
        min_lat, max_lat, min_lon, max_lon = get_fence(cid)
        for lat, lon in (SITL_HOME, S4_FIELD_MAX):
            assert min_lat <= lat - MARGIN_1E7, f"class {cid}: 南界余量 <0.5°"
            assert max_lat >= lat + MARGIN_1E7, f"class {cid}: 北界余量 <0.5°"
            assert min_lon <= lon - MARGIN_1E7, f"class {cid}: 西界余量 <0.5°"
            assert max_lon >= lon + MARGIN_1E7, f"class {cid}: 东界余量 <0.5°"


def test_policy_fence_rects_no_hemisphere_spanning_placeholder():
    """收窄断言：矩形不得横跨半球（盲审二轮实锤：旧 -36°~40.5°N 一张矩形
    同时罩住南半球 SITL 原点与北半球 S4 旧场——地理约束形同虚设）。"""
    from app.authz.policy import FENCE_RECTS

    for cid, rect in FENCE_RECTS.items():
        min_lat, max_lat, min_lon, max_lon = rect
        span_lat = max_lat - min_lat
        span_lon = max_lon - min_lon
        assert span_lat <= 800_000_000, f"class {cid}: 纬度跨度 {span_lat / 1e7:.1f}° 仍近跨半球"
        assert span_lon <= 600_000_000, f"class {cid}: 经度跨度 {span_lon / 1e7:.1f}° 过宽"
        # 同半球硬界：纬度 4 界不得横跨赤道（min_lat/max_lat 同号），经度
        # 4 界同处东经（min_lon/max_lon 同号）——单一演示空域的地理一致性。
        assert min_lat * max_lat > 0, f"class {cid}: 纬度界横跨赤道（{min_lat}~{max_lat}）"
        assert min_lon * max_lon > 0, f"class {cid}: 经度界横跨 0°/180° 经线（{min_lon}~{max_lon}）"
        # 矩形须实际覆盖两演示场（收窄≠漏场）
        for lat, lon in (SITL_HOME, S4_FIELD_MAX):
            assert rect[0] <= lat <= rect[1] and rect[2] <= lon <= rect[3]


def test_policy_params_hash_unchanged_by_fence_rects():
    """围栏收窄不得改动 paramsHash（政策表主体=高度/资质；围栏授权锚=引擎
    签名——policy.py 既有声明；链上已公示版本持续有效）。"""
    # 已发布口径指纹（policy-2026-09-v1：CLASS_RULES 0/1 两档）——围栏不在
    # 指纹域内，本测试钉定「改 FENCE_RECTS 不动指纹」的承诺。
    from app.authz.policy import CLASS_RULES, POLICY_VERSION, policy_params_hash
    from app.crypto.sm3 import sm3_bytes

    buf = POLICY_VERSION.encode()
    for cid in sorted(CLASS_RULES):
        alt, req = CLASS_RULES[cid]
        buf += bytes([cid]) + alt.to_bytes(2, "big") + bytes([req])
    assert policy_params_hash() == sm3_bytes(buf).hex()


def test_authz_consume_endpoint_ledger(client):
    """S1 根修配套：/authz/consume 消费回报——引擎面恒时守卫/配额递减/404
    fail-closed。授权包配额制（2026-10-06）：缺省配额 1 首报即终态（与令牌
    一次性逐字等价）；耗尽后再报=409 quota_exhausted。"""
    import os as _os

    _seed_auth_record("9a" * 32, auth_id=77)
    # ① 无引擎令牌=401
    r0 = client.post(
        "/authz/consume", json={"auth_id": 77, "token_hash_hex": "9a" * 32}
    )
    assert r0.status_code == 401
    # ② 带令牌首报=first=True 且配额归零（缺省 1=终态）
    _os.environ["FZ_ENGINE_TOKEN"] = "test-engine-tok"
    try:
        h = {"X-Engine-Token": "test-engine-tok"}
        r1 = client.post(
            "/authz/consume", json={"auth_id": 77, "token_hash_hex": "9a" * 32}, headers=h
        )
        assert r1.status_code == 200
        assert r1.json()["data"] == {"first": True, "consumed": True, "remaining": 0}
        # ③ 配额耗尽后再报=409 quota_exhausted（幂等语义换代：remaining 递减至
        # 0 后拒绝——桥端视作已入账终态弃重试）
        r2 = client.post(
            "/authz/consume", json={"auth_id": 77, "token_hash_hex": "9a" * 32}, headers=h
        )
        assert r2.status_code == 409 and r2.json()["code"] == "quota_exhausted"
        # ④ 消费后 status 反映 token_consumed=True
        r3 = client.get("/authz/status", params={"auth_id": 77, "token_hash_hex": "9a" * 32})
        assert r3.json()["data"]["token_consumed"] is True
        assert r3.json()["data"]["remaining"] == 0
        # ⑤ 未知令牌=404 fail-closed
        r4 = client.post(
            "/authz/consume", json={"auth_id": 77, "token_hash_hex": "bb" * 32}, headers=h
        )
        assert r4.status_code == 404
    finally:
        del _os.environ["FZ_ENGINE_TOKEN"]


def test_authz_consume_quota_pack_k3(client):
    """授权包配额制核心语义（2026-10-06 拍板）：K=3 三连发——首报 remaining=2
    （first=True、未终态）；第二报 remaining=1；第三报 remaining=0 且
    token_consumed 置位（最后一次架次的回报才置终态）；第四发=409
    quota_exhausted（配额耗尽拒绝）。"""
    import os as _os

    _seed_auth_record("3d" * 32, auth_id=91, sorties=3)
    _os.environ["FZ_ENGINE_TOKEN"] = "test-engine-tok"
    try:
        h = {"X-Engine-Token": "test-engine-tok"}
        # 首报前：在案未消费=token_consumed False（签发≠消费）
        s0 = client.get("/authz/status", params={"auth_id": 91, "token_hash_hex": "3d" * 32})
        assert s0.json()["data"]["token_consumed"] is False
        assert s0.json()["data"]["remaining"] == 3 and s0.json()["data"]["sorties"] == 3
        r1 = client.post(
            "/authz/consume", json={"auth_id": 91, "token_hash_hex": "3d" * 32}, headers=h
        )
        assert r1.json()["data"] == {"first": True, "consumed": False, "remaining": 2}
        # 首报后未终态：token_consumed 仍 False（消费判词=配额归零才置位）
        s1 = client.get("/authz/status", params={"auth_id": 91, "token_hash_hex": "3d" * 32})
        assert s1.json()["data"]["token_consumed"] is False
        assert s1.json()["data"]["remaining"] == 2
        r2 = client.post(
            "/authz/consume", json={"auth_id": 91, "token_hash_hex": "3d" * 32}, headers=h
        )
        assert r2.json()["data"] == {"first": False, "consumed": False, "remaining": 1}
        r3 = client.post(
            "/authz/consume", json={"auth_id": 91, "token_hash_hex": "3d" * 32}, headers=h
        )
        assert r3.json()["data"] == {"first": False, "consumed": True, "remaining": 0}
        s2 = client.get("/authz/status", params={"auth_id": 91, "token_hash_hex": "3d" * 32})
        assert s2.json()["data"]["token_consumed"] is True
        r4 = client.post(
            "/authz/consume", json={"auth_id": 91, "token_hash_hex": "3d" * 32}, headers=h
        )
        assert r4.status_code == 409 and r4.json()["code"] == "quota_exhausted"
    finally:
        del _os.environ["FZ_ENGINE_TOKEN"]


def test_authz_consume_default_single_equiv(client):
    """缺省配额 1 等价性：单报即终态（first=True/consumed=True/remaining=0）
    ——与令牌一次性历史语义逐字等价（既有 e2e 全绿为证）。"""
    import os as _os

    _seed_auth_record("7e" * 32, auth_id=92, sorties=1)
    _os.environ["FZ_ENGINE_TOKEN"] = "test-engine-tok"
    try:
        h = {"X-Engine-Token": "test-engine-tok"}
        r = client.post(
            "/authz/consume", json={"auth_id": 92, "token_hash_hex": "7e" * 32}, headers=h
        )
        assert r.json()["data"] == {"first": True, "consumed": True, "remaining": 0}
        s = client.get("/authz/status", params={"auth_id": 92, "token_hash_hex": "7e" * 32})
        assert s.json()["data"]["token_consumed"] is True
        assert s.json()["data"]["remaining"] == 0 and s.json()["data"]["sorties"] == 1
    finally:
        del _os.environ["FZ_ENGINE_TOKEN"]


def test_authz_status_issued_not_consumed(client):
    """签发≠消费（S1 2.2 实弹缺陷的反向钉定）：auth_records 在案但未回报
    消费 ⟹ token_consumed=False——正常首次 ARM 不再被误拒。"""
    _seed_auth_record("5c" * 32, auth_id=78)  # 默认 consumed=False
    r = client.get("/authz/status", params={"auth_id": 78, "token_hash_hex": "5c" * 32})
    assert r.json()["data"]["token_consumed"] is False, "在案未消费=未消费（旧语义此处置 True 致首 ARM 必拒）"
