"""P0-5 RA 启动自动对账测试：对账核心（可注入）+服务钩子（不阻塞启动）。

- 核心：本地吊销集 SMT 根 vs 链公示根不一致→推链（epoch+1 单调）；一致→零动作幂等
- 钩子：真链档 RA deps 初始化调用一次对账；对账异常不阻塞服务启动（首次锚定
  写面失败会诚实暴露）
- create_app 启动守卫（2026-10-01 批）：真链档启动即对账（漂移自愈后根一致/
  二次启动幂等不再推链/fake 锚不启用/对账失败不阻塞启动）
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.crypto.sm3 import sm3_bytes  # noqa: F401
from app.ra.smt import smt_root


def test_align_pushes_when_drifted():
    """链根漂移→push_fn 以 epoch+1+本地根被调用；返回 pushed=True。"""
    from app.ra.align import align_rev_root_core

    calls = []

    def epoch_fn():
        return 14

    def root_fn():
        return b"\xff" * 32  # 漂移的链上根

    def push_fn(epoch, root):
        calls.append((epoch, bytes(root)))

    out = align_rev_root_core(
        handles=[],  # 空吊销集→本地根=空树根（非零）
        epoch_fn=epoch_fn,
        root_fn=root_fn,
        push_fn=push_fn,
    )
    local_root = smt_root([])
    assert calls == [(15, local_root)], "推链须 epoch+1+本地根"
    assert out["pushed"] is True and out["epoch"] == 15


def test_align_idempotent_when_aligned():
    """链根=本地根→零动作（幂等——不产生交易）。"""
    from app.ra.align import align_rev_root_core

    local_root = smt_root([])
    calls = []

    out = align_rev_root_core(
        handles=[],
        epoch_fn=lambda: 14,
        root_fn=lambda: local_root,
        push_fn=lambda e, r: calls.append((e, r)),
    )
    assert calls == [] and out["pushed"] is False


def test_startup_hook_called_once_and_non_blocking(monkeypatch):
    """真链档 deps 初始化调用对账一次；对账异常不阻塞 deps 构建。"""
    import app.ra.align as align_mod
    import app.ra.router as ra_router

    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    calls = []

    def fake_startup_align():
        calls.append(1)

    monkeypatch.setattr(align_mod, "startup_align", fake_startup_align)
    ra_router._reset_deps_cache()
    d1 = ra_router._ra_deps()
    d2 = ra_router._ra_deps()
    assert len(calls) == 1 and d1 is d2

    # 异常不阻塞：清缓存后换抛异常实现
    calls.clear()

    def boom():
        raise RuntimeError("链不可达")

    monkeypatch.setattr(align_mod, "startup_align", boom)
    ra_router._reset_deps_cache()
    d3 = ra_router._ra_deps()  # 不抛=非阻塞成立
    assert d3 is not None and calls == []
    monkeypatch.delenv("FZ_CHAIN_ANCHOR")
    ra_router._reset_deps_cache()


# ---- create_app 启动守卫（2026-10-01 批）----


def _install_tmp_db(monkeypatch, tmp_path):
    """临时库（test_revoke_e2e_negative 同型）：守卫读取真实本地撤销镜像。"""
    import app.db as db_mod
    from app.ra.models import Base

    db_file = tmp_path / "align_guard.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = db_mod.sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)


def _fake_chain_align(handles_state):
    """状态化假链对账（mock deps——与 startup_align 同构）：本地镜像根 vs 模拟
    链上公示根；漂移即推链（epoch+1），一致零动作。返回 (impl, 观测 dict)。"""
    obs = {"pushes": 0, "epoch": 43}

    def impl():
        from app.db import SessionLocal
        from app.ra.models import Revocation

        s = SessionLocal()
        try:
            handles = [bytes.fromhex(r.handle_hex) for r in s.scalars(select(Revocation)).all()]
        finally:
            s.close()
        local_root = smt_root(handles)
        if handles_state["chain_root"] != local_root:
            handles_state["chain_root"] = local_root
            obs["epoch"] += 1
            obs["pushes"] += 1
            return {"aligned": True, "pushed": True, "epoch": obs["epoch"]}
        return {"aligned": True, "pushed": False, "epoch": obs["epoch"]}

    return impl, obs


@pytest.fixture()
def _guard_env(monkeypatch, tmp_path):
    """真链档守卫测试环境：临时库+索引器线程 no-op（hermetic——不触真链面）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "real")
    monkeypatch.setattr(
        "app.telemetry.indexer.start_background_indexer", lambda *a, **k: None
    )
    _install_tmp_db(monkeypatch, tmp_path)


def test_startup_guard_heals_drift_and_idempotent_across_starts(_guard_env, monkeypatch):
    """人为漂移（链根异源）→启动守卫对账后根一致；二次启动幂等不再推链。"""
    import app.ra.align as align_mod
    from app.db import SessionLocal
    from app.main import create_app
    from app.ra.models import Revocation

    # 本地镜像：一条撤销——本地根非空树根；模拟链上根=异源值（漂移场景）
    s = SessionLocal()
    try:
        s.add(Revocation(handle_hex="ab" * 32, epoch=1, reason="guard-drift-seed"))
        s.commit()
    finally:
        s.close()
    local_root = smt_root([bytes.fromhex("ab" * 32)])
    state = {"chain_root": b"\xff" * 32}
    impl, obs = _fake_chain_align(state)
    monkeypatch.setattr(align_mod, "startup_align", impl)

    create_app()  # 第一次启动：守卫推链自愈
    assert state["chain_root"] == local_root, "启动后链根须与本地镜像根一致"
    assert obs["pushes"] == 1

    create_app()  # 第二次启动：根已一致——幂等零交易
    assert obs["pushes"] == 1, "第二次启动不得再推链（幂等）"


def test_startup_guard_skipped_on_fake_anchor(monkeypatch, tmp_path):
    """fake 锚模式不启用守卫（无链面可对——零链调用）。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    import app.ra.align as align_mod
    from app.main import create_app

    calls = []
    monkeypatch.setattr(align_mod, "startup_align", lambda: calls.append(1))
    create_app()
    assert calls == [], "fake 锚档不得触发启动对账"


def test_startup_guard_failure_non_blocking(_guard_env, monkeypatch):
    """对账失败（链不可达）→WARNING 不阻塞启动——create_app 照常返回。"""
    import app.ra.align as align_mod
    from app.main import create_app

    def boom():
        raise RuntimeError("链不可达")

    monkeypatch.setattr(align_mod, "startup_align", boom)
    app = create_app()  # 不抛=非阻塞成立
    assert app is not None
