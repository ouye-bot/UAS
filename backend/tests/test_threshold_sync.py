"""1.3 份额刷新联动单测（TDD——先红后绿）。

四件验收面：
① owner_set_fp 指纹门：携错 fp 的 ceremonial_reshare 即拒（fingerprint_
   mismatch，零持久变更）；携对 fp 过门并绑定写盘；不带 fp=门跳过（audit
   行 fp_source=skipped 如实——单测直调形态兼容，生产仪式驱动方恒携）；
② watcher 漂移检测：链上 owner-set 指纹≠份额域绑定→drift 判定+红牌落盘
   （sync_state.json）+自动起草 reshare 提案（幂等：已起草不再重复）；
③ 失同步拒解锁：hooks 注入 owner_set_synced=False→request_decrypt_share
   拒（decision 行 denied:owner_set_synced）——止损从『记得做』变『不做不行』；
④ owner_set_synced 真实现判定：domain 无 fp+链可用→惰性绑定 True；绑定后
   漂移→False；fake 档 fail-closed False。
隔离纪律同 test_threshold_envelope：FZ_THRESHOLD_ROOT_DIR→tmp；链读一律
monkeypatch 注入（零真链依赖——实弹在 scripts/threshold_sync_drill.py）。
"""

from __future__ import annotations

import json

import pytest

from app.authz.service import threshold_wrap, unwrap_any
from app.ra import threshold_shares as ts
from app.ra import threshold_sync as sync


@pytest.fixture()
def fresh_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(tmp_path / "threshold_root"))
    return ts.initialize_if_absent()


CHAIN_FP_A = "aa" * 32
CHAIN_FP_B = "bb" * 32


def _chain(fp: str, owners: list[str] | None = None, required: int = 2):
    """链读替位（形态=chain_owner_set 返回契约）。"""
    return lambda: {
        "fp_hex": fp,
        "owners": owners or ["0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20],
        "required": required,
    }


def _all_true_hooks() -> dict:
    return {
        "request_registered": lambda *a: True,
        "warrant_on_chain": lambda *a: True,
        "collab_approved": lambda *a: True,
    }


def _ctx() -> dict:
    return {
        "warrant_hash_hex": "aa" * 32,
        "cred_hash_hex": "bb" * 32,
        "request_sha256_hex": "cc" * 32,
    }


def _meta() -> dict:
    return json.loads((ts._root_dir() / "root.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- 件① 指纹门


def test_fingerprint_gate_mismatch_rejects(fresh_root, monkeypatch):
    """携错误 owner-set 指纹的 re-share 即拒（零持久变更——提案/执行窗内
    owner-set 再漂移=提案作废须重新起草，仪式不被陈旧指纹驱动）。"""
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_B))
    before = (ts._root_dir() / "root.json").read_text(encoding="utf-8")
    with pytest.raises(ts.ShareDomainError) as ei:
        ts.ceremonial_reshare(gov_confirmed_epoch=2, owner_set_fp=CHAIN_FP_A)
    assert ei.value.code == "fingerprint_mismatch"
    assert (ts._root_dir() / "root.json").read_text(encoding="utf-8") == before


def test_fingerprint_gate_match_binds(fresh_root, monkeypatch):
    """携对 fp 过门：仪式完成且 root.json.owner_set_fp=链上指纹（绑定写盘）。"""
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_A))
    r = ts.ceremonial_reshare(gov_confirmed_epoch=2, owner_set_fp=CHAIN_FP_A)
    assert r["epoch"] == 2
    assert _meta()["owner_set_fp"] == CHAIN_FP_A


def test_fingerprint_gate_absent_skips_and_audits(fresh_root):
    """不带 fp=门跳过（单测直调形态兼容——非放行：audit 行 fp_source=skipped
    如实在案，meta 不写 fp 保持未绑定）。生产仪式驱动方恒携（脚本/API）。"""
    r = ts.ceremonial_reshare(gov_confirmed_epoch=2)
    assert r["epoch"] == 2
    assert _meta().get("owner_set_fp") in (None, "")
    rows = [json.loads(x) for x in ts._audit_path("admin").read_text(encoding="utf-8").splitlines()]
    reshare_rows = [x for x in rows if x["action"] == "reshare"]
    assert reshare_rows and reshare_rows[-1].get("fp_source") == "skipped"


# ---------------------------------------------------------------- 件④ 失同步拒解锁


def test_sync_gate_denies_unlock(fresh_root, monkeypatch):
    """失同步期间 fail-closed 拒解锁（第④关：三关全过+owner_set_synced=False
    ⟹ 份额域拒——止损从『记得做』变『不做不行』）。"""
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_A))
    sync.bind_domain_fp(CHAIN_FP_A)  # 绑定后漂移
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_B))  # 除名→漂移
    plaintext = b"unlock-denied-case"
    blob = threshold_wrap(plaintext)
    hooks = {
        **_all_true_hooks(),
        "owner_set_synced": lambda: sync.owner_set_synced(),
    }
    from app.authz.service import AuthzError

    with pytest.raises(AuthzError) as ei:
        unwrap_any(blob, share_hooks=hooks, unlock_ctx=_ctx())
    assert "owner_set_synced" in str(ei.value)  # 解锁面拒：三域同因（失同步）
    # 审计行如实：denied:owner_set_synced
    rows = [json.loads(x) for x in ts._audit_path("admin").read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["decision"] == "denied:owner_set_synced"


def test_sync_gate_passes_when_aligned(fresh_root, monkeypatch):
    """对齐态（fp 绑定=链上现状）解锁放行——第④关不误伤正常解锁。"""
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_A))
    sync.bind_domain_fp(CHAIN_FP_A)
    plaintext = b"unlock-ok-case"
    blob = threshold_wrap(plaintext)
    hooks = {
        **_all_true_hooks(),
        "owner_set_synced": lambda: sync.owner_set_synced(),
    }
    out = unwrap_any(blob, share_hooks=hooks, unlock_ctx=_ctx())
    assert out == plaintext


def test_legacy_hooks_shape_untouched(fresh_root):
    """旧三键 hooks 注入形态（既有测试组/调用方）零破坏——第④关缺席即跳过
    （真实现 _default_hooks 恒含，跳过仅限替位注入形态）。"""
    plaintext = b"legacy-shape"
    blob = threshold_wrap(plaintext)
    out = unwrap_any(blob, share_hooks=_all_true_hooks(), unlock_ctx=_ctx())
    assert out == plaintext


# ---------------------------------------------------------------- 件② watcher


def test_watcher_drift_red_flag_and_draft(fresh_root, monkeypatch):
    """漂移检测：链上 fp≠域绑定→drift+红牌落盘（sync_state.json）+自动起草
    提案（幂等：已起草状态重复轮询不再重复起草）。"""
    sync.bind_domain_fp(CHAIN_FP_A)
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_B))  # 除名→漂移
    drafted = {"n": 0}

    def _fake_draft():
        drafted["n"] += 1
        return {"action": "drafted", "proposal_id": 7, "version": "threshold-epoch-2"}

    monkeypatch.setattr(sync, "draft_reshare_proposal", _fake_draft)
    r1 = sync.run_sync_check_once()
    assert r1["synced"] is False and r1["action"] == "drafted"
    state = json.loads((ts._root_dir() / "sync_state.json").read_text(encoding="utf-8"))
    assert state["drift"] is True and state["drafted_proposal_id"] == 7
    r2 = sync.run_sync_check_once()
    assert r2["action"] == "already_drafted" and drafted["n"] == 1  # 幂等


def test_watcher_aligned_no_draft(fresh_root, monkeypatch):
    """对齐态轮询：无红牌无起草（零动作）。"""
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_A))
    sync.bind_domain_fp(CHAIN_FP_A)
    r = sync.run_sync_check_once()
    assert r["synced"] is True and r["action"] == "ok"
    assert not (ts._root_dir() / "sync_state.json").exists()


def test_watcher_drift_cleared_on_reshare(fresh_root, monkeypatch):
    """re-share 对齐后红牌解除（sync_state 归零——解锁恢复面）。"""
    sync.bind_domain_fp(CHAIN_FP_A)
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_B))
    monkeypatch.setattr(
        sync,
        "draft_reshare_proposal",
        lambda: {"action": "drafted", "proposal_id": 1, "version": "threshold-epoch-2"},
    )
    sync.run_sync_check_once()
    assert json.loads((ts._root_dir() / "sync_state.json").read_text(encoding="utf-8"))["drift"]
    # 重分割完成=域 fp 换绑到链上现状
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_A))
    r = sync.run_sync_check_once()
    assert r["synced"] is True and r["action"] == "ok"
    final = json.loads((ts._root_dir() / "sync_state.json").read_text(encoding="utf-8"))
    assert final["drift"] is False


# ---------------------------------------------------------------- 件③ API 服务函数


def test_propose_and_reshare_version_exists_idempotent(fresh_root, monkeypatch):
    """幂等：链上已有本纪元公示行（version exists）→拒绝重放（409 族），
    零提案零写面（governor propose 不被调用）。"""
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_A))

    class _FakePR:
        def call_fn(self, fn, args):
            assert fn == "getPolicy"
            return [b"\x01" * 32, 12345]  # version 已存在

        def decode_logs(self, receipt):  # pragma: no cover — 不应到达
            raise AssertionError("重放不应发起提案")

    class _FakeGov:
        def send_fn(self, *a, **k):  # pragma: no cover — 不应到达
            raise AssertionError("重放不应发起提案")

    with pytest.raises(sync.SyncError) as ei:
        sync.propose_and_reshare(gov=_FakeGov(), pr=_FakePR())
    assert ei.value.code == "reshare_already_published"


def test_owner_set_synced_lazy_bind(fresh_root, monkeypatch):
    """owner_set_synced 真实现判定：未绑定+链可用→惰性绑定 True；换 fp→False。"""
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_A))
    assert sync.owner_set_synced() is True
    assert sync.read_domain_fp() == CHAIN_FP_A  # 首次对拍即绑定
    monkeypatch.setattr(sync, "chain_owner_set", _chain(CHAIN_FP_B))
    assert sync.owner_set_synced() is False


def test_owner_set_fp_sm3_sorted_deterministic():
    """owner_set_fp=SM3(sorted(owners))：排序无关+大小写归一（任务书钉定）。"""
    a = sync.owner_set_fp_of(["0xBB", "0x AA".replace(" ", ""), "0xaa"])
    b = sync.owner_set_fp_of(["0xaa", "0xbb", "0xAA"])
    assert a == b
