"""批 4-4 构型 profile 单源测试：三档取值表断言 + 缺省档与现网逐 env 等价。

覆盖面：
- release-demo（缺省）：allow 旗标+电路身份键（SM3_LUT/PCS_*）强制注入；
  RAYON/大栈/禁 spec 私钥 setdefault 语义（显式 env 优先——运维可覆盖）
- dev：仅强制 allow 旗标；开发者显式构型 env 全部尊重；缺省供值兜底
- pinned：零隐式注入——构型键须 env 显式齐备，缺一即人话拒绝列缺项
- 缺省等价断言：release-demo 产出 env ⊇ 旧逐 env 拼装形态（allow 旗标强制+
  RAYON=12/大栈 setdefault），且电路键与 zksvc 内部缺省同值（零行为变化）
- 非法档名人话拒绝
"""

from __future__ import annotations

import pytest

from app.zk import profile


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """清 profile 名与全部构型键（用例自设——零跨用例残留）。"""
    for k in (
        profile.PROFILE_ENV,
        "FZ_ZK_ALLOW_AUTH",
        "FZ_ZK_ALLOW_TRAIL",
        "SM3_LUT",
        "PCS_INTERLEAVE",
        "PCS_BATCH_DEDUP",
        "PCS_VERIFY_STREAM",
        "RAYON_NUM_THREADS",
        "RUST_MIN_STACK",
        "FZ_ZK_FORBID_SPEC_KEY",
        "MASK_OFF",
        "FZ_ZK_CACHE_DIR",
        "FZ_ZK_CASES_DIR",
        "FZ_ZKSVC_DIR",
    ):
        monkeypatch.delenv(k, raising=False)


def test_default_profile_is_release_demo(monkeypatch):
    monkeypatch.delenv(profile.PROFILE_ENV, raising=False)
    assert profile.active_profile() == "release-demo"


def test_release_demo_forced_table(monkeypatch):
    """release-demo 取值表：电路身份键+allow 旗标强制；资源旋钮 setdefault。"""
    monkeypatch.setenv("RAYON_NUM_THREADS", "8")  # 运维显式值——必须尊重
    env = profile.zkc_env()
    # 电路档准入旗标（强制）
    assert env["FZ_ZK_ALLOW_AUTH"] == "1"
    assert env["FZ_ZK_ALLOW_TRAIL"] == "1"
    # 电路身份键（强制——与 zksvc 内部缺省同值，显式化非改构型）
    assert env["SM3_LUT"] == "1"
    assert env["PCS_INTERLEAVE"] == "1"
    assert env["PCS_BATCH_DEDUP"] == "0"
    assert env["PCS_VERIFY_STREAM"] == "0"
    # 资源旋钮 setdefault（显式 env 优先）
    assert env["RAYON_NUM_THREADS"] == "8"
    assert env["RUST_MIN_STACK"] == "536870912"
    # spec 明文私钥回落禁用缺省置位（批 4-6）
    assert env["FZ_ZK_FORBID_SPEC_KEY"] == "1"
    # MASK 旋钮不触碰（掩蔽缺省开——不清除不注入）
    assert "MASK_OFF" not in env


def test_release_demo_default_equivalence(monkeypatch):
    """缺省等价断言：release-demo 与旧逐 env 拼装形态逐键等价——
    旧形态：os.environ + ALLOW_AUTH/TRAIL=1 + setdefault(RAYON,12)+setdefault(栈,512M)。"""
    monkeypatch.setenv("RAYON_NUM_THREADS", "12")
    env = profile.zkc_env()
    assert env["FZ_ZK_ALLOW_AUTH"] == "1" and env["FZ_ZK_ALLOW_TRAIL"] == "1"
    assert env["RAYON_NUM_THREADS"] == "12"
    assert env["RUST_MIN_STACK"] == "536870912"
    # 新增的显式电路键全部与 zksvc 内部缺省同值（SM3_LUT=1 组装面 set_var；
    # PCS_INTERLEAVE 缺省开；BATCH_DEDUP/VERIFY_STREAM 缺省关）——零行为变化
    assert (env["SM3_LUT"], env["PCS_INTERLEAVE"], env["PCS_BATCH_DEDUP"],
            env["PCS_VERIFY_STREAM"]) == ("1", "1", "0", "0")


def test_dev_respects_explicit_overrides(monkeypatch):
    """dev 档：仅强制 allow 旗标——开发者显式构型 env（SM3_LUT=0 legacy、
    MASK_OFF 诊断）全部尊重。"""
    monkeypatch.setenv(profile.PROFILE_ENV, "dev")
    monkeypatch.setenv("SM3_LUT", "0")
    monkeypatch.setenv("MASK_OFF", "1")
    monkeypatch.setenv("RAYON_NUM_THREADS", "2")
    env = profile.zkc_env()
    assert env["FZ_ZK_ALLOW_AUTH"] == "1" and env["FZ_ZK_ALLOW_TRAIL"] == "1"
    assert env["SM3_LUT"] == "0"  # 开发覆盖被尊重（release-demo 会强制回 1）
    assert env["MASK_OFF"] == "1"
    assert env["RAYON_NUM_THREADS"] == "2"
    assert env["FZ_ZK_FORBID_SPEC_KEY"] == "1"  # 缺省供值兜底


def test_pinned_requires_explicit_env(monkeypatch):
    """pinned 档：零隐式——缺任一构型键即人话拒绝并列缺项。"""
    monkeypatch.setenv(profile.PROFILE_ENV, "pinned")
    with pytest.raises(RuntimeError) as ei:
        profile.zkc_env()
    msg = str(ei.value)
    assert "SM3_LUT" in msg and "RAYON_NUM_THREADS" in msg
    # 显式齐备 → 原样透传（零注入）
    for k, v in (
        ("FZ_ZK_ALLOW_AUTH", "1"),
        ("FZ_ZK_ALLOW_TRAIL", "1"),
        ("SM3_LUT", "1"),
        ("PCS_INTERLEAVE", "1"),
        ("PCS_BATCH_DEDUP", "0"),
        ("PCS_VERIFY_STREAM", "0"),
        ("RAYON_NUM_THREADS", "12"),
        ("RUST_MIN_STACK", "536870912"),
        ("FZ_ZK_FORBID_SPEC_KEY", "1"),
    ):
        monkeypatch.setenv(k, v)
    env = profile.zkc_env()
    assert env["SM3_LUT"] == "1" and env["RAYON_NUM_THREADS"] == "12"


def test_invalid_profile_name_rejected(monkeypatch):
    monkeypatch.setenv(profile.PROFILE_ENV, "turbo")
    with pytest.raises(RuntimeError) as ei:
        profile.active_profile()
    assert "release-demo" in str(ei.value)


def test_zk_cache_dir_default_derivation(monkeypatch, tmp_path):
    """优化 2（跨证明确定性产物复用）：缓存目录缺省推导——案卷目录同级
    cache/ → zksvc 本地 cache/ → 不注入（zkc 纯计算路径，与现状一致）；
    显式 FZ_ZK_CACHE_DIR 恒尊重（setdefault 语义）。"""
    cases = tmp_path / "fz-zk-cases"
    cases.mkdir()
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(cases))
    env = profile.zkc_env()
    assert env[profile.CACHE_DIR_ENV] == str(tmp_path / "cache")

    monkeypatch.setenv("FZ_ZK_CACHE_DIR", "/opt/fz/cache")
    assert profile.zkc_env()[profile.CACHE_DIR_ENV] == "/opt/fz/cache"
    monkeypatch.delenv("FZ_ZK_CACHE_DIR", raising=False)

    monkeypatch.delenv("FZ_ZK_CASES_DIR", raising=False)
    monkeypatch.setenv("FZ_ZKSVC_DIR", "D:/zksvc")
    import os as _os
    assert profile.zkc_env()[profile.CACHE_DIR_ENV] == _os.path.join("D:/zksvc", "cache")

    monkeypatch.delenv("FZ_ZKSVC_DIR", raising=False)
    assert profile.CACHE_DIR_ENV not in profile.zkc_env()


def test_pinned_profile_no_cache_dir_injection(monkeypatch):
    """pinned 档零隐式注入纪律不变：缓存目录缺省不注入（对拍方自带 env）。"""
    monkeypatch.setenv(profile.PROFILE_ENV, "pinned")
    for k, v in (
        ("FZ_ZK_ALLOW_AUTH", "1"),
        ("FZ_ZK_ALLOW_TRAIL", "1"),
        ("SM3_LUT", "1"),
        ("PCS_INTERLEAVE", "1"),
        ("PCS_BATCH_DEDUP", "0"),
        ("PCS_VERIFY_STREAM", "0"),
        ("RAYON_NUM_THREADS", "12"),
        ("RUST_MIN_STACK", "536870912"),
        ("FZ_ZK_FORBID_SPEC_KEY", "1"),
    ):
        monkeypatch.setenv(k, v)
    env = profile.zkc_env()
    assert profile.CACHE_DIR_ENV not in env, "pinned 零注入纪律被破坏"


def test_describe_names_profile():
    assert "release-demo" in profile.describe()
    assert "dev" in profile.describe("dev")
    assert "pinned" in profile.describe("pinned")
