"""3.2 门限 k-of-n 参数化验收（先红后绿钉面——3.2 任务书验收矩阵）。

矩阵：k=2/n=3（现行复跑=零变化锚）/k=3/n=5/k=2/n=4——分割/重组/k-1 份额不可解/
旧信封跨参数域隔离。负例：k>2 时 ≥2 份额合成放水（R1③——combine 硬编码 ≥2
在 k>2 形态下放水必须同步修）/启动断言（k=1 拒/n=k 拒/域集越界拒）。
"""

from __future__ import annotations

import json

import pytest

from app.crypto.sm2 import encrypt as sm2_encrypt
from app.crypto.threshold import (
    combine_decrypt_shares,
    decrypt_share,
    shamir_split,
    threshold_decrypt,
)
from app.ra import threshold_shares as ts_mod


def _mk(k: int, n: int):
    """随机根钥分割→(sk, shares, c1 全套点份额 helper)。"""
    from app.crypto.sm2 import generate_keypair

    sk, pk = generate_keypair()
    d = int(sk, 16)
    shares = shamir_split(d, n, k)
    return sk, pk, shares


def _pt_shares(shares, c1_hex, idxs):
    return [(i, decrypt_share(f"{s:064x}", c1_hex)) for i, s in shares if i in idxs]


def test_matrix_k2n3_current_semantics():
    """k=2/n=3 现行复跑（零变化锚）：任两份额合成可解。"""
    sk, pk, shares = _mk(2, 3)
    ct = sm2_encrypt(pk, b"canary-k2n3")
    c1 = ct[:64].hex()
    pts = _pt_shares(shares, c1, {1, 3})
    assert threshold_decrypt(ct, pts) == b"canary-k2n3"
    assert threshold_decrypt(ct, pts, k=2) == b"canary-k2n3"  # 显式 k 同语义


def test_matrix_k3n5_combine_and_decrypt():
    """k=3/n=5：三份额合成可解（参数化主路径）。"""
    sk, pk, shares = _mk(3, 5)
    ct = sm2_encrypt(pk, b"canary-k3n5")
    c1 = ct[:64].hex()
    pts = _pt_shares(shares, c1, {1, 3, 5})
    assert threshold_decrypt(ct, pts, k=3) == b"canary-k3n5"
    assert combine_decrypt_shares(pts, c1, k=3)


def test_matrix_k2n4_any_pair():
    """k=2/n=4：任意两份额对（4 选 2 全组合抽验）。"""
    sk, pk, shares = _mk(2, 4)
    ct = sm2_encrypt(pk, b"canary-k2n4")
    c1 = ct[:64].hex()
    for pair in ((1, 2), (2, 4), (1, 4)):
        pts = _pt_shares(shares, c1, set(pair))
        assert threshold_decrypt(ct, pts, k=2) == b"canary-k2n4"


def test_review_k3_two_shares_water_tight(capsys):
    """R1③放水负例（先红）：k=3 时两份额合成必须拒——旧硬编码 ≥2 在 k>2
    形态下放水（2 份额恰可解 2-of-3 子式 ⟹ 门限语义降级）。"""
    sk, pk, shares = _mk(3, 5)
    ct = sm2_encrypt(pk, b"canary-water")
    c1 = ct[:64].hex()
    pts = _pt_shares(shares, c1, {1, 2})  # 仅 2 份额（k=3 需 3）
    from app.crypto.threshold import SM2Error

    with pytest.raises(SM2Error) as ei:
        combine_decrypt_shares(pts, c1, k=3)
    assert "≥3" in str(ei.value) or "3" in str(ei.value)
    with pytest.raises(SM2Error):
        threshold_decrypt(ct, pts, k=3)  # 解密路径同拒（缺省 k=2 不受扰）


def test_matrix_k_minus_one_insufficient():
    """k-1 份额=份额数不足拒（k=2/n=3 现行已钉 1 份额；k=3 显式 k 拒 2 份额）。"""
    sk, pk, shares = _mk(2, 3)
    ct = sm2_encrypt(pk, b"canary-insuf")
    c1 = ct[:64].hex()
    pts = _pt_shares(shares, c1, {2})
    from app.crypto.threshold import SM2Error as _E

    with pytest.raises(_E):
        combine_decrypt_shares(pts, c1, k=2)


def test_matrix_cross_domain_envelope_isolation(tmp_path, monkeypatch):
    """旧信封跨参数域隔离：域 A（2-of-3）v5 信封在域 B（3-of-5 全新根）解=必败
    （不同 D_pub ⟹ C3 校验必败——信封不跨根）。"""
    from app.ra import threshold_shares as ts

    root_a = tmp_path / "dom_a"
    root_b = tmp_path / "dom_b"
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(root_a))
    monkeypatch.setenv("FZ_THRESHOLD_K", "2")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "admin,ra,auditor")
    ts._reset_config_cache()
    init_a = ts.initialize_if_absent()
    assert init_a["created"] is True
    from app.authz.service import threshold_wrap, unwrap_any

    envelope = threshold_wrap(b"secret-A")
    # 域 B：3-of-5 全新根
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(root_b))
    monkeypatch.setenv("FZ_THRESHOLD_K", "3")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "d0,d1,d2,d3,d4")
    ts._reset_config_cache()
    init_b = ts.initialize_if_absent()
    assert init_b["created"] is True and init_b["pub_hex"] != init_a["pub_hex"]
    ctx = {
        "warrant_hash_hex": "11" * 32,
        "cred_hash_hex": "22" * 32,
        "request_sha256_hex": "33" * 64,
    }
    # hooks 全放行替位（本测试只验密码层跨根隔离——四关业务面既有测试钉）
    hooks = {
        "request_registered": lambda *a, **kw: True,
        "warrant_on_chain": lambda *_a: True,
        "collab_approved": lambda *_a: True,
        "owner_set_synced": lambda: True,
    }
    from app.authz.service import AuthzError

    # 形态一（R3⑤归因修正）：域 B 配置域集 d0..d4（k=3）下 unwrap 走配置域
    # 枚举开封 B 真份额合成对 A 信封 ⟹ C3 必败 ⟹ AuthzError 403 判词（裸
    # SM2Error 500 退役）。注：审查员 probe 的 bad_role 形态（征询域 ∉ 配置集）
    # 在泛化后的 unwrap 面不可达——征询域恒取自配置集（R3① probe 测试以
    # seen_domains 钉枚举面）；bad_role 现仅防 request_decrypt_share 直调错域名。
    with pytest.raises(AuthzError) as ei:
        unwrap_any(envelope, share_hooks=hooks, unlock_ctx=ctx)
    assert "份额合成/解密失败" in str(ei.value) or "放行不足 3/5" in str(ei.value)
    # 形态二（同域名跨根——更深形态）：root B 按判词指引**显式归档换代**为与
    # A 相同域名（config_mismatch 红线先实锤——直接改配置 init 被拒即红线
    # 工作证据），归档后重 init 新根钥——unwrap 开封 B 真份额合成对 A 信封
    # ⟹ C3 必败 ⟹ **AuthzError 403 判词**（裸 SM2Error 500 形态退役——unwrap
    # 合成段归一，R3 审查①残留面封死）。
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(root_b))
    monkeypatch.setenv("FZ_THRESHOLD_K", "2")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "admin,ra,auditor")
    ts._reset_config_cache()
    with pytest.raises(ts.ShareDomainError) as ecm:
        ts.initialize_if_absent()
    assert ecm.value.code == "config_mismatch"  # 跨参数域红线实锤（先拒后换代）
    import shutil as _shutil

    _shutil.rmtree(root_b)
    ts.initialize_if_absent()
    with pytest.raises(AuthzError) as ei2:
        unwrap_any(envelope, share_hooks=hooks, unlock_ctx=ctx)
    assert "份额合成/解密失败" in str(ei2.value)
    # 形态三（密码层直接钉——不经 unwrap）：A 信封 C₁ 用 B 根份额点合成 ⟹
    # C3 必败（**信封不跨根的数学归因**——不同 D_pub ⟹ [d]C₁ 不同 ⟹ C3 拒）。
    from app.crypto.threshold import SM2Error, decrypt_share

    c1_hex = envelope[3 : 3 + int.from_bytes(envelope[1:3], "big")][:64].hex()
    b_pts = []
    for idx, d in enumerate(("admin", "ra"), start=1):
        di = ts._open_share(d, 1, ts._domain_share_sealed_path(d).read_bytes()).decode()
        b_pts.append((idx, decrypt_share(di, c1_hex)))
    with pytest.raises(SM2Error):
        threshold_decrypt(envelope[3:], b_pts, k=2)
    # 域 A 配置回切后原信封可解（隔离是双向幂等的——配置域一致即恢复）
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(root_a))
    monkeypatch.setenv("FZ_THRESHOLD_K", "2")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "admin,ra,auditor")
    ts._reset_config_cache()
    plain = unwrap_any(envelope, share_hooks=hooks, unlock_ctx=ctx)
    assert plain == b"secret-A"


# ---------------- 启动断言负例（①配置 fail-fast） ----------------


def test_assert_k1_rejected(monkeypatch):
    from app.ra import threshold_shares as ts

    monkeypatch.setenv("FZ_THRESHOLD_K", "1")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "admin,ra,auditor")
    ts._reset_config_cache()
    with pytest.raises(ts.ShareDomainError) as ei:
        ts.threshold_config()
    assert ei.value.code == "bad_threshold_config"


def test_assert_nk_equal_rejected(monkeypatch):
    from app.ra import threshold_shares as ts

    monkeypatch.setenv("FZ_THRESHOLD_K", "3")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "a,b,c")
    ts._reset_config_cache()
    with pytest.raises(ts.ShareDomainError) as ei:
        ts.threshold_config()
    assert ei.value.code == "bad_threshold_config"


@pytest.mark.parametrize(
    "domains",
    ["admin,admin,ra", "admin,,ra", "admin,ra,aud itor", ",", "a" * 64],
)
def test_assert_domain_shape_rejected(monkeypatch, domains):
    from app.ra import threshold_shares as ts

    monkeypatch.setenv("FZ_THRESHOLD_K", "2")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", domains)
    ts._reset_config_cache()
    with pytest.raises(ts.ShareDomainError) as ei:
        ts.threshold_config()
    assert ei.value.code == "bad_threshold_config"


def test_assert_k_bad_int_rejected(monkeypatch):
    from app.ra import threshold_shares as ts

    monkeypatch.setenv("FZ_THRESHOLD_K", "two")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "admin,ra,auditor")
    ts._reset_config_cache()
    with pytest.raises(ts.ShareDomainError):
        ts.threshold_config()


def test_default_env_zero_change(monkeypatch):
    """红线：默认 env（未设 FZ_THRESHOLD_K/DOMAINS）=2 + (admin,ra,auditor)
    逐字同现行——行为零变化的配置面锚。"""
    import os

    monkeypatch.delenv("FZ_THRESHOLD_K", raising=False)
    monkeypatch.delenv("FZ_THRESHOLD_DOMAINS", raising=False)
    from app.ra import threshold_shares as ts

    ts._reset_config_cache()
    k, domains = ts.threshold_config()
    assert (k, domains) == (2, ("admin", "ra", "auditor"))
    assert json.loads(json.dumps(list(domains))) == ["admin", "ra", "auditor"]
    _ = os.environ  # noqa: F841  显式留痕：未设 env 形态


# ---------------- R3 审查批钉面（2026-10-12 第二轮 3.2 审查 1~5 条） ----------------


def test_r3_1_unwrap_uses_configured_domains(monkeypatch, tmp_path):
    """R3①（高——根修⑥ replace 静默 no-op 实锤的真正钉面）：非默认域集
    gov1,gov2,gov3 下 unwrap_any 走配置域枚举（旧硬编码 admin/ra/auditor
    形态=三域全 bad_role ⟹ threshold_denied 全瘫实锤）。"""
    import app.authz.service as authz_svc
    from app.authz.service import AuthzError

    root = tmp_path / "tr"
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(root))
    monkeypatch.setenv("FZ_THRESHOLD_K", "2")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "gov1,gov2,gov3")
    monkeypatch.setattr(ts_mod, "_reset_config_cache", ts_mod._reset_config_cache)
    ts_mod._reset_config_cache()
    ts_mod.initialize_if_absent()
    envelope = authz_svc.threshold_wrap(b"r3-secret")
    seen_domains: list[str] = []

    def _fake_share(domain, c1_hex, **kw):
        seen_domains.append(domain)
        raise ts_mod.ShareDomainError("share_denied", f"probe {domain}")

    monkeypatch.setattr(ts_mod, "request_decrypt_share", _fake_share)
    ctx = {
        "warrant_hash_hex": "11" * 32,
        "cred_hash_hex": "22" * 32,
        "request_sha256_hex": "33" * 64,
    }
    with pytest.raises(AuthzError) as ei:
        authz_svc.unwrap_any(envelope, share_hooks=_hooks_all_pass(), unlock_ctx=ctx)
    # fake 每域全拒 ⟹ granted 恒 0 ⟹ 全域遍历——seen=配置域全集即泛化实锤
    # （旧硬编码形态 seen=["admin","ra","auditor"] 且三域全 bad_role）
    assert seen_domains == ["gov1", "gov2", "gov3"], f"配置域枚举实锤: {seen_domains}"
    assert "2/3" in ei.value.message, ei.value.message
    ts_mod._reset_config_cache()


def test_r3_1_unwrap_k3_no_water(monkeypatch, tmp_path):
    """R3①放水残留封死：3-of-4 配置下 unwrap 两域拒绝后不得以 2 份走缺省 k=2
    合成（granted<3 → AuthzError 判词——非 C3 裸 SM2Error 500 形态）。"""
    import app.authz.service as authz_svc
    from app.authz.service import AuthzError

    root = tmp_path / "tr3"
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(root))
    monkeypatch.setenv("FZ_THRESHOLD_K", "3")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "admin,ra,auditor,compliance")
    ts_mod._reset_config_cache()
    ts_mod.initialize_if_absent()
    envelope = authz_svc.threshold_wrap(b"r3-k3")
    calls = {"n": 0}

    def _fake_share(domain, c1_hex, **kw):
        calls["n"] += 1
        if domain in ("admin", "ra"):
            from app.crypto.threshold import decrypt_share

            # 前两域真出份额（放水形态下恰可 2 份合成——必须被 granted<3 挡）
            sealed = ts_mod._domain_share_sealed_path(domain).read_bytes()
            d_i = ts_mod._open_share(domain, 1, sealed).decode()
            return decrypt_share(d_i, c1_hex)
        raise ts_mod.ShareDomainError("share_denied", f"probe {domain}")

    monkeypatch.setattr(ts_mod, "request_decrypt_share", _fake_share)
    ctx = {
        "warrant_hash_hex": "11" * 32,
        "cred_hash_hex": "22" * 32,
        "request_sha256_hex": "33" * 64,
    }
    with pytest.raises(AuthzError) as ei:
        authz_svc.unwrap_any(envelope, share_hooks=_hooks_all_pass(), unlock_ctx=ctx)
    assert calls["n"] == 4, f"2 份即 break 放水形态不得复现（征询至域尽/满 k——得 {calls['n']}）"
    assert "3/4" in ei.value.message
    ts_mod._reset_config_cache()


def test_r3_2_production_gate_is_production(monkeypatch, tmp_path):
    """R3②（高——production 判定双向写反根修）：FZ_DEPLOYMENT=production
    （is_production()=True——真实生产形态）下席位对拍触发：链读失败=拒启
    （fail-open 实锤形态的负例钉面）。"""
    import app.ra.threshold_sync as sync_mod

    monkeypatch.setenv("FZ_DEPLOYMENT", "production")
    monkeypatch.setenv("FZ_THRESHOLD_K", "2")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "d0,d1,d2")
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(tmp_path / "trp"))
    ts_mod._reset_config_cache()

    def _boom():
        raise RuntimeError("chain unreachable (R3②)")

    monkeypatch.setattr(sync_mod, "chain_owner_set", _boom)
    with pytest.raises(ts_mod.ShareDomainError) as ei:
        ts_mod.assert_threshold_config()
    assert ei.value.code == "bad_threshold_config"
    assert "席位对拍" in str(ei.value) or "链读失败" in str(ei.value)
    ts_mod._reset_config_cache()


def test_r3_2_demo_skips_seat_check(monkeypatch, tmp_path):
    """R3②反向：demo 档（is_production()=False）不触发席位链读（demo 环回
    零影响——链读调用即视为失败）。"""
    monkeypatch.delenv("FZ_DEPLOYMENT", raising=False)
    monkeypatch.setenv("FZ_THRESHOLD_K", "2")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "d0,d1,d2")
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(tmp_path / "trd"))
    ts_mod._reset_config_cache()
    import app.ra.threshold_sync as sync_mod

    def _boom():
        raise AssertionError("demo 档不得触发席位链读")

    monkeypatch.setattr(sync_mod, "chain_owner_set", _boom)
    out = ts_mod.assert_threshold_config()
    assert out == {"k": 2, "domains": ["d0", "d1", "d2"]}
    ts_mod._reset_config_cache()


def test_r3_4_k_change_reshare_no_selflock(tmp_path, monkeypatch):
    """R3④（中——k 变更换代自锁根修）：2-of-5(d0..d4) → 配置 3-of-4(d0..d3)
    换代 re-share 成功落盘后 root.threshold=3（三键同步）——后续 initialize_
    if_absent 不再 config_mismatch 自锁（threshold_wrap 全死形态负例钉面）。"""
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(tmp_path / "trk"))
    monkeypatch.setenv("FZ_THRESHOLD_K", "2")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "d0,d1,d2,d3,d4")
    ts_mod._reset_config_cache()
    ts_mod.initialize_if_absent()
    envelope = None
    from app.authz.service import threshold_wrap

    envelope = threshold_wrap(b"k-change-canary")
    monkeypatch.setenv("FZ_THRESHOLD_K", "3")
    monkeypatch.setenv("FZ_THRESHOLD_DOMAINS", "d0,d1,d2,d3")
    ts_mod._reset_config_cache()
    r = ts_mod.ceremonial_reshare(gov_confirmed_epoch=2, owner_set_fp=None)
    assert r["epoch"] == 2
    meta = json.loads((ts_mod._root_dir() / "root.json").read_text(encoding="utf-8"))
    assert meta["threshold"] == 3 and meta["domains"] == ["d0", "d1", "d2", "d3"]
    assert meta["roles"] == ["d0", "d1", "d2", "d3"], "R3③ roles 兼容键同步"
    # 自锁负例：换后的 root 对现配置幂等初始化（不再 config_mismatch）
    out = ts_mod.initialize_if_absent()
    assert out["created"] is False
    # 存量信封跨 k 换代仍可解（D_pub 不变——unwrap 面走配置 3 域）
    from app.authz.service import unwrap_any

    ctx = {
        "warrant_hash_hex": "11" * 32,
        "cred_hash_hex": "22" * 32,
        "request_sha256_hex": "33" * 64,
    }
    plain = unwrap_any(envelope, share_hooks=_hooks_all_pass(), unlock_ctx=ctx)
    assert plain == b"k-change-canary"
    ts_mod._reset_config_cache()


def _hooks_all_pass() -> dict:
    return {
        "request_registered": lambda *a, **kw: True,
        "warrant_on_chain": lambda *_a: True,
        "collab_approved": lambda *_a: True,
        "owner_set_synced": lambda: True,
    }
