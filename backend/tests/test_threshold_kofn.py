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

    with pytest.raises(AuthzError):
        unwrap_any(envelope, share_hooks=hooks, unlock_ctx=ctx)
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
