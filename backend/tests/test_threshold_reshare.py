"""⑤站 proactive re-share 单测（TDD——先红后绿）。

任务书验收三命题：
① re-share 后**旧信封仍可解**（D_pub 不变 ⟹ 存量 v5 信封零影响——
   wrap 在刷新前、unwrap 在刷新后，走 unwrap_any 真实全路径）；
② **旧份额作废**（旧份额值+新份额混合 ⟹ C3 必败，不返回垃圾明文）；
③ **单新份额不可解**（2-of-3 语义不回退——combine <2 份即拒）。
另钉：δ(0)=0 数学锚（已知 d 下 g(0)=d，标量域全等）+ 纪元 +1/D_pub 逐字
不变 + 旧纪元密封钥打不开新密封件 + 仪式审计行在案 + 治理纪元门（参数
不带治理公示纪元即拒）。隔离纪律同 test_threshold_envelope：monkeypatch
FZ_THRESHOLD_ROOT_DIR→tmp（生产目录绝不混入测试行）。
"""

from __future__ import annotations

import json

import pytest

from app.authz.service import threshold_wrap, unwrap_any
from app.crypto.sm2 import _N, SM2Error
from app.crypto.sm2 import encrypt as sm2_encrypt
from app.crypto.sm4 import SM4GCMError
from app.crypto.threshold import (
    combine_decrypt_shares,
    decrypt_share,
    lagrange_coeff,
    proactive_reshare,
    shamir_split,
    threshold_decrypt,
)
from app.ra import threshold_shares as ts

# ---------------------------------------------------------------- 环境隔离


@pytest.fixture()
def fresh_root(tmp_path, monkeypatch):
    """每用例独立门限根（tmp 隔离——生产 threshold_root 零触碰）。"""
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(tmp_path / "threshold_root"))
    info = ts.initialize_if_absent()
    return info


def _all_true_hooks() -> dict:
    """全放行 hooks（判定逻辑单测另有多域用例——本文件钉刷新语义非门语义）。"""
    return {
        "request_registered": lambda *a: True,
        "warrant_on_chain": lambda *a: True,
        "collab_approved": lambda *a: True,
    }


def _open_share_hex(role: str, epoch: int) -> str:
    blob = ts._domain_share_sealed_path(role).read_bytes()
    return ts._open_share(role, epoch, blob).decode()


# ---------------------------------------------------------------- 数学锚


def test_reshare_math_anchor_g0_invariant():
    """δ(0)=0 ⟹ g(0)=f(0)=d：已知 d 下，任意 ≥k 份旧份额刷新后，新份额
    拉格朗日合成（0 点）逐位回到 d——标量域全等（无需任何曲线运算）。"""
    d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    old = shamir_split(d, 3, 2)
    new = proactive_reshare(old, 3, 2)
    assert len(new) == 3 and [i for i, _ in new] == [1, 2, 3]
    for xs in ([1, 2], [1, 3], [2, 3], [1, 2, 3]):  # 任两份=任三份全一致
        acc = 0
        for i, s in new:
            if i in xs:
                acc = (acc + lagrange_coeff(i, xs) * s) % _N
        assert acc == d


# ---------------------------------------------------------------- 命题①


def test_reshare_old_envelope_still_decrypts(fresh_root):
    """命题①：wrap（刷新前）→ ceremonial_reshare → unwrap_any（刷新后，
    真实全路径：新纪元开封→[dᵢ]C₁→拉格朗日合成→C3 对拍→SM4-GCM）。"""
    plaintext = "存量实名映射样例——id_number 密文（刷新前 v5 信封）".encode()
    blob = threshold_wrap(plaintext)
    pub_before = ts.root_pub_hex()

    r = ts.ceremonial_reshare(gov_confirmed_epoch=2)

    assert r["epoch"] == 2 and r["pub_hex"] == pub_before
    assert ts.root_pub_hex() == pub_before  # D_pub 逐字不变
    out = unwrap_any(
        blob,
        share_hooks=_all_true_hooks(),
        unlock_ctx={
            "warrant_hash_hex": "aa" * 32,
            "cred_hash_hex": "bb" * 32,
            "request_sha256_hex": "cc" * 32,
        },
    )
    assert out == plaintext


# ---------------------------------------------------------------- 命题②


def test_reshare_old_share_value_invalidated(fresh_root):
    """命题②：旧份额值+新份额混合 ⟹ C3 必败（SM2Error，不回垃圾明文）。"""
    old_d1 = _open_share_hex("admin", 1)  # 刷新前捕获旧份额值（epoch1 域钥开封）
    plaintext = b"mix-case"
    ct = sm2_encrypt(ts.root_pub_hex(), plaintext)
    c1_hex = ct[:64].hex()

    ts.ceremonial_reshare(gov_confirmed_epoch=2)

    new_d1 = _open_share_hex("admin", 2)
    new_d2 = _open_share_hex("ra", 2)
    good = [
        (1, decrypt_share(new_d1, c1_hex)),
        (2, decrypt_share(new_d2, c1_hex)),
    ]
    assert threshold_decrypt(ct, good) == plaintext  # 对照组：全新份额可解
    mixed = [
        (1, decrypt_share(old_d1, c1_hex)),  # 旧纪元份额值
        (2, decrypt_share(new_d2, c1_hex)),
    ]
    with pytest.raises(SM2Error):
        threshold_decrypt(ct, mixed)  # 旧+新混合 ⟹ C3 必败


# ---------------------------------------------------------------- 命题③


def test_single_new_share_insufficient(fresh_root):
    """命题③：单新份额不可解（combine <2 份即拒——2-of-3 不回退）。"""
    plaintext = b"single-share-case"
    ct = sm2_encrypt(ts.root_pub_hex(), plaintext)
    c1_hex = ct[:64].hex()

    ts.ceremonial_reshare(gov_confirmed_epoch=2)

    d1 = _open_share_hex("admin", 2)
    pt1 = decrypt_share(d1, c1_hex)
    with pytest.raises(SM2Error):
        combine_decrypt_shares([(1, pt1)], c1_hex)


# ---------------------------------------------------------------- 仪式面


def test_reshare_epoch_pub_seal_audit(fresh_root):
    """纪元 +1、D_pub 不变、旧纪元密封钥打不开新密封件、三域仪式审计行在案。"""
    pub_before = ts.root_pub_hex()
    old_auditor_blob = ts._domain_share_sealed_path("auditor").read_bytes()

    ts.ceremonial_reshare(gov_confirmed_epoch=2)

    meta = json.loads((ts._root_dir() / "root.json").read_text(encoding="utf-8"))
    assert meta["epoch"] == 2 and meta["prev_epoch"] == 1
    assert meta["pub_hex"] == pub_before
    # 旧纪元密封钥打不开新密封件（epoch 参与密封钥派生——旧钥即作废，
    # SM4-GCM 认证标签必败）
    with pytest.raises(SM4GCMError):
        ts._open_share("auditor", 1, ts._domain_share_sealed_path("auditor").read_bytes())
    # （对照）旧 blob 用旧钥仍可开——"作废"的是份额值有效性而非历史可读性
    assert ts._open_share("auditor", 1, old_auditor_blob) is not None
    # 三域仪式审计行（append-only，零份额材料）
    for role in ("admin", "ra", "auditor"):
        rows = [
            json.loads(line)
            for line in ts._audit_path(role).read_text(encoding="utf-8").splitlines()
        ]
        assert rows[-1]["action"] == "reshare" and rows[-1]["decision"] == "ok"
        assert rows[-1]["from_epoch"] == 1 and rows[-1]["to_epoch"] == 2


def test_reshare_requires_gov_epoch(fresh_root):
    """治理纪元门：不带/带错治理公示纪元即拒（fail-closed——仪式不被绕过）。"""
    with pytest.raises(ts.ShareDomainError):
        ts.ceremonial_reshare(gov_confirmed_epoch=99)  # ≠ 当前+1
    with pytest.raises(ts.ShareDomainError):
        ts.ceremonial_reshare(gov_confirmed_epoch=0)


def test_reshare_insufficient_openable_shares(fresh_root, tmp_path):
    """可开封份额 <k 即拒（≥2 份现存份额是刷新前提——零持久变更）。"""
    for role in ("admin", "ra"):
        ts._domain_share_sealed_path(role).write_bytes(b"\x00" * 92)  # 密封件损毁
    before = (ts._root_dir() / "root.json").read_text(encoding="utf-8")
    with pytest.raises(ts.ShareDomainError):
        ts.ceremonial_reshare(gov_confirmed_epoch=2)
    assert (ts._root_dir() / "root.json").read_text(encoding="utf-8") == before  # 零持久变更


def test_reshare_twice_epoch_accumulates(fresh_root):
    """连续两轮仪式：纪元逐轮 +1（1→2→3），D_pub 恒不变，旧信封跨两轮仍可解。"""
    plaintext = "跨两轮纪元的存量信封".encode()
    blob = threshold_wrap(plaintext)
    pub_before = ts.root_pub_hex()
    assert ts.ceremonial_reshare(gov_confirmed_epoch=2)["epoch"] == 2
    assert ts.ceremonial_reshare(gov_confirmed_epoch=3)["epoch"] == 3
    assert ts.root_pub_hex() == pub_before
    out = unwrap_any(
        blob,
        share_hooks=_all_true_hooks(),
        unlock_ctx={
            "warrant_hash_hex": "dd" * 32,
            "cred_hash_hex": "ee" * 32,
            "request_sha256_hex": "ff" * 32,
        },
    )
    assert out == plaintext
