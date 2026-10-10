"""④站门限信封+份额域校验测试（2026-10-10）。

域校验 hooks=本地真实现形态（判定逻辑同码路径——登记表/判定函数本地跑，
不 mock 网络；链上真查由 e2e/实弹覆盖——分层诚实标注）。
"""

from __future__ import annotations

import pytest

from app.authz.service import AuthzError, threshold_wrap, unwrap_any, wrap_secret
from app.ra.threshold_shares import initialize_if_absent, root_pub_hex


@pytest.fixture(autouse=True)
def _isolated_root(tmp_path, monkeypatch):
    """单测隔离：threshold_root 重定向 tmp（生产 append-only 审计禁混测试行）。"""
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(tmp_path / "threshold_root"))
    yield

_CTX = {
    "warrant_hash_hex": "ab" * 32,
    "cred_hash_hex": "cd" * 32,
    "request_sha256_hex": "12" * 32,
}


def _hooks(all_true: bool) -> dict:
    """本地判定 hooks（真实现签名同构——分层测试：链查真值由实弹覆盖）。"""
    if all_true:
        return {
            "request_registered": lambda sha, wh, ch: True,
            "warrant_on_chain": lambda wh: True,
            "collab_approved": lambda sha: True,
        }
    return {
        "request_registered": lambda sha, wh, ch: False,
        "warrant_on_chain": lambda wh: False,
        "collab_approved": lambda sha: False,
    }


def test_v5_envelope_roundtrip_via_threshold():
    """v5 往返：threshold_wrap → 三域 2-of-3 → unwrap_any == 原文。"""
    initialize_if_absent()
    assert len(root_pub_hex()) == 128
    plain = b'{"username":"u1","id_number":"11010119900307999X","sn":"UAS-SN-1"}'
    blob = threshold_wrap(plain)
    assert blob[0] == 0x05, "v5 信封首字节分派符"
    got = unwrap_any(blob, share_hooks=_hooks(True), unlock_ctx=dict(_CTX))
    assert got == plain


def test_legacy_envelope_dispatch_untouched():
    """legacy（旧单钥域钥）信封：unwrap_any 无 ctx 直读——历史数据兼容。"""
    plain = b"legacy-pii"
    blob = wrap_secret(plain)
    assert blob[0] != 0x05
    assert unwrap_any(blob) == plain


def test_v5_without_ctx_rejected():
    """门限信封无解锁上下文 ⟹ 拒（份额域三关无判据）。"""
    blob = threshold_wrap(b"x")
    with pytest.raises(AuthzError) as ei:
        unwrap_any(blob)
    assert ei.value.code == "threshold_ctx_required"


def test_v5_all_domains_deny():
    """三关全不过 ⟹ threshold_denied 403（份额零出借）。"""
    blob = threshold_wrap(b"denied")
    with pytest.raises(AuthzError) as ei:
        unwrap_any(blob, share_hooks=_hooks(False), unlock_ctx=dict(_CTX))
    assert ei.value.code == "threshold_denied"


def test_v5_tampered_ecies_segment_fails():
    """ECIES 段篡改 ⟹ 合成点漂移 ⟹ C3 校验拒（不返回垃圾 Kₑ）。"""
    blob = bytearray(threshold_wrap(b"tamper"))
    blob[10] ^= 0xFF  # 打进 ECIES 密文体
    with pytest.raises(AuthzError):
        unwrap_any(bytes(blob), share_hooks=_hooks(True), unlock_ctx=dict(_CTX))
