"""阶段四 政策链源对拍测试：本地 paramsHash 必须在链上已发布版本集合中（fail-closed）。"""

from __future__ import annotations

from app.authz.policy import chain_policy_published, policy_params_hash


def test_chain_policy_published_matching():
    """本地 paramsHash 在链上发布集合中 → 通过（公示=承诺）。"""
    mine = bytes.fromhex(policy_params_hash())
    assert chain_policy_published([b"\x00" * 32, mine]) is True


def test_chain_policy_unpublished_rejected():
    """链上没有任何版本与本地一致 → fail-closed False（受理将拒绝）。"""
    assert chain_policy_published([b"\x00" * 32, b"\x11" * 32]) is False


def test_params_hash_deterministic():
    """paramsHash 确定性（同政策表同指纹——版本化公示的前提）。"""
    assert policy_params_hash() == policy_params_hash()
