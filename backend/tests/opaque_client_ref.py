"""OPAQUE 参考客户端对拍参照（⥬O-3 建立；⥬O-4 起本体升格 app/accounts/client.py
——运营件（scripts/script_auth 种子动线）与测试面共用同一实现，O-5 JS 按其对拍）。
本模块保留为 import 兼容 shim——既有测试导入面零改动。"""

from __future__ import annotations

from app.accounts.client import (
    STRETCHED_LEN,
    client_change_v6_materials,
    client_finish_login,
    client_login_blind,
    client_profile_slot_v6,
    client_seal_v6,
    derive_rwd_chain,
    kek_from_rwd,
)

# 旧名兼容（O-3 测试面命名）
ref_seal_v6 = client_seal_v6
ref_login_blind = client_login_blind


def ref_login_unseal(r: int, evaluate_response: dict) -> str:
    """旧名兼容（=client_finish_login）。"""
    return client_finish_login(r, evaluate_response)


__all__ = [
    "STRETCHED_LEN",
    "client_change_v6_materials",
    "client_finish_login",
    "client_login_blind",
    "client_profile_slot_v6",
    "client_seal_v6",
    "derive_rwd_chain",
    "kek_from_rwd",
    "ref_login_blind",
    "ref_login_unseal",
    "ref_seal_v6",
]
