"""KMS（B2：RA 签名钥域；B4 扩政策/审计/设备域+wrap 落库；S5：Provider 抽象）。

密钥供给三层（S5-d1 Provider 抽象——接口统一，实现按部署档替换）：
- demo（缺省，仅环回演示档）：SM3 域派生（幂等锚非生产凭据——B1-d3 纪律），
  零落盘零硬编码；
- env：FZ_*_SK 环境变量注入（部署密钥分离/轮换的最小形态）；
- hsm（生产路线，成文不实现）：PKCS#11/HSM Provider——见 docs/生产部署与安全演进.md
  R2 节。私钥仅进程内持有，任何档零硬编码。

批 2-2.3（演示钥退出默认）：production 档（FZ_DEPLOYMENT=production 或绑
非环回地址，判定见 app/deployment.py）启动时逐钥核查——任一 FZ_*_SK 未
注入且会落到缺省派生即拒绝启动（人话列出缺哪些 env）。演示档维持现状可跑。
轮换仪式：scripts/rotate_kms_keys.py（生成新随机钥→输出 env 行+指纹，
不落库不入 git）。
"""

from __future__ import annotations

import os
from typing import Protocol

from app.crypto.sm2 import pubkey_from_priv
from app.crypto.sm3 import sm3_bytes


class KeyProvider(Protocol):
    """密钥供给协议（S5-d1）：label→私钥 hex。生产=HSM/KMS 实现（签名不出硬件）。"""

    def private_key(self, label: bytes, env_name: str | None = None) -> str: ...


_DEMO_DOMAIN = b"FZ-KMS|ra-signing"

# 生产档必须 env 注入的密钥面（env 名, 用途人话, 材料形态）——缺任一即拒启。
# 指纹/轮换面见 scripts/rotate_kms_keys.py（同表同源）。
PRODUCTION_REQUIRED_KEYS: tuple[tuple[str, str, str], ...] = (
    ("FZ_RA_SK", "RA 凭证签名私钥", "sk32"),
    ("FZ_ENGINE_SK", "政策引擎令牌签名私钥", "sk32"),
    ("FZ_CHAIN_RA_TX_SK", "RA 链上交易签名私钥", "sk32"),
    ("FZ_CHAIN_ENGINE_TX_SK", "engine 链上交易签名私钥", "sk32"),
    ("FZ_CHAIN_AUDITOR_TX_SK", "审计方链上交易签名私钥", "sk32"),
    ("FZ_CHAIN_ADMIN_TX_SK", "治理 admin 链上交易签名私钥（governor owner，批 3.2）", "sk32"),
    ("FZ_WRAP_KEY", "wrap 对称域主钥（16B）", "key16"),
    ("FZ_AUDIT_TOKEN", "审计台 API 令牌", "token"),
    ("FZ_RA_OPS_TOKEN", "RA 运维令牌", "token"),
    ("FZ_AUTHZ_BINDING_KEY", "授权绑定 HMAC-SM3 服务钥（32B hex）", "key32"),
)


def assert_no_demo_keys_in_production() -> None:
    """production 档启动断言（fail-closed）：逐钥核查 env 注入——任一缺位
    （缺省路径会落到 SM3(公开常量) 派生=任何人可推算）即 RuntimeError，人话
    列出全部缺项。demo 档直接返回（演示可跑不受影响）。"""
    from app.deployment import is_production

    if not is_production():
        return
    missing = [
        f"{name}（{desc}）"
        for name, desc, _kind in PRODUCTION_REQUIRED_KEYS
        if not os.environ.get(name)
    ]
    if missing:
        raise RuntimeError(
            "生产档 KMS 密钥未注入——拒绝以演示派生钥启动（演示钥=SM3(公开常量)，"
            "任何人可推算）。请以环境变量注入以下 "
            f"{len(missing)} 项后重启：\n  - " + "\n  - ".join(missing)
        )


def _derive_priv(label: bytes) -> str:
    from gmssl.sm2 import default_ecc_table

    n = int(default_ecc_table["n"], 16)
    d = int.from_bytes(sm3_bytes(label), "big") % (n - 2) + 1
    return format(d, "064x")


def ra_signing_keypair() -> tuple[str, str]:
    """(priv_hex, pub_hex)。env FZ_RA_SK 优先；缺省确定性派生。"""
    sk = os.environ.get("FZ_RA_SK")
    if sk:
        if len(sk) != 64:
            raise ValueError("FZ_RA_SK 须 64 hex")
        return sk, pubkey_from_priv(sk)
    priv = _derive_priv(_DEMO_DOMAIN)
    return priv, pubkey_from_priv(priv)


def chain_ra_tx_key() -> str:
    """RA 链上交易签名钥（B1 烟测接线域 FZ-CHAIN-SMOKE|ra——与凭证签名钥分离：
    链钥轮换不影响凭证验证公钥；演示确定性，生产 env FZ_CHAIN_RA_TX_SK）。"""
    import os

    sk = os.environ.get("FZ_CHAIN_RA_TX_SK")
    return sk if sk else _derive_priv(b"FZ-CHAIN-SMOKE|ra")


# ---- B4 扩域：政策引擎签名域（engine）——令牌签发（与 RA 凭证钥分离） ----

_ENGINE_DOMAIN = b"FZ-KMS|engine-signing"


def chain_engine_tx_key() -> str:
    """engine 链上交易钥（阶段一 D-Ⅰ-1：FlightAuth recordAuth/burnNonce +
    TelemetryAnchor anchorCheckpoint/recordEvent——onlyEngine 四写面）。

    演示=烟测接线域 FZ-CHAIN-SMOKE|engine（与 B1 部署 setEngine 的地址一致）；
    生产 env FZ_CHAIN_ENGINE_TX_SK 注入+setEngine 换钥。
    """
    sk = os.environ.get("FZ_CHAIN_ENGINE_TX_SK")
    return sk if sk else _derive_priv(b"FZ-CHAIN-SMOKE|engine")


def engine_signing_keypair() -> tuple[str, str]:
    """令牌签名钥对（env FZ_ENGINE_SK 优先；演示确定性派生——非生产凭据）。"""
    sk = os.environ.get("FZ_ENGINE_SK")
    if sk:
        if len(sk) != 64:
            raise ValueError("FZ_ENGINE_SK 须 64 hex")
        return sk, pubkey_from_priv(sk)
    priv = _derive_priv(_ENGINE_DOMAIN)
    return priv, pubkey_from_priv(priv)


def ra_pub_hex_of() -> str:
    """RA 凭证验签公钥（子凭证受理门控②消费——单一来源）。"""
    _priv, pub = ra_signing_keypair()
    return pub


def kms_domain_key(label: bytes) -> bytes:
    """对称域钥（16B SM4——A3 通道② wrap 面；env FZ_WRAP_KEY 优先）。

    2026-09-28 安全深检 C-P2 根修：env 设定此前直接返回主钥、忽略 label——
    RA 实名映射钥与协作函钥在强化档恒为同钥（域分离击穿：协作函面泄露=
    全库实名可解）。现 env 主钥经 per-label KDF 派生（SM3(master‖域分隔‖
    label)[:16]），与缺省派生路径同构的域分离强度。
    ⚠ 部署注意：强化档下本修复改变派生式——启用 FZ_WRAP_KEY 的环境需
    重新登记（旧 wrap 数据不可解）；演示缺省档（无 env）派生式不变。"""
    env = os.environ.get("FZ_WRAP_KEY")
    if env:
        if len(env) != 32:
            raise ValueError("FZ_WRAP_KEY 须 32 hex（16B）")
        master = bytes.fromhex(env)
        return sm3_bytes(master + b"|FZ-KMS-DOMAIN|" + label)[:16]
    return sm3_bytes(label)[:16]


def chain_auditor_tx_key() -> str:
    """审计方链上交易钥（B7：logWarrant onlyAuditor——与 RA/engine 链钥同域分离；
    演示=烟测接线域 FZ-CHAIN-SMOKE|auditor，生产 env FZ_CHAIN_AUDITOR_TX_SK）。"""
    import os

    sk = os.environ.get("FZ_CHAIN_AUDITOR_TX_SK")
    return sk if sk else _derive_priv(b"FZ-CHAIN-SMOKE|auditor")


def chain_admin_tx_key() -> str:
    """治理 admin 链上交易钥（批 3.2：governor 三 owner 之一——propose/execute
    仪式面与部署 transferAdmin；不承载任何运行时 API）。

    生产 env FZ_CHAIN_ADMIN_TX_SK 注入（.local_env 同口径）；演示缺省派生
    FZ-CHAIN-SMOKE|admin（仅环回演示档）。兼容旧名 FZ_CHAIN_ADMIN_SK。"""
    import os

    sk = os.environ.get("FZ_CHAIN_ADMIN_TX_SK") or os.environ.get("FZ_CHAIN_ADMIN_SK")
    return sk if sk else _derive_priv(b"FZ-CHAIN-SMOKE|admin")


def audit_api_token() -> str:
    """审计台 API 令牌（B7-d2：无密码体系——密钥即身份；env FZ_AUDIT_TOKEN 优先，
    缺省 KMS 审计域派生 32B hex）。"""
    import os

    tok = os.environ.get("FZ_AUDIT_TOKEN")
    if tok:
        return tok
    return sm3_bytes(b"FZ-KMS|audit|api-token").hex()


def engine_pub_hex() -> str:
    """令牌验签公钥（仅公钥面——地面站/验证方消费；不暴露私钥派生路径）。"""
    _sk, pub = engine_signing_keypair()
    return pub


def ra_ops_token() -> str:
    """RA 运维令牌（S5）：解锁/吊销等 RA 侧运维动作的认证面。
    demo=RA 域派生；生产 env FZ_RA_OPS_TOKEN 注入（恒时比较在调用侧）。"""
    sk = os.environ.get("FZ_RA_OPS_TOKEN")
    if sk:
        return sk
    return sm3_bytes(b"FZ-KMS|ra-ops").hex()


def authz_binding_key() -> bytes:
    """绑定挑战 HMAC-SM3 服务密钥（评审 P3-3）：HMAC 密钥不得为公开常量——
    demo=KMS 域派生；生产 env FZ_AUTHZ_BINDING_KEY 注入（64 位 hex）。与
    ra_ops_token 同纪律：调用侧只经本端口取钥，派生路径不进公钥面/文档。"""
    sk = os.environ.get("FZ_AUTHZ_BINDING_KEY")
    if sk:
        return bytes.fromhex(sk)
    return sm3_bytes(b"FZ-KMS|authz-binding")
