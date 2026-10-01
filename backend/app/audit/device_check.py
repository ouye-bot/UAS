"""设备一致性核对（SN v2）：检查点设备签名 vs RA 登记 SN₁ 派生公钥。

原理（D16）：桥接设备钥按序列号确定性派生（KMS|device|SN）——
「设备公钥 == pubkey_from(derive(SN₁))」当且仅当飞行的是登记的那台飞机。

🔴 口径降格（反方评审 Q2 裁定）：核对需要 SN₁ 明文（令状门控内，非公开）+
fence_state（不在链上，存于 checkpoint_anchors 运营方投影）——「第三方独立
核对」仅限实名解锁后、且以 DB 投影为信任面；不是"公开数据人人可验"。
生产形态承诺（红队评审条件 #4）：真机=SE 生成随机设备钥、登记时 RA 收录
device_pub，本模块改查登记公钥表；SN 派生仅限 demo bootstrap（KMS|device|SN
确定性派生在真机形态失效——诚实边界）。
"""

from __future__ import annotations

from app.crypto.sm2 import pubkey_from_priv, verify_digest
from app.crypto.sm3 import sm3_bytes
from app.kms import _derive_priv
from app.telemetry.checkpoint import checkpoint_message


def _device_priv(sn: str) -> str:
    """设备私钥派生（与桥接 device_key 同式——KMS|device|SN 域）。"""
    return _derive_priv(b"FZ-KMS|device|" + sn.encode())


def expected_device_pub(registered_sn: str) -> str:
    """登记 SN₁ → 预期设备公钥（确定性派生）。"""
    return pubkey_from_priv(_derive_priv(b"FZ-KMS|device|" + registered_sn.encode()))


def device_consistency(checkpoint_rows, registered_sn: str, consumed: bool = False) -> dict:
    """核对核心（纯函数）：rows=检查点字典列表（auth_id/seq/chain_head/fence_state/device_sig/pub）。

    registered_sn=登记 SN₁ 明文（解锁后可得）。verdict:
    match=全部签名与派生公钥一致；mismatch=任一不一致（借机飞行）；
    no_evidence=授权已消费但零检查点（借机者不锚定即逃逸——审计按可疑呈现，
    红队评审 #5）；insufficient=无登记 SN 可核对。
    consumed=该授权是否已有消费记录（approved 即视为已消费）。
    """
    exp_pub = expected_device_pub(registered_sn)
    checked = 0
    mismatch = 0
    for r in checkpoint_rows:
        checked += 1
        msg = checkpoint_message(
            int(r["auth_id"]),
            int(r["seq"]),
            bytes.fromhex(r["chain_head_hex"]),
            bytes.fromhex(r["fence_state_hex"]),
        )
        sig_ok = verify_digest(exp_pub, sm3_bytes(msg), r["device_sig_hex"])
        pub_ok = r.get("device_pub_hex", "").lower() == exp_pub.lower()
        if not (sig_ok and pub_ok):
            mismatch += 1
    if checked == 0:
        if consumed:
            return {
                "verdict": "no_evidence",
                "checked": 0,
                "mismatch": 0,
                "reason": "授权已消费但零检查点锚定——借机者不锚定即逃逸（可疑）",
            }
        return {"verdict": "insufficient", "checked": 0, "mismatch": 0}
    return {
        "verdict": "match" if mismatch == 0 else "mismatch",
        "checked": checked,
        "mismatch": mismatch,
    }


def sn_to_device_pub(registered_sn: str) -> str:
    """SN₁ 明文 → 预期设备公钥 hex（trace 节点消费）。"""
    return expected_device_pub(registered_sn)
