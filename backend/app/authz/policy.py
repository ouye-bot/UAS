"""政策引擎（B4）：机型类规则表 + 申请绑定复合折算。

政策表=公开数据（链上 PolicyRegistry 镜像公示；paramsHash 版本化）。数值口径：
- alt_max 取自《无人驾驶航空器飞行管理暂行条例》公开数值（微型真高 50m/
  轻型真高 120m——框架 v2 §一/三视角评审 E-P2 锚定；B4-d6 拍板：主场景只
  开放微/轻两档，小型/中型 fail-closed 未开放——诚实范围声明）。
- required_level 为治理层参数（非条例数值——paramsHash 上链公示透明）。

绑定复合折算（B3-d10/T6 口径）：服务层把 (challenge)→ctx_tag、
(plan_hash, nonce, policy_version)→pred_id 复合折算进电路实例钉——与 zkc
BindingInput 同构（黄金向量对拍单一事实源）。
"""

from __future__ import annotations

from app.crypto.sm3 import sm3_bytes

# class_id → (alt_max_m, required_level)；None=未开放（fail-closed）
CLASS_RULES: dict[int, tuple[int, int]] = {
    0: (50, 1),  # 微型：真高 50m（条例数值）
    1: (120, 1),  # 轻型：真高 120m（条例数值）
}

POLICY_VERSION = "policy-2026-09-v1"


class PolicyError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message


def policy_params_hash() -> str:
    """政策表参数指纹（链上 publishPolicy 的 paramsHash——版本化公示）。"""
    buf = POLICY_VERSION.encode()
    for cid in sorted(CLASS_RULES):
        alt, req = CLASS_RULES[cid]
        buf += bytes([cid]) + alt.to_bytes(2, "big") + bytes([req])
    return sm3_bytes(buf).hex()


def get_rule(class_id: int) -> tuple[int, int]:
    """机型类查表：返回 (alt_max_m, required_level)；未开放类=fail-closed 拒。"""
    if class_id not in CLASS_RULES:
        open_ids = ", ".join(str(c) for c in sorted(CLASS_RULES))
        raise PolicyError(
            "unsupported_class",
            f"机型类 {class_id} 未开放（已开放：{open_ids}——小型/中型适飞管控"
            "更严，本系统演示范围=微型/轻型，见范围外声明）",
        )
    return CLASS_RULES[class_id]


def chain_policy_published(version_hashes) -> bool:
    """政策公示对拍（阶段四）：本地 paramsHash 是否在链上已发布版本集合中。

    fail-closed：链上没有任何已发布版本与本地政策表一致 → 受理拒绝
    （policy_unpublished）——政策表被单方变更/未公示即不可受理。
    version_hashes: 链上各版本 paramsHash 的 bytes 可迭代。
    """
    mine = bytes.fromhex(policy_params_hash())
    return any(bytes(h) == mine for h in version_hashes)
