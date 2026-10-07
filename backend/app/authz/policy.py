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

# 机型类 → (min_lat, max_lat, min_lon, max_lon)——矩形围栏 4 界（i32×1e7，
# 负值=南/西半球合法域；二批改动1：TRAIL 电路 4 半平面合规门）。
# 🔴 权威通道=引擎轨迹绑定签名（FZ-TRAIL-BIND2 扩域——与 alt_max 同款
# 「证明者不可自报」）；**不并入 policy_params_hash**：已发布政策版本
# paramsHash 面字节稳定（链上公示版本持续有效——政策表主体=高度/资质；
# 围栏的授权锚=引擎签名，第三方凭公示公钥离线复核）。
# 演示围栏=**单一演示空域**（盲审二轮整改 2026-10-04：S4 合成场已迁至 SITL
# 默认原点近旁——ArduPilot 缺省 home≈35.363S/149.165E（负纬度=电路偏置编码
# 的实弹路径），S4 合成场（scripts/scenario_S4_trail.py 采样界 lat
# -345000000+i*11 / lon 1500000000+i*7，i<130）≈34.500S/150.000E，与 SITL
# home 相距≈1.1°、同在南半球；旧场 39.900N/116.300E 已废）。
# 批1 改动1.7 曾删跨半球占位，但旧矩形（-36°~40.5°N）仍一张矩形同时罩住
# 南北两半球两场——地理约束形同虚设；本次收窄为紧贴这片演示空域的单一矩形，
# 四界对两场采样界半径余量≥0.5°（实测：SITL 纬向南余量 0.54°/经向西 0.57°；
# S4 纬向北余量 0.55°/经向东 0.55°；纬/经跨度各 1.95°，全矩形不出南半球）。
FENCE_RECTS: dict[int, tuple[int, int, int, int]] = {
    0: (-359_000_000, -339_500_000, 1_486_000_000, 1_505_500_000),
    1: (-359_000_000, -339_500_000, 1_486_000_000, 1_505_500_000),
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


def get_fence(class_id: int) -> tuple[int, int, int, int]:
    """机型类围栏查表：返回 (min_lat, max_lat, min_lon, max_lon) i32×1e7；
    未开放类=fail-closed 拒（与 get_rule 同法——围栏随机型开放面）。"""
    if class_id not in FENCE_RECTS:
        raise PolicyError("unsupported_class", f"机型类 {class_id} 未开放（无围栏规则）")
    rect = FENCE_RECTS[class_id]
    if rect[0] > rect[1] or rect[2] > rect[3]:
        raise PolicyError("bad_fence", "政策围栏矩形退化（min 界须 ≤ max 界）")
    return rect


def chain_policy_published(version_hashes) -> bool:
    """政策公示对拍（阶段四）：本地 paramsHash 是否在链上已发布版本集合中。

    fail-closed：链上没有任何已发布版本与本地政策表一致 → 受理拒绝
    （policy_unpublished）——政策表被单方变更/未公示即不可受理。
    version_hashes: 链上各版本 paramsHash 的 bytes 可迭代。
    """
    mine = bytes.fromhex(policy_params_hash())
    return any(bytes(h) == mine for h in version_hashes)
