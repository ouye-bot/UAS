"""zkc 子进程构型 profile 单源（批 4-4）：桥/worker 拼 env 的唯一取值点。

「实测数字对应哪个构型」必须一望而知——此前 SM3_LUT/PCS_*/RAYON/大栈等
构型 env 散落在桥 _prove_local 与 worker zkc_verify 两处拼装，无单一档位名。
本模块 =FZ_ZK_PROFILE 三档注册表（纯 stdlib，桥接进程跨包直载同源）：

- release-demo（缺省）＝现网缺省实测构型（与旧逐 env 形态逐键等价，桥/worker
  全量测试钉定零行为变化）：
    · 电路档准入旗标 FZ_ZK_ALLOW_AUTH/TRAIL=1（强制——服务装配面恒开）；
    · SM3_LUT=1（SM3 查表构型——zksvc assemble_auth 内部同值缺省，显式化）；
    · PCS_INTERLEAVE=1（叶交织承诺——zksvc 缺省开，显式化）；PCS_BATCH_DEDUP=0、
      PCS_VERIFY_STREAM=0（zksvc 缺省关，显式化）；
    · MASK 不触碰（零知识掩蔽缺省开；MASK_OFF 诊断开关按 zksvc 既有纪律由
      判决件自述，本档不注入不清除）；
    · RAYON_NUM_THREADS=12（RAYON 扫参判决最优档）、RUST_MIN_STACK=536870912
      （512MiB 大栈）、FZ_ZK_FORBID_SPEC_KEY=1（spec 明文私钥回落禁用——批 4-6）
      ——三者 setdefault 语义（显式 env 优先，运维可覆盖）。
- dev＝开发档：仅强制电路档准入旗标；构型/资源旋钮全部尊重显式 env（开发者
  可做 SM3_LUT=0 legacy、MASK_OFF 诊断等对照实验——判决件自述兜底）；缺省
  供值 RAYON=4/大栈 512MiB/禁 spec 私钥。
- pinned＝复测对拍档：零隐式注入——构型键必须在 env 显式齐备（缺一即人话
  拒绝列出缺项），供性能实测数字与构型的严格一一对应。

桥/worker 消费：zkc_env() 返回注入后的完整子进程 env；active_profile()/
describe() 供任务日志与 stage 信息打点（「哪个构型」一望而知）。
"""

from __future__ import annotations

import os

PROFILE_ENV = "FZ_ZK_PROFILE"
DEFAULT_PROFILE = "release-demo"

# 电路档准入旗标（三档全部强制——服务化装配/验证面恒开，非构型旋钮）
_ALLOW_FLAGS = {"FZ_ZK_ALLOW_AUTH": "1", "FZ_ZK_ALLOW_TRAIL": "1"}

# release-demo 构型身份键（强制注入——跨进程必须同构，证明/判决件互通）
_RELEASE_CIRCUIT = {
    "SM3_LUT": "1",
    "PCS_INTERLEAVE": "1",
    "PCS_BATCH_DEDUP": "0",
    "PCS_VERIFY_STREAM": "0",
}

# 资源/私钥通道旋钮（setdefault 语义——显式 env 优先）
_RELEASE_DEFAULTS = {
    "RAYON_NUM_THREADS": "12",
    "RUST_MIN_STACK": "536870912",
    "FZ_ZK_FORBID_SPEC_KEY": "1",
}
_DEV_DEFAULTS = {
    "RAYON_NUM_THREADS": "4",
    "RUST_MIN_STACK": "536870912",
    "FZ_ZK_FORBID_SPEC_KEY": "1",
}

# 优化 2（跨证明确定性产物复用）：zkc 子进程的确定性产物缓存目录 env——
# 只缓存 pinned 公开输入确定性导出的 setup/preprocess 工件（随机性纪律在
# zksvc/src/zk_cache.rs 模块头钉死；每证明盲化 λ/transcript 熵绝不入缓存）。
# zkc 侧无 env 即不开缓存（hermetic：直跑 zkc 行为与现状一致），故缺省目录
# 必须由桥/worker 拼装点单源透传（本模块）。
CACHE_DIR_ENV = "FZ_ZK_CACHE_DIR"


def _default_zk_cache_dir(env: dict[str, str]) -> str:
    """缓存目录缺省推导（显式 FZ_ZK_CACHE_DIR 恒尊重——setdefault 语义）：

    ① FZ_ZK_CASES_DIR 同级 cache/（桥形态缺省——WSL 桥的案卷目录在本地盘，
       同级 cache 同盘落位，满足「缓存必须落 ext4 本地盘禁 /mnt/c」；/mnt
       前缀防护在桥 prover.py _guard_cache_dir_ext4 顶替为工作区本地盘）；
    ② FZ_ZKSVC_DIR 本地 cache/（worker/直跑形态——无案卷目录语境时回落）；
    ③ 两源皆缺 → 空串（不注入——zkc 纯计算路径，与现状完全一致）。
    """
    cases = (env.get("FZ_ZK_CASES_DIR") or "").strip()
    if cases:
        return os.path.join(os.path.dirname(os.path.abspath(cases)), "cache")
    zksvc = (env.get("FZ_ZKSVC_DIR") or "").strip()
    if zksvc:
        return os.path.join(zksvc, "cache")
    return ""

# pinned 档必须显式齐备的构型键（零隐式——缺一即拒）
_PINNED_REQUIRED = (
    "FZ_ZK_ALLOW_AUTH",
    "FZ_ZK_ALLOW_TRAIL",
    "SM3_LUT",
    "PCS_INTERLEAVE",
    "PCS_BATCH_DEDUP",
    "PCS_VERIFY_STREAM",
    "RAYON_NUM_THREADS",
    "RUST_MIN_STACK",
    "FZ_ZK_FORBID_SPEC_KEY",
)


def active_profile() -> str:
    """当前构型档名（FZ_ZK_PROFILE，缺省 release-demo；非法值人话拒绝）。"""
    name = (os.environ.get(PROFILE_ENV) or "").strip() or DEFAULT_PROFILE
    if name not in ("release-demo", "dev", "pinned"):
        raise RuntimeError(
            f"{PROFILE_ENV}={name} 非法——可选 release-demo（缺省现网构型）/"
            "dev（开发覆盖）/pinned（逐 env 显式对拍）"
        )
    return name


def zkc_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """按当前档返回 zkc 子进程 env（base 缺省=os.environ 快照）。

    - release-demo：强制档＝allow 旗标+电路身份键（SM3_LUT/PCS_*——与 zksvc
      内部缺省同值，显式化不等价于改构型）；缺省档＝RAYON/大栈/禁 spec 私钥。
    - dev：仅强制 allow 旗标，其余显式 env 优先、缺省供值兜底。
    - pinned：不注入任何值——构型键须 env 显式齐备（fail-closed 列缺项）。
    """
    env = dict(os.environ if base is None else base)
    name = active_profile()
    if name == "pinned":
        missing = [k for k in _PINNED_REQUIRED if not (env.get(k) or "").strip()]
        if missing:
            raise RuntimeError(
                "pinned 构型档要求构型键逐 env 显式齐备（零隐式注入，供复测对拍）"
                f"——缺 {len(missing)} 项：{', '.join(missing)}"
            )
        return env
    if name == "dev":
        env.update(_ALLOW_FLAGS)
    else:  # release-demo
        env.update(_ALLOW_FLAGS)
        env.update(_RELEASE_CIRCUIT)
    for k, v in (_DEV_DEFAULTS if name == "dev" else _RELEASE_DEFAULTS).items():
        env.setdefault(k, v)
    # 优化 2：确定性产物缓存目录缺省透传（setdefault——显式值恒尊重；pinned
    # 档零隐式注入纪律不变，缺省不注入由对拍方自带 env）
    cache_default = _default_zk_cache_dir(env)
    if cache_default:
        env.setdefault(CACHE_DIR_ENV, cache_default)
    return env


def describe(profile: str | None = None) -> str:
    """构型自述串（任务日志/stage 打点——「哪个构型」一望而知）。"""
    name = profile or active_profile()
    if name == "release-demo":
        circuit = " ".join(f"{k}={v}" for k, v in _RELEASE_CIRCUIT.items())
        return (
            "zk_profile=release-demo "
            f"({circuit} MASK=on RAYON=12 STACK=512MiB forbid_spec_key=1)"
        )
    if name == "dev":
        return "zk_profile=dev (allow flags forced; 构型旋钮尊重显式 env; RAYON=4 缺省)"
    return "zk_profile=pinned (逐 env 显式——零隐式注入)"
