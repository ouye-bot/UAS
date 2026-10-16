"""分发面与现役引擎代同步门禁（2026-10-15 根修批——结构性防复发，任务书钉定）。

病征（2026-10-15 队长手测实弹）：backend/dist/zkc.wasm 停留 9/28 旧代构建
（binding 报文 FZ-TRAIL-BIND| 旧域模板、无 FZ_ENGINE_PUB_HEX 运行时验签基准），
而分发面 /verify/dist/trail_canonical_spec.json 已按现役引擎钥 FZ-TRAIL-BIND2|
七字段（auth_id/alt_max_cm/chain_head/围栏 4 界）实时重签——浏览器 wasm 装配
面组旧格式报文验新签名恒败（「装配拒绝: 字节字段 binding 非法」）。真链主链
路全绿（桥本机/后端 worker 均走现役 native zkc），唯分发面代差被测试盲区放行
（wasm-verify-worker 单测全桩 WASI/WebAssembly，从不跑真 wasm）。

本门禁（CI 常备，让代差在 CI 阶段红，不再靠队长手测抓）：
①签发侧↔验证侧报文模板逐字对拍：verify_dist.py 重签报文 == zksvc/src/
  assemble.rs 装配验签报文（域分隔+字段序）——任何一侧换代另一侧未跟=当场红；
②分发产物代标记（期望值从现役源码派生，不硬编码）：dist/zkc.wasm 字节级含
  assemble.rs 现役报文域+ENV_ENGINE_PUB_HEX 运行时验签基准、不含旧代域
  ——旧代产物进不了分发面（与 build_dist.py 分发口门禁双保险）；dist 从未
  生成=分发页如实标「未生成」，无陈旧物可陈；
③分发 wasm 实弹全验证门（真链新鲜材料+浏览器同款 WASI shim 全路径）钉在
  e2e_frontend_api.py §5.4b/§5.4c——用当窗真实案卷材料实跑分发 wasm
  verify-instances 正例 OK+篡改期望拒绝（node 是前端门禁既有前提）。
"""

from __future__ import annotations

import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
DIST_WASM = BACKEND / "dist" / "zkc.wasm"
ASSEMBLE_RS = REPO / "zksvc" / "src" / "assemble.rs"

# 规范字段序（七字段——assemble.rs/profile.rs/verify_dist.py 三方同源口径）
CANONICAL_FIELDS = [
    "auth_id",
    "alt_max_cm",
    "chain_head_hex",
    "min_lat",
    "max_lat",
    "min_lon",
    "max_lon",
]


def _verify_dist_template_fields() -> tuple[str, list[str]]:
    """从 verify_dist.py 重签报文 f-string 提取（域, 字段序）（单源=签发侧源码本体）。"""
    src = (BACKEND / "app" / "verify_dist.py").read_text(encoding="utf-8")
    dm = re.search(r'f"(FZ-TRAIL-BIND\d*)\|', src)
    assert dm, "verify_dist.py 缺 FZ-TRAIL-BIND* 重签报文域（签发面被换代？）——门禁失明即失败"
    m = re.search(r"msg = \(\s*f\"FZ-TRAIL-BIND\d*\|(.*?)\)\s*$", src, re.S | re.M)
    assert m, "verify_dist.py 缺 FZ-TRAIL-BIND* 重签报文（签发面被换代？）——门禁失明即失败"
    # body 已含全部续行 f-string 片段——b['field'] 出现序=报文字段序
    # （chain_head 形如 {str(b['chain_head_hex']).lower()}，取 b['..'] 通配）
    return dm.group(1), re.findall(r"b\['(\w+)'\]", m.group(1))


def _assemble_template_fields() -> tuple[str, list[str]]:
    """从 zksvc/src/assemble.rs format! 报文提取（域, 字段序）（单源=验证侧源码本体）。"""
    src = ASSEMBLE_RS.read_text(encoding="utf-8")
    m = re.search(r'format!\(\s*"(FZ-TRAIL-BIND\d*)\|(.*?)"\s*,(.*?)\);', src, re.S)
    assert m, "assemble.rs 缺 FZ-TRAIL-BIND* 装配验签报文（验证面被换代？）——门禁失明即失败"
    names: list[str] = []
    for raw in m.group(3).split(","):
        raw = raw.strip()
        if not raw:
            continue
        raw = raw.replace("binding.", "").strip()
        raw = re.sub(r".*\.to_ascii_lowercase\(\)", "chain_head_hex", raw)
        raw = raw.strip("*").strip()
        if raw and not raw.startswith('"'):
            names.append(raw)
    return m.group(1), names


def test_binding_message_template_signer_verifier_parity():
    """①签发侧↔验证侧报文模板逐字对拍（域+七字段序）。"""
    signer_domain, signer = _verify_dist_template_fields()
    verifier_domain, verifier = _assemble_template_fields()
    assert signer_domain == verifier_domain, (
        f"binding 报文域代差：签发侧 {signer_domain} vs 验证侧 {verifier_domain}"
    )
    assert signer == CANONICAL_FIELDS, f"重签报文字段序漂移：{signer}"
    assert verifier == CANONICAL_FIELDS, f"装配验签字段序漂移：{verifier}"


def test_dist_artifact_generation_markers():
    """②分发产物代标记（期望值从现役源码派生，wasm 与 ELF 双产物对称——与
    build_dist.py 分发口双门同口径）：现役报文域+运行时钥基准在位，旧代域
    绝迹。两产物是同一验证面的两种载体（浏览器 wasm/离线 ELF）。"""
    verifier_domain, _ = _assemble_template_fields()
    src = (REPO / "zksvc" / "src" / "profile.rs").read_text(encoding="utf-8")
    env_m = re.search(r'const\s+ENV_ENGINE_PUB_HEX:\s*&str\s*=\s*"([^"]+)"', src)
    if not env_m:
        # 常量定义换名/换文件=装配面运行时钥面被换代——点名要求同步本门禁
        raise AssertionError(
            "profile.rs 缺 ENV_ENGINE_PUB_HEX 常量（运行时钥面被换代？）——请同步更新本门禁"
        )
    current_markers = (
        verifier_domain.encode() + b"|",
        env_m.group(1).encode(),
    )
    stale_domain = b"FZ-TRAIL-BIND|" if verifier_domain != "FZ-TRAIL-BIND" else b"FZ-TRAIL-BIND2|"
    for artifact in (DIST_WASM, BACKEND / "dist" / "zkc-linux-amd64"):
        if not artifact.is_file():
            # 从未分发生成（/verify/ 页如实标「未生成」）——无陈旧物可陈，如实放行
            continue
        data = artifact.read_bytes()
        for marker in current_markers:
            assert marker in data, (
                f"分发面 {artifact.name} 缺现役代标记 {marker.decode()!r}——旧代构建在分发（"
                "与现役引擎绑定报文/运行时钥代不同步，浏览器/离线验证必败）；"
                "请从现役 zksvc 源重建并重跑 scripts/build_dist.py（构建配方见其头注）"
            )
        assert stale_domain not in data, (
            f"分发面 {artifact.name} 含旧代 binding 模板 {stale_domain.decode()!r}——"
            "现役签名必验败；该产物必须立即重建"
        )
