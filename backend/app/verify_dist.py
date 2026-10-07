"""验证工具分发站（2026-09-28 分发批）：TRAIL/AUTH 证明的第三方复验工具页。

形态（队长拍板建议落地）：backend app.mount 静态 dist 目录——
- GET /verify/          → 分发页（app/verify_static/index.html，git 内）
- GET /verify/dist/*    → 构建产物（backend/dist/，gitignore——二进制不进仓）
- GET /verify/api/checks→ 校验值 JSON（sha256 按磁盘实物实时计算，永不失真）

供应链口径：分发产物由 zksvc 尖峰副本 native 构建（vendor 与官方钉定快照
plonkish-4201a82 逐位一致，diff -rq 实证）；build_manifest 随发。验证器
verify-instances 不消费 vendor 树（PinDrift 仅 prove 面）——单二进制即可
独立复验，这正是分发站存在的产品理由。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["verify-dist"])

# 分发产物目录（backend/dist——根 .gitignore 的 dist/ 规则覆盖，二进制不进 git）
_DIST_DIR = Path(__file__).resolve().parents[1] / "dist"

# 页面展示的产物清单（顺序即页面行序）
_ARTIFACTS = ("zkc-linux-amd64", "zkc.wasm", "zksvc-build-manifest.json")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _pin_block() -> dict:
    """电路指纹公示对拍（活数据——与受理门控同一事实源）。

    2026-10-04 复查根修：分发页此前的指纹/合约名/tx 为硬编码，电路换代后
    漂移成旧值（17a90dc1 旧代 vs 当值 632071fa）且误写 FlightAuthRegistry。
    本地侧=vendor MANIFEST 公式（与 authz/service.py pin_fingerprint、
    scripts/publish_pin.py local_pin_digest 同构）；链侧=PolicyRegistry.circuitPin
    回读（与 authz/router.py _chain_pin 同源）。任一侧不可得=如实 None，
    match=None（未知）——不装一致。
    """
    import json as _json
    import os

    local_str = local_hex = None
    root = os.environ.get("FZ_ZKSVC_DIR")
    if root:
        try:
            with open(f"{root}/vendor/MANIFEST.json", encoding="utf-8") as f:
                man = _json.load(f)
            from app.crypto.sm3 import sm3_bytes

            local_str = f"SM3({man['pin_commit']}|{man['aggregate_sm3']})"
            local_hex = sm3_bytes(local_str.encode()).hex()
        except (OSError, KeyError):
            pass
    chain_hex = None
    try:
        from app.authz.router import _chain_pin

        cp = _chain_pin()
        if cp is not None:
            chain_hex = cp.hex()
    except Exception:
        pass
    match = (local_hex == chain_hex) if (local_hex and chain_hex) else None
    return {"local_str": local_str, "local_digest_hex": local_hex,
            "chain_digest_hex": chain_hex, "chain_contract": "PolicyRegistry.circuitPin",
            "match": match}


@router.get("/verify/api/checks")
def checks() -> JSONResponse:
    """产物校验值（实时计算）。未生成的产物如实标 missing——不硬编码，
    重建 dist 后页面数字自动换代。"""
    items = []
    for name in _ARTIFACTS:
        p = _DIST_DIR / name
        if p.is_file():
            items.append({"name": name, "bytes": p.stat().st_size, "sha256": _sha256(p)})
        else:
            items.append({"name": name, "sha256": None})
    return JSONResponse({"code": "ok", "data": {"artifacts": items, "pin": _pin_block()}})


@router.get("/verify/dist/trail_canonical_spec.json")
def trail_canonical_spec():
    """TRAIL 语句契约（公开规范件——浏览器 wasm 验证与离线复验共用输入；
    源=zksvc/tests 钉定文件，与出证装配同一事实源）。"""
    from fastapi.responses import FileResponse

    p = Path(__file__).resolve().parents[2] / "zksvc" / "tests" / "trail_canonical_spec.json"
    if not p.is_file():
        return JSONResponse(status_code=404, content={"code": "spec_missing"})
    return FileResponse(p, media_type="application/json")
