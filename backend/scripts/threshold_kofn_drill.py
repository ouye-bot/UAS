# -*- coding: utf-8 -*-
"""3.2 k-of-n 参数化实弹 drill（测试档 env 2-of-4 全动线——任务书验收）。

  [S1] 2-of-4 初始化分割（root.json threshold=2/domains=4 断言）
  [S2] 两域解锁（canary SM2 加密→d0/d1 两域 request_decrypt_share 四关替位
       全过→[dᵢ]C₁ 拉格朗日合成→threshold_decrypt k=2 原文对拍）
  [S3] 单份额不可解（1 域份额 combine k=2 拒——门限语义）
  [S4] 除名一域（配置 d0..d3→d1,d2,d3）→ ceremonial_reshare 跨 n 换代
       （旧 4 域取 3 份现配置可开份额→proactive_reshare n'=3→新 3 份+纪元 2
       +root.json domains 换代断言+D_pub 逐字不变）
  [S5] 解锁恢复（新 3 域中两域解锁→原文对拍——存量信封跨纪元零影响实弹）
  [S6] 旧域拒（d0 → bad_role——除名域份额域即时失效）
  [S7] 配置漂移 fail-closed（现配置 k=3 调 initialize_if_absent → config_
       mismatch 拒——静默换根钥红线）

用法：cd uas/backend && python scripts/threshold_kofn_drill.py
（自管临时 FZ_THRESHOLD_ROOT_DIR——不触生产 threshold_root。）
"""

from __future__ import annotations

import json
import secrets
import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import os

_tmp = tempfile.mkdtemp(prefix="fz_kofn_drill_")
os.environ["FZ_THRESHOLD_ROOT_DIR"] = str(Path(_tmp) / "threshold_root")
os.environ["FZ_THRESHOLD_K"] = "2"
os.environ["FZ_THRESHOLD_DOMAINS"] = "d0,d1,d2,d3"

from app.crypto.sm2 import encrypt as sm2_encrypt  # noqa: E402
from app.crypto.threshold import combine_decrypt_shares, decrypt_share, threshold_decrypt  # noqa: E402
from app.ra import threshold_shares as ts  # noqa: E402

_checks = 0


def expect(cond: bool, label: str, detail: str = "") -> None:
    global _checks
    if cond:
        _checks += 1
        print(f"  [OK] {label}")
        return
    print(f"  [FAIL] {label} {detail}")
    raise SystemExit(1)


def _hooks_all_pass() -> dict:
    """测试档四关替位（全 True——本 drill 验密码层/配置层/换代面；四关业务
    判定由 test_threshold_envelope/sync 钉面，此处非网络替身语义=判定逻辑
    不在本 drill 消费面）。"""
    return {
        "request_registered": lambda *a, **kw: True,
        "warrant_on_chain": lambda *_a: True,
        "collab_approved": lambda *_a: True,
        "owner_set_synced": lambda: True,
    }


def _unlock(domains: tuple[str, ...], canary: bytes, ct: bytes, k: int) -> None:
    c1_hex = ct[:64].hex()
    pts = []
    for idx, d in enumerate(domains, start=1):
        pt = ts.request_decrypt_share(
            d,
            c1_hex,
            verify_hooks=_hooks_all_pass(),
            warrant_hash_hex="11" * 32,
            cred_hash_hex="22" * 32,
            request_sha256_hex=secrets.token_hex(32),
        )
        pts.append((idx, pt))
        if len(pts) >= k:
            break
    assert threshold_decrypt(ct, pts, k=k) == canary


def main() -> int:
    print("== 3.2 k-of-n 参数化实弹 drill（测试档 2-of-4 全动线）==")
    # ---- [S1] 初始化 2-of-4 ----
    init = ts.initialize_if_absent()
    meta = json.loads((ts._root_dir() / "root.json").read_text(encoding="utf-8"))
    expect(
        init["created"] is True
        and int(meta["threshold"]) == 2
        and meta["domains"] == ["d0", "d1", "d2", "d3"],
        "S1 2-of-4 初始化（threshold=2/domains=4——d0..d3 四域密封）",
        f"meta={ {k: meta[k] for k in ('threshold', 'domains')} }",
    )
    pub_before = meta["pub_hex"]

    # ---- [S2] 两域解锁 ----
    canary = b"FZ-KOFN-DRILL-CANARY-1|"
    ct = sm2_encrypt(pub_before, canary)
    _unlock(("d0", "d1", "d2", "d3"), canary, ct, k=2)
    expect(True, "S2 两域解锁（d0/d1 四关过→[dᵢ]C₁ 合成→原文对拍）")

    # ---- [S3] 单份额不可解 ----
    c1_hex = ct[:64].hex()
    pt_one = ts.request_decrypt_share(
        "d0",
        c1_hex,
        verify_hooks=_hooks_all_pass(),
        warrant_hash_hex="11" * 32,
        cred_hash_hex="22" * 32,
        request_sha256_hex=secrets.token_hex(32),
    )
    try:
        combine_decrypt_shares([(1, pt_one)], c1_hex, k=2)
        expect(False, "S3 单份额不可解（应拒）")
    except Exception as e:  # noqa: BLE001
        expect("≥2" in str(e), "S3 单份额不可解（combine k=2 拒——门限语义）", str(e)[:80])

    # ---- [S4] 除名一域→re-share 跨 n 换代 ----
    os.environ["FZ_THRESHOLD_DOMAINS"] = "d1,d2,d3"
    ts._reset_config_cache()
    r = ts.ceremonial_reshare(gov_confirmed_epoch=2, owner_set_fp=None)
    meta2 = json.loads((ts._root_dir() / "root.json").read_text(encoding="utf-8"))
    expect(
        r["epoch"] == 2
        and meta2["domains"] == ["d1", "d2", "d3"]
        and meta2["pub_hex"] == pub_before,
        "S4 除名 d0→re-share 跨 n 换代（4→3 域+纪元 2+D_pub 逐字不变）",
        f"r={r}",
    )

    # ---- [S5] 解锁恢复（存量信封跨纪元+跨域集零影响） ----
    _unlock(("d1", "d2", "d3"), canary, ct, k=2)
    expect(True, "S5 解锁恢复（新 3 域中两域解锁原信封——跨纪元/跨域集零影响）")

    # ---- [S6] 旧域拒 ----
    try:
        ts.request_decrypt_share(
            "d0",
            c1_hex,
            verify_hooks=_hooks_all_pass(),
            warrant_hash_hex="11" * 32,
            cred_hash_hex="22" * 32,
            request_sha256_hex=secrets.token_hex(32),
        )
        expect(False, "S6 旧域应拒")
    except ts.ShareDomainError as e:
        expect(e.code == "bad_role", "S6 除名域份额域即时失效（d0 → bad_role）", e.code)
    except Exception as e:  # noqa: BLE001
        expect(False, "S6 旧域应拒（ShareDomainError）", str(e)[:80])

    # ---- [S7] 配置漂移 fail-closed ----
    # （参数自洽但与已初始化 root 不符的形态——3 域 d1,d2,d4 vs root 的
    # d1,d2,d3；k=n/k>n 等参数非法形态会先被启动断言拒=bad_threshold_config，
    # 同为 fail-closed 但非本测意图。）
    os.environ["FZ_THRESHOLD_DOMAINS"] = "d1,d2,d4"
    ts._reset_config_cache()
    try:
        ts.initialize_if_absent()
        expect(False, "S7 配置漂移应拒")
    except ts.ShareDomainError as e:
        expect(
            e.code == "config_mismatch",
            "S7 配置漂移 fail-closed（域集 d1,d2,d4 vs 已初始化 d1,d2,d3 → "
            "config_mismatch 拒——静默换根钥红线）",
            e.code,
        )

    print(f"\n== 3.2 k-of-n 实弹 drill 全绿：{_checks} 项断言 [OK] ==")
    print("    2-of-4 分割→两域解锁→单份额拒→除名跨 n 换代 re-share→解锁恢复→旧域拒→配置漂移拒")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
