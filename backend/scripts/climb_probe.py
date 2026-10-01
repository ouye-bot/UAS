# -*- coding: utf-8 -*-
"""爬升实弹探针（2026-09-27 队长实测「爬升无高度变化」根因批的复现判决）。

全 API 流（零替身）：登记→子凭证→本机出证→受理→取件→ARM→起链→爬升→
高度实测。判决=爬升后相对高度显著高于爬升前（地面怠速自动上锁已由
DISARM_DELAY=0+fc_armed 旁路+同会话重解锁三层根治）。

用法：cd uas/backend && python scripts/climb_probe.py
前置：backend(真链档)+bridge(sitl)+SITL GPS 锁定。
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
UAS = Path(__file__).resolve().parents[2]
API = os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")
BRIDGE = os.environ.get("FZ_BRIDGE_BASE", "http://127.0.0.1:8100")
CASES = UAS / "backend" / "fz-zk-cases"


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _req(url, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"},
                                 method="POST" if body is not None else "GET")
    try:
        with opener().open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except ValueError:
            return e.code, {}


def api(path, body=None, timeout=60):
    return _req(API + path, body, timeout)


def bridge(path, body=None, timeout=60):
    return _req(BRIDGE + path, body, timeout)


def expect(cond, label, detail=""):
    print(("  [OK] " if cond else "  [FAIL] ") + label + (f" {detail}" if detail and not cond else ""))
    if not cond:
        raise SystemExit(1)


def main() -> int:
    from app.crypto.sm2 import decrypt as ecies_decrypt
    from app.crypto.sm2 import generate_keypair
    from app.crypto.sm2 import verify_digest
    from app.crypto.sm3 import sm3_bytes

    print("== 爬升实弹探针（ARM→climb→高度实测）==")
    holder_sk, holder_pk = generate_keypair()
    sn = "FZ-CLB-" + secrets.token_hex(2)
    rc, reg = api("/ra/register", {
        "username": "clb-" + secrets.token_hex(3), "id_number": "110101199001011234",
        "cert_level": 3, "sn": sn, "user_pub_hex": holder_pk, "class_id": 1,
    })
    expect(rc == 200, "1.1 登记")
    cred = reg["data"]
    rc, sub = api("/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": "110101199001011234", "cert_level": 3, "sn": sn,
        "holder_pub_hex": holder_pk,
    })
    expect(rc == 200, "1.2 子凭证")
    sub = sub["data"]
    nonce_hex = secrets.token_hex(16)
    plan_hash_hex = secrets.token_bytes(32).hex()
    rc, st = bridge("/prove/start", {
        "plan_hash_hex": plan_hash_hex, "nonce_hex": nonce_hex, "class_id": 1,
        "id_number": "110101199001011234", "cert_level": 3, "sn": sn,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub["id_prime_hex"],
        "sig_hex": sub["sig_hex"], "expires_at": sub["expires_at"],
        "holder_sk_hex": holder_sk, "holder_pk_hex": holder_pk,
    })
    expect(rc == 200 and st.get("task_id"), "1.3 出证任务受理")
    case_id = st["case_id"]
    prove_t = st["binding"]["t_epoch"]
    t0 = time.time()
    for _ in range(200):
        time.sleep(4)
        _, t = bridge(f"/prove/task/{st['task_id']}")
        stat = t.get("status") or t.get("data", {}).get("status")
        if stat == "failed":
            print("  出证失败:", str(t)[:200]); raise SystemExit(1)
        if stat == "done":
            break
    expect(stat == "done", f"1.4 本机出证完成（{time.time()-t0:.0f}s）")
    rc, snap = api("/ra/revocation/snapshot")
    rc, ap = api("/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub["message_hex"], "sub_sig_hex": sub["sig_hex"],
        "sub_cred_hash_hex": sub["sub_cred_hash_hex"], "nonce_hex": nonce_hex,
        "plan_hash_hex": plan_hash_hex, "class_id": 1, "case_id": case_id,
        "rev_root_hex": snap["data"]["root_hex"],
        "t_start": prove_t, "t_end": prove_t + 7200,
    })
    expect(rc == 200, "2.1 受理")
    receipt_code = ap["data"]["receipt_code"]
    rr = {"status": "waiting"}
    t1 = time.time()
    while time.time() - t1 < 120:
        _, rr = api(f"/authz/receipt/{receipt_code}")
        rr = rr.get("data", rr)
        if rr["status"] != "waiting":
            break
        time.sleep(2)
    expect(rr["status"] == "ready", f"2.2 worker 验证 ready（{time.time()-t1:.0f}s）")
    _, pub = bridge("/engine_pub")
    payload = ecies_decrypt(holder_sk, bytes.fromhex(rr["token_cipher_hex"]))
    body, sig_hex = payload.rsplit(b"|", 1)
    tok = json.loads(body)
    expect(verify_digest(pub["engine_pub_hex"], sm3_bytes(body), sig_hex.decode()), "2.3 令牌验签")
    rc, arm = bridge("/arm", {"token_payload_hex": payload.hex(), "plan_hash_hex": plan_hash_hex}, timeout=300)
    expect(arm.get("ok") is True, "3.1 ARM 解锁", str(arm)[:140])
    rc, ts = bridge("/telemetry/start", {"auth_id": tok["authId"], "fence_state_hex": arm.get("fence_state_hex", "01780000")})
    expect(ts.get("ok") is True, "3.2 遥测链起链")

    def sample():
        _, s = bridge(f"/telemetry/sitl_sample?t_epoch={int(time.time())}")
        return s

    s = sample()
    expect(s.get("ok") is True, "3.3 真采样", str(s)[:140])
    alt_before = s.get("alt_cm") or 0
    print(f"  爬升前高度: {alt_before} cm | fc_armed: {s.get('armed')}")
    rc1, r1 = bridge("/sitl/climb?pwm=1720&hold_s=3.0", {}, timeout=60)
    expect(rc1 == 200 and r1.get("ok") is True, "3.4 爬升指令生效（自动切入定高）", str(r1)[:140])
    peak = r1.get("alt_cm") or 0
    t2 = time.time()
    while time.time() - t2 < 12:
        s = sample()
        peak = max(peak, s.get("alt_cm") or 0)
        time.sleep(0.5)
    print(f"  爬升后峰值高度: {peak} cm（爬升前 {alt_before} cm）")
    expect(peak > alt_before + 100, "4.1 判决：爬升后高度实测上升（>1m）",
           f"before={alt_before} peak={peak}")

    # 4.2 悬停定高（ALT_HOLD 油门 1500=保持）——高度应稳定在悬停起点附近
    rc_h, hover0 = bridge("/sitl/climb?pwm=1500&hold_s=1.5", {}, timeout=60)
    expect(rc_h == 200 and hover0.get("ok") is True, "4.2 悬停指令生效（定高模式）", str(hover0)[:140])
    h0 = hover0.get("alt_cm") or 0
    hmin, hmax = h0, h0
    t3 = time.time()
    while time.time() - t3 < 10:
        s = sample()
        if s.get("ok"):
            a = s.get("alt_cm") or 0
            hmin, hmax = min(hmin, a), max(hmax, a)
        time.sleep(0.5)
    print(f"  悬停带: {hmin}~{hmax} cm（基准 {h0} cm）")
    expect(hmax - hmin <= 300, "4.3 判决：悬停高度带稳定（10s 内波动 ≤3m）",
           f"band={hmin}~{hmax}")

    # 4.4 采样至 128（2Hz 客户端驱动——FlightView 同款序列）
    s = sample()
    while s.get("n", 0) < 128:
        time.sleep(0.5)
        s = sample()
        if not s.get("ok"):
            break
    expect(s.get("n", 0) >= 128, f"4.4 采样满 128（当前 {s.get('n')}）")

    # 4.4' 检查点锚定（2026-09-28 锚定对拍前置：零锚定授权不出轨迹绑定）
    rc_a, anch = bridge("/telemetry/anchor", {}, timeout=120)
    expect(rc_a == 200 and anch.get("ok") is True and anch.get("anchored", 0) >= 1,
           "4.4' 检查点锚定（锚定对拍前置）", str(anch)[:120])

    # 4.5 TRAIL 出证+判决件即时取回（done 瞬间开始打点——可见性窗口判决）
    rc_t, tr = bridge("/prove/trail/start", {"alt_max_cm": tok["alt_max"] * 100}, timeout=30)
    expect(rc_t == 200 and tr.get("task_id"), "4.5 TRAIL 出证受理")
    t4 = time.time()
    stat = ""
    while time.time() - t4 < 300:
        time.sleep(2)
        _, t = bridge(f"/prove/task/{tr['task_id']}")
        stat = t.get("status") or t.get("data", {}).get("status")
        if stat in ("done", "failed"):
            break
    expect(stat == "done", f"4.6 TRAIL 出证完成（{time.time()-t4:.0f}s）")
    done_at = time.time()
    flips = []
    for _ in range(30):
        rc_v, _ = bridge(f"/prove/case/{tr['case_id']}/verdict.json", timeout=10)
        flips.append(rc_v)
        if rc_v == 200:
            break
        time.sleep(0.4)
    expect(flips[-1] == 200, f"4.7 判决件取回 200（时序 {flips}）")
    print(f"== 飞行功能探针全绿：authId={tok['authId']} | 爬升 {alt_before}→{peak} cm | "
          f"悬停带 {hmin}~{hmax} cm | verdict 可用于 done+{time.time()-done_at:.1f}s ==")
    bridge("/sitl/disarm", {}, timeout=30)
    return 0


if __name__ == "__main__":
    sys.exit(main())
