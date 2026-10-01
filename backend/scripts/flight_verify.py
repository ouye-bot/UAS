# -*- coding: utf-8 -*-
"""P1/P2/P3 观感与操控成熟度批 · 实弹验证探针（2026-09-29）。

全 API 流（零替身）：登记→子凭证→本机出证→受理→取件→ARM→起链，然后逐项：
  V1 遥测字段（bat/gps/hud——P3）
  V2 有界自动爬升（恒定率？多快？——P1）
  V3 到达后定高保持精度（回中语义——P1）
  V4 手动脉冲语义（一击爬升量+脉冲后保持——P1）
  V5 围栏施压（持续按住=突破→breach 事件——P1）
  V6 FENCE_ACTION=3 刹停保持（不降落——P1/围栏钉死）
用法：cd uas/backend && python scripts/flight_verify.py
前置：backend(真链档)+bridge(sitl)+SITL GPS 锁定。微型档（围栏 50m）。
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
API = os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")
BRIDGE = os.environ.get("FZ_BRIDGE_BASE", "http://127.0.0.1:8100")


def _req(url, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"},
                                 method="POST" if body is not None else "GET")
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
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

    print("== P1/P2/P3 飞行验证探针（微型档·围栏 50m）==")
    # ---- 授权与 ARM（climb_probe 同款全真流程） ----
    holder_sk, holder_pk = generate_keypair()
    sn = "FZ-VFY-" + secrets.token_hex(2)
    rc, reg = api("/ra/register", {
        "username": "vfy-" + secrets.token_hex(3), "id_number": "110101199001011234",
        "cert_level": 3, "sn": sn, "user_pub_hex": holder_pk, "class_id": 1,
    })
    expect(rc == 200, "0.1 登记")
    cred = reg["data"]
    rc, sub = api("/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": "110101199001011234", "cert_level": 3, "sn": sn,
        "holder_pub_hex": holder_pk,
    })
    expect(rc == 200, "0.2 子凭证")
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
    expect(rc == 200 and st.get("task_id"), "0.3 出证任务受理")
    case_id = st["case_id"]
    prove_t = st["binding"]["t_epoch"]
    t0 = time.time()
    stat = ""
    for _ in range(200):
        time.sleep(4)
        _, t = bridge(f"/prove/task/{st['task_id']}")
        stat = t.get("status") or t.get("data", {}).get("status")
        if stat == "failed":
            print("  出证失败:", str(t)[:200])
            raise SystemExit(1)
        if stat == "done":
            break
    expect(stat == "done", f"0.4 本机出证完成（{time.time()-t0:.0f}s）")
    rc, snap = api("/ra/revocation/snapshot")
    rc, ap = api("/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub["message_hex"], "sub_sig_hex": sub["sig_hex"],
        "sub_cred_hash_hex": sub["sub_cred_hash_hex"], "nonce_hex": nonce_hex,
        "plan_hash_hex": plan_hash_hex, "class_id": 1, "case_id": case_id,
        "rev_root_hex": snap["data"]["root_hex"],
        "t_start": prove_t, "t_end": prove_t + 7200,
    })
    expect(rc == 200, "0.5 受理", json.dumps(ap, ensure_ascii=False)[:300])
    receipt_code = ap["data"]["receipt_code"]
    rr = {"status": "waiting"}
    t1 = time.time()
    while time.time() - t1 < 120:
        _, rr = api(f"/authz/receipt/{receipt_code}")
        rr = rr.get("data", rr)
        if rr["status"] != "waiting":
            break
        time.sleep(2)
    expect(rr["status"] == "ready", f"0.6 worker 验证 ready（{time.time()-t1:.0f}s）")
    _, pub = bridge("/engine_pub")
    payload = ecies_decrypt(holder_sk, bytes.fromhex(rr["token_cipher_hex"]))
    body, sig_hex = payload.rsplit(b"|", 1)
    tok = json.loads(body)
    expect(verify_digest(pub["engine_pub_hex"], sm3_bytes(body), sig_hex.decode()), "0.7 令牌验签")
    rc, arm = bridge("/arm", {"token_payload_hex": payload.hex(), "plan_hash_hex": plan_hash_hex}, timeout=300)
    expect(arm.get("ok") is True, "0.8 ARM 解锁", str(arm)[:140])
    rc, ts = bridge("/telemetry/start", {"auth_id": tok["authId"],
                                         "fence_state_hex": arm.get("fence_state_hex", "01320000")})
    expect(ts.get("ok") is True, "0.9 遥测链起链")

    def sample():
        _, s = bridge(f"/telemetry/sitl_sample?t_epoch={int(time.time())}")
        return s

    s = sample()
    expect(s.get("ok") is True, "0.10 真采样")
    alt0 = s.get("alt_cm") or 0

    # ---- V1 遥测字段（P3） ----
    bat, gps, hud = s.get("bat"), s.get("gps"), s.get("hud")
    print(f"  bat={bat} gps={gps} hud={hud}")
    expect(isinstance(bat, dict) and bat.get("voltage_v"), "V1a 电池遥测在案（电压>0）", str(bat))
    expect(isinstance(gps, dict) and gps.get("sats", 0) >= 6, "V1b GPS 卫星数在案（≥6）", str(gps))
    expect(isinstance(hud, dict) and hud.get("throttle_pct") is not None, "V1c HUD 油门/速度在案", str(hud))

    # ---- V2 有界自动爬升（P1）：目标 15m，采样线程并行记录剖面 ----
    profile: list[tuple[float, int]] = []

    def profiler():
        while not prof_done[0]:
            _, sp = bridge(f"/telemetry/sitl_sample?t_epoch={int(time.time())}")
            if sp.get("ok"):
                profile.append((time.time(), sp.get("alt_cm") or 0))
            time.sleep(0.35)

    prof_done = [False]
    th = threading.Thread(target=profiler, daemon=True)
    th.start()
    ta = time.time()
    rc, r = bridge("/sitl/climb?pwm=2000&until_alt_cm=1500&timeout_s=60", {}, timeout=90)
    prof_done[0] = True
    th.join(timeout=2)
    climb_t = time.time() - ta
    expect(rc == 200 and r.get("ok") is True and r.get("reached") is True,
           "V2a 有界自动爬升到达 15m", str(r)[:140])
    expect(climb_t <= 30, f"V2b 爬升耗时 ≤30s（实测 {climb_t:.1f}s）")
    seg = [p for p in profile if p[0] >= ta]
    if len(seg) >= 4:
        rates = []
        for i in range(1, len(seg)):
            dt = seg[i][0] - seg[i - 1][0]
            if dt > 0:
                rates.append((seg[i][1] - seg[i - 1][1]) / 100 / dt)
        mean_rate = sum(rates) / len(rates)
        print(f"  爬升率均值 {mean_rate:.2f} m/s（采样 {len(seg)} 点，爬升 {climb_t:.1f}s）")
        print(f"  [i] V2c 爬升率均值 {mean_rate:.2f} m/s（PILOT_SPEED_UP 未确认时以缺省速率飞行——观测项）")
    else:
        ok("V2c 爬升率采样点不足（跳过——到达判决已覆盖）")

    # ---- V3 到达后定高保持精度（回中语义） ----
    print("  [diag] 10s 密集采样：mode/alt/armed 轨迹")
    tdiag = time.time()
    while time.time() - tdiag < 10:
        sp = sample()
        if sp.get("ok"):
            print(f"    t+{time.time()-tdiag:.1f}s mode={sp.get('mode')} alt={sp.get('alt_cm')} fc_armed={sp.get('armed')}")
        time.sleep(0.4)
    time.sleep(1.0)
    h0 = (sample().get("alt_cm") or 0)
    hmin, hmax = h0, h0
    t3 = time.time()
    while time.time() - t3 < 6:
        sp = sample()
        if sp.get("ok"):
            a = sp.get("alt_cm") or 0
            hmin, hmax = min(hmin, a), max(hmax, a)
        time.sleep(0.4)
    print(f"  15m 保持带: {hmin}~{hmax} cm（基准 {h0} cm）")
    expect(hmax - hmin <= 150, "V3 定高保持精度（6s 内波动 ≤1.5m）", f"band={hmin}~{hmax}")

    # ---- V4 手动脉冲语义（P1） ----
    base = sample().get("alt_cm") or 0
    rc, r4 = bridge("/sitl/climb?pwm=1750&hold_s=2.5", {}, timeout=60)
    expect(rc == 200 and r4.get("ok") is True, "V4a 手动脉冲执行", str(r4)[:120])
    time.sleep(1.5)  # 回中后观察保持
    a4 = sample().get("alt_cm") or 0
    gain = a4 - base
    print(f"  单击爬升量: {gain} cm（{base}→{a4}），脉冲后 1.5s 保持偏移 {abs(a4 - (r4.get('alt_cm') or 0))} cm")
    expect(gain >= 120, "V4b 单击爬升 ≥1.2m（加力档手感）")
    # 脉冲后应保持（回中=定高），不降落
    t4 = time.time()
    amin = a4
    while time.time() - t4 < 5:
        a = sample().get("alt_cm") or 0
        amin = min(amin, a)
        time.sleep(0.4)
    expect(amin >= a4 - 120, "V4c 脉冲后定高保持（5s 内回落 ≤1.2m——不自行降落）",
           f"{a4}→{amin}")

    # ---- V5 围栏施压（持续按住=有意突破 50m 围栏） ----
    print("  == 围栏施压：持续脉冲推向 50m 围栏 ==")
    max_alt = 0
    breach_at = None
    statustext = None
    t5 = time.time()
    while time.time() - t5 < 160:
        rc, r5 = bridge("/sitl/climb?pwm=2000&hold_s=1.5", {}, timeout=60)
        sp = sample()
        a = sp.get("alt_cm") or 0
        max_alt = max(max_alt, a)
        if sp.get("fence_breached"):
            breach_at = time.time()
            statustext = sp.get("last_statustext")
            break
        if r5.get("fence_breached"):
            breach_at = time.time()
            statustext = r5.get("last_statustext")
            break
        if r5.get("code") == "fc_disarmed":
            break
        time.sleep(0.3)
    print(f"  施压峰值: {max_alt} cm（围栏 5000cm）| breach={breach_at is not None} | {statustext}")
    expect(breach_at is not None, "V5a 持续施压突破围栏（breach 事件触发）",
           f"max={max_alt}")
    expect(max_alt >= 10500, "V5b 突破点在围栏附近（≥105m——非远处被限制）", f"max={max_alt}")

    # ---- V6 FENCE_ACTION=3 刹停保持（不降落） ----
    t6 = time.time()
    while time.time() - t6 < 8:
        sp = sample()
        time.sleep(0.5)
    a6 = sample().get("alt_cm") or 0
    print(f"  触发后 8s 高度: {a6} cm（突破峰值 {max_alt} cm）")
    expect(a6 >= 3000, "V6 刹停保持（触发后 8s 仍在 30m 以上——非降落/非返航）", f"alt={a6}")

    bridge("/sitl/disarm", {}, timeout=30)
    print(f"== P1/P2/P3 飞行验证全绿：authId={tok['authId']} | 峰值 {max_alt} cm ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
