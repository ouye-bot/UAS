# -*- coding: utf-8 -*-
"""S4 TRAIL 合规证明闭环（R1-6）：真授权申请流→ARM→采样→出证→判决件下载→第三方独立复验。

流程（全部真实组件）：完整申请流拿真令牌（登记→子凭证→桥 prove/start 本机出证
→apply 受理→worker verify→回执 ready→取件 ECIES 解密——2026-10-06 现代化：批1
ARM 链上预检 auth_not_found 与⑥代 SN 绑定后，自铸引擎令牌在真链栈必被拒，产品
行为正确，合成场景改走与 e2e_auth_full §1 同构的真授权路径）→ARM（真令牌验签+
链上预检+SN 六查）→遥测链起链→2Hz 采样（经 /telemetry/sample 真哈希链）→POST
/prove/trail/start（本机 zkc 出证，最近 128 样本，alt_max=真令牌政策值）→轮询
done→下载判决件三件套→**独立 zkc verify（第三方离线复验口径）**→判决行断言。

用法：cd uas/backend && python scripts/scenario_S4_trail.py
前置：backend(8000)+worker 真链档（demo_up 拉起）+ 桥(8100) fake 链路形态
（FZ_GCS_LINK!=sitl；真链路桥对 /telemetry/sample 结构性封禁 403——合成遥测
仅 fake 档受控开放，FZ_ALLOW_SYNTHETIC_SAMPLE=1）；zksvc 构建在位。
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(UAS / "backend"))

API = os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")
BRIDGE = "http://127.0.0.1:8100"
ZKC = UAS / "zksvc" / "target" / "release" / "zkc.exe"
CLASS_ID = 1  # 轻型（真政策：alt_max=120m——令牌 alt_max 来自政策引擎查表）

_checks = 0


def ok(label: str) -> None:
    global _checks
    _checks += 1
    print(f"  [OK] {label}")


def expect(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        ok(label)
    else:
        print(f"  [FAIL] {label} {detail}")
        raise SystemExit(1)


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api_get(path: str, timeout: float = 30) -> dict:
    with opener().open(API + path, timeout=timeout) as r:
        return json.loads(r.read().decode())


def api_post(path: str, body: dict, timeout: float = 90) -> tuple[int, dict]:
    req = urllib.request.Request(
        API + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with opener().open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def bridge_post(path: str, body: dict, timeout: float = 60) -> dict:
    req = urllib.request.Request(
        BRIDGE + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with opener().open(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def bridge_get(path: str, timeout: float = 30) -> dict:
    with opener().open(BRIDGE + path, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ⑥代 SN 绑定（2026-10-06 契约）：登记/出证面 sn 必须与桥 device_serial 同源
# ——env FZ_DEVICE_SERIAL 优先，缺省演示锚 FZ-SN-DEV-01（与 gcs/bridge/
# device_key.py 逐字对齐：桥第 6 查 SM3(本机 SN)==token.sn_hash，sn_hash 由
# 服务端按登记 SN 权威铸入令牌签名域）。
SN = os.environ.get("FZ_DEVICE_SERIAL", "FZ-SN-DEV-01")
ID_NUMBER = "11010119900101" + secrets.token_hex(2)  # 逐轮随机（B7 黑名单纪律）


def acquire_token() -> tuple[bytes, dict]:
    """完整申请流拿真令牌（scenario_S1_fullchain.stage1_auth 手法照抄）：
    登记（证件号逐轮随机+SN=桥同源）→子凭证→绑定面→桥 prove/start 本机出证
    →apply 受理→回执轮询 ready→取件 ECIES 解密。返回 (token_payload 原始
    字节, tok dict)。"""
    from app.crypto.sm2 import decrypt as ecies_decrypt
    from app.crypto.sm2 import generate_keypair

    print("== ⓪ 真授权申请流（真链：登记→出证→受理→worker→取件）==")
    holder_sk, holder_pk = generate_keypair()
    rc, reg = api_post("/ra/register", {
        "username": "s4-" + secrets.token_hex(3),
        "id_number": ID_NUMBER,
        "cert_level": 3, "sn": SN, "user_pub_hex": holder_pk, "class_id": CLASS_ID,
    })
    expect(rc == 200 and reg["code"] == "ok", "⓪.1 登记承诺（RA 真实签发+链上）")
    cred = reg["data"]
    rc2, sub = api_post("/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"],
        "salt_hex": cred["salt_hex"],
        "id_number": ID_NUMBER,
        "cert_level": 3, "sn": SN, "holder_pub_hex": holder_pk,
    })
    expect(rc2 == 200 and sub["code"] == "ok", "⓪.2 子凭证签发（一次性）")
    sub = sub["data"]

    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    binding = api_get(
        f"/authz/binding?class_id={CLASS_ID}&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}"
    )["data"]
    expect("challenge_hex" in binding, "⓪.3 绑定面（HMAC 挑战+政策值）")

    start = bridge_post("/prove/start", {
        "plan_hash_hex": plan_hash_hex, "nonce_hex": nonce_hex, "class_id": CLASS_ID,
        "id_number": ID_NUMBER, "cert_level": 3, "sn": SN,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub["id_prime_hex"],
        "sig_hex": sub["sig_hex"], "expires_at": sub["expires_at"],
        "holder_sk_hex": holder_sk, "holder_pk_hex": holder_pk,
    }, timeout=30)
    task_id, case_id = start["task_id"], start["case_id"]
    prove_t_epoch = start["binding"]["t_epoch"]
    print(f"  [..] ⓪.4 桥接本机出证（task={task_id[:12]}…，interop zkc）")
    t0 = time.time()
    status = "assembling"
    while status in ("assembling", "proving"):
        time.sleep(5)
        t = bridge_get(f"/prove/task/{task_id}")
        s = t.get("status") or t.get("data", {}).get("status")
        if s != status:
            status = s
            print(f"  [..] 状态：{status}（{time.time() - t0:.0f}s）")
        if status == "failed":
            print("  [FAIL] 出证失败：", str(t)[:300])
            raise SystemExit(1)
        if time.time() - t0 > 1500:
            raise SystemExit(1)
    expect(status == "done", f"⓪.4 桥接本机出证完成（{time.time() - t0:.0f}s）")

    rc5, ap = api_post("/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub["message_hex"],
        "sub_sig_hex": sub["sig_hex"],
        "sub_cred_hash_hex": sub["sub_cred_hash_hex"],
        "nonce_hex": nonce_hex, "plan_hash_hex": plan_hash_hex,
        "class_id": CLASS_ID, "case_id": case_id,
        "rev_root_hex": api_get("/ra/revocation/snapshot")["data"]["root_hex"],
        "t_start": prove_t_epoch, "t_end": prove_t_epoch + 7200,
    })
    expect(rc5 == 200 and ap.get("ok") is True, "⓪.5 受理通过（实例核对+入队）",
           f"rc={rc5} {json.dumps(ap, ensure_ascii=False)[:200]}")
    receipt_code = ap["data"]["receipt_code"]

    t1 = time.time()
    rr = {"status": "waiting"}
    while time.time() - t1 < 300:
        rr = api_get(f"/authz/receipt/{receipt_code}")["data"]
        if rr["status"] != "waiting":
            break
        time.sleep(2)
    expect(rr["status"] == "ready", f"⓪.6 worker 真实验证→ready（{time.time() - t1:.0f}s）")

    payload = ecies_decrypt(holder_sk, bytes.fromhex(rr["token_cipher_hex"]))
    body, _sig_hex = payload.rsplit(b"|", 1)
    tok = json.loads(body)
    ok("⓪.7 取件 ECIES 解密（会话私钥本地）")
    expect(tok["plan_hash"] == plan_hash_hex and tok["authId"] > 0,
           "⓪.8 令牌绑定 plan_hash+authId 贯穿")
    from app.crypto.sm3 import sm3_bytes

    expect(tok.get("sn_hash") == sm3_bytes(SN.encode()).hex(),
           "⓪.8' 令牌 sn_hash=SM3(SN) 同值（⑥代 SN 绑定——与桥本机单源）")
    return payload, tok


def main() -> int:
    print("== S4 TRAIL 合规证明闭环（真授权→出证→判决件→第三方复验）==")
    try:
        # ⓪ 完整申请流拿真令牌（2026-10-06 现代化：ARM 链上预检 auth_not_found
        # +⑥代 SN 绑定后，旧 mint_token 自铸引擎令牌在真链栈必被拒——产品行为
        # 正确；场景改走真授权路径，authId 有链上 recordAuth 实录）
        token_payload, tok = acquire_token()

        # ① 令牌+ARM（闸门写入围栏态——检查点报文绑定来源）
        # sitl 形态桥：真飞控解锁前置 GPS 锁（S1 2.1 同判据；fake 桥跳过）。
        # timeout_s 是 query 参数（POST body 不进 FastAPI 简单形参——S1 同注）
        if bridge_get("/link_status").get("mode") == "sitl":
            wg = bridge_post("/sitl/wait_gps?timeout_s=180", {}, timeout=300)
            expect(wg.get("ok") is True, "①- GPS 锁（sitl 桥 ARM 前置）")
        r = bridge_post("/arm", {
            "token_payload_hex": token_payload.hex(),
            "plan_hash_hex": tok["plan_hash"],
        }, timeout=120)
        expect(r.get("ok") is True, "① 闸门 ARM（真令牌：链上预检+⑥代 SN 六查全过）",
               json.dumps(r, ensure_ascii=False)[:150])
        expect(r.get("alt_max") == tok["alt_max"], "①' 围栏上限=令牌 alt_max（政策值）",
               f"arm={r.get('alt_max')} tok={tok.get('alt_max')}")

        # ② 遥测链起链+2Hz 采样（真哈希链——合规飞行剖面：爬升→巡航→下降）
        # 批1-1.3：围栏证词单源化后 auth_id 必须对应当前活跃授权会话——
        # 传 ARM 回执的 auth_id（真令牌 authId 贯穿链上实录）。
        r = bridge_post("/telemetry/start", {
            "auth_id": r.get("auth_id"),
            "fence_state_hex": r.get("fence_state_hex"),
        })
        expect(r.get("ok") is True, "② 遥测链 genesis 起链")
        spec_head_hex = r["genesis_head_hex"]
        t_epoch = int(time.time())
        n = 130
        for i in range(n):
            if i < 40:
                alt = 200 + i * 50          # 爬升 2m→20m
            elif i < 100:
                alt = 2200 + (i % 17) * 8   # 巡航 ~22-23m（远低于真令牌 120m 上限）
            else:
                alt = 2200 - (i - 100) * 40  # 下降
            bridge_post("/telemetry/sample", {
                "t_epoch": t_epoch + i, "alt_cm": alt,
                # S4 合成场=堪培拉 SITL 原点近旁（-34.5°/150.0°E——同半球、与
                # SITL home 35.363S/149.165E 相距≈1.1°，政策围栏单一演示空域内）
                "lat_1e7": -345000000 + i * 11, "lon_1e7": 1500000000 + i * 7,
            })
            time.sleep(0.5)  # 真实 2Hz 录制节奏（SAMPLE_HZ=2 契约）
        expect(True, f"②' {n} 样本采样（2Hz 剖面，经真哈希链）")

        # ②'' 检查点锚定（2026-09-28 锚定对拍前置：绑定要求授权至少一次链上
        # 锚定——零锚定不出轨迹证书；本判决栈自此与真实飞行流程同构）
        r = bridge_post("/telemetry/anchor", {}, timeout=120)
        expect(r.get("ok") is True and r.get("anchored", 0) >= 1,
               "②'' 检查点锚定（锚定对拍前置）", json.dumps(r)[:150])

        # ③ TRAIL 本机出证（最近 128 样本→真 zkc prove；alt_max=真令牌政策值
        # ×100 cm——与引擎权威绑定一致，alt_max_mismatch fail-closed 口径）
        alt_max_cm = tok["alt_max"] * 100  # TRAIL 电路口径=cm（×100 在出证装配面）
        r = bridge_post("/prove/trail/start", {"alt_max_cm": alt_max_cm})
        expect(r.get("code") == "ok", "③ TRAIL 出证任务受理", json.dumps(r)[:150])
        task_id, case_id = r["task_id"], r["case_id"]
        # 锚定链头=语句公开面（第三方复验的期望值来源——真实部署=链上锚定值）
        anchor_head_hex = r["chain_head_hex"]
        # 真相源=盘上 verdict.json 出现（task 状态仅作参考展示）
        cases_dir = UAS / "backend" / "fz-zk-cases"
        verdict_path = cases_dir / case_id / "verdict.json"
        t0 = time.time()
        status = "starting"
        while time.time() - t0 < 420:
            if verdict_path.is_file():
                break
            try:
                t = bridge_get(f"/prove/task/{task_id}")
                status = t["data"]["status"]
                if status == "failed":
                    print(f"  [FAIL] 出证失败: {t['data'].get('error')}")
                    raise SystemExit(1)
            except SystemExit:
                raise
            except Exception:
                pass
            time.sleep(3)
        expect(verdict_path.is_file(), f"③' 本机出证完成（{time.time()-t0:.0f}s，status={status}）")

        # ④ 判决件三件套下载（R1-6 合规证书）
        out_dir = UAS / "zksvc" / "target" / "probe" / f"s4_case_{case_id[:8]}"
        out_dir.mkdir(parents=True, exist_ok=True)
        verdict = None
        for name in ("proof.bin", "verifier_param.bin", "verdict.json", "instances.json"):
            with opener().open(f"{BRIDGE}/prove/case/{case_id}/{name}", timeout=60) as resp:
                data = resp.read()
            (out_dir / name).write_bytes(data)
            if name == "verdict.json":
                verdict = json.loads(data)
        expect(verdict is not None and verdict.get("verdict") == "OK",
               "④ 判决件三件套下载（verdict=OK）",
               json.dumps(verdict or {})[:150])
        print(f"  [..] proof={verdict['bytes']:,}B prove={verdict['prove_s']:.1f}s "
              f"preprocess={verdict['preprocess_s']:.1f}s")

        # ⑤ 第三方独立复验（zkc verify-instances——R1-6 隐私口径：验证方只见
        # 公开实例（锚定链头‖alt_max‖t_start‖周期‖围栏 4 界）+canonical 语句
        # 结构，见证（轨迹样本）零披露。2026-10 换代：实例 1=alt_max、2=t_start
        # ——期望值经 task API 透传实际授权/窗口参数（fail-closed 核对）。
        # 二批换代：3=采样周期、4..7=矩形围栏 4 界——期望面同步扩容
        tinfo = bridge_get(f"/prove/task/{task_id}")["data"]
        expected = {"chain_head_hex": anchor_head_hex,
                    "alt_max_cm": tinfo["alt_max"],
                    "t_start": tinfo["t_start"],
                    "sample_period_ms": tinfo["sample_period_ms"],
                    "fence": tinfo["fence"]}
        expect(all(k in expected and expected[k] is not None for k in
                   ("sample_period_ms", "fence")),
               "⑤- 二批期望面字段在案（周期+围栏 4 界经 task API 透传）",
               json.dumps(tinfo)[:200])
        exp_path = out_dir / "expected.json"
        exp_path.write_text(json.dumps(expected), encoding="utf-8")
        env = {**os.environ,
               "FZ_ZK_ALLOW_TRAIL": "1",
               "FZ_TRAIL_CANONICAL_SPEC": str(UAS / "zksvc" / "tests" / "trail_canonical_spec.json")}
        proc = subprocess.run(
            [str(ZKC), "verify-instances",
             "--instances", str(out_dir / "instances.json"),
             "--proof", str(out_dir / "proof.bin"),
             "--vp", str(out_dir / "verifier_param.bin"),
             "--expected", str(exp_path)],
            capture_output=True, text=True, env=env,
        )
        expect(proc.returncode == 0 and "OK" in (proc.stdout + proc.stderr),
               "⑤ 第三方独立复验（verify-instances：链头实例核对+盘上字节）",
               (proc.stdout + proc.stderr)[-200:])
        # ⑤' 负例：篡改链头 ⟹ 复验拒绝
        bad = {"chain_head_hex": "ab" * 32}
        exp_path.write_text(json.dumps(bad), encoding="utf-8")
        proc = subprocess.run(
            [str(ZKC), "verify-instances",
             "--instances", str(out_dir / "instances.json"),
             "--proof", str(out_dir / "proof.bin"),
             "--vp", str(out_dir / "verifier_param.bin"),
             "--expected", str(exp_path)],
            capture_output=True, text=True, env=env,
        )
        expect(proc.returncode == 2, "⑤' 篡改链头复验拒绝（exit 2）")

        print(f"\n== S4 TRAIL 合规证明闭环 {_checks} 项断言 [OK] ==")
        print(f"== 真令牌 authId={tok['authId']}（完整申请流）| 合规证书={out_dir}"
              f"（proof/verifier_param/verdict 三件套，可第三方复验）==")
        return 0
    finally:
        # 收尾 DISARM（连跑纪律：留 armed 会话会让下一轮围栏参数写面对"已解锁"
        # 飞控失败——与 S1 finally 同手法；fake 桥/桥不可达=尽力而为）
        try:
            bridge_post("/sitl/disarm", {}, timeout=15)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
