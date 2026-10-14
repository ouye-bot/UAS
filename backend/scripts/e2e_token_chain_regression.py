"""令牌链路回归（签发→领取→桥验签解锁——2026-10-14 验签假败回归的验收件）。

全流程（全新飞手，API 级实弹，零替身）：
  OPAQUE v6 注册 → prelogin 稳态 → 挑战登录（会话 Cookie）→ RA 实名登记
  → 子凭证 → 绑定面 → 桥接本机出证（约 2 分钟）→ /authz/apply 受理
  → worker 判决 ready → 取件 ECIES 解密 → 令牌三方字节对拍 → 桥 /arm 验签解锁。

三方对拍（根因定位件——签发侧签名输入 / 飞手领取字节 / 桥验签公钥三面）：
  A. 原始 body vs 规范化重建（json.dumps sort_keys 紧凑——build_token 同式）
     —— 序列化单源断言：分叉=签发/验签规范化分歧；
  B. 签名 vs 后端公示公钥（/authz/engine/pub）—— 工人签名钥=公示钥？
  C. 签名 vs 确定性派生公钥（kms 演示域）—— 签名钥归因；
  D. 签名 vs %TEMP% 每场持久钥公钥 —— 签名钥归因（桥 gcs_bridge_start.sh
     曾读同族文件——钥分脑定位面）；
  E. 桥 /arm 判定 —— 功能面终审（验签失败=bad_signature 原样复现）。

用法：cd backend && .venv/Scripts/python.exe scripts/e2e_token_chain_regression.py
前置：backend(8000)+bridge(8100)+worker 在线（demo_up 栈）；桥 device_serial
缺省 FZ-SN-DEV-01（第 6 查 SN 绑定——登记 SN 必须同值，env FZ_REG_SN 可改）。
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

API = os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")
BRIDGE = os.environ.get("FZ_BRIDGE_BASE", "http://127.0.0.1:8100")
SN = os.environ.get("FZ_REG_SN", "FZ-SN-DEV-01")

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


_OPENER = None


def opener() -> urllib.request.OpenerDirector:
    global _OPENER
    if _OPENER is None:
        _OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return _OPENER


def api_get(path: str, cookies: dict | None = None) -> dict:
    req = urllib.request.Request(API + path)
    for k, v in (cookies or {}).items():
        req.add_header("Cookie", f"{k}={v}")
    with opener().open(req, timeout=30) as r:
        return json.loads(r.read().decode())


def api_post(path: str, body: dict, cookies: dict | None = None):
    req = urllib.request.Request(
        API + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    for k, v in (cookies or {}).items():
        req.add_header("Cookie", f"{k}={v}")
    try:
        with opener().open(req, timeout=30) as r:
            return r.status, r.headers, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.headers, json.loads(e.read().decode())


def bridge_post(path: str, body: dict):
    req = urllib.request.Request(
        BRIDGE + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with opener().open(req, timeout=180) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def main() -> int:
    from app.accounts.client import client_seal_v6
    from app.crypto.sm2 import decrypt as ecies_decrypt
    from app.crypto.sm2 import generate_keypair, pubkey_from_priv, sign, verify_digest
    from app.crypto.sm3 import sm3_bytes
    from app.kms import _ENGINE_DOMAIN, _derive_priv

    print("== 令牌链路回归（注册→登录→登记→出证→领取→对拍→桥验签）==")
    t_all = time.time()

    # ---- ① 全新飞手账户（OPAQUE v6 注册） ----
    username = "reg-" + secrets.token_hex(3)
    password = "Reg-Pw-" + secrets.token_hex(4)
    acct_sk, acct_pk = generate_keypair()
    mats = client_seal_v6(username, password, acct_sk, acct_pk)
    rc, _h, body = api_post(
        "/auth/register",
        {
            "username": username,
            "pubkey_hex": acct_pk,
            "sealed_blob": mats["sealed_blob"],
            "masking_key_hex": mats["masking_key_hex"],
            "kdf_salt_hex": mats["kdf_salt_hex"],
            "kdf_iter": mats["kdf_iter"],
        },
    )
    expect(rc == 201 and body.get("code") == "ok", "① OPAQUE v6 注册 201", f"rc={rc} {body}")

    # ---- ② prelogin 稳态+挑战登录（会话 Cookie） ----
    pre = api_get(f"/auth/prelogin/{username}")["data"]
    expect(pre.get("mode") == "challenge", "② prelogin=challenge（注册即激活稳态）", str(pre))
    st, _h, body = api_post(f"/auth/challenge/{username}", {})
    expect(st == 200, "② 登录挑战 200", body)
    nonce_hex = body["data"]["nonce_hex"]
    st, h, body = api_post(
        "/auth/login",
        {
            "username": username,
            "nonce_hex": nonce_hex,
            "sig_hex": sign(acct_sk, f"FZ-AUTH-LOGIN|{nonce_hex}".encode()),
        },
    )
    expect(st == 200 and body.get("code") == "ok", "② OPAQUE 账户挑战登录 200", f"rc={st} {body}")
    setc = (h.get("Set-Cookie") or "")
    cookies = {}
    if "fz_session=" in setc:
        cookies["fz_session"] = setc.split("fz_session=")[1].split(";")[0]
    expect(bool(cookies), "② 会话 Cookie 落手（fz_session）")
    who = api_get("/auth/whoami", cookies=cookies)
    expect(
        who.get("data", {}).get("username") == username,
        "② 会话态 whoami=本飞手（登录→业务动线贯通）",
        str(who),
    )

    # ---- ③ RA 实名登记+子凭证（SN=桥 device_serial——第 6 查同源） ----
    holder_sk, holder_pk = generate_keypair()
    id_number = "11010119900101" + secrets.token_hex(2)
    rc, _h, reg = api_post(
        "/ra/register",
        {
            "username": username,
            "id_number": id_number,
            "cert_level": 3,
            "sn": SN,
            "user_pub_hex": holder_pk,
            "class_id": 1,
        },
    )
    expect(rc == 200 and reg["code"] == "ok", "③ RA 实名登记（承诺签发）", f"rc={rc} {reg}")
    cred = reg["data"]
    rc, _h, sub = api_post(
        "/ra/sub-credentials",
        {
            "master_cred_hash_hex": cred["master_cred_hash_hex"],
            "salt_hex": cred["salt_hex"],
            "id_number": id_number,
            "cert_level": 3,
            "sn": SN,
            "holder_pub_hex": holder_pk,
        },
    )
    expect(rc == 200 and sub["code"] == "ok", "③ 子凭证签发（一次性出示）", f"rc={rc} {sub}")
    sub = sub["data"]

    # ---- ④ 绑定面+桥接本机出证（约 2 分钟） ----
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    api_get(f"/authz/binding?class_id=1&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}")
    st, start = bridge_post(
        "/prove/start",
        {
            "plan_hash_hex": plan_hash_hex,
            "nonce_hex": nonce_hex,
            "class_id": 1,
            "id_number": id_number,
            "cert_level": 3,
            "sn": SN,
            "salt_hex": cred["salt_hex"],
            "id_prime_hex": sub["id_prime_hex"],
            "sig_hex": sub["sig_hex"],
            "expires_at": sub["expires_at"],
            "holder_sk_hex": holder_sk,
            "holder_pk_hex": holder_pk,
        },
    )
    expect(st == 200 and "task_id" in start, "④ 桥接出证受理", f"st={st} {start}")
    task_id, case_id = start["task_id"], start["case_id"]
    prove_t_epoch = start["binding"]["t_epoch"]
    print(f"  [..] 本机出证中（task={task_id[:12]}…，约 2 分钟）")
    t0 = time.time()
    status = "assembling"
    while status in ("assembling", "proving"):
        time.sleep(5)
        with opener().open(f"{BRIDGE}/prove/task/{task_id}", timeout=15) as r:
            t = json.loads(r.read().decode())
        status = t.get("status") or t.get("data", {}).get("status", status)
        if status not in ("assembling", "proving"):
            break
        if time.time() - t0 > 1500:
            print("  [FAIL] 出证超时（25 分钟）")
            return 1
    expect(status == "done", f"④ 出证完成（{time.time() - t0:.0f}s）", f"status={status} {t}")

    # ---- ⑤ 受理→worker 判决→ready ----
    rc, _h, apply = api_post(
        "/authz/apply",
        {
            "session_pk_hex": holder_pk,
            "sub_cred_message_hex": sub["message_hex"],
            "sub_sig_hex": sub["sig_hex"],
            "sub_cred_hash_hex": sub["sub_cred_hash_hex"],
            "nonce_hex": nonce_hex,
            "plan_hash_hex": plan_hash_hex,
            "class_id": 1,
            "case_id": case_id,
            "rev_root_hex": api_get("/ra/revocation/snapshot")["data"]["root_hex"],
            "t_start": prove_t_epoch,
            "t_end": prove_t_epoch + 3600,
        },
    )
    expect(rc == 200 and apply.get("ok") is True, "⑤ 受理通过（入队）", f"rc={rc} {apply}")
    receipt_code = apply["data"]["receipt_code"]
    t1 = time.time()
    r = {"status": "waiting"}
    while time.time() - t1 < 180:
        r = api_get(f"/authz/receipt/{receipt_code}")["data"]
        if r["status"] != "waiting":
            break
        time.sleep(2)
    expect(r["status"] == "ready", f"⑤ worker 判决 ready（{time.time() - t1:.0f}s）", str(r))

    # ---- ⑥ 领取令牌（飞手侧 ECIES 解密） ----
    payload = ecies_decrypt(holder_sk, bytes.fromhex(r["token_cipher_hex"]))
    tok_body, sig_hex = payload.rsplit(b"|", 1)
    tok = json.loads(tok_body)
    expect(tok.get("plan_hash") == plan_hash_hex, "⑥ 取件解密+plan_hash 绑定")

    # ---- ⑦ 三方字节对拍（签发输入 / 领取字节 / 验签公钥三面） ----
    print("  [对拍] A. 原始 body vs 规范化重建（build_token 同式）")
    canonical = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    a_same = canonical.encode() == tok_body
    expect(a_same, "对拍A 序列化单源：规范化重建逐字节一致（分叉=规范化分歧）",
           f"\n    raw={tok_body.decode()[:200]}\n    can={canonical[:200]}")
    api_pub = api_get("/authz/engine/pub")["data"]["engine_pub_hex"]
    # 桥 /engine_pub 为 backend 代理（R3-B2 裁钥——服务端公示面），非桥本地钥：
    # 真正参与验签的桥本地钥只有 /arm 功能判定可观测（故终审=⑧）。
    bridge_pub = json.loads(
        opener().open(BRIDGE + "/engine_pub", timeout=15).read().decode()
    )["engine_pub_hex"]
    print(
        f"  [对拍] 公示面：backend={api_pub[:16]}… bridge代理={bridge_pub[:16]}…"
        f" 一致={api_pub == bridge_pub}"
    )
    e = sm3_bytes(tok_body)
    b_ok = verify_digest(api_pub, e, sig_hex)
    print(f"  [对拍] B. 签名 vs 后端公示公钥（/authz/engine/pub={api_pub[:16]}…）→ {b_ok}")
    det_pub = pubkey_from_priv(_derive_priv(_ENGINE_DOMAIN))
    c_ok = verify_digest(det_pub, e, sig_hex)
    print(f"  [对拍] C. 签名 vs 确定性派生公钥（kms 演示域={det_pub[:16]}…）→ {c_ok}")
    d_note = "-"
    tp = Path(os.environ.get("TEMP", "")) / "fz_engine_sk.txt"
    if tp.is_file():
        sk_persist = tp.read_text(encoding="utf-8").strip().removeprefix("SK=")
        d_pub = pubkey_from_priv(sk_persist)
        d_ok = verify_digest(d_pub, e, sig_hex)
        d_note = f"每场持久钥公钥={d_pub[:16]}… → {d_ok}"
        print(f"  [对拍] D. 签名 vs %TEMP% {d_note}")
    sn_ok = tok.get("sn_hash") == sm3_bytes(SN.encode()).hex()
    expect(sn_ok, "对拍E 令牌 sn_hash=SM3(桥 SN)（第 6 查预检同值）", str(tok.get("sn_hash")))

    # ---- ⑧ 桥 /arm 验签解锁（功能面终审） ----
    st, arm = bridge_post(
        "/arm",
        {
            "token_payload_hex": payload.hex(),
            "plan_hash_hex": plan_hash_hex,
            "plan_altitude_m": 100,
        },
    )
    msg80 = (arm.get("message") or "")[:80]
    print(f"  [桥] /arm → st={st} ok={arm.get('ok')} code={arm.get('code')} msg={msg80}")
    if not arm.get("ok"):
        print(f"  [FAIL] 桥验签解锁被拒（code={arm.get('code')}）——"
              f"对拍归因：B={b_ok} C={c_ok} {d_note}")
        return 1
    expect(arm.get("ok") is True, "⑧ 桥验签通过+解锁（ARM）成功——令牌链路回归全绿")
    print(f"== 回归通过 {_checks} 断言｜全程 {time.time() - t_all:.0f}s ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
