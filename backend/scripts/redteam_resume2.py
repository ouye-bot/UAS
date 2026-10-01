# -*- coding: utf-8 -*-
"""红队续跑 2（阶段六）：A5 时间窗滥用 + A9 nonce 重放的**正确攻击形态**
（新鲜出证使实例一致，然后三次申请变体）+ B1 闸门一次性边界确认。"""

from __future__ import annotations

import json
import secrets
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(UAS / "backend"))
API = "http://127.0.0.1:8000"
BRIDGE = "http://127.0.0.1:8100"

_records = []


def record(v, attack, evidence):
    _records.append((v, attack, evidence))
    print(f"  [{v}] {attack} — {evidence}")


def _open(req, timeout=60):
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"_raw": raw[:200]}


def post(url, body=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else b"{}",
                                 headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
    return _open(req, timeout)


def get(url, timeout=30):
    req = urllib.request.Request(url)
    return _open(req, timeout)


def main() -> int:
    from app.crypto.sm2 import generate_keypair, sign_digest
    from app.crypto.sm3 import sm3_bytes
    from app.kms import engine_signing_keypair, ra_signing_keypair
    from app.ra.credential import build_message, sign_credential

    print("== 红队续跑 2：A5 时间窗 + A9 nonce 重放（正确攻击形态）==\n")
    holder_sk, holder_pk = generate_keypair()
    rc, reg = post(API + "/ra/register", {
        "username": "rt3-" + secrets.token_hex(3), "id_number": "110101199001011234",
        "cert_level": 3, "sn": "FZ-RT3-01", "user_pub_hex": holder_pk, "class_id": 1})
    assert rc == 200
    cred = reg["data"]
    rev_root = None  # 出证后重取（新鲜性）

    # 新鲜出证（绑定 t_epoch=T——实例 21 与申请一致的前提）
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    rc, binding = get(API + f"/authz/binding?class_id=1&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}")
    t_epoch = binding["data"]["t_epoch"]
    rc, sub = post(API + "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": "110101199001011234", "cert_level": 3, "sn": "FZ-RT3-01",
        "holder_pub_hex": holder_pk})
    sub = sub["data"]
    rc, start = post(BRIDGE + "/prove/start", {
        "plan_hash_hex": plan_hash_hex, "nonce_hex": nonce_hex, "class_id": 1,
        "id_number": "110101199001011234", "cert_level": 3, "sn": "FZ-RT3-01",
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub["id_prime_hex"],
        "sig_hex": sub["sig_hex"], "expires_at": sub["expires_at"],
        "holder_sk_hex": holder_sk, "holder_pk_hex": holder_pk}, timeout=30)
    assert rc == 200, str(start)[:200]
    case_id = start["case_id"]
    print(f"[..] 新鲜出证 {case_id} …")
    status = "assembling"
    while status in ("assembling", "proving"):
        time.sleep(5)
        _, t = get(f"{BRIDGE}/prove/task/{start['task_id']}")
        status = t.get("status") or t.get("data", {}).get("status")
        if status == "failed":
            print("[FAIL]", str(t)[:150]); return 1
    status = "assembling"
    while status in ("assembling", "proving"):
        time.sleep(5)
        _, t = get(f"{BRIDGE}/prove/task/{start['task_id']}")
        status = t.get("status") or t.get("data", {}).get("status")
        if status == "failed":
            print("[FAIL]", str(t)[:150]); return 1

    # 文件可见性等待（Windows：rename 后杀毒/索引器短暂占用——轮询到实际可读）
    _case_dir = Path(os.environ.get("FZ_ZK_CASES_DIR", str(UAS / "backend" / "fz-zk-cases"))) / case_id
    _t_files = time.time()
    while not (_case_dir / "proof.bin").exists() and time.time() - _t_files < 90:
        time.sleep(2)
    if not (_case_dir / "proof.bin").exists():
        print(f"[FAIL] 出证产物 90s 未落盘: {_case_dir}")
        raise SystemExit(1)

    def apply_variant(t_end):
        rev_root = get(API + "/ra/revocation/snapshot")[1]["data"]["root_hex"]
        return post(API + "/authz/apply", {
            "session_pk_hex": holder_pk,
            "sub_cred_message_hex": sub["message_hex"], "sub_sig_hex": sub["sig_hex"],
            "sub_cred_hash_hex": sub["sub_cred_hash_hex"], "nonce_hex": nonce_hex,
            "plan_hash_hex": plan_hash_hex, "class_id": 1, "case_id": case_id,
            "rev_root_hex": rev_root, "t_start": t_epoch, "t_end": t_end})

    # A5：时间窗滥用（同一合法证明，把窗拉到 24h）
    rc, wide = apply_variant(t_epoch + 86400)
    record("REJECTED" if (rc == 409 and wide.get("code") == "window_too_long") else "OPEN",
           "A5 时间窗滥用（合法证明+窗拉到 24h > 政策窗 6h）",
           f"rc={rc} code={wide.get('code')}")

    # A9：合法受理一次 → 同 nonce 同材料重放
    rc, ok = apply_variant(t_epoch + 3600)
    a9_first = (rc == 200)
    rc2, rep = apply_variant(t_epoch + 3600)
    a9_replay = (rc2 == 409 and rep.get("code") in ("nonce_used", "sub_cred_used"))
    record("REJECTED" if (a9_first and a9_replay) else "OPEN",
           "A9 nonce 重放（合法受理后同材料重放）",
           f"首受理 rc={rc} 重放 rc={rc2} code={rep.get('code')}")

    # B1：同闸门二次 ARM（一次性令牌边界）
    import os as _os
    _sk_file = _os.path.expandvars(r"%LOCALAPPDATA%\Temp") + "/fz_engine_sk.txt"
    _os.environ["FZ_ENGINE_SK"] = open(_sk_file).read().strip()
    from app.kms import engine_signing_keypair
    sk_e, _ = engine_signing_keypair()
    tok = {"authId": 1, "plan_hash": "ee" * 32, "alt_max": 30, "t_start": int(time.time()) - 60,
           "t_end": int(time.time()) + 3600, "nonce": "ee" * 16, "policy_version": "policy-2026-09-v1"}
    tb = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    payload = (tb + "|" + sign_digest(sk_e, sm3_bytes(tb.encode()))).encode()
    r1 = post(BRIDGE + "/arm", {"token_payload_hex": payload.hex(), "plan_hash_hex": "ee" * 32})
    r2 = post(BRIDGE + "/arm", {"token_payload_hex": payload.hex(), "plan_hash_hex": "ee" * 32})
    r1_ok = r1[1].get("ok") if isinstance(r1[1], dict) else False
    r2_code = r2[1].get("code") if isinstance(r2[1], dict) else "?"
    record("BOUNDARY" if (r1_ok and r2_code == "token_used") else "OPEN",
           "B1 同闸门二次 ARM（一次性令牌·方案 A）",
           f"一次 ok={r1_ok} 二次 code={r2_code}（桥接本机状态=TCB①声明；彻底方案=SE 计数器 R2）")

    rej = sum(1 for v, _, _ in _records if v == "REJECTED")
    bnd = sum(1 for v, _, _ in _records if v == "BOUNDARY")
    opn = sum(1 for v, _, _ in _records if v == "OPEN")
    print(f"\n== 红队续跑 2：REJECTED {rej} · BOUNDARY {bnd} · OPEN {opn} ==")
    return 0 if opn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
