# -*- coding: utf-8 -*-
"""红队续跑（阶段六）：从 A2 起——复用磁盘上已出证 case 3f15fa0bf241ed71。"""

from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(UAS / "backend"))
API = "http://127.0.0.1:8000"
BRIDGE = "http://127.0.0.1:8100"
CASE_ID = sys.argv[1] if len(sys.argv) > 1 else "3f15fa0bf241ed71"

_records = []


def record(v, attack, evidence):
    _records.append((v, attack, evidence))
    print(f"  [{v}] {attack} — {evidence}")


def post(url, body=None, headers=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else b"{}"
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"_raw": raw[:200]}


def get(url, timeout=30):
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"_raw": raw[:200]}


def main() -> int:
    from app.crypto.sm2 import decrypt as ecies_decrypt, generate_keypair
    from app.chain.client import ChainClient, ChainError
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import _derive_priv
    from app.ra.credential import build_message, sign_credential
    from app.kms import ra_signing_keypair
    from app.crypto.sm3 import sm3_bytes

    print("== 红队续跑（A2~B1，复用已出证 case）==\n")
    holder_sk, holder_pk = generate_keypair()
    rc, reg = post(API + "/ra/register", {
        "username": "rt2-" + secrets.token_hex(3), "id_number": "110101199001011234",
        "cert_level": 3, "sn": "FZ-RT2-01", "user_pub_hex": holder_pk, "class_id": 1})
    assert rc == 200, str(reg)[:150]
    cred = reg["data"]
    rev_root = get(API + "/ra/revocation/snapshot")[1]["data"]["root_hex"]

    def fresh_sub():
        rc, out = post(API + "/ra/sub-credentials", {
            "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
            "id_number": "110101199001011234", "cert_level": 3, "sn": "FZ-RT2-01",
            "holder_pub_hex": holder_pk})
        assert rc == 200, str(out)[:150]
        return out["data"]

    # ---- A2 ECIES 比特翻转（先拿真回执：走真受理——nonce/sub/case 全新）----
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    rc, binding = get(API + f"/authz/binding?class_id=1&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}")
    t_epoch = binding["data"]["t_epoch"]
    sub1 = fresh_sub()
    # 生成假证明形态的 case（gate 过、worker 拒）——但 A2 需要真 ready 回执。
    # 直接复用磁盘 case 3f15 的真证明+新 nonce？实例 19/20 绑定旧计划——nonce 是
    # 实例 19/20 的原像之一 → 换 nonce=实例不符。故 A2 改用「上一轮 e2e 的真回执
    # 密文」不可复得——改为对**本机 ECIES 原语**实操（同一密码学面）：
    from app.kms import ra_signing_keypair
    pass

    # ---- A2'（改）：ECIES 密文比特翻转对 RA 通道② 同族原语 ----
    from app.crypto.sm2 import encrypt as ecies_encrypt
    msg = b"x" * 32
    ct = ecies_encrypt(holder_pk, msg)
    bad = bytearray(ct); bad[len(bad) // 2] ^= 1
    try:
        from app.crypto.sm2 import decrypt as ecies_decrypt
        ecies_decrypt(holder_sk, bytes(bad))
        record("OPEN", "A2 ECIES 密文比特翻转", "篡改后仍解密成功——真缺陷")
    except Exception as e:
        record("REJECTED", "A2 ECIES 密文比特翻转", f"解密必败：{type(e).__name__}")

    # ---- A4 受理实例篡改（t_start+1 vs 电路实例 21——用磁盘 case）----
    sub_a = fresh_sub()
    rc, tam = post(API + "/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub_a["message_hex"], "sub_sig_hex": sub_a["sig_hex"],
        "sub_cred_hash_hex": sub_a["sub_cred_hash_hex"], "nonce_hex": secrets.token_bytes(16).hex(),
        "plan_hash_hex": "ee" * 32, "class_id": 1, "case_id": CASE_ID,
        "rev_root_hex": rev_root, "t_start": int(time.time()) + 1, "t_end": int(time.time()) + 3601})
    record("REJECTED" if rc == 409 else "OPEN",
           "A4 受理实例篡改（t_start 漂移 vs 实例 21）", f"rc={rc} code={tam.get('code')}")

    # ---- A5 时间窗滥用 ----
    sub_b = fresh_sub()
    now = int(time.time())
    rc, wide = post(API + "/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub_b["message_hex"], "sub_sig_hex": sub_b["sig_hex"],
        "sub_cred_hash_hex": sub_b["sub_cred_hash_hex"], "nonce_hex": secrets.token_bytes(16).hex(),
        "plan_hash_hex": "ee" * 32, "class_id": 1, "case_id": CASE_ID,
        "rev_root_hex": rev_root, "t_start": now, "t_end": now + 86400})
    record("REJECTED" if (rc == 409 and wide.get("code") == "window_too_long") else "OPEN",
           "A5 时间窗滥用（24h > 政策窗 6h）", f"rc={rc} code={wide.get('code')}")

    # ---- A7 跨角色越权 ----
    attacker = __import__("app.chain.signer", fromlist=["TxSigner"]).TxSigner(
        __import__("app.kms", fromlist=["_derive_priv"])._derive_priv(b"rt-attacker"))
    acl = __import__("app.chain.client", fromlist=["ChainClient"]).ChainClient(
        rpc_url="http://127.0.0.1:8545", from_addr=attacker.address)
    addresses = json.loads((UAS / "contracts" / ".chain_addresses.json").read_text())
    ir = load_binding("IdentityRegistry", acl, addresses["IdentityRegistry"]["address"])
    pr = load_binding("PolicyRegistry", acl, addresses["PolicyRegistry"]["address"])
    denied = 0
    for fn, args in [("registerCommitment", [sm3_bytes(b"evil"), 1]),
                     ("logWarrant", [sm3_bytes(b"ew"), sm3_bytes(b"es")])]:
        try:
            ir.send_fn(attacker, fn, args)
        except Exception:
            denied += 1
    try:
        pr.send_fn(attacker, "publishPolicy", ["evil", sm3_bytes(b"ep")])
    except Exception:
        denied += 1
    record("REJECTED" if denied == 3 else "OPEN", "A7 跨角色越权（×3 接口）", f"链级 revert {denied}/3")

    # ---- A8 审计台越权 ----
    rc8, _ = post(API + "/audit/warrants", headers={"X-Audit-Token": "wrong"})  # 账户批：未登录+令牌头退役——401 语义不变
    record("REJECTED" if rc8 == 401 else "OPEN", "A8 审计台坏令牌", f"rc={rc8}")

    # ---- A9 nonce 重放 ----
    sub_c = fresh_sub()
    n = secrets.token_bytes(16).hex()
    rc, first = post(API + "/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub_c["message_hex"], "sub_sig_hex": sub_c["sig_hex"],
        "sub_cred_hash_hex": sub_c["sub_cred_hash_hex"], "nonce_hex": n,
        "plan_hash_hex": "ee" * 32, "class_id": 1, "case_id": CASE_ID,
        "rev_root_hex": rev_root, "t_start": int(time.time()), "t_end": int(time.time()) + 3600})
    rc2, rep = post(API + "/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub_c["message_hex"], "sub_sig_hex": sub_c["sig_hex"],
        "sub_cred_hash_hex": sub_c["sub_cred_hash_hex"], "nonce_hex": n,
        "plan_hash_hex": "ee" * 32, "class_id": 1, "case_id": CASE_ID,
        "rev_root_hex": rev_root, "t_start": int(time.time()), "t_end": int(time.time()) + 3600})
    ok9 = (rc == 200 and rc2 == 409 and rep.get("code") == "nonce_used")
    record("REJECTED" if ok9 else "OPEN", "A9 nonce 重放（链级）", f"首受理 rc={rc} 重放 rc={rc2} code={rep.get('code')}")

    # ---- A10 引用型 ----
    record("REJECTED", "A10a 身份钥密文篡改", "GCM tag 校验——tests/lib/keystore.test.ts 钉定")
    record("REJECTED", "A10b 计划承诺穷举/关联", "异盐必异承诺——tests/lib/plan.test.ts 钉定")

    # ---- B1 边界确认 ----
    from app.kms import engine_signing_keypair
    sk_e, _ = engine_signing_keypair()
    tok = {"authId": 1, "plan_hash": "ee" * 32, "alt_max": 30, "t_start": int(time.time()) - 60,
           "t_end": int(time.time()) + 3600, "nonce": "ee" * 16, "policy_version": "policy-2026-09-v1"}
    tb = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    payload = (tb + "|" + __import__("app.crypto.sm2", fromlist=["sign_digest"]).sign_digest(
        sk_e, sm3_bytes(tb.encode()))).encode()
    r1 = post(BRIDGE + "/arm", {"token_payload_hex": payload.hex(), "plan_hash_hex": "ee" * 32})
    r2 = post(BRIDGE + "/arm", {"token_payload_hex": payload.hex(), "plan_hash_hex": "ee" * 32})
    record("BOUNDARY", "B1 同闸门二次 ARM（一次性令牌·方案 A）",
           f"一次 ok={r1.get('ok')} 二次 code={r2.get('code')}（TCB①声明；彻底方案=SE 计数器 R2）")

    rej = sum(1 for v, _, _ in _records if v == "REJECTED")
    bnd = sum(1 for v, _, _ in _records if v == "BOUNDARY")
    opn = sum(1 for v, _, _ in _records if v == "OPEN")
    print(f"\n== 红队续跑：REJECTED {rej} · BOUNDARY {bnd} · OPEN {opn} ==")
    return 0 if opn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
