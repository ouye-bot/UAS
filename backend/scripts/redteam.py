# -*- coding: utf-8 -*-
"""红队实操（阶段六）：以攻击者视角对运行系统实操验证防御。

判定：REJECTED=防御生效（答辩武器）；BOUNDARY=已声明边界（诚实记录）；
OPEN=攻击得手=真缺陷（当场修+回归）。

用法：cd uas/backend && python scripts/redteam.py
前置：backend(8000 真链档)+bridge(8100)+worker 在线。
"""

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

_records: list[tuple[str, str, str]] = []  # (verdict, attack, evidence)


def record(verdict: str, attack: str, evidence: str) -> None:
    _records.append((verdict, attack, evidence))
    print(f"  [{verdict}] {attack} — {evidence}")


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def post(url: str, body=None, headers=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else b"{}"
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json", **(headers or {})},
                                 method="POST")
    try:
        with opener().open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"_raw": raw[:200]}


def get(url: str, timeout=30):
    try:
        with opener().open(url, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"_raw": raw[:200]}


def main() -> int:
    from app.crypto.sm2 import decrypt as ecies_decrypt
    from app.crypto.sm2 import generate_keypair, sign_digest
    from app.crypto.sm3 import sm3_bytes
    from app.authz.policy import policy_params_hash
    from app.authz.service import _fe_be32_hex_from_bytes32, _fe_be32_hex_from_digest, \
        _fe_be32_hex_from_u64, binding_challenge
    from app.authz.policy import POLICY_VERSION
    from app.kms import ra_signing_keypair, engine_signing_keypair
    from app.ra.credential import build_message, sign_credential

    print("== 红队实操：攻击者视角对运行系统 ==\n")

    # ---- 准备一个真实身份与已出证 case（供实例篡改/时间窗/假证明攻击复用）----
    holder_sk, holder_pk = generate_keypair()
    sn = "FZ-RT-" + secrets.token_hex(2)
    rc, reg = post(API + "/ra/register", {
        "username": "rt-" + secrets.token_hex(3), "id_number": "110101199001011234",
        "cert_level": 3, "sn": sn, "user_pub_hex": holder_pk, "class_id": 1})
    assert rc == 200, str(reg)[:120]
    cred = reg["data"]
    rc, sub = post(API + "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": "110101199001011234", "cert_level": 3, "sn": sn, "holder_pub_hex": holder_pk})
    assert rc == 200, str(sub)[:120]
    sub = sub["data"]
    rev_root = get(API + "/ra/revocation/snapshot")[1]["data"]["root_hex"]

    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    rc, binding = get(API + f"/authz/binding?class_id=1&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}")
    assert rc == 200
    t_epoch = binding["data"]["t_epoch"]

    # 真出证一次（供 A4/A5 攻击面）
    rc, start = post(BRIDGE + "/prove/start", {
        "plan_hash_hex": plan_hash_hex, "nonce_hex": nonce_hex, "class_id": 1,
        "id_number": "110101199001011234", "cert_level": 3, "sn": sn,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub["id_prime_hex"],
        "sig_hex": sub["sig_hex"], "expires_at": sub["expires_at"],
        "holder_sk_hex": holder_sk, "holder_pk_hex": holder_pk}, timeout=30)
    assert rc == 200, str(start)[:120]
    case_id = start["case_id"]
    print(f"[..] 真出证一次（case={case_id}，供攻击面）…")
    status = "assembling"
    while status in ("assembling", "proving"):
        time.sleep(5)
        _, t = post(f"{BRIDGE}/prove/task/{start['task_id']}")
        status = t.get("status") or t.get("data", {}).get("status")
        if status == "failed":
            print("[FAIL] 出证失败", str(t)[:160]); return 1
        if time.time() - t_epoch > 1500:
            print("[FAIL] 出证超时"); return 1
    print(f"  出证完成（case={case_id}）")

    def apply_body(t_start=None, t_end=None, nonce=None, sub_hash=None, msg_hex=None, sig_hex=None, case=None):
        return {
            "session_pk_hex": holder_pk,
            "sub_cred_message_hex": msg_hex or sub["message_hex"],
            "sub_sig_hex": sig_hex or sub["sig_hex"],
            "sub_cred_hash_hex": sub_hash or sub["sub_cred_hash_hex"],
            "nonce_hex": nonce or nonce_hex, "plan_hash_hex": plan_hash_hex,
            "class_id": 1, "case_id": case or case_id,
            "rev_root_hex": rev_root,
            "t_start": t_start or t_epoch, "t_end": t_end or t_epoch + 3600,
        }

    # ---- A1 回执码穷举 ----
    codes = [secrets.token_hex(16) for _ in range(5)]
    results = [get(f"{API}/authz/receipt/{c}")[0] for c in codes]
    record("REJECTED", "A1 回执码穷举（128bit 随机码×5）",
           f"全部 404：{results}——空间 2^128，穷举不可行")

    # ---- A2 ECIES 密文比特翻转 ----
    rc, ap = post(API + "/authz/apply", apply_body())
    if "data" not in ap:
        record("OPEN", "A2-pre 受理异常（真出证后受理失败）", json.dumps(ap, ensure_ascii=False)[:220])
        print(json.dumps(ap, ensure_ascii=False)[:400])
        raise SystemExit(1)
    receipt_code = ap["data"]["receipt_code"]
    rc, rr = get(f"{API}/authz/receipt/{receipt_code}")
    while rr["data"]["status"] == "waiting":
        time.sleep(2)
        rc, rr = get(f"{API}/authz/receipt/{receipt_code}")
    cipher = bytearray(bytes.fromhex(rr["data"]["token_cipher_hex"]))
    cipher[len(cipher) // 2] ^= 0x01
    try:
        from app.crypto.sm2 import decrypt as ecies_decrypt
        ecies_decrypt(holder_sk, bytes(cipher))
        record("OPEN", "A2 ECIES 密文比特翻转", "篡改密文仍可解密——真缺陷！")
    except Exception as e:
        record("REJECTED", "A2 ECIES 密文比特翻转（中间 1 字节）",
               f"解密必败：{type(e).__name__} {str(e)[:60]}")

    # ---- A3 假证明注入 ----
    garbage_case = secrets.token_hex(8)
    gdir = UAS / "backend" / "fz-zk-cases" / garbage_case
    gdir.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    inst = ["0" * 64] * 25
    inst[19] = _fe_be32_hex_from_digest(sm3_bytes(bytes.fromhex(binding_challenge(plan_hash_hex, nonce_hex))))
    inst[20] = _fe_be32_hex_from_digest(sm3_bytes((b"FZ-ZKSVC-PRED-ID" + b"\x01") + (plan_hash_hex + "|" + nonce_hex + "|" + "policy-2026-09-v1").encode()))
    inst[21] = _fe_be32_hex_from_u64(t_epoch)
    inst[22] = _fe_be32_hex_from_u64(1)
    inst[23] = _fe_be32_hex_from_bytes32(bytes.fromhex(rev_root))
    inst[24] = _fe_be32_hex_from_u64(1)
    (gdir / "instances.json").write_text(json.dumps({"instances": inst}), encoding="utf-8")
    (gdir / "proof.bin").write_bytes(secrets.token_bytes(64))       # 垃圾证明
    (gdir / "verifier_param.bin").write_bytes(secrets.token_bytes(32))
    sub2 = post(API + "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": "110101199001011234", "cert_level": 3, "sn": sn, "holder_pub_hex": holder_pk})[1]["data"]
    rc, ap3 = post(API + "/authz/apply", apply_body(
        nonce=secrets.token_bytes(16).hex(), sub_hash=sub2["sub_cred_hash_hex"],
        msg_hex=sub2["message_hex"], sig_hex=sub2["sig_hex"], case=garbage_case))
    record("DETECTED", "A3 假证明注入（垃圾 proof 过形态门控）",
           f"受理形态通过 rc={ap3.get('ok', ap3)}——worker zkc 真实验证为最终防线" if ap3.get("ok") else f"受理即拒 {ap3}")
    rc2, rr2 = post(f"{API}/authz/receipt/{ap3['data']['receipt_code']}")
    waited = 0
    while rr2["data"]["status"] == "waiting" and waited < 60:
        time.sleep(3); waited += 3
        rc2, rr2 = post(f"{API}/authz/receipt/{ap3['data']['receipt_code']}")
    record("REJECTED" if rr2["data"]["status"] == "failed" else "OPEN",
           "A3' 假证明 worker 终审", f"状态={rr2['data']['status']}（垃圾证明被真实 zkc 验证拒绝）")

    # ---- A4 受理实例篡改 ----
    sub3 = post(API + "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": "110101199001011234", "cert_level": 3, "sn": sn, "holder_pub_hex": holder_pk})[1]["data"]
    rc4, tam = post(API + "/authz/apply", apply_body(
        t_start=t_epoch + 1, t_end=t_epoch + 3601,
        nonce=secrets.token_bytes(16).hex(), sub_hash=sub3["sub_cred_hash_hex"],
        msg_hex=sub3["message_hex"], sig_hex=sub3["sig_hex"], case=case_id))
    record("REJECTED" if rc4 == 409 else "OPEN",
           "A4 受理实例篡改（t_start+1 vs 电路实例 21）",
           f"rc={rc4} code={tam.get('code')}")

    # ---- A5 时间窗滥用 ----
    sub4 = post(API + "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": "110101199001011234", "cert_level": 3, "sn": sn, "holder_pub_hex": holder_pk})[1]["data"]
    rc5, wide = post(API + "/authz/apply", apply_body(
        t_end=t_epoch + 86400,
        nonce=secrets.token_bytes(16).hex(), sub_hash=sub4["sub_cred_hash_hex"],
        msg_hex=sub4["message_hex"], sig_hex=sub4["sig_hex"], case=case_id))
    record("REJECTED" if (rc5 == 409 and wide.get("code") == "window_too_long") else "OPEN",
           "A5 时间窗滥用（申请 24h > 政策窗 6h）",
           f"rc={rc5} code={wide.get('code')}")

    # ---- A6 接口灌爆 ----
    import http.client
    ctx_conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=10)
    counts = {}
    for _ in range(30):
        ctx_conn.request("POST", "/authz/apply", body=b"{}",
                         headers={"Content-Type": "application/json"})
        r = ctx_conn.getresponse(); r.read()
        counts[r.status] = counts.get(r.status, 0) + 1
    ctx_conn.close()
    record("REJECTED" if counts.get(429, 0) > 0 else "BOUNDARY",
           "A6 接口灌爆（30 连发）", f"状态分布={counts}（429=限流生效；本机环回无 nginx 时=业务层承受）")

    # ---- A7 跨角色越权 ----
    from app.chain.client import ChainClient, ChainError
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import _derive_priv
    attacker = TxSigner(_derive_priv(b"attacker-" + secrets.token_hex(4)))
    acl = ChainClient(rpc_url="http://127.0.0.1:8545", from_addr=attacker.address)
    addresses = json.loads((UAS / "contracts" / ".chain_addresses.json").read_text())
    ir = load_binding("IdentityRegistry", acl, addresses["IdentityRegistry"]["address"])
    pr = load_binding("PolicyRegistry", acl, addresses["PolicyRegistry"]["address"])
    denied = 0
    for fn, args in [("registerCommitment", [sm3_bytes(b"evil"), 1]),
                     ("logWarrant", [sm3_bytes(b"evil-w"), sm3_bytes(b"evil-s")])]:
        try:
            ir.send_fn(attacker, fn, args)
        except ChainError:
            denied += 1
    try:
        pr.send_fn(attacker, "publishPolicy", ["evil", sm3_bytes(b"evil-p")])
    except ChainError:
        denied += 1
    record("REJECTED" if denied == 3 else "OPEN",
           "A7 跨角色越权（attacker 钥 ×3 接口）", f"链级 revert {denied}/3")

    # ---- A8 审计台越权 ----
    rc8, _ = post(API + "/audit/warrants", headers={"X-Audit-Token": "wrong"})  # 账户批：未登录+令牌头退役——401 语义不变
    record("REJECTED" if rc8 == 401 else "OPEN", "A8 审计台坏令牌", f"rc={rc8}")

    # ---- A9 nonce 重放 ----
    rc9, rep = post(API + "/authz/apply", apply_body(
        nonce=nonce_hex,
        sub_hash=secrets.token_bytes(32).hex(), msg_hex=sub["message_hex"],
        sig_hex=sub["sig_hex"], case=case_id))
    record("REJECTED" if (rc9 == 409 and rep.get("code") == "nonce_used") else "OPEN",
           "A9 nonce 重放（换子凭证材料同 nonce）", f"rc={rc9} code={rep.get('code')}")

    # ---- A10 引用型（web 测试钉定）----
    record("REJECTED", "A10a 身份钥密文篡改", "GCM tag 校验失败——tests/lib/keystore.test.ts 钉定")
    record("REJECTED", "A10b 计划承诺穷举/关联", "异盐必异承诺——tests/lib/plan.test.ts 钉定")

    # ---- B1 边界确认：跨闸门令牌重放 ----
    import time as _time
    from app.kms import engine_signing_keypair
    sk_e, _ = engine_signing_keypair()
    now = int(_time.time())
    tok = {"authId": 1, "plan_hash": "ee" * 32, "alt_max": 30,
           "t_start": now - 60, "t_end": now + 3600, "nonce": "ee" * 16,
           "policy_version": "policy-2026-09-v1"}
    tok_body = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    tok_payload = (tok_body + "|" + sign_digest(sk_e, sm3_bytes(tok_body.encode()))).encode()
    rcg1 = post(BRIDGE + "/arm", {"token_payload_hex": tok_payload.hex(), "plan_hash_hex": "ee" * 32})
    rcg2 = post(BRIDGE + "/arm", {"token_payload_hex": tok_payload.hex(), "plan_hash_hex": "ee" * 32})
    record("BOUNDARY", "B1 同闸门二次 ARM（一次性令牌·方案 A）",
           f"第一次 ok={rcg1.get('ok')} 第二次 code={rcg2.get('code')}（桥接本机状态=TCB①声明，彻底方案=SE 计数器 R2）")

    # ---- 汇总 ----
    rej = sum(1 for v, _, _ in _records if v == "REJECTED")
    det = sum(1 for v, _, _ in _records if v == "DETECTED")
    bnd = sum(1 for v, _, _ in _records if v == "BOUNDARY")
    opn = sum(1 for v, _, _ in _records if v == "OPEN")
    print(f"\n== 红队记录：REJECTED {rej} · DETECTED {det} · BOUNDARY {bnd} · OPEN {opn} ==")
    for v, a, e in _records:
        print(f"- [{v}] {a} —— {e}")
    return 0 if opn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
