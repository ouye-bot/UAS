"""飞证 AUTH 实时出证端到端 e2e（R1 验收：任意新用户全流程真实走通）。

流程（全部真实组件——无替身/无占位）：
  登记（RA 真实签发）→ 子凭证 → 绑定面 → 桥接组装 JobSpec → zkc prove 本机实时出证
  → /authz/apply 受理（实例一致性核对）→ worker verify-instances（真实 zkc）
  → ready → 取件 ECIES 解密 → 令牌字段断言。

用法：cd uas/backend && python scripts/e2e_auth_full.py
前置：backend(8000) + bridge(8100) + worker 在线（demo_up 或分立启动）。
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
# 桥接出证目录同源（prover._cases_dir 同 env；缺省=backend/fz-zk-cases——
# 阶一修复：旧缺省 parents[1]/backend 双拼致真链档 proof.bin 对账路径错）
CASES = Path(
    os.environ.get(
        "FZ_ZK_CASES_DIR", str(Path(__file__).resolve().parents[1] / "fz-zk-cases")
    )
)

_checks = 0


def sm3_hex(b: bytes) -> str:
    from app.crypto.sm3 import sm3_bytes

    return sm3_bytes(b).hex()


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
    """API opener：https 档自动注入客户端证书（P0-4 mTLS——服务互认档）。

    env：FZ_API_BASE=https://localhost:9443 + FZ_API_CERT/FZ_API_KEY（PEM）+
    FZ_API_CA（CA 根）。缺省=明文环回档（回环禁系统代理不变）。
    """
    global _OPENER
    if _OPENER is None:
        handlers: list = [urllib.request.ProxyHandler({})]
        if API.startswith("https"):
            import ssl

            cert_dir = Path(__file__).resolve().parents[1] / "certs"
            ca = os.environ.get("FZ_API_CA", str(cert_dir / "ca.crt"))
            cert = os.environ.get("FZ_API_CERT", str(cert_dir / "client-e2e.crt"))
            key = os.environ.get("FZ_API_KEY", str(cert_dir / "client-e2e.key"))
            ctx = ssl.create_default_context(cafile=ca)
            ctx.load_cert_chain(cert, key)
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        _OPENER = urllib.request.build_opener(*handlers)
    return _OPENER



# ---- 账户会话（2026-09-29 账户批：X-Audit/X-RA-Token 退役）----
def _account_sessions():
    """按需登录审计员/管理员（env 初始口令；未激活态激活、已注册则跳过）。"""
    import os as _os
    from scripts.script_auth import script_login

    aud_pw = _os.environ.get("FZ_SEED_AUDITOR_PASSWORD")
    adm_pw = _os.environ.get("FZ_SEED_ADMIN_PASSWORD")
    if not aud_pw or not adm_pw:
        raise SystemExit(
            "需要 FZ_SEED_AUDITOR_PASSWORD / FZ_SEED_ADMIN_PASSWORD（部署方交付的"
            "预置账户初始口令——未激活态）。请先运行 scripts/seed_accounts.py 并以"
            "env 注入口令。"
        )
    return script_login(API, "auditor", aud_pw), script_login(API, "admin", adm_pw)


_AUD_SESS = None
_ADM_SESS = None


def _sess_cookie(path: str) -> str:
    """按路径分发会话 Cookie：/audit→审计员；/ra/revoke|/ra/collab|/admin→管理员。"""
    global _AUD_SESS, _ADM_SESS
    if _AUD_SESS is None:
        _AUD_SESS, _ADM_SESS = _account_sessions()
    if path.startswith("/ra/revoke") or path.startswith("/ra/collab") or path.startswith("/admin"):
        s = _ADM_SESS
    elif path.startswith("/audit"):
        s = _AUD_SESS
    else:
        return ""
    return "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items())


def api_get(path: str) -> dict:
    with opener().open(API + path, timeout=30) as r:
        return json.loads(r.read().decode())


def api_post(path: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(
        API + path, data=json.dumps(body).encode(), headers=hdrs, method="POST"
    )
    try:
        with opener().open(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def api_get_status(path: str) -> tuple[int, dict]:
    """GET（负例形态——HTTPError 也返回 (status, body) 而非上抛）。"""
    try:
        with opener().open(API + path, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def main() -> int:
    from app.crypto.sm2 import decrypt as ecies_decrypt
    from app.crypto.sm2 import generate_keypair

    print("== R1 AUTH 实时出证端到端（任意新用户，全部真实组件）==")
    t_all = time.time()

    # ① 登记（RA 真实签发）
    holder_sk, holder_pk = generate_keypair()
    sn = "FZ-SN-E2E-" + secrets.token_hex(2)
    rc, reg = api_post(
        "/ra/register",
        {
            "username": "e2e-" + secrets.token_hex(3),
            "id_number": "110101199001011234",
            "cert_level": 3,
            "sn": sn,
            "user_pub_hex": holder_pk,
            "class_id": 1,
        },
    )
    expect(rc == 200 and reg["code"] == "ok", "① 登记承诺（RA 真实签发）")
    cred = reg["data"]

    # ② 子凭证（一次性出示身份；sn/身份/资质须与登记一致——承诺原像知识认证）
    rc2, sub = api_post(
        "/ra/sub-credentials",
        {
            "master_cred_hash_hex": cred["master_cred_hash_hex"],
            "salt_hex": cred["salt_hex"],
            "id_number": "110101199001011234",
            "cert_level": 3,
            "sn": sn,
            "holder_pub_hex": holder_pk,
        },
    )
    expect(
        rc2 == 200 and sub["code"] == "ok",
        "② 子凭证签发（一次性出示身份）",
        f"rc={rc2} body={json.dumps(sub, ensure_ascii=False)[:300]}",
    )
    sub = sub["data"]

    # ③ 绑定面（确定性挑战+政策查表）
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    binding = api_get(
        f"/authz/binding?class_id=1&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}"
    )["data"]
    expect("challenge_hex" in binding and "pred_id" in binding, "③ 绑定面（HMAC 挑战+政策值）")

    # ④ 桥接实时出证（见证组装+本地 prove——秘密不出飞手侧）
    req = urllib.request.Request(
        BRIDGE + "/prove/start",
        data=json.dumps(
            {
                "plan_hash_hex": plan_hash_hex,
                "nonce_hex": nonce_hex,
                "class_id": 1,
                "id_number": "110101199001011234",
                "cert_level": 3,
                "sn": sn,
                "salt_hex": cred["salt_hex"],
                "id_prime_hex": sub["id_prime_hex"],
                "sig_hex": sub["sig_hex"],
                "expires_at": sub["expires_at"],
                "holder_sk_hex": holder_sk,
                "holder_pk_hex": holder_pk,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener().open(req, timeout=30) as r:
            start = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print("  [FAIL] /prove/start 422 详情:", e.read().decode()[:400])
        raise
    task_id = start["task_id"]
    case_id = start["case_id"]  # 桥接生成的出证目录号（apply 消费同一 case）
    # 绑定单源纪律：t_epoch 必须消费桥接出证所用的同一绑定（实例 21 同源）——
    # 自行再取 /authz/binding 必得不同 t_epoch（now 非确定）⟹ instance_mismatch。
    prove_t_epoch = start["binding"]["t_epoch"]
    print(f"  [..] ④ 桥接本机出证中（task={task_id[:12]}…，AUTH 本机约 2 分钟）")
    t0 = time.time()
    status = "assembling"
    t = {"status": "assembling"}
    while status in ("assembling", "proving"):
        time.sleep(5)
        with opener().open(f"{BRIDGE}/prove/task/{task_id}", timeout=15) as r:
            t = json.loads(r.read().decode())
        if "status" in t:
            if t["status"] != status:
                status = t["status"]
                print(f"  [..] 状态：{status}（{time.time() - t0:.0f}s）")
        elif "status" in t.get("data", {}):
            new_status = t["data"]["status"]
            if new_status != status:
                status = new_status
                print(f"  [..] 状态：{status}（{time.time() - t0:.0f}s）")
            if new_status == "failed":
                print(f"  [..] 失败原因：{t['data'].get('error')}")
        if time.time() - t0 > 1500:
            print("  [FAIL] 出证超时（25 分钟）")
            raise SystemExit(1)
    expect(status == "done", f"④ 桥接本机出证完成（{time.time() - t0:.0f}s）")
    t_prove = time.time() - t0

    # ⑤ 受理（实例一致性核对+入队）
    rc5, apply = api_post(
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
    expect(
        rc5 == 200 and apply.get("ok") is True,
        "⑤ 受理通过（实例一致性核对+入队）",
        f"rc={rc5} body={json.dumps(apply, ensure_ascii=False)[:300]}",
    )
    receipt_code = apply["data"]["receipt_code"]

    # ⑥ worker 真实验证（verify-instances）→ ready
    t1 = time.time()
    status = "waiting"
    r = {"status": "waiting"}
    while time.time() - t1 < 90:
        with opener().open(f"{API}/authz/receipt/{receipt_code}", timeout=15) as resp:
            r = json.loads(resp.read().decode())["data"]
        status = r["status"]
        if status != "waiting":
            break
        time.sleep(2)
    expect(status == "ready", f"⑥ worker 真实验证通过→回执 ready（{time.time() - t1:.0f}s）")

    # ⑦ 取件解密（飞手侧 ECIES——会话私钥不出设备）
    payload = ecies_decrypt(holder_sk, bytes.fromhex(r["token_cipher_hex"]))
    body, sig_hex = payload.rsplit(b"|", 1)
    tok = json.loads(body)
    ok("⑦ 取件 ECIES 解密成功（会话私钥本地）")

    # ⑧ 令牌字段断言
    expect(tok["plan_hash"] == plan_hash_hex, "⑧ 令牌绑定 plan_hash（A2）")
    expect(len(tok["nonce"]) == 32, "nonce 一次性形态")
    expect(tok["authId"] > 0, "authId 贯穿键在场")
    expect("sn_hash" not in tok and "sn" not in tok, "令牌零设备字段（B4-d7）")

    # ⑨⑩⑪ 真链档断言组（阶段一：recordAuth 链上对账+nonce 链级重放拒绝）
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") != "fake":
        from app.chain.client import ChainClient
        from app.chain.contracts import load_binding
        from app.chain.signer import TxSigner
        from app.kms import chain_ra_tx_key

        addr = json.loads(
            (
                Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json"
            ).read_text()
        )
        signer = TxSigner(chain_ra_tx_key())
        client = ChainClient(
            rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
            from_addr=signer.address,
        )
        fa = load_binding("FlightAuthRegistry", client, addr["FlightAuthRegistry"]["address"])
        auth_id = tok["authId"]

        # ⑨ recordAuth 11 元组逐项对账（D17/D18 在链）
        rec = fa.call_fn("getAuth", [auth_id])
        th_local = sm3_hex(body)
        proof_digest_local = sm3_hex((CASES / case_id / "proof.bin").read_bytes())
        expect(
            rec[0].hex() == th_local and rec[1].hex() == nonce_hex,
            "⑨-1 链上 tokenHash/nonce 与本地一致（recordAuth 真链）",
            f"链上 {rec[0].hex()[:16]}…/{rec[1].hex()[:16]}…",
        )
        expect(rec[2] == 1 and rec[3] == 120, "⑨-2 classId/altMaxM（meters 单位契约）")
        expect(rec[4] == prove_t_epoch and rec[5] == prove_t_epoch + 3600, "⑨-3 授权窗链上一致")
        expect(
            rec[6].hex() == sub["sub_cred_hash_hex"] and rec[7].hex() == proof_digest_local,
            "⑨-4 subCredHash/proofDigest 链上一致（D18 逐次不可关联+D17 可审计签发）",
        )
        expect(int(rec[8]) == 0, "⑨-5 授权状态有效")
        # ⑪ tokenAuthIds 回读（B5 闸门验证键）
        expect(
            int(fa.call_fn("tokenAuthIds", [bytes.fromhex(th_local)])[0]) == auth_id,
            "⑪ tokenAuthIds 回读=authId（闸门验证键）",
        )

        # ⑩ nonce 链级重放拒绝（门控③链视图——recordAuth 已烧毁 ⟹ 二次受理必拒）
        expect(
            fa.call_fn("nonceUsed", [bytes.fromhex(nonce_hex)])[0] is True,
            "⑩-1 链上 nonceUsed=true（烧毁在链）",
        )
        rc10, again = api_post(
            "/authz/apply",
            {
                "session_pk_hex": holder_pk,
                "sub_cred_message_hex": sub["message_hex"],
                "sub_sig_hex": sub["sig_hex"],
                # 换新子凭证材料仍拒——nonce 链级烧毁是独立拒绝轴
                "sub_cred_hash_hex": secrets.token_bytes(32).hex(),
                "nonce_hex": nonce_hex,
                "plan_hash_hex": plan_hash_hex,
                "class_id": 1,
                "case_id": case_id,
                "rev_root_hex": api_get("/ra/revocation/snapshot")["data"]["root_hex"],
                "t_start": prove_t_epoch,
                "t_end": prove_t_epoch + 3600,
            },
        )
        expect(
            rc10 == 409 and again.get("code") == "nonce_used",
            "⑩-2 同 nonce 二次受理=链级重放拒绝 409",
            f"rc={rc10} body={json.dumps(again, ensure_ascii=False)[:200]}",
        )
        chain_note = "（真链档 ⑨⑩⑪ 全绿）"
    else:
        chain_note = "（fake 档——链断言组跳过）"

    # ⑫ 撤销端到端负例（R4 第二批 A-P1-2/B-P2-4——B4「撤销即时」验证升档：
    # 分层防线=受理门 stale 根拒 / RA 见证 fail-fast / RA 拒新签发；真链档另
    # 对账 revEpoch/revRoot 上链实况。本段吊销本脚本用户——演示库首个真实吊销行）
    sub_in = {
        "master_cred_hash_hex": cred["master_cred_hash_hex"],
        "salt_hex": cred["salt_hex"],
        "id_number": "110101199001011234",
        "cert_level": 3,
        "sn": sn,
        "holder_pub_hex": holder_pk,
    }
    old_root = api_get("/ra/revocation/snapshot")["data"]["root_hex"]
    rc12a, sub2 = api_post("/ra/sub-credentials", sub_in)
    expect(rc12a == 200 and sub2["code"] == "ok", "⑫-1 吊销前子凭证签发（基线）")
    sub2 = sub2["data"]
    rc12b, rv = api_post(
        "/ra/revoke",
        {"master_cred_hash_hex": cred["master_cred_hash_hex"], "reason": "e2e 撤销负例"},
    )
    expect(
        rc12b == 200 and rv["code"] == "ok" and rv["data"]["root_hex"] != old_root,
        "⑫-2 吊销（机构管理员会话——账户批）→纪元根更迭",
        f"rc={rc12b} body={json.dumps(rv, ensure_ascii=False)[:200]}",
    )
    rc12c, stale = api_post(
        "/authz/apply",
        {
            "session_pk_hex": holder_pk,
            "sub_cred_message_hex": sub2["message_hex"],
            "sub_sig_hex": sub2["sig_hex"],
            "sub_cred_hash_hex": sub2["sub_cred_hash_hex"],
            "nonce_hex": secrets.token_bytes(16).hex(),
            "plan_hash_hex": secrets.token_bytes(32).hex(),
            "class_id": 1,
            "case_id": case_id,
            "rev_root_hex": old_root,
            "t_start": prove_t_epoch,
            "t_end": prove_t_epoch + 3600,
        },
    )
    expect(
        rc12c == 409 and stale.get("code") == "stale_rev_root",
        "⑫-3 旧子凭证携旧撤销根申请=409 stale_rev_root（受理门拦截）",
        f"rc={rc12c} body={json.dumps(stale, ensure_ascii=False)[:200]}",
    )
    rc12d, w = api_get_status(f"/ra/revocation/witness?holder_pk_hex={holder_pk}")
    expect(
        rc12d == 403 and w.get("code") == "revoked",
        "⑫-4 重取见证=403 revoked（fail-fast——不烧出证）",
        f"rc={rc12d} body={json.dumps(w, ensure_ascii=False)[:200]}",
    )
    rc12e, sub3 = api_post("/ra/sub-credentials", sub_in)
    expect(
        rc12e == 403 and sub3.get("code") == "cred_revoked",
        "⑫-5 二次签发=403 cred_revoked（撤销后拒新子凭证）",
        f"rc={rc12e} body={json.dumps(sub3, ensure_ascii=False)[:200]}",
    )
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") != "fake":
        from app.chain.contracts import load_binding

        ir = load_binding("IdentityRegistry", client, addr["IdentityRegistry"]["address"])
        c_epoch = int(ir.call_fn("revEpoch", [])[0])
        c_root = ir.call_fn("revRoot", [])[0].hex()
        expect(
            c_epoch == rv["data"]["epoch"] and c_root == rv["data"]["root_hex"],
            "⑫-6 链上 revEpoch/revRoot 与吊销回执逐位一致（撤销公示上链）",
            f"链上 ({c_epoch},{c_root[:16]}…) vs 回执 "
            f"({rv['data']['epoch']},{rv['data']['root_hex'][:16]}…)",
        )

    print(f"\n== R1 端到端全绿：{_checks} 项断言 [OK] =={chain_note}（⑫ 撤销负例全绿）")
    print(f"== 出证 {t_prove:.0f}s ｜ 全程 {time.time() - t_all:.0f}s ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
