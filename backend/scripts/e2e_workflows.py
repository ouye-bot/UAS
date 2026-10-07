# -*- coding: utf-8 -*-
"""三角色全流程接口级 e2e（2026-10-07 队长指令：界面上能做的一切动作→真实工作流串联）。

对**运行中的栈**（backend 8000 / bridge 8100，真链档+真 SITL）逐工作流实测。
工程范式=scripts/e2e_roles_live.py + e2e_auth_full.py：requests 会话、真链真出证、
断言只增不减、口令走 env/seed 文件（禁入代码）。

  [P] 飞手：注册(v4 信封)→登记→子凭证→授权包 sorties=3 申请→桥出证→受理
      →取件解密→三次架次循环（ARM 消费配额/remaining 递减/真链权威核对）
      →配额耗尽第四发拒→窗过期负例→被吊销后的人话报错
  [A] 审计员：登录→收件箱 fileable→立案→签名发函→verify-sigs 复验→
      恢复核验 countersign 面→结案(结论+签名+案卷指纹)→trace 全字段断言
  [M] 机构管理员：待批列表→批准→执行终态→待处置卡+resolve→签名撤销
      (preview→FZ-REVOKE→linked_auth_ids)→公示理由→恢复发起→授权轴联动→台账
  [N] 负例组：结案缺结论/坏签名、撤销缺签名、恢复单签不执行、v3 注册 422、
      配额越界 422、case_taken、幂等重放(重复批准/重复结案/重复处置)

用法：cd uas/backend && python scripts/e2e_workflows.py
前置：backend(8000)+bridge(8100,SITL)+worker 在线；真链档（FZ_CHAIN_ANCHOR!=fake）。
口令：FZ_SEED_AUDITOR_PASSWORD / FZ_SEED_ADMIN_PASSWORD env 优先，缺省回落
%TEMP%\\fz_accounts_seed.txt（seed_accounts.py 交付面——与 e2e_roles_live 同式）。
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import requests  # noqa: E402

API = os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")
BRIDGE = os.environ.get("FZ_BRIDGE_BASE", "http://127.0.0.1:8100")
# ⑥代 SN 绑定：登记 SN 必须与桥 device_serial 同源（第 6 查 sn_hash 对拍）——
# 单源读法与 e2e_frontend_api.py 逐字一致（一证一机闭环）。
SN = os.environ.get("FZ_DEVICE_SERIAL", "FZ-SN-DEV-01")
REAL_CHAIN = os.environ.get("FZ_CHAIN_ANCHOR", "fake") != "fake"

_checks = 0


def ok(label: str) -> None:
    global _checks
    _checks += 1
    print(f"  [OK] {label}")


def expect(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        ok(label)
        return
    print(f"  [FAIL] {label} {detail}")
    raise SystemExit(1)


# ---------------------------------------------------------------- HTTP 助手


def bpost(path: str, body: dict, timeout: float = 60) -> dict:
    r = requests.post(BRIDGE + path, json=body, timeout=timeout)
    try:
        return r.json()
    except ValueError:
        return {"http": r.status_code}


def bget(path: str, timeout: float = 30) -> dict:
    r = requests.get(BRIDGE + path, timeout=timeout)
    try:
        return r.json()
    except ValueError:
        return {"http": r.status_code}


def g(sess, path: str, timeout: float = 30):
    r = sess.get(API + path, timeout=timeout)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


def p(sess, path: str, body: dict, timeout: float = 90):
    r = sess.post(API + path, json=body, timeout=timeout)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


def anon() -> requests.Session:
    return requests.Session()


def _pw(env_key: str, marker: str) -> str:
    """口令来源：env > %TEMP%\\fz_accounts_seed.txt（seed 交付面）——禁入代码。"""
    if os.environ.get(env_key):
        return os.environ[env_key]
    seed = Path(tempfile.gettempdir()) / "fz_accounts_seed.txt"
    if seed.is_file():
        for line in seed.read_text(encoding="utf-8").splitlines():
            if marker in line:
                tail = line.rsplit(" ", 1)[-1].strip()
                if tail:
                    return tail
    raise SystemExit(f"缺 {marker} 口令——env {env_key} 或 seed 文件二选一")


# ---------------------------------------------------------------- 密码学助手


def sm3_hex(b: bytes) -> str:
    from app.crypto.sm3 import sm3_bytes

    return sm3_bytes(b).hex()


def sign(sk: str, msg: str) -> str:
    from app.crypto.sm2 import sign as _sign

    return _sign(sk, msg.encode())


def gen_keypair():
    from app.crypto.sm2 import generate_keypair

    return generate_keypair()  # (sk, pk 128hex 无 04 前缀)


def ecies_decrypt(sk: str, ct: bytes) -> bytes:
    from app.crypto.sm2 import decrypt as _dec

    return _dec(sk, ct)


def seal_profile_slot(obj: dict, passphrase: str) -> str:
    """{cred,form} 密码 KEK 密封（前端 sealProfileSlot 同族原语：PBKDF2-HMAC-SM3
    +SM4-GCM——服务端透明存储，本函数与解封互为回执自证）。"""
    import secrets as _sec

    from app.accounts.kdf import KDF_NAME_V4, derive_kek
    from app.crypto.sm4 import SM4GCM

    salt, nonce = _sec.token_hex(16), _sec.token_hex(12)
    kek = bytes.fromhex(derive_kek(passphrase, salt, 600_000))
    pt = json.dumps(obj, ensure_ascii=False).encode()
    ct, tag = SM4GCM(kek).encrypt(bytes.fromhex(nonce), pt, b"FZ-PROFILE-v1|pass")
    return json.dumps(
        {
            "v": 4, "kdf": KDF_NAME_V4, "iter": 600_000, "salt": salt, "nonce": nonce,
            "ct": ct.hex(), "tag": tag.hex(),
        }
    )


def pilot_session(username: str, password: str, sk: str) -> requests.Session:
    """pilot 会话（注册后静默登录——与前端 loginWithSk 同一挑战-应答路径）。"""
    s = anon()
    nonce = s.post(f"{API}/auth/challenge/{username}", timeout=15).json()["data"]["nonce_hex"]
    r = s.post(
        API + "/auth/login",
        json={"username": username, "nonce_hex": nonce, "sig_hex": sign(sk, f"FZ-AUTH-LOGIN|{nonce}")},
        timeout=15,
    )
    r.raise_for_status()
    return s


# ---------------------------------------------------------------- 等待面


def wait_prove(task_id: str, what: str, cap_s: float = 1500) -> None:
    t0, status = time.time(), "assembling"
    while status in ("assembling", "proving"):
        time.sleep(5)
        t = bget(f"/prove/task/{task_id}")
        d = t.get("data") or {}
        status = d.get("status") or t.get("status") or status
        if status == "failed":
            raise SystemExit(f"  [FAIL] {what} 出证失败: {str(t)[:300]}")
        if time.time() - t0 > cap_s:
            raise SystemExit(f"  [FAIL] {what} 出证超时（{cap_s:.0f}s）")
    expect(status == "done", f"{what}（{time.time() - t0:.0f}s）")


def wait_receipt(code: str, cap_s: float = 150) -> dict:
    t0, r = time.time(), {"status": "waiting"}
    while time.time() - t0 < cap_s:
        rc, body = g(anon(), f"/authz/receipt/{code}")
        r = body.get("data") or {}
        if r.get("status") != "waiting":
            break
        time.sleep(2)
    expect(r.get("status") == "ready", f"回执 ready（worker 真实验证 {time.time() - t0:.0f}s）",
           json.dumps(r, ensure_ascii=False)[:200])
    return r


def wait_terminal(sess, req_id: int, cap_s: float = 240) -> dict | None:
    deadline = time.time() + cap_s
    while time.time() < deadline:
        _, body = g(sess, "/audit/collab-requests")
        for x in (body.get("data") or {}).get("items", []):
            if x["id"] == req_id and x["status"] in ("executed", "execute_failed"):
                return x
        time.sleep(2)
    return None


# ---------------------------------------------------------------- 工作流段


def full_authorization(pil: requests.Session, holder_sk: str, holder_pk: str, cred: dict,
                       sub: dict, id_number: str, tag: str, sorties: int = 1,
                       win_s: int = 3600) -> tuple[dict, dict]:
    """绑定→桥出证→受理→取件解密（fresh 申请段——applyAndFetch+pickup 同构）。
    返回 (tok, 材料)。win_s=授权窗长（窗过期负例传 5）。"""
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    _, bj = g(pil, f"/authz/binding?class_id=1&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}")
    b = bj["data"]
    expect(all(k in b for k in ("challenge_hex", "pred_id", "t_epoch", "alt_max", "required_level")),
           f"{tag} 绑定面（HMAC 挑战+政策值+时间锚）")
    st = bpost("/prove/start", {
        "plan_hash_hex": plan_hash_hex, "nonce_hex": nonce_hex, "class_id": 1,
        "id_number": id_number, "cert_level": 3, "sn": SN,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub["id_prime_hex"],
        "sig_hex": sub["sig_hex"], "expires_at": sub["expires_at"],
        "holder_sk_hex": holder_sk, "holder_pk_hex": holder_pk,
    }, timeout=60)
    expect("task_id" in st and "case_id" in st, f"{tag} 桥受理出证任务", str(st)[:200])
    t_epoch = st["binding"]["t_epoch"]
    print(f"  [..] {tag} 本机出证中（task={st['task_id'][:12]}…）")
    wait_prove(st["task_id"], f"{tag} 桥本机出证完成")
    _, snap = g(anon(), "/ra/revocation/snapshot")
    rc, ap = p(pil, "/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub["message_hex"],
        "sub_sig_hex": sub["sig_hex"],
        "sub_cred_hash_hex": sub["sub_cred_hash_hex"],
        "nonce_hex": nonce_hex, "plan_hash_hex": plan_hash_hex,
        "class_id": 1, "case_id": st["case_id"],
        "rev_root_hex": snap["data"]["root_hex"],
        "t_start": t_epoch, "t_end": t_epoch + win_s,
        "sorties": sorties,
    })
    expect(rc == 200 and ap.get("ok") is True, f"{tag} 受理（实例一致性核对+入队）",
           f"rc={rc} {json.dumps(ap, ensure_ascii=False)[:250]}")
    expect(ap["data"].get("sorties") == sorties and ap["data"].get("mode") == "real",
           f"{tag} 受理回执 sorties={sorties}+mode=real（授权包配额制）")
    rr = wait_receipt(ap["data"]["receipt_code"])
    payload = ecies_decrypt(holder_sk, bytes.fromhex(rr["token_cipher_hex"]))
    body, sig_hex = payload.rsplit(b"|", 1)
    tok = json.loads(body)
    expect(tok["plan_hash"] == plan_hash_hex and tok["authId"] > 0 and len(tok["nonce"]) == 32,
           f"{tag} 取件 ECIES 解密+令牌贯穿字段（plan_hash/authId/nonce）")
    expect(tok["sn_hash"] == sm3_hex(SN.encode()), f"{tag} 令牌 sn_hash=SM3(桥序列号)（一证一机）")
    mats = {"tok": tok, "payload_hex": payload.hex(), "body": body,
            "plan_hash_hex": plan_hash_hex, "case_id": st["case_id"], "t_epoch": t_epoch}
    return tok, mats


def sortie_flight(i: int, mats: dict, expect_checkpoint: bool, breach: bool) -> None:
    """单架次真实飞行段：ARM→起链→真采样（→围栏取证）→DISARM（真 SITL）。"""
    r = bpost("/arm", {"token_payload_hex": mats["payload_hex"],
                       "plan_hash_hex": mats["plan_hash_hex"]}, timeout=180)
    expect(r.get("ok") is True, f"架次{i} ARM（围栏写入+ACK+消费回报）", json.dumps(r, ensure_ascii=False)[:220])
    expect(r.get("alt_max") == 120, f"架次{i} 围栏上限=政策值 120m")
    aid = r["auth_id"]
    ch = bpost("/telemetry/start", {"auth_id": aid}, timeout=30)
    expect(ch.get("ok") is True and len(ch.get("genesis_head_hex", "")) == 64,
           f"架次{i} 遥测链 genesis（authId+围栏态绑定）", str(ch)[:150])
    n0, breached, event = 0, False, None
    t0 = time.time()
    while time.time() - t0 < (300 if breach else 12):
        if breach and not breached:
            bpost("/sitl/climb?pwm=2000&hold_s=1.2", {}, timeout=30)
        s = bget(f"/telemetry/sitl_sample?t_epoch={int(time.time())}")
        if s.get("ok"):
            n0 = s.get("n", n0)
            if s.get("fence_breached"):
                breached = True
            if breached and s.get("event") and event is None:
                event = s["event"]
            if expect_checkpoint and s.get("checkpoint"):
                break
        if (not breach) and expect_checkpoint and s.get("checkpoint"):
            break
        time.sleep(0.6)
    expect(n0 >= 1, f"架次{i} 真采样入链（n={n0}）")
    if breach:
        expect(breached, f"架次{i} 固件围栏触发（真飞控 STATUSTEXT）")
        expect(event is not None and event.get("event_type") == 1,
               f"架次{i} 违规取证事件（source=1 固件权威）", str(event)[:120])
        ev = bpost("/telemetry/event", event, timeout=60)
        expect(ev.get("ok") is True, f"架次{i} 违规事件上链（前端 E-14 补发路径）", str(ev)[:150])
    if expect_checkpoint:
        an = bpost("/telemetry/anchor", {}, timeout=180)
        expect(an.get("ok") is True and an.get("anchored", 0) >= 1,
               f"架次{i} 检查点真链锚定（设备签名+围栏态）", str(an)[:200])
    d = bpost("/sitl/disarm", {}, timeout=30)
    expect(d.get("ok") is True, f"架次{i} DISARM 收尾（授权态复位）")
    for _ in range(20):  # 飞控侧上锁位回落（下一架次 ARM 前置）
        st = bget("/telemetry/state")
        if st.get("fc_armed") is False:
            break
        time.sleep(0.5)


def quota_check(i: int, aid: int, th: str, remaining: int, consumed: bool) -> None:
    """配额三面对账：/authz/status 服务端权威+真链 remainingOf（real 档）。
    token_consumed 判词须携 token_hash_hex（服务端按令牌哈希查消费账本——
    与桥端 authz_quota_fetch 同键口径）；消费回报为 ARM 成功后 best-effort
    ——留短重试窗等账面收敛（不放松终判）。"""
    deadline = time.time() + 30
    d: dict = {}
    while time.time() < deadline:
        _, st = g(anon(), f"/authz/status?auth_id={aid}&token_hash_hex={th}")
        d = st.get("data") or {}
        if (d.get("remaining") == remaining and d.get("sorties") == 3
                and d.get("token_consumed") is consumed):
            break
        time.sleep(2)
    expect(d.get("remaining") == remaining and d.get("sorties") == 3
           and d.get("token_consumed") is consumed and d.get("mode") == "real",
           f"架次{i} 后 /authz/status 配额面 remaining={remaining} consumed={consumed}",
           str(d)[:160])
    if REAL_CHAIN:
        from app.chain.client import ChainClient
        from app.chain.contracts import load_binding
        from app.chain.signer import TxSigner

        from app.kms import chain_ra_tx_key

        addr = json.loads((BACKEND.parent / "contracts" / ".chain_addresses.json").read_text())
        signer = TxSigner(chain_ra_tx_key())
        client = ChainClient(rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
                             from_addr=signer.address)
        fa = load_binding("FlightAuthRegistry", client, addr["FlightAuthRegistry"]["address"])
        rec = fa.call_fn("getAuth", [aid])
        expect(int(rec[11]) == remaining, f"架次{i} 后 链上 remainingOf 权威={remaining}",
               f"链={int(rec[11])}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-flight", action="store_true", help="跳过真机架次段（仅排障用——缺省全跑）")
    args = ap.parse_args()

    t_all = time.time()
    print("== 三角色全流程接口级 e2e（真链+真 SITL）==")

    # ============ [P] 飞手 ============
    print("== [P] 飞手：注册→登记→子凭证→授权包→架次循环 ==")
    pilot_user = "wf-" + secrets.token_hex(3)
    password = secrets.token_urlsafe(12)  # 随机口令——不落代码不落盘
    id_number = "11010119900101" + secrets.token_hex(2)  # 18 位逐轮随机（B7 黑名单纪律）
    sk_u, pk_u = gen_keypair()

    from app.accounts.envelope import seal_envelope_v4

    reg_s = anon()
    rc, reg = p(reg_s, "/auth/register", {
        "username": pilot_user, "pubkey_hex": pk_u,
        "sealed_blob": seal_envelope_v4(sk_u, pk_u, password)})
    expect(rc == 201 and reg.get("code") == "ok" and reg["data"]["status"] == "pending_profile",
           "P1 v4 信封注册（零明文私钥上行）→ pending_profile", f"rc={rc} {str(reg)[:150]}")

    pil = pilot_session(pilot_user, password, sk_u)
    who = pil.get(API + "/auth/whoami", timeout=15).json()["data"]
    expect(who["role"] == "pilot", "P2 挑战-应答登录 → role=pilot", str(who))

    form = {"id_number": id_number, "cert_level": 3, "sn": SN, "class_id": 1}
    rc, prof = p(pil, "/auth/profile", form)
    expect(rc == 200 and "master_cred_hash_hex" in prof.get("data", {}),
           "P3 资料补全=上链注册（RA 签发+链锚）", f"rc={rc} {str(prof)[:150]}")
    cred = prof["data"]
    rc, kept = p(pil, "/auth/profile/keep", {"sealed_profile": seal_profile_slot(
        {"cred": cred, "form": form}, password)})
    expect(rc == 200, "P4 密封资料二相回存（KEK 密封零明文 PIII）")
    _, me = g(pil, "/auth/me")
    expect(bool((me.get("data") or {}).get("sealed_profile")), "P4b /auth/me 回读密封资料在场")

    def issue_sub(holder_pk: str) -> dict:
        rc, sj = p(anon(), "/ra/sub-credentials", {
            "master_cred_hash_hex": cred["master_cred_hash_hex"],
            "salt_hex": cred["salt_hex"], "id_number": id_number,
            "cert_level": 3, "sn": SN, "holder_pub_hex": holder_pk})
        expect(rc == 200 and sj.get("code") == "ok", "子凭证签发（一次性出示身份）",
               f"rc={rc} {str(sj)[:150]}")
        return sj["data"]

    sub_sk1, sub_pk1 = gen_keypair()
    sub1 = issue_sub(sub_pk1)
    expect(len(sub1["message_hex"]) == 330 and sub1["id_prime_hex"], "P5 子凭证#1 形态（M_A′ 330hex+id′）")

    tok1, mats1 = full_authorization(pil, sub_sk1, sub_pk1, cred, sub1, id_number,
                                     "P6-P9 授权包(sorties=3)", sorties=3, win_s=3600)
    aid1 = tok1["authId"]
    expect(tok1["alt_max"] == 120, "P9b 令牌 alt_max=政策值（meters 单位契约）")

    if not args.skip_flight:
        print("  [..] GPS 锁等待…")
        wg = bpost("/sitl/wait_gps?timeout_s=180", {}, timeout=300)
        expect(wg.get("ok") is True, "P10 SITL GPS 锁（fix_type≥3）", str(wg)[:120])
        for i in (1, 2, 3):
            sortie_flight(i, mats1, expect_checkpoint=(i == 1), breach=(i == 3))
            quota_check(i, aid1, sm3_hex(mats1["body"]), remaining=3 - i, consumed=(i == 3))
        r4 = bpost("/arm", {"token_payload_hex": mats1["payload_hex"],
                            "plan_hash_hex": mats1["plan_hash_hex"]}, timeout=60)
        expect(r4.get("ok") is False and r4.get("code") == "quota_exhausted",
               "P11 负例：配额耗尽第四发 → quota_exhausted（fail-closed）",
               json.dumps(r4, ensure_ascii=False)[:200])
    else:
        print("  [SKIP] --skip-flight：架次段未跑（排障档）")

    # ============ [N] 负例组（受理面） ============
    print("== [N] 负例组：v3 注册/配额越界/case_taken ==")
    rc, v3 = p(anon(), "/auth/register", {
        "username": "wf-v3-" + secrets.token_hex(3), "pubkey_hex": pk_u,
        "sealed_blob": json.dumps({"v": 3, "pk": pk_u,
                                   "enc": {"salt": "00" * 16, "nonce": "00" * 12,
                                           "ct": "00" * 48, "tag": "00" * 16}})})
    expect(rc == 422 and v3.get("code") == "v3_register_rejected",
           "N1 v3 旧信封注册 → 422 v3_register_rejected（停发换代）", f"rc={rc} {str(v3)[:120]}")

    _, snap0 = g(anon(), "/ra/revocation/snapshot")
    rc, oob = p(pil, "/authz/apply", {
        "session_pk_hex": pk_u, "sub_cred_message_hex": sub1["message_hex"],
        "sub_sig_hex": sub1["sig_hex"], "sub_cred_hash_hex": sub1["sub_cred_hash_hex"],
        "nonce_hex": secrets.token_bytes(16).hex(),
        "plan_hash_hex": secrets.token_bytes(32).hex(), "class_id": 1,
        "case_id": "ff" + secrets.token_hex(7), "rev_root_hex": snap0["data"]["root_hex"],
        "t_start": 1, "t_end": 2, "sorties": 6})
    expect(rc == 422, "N2 sorties=6 越界 → 422（授权包上限 1~5）", f"rc={rc} {str(oob)[:120]}")

    sub_sk2, sub_pk2 = gen_keypair()
    sub2 = issue_sub(sub_pk2)
    rc, taken = p(pil, "/authz/apply", {
        "session_pk_hex": sub_pk2, "sub_cred_message_hex": sub2["message_hex"],
        "sub_sig_hex": sub2["sig_hex"], "sub_cred_hash_hex": sub2["sub_cred_hash_hex"],
        "nonce_hex": secrets.token_bytes(16).hex(),
        "plan_hash_hex": secrets.token_bytes(32).hex(), "class_id": 1,
        "case_id": mats1["case_id"], "rev_root_hex": snap0["data"]["root_hex"],
        "t_start": 1, "t_end": 2})
    expect(rc == 409 and taken.get("code") == "case_taken",
           "N3 他材料抢注已归属案卷 → 409 case_taken（案卷唯一归属门）",
           f"rc={rc} {str(taken)[:150]}")

    # 窗过期负例：全合法新材料，仅窗口 5s——ARM 时点必已越窗
    tok2, mats2 = full_authorization(pil, sub_sk2, sub_pk2, cred, sub2, id_number,
                                     "P12 窗过期授权", sorties=1, win_s=5)
    r = bpost("/arm", {"token_payload_hex": mats2["payload_hex"],
                       "plan_hash_hex": mats2["plan_hash_hex"]}, timeout=60)
    expect(r.get("ok") is False and r.get("code") == "window_expired",
           "P13 负例：窗过期令牌 ARM → window_expired（闸门时间轴权威）",
           json.dumps(r, ensure_ascii=False)[:200])

    sub_sk3, sub_pk3 = gen_keypair()
    sub3 = issue_sub(sub_pk3)  # 不消费——留给撤销传播叶（见证 403 人话报错的键）

    # ============ [A] 审计员 ============
    print("== [A] 审计员：收件箱→立案→发函→复验 ==")
    from scripts.script_auth import script_login

    aud = script_login(API, "auditor", _pw("FZ_SEED_AUDITOR_PASSWORD", "auditor"))
    adm = script_login(API, "admin", _pw("FZ_SEED_ADMIN_PASSWORD", "admin"))

    lead = None
    t0 = time.time()
    while time.time() - t0 < 120:  # 事件索引守护线程 10s 拍——围栏违规入箱
        _, vj = g(aud, "/audit/violations?unfiled=1")
        items = (vj.get("data") or {}).get("items", [])
        lead = next((x for x in items if x["auth_id"] == aid1), None)
        if lead:
            break
        time.sleep(5)
    expect(lead is not None and lead["fileable"] is True and lead["events"] >= 1,
           "A1 违规收件箱：auth1 线索在箱且 fileable（授权在案）",
           f"lead={str(lead)[:150]} items={len(items)}")

    rc, wl = g(aud, "/audit/warrants")
    rows = wl.get("data") or []
    expect(rc == 200 and isinstance(rows, list)
           and all(isinstance(w.get("unlocked"), dict) and "ts" in w["unlocked"]
                   and "username" in w["unlocked"] for w in rows),
           "A2 令状列表 unlocked=嵌套对象契约（对账矩阵钉：ts/username 键在场）",
           str(rows[:1])[:150])

    case_no = "WF-" + secrets.token_hex(3)
    basis = f"授权 #{aid1} 围栏超限违规（workflows 全流程实弹）——依据相关条款立案调查"
    rc, w = p(aud, "/audit/warrants", {"case_no": case_no, "legal_basis_text": basis,
                                       "target_auth_id": aid1})
    expect(rc == 200 and w.get("code") == "ok", "A3 立案（依据原文+哈希双锚上链）",
           f"rc={rc} {str(w)[:150]}")
    wh = w["data"]["warrant_hash_hex"]
    rc, dup = p(aud, "/audit/warrants", {"case_no": case_no, "legal_basis_text": basis,
                                         "target_auth_id": aid1})
    expect(rc == 400 and dup.get("code") == "warrant_exists", "A3b 负例：重复立案 → 400",
           f"rc={rc} {str(dup)[:100]}")

    note = "workflows 实弹：请求协同解锁当事人实名以完成调查"
    req_msg = f"FZ-COLLAB-REQ|v1|{wh}|{note}"
    rc, fr = p(aud, "/audit/collab-requests", {"warrant_hash_hex": wh, "note": note,
                                               "sig_hex": sign(aud.sk, req_msg)})
    expect(rc == 200 and fr["data"]["status"] == "pending", "A4 签名发函 → pending",
           f"rc={rc} {str(fr)[:150]}")
    req_id = fr["data"]["id"]
    rc, vs = g(aud, f"/audit/collab-requests/{req_id}/verify-sigs")
    va = (vs.get("data") or {})
    expect(va.get("auditor", {}).get("ok") is True
           and va.get("admin", {}).get("reason") == "not_decided",
           "A5 verify-sigs 复验：审计签在场/机构未决（not_decided）", str(vs)[:150])

    # ============ [M] 机构管理员 ============
    print("== [M] 机构管理员：批准→终态→（结案后）处置/撤销/恢复 ==")
    rc, lst = g(adm, "/admin/collab-requests")
    expect(any(x["id"] == req_id for x in (lst.get("data") or {}).get("items", [])),
           "M1 待批列表含新请求")
    rc, ap_r = p(adm, f"/admin/collab-requests/{req_id}/approve", {"sig_hex": sign(adm.sk, req_msg)})
    expect(rc == 200 and ap_r["data"]["status"] == "approved", "M2 批准（管理员钥签同内容）",
           f"rc={rc} {str(ap_r)[:150]}")
    final = wait_terminal(aud, req_id)
    expect(final is not None and final["status"] == "executed",
           "M3 自动执行终态 executed（FZC2 出函+解锁链上留痕）", str(final)[:200])
    rc, ap2 = p(adm, f"/admin/collab-requests/{req_id}/approve", {"sig_hex": sign(adm.sk, req_msg)})
    expect(rc == 409, "N4 幂等重放：重复批准 → 409（状态仲裁）", f"rc={rc}")

    rc, vs = g(aud, f"/audit/collab-requests/{req_id}/verify-sigs")
    vd = vs.get("data") or {}
    expect(vd.get("auditor", {}).get("ok") is True and vd.get("admin", {}).get("ok") is True
           and (vd.get("admin", {}).get("epoch") or 0) >= 1,
           "A6 verify-sigs 复验：双签双过+纪元可回取（公钥纪元史消费面）", str(vs)[:200])

    # ---- trace 全字段断言（结案前 closure=None）----
    _, tr = g(aud, f"/audit/warrants/{wh}/trace")
    td = tr.get("data") or {}
    ct = td.get("chain_trace") or {}
    expect((td.get("warrant") or {}).get("unlocked", {}).get("username") == pilot_user,
           "A7 trace 实名解锁面=登记人")
    ar = ct.get("auth_record") or {}
    expect(ar.get("token_hash") == sm3_hex(mats1["body"]) and int(ar.get("status", -1)) == 0
           and ar.get("nonce") == json.loads(mats1["body"])["nonce"],
           "A7b trace 链上授权原文回读（tokenHash/nonce/status=0）", str(ar)[:150])
    expect(len(ct.get("checkpoints") or []) >= 1, "A7c trace 检查点留痕 ≥1")
    dc = ct.get("device_check") or {}
    expect(dc.get("verdict") == "match" and dc.get("checked", 0) >= 1
           and dc.get("mismatch") == 0,
           "A7d 设备一致性判词 match（登记 SN₁ 派生钥=检查点签名钥）", str(dc)[:150])
    expect(len(ct.get("events") or []) >= 1, "A7e trace 链上事件时间线 ≥1（围栏违规取证）")
    expect(td.get("closure", "missing") is None, "A7f 未结案 closure=None（诚实缺省）")
    expect(td.get("mode") == "real", "A7g trace 档位显式 mode=real")

    # ---- 结案（含负例）----
    _, frv = g(aud, "/audit/collab-requests")
    req_row = next(x for x in frv["data"]["items"] if x["id"] == req_id)
    req_hash_hex = req_row["req_hash_hex"]
    close_text = "属实：围栏违规取证与链上授权一致，解锁实名与登记吻合（workflows 实弹）"
    rc, nc = p(aud, f"/audit/collab-requests/{req_id}/close",
               {"conclusion": "", "conclusion_text": close_text, "sig_hex": "00" * 64})
    expect(rc == 422, "N5 负例：结案缺结论 → 422", f"rc={rc} {str(nc)[:100]}")
    bad_close = {"conclusion": "verified", "conclusion_text": close_text,
                 "sig_hex": sign(aud.sk, "FZ-COLLAB-CLOSE|v1|tampered")}
    rc, bs = p(aud, f"/audit/collab-requests/{req_id}/close", bad_close)
    expect(rc == 401 and bs.get("code") == "bad_sig", "N6 负例：结案坏签名 → 401",
           f"rc={rc} {str(bs)[:100]}")
    good_close = {"conclusion": "verified", "conclusion_text": close_text,
                  "sig_hex": sign(aud.sk, f"FZ-COLLAB-CLOSE|v1|{req_hash_hex}|verified|{close_text}")}
    rc, cl = p(aud, f"/audit/collab-requests/{req_id}/close", good_close)
    expect(rc == 200 and len(cl.get("data", {}).get("case_archive_fp_hex") or "") == 64
           and cl["data"].get("closed_ts"),
           "A8 结案 verified（结论+说明+签名）→ 案卷指纹+时间戳", f"rc={rc} {str(cl)[:200]}")
    archive_fp = cl["data"]["case_archive_fp_hex"]
    rc, cl2 = p(aud, f"/audit/collab-requests/{req_id}/close", good_close)
    expect(rc == 409, "N7 幂等重放：重复结案 → 409", f"rc={rc}")
    _, tr = g(aud, f"/audit/warrants/{wh}/trace")
    clo = (tr.get("data") or {}).get("closure") or {}
    expect(clo.get("conclusion") == "verified" and clo.get("case_archive_fp_hex") == archive_fp
           and clo.get("auditor_username") == "auditor"
           and clo.get("admin_username") == "admin"
           and clo.get("fzc2_fingerprint_hex"),
           "A9 trace.closure 全字段（结论/案卷指纹/双控/函指纹）", str(clo)[:200])

    # ---- 处置待办 ----
    todo = None
    t0 = time.time()
    while time.time() - t0 < 20:
        _, tj = g(adm, "/admin/disposal-todos")
        todo = next((x for x in (tj.get("data") or {}).get("items", [])
                     if x["case_no"] == case_no), None)
        if todo:
            break
        time.sleep(2)
    expect(todo is not None and todo["status"] == "pending"
           and todo["username"] == pilot_user and todo["conclusion"] == "verified",
           "M4 处置待办卡：结案属实自动建单（案号+实名+判词）", str(todo)[:200])
    rc, rs = p(adm, f"/admin/disposal-todos/{todo['id']}/resolve",
               {"note": "已按判词执行凭证吊销处置（workflows 实弹）"})
    expect(rc == 200 and rs["data"]["status"] == "done", "M5 处置 resolve → done（留痕入库）")
    rc, rs2 = p(adm, f"/admin/disposal-todos/{todo['id']}/resolve", {"note": "x"})
    expect(rc == 409 and rs2.get("code") == "already_resolved", "N8 幂等重放：重复处置 → 409",
           f"rc={rc} {str(rs2)[:100]}")

    # ---- 撤销（两步式签名契约）----
    rc, r0 = p(adm, "/ra/revoke/by-username", {"username": pilot_user,
                                               "reason": "workflows 撤销负例（无签名）",
                                               "sig_hex": "", "epoch": 0})
    expect(rc in (400, 401) and r0.get("code") in ("bad_sig", "bad_epoch", "reason_required"),
           "N9 负例：撤销缺签名 → 拒（bad_sig/bad_epoch）", f"rc={rc} {str(r0)[:120]}")
    _, pv = g(adm, f"/ra/revoke/by-username/preview?username={pilot_user}")
    pvd = pv.get("data") or {}
    expect(pvd.get("handles") and pvd.get("epoch", 0) >= 1,
           "M6 撤销预览：句柄集+目标纪元（公示纪元+1）", str(pvd)[:150])
    reason = "审计结案属实——依终局判词吊销该当事人全部有效凭证"
    msg = "FZ-REVOKE|v1|" + "|".join(sorted(h.lower() for h in pvd["handles"])) + f"|{reason}|{pvd['epoch']}"
    rc, rv = p(adm, "/ra/revoke/by-username", {"username": pilot_user, "reason": reason,
                                               "sig_hex": sign(adm.sk, msg), "epoch": pvd["epoch"]})
    rvd = rv.get("data") or {}
    expect(rc == 200 and aid1 in (rvd.get("linked_auth_ids") or []) and rvd.get("ledger_id", 0) > 0,
           "M7 签名撤销 → linked_auth_ids 联动授权轴（非空+auth1 在列）+台账行 id",
           f"rc={rc} {str(rv)[:250]}")
    if REAL_CHAIN:
        from app.chain.client import ChainClient
        from app.chain.contracts import load_binding
        from app.chain.signer import TxSigner

        from app.kms import chain_ra_tx_key

        addr = json.loads((BACKEND.parent / "contracts" / ".chain_addresses.json").read_text())
        client = ChainClient(rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
                             from_addr=TxSigner(chain_ra_tx_key()).address)
        ir = load_binding("IdentityRegistry", client, addr["IdentityRegistry"]["address"])
        expect(int(ir.call_fn("revEpoch", [])[0]) == rvd["epoch"],
               "M7b 链上 revEpoch=回执纪元（撤销公示上链）")
    _, snap1 = g(anon(), "/ra/revocation/snapshot")
    leaf = next((x for x in snap1["data"]["revoked"]
                 if x["handle_hex"] == cred["master_cred_hash_hex"]), None)
    expect(leaf is not None and leaf.get("reason") == reason
           and leaf.get("revoked_by") == "admin" and leaf.get("epoch") == rvd["epoch"],
           "M8 公示镜像：撤销理由/执行人/纪元逐字在列（公示理由字段面）", str(leaf)[:200])
    expect(snap1["data"]["root_hex"] != snap0["data"]["root_hex"], "M8b 撤销纪元根更迭")

    # ---- 被吊销后申请的人话报错 ----
    rc, wj = g(anon(), f"/ra/revocation/witness?holder_pk_hex={sub_pk3.lower()}")
    expect(rc == 403 and wj.get("code") == "revoked" and "撤销" in (wj.get("message") or ""),
           "P14 被吊销者取见证 → 403 revoked（fail-fast 人话判词）",
           f"rc={rc} {str(wj)[:150]}")
    rc, sj = p(anon(), "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": id_number, "cert_level": 3, "sn": SN, "holder_pub_hex": sub_pk3})
    expect(rc == 403 and sj.get("code") == "cred_revoked",
           "P15 被吊销者签子凭证 → 403 cred_revoked（拒新签发人话判词）",
           f"rc={rc} {str(sj)[:150]}")

    # ---- 恢复双控（单签不执行→countersign 执行）----
    handle = cred["master_cred_hash_hex"]
    rreason = "误报复核改判——恢复该凭证（workflows 恢复双控实弹）"
    rc, rr = p(adm, "/ra/restore/request", {
        "handle_hex": handle, "reason": rreason,
        "sig_hex": sign(adm.sk, f"FZ-RESTORE|v1|{handle.lower()}|{rreason}")})
    expect(rc == 200 and rr["data"]["status"] == "pending", "M9 恢复发起（admin 第一签）→ pending",
           f"rc={rc} {str(rr)[:150]}")
    restore_id = rr["data"]["id"]
    _, snap_mid = g(anon(), "/ra/revocation/snapshot")
    expect(any(x["handle_hex"] == handle for x in snap_mid["data"]["revoked"]),
           "N10 恢复单签不执行：公示撤销集不变（pending 挂起）")
    rc, rlist = g(aud, "/ra/restore/requests")
    row = next((x for x in rlist["data"]["items"] if x["id"] == restore_id), None)
    expect(row is not None and row["requested_by"] == "admin" and row["reason"] == rreason,
           "A10 恢复核验面：待复核列表可见（句柄/理由/发起人）", str(row)[:150])
    rc, cs = p(aud, f"/ra/restore/{restore_id}/countersign", {
        "sig_hex": sign(aud.sk, f"FZ-RESTORE-COUNTERSIGN|v1|{handle.lower()}|{rreason}")})
    expect(rc == 200 and cs["data"]["status"] == "executed"
           and cs["data"]["countersign_by"] == "auditor",
           "A11 恢复核签（auditor 第二签）→ executed", f"rc={rc} {str(cs)[:150]}")
    _, snap2 = g(anon(), "/ra/revocation/snapshot")
    expect(not any(x["handle_hex"] == handle for x in snap2["data"]["revoked"]),
           "A11b 恢复生效：句柄摘出公示撤销集（SMT 摘叶）")
    expect(int(snap2["data"]["epoch"]) > int(snap1["data"]["epoch"]),
           "A11c 恢复推链：公示纪元仍单调（摘叶不落叶行）")

    # ---- 台账行断言 ----
    rc, ov = g(adm, "/admin/overview")
    od = ov.get("data") or {}
    expect(any(x["warrant_hash_hex"] == wh for x in od.get("collab_ledger", [])),
           "M10 出函台账行：FZC2 指纹随令状在案（机构本职可视面）")
    expect(any(x["case_no"] == case_no for x in od.get("warrants", [])),
           "M10b 机构台令状台账含本案（unlocked 布尔权威面）")

    print(f"\n== 三角色全流程接口级 e2e 全绿：{_checks} 项断言 [OK]（{time.time() - t_all:.0f}s）==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
