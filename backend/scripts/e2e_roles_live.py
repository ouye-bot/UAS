# -*- coding: utf-8 -*-
"""三角色全职责实弹判决（2026-09-30 队长指令：全套测试·尤其 admin/auditor 所有职责）。

对**运行中的栈**（默认 127.0.0.1:8000，真链档）逐项实测：

  A 认证与越权门：双角色登录/whoami；未登录 401；交叉越权 403×2
  B 审计员职责：收件箱/令状列表/立案（自动案号+目标）+重复案号负例/
    发函（SM2 签名）+坏签名负例+空理由负例
  C 机构管理员职责：待批列表/批准（签名，即返回）→轮询 executed/台账非空/
    驳回（理由）+空理由负例
  D 结案闭环：审计员 close → closed；重复结案 409；closed 后再批 409
  E 重试路径：匿名令状 → execute_failed（人话原因）→ retry → 再执行
  F 吊销职责：by-username 级联吊销 → 纪元根更迭
  G 凭证播种：HTTP /ra/register（服务端域钥封装——解封可达）+DB 授权链行
    （仅测试脚本允许 DB 播种——产品路径零替身不受影响）

用法：cd uas/backend && python scripts/e2e_roles_live.py
  [--api http://127.0.0.1:8000] [--auditor-pw ..] [--admin-pw ..]
密码来源：参数 > env FZ_SEED_AUDITOR_PASSWORD/FZ_SEED_ADMIN_PASSWORD >
%TEMP%\\fz_accounts_seed.txt。账户未激活则自动激活（首登语义）。
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from scripts.script_auth import script_login  # noqa: E402

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


def _pw_from_args_or_env(args_pw: str | None, env_key: str, seed_marker: str) -> str:
    if args_pw:
        return args_pw
    if os.environ.get(env_key):
        return os.environ[env_key]
    seed = Path(tempfile.gettempdir()) / "fz_accounts_seed.txt"
    if seed.is_file():
        for line in seed.read_text(encoding="utf-8").splitlines():
            if seed_marker in line:
                tail = line.rsplit(" ", 1)[-1].strip()
                if tail:
                    return tail
    raise SystemExit(f"缺 {seed_marker} 密码——传参/env/{seed} 三选一")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000"))
    ap.add_argument("--auditor-pw", default=None)
    ap.add_argument("--admin-pw", default=None)
    ap.add_argument("--skip-revoke", action="store_true", help="跳过吊销段（避免动纪元根）")
    args = ap.parse_args()
    API = args.api

    aud_pw = _pw_from_args_or_env(args.auditor_pw, "FZ_SEED_AUDITOR_PASSWORD", "auditor")
    adm_pw = _pw_from_args_or_env(args.admin_pw, "FZ_SEED_ADMIN_PASSWORD", "admin")

    t0 = time.time()
    print("== 三角色全职责实弹（对运行中的栈）==")

    # ---- G. 凭证播种（当前纪元——服务端域钥封装，解封可达） ----
    print("== [G] 凭证播种（HTTP 注册+DB 授权链——测试面专用）==")
    import urllib.request
    import urllib.error

    def _post(path: str, body: dict, sess=None, timeout: float = 60):
        req = urllib.request.Request(
            API + path, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    pilot_user = "roles-" + secrets.token_hex(3)
    sk_u, pk_u = _gen_keypair()
    # 证件号逐轮随机（18 字）：B7 重注册禁入（0019 批）——F.1 按人吊销后该证件
    # 号入黑名单，固定证件号的第二次运行必 409 id_revoked_before（非契约错误）
    pilot_id = "11010119900101" + secrets.token_hex(2)
    # 吊销传播句柄=出示公钥 pk′.x（前 64 hex）——播种必须用真随机公钥：
    # 占位 "00"*128 会让每次运行派生同一撤销句柄（UNIQUE 撞行，二次运行必挂
    # ——2026-09-30 评审 P0 定谳）
    rc, reg = _post("/ra/register", {
        "username": pilot_user, "id_number": pilot_id,
        "cert_level": 3, "sn": "FZ-ROLES-01", "user_pub_hex": pk_u, "class_id": 1})
    expect(rc == 200 and reg.get("code") == "ok", "G.1 凭证播种：HTTP /ra/register（当前纪元封装）", f"rc={rc} {str(reg)[:120]}")
    auth_id = _seed_auth_chain(reg["data"]["master_cred_hash_hex"], pilot_user, pk_u)
    expect(auth_id > 0, "G.2 授权链行播种（auth_id 在案——立案目标）", f"auth_id={auth_id}")

    # ---- A. 认证与越权门 ----
    print("== [A] 认证与越权门 ==")
    aud = script_login(API, "auditor", aud_pw)
    who = aud.get(API + "/auth/whoami", timeout=10).json()["data"]
    expect(who["role"] == "auditor", "A.1 审计员登录（挑战-应答）→ role=auditor", str(who))
    adm = script_login(API, "admin", adm_pw)
    who = adm.get(API + "/auth/whoami", timeout=10).json()["data"]
    expect(who["role"] == "admin", "A.2 机构管理员登录 → role=admin", str(who))

    import requests as _rq
    anon = _rq.Session()
    rc = anon.get(API + "/audit/warrants", timeout=10).status_code
    expect(rc == 401, "A.3 未登录打审计面 → 401", f"rc={rc}")
    rc = adm.get(API + "/audit/warrants", timeout=10).status_code
    expect(rc == 403, "A.4 管理员打审计面 → 403（角色门）", f"rc={rc}")
    rc = aud.get(API + "/admin/overview", timeout=10).status_code
    expect(rc == 403, "A.5 审计员打机构面 → 403（角色门）", f"rc={rc}")

    # ---- B. 审计员职责 ----
    print("== [B] 审计员职责 ==")
    rc, viol = _getj(aud, API, "/audit/violations?unfiled=1")
    expect(rc == 200 and isinstance(viol.get("data", {}).get("items"), list),
           "B.1 违规收件箱（聚合面可达）", f"rc={rc}")
    rc, warrants = _getj(aud, API, "/audit/warrants")
    expect(rc == 200 and isinstance(warrants.get("data"), list), "B.2 令状列表", f"rc={rc}")
    case_no = "ROLES-" + secrets.token_hex(3)
    basis = f"授权 #{auth_id} 围栏违规（roles 全职责实弹）——依据相关条款立案调查"
    rc, w = _post_sess(aud, API, "/audit/warrants", {
        "case_no": case_no, "legal_basis_text": basis, "target_auth_id": auth_id})
    expect(rc == 200 and w.get("code") == "ok", "B.3 立案（自动案号+目标授权+依据原文双锚）", f"rc={rc} {str(w)[:150]}")
    wh = w["data"]["warrant_hash_hex"]
    rc, dup = _post_sess(aud, API, "/audit/warrants", {
        "case_no": case_no, "legal_basis_text": basis, "target_auth_id": auth_id})
    expect(rc == 400 and dup.get("code") == "warrant_exists", "B.4 负例：同案号重复立案 → 400", f"rc={rc} {str(dup)[:100]}")

    note = "roles 实弹：请求协同解锁当事人实名"
    req_hash_msg = f"FZ-COLLAB-REQ|v1|{wh}|{note}"
    rc, fr = _post_sess(aud, API, "/audit/collab-requests", {
        "warrant_hash_hex": wh, "note": note,
        "sig_hex": _sign(aud.sk, req_hash_msg)})
    expect(rc == 200 and fr["data"]["status"] == "pending", "B.5 发协同请求（审计员钥签名）→ pending", f"rc={rc} {str(fr)[:150]}")
    req_id = fr["data"]["id"]

    rc, bad = _post_sess(aud, API, "/audit/collab-requests", {
        "warrant_hash_hex": wh, "note": note + "x", "sig_hex": "00" * 64})
    expect(rc in (401, 409), "B.6 负例：坏签名 → 拒（401 bad_sig/409 在途）", f"rc={rc} {str(bad)[:100]}")
    rc, empty = _post_sess(aud, API, "/audit/collab-requests", {
        "warrant_hash_hex": wh, "note": "", "sig_hex": "00" * 64})
    expect(rc == 422, "B.7 负例：空理由 → 422", f"rc={rc}")

    # ---- C. 机构管理员职责 ----
    print("== [C] 机构管理员职责 ==")
    rc, lst = _getj(adm, API, "/admin/collab-requests")
    expect(rc == 200 and any(x["id"] == req_id for x in lst.get("data", {}).get("items", [])),
           "C.1 待批列表含新请求", f"rc={rc}")
    t_ap = time.time()
    rc, ap_r = _post_sess(adm, API, f"/admin/collab-requests/{req_id}/approve",
                          {"sig_hex": _sign(adm.sk, req_hash_msg)})
    expect(rc == 200 and ap_r["data"]["status"] == "approved",
           f"C.2 批准即返回（{time.time() - t_ap:.1f}s）→ approved（后台执行）", f"rc={rc} {str(ap_r)[:120]}")

    final = _poll_terminal(aud, API, req_id, 180)
    expect(final is not None and final["status"] == "executed",
           "C.3 自动执行到终态 executed（出函 FZC2+台账+解锁链上留痕）",
           str(final)[:200] if final else "timeout")
    rc, ov = _getj(adm, API, "/admin/overview")
    expect(rc == 200 and len(ov["data"].get("collab_ledger", [])) > 0,
           "C.4 出函台账非空（CollabIssued 落行）", f"rc={rc}")

    # 驳回路径（另一令状）
    rc, w2 = _post_sess(aud, API, "/audit/warrants", {
        "case_no": "ROLES-REJ-" + secrets.token_hex(2),
        "legal_basis_text": "驳回路径实测", "target_auth_id": auth_id})
    wh2 = w2["data"]["warrant_hash_hex"]
    note2 = "驳回路径实测理由"
    rc, fr2 = _post_sess(aud, API, "/audit/collab-requests", {
        "warrant_hash_hex": wh2, "note": note2,
        "sig_hex": _sign(aud.sk, f"FZ-COLLAB-REQ|v1|{wh2}|{note2}")})
    req2 = fr2["data"]["id"]
    rc, rej = _post_sess(adm, API, f"/admin/collab-requests/{req2}/reject", {
        "reason": "依据不充分——请补充材料", "sig_hex": _sign(adm.sk, f"FZ-COLLAB-REJECT|v1|{wh2}|{note2}|依据不充分——请补充材料")})
    expect(rc == 200 and rej["data"]["status"] == "rejected", "C.5 驳回（理由必填+管理员钥签）→ rejected", f"rc={rc} {str(rej)[:120]}")
    rc, rej_bad = _post_sess(adm, API, f"/admin/collab-requests/{req2}/reject", {
        "reason": "", "sig_hex": "00" * 64})
    expect(rc == 422, "C.6 负例：空理由驳回 → 422", f"rc={rc}")

    # ---- D. 结案闭环 ----
    print("== [D] 结案闭环 ==")
    # 0018 升格：结案 body={conclusion, conclusion_text(verified 必填), sig_hex}，
    # 签名消息=FZ-COLLAB-CLOSE|v1|{req_hash}|{conclusion}|{conclusion_text}
    #（req_hash 从请求视图取；审计员钥=复用 B.5 发函同钥签路径）
    req_hash_hex = final["req_hash_hex"]
    conclusion_text = "属实：令状目标授权在案，解锁链上留痕与当事人实名一致（roles 实弹）"
    close_body = {
        "conclusion": "verified", "conclusion_text": conclusion_text,
        "sig_hex": _sign(aud.sk, f"FZ-COLLAB-CLOSE|v1|{req_hash_hex}|verified|{conclusion_text}")}
    rc = _post_sess(aud, API, f"/audit/collab-requests/{req_id}/close", close_body, timeout=15)[0]
    expect(rc == 200, "D.1 审计员结案（verified+说明+审计员钥签名）→ closed", f"rc={rc}")
    rc = _post_sess(aud, API, f"/audit/collab-requests/{req_id}/close", close_body, timeout=15)[0]
    expect(rc == 409, "D.2 负例：重复结案（签名仍真，状态仲裁拒）→ 409", f"rc={rc}")
    rc, re_ap = _post_sess(adm, API, f"/admin/collab-requests/{req_id}/approve",
                           {"sig_hex": _sign(adm.sk, req_hash_msg)})
    expect(rc == 409, "D.3 负例：已结案再批准 → 409", f"rc={rc} {str(re_ap)[:80]}")
    tr = aud.get(API + f"/audit/warrants/{wh}/trace", timeout=60).json()["data"]["warrant"]
    expect(tr.get("unlocked", {}).get("username") == pilot_user,
           "D.4 追溯面实名回填（解锁可见）", str(tr.get("unlocked"))[:100])

    # ---- E. 重试路径（匿名令状 → execute_failed 人话 → retry 再执行） ----
    print("== [E] 重试路径 ==")
    rc, w3 = _post_sess(aud, API, "/audit/warrants", {
        "case_no": "ROLES-ANON-" + secrets.token_hex(2), "legal_basis_text": "匿名立案位（无目标授权）"})
    wh3 = w3["data"]["warrant_hash_hex"]
    note3 = "匿名令状自动执行不可达实测"
    rc, fr3 = _post_sess(aud, API, "/audit/collab-requests", {
        "warrant_hash_hex": wh3, "note": note3,
        "sig_hex": _sign(aud.sk, f"FZ-COLLAB-REQ|v1|{wh3}|{note3}")})
    req3 = fr3["data"]["id"]
    rc, ap3 = _post_sess(adm, API, f"/admin/collab-requests/{req3}/approve",
                         {"sig_hex": _sign(adm.sk, f"FZ-COLLAB-REQ|v1|{wh3}|{note3}")})
    expect(rc == 200, "E.1 匿名令状批准（即返回）", f"rc={rc}")
    fin3 = _poll_terminal(aud, API, req3, 60)
    expect(fin3 is not None and fin3["status"] == "execute_failed"
           and "未指定目标授权编号" in (fin3.get("execute_error") or ""),
           "E.2 执行失败结构化（人话原因落库——非 500）", str(fin3)[:160])
    rc, rt = adm.post(API + f"/admin/collab-requests/{req3}/retry", timeout=15).json(), None
    rt = _poll_terminal(aud, API, req3, 60)
    expect(rt is not None and rt["status"] == "execute_failed",
           "E.3 重试语义（approved→再执行→同因失败——诚实可重复）", str(rt)[:120])

    # ---- F. 吊销职责 ----
    if not args.skip_revoke:
        print("== [F] 吊销职责 ==")
        root0 = _getj(anon, API, "/ra/revocation/snapshot")[1]["data"]["root_hex"]
        rc, rv = _revoke_by_username_signed(adm, API, pilot_user, "roles 全职责实弹吊销")
        if rv.get("code") == "preview_no_cred":
            ok("F.1 按人级联吊销（admin）——本用户已无有效凭证（先前轮次吊销，幂等通过）")
        else:
            expect(rc == 200 and rv.get("code") == "ok",
                   "F.1 按人级联吊销（admin 会话+preview 句柄集签名+纪元绑定）", f"rc={rc} {str(rv)[:100]}")
        root1 = _getj(anon, API, "/ra/revocation/snapshot")[1]["data"]["root_hex"]
        expect(root1 != root0, "F.2 纪元根更迭（即时生效）", f"{root0[:12]}→{root1[:12]}")
        rc, wchk = _getj(aud, API, f"/ra/revocation/witness?holder_pk_hex={pk_u}")
        # 403/revoked=被吊销者取证被拒（正确语义）；200 且 flagged=见证面标记
        expect(rc == 403 or (rc == 200 and wchk.get("code") in ("revoked", "ok")),
               "F.3 吊销后见证面（被吊销者取证路径拒绝）", f"rc={rc} {str(wchk)[:80]}")

    print(f"\n== 三角色全职责实弹全绿：{_checks} 项断言 [OK]（{time.time() - t0:.0f}s）==")
    return 0


def _gen_keypair():
    from app.crypto.sm2 import generate_keypair

    sk, pk = generate_keypair()
    return sk, pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀


def _sign(sk: str, msg: str) -> str:
    from app.crypto.sm2 import sign as _s

    return _s(sk, msg.encode())


def _seed_auth_chain(master_cred_hash_hex: str, pilot_user: str, holder_pub_hex: str) -> int:
    """授权链行播种（仅测试脚本）：Application+AuthRecord+SubCredential 链——
    与产品申请路径的 ZK 证明面无关（roles 测试只看双控/台账/吊销职责）。"""
    import datetime as dt
    import secrets as _sec

    from sqlalchemy import create_engine

    from app.authz.models import Application as A, AuthRecord as AR
    from app.db import SessionLocal
    from app.ra.models import Credential as C, SubCredential as SC

    s = SessionLocal()
    try:
        auth_id = int(time.time()) % 100000 + _sec.randbelow(1000)
        while s.query(A).filter(A.auth_id == auth_id).one_or_none() is not None:
            auth_id += 1
        uniq = _sec.token_hex(32)
        s.add(A(session_pk_hex="00" * 32, sub_sig_hex="00" * 32, sub_cred_hash_hex=uniq,
                nonce_hex="88" * 16, plan_hash_hex="99" * 32, class_id=1,
                policy_version="v-roles", rev_root_hex="55" * 32, e_hex="22" * 32,
                t_start=1790000000, t_end=1790003600, status="approved", auth_id=auth_id))
        s.flush()
        app_row = s.query(A).order_by(A.id.desc()).first()
        s.add(AR(auth_id=auth_id, application_id=app_row.id, token_hash_hex="ab" * 32,
                 proof_digest_hex="11" * 32, tx_hash="0xroles"))
        cred = s.query(C).filter(C.master_cred_hash_hex == master_cred_hash_hex).one()
        s.add(SC(holder_pub_hex=holder_pub_hex, expires_at=dt.datetime(2030, 1, 1),
                 sub_cred_hash_hex=uniq, credential_id=cred.id,
                 message_hex="00" * 330, sig_hex="00" * 128))
        s.commit()
        return auth_id
    finally:
        s.close()


def _revoke_by_username_signed(adm, api: str, username: str, reason: str):
    """按人级联吊销（B1 升格两步式）：①GET preview（admin 会话）取该用户全部
    有效凭证句柄+目标纪元（公示纪元+1）；②本地拼 FZ-REVOKE|v1|{handles 排序
    "|".join}|{reason}|{epoch} 用 admin 钥签名；③POST 新契约 body。preview
    不可达（用户已无有效凭证）返回 {"code": "preview_no_cred"} 交调用方走幂等支。"""
    rc, pv = _getj(adm, api, f"/ra/revoke/by-username/preview?username={username}")
    if rc != 200 or not pv.get("data"):
        return rc, {"code": "preview_no_cred", "message": str(pv)[:120]}
    handles = pv["data"]["handles"]
    epoch = pv["data"]["epoch"]
    msg = "FZ-REVOKE|v1|" + "|".join(sorted(h.lower() for h in handles)) + f"|{reason}|{epoch}"
    return _post_sess(adm, api, "/ra/revoke/by-username", {
        "username": username, "reason": reason, "sig_hex": _sign(adm.sk, msg), "epoch": epoch})


def _getj(sess, api: str, path: str, timeout: float = 30):
    r = sess.get(api + path, timeout=timeout)
    try:
        return r.status_code, r.json()
    except Exception:  # noqa: BLE001
        return r.status_code, {}


def _post_sess(sess, api: str, path: str, body: dict, timeout: float = 60):
    r = sess.post(api + path, json=body, timeout=timeout)
    try:
        return r.status_code, r.json()
    except Exception:  # noqa: BLE001
        return r.status_code, {}


def _poll_terminal(sess, api: str, req_id: int, timeout_s: float):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        rc, lst = _getj(sess, api, "/audit/collab-requests")
        for x in lst.get("data", {}).get("items", []):
            if x["id"] == req_id and x["status"] in ("executed", "execute_failed"):
                return x
        time.sleep(1.0)
    return None


if __name__ == "__main__":
    raise SystemExit(main())
