"""⑥站跨域演示 e2e（多机构一期——真链档，电路零改动口径）。

  [X1] org-b 机构管理员（seed 预置 admin-b）激活登录 → whoami.org_id=org-b
       （机构域账户读回面）
  [X2] org-b 用户：pilot 自注册 → /auth/profile org_id="org-b"（受理机构域
       选择——users.org_id=org-b）
  [X3] 跨域出证：org-b 用户在系统受理面走完整 绑定→桥真出证→受理→取件
       （一期电路 pk_RA 单钥——受理面即缺省机构域(org-a)运营面，跨域语义=
       同一受理面认 B 域用户）
  [X4] org-b 管理员签名吊销该用户（preview→FZ-REVOKE 签名→by-username）
  [X5] 链面归因断言：IdentityRegistry revEpoch=回执纪元；FedRegistry org-b
       锚 epoch=同值+root==共享树根；org-a 锚**未动**（吊销归因 org-b）；
       全局聚合根更迭（SM3 同构离线重算对拍）
  [Z]  即时生效：被吊销者取见证=403 revoked、重签子凭证=403 cred_revoked
       （本域吊销直接进本域树=共享树——任何域受理面即时生效）
  [X6] 治理大屏互认面：/chain/governance federation.orgs 含 org-b（锚推进在列）
  [N]  负例：未登记机构域（org-z）注册 → 4xx unknown_org（fail-closed）

用法：cd uas/backend && python scripts/e2e_cross_org.py
前置：backend(8000)+bridge(8100)+worker 在线；真链档；FedRegistry 已登记
org-a/org-b（chain_smoke --deploy §⑨ 治理仪式完成）；org-b 种子账户在案
（seed_accounts org-b demo 种子：admin-b/auditor-b）。
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import e2e_workflows as wf  # noqa: E402  复用出证/断言助手（单一事实源）
import requests  # noqa: E402
from e2e_workflows import (  # noqa: E402
    API,
    SN,
    anon,
    expect,
    full_authorization,
    g,
    gen_keypair,
    p,
    seal_profile_slot,
)
from script_auth import script_login  # noqa: E402

_checks = 0


def _oid(s: str) -> bytes:
    return s.encode().ljust(32, b"\x00")


def _fed_chain():
    """FedRegistry+IdentityRegistry 只读 binding（真链档专用）。"""
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_ra_tx_key

    addr = json.loads((BACKEND.parent / "contracts" / ".chain_addresses.json").read_text())
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=TxSigner(chain_ra_tx_key()).address,
    )
    fed = load_binding("FedRegistry", client, addr["FedRegistry"]["address"])
    ir = load_binding("IdentityRegistry", client, addr["IdentityRegistry"]["address"])
    return fed, ir


def _pw(marker: str) -> str:
    seed = Path(tempfile.gettempdir()) / "fz_accounts_seed.txt"
    for line in seed.read_text(encoding="utf-8").splitlines():
        if marker in line:
            tail = line.rsplit(" ", 1)[-1].strip()
            if tail:
                return tail
    raise SystemExit(f"缺 {marker} 口令（seed 文件无该行——先跑 seed_accounts org-b 种子）")


def main() -> int:
    t0 = time.time()
    print("== ⑥站跨域演示 e2e（多机构一期：互认注册表+全局撤销树聚合）==")
    r = requests.get(f"{API}/healthz", timeout=10).json()
    expect(r.get("status") == "ok", "X0 backend 健康")
    pub = wf.bget("/engine_pub")
    expect(bool(pub.get("engine_pub_hex")), "X0 桥在线（engine_pub 面在场）")
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
        raise SystemExit("[FAIL] 跨域演示须真链档（FZ_CHAIN_ANCHOR=real）")
    fed, ir = _fed_chain()
    expect(
        int(fed.call_fn("orgs", [_oid("org-b")])[0]) == 1,
        "X0 FedRegistry org-b 已登记（chain_smoke §⑨ 治理仪式前置）",
    )

    # ============ [X1] org-b 机构管理员域 ============
    print("== [X1] org-b 机构域账户 ==")
    adm_b = script_login(API, "admin-b", _pw("admin-b"))
    who = adm_b.get(f"{API}/auth/whoami", timeout=10).json()["data"]
    expect(who["role"] == "admin" and who.get("org_id") == "org-b",
           "X1 org-b 管理员激活登录+whoami.org_id=org-b（机构域键读回）", str(who))
    aud_b = script_login(API, "auditor-b", _pw("auditor-b"))
    who_a = aud_b.get(f"{API}/auth/whoami", timeout=10).json()["data"]
    expect(who_a.get("org_id") == "org-b", "X1b org-b 审计员域=org-b", str(who_a))

    # ============ [X2/X3] org-b 用户跨域出证 ============
    print("== [X2/X3] org-b 用户注册+跨域出证 ==")
    buser = "xorg-" + secrets.token_hex(3)
    bpassword = secrets.token_urlsafe(12)
    bid_number = "11010119920303" + secrets.token_hex(2)
    bpil = script_login(API, buser, bpassword)
    form = {"id_number": bid_number, "cert_level": 3, "sn": SN, "class_id": 1}
    rc, prof = p(bpil, "/auth/profile", {**form, "org_id": "org-b"})
    expect(rc == 200 and "master_cred_hash_hex" in prof.get("data", {}),
           "X2 org-b 用户登记（受理机构域=org-b——users.org_id 域键）",
           f"rc={rc} {str(prof)[:150]}")
    cred = prof["data"]
    p(bpil, "/auth/profile/keep", {"sealed_profile": seal_profile_slot(
        {"cred": cred, "form": form}, bpassword)})
    sub_sk, sub_pk = gen_keypair()
    rc, sj = p(anon(), "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"],
        "salt_hex": cred["salt_hex"], "id_number": bid_number,
        "cert_level": 3, "sn": SN, "holder_pub_hex": sub_pk})
    expect(
        rc == 200 and sj.get("code") == "ok",
        "X3 org-b 用户子凭证签发",
        f"rc={rc} {str(sj)[:120]}",
    )
    sub1 = sj["data"]
    tok, mats = full_authorization(bpil, sub_sk, sub_pk, cred, sub1, bid_number,
                                   "X3 跨域出证（B 域用户@受理面）", sorties=1, win_s=3600)
    expect(tok["authId"] > 0, "X3 跨域出证完成（B 域用户令牌贯穿——受理面认 B 域用户）")
    # 第二子凭证（未消费——吊销传播面 R3-0.3：未消费子凭证 pk′.x 并入撤销集）
    z_sk, z_pk = gen_keypair()
    rc, sj_z = p(anon(), "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"],
        "salt_hex": cred["salt_hex"], "id_number": bid_number,
        "cert_level": 3, "sn": SN, "holder_pub_hex": z_pk})
    expect(
        rc == 200 and sj_z.get("code") == "ok",
        "X3b 第二子凭证（未消费——撤销传播面载体）",
        f"rc={rc} {str(sj_z)[:120]}",
    )

    # ============ [X4/X5] org-b 管理员吊销+链面归因 ============
    print("== [X4/X5] org-b 吊销+归因断言 ==")
    fed, ir = _fed_chain()
    pre = {
        "org_a": fed.call_fn("revAnchors", [_oid("org-a")]),
        "org_b": fed.call_fn("revAnchors", [_oid("org-b")]),
        "global_root": bytes(fed.call_fn("globalRevRoot", [])[0]).hex(),
        "global_epoch": int(fed.call_fn("globalRevEpoch", [])[0]),
    }
    _, pv = g(adm_b, f"/ra/revoke/by-username/preview?username={buser}")
    pvd = pv.get("data") or {}
    expect(pvd.get("handles") and pvd.get("epoch", 0) >= 1,
           "X4 org-b 管理员撤销预览（句柄集+目标纪元）", str(pvd)[:150])
    reason = "跨域演示：B 机构依本域判词吊销当事人全部有效凭证"
    handles_sorted = "|".join(sorted(h.lower() for h in pvd["handles"]))
    msg = f"FZ-REVOKE|v1|{handles_sorted}|{reason}|{pvd['epoch']}"
    rc, rv = p(adm_b, "/ra/revoke/by-username", {
        "username": buser, "reason": reason,
        "sig_hex": wf.sign(adm_b.sk, msg), "epoch": pvd["epoch"]})
    rvd = rv.get("data") or {}
    expect(rc == 200 and rvd.get("ledger_id", 0) > 0,
           "X4 org-b 管理员签名吊销 → 200（台账行在案）", f"rc={rc} {str(rv)[:200]}")
    # 链面归因：共享树纪元+org-b 锚同值推进；org-a 锚不动；聚合根更迭
    expect(int(ir.call_fn("revEpoch", [])[0]) == rvd["epoch"],
           "X5 共享树 revEpoch=回执纪元（IdentityRegistry）")
    epoch_b, root_b, _ts = fed.call_fn("revAnchors", [_oid("org-b")])
    ir_root = bytes(ir.call_fn("revRoot", [])[0]).hex()
    expect(int(epoch_b) == rvd["epoch"] and bytes(root_b).hex() == ir_root,
           "X5 FedRegistry org-b 锚=回执纪元+共享树根（吊销归因 org-b）")
    org_a_now = bytes(fed.call_fn("revAnchors", [_oid("org-a")])[1]).hex()
    expect(org_a_now == bytes(pre["org_a"][1]).hex(),
           "X5 org-a 锚未动（org-b 吊销不归因 org-a——机构署名面诚实）")
    post_root = bytes(fed.call_fn("globalRevRoot", [])[0]).hex()
    buf = b""
    i = 0
    while True:
        try:
            oid = bytes(fed.call_fn("orgIds", [i])[0])
        except Exception:  # noqa: BLE001 —— 越界=枚举完
            break
        i += 1
        if not oid.strip(b"\x00"):
            continue
        ep, rt, _ = fed.call_fn("revAnchors", [oid])
        buf += oid + int(ep).to_bytes(8, "big") + bytes(rt)
    expect(post_root != pre["global_root"] and post_root == wf.sm3_hex(buf),
           "X5 全局聚合根更迭+离线 SM3 同构对拍（逐机构 orgId‖epoch‖root）")
    expect(int(fed.call_fn("globalRevEpoch", [])[0]) == pre["global_epoch"] + 1,
           "X5 聚合纪元单调 +1")

    # ============ [Z] 即时生效 ============
    print("== [Z] 跨域吊销即时生效 ==")
    rc, wj = g(anon(), f"/ra/revocation/witness?holder_pk_hex={z_pk.lower()}")
    expect(rc == 403 and wj.get("code") == "revoked",
           "Z1 未消费子凭证取见证 → 403 revoked（B 域吊销即时进共享树——R3-0.3 传播）",
           f"rc={rc} {str(wj)[:120]}")
    rc, sj2 = p(anon(), "/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": bid_number, "cert_level": 3, "sn": SN, "holder_pub_hex": z_pk})
    expect(rc == 403 and sj2.get("code") == "cred_revoked",
           "Z2 被吊销者重签子凭证 → 403 cred_revoked", f"rc={rc} {str(sj2)[:120]}")

    # ============ [X6] 治理大屏互认面 ============
    print("== [X6] 治理大屏互认公示 ==")
    rc, gov = g(anon(), "/chain/governance")
    fedp = (gov.get("data") or {}).get("federation") or {}
    orgs = {o.get("org_id"): o for o in fedp.get("orgs", [])}
    expect("org-b" in orgs and int(orgs["org-b"].get("rev_epoch", 0)) == rvd["epoch"],
           "X6 大屏互认面：org-b 在列且锚纪元=回执值（公示可观测）",
           str(fedp)[:200])
    expect(fedp.get("global_rev_root_hex") == post_root,
           "X6 大屏聚合根=链上值（全局撤销树公示）")

    # ============ [N] 负例：未登记机构域 ============
    print("== [N] 负例：未登记机构域 ==")
    zuser = "xorg-z-" + secrets.token_hex(3)
    zpw = secrets.token_urlsafe(12)
    zpil = script_login(API, zuser, zpw)
    zform = {"id_number": "11010119930404" + secrets.token_hex(2), "cert_level": 3,
             "sn": SN, "class_id": 1}
    rc, zr = p(zpil, "/auth/profile", {**zform, "org_id": "org-z"})
    expect(rc in (400, 422) and zr.get("code") == "unknown_org",
           "N1 未登记机构域注册 → 4xx unknown_org（fail-closed）", f"rc={rc} {str(zr)[:150]}")

    print(f"\n== ⑥站跨域演示全绿：{_checks + wf._checks} 项断言 [OK]（{time.time()-t0:.0f}s）==")
    print(
        "    多机构一期：互认注册表（governor 准入）+共享树机构署名锚"
        "+全局聚合根+跨域吊销即时生效"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
