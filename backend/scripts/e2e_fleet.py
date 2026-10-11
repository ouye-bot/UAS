"""3.1 机构机队接口 e2e（真链档——登记→批量签发→受理出证→吊销即时生效→桥侧绑定校验）。

  [F1] org-b 机构管理员批量登记机队设备（kind=2 机构承诺主凭证——链面
       registerCommitment(kind=2)，设备 1 SN=桥 /engine_pub device_serial 单源）
  [F2] 机队子凭证批量签发（原像知识认证同构+机构共享池）
  [F3] 设备 1 受理出证全动线（绑定→桥真出证→受理→取件）+ARM 实弹
       （桥第 6 查 SN 绑定=verify_token 六查全过——机队令牌与桥本机序列号绑定）
  [F4] org-b 管理员签名吊销设备 2（按句柄 FZ-REVOKE）→即时生效：未消费子凭证
       取见证 403 revoked+重签 403 cred_revoked+org 署名推根（FedRegistry org-b
       锚推进/org-a 锚不动/聚合根离线 SM3 对拍）
  [N]  负例：kind 语义错配拒（个人凭证走机队签发端点 409 not_fleet_credential）+
       跨域机队操作拒（org-a 管理员签发 org-b 设备 403 org_forbidden）

用法：cd uas/backend && python scripts/e2e_fleet.py
前置：backend(8000)+bridge(8100,SITL)+worker 在线；真链档（FZ_CHAIN_ANCHOR=real）；
FedRegistry 已登记 org-a/org-b（chain_smoke --deploy §⑨）；org-b 种子账户在案
（admin-b——seed_accounts org-b demo 种子）。
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
    sortie_flight,
)
from script_auth import script_login  # noqa: E402

_checks = 0


def _oid(s: str) -> bytes:
    return s.encode().ljust(32, b"\x00")


def _fed_chain():
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
    if marker == "admin" and os.environ.get("FZ_SEED_ADMIN_PASSWORD"):
        return os.environ["FZ_SEED_ADMIN_PASSWORD"]
    seed = Path(tempfile.gettempdir()) / "fz_accounts_seed.txt"
    for line in seed.read_text(encoding="utf-8").splitlines():
        if marker in line and "-b" not in line.split("（")[0]:
            # org-a 账户行（marker="admin" 时行序先于 admin-b——双保险排除 -b 席）
            tail = line.rsplit(" ", 1)[-1].strip()
            if tail:
                return tail
    for line in seed.read_text(encoding="utf-8").splitlines():
        if marker in line:
            tail = line.rsplit(" ", 1)[-1].strip()
            if tail:
                return tail
    raise SystemExit(f"缺 {marker} 口令（seed 文件无该行——先跑 seed_accounts）")


def main() -> int:
    t0 = time.time()
    print("== 3.1 机构机队接口 e2e（credKind=2 全动线实弹）==")
    r = requests.get(f"{API}/healthz", timeout=10).json()
    expect(r.get("status") == "ok", "F0 backend 健康")
    pub = wf.bget("/engine_pub")
    bridge_sn = pub.get("device_serial") or ""
    expect(bool(pub.get("engine_pub_hex")) and bridge_sn,
           "F0 桥在线（engine_pub+device_serial 单源读数）", f"sn={bridge_sn!r}")
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
        raise SystemExit("[FAIL] 机队 e2e 须真链档（FZ_CHAIN_ANCHOR=real）")
    # R2⑥（观察项——SN 双源前置对拍）：登记面 SN=bridge_sn（/engine_pub 实读）
    # vs prove 面 SN=e2e_workflows.SN 模块常量（env FZ_DEVICE_SERIAL 缺省
    # FZ-SN-DEV-01）——桥读数漂离缺省时 F3 prove 原像 C 必挂（fail-loud 前移
    # 到 F0 即时定位，不留到 45s 出证后）。
    expect(bridge_sn == SN,
           "F0 SN 双源对拍（登记面=/engine_pub 实读==prove 面=e2e_workflows.SN）",
           f"bridge={bridge_sn!r} SN={SN!r}——漂离时设 FZ_DEVICE_SERIAL={bridge_sn!r}")
    fed, ir = _fed_chain()
    expect(
        int(fed.call_fn("orgs", [_oid("org-b")])[0]) == 1,
        "F0 FedRegistry org-b 已登记（chain_smoke §⑨ 前置）",
    )

    # ============ [F1] org-b 批量登记机队设备 ============
    print("== [F1] org-b 机构管理员批量登记 ==")
    adm_b = script_login(API, "admin-b", _pw("admin-b"))
    who = adm_b.get(f"{API}/auth/whoami", timeout=10).json()["data"]
    expect(who.get("org_id") == "org-b", "F1 org-b 管理员登录（域=org-b）")
    # 幂等：登记号带随机尾（脚本终态 F7 吊销双机回收 SN 槽位——重跑不撞判重）
    dev1_no = ("FZ-FLT-E2E-" + secrets.token_hex(3) + "D1").ljust(18, "0")[:18]
    dev2_no = ("FZ-FLT-E2E-" + secrets.token_hex(3) + "D2").ljust(18, "0")[:18]
    dev2_sn = "FZ-SN-FLEET-E2E-" + secrets.token_hex(3)
    rc, rj = p(adm_b, "/ra/fleet/devices", {"devices": [
        {"device_no": dev1_no, "sn": bridge_sn, "cert_level": 3, "class_id": 1},
        {"device_no": dev2_no, "sn": dev2_sn, "cert_level": 3, "class_id": 1},
    ]})
    expect(rc == 200 and rj.get("code") == "ok" and len(rj["data"]["devices"]) == 2,
           "F1 批量登记 2 台（kind=2 机构承诺——设备 1 SN=桥序列号单源）",
           f"rc={rc} {str(rj)[:200]}")
    dev1, dev2 = rj["data"]["devices"]
    _, listj = g(adm_b, "/ra/fleet/devices")
    listed = {x["device_no"]: x for x in listj["data"]["items"]}
    expect(dev1_no in listed and dev2_no in listed and listed[dev1_no]["cred_kind"] == 2,
           "F1b 设备列表本域可见（域隔离数据面）", str(listj)[:150])
    # 链面归因：机队承诺 kind=2 在链（getCred 读回）
    _st, kind1, _ts = ir.call_fn("getCred", [bytes.fromhex(dev1["master_cred_hash_hex"])])
    expect(int(kind1) == 2, "F1c 链面 getCred.credKind=2（预留面激活——DB/链同构）")

    # ============ [F2] 机队子凭证批量签发 ============
    print("== [F2] 机队子凭证批量签发 ==")
    sk1, pk1 = gen_keypair()
    sk2, pk2 = gen_keypair()
    rc, sj = p(adm_b, "/ra/fleet/sub-credentials", {"items": [
        {"master_cred_hash_hex": dev1["master_cred_hash_hex"],
         "salt_hex": dev1["salt_hex"], "holder_pub_hex": pk1},
        {"master_cred_hash_hex": dev2["master_cred_hash_hex"],
         "salt_hex": dev2["salt_hex"], "holder_pub_hex": pk2},
    ]})
    expect(rc == 200 and sj.get("code") == "ok" and len(sj["data"]["items"]) == 2,
           "F2 批量签发 2 张（原像知识认证+共享池计数）", f"rc={rc} {str(sj)[:200]}")
    sub1, sub2 = sj["data"]["items"]

    # ============ [F3] 设备 1 受理出证+桥侧 SN 绑定校验（ARM 实弹） ============
    print("== [F3] 设备 1 出证→桥侧绑定校验 ==")
    tok, mats = full_authorization(
        adm_b, sk1, pk1, dev1, sub1, dev1["device_no"],
        "F3 机队设备出证", sorties=1, win_s=3600)
    expect(tok["sn_hash"] == wf.sm3_hex(bridge_sn.encode()),
           "F3 令牌 sn_hash=SM3(桥 device_serial)——机队子凭证 SN 绑定与 /engine_pub 同源（③）")
    sortie_flight(1, mats, expect_checkpoint=False, breach=False)
    print("  [OK] F3 ARM 实弹全过（verify_token 六查含 SN 绑定第 6 查——桥侧绑定校验闭环）")
    _ = wf._checks  # sortie_flight 计数入 wf

    # ============ [F4] 设备 2 吊销即时生效+org 署名推根 ============
    print("== [F4] 设备 2 吊销→即时生效→org 归因 ==")
    fed, ir = _fed_chain()
    pre = {
        "org_a": fed.call_fn("revAnchors", [_oid("org-a")]),
        "org_b": fed.call_fn("revAnchors", [_oid("org-b")]),
        "global_root": bytes(fed.call_fn("globalRevRoot", [])[0]).hex(),
    }
    # 目标纪元=链上权威 revEpoch+1（IdentityRegistry 唯一时钟——服务端 _base_
    # epoch 真链档即此值；DB snapshot 镜像可能滞后/超前于链（跨脚本运行漂移
    # 实锤），签名纪元必须与链权威同源。审查回归 F4 bad_epoch 实弹抓出即改。）
    epoch = int(ir.call_fn("revEpoch", [])[0]) + 1
    handle2 = dev2["master_cred_hash_hex"]
    reason = "机队 e2e：设备退役依规吊销（org-b 署名推根）"
    msg = f"FZ-REVOKE|v1|{handle2.lower()}|{reason}|{epoch}"
    rc, rv = p(adm_b, "/ra/revoke", {
        "master_cred_hash_hex": handle2, "reason": reason,
        "sig_hex": wf.sign(adm_b.sk, msg), "epoch": epoch})
    rvd = rv.get("data") or {}
    expect(rc == 200 and rvd.get("ledger_id", 0) > 0,
           "F4 org-b 管理员按句柄签名吊销设备 2（台账在案）", f"rc={rc} {str(rv)[:200]}")
    rc, wj = g(anon(), f"/ra/revocation/witness?holder_pk_hex={pk2.lower()}")
    expect(rc == 403 and wj.get("code") == "revoked",
           "F4b 未消费子凭证取见证 → 403 revoked（R3-0.3 传播即时生效）",
           f"rc={rc} {str(wj)[:120]}")
    rc, sj2 = p(adm_b, "/ra/fleet/sub-credentials", {"items": [
        {"master_cred_hash_hex": handle2, "salt_hex": dev2["salt_hex"], "holder_pub_hex": pk2}]})
    expect(rc == 403 and sj2.get("code") == "cred_revoked",
           "F4c 已吊销设备重签 → 403 cred_revoked", f"rc={rc} {str(sj2)[:120]}")
    epoch_b, root_b, _ts = fed.call_fn("revAnchors", [_oid("org-b")])
    ir_root = bytes(ir.call_fn("revRoot", [])[0]).hex()
    expect(int(epoch_b) == rvd["epoch"] and bytes(root_b).hex() == ir_root,
           "F4d org-b 锚=回执纪元+共享树根（org 署名推根——⑥站 FedRegistry 分支贯通）")
    org_a_now = bytes(fed.call_fn("revAnchors", [_oid("org-a")])[1]).hex()
    expect(org_a_now == bytes(pre["org_a"][1]).hex(),
           "F4e org-a 锚未动（机队吊销归因 org-b——机构署名面诚实）")
    post_root = bytes(fed.call_fn("globalRevRoot", [])[0]).hex()
    buf = b""
    i = 0
    while True:
        try:
            oid = bytes(fed.call_fn("orgIds", [i])[0])
        except Exception:  # noqa: BLE001
            break
        i += 1
        if not oid.strip(b"\x00"):
            continue
        ep, rt, _ = fed.call_fn("revAnchors", [oid])
        buf += oid + int(ep).to_bytes(8, "big") + bytes(rt)
    expect(post_root != pre["global_root"] and post_root == wf.sm3_hex(buf),
           "F4f 全局聚合根更迭+离线 SM3 同构对拍")

    # ============ [F7] 设备 1 吊销（幂等收尾——SN 槽位回收，重跑不撞判重） ============
    print("== [F7] 设备 1 吊销收尾（SN 槽位回收——幂等重跑语义） ==")
    epoch2 = int(ir.call_fn("revEpoch", [])[0]) + 1  # 链上权威（F4 同源——DB 镜像漂移免疫）
    handle1 = dev1["master_cred_hash_hex"]
    reason1 = "机队 e2e 收尾：演示设备退役（SN 槽位回收）"
    msg1 = f"FZ-REVOKE|v1|{handle1.lower()}|{reason1}|{epoch2}"
    rc, rv1 = p(adm_b, "/ra/revoke", {
        "master_cred_hash_hex": handle1, "reason": reason1,
        "sig_hex": wf.sign(adm_b.sk, msg1), "epoch": epoch2})
    expect(rc == 200 and (rv1.get("data") or {}).get("ledger_id", 0) > 0,
           "F7 设备 1 吊销收尾（出证后撤销联动语义同构）", f"rc={rc} {str(rv1)[:150]}")

    # ============ [N] 负例：kind 错配拒+跨域机队操作拒 ============
    print("== [N] 负例组 ==")
    adm_a = script_login(API, "admin", _pw("admin"))
    zuser = "fleet-n-" + secrets.token_hex(3)
    zpw = secrets.token_urlsafe(12)
    zpil = script_login(API, zuser, zpw)
    zid = "11010119930505" + secrets.token_hex(2)
    rc, prof = p(zpil, "/auth/profile", {"id_number": zid, "cert_level": 3,
                                         "sn": bridge_sn, "class_id": 1, "org_id": "org-a"})
    expect(rc == 200, "N1 个人凭证登记（kind=1——错配负例载体）", f"rc={rc}")
    per = prof["data"]
    rc, nj = p(adm_a, "/ra/fleet/sub-credentials", {"items": [
        {"master_cred_hash_hex": per["master_cred_hash_hex"],
         "salt_hex": per["salt_hex"], "holder_pub_hex": pk1}]})
    expect(rc == 409 and nj.get("code") == "not_fleet_credential",
           "N2 kind 语义错配拒：个人凭证走机队签发端点 → 409 not_fleet_credential",
           f"rc={rc} {str(nj)[:150]}")
    rc, nj2 = p(adm_a, "/ra/fleet/sub-credentials", {"items": [
        {"master_cred_hash_hex": handle1,
         "salt_hex": dev1["salt_hex"], "holder_pub_hex": pk1}]})
    expect(rc == 403 and nj2.get("code") == "org_forbidden",
           "N3 跨域机队操作拒：org-a 管理员签发 org-b 设备 → 403 org_forbidden",
           f"rc={rc} {str(nj2)[:150]}")

    print(f"\n== 3.1 机队接口 e2e 全绿：{_checks + wf._checks} 项断言 [OK]"
          f"（{time.time()-t0:.0f}s）==")
    print("    机构机队闭环：kind=2 承诺登记→共享池批量签发→受理出证→ARM 桥侧"
          "SN 绑定→org 署名推根即时生效")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
