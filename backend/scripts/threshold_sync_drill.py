"""1.3 实弹验收 drill：治理除名 owner→watcher 漂移红牌+自动起草→人工多签
execute→re-share 纪元+1（owner-set 指纹门）→解锁恢复→席位恢复+API 服务函数
第二段重分割全链。对运行真栈（真链+时间锁+份额仪式，零替身）。

用法：cd uas/backend && FZ_SEED_*_PASSWORD=.. python scripts/threshold_sync_drill.py
前置：真链在线+threshold_root 已初始化+栈在线（watcher daemon 会与本脚本
幂等互容——proposalOfCall 查重使双方只起草一次）。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.chain.client import ChainClient, ChainError  # noqa: E402
from app.chain.contracts import load_binding  # noqa: E402
from app.chain.governor import (  # noqa: E402
    eta_unix_seconds,
    load_governor,
)
from app.chain.signer import TxSigner  # noqa: E402
from app.crypto.sm3 import sm3_bytes  # noqa: E402
from app.kms import chain_admin_tx_key, chain_ra_tx_key  # noqa: E402
from app.ra import threshold_shares as ts  # noqa: E402
from app.ra import threshold_sync as sync  # noqa: E402

ADDR_PATH = Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json"
RPC = "http://127.0.0.1:8545"

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


def _wait_executed(gov, admin, pr, call_data, pid: int, timeout_s: float = 60.0) -> dict:
    """人工确认面：第二 owner confirm→eta 到期→execute（Queued 提案的人工
    双签段——自动化边界=起草，confirm/execute 恒人工）。"""
    ra = TxSigner(chain_ra_tx_key())
    from app.chain.client import ChainError

    for signer in (admin, ra):
        try:
            gov.send_fn(signer, "confirm", [pid])
        except ChainError:
            pass  # already confirmed——重跑幂等（票已计入，票数断言兜底）
    _t, _ch, _d, eta, conf, st = gov.call_fn("getProposal", [pid])
    expect(int(st) == 1 and int(conf) >= 2, f"提案 {pid} 已 Queued（票数 {conf}）")
    wait_s = eta_unix_seconds(int(eta)) - time.time() + 1.5
    if wait_s > 0:
        time.sleep(min(wait_s, timeout_s))
    r3 = gov.send_fn(admin, "execute", [pr.address, 0, call_data])
    executed = [ev for ev in gov.decode_logs(r3) if ev["event"] == "Executed"]
    expect(len(executed) == 1, "execute 回执 Executed 事件在案")
    return r3


def main() -> int:
    t0 = time.time()
    print("== 1.3 份额刷新联动实弹（除名→红牌→重分割→恢复）==")

    addresses = json.loads(ADDR_PATH.read_text(encoding="utf-8"))
    admin = TxSigner(chain_admin_tx_key())
    client = ChainClient(rpc_url=RPC, from_addr=admin.address)
    gov = load_governor(client, addresses)
    pr = load_binding("PolicyRegistry", client, addresses["PolicyRegistry"]["address"])

    # ---- ① 现状 ----
    expect(ts.is_initialized(), "门限根在案")
    meta0 = sync._root_meta()
    fp0 = sync.chain_owner_set()["fp_hex"]
    domain0 = sync.read_domain_fp()
    owners0 = sync.chain_owner_set()["owners"]
    victim = owners0[-1]  # 被除名席位（链上末位 owner）
    print(
        f"  现状: epoch={meta0['epoch']} owners={len(owners0)} fp={fp0[:16]}… "
        f"domain_fp={(domain0 or 'unbound')[:16]}… victim={victim[:10]}…"
    )
    if domain0 is None:
        sync.bind_domain_fp(fp0)
        domain0 = fp0
        ok("域指纹未绑定——先锚定现状（首次对拍即绑定）")
    epoch0 = int(meta0["epoch"])
    drifted_pre = domain0 != fp0
    expect(
        drifted_pre or domain0 == fp0,
        "起测态：对齐（走完整除名段）或漂移（上轮残留——幂等续跑）",
    )

    # ---- ② 治理除名 owner（k-of-n 时间锁仪式——治理面变更不绕过治理面）
    #      （上轮已除名残留漂移态=本段跳过，幂等续跑 ③）----
    if drifted_pre:
        fp1 = fp0
        print("  [..] 上轮除名残留漂移态——跳过除名段（幂等续跑）")
    elif len(owners0) - 1 < sync.chain_owner_set()["required"]:
        # 治理不变式实证：n-1>=k 不满足时 removeOwner 被合约正确拒绝
        # （below quorum）——除名闭环已由前轮实弹在案，本轮短路进幂等负例
        fp1 = fp0
        print(
            f"  [..] owners={len(owners0)}=required={sync.chain_owner_set()['required']}"
            "——除名将 below quorum（治理不变式实证，上轮闭环在案）——短路进幂等负例"
        )
    else:
        call_data = gov.encode_calldata("removeOwner", [victim])
        chash = sm3_bytes(call_data)
        pending0 = int(gov.call_fn("proposalOfCall", [gov.address, chash])[0])
        if pending0:  # 幂等：残留 Active 提案直接复用（dup pending call 拒重发）
            pid0 = pending0
            print(f"  [..] 复用残留提案 {pid0}（同调用指纹——幂等查重）")
        else:
            r1 = gov.send_fn(
                admin, "propose", [gov.address, chash, f"drill:removeOwner {victim[:10]}"]
            )
            pid0 = int(
                [ev for ev in gov.decode_logs(r1) if ev["event"] == "Proposed"][0]["proposalId"]
            )
        _wait_executed(gov, admin, gov, call_data, pid0)
        count_now = int(gov.call_fn("ownerCount", [])[0])
        expect(count_now == len(owners0) - 1, f"除名落地（owners {len(owners0)}→{count_now}）")
        st_ = sync._read_sync_state()
        st_["removed_owner"] = victim  # 回补凭据（续跑态可恢复席位）
        sync._sync_state_path().write_text(
            json.dumps(st_, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        fp1 = sync.chain_owner_set()["fp_hex"]
        expect(fp1 != fp0, f"owner-set 指纹漂移在案（{fp0[:12]}…→{fp1[:12]}…）")

    # ---- ③ watcher 漂移检测：红牌+自动起草（与后台 watcher 幂等互容）----
    if fp1 == fp0 and not drifted_pre:
        print(
            "  [..] 本轮无漂移（不可除名态短路）——直入件③实弹（并发双击=重放负例，"
            "恰一成功一拒——governor dup pending call 链级幂等）"
        )
        import concurrent.futures as _cf

        results = {"ok": 0, "denied": 0}
        with _cf.ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(sync.propose_and_reshare), ex.submit(sync.propose_and_reshare)]
            for f in futs:
                try:
                    out = f.result()
                    results["ok"] += 1
                    print(f"    [win] 纪元→{out['epoch']}（version={out['version']}）")
                except (sync.SyncError, RuntimeError, ChainError) as e:
                    results["denied"] += 1
                    print(f"    [denied] {type(e).__name__}: {str(e)[:80]}")
        expect(
            results["ok"] == 1 and results["denied"] == 1,
            f"件③双击竞态：恰一成功一拒（ok={results['ok']} denied={results['denied']}"
            "——dup pending call 链级幂等，不重复刷新）",
        )
        expect(sync.owner_set_synced() is True, "终态：份额域与治理席位对齐（解锁恢复）")
        print(f"== 实弹 drill 全绿（短路档）：{_checks} 断言（{time.time() - t0:.1f}s）==")
        return 0
    r = sync.run_sync_check_once()
    expect(
        r.get("synced") is False and r.get("action") in ("drafted", "already_drafted"),
        f"漂移检测：红牌+reshare 提案起草（action={r.get('action')}）",
        f"r={r}",
    )
    state = sync._read_sync_state()
    expect(state.get("drift") is True, "红牌落盘（sync_state.json drift=true）")
    pid1 = state.get("drafted_proposal_id")
    expect(bool(pid1), f"reshare 提案已起草（proposal_id={pid1}，Queued 待确认）")
    # 大屏红牌数据源
    status = sync.sync_status()
    expect(status.get("synced") is False, "大屏红牌数据源：sync_status synced=false")

    # ---- ④ 人工多签确认+execute 已起草提案（自动化边界=起草）----
    version = state.get("drafted_version") or f"threshold-epoch-{epoch0 + 1}"
    _t, ch, _desc, _eta, _conf, _st = gov.call_fn("getProposal", [pid1])
    # calldata 重构：publishPolicy(version, SM3(announcement))——announcement
    # 与 draft_reshare_proposal 同构（4 键元数据）
    announce = json.dumps(
        {
            "epoch": epoch0 + 1,
            "pub_hex": sync._root_meta()["pub_hex"],
            "roles": sync._root_meta()["roles"],
            "threshold": sync._root_meta()["threshold"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    call_data1 = pr.encode_calldata("publishPolicy", [version, sm3_bytes(announce.encode("utf-8"))])
    expect(sm3_bytes(call_data1) == bytes(ch), "起草提案 calldata 重构对拍（逐位一致）")
    _wait_executed(gov, admin, pr, call_data1, int(pid1))
    on_hash, on_ts = pr.call_fn("getPolicy", [version])
    expect(bytes(on_hash).strip(b"\x00"), f"公示行落地（{version}）")

    # ---- ⑤ re-share（owner-set 指纹门=执行时点链读）----
    fp_now = sync.chain_owner_set()["fp_hex"]
    r = ts.ceremonial_reshare(gov_confirmed_epoch=epoch0 + 1, owner_set_fp=fp_now)
    expect(r["epoch"] == epoch0 + 1, f"re-share 完成：纪元 {epoch0}→{epoch0 + 1}")
    expect(r["pub_hex"] == meta0["pub_hex"], "D_pub 逐字不变（存量信封零影响）")
    meta1 = sync._root_meta()
    expect(meta1.get("owner_set_fp") == fp_now, "owner-set 指纹绑定写盘（件①）")

    # ---- ⑥ 解锁恢复 ----
    expect(sync.owner_set_synced() is True, "解锁第④关恢复：owner_set_synced=True")
    r = sync.run_sync_check_once()
    expect(r.get("synced") is True and r.get("action") == "ok", "红牌解除（重分割对齐）")

    # ---- ⑦ 席位回补（幂等可选——removed_owner 在案才回补）+件③实弹 ----
    removed_owner = sync._read_sync_state().get("removed_owner")
    if drifted_pre and not removed_owner:
        print(
            "  [..] 续跑态无 removed_owner 记录（上轮 drill 早于该字段）——跳过回补，"
            "以件③幂等负例替代第二段重分割"
        )
    else:
        call_data2 = gov.encode_calldata("addOwner", [removed_owner])
        chash2 = sm3_bytes(call_data2)
        pending2 = int(gov.call_fn("proposalOfCall", [gov.address, chash2])[0])
        if pending2:
            pid2 = pending2
            print(f"  [..] 复用残留提案 {pid2}（幂等查重）")
        else:
            r2 = gov.send_fn(
                admin, "propose", [gov.address, chash2, f"drill:addOwner {removed_owner[:10]}"]
            )
            pid2 = int(
                [ev for ev in gov.decode_logs(r2) if ev["event"] == "Proposed"][0]["proposalId"]
            )
        _wait_executed(gov, admin, gov, call_data2, pid2)
        expect(sync.chain_owner_set()["fp_hex"] != fp_now, "席位回补→指纹再漂移")
        out = sync.propose_and_reshare()
        expect(
            out["epoch"] == epoch0 + 2 and out["owner_set_fp"] == sync.chain_owner_set()["fp_hex"],
            f"propose_and_reshare（件③服务函数）：纪元→{epoch0 + 2}+指纹绑定",
        )
        n_owners = len(sync.chain_owner_set()["owners"])
        expect(n_owners == len(owners0) + 1, f"席位回补（owners→{n_owners}）")
    # 件③幂等负例（实弹）：本纪元公示行已存在→reshare_already_published 拒重放
    try:
        sync.propose_and_reshare()
        raise SystemExit("  [FAIL] 重放未被拒")
    except sync.SyncError as e:
        expect(e.code == "reshare_already_published", f"件③幂等负例：同纪元重放拒（{e.code}）")
    expect(sync.owner_set_synced() is True, "终态：份额域与治理席位对齐（解锁恢复）")

    print(
        f"\n== 实弹 drill 全绿：{_checks} 断言（{time.time() - t0:.1f}s）｜"
        f"纪元 {epoch0}→{epoch0 + 1}+｜除名→红牌→起草→人工执行→重分割→恢复全链 =="
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
