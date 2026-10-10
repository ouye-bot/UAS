"""1.3 实弹验收 drill（漂移档全链，审查批②重构）：治理增席位→watcher 漂移
红牌+自动起草→人工多签 execute→watcher 自动 finalized（re-share 纪元+1 指纹
门）→治理除名回补→**新漂移重新起草**（起草账滞留自愈实证）→双击竞态幂等
→回初始席位形态。对运行真栈（真链+时间锁+份额仪式，零替身）。

用法：cd uas/backend && set -a && source ../.local_env && set +a &&
FZ_CHAIN_ANCHOR=real python scripts/threshold_sync_drill.py
前置：真链在线+threshold_root 已初始化（与后台 watcher 幂等互容）。
"""

from __future__ import annotations

import json
import secrets
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


def _wait_executed(gov, admin, pr, call_data, pid: int, timeout_s: float = 60.0) -> None:
    """人工确认面：双 owner confirm→eta 到期→execute（Queued 提案的人工
    双签段——自动化边界=起草，confirm/execute 恒人工）。confirm 幂等
    （already confirmed 重跑容忍——票数断言兜底）。"""
    ra = TxSigner(chain_ra_tx_key())
    for signer in (admin, ra):
        try:
            gov.send_fn(signer, "confirm", [pid])
        except ChainError:
            pass
    _t, _ch, _d, eta, conf, st = gov.call_fn("getProposal", [pid])
    expect(int(st) == 1 and int(conf) >= 2, f"提案 {pid} 已 Queued（票数 {conf}）")
    wait_s = eta_unix_seconds(int(eta)) - time.time() + 1.5
    if wait_s > 0:
        time.sleep(min(wait_s, timeout_s))
    r3 = gov.send_fn(admin, "execute", [pr.address, 0, call_data])
    executed = [ev for ev in gov.decode_logs(r3) if ev["event"] == "Executed"]
    expect(len(executed) == 1, "execute 回执 Executed 事件在案")


def _propose_member_change(gov, admin, fn: str, addr: str) -> int:
    """席位变更提案（幂等：proposalOfCall 查重复用残留 Active 提案）。"""
    call_data = gov.encode_calldata(fn, [addr])
    chash = sm3_bytes(call_data)
    pending = int(gov.call_fn("proposalOfCall", [gov.address, chash])[0])
    if pending:
        print(f"  [..] 复用残留提案 {pending}（同调用指纹——幂等查重）")
        return pending, call_data
    r1 = gov.send_fn(admin, "propose", [gov.address, chash, f"drill:{fn} {addr[:10]}"])
    pid = int([ev for ev in gov.decode_logs(r1) if ev["event"] == "Proposed"][0]["proposalId"])
    return pid, call_data


def _expected_calldata(pr, version: str, meta: dict, fp: str) -> bytes:
    """起草提案 calldata 重构（5 键元数据——与 draft_reshare_proposal 同构，
    审查批②钉死：含 owner_set_fp=起草时点链上指纹）。"""
    announcement = json.dumps(
        {
            "epoch": int(version.rsplit("-", 1)[-1]),
            "pub_hex": meta["pub_hex"],
            "roles": meta["roles"],
            "threshold": meta["threshold"],
            "owner_set_fp": fp,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return pr.encode_calldata(
        "publishPolicy", [version, sm3_bytes(announcement.encode("utf-8"))]
    )


def main() -> int:
    t0 = time.time()
    print("== 1.3 份额刷新联动实弹（漂移档全链：增席位→红牌→起草→execute→"
          "自动 finalized→除名回补→重新起草→双击竞态）==")

    addresses = json.loads(ADDR_PATH.read_text(encoding="utf-8"))
    admin = TxSigner(chain_admin_tx_key())
    client = ChainClient(rpc_url=RPC, from_addr=admin.address)
    gov = load_governor(client, addresses)
    pr = load_binding("PolicyRegistry", client, addresses["PolicyRegistry"]["address"])

    # ---- ① 现状+绑定持久化判别 ----
    expect(ts.is_initialized(), "门限根在案")
    meta0 = sync._root_meta()
    fp0 = sync.chain_owner_set()["fp_hex"]
    domain0 = sync.read_domain_fp()
    owners0 = sync.chain_owner_set()["owners"]
    print(
        f"  现状: epoch={meta0['epoch']} owners={len(owners0)} fp={fp0[:16]}… "
        f"domain_fp={(domain0 or 'unbound')[:16]}…"
    )
    if domain0 is None:
        sync.bind_domain_fp(fp0)
        ok("域指纹未绑定——先锚定现状（首次对拍即绑定）")
    epoch0 = int(meta0["epoch"])
    fp_before = fp0
    expect(
        sync.read_domain_fp() == fp0,
        "起测前提：域指纹绑定已持久化落盘（read_domain_fp 复读=链上 fp）",
    )

    new_addr = "0x" + secrets.token_bytes(20).hex()  # 新席位（每轮随机——无钥席位）

    # ---- 段A：治理增席位→漂移→起草→5 键重构对拍→execute→watcher 自动
    #      finalized（①②修复实证）----
    pid_a, call_a = _propose_member_change(gov, admin, "addOwner", new_addr)
    _wait_executed(gov, admin, gov, call_a, pid_a)
    fp1 = sync.chain_owner_set()["fp_hex"]
    expect(fp1 != fp_before, f"增席位→owner-set 指纹漂移（{fp_before[:12]}…→{fp1[:12]}…）")

    r = sync.run_sync_check_once()
    expect(
        r.get("synced") is False and r.get("action") in ("drafted", "already_drafted"),
        f"漂移检测：红牌+reshare 提案起草（action={r.get('action')}）",
        f"r={r}",
    )
    state = sync._read_sync_state()
    expect(state.get("drift") is True, "红牌落盘（sync_state.json drift=true）")
    pid1 = state.get("drafted_proposal_id")
    version1 = state.get("drafted_version")
    expect(bool(pid1 and version1), f"reshare 提案已起草（{version1}，Queued 待确认）")
    expect(sync.sync_status().get("synced") is False, "大屏红牌数据源：synced=false")

    meta_now = sync._root_meta()
    call_data1 = _expected_calldata(pr, version1, meta_now, fp1)
    _t, ch, _d, _eta, _conf, _st = gov.call_fn("getProposal", [int(pid1)])
    expect(bytes(ch) == sm3_bytes(call_data1), "起草提案 calldata 重构对拍（5 键含 owner_set_fp——逐位一致）")
    _wait_executed(gov, admin, pr, call_data1, int(pid1))
    on_hash, _on_ts = pr.call_fn("getPolicy", [version1])
    expect(bytes(on_hash).strip(b"\x00"), f"公示行落地（{version1}）")

    r = sync.run_sync_check_once()
    expect(
        r.get("action") == "finalized" and r.get("synced") is True,
        f"watcher 自动 finalized（『执行后自动恢复』实证——action={r.get('action')}）",
        f"r={r}",
    )
    epoch1 = int(sync._root_meta()["epoch"])
    expect(epoch1 == epoch0 + 1, f"re-share 完成：纪元 {epoch0}→{epoch1}")
    expect(sync._root_meta().get("owner_set_fp") == fp1, "owner-set 指纹绑定写盘（件①）")
    expect(sync.owner_set_synced() is True, "解锁第④关恢复：owner_set_synced=True")

    # ---- 段B：治理除名回补→再漂移→**新 version 重新起草**（起草账滞留自愈
    #      实证——旧实现卡 already_drafted→finalize 撞纪元门）----
    pid_b, call_b = _propose_member_change(gov, admin, "removeOwner", new_addr)
    _wait_executed(gov, admin, gov, call_b, pid_b)
    fp2 = sync.chain_owner_set()["fp_hex"]
    expect(fp2 != fp1, f"除名回补→指纹再漂移（{fp1[:12]}…→{fp2[:12]}…）")
    r = sync.run_sync_check_once()
    expect(
        r.get("action") in ("drafted", "already_drafted") and r.get("synced") is False,
        f"新漂移重新起草（滞留账自愈——action={r.get('action')}）",
        f"r={r}",
    )
    state = sync._read_sync_state()
    version2 = state.get("drafted_version")
    pid2 = state.get("drafted_proposal_id")
    expect(
        version2 == f"threshold-epoch-{epoch1 + 1}" and bool(pid2),
        f"新漂移起草新 version（{version2}——非卡死旧账）",
    )
    call_data2 = _expected_calldata(pr, version2, sync._root_meta(), fp2)
    _t, ch2, _d, _eta, _conf, _st = gov.call_fn("getProposal", [int(pid2)])
    expect(bytes(ch2) == sm3_bytes(call_data2), "第二轮起草 calldata 重构对拍（逐位一致）")
    _wait_executed(gov, admin, pr, call_data2, int(pid2))
    r = sync.run_sync_check_once()
    expect(r.get("action") == "finalized" and r.get("synced") is True, "第二轮 watcher 自动 finalized")
    expect(int(sync._root_meta()["epoch"]) == epoch1 + 1, f"纪元 {epoch1}→{epoch1 + 1}")
    expect(sync.owner_set_synced() is True, "第二轮解锁恢复")

    # ---- 段C：双击竞态（恰一成功一拒——dup pending call 链级幂等）----
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
        f"双击竞态：恰一成功一拒（dup pending call 链级幂等）",
    )
    expect(sync.owner_set_synced() is True, "终态：份额域与治理席位对齐（解锁恢复）")
    expect(
        len(sync.chain_owner_set()["owners"]) == len(owners0),
        f"席位形态还原（owners={len(owners0)}——新席位除名回补）",
    )

    print(
        f"\n== 实弹 drill 全绿（漂移档）：{_checks} 断言（{time.time() - t0:.1f}s）｜"
        f"纪元 {epoch0}→{int(sync._root_meta()['epoch'])}｜增席位→红牌→起草→"
        f"execute→自动 finalized→除名→重新起草→双击竞态全链 =="
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
