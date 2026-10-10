"""1.3 份额域↔治理席位同步（J2 下半截——单域失陷=除名+重分割的止损闭环）。

职责三面：
- 对拍：链上 owner-set 指纹（SM3(sorted(owners))，任务书钉定）vs 份额域
  绑定指纹（threshold_root/root.json owner_set_fp）——漂移=治理席位变更后
  未重分割；
- 止损自动化边界（任务书钉定）：watcher 检测漂移→治理大屏红牌数据源+自动
  **起草** reshare 提案（propose，幂等三重查重）——confirm/execute 保持人工
  （防事件注入 DoS：自动化只到起草为止）；
- 仪式服务：propose_and_reshare=⑤站三步提案+ceremonial_reshare 的服务化
  （scripts/threshold_reshare.py 与 POST /admin/threshold/reshare 双消费），
  幂等=PolicyRegistry version exists 拒重放。

fail-closed 全套（⑤站工艺继承）：纪元门+owner-set 指纹门+canary 自证+
先份额后纪元写序（threshold_shares.ceremonial_reshare 原样，本模块只携门参）。
链不可达=对拍 fail-closed（owner_set_synced False→解锁第④关拒）。
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path


class SyncError(Exception):
    """份额域同步面错误（漂移起草/幂等拒重放/链读失败）。"""

    def __init__(self, code: str, message: str = "", status: int = 409):
        super().__init__(message or code)
        self.code = code
        self.status = status


def _addr_path() -> Path:
    return Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"


def _rpc_url() -> str:
    return os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545")


def owner_set_fp_of(owners: list[str]) -> str:
    """owner-set 指纹=SM3(sorted(owners))——排序无关+大小写归一（任务书钉定）。"""
    from app.crypto.sm3 import sm3_bytes

    norm = sorted(str(a).strip().lower().removeprefix("0x") for a in owners)
    return sm3_bytes("\n".join(norm).encode("utf-8")).hex()


def chain_owner_set() -> dict:
    """链读治理席位现状（owners 全量+required+指纹）。链不可达/fake 档=抛
    SyncError（对拍面 fail-closed——调用方决定拒绝形态）。"""
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
        raise SyncError("chain_unavailable", "fake 档无链上治理面")
    try:
        from app.chain.client import ChainClient
        from app.chain.governor import load_governor
        from app.chain.signer import TxSigner
        from app.kms import chain_admin_tx_key

        addresses = json.loads(_addr_path().read_text(encoding="utf-8"))
        signer = TxSigner(chain_admin_tx_key())
        client = ChainClient(rpc_url=_rpc_url(), from_addr=signer.address)
        gov = load_governor(client, addresses)
        count = int(gov.call_fn("ownerCount", [])[0])
        owners = [str(gov.call_fn("owners", [i])[0]).lower() for i in range(count)]
        required = int(gov.call_fn("required", [])[0])
        return {
            "fp_hex": owner_set_fp_of(owners),
            "owners": owners,
            "required": required,
        }
    except SyncError:
        raise
    except Exception as e:  # noqa: BLE001 —— 链不可达=对拍 fail-closed
        raise SyncError("chain_unavailable", f"链读治理席位失败: {e}") from e


def _root_meta() -> dict:
    from app.ra.threshold_shares import _root_dir

    p = _root_dir() / "root.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def read_domain_fp() -> str | None:
    fp = _root_meta().get("owner_set_fp")
    return str(fp) if fp else None


def bind_domain_fp(fp: str) -> None:
    """域绑定指纹写回（保留 root.json 其余键——纪元/D_pub 零触碰）。"""
    from app.ra.threshold_shares import _lock, _root_dir

    with _lock:
        p = _root_dir() / "root.json"
        meta = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        meta["owner_set_fp"] = fp
        p.write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")


def _sync_state_path():
    from app.ra.threshold_shares import _root_dir

    return _root_dir() / "sync_state.json"


def _read_sync_state() -> dict:
    p = _sync_state_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def owner_set_synced() -> bool:
    """解锁第④关真实现（份额域与治理席位同步）——threshold_hooks 消费。

    - fake 档=False（同 warrant_on_chain：份额出借面不因演示档放行）；
    - 链不可达=False（fail-closed）；
    - 域未绑定+链可用=惰性绑定当前链上指纹→True（首次对拍即锚定）；
    - 已绑定≠链上=漂移→False+红牌落盘（watcher/解锁面双触发源）。"""
    try:
        chain = chain_owner_set()
    except SyncError:
        return False
    domain = read_domain_fp()
    if domain is None:
        bind_domain_fp(chain["fp_hex"])
        return True
    if domain != chain["fp_hex"]:
        _write_red_flag(chain)
        return False
    return True


def _write_red_flag(chain: dict) -> None:
    from app.ra.threshold_shares import _root_dir

    _root_dir().mkdir(parents=True, exist_ok=True)
    state = _read_sync_state()
    state.update(
        {
            "drift": True,
            "chain_fp_hex": chain["fp_hex"],
            "domain_fp_hex": read_domain_fp(),
            "chain_required": chain["required"],
            "drift_detected_ts": state.get("drift_detected_ts") or time.time(),
        }
    )
    _sync_state_path().write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


def sync_status() -> dict:
    """同步状态（治理大屏红牌数据源——live 对拍）。

    fake 档={"mode":"fake"}（大屏诚实降级同款）；真链档=对拍结果
    （synced/chain_fp/domain_fp/red_flag）。链不可达=synced None+error。"""
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
        return {"mode": "fake", "synced": None}
    try:
        chain = chain_owner_set()
    except SyncError as e:
        return {"mode": "real", "synced": None, "error": str(e)}
    domain = read_domain_fp()
    synced = domain is None or domain == chain["fp_hex"]
    return {
        "mode": "real",
        "synced": synced,
        "bound": domain is not None,
        "chain_fp_hex": chain["fp_hex"],
        "domain_fp_hex": domain,
        "chain_required": chain["required"],
        "chain_owner_count": len(chain["owners"]),
        "red_flag": bool(_read_sync_state().get("drift")) and not synced,
    }


def draft_reshare_proposal() -> dict:
    """自动起草 reshare 提案（只 propose 不 confirm/execute——confirm 与
    execute 保持人工，防事件注入 DoS）。幂等三重查重：
    ① PolicyRegistry version 已公示（本纪元已执行过）→ already_published；
    ② governor proposalOfCall 已有待决同调用提案 → already_pending；
    ③ sync_state 已记未决起草 → already_drafted。"""
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.governor import load_governor
    from app.chain.signer import TxSigner
    from app.crypto.sm3 import sm3_bytes
    from app.kms import chain_admin_tx_key
    from app.ra import threshold_shares as ts

    if not ts.is_initialized():
        raise SyncError("not_initialized", "门限根未初始化")
    meta = _root_meta()
    target_epoch = int(meta["epoch"]) + 1
    version = f"threshold-epoch-{target_epoch}"
    addresses = json.loads(_addr_path().read_text(encoding="utf-8"))
    admin = TxSigner(chain_admin_tx_key())
    client = ChainClient(rpc_url=_rpc_url(), from_addr=admin.address)
    gov = load_governor(client, addresses)
    pr = load_binding("PolicyRegistry", client, addresses["PolicyRegistry"]["address"])

    prev_hash, _ts0 = pr.call_fn("getPolicy", [version])
    if bytes(prev_hash).strip(b"\x00"):
        raise SyncError(
            "reshare_already_published",
            f"{version} 已公示（本纪元已执行过重分割）",
        )
    announcement = json.dumps(
        {
            "epoch": target_epoch,
            "pub_hex": meta["pub_hex"],
            "roles": meta["roles"],
            "threshold": meta["threshold"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    params_hash = sm3_bytes(announcement.encode("utf-8"))
    call_data = pr.encode_calldata("publishPolicy", [version, params_hash])
    chash = sm3_bytes(call_data)
    pending = int(gov.call_fn("proposalOfCall", [pr.address, chash])[0])
    if pending:
        return {"action": "already_pending", "proposal_id": pending, "version": version}
    r1 = gov.send_fn(
        admin, "propose", [pr.address, chash, f"threshold-reshare:epoch-{target_epoch}"]
    )
    proposed = [ev for ev in gov.decode_logs(r1) if ev["event"] == "Proposed"]
    if len(proposed) != 1:
        raise SyncError("draft_failed", f"Proposed 事件缺失/重复: {len(proposed)}")
    pid = int(proposed[0]["proposalId"])
    state = _read_sync_state()
    state.update(
        {
            "drift": True,
            "drafted_proposal_id": pid,
            "drafted_version": version,
            "drafted_ts": time.time(),
        }
    )
    _sync_state_path().write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"action": "drafted", "proposal_id": pid, "version": version}


def run_sync_check_once() -> dict:
    """watcher 一轮（daemon 线程周期调）：对拍→对齐零动作/漂移红牌+起草。"""
    try:
        chain = chain_owner_set()
    except SyncError as e:
        return {"action": "unavailable", "synced": None, "error": str(e)}
    domain = read_domain_fp()
    if domain is None:
        bind_domain_fp(chain["fp_hex"])
        return {"action": "bound", "synced": True, "fp_hex": chain["fp_hex"]}
    if domain == chain["fp_hex"]:
        state = _read_sync_state()
        if state.get("drift"):
            # 已对齐（重分割完成）——解除红牌+清起草账（下一漂移窗重新起草）
            state["drift"] = False
            state["resolved_ts"] = time.time()
            state.pop("drafted_proposal_id", None)
            state.pop("drafted_version", None)
            state.pop("drafted_ts", None)
            _sync_state_path().write_text(
                json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8"
            )
        return {"action": "ok", "synced": True}
    _write_red_flag(chain)
    # 幂等序：先查已起草账（本轮漂移窗内只起草一次），后起草
    if _read_sync_state().get("drafted_proposal_id"):
        return {"action": "already_drafted", "synced": False}
    try:
        draft = draft_reshare_proposal()
    except SyncError as e:
        if e.code == "reshare_already_published":
            return {"action": "already_published", "synced": False, "error": str(e)}
        return {"action": "draft_failed", "synced": False, "error": str(e)}
    # 起草账落盘（状态机归本函数——链写函数不承担副作用外的账目职责）
    state = _read_sync_state()
    state.update(
        {
            "drafted_proposal_id": draft.get("proposal_id"),
            "drafted_version": draft.get("version"),
            "drafted_ts": time.time(),
        }
    )
    _sync_state_path().write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"action": draft["action"], "synced": False, **draft}


def propose_and_reshare(gov=None, pr=None) -> dict:
    """⑤站三步提案+份额刷新的服务化（脚本/API 双消费）——幂等面在链上
    （PolicyRegistry version exists 拒重放——合约级幂等，不可重放同纪元）。

    返回对拍 dict（epoch/fp/公示行）。gov/pr 可注入（单测替位）。"""
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.governor import load_governor, run_proposal
    from app.chain.signer import TxSigner
    from app.crypto.sm3 import sm3_bytes
    from app.kms import chain_admin_tx_key, chain_ra_tx_key
    from app.ra import threshold_shares as ts

    if not ts.is_initialized():
        raise SyncError("not_initialized", "门限根未初始化（先 initialize_if_absent）")
    meta = _root_meta()
    old_epoch = int(meta["epoch"])
    target = old_epoch + 1
    version = f"threshold-epoch-{target}"
    addresses = json.loads(_addr_path().read_text(encoding="utf-8"))
    admin = TxSigner(chain_admin_tx_key())
    if gov is None or pr is None:
        client = ChainClient(rpc_url=_rpc_url(), from_addr=admin.address)
        gov = gov or load_governor(client, addresses)
        pr = pr or load_binding("PolicyRegistry", client, addresses["PolicyRegistry"]["address"])
    ra = TxSigner(chain_ra_tx_key())
    # 幂等预检（fail-closed：预检不过不发起任何写）
    prev_hash, _ts0 = pr.call_fn("getPolicy", [version])
    if bytes(prev_hash).strip(b"\x00"):
        raise SyncError("reshare_already_published", f"链上已有 {version} 公示行——本纪元不可重放")
    # owner-set 指纹=提案时点链读（执行窗漂移由 ceremonial_reshare 指纹门兜底）
    chain = chain_owner_set()
    fp = chain["fp_hex"]
    announcement = json.dumps(
        {
            "epoch": target,
            "pub_hex": meta["pub_hex"],
            "roles": meta["roles"],
            "threshold": meta["threshold"],
            "owner_set_fp": fp,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    params_hash = sm3_bytes(announcement.encode("utf-8"))
    description = f"threshold-reshare:epoch-{target}"
    r3 = run_proposal(gov, admin, ra, pr, "publishPolicy", [version, params_hash], description)
    published = [ev for ev in pr.decode_logs(r3) if ev["event"] == "PolicyPublished"]
    if len(published) != 1:
        raise SyncError("publish_failed", f"PolicyPublished 事件缺失/重复: {len(published)}")
    onchain_hash, onchain_ts = pr.call_fn("getPolicy", [version])
    if bytes(onchain_hash) != params_hash:
        raise SyncError("publish_mismatch", "getPolicy 对拍失败（paramsHash 不一致）")
    r = ts.ceremonial_reshare(gov_confirmed_epoch=target, owner_set_fp=fp)
    if r["epoch"] != target or r["pub_hex"] != meta["pub_hex"]:
        raise SyncError("reshare_mismatch", f"刷新对拍失败: {r}")
    return {
        "epoch": target,
        "prev_epoch": old_epoch,
        "pub_hex": r["pub_hex"],
        "owner_set_fp": fp,
        "version": version,
        "announce_ts": int(onchain_ts),
    }


def start_background_watcher(interval_s: float = 10.0) -> None:
    """真链档守护线程（create_app 挂载——同 event indexer 工艺，进程内幂等）。"""
    global _watcher_started
    if _watcher_started:
        return
    _watcher_started = True

    def loop() -> None:
        while True:
            try:
                r = run_sync_check_once()
                if r.get("action") not in ("ok", "bound", "already_drafted"):
                    print(f"[threshold-watcher] {r}", flush=True)
            except Exception as e:  # noqa: BLE001 —— 抖动下一轮重试
                print(f"[threshold-watcher] 轮询失败（下轮重试）: {e}", flush=True)
            time.sleep(interval_s)

    threading.Thread(target=loop, daemon=True, name="fz-threshold-watcher").start()


_watcher_started = False
