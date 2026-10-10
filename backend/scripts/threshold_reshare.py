"""⑤站门限份额刷新仪式（proactive re-share × 治理 k-of-n 联动）。

治理语义（任务书钉定）：re-share 是治理面动作——governor 提案
description=『threshold-reshare:epoch-N』，calldata=PolicyRegistry.publishPolicy
("threshold-epoch-N", SM3(元数据))——链上公示行=仪式公示面（合约 "version
exists" 幂等拒=同纪元不可重放；currentVersion 指针零 off-chain 消费者，
公示大屏逐版本扫描对多版本鲁棒）；execute 回执取证后 backend 侧执行真正的
份额刷新（ceremonial_reshare：三域密封件换纪元重封——**D_pub 不变、根钥 d
全程不重组**，δ(0)=0 随机增项+拉格朗日换基，存量 v5 信封零影响）。

用法：cd uas/backend && python scripts/threshold_reshare.py
前置：真链在线（scripts/chain_nodes_up.sh）+ threshold_root 已初始化（epoch≥1）
+链上交易钥 env（.local_env 同口径——demo 缺省派生亦可，production 档必须注入）。
owner 增删触发的漂移检测/红牌/自动起草=watcher（app.ra.threshold_sync，
1.3 件②）；本脚本=人工/定时驱动的完整仪式（提案→execute→re-share 一气呵成）；
API 面=POST /admin/threshold/reshare（同 propose_and_reshare 服务函数）。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.chain.client import ChainClient  # noqa: E402
from app.chain.contracts import load_binding  # noqa: E402
from app.chain.governor import load_governor, run_proposal  # noqa: E402
from app.chain.signer import TxSigner  # noqa: E402
from app.crypto.sm3 import sm3_bytes  # noqa: E402
from app.kms import chain_admin_tx_key, chain_ra_tx_key  # noqa: E402
from app.ra import threshold_shares as ts  # noqa: E402

RPC = "http://127.0.0.1:8545"
ADDR_PATH = Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json"

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


def main() -> int:
    t0 = time.time()
    print("== ⑤站门限份额刷新仪式（proactive re-share × governor k-of-n）==")

    addresses = json.loads(ADDR_PATH.read_text(encoding="utf-8"))
    admin = TxSigner(chain_admin_tx_key())
    ra = TxSigner(chain_ra_tx_key())
    client = ChainClient(rpc_url=RPC, from_addr=admin.address)
    gov = load_governor(client, addresses)
    pr = load_binding("PolicyRegistry", client, addresses["PolicyRegistry"]["address"])
    print(
        f"  链块高: {client.block_number()}｜proposer=admin({admin.address[:10]}…)"
        f" confirmer=ra({ra.address[:10]}…)"
    )
    expect(True, "governor/PolicyRegistry 装载+链连通")

    # ---- ① 读门限根现状（仪式对象面）----
    if not ts.is_initialized():
        raise SystemExit("[仪式] threshold_root 未初始化——先由注册路径 initialize_if_absent 自举")
    meta = json.loads((ts._root_dir() / "root.json").read_text(encoding="utf-8"))
    old_epoch = int(meta["epoch"])
    target = old_epoch + 1
    pub_before = meta["pub_hex"]
    print(f"  现状: epoch={old_epoch} threshold={meta['threshold']} D_pub={pub_before[:20]}…")
    expect(True, "门限根在案（初始化态）")

    # ---- ② 治理提案面：description=threshold-reshare:epoch-N ----
    version = f"threshold-epoch-{target}"
    description = f"threshold-reshare:epoch-{target}"
    # owner-set 指纹（1.3 件①）：提案时点链读——携入仪式指纹门（执行窗漂移
    # 即拒 fail-closed）+公告元数据（链上公示行含 fp=第三方可独立对拍）
    from app.ra.threshold_sync import chain_owner_set

    chain = chain_owner_set()
    owner_fp = chain["fp_hex"]
    announcement = json.dumps(
        {
            "epoch": target,
            "pub_hex": pub_before,
            "roles": meta["roles"],
            "threshold": meta["threshold"],
            "owner_set_fp": owner_fp,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    params_hash = sm3_bytes(announcement.encode("utf-8"))
    # 幂等预检：version exists 幂等拒=同纪元不可重放（诚实中止，不做任何写；
    # 链读异常=自然中止=fail-closed——预检不过不发起提案）
    prev_hash, _prev_ts = pr.call_fn("getPolicy", [version])
    if bytes(prev_hash).strip(b"\x00"):
        raise SystemExit(
            f"[仪式] 链上已有 {version} 公示行——本纪元仪式不可重放（中止，零写面）"
        )
    expect(True, f"幂等预检：{version} 未发布（提案可发起）")

    # ---- ③ governor 三步仪式：propose→confirm×2→eta 到期 execute ----
    print(f"  发起治理提案：description=『{description}』 target=PolicyRegistry.publishPolicy")
    r3 = run_proposal(gov, admin, ra, pr, "publishPolicy", [version, params_hash], description)
    published = [ev for ev in pr.decode_logs(r3) if ev["event"] == "PolicyPublished"]
    expect(len(published) == 1, "execute 回执含 PolicyPublished 事件（目标合约公示行落地）",
           f"events={[ev['event'] for ev in pr.decode_logs(r3)]}")
    # ---- ④ 链上对拍：公示行 paramsHash=本地元数据 SM3 ----
    onchain_hash, onchain_ts = pr.call_fn("getPolicy", [version])
    expect(bytes(onchain_hash) == params_hash, "getPolicy 对拍：paramsHash=SM3(元数据) 逐字一致")
    expect(int(onchain_ts) > 0, "公示行时间戳在案")
    print(
        f"  公示行: version={version} paramsHash=0x{params_hash.hex()[:16]}… ts={int(onchain_ts)}"
    )

    # ---- ⑤ backend 侧执行份额刷新（纪元门+owner-set 指纹门 fail-closed）----
    r = ts.ceremonial_reshare(gov_confirmed_epoch=target, owner_set_fp=owner_fp)
    expect(
        r["epoch"] == target and r["prev_epoch"] == old_epoch,
        f"份额刷新完成：纪元 {old_epoch}→{target}",
        f"r={r}",
    )
    expect(r["pub_hex"] == pub_before, "D_pub 逐字不变（存量 v5 信封零影响）")
    meta_after = json.loads((ts._root_dir() / "root.json").read_text(encoding="utf-8"))
    expect(
        int(meta_after["epoch"]) == target and meta_after["pub_hex"] == pub_before,
        "root.json 纪元/公钥面落盘对拍",
    )
    for role in ("admin", "ra", "auditor"):
        audit_text = ts._audit_path(role).read_text(encoding="utf-8")
        rows = [json.loads(x) for x in audit_text.splitlines()]
        expect(
            rows[-1]["action"] == "reshare" and rows[-1]["to_epoch"] == target,
            f"域审计行在案：{role}（reshare→epoch {target}）",
        )

    print(f"\n== 份额刷新仪式全绿：{_checks} 断言 [OK]（{time.time()-t0:.1f}s）==")
    print(
        f"    纪元 {old_epoch}→{target}｜D_pub 不变｜旧份额值+旧密封钥已作废"
        f"｜治理提案=『{description}』已 execute 公示"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
