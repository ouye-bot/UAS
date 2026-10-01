"""B1 chain_smoke：四合约部署（--deploy）+六项自检（幂等默认模式）。

六项自检：
  ① 字节码对账：getCode(addr) == build/<name>.runtime.bin 逐字节一致
  ② 权限锁定：admin==部署者；ra/engine/auditor 回读正确
  ③ 权限负例矩阵：临时钥（secrets，用后即弃）跨域调用 → 回执 status!=0x0
  ④ 正路径全接口冒烟：各权限面全写接口+view 回读（幂等模式参数每轮随机）
  ⑤ 事件解码：decode_logs[0]["event"] 与预期事件名一致
  ⑥ 抢注负例：非 admin 调 setXxx 换钥 → revert

钥策略（B1-d3）：admin/ra/engine/auditor=确定性演示钥（SM3("FZ-CHAIN-SMOKE|role")
入 SM2 标量域——幂等锚非生产凭据，生产钥 B2 起 KMS 域派生）；攻击者=每轮 secrets。
上链以回执 status==0x0 为据（wait_receipt 内置断言+deploy 双断言）。

用法：
  python scripts/chain_smoke.py --deploy   # 部署+权限接线+地址轮换（retired 归档）+全自检
  python scripts/chain_smoke.py            # 既有地址幂等自检
退出码：0=全绿；1=任一失败（fail-closed，业务不得接线）。
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.chain.client import ChainClient  # noqa: E402
from app.chain.contracts import load_binding  # noqa: E402
from app.chain.signer import TxSigner  # noqa: E402
from app.crypto.sm2 import generate_keypair  # noqa: E402
from app.crypto.sm3 import sm3_bytes  # noqa: E402

BUILD_DIR = Path(__file__).resolve().parents[2] / "contracts" / "build"
ADDR_PATH = Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json"
RETIRED_PATH = ADDR_PATH.with_name(".chain_addresses.retired.json")
RPC = os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545")

CONTRACTS = ("IdentityRegistry", "PolicyRegistry", "FlightAuthRegistry", "TelemetryAnchor")

_checks = 0


def ok(label: str) -> None:
    global _checks
    _checks += 1
    print(f"  [OK] {label}")


def fail(label: str, detail: str = "") -> None:
    print(f"  [FAIL] {label} {detail}")
    raise SystemExit(1)


def expect(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        ok(label)
    else:
        fail(label, detail)


def demo_key(role: str) -> str:
    """确定性演示钥（B1-d3）：SM3("FZ-CHAIN-SMOKE|role") 入 SM2 标量域 [1,n-2]。

    幂等锚非生产凭据（旧系统 seed 纪律）；生产钥 B2 起 KMS 域派生。
    """
    from gmssl.sm2 import default_ecc_table

    n = int(default_ecc_table["n"], 16)
    d = int.from_bytes(sm3_bytes(f"FZ-CHAIN-SMOKE|{role}".encode()), "big") % (n - 2) + 1
    return format(d, "064x")


def deploy(client: ChainClient, signer: TxSigner, name: str) -> tuple[str, int]:
    """部署单合约：回执 status==0x0 + contractAddress 非空双断言。"""
    bin_hex = (BUILD_DIR / f"{name}.bin").read_text().strip().removeprefix("0x")
    from app.chain.contracts import _DEFAULT_GAS  # noqa: E402
    from app.chain.signer import UnsignedTx  # noqa: E402

    tx = UnsignedTx(
        randomid=signer.new_randomid(),
        gas_price=_DEFAULT_GAS,
        gas_limit=_DEFAULT_GAS,
        block_limit=client.block_limit(),
        to=b"",
        value=0,
        data=bytes.fromhex(bin_hex),
        fisco_chain_id=client.group_id,
        group_id=client.group_id,
    )
    txhash = client.send_raw_tx(signer.sign_tx(tx))
    receipt = client.wait_receipt(txhash, timeout_s=20.0)  # 内含 status!=0x0 即抛
    addr = receipt.get("contractAddress")
    if addr in ("", "0x", None):
        fail(f"{name} 部署失败（无 contractAddress）", str(receipt)[:200])
    return str(addr), int(receipt.get("blockNumber", "0x0"), 16)


def expect_revert(
    client: ChainClient, attacker: TxSigner, binding, fn: str, args: list, label: str
) -> None:
    """负例：跨域调用必须 revert（status!=0x0），非超时/异常。

    wait_receipt 内置 status!=0x0 即抛（正例保护）——负例走原始轮询。
    """
    from app.chain.contracts import _DEFAULT_GAS  # noqa: E402
    from app.chain.signer import UnsignedTx  # noqa: E402

    tx = UnsignedTx(
        randomid=attacker.new_randomid(),
        gas_price=_DEFAULT_GAS,
        gas_limit=_DEFAULT_GAS,
        block_limit=client.block_limit(),
        to=bytes.fromhex(binding.address.removeprefix("0x")),
        value=0,
        data=binding.encode_calldata(fn, args),
        fisco_chain_id=client.group_id,
        group_id=client.group_id,
    )
    txhash = client.send_raw_tx(attacker.sign_tx(tx))
    deadline = time.time() + 20.0
    receipt = None
    while time.time() < deadline:
        receipt = client.get_tx_receipt(txhash)
        if receipt is not None:
            break
        time.sleep(0.2)
    if receipt is None:
        fail(label, "回执超时（不可与 revert 混淆）")
    status = receipt.get("status")
    expect(status not in ("0x0", 0), label, f"status={status}（应 revert）")


def main() -> int:
    deploy_mode = "--deploy" in sys.argv
    admin_sk = os.environ.get("FZ_CHAIN_ADMIN_SK") or demo_key("admin")
    admin = TxSigner(admin_sk)
    # call 必须带有效 from（FISCO 2.x 零地址 from 静默返回空——旧系统 MEMORY 事实#1）
    client = ChainClient(rpc_url=RPC, from_addr=admin.address)
    print(f"== chain_smoke（{'部署+全自检' if deploy_mode else '既有地址幂等自检'}）==")
    print(f"  链版本: {client.client_version()}  块高: {client.block_number()}")

    ra = TxSigner(demo_key("ra"))
    engine = TxSigner(demo_key("engine"))
    auditor = TxSigner(demo_key("auditor"))

    if deploy_mode:
        if ADDR_PATH.exists():
            retired = json.loads(RETIRED_PATH.read_text()) if RETIRED_PATH.exists() else []
            retired.append({"retired_at": int(time.time()), **json.loads(ADDR_PATH.read_text())})
            RETIRED_PATH.write_text(json.dumps(retired, ensure_ascii=False, indent=2))
        addresses: dict[str, dict] = {}
        for name in CONTRACTS:
            addr, block = deploy(client, admin, name)
            addresses[name] = {"address": addr, "block": block}
            print(f"  部署 {name} → {addr} (块 {block})")
        ADDR_PATH.write_text(json.dumps(addresses, ensure_ascii=False, indent=2))
        # 权限接线（部署即治理仪式）：admin 设三权限域地址（B2/B4 正式钥经 setXxx 换钥）
        B0 = {name: load_binding(name, client, addresses[name]["address"]) for name in CONTRACTS}
        B0["IdentityRegistry"].send_fn(admin, "setRA", [ra.address])
        B0["IdentityRegistry"].send_fn(admin, "setAuditor", [auditor.address])
        B0["FlightAuthRegistry"].send_fn(admin, "setEngine", [engine.address])
        B0["TelemetryAnchor"].send_fn(admin, "setEngine", [engine.address])
        print("  权限接线：ra/engine/auditor 已设定")
    else:
        if not ADDR_PATH.exists():
            fail("地址文件缺失", f"先跑 --deploy：{ADDR_PATH}")
        addresses = json.loads(ADDR_PATH.read_text())

    B = {name: load_binding(name, client, addresses[name]["address"]) for name in CONTRACTS}

    # ===== ① 字节码对账 =====
    print("== ① 字节码对账 ==")
    for name in CONTRACTS:
        onchain = str(
            client.rpc("getCode", [client.group_id, addresses[name]["address"]])
        ).removeprefix("0x")
        runtime = (BUILD_DIR / f"{name}.runtime.bin").read_text().strip().removeprefix("0x")
        expect(
            onchain.lower() == runtime.lower(),
            f"{name} 字节码对账 getCode==runtime.bin",
            f"(链上 {len(onchain) // 2}B vs 本地 {len(runtime) // 2}B)",
        )

    # ===== ② 权限锁定 =====
    print("== ② 权限锁定 ==")
    expect(
        B["IdentityRegistry"].call_fn("admin", [])[0].lower() == admin.address.lower(),
        "Identity admin 锁定",
    )
    expect(
        B["IdentityRegistry"].call_fn("ra", [])[0].lower() == ra.address.lower(), "Identity ra 锁定"
    )
    expect(
        B["IdentityRegistry"].call_fn("auditor", [])[0].lower() == auditor.address.lower(),
        "Identity auditor 锁定",
    )
    expect(
        B["FlightAuthRegistry"].call_fn("engine", [])[0].lower() == engine.address.lower(),
        "FlightAuth engine 锁定",
    )
    expect(
        B["TelemetryAnchor"].call_fn("engine", [])[0].lower() == engine.address.lower(),
        "Telemetry engine 锁定",
    )

    # ===== ③ 权限负例矩阵（攻击者=每轮 secrets 临时钥）=====
    print("== ③ 权限负例矩阵 ==")
    a_priv, _ = generate_keypair()
    attacker = TxSigner(a_priv)
    expect_revert(
        client,
        attacker,
        B["IdentityRegistry"],
        "registerCommitment",
        [b"\x11" * 32, 1],
        "非 RA registerCommitment → revert",
    )
    expect_revert(
        client,
        attacker,
        B["IdentityRegistry"],
        "setRevocationRoot",
        [99, b"\x22" * 32],
        "非 RA setRevocationRoot → revert",
    )
    expect_revert(
        client,
        attacker,
        B["IdentityRegistry"],
        "logWarrant",
        [b"\x33" * 32, b"\x34" * 32],
        "非 Auditor logWarrant → revert",
    )
    expect_revert(
        client,
        attacker,
        B["PolicyRegistry"],
        "publishPolicy",
        ["evil", b"\x44" * 32],
        "非 Admin publishPolicy → revert",
    )
    expect_revert(
        client,
        attacker,
        B["FlightAuthRegistry"],
        "recordAuth",
        [b"\x55" * 32, b"\x56" * 16, 1, 120, 1, 2, b"\x58" * 32, b"\x59" * 32],
        "非 Engine recordAuth → revert",
    )
    expect_revert(
        client,
        attacker,
        B["TelemetryAnchor"],
        "anchorCheckpoint",
        [1, 1, b"\x66" * 32, b"\x67" * 4],
        "非 Engine anchorCheckpoint → revert",
    )

    # ===== ④ 正路径全接口冒烟（参数每轮随机=幂等）=====
    print("== ④ 正路径全接口 ==")
    rnd = secrets.token_bytes(32)
    cred_hash = sm3_bytes(b"smoke-cred" + rnd)
    r1 = B["IdentityRegistry"].send_fn(ra, "registerCommitment", [cred_hash, 1])
    ok("registerCommitment 上链（status==0x0）")
    status, kind, _ = B["IdentityRegistry"].call_fn("getCred", [cred_hash])
    expect(status == 1 and kind == 1, "getCred 回读 (有效,个人)")
    r2 = B["IdentityRegistry"].send_fn(ra, "setStatus", [cred_hash, 2])
    del r1, r2
    ok("setStatus(吊销) 上链")
    expect(
        B["IdentityRegistry"].call_fn("isRevoked", [cred_hash])[0] is True,
        "isRevoked=true（吊销即时可查）",
    )
    epoch_now = B["IdentityRegistry"].call_fn("revEpoch", [])[0]
    # 🔴 撤销根保存/恢复（阶段二修复——与 pinCircuit 保护同族：烟测随机根会毁掉
    # align_rev_root 仪式值 ⟹ 受理门控④全拒。测试后必须恢复进入时根
    # （epoch 顺延单调合法，根值回原——幂等烟测不破坏公示态）。
    root_saved = B["IdentityRegistry"].call_fn("revRoot", [])[0]
    r3 = B["IdentityRegistry"].send_fn(
        ra, "setRevocationRoot", [epoch_now + 1, sm3_bytes(b"smoke-root" + rnd)]
    )
    del r3
    ok(f"setRevocationRoot(纪元 {epoch_now + 1}) 上链")
    expect(
        B["IdentityRegistry"].call_fn("revEpoch", [])[0] == epoch_now + 1, "revEpoch 单调递增回读"
    )
    epoch_cur = B["IdentityRegistry"].call_fn("revEpoch", [])[0]
    B["IdentityRegistry"].send_fn(ra, "setRevocationRoot", [epoch_cur + 1, root_saved])
    ok(f"撤销根恢复（epoch {epoch_cur + 1}，公示值保护）")
    expect(
        B["IdentityRegistry"].call_fn("revRoot", [])[0] == root_saved, "revRoot 恢复回读一致"
    )
    warrant = sm3_bytes(b"smoke-warrant" + rnd)
    r4 = B["IdentityRegistry"].send_fn(auditor, "logWarrant", [warrant, sm3_bytes(b"scope" + rnd)])
    del r4
    ok("logWarrant 上链")
    expect(B["IdentityRegistry"].call_fn("warrants", [warrant])[0] is True, "warrants 在案回读")
    # B7：解锁留痕面（logWarrantUnlock onlyRA——RA 协作解锁的链上审计锚）
    cred_for_unlock = cred_hash
    r4b = B["IdentityRegistry"].send_fn(ra, "logWarrantUnlock", [warrant, cred_for_unlock])
    del r4b
    ok("logWarrantUnlock(RA) 上链")
    expect(
        B["IdentityRegistry"].call_fn("warrantUnlocks", [warrant])[0] is True,
        "warrantUnlocks 在案回读",
    )
    expect_revert(
        client,
        auditor,
        B["IdentityRegistry"],
        "logWarrantUnlock",
        [warrant, cred_for_unlock],
        "非 RA logWarrantUnlock → revert",
    )
    warrant_ghost = sm3_bytes(b"smoke-warrant-ghost" + rnd)
    expect_revert(
        client,
        ra,
        B["IdentityRegistry"],
        "logWarrantUnlock",
        [warrant_ghost, cred_for_unlock],
        "未在案令状 logWarrantUnlock → revert",
    )

    ver = f"smoke-{secrets.token_hex(4)}"
    params_hash = sm3_bytes(b"smoke-policy" + rnd)
    B["PolicyRegistry"].send_fn(admin, "publishPolicy", [ver, params_hash])
    ok("publishPolicy 上链")
    ph, _ts = B["PolicyRegistry"].call_fn("getPolicy", [ver])
    expect(ph.hex() == params_hash.hex(), "getPolicy 回读 paramsHash 一致")
    # pinCircuit 幂等保护（阶段一 D-Ⅰ-5）：已公示指纹不随机重设——防烟测毁掉
    # publish_pin 仪式值（未设置态才写入随机值覆盖接口路径）。
    cur_pin = bytes(B["PolicyRegistry"].call_fn("circuitPin", [])[0])
    if cur_pin == b"\x00" * 32:
        B["PolicyRegistry"].send_fn(admin, "pinCircuit", [sm3_bytes(b"smoke-pin" + rnd)])
        ok("pinCircuit 上链（未设置态——接口路径覆盖）")
    else:
        expect(
            B["PolicyRegistry"].call_fn("circuitPin", [])[0] == cur_pin,
            f"pinCircuit 已公示保护（不重设，值 {cur_pin.hex()[:16]}…）",
        )
    B["PolicyRegistry"].send_fn(admin, "setClassRule", [1, 120, 2])
    alt, lvl = B["PolicyRegistry"].call_fn("getClassRule", [1])
    expect(alt == 120 and lvl == 2, "getClassRule 回读 (120m, L2)")

    nonce = secrets.token_bytes(16)
    sub_cred = sm3_bytes(b"smoke-sub" + rnd)
    token_hash = sm3_bytes(b"smoke-token" + rnd)
    proof_digest = sm3_bytes(b"smoke-proof" + rnd)
    r5 = B["FlightAuthRegistry"].send_fn(
        engine,
        "recordAuth",
        [token_hash, nonce, 1, 120, 1000, 2000, sub_cred, proof_digest],
    )
    auth_id = B["FlightAuthRegistry"].call_fn("tokenAuthIds", [token_hash])[0]
    expect(auth_id >= 1, f"recordAuth 上链 authId={auth_id}")
    del r5
    expect(
        B["FlightAuthRegistry"].call_fn("nonceUsed", [nonce])[0] is True,
        "nonceUsed=true（recordAuth 即烧毁）",
    )
    expect_revert(
        client,
        engine,
        B["FlightAuthRegistry"],
        "recordAuth",
        [
            sm3_bytes(b"t2" + rnd),
            nonce,
            1,
            120,
            1,
            2,
            sm3_bytes(b"s2" + rnd),
            sm3_bytes(b"p2" + rnd),
        ],
        "同 nonce 重放 recordAuth → revert",
    )
    expect_revert(
        client,
        engine,
        B["FlightAuthRegistry"],
        "recordAuth",
        [
            sm3_bytes(b"t3" + rnd),
            secrets.token_bytes(16),
            1,
            120,
            1,
            2,
            sub_cred,
            sm3_bytes(b"p3" + rnd),
        ],
        "同 subCredHash 二次授权 → revert（子凭证一次性链级强制）",
    )
    expect_revert(
        client,
        engine,
        B["TelemetryAnchor"],
        "anchorCheckpoint",
        [auth_id, 2, b"\x77" * 32, b"\x78" * 4],
        "冷启动跳号 seq=2 → revert（须从 1 起）",
    )
    head1 = sm3_bytes(b"smoke-head1" + rnd)
    B["TelemetryAnchor"].send_fn(engine, "anchorCheckpoint", [auth_id, 1, head1, b"\x01\x02"])
    ok("anchorCheckpoint(seq=1) 上链")
    expect(
        B["TelemetryAnchor"].call_fn("verifyHead", [auth_id, head1])[0] is True, "verifyHead=true"
    )
    expect_revert(
        client,
        engine,
        B["TelemetryAnchor"],
        "anchorCheckpoint",
        [auth_id, 1, sm3_bytes(b"x" + rnd), b"\x01"],
        "seq 重放(1) → revert（非单调）",
    )
    head2 = sm3_bytes(b"smoke-head2" + rnd)
    B["TelemetryAnchor"].send_fn(engine, "anchorCheckpoint", [auth_id, 2, head2, b"\x03"])
    ok("anchorCheckpoint(seq=2) 上链")
    expect(B["TelemetryAnchor"].call_fn("latestSeq", [auth_id])[0] == 2, "latestSeq=2 回读")
    B["TelemetryAnchor"].send_fn(engine, "recordEvent", [auth_id, 1, sm3_bytes(b"evt" + rnd)])
    ok("recordEvent(围栏触发) 上链")
    B["FlightAuthRegistry"].send_fn(engine, "revokeAuth", [auth_id, 1])
    ok("revokeAuth 上链")
    got = B["FlightAuthRegistry"].call_fn("getAuth", [auth_id])
    expect(got[8] == 1, "getAuth status=已撤销 回读")
    expect(
        got[6].hex() == sub_cred.hex() and got[7].hex() == proof_digest.hex(),
        "getAuth subCredHash/proofDigest 回读一致（D17/D18 字段在链；snHash 已删=B3b-d6）",
    )

    # ===== ⑤ 事件解码 =====
    print("== ⑤ 事件解码 ==")
    ev_ver = f"smoke-ev-{secrets.token_hex(4)}"
    r6 = B["PolicyRegistry"].send_fn(admin, "publishPolicy", [ev_ver, params_hash])
    logs = B["PolicyRegistry"].decode_logs(r6)
    del r6
    expect(len(logs) >= 1 and logs[0]["event"] == "PolicyPublished", "PolicyPublished 事件解码一致")
    cred2 = sm3_bytes(b"smoke-cred-ev" + rnd)
    r7 = B["IdentityRegistry"].send_fn(ra, "registerCommitment", [cred2, 2])
    logs = B["IdentityRegistry"].decode_logs(r7)
    del r7
    expect(
        logs[0]["event"] == "CommitmentRegistered" and logs[0]["credKind"] == 2,
        "CommitmentRegistered 事件解码一致（credKind=机构）",
    )

    # ===== ⑥ 抢注负例 =====
    print("== ⑥ 抢注负例 ==")
    expect_revert(
        client,
        attacker,
        B["IdentityRegistry"],
        "setRA",
        [attacker.address],
        "非 admin setRA 抢注 → revert",
    )
    expect_revert(
        client,
        attacker,
        B["FlightAuthRegistry"],
        "setEngine",
        [attacker.address],
        "非 admin setEngine 抢注 → revert",
    )
    expect_revert(
        client,
        attacker,
        B["TelemetryAnchor"],
        "setEngine",
        [attacker.address],
        "非 admin setEngine(Telemetry) 抢注 → revert",
    )
    # admin 自身换钥合法路径不测（避免污染状态）

    print(f"== chain_smoke 全绿：{_checks} 项断言 [OK] ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
