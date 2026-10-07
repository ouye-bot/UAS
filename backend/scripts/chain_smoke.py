"""B1 chain_smoke：五合约部署（--deploy，含 AdminGovernor 多签+时间锁）+七项自检。

七项自检：
  ① 字节码对账：getCode(addr) == build/<name>.runtime.bin 逐字节一致
  ② 权限锁定：四合约 admin==AdminGovernor（批 3.2 治理面移交）；governor
    owners=[admin,RA,auditor]/required=2/delay==FZ_GOVERNOR_DELAY_S；
    ra/engine/auditor 业务角色回读正确（读面零变化）
  ③ 权限负例矩阵：临时钥（secrets，用后即弃）跨域调用 → 回执 status!=0x0
  ④ 正路径全接口冒烟：各权限面全写接口+view 回读（幂等模式参数每轮随机）——
    admin 面（publishPolicy/pinCircuit/setClassRule）一律经 governor 三步仪式
    （propose→confirm→延迟到期 execute，app/chain/governor.py 单源）
  ⑤ 事件解码：decode_logs[0]["event"] 与预期事件名一致
  ⑥ 抢注负例：非 admin（=governor）调 setXxx/transferAdmin 换钥 → revert；
    非 owner 调 governor.propose/confirm → revert
  ⑦ governor 生命周期矩阵（批 3.2 新增，只增不减）：
    非 owner propose 拒 / 非 owner confirm 拒 / 单 confirm 不执行（quorum 未达）
    / 未到期不执行（timelock）/ calldata 篡改 execute 拒 / 双确认到期执行成功
    / 执行后重放拒 / 重复 confirm 拒 / cancel 后执行与再确认拒

钥策略（B1-d3 + 批 3.2）：链上交易钥 env 注入优先（FZ_CHAIN_ADMIN_TX_SK/
FZ_CHAIN_RA_TX_SK/FZ_CHAIN_ENGINE_TX_SK/FZ_CHAIN_AUDITOR_TX_SK——与 .local_env
/kms 同口径，部署与运行时同钥），缺省回落确定性演示钥 SM3("FZ-CHAIN-SMOKE|role")
入 SM2 标量域（幂等锚非生产凭据）；攻击者=每轮 secrets。
上链以回执 status==0x0 为据（wait_receipt 内置断言+deploy 双断言）。

用法：
  python scripts/chain_smoke.py --deploy   # 部署（governor+四合约+移交）+权限接线
  #                                        +地址轮换（retired 归档）+全自检
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
from app.chain.governor import (  # noqa: E402
    GOVERNOR_NAME,
    ctor_args,
    eta_unix_seconds,
    governor_delay_s,
    load_governor,
    run_proposal,
)
from app.chain.signer import TxSigner  # noqa: E402
from app.crypto.sm2 import generate_keypair  # noqa: E402
from app.crypto.sm3 import sm3_bytes  # noqa: E402
from app.kms import (  # noqa: E402
    chain_admin_tx_key,
    chain_auditor_tx_key,
    chain_engine_tx_key,
    chain_ra_tx_key,
)

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


def deploy(
    client: ChainClient, signer: TxSigner, name: str, ctor_data: bytes = b""
) -> tuple[str, int, str]:
    """部署单合约：回执 status==0x0 + contractAddress 非空双断言。返回 (地址, 块, tx)。"""
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
        data=bytes.fromhex(bin_hex) + ctor_data,
        fisco_chain_id=client.group_id,
        group_id=client.group_id,
    )
    txhash = client.send_raw_tx(signer.sign_tx(tx))
    receipt = client.wait_receipt(txhash, timeout_s=20.0)  # 内含 status!=0x0 即抛
    addr = receipt.get("contractAddress")
    if addr in ("", "0x", None):
        fail(f"{name} 部署失败（无 contractAddress）", str(receipt)[:200])
    return str(addr), int(receipt.get("blockNumber", "0x0"), 16), str(txhash)


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
    # 链上交易钥（批 3.2：env 注入优先——.local_env 随机钥与运行时 kms 同口径）
    admin = TxSigner(chain_admin_tx_key())
    # call 必须带有效 from（FISCO 2.x 零地址 from 静默返回空——旧系统 MEMORY 事实#1）
    client = ChainClient(rpc_url=RPC, from_addr=admin.address)
    print(f"== chain_smoke（{'部署+全自检' if deploy_mode else '既有地址幂等自检'}）==")
    print(f"  链版本: {client.client_version()}  块高: {client.block_number()}")

    ra = TxSigner(chain_ra_tx_key())
    engine = TxSigner(chain_engine_tx_key())
    auditor = TxSigner(chain_auditor_tx_key())
    print(
        "  钥指纹: admin="
        + admin.address
        + " ra="
        + ra.address
        + " engine="
        + engine.address
        + " auditor="
        + auditor.address
    )
    delay_s = governor_delay_s()

    if deploy_mode:
        if ADDR_PATH.exists():
            retired = json.loads(RETIRED_PATH.read_text()) if RETIRED_PATH.exists() else []
            retired.append({"retired_at": int(time.time()), **json.loads(ADDR_PATH.read_text())})
            RETIRED_PATH.write_text(json.dumps(retired, ensure_ascii=False, indent=2))
        addresses: dict[str, dict] = {}
        # 治理合约先部署（owners=[admin,RA,auditor]，required=2，delay=FZ_GOVERNOR_DELAY_S——
        # 缺省 10s 保测试性；生产应调大，见 AdminGovernor.sol 头注）
        gov_addr, gov_block, gov_tx = deploy(
            client,
            admin,
            GOVERNOR_NAME,
            ctor_args([admin.address, ra.address, auditor.address], 2, delay_s),
        )
        addresses[GOVERNOR_NAME] = {"address": gov_addr, "block": gov_block}
        print(
            f"  部署 {GOVERNOR_NAME}(required=2, delay={delay_s}s)"
            f" → {gov_addr} (块 {gov_block}, tx {gov_tx})"
        )
        for name in CONTRACTS:
            addr, block, tx = deploy(client, admin, name)
            addresses[name] = {"address": addr, "block": block}
            print(f"  部署 {name} → {addr} (块 {block}, tx {tx})")
        # 权限接线（业务角色不变——RA/engine/auditor 直属各合约，不经 governor）：
        B0 = {name: load_binding(name, client, addresses[name]["address"]) for name in CONTRACTS}
        B0["IdentityRegistry"].send_fn(admin, "setRA", [ra.address])
        B0["IdentityRegistry"].send_fn(admin, "setAuditor", [auditor.address])
        B0["FlightAuthRegistry"].send_fn(admin, "setEngine", [engine.address])
        B0["TelemetryAnchor"].send_fn(admin, "setEngine", [engine.address])
        print("  权限接线：ra/engine/auditor 已设定")
        # 管理面移交（批 3.2 治理仪式第一步=部署时一次性 transferAdmin）：
        # 此后 onlyAdmin 面（政策/指纹公示+角色授予）唯 governor 可写
        for name in CONTRACTS:
            B0[name].send_fn(admin, "transferAdmin", [gov_addr])
        print(f"  管理面移交：四合约 admin → {GOVERNOR_NAME}({gov_addr})")
        ADDR_PATH.write_text(json.dumps(addresses, ensure_ascii=False, indent=2))
    else:
        if not ADDR_PATH.exists():
            fail("地址文件缺失", f"先跑 --deploy：{ADDR_PATH}")
        addresses = json.loads(ADDR_PATH.read_text())

    B = {name: load_binding(name, client, addresses[name]["address"]) for name in CONTRACTS}
    GOV = load_governor(client, addresses)

    # ===== ① 字节码对账 =====
    print("== ① 字节码对账 ==")
    for name in CONTRACTS + (GOVERNOR_NAME,):
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
    for name in CONTRACTS:
        expect(
            B[name].call_fn("admin", [])[0].lower() == GOV.address.lower(),
            f"{name} admin==AdminGovernor（治理面移交锁定）",
        )
    expect(
        GOV.call_fn("required", [])[0] == 2
        and GOV.call_fn("delay", [])[0] == delay_s,
        f"governor 参数锁定 (required=2, delay={delay_s}s)",
    )
    owners_on = [str(GOV.call_fn("owners", [i])[0]).lower() for i in range(3)]
    expect(
        owners_on == [admin.address.lower(), ra.address.lower(), auditor.address.lower()],
        "governor owners=[admin,RA,auditor] 三钥注入一致",
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
        "非 Admin(=governor) publishPolicy → revert",
    )
    expect_revert(
        client,
        attacker,
        B["FlightAuthRegistry"],
        "recordAuth",
        [b"\x55" * 32, b"\x56" * 16, 1, 120, 1, 2, b"\x58" * 32, b"\x59" * 32, 1],
        "非 Engine recordAuth → revert",
    )
    expect_revert(
        client,
        attacker,
        B["FlightAuthRegistry"],
        "consumeSortie",
        [1],
        "非 Engine consumeSortie → revert",
    )
    expect_revert(
        client,
        attacker,
        B["TelemetryAnchor"],
        "anchorCheckpoint",
        [1, 1, b"\x66" * 32, b"\x67" * 4],
        "非 Engine anchorCheckpoint → revert",
    )

    # ===== ④ 正路径全接口冒烟（参数每轮随机=幂等；admin 面经 governor 三步仪式）=====
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
    # admin 面三写接口（publishPolicy/pinCircuit/setClassRule）均走 governor 三步仪式
    # （propose(admin)→confirm(ra)→延迟到期 execute；2/3 多签+时间锁，批 3.2）
    r_pol = run_proposal(GOV, admin, ra, B["PolicyRegistry"], "publishPolicy", [ver, params_hash],
                         "smoke: publishPolicy")
    ok("publishPolicy 上链（governor 三步仪式）")
    ph, _ts = B["PolicyRegistry"].call_fn("getPolicy", [ver])
    expect(ph.hex() == params_hash.hex(), "getPolicy 回读 paramsHash 一致")
    del r_pol
    # pinCircuit 幂等保护（阶段一 D-Ⅰ-5）：已公示指纹不随机重设——防烟测毁掉
    # publish_pin 仪式值（未设置态才写入随机值覆盖接口路径）。
    cur_pin = bytes(B["PolicyRegistry"].call_fn("circuitPin", [])[0])
    if cur_pin == b"\x00" * 32:
        run_proposal(GOV, admin, ra, B["PolicyRegistry"], "pinCircuit",
                     [sm3_bytes(b"smoke-pin" + rnd)], "smoke: pinCircuit")
        ok("pinCircuit 上链（未设置态——接口路径覆盖，governor 仪式）")
    else:
        expect(
            B["PolicyRegistry"].call_fn("circuitPin", [])[0] == cur_pin,
            f"pinCircuit 已公示保护（不重设，值 {cur_pin.hex()[:16]}…）",
        )
    run_proposal(GOV, admin, ra, B["PolicyRegistry"], "setClassRule", [1, 120, 2],
                 "smoke: setClassRule")
    alt, lvl = B["PolicyRegistry"].call_fn("getClassRule", [1])
    expect(alt == 120 and lvl == 2, "getClassRule 回读 (120m, L2)")

    nonce = secrets.token_bytes(16)
    sub_cred = sm3_bytes(b"smoke-sub" + rnd)
    token_hash = sm3_bytes(b"smoke-token" + rnd)
    proof_digest = sm3_bytes(b"smoke-proof" + rnd)
    r5 = B["FlightAuthRegistry"].send_fn(
        engine,
        "recordAuth",
        [token_hash, nonce, 1, 120, 1000, 2000, sub_cred, proof_digest, 3],
    )
    auth_id = B["FlightAuthRegistry"].call_fn("tokenAuthIds", [token_hash])[0]
    expect(auth_id >= 1, f"recordAuth 上链 authId={auth_id}")
    del r5
    expect(
        B["FlightAuthRegistry"].call_fn("nonceUsed", [nonce])[0] is True,
        "nonceUsed=true（recordAuth 即烧毁）",
    )
    # 授权包配额制（2026-10-06）：sorties=3 登记 → remaining=3；consumeSortie
    # 逐架次递减；第 4 发 quota exhausted revert；revoke 清零。
    expect(
        B["FlightAuthRegistry"].call_fn("remainingOf", [auth_id])[0] == 3,
        "remainingOf=3（配额登记回读）",
    )
    for i in (2, 1, 0):
        B["FlightAuthRegistry"].send_fn(engine, "consumeSortie", [auth_id])
        expect(
            B["FlightAuthRegistry"].call_fn("remainingOf", [auth_id])[0] == i,
            f"consumeSortie 递减回读 remaining={i}",
        )
    expect_revert(
        client,
        engine,
        B["FlightAuthRegistry"],
        "consumeSortie",
        [auth_id],
        "配额耗尽（remaining=0）consumeSortie → revert",
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
            1,
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
            1,
        ],
        "同 subCredHash 二次授权 → revert（子凭证一次性链级强制）",
    )
    expect_revert(
        client,
        engine,
        B["FlightAuthRegistry"],
        "recordAuth",
        [
            sm3_bytes(b"t4" + rnd),
            secrets.token_bytes(16),
            1,
            120,
            1,
            2,
            sm3_bytes(b"s4" + rnd),
            sm3_bytes(b"p4" + rnd),
            0,
        ],
        "sorties=0 越界 recordAuth → revert（配额 1~5）",
    )
    expect_revert(
        client,
        engine,
        B["FlightAuthRegistry"],
        "recordAuth",
        [
            sm3_bytes(b"t5" + rnd),
            secrets.token_bytes(16),
            1,
            120,
            1,
            2,
            sm3_bytes(b"s5" + rnd),
            sm3_bytes(b"p5" + rnd),
            6,
        ],
        "sorties=6 越界 recordAuth → revert（配额 1~5）",
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
    expect(got[11] == 0, "getAuth remaining=0 回读（撤销清零配额）")
    expect(
        got[6].hex() == sub_cred.hex() and got[7].hex() == proof_digest.hex(),
        "getAuth subCredHash/proofDigest 回读一致（D17/D18 字段在链；snHash 已删=B3b-d6）",
    )

    # ===== ⑤ 事件解码（publishPolicy 经 governor 仪式——目标合约事件随 execute 回执）=====
    print("== ⑤ 事件解码 ==")
    ev_ver = f"smoke-ev-{secrets.token_hex(4)}"
    r6 = run_proposal(GOV, admin, ra, B["PolicyRegistry"], "publishPolicy",
                      [ev_ver, params_hash], "smoke: publishPolicy(ev)")
    logs = B["PolicyRegistry"].decode_logs(r6)
    expect(len(logs) >= 1 and logs[0]["event"] == "PolicyPublished", "PolicyPublished 事件解码一致")
    cred2 = sm3_bytes(b"smoke-cred-ev" + rnd)
    r7 = B["IdentityRegistry"].send_fn(ra, "registerCommitment", [cred2, 2])
    logs = B["IdentityRegistry"].decode_logs(r7)
    del r7
    expect(
        logs[0]["event"] == "CommitmentRegistered" and logs[0]["credKind"] == 2,
        "CommitmentRegistered 事件解码一致（credKind=机构）",
    )
    del r6

    # ===== ⑥ 抢注负例 =====
    print("== ⑥ 抢注负例 ==")
    expect_revert(
        client,
        attacker,
        B["IdentityRegistry"],
        "setRA",
        [attacker.address],
        "非 admin(=governor) setRA 抢注 → revert",
    )
    expect_revert(
        client,
        attacker,
        B["FlightAuthRegistry"],
        "setEngine",
        [attacker.address],
        "非 admin(=governor) setEngine 抢注 → revert",
    )
    expect_revert(
        client,
        attacker,
        B["TelemetryAnchor"],
        "setEngine",
        [attacker.address],
        "非 admin(=governor) setEngine(Telemetry) 抢注 → revert",
    )
    expect_revert(
        client,
        attacker,
        B["PolicyRegistry"],
        "transferAdmin",
        [attacker.address],
        "非 admin transferAdmin 抢治理面 → revert",
    )
    # 非 owner 调 governor 提案/确认面 → revert（governor 自身权限锁）
    expect_revert(
        client,
        attacker,
        GOV,
        "propose",
        [B["PolicyRegistry"].address, b"\x88" * 32, "evil"],
        "非 owner governor.propose → revert",
    )
    expect_revert(
        client,
        attacker,
        GOV,
        "confirm",
        [0],
        "非 owner governor.confirm → revert",
    )
    # admin 自身换钥合法路径不测（避免污染状态；合法 transferAdmin 仅在部署仪式执行）

    # ===== ⑦ governor 生命周期矩阵（批 3.2 新增——只增不减）=====
    print("== ⑦ governor 生命周期矩阵 ==")
    gov_pr = B["PolicyRegistry"]

    def _propose(class_id: int, alt: int, lvl: int, proposer):
        """propose 一笔 setClassRule 提案，返回 (proposalId, calldata)。"""
        call_data = gov_pr.encode_calldata("setClassRule", [class_id, alt, lvl])
        r = GOV.send_fn(proposer, "propose", [gov_pr.address, sm3_bytes(call_data), "smoke:⑦"])
        props = [ev for ev in GOV.decode_logs(r) if ev["event"] == "Proposed"]
        expect(len(props) == 1, "⑦ Proposed 事件解码一致")
        return int(props[0]["proposalId"]), call_data

    # ⑦-a 非 owner propose（owner 三钥外）→ 拒
    expect_revert(
        client,
        attacker,
        GOV,
        "propose",
        [gov_pr.address, b"\x89" * 32, "evil"],
        "⑦ 非 owner propose → revert",
    )
    # ⑦-b/c 单 confirm 不执行：propose(admin)+仅 admin 一票（1/2 未达法定人数）→ execute 拒
    pid, call_data = _propose(3, 150, 2, admin)
    GOV.send_fn(admin, "confirm", [pid])
    _t1, _c1, _d1, eta1, conf1, st1 = GOV.call_fn("getProposal", [pid])
    expect(int(conf1) == 1 and int(st1) == 0, "⑦ 单票态回读（confirmations=1, 仍 Active）")
    expect_revert(
        client,
        admin,
        GOV,
        "execute",
        [gov_pr.address, 0, call_data],
        "⑦ 单 confirm（quorum 未达）execute → revert",
    )
    # ⑦-d 非 owner confirm → 拒
    expect_revert(
        client,
        attacker,
        GOV,
        "confirm",
        [pid],
        "⑦ 非 owner confirm → revert",
    )
    # ⑦-e 第二票（ra confirm）达 required=2 → Queued 态+eta 锁定
    GOV.send_fn(ra, "confirm", [pid])
    _t, _ch, _d, eta, confirmations, status = GOV.call_fn("getProposal", [pid])
    expect(
        int(confirmations) == 2 and int(status) == 1 and int(eta) > 0,
        "⑦ 双票 Queued 态锁定（confirmations=2, eta 已定）",
    )
    # ⑦-f 未到期（timelock）execute → 拒
    expect_revert(
        client,
        admin,
        GOV,
        "execute",
        [gov_pr.address, 0, call_data],
        "⑦ 未到期（timelock）execute → revert",
    )
    # ⑦-g calldata 篡改 execute → 拒（同目标不同参数=不同调用指纹，无此提案）
    tampered = gov_pr.encode_calldata("setClassRule", [3, 151, 2])
    expect_revert(
        client,
        admin,
        GOV,
        "execute",
        [gov_pr.address, 0, tampered],
        "⑦ calldata 篡改 execute → revert",
    )
    # ⑦-h 双票到期 execute 成功（时间锁过期后；链时间戳=毫秒——eta 换算见 governor.eta_unix_seconds）
    wait_s = eta_unix_seconds(int(eta)) - time.time() + 1.5
    if wait_s > 0:
        print(f"  （⑦ 等待时间锁到期 {wait_s:.1f}s——delay={GOV.call_fn('delay', [])[0]}s）")
        time.sleep(wait_s)
    r_exec = GOV.send_fn(admin, "execute", [gov_pr.address, 0, call_data])
    exec_logs = [ev for ev in GOV.decode_logs(r_exec) if ev["event"] == "Executed"]
    expect(len(exec_logs) == 1, "⑦ Executed 事件解码一致")
    alt3, lvl3 = gov_pr.call_fn("getClassRule", [3])
    expect(alt3 == 150 and lvl3 == 2, "⑦ 双票到期执行生效 getClassRule(3)=(150m, L2)")
    # ⑦-i 执行后重放 execute → 拒（待决索引已清除）
    expect_revert(
        client,
        admin,
        GOV,
        "execute",
        [gov_pr.address, 0, call_data],
        "⑦ 执行后重放 execute → revert",
    )
    # ⑦-j 重复 confirm → 拒（owner 各一票，不可重复）
    pid2, _cd2 = _propose(3, 153, 2, admin)
    GOV.send_fn(ra, "confirm", [pid2])
    expect_revert(
        client,
        ra,
        GOV,
        "confirm",
        [pid2],
        "⑦ 同 owner 重复 confirm → revert",
    )
    # ⑦-k cancel 生命周期：取消后 execute 拒、再 confirm 拒
    GOV.send_fn(ra, "cancel", [pid2])
    cancels = GOV.call_fn("getProposal", [pid2])
    expect(int(cancels[5]) == 3, "⑦ cancel 后状态=Cancelled 回读")
    expect_revert(
        client,
        admin,
        GOV,
        "execute",
        [gov_pr.address, 0, gov_pr.encode_calldata("setClassRule", [3, 153, 2])],
        "⑦ cancel 后 execute → revert",
    )
    expect_revert(
        client,
        admin,
        GOV,
        "confirm",
        [pid2],
        "⑦ cancel 后再 confirm → revert",
    )

    print(f"== chain_smoke 全绿：{_checks} 项断言 [OK] ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
