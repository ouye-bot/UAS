"""B7 S4 场景：令状追溯真链端到端（验收门判决行——事件→个人全链留痕）。

流程：注册（通道②密文落库）→ 种子授权记录+违规事件（链上，engine 钥）→
审计台创建令状（logWarrant onlyAuditor）→ **无令状解锁负例（必拒）** →
RA 协作解锁（A3 通道② unwrap+logWarrantUnlock 留痕）→ 追溯视图链上回读对账。

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/scenario_S4.py
前置：WSL FISCO 链在线 + chain_smoke --deploy 已执行（.chain_addresses.json）
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.audit.models import Warrant as WarrantRow  # noqa: F401——建表先于 create_all
from app.chain.client import ChainClient
from app.chain.contracts import load_binding
from app.chain.signer import TxSigner
from app.crypto.sm2 import generate_keypair
from app.crypto.sm3 import sm3_bytes
from app.kms import chain_auditor_tx_key, chain_ra_tx_key, ra_signing_keypair
from app.ra.models import Base
from app.ra.service import ChainAnchor, RaDeps, RaService

RPC = os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545")
ADDR_PATH = Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json"

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


def _b32(v):
    return bytes.fromhex(str(v).removeprefix("0x")) if isinstance(v, str) else v


def main() -> int:
    import contextlib

    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    print("== S4 令状追溯：事件→个人 全链留痕（真链） ==")
    addresses = json.loads(ADDR_PATH.read_text())
    ra_signer = TxSigner(chain_ra_tx_key())
    auditor_signer = TxSigner(chain_auditor_tx_key())
    # engine 链钥（FlightAuth/Telemetry onlyEngine 写面——阶段一 D-Ⅰ-1 KMS 正式域）
    from app.kms import chain_engine_tx_key

    engine_signer = TxSigner(chain_engine_tx_key())
    client = ChainClient(rpc_url=RPC, from_addr=auditor_signer.address)
    ir = load_binding("IdentityRegistry", client, addresses["IdentityRegistry"]["address"])
    fa = load_binding("FlightAuthRegistry", client, addresses["FlightAuthRegistry"]["address"])
    ta = load_binding("TelemetryAnchor", client, addresses["TelemetryAnchor"]["address"])

    # 角色接线检查（演示钥同派生域）
    for role, want, label in [
        ("ra", ra_signer.address, "合约 ra==RA 链钥"),
        ("auditor", auditor_signer.address, "合约 auditor==审计链钥"),
    ]:
        got = ir.call_fn(role, [])[0]
        expect(got.lower() == want.lower(), label, f"链上 {got} vs 本地 {want}")

    td = tempfile.mkdtemp(prefix="fz_s4_")
    with contextlib.ExitStack() as stack:
        stack.callback(lambda: __import__("shutil").rmtree(td, ignore_errors=True))
        eng = create_engine(f"sqlite:///{td}/s4.db")
        Base.metadata.create_all(eng)

        def ra_anchor_call(fn: str, args: list) -> None:
            m = {
                "register_commitment": "registerCommitment",
                "set_status": "setStatus",
                "set_revocation_root": "setRevocationRoot",
                "log_warrant_unlock": "logWarrantUnlock",
            }
            ir.send_fn(ra_signer, m[fn], [_b32(a) for a in args])

        s = sessionmaker(bind=eng, expire_on_commit=False)()
        ra_priv, ra_pub = ra_signing_keypair()
        ra = RaService(
            s,
            RaDeps(
                ra_priv_hex=ra_priv,
                ra_pub_hex=ra_pub,
                anchor=ChainAnchor(
                    call=ra_anchor_call,
                    warrant_on_chain=lambda wh: bool(ir.call_fn("warrants", [wh])[0]),
                ),
            ),
        )

        # ① 注册（通道②密文落库）
        _up = generate_keypair()[1]
        reg = ra.register(
            username="s4-pilot",
            id_number="110101199001011234",
            cert_level=3,
            sn="FZ-SN-S4",
            user_pub_hex=_up,
        )
        mch = reg["master_cred_hash_hex"]
        s.commit()
        ok(f"注册（通道②密文落库，masterCredHash={mch[:16]}…）")

        # ② 种子授权记录+违规事件（engine 写面——S2 围栏触发形态）
        rnd = secrets.token_bytes(8)
        fa.send_fn(
            engine_signer,
            "recordAuth",
            [
                sm3_bytes(b"s4-token" + rnd),
                secrets.token_bytes(16),
                1,
                120,
                1700000000,
                1700003600,
                sm3_bytes(b"s4-sub" + rnd),
                sm3_bytes(b"s4-proof" + rnd),
            ],
        )
        auth_id = int(fa.call_fn("authCount", [])[0])
        ok(f"授权记录上链（authId={auth_id}，proofDigest 在案=D17）")
        ev_hash = sm3_bytes(b"s4-event" + rnd)
        ta.send_fn(engine_signer, "recordEvent", [auth_id, 1, ev_hash])
        ok("违规事件上链（eventType=1 围栏触发——追溯起点）")
        head_seed = sm3_bytes(b"s4-head" + rnd)
        ta.send_fn(engine_signer, "anchorCheckpoint", [auth_id, 1, head_seed, b"s4-sig"])
        ok("检查点锚定上链（seq=1——留痕面）")

        # ③ 审计台创建令状（onlyAuditor 上链）
        from app.audit.router import _real_chain_anchor
        from app.audit.service import AuditDeps, AuditService

        # 真链审计锚复用（含追溯视图链上回读 trace_auth）
        audit = AuditService(
            s,
            AuditDeps(
                anchor=_real_chain_anchor(),
                ra_unlock=lambda wh_hex, c_hex: ra.warrant_unlock(
                    warrant_hash_hex=wh_hex, master_cred_hash_hex=c_hex
                ),
                audit_token="s4-script",
            ),
        )
        w = audit.create_warrant(
            case_no=f"S4-{secrets.token_hex(4)}",
            legal_basis_hash_hex=sm3_bytes(b"s4-law").hex(),
            target_auth_id=auth_id,
            note="S2 围栏触发事件追溯",
        )
        wh = w["warrant_hash_hex"]
        expect(
            bool(ir.call_fn("warrants", [_b32(wh)])[0]) is True, "令状上链在案回读（WarrantLogged）"
        )
        expect(len(s.scalars(select(WarrantRow)).all()) == 1, "令状登记面落库（append-only）")

        # ④ 无令状解锁负例（验收门：必拒）
        ghost = sm3_bytes(b"s4-ghost-warrant" + rnd).hex()
        try:
            ra.warrant_unlock(warrant_hash_hex=ghost, master_cred_hash_hex=mch)
            expect(False, "无令状解锁必须拒绝", "异常未抛出")
        except Exception as e:  # noqa: BLE001
            expect(
                "warrant_not_found" in str(e) or "令状" in str(e),
                f"无令状解锁拒绝（{str(e)[:44]}…）",
            )

        # ⑤ RA 协作解锁（unwrap 实名映射+解锁留痕 onlyRA 一次性）
        out = audit.unlock(warrant_hash_hex=wh, master_cred_hash_hex=mch)
        expect(out["unlocked"]["username"] == "s4-pilot", "解锁面==注册实名（通道② unwrap）")
        expect(out["unlocked"]["id_number"] == "110101199001011234", "身份证号回读一致")
        expect(
            bool(ir.call_fn("warrantUnlocks", [_b32(wh)])[0]) is True,
            "解锁留痕上链在案回读（WarrantUnlockLogged）",
        )

        # ⑥ 重复解锁负例（一次性——链级 require）
        try:
            ir.send_fn(ra_signer, "logWarrantUnlock", [_b32(wh), _b32(mch)])
            expect(False, "重复解锁留痕必须链级 revert", "revert 未发生")
        except Exception:  # noqa: BLE001
            expect(True, "重复解锁留痕链级 revert（unlock already logged）")

        # ⑦ 追溯视图：链是留痕单一事实源
        tr = audit.trace(warrant_hash_hex=wh)
        rec = tr["chain_trace"]["auth_record"]
        expect(
            rec is not None and int(rec["status"]) == 0,
            "授权记录链上回读（authId 贯穿，status=0 有效）",
        )
        expect(
            rec["proof_digest"] == sm3_bytes(b"s4-proof" + rnd).hex(),
            "proofDigest 回读一致（可审计签发）",
        )
        cps = tr["chain_trace"]["checkpoints"]
        expect(
            bool(cps) and cps[0]["chain_head"] == head_seed.hex(),
            "检查点留痕回读（chain_head 一致）",
        )
        expect(tr["warrant"]["unlocked"]["id_number"] == "110101199001011234", "追溯=事件→个人闭环")

        print(f"\n== S4 全绿：{_checks} 项断言 [OK] —— 追溯判决行（事件→个人全链留痕）==")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
