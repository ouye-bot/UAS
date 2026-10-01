"""B2 真链端到端：RA 仪式全流程 × IdentityRegistry 真链回执对账（验收门判决行）。

流程：register（链上 registerCommitment status==0x0+getCred 回读有效）
→ revoke（setStatus 回执+setRevocationRoot 回执+链上 revEpoch/revRoot 回读
   ==本地 SMT(吊销集)）→ snapshot 根==链上根 → 被吊销句柄 isRevoked==true。

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/smoke_ra_chain.py
退出码 0=全绿；1=失败。上链以回执 status==0x0 为据（send_fn 内置断言）。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.chain.client import ChainClient  # noqa: E402
from app.chain.contracts import load_binding  # noqa: E402
from app.chain.signer import TxSigner  # noqa: E402
from app.crypto.sm2 import generate_keypair  # noqa: E402
from app.kms import chain_ra_tx_key, ra_signing_keypair  # noqa: E402
from app.ra.models import Base  # noqa: E402
from app.ra.service import ChainAnchor, RaDeps, RaService  # noqa: E402
from app.ra.smt import smt_root  # noqa: E402

RPC = "http://127.0.0.1:8545"
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


def main() -> int:
    import tempfile

    print("== smoke_ra_chain：RA 仪式×IdentityRegistry 真链对账 ==")
    ra_priv, ra_pub = ra_signing_keypair()
    ra_signer = TxSigner(chain_ra_tx_key())  # 链交易钥（B1 域）与凭证签名钥（KMS 域）分离
    client = ChainClient(rpc_url=RPC, from_addr=ra_signer.address)
    identity_addr = json_load_identity()
    binding = load_binding("IdentityRegistry", client, identity_addr)

    # RA 演示钥接线检查：合约 ra 必须==本进程 RA 钥地址（B1 部署时同派生钥）
    chain_ra = binding.call_fn("ra", [])[0]
    expect(
        chain_ra.lower() == ra_signer.address.lower(),
        f"合约 ra 权限==RA 签名钥（{ra_signer.address[:10]}…）",
        f"链上 {chain_ra} vs 本地 {ra_signer.address}",
    )

    # 独立临时库（不污染开发库）
    td = tempfile.mkdtemp(prefix="fz_ra_smoke_")
    import contextlib

    with contextlib.ExitStack() as stack:
        stack.callback(lambda: __import__("shutil").rmtree(td, ignore_errors=True))
        eng = create_engine(f"sqlite:///{td}/smoke.db")
        Base.metadata.create_all(eng)
        s = sessionmaker(bind=eng, expire_on_commit=False)()

        calls: list[tuple[str, list]] = []

        def anchor_call(fn: str, args: list) -> None:
            """真链锚：直调 IdentityRegistry 并记录（回执 status==0x0 内置断言）。"""
            m = {
                "register_commitment": "registerCommitment",
                "set_status": "setStatus",
                "set_revocation_root": "setRevocationRoot",
            }

            def _b32(v):
                return bytes.fromhex(str(v).removeprefix("0x")) if isinstance(v, str) else v

            from app.chain.contracts import _DEFAULT_GAS
            from app.chain.signer import UnsignedTx

            tx = UnsignedTx(
                randomid=ra_signer.new_randomid(),
                gas_price=_DEFAULT_GAS,
                gas_limit=_DEFAULT_GAS,
                block_limit=client.block_limit(),
                to=bytes.fromhex(binding.address[2:]),
                value=0,
                data=binding.encode_calldata(m[fn], [_b32(a) for a in args]),
                fisco_chain_id=client.group_id,
                group_id=client.group_id,
            )
            txhash = client.send_raw_tx(ra_signer.sign_tx(tx))
            import time as _t

            deadline = _t.time() + 20
            r = None
            while _t.time() < deadline:
                r = client.get_tx_receipt(txhash)
                if r:
                    break
                _t.sleep(0.3)
            if not r or str(r.get("status")) != "0x0":
                st = r.get("status") if r else None
                out = str(r.get("output"))[:100] if r else ""
                print(f"  [revert 详情] fn={fn} status={st} output={out}")
                raise SystemExit(f"链上 {m[fn]} 失败")
            calls.append((fn, args))

        svc = RaService(
            s,
            RaDeps(
                ra_priv_hex=ra_priv,
                ra_pub_hex=ra_pub,
                anchor=ChainAnchor(call=anchor_call),
                chain_rev_epoch=lambda: int(binding.call_fn("revEpoch", [])[0]),
            ),
        )
        _, user_pub = generate_keypair()
        reg = svc.register(
            username="smoke-chain",
            id_number="11010119900307999X",
            cert_level=3,
            sn="UAS-SN-SMOKE-01",
            user_pub_hex=user_pub,
        )
        status, kind, _ = binding.call_fn("getCred", [bytes.fromhex(reg["master_cred_hash_hex"])])
        expect(status == 1 and kind == 1, "registerCommitment 真链回读 (有效,个人)")

        svc.revoke(master_cred_hash_hex=reg["master_cred_hash_hex"], reason="smoke 撤销")
        expect(
            binding.call_fn("isRevoked", [bytes.fromhex(reg["master_cred_hash_hex"])])[0] is True,
            "isRevoked=true（吊销即时链上可查）",
        )
        epoch = binding.call_fn("revEpoch", [])[0]
        root = binding.call_fn("revRoot", [])[0]
        expect(epoch >= 1, f"链上 revEpoch 单调（本次={epoch}，D14 纪元公示）")
        local_root = smt_root([bytes.fromhex(reg["master_cred_hash_hex"])])
        root_bytes = (
            bytes(root) if not isinstance(root, str) else bytes.fromhex(root.removeprefix("0x"))
        )
        expect(
            root_bytes == local_root,
            "链上 revRoot==本地 SMT(吊销集) 根逐字节一致",
            f"链上 {root_bytes.hex()[:20]}… vs 本地 {local_root.hex()[:20]}…",
        )

        s.commit()
        s.close()
        eng.dispose()

    print(f"== smoke_ra_chain 全绿：{_checks} 项断言 [OK] ==")
    return 0


def json_load_identity() -> str:
    import json

    p = Path(__file__).resolve().parents[2] / "contracts" / ".chain_addresses.json"
    return json.loads(p.read_text())["IdentityRegistry"]["address"]


if __name__ == "__main__":
    sys.exit(main())
