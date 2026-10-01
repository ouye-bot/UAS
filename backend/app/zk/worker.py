"""ZK 验证 worker（B4-T3）：轮询 pending→zkc verify→判决件归档→令牌签发。

验证语义（D17 可审计签发）：
- zkc verify exit 0=证明有效（电路内全量强制：验签/承诺/范围门/有效期/绑定/SMT）
- 判决件（proof/verdict/spec）按 application 归档可下载——proofDigest=SM3(proof)
- 链上 recordAuth（tokenHash+proofDigest+subCredHash——D17/D18）+ burnNonce

令牌（B4-d3/d7）：{authId, plan_hash, alt_max, t_start, t_end, nonce,
policy_version}+Sig_engine——零设备信息（设备绑定由证明内 sn_h 等值钉承担）。
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.authz.models import Application, AuthRecord, Receipt
from app.authz.policy import POLICY_VERSION, get_rule
from app.authz.service import (
    build_token,
    seal_receipt,
    sign_token,
    token_hash,
)
from app.crypto.sm3 import sm3_bytes
from app.obs import inc, observe, set_gauge


class WorkerDeps:
    """链上写面与 zkc 环境（测试替身位）。"""

    def __init__(self) -> None:
        self.zksvc_dir = os.environ.get("FZ_ZKSVC_DIR", "")

    def zkc_verify(self, case_dir: str, expected: dict) -> tuple[int, str]:
        """实例驱动验证（R1-1a）：zkc verify-instances——服务端零秘密（spec 不上路）。"""
        exe = os.path.join(self.zksvc_dir, "target", "release", "zkc.exe")
        if not os.path.exists(exe):
            return (1, f"zkc 不存在: {exe}")
        env = dict(os.environ)
        env["FZ_ZK_ALLOW_AUTH"] = "1"
        # canonical 电路参照=JobSpec 形态（verify-instances 按 JobSpec 解析装配，
        # 只取 info 结构；黄金向量文件是见证向量源非 JobSpec——R1 收口修正：
        # 旧默认指向 auth_golden_vector.json 会在 serde 解析处必炸 missing field）。
        env.setdefault(
            "FZ_AUTH_CANONICAL_SPEC",
            os.path.join(self.zksvc_dir, "tests", "auth_canonical_spec.json"),
        )
        # 期望值写入验证方私有位置（2026-09-28 安全深检 B-P2 根修）：原写进
        # case 目录（证明者域）——同目录写入者可替换期望值绕过最后一道实例
        # 核对。改 tempfile（验证方独占，用毕即焚）；case 目录的 expected.json
        # 是 W-8 复验材料下载面（内容同源，见 :561 归档），与消费路径分离。
        import tempfile as _tf

        fd, expected_path = _tf.mkstemp(prefix="fz-expected-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(expected, f)
        try:
            proc = subprocess.run(
                [
                    exe,
                    "verify-instances",
                    "--instances",
                    os.path.join(case_dir, "instances.json"),
                    "--proof",
                    os.path.join(case_dir, "proof.bin"),
                    "--vp",
                    os.path.join(case_dir, "verifier_param.bin"),
                    "--expected",
                    expected_path,
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=_verify_timeout_s(),
            )
        finally:
            try:
                os.unlink(expected_path)
            except OSError:
                pass
        return (proc.returncode, (proc.stdout + proc.stderr)[-2000:])

    def next_auth_id(self, *, after_auth_id: int = 0) -> int:
        """authId 预分配（阶段一根修：令牌 authId 与链上分配一致性）。

        真链=authCount()+1（recordAuth 前读取；单 worker 进程=engine 唯一写面，
        预测错位由调用侧 fail-closed 捕获）；fake=计数播种（库内 max 单调）。
        """
        if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
            return max(int(getattr(self, "_fake_auth_seq", 0)), int(after_auth_id)) + 1
        fa = self._flight_auth_binding()
        return int(fa.call_fn("authCount", [])[0]) + 1

    def chain_record_auth(
        self,
        *,
        token_hash_hex: str,
        nonce_hex: str,
        class_id: int,
        alt_max: int,
        t_start: int,
        t_end: int,
        sub_cred_hash_hex: str,
        proof_digest_hex: str,
        after_auth_id: int = 0,
    ) -> tuple[int, str]:
        """链上 recordAuth+burnNonce（engine 交易钥）。返回 (authId, tx)。

        fake 模式（FZ_CHAIN_ANCHOR=fake）：本地 authId 计数替身（授权登记镜像
        auth_records 表仍完整落库——追溯/令牌面语义不变）；计数以调用方传入的
        库内现况 max(auth_id) 播种（R1 收口修正：进程内计数不落库 ⟹ 重启后
        与持久库唯一键撞车）。
        真链模式（阶段一 D-Ⅰ-2）：FlightAuthRegistry.recordAuth 发送（args 与
        B1 烟测同构）→ authId 从 AuthRecorded 事件解出（无事件=fail-closed
        异常禁吞）；nonce 由合约 recordAuth 内部即烧毁（usedNonces）。
        """
        if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
            n = max(int(getattr(self, "_fake_auth_seq", 0)), int(after_auth_id)) + 1
            self._fake_auth_seq = n
            return (n, "fake")
        fa = self._flight_auth_binding()
        receipt = fa.send_fn(
            self._engine_signer,
            "recordAuth",
            [
                bytes.fromhex(token_hash_hex),
                bytes.fromhex(nonce_hex),
                class_id,
                alt_max,  # meters（单位契约：政策/令牌/链 altMaxM/固件同单位）
                t_start,
                t_end,
                bytes.fromhex(sub_cred_hash_hex),
                bytes.fromhex(proof_digest_hex),
            ],
        )
        for ev in fa.decode_logs(receipt):
            if ev["event"] == "AuthRecorded":
                return (int(ev["authId"]), str(receipt.get("transactionHash", "")))
        raise RuntimeError(
            f"recordAuth 回执无 AuthRecorded 事件（fail-closed）: {str(receipt)[:160]}"
        )

    def chain_burn_nonce(self, *, nonce_hex: str) -> str:
        """链上 burnNonce（四写面完备性接线 D-Ⅰ-3；产品调用点=运维/演示位——
        recordAuth 已内含烧毁，失败路径不烧=诚实重试友好，见实施计划拍板）。"""
        fa = self._flight_auth_binding()
        receipt = fa.send_fn(self._engine_signer, "burnNonce", [bytes.fromhex(nonce_hex)])
        return str(receipt.get("transactionHash", ""))

    def _flight_auth_binding(self):
        """FlightAuthRegistry binding（进程内惰性缓存——worker 长循环复用）。"""
        cached = getattr(self, "_fa_binding", None)
        if cached is not None:
            return cached
        import json
        from pathlib import Path

        from app.chain.client import ChainClient
        from app.chain.contracts import load_binding
        from app.chain.signer import TxSigner
        from app.kms import chain_engine_tx_key

        addr = json.loads(
            (
                Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
            ).read_text()
        )
        signer = TxSigner(chain_engine_tx_key())
        http = getattr(self, "_chain_http", None)  # 测试注入位（MockTransport）
        client = ChainClient(
            rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
            from_addr=signer.address,
            http=http,
        )
        self._engine_signer = signer
        self._fa_binding = load_binding(
            "FlightAuthRegistry", client, addr["FlightAuthRegistry"]["address"]
        )
        return self._fa_binding

    def _identity_binding(self):
        """IdentityRegistry binding（进程内惰性缓存——撤销公示回读 A-P2-3）。"""
        cached = getattr(self, "_ir_binding", None)
        if cached is not None:
            return cached
        import json
        from pathlib import Path

        from app.chain.client import ChainClient
        from app.chain.contracts import load_binding
        from app.chain.signer import TxSigner
        from app.kms import chain_ra_tx_key

        addr = json.loads(
            (
                Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
            ).read_text()
        )
        signer = TxSigner(chain_ra_tx_key())  # 只读视图（from 须有效地址——同 authz 路由）
        http = getattr(self, "_chain_http", None)
        client = ChainClient(
            rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
            from_addr=signer.address,
            http=http,
        )
        self._ir_binding = load_binding(
            "IdentityRegistry", client, addr["IdentityRegistry"]["address"]
        )
        return self._ir_binding

    def chain_rev_root_now(self) -> tuple[int, str]:
        """撤销公示当前值（IdentityRegistry.revEpoch/revRoot——TOCTOU 复查源）。"""
        ir = self._identity_binding()
        epoch = int(ir.call_fn("revEpoch", [])[0])
        root = ir.call_fn("revRoot", [])[0]
        return (epoch, root.hex() if hasattr(root, "hex") else str(root))


def _db_max_auth_id(session: Session) -> int:
    """库内现况 max(auth_id)（fake 计数播种——持久库跨进程/跨重启单调）。"""
    return int(session.scalar(select(func.max(AuthRecord.auth_id))) or 0)


def verdict_dir() -> Path:
    d = Path(os.environ.get("FZ_ZK_CASES_DIR", "/tmp/fz-zk-cases")) / "verdicts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _pending_gauge(session: Session) -> None:
    """pending 深度即时量（/metrics 抓取口径——排水滞后告警输入）。"""
    from sqlalchemy import func as _f

    try:
        n = session.scalar(
            select(_f.count()).select_from(Application).where(Application.status == "pending")
        )
        set_gauge("fz_worker_pending", None, float(n or 0))
    except Exception:  # noqa: BLE001  指标失败不阻塞业务
        pass


def _max_attempts() -> int:
    """瞬时失败重试上限（链抖动类临时错误——证明无效不在此轴，直接终态）。"""
    return int(os.environ.get("FZ_WORKER_MAX_ATTEMPTS", "3"))


def _verify_timeout_s() -> int:
    """zkc verify 子进程超时（与 subprocess.run timeout 同源）。"""
    return int(os.environ.get("FZ_WORKER_VERIFY_TIMEOUT_S", "600"))


def _lease_seconds() -> int:
    """认领租约秒数：locked_at 超此限视为 worker 孤儿（崩溃），可被接手。

    R3-1.1（评审 P1-1）：租约必须 ≥2×verify 超时——旧值恰等于 600s，verify
    耗时逼近上限时租约先行过期被他人认领，先到者 recordAuth 成功后后来者把
    approved 翻案为 rejected（生产档多 worker 不安全）。"""
    return int(os.environ.get("FZ_WORKER_LEASE_S", str(2 * _verify_timeout_s())))


def _claimable():
    import datetime as dt

    cutoff = dt.datetime.utcnow() - dt.timedelta(seconds=_lease_seconds())
    return (
        Application.status == "pending",
        or_(
            Application.locked_by.is_(None),
            Application.locked_at.is_(None),
            Application.locked_at < cutoff,
        ),
    )


def _claim_pending(session: Session, worker_id: str, limit: int = 4) -> list:
    """认领一批 pending（P0-2 队列语义）。

    两步乐观认领（方言可移植）：候选 id 选出后条件 UPDATE 抢租约，以 RETURNING
    行数裁决归属——两 worker 同时候选同一行时仅一方 rowcount>0，无双处理。
    PG 可换 FOR UPDATE SKIP LOCKED 优化争用窗口（毫秒级，当前规模不必要）。
    """
    import datetime as dt

    candidates = session.scalars(select(Application.id).where(*_claimable()).limit(limit)).all()
    if not candidates:
        return []
    claimed = (
        session.execute(
            update(Application)
            .where(Application.id.in_(candidates), *_claimable())
            .values(locked_by=worker_id, locked_at=dt.datetime.utcnow())
            .returning(Application.id)
        )
        .scalars()
        .all()
    )
    session.commit()
    if not claimed:
        return []
    return session.scalars(select(Application).where(Application.id.in_(claimed))).all()


def _reconcile_burned_pending(session: Session, deps: WorkerDeps) -> int:
    """跨重启对账（R3-1 收尾，评审 P2-7）：进程崩溃窗内 recordAuth 可能已
    落地而库态仍 pending——重启后盲重试必撞 0x16。启动时扫描：nonce 已烧的
    pending 申请诚实拒绝（链上孤儿授权=赛后对账工具挂账），防误导性
    transient x3。返回对账条数。fake 模式跳过。"""
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
        return 0
    rows = session.scalars(select(Application).where(Application.status == "pending")).all()
    n = 0
    for row in rows:
        if _nonce_burned(deps, row.nonce_hex):
            row.status = "rejected"
            row.reject_reason = (
                "nonce_conflict: 跨重启对账——nonce 已被消耗（疑似崩溃窗孤儿授权），"
                "请换 nonce 重新出证"
            )[:200]
            r = session.get(Receipt, row.receipt_id)
            if r is not None and r.status != "ready":
                r.status = "failed"
            row.locked_by = None
            row.locked_at = None
            n += 1
    if n:
        session.commit()
    return n


def process_pending(session: Session, deps: WorkerDeps, limit: int = 4) -> dict:
    """一轮排水：认领→verify→approved(令牌+链)/rejected；瞬时异常→重试（P0-2）。"""
    rows = _claim_pending(session, f"pid-{os.getpid()}", limit)
    _pending_gauge(session)
    stats = {"processed": 0, "approved": 0, "rejected": 0, "retried": 0}
    for row in rows:
        stats["processed"] += 1
        try:
            stats = _process_one(session, deps, row, stats)
        except Exception as e:  # noqa: BLE001  瞬时错误轴：链写/文件系统/子进程崩溃
            session.rollback()
            row = session.get(Application, row.id)
            row.attempts = (row.attempts or 0) + 1
            if row.attempts >= _max_attempts():
                if _set_terminal(
                    session,
                    row,
                    "rejected",
                    f"transient x{row.attempts}: {e}"[:200],
                    receipt_failed=True,
                ):
                    stats["rejected"] += 1
                else:
                    stats["retried"] += 1  # 他人已接手——不翻案
            else:
                stats["retried"] += 1
            # 释放租约（重试态可被任何 worker 立即接手；终态同清）
            row.locked_by = None
            row.locked_at = None
            session.commit()
    return stats


class NonceConsumedPermanent(Exception):
    """nonce 已被链上消耗且非本申请令牌——永久冲突，重试无意义（R2-c）。"""


def _nonce_burned(deps: WorkerDeps, nonce_hex: str) -> bool | None:
    """链上 nonce 烧毁视图；查询失败返回 None（链不可用——调用方按原异常处理）。"""
    try:
        fa = deps._flight_auth_binding()
        return bool(fa.call_fn("nonceUsed", [bytes.fromhex(nonce_hex)])[0])
    except Exception:  # noqa: BLE001 恢复探针自身失败=链不可用
        return None


def _recover_landed_auth(deps: WorkerDeps, token_hash_hex: str, nonce_hex: str) -> int | None:
    """R2-c 恢复路径（2026-09-24 链不稳定窗实测教训）：recordAuth 首次发送可能
    **已上链**而回执读取失败（WSL 链濒死窗口实测：attempt1 落地烧毁 nonce、
    回执超时误判瞬时，重试全撞 0x16 误拒）。

    判据=nonce 已烧 ∧ tokenAuthIds 命中本令牌哈希 ⟹ 交易已落地，返回 authId
    供调用方按已记录继续；nonce 未烧/查询失败/非本方令牌 ⟹ None（调用方按
    原异常或永久冲突处理）。"""
    try:
        fa = deps._flight_auth_binding()
        if not bool(fa.call_fn("nonceUsed", [bytes.fromhex(nonce_hex)])[0]):
            return None
        ids = fa.call_fn("tokenAuthIds", [bytes.fromhex(token_hash_hex)])
        auth_id = int(ids[0]) if ids and ids[0] is not None else 0
        return auth_id if auth_id > 0 else None
    except Exception:  # noqa: BLE001
        return None


def _set_terminal(
    session: Session,
    row: Application,
    status: str,
    reason: str | None = None,
    receipt_failed: bool = False,
) -> bool:
    """终态守卫（R3-1.1，评审 P1-1 竞态）：条件 UPDATE 原子裁决——仅 pending
    可入终态。租约过期被他 worker 认领后，先到者的迟到写入不得把 approved
    翻案为 rejected；回执仅在未 ready 时置 failed（ready 已下发不回收）。
    返回 False=该行已被他人终态化（调用方静默让位，不计本 worker 统计）。"""
    from sqlalchemy import update as _u

    vals: dict = {"status": status, "locked_by": None, "locked_at": None}
    if reason is not None:
        vals["reject_reason"] = reason
    rc = session.execute(
        _u(Application)
        .where(Application.id == row.id, Application.status == "pending")
        .values(**vals)
    ).rowcount
    session.commit()
    if not rc:
        return False
    if receipt_failed:
        r = session.get(Receipt, row.receipt_id)
        if r is not None and r.status != "ready":
            r.status = "failed"
            session.commit()
    return True


def _process_one(session: Session, deps: WorkerDeps, row: Application, stats: dict) -> dict:
    """单申请处理（verify→终态；由 process_pending 的认领/重试框架调用）。"""
    from app.authz.service import binding_challenge, binding_pred_id

    # R3-1 收尾（评审 P2-4）：策略规则单源 get_rule——旧特判 class∈{0,1} else 0
    # 在政策扩表后 ⟹ 期望 θ=0 ≠ 实例 22 ⟹ 白跑 20s 验证后假拒
    required_level = get_rule(row.class_id)[1]
    expected = {
        "e_hex": row.e_hex,
        "challenge_hex": binding_challenge(row.plan_hash_hex, row.nonce_hex),
        "pred_id": binding_pred_id(
            row.plan_hash_hex,
            row.nonce_hex,
            row.policy_version or POLICY_VERSION,
        ),
        "t_epoch": row.t_start,
        "required_level": required_level,
        "class_id": row.class_id,
        "smt_root_hex": row.rev_root_hex,
    }
    case_dir = os.path.dirname(row.proof_path) or "."
    _t0 = time.perf_counter()
    rc, log = deps.zkc_verify(case_dir, expected)
    verify_s = round(time.perf_counter() - _t0, 2)
    observe("fz_verify_seconds", verify_s, {"profile": "auth"})
    proof_digest = sm3_bytes(Path(row.proof_path).read_bytes()).hex()
    if rc != 0:
        if _set_terminal(
            session, row, "rejected", f"zkc verify exit {rc}: {log[:160]}", receipt_failed=True
        ):
            stats["rejected"] += 1
        return stats
    alt_max, _req = get_rule(row.class_id)
    # 撤销 TOCTOU 复查（R4 第二批 A-P2-3）：受理核根（门控④）与 recordAuth 之间
    # 存在验证窗（zkc verify 分钟级）——窗内吊销不拦截则旧根证明仍被 approved
    # （「撤销即时」的残余窗口）。recordAuth 前链上复查一次公示根；更迭=终态
    # 拒绝（申请人刷新见证重新出证）；链不可达=异常自然走瞬时重试轴。
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") != "fake":
        _epoch_now, root_now = deps.chain_rev_root_now()
        if root_now != row.rev_root_hex:
            if _set_terminal(
                session,
                row,
                "rejected",
                "rev_root_moved: 撤销根在验证窗内更迭（吊销已生效）——请刷新见证重新出证",
                receipt_failed=True,
            ):
                stats["rejected"] += 1
            return stats
    # 时间窗（申请时申报——预授权窗语义）
    # 授权窗=受理面核验过的申请窗（R1：instances[21]=t_start 已由 gate 逐位核对）
    t_start = row.t_start
    t_end = row.t_end
    # B-P2-6 根修（R4 第二批）：authId 预测临界区互斥——令牌内嵌 authId 先铸后链
    # （链在 recordAuth 按 tokenHash 顺序分配），并发排水下无锁必错位；错位后
    # 「按实际值放行」=锚定串号到他人授权（record_lock 模块 docstring 定谳）。
    # 互斥后预测恒中；mismatch 仅剩 engine 唯一写面被进程组外破——保持拒绝。
    from app.zk.record_lock import record_auth_lock

    with record_auth_lock():
        # authId 预分配→一次铸正式令牌（阶段一根修：链上 tokenHash=SM3(正式令牌)，
        # 与判决件/落库/闸门键 tokenAuthIds 同源——旧序前体(authId=0)哈希上链，
        # 链上键与飞手实际令牌断链，真链对账首跑即暴露）
        predicted = deps.next_auth_id(after_auth_id=_db_max_auth_id(session))
        body = build_token(
            auth_id=predicted,
            plan_hash_hex=row.plan_hash_hex,
            alt_max=alt_max,
            t_start=t_start,
            t_end=t_end,
            nonce_hex=row.nonce_hex,
            policy_version=POLICY_VERSION,
        )
        sig = sign_token(body)
        th = token_hash(body)
        try:
            auth_id, tx = deps.chain_record_auth(
                token_hash_hex=th,
                nonce_hex=row.nonce_hex,
                class_id=row.class_id,
                alt_max=alt_max,
                t_start=t_start,
                t_end=t_end,
                sub_cred_hash_hex=row.sub_cred_hash_hex,
                proof_digest_hex=proof_digest,
                after_auth_id=_db_max_auth_id(session),
            )
        except Exception as ce:
            # R2-c 恢复序（先恢复、再分类、最后原样上抛）：
            # ① 首次发送可能已落地（回执读取撞链不稳窗口）⟹ 按已记录继续；
            # ② nonce 已烧但非本方 ⟹ 永久冲突，立即拒绝（重试无意义）；
            # ③ nonce 未烧/探针失败 ⟹ 瞬时，原样上抛走既有重试轴。
            recovered = _recover_landed_auth(deps, th, row.nonce_hex)
            if recovered is not None:
                auth_id, tx = recovered, None
            else:
                burned = _nonce_burned(deps, row.nonce_hex)
                if burned:
                    reason = (
                        f"nonce_conflict: 链上 nonce 已被消耗且非本申请令牌——"
                        f"请换 nonce 重新出证（原始错误: {ce}）"
                    )[:200]
                    if _set_terminal(session, row, "rejected", reason, receipt_failed=True):
                        stats["rejected"] += 1
                    return stats
            inc("fz_chain_writes_total", {"op": "recordAuth", "ok": "0"})
            raise
        inc("fz_chain_writes_total", {"op": "recordAuth", "ok": "1"})
    # 读后写对拍（阶段四）：真链档回读 getAuth 核对写入内容——不一致=fail-closed 拒绝
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") != "fake":
        rec = deps._flight_auth_binding().call_fn("getAuth", [auth_id])
        if (
            rec[0].hex() != th
            or rec[7].hex() != proof_digest
            or rec[6].hex() != row.sub_cred_hash_hex
        ):
            if _set_terminal(
                session,
                row,
                "rejected",
                "chain_readback_mismatch: 链上记录与本地写入不一致",
                receipt_failed=True,
            ):
                stats["rejected"] += 1
            return stats
    if auth_id != predicted:
        # 预测错位（临界区互斥后仅剩「engine 唯一写面被进程组外并发写入破」
        # 形态——链外手工 recordAuth/烟测残留）：fail-closed 拒绝该申请
        # （nonce 已被链上登记消耗——申请人换 nonce 重新出证）
        if _set_terminal(
            session,
            row,
            "rejected",
            f"auth_id_mismatch: predicted={predicted} actual={auth_id}",
            receipt_failed=True,
        ):
            stats["rejected"] += 1
        return stats
    # 判决件归档（D17——按 application 可下载）。expected/verify_s=W-8 飞手视角
    # 复验材料：expected=验证时真实消费的期望绑定（zkc_verify 经 tempfile 消费
    # 的同一 dict——复验与验证同源，杜绝事后重建口径漂移；期望值文件本身不再
    # 落证明者域，见 zkc_verify 注释）。
    vpath = verdict_dir() / f"app-{row.id}.verdict.json"
    vpath.write_text(
        json.dumps(
            {
                "application_id": row.id,
                "auth_id": auth_id,
                "proof_digest": proof_digest,
                "token_hash": token_hash(body),
                "tx": tx,
                "verify_s": verify_s,
                "expected": expected,
                "verify_log": log[-400:],
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )
    from sqlalchemy import update as _u2

    rc = session.execute(
        _u2(Application)
        .where(Application.id == row.id, Application.status == "pending")
        .values(status="approved", auth_id=auth_id, locked_by=None, locked_at=None)
    ).rowcount
    session.commit()
    if not rc:
        return stats  # 已被他 worker 终态化——不翻案（评审 P1-1 竞态守卫）
    # 子凭证消费回写（R3-1.2）：approved 才算消费——配额释放口径的另一半
    from app.ra.models import SubCredential as _Sub

    sc = session.scalars(
        select(_Sub).where(_Sub.sub_cred_hash_hex == row.sub_cred_hash_hex)
    ).first()
    if sc is not None and not sc.consumed:
        sc.consumed = True
        session.commit()
    rec = AuthRecord(
        auth_id=auth_id,
        application_id=row.id,
        token_hash_hex=token_hash(body),
        proof_digest_hex=proof_digest,
        verdict_path=str(vpath),
        tx_hash=tx,
    )
    session.add(rec)
    seal_receipt(session, row.receipt_id, body, sig, row.session_pk_hex)
    stats["approved"] += 1
    return stats


def run_once(session: Session, deps: WorkerDeps | None = None) -> dict:
    return process_pending(session, deps or WorkerDeps())


class AuthzWorkerError(Exception):
    pass


__all__ = ["WorkerDeps", "process_pending", "run_once", "verdict_dir", "AuthzWorkerError"]


if __name__ == "__main__":
    # R3-1 收尾：启动对账（真链档——崩溃窗孤儿授权防盲重试）
    try:
        from app.db import SessionLocal

        _s = SessionLocal()
        _n = _reconcile_burned_pending(_s, WorkerDeps())
        _s.close()
        if _n:
            print(f"[fz-worker] 启动对账：{_n} 条 nonce 已消耗的 pending 申请诚实拒绝", flush=True)
    except Exception as _e:  # noqa: BLE001 链不可达时照常启动（逐条处理时再熔断）
        print(f"[fz-worker] 启动对账跳过: {_e}", flush=True)
    """demo/演示 worker 循环：每 2s 排水一次 pending（真实 zkc verify——占位证明
    会被真实验证拒绝，回执转 failed；真实出证=彩排窗预生成件）。"""
    import json
    import time

    from app.db import SessionLocal

    print("[fz-worker] ZK 验证 worker 启动（轮询 2s，真实 zkc verify）", flush=True)
    while True:
        n = 0
        s = SessionLocal()
        try:
            stats = run_once(s)
            n = sum(stats.values())
            if n:
                print(f"[fz-worker] {json.dumps(stats, ensure_ascii=False)}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[fz-worker] error: {e}", flush=True)
        finally:
            s.close()
        time.sleep(2)
