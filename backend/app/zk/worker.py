"""ZK 验证 worker（B4-T3）：轮询 pending→zkc verify→判决件归档→令牌签发。

验证语义（D17 可审计签发）：
- zkc verify exit 0=证明有效（电路内全量强制：验签/承诺/范围门/有效期/绑定/SMT）
- 判决件（proof/verdict/spec）按 application 归档可下载——proofDigest=SM3(proof)
- 链上 recordAuth（tokenHash+proofDigest+subCredHash——D17/D18）+ burnNonce

令牌（B4-d3/d7）：{authId, plan_hash, alt_max, t_start, t_end, nonce,
policy_version}+Sig_engine——零设备**明文**信息（⑥代起另含 sn_hash 绑定
域=SM3(serial)，见下）。
SN 绑定⑥代已交付（2026-10-06，prove 窗收账）：AUTH 电路公开实例 25=sn_hash
（服务端权威 SM3(serial) 全 32B，词折叠口径 fold_words_be）——一证多机拦截
全链在位：服务端权威自算（server_sn_hash_hex，DB 溯源链）→令牌 sn_hash 域
（engine 签名覆盖）→桥第 6 查（telemetry，SM3(本机 SN)!=token.sn_hash 即
sn_mismatch 拒解锁）。历史批 3.1 定谳的「电路内无 SN 等值钉、解锁面无事前
拦截」缺口已随 vendor 电路换代闭环；签发面原像知识认证+事后设备交叉审计
（audit/device_check.py）保留为纵深防线。残余边界=真机 SE（本源 SN 读数
可信根，桥接模拟 TCB 声明在案）。
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.authz.models import Application, AuthRecord, Receipt
from app.authz.policy import POLICY_VERSION, get_rule
from app.authz.service import (
    build_token,
    seal_receipt,
    server_sn_hash_hex,
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
        # 批 4-4 构型 profile 单源：verify 子进程 env 与桥出证同源取值（档名随
        # 日志/判决件自述——「哪个构型」一望而知）。
        from app.zk.profile import describe, zkc_env

        env = zkc_env()
        # canonical 电路参照=JobSpec 形态（verify-instances 按 JobSpec 解析装配，
        # 只取 info 结构；黄金向量文件是见证向量源非 JobSpec——R1 收口修正：
        # 旧默认指向 auth_golden_vector.json 会在 serde 解析处必炸 missing field）。
        canonical_path = env.setdefault(
            "FZ_AUTH_CANONICAL_SPEC",
            os.path.join(self.zksvc_dir, "tests", "auth_canonical_spec.json"),
        )
        # 批 4-6 spec 私钥回落禁用：verify 装配 canonical 参照同样不从 spec 消费
        # 私钥。**2026-10-06 prove 窗根修补全**：zkc 装配面禁令=「spec 文件出现
        # 明文钥即拒（env 在场不豁免——通道歧义 fail-closed）」，而仓内
        # canonical 原件带夹具钥⟹真案卷复验必被误拒（e2e_auth_full ⑥ 实弹抓
        # 出，批 4 当时只做了 env 搬运漏了文件脱敏）。修法=现场脱敏副本：
        # 副本 input.holder_sk_hex=""（过禁令）+夹具钥走 FZ_ZK_HOLDER_SK_HEX
        # （fixture 钥=仓内公开测试材料，非秘密，通道搬运）；仓内原件不动
        # （FORBID=0 的测试构型照旧可用）；副本 tempfile 用毕即焚。
        _sanitized_path: str | None = None
        if env.get("FZ_ZK_FORBID_SPEC_KEY") == "1":
            try:
                with open(canonical_path, encoding="utf-8") as _f:
                    _spec = json.load(_f)
                _cand = ((_spec.get("input") or {}).get("holder_sk_hex")) or ""
                if _cand:
                    import tempfile as _tf

                    _spec["input"]["holder_sk_hex"] = ""
                    _fd, _sanitized_path = _tf.mkstemp(
                        prefix="fz-canonical-", suffix=".json")
                    with os.fdopen(_fd, "w", encoding="utf-8") as _w:
                        json.dump(_spec, _w)
                    env["FZ_AUTH_CANONICAL_SPEC"] = _sanitized_path
                    env["FZ_ZK_HOLDER_SK_HEX"] = _cand
            except (OSError, ValueError, KeyError, TypeError):
                pass  # 读取失败=如实交由 zkc 装配面人话拒绝（不吞验证结果）
        print(f"[worker] zkc verify 构型 {describe()} task_case={os.path.basename(case_dir)}",
              flush=True)
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
            if _sanitized_path:
                try:
                    os.unlink(_sanitized_path)
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
        sorties: int = 1,
    ) -> tuple[int, str]:
        """链上 recordAuth+burnNonce（engine 交易钥）。返回 (authId, tx)。

        fake 模式（FZ_CHAIN_ANCHOR=fake）：本地 authId 计数替身（授权登记镜像
        auth_records 表仍完整落库——追溯/令牌面语义不变）；计数以调用方传入的
        库内现况 max(auth_id) 播种（R1 收口修正：进程内计数不落库 ⟹ 重启后
        与持久库唯一键撞车）。
        真链模式（阶段一 D-Ⅰ-2）：FlightAuthRegistry.recordAuth 发送（args 与
        B1 烟测同构）→ authId 从 AuthRecorded 事件解出（无事件=fail-closed
        异常禁吞）；nonce 由合约 recordAuth 内部即烧毁（usedNonces）。
        sorties（2026-10-06 授权包配额制）：登记架次配额 1~5 透传上链——
        链上 remaining=sorties 起步，消费回报逐架次递减。
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
                int(sorties),
            ],
        )
        for ev in fa.decode_logs(receipt):
            if ev["event"] == "AuthRecorded":
                return (int(ev["authId"]), str(receipt.get("transactionHash", "")))
        raise RuntimeError(
            f"recordAuth 回执无 AuthRecorded 事件（fail-closed）: {str(receipt)[:160]}"
        )

    def chain_consume_sortie(self, *, auth_id: int) -> int:
        """链上 consumeSortie（授权包配额制 2026-10-06）：/authz/consume 回报
        路径的 engine 链写——remaining-=1，返回链上递减后 remaining。

        合约面 quota exhausted/auth revoked revert=fail-closed 异常上抛
        （调用方折 409/503）；SortieConsumed 事件 remaining=权威值（调用方
        按其校正镜像）。fake 模式不达此处（路由层分档）。"""
        fa = self._flight_auth_binding()
        receipt = fa.send_fn(self._engine_signer, "consumeSortie", [int(auth_id)])
        for ev in fa.decode_logs(receipt):
            if ev["event"] == "SortieConsumed":
                return int(ev["remaining"])
        raise RuntimeError(
            f"consumeSortie 回执无 SortieConsumed 事件（fail-closed）: {str(receipt)[:160]}"
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
    """pending 深度即时量（/metrics 抓取口径——排水滞后告警输入）。
    2026-10-02 乙5 归位：worker 是独立进程——set_gauge 写本进程 dict 对
    backend /metrics 不可见（指标写错进程）。改为落共享 gauge 文件
    （FZ_ZK_CASES_DIR/worker_gauges.json），backend /metrics 渲染时合并。"""
    from sqlalchemy import func as _f

    try:
        n = session.scalar(
            select(_f.count()).select_from(Application).where(Application.status == "pending")
        )
        set_gauge("fz_worker_pending", None, float(n or 0))  # 本进程面（保留）
        _dump_worker_gauges({"fz_worker_pending": float(n or 0)})
    except Exception:  # noqa: BLE001  指标失败不阻塞业务
        pass


def _dump_worker_gauges(gauges: dict[str, float]) -> None:
    """worker gauges → 共享文件（backend /metrics 合并读取——原子写）。"""
    import json as _json
    import tempfile as _tf

    try:
        d = Path(os.environ.get("FZ_ZK_CASES_DIR", "/tmp/fz-zk-cases"))
        d.mkdir(parents=True, exist_ok=True)
        f = d / "worker_gauges.json"
        tmp = f.with_suffix(".tmp")
        tmp.write_text(_json.dumps({"ts": time.time(), "gauges": gauges}), encoding="utf-8")
        tmp.replace(f)
    except Exception:  # noqa: BLE001
        pass


def _max_attempts() -> int:
    """瞬时失败重试上限（链抖动类临时错误——证明无效不在此轴，直接终态）。"""
    return int(os.environ.get("FZ_WORKER_MAX_ATTEMPTS", "3"))


def _verify_timeout_s() -> int:
    """zkc verify 子进程超时（与 subprocess.run timeout 同源）。"""
    return int(os.environ.get("FZ_WORKER_VERIFY_TIMEOUT_S", "600"))


def _lease_seconds() -> int:
    """认领租约秒数：locked_at 超此限视为 worker 孤儿（崩溃），可被接手。

    租约心跳批（2026-10-04 worker 扩展前置）：认领后心跳线程每
    FZ_WORKER_LEASE_HEARTBEAT_S（缺省 60s）续 locked_at——租约可从旧形态的
    2×verify 超时（1200s）降到 ~90s（接管窗）。心跳存续期间长 verify（分钟级）
    不再误过期；心跳停止（进程崩溃）→ 其他 worker 最迟 ~90s 接手。
    （R3-1.1 的「租约 ≥2×verify」语义由心跳承担：无心跳形态下租约必须盖过
    verify 全程，否则 verify 耗时逼近上限时先被误接手、先到者 recordAuth 后
    后来者翻案——本缺省收紧以心跳存在为前提，两者一体上线。）"""
    return int(os.environ.get("FZ_WORKER_LEASE_S", "90"))


def _lease_heartbeat_interval_s() -> int:
    """租约心跳周期（须 < _lease_seconds——留半窗以上余量）。"""
    return int(os.environ.get("FZ_WORKER_LEASE_HEARTBEAT_S", "60"))


def _renew_leases(session: Session, worker_id: str, app_ids: list[int]) -> int:
    """一轮租约续期：仅本 worker 名下且仍 pending 的行推进 locked_at。
    返回续到行数；0=全部终态/被接管（心跳使命结束）。"""
    import datetime as dt

    rc = session.execute(
        update(Application)
        .where(
            Application.id.in_(app_ids),
            Application.locked_by == worker_id,
            Application.status == "pending",
        )
        .values(locked_at=dt.datetime.utcnow())
    ).rowcount
    session.commit()
    return rc


def _start_lease_heartbeat(worker_id: str, app_ids: list[int], stop: threading.Event):
    """认领租约心跳守护线程（2026-10-04）：每 60s UPDATE locked_at——接管窗
    1200s→~90s。自带会话（SQLAlchemy 会话不得跨线程共享）；续到 0 行（全部
    终态/被接管）即自停；单轮失败静默下一轮再试（租约尚有半窗余量）。"""

    def _loop() -> None:
        while not stop.wait(_lease_heartbeat_interval_s()):
            from app.db import SessionLocal

            s = SessionLocal()
            try:
                if _renew_leases(s, worker_id, app_ids) == 0:
                    return
            except Exception:  # noqa: BLE001 下一轮再试（租约尚有半窗余量）
                try:
                    s.rollback()
                except Exception:  # noqa: BLE001
                    pass
            finally:
                s.close()

    t = threading.Thread(target=_loop, daemon=True, name=f"lease-hb-{worker_id}")
    t.start()
    return t


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
    """一轮排水：认领→verify→approved(令牌+链)/rejected；瞬时异常→重试（P0-2）。

    认领后启动租约心跳守护（2026-10-04）：排水全程每 60s 续 locked_at——
    排水（含分钟级 verify）期间租约不再先行过期；轮末停心跳。"""
    worker_id = f"pid-{os.getpid()}"
    rows = _claim_pending(session, worker_id, limit)
    _pending_gauge(session)
    stats = {"processed": 0, "approved": 0, "rejected": 0, "retried": 0}
    stop_hb = threading.Event()
    if rows:
        _start_lease_heartbeat(worker_id, [r.id for r in rows], stop_hb)
    try:
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
    finally:
        stop_hb.set()  # 心跳线程下一 tick 自停（daemon——进程退出亦不阻塞）
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
    # 绑定挑战单源（2026-10-07 prove 窗根修）：challenge_hex 是钥控 HMAC 值——
    # 受理门⑤按**受理进程**的 FZ_AUTHZ_BINDING_KEY 现算并钉实例 19；本进程若按
    # env 重建，两进程钥漂移（demo_up 随机钥 vs 裸 env 缺省派生）即真案卷假拒
    # （e2e_auth_full ⑥ 实弹：实例 19 与申请绑定不一致，proof 本身有效）。
    # 现消费受理时落库的已钉定值（expected 与⑤逐位同源）；历史行（迁移前
    # 空 challenge_hex）回落旧重建式——语义=改动前的唯一路径，不放松任何核对。
    row_challenge = row.challenge_hex or binding_challenge(row.plan_hash_hex, row.nonce_hex)
    expected = {
        "e_hex": row.e_hex,
        "challenge_hex": row_challenge,
        "pred_id": binding_pred_id(
            row.plan_hash_hex,
            row.nonce_hex,
            row.policy_version or POLICY_VERSION,
        ),
        "t_epoch": row.t_start,
        "required_level": required_level,
        "class_id": row.class_id,
        "smt_root_hex": row.rev_root_hex,
        # S6 安全闭环（2026-10-04）：子凭证有效期随判决件归档——第三方拿到
        # 判决件即可自行核对「凭证有效期覆盖授权窗」（exp_u ≥ t_end；t_end 经
        # 链上 recordAuth/getAuth 记录同源可得）。受理面已核对同一谓词
        # （authz/service.py cred_expired_window），此处为审计可见性归档。
        # zkc 侧 BindingExpectations 未开 deny_unknown_fields（zksvc/prove.rs），
        # 未知名安全忽略——电路验证消费零影响。
        "exp_u": row.exp_u,
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
            # SN 绑定换代（2026-10-06）：sn_hash=服务端权威自算（DB 溯源链——
            # 与受理门控实例 25 同源单一事实源），入 body ⟹ engine 签名域覆盖。
            sn_hash_hex=server_sn_hash_hex(session, row.sub_cred_hash_hex),
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
                # 授权包配额制（2026-10-06）：申请配额透传上链（缺省 1=与
                # 令牌一次性历史语义逐字等价）
                sorties=int(getattr(row, "sorties", 1) or 1),
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
    _quota = int(getattr(row, "sorties", 1) or 1)
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") != "fake":
        rec = deps._flight_auth_binding().call_fn("getAuth", [auth_id])
        if (
            rec[0].hex() != th
            or rec[7].hex() != proof_digest
            or rec[6].hex() != row.sub_cred_hash_hex
            or int(rec[11]) != _quota  # 配额制：链上 remaining=登记架次数
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
                # 批 4-3 档位显式化：判决件自述链锚档——第三方核对「这份授权
                # 登记是否落真链」不必猜档（fake=演示假链，tx 形态如实可辨）。
                "mode": (
                    "fake" if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake" else "real"
                ),
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
        # 授权包配额制（2026-10-06）：配额账本随登记落库——remaining 起步=
        # sorties（缺省 1），消费回报逐次递减（router /authz/consume）
        sorties=_quota,
        remaining=_quota,
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
