"""令牌验签+飞行闸门（B5-T1/T3，D9/D15）。

令牌格式（B4-d3/d7）：JSON{authId, plan_hash, alt_max, t_start, t_end, nonce,
policy_version}+Sig_engine（SM2 域）。地面站层验证：engine 公钥+时间窗+
nonce 未用（本地状态）+plan_hash 一致——失败拒绝发 ARM 并留本地审计行
（TCB 第①层声明：用户理论可绕，固件围栏=第②层硬强制）。

已用令牌本地状态记录（A7）：token_hash+authId+首次 ARM 时间戳——令牌=时间窗
授权（窗内可多次起飞语义），本记录=审计行非消费销毁。
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import time

from app.crypto.sm2 import verify_digest
from app.crypto.sm3 import sm3_bytes


class TokenError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message


def engine_pub_hex() -> str:
    """令牌验签公钥（仅公钥面——🔴 bridge 职责边界=永不持有政策引擎私钥）。

    钥源优先级（2026-09-26 队长实测验签假败根修）：
    ① 本进程 FZ_ENGINE_SK（S1/S2 拓扑——桥持钥场景）；
    ② backend /authz/engine/pub 代理——仅当 FZ_ENGINE_PUB_PROXY=1（demo_up
      桥裁钥时置位：worker 持每场随机钥，桥端确定性派生会"验错人"）；
    ③ 确定性域派生（测试/离线兜底——显式开关隔离，避免误代理活后端）。"""
    import os

    if os.environ.get("FZ_ENGINE_SK"):
        from app.kms import engine_pub_hex as _pub

        return _pub()
    if os.environ.get("FZ_ENGINE_PUB_PROXY") == "1":
        # 代理模式（demo 桥裁钥：每场随机钥在 backend 侧）——backend 不可达时
        # **fail-closed 拒绝**而非静默回落确定性派生钥（2026-09-28 B 席 P1-5：
        # 错钥验签=合法令牌全部"验签失败"误导排障；确定性钥与真钥不同人）。
        try:
            import json as _json
            import urllib.request as _ur

            base = os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")
            opener = _ur.build_opener(_ur.ProxyHandler({}))
            with opener.open(_ur.Request(base + "/authz/engine/pub"), timeout=5) as r:
                d = _json.loads(r.read().decode())
            pub = (d.get("data") or d)["engine_pub_hex"]
            if isinstance(pub, str) and len(pub) >= 128:
                return pub
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(
                f"引擎公钥不可得（backend 不可达: {e}）——闸门拒绝验签；"
                f"请先恢复授权服务再重试"
            ) from e
    from app.kms import engine_pub_hex as _pub

    return _pub()


def split_token(payload: bytes) -> tuple[dict, str, bytes]:
    """payload=token_body|sig_hex（B4 seal_receipt 同式）。第三返回=原始 body
    字节（2026-09-28 B 席 P1-6：验签对象=原始字节——重规范化 JSON 在畸形
    形态（重复键/数值写法）下与签发字节面可能分叉，验签以原字节为准）。"""
    body, sig = payload.rsplit(b"|", 1)
    return json.loads(body), sig.decode(), body


def verify_token(payload: bytes, *, plan_hash_hex: str, now: int | None = None) -> dict:
    """地面站层令牌验证（六查：签名/窗/计划一致/字段完整/nonce 形态/SN 绑定）。

    第 6 查（SN 绑定换代 2026-10-06）：SM3(本机 SN)==token.sn_hash——本机 SN
    与 device_key.device_serial() 同源（设备钥派生同一读数）；不符=sn_mismatch
    拒绝（授权令牌钉死到出证序列号——换机重放/套用他机令牌面封堵）。"""
    tok, sig, body_raw = split_token(payload)
    for f in ("authId", "plan_hash", "alt_max", "t_start", "t_end", "nonce", "policy_version", "sn_hash"):
        if f not in tok:
            raise TokenError("bad_token", f"令牌缺字段 {f}")
    e = sm3_bytes(body_raw)  # 验签对象=原始 body 字节（非重规范化形态）
    if not verify_digest(engine_pub_hex(), e, sig):
        raise TokenError("bad_signature", "令牌签名验证失败（非 engine 签发或篡改）")
    now_i = int(now if now is not None else time.time())
    if not tok["t_start"] <= now_i <= tok["t_end"]:
        raise TokenError("window_expired", f"令牌窗外（[{tok['t_start']},{tok['t_end']}] vs {now_i}）")
    if tok["plan_hash"] != plan_hash_hex:
        raise TokenError("plan_mismatch", "令牌 plan_hash 与本机计划不一致（A2 绑定面）")
    if len(tok["nonce"]) != 32:
        raise TokenError("bad_nonce", "nonce 形态非法")
    # ⑥ SN 绑定：令牌 sn_hash（服务端权威 SM3(serial) 全 32B，engine 签名域
    # 覆盖）vs 本机 SN 自算——同 device_key 单源。
    from device_key import device_serial

    local_sn_hash = sm3_bytes(device_serial().encode()).hex()
    if tok["sn_hash"] != local_sn_hash:
        raise TokenError(
            "sn_mismatch",
            "令牌 sn_hash 与本机序列号不符（授权钉死出证设备——换机不可用）",
        )
    return tok


class LocalAudit:
    """已用令牌本地审计（A7）+拒绝审计行——SQLite 本地文件（桥接进程持有）。"""

    def __init__(self, db_path: str | None = None) -> None:
        # 缺省=模块同目录绝对路径（B-P3-11：相对路径随 CWD 漂移曾产出三份库，
        # 一次性令牌审计态分叉=同令牌可二次 ARM）
        from pathlib import Path as _P

        path = db_path or os.environ.get(
            "FZ_GCS_AUDIT_DB", str(_P(__file__).resolve().parent / "gcs_audit.db")
        )
        self._c = sqlite3.connect(path, check_same_thread=False)
        self._c.execute(
            "CREATE TABLE IF NOT EXISTS token_arms ("
            "token_hash_hex TEXT PRIMARY KEY, auth_id INTEGER, first_arm_at TEXT)"
        )
        self._c.execute(
            "CREATE TABLE IF NOT EXISTS denials ("
            "at TEXT, code TEXT, detail TEXT)"
        )
        # 消费回报待重试队列（信任根收口件1）：/authz/consume 回报失败时落行——
        #堵「同令牌双飞」窗（服务端消费账本缺失期间，删本地库重放可绕
        # token_consumed 终拒）。下次任意 ARM/采样定时触发重试，成功即删。
        self._c.execute(
            "CREATE TABLE IF NOT EXISTS consume_pending ("
            "auth_id INTEGER, token_hash_hex TEXT, enqueued_at TEXT, "
            "PRIMARY KEY (auth_id, token_hash_hex))"
        )
        # 架次账本（授权包配额制 2026-10-06）：每个「新架次 ARM」一行（同会话
        # 重解锁不记账）。本地执法轴——服务端 remaining 迟到位/回报失败窗内，
        # 本地计数仍封锁超配额解锁（零弱化：缺省配额 1 时第 2 架次恒拒）。
        self._c.execute(
            "CREATE TABLE IF NOT EXISTS sortie_arms ("
            "token_hash_hex TEXT, armed_at TEXT, PRIMARY KEY (token_hash_hex, armed_at))"
        )
        self._c.commit()

    def first_arm(self, payload: bytes) -> tuple[str, int, str] | None:
        th, auth_id, at = self._c.execute(
            "SELECT token_hash_hex, auth_id, first_arm_at FROM token_arms WHERE token_hash_hex=?",
            (sm3_bytes(payload).hex(),),
        ).fetchone() or (None, None, None)
        return (th, auth_id, at) if th else None

    def record_arm(self, payload: bytes, auth_id: int) -> str:
        th = sm3_bytes(payload).hex()
        at = dt.datetime.utcnow().isoformat()
        self._c.execute(
            "INSERT OR IGNORE INTO token_arms VALUES (?,?,?)", (th, auth_id, at)
        )
        self._c.commit()
        return at

    def record_sortie(self, payload: bytes) -> str:
        """架次记账（授权包配额制）：仅「新架次 ARM」调用（同会话重解锁不记
        ——重解锁路径在闸门早退，不达此处）。isoformat 含微秒=同令牌连发键
        不碰撞；INSERT OR IGNORE 幂等。"""
        th = sm3_bytes(payload).hex()
        at = dt.datetime.utcnow().isoformat()
        self._c.execute(
            "INSERT OR IGNORE INTO sortie_arms VALUES (?,?)", (th, at)
        )
        self._c.commit()
        return at

    def sortie_count(self, payload: bytes) -> int:
        """本令牌本地架次计数（授权包配额制执法轴）。表查询异常（旧库损坏等
        形态）=保守按 1 计（fail-closed——按已用处理，不放大配额）。"""
        try:
            row = self._c.execute(
                "SELECT COUNT(*) FROM sortie_arms WHERE token_hash_hex=?",
                (sm3_bytes(payload).hex(),),
            ).fetchone()
            return int(row[0]) if row else 0
        except Exception:  # noqa: BLE001 —— 账本不可读=保守已用
            return 1

    def record_denial(self, code: str, detail: str) -> None:
        self._c.execute(
            "INSERT INTO denials VALUES (?,?,?)",
            (dt.datetime.utcnow().isoformat(), code, detail[:200]),
        )
        self.c_commit()

    def c_commit(self) -> None:
        self._c.commit()

    def denials(self) -> list:
        return self._c.execute("SELECT at, code, detail FROM denials ORDER BY at").fetchall()

    # ---- 消费回报待重试队列（信任根收口件1：consume_pending） ----

    def consume_pending_enqueue(self, auth_id: int, token_hash_hex: str) -> str:
        """回报失败落队（进程重启不丢——SQLite 与令牌账本同库同生命周期）。
        同 (auth_id, token_hash) 重复失败覆盖重记（enqueued_at 刷新，幂等）。"""
        at = dt.datetime.utcnow().isoformat()
        self._c.execute(
            "INSERT OR REPLACE INTO consume_pending VALUES (?,?,?)",
            (int(auth_id), token_hash_hex, at),
        )
        self.c_commit()
        return at

    def consume_pending_all(self) -> list:
        """全队列（auth_id, token_hash_hex, enqueued_at）——按入队序重试。"""
        return self._c.execute(
            "SELECT auth_id, token_hash_hex, enqueued_at FROM consume_pending "
            "ORDER BY enqueued_at, auth_id"
        ).fetchall()

    def consume_pending_remove(self, auth_id: int, token_hash_hex: str) -> None:
        """回报成功即删（幂等——行不存在为无害 no-op）。"""
        self._c.execute(
            "DELETE FROM consume_pending WHERE auth_id=? AND token_hash_hex=?",
            (int(auth_id), token_hash_hex),
        )
        self.c_commit()
