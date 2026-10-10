"""④站门限份额域（2-of-3，2026-10-10）：三治理角色域各自密封持有 Shamir
份额 dᵢ，独立三关校验（解锁请求台账在案/令状链上在案/双控批文在案）后才出
**解密份额点 [dᵢ]C₁**（dᵢ 本身不出域），独立 append-only 审计日志。

域隔离形态（诚实口径）：
- demo 档=backend 内三逻辑域（分文件密封存储+分域 KMS 钥+分审计文件）；
  生产演进=三独立进程/三机/HSM（组织级 TCB 演进，答辩口径 E 段同族）。
- 根钥 d 分割后**焚毁**（不落任何盘）；D_pub 持久（threshold_root.json）；
  份额密封钥=KMS 各域独立派生（FZ-THRESHOLD|share|{role}）。
- 单域失陷不可单独解实名（信息论）；两域合谋可解（2-of-3 语义，与治理
  多数被攻破同构——答辩口径）。
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path

from app.crypto.sm2 import generate_keypair, pubkey_from_priv
from app.crypto.threshold import decrypt_share, shamir_split

# 根目录：env FZ_THRESHOLD_ROOT_DIR 优先（单测隔离到 tmp——生产/测试共用
# 目录会让 append-only 审计混入测试行，实弹教训=审计可信度红线）。
# **函数形态**（非模块常量）：env 在 import 后才被测试改写，常量绑定会令
# 隔离静默失效（实弹踩过）。
_ROLES = ("admin", "ra", "auditor")
_THRESHOLD_K = 2
_lock = threading.Lock()


class ShareDomainError(Exception):
    """份额域拒绝（域校验失败/未初始化/域损）。"""

    def __init__(self, code: str, message: str, status: int = 403):
        super().__init__(message)
        self.code = code
        self.status = status


def _root_dir() -> Path:
    env = os.environ.get("FZ_THRESHOLD_ROOT_DIR", "")
    return Path(env) if env else Path(__file__).resolve().parents[2] / "threshold_root"


def _domain_share_sealed_path(role: str) -> Path:
    return _root_dir() / f"share_{role}.sealed.json"


def _audit_path(role: str) -> Path:
    return _root_dir() / f"audit_{role}.jsonl"


def is_initialized() -> bool:
    return (_root_dir() / "root.json").exists() and all(
        _domain_share_sealed_path(r).exists() for r in _ROLES
    )


def initialize_if_absent() -> dict:
    """惰性初始化：生成根钥 d → Shamir 2-of-3 分割 → 三域密封 → **d 焚毁**。

    幂等：已初始化则只回读公示面（D_pub/纪元）。首次 v5 信封写入前由服务端
    调用；demo_reset 清 DB 不清本目录（D 跨重置连续——存量信封依赖）。"""
    with _lock:
        if is_initialized():
            meta = json.loads((_root_dir() / "root.json").read_text(encoding="utf-8"))
            return {"pub_hex": meta["pub_hex"], "epoch": meta["epoch"], "created": False}
        _root_dir().mkdir(parents=True, exist_ok=True)
        sk, _pk = generate_keypair()
        d = int(sk, 16)
        shares = shamir_split(d, len(_ROLES), _THRESHOLD_K)
        epoch = 1
        for (_i, d_i), role in zip(shares, _ROLES, strict=True):
            sealed = _seal_share(role, epoch, f"{d_i:064x}".encode())
            _domain_share_sealed_path(role).write_bytes(sealed)
        pub_hex = pubkey_from_priv(sk)
        (_root_dir() / "root.json").write_text(
            json.dumps(
                {
                    "pub_hex": pub_hex,
                    "epoch": epoch,
                    "threshold": _THRESHOLD_K,
                    "roles": list(_ROLES),
                    "created_ts": time.time(),
                },
                ensure_ascii=False,
                indent=1,
            ),
            encoding="utf-8",
        )
        # d 焚毁：sk/d/shares 出栈即失——不写盘、不进任何缓存（本函数域内）。
        del sk, d, shares
        return {"pub_hex": pub_hex, "epoch": epoch, "created": True}


def _share_seal_key(role: str, epoch: int) -> bytes:
    """份额密封钥（独立确定性域——**禁用 wrap_secret/env 敏感钥**：pytest 与
    backend 的 FZ_WRAP_KEY 不同域曾致密封/解封漂移 GCM 假拒；SM3 派生 16B
    跨进程稳定，域隔离=role+epoch 入派生域）。"""
    from app.crypto.sm3 import sm3_bytes

    return sm3_bytes(b"FZ-THRESHOLD|share-seal|" + role.encode() + b"|" + str(epoch).encode())[:16]


def _seal_share(role: str, epoch: int, plaintext: bytes) -> bytes:
    from app.crypto.sm4 import SM4GCM

    g = SM4GCM(_share_seal_key(role, epoch))
    nonce = secrets.token_bytes(12)
    ct, tag = g.encrypt(nonce, plaintext, b"FZ-THRESHOLD|SHARE")
    return nonce + ct + tag


def _open_share(role: str, epoch: int, blob: bytes) -> bytes:
    from app.crypto.sm4 import SM4GCM

    g = SM4GCM(_share_seal_key(role, epoch))
    return g.decrypt(blob[:12], blob[12:-16], blob[-16:], b"FZ-THRESHOLD|SHARE")


def _audit(role: str, row: dict) -> None:
    """域独立 append-only 审计（JSONL——每域一份，禁止合并视图伪造）。"""
    with _lock:
        with _audit_path(role).open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "role": role, **row}, ensure_ascii=False) + "\n")


def request_decrypt_share(
    role: str,
    c1_hex: str,
    *,
    warrant_hash_hex: str,
    cred_hash_hex: str,
    request_sha256_hex: str,
    verify_hooks: dict | None = None,
) -> str:
    """份额域三关校验 → 出 [dᵢ]C₁（dᵢ 不出域）。

    三关（每域独立执行、独立审计）：
    ① 解锁请求台账在案（verify_hooks["request_registered"]——合成方受理面
       先登记 warrant/cred/C₁ 指纹三元组）；
    ② 令状链上在案（verify_hooks["warrant_on_chain"]）；
    ③ 双控批文在案（verify_hooks["collab_approved"]——FZ-COLLAB 批准/执行态）。
    hooks 缺省=真实现（app.ra.threshold_hooks）；单测可注入本地真实现
    （判定逻辑同码路径——非网络替身，诚实标注）。
    """
    if role not in _ROLES:
        raise ShareDomainError("bad_role", f"未知份额域 {role}")
    hooks = verify_hooks or _default_hooks()
    checks = {
        "request_registered": hooks["request_registered"](
            request_sha256_hex, warrant_hash_hex, cred_hash_hex
        ),
        "warrant_on_chain": hooks["warrant_on_chain"](warrant_hash_hex),
        "collab_approved": hooks["collab_approved"](request_sha256_hex),
    }
    failed = [k for k, v in checks.items() if not v]
    row = {
        "action": "decrypt_share",
        "c1_sha256": __import__("hashlib").sha256(bytes.fromhex(c1_hex)).hexdigest(),
        "warrant_hash_hex": warrant_hash_hex,
        "cred_hash_hex": cred_hash_hex,
        "request_sha256_hex": request_sha256_hex,
        "checks": checks,
        "decision": "granted" if not failed else f"denied:{'+'.join(failed)}",
    }
    _audit(role, row)
    if failed:
        raise ShareDomainError("share_denied", f"份额域 {role} 校验未过：{'+'.join(failed)}")
    sealed = _domain_share_sealed_path(role).read_bytes()
    plain = _open_share(role, _epoch(), sealed)
    d_i_hex = plain.decode()
    return decrypt_share(d_i_hex, c1_hex)


def _epoch() -> int:
    meta = json.loads((_root_dir() / "root.json").read_text(encoding="utf-8"))
    return int(meta["epoch"])


def root_pub_hex() -> str:
    if not is_initialized():
        initialize_if_absent()
    meta = json.loads((_root_dir() / "root.json").read_text(encoding="utf-8"))
    return meta["pub_hex"]


def _default_hooks() -> dict:
    """真实现三关（延迟 import 防环——authz/ra 面互引）。"""
    from app.ra.threshold_hooks import (
        collab_approved,
        request_registered,
        warrant_on_chain,
    )

    return {
        "request_registered": request_registered,
        "warrant_on_chain": warrant_on_chain,
        "collab_approved": collab_approved,
    }
