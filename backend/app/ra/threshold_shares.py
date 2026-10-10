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
from app.crypto.threshold import decrypt_share, proactive_reshare, shamir_split

# 根目录：env FZ_THRESHOLD_ROOT_DIR 优先（单测隔离到 tmp——生产/测试共用
# 目录会让 append-only 审计混入测试行，实弹教训=审计可信度红线）。
# **函数形态**（非模块常量）：env 在 import 后才被测试改写，常量绑定会令
# 隔离静默失效（实弹踩过）。
_ROLES = ("admin", "ra", "auditor")
_THRESHOLD_K = 2
# RLock（可重入）：ceremonial_reshare 全程持锁、函数体内 _audit 再入同锁——
# 用 Lock 曾自死锁（pytest 全量挂起实锤，⑤站教训=仪式面持锁范围必须与
# 审计面再入兼容）；非重入路径（request_decrypt_share/_audit）行为不变。
_lock = threading.RLock()


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


def ceremonial_reshare(gov_confirmed_epoch: int) -> dict:
    """⑤站 proactive re-share 仪式（治理提案 execute 后由 backend 侧执行）。

    语义（任务书钉定）：**D_pub 不变、无需根钥 d**——从任意 ≥2 份现存份额
    出发（app.crypto.threshold.proactive_reshare：δ(0)=0 随机增项+拉格朗日
    换基外推），新份额入三域+纪元+1 ⟹ 存量 v5 信封零影响（C₁ 密文与根公
    钥均不涉）；旧份额值/旧纪元密封钥同时作废（epoch 参与密封钥派生）。

    纪元门（fail-closed）：gov_confirmed_epoch 必须等于当前纪元+1——脚本面
    在 governor 提案（description=『threshold-reshare:epoch-N』）execute 并
    链上回读对拍后才携 N 调用；直调不带正确治理纪元即拒（仪式不被绕过）。

    原子序：先内存全量自证（canary=SM2(D_pub) 加解对拍走 decrypt_share/
    combine_decrypt_shares/threshold_decrypt 真实原语），后落盘（先份额后
    纪元——窗内解封请求开封失败=域拒绝=fail-closed，无安全面）。三域审计
    append-only 各记一行（零份额材料）。中途任何失败=零持久变更。
    """
    if not isinstance(gov_confirmed_epoch, int) or isinstance(gov_confirmed_epoch, bool):
        raise ShareDomainError("bad_epoch_arg", "gov_confirmed_epoch 须为整数纪元")
    if gov_confirmed_epoch < 2:
        raise ShareDomainError("bad_epoch_arg", "目标纪元须 ≥2（纪元 1=初始化态）")
    with _lock:
        if not is_initialized():
            raise ShareDomainError("not_initialized", "门限根未初始化（先 initialize_if_absent）")
        meta = json.loads((_root_dir() / "root.json").read_text(encoding="utf-8"))
        old_epoch = int(meta["epoch"])
        new_epoch = old_epoch + 1
        if gov_confirmed_epoch != new_epoch:
            raise ShareDomainError(
                "epoch_mismatch",
                f"治理公示纪元 {gov_confirmed_epoch} ≠ 下一纪元 {new_epoch}",
            )
        # ① 开封现存份额（逐域尝试，取先开成功的前 k 份——损毁域跳过）
        opened: list[tuple[int, str]] = []
        for idx, role in enumerate(_ROLES, start=1):
            if len(opened) >= _THRESHOLD_K:
                break
            try:
                plain = _open_share(role, old_epoch, _domain_share_sealed_path(role).read_bytes())
                opened.append((idx, plain.decode()))
            except Exception:  # noqa: BLE001 —— 域损即跳过（≥k 份可开即可刷新）
                continue
        if len(opened) < _THRESHOLD_K:
            raise ShareDomainError(
                "insufficient_shares",
                f"可开封份额 {_THRESHOLD_K} 不足（仅 {len(opened)}）——刷新中止",
            )
        # ② 标量域 re-share（d 不重组——proactive_reshare 域内无 d 路径）
        new_shares = proactive_reshare(
            [(i, int(s, 16)) for i, s in opened], len(_ROLES), _THRESHOLD_K
        )
        # ③ 内存自证（先于任何落盘）：canary 对 D_pub 加解全对拍
        canary = b"FZ-RESHARE-CANARY|" + str(new_epoch).encode()
        from app.crypto.sm2 import encrypt as sm2_encrypt
        from app.crypto.threshold import threshold_decrypt

        pub_hex = meta["pub_hex"]
        ct = sm2_encrypt(pub_hex, canary)
        c1_hex = ct[:64].hex()
        pts = [(i, decrypt_share(f"{d_i:064x}", c1_hex)) for i, d_i in new_shares[:_THRESHOLD_K]]
        if threshold_decrypt(ct, pts) != canary:
            raise ShareDomainError("canary_mismatch", "新份额对 D_pub 自证失败（未落盘，零变更）")
        # ④ 持久化：先份额（新纪元域钥重封=旧份额值+旧密封钥同时作废）后纪元
        for (_i, d_i), role in zip(new_shares, _ROLES, strict=True):
            _domain_share_sealed_path(role).write_bytes(
                _seal_share(role, new_epoch, f"{d_i:064x}".encode())
            )
        meta["epoch"] = new_epoch
        meta["prev_epoch"] = old_epoch
        meta["reshared_ts"] = time.time()
        (_root_dir() / "root.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        # ⑤ 三域仪式审计（append-only；记录纪元不含任何份额材料）
        for role in _ROLES:
            _audit(
                role,
                {
                    "action": "reshare",
                    "decision": "ok",
                    "from_epoch": old_epoch,
                    "to_epoch": new_epoch,
                },
            )
        # 中间值出栈即焚（opened 旧份额/new_shares 新份额不外溢本函数域）
        del opened, new_shares, pts
        return {"epoch": new_epoch, "prev_epoch": old_epoch, "pub_hex": pub_hex}


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
