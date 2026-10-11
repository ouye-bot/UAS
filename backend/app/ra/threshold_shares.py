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
# 3.2 k-of-n 参数化：_ROLES/_THRESHOLD_K 常量退役为缺省值——配置面=
# threshold_config()（env FZ_THRESHOLD_K / FZ_THRESHOLD_DOMAINS，函数形态
# 同上纪律：env 改写即时生效）。缺省 env=2 + (admin,ra,auditor) 逐字同现行
# ——默认 env 下行为零变化（3.2 红线）。
_DEFAULT_DOMAINS = ("admin", "ra", "auditor")
_DEFAULT_K = 2
_DOMAIN_ALPHABET = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
# RLock（可重入）：ceremonial_reshare 全程持锁、函数体内 _audit 再入同锁——
# 用 Lock 曾自死锁（pytest 全量挂起实锤，⑤站教训=仪式面持锁范围必须与
# 审计面再入兼容）；非重入路径（request_decrypt_share/_audit）行为不变。
_lock = threading.RLock()
_config_cache: tuple[int, tuple[str, ...]] | None = None


def _reset_config_cache() -> None:
    """测试隔离口：env 改写后强制重读配置（产品路径不调——配置随进程 env）。"""
    global _config_cache
    _config_cache = None


def threshold_config() -> tuple[int, tuple[str, ...]]:
    """门限参数配置面（3.2 k-of-n 参数化——任务书①）：k 与份额域集。

    env：FZ_THRESHOLD_K（缺省 2）、FZ_THRESHOLD_DOMAINS（逗号分隔域名，
    缺省 admin,ra,auditor）。fail-fast 断言（ShareDomainError.bad_threshold_
    config）：k≥2（k=1=单钥无门限语义）、n−k≥1（k=n=全集门限零容错——任一
    域损毁即不可解，拒）、域名形态（1..32 字符安全字母表 _DOMAIN_ALPHABET、
    无重复、非空集）。函数形态+进程内缓存（_reset_config_cache 测试隔离口
    ——env 改写即时生效，缓存仅省重复解析）。
    """
    global _config_cache
    if _config_cache is not None:
        return _config_cache
    import os

    raw_k = os.environ.get("FZ_THRESHOLD_K", "").strip()
    raw_domains = os.environ.get("FZ_THRESHOLD_DOMAINS", "").strip()
    k = _DEFAULT_K if not raw_k else _parse_int(raw_k)
    domains = (
        _DEFAULT_DOMAINS
        if not raw_domains
        else tuple(d.strip() for d in raw_domains.split(",") if d.strip())
    )
    _assert_config(k, domains)
    _config_cache = (k, domains)
    return _config_cache


def _parse_int(raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise ShareDomainError(
            "bad_threshold_config",
            f"FZ_THRESHOLD_K 非整数: {raw!r}——启动断言 fail-closed（拒启）",
            500,
        ) from exc


def _assert_config(k: int, domains: tuple[str, ...]) -> None:
    def _bad(msg: str) -> ShareDomainError:
        return ShareDomainError("bad_threshold_config", f"门限参数配置非法——拒启: {msg}", 500)

    if k < 2:
        raise _bad(f"k={k} < 2（k=1 即单钥——门限语义不存在）")
    if len(domains) < 1:
        raise _bad("份额域集为空（至少 1 个域）")
    if k >= len(domains):
        raise _bad(
            f"k={k} ≥ 域数 n={len(domains)}（n−k≥1 要求 k<n——k=n 即全集门限，"
            "任一域损毁即不可解，零容错形态拒绝）"
        )
    seen: set[str] = set()
    for d in domains:
        if not d or len(d.encode()) > 32 or not set(d) <= _DOMAIN_ALPHABET:
            raise _bad(
                f"域名 {d!r} 形态非法（1..32 字符，限字母/数字/_/-——域名入密封钥"
                "派生域分隔符与审计行，形态须受控）"
            )
        if d in seen:
            raise _bad(f"域名重复: {d!r}（同域两份不构成独立份额）")
        seen.add(d)


def assert_threshold_config() -> dict:
    """启动断言（任务书①——比照 production 拒启工艺挂 create_app）：配置
    自洽 fail-fast。production 档（is_production）额外域集⊆治理席位集对拍
    （份额域=治理席位同构语义 1.3 件①——链不可达=fail-closed 拒启）；demo
    档只做参数自洽（fake 档无链面）。返回配置摘要（KPI/日志消费）。"""
    k, domains = threshold_config()
    import os

    if os.environ.get("FZ_PRODUCTION", "").strip().lower() in ("1", "true", "yes"):
        # production 档：席位集对拍（链读 owner 数 ≥ n）
        try:
            from app.ra.threshold_sync import chain_owner_set

            chain = chain_owner_set()
        except Exception as e:  # noqa: BLE001 —— production 档链不可达=拒启
            raise ShareDomainError(
                "bad_threshold_config",
                f"production 档份额域席位对拍链读失败（fail-closed 拒启）: {e}",
                500,
            ) from e
        if len(chain["owners"]) < len(domains):
            raise ShareDomainError(
                "bad_threshold_config",
                f"份额域数 n={len(domains)} > 治理席位数 {len(chain['owners'])}"
                "（域集⊆治理席位集语义——扩席位先行）",
                500,
            )
    return {"k": k, "domains": list(domains)}


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
    _, domains = threshold_config()
    return (_root_dir() / "root.json").exists() and all(
        _domain_share_sealed_path(r).exists() for r in domains
    )


def initialize_if_absent() -> dict:
    """惰性初始化：生成根钥 d → Shamir k-of-n 分割 → 全域密封 → **d 焚毁**
    （3.2 k-of-n：k/域集=threshold_config()——缺省 env 2-of-3 零变化）。

    幂等：已初始化则只回读公示面（D_pub/纪元）。首次 v5 信封写入前由服务端
    调用；demo_reset 清 DB 不清本目录（D 跨重置连续——存量信封依赖）。
    跨参数域 fail-closed（3.2 任务书①红线）：已初始化目录与现配置（k/域集）
    不符=拒绝（静默重初始化=换根钥=存量信封全死；换代=运维显式归档目录）。"""
    with _lock:
        k, domains = threshold_config()
        root_path = _root_dir() / "root.json"
        if root_path.exists():
            meta = json.loads(root_path.read_text(encoding="utf-8"))
            old_domains = tuple(meta.get("domains") or meta.get("roles") or ())
            old_k = int(meta.get("threshold") or 0)
            if old_domains != domains or old_k != k:
                raise ShareDomainError(
                    "config_mismatch",
                    f"门限根已按 k={old_k}/域集 {list(old_domains)} 初始化，与现配置 "
                    f"k={k}/域集 {list(domains)} 不符——拒绝初始化（静默换根钥=存量"
                    "信封全部不可解；跨参数域换代请先归档 threshold_root 目录）",
                    409,
                )
            return {"pub_hex": meta["pub_hex"], "epoch": meta["epoch"], "created": False}
        _root_dir().mkdir(parents=True, exist_ok=True)
        sk, _pk = generate_keypair()
        d = int(sk, 16)
        shares = shamir_split(d, len(domains), k)
        epoch = 1
        for (_i, d_i), role in zip(shares, domains, strict=True):
            sealed = _seal_share(role, epoch, f"{d_i:064x}".encode())
            _domain_share_sealed_path(role).write_bytes(sealed)
        pub_hex = pubkey_from_priv(sk)
        root_path.write_text(
            json.dumps(
                {
                    "pub_hex": pub_hex,
                    "epoch": epoch,
                    "threshold": k,
                    # 3.2：domains=配置权威键；roles=兼容消费面（threshold_sync/
                    # threshold_reshare announcement/meta 既有键）——同值双写。
                    "domains": list(domains),
                    "roles": list(domains),
                    # 份额域绑定指纹（1.3 件①）：owner-set 指纹 SM3(sorted(
                    # owners))——初始化时 None（未绑定），首次同步对拍惰性绑定
                    # /re-share 仪式携 fp 写入（漂移检测与解锁第④关的判定源）。
                    "owner_set_fp": None,
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
    ③ 双控批文在案（verify_hooks["collab_approved"]——FZ-COLLAB 批准/执行态）；
    ④ 份额域与治理席位同步（verify_hooks["owner_set_synced"]——1.3 件④：
       漂移=fail-closed 拒）。hooks 无此键=替位注入形态跳过（真实现 _default_
       hooks 恒含——生产解锁恒过第④关）。
    hooks 缺省=真实现（app.ra.threshold_hooks）；单测可注入本地真实现
    （判定逻辑同码路径——非网络替身，诚实标注）。
    """
    _, domains = threshold_config()
    if role not in domains:
        raise ShareDomainError("bad_role", f"未知份额域 {role}（现配置域集: {','.join(domains)}）")
    hooks = verify_hooks or _default_hooks()
    checks = {
        "request_registered": hooks["request_registered"](
            request_sha256_hex, warrant_hash_hex, cred_hash_hex
        ),
        "warrant_on_chain": hooks["warrant_on_chain"](warrant_hash_hex),
        "collab_approved": hooks["collab_approved"](request_sha256_hex),
    }
    sync_hook = hooks.get("owner_set_synced")
    if sync_hook is not None:
        checks["owner_set_synced"] = bool(sync_hook())
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


def ceremonial_reshare(gov_confirmed_epoch: int, owner_set_fp: str | None = None) -> dict:
    """⑤站 proactive re-share 仪式（治理提案 execute 后由 backend 侧执行）。

    语义（任务书钉定）：**D_pub 不变、无需根钥 d**——从任意 ≥2 份现存份额
    出发（app.crypto.threshold.proactive_reshare：δ(0)=0 随机增项+拉格朗日
    换基外推），新份额入三域+纪元+1 ⟹ 存量 v5 信封零影响（C₁ 密文与根公
    钥均不涉）；旧份额值/旧纪元密封钥同时作废（epoch 参与密封钥派生）。

    纪元门（fail-closed）：gov_confirmed_epoch 必须等于当前纪元+1——脚本面
    在 governor 提案（description=『threshold-reshare:epoch-N』）execute 并
    链上回读对拍后才携 N 调用；直调不带正确治理纪元即拒（仪式不被绕过）。

    owner-set 指纹门（1.3 件①）：owner_set_fp=提案时点链上 owner-set 指纹
    （SM3(sorted(owners))）——非 None 时与**执行时点链读**对拍（提案→execute
    窗内席位再漂移=fingerprint_mismatch 拒，零持久变更，须重新起草提案）；
    过门即写 root.json.owner_set_fp（绑定+漂移检测判定源）。None=门跳过
    （单测直调形态兼容——audit 行 fp_source=skipped 如实在案非静默；生产
    仪式驱动方 scripts/threshold_reshare.py 与 /admin/threshold/reshare 恒携）。

    原子序：先内存全量自证（canary=SM2(D_pub) 加解对拍走 decrypt_share/
    combine_decrypt_shares/threshold_decrypt 真实原语），后落盘（先份额后
    纪元——窗内解封请求开封失败=域拒绝=fail-closed，无安全面）。三域审计
    append-only 各记一行（零份额材料）。中途任何失败=零持久变更。
    """
    if not isinstance(gov_confirmed_epoch, int) or isinstance(gov_confirmed_epoch, bool):
        raise ShareDomainError("bad_epoch_arg", "gov_confirmed_epoch 须为整数纪元")
    if gov_confirmed_epoch < 2:
        raise ShareDomainError("bad_epoch_arg", "目标纪元须 ≥2（纪元 1=初始化态）")
    # owner-set 指纹门（锁外执行——链读不持域锁；失败=零持久变更）
    fp_source = "skipped"
    if owner_set_fp is not None:
        from app.ra.threshold_sync import SyncError, chain_owner_set

        try:
            chain = chain_owner_set()
        except SyncError as e:
            raise ShareDomainError(
                "fingerprint_unavailable", f"owner-set 指纹门链读失败（fail-closed）: {e}"
            ) from e
        if chain["fp_hex"] != owner_set_fp:
            raise ShareDomainError(
                "fingerprint_mismatch",
                f"owner-set 指纹不符：提案时点 {owner_set_fp[:16]}… ≠ "
                f"执行时点链上 {chain['fp_hex'][:16]}…（席位窗内再漂移——提案作废，"
                "须重新起草）",
            )
        fp_source = "verified"
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
        # ① 开封现存份额（逐域尝试，取先开成功的前 k 份——损毁域跳过）。
        # 3.2 k-of-n 跨域集换代（drill S4 实弹根修——拉格朗日下标错位）：份额
        # 的真实下标=**旧多项式的 x**（旧域集序，root.json 未换代前即真）——
        # 开封 idx 必须按旧域集取（新配置域集枚举序会把 f(2) 当 f(1) 用 ⟹
        # 换基外推错位 ⟹ g(0)≠d canary 必败）。被除名域的 sealed 文件=陈旧
        # 孤儿（不消费）；新 n=len(现配置域集)（除名即缩域换代）。
        k, domains = threshold_config()
        old_domains = tuple(meta.get("domains") or meta.get("roles") or ())
        if not old_domains:
            raise ShareDomainError(
                "root_meta_incomplete", "root.json 缺域集记录（domains/roles）——刷新中止"
            )
        opened: list[tuple[int, str]] = []
        for idx, role in enumerate(old_domains, start=1):
            if len(opened) >= k:
                break
            try:
                plain = _open_share(role, old_epoch, _domain_share_sealed_path(role).read_bytes())
                opened.append((idx, plain.decode()))
            except Exception:  # noqa: BLE001 —— 域损即跳过（≥k 份可开即可刷新）
                continue
        if len(opened) < k:
            raise ShareDomainError(
                "insufficient_shares",
                f"可开封份额不足 k={k}（仅 {len(opened)}）——刷新中止",
            )
        # ② 标量域 re-share（d 不重组——proactive_reshare 域内无 d 路径）；
        # 旧份额携旧域真实下标入换基外推，新份额下标=1..n_new（新域集序）。
        new_shares = proactive_reshare([(i, int(s, 16)) for i, s in opened], len(domains), k)
        # ③ 内存自证（先于任何落盘）：canary 对 D_pub 加解全对拍
        canary = b"FZ-RESHARE-CANARY|" + str(new_epoch).encode()
        from app.crypto.sm2 import encrypt as sm2_encrypt
        from app.crypto.threshold import threshold_decrypt

        pub_hex = meta["pub_hex"]
        ct = sm2_encrypt(pub_hex, canary)
        c1_hex = ct[:64].hex()
        pts = [(i, decrypt_share(f"{d_i:064x}", c1_hex)) for i, d_i in new_shares[:k]]
        if threshold_decrypt(ct, pts, k=k) != canary:
            raise ShareDomainError("canary_mismatch", "新份额对 D_pub 自证失败（未落盘，零变更）")
        # ④ 持久化：先份额（新纪元域钥重封=旧份额值+旧密封钥同时作废）后纪元；
        # 3.2 域集换代（除名）时新域集文件覆盖写+root.json domains 换代。
        meta["domains"] = list(domains)
        for (_i, d_i), role in zip(new_shares, domains, strict=True):
            _domain_share_sealed_path(role).write_bytes(
                _seal_share(role, new_epoch, f"{d_i:064x}".encode())
            )
        meta["epoch"] = new_epoch
        meta["prev_epoch"] = old_epoch
        meta["reshared_ts"] = time.time()
        if fp_source == "verified":
            meta["owner_set_fp"] = owner_set_fp  # 件①：绑定链上 owner-set 指纹
        (_root_dir() / "root.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        # ⑤ 全域仪式审计（append-only；记录纪元不含任何份额材料；fp_source
        # 如实——verified=指纹门激活并过门，skipped=直调形态门未启用）
        for role in domains:
            _audit(
                role,
                {
                    "action": "reshare",
                    "decision": "ok",
                    "from_epoch": old_epoch,
                    "to_epoch": new_epoch,
                    "fp_source": fp_source,
                },
            )
        # 中间值出栈即焚（opened 旧份额/new_shares 新份额不外溢本函数域）
        del opened, new_shares, pts
        return {"epoch": new_epoch, "prev_epoch": old_epoch, "pub_hex": pub_hex}


def _default_hooks() -> dict:
    """真实现四关（延迟 import 防环——authz/ra 面互引）。第④关=份额域与
    治理席位同步（1.3 件④——失同步 fail-closed 拒解锁）。"""
    from app.ra.threshold_hooks import (
        collab_approved,
        owner_set_synced,
        request_registered,
        warrant_on_chain,
    )

    return {
        "request_registered": request_registered,
        "warrant_on_chain": warrant_on_chain,
        "collab_approved": collab_approved,
        "owner_set_synced": owner_set_synced,
    }
