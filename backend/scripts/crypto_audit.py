"""密码技术审计套件（crypto_audit）——三套件之一 · 批 1（docs/三大测试体系设计方案.md §3.1）。

定位：算法正确性之上测**协议与生命周期**。八模块：

    C1 向量对拍        三语言共享 JSON 事实源（app/crypto/vectors/*.json）+ tests 内联
                       HMAC/PBKDF2 官方向量，全量回放 Python 实现侧（app.crypto.*）
    C2 信封版本矩阵    KEK 密封 v3 正回环 + AAD 三处篡改（盐/nonce/tag 各 1 字节）+
                       跨盐解封 + v1/v2 旧格式显式拒绝（不许静默兼容）
    C3 电路边界×门控   app/authz/service.py 受理门控五步负例函数级驱动（引用拒绝码）
                       + 电路 pin 指纹=链上公示正对照 + zkc 期望门垃圾证明 fail-closed
    C4 嫁接拒绝        AUTH 证明配 TRAIL 期望 / TRAIL 形态配 AUTH 期望 / 错误电路 spec /
                       换 vkey——垃圾 proof 驱动 zkc verify-instances 期望门，全部必拒
    C5 密钥生命周期    两次签发出示钥互异（M_A′ pk′ 段逐位对拍）、登出会话焚毁、
                       零出示钥私钥存储断言、吊销传播后签发预检拒绝（holder_revoked/
                       cred_revoked）
    C6 双控签名链      缺审计签/缺管理员签/坏签/篡改 note 拒 + 双签全过 + 历史双签复验
    C7 恒时性护栏      KEK derive 与 SM2 验签（对/错输入各 ≥3000 次，gc 隔离+预热 50
                       轮）时延全分布（p1/p50/p99+均值+标准差）对比，宽松护栏：
                       错误 p50 > 正确 p50 ×1.3 = fail（1.1~1.3 = xfail）
    C8 模糊注入护栏    解封函数与 SM2 验签灌 ≥1000 轮随机畸形输入（独立子进程）：
                       全部拒绝 + 进程不崩溃 + 无未捕获异常逃逸；任一通过=attack_success

形态：全函数级 + 临时 SQLite 夹具（零演示库/零真链副作用）；C3/C4 的 zkc 实弹直接
调本地 zksvc/target/release/zkc.exe（期望门秒级，不跑真证明）。

用法：
    cd backend && python scripts/crypto_audit.py [--quick]
输出：backend/reports/crypto-report-<run_id>.json（schema=testkit/report.py 底盘）
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
UAS = BACKEND.parent
ZKSVC = UAS / "zksvc"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "scripts"))

# 函数级夹具纪律：fake 链锚——零真链写面（进程局部 env，不影响外部运行栈）
os.environ.setdefault("FZ_CHAIN_ANCHOR", "fake")

from testkit.report import Module, ReportBuilder  # noqa: E402

VEC_DIR = BACKEND / "app" / "crypto" / "vectors"
# 电路 pin 链上公示值（docs/性能档案.md「电路换代批」：2026-10-01 换代仪式 tx=0x01cefa9b）
# 电路 pin 链上公示值（⑦代修复重钉 2026-10-06：prove 窗根修——basefold batch_open_inner
# 掩蔽项并入未归一槽的 c²λ 组合缺陷（详见 vendor 注释）；电路本体零变化，仅 vendor
# basefold.rs 修复+MANIFEST 就地重钉 148 文件/aggregate 4aaf67d0…；
# 重公示 tx=0xb7209b334fb97d88f5f7da6631d434e4a84cb9e90504d9a170460e472952bce2）
# 电路 pin 链上公示值（prove 级 vendor 双根修重钉 2026-10-06：缺陷 A=交织档批次树
# serde 丢树确定性重建+根对账（zk_cache 命中路径）；缺陷 B=窗口累加 P=Q 行仿射
# 完备化（倍点斜率）。电路本体（约束/列布局）零变化，MANIFEST 就地重钉 148 文件/
# aggregate e6481fb5…；重公示 tx=0xc215983bcafc6f0808cd8dc3373c386542ad9702652ccdd3fa687ad4202e7b8d）
PIN_LOCAL_EXPECTED = "SM3(4201a82|e6481fb56957dd8520acd94236f9880a93264e04ee48b00f9a1ebcdb974a86e8)"
PIN_CHAIN_DIGEST_EXPECTED = "5bc38e56230f35ce927fe8ef6858521ab6e691a364c2b7acd00d875094eb8374"


def _load_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _utc_naive():
    """naive UTC now（与 app.accounts.service._utcnow 同口径——不触发弃用告警）。"""
    from datetime import UTC

    return datetime.now(UTC).replace(tzinfo=None)


def _flip_hex_byte(hexstr: str, pos: int = 0) -> str:
    """hex 串指定字节翻转 1 bit（篡改面最小形态）。"""
    b = bytearray(bytes.fromhex(hexstr))
    b[pos % len(b)] ^= 0x01
    return b.hex()


def _expect_reject(
    m: Module,
    name: str,
    fn,
    *,
    defense_ref: str,
    expected: str = "拒绝（抛异常/返回 False）",
    detail=None,
):
    """负例统一裁决：被测函数必须拒绝。意外放行 → attack_success=true。"""
    try:
        out = fn()
    except Exception as e:  # noqa: BLE001  拒绝面=异常即拒
        m.pass_(
            name,
            defense_ref=defense_ref,
            detail={**(detail or {}), "rejected_by": type(e).__name__},
        )
        return
    accepted = out is True or (not isinstance(out, bool) and out not in (None, False))
    if accepted:
        m.fail(
            name,
            expected=expected,
            actual=f"被接受（返回 {type(out).__name__}）",
            defense_ref=defense_ref,
            attack_success=True,
            detail=detail,
        )
    else:
        m.pass_(name, defense_ref=defense_ref, detail=detail)


# ============================================================================
# C1 向量对拍
# ============================================================================


def c1_vectors(rb: ReportBuilder) -> None:
    from app.accounts.kdf import derive_kek
    from app.crypto.hmac_sm3 import hmac_sm3
    from app.crypto.kdf import pbkdf2_hmac_sm3
    from app.crypto.sm2 import generate_keypair, sign, verify, verify_digest
    from app.crypto.sm3 import sm3_bytes
    from app.crypto.sm4 import SM4GCM, PureSM4GCM
    from tests.test_crypto_hmac import VECTORS as HMAC_VECTORS
    from tests.test_crypto_kdf import VECTORS as PBKDF2_VECTORS

    m = rb.module("C1_vectors", "C1 向量对拍（共享 JSON 事实源 × Python 实现）")
    total = 0
    matched = 0

    def _check(name: str, ok: bool, defense: str, detail=None, latency_ms=None) -> None:
        nonlocal total, matched
        total += 1
        if ok:
            matched += 1
            m.pass_(name, defense_ref=defense, latency_ms=latency_ms, detail=detail)
        else:
            m.fail(name, expected="MATCH", actual="MISMATCH", defense_ref=defense, detail=detail)

    # --- SM3（GB/T 32905 附录 A + 空消息一致性例） ---
    sm3j = _load_json(VEC_DIR / "sm3_official.json")
    for v in sm3j["vectors"] + sm3j["extra_consistency"]:
        _check(
            f"C1-SM3 {v['name']}",
            sm3_bytes(bytes.fromhex(v["msg_hex"])).hex() == v["digest_hex"].lower(),
            "app/crypto/sm3.py",
        )

    # --- SM2（GB/T 32918 验证方程五元组 + TS 前端对拍夹具 + 活体签验回环） ---
    sm2j = _load_json(VEC_DIR / "sm2_official.json")
    for v in sm2j["verify_digest_vectors"]:
        _check(
            f"C1-SM2 {v['name']} 正验",
            verify_digest(v["pub_hex"], bytes.fromhex(v["e_hex"]), v["sig_hex"]) is True,
            "app/crypto/sm2.py:verify_digest",
        )
        bad = "0" + v["sig_hex"][1:]
        _check(
            f"C1-SM2 {v['name']} 篡改拒",
            verify_digest(v["pub_hex"], bytes.fromhex(v["e_hex"]), bad) is False,
            "app/crypto/sm2.py:verify_digest",
        )
    fx = sm2j["ts_parity_fixture"]
    msg = bytes.fromhex(fx["msg_hex"])
    _check(
        "C1-SM2 ts_parity 前端对拍（正验+邻字节拒）",
        verify(fx["pub_hex"], msg, fx["sig_hex"]) is True
        and verify(fx["pub_hex"], msg + b"x", fx["sig_hex"]) is False,
        "app/crypto/sm2.py:verify",
    )
    t0 = time.perf_counter()
    sk, pk = generate_keypair()
    live_msg = b"FZ-CRYPTO-AUDIT-C1-LIVE"
    live_sig = sign(sk, live_msg)
    bad_sig = _flip_hex_byte(live_sig, 0)  # 确定性异或翻转——不会与原签名重合
    _check(
        "C1-SM2 活体签验回环（generate→sign→verify）",
        verify(pk, live_msg, live_sig) is True and verify(pk, live_msg, bad_sig) is False,
        "app/crypto/sm2.py",
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )

    # --- SM4（RFC 8998 A.1 + GB/T 36624 C.5：双引擎逐字节+解密回环；ECB 裸块） ---
    sm4j = _load_json(VEC_DIR / "sm4_official.json")
    for eng_name, eng_cls in (("当前引擎", SM4GCM), ("Pure 参考引擎", PureSM4GCM)):
        for v in sm4j["gcm_vectors"]:
            t0 = time.perf_counter()
            g = eng_cls(bytes.fromhex(v["key_hex"]))
            ct, tag = g.encrypt(
                bytes.fromhex(v["iv_hex"]), bytes.fromhex(v["pt_hex"]), bytes.fromhex(v["aad_hex"])
            )
            pt_back = g.decrypt(bytes.fromhex(v["iv_hex"]), ct, tag, bytes.fromhex(v["aad_hex"]))
            _check(
                f"C1-SM4-GCM {v['name']} [{eng_name}]",
                ct.hex().upper() == v["ct_hex"]
                and tag.hex().upper() == v["tag_hex"]
                and pt_back == bytes.fromhex(v["pt_hex"]),
                "app/crypto/sm4.py",
                latency_ms=round((time.perf_counter() - t0) * 1000, 2),
            )
    ecb = sm4j["ecb_vectors"][0]
    _check(
        "C1-SM4-ECB GB/T 32907 A 裸块（Pure 引擎）",
        PureSM4GCM(bytes.fromhex(ecb["key_hex"]))
        ._raw_block(bytes.fromhex(ecb["pt_hex"]))
        .hex()
        .upper()
        == ecb["ct_hex"],
        "app/crypto/sm4.py:PureSM4GCM._raw_block",
    )

    # --- HMAC-SM3（GmSSL C 官方套件/Wycheproof 子集，tests 内联事实源） ---
    for key, msg_h, tag, name in HMAC_VECTORS:
        _check(
            f"C1-HMAC-SM3 {name}",
            hmac_sm3(bytes.fromhex(key), bytes.fromhex(msg_h)).hex() == tag,
            "app/crypto/hmac_sm3.py",
        )

    # --- PBKDF2-HMAC-SM3（GmSSL C 官方套件子集，tests 内联事实源） ---
    for pw, salt, iters, dklen, expect, src in PBKDF2_VECTORS:
        t0 = time.perf_counter()
        out = pbkdf2_hmac_sm3(pw, salt, iters, dklen).hex()
        _check(
            f"C1-PBKDF2-SM3 {src}",
            out == expect,
            "app/crypto/kdf.py:pbkdf2_hmac_sm3",
            latency_ms=round((time.perf_counter() - t0) * 1000, 1),
        )

    # --- 密码 KEK 交叉对拍锚（JS 前端 deriveKekV4/_legacyV3 实测产出，test_accounts 同源） ---
    # v4 现行口径（PBKDF2-HMAC-SM3——node+hash-wasm createSM3 实测产出，与
    # Python hashlib/pure 双引擎逐字节一致）
    from app.accounts.kdf import _legacy_v3

    _check(
        "C1-KEK v4 JS 对拍锚（8 轮）",
        derive_kek("Test-Pass-8", "aabbccdd", 8) == "1277e3342905e4695e67bde5dd3d89dd",
        "app/accounts/kdf.py:derive_kek（PBKDF2-HMAC-SM3）",
    )
    t0 = time.perf_counter()
    ok_v4 = derive_kek("Test-Pass-8", "aabbccdd", 21000) == "0b1e8a811af3d432501681bf8372023b"
    _check(
        "C1-KEK v4 JS 对拍锚（21000 轮）",
        ok_v4,
        "app/accounts/kdf.py:derive_kek（PBKDF2-HMAC-SM3）",
        latency_ms=round((time.perf_counter() - t0) * 1000, 1),
    )
    # v3 legacy 对拍锚（旧 SM3 迭代链——存量密封件兼容面，不删不升档）
    _check(
        "C1-KEK v3 legacy 对拍锚（8 轮）",
        _legacy_v3("Test-Pass-8", "aabbccdd", 8) == "b7a19b8f13a8ea0768e16242baaf6d14",
        "app/accounts/kdf.py:_legacy_v3",
    )
    _check(
        "C1-KEK v3 legacy 对拍锚（21000 轮）",
        _legacy_v3("Test-Pass-8", "aabbccdd", 21000) == "8c30c8ae0a6067df7085e7230c92096d",
        "app/accounts/kdf.py:_legacy_v3",
    )

    rate = round(matched / total, 4) if total else 0.0
    if matched == total:
        m.pass_(
            "C1-99 全量 MATCH 率汇总",
            defense_ref="app/crypto/ + app/accounts/kdf.py",
            detail={"vectors": total, "matched": matched, "match_rate": rate},
        )
    else:
        m.fail(
            "C1-99 全量 MATCH 率汇总",
            expected=f"全 MATCH（{total}/{total}）",
            actual=f"{matched}/{total}",
            defense_ref="app/crypto/ + app/accounts/kdf.py",
            detail={"vectors": total, "matched": matched, "match_rate": rate},
        )


# ============================================================================
# C2 信封版本矩阵
# ============================================================================

AAD_V3 = b"FZ-KEYSTORE-v3|pass"  # keystore.ts AAD_PASS_V3 同源（v3 单因子信封）
AAD_V4 = b"FZ-KEYSTORE-v4|pass"  # keystore.ts AAD_PASS_V4 同源（v4=PBKDF2 口径）


def _seal_v3(
    sk_hex: str,
    passphrase: str,
    *,
    salt_hex: str | None = None,
    nonce_hex: str | None = None,
    pk_hex: str | None = None,
) -> str:
    """v3 信封密封（keystore.ts legacy 同构——SM3 迭代链 KDF KEK + SM4-GCM）。
    批 2 后 v3=legacy 兼容面：KDF 显式走 _legacy_v3（新密封一律 v4）。"""
    from app.accounts.kdf import _legacy_v3
    from app.crypto.sm2 import pubkey_from_priv
    from app.crypto.sm4 import SM4GCM

    salt = salt_hex or secrets.token_hex(16)
    nonce = nonce_hex or secrets.token_hex(12)
    kek = bytes.fromhex(_legacy_v3(passphrase, salt))
    ct, tag = SM4GCM(kek).encrypt(bytes.fromhex(nonce), bytes.fromhex(sk_hex), AAD_V3)
    return json.dumps(
        {
            "v": 3,
            "pk": pk_hex if pk_hex is not None else pubkey_from_priv(sk_hex),
            "enc": {"salt": salt, "nonce": nonce, "ct": ct.hex(), "tag": tag.hex()},
        }
    )


def _unseal_v3(blob_text: str, passphrase: str) -> str:
    """信封解封（app.accounts.envelope:unseal_envelope 版本分派——v3 legacy/
    v4 现行；C2/C8 共用单一事实源）：GCM 认证失败/形态坏=抛异常。"""
    from app.accounts.envelope import unseal_envelope

    return unseal_envelope(blob_text, passphrase)


def _seal_v4(sk_hex: str, passphrase: str, *, iterations: int = 4096) -> str:
    """v4 信封密封（envelope 单一事实源——PBKDF2-HMAC-SM3+iter 落盘）。"""
    from app.accounts.envelope import seal_envelope_v4
    from app.crypto.sm2 import pubkey_from_priv

    return seal_envelope_v4(
        sk_hex, pubkey_from_priv(sk_hex), passphrase, iterations=iterations
    )


def c2_envelope(rb: ReportBuilder) -> None:
    from app.accounts.service import AccountError, _validate_sealed_blob
    from app.crypto.sm2 import generate_keypair

    m = rb.module("C2_envelope", "C2 KEK 信封版本矩阵（v4 现行+v3 legacy 回环/篡改/旧版显式拒绝）")
    sk, pk = generate_keypair()
    pw_ok = "Audit-Correct-Pw-1"
    pw_bad = "Audit-Wrong---Pw-1"  # 等长错误口令（仅口令域差异）
    blob = _seal_v4(sk, pw_ok)
    blob_legacy = _seal_v3(sk, pw_ok)
    obj = json.loads(blob)
    enc = obj["enc"]

    # ① 正回环：v4 密封→解封逐字节一致 + 服务端结构门放行
    t0 = time.perf_counter()
    back = _unseal_v3(blob, pw_ok)
    struct_ok = True
    try:
        _validate_sealed_blob(blob, pk)
    except AccountError:
        struct_ok = False
    if back == sk and struct_ok:
        m.pass_(
            "C2-01 v4 正回环（seal→unseal 逐字节 + 结构门放行）",
            defense_ref="app/crypto/sm4.py:SM4GCM + app/accounts/envelope.py + "
            "app/accounts/service.py:_validate_sealed_blob",
            latency_ms=round((time.perf_counter() - t0) * 1000, 1),
        )
    else:
        m.fail(
            "C2-01 v4 正回环（seal→unseal 逐字节 + 结构门放行）",
            expected="解封=原私钥 且 结构门放行",
            actual=f"回环一致={back == sk} 结构门放行={struct_ok}",
            defense_ref="app/crypto/sm4.py:SM4GCM",
        )

    # ①b legacy：v3 存量口径回环（版本分派仍可解——迁移语义根基）
    back_l = _unseal_v3(blob_legacy, pw_ok)
    struct_l = True
    try:
        _validate_sealed_blob(blob_legacy, pk)
    except AccountError:
        struct_l = False
    if back_l == sk and struct_l:
        m.pass_(
            "C2-01b v3 legacy 正回环（版本分派仍可解+结构门放行）",
            defense_ref="app/accounts/envelope.py:unseal_envelope（v3→_legacy_v3）",
        )
    else:
        m.fail(
            "C2-01b v3 legacy 正回环（版本分派仍可解+结构门放行）",
            expected="解封=原私钥 且 结构门放行",
            actual=f"回环一致={back_l == sk} 结构门放行={struct_l}",
            defense_ref="app/accounts/envelope.py:unseal_envelope",
        )

    # ①c 惰性重封：v3 存量件同口令 v4 重封→解封一致（无感升级路径）
    from app.accounts.envelope import reseal_v4

    blob_up = reseal_v4(blob_legacy, pw_ok, iterations=4096)
    back_up = _unseal_v3(blob_up, pw_ok)
    up_ok = (
        back_up == sk
        and json.loads(blob_up)["v"] == 4
        and json.loads(blob_up)["enc"]["kdf"] == "pbkdf2-sm3"
    )
    if up_ok:
        m.pass_(
            "C2-01c 惰性重封（v3→v4 同口令升级回环）",
            defense_ref="app/accounts/envelope.py:reseal_v4",
        )
    else:
        m.fail(
            "C2-01c 惰性重封（v3→v4 同口令升级回环）",
            expected="重封件=v4 且解封=原私钥",
            actual=f"回环一致={back_up == sk} v={json.loads(blob_up)['v']}",
            defense_ref="app/accounts/envelope.py:reseal_v4",
        )

    # ② 错口令
    _expect_reject(
        m,
        "C2-02 错口令解封",
        lambda: _unseal_v3(blob, pw_bad),
        defense_ref="app/crypto/sm4.py:SM4GCM.decrypt（GCM 认证）",
        detail={"口令": "与密封口令不同（形态等长）"},
    )

    # ③④⑤⑥ 盐/nonce/tag/ct 各改 1 字节
    for nm, enc_mut, axis in (
        (
            "C2-03 盐改 1 字节",
            dict(enc, salt=_flip_hex_byte(enc["salt"])),
            "KDF 盐（KEK 派生输入）",
        ),
        ("C2-04 nonce 改 1 字节", dict(enc, nonce=_flip_hex_byte(enc["nonce"])), "GCM IV"),
        ("C2-05 tag 改 1 字节", dict(enc, tag=_flip_hex_byte(enc["tag"])), "GCM 认证标签"),
        ("C2-06 ct 改 1 字节", dict(enc, ct=_flip_hex_byte(enc["ct"])), "GCM 密文"),
    ):
        blob_mut = json.dumps(dict(obj, enc=enc_mut))
        _expect_reject(
            m,
            nm,
            lambda b=blob_mut: _unseal_v3(b, pw_ok),
            defense_ref="app/crypto/sm4.py:SM4GCM.decrypt",
            detail={"篡改轴": axis},
        )

    # ⑦ 跨盐解封（他账户盐派生 KEK 套本信封——跨账户隔离面）
    salt_b = json.loads(_seal_v3(sk, pw_ok, salt_hex=secrets.token_hex(16)))["enc"]["salt"]
    blob_ab = json.dumps(dict(obj, enc=dict(enc, salt=salt_b)))
    _expect_reject(
        m,
        "C2-07 跨盐解封（他账户盐 KEK 套本信封）",
        lambda: _unseal_v3(blob_ab, pw_ok),
        defense_ref="app/accounts/kdf.py:derive_kek（盐域分离）",
        detail={"机制": "不同盐→不同 KEK→GCM 认证失败"},
    )

    # ⑧⑨ v1/v2 旧格式显式拒绝（不许静默兼容）
    v1_blob = json.dumps({"v": 1, "pk": pk, "enc": enc})
    v2_blob = json.dumps(
        {"v": 2, "pk": pk, "enc": enc, "rec": json.loads(_seal_v3(sk, pw_ok))["enc"]}
    )

    def _v1() -> bool:
        """True=被放行（攻击面）；False=显式拒绝。"""
        try:
            _validate_sealed_blob(v1_blob, pk)
        except AccountError as e:
            if e.code != "bad_blob":
                raise
            return False
        return True

    def _v2() -> bool:
        try:
            _validate_sealed_blob(v2_blob, pk)
        except AccountError as e:
            if e.code != "bad_blob":
                raise
            return False
        return True

    _expect_reject(
        m,
        "C2-08 v1 旧格式显式拒绝",
        _v1,
        defense_ref="app/accounts/service.py:_validate_sealed_blob",
        expected="AccountError(bad_blob)",
        detail={"机制": "信封版本字段 v=1 非当前代——注册/激活面拒收（不许静默兼容）"},
    )
    _expect_reject(
        m,
        "C2-09 v2 旧格式显式拒绝（真实双槽形态 enc+rec）",
        _v2,
        defense_ref="app/accounts/service.py:_validate_sealed_blob",
        expected="AccountError(bad_blob)",
        detail={"机制": "v2 双因子信封不入 v3 单因子面（AAD 分域不可互解+版本门）"},
    )

    # ⑩ pk 错配（跨账户绑定）
    _sk2, pk2 = generate_keypair()

    def _pkmix() -> bool:
        try:
            _validate_sealed_blob(blob, pk2)
        except AccountError as e:
            if e.code != "bad_blob":
                raise
            return False
        return True

    _expect_reject(
        m,
        "C2-10 信封 pk 与登记公钥错配（跨账户隔离）",
        _pkmix,
        defense_ref="app/accounts/service.py:_validate_sealed_blob",
        expected="AccountError(bad_blob)",
        detail={"机制": "密封件绑定账户公钥——错配即拒，不带病入库"},
    )


# ============================================================================
# C3 电路边界 × 受理门控矩阵
# ============================================================================


def _fake_deps(nonce_used=None, rev_root="00" * 32):
    """受理门控链面替身（tests/test_authz_gate.py FakeDeps 同构）。"""
    from app.authz import service

    obj = service.AuthzDeps()
    obj._used = nonce_used or set()
    obj._rev = rev_root
    obj.chain_nonce_used = lambda n: n in obj._used
    obj.chain_rev_root = lambda: (1, obj._rev)
    obj.pin_fingerprint = lambda: PIN_LOCAL_EXPECTED
    return obj


def _fe_u64(v: int) -> str:
    from app.authz.service import _fe_be32_hex_from_u64

    return _fe_be32_hex_from_u64(v)


def _gate_case(
    plan_hash_hex: str,
    nonce_hex: str,
    *,
    t_start: int,
    rev_root="00" * 32,
    class_id: int = 0,
    overrides: dict | None = None,
) -> dict:
    """造合法出证产物目录（instances 同源折算——test_authz_gate._make_case 同构）。"""
    from app.authz.policy import POLICY_VERSION, get_rule
    from app.authz.service import (
        _fe_be32_hex_from_bytes32,
        _fe_be32_hex_from_digest,
        binding_challenge,
    )
    from app.crypto.sm3 import sm3_bytes

    d = os.path.join(tempfile.mkdtemp(prefix="fzca-case"), plan_hash_hex[:16])
    os.makedirs(d, exist_ok=True)
    # 实例面 26 项（⑥代 SN 绑定加实例 25=sn_hash 后服务面要求 >=26——本函
    # 数此前仍造 25 项致 C3 族全拒（⑥代换代未回写，⑦代批收口）。
    inst = ["0" * 64] * 26
    # SN 绑定换代（2026-10-06 ⑦代批收口）：实例 25=sn_hash——与 _gate_kwargs
    # build_message 的 serial 常量同源（服务端权威 SM3(serial) 折叠口径）。
    inst[25] = _fe_be32_hex_from_bytes32(sm3_bytes(b"FZ-SN-CRYPTO-AUDIT"))  # 词折叠环 fold_words_be（S1 根修定谳口径）
    challenge = binding_challenge(plan_hash_hex, nonce_hex)
    inst[19] = _fe_be32_hex_from_digest(sm3_bytes(bytes.fromhex(challenge)))
    pred_str = plan_hash_hex + "|" + nonce_hex + "|" + POLICY_VERSION
    pred_domain = b"FZ-ZKSVC-PRED-ID" + b"\x01"
    inst[20] = _fe_be32_hex_from_digest(sm3_bytes(pred_domain + pred_str.encode()))
    inst[21] = _fe_u64(t_start)
    try:
        inst[22] = _fe_u64(get_rule(class_id)[1])
    except Exception:  # noqa: BLE001  未开放类（门控会在政策查表处先拒——实例仅备形）
        inst[22] = _fe_u64(1)
    inst[23] = _fe_be32_hex_from_bytes32(bytes.fromhex(rev_root))
    inst[24] = _fe_u64(class_id)
    for idx, val in (overrides or {}).items():
        inst[idx] = val
    paths = {
        "dir": d,
        "proof": os.path.join(d, "proof.bin"),
        "instances": os.path.join(d, "instances.json"),
        "verifier_param": os.path.join(d, "verifier_param.bin"),
        # 绑定同源：_gate_kwargs 缺省回读本对值——实例 19/20 逐位核对的前提
        "plan_hash_hex": plan_hash_hex,
        "nonce_hex": nonce_hex,
    }
    with open(paths["proof"], "wb") as f:
        f.write(b"proof")
    with open(paths["instances"], "w", encoding="utf-8") as f:
        f.write(json.dumps({"instances": inst}))
    with open(paths["verifier_param"], "wb") as f:
        f.write(b"vp")
    return paths


def _gate_kwargs(
    case: dict,
    *,
    session_pk_hex: str,
    t_start: int,
    t_end: int,
    rev_root="00" * 32,
    class_id: int = 0,
    over: dict | None = None,
    plan_hash_hex: str | None = None,
    nonce_hex: str | None = None,
    seed_session=None,
) -> dict:
    """受理门控入参组装（诚实子凭证材料——RA 同源签发面）。

    plan/nonce 须与 _gate_case 的绑定同源（实例 19/20 逐位核对的前提）——缺省随机
    生成（此时 case 必须由同一对值构造，调用方负责传递）。"""
    from app.crypto.sm3 import sm3_bytes
    from app.kms import ra_signing_keypair
    from app.ra.credential import build_message, sign_credential

    ra_priv, ra_pub = ra_signing_keypair()
    msg = build_message(
        ra_pub,
        secrets.token_bytes(32),
        secrets.token_bytes(16),
        b"110101199001011234",
        3,
        b"FZ-SN-CRYPTO-AUDIT",
        session_pk_hex,
        1900000000,
    )
    sig = sign_credential(ra_priv, msg)
    base = dict(
        session_pk_hex=session_pk_hex,
        sub_cred_message_hex=msg.hex(),
        sub_sig_hex=sig,
        sub_cred_hash_hex=sm3_bytes(msg).hex(),
        # plan/nonce 与 case 绑定同源（实例 19/20 逐位核对的前提）——显式传入优先
        nonce_hex=nonce_hex or case.get("nonce_hex") or secrets.token_bytes(16).hex(),
        plan_hash_hex=plan_hash_hex or case.get("plan_hash_hex") or secrets.token_bytes(32).hex(),
        class_id=class_id,
        proof_path=case["proof"],
        spec_path=case["instances"],
        rev_root_hex=rev_root,
        t_start=t_start,
        t_end=t_end,
    )
    base.update(over or {})
    # SN 溯源落库（⑥代查库面回写）：sub_cred_hash→SubCredential→Credential
    #（serial 原文=与实例 25 同源的常量；幂等——同 hash 重跑不重复插）。
    if seed_session is not None:
        import datetime as dt

        from sqlalchemy import select

        from app.ra.models import Credential, SubCredential

        if (
            seed_session.scalar(
                select(SubCredential).where(
                    SubCredential.sub_cred_hash_hex == base["sub_cred_hash_hex"]
                )
            )
            is None
        ):
            cred = Credential(
                user_id=0,
                commitment_hex=secrets.token_bytes(32).hex(),
                master_cred_hash_hex=secrets.token_bytes(32).hex(),
                sn_hash_hex=sm3_bytes(b"FZ-SN-CRYPTO-AUDIT").hex()[:32],
                serial_hex=b"FZ-SN-CRYPTO-AUDIT".hex(),
                id_cipher=b"",
                cert_level=3,
                class_id=0,
                expires_at=dt.datetime(2030, 1, 1),
                status="active",
            )
            seed_session.add(cred)
            seed_session.flush()
            seed_session.add(
                SubCredential(
                    credential_id=cred.id,
                    sub_cred_hash_hex=base["sub_cred_hash_hex"],
                    message_hex=base["sub_cred_message_hex"],
                    sig_hex=base["sub_sig_hex"],
                    holder_pub_hex=base["session_pk_hex"],
                    expires_at=dt.datetime(2030, 1, 1),
                )
            )
            seed_session.commit()
    return base


def c3_gate_matrix(rb: ReportBuilder) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.authz import models as _azm  # noqa: F401  先注册共享 Base 再建表
    from app.ra.models import Base

    m = rb.module("C3_gate_matrix", "C3 电路边界×受理门控矩阵（函数级）+ pin 对照 + zkc 期望门")
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)  # 须在 authz 模型导入之后（applications 等表注册）
    session = sessionmaker(bind=eng)()
    try:
        _c3_body(rb, m, session, eng)
    finally:
        # 确定性释放（main 线程）：内存库连接 flag=True（SingletonThreadPool）——
        # 若留给 GC 且落在后台线程（如 C6 执行线程）即触发跨线程 rollback 噪声
        session.close()
        eng.dispose()


def _c3_body(rb: ReportBuilder, m: Module, session, eng) -> None:
    from app.authz import service
    from app.authz.models import Receipt
    from app.crypto.sm2 import generate_keypair

    _sk, spk = generate_keypair()
    now = int(time.time())
    max_window = int(os.environ.get("FZ_MAX_TOKEN_WINDOW_S", "21600"))

    def _negative(
        item: str,
        expected_code: str,
        kwargs: dict,
        defense: str,
        deps=None,
        expect_msg: str | None = None,
    ) -> None:
        try:
            service.admission_gate(session, deps or _fake_deps(), **kwargs)
        except service.AuthzError as e:
            ok = e.code == expected_code and (expect_msg is None or expect_msg in e.message)
            if ok:
                m.pass_(item, defense_ref=defense, detail={"reject_code": e.code})
            else:
                m.fail(
                    item,
                    expected=expected_code + (f"（{expect_msg}）" if expect_msg else ""),
                    actual=e.code,
                    defense_ref=defense,
                    detail={"message": e.message},
                )
            return
        except Exception as e:  # noqa: BLE001
            m.fail(
                item, expected=expected_code, actual=f"{type(e).__name__}: {e}", defense_ref=defense
            )
            return
        m.fail(
            item,
            expected=expected_code,
            actual="被受理（未拒绝）",
            defense_ref=defense,
            attack_success=True,
        )

    # 正例对照：诚实申请受理（pending + 128bit 回执）
    case0 = _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now)
    kw0 = _gate_kwargs(case0, session_pk_hex=spk, t_start=now, t_end=now + 3600, seed_session=session)
    try:
        row = service.admission_gate(session, _fake_deps(), **kw0)
        r = session.get(Receipt, row.receipt_id)
        if row.status == "pending" and len(r.code_hex) == 32:
            m.pass_(
                "C3-01 正例对照：诚实申请受理（pending+128bit 回执）",
                defense_ref="app/authz/service.py:admission_gate",
                detail={"status": row.status, "receipt_code_len": len(r.code_hex)},
            )
        else:
            m.fail(
                "C3-01 正例对照：诚实申请受理（pending+128bit 回执）",
                expected="pending+32hex 回执",
                actual=f"{row.status}",
                defense_ref="app/authz/service.py:admission_gate",
            )
    except Exception as e:  # noqa: BLE001
        m.fail(
            "C3-01 正例对照：诚实申请受理（pending+128bit 回执）",
            expected="pending",
            actual=f"{type(e).__name__}: {e}",
            defense_ref="app/authz/service.py:admission_gate",
        )

    # 高度轴·政策类边界（门控层高度轴=政策类查表；高度数值本体由电路 RangeCheck 强制）
    caseA = _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now)
    kwA = _gate_kwargs(caseA, session_pk_hex=spk, t_start=now, t_end=now + 3600, seed_session=session, class_id=0)
    caseB = _gate_case(
        secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now, class_id=1
    )
    kwB = _gate_kwargs(caseB, session_pk_hex=spk, t_start=now, t_end=now + 3600, seed_session=session, class_id=1)
    try:
        ra = service.admission_gate(session, _fake_deps(), **kwA)
        rbo = service.admission_gate(session, _fake_deps(), **kwB)
        if ra.status == "pending" and rbo.status == "pending":
            m.pass_(
                "C3-02 高度类边界·开放类放行（微型 50m/轻型 120m）",
                defense_ref="app/authz/policy.py:get_rule + app/authz/service.py:admission_gate",
                detail={
                    "alt_max_m": {"class_0": 50, "class_1": 120},
                    "注记": "高度数值本体=电路 RangeCheck 面；门控层高度轴=政策类查表",
                },
            )
        else:
            m.fail(
                "C3-02 高度类边界·开放类放行（微型 50m/轻型 120m）",
                expected="两开放类均 pending",
                actual=f"{ra.status}/{rbo.status}",
                defense_ref="app/authz/policy.py:get_rule",
            )
    except Exception as e:  # noqa: BLE001
        m.fail(
            "C3-02 高度类边界·开放类放行（微型 50m/轻型 120m）",
            expected="两开放类均 pending",
            actual=f"{type(e).__name__}: {e}",
            defense_ref="app/authz/policy.py:get_rule",
        )

    _negative(
        "C3-03 高度类边界·未开放类拒（超政策表上限类）",
        "unsupported_class",
        _gate_kwargs(
            _gate_case(
                secrets.token_bytes(32).hex(),
                secrets.token_bytes(16).hex(),
                t_start=now,
                class_id=2,
            ),
            session_pk_hex=spk,
            t_start=now,
            t_end=now + 3600,
            class_id=2,
        ),
        "app/authz/policy.py:get_rule（fail-closed 未开放类）",
    )

    # 窗上限边界：恰好等于 → 放行；+1 → window_too_long（S5「10 年令牌」门）
    caseW = _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now)
    kwW = _gate_kwargs(caseW, session_pk_hex=spk, t_start=now, t_end=now + max_window, seed_session=session)
    try:
        row = service.admission_gate(session, _fake_deps(), **kwW)
        if row.status == "pending":
            m.pass_(
                f"C3-04 授权窗恰好等于上限 {max_window}s（不误拒）",
                defense_ref="app/authz/service.py:admission_gate（S5 窗上限门）",
            )
        else:
            m.fail(
                f"C3-04 授权窗恰好等于上限 {max_window}s（不误拒）",
                expected="pending",
                actual=row.status,
                defense_ref="app/authz/service.py:admission_gate",
            )
    except Exception as e:  # noqa: BLE001
        m.fail(
            f"C3-04 授权窗恰好等于上限 {max_window}s（不误拒）",
            expected="pending",
            actual=f"{type(e).__name__}: {e}",
            defense_ref="app/authz/service.py:admission_gate",
        )

    _negative(
        f"C3-05 授权窗超上限 1s（{max_window + 1}s）",
        "window_too_long",
        _gate_kwargs(
            _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now),
            session_pk_hex=spk,
            t_start=now,
            t_end=now + max_window + 1,
            seed_session=session,
        ),
        "app/authz/service.py:admission_gate（S5 窗上限门）",
    )

    # rev_root 过期
    _negative(
        "C3-06 rev_root 与链上纪元不一致（过期）",
        "stale_rev_root",
        _gate_kwargs(
            _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now),
            session_pk_hex=spk,
            t_start=now,
            t_end=now + 3600,
            rev_root="aa" * 32,
        ),
        "app/authz/service.py:admission_gate（④ rev_root 核对）",
    )

    # ctx_tag / pred_id / class_id 实例逐位核对
    plan = secrets.token_bytes(32).hex()
    non = secrets.token_bytes(16).hex()
    case19 = _gate_case(plan, non, t_start=now, overrides={19: "1" * 64})
    _negative(
        "C3-07 ctx_tag 不符（实例 19 篡改）",
        "instance_mismatch",
        _gate_kwargs(case19, session_pk_hex=spk, t_start=now, t_end=now + 3600),
        "app/authz/service.py:admission_gate._expect（实例 19）",
        expect_msg="实例 19",
    )
    case20 = _gate_case(plan, non, t_start=now, overrides={20: "2" * 64})
    _negative(
        "C3-08 pred_id 不符（实例 20 篡改）",
        "instance_mismatch",
        _gate_kwargs(case20, session_pk_hex=spk, t_start=now, t_end=now + 3600),
        "app/authz/service.py:admission_gate._expect（实例 20）",
        expect_msg="实例 20",
    )
    case24 = _gate_case(plan, non, t_start=now, overrides={24: _fe_u64(7)})
    _negative(
        "C3-09 class_id 实例不符（实例 24 自报套高类）",
        "instance_mismatch",
        _gate_kwargs(case24, session_pk_hex=spk, t_start=now, t_end=now + 3600),
        "app/authz/service.py:admission_gate._expect（实例 24）",
        expect_msg="实例 24",
    )

    # nonce 链上已用
    used_nonce = secrets.token_bytes(16)
    _negative(
        "C3-10 nonce 链上已用（重放）",
        "nonce_used",
        _gate_kwargs(
            _gate_case(secrets.token_bytes(32).hex(), used_nonce.hex(), t_start=now),
            session_pk_hex=spk,
            t_start=now,
            t_end=now + 3600,
            over={"nonce_hex": used_nonce.hex()},
        ),
        "app/authz/service.py:admission_gate（③ nonce 查重）",
        deps=_fake_deps(nonce_used={used_nonce}),
    )

    # 子凭证重放（首受理成功 → 同材料二刷必拒）
    kw_replay = _gate_kwargs(
        _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now),
        session_pk_hex=spk,
        t_start=now,
        t_end=now + 3600,
        seed_session=session,
    )
    try:
        service.admission_gate(session, _fake_deps(), **kw_replay)
    except Exception as e:  # noqa: BLE001
        m.fail(
            "C3-11 子凭证一次性（重放拒）",
            expected="首受理成功",
            actual=f"{type(e).__name__}: {e}",
            defense_ref="app/authz/service.py:admission_gate",
        )
    _negative(
        "C3-11 子凭证一次性（重放拒）",
        "sub_cred_used",
        kw_replay,
        "app/authz/service.py:admission_gate（库级查重）",
    )

    # 坏会话钥（hex 合法但非曲线点——毒丸防线的曲线方程校验）
    _negative(
        "C3-12 会话公钥不在 SM2 曲线上",
        "bad_session_key",
        _gate_kwargs(
            _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now),
            session_pk_hex="11" * 64,
            t_start=now,
            t_end=now + 3600,
        ),
        "app/authz/service.py:admission_gate（① assert_pub——S5 毒丸修复）",
    )

    # 坏子凭证签名
    kw_badsig = _gate_kwargs(
        _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now),
        session_pk_hex=spk,
        t_start=now,
        t_end=now + 3600,
    )
    kw_badsig["sub_sig_hex"] = "0" + secrets.token_hex(63)
    _negative(
        "C3-13 子凭证签名验证失败（非 RA 签发）",
        "bad_sub_signature",
        kw_badsig,
        "app/authz/service.py:admission_gate（② SM2 验签）",
    )

    # 子凭证哈希对拍（A-P1-1 根修正例）
    kw_hashmix = _gate_kwargs(
        _gate_case(secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now),
        session_pk_hex=spk,
        t_start=now,
        t_end=now + 3600,
    )
    kw_hashmix["sub_cred_hash_hex"] = secrets.token_bytes(32).hex()
    _negative(
        "C3-14 子凭证哈希与报文不符（服务器重算对拍）",
        "sub_cred_hash_mismatch",
        kw_hashmix,
        "app/authz/service.py:admission_gate（②' 重算对拍——A-P1-1 根修）",
    )

    # 电路 pin 指纹=链上公示正对照（C4 嫁接拒绝的正面对照证据）
    local_pin = ""
    chain_digest = ""
    pin_ok = False
    try:
        local_pin, chain_digest = _local_pin_fingerprint()
        pin_ok = local_pin == PIN_LOCAL_EXPECTED and chain_digest == PIN_CHAIN_DIGEST_EXPECTED
    except Exception as e:  # noqa: BLE001
        local_pin = f"读取失败: {e}"
    if pin_ok:
        m.pass_(
            "C3-15 电路 pin 指纹=链上公示（正对照）",
            defense_ref="app/authz/service.py:AuthzDeps.pin_fingerprint"
            " + docs/性能档案.md 换代仪式",
            detail={"local_pin": local_pin, "chain_digest": chain_digest, "tx": "0xfa162fbb"},
        )
    else:
        m.fail(
            "C3-15 电路 pin 指纹=链上公示（正对照）",
            expected=f"{PIN_LOCAL_EXPECTED} → sm3={PIN_CHAIN_DIGEST_EXPECTED}",
            actual=f"{local_pin} → sm3={chain_digest}",
            defense_ref="app/authz/service.py:AuthzDeps.pin_fingerprint",
        )

    # zkc 期望门垃圾证明 fail-closed（秒级，不跑真证明）
    _zkc_fail_closed(m)


def _local_pin_fingerprint() -> tuple[str, str]:
    """（本地指纹串, 链上公示摘要）——AuthzDeps.pin_fingerprint 同式。"""
    from app.crypto.sm3 import sm3_bytes

    man = _load_json(ZKSVC / "vendor" / "MANIFEST.json")
    local = f"SM3({man['pin_commit']}|{man['aggregate_sm3']})"
    return local, sm3_bytes(local.encode()).hex()


def _zkc_run(
    exe: Path, case: dict, expected: dict, *, env_over: dict, spec_env_key: str, spec_path: str
) -> tuple[int, str, float]:
    """zkc verify-instances 单次驱动（worker.zkc_verify 调用形态同构）。"""
    fd, expected_path = tempfile.mkstemp(prefix="fzca-expected-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(expected, f)
    env = dict(os.environ)
    env[spec_env_key] = spec_path
    env.update(env_over)
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [
                str(exe),
                "verify-instances",
                "--instances",
                case["instances"],
                "--proof",
                case["proof"],
                "--vp",
                case["verifier_param"],
                "--expected",
                expected_path,
            ],
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
            timeout=180,
        )
        rc, log = proc.returncode, (proc.stdout + proc.stderr)[-400:]
    except subprocess.TimeoutExpired:
        rc, log = 124, "timeout 180s"
    finally:
        try:
            os.unlink(expected_path)
        except OSError:
            pass
    return rc, log, time.perf_counter() - t0


def _zkc_fail_closed(m: Module) -> None:
    """垃圾 proof 驱动 zkc verify-instances 期望门——必须拒绝（fail-closed）。"""
    from app.authz.policy import POLICY_VERSION
    from app.authz.service import binding_challenge, binding_pred_id

    exe = ZKSVC / "target" / "release" / "zkc.exe"
    if not exe.exists():
        m.env_error("C3-16 zkc 期望门垃圾证明 fail-closed", detail={"reason": f"zkc 不存在: {exe}"})
        return
    plan = secrets.token_bytes(32).hex()
    non = secrets.token_bytes(16).hex()
    t0w = int(time.time())
    case = _gate_case(plan, non, t_start=t0w)
    expected = {
        "e_hex": "00" * 32,
        "challenge_hex": binding_challenge(plan, non),
        "pred_id": binding_pred_id(plan, non, POLICY_VERSION),
        "t_epoch": t0w,
        "required_level": 1,
        "class_id": 0,
        "smt_root_hex": "00" * 32,
    }
    local_pin, chain_digest = _local_pin_fingerprint()
    rc, log, dur = _zkc_run(
        exe,
        case,
        expected,
        env_over={"FZ_ZK_ALLOW_AUTH": "1"},
        spec_env_key="FZ_AUTH_CANONICAL_SPEC",
        spec_path=str(ZKSVC / "tests" / "auth_canonical_spec.json"),
    )
    if rc != 0:
        m.pass_(
            "C3-16 zkc 期望门垃圾证明 fail-closed",
            defense_ref="app/zk/worker.py:zkc_verify（verify-instances 期望门）",
            latency_ms=round(dur * 1000, 0),
            detail={
                "zkc": str(exe),
                "local_pin": local_pin,
                "chain_digest": chain_digest,
                "exit": rc,
                "log_tail": log[-160:],
            },
        )
    else:
        m.fail(
            "C3-16 zkc 期望门垃圾证明 fail-closed",
            expected="exit≠0（拒绝）",
            actual="exit=0（垃圾证明被接受）",
            defense_ref="app/zk/worker.py:zkc_verify",
            attack_success=True,
            detail={"zkc": str(exe), "local_pin": local_pin},
        )


# ============================================================================
# C4 嫁接拒绝
# ============================================================================


def c4_graft_rejection(rb: ReportBuilder, quick: bool = False) -> None:
    from app.authz.policy import POLICY_VERSION
    from app.authz.service import binding_challenge, binding_pred_id

    m = rb.module("C4_graft", "C4 嫁接拒绝（换期望/换 spec/换 vkey 必拒——期望门层实弹）")
    exe = ZKSVC / "target" / "release" / "zkc.exe"
    if not exe.exists():
        m.env_error("C4 嫁接拒绝", detail={"reason": f"zkc 不存在: {exe}"})
        return
    local_pin, chain_digest = _local_pin_fingerprint()
    now = int(time.time())
    plan = secrets.token_bytes(32).hex()
    non = secrets.token_bytes(16).hex()
    case_auth = _gate_case(plan, non, t_start=now)
    exp_auth = {
        "e_hex": "00" * 32,
        "challenge_hex": binding_challenge(plan, non),
        "pred_id": binding_pred_id(plan, non, POLICY_VERSION),
        "t_epoch": now,
        "required_level": 1,
        "class_id": 0,
        "smt_root_hex": "00" * 32,
    }
    exp_trail = {"chain_head_hex": "ab" * 32, "alt_max_cm": 120, "t_start": now}
    trail_spec = str(ZKSVC / "tests" / "trail_canonical_spec.json")
    auth_spec = str(ZKSVC / "tests" / "auth_canonical_spec.json")

    # 换 vkey 面 case：verifier_param 换为 64B 随机字节（≠装配产物）
    case_vkey = _gate_case(
        secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(), t_start=now
    )
    with open(case_vkey["verifier_param"], "wb") as f:
        f.write(secrets.token_bytes(64))

    drives = [
        (
            "C4-01",
            "AUTH 语句×AUTH 期望（垃圾证明基线）",
            case_auth,
            exp_auth,
            {"FZ_ZK_ALLOW_AUTH": "1"},
            "FZ_AUTH_CANONICAL_SPEC",
            auth_spec,
        ),
        (
            "C4-02",
            "AUTH 语句×TRAIL 形态期望（跨电路嫁接）",
            case_auth,
            exp_trail,
            {"FZ_ZK_ALLOW_AUTH": "1"},
            "FZ_AUTH_CANONICAL_SPEC",
            auth_spec,
        ),
        (
            "C4-03",
            "TRAIL 形态×AUTH 形态期望（反向嫁接）",
            case_auth,
            exp_auth,
            {"FZ_ZK_ALLOW_TRAIL": "1"},
            "FZ_TRAIL_CANONICAL_SPEC",
            trail_spec,
        ),
        (
            "C4-04",
            "错误电路 spec（AUTH 面挂 TRAIL canonical spec）",
            case_auth,
            exp_auth,
            {"FZ_ZK_ALLOW_AUTH": "1"},
            "FZ_AUTH_CANONICAL_SPEC",
            trail_spec,
        ),
        (
            "C4-05",
            "换 vkey 面（verifier_param≠装配产物）",
            case_vkey,
            exp_auth,
            {"FZ_ZK_ALLOW_AUTH": "1"},
            "FZ_AUTH_CANONICAL_SPEC",
            auth_spec,
        ),
    ]
    if quick:
        keep = {"C4-01", "C4-02", "C4-04"}
        drives = [d for d in drives if d[0] in keep]

    for tag, desc, case, expected, env_over, spec_key, spec_path in drives:
        rc, log, dur = _zkc_run(
            exe, case, expected, env_over=env_over, spec_env_key=spec_key, spec_path=spec_path
        )
        name = f"{tag} {desc}"
        if rc != 0:
            m.pass_(
                name,
                defense_ref="app/zk/worker.py:zkc_verify + zkc verify-instances 期望门",
                latency_ms=round(dur * 1000, 0),
                detail={
                    "zkc": str(exe),
                    "local_pin": local_pin,
                    "chain_digest": chain_digest,
                    "exit": rc,
                    "log_tail": log[-160:],
                },
            )
        else:
            m.fail(
                name,
                expected="exit≠0（嫁接提交必拒）",
                actual="exit=0（嫁接提交被接受）",
                defense_ref="app/zk/worker.py:zkc_verify",
                attack_success=True,
                detail={"zkc": str(exe), "local_pin": local_pin},
            )


# ============================================================================
# C5 密钥生命周期
# ============================================================================


def c5_key_lifecycle(rb: ReportBuilder) -> None:
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    from app.crypto.sm2 import generate_keypair
    from app.kms import ra_signing_keypair
    from app.ra.models import Base, Revocation, SubCredential
    from app.ra.service import ChainAnchor, RaDeps, RaError, RaService

    m = rb.module("C5_lifecycle", "C5 密钥生命周期（出示钥/会话/吊销传播）")
    d = tempfile.mkdtemp(prefix="fzca-c5")
    eng = create_engine(f"sqlite:///{d}/c5.db")
    Base.metadata.create_all(eng)
    session = sessionmaker(bind=eng, expire_on_commit=False)()

    ra_priv, ra_pub = ra_signing_keypair()
    svc = RaService(
        session,
        RaDeps(
            ra_priv_hex=ra_priv, ra_pub_hex=ra_pub, anchor=ChainAnchor(call=lambda fn, args: None)
        ),
    )

    holder_sk, holder_pk = generate_keypair()
    sn = "FZ-CA-C5-01"
    try:
        reg = svc.register(
            username="c5-pilot",
            id_number="110101199001011234",
            cert_level=3,
            sn=sn,
            user_pub_hex=holder_pk,
            class_id=1,
        )
    except RaError as e:
        m.env_error("C5-01 登记承诺正例（对照）", detail={"reason": f"{e.code}: {e}"})
        return
    m.pass_(
        "C5-01 登记承诺正例（对照）",
        defense_ref="app/ra/service.py:RaService.register",
        detail={"master_cred_hash_hex": reg["master_cred_hash_hex"][:16] + "…"},
    )

    def _issue(cred: dict, pk: str) -> dict:
        return svc.issue_sub_credential(
            master_cred_hash_hex=cred["master_cred_hash_hex"],
            salt_hex=cred["salt_hex"],
            id_number="110101199001011234",
            cert_level=3,
            sn=sn,
            holder_pub_hex=pk,
        )

    sub1_sk, sub1_pk = generate_keypair()
    s1 = _issue(reg, sub1_pk)
    ok21 = (
        all(
            k in s1
            for k in ("id_prime_hex", "expires_at", "message_hex", "sig_hex", "sub_cred_hash_hex")
        )
        and s1["message_hex"][192:320] == sub1_pk.lower()
    )
    if ok21:
        m.pass_(
            "C5-02 签发#1：字段齐 + M_A′ pk′ 段=新出示钥逐位（e2e 2.1b 收拢）",
            defense_ref="app/ra/service.py:issue_sub_credential + "
            "app/ra/credential.py:build_message",
            detail={"pk_offset": "hex[192:320]=holder x‖y"},
        )
    else:
        pk_seg_ok = s1.get("message_hex", "")[192:320] == sub1_pk.lower()
        m.fail(
            "C5-02 签发#1：字段齐 + M_A′ pk′ 段=新出示钥逐位（e2e 2.1b 收拢）",
            expected="字段齐且 pk′ 段逐位一致",
            actual=f"fields={sorted(s1)} pk_ok={pk_seg_ok}",
            defense_ref="app/ra/service.py:issue_sub_credential",
        )

    sub2_sk, sub2_pk = generate_keypair()
    s2 = _issue(reg, sub2_pk)
    if (
        s1["message_hex"][192:320] != s2["message_hex"][192:320]
        and s2["message_hex"][192:320] == sub2_pk.lower()
    ):
        m.pass_(
            "C5-03 签发#2：新出示钥（两次 pk′ 互异——跨申请不可链接，e2e 2.4 收拢）",
            defense_ref="app/ra/service.py:issue_sub_credential（fresh id′+一次性出示钥）",
        )
    else:
        m.fail(
            "C5-03 签发#2：新出示钥（两次 pk′ 互异——跨申请不可链接，e2e 2.4 收拢）",
            expected="pk′ 互异且各绑定本报文",
            actual="对拍失败",
            defense_ref="app/ra/service.py:issue_sub_credential",
        )

    # 登出会话焚毁（函数级：WebSession 行删除 + token 失效）
    from app.accounts.models import Account, WebSession
    from app.accounts.service import logout as acct_logout
    from app.accounts.service import session_of

    session.add(Account(username="c5-pilot", role="pilot", status="active", pubkey_hex=holder_pk))
    session.commit()
    from app.crypto.sm3 import sm3_bytes as _sm3

    tok = secrets.token_hex(32)
    session.add(
        WebSession(
            token_hash_hex=_sm3(tok.encode()).hex(),
            username="c5-pilot",
            role="pilot",
            expires_ts=_utc_naive() + timedelta(hours=1),
        )
    )
    session.commit()
    pre = session_of(session, tok) is not None
    acct_logout(session, tok)
    post_alive = session_of(session, tok) is not None
    rows_left = len(session.scalars(select(WebSession)).all())
    if pre and not post_alive and rows_left == 0:
        m.pass_(
            "C5-04 登出会话焚毁（WebSession 删除+token 失效）",
            defense_ref="app/accounts/service.py:logout/session_of",
        )
    else:
        m.fail(
            "C5-04 登出会话焚毁（WebSession 删除+token 失效）",
            expected="登出前有效、登出后失效且行清零",
            actual=f"pre={pre} post_alive={post_alive} rows={rows_left}",
            defense_ref="app/accounts/service.py:logout/session_of",
        )

    # 服务端零出示钥私钥存储（模型列断言——sk′ 仅客户端会话域内存态）
    cols = {c.name for c in SubCredential.__table__.columns}
    leak = {c for c in cols if any(h in c for h in ("sk", "priv", "secret"))}
    if not leak:
        m.pass_(
            "C5-05 服务端零出示钥私钥存储（SubCredential 列集合断言）",
            defense_ref="app/ra/models.py:SubCredential",
            detail={"columns": sorted(cols)},
        )
    else:
        m.fail(
            "C5-05 服务端零出示钥私钥存储（SubCredential 列集合断言）",
            expected="无私钥列",
            actual=f"泄漏列: {leak}",
            defense_ref="app/ra/models.py:SubCredential",
        )

    # 吊销传播：主凭证+未消费子凭证 pk′.x 并入撤销集
    # （B1 升格契约：理由≥4 字+admin SM2 签名（FZ-REVOKE|v1 域）+纪元绑定=
    # 公示纪元+1；先证「缺签名=401 bad_sig」再走真签正例）
    from app.crypto.sm2 import sign as _ca_sign

    from app.ra.service import revoke_msg

    rev_reason = "crypto-audit C5"
    rev_epoch = svc.snapshot()["epoch"] + 1
    adm_sk, adm_pk = generate_keypair()
    try:
        svc.revoke(
            master_cred_hash_hex=reg["master_cred_hash_hex"], reason=rev_reason,
            admin_username="ca-admin", admin_pub_hex=adm_pk, admin_sig_hex="", epoch=rev_epoch,
        )
        m.fail(
            "C5-06pre 缺管理员签名撤销",
            expected="RaError bad_sig（无签名=401）",
            actual="撤销被放行",
            defense_ref="app/ra/service.py:_verify_admin_sig",
            attack_success=True,
        )
    except RaError as e:
        if e.code == "bad_sig":
            m.pass_(
                "C5-06pre 缺管理员签名撤销 → bad_sig（fail-closed）",
                defense_ref="app/ra/service.py:_verify_admin_sig",
            )
        else:
            m.fail(
                "C5-06pre 缺管理员签名撤销",
                expected="bad_sig",
                actual=f"{e.code}: {e}",
                defense_ref="app/ra/service.py:_verify_admin_sig",
            )
    out = svc.revoke(
        master_cred_hash_hex=reg["master_cred_hash_hex"], reason=rev_reason,
        admin_username="ca-admin", admin_pub_hex=adm_pk,
        admin_sig_hex=_ca_sign(
            adm_sk, revoke_msg([reg["master_cred_hash_hex"]], rev_reason, rev_epoch).encode()
        ),
        epoch=rev_epoch,
    )
    handles = {r.handle_hex for r in session.scalars(select(Revocation)).all()}
    propagated = sub1_pk.lower()[:64] in handles and sub2_pk.lower()[:64] in handles
    root_moved = bool(out.get("root_hex")) and out["root_hex"] != "00" * 32
    if propagated and root_moved and out.get("epoch", 0) >= 1:
        m.pass_(
            "C5-06 吊销传播（未消费子凭证 pk′.x 并入撤销集+根更迭）",
            defense_ref="app/ra/service.py:_revoke_credentials（R3-0.3 传播）",
            detail={
                "epoch": out["epoch"],
                "handles": len(handles),
                "root_hex": out["root_hex"][:16] + "…",
            },
        )
    else:
        m.fail(
            "C5-06 吊销传播（未消费子凭证 pk′.x 并入撤销集+根更迭）",
            expected="pk′.x 入集+根更迭",
            actual=f"propagated={propagated} out={out}",
            defense_ref="app/ra/service.py:_revoke_credentials",
        )

    # 吊销后同凭证重签 → cred_revoked
    _sk3, pk3 = generate_keypair()
    try:
        _issue(reg, pk3)
        m.fail(
            "C5-07 已吊销凭证重签拒绝",
            expected="cred_revoked",
            actual="被签发",
            defense_ref="app/ra/service.py:issue_sub_credential",
            attack_success=True,
        )
    except RaError as e:
        if e.code == "cred_revoked":
            m.pass_(
                "C5-07 已吊销凭证重签拒绝（cred_revoked 预检）",
                defense_ref="app/ra/service.py:issue_sub_credential（本凭证状态优先报）",
            )
        else:
            m.fail(
                "C5-07 已吊销凭证重签拒绝（cred_revoked 预检）",
                expected="cred_revoked",
                actual=e.code,
                defense_ref="app/ra/service.py:issue_sub_credential",
            )

    # holder_revoked（跨凭证键传染形态：新凭证+旧出示钥——原凭证吊销传播的 pk′）
    # B7 重注册禁入（0019 批）：同证件号重登被黑名单 409 拒——传染形态本不依赖
    # 同号，pilot-b 改用未入黑名单的另一证件号（语义保持：新凭证+被传播旧 pk′）
    sn2 = "FZ-CA-C5-02"
    id_number_b = "110101199001012345"
    _hsk2, _hpk2 = generate_keypair()
    reg2 = svc.register(
        username="c5-pilot-b",
        id_number=id_number_b,
        cert_level=3,
        sn=sn2,
        user_pub_hex=_hpk2,
        class_id=1,
    )
    try:
        svc.issue_sub_credential(
            master_cred_hash_hex=reg2["master_cred_hash_hex"],
            salt_hex=reg2["salt_hex"],
            id_number=id_number_b,
            cert_level=3,
            sn=sn2,
            holder_pub_hex=sub1_pk,
        )  # 被吊销传播的旧出示钥
        m.fail(
            "C5-08 吊销传播后旧出示钥重签拒绝（holder_revoked）",
            expected="holder_revoked",
            actual="被签发",
            defense_ref="app/ra/service.py:issue_sub_credential",
            attack_success=True,
        )
    except RaError as e:
        if e.code == "holder_revoked":
            m.pass_(
                "C5-08 吊销传播后旧出示钥重签拒绝（holder_revoked 预检）",
                defense_ref="app/ra/service.py:issue_sub_credential（B-P2-5 签发面撤销预检）",
                detail={"机制": "新凭证+被传播旧 pk′——跨凭证传染形态"},
            )
        else:
            m.fail(
                "C5-08 吊销传播后旧出示钥重签拒绝（holder_revoked 预检）",
                expected="holder_revoked",
                actual=e.code,
                defense_ref="app/ra/service.py:issue_sub_credential",
            )

    session.close()


# ============================================================================
# C6 双控签名链
# ============================================================================


def c6_dual_control(rb: ReportBuilder) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.accounts.collab import (
        CollabError,
        approve_and_execute,
        create_request,
        verify_request_sigs,
    )
    from app.accounts.models import Account, AccountPubkeyHistory
    from app.audit.models import Warrant
    from app.crypto.sm2 import generate_keypair, sign
    from app.crypto.sm3 import sm3_bytes
    from app.ra.models import Base

    m = rb.module("C6_dual_control", "C6 双控签名链（缺一拒/坏签拒/篡改拒/双签过+复验）")
    d = tempfile.mkdtemp(prefix="fzca-c6")
    eng = create_engine(f"sqlite:///{d}/c6.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    SessionF = sessionmaker(bind=eng, expire_on_commit=False)

    # 后台执行线程走 app.db.SessionLocal——钉到临时库（零演示库写面）
    import app.db as db_mod

    real_sl = db_mod.SessionLocal
    db_mod.SessionLocal = SessionF

    session = SessionF()
    aud_sk, aud_pk = generate_keypair()
    adm_sk, adm_pk = generate_keypair()
    session.add(Account(username="ca-auditor", role="auditor", status="active", pubkey_hex=aud_pk))
    session.add(Account(username="ca-admin", role="admin", status="active", pubkey_hex=adm_pk))
    session.flush()
    session.add(
        AccountPubkeyHistory(
            username="ca-auditor",
            epoch=1,
            pubkey_hex=aud_pk.lower(),
            activated_ts=_utc_naive(),
        )
    )
    session.add(
        AccountPubkeyHistory(
            username="ca-admin", epoch=1, pubkey_hex=adm_pk.lower(), activated_ts=_utc_naive()
        )
    )
    wh = sm3_bytes(b"FZ-CA-C6|" + secrets.token_bytes(16)).hex()
    session.add(
        Warrant(
            warrant_hash_hex=wh,
            case_no="CA-C6-1",
            scope_hash_hex=wh,
            legal_basis_hash_hex="00" * 32,
            legal_basis_text="密码审计套件双控签名链实弹",
            target_auth_id=None,
        )
    )
    session.commit()
    time.sleep(0.02)  # created_ts 与 activated_ts 分辨（时点公钥回取前提）

    class Auditor:
        username = "ca-auditor"
        role = "auditor"
        pubkey_hex = aud_pk

    class Admin:
        username = "ca-admin"
        role = "admin"
        pubkey_hex = adm_pk

    note = "核实超限事件当事人实名"

    def _aud_sig(n: str) -> str:
        return sign(aud_sk, f"FZ-COLLAB-REQ|v1|{wh}|{n}".encode())

    def _adm_sig(n: str) -> str:
        return sign(adm_sk, f"FZ-COLLAB-REQ|v1|{wh}|{n}".encode())

    try:
        # ① 缺审计签（空签名）
        _expect_reject(
            m,
            "C6-01 缺审计签拒（空签名）",
            lambda: create_request(
                session, auditor=Auditor(), warrant_hash_hex=wh, note=note, sig_hex=""
            ),
            defense_ref="app/accounts/collab.py:_verify_action_sig（SM2 验签门）",
            expected="CollabError(bad_sig)",
        )
        # ② 坏审计签
        _expect_reject(
            m,
            "C6-02 坏审计签拒（随机签名）",
            lambda: create_request(
                session,
                auditor=Auditor(),
                warrant_hash_hex=wh,
                note=note,
                sig_hex=secrets.token_hex(64),
            ),
            defense_ref="app/accounts/collab.py:_verify_action_sig",
            expected="CollabError(bad_sig)",
        )
        # ③ 正例发函（对照）
        row = create_request(
            session, auditor=Auditor(), warrant_hash_hex=wh, note=note, sig_hex=_aud_sig(note)
        )
        if row.status == "pending":
            m.pass_(
                "C6-03 正例发函（对照，pending 在途）",
                defense_ref="app/accounts/collab.py:create_request",
            )
        else:
            m.fail(
                "C6-03 正例发函（对照，pending 在途）",
                expected="pending",
                actual=row.status,
                defense_ref="app/accounts/collab.py:create_request",
            )
        # ④ 缺管理员签
        _expect_reject(
            m,
            "C6-04 缺管理员签拒（空签名批准）",
            lambda: approve_and_execute(session, admin=Admin(), request_id=row.id, sig_hex=""),
            defense_ref="app/accounts/collab.py:approve_and_execute（批准即绑定内容）",
            expected="CollabError(bad_sig)",
        )
        # ⑤ 坏管理员签
        _expect_reject(
            m,
            "C6-05 坏管理员签拒",
            lambda: approve_and_execute(
                session, admin=Admin(), request_id=row.id, sig_hex=secrets.token_hex(64)
            ),
            defense_ref="app/accounts/collab.py:approve_and_execute",
            expected="CollabError(bad_sig)",
        )
        # ⑥ 篡改 note（对另一 note 签名批准）
        _expect_reject(
            m,
            "C6-06 篡改 note 拒（批准签名绑定请求原文）",
            lambda: approve_and_execute(
                session, admin=Admin(), request_id=row.id, sig_hex=_adm_sig("被篡改的理由")
            ),
            defense_ref="app/accounts/collab.py:approve_and_execute"
            "（REQ_MSG_PREFIX+wh|note 原文绑定）",
            expected="CollabError(bad_sig)",
        )
        # ⑦ 双签全过（批准落定；后台执行=临时库内匿名令状终态，与签名门无关）
        view = approve_and_execute(
            session, admin=Admin(), request_id=row.id, sig_hex=_adm_sig(note), wait_s=15
        )
        if (
            view["status"] in ("approved", "executed", "execute_failed")
            and view["admin_username"] == "ca-admin"
        ):
            m.pass_(
                "C6-07 双签全过（批准落定+自动执行受理）",
                defense_ref="app/accounts/collab.py:approve_and_execute",
                detail={"status": view["status"], "admin_fp_set": bool(view.get("admin_fp"))},
            )
        else:
            m.fail(
                "C6-07 双签全过（批准落定+自动执行受理）",
                expected="approved/executed/execute_failed 且 admin 落名",
                actual=f"{view['status']}/{view.get('admin_username')}",
                defense_ref="app/accounts/collab.py:approve_and_execute",
            )
        # ⑧ 历史双签复验（签名时点公钥纪元复验）
        v = verify_request_sigs(session, row.id)
        if (
            v["auditor"]["ok"] is True
            and v["admin"]["ok"] is True
            and v["auditor"]["epoch"] == 1
            and v["admin"]["epoch"] == 1
        ):
            m.pass_(
                "C6-08 历史双签按签名时点公钥复验通过（不可抵赖）",
                defense_ref="app/accounts/collab.py:verify_request_sigs",
                detail={"auditor_epoch": v["auditor"]["epoch"], "admin_epoch": v["admin"]["epoch"]},
            )
        else:
            m.fail(
                "C6-08 历史双签按签名时点公钥复验通过（不可抵赖）",
                expected="双签 ok 且纪元=1",
                actual=json.dumps(v, ensure_ascii=False)[:160],
                defense_ref="app/accounts/collab.py:verify_request_sigs",
            )
    except CollabError as e:
        m.fail(
            "C6-harness 未预期协作拒绝",
            expected="双控链路按序走完",
            actual=f"CollabError({e.code})",
            defense_ref="app/accounts/collab.py",
        )
    finally:
        # 排空后台执行线程（与 test_collab_dual_control 夹具同纪律）
        from app.accounts import collab as _cs

        deadline = time.time() + 15
        while time.time() < deadline and getattr(_cs, "_executing", None):
            time.sleep(0.1)
        db_mod.SessionLocal = real_sl
        session.close()


# ============================================================================
# C7 恒时性护栏（批 2-2.4 方法学升档：gc 隔离+预热+≥3000 样本+完整分布）
# ============================================================================


def _samples_ms_interleaved(
    fn_ok, fn_bad, n: int, warmup: int = 50, gc_isolated: bool = True
) -> tuple[list, list, dict]:
    """A/B 交错采样（ok,bad,ok,bad,…）：负载漂移同时作用于两组——中位数对比
    反映输入差异而非时间漂移（顺序分块采样对机器负载敏感，会假阳性 xfail）。

    方法学升档（批 2-2.4）：①预热轮（默认 50——JIT/缓存/引擎句柄达稳态）；
    ②采样段 gc.disable（还原现场——GC 暂停不进样本）；③样本数 ≥3000（规格
    下限，p99 可辨）。返回（ok 样本, bad 样本, 采样元数据）。"""
    import gc

    was_enabled = gc.isenabled()
    for _ in range(warmup):
        fn_ok()
        fn_bad()
    ok_s, bad_s = [], []
    if gc_isolated and was_enabled:
        gc.disable()
    try:
        for i in range(n):
            for lst, fn in (
                ((ok_s, fn_ok), (bad_s, fn_bad))
                if i % 2 == 0
                else (
                    (bad_s, fn_bad),
                    (ok_s, fn_ok),
                )
            ):
                t0 = time.perf_counter_ns()
                fn()
                lst.append((time.perf_counter_ns() - t0) / 1e6)
    finally:
        if gc_isolated and was_enabled:
            gc.enable()
    meta = {
        "warmup_rounds": warmup,
        "gc_isolated": bool(gc_isolated and was_enabled),
        "n_per_side": n,
    }
    return ok_s, bad_s, meta


def _pct(samples: list[float], p: float) -> float:
    """线性插值百分位（p∈(0,1]——p1/p50/p99 全分布口径）。"""
    s = sorted(samples)
    k = (len(s) - 1) * p
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def _stats_of(samples: list[float]) -> dict:
    """完整分布（批 2-2.4：p1/p50/p99+均值+标准差——不再只报中位数）。"""
    return {
        "n": len(samples),
        "p1_ms": round(_pct(samples, 0.01), 3),
        "p50_ms": round(_pct(samples, 0.50), 3),
        "p99_ms": round(_pct(samples, 0.99), 3),
        "mean_ms": round(statistics.fmean(samples), 3),
        "stdev_ms": round(statistics.pstdev(samples), 3),
    }


def _ct_verdict(
    m: Module, name: str, correct: list[float], wrong: list[float], defense: str, note: str,
    sampling_meta: dict | None = None,
) -> None:
    """宽松护栏（规格口径不变）：错误中位数 > 正确 ×1.3=fail（attack_success）；
    1.1~1.3=xfail。报告完整分布（p1/p50/p99+均值+标准差双侧）。"""
    cs, ws = _stats_of(correct), _stats_of(wrong)
    base = cs["p50_ms"] or cs["mean_ms"] or 1e-9
    ratio = round(ws["p50_ms"] / base, 3)
    detail = {
        "correct": cs,
        "wrong_input": ws,
        "ratio_wrong_over_correct": ratio,
        "sampling": sampling_meta or {},
        "rule": "fail: 错误 p50 > 正确 p50 ×1.3；xfail: 1.1~1.3；pass: ≤1.1（阈值不放松）",
        "note": note,
    }
    if ratio > 1.3:
        m.fail(
            name,
            expected="错误输入 p50 ≤ 正确 p50 ×1.3",
            actual=f"倍数 {ratio}×",
            defense_ref=defense,
            attack_success=True,
            detail=detail,
        )
    elif ratio > 1.1:
        m.xfail(
            name, reason=f"时延倍数 {ratio}× 落 1.1~1.3 容忍带（宽松护栏）", defense_ref=defense
        )
    else:
        m.pass_(name, defense_ref=defense, detail=detail)


# KEK 派生测量档迭代数：恒时性被测性质=「无输入相关早退分支」——PBKDF2 的
# 迭代数与输入无关，该性质在任意迭代数下同构（4096 轮 6000 样本≈15s，生产
# 600k 轮跑同样方法学需小时级）；生产档工作因子由 C1 官方向量+C2 回环锚定。
# 阈值 1.3× 与采样规格（≥3000）不因测量档降低。
_KEK_MEASURE_ITERATIONS = 4096


def c7_constant_time(rb: ReportBuilder, n: int = 3000) -> None:
    from app.accounts.kdf import derive_kek
    from app.crypto.sm2 import generate_keypair, sign
    from app.crypto.sm2 import verify as sm2_verify

    n = max(n, 3000)  # 规格下限：样本数 ≥3000/侧（含 --quick 档——方法学不缩水）
    m = rb.module(
        "C7_constant_time",
        f"C7 恒时性护栏（对/错输入时延全分布 p1/p50/p99，gc 隔离+预热 50 轮，n={n}/侧，阈值 ×1.3）",
    )

    # KEK derive：同盐等长口令（仅口令域差异——PBKDF2 无早退分支，工作因子恒等）
    salt = secrets.token_hex(16)
    pw_ok = "Timing-Correct-Pw"
    pw_bad = "Timing-Wrong--Pw"
    t0 = time.perf_counter()
    correct, wrong, meta = _samples_ms_interleaved(
        lambda: derive_kek(pw_ok, salt, _KEK_MEASURE_ITERATIONS),
        lambda: derive_kek(pw_bad, salt, _KEK_MEASURE_ITERATIONS),
        n,
    )
    _ct_verdict(
        m,
        f"C7-01 KEK derive（正确 vs 错误口令各 {n} 次）",
        correct,
        wrong,
        "app/accounts/kdf.py:derive_kek（PBKDF2-HMAC-SM3——无早退分支）",
        note=f"全组耗时 {time.perf_counter() - t0:.1f}s；同盐等长口令唯口令域差异；"
        f"A/B 交错采样+gc 隔离+预热 50 轮；测量档 {_KEK_MEASURE_ITERATIONS} 轮"
        f"（恒时性质与迭代数无关——生产档 {600000} 轮由 C1/C2 锚定）",
        sampling_meta=meta,
    )

    # SM2 验签：对/错签名各 n 次（20 组消息轮换防缓存/画像偏置）
    sk, pk = generate_keypair()
    pairs = []
    for _ in range(20):
        msg = b"FZ-CA-C7|" + secrets.token_bytes(16)
        pairs.append((msg, sign(sk, msg)))
    it = {"i": 0}

    def _v_ok():
        msg, sig = pairs[it["i"] % 20]
        it["i"] += 1
        return sm2_verify(pk, msg, sig)

    def _v_bad():
        msg, sig = pairs[it["i"] % 20]
        it["i"] += 1
        pos = secrets.randbelow(64) * 2  # r/s 域随机字节翻转（必 False 的错误输入）
        return sm2_verify(pk, msg, _flip_hex_byte(sig, pos))

    t0 = time.perf_counter()
    correct_v, wrong_v, meta_v = _samples_ms_interleaved(_v_ok, _v_bad, n)
    _ct_verdict(
        m,
        f"C7-02 SM2 验签（对/错签名各 {n} 次）",
        correct_v,
        wrong_v,
        "app/crypto/sm2.py:verify（EVP 主径/纯实现差分双引擎）",
        note=f"全组耗时 {time.perf_counter() - t0:.1f}s；错误输入=随机字节翻转（恒拒绝）；"
        f"A/B 交错采样+gc 隔离+预热 50 轮",
        sampling_meta=meta_v,
    )


# ============================================================================
# C8 模糊注入护栏（独立子进程——「进程不崩溃」可判）
# ============================================================================


def _fuzz_blobgens(blob: str) -> list:
    """畸形信封生成器族（对合法 v3 信封的 15 类变异）。"""
    obj = json.loads(blob)
    enc = obj["enc"]

    def _mut_enc(**kw) -> str:
        return json.dumps(dict(obj, enc=dict(enc, **kw)))

    return [
        lambda: "",
        lambda: "null",
        lambda: "[]",
        lambda: blob[: max(1, len(blob) // 2)],
        lambda: _mut_enc(salt="zz" * 32),
        lambda: _mut_enc(salt=_flip_hex_byte(enc["salt"], secrets.randbelow(16))),
        lambda: _mut_enc(nonce=_flip_hex_byte(enc["nonce"], secrets.randbelow(12))),
        lambda: _mut_enc(tag=_flip_hex_byte(enc["tag"], secrets.randbelow(16))),
        lambda: _mut_enc(
            ct=_flip_hex_byte(enc["ct"], secrets.randbelow(max(1, len(enc["ct"]) // 2)))
        ),
        lambda: _mut_enc(ct="ab" * 524288),  # 1MB 密文
        lambda: json.dumps(dict(obj, v=secrets.choice([1, 2, 4, "3", None]))),
        lambda: json.dumps(dict(obj, enc=json.dumps(enc))),  # enc=嵌套 JSON 字符串
        lambda: json.dumps({"v": 3, "pk": obj["pk"], "enc": "A" * secrets.randbelow(64)}),
        lambda: "%s%s%n" + blob,
        lambda: bytes(secrets.token_bytes(64)).decode("latin-1"),
    ]


def _fuzz_sm2gens(pk: str, msg: bytes, sig: str) -> list:
    """畸形验签输入生成器族（12 类）。"""
    return [
        lambda: ("", b"", ""),
        lambda: ("zz" * 64, msg, sig),
        lambda: (pk, msg, _flip_hex_byte(sig, secrets.randbelow(64) * 2)),
        lambda: (pk, msg[: secrets.randbelow(len(msg))], sig),
        lambda: (pk[: 2 * max(1, secrets.randbelow(64))], msg, sig),
        lambda: ("0x" + pk, msg, sig),
        lambda: (pk, msg, sig + "aa"),
        lambda: (pk, msg, "00" * 64),
        lambda: (pk, f"坏消息{secrets.randbelow(9)}".encode(), sig),
        lambda: (secrets.token_hex(64), secrets.token_bytes(32), secrets.token_hex(64)),
        lambda: (pk, msg, sig[64:] + sig[:64]),  # r/s 对调
        lambda: (pk, msg, json.dumps({"sig": sig})),
    ]


def _run_fuzz(rounds_per_target: int) -> int:
    """子进程体：全拒 + 不崩溃 + 无逃逸。stdout 输出 FUZZ_JSON 统计行。"""
    from app.crypto.sm2 import generate_keypair, sign
    from app.crypto.sm2 import verify as sm2_verify

    stats = {}
    for tgt in ("unseal", "sm2"):
        stats[tgt] = {
            "rounds": 0,
            "rejected": 0,
            "accepted": 0,
            "captured": 0,
            "unexpected_types": {},
        }

    sk, pk = generate_keypair()
    msg0 = b"FZ-CA-C8-TARGET"
    sig0 = sign(sk, msg0)
    blob0 = _seal_v3(sk, "Fuzz-Pass-1")
    bgens, sgens = _fuzz_blobgens(blob0), _fuzz_sm2gens(pk, msg0, sig0)

    for i in range(rounds_per_target):
        blob = bgens[i % len(bgens)]()
        st = stats["unseal"]
        st["rounds"] += 1
        try:
            _unseal_v3(blob, "Fuzz-Pass-1")
            st["accepted"] += 1  # 无异常返回=GCM 认证被攻破（形态缺陷=攻破）
        except Exception as e:  # noqa: BLE001  拒绝面=异常即拒（捕获计数）
            st["captured"] += 1
            st["rejected"] += 1
            tn = type(e).__name__
            if tn not in (
                "ValueError",
                "SM4GCMError",
                "KeyError",
                "TypeError",
                "JSONDecodeError",
                "UnicodeDecodeError",
            ):
                st["unexpected_types"][tn] = st["unexpected_types"].get(tn, 0) + 1

        pub_h, msg_b, sig_h = sgens[i % len(sgens)]()
        st = stats["sm2"]
        st["rounds"] += 1
        try:
            if sm2_verify(pub_h, msg_b, sig_h) is True:
                st["accepted"] += 1
            else:
                st["rejected"] += 1
        except Exception as e:  # noqa: BLE001
            st["captured"] += 1
            st["rejected"] += 1
            tn = type(e).__name__
            if tn not in ("ValueError", "SM2Error", "TypeError", "UnicodeDecodeError"):
                st["unexpected_types"][tn] = st["unexpected_types"].get(tn, 0) + 1

    attacked = any(s["accepted"] for s in stats.values())
    print("FUZZ_JSON:" + json.dumps(stats, ensure_ascii=False), flush=True)
    return 2 if attacked else 0


def c8_fuzz(rb: ReportBuilder, rounds_per_target: int = 500) -> None:
    m = rb.module("C8_fuzz", "C8 模糊注入护栏（解封+SM2 验签畸形输入，子进程隔离）")
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--fuzz-child", str(rounds_per_target)],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=600,
        env={**os.environ, "PYTHONPATH": str(BACKEND)},
        cwd=str(BACKEND),
    )
    payload = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("FUZZ_JSON:"):
            payload = json.loads(line[len("FUZZ_JSON:") :])
    if proc.returncode not in (0, 2) or payload is None:
        m.env_error(
            "C8-03 模糊子进程存活（进程不崩溃）",
            detail={"returncode": proc.returncode, "stderr_tail": (proc.stderr or "")[-300:]},
        )
        return

    un, sm = payload["unseal"], payload["sm2"]
    if un["accepted"] == 0:
        m.pass_(
            f"C8-01 解封函数 {un['rounds']} 轮畸形输入全拒",
            defense_ref="app/crypto/sm4.py:SM4GCM.decrypt + keystore.ts unseal 镜像",
            detail=un,
        )
    else:
        m.fail(
            f"C8-01 解封函数 {un['rounds']} 轮畸形输入全拒",
            expected="accepted=0",
            actual=f"accepted={un['accepted']}",
            defense_ref="app/crypto/sm4.py:SM4GCM.decrypt",
            attack_success=True,
            detail=un,
        )
    if sm["accepted"] == 0:
        m.pass_(
            f"C8-02 SM2 验签 {sm['rounds']} 轮畸形输入全拒",
            defense_ref="app/crypto/sm2.py:verify",
            detail=sm,
        )
    else:
        m.fail(
            f"C8-02 SM2 验签 {sm['rounds']} 轮畸形输入全拒",
            expected="accepted=0",
            actual=f"accepted={sm['accepted']}",
            defense_ref="app/crypto/sm2.py:verify",
            attack_success=True,
            detail=sm,
        )
    m.pass_(
        "C8-03 模糊子进程存活（进程不崩溃）",
        defense_ref="app/crypto/sm4.py + app/crypto/sm2.py（异常面收敛）",
        detail={
            "returncode": proc.returncode,
            "注记": "子进程内全部输入经 try/except 捕获——exit 0 即无逃逸",
        },
    )
    unexpected = {**un["unexpected_types"], **sm["unexpected_types"]}
    if unexpected:
        m.xfail(
            "C8-04 无未捕获异常逃逸（含非预期异常类型计数）",
            reason=f"全部被捕获未逃逸，但出现非预期异常类型: {unexpected}",
            defense_ref="app/crypto/sm4.py + app/crypto/sm2.py",
        )
    else:
        m.pass_(
            "C8-04 无未捕获异常逃逸（捕获计数入报告）",
            defense_ref="app/crypto/sm4.py + app/crypto/sm2.py",
            detail={"captured": un["captured"] + sm["captured"]},
        )


# ============================================================================
# 主流程
# ============================================================================


def _guarded(rb: ReportBuilder, mod_key: str, fn, *args) -> None:
    """模块体兜底：夹具级未捕获异常=如实红（绝不静默半绿）。"""
    try:
        fn(rb, *args)
    except Exception as e:  # noqa: BLE001
        rb.module(mod_key).fail(
            f"{mod_key}-harness 未捕获异常",
            expected="模块体零未捕获异常",
            actual=f"{type(e).__name__}: {e}",
            defense_ref="scripts/crypto_audit.py",
        )


def main() -> int:
    ap = argparse.ArgumentParser(description="飞证密码技术审计套件（C1~C8）")
    ap.add_argument(
        "--quick",
        action="store_true",
        help="快档：C4 仅 3 项 zkc 实弹、C8 1000 轮（C7 采样规格不缩水——≥3000/侧）",
    )
    ap.add_argument("--fuzz-child", type=int, default=0, metavar="ROUNDS", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.fuzz_child:
        return _run_fuzz(args.fuzz_child)

    rb = ReportBuilder(suite="crypto", uas_root=UAS)
    print("== 密码技术审计套件（C1~C8）==", flush=True)

    _guarded(rb, "C1_vectors", c1_vectors)
    _guarded(rb, "C2_envelope", c2_envelope)
    _guarded(rb, "C3_gate_matrix", c3_gate_matrix)
    _guarded(rb, "C4_graft", c4_graft_rejection, args.quick)
    _guarded(rb, "C5_lifecycle", c5_key_lifecycle)
    _guarded(rb, "C6_dual_control", c6_dual_control)
    # 批 2-2.4：C7 采样规格 ≥3000/侧为下限（c7 内部再抬升）——--quick 不缩水
    _guarded(rb, "C7_constant_time", c7_constant_time, 3000)
    _guarded(rb, "C8_fuzz", c8_fuzz, 600 if not args.quick else 500)

    rep = rb.build()
    rb.save(str(BACKEND / "reports"))
    return 0 if rep["summary"]["verdict"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
