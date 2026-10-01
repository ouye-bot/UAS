"""SM2 封装测试。

A.2 族五元组向量——溯源（口径修正 SP-20 OP-4：印刷 e 值不可由声明 (ID,M) 复现，
实为论文栈 M2a 溯源五元组，内部数学一致+三实现对拍——详见 TestTSParityFixture 勘误）：
来源 = M0_sm3_circuit/src/sm2_verify_native.rs:117-121（M2a 三层验证：
标准附录 ↔ Rust 电路 ↔ gmssl 对拍），并与
literature_review/M2a_SM2验签电路_实测.md（IDA=ALICE123@YAHOO.COM，
M="message digest"）双源交叉一致 [核查 2026-09-01]。
"""

import os

import pytest
from gmssl.sm2 import default_ecc_table

import app.crypto.sm2 as _sm2_mod
from app.crypto.sm2 import (
    SM2Error,
    _digest_z,
    decrypt,
    encrypt,
    generate_keypair,
    pubkey_from_priv,
    sign,
    verify,
    verify_digest,
)

# ---- GB/T 32918.2-2016 附录 A.2（溯源自 sm2_verify_native.rs，M2a 三层验证） ----
_A2_ID = "ALICE123@YAHOO.COM"
_A2_E_HEX = "ABF7EB631D94615FD1A941D40E99932DDB1899E1DFAE7179B4A79417EA3743E5"
_A2_PUB_HEX = (
    "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
    "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
)
_A2_SIG_HEX = (
    "88348A09A3E324C4FE946843123E40C175468F3E36481885844A144D2167EA4C"
    "0AD2CE552FD33EAB792E5A2805E0504D014C96135F8E03891087132ABB24D48D"
)


class TestGBT_A2_Vector:
    def test_verify_digest_official_vector(self):
        assert verify_digest(_A2_PUB_HEX, bytes.fromhex(_A2_E_HEX), _A2_SIG_HEX) is True

    def test_verify_digest_tamper_r(self):
        bad = "0" + _A2_SIG_HEX[1:]
        assert verify_digest(_A2_PUB_HEX, bytes.fromhex(_A2_E_HEX), bad) is False

    def test_verify_digest_wrong_digest(self):
        other = bytes(32)
        assert verify_digest(_A2_PUB_HEX, other, _A2_SIG_HEX) is False


class TestKeypair:
    def test_generate_and_pubkey_consistency(self):
        priv, pub = generate_keypair()
        assert len(priv) == 64 and len(pub) == 128
        assert pubkey_from_priv(priv) == pub

    def test_priv_in_range(self):
        n = int(default_ecc_table["n"], 16)  # 曲线常量只从库引用，禁手抄
        for _ in range(10):
            priv, _ = generate_keypair()
            assert 1 <= int(priv, 16) < n


class TestSignVerify:
    def test_roundtrip_and_cross_verify(self):
        """differential：自实现 verify_digest 与 gmssl 原生裸 verify 必须同判。

        勘误（执行期实测）：gmssl.sign/verify 是"对摘要直接签名"的原语
        （内部无哈希、无 Z 路径）；_sm3_z(msg) 返回的已是最终摘要 e（默认
        ID=1234567812345678）。三实现对同一摘要 e 同判。
        """
        from gmssl.sm2 import CryptSM2

        priv, pub = generate_keypair()
        msg = "policy-2026-09-01-授权-小明".encode()
        sig = sign(priv, msg)
        assert verify(pub, msg, sig) is True

        # gmssl 侧的 Z 路径摘要（其 _sm3_z 直接返回 e）
        c = CryptSM2(private_key=priv, public_key=pub)
        e = bytes.fromhex(c._sm3_z(msg))
        assert verify_digest(pub, e, sig) is True

        # gmssl 原生裸 verify（独立实现）对同一摘要同判
        raw = CryptSM2(private_key="0" * 64, public_key=pub, mode=1)
        assert raw.verify(sig, e) == 1

        # 篡改 s 一位：三路都必须拒绝
        bad = sig[:64] + format(int(sig[64:], 16) ^ 1, "064x")
        assert verify(pub, msg, bad) is False
        assert verify_digest(pub, e, bad) is False
        assert raw.verify(bad, e) == 0

    def test_z_digest_matches_gmssl(self):
        """自实现 Z 路径摘要（默认 ID）与 gmssl._sm3_z 必须逐字节一致。"""
        from gmssl.sm2 import CryptSM2

        priv, pub = generate_keypair()
        msg = b"cross-check"
        c = CryptSM2(private_key=priv, public_key=pub)
        assert _digest_z(pub, msg) == bytes.fromhex(c._sm3_z(msg))

    def test_verify_rejects_wrong_pubkey(self):
        _, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()
        sig = sign(priv_b, b"m")
        assert verify(pub_a, b"m", sig) is False

    def test_verify_rejects_malformed(self):
        _, pub = generate_keypair()
        assert verify(pub, b"m", "zz") is False
        assert verify("00" * 64, b"m", "11" * 64) is False  # 不在曲线上

    def test_sign_is_randomized(self):
        priv, _ = generate_keypair()
        assert sign(priv, b"m") != sign(priv, b"m")  # 随机 K


class TestECIES:
    def test_roundtrip(self):
        priv, pub = generate_keypair()
        for pt in (b"x", b"policy-secret-2026", os.urandom(100)):
            ct = encrypt(pub, pt)
            assert decrypt(priv, ct) == pt

    def test_tampered_ciphertext_rejected(self):
        priv, pub = generate_keypair()
        ct = bytearray(encrypt(pub, b"secret"))
        ct[-1] ^= 0x01
        with pytest.raises(SM2Error):
            decrypt(priv, bytes(ct))


# ---- EVP 验签引擎（2026-09-05 根修：0.324ms/op vs 纯 Python 10.15ms/op） ----


class TestEvpEngine:
    def test_engine_name_introspection(self):
        from app.crypto.sm2 import engine_name

        assert engine_name() in {"openssl", "pure"}

    def test_selected_engine_verify_semantics(self):
        """选通引擎（openssl，锚验证失败自动回落 pure）必须全语义正确。"""
        from app.crypto.sm2 import generate_keypair as gk
        from app.crypto.sm2 import sign, verify

        priv, pub = gk()
        msg = "策略-2026-09-05".encode()
        sig = sign(priv, msg)
        assert verify(pub, msg, sig) is True
        bad = format(int(sig[:64], 16) ^ 1, "064x") + sig[64:]
        assert verify(pub, msg, bad) is False
        _, pub2 = gk()
        assert verify(pub2, msg, sig) is False
        assert verify(pub, msg + b"x", sig) is False

    def test_cross_engine_differential(self):
        """跨引擎同判（最强锚）：引擎路径 verify() 与纯路径 verify_digest(Z)
        对同一签名集（含正/负例）判决逐条一致。"""
        from app.crypto.sm2 import _digest_z, sign, verify, verify_digest
        from app.crypto.sm2 import generate_keypair as gk

        for _ in range(8):
            priv, pub = gk()
            msg = "差分-".encode() + bytes.fromhex(format(_, "02x")) + "隐证通".encode()
            sig = sign(priv, msg)
            cases = [
                (sig, True),
                (format(int(sig[:64], 16) ^ 1, "064x") + sig[64:], False),  # r 翻转
                (sig[:64] + format(int(sig[64:], 16) ^ 1, "064x"), False),  # s 翻转
                (sig[:126] + ("00" if sig[-2:] != "00" else "11"), False),  # 尾字节
            ]
            for s, expect in cases:
                assert verify(pub, msg, s) is expect
                assert verify_digest(pub, _digest_z(pub, msg), s) is expect


# ---- SP9 9.19 秘密标量盲化（时序侧信道防线） ----


class _ScalarRecorder:
    """包装 CryptSM2._kg 记录每次调用的标量（不改变行为）。"""

    def __init__(self, monkeypatch):
        self.scalars: list[int] = []
        orig = _sm2_mod.CryptSM2._kg

        def rec(csm2_self, k, Point):
            self.scalars.append(int(k))
            return orig(csm2_self, k, Point)

        monkeypatch.setattr(_sm2_mod.CryptSM2, "_kg", rec)


def test_pubkey_from_priv_blinded_scalar_varies_same_output(monkeypatch):
    """盲化机制：分裂标量与 d 去相关（互异且≠d），输出恒等 [d]G；LRU 每钥一次。"""
    import app.crypto.sm2 as sm2_mod

    priv, _ = generate_keypair()
    d = int(priv, 16)
    # 参考值：非盲化 [d]G（直接底层原语，先于记录器安装）
    from app.crypto.sm2 import _G, _c

    expected = _c(priv, _G)._kg(d, _G)
    sm2_mod._pub_cache.clear()
    rec = _ScalarRecorder(monkeypatch)  # 记录器后装：只捕获被测两次调用
    out1 = pubkey_from_priv(priv)
    out2 = pubkey_from_priv(priv)
    assert out1 == expected and out2 == expected, "盲化不得改变数学输出"
    # 首调用=2 次分裂乘；再调用命中 LRU（每钥仅一次秘密标量乘——暴露面最小化）
    assert len(rec.scalars) == 2, f"清缓存后首推导应恰 2 次分裂乘（实得 {len(rec.scalars)}）"
    assert all(s != d for s in rec.scalars), "分裂标量必须≠d"
    assert rec.scalars[0] != rec.scalars[1], "分裂标量互异（去相关）"


def test_decrypt_blinded_scalar_varies_same_plaintext(monkeypatch):
    """ECIES 解密 [d]C1：重复采样的高危面——两次解密标量互异且明文恒等。"""
    rec = _ScalarRecorder(monkeypatch)
    priv, pub = generate_keypair()
    from app.crypto.sm2 import encrypt

    ct = encrypt(pub, "侧信道盲化验证明文".encode())
    m1 = decrypt(priv, ct)
    m2 = decrypt(priv, ct)
    assert m1 == m2 == "侧信道盲化验证明文".encode(), "盲化不得改变解密输出"
    d = int(priv, 16)
    assert all(s != d for s in rec.scalars), "解密路径标量必须≠d"
    assert len(set(rec.scalars)) >= 4, "两次解密应各走两次互异分裂标量乘"


class TestPrivDomainBoundary:
    """SP-19 跨线同步①（共享仓 T6-defect-1 同族）：d=n-1 挂死防线。

    论文侧机器实锤：d=n-1 ⟹ den=1+d≡0 ⟹ (1+d)^{-1} 不存在 ⟹ s≡0 对一切 k
    恒成立 ⟹ 签名重采样循环非终止（40,000+ 迭代 trace）。系统 Python 签名器
    同构（while True: c.sign 返 None 即重试）——ingest 咽点 _assert_priv 必须
    拒收 n-1（GB/T 32918.2 Keygen 域 [1, n-2]）。
    """

    def test_priv_n_minus_one_rejected_at_ingest(self):
        from app.crypto.sm2 import SM2Error, _assert_priv

        n = int(default_ecc_table["n"], 16)  # 曲线常量只从库引用，禁手抄
        bad = format(n - 1, "064x")
        with pytest.raises(SM2Error):
            _assert_priv(bad)

    def test_sign_n_minus_one_fails_fast_not_hang(self):
        """sign 直调 d=n-1 必须快速抛错（而非进入非终止重采样）。"""
        from app.crypto.sm2 import SM2Error, sign

        n = int(default_ecc_table["n"], 16)
        with pytest.raises(SM2Error):
            sign(format(n - 1, "064x"), b"x")


class TestTSParityFixture:
    """SP-20 OP-4：TS(sm-crypto) 签名 → Py 验签互操作锚（生产登录路径方向）。

    fixture=2026-09-14 由前端 sm-crypto doSignature(hash:true, 默认 userId)
    对示例钥 d（A.2 例族 well-known 值，非生产钥）生成 [实测]；
    sm-crypto 升级时此测试即供应链漂移检测器（签名格式/Z 路径漂移必红）。

    勘误记录（SP-20 探针）：①GB/T 32918.5 A.2 印刷 e 值不可由其声明 (ID,M)
    经 Z 路径公式复现——上方"官方向量"实为论文栈 M2a 溯源五元组（内部数学
    一致+三实现对拍），标准文本核对归论文线行动项（依赖清单 F1）；
    ②sm-crypto 的 Py 签→TS 验方向不对称（verify 侧 Z/编码与 sign 不同源）——
    生产前端只签不验，零产品面；TS 签→Py 验=生产互操作方向（本测试钉定）。
    """

    def test_ts_signature_fixture_verified_by_py(self):
        pub = (
            "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
            "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
        )
        msg = b"YZT-SM2-PARITY-VECTOR"
        ts_sig = (
            "132205c0678b2225203337f4a4e0d175a5900816eabcb570016fc18af8701b93"
            "c6cbb9cbfb3b5c2db60479cb11a949445c9d35bb15d616212391a57775c266e2"
        )
        assert verify(pub, msg, ts_sig) is True
        assert verify(pub, msg + b"x", ts_sig) is False
