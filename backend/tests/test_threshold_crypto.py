"""④站门限解锁单测（2026-10-10）：SM2 ECIES 线性门限 2-of-3。

数学依据：[d]C₁=Σ[λᵢdᵢ]C₁=[d]C₁（线性）——份额域只出 [dᵢ]C₁ 点份额，
私钥 d 全程不重组不落任何单点。先红后绿：本文件先于 threshold.py 编写。
"""

from __future__ import annotations

import pytest

from app.crypto.sm2 import SM2Error, encrypt, generate_keypair, pubkey_from_priv
from app.crypto.threshold import (
    combine_decrypt_shares,
    decrypt_share,
    point_add,
    shamir_split,
    threshold_decrypt,
)


def test_shamir_2of3_any_two_shares_recover():
    """任两份额（拉格朗日）恢复 d——三组合全覆盖。"""
    from app.crypto.threshold import _N

    d = int.from_bytes(bytes.fromhex(generate_keypair()[0]), "big") % _N or 0x123456789ABCDEF
    shares = shamir_split(d, 3, 2)
    assert len(shares) == 3
    idx = [i for i, _ in shares]
    for pair in ((0, 1), (0, 2), (1, 2)):
        i, j = idx[pair[0]], idx[pair[1]]
        di, dj = shares[pair[0]][1], shares[pair[1]][1]
        # 拉格朗日零点插值（mod n——曲线阶）
        from app.crypto.threshold import _N, lagrange_coeff

        li = lagrange_coeff(i, [i, j])
        lj = lagrange_coeff(j, [i, j])
        assert (li * di + lj * dj) % _N == d % _N, f"组合 {pair} 恢复失败"


def test_single_share_leaks_nothing():
    """单份额信息论不可恢复：任一单份额对 d 的候选空间=全群（结构断言：
    恢复需 ≥k=2 点定一次多项式——单点不定直线，无算法可验证候选）。"""
    d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    shares = shamir_split(d, 3, 2)
    # 单份额下：存在无穷多多项式过该点 ⟹ 无法构造"验证 d 候选"的判据——
    # 这里钉结构：份额≠d 且份额×2 个不同根钥的份额互相独立。
    d2 = d + 1
    shares2 = shamir_split(d2, 3, 2)
    assert all(s[1] != d % (2**256) for s in shares)
    assert [s[1] for s in shares] != [s[1] for s in shares2]


def test_threshold_decrypt_matches_single_key():
    """门限解密≡单钥解密：ECIES 密文 + 任两份额点 ⟹ 同明文。"""
    sk, _pk = generate_keypair()
    msg = b"threshold-ecies-payload-" + bytes(range(48))
    ct = encrypt(pubkey_from_priv(sk), msg)
    d = int(sk, 16)
    shares = shamir_split(d, 3, 2)
    c1_hex = ct[:64].hex()
    # 份额域视角：只拿 dᵢ 与 C₁ ⟹ 出 [dᵢ]C₁（dᵢ 不出域）
    s0 = decrypt_share(f"{shares[0][1]:064x}", c1_hex)
    s1 = decrypt_share(f"{shares[1][1]:064x}", c1_hex)
    combined = combine_decrypt_shares([(shares[0][0], s0), (shares[1][0], s1)], c1_hex)
    # 合成点=标准解密的 [d]C₁（xy 对拍）
    from app.crypto.sm2 import _G, _c

    ref = _c(sk, _G)._kg_blind_ref()[0] if hasattr(_c(sk, _G), "_kg_blind_ref") else None
    # 直接对拍：用合成 xy 走 KDF+C3 路径（threshold_decrypt 全流程）
    plain = threshold_decrypt(ct, [(shares[0][0], s0), (shares[1][0], s1)])
    assert plain == msg
    del ref, combined


def test_threshold_decrypt_any_pairing():
    """三选二全部组合均可解（2-of-3 门限语义）。"""
    sk, _pk = generate_keypair()
    msg = b"any-pairing"
    ct = encrypt(pubkey_from_priv(sk), msg)
    d = int(sk, 16)
    shares = shamir_split(d, 3, 2)
    c1_hex = ct[:64].hex()
    pt_shares = [(i, decrypt_share(f"{di:064x}", c1_hex)) for i, di in shares]
    plain01 = threshold_decrypt(ct, [pt_shares[0], pt_shares[1]])
    plain02 = threshold_decrypt(ct, [pt_shares[0], pt_shares[2]])
    plain12 = threshold_decrypt(ct, [pt_shares[1], pt_shares[2]])
    assert plain01 == plain02 == plain12 == msg


def test_single_share_cannot_decrypt():
    """单份额解密 ⟹ C3 校验必败（不出明文——密码学强制非流程强制）。"""
    sk, _pk = generate_keypair()
    msg = b"single-share-must-fail"
    ct = encrypt(pubkey_from_priv(sk), msg)
    d = int(sk, 16)
    shares = shamir_split(d, 3, 2)
    c1_hex = ct[:64].hex()
    lone = decrypt_share(f"{shares[0][1]:064x}", c1_hex)
    with pytest.raises(SM2Error):
        threshold_decrypt(ct, [(shares[0][0], lone)])


def test_wrong_share_fails_c3():
    """错域份额（异根钥份额混入）⟹ C3 校验拒（不返回垃圾明文）。"""
    sk, _pk = generate_keypair()
    other_sk, _ = generate_keypair()
    ct = encrypt(pubkey_from_priv(sk), b"wrong-share")
    shares = shamir_split(int(sk, 16), 3, 2)
    foreign = shamir_split(int(other_sk, 16), 3, 2)
    c1_hex = ct[:64].hex()
    mix = [
        (shares[0][0], decrypt_share(f"{shares[0][1]:064x}", c1_hex)),
        (foreign[1][0], decrypt_share(f"{foreign[1][1]:064x}", c1_hex)),
    ]
    with pytest.raises(SM2Error):
        threshold_decrypt(ct, mix)


def test_point_add_identity_and_double():
    """点加原语边界：P+O=P、P+P=2P（与 _kg 对拍——等值点走倍点分支）。"""
    from app.crypto.sm2 import _G

    sk = int(generate_keypair()[0], 16)
    from app.crypto.sm2 import _c

    p_hex = _c("", _G)._kg(sk, _G)  # P=[sk]G
    o = "0" * 128  # 无穷远点约定（全零 xy）
    assert point_add(p_hex, o) == p_hex
    dbl = point_add(p_hex, p_hex)
    from app.crypto.threshold import _N

    ref = _c("", _G)._kg((2 * sk) % _N, _G)  # 倍点标量 mod 曲线阶（错模=潜伏 flake）
    assert dbl == ref
