//! T2 · 参考实现 B（净室二写，2026-09-11；(A7) 测试体系第二族）
//!
//! 独立性纪律：本文件自 GB/T 32905（SM3）/32918.2（SM2 验证）规范算法直译，
//! **写作时未参照 sm3_native_ref / sm2_verify_assemble / gmssl 任何一方实现**；
//! 与既有实现的差分一致性由本文件 tests 承载（SM3=随机消息+GB/T 示例锚点
//! 对拍 [`crate::sm3_native_ref`]；SM2=接受集+篡改+范围拒绝三面差分）。
//! 算术栈刻意选 BigUint（与生产 u64-limb 栈异构，杜绝同源实现错误）。
//! 常量纪律：p/a/b/G/GY/n 十进制串逐字转录自权威源 `m0_sm3_circuit/src/fp_sm2.rs`
//! （[实测核验 2026-08-26] 注记）与 `sm2_params::N_HEX`——任何转录错误会被差分
//! 测试当场抓获（这就是差分测试的存在意义）。
pub mod sm2_ref_b {
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    // ── 权威源常量（十进制逐字转录） ──
    fn p() -> BigUint {
        BigUint::parse_bytes(
            b"115792089210356248756420345214020892766250353991924191454421193933289684991999",
            10,
        )
        .unwrap()
    }
    fn a_curve() -> BigUint {
        BigUint::parse_bytes(
            b"115792089210356248756420345214020892766250353991924191454421193933289684991996",
            10,
        )
        .unwrap()
    }
    fn b_curve() -> BigUint {
        BigUint::parse_bytes(
            b"18505919022281880113072981827955639221458448578012075254857346196103069175443",
            10,
        )
        .unwrap()
    }
    fn gx() -> BigUint {
        BigUint::parse_bytes(
            b"22963146547237050559479531362550074578802567295341616970375194840604139615431",
            10,
        )
        .unwrap()
    }
    fn gy() -> BigUint {
        BigUint::parse_bytes(
            b"85132369209828568825618990617112496413088388631904505083283536607588877201568",
            10,
        )
        .unwrap()
    }
    fn nn() -> BigUint {
        BigUint::parse_bytes(
            b"115792089210356248756420345214020892766061623724957744567843809356293439045923",
            10,
        )
        .unwrap()
    }

    type Pt = Option<(BigUint, BigUint)>; // None = 无穷远

    fn mod_inv(x: &BigUint, m: &BigUint) -> BigUint {
        // Fermat：x^(m−2) mod m（m 素数）
        let e = m - 2u32;
        let mut acc = BigUint::one();
        let mut base = x % m;
        let mut exp = e;
        while !exp.is_zero() {
            if exp.bit(0) {
                acc = acc * &base % m;
            }
            base = &base * &base % m;
            exp >>= 1;
        }
        acc
    }

    fn on_curve(x: &BigUint, y: &BigUint) -> bool {
        let lhs = (y * y) % p();
        let rhs = ((x * x * x) + (a_curve() * x) + b_curve()) % p();
        lhs == rhs
    }

    fn sub_mod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
        if a >= b { a - b } else { a + m - b }
    }
    fn add_mod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint { (a + b) % m }
    fn mul_mod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint { a * b % m }

    fn pt_add(p1: &Pt, p2: &Pt) -> Pt {
        let (x1, y1) = match p1 {
            None => return p2.clone(),
            Some(v) => v,
        };
        let (x2, y2) = match p2 {
            None => return p1.clone(),
            Some(v) => v,
        };
        let pp = p();
        if x1 == x2 {
            if add_mod(y1, y2, &pp).is_zero() {
                return None; // 对和点（含 y=0 自逆角）
            }
            return pt_dbl(p1);
        }
        let lam = mul_mod(&sub_mod(y2, y1, &pp), &mod_inv(&sub_mod(x2, x1, &pp), &pp), &pp);
        let x3 = sub_mod(&mul_mod(&lam, &lam, &pp), &add_mod(x1, x2, &pp), &pp);
        let y3 = sub_mod(&mul_mod(&lam, &sub_mod(x1, &x3, &pp), &pp), y1, &pp);
        Some((x3, y3))
    }

    fn pt_dbl(ptv: &Pt) -> Pt {
        let (x, y) = match ptv {
            None => return None,
            Some(v) => v,
        };
        let pp = p();
        if y.is_zero() {
            return None;
        }
        let lam = mul_mod(
            &add_mod(
                &mul_mod(&BigUint::from(3u32), &mul_mod(x, x, &pp), &pp),
                &a_curve(),
                &pp,
            ),
            &mod_inv(&mul_mod(&BigUint::from(2u32), y, &pp), &pp),
            &pp,
        );
        let x3 = sub_mod(&mul_mod(&lam, &lam, &pp), &add_mod(x, x, &pp), &pp);
        let y3 = sub_mod(&mul_mod(&lam, &sub_mod(x, &x3, &pp), &pp), y, &pp);
        Some((x3, y3))
    }

    fn scalar_mul(k: &BigUint, pt: &Pt) -> Pt {
        let bits: Vec<bool> = {
            let s = k.to_bytes_be();
            let mut v = Vec::new();
            for byte in s.iter() {
                for i in (0..8).rev() {
                    v.push((byte >> i) & 1 == 1);
                }
            }
            v
        };
        let mut acc: Pt = None;
        for bit in bits {
            acc = pt_dbl(&acc);
            if bit {
                acc = pt_add(&acc, pt);
            }
        }
        acc
    }

    fn pt_g() -> Pt {
        Some((gx(), gy()))
    }

    /// 曲线常量自洽复验（差分测试辅助）：G 在曲线上、[n]G=∞、[G 阶一半+1]≠∞。
    pub fn selfcheck_g() -> bool {
        let g = pt_g();
        let (x, y) = g.as_ref().unwrap();
        if !on_curve(x, y) {
            return false;
        }
        let n = nn();
        if scalar_mul(&n, &g).is_some() {
            return false;
        }
        let half = (&n + 1u32) / 2u32;
        scalar_mul(&half, &g).is_some() // (n+1)/2 · G = −G ≠ ∞（素数阶群）
    }

    /// GB/T 32918.2 验证方程（净室）：完整范围检查 + t≠0 + (x₁,y₁)=[s]G+[t]P_A
    /// + r ≡ (e+x₁) mod n；无穷远结果拒绝。
    pub fn verify_refb(e: &BigUint, r: &BigUint, s: &BigUint, pax: &BigUint, pay: &BigUint) -> bool {
        let n = nn();
        if r.is_zero() || r >= &n || s.is_zero() || s >= &n {
            return false;
        }
        let t = (r + s) % &n;
        if t.is_zero() {
            return false;
        }
        if !on_curve(pax, pay) {
            return false;
        }
        let sg = scalar_mul(s, &pt_g());
        let tpa = scalar_mul(&t, &Some((pax.clone(), pay.clone())));
        let x1 = match pt_add(&sg, &tpa) {
            Some((x, _y)) => x,
            None => return false,
        };
        let chk = (e % &n + &x1) % &n;
        &chk == r
    }

    // ── SM3（净室） ──
    const IV_B: [u32; 8] = [
        0x7380_166F, 0x4914_B2B9, 0x1724_42D7, 0xDA8A_0600,
        0xA96F_30BC, 0x1631_38AA, 0xE38D_EE4D, 0xB0FB_0E4E,
    ];
    fn rotl(x: u32, k: u32) -> u32 { x.rotate_left(k) }
    fn p0(x: u32) -> u32 { x ^ rotl(x, 9) ^ rotl(x, 17) }
    fn p1(x: u32) -> u32 { x ^ rotl(x, 15) ^ rotl(x, 23) }
    fn ff(j: usize, x: u32, y: u32, z: u32) -> u32 {
        if j < 16 { x ^ y ^ z } else { (x & y) | (x & z) | (y & z) }
    }
    fn gg(j: usize, x: u32, y: u32, z: u32) -> u32 {
        if j < 16 { x ^ y ^ z } else { (x & y) | (!x & z) }
    }

    pub fn sm3_compress_refb(v: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
        let mut w = [0u32; 68];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        for j in 16..68 {
            let x = w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15);
            w[j] = p1(x) ^ rotl(w[j - 13], 7) ^ w[j - 6];
        }
        let (mut a, mut b, mut c, mut d) = (v[0], v[1], v[2], v[3]);
        let (mut e, mut f, mut g, mut h) = (v[4], v[5], v[6], v[7]);
        for j in 0..64 {
            let tj: u32 = if j < 16 { 0x79CC_4519 } else { 0x7A87_9D8A };
            let ss1 = rotl(rotl(a, 12).wrapping_add(e).wrapping_add(rotl(tj, (j as u32) % 32)), 7);
            let ss2 = ss1 ^ rotl(a, 12);
            let tt1 = ff(j, a, b, c).wrapping_add(d).wrapping_add(ss2).wrapping_add(w[j] ^ w[j + 4]);
            let tt2 = gg(j, e, f, g).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
            d = c; c = rotl(b, 9); b = a; a = tt1;
            h = g; g = rotl(f, 19); f = e; e = p0(tt2);
        }
        [
            v[0] ^ a, v[1] ^ b, v[2] ^ c, v[3] ^ d,
            v[4] ^ e, v[5] ^ f, v[6] ^ g, v[7] ^ h,
        ]
    }

    pub fn sm3_hash_refb(msg: &[u8]) -> [u8; 32] {
        let bitlen = (msg.len() as u64) * 8;
        let mut m = msg.to_vec();
        m.push(0x80);
        while m.len() % 64 != 56 { m.push(0); }
        m.extend_from_slice(&bitlen.to_be_bytes());
        let mut v = IV_B;
        for chunk in m.chunks(64) {
            let mut blk = [0u8; 64];
            blk.copy_from_slice(chunk);
            v = sm3_compress_refb(&v, &blk);
        }
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&v[i].to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod refb_tests {
    use super::sm2_ref_b::{selfcheck_g, sm3_hash_refb, verify_refb};
    use crate::sm2_full_statement_assemble::sm2_sign_host;
    use crate::sm2_params::{fr_to_limbs, n_limbs};
    use num_bigint::BigUint;
    use num_traits::Zero;

    struct SplitMix(u64);
    impl SplitMix {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }
    fn to_big(l: &[u64; 4]) -> BigUint {
        let mut b = BigUint::zero();
        for w in (0..4).rev() {
            b = (b << 64) | BigUint::from(l[w]);
        }
        b
    }
    fn from_big(x: &BigUint) -> [u64; 4] {
        let mask = BigUint::from(u64::MAX);
        let mut out = [0u64; 4];
        let mut v = x.clone();
        for slot in out.iter_mut() {
            *slot = (&v & &mask).to_u64_digits().get(0).copied().unwrap_or(0);
            v >>= 64;
        }
        out
    }

    /// T2-SM3①：GB/T 32905 附录 A 示例锚（"abc"；规范摘要常量——若此锚失败而
    /// ②差分通过，则是本锚常量誊写错误而非实现错误）。
    #[test]
    fn refb_sm3_abc_anchor() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("refb_sm3_abc_anchor", "T2; SM3 abc anchor");
        let dg = sm3_hash_refb(b"abc");
        let hex: String = dg.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }

    /// T2-SM3②：随机消息 300 条（长度 0–299 覆盖全部 padding 边界：55/56/63/64/
    /// 65/127/128 全入样）与 native_ref（GB/T 向量三层核验链）逐条差分。
    #[test]
    fn refb_sm3_differential_vs_native() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("refb_sm3_differential_vs_native", "T2; SM3 300-msg differential vs native");
        let mut sm = SplitMix(0x7E57_11);
        for len in 0..300usize {
            let mut msg = Vec::with_capacity(len);
            for _ in 0..len {
                msg.push(sm.next() as u8);
            }
            let a = sm3_hash_refb(&msg);
            let b = crate::sm3_native_ref::hash(&msg);
            assert!(a == b, "SM3 净室差分失配 @len={len}");
        }
    }

    /// T2-SM2①：接受集差分——20 随机合法 (sk∈[1,n−2], e)，宿主签名 ⟹ ref_b 全接受。
    #[test]
    fn refb_sm2_accept_set_agrees() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("refb_sm2_accept_set_agrees", "T2; SM2 accept-set 20 random keys");
        let mut sm = SplitMix(0x5E1B_22);
        let n_b = to_big(&n_limbs());
        let one = BigUint::from(1u8);
        let nm2 = &n_b - 2u32;
        for _ in 0..20 {
            let sk_b = to_big(&[sm.next(), sm.next(), sm.next() % (1 << 32), 0]) % &n_b;
            if sk_b < one || sk_b > nm2 {
                continue; // 域外抽样跳过（合法域拒绝面由②覆盖）
            }
            let sk_limbs = from_big(&sk_b);
            let pk = sm2_sign_host::pk_from_sk(&sk_limbs);
            let e_l = [sm.next(), sm.next(), sm.next() % (1 << 63), 0];
            let (r, s) = sm2_sign_host::sign(&e_l, &sk_limbs);
            let ok = verify_refb(
                &to_big(&e_l),
                &to_big(&r),
                &to_big(&s),
                &to_big(&fr_to_limbs(&pk.0)),
                &to_big(&fr_to_limbs(&pk.1)),
            );
            assert!(ok, "ref_b 拒绝了宿主合法签名");
        }
    }

    /// T2-SM2②：拒绝面——e/r/s 各单点篡改 + r=0/r=n/s=0 范围拒绝（固定测试钥）。
    #[test]
    fn refb_sm2_rejection_face() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("refb_sm2_rejection_face", "T2; SM2 rejection face e|r|s tamper");
        let mut sm = SplitMix(0x7A8E_55);
        let n_b = to_big(&n_limbs());
        let sk_b = to_big(&[0x0A1B_2C3D, 0x5E6F_8091, 0xA2B3_C4D5, 0x0E6F_1234]) % &n_b;
        let d_bytes = from_big(&sk_b);
        let (pax, pay) = sm2_sign_host::pk_from_sk(&d_bytes);
        let (paxb, payb) = (to_big(&fr_to_limbs(&pax)), to_big(&fr_to_limbs(&pay)));
        for _ in 0..10 {
            let e_l = [sm.next(), sm.next(), sm.next(), sm.next() >> 32];
            let (r, s) = sm2_sign_host::sign(&e_l, &d_bytes);
            let e_b = to_big(&e_l);
            let rb = to_big(&r);
            let sb = to_big(&s);
            assert!(verify_refb(&e_b, &rb, &sb, &paxb, &payb));
            assert!(!verify_refb(&(e_b.clone() ^ BigUint::from(1u8)), &rb, &sb, &paxb, &payb), "e 篡改未拒");
            let r_t = (rb.clone() + 1u32) % &n_b;
            assert!(!verify_refb(&e_b, &r_t, &sb, &paxb, &payb), "r 篡改未拒");
            let s_t = (sb.clone() + 1u32) % &n_b;
            assert!(!verify_refb(&e_b, &rb, &s_t, &paxb, &payb), "s 篡改未拒");
            assert!(!verify_refb(&e_b, &BigUint::zero(), &sb, &paxb, &payb), "r=0 未拒");
            assert!(!verify_refb(&e_b, &n_b, &sb, &paxb, &payb), "r=n 未拒");
            assert!(!verify_refb(&e_b, &rb, &BigUint::zero(), &paxb, &payb), "s=0 未拒");
        }
    }

    /// T2-SM2③：曲线常量自洽——G 在曲线上、[n]G=∞、[(n+1)/2]G=−G≠∞。
    #[test]
    fn refb_curve_constants_selfconsistent() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("refb_curve_constants_selfconsistent", "T2; curve constants self-check");
        assert!(selfcheck_g(), "G 在曲线/阶/半阶点自洽失败");
    }
}
