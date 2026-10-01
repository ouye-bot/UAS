//! 🔍T6 根因二分探针（2026-09-11）：d=n−2 时 sign_with_nonce s≡0 不变量的根因定位。
//! 对照真值源 = num_bigint::BigUint（仓内既有依赖）。生产码零改动。
#[cfg(test)]
mod tests {
    use crate::sm2_full_statement_assemble::sm2_sign_host::{inv_mod_n, mul_mod_n, sub_mod_n};
    use crate::sm2_params::{n_limbs, hex_to_limbs_le};
    use num_bigint::BigUint;

    fn to_big(v: &[u64; 4]) -> BigUint {
        let mut b = BigUint::from(0u8);
        for w in (0..4).rev() {
            b = (b << 64) | BigUint::from(v[w]);
        }
        b
    }
    fn from_big(x: &BigUint) -> [u64; 4] {
        let mask = BigUint::from(u64::MAX);
        let mut out = [0u64; 4];
        let mut v = x.clone();
        for i in 0..4 {
            out[i] = (&v & &mask).to_u64_digits().get(0).copied().unwrap_or(0);
            v >>= 64;
        }
        out
    }

    /// 分支 1：inv_mod_n(n−1)——数学应 = n−1（−1 的逆 = −1）。
    #[test]
    fn probe_inv_of_n_minus_1() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("probe_inv_of_n_minus_1", "T6; inv(n-1) BigUint probe");
        let n = n_limbs();
        let nm1 = {
            let mut v = n;
            v[0] = v[0].wrapping_sub(1);
            v
        };
        let got = inv_mod_n(&nm1);
        assert_eq!(got, nm1, "inv(n−1) 应 = n−1（−1 自逆）");
    }

    /// 分支 2：mul_mod_n(r, n−2) 对 BigUint 真值——锁定 reduce_wide 对近 n 乘数是否失效。
    #[test]
    fn probe_mul_by_n_minus_2_vs_bigint() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("probe_mul_by_n_minus_2_vs_bigint", "T6; mul n-2 vs BigUint");
        let n = n_limbs();
        let nm2 = {
            let mut v = n;
            v[0] = v[0].wrapping_sub(2);
            v
        };
        let n_b = to_big(&n);
        let nm2_b = to_big(&nm2);
        for (i, r_hex) in [
            "00000000000000000000000000000000000000000000000000000000000000AA",
            "0A11CE650B501E5A000000000000000300000000000000000000000000005EED",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ]
        .iter()
        .enumerate()
        {
            let r = hex_to_limbs_le(r_hex);
            let got = mul_mod_n(&r, &nm2);
            let want_b = (to_big(&r) * nm2_b.clone()) % n_b.clone();
            let want = from_big(&want_b);
            assert_eq!(got, want, "case {i}: mul_mod_n(r, n−2) 偏离 BigUint 真值");
        }
    }

    /// 分支 3：sub_mod_n(k, x) 对 BigUint 真值（limb 字面量，无 hex 长度歧义）。
    #[test]
    fn probe_sub_vs_bigint() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("probe_sub_vs_bigint", "T6; sub vs BigUint");
        let n = n_limbs();
        let n_b = to_big(&n);
        let k = [0xF0E1_D2C3_B4A5_9687, 0x1234_5678_9ABC_DEF0, 7, 0x5EED];
        let x = [0x0000_0000_00BB_CCAA, 0xAA00_0000_0000_0000, 0, 0x00AA];
        let got = sub_mod_n(&k, &x);
        let kb = to_big(&k) % n_b.clone();
        let xb = to_big(&x) % n_b.clone();
        let want = from_big(&((kb + n_b.clone() - xb) % n_b));
        assert_eq!(got, want, "sub_mod_n 偏离 BigUint 真值");
    }
}
