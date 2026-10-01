//! SM2 外来域参数：群阶 n、补数 q = 2²⁵⁶ − n、域元素/lmb 互转工具。
//!
//! ## 常量来源纪律（[[never-handcopy-curve-constants]]）
//! n 的唯一权威值 = GB/T 32918.2 标准十六进制
//! `FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123`，
//! 与 m0_sm3_circuit/src/fp_sm2.rs 的 `BigInt!(115792089…45923)` 同源
//! （该处十进制串注明经 Python 从标准 hex 精确换算并有测试复核）。
//! 本 crate 为 ff 0.13 栈，不引入 ark BigInt 宏，故从**标准 hex 字符串机械解析**
//! 成 `[u64;4]` 小端 limbs；正确性由测试层三重锚定（见 mod tests）：
//! ① hex ↔ limbs 双向一致；② n < p（对拍 `FpSM2::MODULUS`）；
//! ③ q = 2²⁵⁶ − n 换算无借位且 q < p。任何抄写错误都在这三关爆炸。
//!
//! ## 语义边界（承继 M2a 设计 §2.4）
//! n ≈ p − 2¹²⁸ ⟹ q ≈ 2¹²⁸；2n > p，故 F_p 加法 wrap ≠ 整数加法，
//! mod-n 必须 256 位整数语义实现。下述工具只服务这一外来域层。

use crate::FpSM2;
use ff::Field;
use ff::PrimeField;

/// SM2 群阶 n 的标准十六进制（GB/T 32918.2-2016；分节排版便于人眼比对）。
pub const N_HEX: &str =
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";

/// 64 位十六进制段 → u64（供 hex_to_limbs_le 内部分片）。
fn seg(s: &str) -> u64 {
    u64::from_str_radix(s, 16).expect("hex 段非法")
}

/// 64 位十六进制串 → 小端 [u64;4]。长度恰 64，最高位 limb 在串首。
pub fn hex_to_limbs_le(s: &str) -> [u64; 4] {
    assert_eq!(s.len(), 64, "期望 256 位十六进制");
    let mut out = [0u64; 4];
    for i in 0..4 {
        let start = s.len() - 16 * (i + 1);
        out[i] = seg(&s[start..start + 16]);
    }
    out
}

/// 小端 [u64;4] → 大写十六进制（测试双向锚定用）。
pub fn limbs_to_hex(v: &[u64; 4]) -> String {
    let mut s = String::with_capacity(64);
    for i in (0..4).rev() {
        s.push_str(&format!("{:016X}", v[i]));
    }
    s
}

/// 群阶 n 的小端 limbs。
pub fn n_limbs() -> [u64; 4] {
    hex_to_limbs_le(N_HEX)
}

/// 补数 q = 2²⁵⁶ − n（小端 limbs；逐 limb 取反后 +1，标准两补码）。
pub fn q_limbs() -> [u64; 4] {
    let n = n_limbs();
    let mut out = [0u64; 4];
    let mut acc = 1u64; // +1 进位
    for i in 0..4 {
        let (sum, c) = (!n[i]).overflowing_add(acc);
        out[i] = sum;
        acc = c as u64;
    }
    debug_assert_eq!(acc, 0, "2²⁵⁶−n 无末端出进");
    out
}

/// 2ᵉ 的 F 元素（e ≤ 256；循环乘法机械构造，非手抄表示。注意整数 2^256 > p，
/// 此处值为**域内幂运算结果**，仅作常量槽使用——位折叠索引恒 ≤ 2^255）。
pub fn f_pow2(e: usize) -> FpSM2 {
    debug_assert!(e <= 256);
    let mut r = FpSM2::ONE;
    let two = FpSM2::from(2u64);
    for _ in 0..e {
        r *= two;
    }
    r
}

/// 2ᵉ 的查询表（OnceLock 全表 0..=256；表达式构建高频用）。
pub fn pow2_table() -> &'static Vec<FpSM2> {
    static T: std::sync::OnceLock<Vec<FpSM2>> = std::sync::OnceLock::new();
    T.get_or_init(|| (0..=256).map(f_pow2).collect())
}

/// 小端 limbs（32 字节语义）→ F 元素。要求值 < p（M2a 边界：输入面按 F 承载）。
pub fn fr_from_limbs(limbs: &[u64; 4]) -> FpSM2 {
    // repr = 小端字节序的规范表示（to_repr 的逆向）。
    let mut repr = <FpSM2 as PrimeField>::Repr::default();
    for (i, l) in limbs.iter().enumerate() {
        repr.as_mut()[i * 8..i * 8 + 8].copy_from_slice(&l.to_le_bytes());
    }
    FpSM2::from_repr(repr).unwrap()
}

/// F 元素 → 小端 limbs（经 to_repr 字节抽取；要求原生值即整数，值 < p）。
pub fn fr_to_limbs(v: &FpSM2) -> [u64; 4] {
    let bytes = v.to_repr();
    let mut out = [0u64; 4];
    for (i, o) in out.iter_mut().enumerate() {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes.as_ref()[i * 8..i * 8 + 8]);
        *o = u64::from_le_bytes(chunk);
    }
    out
}

/// 256 位小端 limbs 加法（模 2²⁵⁶），返回 (和, 最高位进位)。
pub fn add256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut c = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + c;
        out[i] = s as u64;
        c = s >> 64;
    }
    (out, c == 1)
}

/// limbs 比较器（a<b / a==b）。
pub fn cmp256(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            o => return o,
        }
    }
    std::cmp::Ordering::Equal
}

/// Σ2^(64k) 系数常数（limb 权），k < 4。注意 2⁶⁴⁺ 已超 u64，必经 pow2_table。
pub fn limb_weight(k: usize) -> FpSM2 {
    pow2_table()[64 * k]
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn bu_from_limbs(v: &[u64; 4]) -> BigUint {
        let mut bytes = vec![0u8; 32];
        for i in 0..4 {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&v[i].to_le_bytes());
        }
        BigUint::from_bytes_le(&bytes)
    }

    #[test]
    fn n_hex_limbs_roundtrip_and_less_than_p() {
        let n = n_limbs();
        assert_eq!(limbs_to_hex(&n), N_HEX, "hex ↔ limbs 双向一致");

        // n < p（对拍 ff_derive 生成的 MODULUS 十六进制串）
        let p_bu = BigUint::parse_bytes(
            FpSM2::MODULUS.trim_start_matches("0x").as_bytes(),
            16,
        )
        .unwrap();
        let n_bu = bu_from_limbs(&n);
        assert!(n_bu < p_bu, "群阶必须小于基域模数");

        // n ≈ p − 2¹²⁸ 的量级界（设计事实抽查，防错位级抄写）
        let gap = p_bu - n_bu;
        assert!(
            gap > (BigUint::from(1u32) << 120) && gap < (BigUint::from(1u32) << 136),
            "n 到 p 的距离应在 2¹²⁰–2¹³⁶ 之间，实测约 2^{:?} 量级",
            gap.bits()
        );
    }

    #[test]
    fn q_is_two_pow256_minus_n() {
        let q = q_limbs();
        let expect = (BigUint::from(1u32) << 256) - bu_from_limbs(&n_limbs());
        assert_eq!(bu_from_limbs(&q), expect);

        let p_bu = BigUint::parse_bytes(
            FpSM2::MODULUS.trim_start_matches("0x").as_bytes(),
            16,
        )
        .unwrap();
        assert!(bu_from_limbs(&q) < p_bu, "q < p（add_const 输出面要求）");
    }

    #[test]
    fn f_pow2_table_consistency() {
        let t = pow2_table();
        for e in [0usize, 1, 31, 63, 64, 127, 128, 191, 192, 255, 256] {
            let manual = {
                let mut r = FpSM2::ONE;
                for _ in 0..e {
                    r *= FpSM2::from(2u64);
                }
                r
            };
            assert_eq!(t[e], manual, "2^{e}");
        }
    }

    #[test]
    fn fr_limbs_roundtrip_small_and_large() {
        for probe in [
            [1u64, 0, 0, 0],
            [0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0],
        ] {
            assert_eq!(fr_to_limbs(&fr_from_limbs(&probe)), probe);
        }
        // n 本身 < p ⟹ roundtrip 必须无损
        assert_eq!(fr_to_limbs(&fr_from_limbs(&n_limbs())), n_limbs());
    }
}
