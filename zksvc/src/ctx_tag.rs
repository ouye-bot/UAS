//! ctx_tag 规范映射（SP-4 0D 定版——系统线规范，非论文栈口径）。
//!
//! 定版：`ctx_tag = FpSM2(SM3(challenge) mod p)`，32B 大端为规范外部编码
//! （与 `fe_be32` 同语义）。论文栈无权威 H(challenge) 口径（PROBE.md P1
//! 定谳：测试注入任意常量 `FpSM2::from(0xC7)`），本映射由竞赛侧定版，
//! Python↔Rust 双侧对拍锚定（`tests/ctx_tag_vectors.json`，编译期内嵌）。
//!
//! 全函数性：p = 2²⁵⁶−2²²⁴−2⁹⁶+2⁶⁴−1 > 2²⁵⁵ ⟹ 任意 256 位输入 v < 2p，
//! mod p 至多一次条件减法——**无失败分支，攻击面消除而非概率降低**
//! （对照：FpSM2::from_repr 拒绝 ≥p 输入，裸用即 2⁻³² 概率拒绝分支）。
//!
//! 纪律：p 一律机械派生自 `FpSM2::MODULUS`（ff 权威，禁手抄曲线常量）；
//! SM3 用 crates.io `sm3`（与论文栈 transcript 同源，PROBE.md P2 定谳）。

use ff::PrimeField;
use plonkish_sm2_probe::FpSM2;
use sm3::{Digest, Sm3};

/// 0D 定版映射：`ctx_tag = FpSM2(SM3(challenge) mod p)`——全函数，无失败分支。
pub fn ctx_tag_from_challenge(challenge: &[u8]) -> FpSM2 {
    let digest: [u8; 32] = Sm3::digest(challenge).into();
    reduce_be32(digest)
}

/// 严格域元素解析：64 位 hex（32B 大端，`fe_be32` 规范编码）→ `FpSM2`。
/// 非法 hex/长度错误或值 ≥ p 一律 `None`——**语句域元素必须规范，本函数无归约**；
/// 归约语义仅限 [`ctx_tag_from_challenge`]（0D 映射的对抗面路径）。
pub fn fp_from_be32_hex(s: &str) -> Option<FpSM2> {
    let be = be32_hex(s)?;
    // 与 reduce_be32 快径同款：Repr 小端逐字节倒序填充后 from_repr 严格直载。
    let mut repr = <FpSM2 as PrimeField>::Repr::default();
    for (i, b) in be.iter().rev().enumerate() {
        repr.as_mut()[i] = *b;
    }
    <FpSM2 as PrimeField>::from_repr(repr).into_option()
}

/// 任意长度 hex（偶数位）→ 字节串。验证方 challenge nonce 的外部编码。
pub fn hex_decode_bytes(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    (0..b.len() / 2)
        .map(|k| hex_pair(b[2 * k], b[2 * k + 1]))
        .collect()
}

/// 单字节 hex 解析：高低各一位十六进制数字（`to_digit` 只认 0-9a-fA-F，
/// 不经 `from_str_radix`——后者接受前导 `+`，非规范 hex 会假绿）。
fn hex_pair(hi: u8, lo: u8) -> Option<u8> {
    let h = (hi as char).to_digit(16)?;
    let l = (lo as char).to_digit(16)?;
    Some((h * 16 + l) as u8)
}

/// 64 位 hex → 32B 大端。
fn be32_hex(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for k in 0..32 {
        out[k] = hex_pair(b[2 * k], b[2 * k + 1])?;
    }
    Some(out)
}

/// p 的小端 limbs。ff_derive 的 `MODULUS` 常量为 "0x…" 十六进制串（vendor
/// lib.rs:63 同一用法），去前缀后经 vendor 自有 `hex_to_limbs_le` 机械解析
/// ——禁手抄曲线常量纪律的唯一权威入口。
fn p_limbs() -> [u64; 4] {
    let hex = FpSM2::MODULUS.trim_start_matches("0x");
    plonkish_sm2_probe::sm2_params::hex_to_limbs_le(hex)
}

/// 小端 limbs → BE 32B 整数（`fe_be32` 的 limbs 视角镜像；测试边界构造用）。
#[cfg(test)]
fn limbs_to_be32(l: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&l[3 - i].to_be_bytes());
    }
    out
}

/// limbs 比较：a < b（小端，高位在尾部；测试值域断言用）。
#[cfg(test)]
fn lt_limbs(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// BE 32B 整数 → 小端 limbs。
fn be32_to_limbs(be: [u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| {
        let s = 24 - 8 * i;
        u64::from_be_bytes(be[s..s + 8].try_into().expect("界内"))
    })
}

/// u256（小端 limbs）减法：a − b，返回 (差, 借位)。
fn sub_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow as u64);
        out[i] = d2;
        borrow = b1 || b2;
    }
    (out, borrow)
}

/// 规范归约：v mod p（全函数）。p > 2²⁵⁵ ⟹ v < 2p ⟹ 至多一次条件减法。
fn reduce_be32(v: [u8; 32]) -> FpSM2 {
    // 快径：值 < p 时 from_repr 直载（SM3 输出 ≥p 概率 ≈ 2⁻³²，日常全走此径）
    let mut repr = <FpSM2 as PrimeField>::Repr::default();
    for (i, b) in v.iter().rev().enumerate() {
        repr.as_mut()[i] = *b;
    }
    if let Some(x) = <FpSM2 as PrimeField>::from_repr(repr).into_option() {
        return x;
    }
    // 慢径（对抗面）：v ≥ p ⟹ 单次减法归约，结果 < p 由 v < 2p 保证
    let (out, borrow) = sub_limbs(be32_to_limbs(v), p_limbs());
    assert!(!borrow, "v ≥ p 且 v < 2p ⟹ 无借位");
    plonkish_sm2_probe::sm2_params::fr_from_limbs(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use plonkish_sm2_probe::sm2_params::{fr_from_limbs, fr_to_limbs};
    use plonkish_sm2_probe::sm2_z_anchor::fe_be32;

    /// Python 侧 scripts/gen_ctx_tag_vectors.py 生成的锚值（跨语言对拍全集
    /// 见 tests/ctx_tag_xlang.rs；此处锚两条防实现与夹具同步走偏）。
    const ABC_TAG_HEX: &str =
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    const EMPTY_TAG_HEX: &str =
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b";

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn tag_hex(c: &[u8]) -> String {
        hex_encode(&fe_be32(&ctx_tag_from_challenge(c)))
    }

    #[test]
    fn gbt_and_empty_anchors_match_python_generator() {
        assert_eq!(tag_hex(b"abc"), ABC_TAG_HEX);
        assert_eq!(tag_hex(b""), EMPTY_TAG_HEX);
    }

    #[test]
    fn deterministic_and_discriminating() {
        let a = ctx_tag_from_challenge(b"replay-guard-challenge");
        assert_eq!(a, ctx_tag_from_challenge(b"replay-guard-challenge"));
        assert_ne!(a, ctx_tag_from_challenge(b"replay-guard-challenge-2"));
    }

    /// 归约边界（零手抄常量——p 全部由 `FpSM2::MODULUS` 机械派生）：
    /// v = p → 0；v = p−1 → 原值；v = 2²⁵⁶−1 → !p（= (2²⁵⁶−1) mod p，
    /// 按位非即 d−1、d=2²⁵⁶−p<p）。
    #[test]
    fn reduce_boundary_cases_derived_from_modulus() {
        let p = p_limbs();

        // p → 0
        assert_eq!(reduce_be32(limbs_to_be32(&p)), FpSM2::ZERO);

        // p−1 → p−1（最大合法元素必须原样通过）
        let (pm1, borrow) = sub_limbs(p, [1, 0, 0, 0]);
        assert!(!borrow);
        assert_eq!(reduce_be32(limbs_to_be32(&pm1)), fr_from_limbs(&pm1));

        // 全 FF（2²⁵⁶−1）→ (2²⁵⁶−1) mod p = !p
        let not_p = std::array::from_fn(|i| !p[i]);
        assert_eq!(reduce_be32([0xFF; 32]), fr_from_limbs(&not_p));
    }

    /// 规范编码不动点：场元素经 `fe_be32` 再归约必须回到自身（编码即权威外部形态）。
    #[test]
    fn canonical_be32_roundtrip_stability() {
        for c in ["", "a", "abc", "ctx-roundtrip", "策略A:查询授权"] {
            let t = ctx_tag_from_challenge(c.as_bytes());
            assert_eq!(reduce_be32(fe_be32(&t)), t, "{c}");
        }
    }

    /// 值域恒真式防御（计划 0D 注记：检查实现未跑偏）——结果必须 < p。
    #[test]
    fn output_strictly_below_modulus() {
        let p = p_limbs();
        for i in 0..64 {
            let c = format!("ctx-tag-vector-{i:04}");
            let l = fr_to_limbs(&ctx_tag_from_challenge(c.as_bytes()));
            assert!(lt_limbs(&l, &p), "{c}");
        }
    }

    /// 1MB 多块流式边界：完成性+确定性（对拍值在 xlang 夹具 patterns）。
    #[test]
    fn one_megabyte_boundary_deterministic() {
        let big = vec![b'a'; 1024 * 1024];
        let t = ctx_tag_from_challenge(&big);
        assert_eq!(t, ctx_tag_from_challenge(&big));
        assert_ne!(t, ctx_tag_from_challenge(b"a"));
    }
}
