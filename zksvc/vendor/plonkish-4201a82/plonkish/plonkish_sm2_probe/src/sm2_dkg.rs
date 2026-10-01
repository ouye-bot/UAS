//! T2.2：无经销者分布式密钥生成（Joint-Feldman 两轮式，委员会侧协议仿真；
//!
//! 论文对应物：def:teg 的 DKG 机制、def:pi 的 Setup、§4.5「Setup 的信任结构」
//! 披露（D16-3 拍板：apk=Y_i 结构不变、零电路改动）。
//!
//! ## 协议（Joint-Feldman 变体：Feldman 承诺广播+份额私送+核验投诉；GJKR99
//! 完整协议的 QUAL/抗议阶段=标量他用场景的部署强化义务，见论文 §2 偏置面披露）
//! 每位委员 O_j（1 基编号）采样随机多项式 f_j ∈ F_n[z]（次数 t−1），广播
//! Feldman 承诺 A_{j,k} := f_{j,k}·G，并经认证私密信道把份额 f_j(i) 送达 O_i。
//! O_i 逐份额对承诺核验（不一致即投诉——本模块以 `DkgError::Complaint` 上抛
//! 模拟投诉路径）。聚合输出：
//! - apk = Σ_j A_{j,0} = x·G，其中 x = Σ_j f_j(0)——**任何代码路径都不合成 x**
//!   （类型层面：`DkgOutput` 不含 x 字段；协议层面：仅点上加法聚合）；
//! - sh_i = Σ_j f_j(i)（O_i 自持份额），Y_i = sh_i·G 可由承诺公开复核
//!   （= Σ_{j,k} i^k·A_{j,k}，双路径交叉锚定）。
//!
//! ## 纪律（L2）
//! - n 取自 [`crate::sm2_params`]（永不手抄，三重锚定既有测试在位）；
//! - 点运算/标量乘复用 [`crate::sm2_ec_plonkish`]（零第二份 EC 实现）；
//! - mod-n 乘/逆/减复用 [`crate::sm2_sign_host`]；本模块新增算术仅
//!   add_mod_n / i^k 幂 / Lagrange 系数，由「重构-聚合双路径一致」测试覆盖；
//! - 随机性：生产入口 OsRng；测试入口 StdRng 固定种子（可复现）。

use crate::sm2_ec_plonkish::{affine_add, affine_mul_bits, Affine};
use crate::sm2_params::{add256, cmp256, n_limbs};
use crate::sm2_full_statement_assemble::sm2_sign_host::{bits_le, inv_mod_n, mul_mod_n, sub_mod_n};
use rand::RngCore;

/// DKG 参数：N = n_committee，重构门限 t = threshold。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DkgParams {
    pub n_committee: usize,
    pub threshold: usize,
}

/// 单个委员的广播件：Feldman 承诺（公开）+ 经私密信道送达各收方的份额。
/// delivered[i-1] = f_j(i)（i 1 基）；真实协议中 delivered 走认证私密信道，
/// 仿真中作为结构体字段在 combine 阶段被收方逐一核验。
#[derive(Debug, Clone)]
pub struct MemberBroadcast {
    /// A_{j,k} = f_{j,k}·G，k ∈ [0, t)。
    pub commitments: Vec<Affine>,
    /// delivered[i-1] = f_j(i)，i ∈ [1, N]。
    pub delivered: Vec<[u64; 4]>,
}

/// 协议公开输出（**不含 x**——隐私性质的结构面承诺）。
#[derive(Debug, Clone)]
pub struct DkgOutput {
    /// 聚合公钥 apk = Σ_j A_{j,0} = x·G。
    pub apk: Affine,
    /// 各委员公开验证钥 ys[i-1] = sh_i·G（i 1 基）。
    pub ys: Vec<Affine>,
    /// 全体 Feldman 承诺 commitments[j-1] = A_{j,*}（任何人可复核）。
    pub commitments: Vec<Vec<Affine>>,
}

/// 各委员自持份额（委员知道自己的份额是协议设计使然；**无人知 x**）。
#[derive(Debug, Clone)]
pub struct CommitteeShares {
    /// shares[i-1] = sh_i（i 1 基）。
    pub shares: Vec<[u64; 4]>,
}

/// 协议错误：投诉路径（份额与 Feldman 承诺不一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgError {
    Complaint { broadcaster: usize, recipient: usize },
}

/// 生产入口（OsRng）。
pub fn run_dkg(params: &DkgParams) -> Result<(DkgOutput, CommitteeShares), DkgError> {
    let mut rng = rand::rngs::OsRng;
    run_dkg_with_rng(params, &mut rng)
}

/// 确定性/可注随机入口：N 次 [`member_broadcast`] + [`combine_output`]。
pub fn run_dkg_with_rng<R: RngCore>(
    params: &DkgParams,
    rng: &mut R,
) -> Result<(DkgOutput, CommitteeShares), DkgError> {
    assert!(params.threshold >= 1 && params.threshold <= params.n_committee, "dkg: require 1 <= t <= N");
    assert!(
        params.n_committee >= 2 * params.threshold - 1,
        "dkg requires N >= 2t-1 (got N={}, t={})",
        params.n_committee,
        params.threshold
    );
    let broadcasts: Vec<MemberBroadcast> =
        (0..params.n_committee).map(|_| member_broadcast(params, rng)).collect();
    combine_output(params, &broadcasts)
}

/// Phase 1：委员 j 采样 f_j（次数 t−1，系数均匀 [0,n)），产出广播件
/// （承诺 + 送达 N 个收方的份额）。
pub fn member_broadcast<R: RngCore>(
    params: &DkgParams,
    rng: &mut R,
) -> MemberBroadcast {
    let coeffs: Vec<[u64; 4]> =
        (0..params.threshold).map(|_| sample_scalar(rng)).collect();
    let g = crate::sm2_ec_plonkish::g_coords();
    let commitments: Vec<Affine> = coeffs
        .iter()
        .map(|a| affine_mul_bits(&bits_le(a), Some(g)))
        .collect();
    // delivered[i-1] = f(i)（Horner，i ∈ [1, N]，永不取 0）。
    let mut delivered = Vec::with_capacity(params.n_committee);
    for i in 1..=params.n_committee {
        let i_limbs = [i as u64, 0, 0, 0];
        let mut acc = coeffs[params.threshold - 1];
        for k in (0..params.threshold - 1).rev() {
            acc = add_mod_n(&mul_mod_n(&acc, &i_limbs), &coeffs[k]);
        }
        delivered.push(acc);
    }
    MemberBroadcast { commitments, delivered }
}

/// Phase 2 + 输出装配：逐收方核验每一份送达份额（投诉路径），
/// 聚合 sh_i、apk、Y_i。
pub fn combine_output(
    params: &DkgParams,
    broadcasts: &[MemberBroadcast],
) -> Result<(DkgOutput, CommitteeShares), DkgError> {
    let n = params.n_committee;
    assert_eq!(broadcasts.len(), n, "广播件数量必须等于 N");
    let mut shares = Vec::with_capacity(n);
    let mut ys = Vec::with_capacity(n);
    for i in 1..=n {
        // 先核验送达份额（Feldman），不一致即投诉。
        for (j, b) in broadcasts.iter().enumerate() {
            if !check_share_against_commitments(&b.delivered[i - 1], i, &b.commitments) {
                return Err(DkgError::Complaint {
                    broadcaster: j + 1,
                    recipient: i,
                });
            }
        }
        // sh_i = Σ_j f_j(i)。
        let mut sh_i = [0u64; 4];
        for b in broadcasts {
            sh_i = add_mod_n(&sh_i, &b.delivered[i - 1]);
        }
        ys.push(share_decrypt(&sh_i, &Some(crate::sm2_ec_plonkish::g_coords())));
        shares.push(sh_i);
    }
    let commitments: Vec<Vec<Affine>> =
        broadcasts.iter().map(|b| b.commitments.clone()).collect();
    let apk = apk_from_commitments(&commitments);
    Ok((DkgOutput { apk, ys, commitments }, CommitteeShares { shares }))
}

/// 份额核验：s·G == Σ_k (i^k mod n)·A_{j,k}（Feldman，i 为接收者 1 基编号）。
pub fn check_share_against_commitments(
    share: &[u64; 4],
    recipient: usize,
    member_commitments: &[Affine],
) -> bool {
    let lhs = affine_mul_bits(&bits_le(share), Some(crate::sm2_ec_plonkish::g_coords()));
    lhs == poly_eval_point(recipient, member_commitments)
}

/// 承诺公开复核：Y_i = Σ_{j,k} (i^k mod n)·A_{j,k}（只用公开承诺）。
pub fn y_from_commitments(i: usize, commitments: &[Vec<Affine>]) -> Affine {
    let mut acc: Affine = None;
    for member_commitments in commitments {
        acc = affine_add(acc, poly_eval_point(i, member_commitments));
    }
    acc
}

/// 承诺公开复核：apk = Σ_j A_{j,0}。
pub fn apk_from_commitments(commitments: &[Vec<Affine>]) -> Affine {
    let mut acc: Affine = None;
    for member_commitments in commitments {
        acc = affine_add(acc, member_commitments[0]);
    }
    acc
}

/// 0 处 Lagrange 系数（F_n）：λ_i = Π_{j∈S\{i\}} (−j)·(i−j)^{-1}。
/// subset 为 1 基委员编号（Shamir 求值点 = 委员编号，永不取 0）。
pub fn lagrange_zero(subset: &[usize]) -> Vec<[u64; 4]> {
    assert!(!subset.is_empty(), "Lagrange 子集非空");
    let zero = [0u64; 4];
    let one = [1u64, 0, 0, 0];
    subset
        .iter()
        .map(|&i| {
            let mut lam = one;
            for &j in subset {
                if j == i {
                    continue;
                }
                let num = sub_mod_n(&zero, &[j as u64, 0, 0, 0]); // −j mod n
                let den = sub_mod_n(&[i as u64, 0, 0, 0], &[j as u64, 0, 0, 0]);
                lam = mul_mod_n(&lam, &mul_mod_n(&num, &inv_mod_n(&den)));
            }
            lam
        })
        .collect()
}

/// 份额解密 d_i = sh_i·C₁。
pub fn share_decrypt(sh_i: &[u64; 4], c1: &Affine) -> Affine {
    affine_mul_bits(&bits_le(sh_i), *c1)
}

/// 组合解密 M = C₂ − Σ_{i∈S} λ_i·d_i（|S| = t）。
pub fn combine_decrypt(c1: &Affine, c2: &Affine, subset: &[(usize, [u64; 4])]) -> Affine {
    let indices: Vec<usize> = subset.iter().map(|(i, _)| *i).collect();
    let lam = lagrange_zero(&indices);
    let mut acc: Affine = None;
    for (idx, (_, sh_i)) in subset.iter().enumerate() {
        let d_i = share_decrypt(sh_i, c1);
        acc = affine_add(acc, affine_mul_bits(&bits_le(&lam[idx]), d_i));
    }
    affine_add(*c2, affine_neg(&acc))
}

// ══════════════════ 模块内部算术 ══════════════════

/// 承诺行在点 i 处的求值：Σ_k (i^k mod n)·A_k（Horner 于标量侧先聚合幂）。
fn poly_eval_point(i: usize, member_commitments: &[Affine]) -> Affine {
    let mut acc: Affine = None;
    for (k, &a_k) in member_commitments.iter().enumerate() {
        let coeff = pow_mod_n(&[i as u64, 0, 0, 0], k);
        acc = affine_add(acc, affine_mul_bits(&bits_le(&coeff), a_k));
    }
    acc
}

/// (a + b) mod n（前置 a,b < n）。
fn add_mod_n(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let n = n_limbs();
    let (sum, carry) = add256(a, b);
    if carry {
        // 真 = sum + 2^256 = sum + n + q（q=2^256−n）⟹ 真 − n = sum + q < n
        //（2n−2 ≤ 真 ⟹ 真 − n ≤ n−2），无溢出、无需再减。
        add256(&sum, &crate::sm2_params::q_limbs()).0
    } else if cmp256(&sum, &n) == std::cmp::Ordering::Less {
        sum
    } else {
        sub_mod_n(&sum, &n)
    }
}

/// base^exp mod n（square-and-multiply；exp 为小指数）。
fn pow_mod_n(base: &[u64; 4], exp: usize) -> [u64; 4] {
    let mut result = [1u64, 0, 0, 0];
    let mut b = *base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = mul_mod_n(&result, &b);
        }
        b = mul_mod_n(&b, &b);
        e >>= 1;
    }
    result
}

/// 均匀采样 [0, n)（32 字节拒绝采样；n≈2^256−2^128 ⟹ 拒绝率 ≈2^−128）。
fn sample_scalar<R: RngCore>(rng: &mut R) -> [u64; 4] {
    let n = n_limbs();
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let v = [
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        ];
        if cmp256(&v, &n) == std::cmp::Ordering::Less && v != [0u64; 4] {
            return v;
        }
    }
}

/// 仿射点取负：(x, y) ↦ (x, −y mod p)；O ↦ O。
fn affine_neg(p: &Affine) -> Affine {
    p.as_ref().map(|(x, y)| (*x, -*y))
}

// ══════════════════ 测试（TDD：红先于绿，测试本体红绿两阶段零改动） ══════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_ec_plonkish::{affine_add, affine_mul_bits, g_coords};
    use crate::sm2_full_statement_assemble::sm2_sign_host::{bits_le, sub_mod_n};
    use crate::sm2_params::n_limbs;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const N: usize = 7;
    const T: usize = 3;
    const SEED: [u8; 32] = [0xD1; 32]; // DKG 确定性测试种子

    fn params() -> DkgParams {
        DkgParams {
            n_committee: N,
            threshold: T,
        }
    }

    fn run_seeded() -> (DkgOutput, CommitteeShares) {
        let mut rng = StdRng::from_seed(SEED);
        run_dkg_with_rng(&params(), &mut rng).expect("无投诉路径下 DKG 成功")
    }

    fn g() -> Affine {
        Some(g_coords())
    }

    fn mul_g(s: &[u64; 4]) -> Affine {
        affine_mul_bits(&bits_le(s), g())
    }

    /// 随机明文点 M = m·G 与随机 ρ（确定性种子派生）。
    fn message_and_nonce(seed: u8) -> (Affine, [u64; 4]) {
        let mut rng = StdRng::from_seed([seed; 32]);
        let m = sample_scalar(&mut rng);
        let rho = sample_scalar(&mut rng);
        (mul_g(&m), rho)
    }

    /// T-1 主正确性：t 份额组合解密还原明文点（含 apk 双路径一致 + 种子确定性）。
    #[test]
    fn dkg_threshold_decryption_roundtrip() {
        let (out, shares) = run_seeded();
        let (out2, _) = run_seeded();
        assert_eq!(out.apk, out2.apk, "DKG 输出必须种子确定");
        assert_eq!(out.apk, apk_from_commitments(&out.commitments), "apk=Σ A_{{j,0}}");
        let (m_pt, rho) = message_and_nonce(0xA1);
        let c1 = mul_g(&rho);
        let c2 = affine_add(m_pt, affine_mul_bits(&bits_le(&rho), out.apk));
        let subset: Vec<(usize, [u64; 4])> =
            [1usize, 4, 6].iter().map(|&i| (i, shares.shares[i - 1])).collect();
        let dec = combine_decrypt(&c1, &c2, &subset);
        assert_eq!(dec, m_pt, "t=3 份额组合解密必须还原明文点");
    }

    /// T-2 全部合格子集的 Shamir 重构（点层面）：Σ λ_i·(sh_i·G) = apk，
    /// x 全程不出场。C(7,3)=35 子集全扫。
    #[test]
    fn dkg_every_qualifying_subset_reconstructs_apk() {
        let (out, shares) = run_seeded();
        let mut count = 0usize;
        for s1 in 1..=N {
            for s2 in (s1 + 1)..=N {
                for s3 in (s2 + 1)..=N {
                    let subset = [s1, s2, s3];
                    let lam = lagrange_zero(&subset);
                    let mut acc: Affine = None;
                    for (idx, &i) in subset.iter().enumerate() {
                        let pt = mul_g(&shares.shares[i - 1]);
                        acc = affine_add(acc, affine_mul_bits(&bits_le(&lam[idx]), pt));
                    }
                    assert_eq!(acc, out.apk, "子集 {:?} 重构必须命中 apk", subset);
                    count += 1;
                }
            }
        }
        assert_eq!(count, 35, "C(7,3)=35 个合格子集全扫");
    }

    /// T-3 阈值语义：t−1 份额组合解密不得还原明文（确定性偏差）。
    #[test]
    fn dkg_t_minus_1_subset_fails_decrypt() {
        let (out, shares) = run_seeded();
        let (m_pt, rho) = message_and_nonce(0xB2);
        let c1 = mul_g(&rho);
        let c2 = affine_add(m_pt, affine_mul_bits(&bits_le(&rho), out.apk));
        let subset: Vec<(usize, [u64; 4])> =
            [1usize, 4].iter().map(|&i| (i, shares.shares[i - 1])).collect();
        let dec = combine_decrypt(&c1, &c2, &subset);
        assert_ne!(dec, m_pt, "t−1 份额不得还原明文点");
    }

    /// T-4 公开可验证：Y_i 仅由承诺复核（Σ_{{j,k}} i^k·A_{{j,k}}）且与
    /// 私有份额路径 sh_i·G 逐字节一致（双路径交叉锚定）。
    #[test]
    fn dkg_ys_publicly_verifiable_from_commitments() {
        let (out, shares) = run_seeded();
        for i in 1..=N {
            assert_eq!(out.ys[i - 1], mul_g(&shares.shares[i - 1]), "Y_{} 份额路径", i);
            assert_eq!(
                out.ys[i - 1],
                y_from_commitments(i, &out.commitments),
                "Y_{} 承诺公开复核路径必须一致",
                i
            );
        }
    }

    /// T-5 投诉路径（协议层）：篡改委员 5 送达委员 2 的份额（位翻转），
    /// combine_output 必须返回 Complaint{broadcaster:5, recipient:2}。
    #[test]
    fn dkg_corrupt_share_triggers_complaint() {
        let mut rng = StdRng::from_seed(SEED);
        let mut broadcasts: Vec<MemberBroadcast> =
            (0..N).map(|_| member_broadcast(&params(), &mut rng)).collect();
        broadcasts[4].delivered[1][0] ^= 0x80; // 位翻转，必异于原值
        let err = combine_output(&params(), &broadcasts)
            .expect_err("被篡改份额必须触发投诉");
        assert_eq!(
            err,
            DkgError::Complaint { broadcaster: 5, recipient: 2 },
            "投诉必须定位到（广播者 5，收方 2）"
        );
    }

    /// T-6 前提卫兵：N < 2t−1 必须拒绝（prem:panel 的 N≥2t−1）。
    #[test]
    #[should_panic(expected = "N >= 2t-1")]
    fn dkg_rejects_n_below_2t_minus_1() {
        let _ = run_dkg(&DkgParams {
            n_committee: 4, // 2t−1=5 > 4 ⟹ 必须拒绝
            threshold: 3,
        });
    }

    /// T-7 add_mod_n 三路径回归钉（无进位 <n / 无进位 ≥n / 进位）：n−1+1=0、
    /// n−1+2=1、(n−1)+(n−1)=n−2（进位路径：sum+q 恰=n−2）。
    #[test]
    fn dkg_add_mod_n_carry_paths() {
        let n = n_limbs();
        let nm1 = sub_mod_n(&n, &[1, 0, 0, 0]);
        assert_eq!(add_mod_n(&nm1, &[1, 0, 0, 0]), [0, 0, 0, 0], "n−1+1=n→0");
        assert_eq!(add_mod_n(&nm1, &[2, 0, 0, 0]), [1, 0, 0, 0], "n−1+2→1");
        assert_eq!(
            add_mod_n(&nm1, &nm1),
            sub_mod_n(&n, &[2, 0, 0, 0]),
            "进位路径 (n−1)+(n−1)=n−2"
        );
    }
}
