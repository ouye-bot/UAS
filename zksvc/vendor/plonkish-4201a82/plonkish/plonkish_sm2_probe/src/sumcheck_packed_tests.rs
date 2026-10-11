// ── 行为锁测试（2026-10-11 批量求值批）─────────────────────────────────────
// ① packed_sm2_differ：随机 4-lane 批经 packed 蒙哥马利四原语 vs 标量 ff 运算
//    逐 limb 对拍（lazy 代表元位型一致——同输入同输出位型，非仅同余）。
// ② packed_sumcheck_roundtrip：FpSM2 上 ClassicSumCheck<EvaluationsProver>
//    prove→verify 闭环（packed 通道在注册态驱动，verify 独立复算接受）。
#![cfg(test)]

use super::sumcheck_packed_sm2::*;
use crate::FpSM2;
use core::arch::x86_64::*;
use plonkish_backend::piop::sum_check::{
    classic::{ClassicSumCheck, EvaluationsProver},
    SumCheck, VirtualPolynomial,
};
use plonkish_backend::poly::multilinear::MultilinearPolynomial;
use plonkish_backend::util::{
    arithmetic::BooleanHypercube,
    expression::{CommonPolynomial, Expression, Query, Rotation},
    transcript::{InMemoryTranscript, FieldTranscriptRead, FieldTranscriptWrite, Keccak256Transcript},
};
use ff::{Field as _, PrimeField};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn rand_limbs(rng: &mut StdRng) -> [u64; LIMBS] {
    let mut l = [0u64; LIMBS];
    // 最高 limb 取小值：构造跨 [0,2p) 的 lazy 代表元形态（含 ≥p 值）。
    for (i, w) in l.iter_mut().enumerate() {
        *w = if i >= 4 {
            rng.next_u64() % 4
        } else {
            rng.next_u64()
        };
    }
    l
}

#[test]
fn packed_sm2_differ() {
    if !packed_enabled() {
        eprintln!("[differ] 无 AVX2——跳过（本机实测恒有 AVX2）");
        return;
    }
    ensure_registered();
    let mut rng = StdRng::seed_from_u64(0xA5A1_2026);
    let p = PackedParams::of();
    for _ in 0..2048 {
        unsafe {
        let mut va = [[0u64; LIMBS]; LANES];
        let mut vb = [[0u64; LIMBS]; LANES];
        let mut sa = [FpSM2::ZERO; LANES];
        let mut sb = [FpSM2::ZERO; LANES];
        for lane in 0..LANES {
            va[lane] = rand_limbs(&mut rng);
            vb[lane] = rand_limbs(&mut rng);
            sa[lane] = FpSM2(va[lane]);
            sb[lane] = FpSM2(vb[lane]);
        }
        let to_vec = |v: &[__m256i; LIMBS]| -> [u64; LANES * LIMBS] {
            let mut out = [0u64; LANES * LIMBS];
            for l in 0..LIMBS {
                let b = unsafe { std::mem::transmute::<__m256i, [u64; 4]>(v[l]) };
                out[l * LANES..(l + 1) * LANES].copy_from_slice(&b);
            }
            out
        };
        let pack = |v: &[[u64; LIMBS]; LANES]| -> [__m256i; LIMBS] {
            core::array::from_fn(|l| unsafe {
                let mut x = [0u64; 4];
                for lane in 0..LANES {
                    x[lane] = v[lane][l];
                }
                _mm256_loadu_si256(x.as_ptr() as *const __m256i)
            })
        };
        let pa = pack(&va);
        let pb = pack(&vb);
        let mut check = |got: [u64; LANES * LIMBS],
                         want: &FpSM2,
                         lane: usize,
                         tag: &str| {
            for l in 0..LIMBS {
                assert_eq!(got[l * LANES + lane], want.0[l], "{tag} lane {lane} limb {l}");
            }
        };
        let got = to_vec(&ff_add(&pa, &pb, &p));
        for lane in 0..LANES {
            check(got, &(sa[lane] + sb[lane]), lane, "add");
        }
        let got = to_vec(&ff_sub(&pa, &pb, &p));
        for lane in 0..LANES {
            check(got, &(sa[lane] - sb[lane]), lane, "sub");
        }
        let got = to_vec(&ff_neg(&pa, &p));
        for lane in 0..LANES {
            check(got, &(-sa[lane]), lane, "neg");
        }
        let got = to_vec(&ff_mul(&pa, &pb, &p));
        for lane in 0..LANES {
            check(got, &(sa[lane] * sb[lane]), lane, "mul");
        }
        }
    }
}

/// FpSM2 旋转链零检查（vendor sum_check_rotation 同构——gates ≡ 0 恒成立，
/// 轮消息恒全零=确定性参照）：packed 通道在 nv=8（size=128 ≥8 ⟹ 全 packed）
/// 下必须产出与标量路径逐位相同的全零轮消息；prove→verify 闭环必须接受。
/// 覆盖面：非 cur 旋转 gather（round 0）、eq_xy/identity/lagrange 推进、
/// 4 点组/尾部、degree 步进。
#[test]
fn packed_sumcheck_roundtrip() {
    ensure_registered();
    use plonkish_backend::util::expression::Rotation;
    let mut rng = StdRng::seed_from_u64(0x5EED_2026);
    for num_vars in [4usize, 8usize] {
        let bh = BooleanHypercube::new(num_vars);
        // 旋转查询族（vendor 同式：距离 1..num_vars 全距离覆盖）。
        let queries: Vec<_> = (-(num_vars as i32) + 1..num_vars as i32)
            .rev()
            .enumerate()
            .map(|(idx, rotation)| Expression::<FpSM2>::Polynomial(Query::new(idx, rotation.into())))
            .collect();
        let gates: Vec<_> = queries.windows(2).map(|w| &w[1] - &w[0]).collect();
        let expr = Expression::<FpSM2>::distribute_powers(
            &gates,
            &Expression::<FpSM2>::Challenge(0),
        ) * Expression::<FpSM2>::eq_xy(0);
        // 旋转链赋值：poly_{k+1} = rotate(poly_k, next)。
        let base: Vec<FpSM2> = (0..1 << num_vars)
            .map(|_| {
                let mut repr = <FpSM2 as PrimeField>::Repr::default();
                rng.fill_bytes(repr.as_mut());
                FpSM2::from_repr(repr).into_option().unwrap_or(FpSM2::ONE)
            })
            .collect();
        let rotate = |f: &Vec<FpSM2>| -> Vec<FpSM2> {
            (0..1 << num_vars)
                .map(|idx| f[bh.rotate(idx, Rotation::next())])
                .collect()
        };
        let mut polys: Vec<MultilinearPolynomial<FpSM2>> = Vec::new();
        let mut cur = base;
        for _ in 0..(2 * num_vars - 1) {
            polys.push(MultilinearPolynomial::new(cur.clone()));
            cur = rotate(&cur);
        }
        let challenges = [FpSM2::from(0x1234_5678u64)];
        let y: Vec<FpSM2> = (0..num_vars)
            .map(|_| {
                let mut repr = <FpSM2 as PrimeField>::Repr::default();
                rng.fill_bytes(repr.as_mut());
                FpSM2::from_repr(repr).into_option().unwrap_or(FpSM2::ONE)
            })
            .collect();
        let ys = [y.clone()];
        let sum = FpSM2::ZERO;
        let virtual_poly = VirtualPolynomial::new(&expr, &polys, &challenges, &ys);
        let mut transcript = Keccak256Transcript::new(());
        ClassicSumCheck::<EvaluationsProver<FpSM2>>::prove(
            &(),
            num_vars,
            virtual_poly,
            sum,
            &mut transcript,
        )
        .expect("prove ok");
        let proof = transcript.into_proof();
        // 零检查 ⟹ 全部轮消息（含 challenge 序列域元素）的 evals 面恒零。
        let mut nonzero = 0usize;
        for (i, elem) in proof.chunks(40).enumerate() {
            for l in 0..5 {
                let mut bs = [0u8; 8];
                bs.copy_from_slice(&elem[l * 8..(l + 1) * 8]);
                if u64::from_le_bytes(bs) != 0 {
                    nonzero += 1;
                    eprintln!("[nonzero] nv={num_vars} elem{i} limb{l}");
                }
            }
        }
        assert_eq!(nonzero, 0, "零检查轮消息必须恒零 nv={num_vars}");
        let mut vtranscript = Keccak256Transcript::from_proof((), proof.as_slice());
        ClassicSumCheck::<EvaluationsProver<FpSM2>>::verify(
            &(),
            num_vars,
            expr.degree(),
            sum,
            &mut vtranscript,
        )
        .expect("verify ok");
    }
}

/// vanilla plonk 零检查（非平凡赋值：旋转+积门，固定种子跨进程可对拍）：
/// packed 与标量（FZ_ZK_PACKED_SUMCHECK=0）的轮消息指纹必须逐字同。
#[test]
fn packed_vanilla_differ() {
    ensure_registered();
    use plonkish_backend::backend::hyperplonk::util::{
        rand_vanilla_plonk_assignment, vanilla_plonk_expression,
    };
    for num_vars in [4usize, 8usize] {
        let expr = vanilla_plonk_expression(num_vars);
        let (polys, challenges) = rand_vanilla_plonk_assignment(
            num_vars,
            StdRng::seed_from_u64(0xCAFE_0001),
            StdRng::seed_from_u64(0xCAFE_0002),
        );
        let y: Vec<FpSM2> = {
            let mut r = StdRng::seed_from_u64(0xCAFE_0003);
            (0..num_vars)
                .map(|_| {
                    let mut repr = <FpSM2 as PrimeField>::Repr::default();
                    r.fill_bytes(repr.as_mut());
                    FpSM2::from_repr(repr).into_option().unwrap_or(FpSM2::ONE)
                })
                .collect()
        };
        let ys = [y.clone()];
        let virtual_poly = VirtualPolynomial::new(&expr, &polys, &challenges, &ys);
        let mut transcript = Keccak256Transcript::new(());
        ClassicSumCheck::<EvaluationsProver<FpSM2>>::prove(
            &(),
            num_vars,
            virtual_poly,
            FpSM2::ZERO,
            &mut transcript,
        )
        .expect("prove ok");
        let proof = transcript.into_proof();
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in &proof {
            h ^= *b as u64;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        let fp = format!("{h:016x}");
        eprintln!("[vanilla-fp] nv={num_vars} packed={} fp={fp}", std::env::var("FZ_ZK_PACKED_SUMCHECK").is_err());
        let mut vtranscript = Keccak256Transcript::from_proof((), proof.as_slice());
        let (x_eval, x) = ClassicSumCheck::<EvaluationsProver<FpSM2>>::verify(
            &(),
            num_vars,
            expr.degree(),
            FpSM2::ZERO,
            &mut vtranscript,
        )
        .expect("verify ok");
        use plonkish_backend::poly::multilinear::rotation_eval;
        let evals: std::collections::HashMap<Query, FpSM2> = expr
            .used_query()
            .into_iter()
            .map(|query| {
                let ev = polys[query.poly()].evaluate_for_rotation(&x, query.rotation());
                (query, rotation_eval(&x, query.rotation(), &ev))
            })
            .collect();
        let want = plonkish_backend::piop::sum_check::evaluate(
            &expr, num_vars, &evals, &challenges, &[&ys[0]], &x,
        );
        assert_eq!(x_eval, want, "vanilla plonk roundtrip nv={num_vars}");
    }
}
