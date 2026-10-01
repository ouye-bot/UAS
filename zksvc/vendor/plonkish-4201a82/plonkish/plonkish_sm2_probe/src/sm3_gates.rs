//! SM3 模加门 spike：mod-2^32 加法 + 字节范围查找（lookup + BaseFold + FpSM2 仓库内首次）。
//!
//! 电路语义（k=10 → 2^10 = 1024 行；真实模加行位于第 1<<i 行，i=0..NUM_ADD_ROWS−1
//! [对齐 HyperPlonk 实例行布局 row_mapping 的前 NUM_ADD_ROWS 个 LFSR 值 = 2 的幂]，
//! 其余行为零填充）：
//!
//! 列布局（全局多项式索引）：
//!   [0]  instance(pi)          [1] s_op  [2] s_bind  [3] table(0..255 循环)
//!   [4]=a [5]=b [6]=c [7]=k
//!   [8..12]=a 字节 [12..16]=b 字节 [16..20]=c 字节
//!
//! 门（全部 ≤ 度数 3；lookup 约束度数 = 4，故 max_degree=4）：
//!   1. s_op·(a + b − c − 2^32·k) = 0           模加
//!   2. s_op·k·(1 − k) = 0                      carry 布尔性
//!   3. s_op·(a − Σ_p 2^{8p}·a_p) = 0            a/b/c 字节分解（三个门）
//!   4. s_bind·(c − pi) = 0                      公开输入绑定（行 1 = 实例 c0 所在行）
//!   lookup（12 个独立 1-对 lookup，每对 (s_op·byte_p, table[0..255])）
//!
//! witness 由原生 u32 代码计算（`block_words` + `mod_add`），与 R1CS 电路
//! `m0_sm3_circuit/src/sm3_native.rs` 同源（消息字 W[j] 取 u32::from_be_bytes）。

use plonkish_backend::{
    backend::{PlonkishCircuit, PlonkishCircuitInfo},
    util::{
        arithmetic::PrimeField,
        expression::{Expression, Query, Rotation},
    },
    Error,
};

/// 电路规模 k（2^k 行）。真实行只占前 NUM_ADD_ROWS 行，其余零填充。
pub const K: usize = 10;
/// 2^K。
pub const ROWS: usize = 1 << K;
/// 真实 SM3 模加行数（块 W[0..7] → 4 行 W[i] + W[i+4]）。
pub const NUM_ADD_ROWS: usize = 4;

// 多项式索引（全局，instance 从 0 起、preprocess 从 1 起、advice 从 4 起）。
pub const COL_INST: usize = 0;
pub const COL_SOP: usize = 1;
pub const COL_SBIND: usize = 2;
pub const COL_TABLE: usize = 3;
pub const COL_A: usize = 4;
pub const COL_B: usize = 5;
pub const COL_C: usize = 6;
pub const COL_K: usize = 7;
pub const COL_A0: usize = 8;
pub const COL_B0: usize = 12;
pub const COL_C0: usize = 16;
/// 首个 advice 多项式的全局索引（= num_instances.len() + preprocess_polys.len()）。
pub const COL_ADVICE_OFFSET: usize = 4;
/// advice（witness）多项式个数。
pub const NUM_ADVICE: usize = 16;
/// preprocess 多项式个数。
pub const NUM_PREPROCESS: usize = 3;

/// 单个 32 位模加真值（原生 u32 计算，非电路值）。
#[derive(Clone, Copy, Debug)]
pub struct WordAdd {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub k: u32,
}

/// 原生 32 位模加：(a + b) mod 2^32，carry k = floor((a+b)/2^32)。
pub fn mod_add(a: u32, b: u32) -> WordAdd {
    let s = (a as u64) + (b as u64);
    WordAdd {
        a,
        b,
        c: s as u32,
        k: (s >> 32) as u32,
    }
}

/// SM3 块 → 消息扩展前 16 个直接字 W[0..16]（j<16 时 W[j] = 消息字，无需 P1 置换）。
pub fn block_words(block: &[u8; 64]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    w
}

fn poly<F: PrimeField>(idx: usize) -> Expression<F> {
    Expression::Polynomial(Query::new(idx, Rotation::cur()))
}

fn cexpr<F: PrimeField>(v: u64) -> Expression<F> {
    Expression::Constant(F::from(v))
}

/// 字节分解门：s_op·(word − Σ_p 2^{8p}·byte_p)。
fn decompose_gate<F: PrimeField>(
    s_op: &Expression<F>,
    word: Expression<F>,
    base: usize,
) -> Expression<F> {
    let recomposed = poly::<F>(base)
        + cexpr::<F>(1u64 << 8) * poly::<F>(base + 1)
        + cexpr::<F>(1u64 << 16) * poly::<F>(base + 2)
        + cexpr::<F>(1u64 << 24) * poly::<F>(base + 3);
    s_op.clone() * (word - recomposed)
}

/// 真实 SM3 模加电路：witness 由原生 u32 计算，列布局见模块头注释。
#[derive(Clone, Debug)]
pub struct ModAddCircuit<F> {
    pub info: PlonkishCircuitInfo<F>,
    pub advice: Vec<Vec<F>>,
    pub instances: Vec<Vec<F>>,
}

impl<F: PrimeField> ModAddCircuit<F> {
    pub fn build(adds: &[WordAdd]) -> Self {
        assert!(!adds.is_empty(), "需至少一个真实模加行");
        assert!(
            adds.len() <= NUM_ADD_ROWS,
            "真实行数 {} > {NUM_ADD_ROWS}（列布局上限）",
            adds.len()
        );

        // witness 列：真实行填 u32 值及其字节分解，其余行为 0（s_op=0 使门平凡满足）。
        // 行位置 = row_mapping[i]（HyperPlonk 实例布局）：LFSR 前 NUM_ADD_ROWS 步为 2 的幂，
        // 实例值 c0 落在 row_mapping[0] = LFSR 首值 1 → 第 i 个模加放第 1<<i 行。
        let mut advice = vec![vec![F::ZERO; ROWS]; NUM_ADVICE];
        for (i, wa) in adds.iter().enumerate() {
            let row = 1usize << i;
            advice[COL_A - COL_ADVICE_OFFSET][row] = F::from(wa.a as u64);
            advice[COL_B - COL_ADVICE_OFFSET][row] = F::from(wa.b as u64);
            advice[COL_C - COL_ADVICE_OFFSET][row] = F::from(wa.c as u64);
            advice[COL_K - COL_ADVICE_OFFSET][row] = F::from(wa.k as u64);
            let words = [wa.a, wa.b, wa.c];
            for (wi, w) in words.iter().enumerate() {
                let base = match wi {
                    0 => COL_A0,
                    1 => COL_B0,
                    _ => COL_C0,
                };
                for p in 0..4 {
                    let byte = ((w >> (8 * p)) & 0xff) as u64;
                    advice[base + p - COL_ADVICE_OFFSET][row] = F::from(byte);
                }
            }
        }

        // 预计算多项式。
        let mut s_op = vec![F::ZERO; ROWS];
        for i in 0..NUM_ADD_ROWS {
            s_op[1usize << i] = F::ONE;
        }
        let mut s_bind = vec![F::ZERO; ROWS];
        s_bind[1] = F::ONE; // 实例 c0 落在行 1（row_mapping[0] = LFSR 首值 1）。
        let table: Vec<F> = (0..ROWS).map(|r| F::from((r % 256) as u64)).collect();
        let preprocess = vec![s_op, s_bind, table];

        // 实例：公开输入 c0（经 instance_polys 落在第 1 行）。
        let instances = vec![vec![F::from(adds[0].c as u64)]];

        // 门表达式。
        let s_op_e = poly::<F>(COL_SOP);
        let s_bind_e = poly::<F>(COL_SBIND);
        let a_e = poly::<F>(COL_A);
        let b_e = poly::<F>(COL_B);
        let c_e = poly::<F>(COL_C);
        let k_e = poly::<F>(COL_K);
        let pi_e = poly::<F>(COL_INST);
        let two32 = cexpr::<F>(1u64 << 32);

        // 1. 模加：s_op·(a + b − c − 2^32·k)
        let g_add = s_op_e.clone() * (a_e.clone() + b_e.clone() - c_e.clone() - two32 * k_e.clone());
        // 2. carry 布尔：s_op·k·(1−k)
        let one_e = Expression::<F>::one();
        let g_bool = s_op_e.clone() * k_e.clone() * (one_e - k_e.clone());
        // 3. 字节分解 ×3（c_e 还需给 g_bind 用，故 clone）
        let g_dec_a = decompose_gate(&s_op_e, a_e, COL_A0);
        let g_dec_b = decompose_gate(&s_op_e, b_e, COL_B0);
        let g_dec_c = decompose_gate(&s_op_e, c_e.clone(), COL_C0);
        // 4. 公开输入绑定：s_bind·(c − pi)
        let g_bind = s_bind_e.clone() * (c_e.clone() - pi_e);

        let constraints = vec![g_add, g_bool, g_dec_a, g_dec_b, g_dec_c, g_bind];

        // lookup：12 个独立 1-对 vector lookup（LogUp/压缩语义：压缩 input = 单值 s_op·byte、
        // 压缩 table = 单值 table[r]，包含关系 ⟺ byte ∈ {0..255}）。
        // ⚠️ 不能合并为单个 12-对 lookup：压缩 input = Σ_j β^j·byte_j 仅当 12 字节全相等时
        // 才落在压缩表 {v·Σβ^j : v∈0..255} 中（否则 prove 报 Invalid lookup input）。
        let table_e = poly::<F>(COL_TABLE);
        let lookups: Vec<Vec<(Expression<F>, Expression<F>)>> = [COL_A0, COL_B0, COL_C0]
            .iter()
            .flat_map(|&base| (0..4).map(move |p| base + p))
            .map(|col| vec![(s_op_e.clone() * poly::<F>(col), table_e.clone())])
            .collect();

        let info = PlonkishCircuitInfo {
            k: K,
            num_instances: vec![1],
            preprocess_polys: preprocess,
            num_witness_polys: vec![NUM_ADVICE],
            num_challenges: vec![0],
            constraints,
            lookups,
            permutations: Vec::new(),
            max_degree: Some(4),
        };
        assert!(info.is_well_formed(), "电路 info 未通过 well-formed 检查");
        Self {
            info,
            advice,
            instances,
        }
    }
}

impl<F: PrimeField> PlonkishCircuit<F> for ModAddCircuit<F> {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<F>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<F>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<F>] {
        &self.instances
    }
    fn synthesize(&self, round: usize, challenges: &[F]) -> Result<Vec<Vec<F>>, Error> {
        assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
        Ok(self.advice.clone())
    }
}

/// 原生门检查（TDD mock-prover）：逐行验证全部 6 个门在 F 上成立。
/// 返回 false 表示 witness 与电路不一致（lookup 由 prove/verify 端到端验证）。
pub fn check_gates<F: PrimeField>(circ: &ModAddCircuit<F>) -> bool {
    let val = |col: usize, row: usize| circ.advice[col - COL_ADVICE_OFFSET][row];
    let s_op = &circ.info.preprocess_polys[0];
    let s_bind = &circ.info.preprocess_polys[1];
    let two32 = F::from(1u64 << 32);
    let inst = circ.instances[0][0];
    for row in 0..ROWS {
        let sop = s_op[row];
        let sbind = s_bind[row];
        if sop == F::ONE {
            let a = val(COL_A, row);
            let b = val(COL_B, row);
            let c = val(COL_C, row);
            let k = val(COL_K, row);
            // 1. 模加
            if a + b - c - two32 * k != F::ZERO {
                return false;
            }
            // 2. carry 布尔
            if k * (F::ONE - k) != F::ZERO {
                return false;
            }
            // 3. 字节分解（a/b/c 各一次）
            for (word, base) in [(a, COL_A0), (b, COL_B0), (c, COL_C0)] {
                let recomposed = val(base, row)
                    + F::from(1u64 << 8) * val(base + 1, row)
                    + F::from(1u64 << 16) * val(base + 2, row)
                    + F::from(1u64 << 24) * val(base + 3, row);
                if word != recomposed {
                    return false;
                }
            }
        }
        // 4. 公开输入绑定
        if sbind == F::ONE && val(COL_C, row) != inst {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FpSM2;

    fn real_witness() -> Vec<WordAdd> {
        let block: [u8; 64] = b"abcd".repeat(16).try_into().unwrap();
        let w = block_words(&block);
        (0..NUM_ADD_ROWS).map(|i| mod_add(w[i], w[i + 4])).collect()
    }

    #[test]
    fn mod_add_correct() {
        // 无进位 / 1 进位 / 双满进位
        let x = mod_add(1, 2);
        assert_eq!((x.a, x.b, x.c, x.k), (1, 2, 3, 0));
        let y = mod_add(0xffff_ffff, 1);
        assert_eq!((y.a, y.b, y.c, y.k), (0xffff_ffff, 1, 0, 1));
        let z = mod_add(0xffff_ffff, 0xffff_ffff);
        assert_eq!(
            (z.a, z.b, z.c, z.k),
            (0xffff_ffff, 0xffff_ffff, 0xffff_fffe, 1)
        );
    }

    #[test]
    fn block_words_from_abcd() {
        // "abcd"×16 → 每个 4 字节块 = 0x61626364（ASCII a/b/c/d）。
        let block: [u8; 64] = b"abcd".repeat(16).try_into().unwrap();
        let w = block_words(&block);
        for i in 0..16 {
            assert_eq!(w[i], 0x61626364, "W[{i}]");
        }
    }

    #[test]
    fn witness_satisfies_all_gates() {
        let adds = real_witness();
        let circ = ModAddCircuit::<FpSM2>::build(&adds);
        assert!(check_gates(&circ), "真实 witness 应满足全部门");
    }

    #[test]
    fn mutated_witness_rejected() {
        // 篡改 a 的字节分解 cell → decompose 门必须拒绝（TDD 负向测试）。
        // 注意：首个真实行位于第 1<<0 = 1 行（行布局 = row_mapping，实例 c0 在第 1 行）。
        let adds = real_witness();
        let mut circ = ModAddCircuit::<FpSM2>::build(&adds);
        circ.advice[COL_A0 - COL_ADVICE_OFFSET][1] = FpSM2::from(0xFFu64);
        assert!(!check_gates(&circ), "篡改字节分解后的 witness 必须被拒绝");
    }

    #[test]
    fn mutated_carry_rejected() {
        // carry 篡改为 2 → 布尔门必须拒绝。
        let adds = real_witness();
        let mut circ = ModAddCircuit::<FpSM2>::build(&adds);
        circ.advice[COL_K - COL_ADVICE_OFFSET][1] = FpSM2::from(2u64);
        assert!(!check_gates(&circ), "carry 篡改为 2 必须被拒绝");
    }

    #[test]
    fn info_well_formed_and_degree_bounded() {
        let adds = real_witness();
        let circ = ModAddCircuit::<FpSM2>::build(&adds);
        assert!(circ.info.is_well_formed());
        // 门度数 ≤ 3（lookup 约束度数 ≤ 4，由 max_degree=4 覆盖）
        for c in &circ.info.constraints {
            assert!(c.degree() <= 3, "门度数 {} 超 3", c.degree());
        }
        assert_eq!(circ.info.num_poly(), 20);
    }
}
