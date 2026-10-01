//! SM3 查表化原型（系统线 2026-09-17，分支 `system/sm3-lookup-proto`，从 paper-anchor-v3
//! 分出；**不入论文线任何分支/tag**——原型只产出立项判据）。
//!
//! Phase A（本文件）：
//!   ① lookup 相位飞行——K=12、4 位 XOR 表（256 项 (a,b,a⊕b)，其余行 (0,0,0)）、一条
//!      向量查表论证覆盖全部 4,096 行：诚实 verify 必 Ok；破表负例必拒；
//!   ② 汇率微基准——同等 XOR 工作量（L 条通道 × 4,096 行 4 位异或）下，
//!      "查表通道"（3 见证列 + 1 lookup 论证/通道）vs "布尔门通道"（15 见证列 + 14 约束/通道）
//!      的约束数与 prove/verify 时延。它决定 SM3 单块查表化的净收益估算是否成立。
//!
//! 背景事实：仓内 lookup 仅在 k=10 模加 spike（sm3_gates.rs）飞过一次；D27 交织给 lookup
//! 相位加的是空批防护（num_lookups=0）——**交织构型下带 lookup 的电路从未被证过**，
//! 故 ① 在 PCS_INTERLEAVE=0/1 两构型下各跑一遍（由测试外层 env 控制）。

use ff::Field;
use plonkish_backend::{
    backend::{PlonkishCircuit, PlonkishCircuitInfo},
    pcs::multilinear::BasefoldExtParams,
    util::expression::{Expression, Query, Rotation},
    Error,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

pub type Fr = crate::FpSM2;

/// 生产口径参数（zksvc ZkcVerifySpec 同款：reps=16 / rate=1 / random 码）。
#[derive(Debug)]
pub struct ProtoSpec;
impl BasefoldExtParams for ProtoSpec {
    fn get_reps() -> usize {
        16
    }
    fn get_rate() -> usize {
        1
    }
    fn get_basecode_rounds() -> usize {
        0
    }
    fn get_rs_basecode() -> bool {
        false
    }
    fn get_code_type() -> String {
        "random".to_string()
    }
}

pub const K: usize = 12;
pub const ROWS: usize = 1 << K;

fn poly(idx: usize) -> Expression<Fr> {
    Expression::Polynomial(Query::new(idx, Rotation::cur()))
}

fn c(v: u64) -> Expression<Fr> {
    Expression::Constant(Fr::from(v))
}

/// 4 位 XOR 表三列：行 i<256 = (i>>4, i&15, (i>>4)^(i&15))，其余行全零（(0,0,0) 亦为合法项，
/// 使非活跃行的全零查询天然命中——上游 vanilla_plonk_with_lookup 同款技巧）。
pub fn xor4_table() -> [Vec<Fr>; 3] {
    let mut t = [vec![Fr::ZERO; ROWS], vec![Fr::ZERO; ROWS], vec![Fr::ZERO; ROWS]];
    for i in 0..256usize {
        let (a, b) = ((i >> 4) as u64, (i & 15) as u64);
        t[0][i] = Fr::from(a);
        t[1][i] = Fr::from(b);
        t[2][i] = Fr::from(a ^ b);
    }
    t
}

/// 同一份随机 4 位异或工作量（L 通道 × rows_used 行），两种电路化路线共用。
pub struct XorWork {
    pub lanes: usize,
    pub rows_used: usize,
    /// [lane][row] = (a, b)
    pub ops: Vec<Vec<(u8, u8)>>,
}

impl XorWork {
    pub fn random(lanes: usize, rows_used: usize, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let ops = (0..lanes)
            .map(|_| {
                (0..rows_used)
                    .map(|_| ((rng.next_u32() & 15) as u8, (rng.next_u32() & 15) as u8))
                    .collect()
            })
            .collect();
        XorWork { lanes, rows_used, ops }
    }
}

impl XorWork {
    /// 链式工作量：a_{l+1}[r] = a_l[r] ⊕ b_l[r]（通道间数据流动——接线成本基准用）。
    pub fn chained(lanes: usize, rows_used: usize, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut ops: Vec<Vec<(u8, u8)>> = Vec::with_capacity(lanes);
        let mut a_prev: Vec<u8> = (0..rows_used).map(|_| (rng.next_u32() & 15) as u8).collect();
        for _ in 0..lanes {
            let lane: Vec<(u8, u8)> = a_prev
                .iter()
                .map(|&a| (a, (rng.next_u32() & 15) as u8))
                .collect();
            a_prev = lane.iter().map(|&(a, b)| a ^ b).collect();
            ops.push(lane);
        }
        XorWork { lanes, rows_used, ops }
    }
}

#[derive(Clone, Debug)]
pub struct ProtoCircuit {
    pub info: PlonkishCircuitInfo<Fr>,
    pub witness: Vec<Vec<Fr>>,
}

impl ProtoCircuit {
    /// 查表路线：预处理 3 列（表）；每通道 3 见证列 (a,b,c)；每通道 1 条向量查表论证
    /// [(a,T_a),(b,T_b),(c,T_c)]；零约束。
    pub fn build_lookup(work: &XorWork) -> Self {
        let table = xor4_table();
        let base = 3; // 无实例，预处理 3 列，见证自 3 起
        let mut witness = vec![vec![Fr::ZERO; ROWS]; 3 * work.lanes];
        let mut lookups = Vec::with_capacity(work.lanes);
        for l in 0..work.lanes {
            let (ia, ib, ic) = (base + 3 * l, base + 3 * l + 1, base + 3 * l + 2);
            for (r, &(a, b)) in work.ops[l].iter().enumerate() {
                witness[3 * l][r] = Fr::from(a as u64);
                witness[3 * l + 1][r] = Fr::from(b as u64);
                witness[3 * l + 2][r] = Fr::from((a ^ b) as u64);
            }
            lookups.push(vec![(poly(ia), poly(0)), (poly(ib), poly(1)), (poly(ic), poly(2))]);
        }
        let info = PlonkishCircuitInfo::<Fr> {
            k: K,
            num_instances: Vec::new(),
            preprocess_polys: table.to_vec(),
            num_witness_polys: vec![3 * work.lanes],
            num_challenges: vec![0],
            constraints: Vec::new(),
            lookups,
            permutations: Vec::new(),
            max_degree: Some(4),
        };
        assert!(info.is_well_formed(), "lookup 原型 info 未通过 well-formed");
        ProtoCircuit { info, witness }
    }

    /// 接线基准：查表路线 + 复制环 (c_l@r ↔ a_{l+1}@r)，r∈[1,rows_used)（点 0 禁用，
    /// 与 perm_smoke 同款）——量"限位值在通道间流动"的置换论证成本。
    pub fn build_lookup_wired(work: &XorWork) -> Self {
        let mut circ = Self::build_lookup(work);
        let base = 3;
        let mut perms = Vec::with_capacity((work.lanes - 1) * work.rows_used);
        for l in 0..work.lanes.saturating_sub(1) {
            let (ic, ia_next) = (base + 3 * l + 2, base + 3 * (l + 1));
            for r in 1..work.rows_used {
                perms.push(vec![(ic, r), (ia_next, r)]);
            }
        }
        circ.info.permutations = perms;
        assert!(circ.info.is_well_formed(), "wired 原型 info 未通过 well-formed");
        circ
    }

    /// 布尔门路线（现行 SM3 gadget 的做法）：每通道 15 见证列 = a,b,c + a0..3,b0..3,c0..3；
    /// 约束/通道 = 8 布尔性 + 4 位异或 (c_i = a_i + b_i − 2a_i b_i) + 3 分解 = 15 条（全点，
    /// 非活跃行全零自然满足）。
    pub fn build_boolean(work: &XorWork) -> Self {
        const W: usize = 15;
        let mut witness = vec![vec![Fr::ZERO; ROWS]; W * work.lanes];
        let mut constraints = Vec::with_capacity(15 * work.lanes);
        for l in 0..work.lanes {
            let b0 = W * l;
            let (ia, ib, ic) = (b0, b0 + 1, b0 + 2);
            let abit = |i: usize| b0 + 3 + i;
            let bbit = |i: usize| b0 + 7 + i;
            let cbit = |i: usize| b0 + 11 + i;
            for (r, &(a, b)) in work.ops[l].iter().enumerate() {
                let x = a ^ b;
                witness[ia][r] = Fr::from(a as u64);
                witness[ib][r] = Fr::from(b as u64);
                witness[ic][r] = Fr::from(x as u64);
                for i in 0..4 {
                    witness[abit(i)][r] = Fr::from(((a >> i) & 1) as u64);
                    witness[bbit(i)][r] = Fr::from(((b >> i) & 1) as u64);
                    witness[cbit(i)][r] = Fr::from(((x >> i) & 1) as u64);
                }
            }
            for i in 0..4 {
                let (pa, pb, pc) = (poly(abit(i)), poly(bbit(i)), poly(cbit(i)));
                constraints.push(pa.clone() * (pa.clone() - c(1)));
                constraints.push(pb.clone() * (pb.clone() - c(1)));
                constraints.push(pc - (pa.clone() + pb.clone() - c(2) * pa * pb));
            }
            let recomp = |bit: &dyn Fn(usize) -> usize| {
                (0..4).fold(Expression::Constant(Fr::ZERO), |acc, i| acc + c(1u64 << i) * poly(bit(i)))
            };
            constraints.push(poly(ia) - recomp(&abit));
            constraints.push(poly(ib) - recomp(&bbit));
            constraints.push(poly(ic) - recomp(&cbit));
        }
        let info = PlonkishCircuitInfo::<Fr> {
            k: K,
            num_instances: Vec::new(),
            preprocess_polys: Vec::new(),
            num_witness_polys: vec![W * work.lanes],
            num_challenges: vec![0],
            constraints,
            lookups: Vec::new(),
            permutations: Vec::new(),
            max_degree: Some(4),
        };
        assert!(info.is_well_formed(), "boolean 原型 info 未通过 well-formed");
        ProtoCircuit { info, witness }
    }

    /// 破表负例：把第 lane 通道第 row 行的 c 改成 (a⊕b)⊕1（仍在 0..15 内——排除"越界"这一
    /// 无关失败模式，只留"元组不在表中"）。
    pub fn corrupt_lookup_c(&mut self, lane: usize, row: usize) {
        let ic = 3 * lane + 2;
        let cur = self.witness[ic][row];
        self.witness[ic][row] = cur + Fr::ONE;
    }
}

impl PlonkishCircuit<Fr> for ProtoCircuit {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<Fr>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<Fr>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<Fr>] {
        &[]
    }
    fn synthesize(&self, round: usize, challenges: &[Fr]) -> Result<Vec<Vec<Fr>>, Error> {
        assert!(round == 0 && challenges.is_empty());
        Ok(self.witness.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonkish_backend::{
        backend::{hyperplonk::HyperPlonk, PlonkishBackend},
        pcs::multilinear::Basefold,
        util::{
            hash::Sm3,
            transcript::{InMemoryTranscript, SM3Transcript},
        },
    };
    use std::io::Cursor;
    use std::time::Instant;

    type Pcs = Basefold<Fr, Sm3, ProtoSpec>;
    type Pb = HyperPlonk<Pcs>;
    type T = SM3Transcript<Cursor<Vec<u8>>>;

    struct Run {
        setup_s: f64,
        pre_s: f64,
        prove_s: f64,
        verify_s: f64,
        proof_bytes: usize,
        ok: bool,
    }

    fn fly(circ: &ProtoCircuit, tag: &str) -> Run {
        let t = Instant::now();
        let param = Pb::setup(&circ.info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let setup_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let (pp, vp) = Pb::preprocess(&param, &circ.info).unwrap();
        let pre_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let proof = {
            let mut tr = T::new(());
            Pb::prove(&pp, circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let prove_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let ok = {
            let mut tr = T::from_proof((), proof.as_slice());
            Pb::verify(&vp, &[], &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
        };
        let verify_s = t.elapsed().as_secs_f64();
        let il = std::env::var("PCS_INTERLEAVE").as_deref() == Ok("1");
        eprintln!(
            "[sm3-lookup-proto] {tag} il={} polys={} constraints={} lookups={} setup={setup_s:.2}s pre={pre_s:.2}s prove={prove_s:.2}s verify={verify_s:.3}s proof={}B ok={ok}",
            u8::from(il),
            circ.info.num_poly(),
            circ.info.constraints.len(),
            circ.info.lookups.len(),
            proof.len()
        );
        Run { setup_s, pre_s, prove_s, verify_s, proof_bytes: proof.len(), ok }
    }

    /// ① 飞行：K=12 全行活跃的一条 XOR 查表论证，诚实必 Ok。
    #[test]
    fn a1_xor4_lookup_flight_ok() {
        let work = XorWork::random(1, ROWS, 7);
        let circ = ProtoCircuit::build_lookup(&work);
        let r = fly(&circ, "A1-flight lanes=1 rows=4096");
        assert!(r.ok, "lookup 诚实电路 VERIFY FAILED——后端 lookup 相位不可飞行");
        let _ = (r.setup_s, r.pre_s, r.prove_s, r.verify_s, r.proof_bytes);
    }

    /// ① 负例：破表元组 (a,b,a⊕b⊕1) 必须被拒——"查表真的在约束"的直接证据。
    #[test]
    fn a1_xor4_lookup_broken_tuple_rejected() {
        let work = XorWork::random(1, ROWS, 7);
        let mut circ = ProtoCircuit::build_lookup(&work);
        circ.corrupt_lookup_c(0, 1234);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fly(&circ, "A1-negative")));
        match outcome {
            Ok(r) => assert!(!r.ok, "破表元组被静默接受——lookup 论证未生效！"),
            Err(_) => eprintln!("[sm3-lookup-proto] A1-negative: prove panic（视为拒绝）"),
        }
    }

    /// ③ 接线成本：8 通道链式 + 复制环（约 2.9 万复制格）vs 无环，prove 时延差 = 置换论证价格。
    #[test]
    fn a3_wiring_permutation_cost() {
        let work = XorWork::chained(8, ROWS, 13);
        let plain = fly(&ProtoCircuit::build_lookup(&work), "A3-lookup-8-plain");
        let wired = fly(&ProtoCircuit::build_lookup_wired(&work), "A3-lookup-8-wired(7x4095 rings)");
        assert!(plain.ok && wired.ok, "接线基准两电路均须 Ok");
        eprintln!(
            "[sm3-lookup-proto] A3-WIRING: prove plain/wired = {:.2}/{:.2}s (+{:.2}s for {} rings) proof {}/{}B",
            plain.prove_s, wired.prove_s, wired.prove_s - plain.prove_s, 7 * (ROWS - 1), plain.proof_bytes, wired.proof_bytes
        );
        // 破环负例：让某一行 a_{l+1} ≠ c_l（仍是合法查表元组——只留"环被违反"这一失败模式）
        let mut bad = ProtoCircuit::build_lookup_wired(&work);
        let (ia1, ib1, ic1) = (3, 4, 5);
        let a = bad.witness[ia1][100];
        let _ = (ib1, ic1);
        bad.witness[3 * 1][100] = a + Fr::ONE; // lane1.a@100 偏离 lane0.c@100
        // 同步修正 lane1.c 使查表元组仍合法：c = (a+1) ⊕ b —— 用原生值重算
        let a_u = (work.ops[1][100].0 ^ 0) as u8 + 1;
        let b_u = work.ops[1][100].1;
        bad.witness[3 * 1 + 2][100] = Fr::from(((a_u & 15) ^ b_u) as u64);
        bad.witness[3 * 1][100] = Fr::from((a_u & 15) as u64);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fly(&bad, "A3-broken-ring")));
        match outcome {
            Ok(r) => assert!(!r.ok, "破环见证被静默接受——置换论证未生效！"),
            Err(_) => eprintln!("[sm3-lookup-proto] A3-broken-ring: prove panic（视为拒绝）"),
        }
    }

    /// ② 汇率：L ∈ {1, 8, 32} 通道，查表 vs 布尔门（同工作量）。打印表格供判据。
    #[test]
    fn a2_exchange_rate_lookup_vs_boolean() {
        for &lanes in &[1usize, 8, 32] {
            let work = XorWork::random(lanes, ROWS, 11);
            let lk = fly(&ProtoCircuit::build_lookup(&work), &format!("A2-lookup  lanes={lanes}"));
            let bl = fly(&ProtoCircuit::build_boolean(&work), &format!("A2-boolean lanes={lanes}"));
            assert!(lk.ok && bl.ok, "汇率基准两路线诚实电路均须 Ok（lanes={lanes}）");
            eprintln!(
                "[sm3-lookup-proto] A2-RATE lanes={lanes}: prove lookup/boolean = {:.2}/{:.2}s ({:.2}x) verify {:.3}/{:.3}s proof {}/{}B",
                lk.prove_s,
                bl.prove_s,
                bl.prove_s / lk.prove_s.max(1e-9),
                lk.verify_s,
                bl.verify_s,
                lk.proof_bytes,
                bl.proof_bytes
            );
        }
    }
}
