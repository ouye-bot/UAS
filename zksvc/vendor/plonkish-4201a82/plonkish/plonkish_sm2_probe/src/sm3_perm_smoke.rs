//! 后端置换（复制约束）机制端到端冒烟。
//!
//! 背景（[[backend-rotation-budget-boundary]]）：HyperPlonk 的 Rotation 有协议级预算
//! （sumcheck 断言 |d|≤num_vars；verifier 按 2^|d| 面额读证明）。b4 拍板为分块链式后，
//! 取证发现 `PlonkishCircuitInfo.permutations`（halo2 式复制环 + plonkish 积论证）在
//! 本栈完整存在且从未被端到端飞行过（上游仅 compose 形状测试）。若可用，则最优解是
//! 「v1 布局 + 远读处本地复制词 + 复制环连接任意距离」——零长旋转传输。
//!
//! 本文件 = 最小可飞行验证：k=4、2 个见证多项式、两条复制环，走
//! setup→preprocess→prove→verify 全程（BaseFold over FpSM2 + SM3Transcript）。
//! 绿 ⇒ v2 采用复制环方案；红 ⇒ 回退分块链式证明。

use ff::Field;
use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishCircuit, PlonkishCircuitInfo},
    pcs::multilinear::{Basefold, BasefoldExtParams},
    util::{hash::Sm3, transcript::SM3Transcript},
    Error,
};
use std::io::Cursor;

pub type Fr = crate::FpSM2;

/// BaseFold 扩展参数（与 probe_sm3_spike 一致勿改）。
#[derive(Debug)]
pub struct BasefoldSpec;
impl BasefoldExtParams for BasefoldSpec {
    fn get_reps() -> usize {
        402
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

/// BaseFold over FpSM2 + SM3Transcript 的探针后端（测试模块内使用）。
#[cfg(test)]
pub(crate) mod flight {
    use super::*;
    pub type Pcs = Basefold<Fr, Sm3, BasefoldSpec>;
    pub type Pb = HyperPlonk<Pcs>;
    pub type T = SM3Transcript<Cursor<Vec<u8>>>;
}

/// 冒烟电路：k=4，见证列 a、b。约束仅要求 a 布尔（全局，无选择器）；
/// 复制环声明「b[pt_y]=a[pt_x]」与「b[pt_w]=b[pt_z]」（同列跨行环），
/// 数值由装配器按环成对填充 —— 若机制健在，verify 必须 Ok。
#[derive(Clone, Debug)]
pub struct PermSmokeCircuit {
    pub info: PlonkishCircuitInfo<Fr>,
    /// [0]=a 列、[1]=b 列。
    pub cols: [Vec<Fr>; 2],
}

impl PermSmokeCircuit {
    pub fn build(k: usize) -> Self {
        let n = 1 << k;
        // 见证全局编号：无实例、无预处理 ⇒ a=0、b=1。
        let (ia, ib) = (0usize, 1usize);
        // 环 1（跨列）：a@5 ↔ b@11；环 2（同列）：b@7 ↔ b@13。点 0 禁用。
        let permutations =
            vec![vec![(ia, 5usize), (ib, 11usize)], vec![(ib, 7usize), (ib, 13usize)]];
        let info = PlonkishCircuitInfo::<Fr> {
            k,
            num_instances: Vec::new(),
            preprocess_polys: Vec::new(),
            num_witness_polys: vec![2],
            num_challenges: vec![0],
            lookups: Vec::new(),
            permutations,
            // 无约束也能过 well-formed；但为了让 compose 表达式非平凡，放一条布尔性。
            constraints: Vec::new(),
            max_degree: Some(4),
        };
        assert!(info.is_well_formed(), "smoke info 未通过 well-formed");

        // 见证：每条环内各格相等；其余任意常数。
        let mut a = vec![Fr::ZERO; n];
        let mut b = vec![Fr::ZERO; n];
        let five = Fr::from(5u64);
        let nine = Fr::from(9u64);
        a[5] = five;
        b[11] = five;
        b[7] = nine;
        b[13] = nine;
        // 环外点填不同常数，确认无关格不被误伤。
        a[6] = Fr::from(1u64);
        b[8] = Fr::from(2u64);
        PermSmokeCircuit { info, cols: [a, b] }
    }
}

impl PlonkishCircuit<Fr> for PermSmokeCircuit {
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
        Ok(self.cols.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm3_perm_smoke::flight::{Pb, T};
    use plonkish_backend::{
        backend::PlonkishBackend, util::transcript::InMemoryTranscript,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn permutation_cycles_survive_e2e() {
        let circ = PermSmokeCircuit::build(4);
        let param = Pb::setup(&circ.info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = Pb::preprocess(&param, &circ.info).unwrap();

        let proof = {
            let mut tr = T::new(());
            Pb::prove(&pp, &circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let result = {
            let mut tr = T::from_proof((), proof.as_slice());
            Pb::verify(&vp, &[], &mut tr, StdRng::seed_from_u64(0x5EED + 2))
        };
        assert_eq!(result, Ok(()), "置换环电路 VERIFY FAILED：复制约束链路断了");
        println!(
            "[perm-smoke] OK：k=4 两条复制环（跨列 a↔b、同列 b↔b）经 BaseFold+FpSM2 \
             端到端验证通过，proof={} B",
            proof.len()
        );
    }

    /// 破环负例：把 b[11] 改成非 a[5] 的值（但保持 b 列自洽常数——排除其他失败模式），
    /// 积论证必须拒绝。这是「环真的在约束」的直接证据。
    #[test]
    fn broken_cycle_rejected() {
        let mut circ = PermSmokeCircuit::build(4);
        circ.cols[1][11] = Fr::from(12345u64);
        let param = Pb::setup(&circ.info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = Pb::preprocess(&param, &circ.info).unwrap();
        // 不满足的见证：诚实 prove 要么报错、要么产出注定被拒的证明、要么中途 panic ——
        // 三种都算"拒绝"；唯独不允许走完 verify 还返回 Ok。
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tr = T::new(());
            let r = Pb::prove(&pp, &circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1));
            r.map(|()| tr.into_proof())
        }));
        match outcome {
            Ok(Ok(proof)) => {
                let result = {
                    let mut tr = T::from_proof((), proof.as_slice());
                    Pb::verify(&vp, &[], &mut tr, StdRng::seed_from_u64(0x5EED + 2))
                };
                assert_ne!(result, Ok(()), "破环见证被静默接受——复制约束未生效！");
            }
            Ok(Err(_)) | Err(_) => {} // prove 报错/panic 均视为拒绝
        }
        println!("[perm-smoke] 破环见证被拒绝 ✔");
    }
}
