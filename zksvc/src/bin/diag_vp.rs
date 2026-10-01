// 一次性诊断（R1 内存归因）：装配→setup→preprocess → 打印 vp 各字段 bincode 尺寸
// 用法: diag_vp <job.json>   （env: FZ_ZK_ALLOW_AUTH=1 / FZ_ZK_ALLOW_TRAIL=1）
use plonkish_backend::backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit};
use plonkish_backend::pcs::multilinear::{Basefold, BasefoldExtParams};
use plonkish_backend::util::hash::Sm3;
use plonkish_sm2_probe::FpSM2;
use rand::{rngs::StdRng, SeedableRng};
use zksvc::assemble::assemble;

#[derive(Debug)]
struct DiagSpec;
impl BasefoldExtParams for DiagSpec {
    fn get_reps() -> usize { 16 }
    fn get_rate() -> usize { 1 }
    fn get_basecode_rounds() -> usize { 0 }
    fn get_rs_basecode() -> bool { false }
    fn get_code_type() -> String { "random".to_string() }
}

type Pcs = Basefold<FpSM2, Sm3, DiagSpec>;
type Pb = HyperPlonk<Pcs>;

struct JobCircuit {
    info: plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>,
    advice: Vec<Vec<FpSM2>>,
    instances: Vec<Vec<FpSM2>>,
}

impl plonkish_backend::backend::PlonkishCircuit<FpSM2> for JobCircuit {
    fn circuit_info_without_preprocess(
        &self,
    ) -> Result<plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(
        &self,
    ) -> Result<plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<FpSM2>] {
        &self.instances
    }
    fn synthesize(
        &self,
        _r: usize,
        _c: &[FpSM2],
    ) -> Result<Vec<Vec<FpSM2>>, plonkish_backend::Error> {
        Ok(self.advice.clone())
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("用法: diag_vp <job.json>");
    let text = std::fs::read_to_string(&path).expect("job 不可读");
    let spec: zksvc::profile::JobSpec = serde_json::from_str(&text).expect("spec 损坏");

    let asm = assemble(&spec).expect("装配失败");
    println!(
        "structure: k={} prep={} wit={} lookups={} cycles={} rings={}",
        asm.info.k,
        asm.info.preprocess_polys.len(),
        asm.info.num_witness_polys.iter().sum::<usize>(),
        asm.info.lookups.len(),
        asm.info.permutations.len(),
        asm.info.permutations.iter().map(Vec::len).sum::<usize>(),
    );
    // permutation_polys() 可见性（pub）下打印 σ 列数
    let sigma = {
        let mut set = std::collections::BTreeSet::new();
        for cyc in &asm.info.permutations {
            for &(p, _) in cyc {
                set.insert(p);
            }
        }
        set.len()
    };
    println!("sigma columns (distinct polys in rings) = {}", sigma);

    let circuits = JobCircuit {
        info: asm.info.clone(),
        advice: asm.advice.clone(),
        instances: asm.instances.clone(),
    };
    let nv = asm.info.k;
    let param = Pb::setup(&circuits.info, StdRng::seed_from_u64(0x5317_0001 ^ nv as u64)).expect("setup");
    let (_pp, vp) = Pb::preprocess(&param, &circuits.info).expect("preprocess");
    println!("vp fields: {}", vp.debug_field_sizes());
    let whole = bincode::serialize(&vp).expect("vp serialize");
    println!("vp whole = {} bytes", whole.len());
}
