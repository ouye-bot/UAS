//! M3 探针（BaseFold 版，#27）：SM2 基域 F_p 上透明 SNARK（HyperPlonk + Basefold + SM3）
//! 的端到端计量，目标 M2c 132k 全电路规模。
//!
//! 与 Brakedown 版 `probe.rs`（M3a 记录）的区别：
//!   - PCS 换 `Basefold<FpSM2, Sm3, BasefoldSpec>`：fold-based，无列开爆炸
//!     （Brakedown @2^18 proof ≈70MB 不可用，见 SPIKE_REPORT #27 硬约束）；
//!   - 规模扩展至 2^16 / 2^17 / 2^18（对标 M2c 实测 132,705 约束 → 2^17=131,072 最贴近，
//!     2^18=262,144 留 2× 余量）。
//!
//! Basefold 参数 `BasefoldSpec` 对标 blaze.rs 协议级 Five（reps=402, rate=1, rounds=0,
//! code_type="random"）。FpSM2 为**奇特征**域 → "random" 路径（AES 表 + x1=-x0 插值，
//! basefold.rs:2558-2565）与 Fr 同构，端到端可行（#29 已证实奇特征域走该路径）。
//!
//! 跑法：cargo +nightly run --release -p plonkish_sm2_probe --bin probe_basefold [max_num_vars]
//! 判定（Gate A1 扩展）：F_p 上 BaseFold prove→verify 全链路可跑通、VERIFY OK、效率 sane。

use plonkish_backend::{
    backend::{
        hyperplonk::{util::rand_vanilla_plonk_circuit, HyperPlonk},
        PlonkishBackend, PlonkishCircuit,
    },
    pcs::multilinear::{Basefold, BasefoldExtParams},
    util::{
        arithmetic::PrimeField,
        hash::Sm3,
        transcript::{InMemoryTranscript, SM3Transcript},
    },
};
use plonkish_sm2_probe::FpSM2;
use rand::{rngs::StdRng, SeedableRng};
use std::io::Cursor;
use std::time::Instant;

/// BaseFold 扩展参数（对标 blaze.rs 协议级 Five，reps=402）。
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

/// 透明 PCS：BaseFold（fold-based、域无关）+ SM3 哈希（#28），超 SM2 基域 FpSM2。
type Pcs = Basefold<FpSM2, Sm3, BasefoldSpec>;
/// 后端：HyperPlonk。
type Pb = HyperPlonk<Pcs>;
/// transcript：SM3（与 brakedown.rs/`probe.rs` 同款 InMemoryTranscript 约定）。
type T = SM3Transcript<Cursor<Vec<u8>>>;

fn run_case(num_vars: usize) {
    let size = 1usize << num_vars;
    // 各阶段传所有型 rng（同 `probe.rs`，`rand_vanilla_plonk_circuit` 返回不透明
    // `impl PlonkishCircuit`，编译器视其可能持有 rng 的 &mut 借用）。
    let (circuit_info, circuit) = rand_vanilla_plonk_circuit::<FpSM2>(
        num_vars,
        StdRng::seed_from_u64(num_vars as u64 * 0x9E37_79B9 + 1),
        StdRng::seed_from_u64(num_vars as u64 * 0x9E37_79B9 + 2),
    );
    let instances: Vec<Vec<FpSM2>> = circuit.instances().to_vec();

    let t0 = Instant::now();
    let param = Pb::setup(&circuit_info, StdRng::seed_from_u64(num_vars as u64 * 0x9E37_79B9 + 3))
        .unwrap();
    let t_setup = t0.elapsed();

    let t0 = Instant::now();
    let (pp, vp) = Pb::preprocess(&param, &circuit_info).unwrap();
    let t_pre = t0.elapsed();

    let t0 = Instant::now();
    let proof = {
        let mut transcript = T::new(());
        Pb::prove(
            &pp,
            &circuit,
            &mut transcript,
            StdRng::seed_from_u64(num_vars as u64 * 0x9E37_79B9 + 4),
        )
        .unwrap();
        transcript.into_proof()
    };
    let t_prove = t0.elapsed();

    let t0 = Instant::now();
    let result = {
        let mut transcript = T::from_proof((), proof.as_slice());
        Pb::verify(
            &vp,
            &instances,
            &mut transcript,
            StdRng::seed_from_u64(num_vars as u64 * 0x9E37_79B9 + 5),
        )
    };
    let t_verify = t0.elapsed();

    assert_eq!(result, Ok(()), "num_vars={num_vars} verify FAILED");
    println!(
        "  num_vars={:>2}  rows=2^{:>2}={:<7}  setup={:>7.2}s  preprocess={:>8.2}s  prove={:>9.2}s  verify={:>7.3}s  proof={} B",
        num_vars,
        num_vars,
        size,
        t_setup.as_secs_f64(),
        t_pre.as_secs_f64(),
        t_prove.as_secs_f64(),
        t_verify.as_secs_f64(),
        proof.len()
    );
}

fn main() {
    // 可选：最大 num_vars（缺省全跑）
    let max_nv = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(18);

    println!("== M3 probe (BaseFold): transparent SNARK over SM2 F_p ==");
    println!("field p = {} (SM2 基域, v2(p-1)=1)", FpSM2::MODULUS);
    println!(
        "PCS = Basefold<FpSM2, Sm3, BasefoldSpec> (reps=402, rate=1, rounds=0, code_type=\"random\")"
    );
    println!("backend = HyperPlonk; transcript = SM3");
    println!("max_num_vars = {max_nv}");

    println!("\n== smoke test (num_vars=4) ==");
    run_case(4);
    println!("\n== scale sweep ==");
    // 小档（对标 M3a Brakedown 基线比较）→ 中档 → 目标档 2^17/2^18
    let sweep: Vec<usize> = [8usize, 10, 12, 13, 14, 15, 16, 17, 18]
        .into_iter()
        .filter(|&nv| nv <= max_nv)
        .collect();
    for nv in sweep {
        run_case(nv);
    }
    println!(
        "\n== ALL VERIFY OK: BaseFold transparent SNARK end-to-end over SM2 F_p confirmed =="
    );
}
