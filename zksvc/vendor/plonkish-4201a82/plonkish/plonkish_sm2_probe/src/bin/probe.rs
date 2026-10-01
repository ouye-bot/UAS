//! M3 探针：SM2 基域 F_p 上透明 SNARK（HyperPlonk + MultilinearBrakedown + SM3）
//! 的端到端计量。复用 crate 的 vanilla plonk 测试电路（任意 Plonkish 电路走同一代码路径；
//! 真实 SM2/SM3 电路的 Plonkish 移植属 M3 主体工作，不在探针范围）。
//! SM3 承诺哈希（#28）：承诺树哈希与 Fiat-Shamir transcript 均用国密 SM3。
//!
//! 跑法：cargo +nightly-x86_64-pc-windows-gnu run --release -p plonkish_sm2_probe --bin probe
//! 判定（Gate A1）：F_p 上 prove→verify 全链路是否可跑通、可满足性断言通过、效率 sane。

use plonkish_backend::{
    backend::{
        hyperplonk::{util::rand_vanilla_plonk_circuit, HyperPlonk},
        PlonkishBackend, PlonkishCircuit,
    },
    pcs::multilinear::MultilinearBrakedown,
    util::{
        arithmetic::PrimeField,
        code::BrakedownSpec6,
        hash::Sm3,
        transcript::{InMemoryTranscript, SM3Transcript},
    },
};
use plonkish_sm2_probe::FpSM2;
use rand::{rngs::StdRng, SeedableRng};
use std::io::Cursor;
use std::time::Instant;

/// 透明 PCS：Brakedown（无 FFT、域无关）+ SM3 哈希（#28），超 SM2 基域 FpSM2。
type Pcs = MultilinearBrakedown<FpSM2, Sm3, BrakedownSpec6>;
/// 后端：HyperPlonk（BaseFold folding 家族）。
type Pb = HyperPlonk<Pcs>;
/// transcript：`InMemoryTranscript` 仅对 `FiatShamirTranscript<H, Cursor<Vec<u8>>>` 实现
/// （见 `util/transcript.rs:112`，与 brakedown.rs 自测一致）。
type T = SM3Transcript<Cursor<Vec<u8>>>;

fn run_case(num_vars: usize) {
    let size = 1usize << num_vars;
    // 各阶段传所有型 rng（crate 自带测试同款）：`rand_vanilla_plonk_circuit` 返回
    // `impl PlonkishCircuit` 不透明类型，编译器视其可能持有传入 rng 的 &mut 借用至
    // circuit 生命周期结束，故不可在电路存活期间复用同一 rng。
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
    println!("== M3 probe: transparent SNARK over SM2 F_p ==");
    println!("field p = {} (SM2 基域, v2(p-1)=1)", FpSM2::MODULUS);
    println!("PCS = MultilinearBrakedown<FpSM2, Sm3, BrakedownSpec6>");
    println!("backend = HyperPlonk; transcript = SM3");

    println!("\n== smoke test (num_vars=4) ==");
    run_case(4);
    println!("\n== scale sweep ==");
    for nv in [8usize, 10, 12, 13, 14] {
        run_case(nv);
    }
    println!("\n== ALL VERIFY OK: transparent SNARK end-to-end over SM2 F_p confirmed ==");
}
