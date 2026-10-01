//! M3 spike #1：真实 SM3 模加电路（mod-2^32 加法 + 字节范围查找）经 HyperPlonk + BaseFold
//! over FpSM2 端到端证明。
//!
//! 这是**仓库内首次**验证 lookup + BaseFold + FpSM2 组合（basefold/kzg 的 lookup 测试此前被
//! 注释；`probe_basefold.rs` 用的是无 lookup 的 vanilla MockCircuit）。通过则阶段 1 的关键
//! 去风险未知数解除：真实 Show 电路 = 手写 gate Expression + 原生 u32 算 witness。
//!
//! 跑法：cargo +nightly run --release -p plonkish_sm2_probe --bin probe_sm3_spike

use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit},
    pcs::multilinear::{Basefold, BasefoldExtParams},
    util::{
        hash::Sm3,
        transcript::{InMemoryTranscript, SM3Transcript},
    },
};
use plonkish_sm2_probe::{
    sm3_gates::{self, ModAddCircuit, WordAdd},
    FpSM2,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{io::Cursor, time::Instant};

/// BaseFold 扩展参数（对标 blaze.rs 协议级 Five，reps=402，与 probe_basefold 一致勿改）。
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
/// transcript：SM3。
type T = SM3Transcript<Cursor<Vec<u8>>>;

fn main() {
    // 真实 SM3 消息字：块 "abcd"×16（GB/T 32918-2016 附录 A 向量所用块），W[0..15] = 0x61626364。
    let block: [u8; 64] = b"abcd".repeat(16).try_into().unwrap();
    let w = sm3_gates::block_words(&block);
    let adds: Vec<WordAdd> = (0..sm3_gates::NUM_ADD_ROWS)
        .map(|i| sm3_gates::mod_add(w[i], w[i + 4]))
        .collect();
    println!("== M3 spike: 真实 SM3 模加电路 over FpSM2（lookup + BaseFold 首次验证）==");
    println!("SM3 块 = \"abcd\"×16 → W[0..15] = 0x61626364；4 个模加 W[i] + W[i+4] mod 2^32：");
    for (i, wa) in adds.iter().enumerate() {
        println!(
            "  W[{i}]={:#010x} + W[{}+4]={:#010x} = c={:#010x}, carry={}",
            wa.a, i, wa.b, wa.c, wa.k
        );
    }

    // 原生门检查（TDD mock-prover：真实 witness 必须全过）。
    let circ = ModAddCircuit::<FpSM2>::build(&adds);
    assert!(sm3_gates::check_gates(&circ), "原生门检查失败");
    println!(
        "原生门检查通过：k={}, rows=2^{}={}, 真实行={}（第 1<<i 行）, 门=6, lookup=12×1-对 (s_op·byte, table[0..255])",
        sm3_gates::K,
        sm3_gates::K,
        1usize << sm3_gates::K,
        adds.len()
    );

    let circuit_info = circ.circuit_info().unwrap();
    let instances: Vec<Vec<FpSM2>> = circ.instances().to_vec();

    let t0 = Instant::now();
    let param = Pb::setup(&circuit_info, StdRng::seed_from_u64(0x5EED)).unwrap();
    let t_setup = t0.elapsed();

    let t0 = Instant::now();
    let (pp, vp) = Pb::preprocess(&param, &circuit_info).unwrap();
    let t_pre = t0.elapsed();

    let t0 = Instant::now();
    let proof = {
        let mut transcript = T::new(());
        Pb::prove(&pp, &circ, &mut transcript, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
        transcript.into_proof()
    };
    let t_prove = t0.elapsed();

    let t0 = Instant::now();
    let result = {
        let mut transcript = T::from_proof((), proof.as_slice());
        Pb::verify(&vp, &instances, &mut transcript, StdRng::seed_from_u64(0x5EED + 2))
    };
    let t_verify = t0.elapsed();

    assert_eq!(result, Ok(()), "VERIFY FAILED");
    println!(
        "setup={:.3}s preprocess={:.3}s prove={:.3}s verify={:.3}s proof={} B",
        t_setup.as_secs_f64(),
        t_pre.as_secs_f64(),
        t_prove.as_secs_f64(),
        t_verify.as_secs_f64(),
        proof.len()
    );
    println!(
        "== SPIKE OK: 真实 SM3 mod-add 电路 end-to-end over FpSM2（lookup+BaseFold 首次验证）=="
    );
}
