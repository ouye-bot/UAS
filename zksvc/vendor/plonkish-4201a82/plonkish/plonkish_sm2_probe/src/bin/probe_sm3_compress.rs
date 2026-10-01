//! 阶段 1 · 1.1b-b4：SM3 **单块压缩函数全电路**（64 轮，30,480 条约束 / 1024 行）
//! 经 HyperPlonk + BaseFold over FpSM2 端到端 prove/verify 计时。
//!
//! 语句：`V'(k) = state_k ⊕ IV_k`（8 个实例值），witness 由 sm3_native_ref 原生推导，
//! GB/T 锚定在 `compress_abc_end_to_end_matches_native` 测试承担；本 bin 出论文口径
//! 四元组（行数 / advice 列 / 约束数 / proof 大小）+ 计时。
//!
//! 口径红线：R1CS 口径（M0 31,295）≠ Plonkish 行数/约束口径，不可混用。
//!
//! 跑法：cargo +nightly run --release -p plonkish_sm2_probe --bin probe_sm3_compress

use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit},
    pcs::multilinear::{Basefold, BasefoldExtParams},
    util::{
        hash::Sm3,
        transcript::{InMemoryTranscript, SM3Transcript},
    },
};
use plonkish_sm2_probe::{sm3_compress, FpSM2};
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

/// 透明 PCS：BaseFold（fold-based、域无关）+ SM3 承诺哈希（#28），超 SM2 基域 FpSM2。
type Pcs = Basefold<FpSM2, Sm3, BasefoldSpec>;
/// 后端：HyperPlonk。
type Pb = HyperPlonk<Pcs>;
/// transcript：SM3。
type T = SM3Transcript<Cursor<Vec<u8>>>;

fn main() {
    // 与测试侧同款单块填充："abc" + 0x80 + 补零到 56 字节 + 大端比特长度。
    let msg = b"abc";
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
    let mut block = [0u8; 64];
    block.copy_from_slice(&padded);

    println!("== 1.1b-b4：SM3 单块压缩全电路 over FpSM2（HyperPlonk + BaseFold + SM3 transcript）==");
    println!("消息块 = \"abc\" 的标准填充单块（{:#02x}..{:02x}，64 B）", block[0], block[63]);

    // 装配电路并做出厂自检：实例必须逐字等于原生参照输出（GB/T 锚定链）。
    let circ = sm3_compress::build_compress(&block);
    let expect = plonkish_sm2_probe::sm3_native_ref::compress(
        &plonkish_sm2_probe::sm3_native_ref::IV,
        &block,
    );
    for k in 0..8 {
        let want = <FpSM2 as From<u64>>::from(expect[k] as u64);
        assert_eq!(circ.instances[0][k], want, "实例 {k} ≠ 原生参照（装配漂移）");
    }
    println!(
        "[tally] rows=2^{}={} advice_cols={} preprocess_polys={} constraints={}",
        sm3_compress::K,
        sm3_compress::ROWS,
        circ.advice.len(),
        circ.info.preprocess_polys.len(),
        circ.info.constraints.len()
    );
    println!(
        "实例 V'[0..8]（native 参照锚定）：{}",
        expect.iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>().join(" ")
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
        "== B4 OK: SM3 单块压缩全电路（{} 行 / {} 列 / {} 约束）end-to-end VERIFY over FpSM2 ==",
        sm3_compress::ROWS,
        circ.advice.len(),
        circ.info.constraints.len()
    );
}
