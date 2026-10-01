//! 阶段 1 · 1.1b-b4（管线化 v2）：SM3 **单块压缩函数全电路** —— 复制环传输形态
//! （值列中继环 + 本地 link 重分解），单证明满足后端旋转预算。
//!
//! 相对 probe_sm3_compress（v1 秩窗口布局）：v2 把跨条带引用全部改为「远读处
//! 本地复制词 + 复制环」，一切约束查询距离 ≤ K=11；公开语句面扩为
//! 16 消息字 + 8 摘要字 = [`sm3_compress_v2::ord::TOTAL`] 个实例值。
//! 复制等式的健全性由后端积论证承担（取证见 sm3_perm_smoke 负例），
//! 本 bin 只走诚实路径出计时。
//!
//! 口径红线：v2 约束数 ≠ v1 30,480 ≠ R1CS 31,295，三者电路语义不同层级。
//!
//! 跑法：cargo +nightly run --release -p plonkish_sm2_probe --bin probe_sm3_compress_v2

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

/// BaseFold 扩展参数（与全部探针一致勿改）。
#[derive(Debug)]
pub struct BasefoldSpec;
impl BasefoldExtParams for BasefoldSpec {
    // 2026-08-27: reps doubles as num_verifier_queries inside Basefold --
    // and this fork's batch_open re-authenticates EVERY opened polynomial
    // at EVERY verifier query (basefold.rs batch_open: query×eval double
    // loop), so ram/proof cost scales as reps × #open-evals. At b4's 2169
    // advice columns (#evals=34,962) reps=402 ⇒ 14M merkle paths ≈ >10 GB
    // -- measured abort at 8.75 GB private before transcript streaming even
    // began. Env override B4_REPS lets us probe the cliff empirically while
    // keeping the historical default byte-identical.
    fn get_reps() -> usize {
        std::env::var("B4_REPS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(402)
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

type Pcs = Basefold<FpSM2, Sm3, BasefoldSpec>;
type Pb = HyperPlonk<Pcs>;
type T = SM3Transcript<Cursor<Vec<u8>>>;

fn main() {
    // 置换论证 + 6 万约束全电路首次在本栈走通 prove 路径；Windows 主线程默认
    // 栈 1MB 不够（首跑 STATUS_STACK_OVERFLOW）——探针侧起大栈工作线程，
    // 后端代码零改动。预留 128MB（实际递归深度需几 MB 量级；1GB 预留给
    // 低内存机器添压，2026-08-27 护栏化后收缩）。
    let child = std::thread::Builder::new()
        .stack_size(128 * 1024 * 1024)
        .spawn(real_main)
        .expect("spawn 计时线程");
    let _ = child.join();
}

fn real_main() {
    use plonkish_sm2_probe::sm3_compress_v2;

    let msg = b"abc";
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
    let mut block = [0u8; 64];
    block.copy_from_slice(&padded);

    println!(
        "== 1.1b-b4 v2：SM3 单块压缩（复制环传输）over FpSM2（HyperPlonk + BaseFold + SM3 transcript）=="
    );
    println!("消息块 = \"abc\" 的标准填充单块（{:#02x}..{:02x}，64 B）", block[0], block[63]);

    // 装配 + 出厂自检：24 个实例（16 消息 + 8 摘要）必须逐字等于原生参照。
    let circ = sm3_compress_v2::build_compress_v2(&block);
    let digest = plonkish_sm2_probe::sm3_native_ref::compress(
        &plonkish_sm2_probe::sm3_native_ref::IV,
        &block,
    );
    for k in 0..8 {
        let want = <FpSM2 as From<u64>>::from(digest[k] as u64);
        assert_eq!(circ.instances[0][sm3_compress_v2::ord::BASE_DG + k], want);
    }
    println!(
        "[tally] rows=2^{}={} advice_cols={} preprocess_polys={} constraints={} \
         perm_cycles={} cycle_cells={}",
        sm3_compress::K,
        sm3_compress::ROWS,
        circ.advice.len(),
        circ.info.preprocess_polys.len(),
        circ.info.constraints.len(),
        circ.info.permutations.len(),
        circ.relay_census.iter().sum::<usize>()
    );

    let circuit_info = circ.circuit_info().unwrap();
    let instances: Vec<Vec<FpSM2>> = circ.instances().to_vec();

    let t0 = Instant::now();
    eprintln!("[phase] setup...");
    let param = Pb::setup(&circuit_info, StdRng::seed_from_u64(0x5EED)).unwrap();
    let t_setup = t0.elapsed();

    let t0 = Instant::now();
    eprintln!("[phase] preprocess...");
    let (pp, vp) = Pb::preprocess(&param, &circuit_info).unwrap();
    let t_pre = t0.elapsed();

    let t0 = Instant::now();
    eprintln!("[phase] prove...");
    let proof = {
        let mut transcript = T::new(());
        Pb::prove(&pp, &circ, &mut transcript, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
        transcript.into_proof()
    };
    let t_prove = t0.elapsed();

    let t0 = Instant::now();
    eprintln!("[phase] verify...");
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
        "== B4-v2 OK: SM3 单块压缩复制环版（{} 行 / {} 列 / {} 约束 / {} 环 {} 格）\
         单证明 end-to-end VERIFY over FpSM2 ==",
        sm3_compress::ROWS,
        circ.advice.len(),
        circ.info.constraints.len(),
        circ.info.permutations.len(),
        circ.relay_census.iter().sum::<usize>()
    );
}
