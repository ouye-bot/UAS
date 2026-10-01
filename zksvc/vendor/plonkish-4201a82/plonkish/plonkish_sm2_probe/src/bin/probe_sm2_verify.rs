//! 簇E 探针：SM2 验签体完整电路在透明 SNARK 栈
//! （HyperPlonk + Basefold<FpSM2,Sm3>）上的端到端计量。
//!
//! 两档（簇I 扩档，环境变量选档）：
//!   - 默认 = standalone 验签体（`assemble_sm2_verify`，16,554 约束 / 环 534）；
//!   - `ZANCHOR=1` = merged 验签体+Z_U 两体段（`assemble_show_z_merged`，
//!     138,004 约束 / 环 958 / 实例面 20 —— 簇H 主电路，Show 核心闭环形态）；
//!   - `ZANCHOR=2` = 簇J T1 全语句 (S1)–(S5)（`assemble_full_statement`，
//!     225,175 约束 / 环 1,957 / 实例面 19 —— E12 收官态，e2e 服务器档）。
//!
//! 与 `probe_basefold.rs`（M3c 合成电路扫档）的区别：
//!   - 电路换**真实验签体**（GB/T A.2 权威向量装配，含复制环）；
//!   - 正确性档 reps=16（协议档 402 另测；承 b4-v2 e2e 的内存纪律）；
//!   - 输出四元组 + `[pcs-query-census]`（开口乘数定律的离线普查：
//!     Σ 各非 cur (列,|d|) 对 ×2^d 即验证方读入单元数的结构下界，
//!     口径同 [[pcs-evals-multiplicity-law]] 的 run13 普查）。
//!
//! 跑法（机器护栏必挂）：
//!   powershell -File M3_probe/memwatch.ps1 -AbortMB 6500 &
//!   RAYON_NUM_THREADS=4 cargo +nightly-x86_64-pc-windows-msvc run --release \
//!     -p plonkish_sm2_probe --bin probe_sm2_verify [-- features=env ZANCHOR=1]
//!   （merged 档：ZANCHOR=1 cargo run …）

use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit, PlonkishCircuitInfo},
    pcs::multilinear::{Basefold, BasefoldExtParams},
    util::{
        hash::Sm3,
        transcript::{InMemoryTranscript, SM3Transcript},
    },
    Error,
};
use plonkish_sm2_probe::{sm2_verify_assemble::a2_inputs, FpSM2};
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::BTreeSet, io::Cursor, time::Instant};

/// 正确性档规格（reps=16）。
#[derive(Debug)]
pub struct VerifySpec;
impl BasefoldExtParams for VerifySpec {
    fn get_reps() -> usize {
        // R3-P1R2 中间档锚点：REPS 环境变量覆盖（未设=16 正确性档，语义零变化；
        // 内存∝reps×列三点线性定律 ⟹ 高档必挂 memwatch 看门狗）。
        std::env::var("REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(16)
    }
    fn get_rate() -> usize {
        // T1.2 码率重参数化 spike（D16，2026-09-01）：LOG_RATE 环境变量覆盖
        //（未设=1，现行码率 1/2 语义零变化——D1 merged 138,010 逐字节锚保护）。
        // LOG_RATE=3 即码率 1/8：引理 7 前提组带余量满足（ΔC_d=0.728 已发表
        // Table 1 [文献]，处置表 §二E3）；AES random 码表对 rate 通用
        //（lg_n=rate+log2(poly_size)，basefold.rs:2671 [实测:grep]）。
        std::env::var("LOG_RATE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1)
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

type Pcs = Basefold<FpSM2, Sm3, VerifySpec>;
type Pb = HyperPlonk<Pcs>;
type T = SM3Transcript<Cursor<Vec<u8>>>;

/// 裸部件 → PlonkishCircuit 适配器（Sm3V2Circuit 同款）。
#[derive(Clone, Debug)]
struct Sm2VerifyCircuit {
    info: PlonkishCircuitInfo<FpSM2>,
    advice: Vec<Vec<FpSM2>>,
    instances: Vec<Vec<FpSM2>>,
}

impl PlonkishCircuit<FpSM2> for Sm2VerifyCircuit {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<FpSM2>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<FpSM2>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<FpSM2>] {
        &self.instances
    }
    fn synthesize(&self, round: usize, challenges: &[FpSM2]) -> Result<Vec<Vec<FpSM2>>, Error> {
        assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
        Ok(self.advice.clone())
    }
}

fn main() {
    // 协议段的 setup 对深表达式递归求值，默认 1MB 主线程栈在本电路规模下
    // STATUS_STACK_OVERFLOW（run2 实测）。挪到 256MB 栈的工作线程执行——
    // 纯运行期容器，语义零改动；根因位点待 debug 档定位后回填勘误。
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(run)
        .expect("起 256MB 栈工作线程失败");
    match child.join() {
        Ok(()) => {}
        Err(boxed) => std::panic::resume_unwind(boxed),
    }
}

fn run() {
    // 簇I 扩档：ZANCHOR=1 ⟹ merged 形态（验签体 + Z_U 两体段，138,004 约束
    // / K=12 / 复制环 958 条）；默认档保持 standalone 验签体（16,554 / K=12
    // / 534 条）。端到端流程（census/ring-audit/协议）两档完全共用。
    let zanchor = std::env::var("ZANCHOR").ok();
    let (e, r, s, pax, pay) = a2_inputs();
    let (asm, tag) = match zanchor.as_deref() {
        // 簇J T1 全语句档：见证构造器 = E12 witness_from（模块级 pub，e2e 复用）。
        Some("2") => {
            let mut id32 = [0u8; 32];
            id32[..16].copy_from_slice(plonkish_sm2_probe::sm2_z_anchor::DEFAULT_ID);
            let w = plonkish_sm2_probe::sm2_full_statement_assemble::witness_from(
                [0x0B0B, 0, 0, 0x0A0A],
                id32,
                [0x11, 0, 0, 0x22],
            );
            (
                plonkish_sm2_probe::sm2_full_statement_assemble::assemble_full_statement(&w),
                "t1-full(S1–S6)",
            )
        }
        Some(_) => {
            let id: &[u8] = plonkish_sm2_probe::sm2_z_anchor::DEFAULT_ID;
            let blocks = plonkish_sm2_probe::sm2_z_anchor::z_u_blocks(id, &pax, &pay);
            let iv2 = plonkish_sm2_probe::sm2_z_anchor::z_u_prelude_state(id);
            (
                plonkish_sm2_probe::sm2_verify_assemble::assemble_show_z_merged(
                    e, r, s, pax, pay, &blocks[2], &blocks[3], &iv2,
                ),
                "merged(验签体+Z_U)",
            )
        }
        None => (
            plonkish_sm2_probe::sm2_verify_assemble::assemble_sm2_verify(e, r, s, pax, pay),
            "standalone(验签体)",
        ),
    };
    let circuits = Sm2VerifyCircuit {
        info: asm.info.clone(),
        advice: asm.advice.clone(),
        instances: asm.instances.clone(),
    };
    let nv = asm.info.k;
    println!("== 簇E probe: SM2 verify body on transparent SNARK (BaseFold/SM3) ==");
    println!(
        "[档位 {tag}] 总约束={} advice列={} 选择器族={} 预处理={} 复制环={} 实例数={}",
        asm.info.constraints.len(),
        asm.advice.len(),
        asm.num_selectors,
        asm.info.preprocess_polys.len(),
        asm.info.permutations.len(),
        asm.instances[0].len()
    );

    // ── [pcs-query-census] 开口乘数普查（离线、确定性、不依赖后端钩子）──
    let mut pairs: BTreeSet<(usize, i64)> = BTreeSet::new();
    for c in &circuits.info.constraints {
        for q in c.used_query() {
            pairs.insert((q.poly(), q.rotation().0 as i64));
        }
    }
    let mut by_d: std::collections::BTreeMap<i64, usize> = std::collections::BTreeMap::new();
    for (_, rot) in &pairs {
        *by_d.entry(rot.abs()).or_insert(0) += 1;
    }
    let units: u128 = by_d
        .iter()
        .filter(|(&d, _)| d > 0)
        .map(|(&d, &n)| n as u128 * 1u128 << d)
        .sum();
    println!(
        "[pcs-query-census] (列,|d|)桶={{ {:?} }} 去重对={} cur对={} 非cur读入单元Σn_d·2^d={}",
        by_d.iter().map(|(d, n)| format!("{d}:{n}")).collect::<Vec<_>>().join(" "),
        pairs.len(),
        by_d.get(&0).copied().unwrap_or(0),
        units
    );

    // ── [edge-table] R1-v3b 纸面审计：按 rot 分组输出非 cur 查询的 advice
    // 局部列连续段（实证边表，Builder q() 登记聚合计数）。连续段 ≈ 一条
    // (激活点→家点) 读边：列数 = 车道宽，count = 逐列约束引用次数。
    {
        let mut by_rot: std::collections::BTreeMap<i64, Vec<(usize, usize)>> =
            std::collections::BTreeMap::new();
        for &((local, r), cnt) in &asm.q_edges {
            by_rot.entry(r).or_default().push((local, cnt));
        }
        for (r, mut cols) in by_rot {
            cols.sort_unstable();
            // 连续段压缩："a..=b(n列,引用m)"，段内 count 取 min..max
            let mut segs: Vec<String> = Vec::new();
            let mut i = 0;
            while i < cols.len() {
                let mut j = i;
                while j + 1 < cols.len() && cols[j + 1].0 == cols[j].0 + 1 {
                    j += 1;
                }
                let lo = cols[i..=j].iter().map(|(_, c)| c).min().unwrap();
                let hi = cols[i..=j].iter().map(|(_, c)| c).max().unwrap();
                let cnt = if lo == hi { format!("{lo}") } else { format!("{lo}..{hi}") };
                segs.push(format!(
                    "{}..={}(n={},引{cnt})",
                    cols[i].0,
                    cols[j].0,
                    j - i + 1
                ));
                i = j + 1;
            }
            println!("[edge-table] rot={r:>3} 段={}", segs.join(" "));
        }

        // ── [edge-at] 每条边采样 3 个引用约束，解码 at 行（选择器激活点秩）
        //    ⟹ (at 秩 → 读边) 的机械归因。poly 号语义：0=实例，1..=ns
        //    预处理（选择器），其余 advice[p-1-ns]。at = 样本约束 cur 查询中
        //    选择器 poly 的非零点（激活点集；共享家族取代表首点）。──
        let inv_rank = plonkish_sm2_probe::sm3_compress::rank_inverse(); // 秩→点
        let mut pt2rk = vec![usize::MAX; plonkish_sm2_probe::sm3_compress::ROWS];
        for (rk, &p) in inv_rank.iter().enumerate() {
            if p < pt2rk.len() {
                pt2rk[p] = rk;
            }
        }
        let ns = asm.num_selectors;
        let zero = <plonkish_sm2_probe::FpSM2 as ff::Field>::ZERO;
        let edge_set: std::collections::HashSet<(usize, i64)> =
            asm.q_edges.iter().map(|((l, r), _)| (*l, *r)).collect();
        let mut samples: std::collections::BTreeMap<(usize, i64), Vec<usize>> =
            std::collections::BTreeMap::new();
        for (ci, c) in circuits.info.constraints.iter().enumerate() {
            for q in c.used_query() {
                let (p, r) = (q.poly(), q.rotation().0 as i64);
                if r != 0 && p > ns + 1 && edge_set.contains(&(p - 1 - ns, r)) {
                    let e = samples.entry((p - 1 - ns, r)).or_default();
                    if e.len() < 3 && !e.contains(&ci) {
                        e.push(ci);
                    }
                }
            }
        }
        // (at 秩 → 读边) 汇总：先按 rot 分组做**列段压缩**，每段取中位列的
        // 样本约束解码 at（共享家族同段同 at）。
        let mut by_rot: std::collections::BTreeMap<i64, Vec<usize>> =
            std::collections::BTreeMap::new();
        for ((local, r), _) in &samples {
            by_rot.entry(*r).or_default().push(*local);
        }
        println!("[edge-at] rot → 列段 → at 秩（样例约束号）:");
        for (r, mut locals) in by_rot {
            locals.sort_unstable();
            locals.dedup();
            let mut segs: Vec<String> = Vec::new();
            let mut i = 0;
            while i < locals.len() {
                let mut j = i;
                while j + 1 < locals.len() && locals[j + 1] == locals[j] + 1 {
                    j += 1;
                }
                let mid = locals[(i + j) / 2];
                let cis = samples.get(&(mid, r)).expect("段中位列必有样本");
                let mut ats: Vec<i64> = Vec::new();
                for q in circuits.info.constraints[cis[0]].used_query() {
                    let p = q.poly();
                    if q.rotation().0 == 0 && p >= 1 && p <= ns + 1 {
                        for (ptc, v) in circuits.info.preprocess_polys[p - 1].iter().enumerate() {
                            if *v != zero {
                                ats.push(pt2rk[ptc] as i64);
                            }
                        }
                    }
                }
                ats.sort_unstable();
                ats.dedup();
                let adisp = if ats.len() <= 4 {
                    ats.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
                } else {
                    format!("{}..{}(共{})", ats[0], ats[ats.len() - 1], ats.len())
                };
                segs.push(format!(
                    "{}..={}(n={},at[{}],#{})",
                    locals[i],
                    locals[j],
                    j - i + 1,
                    adisp,
                    cis[0]
                ));
                i = j + 1;
            }
            println!("[edge-at] rot={r:>3}: {}", segs.join("  "));
        }
    }

    // 地标点解码（点值 → 秩）：帮环审计把成员坐标翻译成角色。
    // 🔴 方向勘误（2026-08-31）：rank_inverse = 秩→点，点→秩须反转建 pt2rk
    //    （本文件上方 census 解码同款先例；首版 inv[pt] 输出的是错位值）。
    {
        let inv = plonkish_sm2_probe::sm3_compress::rank_inverse();
        let mut lm_pt2rk = vec![usize::MAX; plonkish_sm2_probe::sm3_compress::ROWS];
        for (rk, &p) in inv.iter().enumerate() {
            if p < lm_pt2rk.len() {
                lm_pt2rk[p] = rk;
            }
        }
        println!("[landmarks] pt→秩:");
        for (name, pt) in plonkish_sm2_probe::sm2_verify_assemble::landmark_points() {
            println!("    {name}: pt{pt} 秩{}", lm_pt2rk[pt]);
        }
    }

    // ── 环取值一致性审计（mock 盲区的前置自检；不等环 ⟹ 后端积论证必炸）──
    let bad_rings =
        plonkish_sm2_probe::sm3_compress::audit_ring_values(&circuits.info, &circuits.advice);
    println!("[ring-audit] {} 条环取值不一致", bad_rings.len());
    for (rid, groups) in bad_rings.iter().take(8) {
        println!("  ring#{rid}: {}", groups.join(" | "));
    }
    if !bad_rings.is_empty() {
        panic!(
            "[ring-audit] {} 条复制环成员值不相等 —— 积论证闭合失败根因",
            bad_rings.len()
        );
    }

    // 轻量档：只做装配级普查（蓝图 §六 开口预算回填），不跑协议。
    if std::env::var("CENSUS_ONLY").is_ok() {
        println!("== census-only：跳过协议端到端 ==");
        return;
    }

    // ── 协议端到端 ──
    let t0 = Instant::now();
    let param =
        Pb::setup(&circuits.info, StdRng::seed_from_u64(0x5317_0001u64 ^ nv as u64)).unwrap();
    let t_setup = t0.elapsed();

    let t0 = Instant::now();
    let (pp, vp) = Pb::preprocess(&param, &circuits.info).unwrap();
    let t_pre = t0.elapsed();

    // PROOF_LOAD=路径 ⟹ 分相架构的验证侧：完全跳过证明相（113GB 级证明在单进程
    // 内重证会复现 prove 峰值 RSS），直接从文件读入证明仅做验证；prove 时间不打印。
    let load_path = std::env::var("PROOF_LOAD").ok();
    let (proof, t_prove) = if let Some(lp) = &load_path {
        (std::fs::read(lp).expect("proof load read"), std::time::Duration::ZERO)
    } else {
        let t0 = Instant::now();
        let proof = {
            let mut transcript = T::new(());
            Pb::prove(&pp, &circuits, &mut transcript, StdRng::seed_from_u64(0x5317_0002)).unwrap();
            transcript.into_proof()
        };
        (proof, t0.elapsed())
    };

    // #13/ℓ448 消融工具（ablation 分支）：PROOF_DUMP=路径 ⟹ 证明相完成即落盘退出
    //（独立验证进程以 PROOF_LOAD 读回——113GB 级证明的部署架构：证明与验证分进程、
    //  证明经页缓存常驻，避免单进程内交换读放大）。
    if let Ok(dump_path) = std::env::var("PROOF_DUMP") {
        // SWAP_CLEAN=1 ⟹ dump 前释放 swap（证明相完成后中间量已析出，swap 页全部
        // 回驻内存 <物理容量；腾出的磁盘供证明文件写入——同盘 swap+dump 二选一的空间约束）。
        if std::env::var("SWAP_CLEAN").is_ok() {
            let _ = std::process::Command::new("swapoff").arg("-a").status();
            let _ = std::fs::remove_file("/root/swapfile");
            let _ = std::fs::remove_file("/root/swapfile2");
        }
        let t0 = Instant::now();
        std::fs::write(&dump_path, proof.as_slice()).expect("proof dump write");
        println!(
            "  nv={nv}  setup={:.2}s  preprocess={:.2}s  prove={:.2}s  proof={} B  DUMPED={} ({} s)",
            t_setup.as_secs_f64(),
            t_pre.as_secs_f64(),
            t_prove.as_secs_f64(),
            proof.len(),
            dump_path,
            t0.elapsed().as_secs_f64()
        );
        println!("== PROVE+DUMP OK（{tag}）[实测] ==");
        return;
    }

    let proof_len = proof.len();
    let peak_before_verify = peak_rss_bytes();
    let t0 = Instant::now();
    let result = if plonkish_backend::util::transcript::a3_stream::enabled() {
        // A3 两遍流式档(PCS_VERIFY_STREAM=1):零拷贝借用 + 线程局部回放源注册;
        // 峰值 RSS 不再含 from_proof 的整份 to_vec 复制与 Q·E 条个体路径的整体常驻。
        let src = std::sync::Arc::new(proof);
        plonkish_backend::util::transcript::a3_stream::register(src.clone());
        let r = {
            let mut tr = plonkish_backend::util::transcript::SM3StreamTranscript::new(&src[..]);
            Pb::verify(&vp, &circuits.instances, &mut tr, StdRng::seed_from_u64(0x5317_0003))
        };
        plonkish_backend::util::transcript::a3_stream::clear();
        r
    } else {
        let mut transcript = T::from_proof((), proof.as_slice());
        Pb::verify(&vp, &circuits.instances, &mut transcript, StdRng::seed_from_u64(0x5317_0003))
    };
    let t_verify = t0.elapsed();

    assert_eq!(result, Ok(()), "[簇E] verify FAILED");
    println!(
        "  nv={nv}  setup={:.2}s  preprocess={:.2}s  prove={:.2}s  verify={:.3}s  proof={} B  stream={}  peak_rss_before_verify={}  peak_rss_after_verify={}",
        t_setup.as_secs_f64(),
        t_pre.as_secs_f64(),
        t_prove.as_secs_f64(),
        t_verify.as_secs_f64(),
        proof_len,
        plonkish_backend::util::transcript::a3_stream::enabled() as u8,
        fmt_mb(peak_before_verify),
        fmt_mb(peak_rss_bytes())
    );
    println!("== VERIFY OK: A.2 正例（{tag}）端到端贯通 [实测] ==");
}

fn fmt_mb(b: Option<u64>) -> String {
    match b {
        Some(b) => format!("{:.1}MB", b as f64 / 1048576.0),
        None => "n/a".to_string(),
    }
}

/// 进程峰值常驻(VmHWM 等价;A3 流式档 OFF/ON 对照用):Linux 读 /proc/self/status 的 VmHWM,
/// Windows 经 K32GetProcessMemoryInfo 的 PeakWorkingSetSize;其他平台 None。
fn peak_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = s.lines().find(|l| l.starts_with("VmHWM:"))?;
        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct ProcessMemoryCounters {
            cb: u32,
            page_fault_count: u32,
            peak_working_set_size: usize,
            working_set_size: usize,
            quota_peak_paged_pool_usage: usize,
            quota_paged_pool_usage: usize,
            quota_peak_non_paged_pool_usage: usize,
            quota_non_paged_pool_usage: usize,
            pagefile_usage: usize,
            peak_pagefile_usage: usize,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(h: isize, pmc: *mut ProcessMemoryCounters, cb: u32) -> i32;
        }
        let mut pmc: ProcessMemoryCounters = unsafe { std::mem::zeroed() };
        pmc.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) };
        if ok != 0 {
            Some(pmc.peak_working_set_size as u64)
        } else {
            None
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}
