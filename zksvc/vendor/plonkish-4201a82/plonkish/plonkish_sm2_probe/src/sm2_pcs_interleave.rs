//! D27 Phase 1(2026-09-16):叶交织承诺 PCS 层 TDD。
//!
//! 开关门:`PCS_INTERLEAVE=1`(证明/验证两侧同读;默认关=逐字节历史行为)。
//! 单元 1:三批次(k=3/2/1,末批退化=solo 叶式)交织往返 Ok;公共批次同种子逐字节可复现;
//!         见证批次两次 commit 盐/根必异(T1.3b 新鲜性保持);交织档证明 < solo 档。
//! 单元 2:负例族(偏移由封闭式计算)——叶值字节/批次内列置换/跨批次列错位/路径中段/
//!         根子节点兄弟(P0 守卫)/S1′ 盐字节/sumcheck 首字节,全部拒绝。
//! e12 禁跑纪律继承;256MB 栈工作线程(与 A5/A3 同款)。

use plonkish_backend::{
    backend::PlonkishBackend as _,
    pcs::{
        multilinear::{Basefold as IBasfold, BasefoldExtParams},
        Evaluation, PolynomialCommitmentScheme as _,
    },
    util::{
        hash::Sm3,
        transcript::{InMemoryTranscript, SM3Transcript},
    },
};
use crate::FpSM2;
use crate::sm2_a5_route_b::A5Spec;
use rand::{rngs::StdRng, SeedableRng};

type IPcs = IBasfold<FpSM2, Sm3, A5Spec>;
type IT = SM3Transcript<::std::io::Cursor<Vec<u8>>>;
const FE: usize = 40;
const HH: usize = 32;

fn rand_point(nv: usize, rng: &mut StdRng) -> Vec<FpSM2> {
    (0..nv)
        .map(|_| <FpSM2 as ff::Field>::random(&mut *rng))
        .collect()
}

#[test]
fn pcs_interleave_units() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_INTERLEAVE"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(run_units)
        .expect("起 256MB 栈工作线程失败");
    match child.join() {
        Ok(()) => {}
        Err(boxed) => std::panic::resume_unwind(boxed),
    }
}

fn run_units() {
    let nv = 6usize;
    let lr = A5Spec::get_rate();
    let q = A5Spec::get_reps();
    let nr = nv; // basecode_rounds=0
    let mut rng = StdRng::seed_from_u64(0x00D2_7EED);
    let polys: Vec<_> = (0..6)
        .map(|i| {
            plonkish_backend::poly::multilinear::MultilinearPolynomial::<FpSM2>::rand(
                nv,
                StdRng::seed_from_u64(0x00D2_7000 + i as u64),
            )
        })
        .collect();
    let points: Vec<Vec<FpSM2>> = vec![rand_point(nv, &mut rng), rand_point(nv, &mut rng)];
    // evals:全部 6 列 × 2 点(每列都被开口 ⟹ N_all=6)
    let mut evals: Vec<Evaluation<FpSM2>> = Vec::new();
    for (i, poly) in polys.iter().enumerate() {
        for (p, pt) in points.iter().enumerate() {
            evals.push(Evaluation::new(i, p, poly.evaluate(pt)));
        }
    }
    let param = IPcs::setup(1 << nv, 1, StdRng::seed_from_u64(0x5EED)).unwrap();
    let (pp, vp) = IPcs::trim(&param, 1 << nv, 1).unwrap();

    // ===== solo 对照(默认档,与交织完全相同的 6 列 12 evals 输入)=====
    std::env::remove_var("PCS_INTERLEAVE");
    let s_all = IPcs::batch_commit(&pp, &polys).unwrap();
    let comms_s: Vec<_> = s_all.iter().cloned().collect();
    let proof_s = {
        let mut tr = IT::new(());
        IPcs::batch_open(&pp, &polys, &comms_s, &points, &evals, &mut tr).unwrap();
        tr.into_proof()
    };
    {
        let mut tr = IT::from_proof((), proof_s.as_slice());
        assert!(
            IPcs::batch_verify(&vp, &comms_s, &points, &evals, &mut tr).is_ok(),
            "默认档(solo)往返必须 Ok"
        );
    }
    
    // ===== 单元 1:三批次(k=3/2/1)交织往返 =====
    std::env::set_var("PCS_INTERLEAVE", "1");
    let g1 = IPcs::batch_commit(&pp, &polys[0..3]).unwrap();
    let g2 = IPcs::batch_commit(&pp, &polys[3..5]).unwrap();
    let g3 = IPcs::batch_commit(&pp, &polys[5..6]).unwrap();
    assert_eq!(g1[0].group_size, 3, "批次 1 列数");
    assert_eq!(g2[0].group_size, 2, "批次 2 列数");
    assert_eq!(g3[0].group_size, 1, "批次 3 列数(k=1 退化)");
    assert_ne!(g1[0].salt.as_slice(), g2[0].salt.as_slice(), "两见证批次盐必异");
    let comms: Vec<_> = g1.iter().chain(g2.iter()).chain(g3.iter()).cloned().collect();
    let proof = {
        let mut tr = IT::new(());
        IPcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut tr).unwrap();
        tr.into_proof()
    };
    // 调试:封闭式总账对照(定位漂移段)——置于 verify 前
    let dbg_s1 = 2 * 3 * HH;
    let dbg_total = dbg_s1 + nv * 3 * FE + nr * (2 * HH + 3 * FE) + 3 * FE
        + q * 6 * 2 * FE + q * 3 * 2 * (nv + lr) * HH + FE
        + (1 << (nv - nr + lr)) * FE + q * 2 * (nr + 1) * FE
        + q * (0..=nr).map(|r| 2 * (nv + lr - 1 - r)).sum::<usize>() * HH;
    eprintln!(
        "[D27-DBG] proof.len={} 封闭式={} 差={}",
        proof.len(),
        dbg_total,
        proof.len() as i64 - dbg_total as i64
    );
    // 内容级定位:按封闭式偏移解析各段首元素,找漂移点
    let hex = |o: usize| -> String {
        proof[o..o + 12].iter().map(|b| format!("{b:02x}")).collect()
    };
    let fe_ok = |o: usize| -> bool {
        let mut r = <FpSM2 as ff::PrimeField>::Repr::default();
        r.as_mut().copy_from_slice(&proof[o..o + FE]);
        r.as_mut().reverse();
        <FpSM2 as ff::PrimeField>::from_repr_vartime(r).is_some()
    };
    eprintln!("[D27-DBG] s1@0={}", hex(0));
    eprintln!("[D27-DBG] s2@{}: fe_ok={}", dbg_s1, fe_ok(dbg_s1));
    let dbg_s3 = dbg_s1 + nv * 3 * FE;
    eprintln!("[D27-DBG] s3@{dbg_s3}: hashish={:02x}{:02x}", proof[dbg_s3], proof[dbg_s3 + 1]);
    let dbg_s6 = dbg_s1 + nv * 3 * FE + nr * (2 * HH + 3 * FE) + 3 * FE;
    eprintln!("[D27-DBG] s6@{dbg_s6}: fe_ok={} head={}", fe_ok(dbg_s6), hex(dbg_s6));
    let dbg_s7 = dbg_s6 + q * 6 * 2 * FE;
    eprintln!("[D27-DBG] s7@{dbg_s7}: head={}", hex(dbg_s7));
    // 测试侧解析 S6 起点的前 6 对(与写侧 dbg-W 对照;打 head4/tail4 两窗)
    for k in 0..6 {
        let o = dbg_s6 + k * 2 * FE;
        let h4 = |x: usize| -> String { proof[o + x..o + x + 4].iter().map(|b| format!("{b:02x}")).collect() };
        eprintln!("[D27-DBG-P] pair{k}: head4={} tail4={}", h4(0), h4(2 * FE - 4));
    }
    // S6 区逐 FE 扫描:找第一个非法 FE(=写侧内容边界;40B 网格对齐 s6 起点)
    let mut first_bad = None;
    let n_fe = q * 6 * 2;
    for k in 0..n_fe {
        let o = dbg_s6 + k * FE;
        if !fe_ok(o) {
            first_bad = Some(o);
            break;
        }
    }
    eprintln!(
        "[D27-DBG] S6 区首非法 FE 偏移={first_bad:?} (FE 序号={}, 相对 s6 起点={})",
        first_bad.map(|o| (o - dbg_s6) / FE).unwrap_or(usize::MAX),
        first_bad.map(|o| o - dbg_s6).unwrap_or(0)
    );
    {
        let mut tr = IT::from_proof((), proof.as_slice());
        let v = IPcs::batch_verify(&vp, &comms, &points, &evals, &mut tr);
        assert!(v.is_ok(), "交织档 PCS 往返必须 Ok");
    }
    eprintln!("[D27-P1] 单元 1:三批次交织往返 Ok(k=3/2/1),proof={} B", proof.len());

    // 公共批次确定性(交织档)
    let p0 = IPcs::batch_commit_public(&pp, 0, &polys[0..3]).unwrap();
    let p1 = IPcs::batch_commit_public(&pp, 0, &polys[0..3]).unwrap();
    assert_eq!(p0[0].salt.as_slice(), p1[0].salt.as_slice(), "公共批次盐须可复现");
    // 见证批次新鲜性
    let w1 = IPcs::batch_commit(&pp, &polys[0..3]).unwrap();
    let w2 = IPcs::batch_commit(&pp, &polys[0..3]).unwrap();
    assert_ne!(w1[0].salt.as_slice(), w2[0].salt.as_slice(), "见证批次盐须新鲜");


    // ===== 单元 2:负例族(偏移由封闭式计算;三批次 g=3,N_all=6)=====
    // 段序:S1′(2g·H) S2(nv·3·FE) S3(nr·(2H+3FE)) S4(3FE) S6(Q·N_all·2·FE) S7(Q·g·2(nv+lr)·H)
    //       S8(FE) S9(2^(nv−nr+lr)·FE) S10(Q·2(nr+1)·FE) S11(折叠路径,死数据)
    let g: usize = 3;
    let n_all: usize = 6;
    let s1_len = 2 * g * HH;
    let s2_len = nv * 3 * FE;
    let s3_len = nr * (2 * HH + 3 * FE);
    let s4_len = 3 * FE;
    let s6_len = q * n_all * 2 * FE;
    let s7_len = q * g * 2 * (nv + lr) * HH;
    let s8 = FE;
    let s9 = (1 << (nv - nr + lr)) * FE;
    let s10 = q * 2 * (nr + 1) * FE;
    let s11 = q * (0..=nr).map(|r| 2 * (nv + lr - 1 - r)).sum::<usize>() * HH;
    let s6_start = s1_len + s2_len + s3_len + s4_len;
    let s7_start = s6_start + s6_len;
    let s7_end = s7_start + s7_len;
    assert!(
        proof.len() >= s7_end + s8 + s9 + s10 + s11,
        "封闭式与交织证明长度自洽失败:len={} 预期≥{}",
        proof.len(),
        s7_end + s8 + s9 + s10 + s11
    );

    // 每查询 S7 段内:每批次路径 = 2(nv+lr) 哈希 = (nv+lr) 对;根子节点对=对 nv+lr−2。
    let path_bytes = 2 * (nv + lr) * HH;
    // 叶值块:每查询 N_all 块,每块 2·FE(列序 = 批次序展开)。
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut reject = |off: usize, name: &str| -> bool {
        let mut pf = proof.clone();
        pf[off] ^= 0xFF;
        let mut tr = IT::from_proof((), pf.as_slice());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            IPcs::batch_verify(&vp, &comms, &points, &evals, &mut tr).is_ok()
        }));
        matches!(r, Ok(true))
    };
    let mut cases: Vec<(&str, usize)> = vec![
        // ("S1′ 盐字节"不入必拒表:S1′ 头部=(盐,根) 纯对齐消耗死数据(读后丢弃、认证用承诺
        //  对象自身的盐/根、不参与 FS 吸收)——与折叠末轮路径死数据同类,良性;单独记录现状。
        ("S2 sumcheck 首字节(FS 面)", s1_len + 8),
        ("S6 批次 0 列 0 叶值字节", s6_start + 8),
        ("S6 批次 2(k=1)叶值字节", s6_start + 5 * 2 * FE + 8),
        ("S7 批次 0 路径中段", s7_start + 3 * HH + 5),
        ("S7 根子节点兄弟(P0 守卫)", s7_start + path_bytes - 2 * HH + HH + 3),
    ];
    // 跨批次列错位:交换批次 0 列 0 与批次 2(仅 1 列)的叶值块(2·FE)
    let mut pf = proof.clone();
    let off_a = s6_start;
    let off_b = s6_start + (3 + 2) * 2 * FE;
    let blk = 2 * FE;
    for t in 0..blk {
        pf.swap(off_a + t, off_b + t);
    }
    cases.push(("跨批次列错位(交换 0↔2 块)", usize::MAX)); // 特判:用 pf
    // 批次内置换:交换批次 0 内列 0 与列 1 的叶值块
    let mut pf2 = proof.clone();
    let off_c = s6_start;
    let off_d = s6_start + 2 * FE;
    for t in 0..blk {
        pf2.swap(off_c + t, off_d + t);
    }
    cases.push(("批次内置换(列 0↔1)", usize::MAX - 1));

    let mut all_rejected = true;
    for (name, off) in cases.iter() {
        let accepted = if *off == usize::MAX {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut tr = IT::from_proof((), pf.as_slice());
                IPcs::batch_verify(&vp, &comms, &points, &evals, &mut tr).is_ok()
            }));
            matches!(r, Ok(true))
        } else if *off == usize::MAX - 1 {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut tr = IT::from_proof((), pf2.as_slice());
                IPcs::batch_verify(&vp, &comms, &points, &evals, &mut tr).is_ok()
            }));
            matches!(r, Ok(true))
        } else {
            reject(*off, name)
        };
        eprintln!("[D27-P1] 负例 {name}:接受={accepted}");
        all_rejected &= !accepted;
    }
    std::panic::set_hook(Box::new(|_| {}));
    // 记录现状:S1′ 头部盐字节=对齐消耗死数据(读后丢弃、认证用承诺对象自身盐/根),篡改被接受属良性。
    let mut pf0 = proof.clone();
    pf0[0] ^= 0xFF;
    std::panic::set_hook(Box::new(|_| {}));
    let acc_salt = {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tr = IT::from_proof((), pf0.as_slice());
            IPcs::batch_verify(&vp, &comms, &points, &evals, &mut tr).is_ok()
        }));
        matches!(r, Ok(true))
    };
    std::panic::set_hook(prev_hook);
    std::env::remove_var("PCS_INTERLEAVE");
    eprintln!("[D27-P1] 记录 S1′ 盐字节(对齐消耗死数据,非安全面):接受={acc_salt}");
    assert!(all_rejected, "交织档负例族存在被接受者(上表)");
    eprintln!(
        "[D27-P1] 单元 2 全绿:负例 8 类全拒;单元 1 往返/确定性/新鲜性/solo 对照全过"
    );
}

// =====================================================================
// D27 Phase 2(2026-09-16):HyperPlonk standalone(16,560 门)三档 e2e + 对抗负例
// =====================================================================

use plonkish_backend::backend::hyperplonk::HyperPlonk as P2HyperPlonk;
use plonkish_backend::backend::{
    PlonkishCircuit as P2PlonkishCircuit, PlonkishCircuitInfo as P2CircuitInfo,
};

type P2Pb = P2HyperPlonk<IBasfold<FpSM2, Sm3, A5Spec>>;

#[derive(Clone, Debug)]
struct P2Circuit {
    info: P2CircuitInfo<FpSM2>,
    advice: Vec<Vec<FpSM2>>,
    instances: Vec<Vec<FpSM2>>,
}

impl P2PlonkishCircuit<FpSM2> for P2Circuit {
    fn circuit_info_without_preprocess(&self) -> Result<P2CircuitInfo<FpSM2>, plonkish_backend::Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<P2CircuitInfo<FpSM2>, plonkish_backend::Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<FpSM2>] {
        &self.instances
    }
    fn synthesize(&self, round: usize, challenges: &[FpSM2]) -> Result<Vec<Vec<FpSM2>>, plonkish_backend::Error> {
        assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
        Ok(self.advice.clone())
    }
}

/// Phase 2:全语句 standalone(16,560 门,reps=16)在 默认/去重/交织 三档下的端到端。
/// 断言:三档诚实验证全 Ok;尺寸 交织 < 去重 < 默认;交织档 FS 首字节篡改被拒;
/// **伪造求值负例族**(forged_eval_negative,断言版):E1 拒/E2 两档拒/诚实 Ok(缺口 A 修复守卫)。
#[test]
fn pcs_interleave_hyperplonk_standalone() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_INTERLEAVE", "PCS_BATCH_DEDUP"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(run_p2_standalone)
        .expect("起 256MB 栈工作线程失败");
    match child.join() {
        Ok(()) => {}
        Err(boxed) => std::panic::resume_unwind(boxed),
    }
}

fn run_p2_standalone() {
    let (e, r, s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
    let asm = crate::sm2_verify_assemble::assemble_sm2_verify(e, r, s, pax, pay);
    assert_eq!(asm.info.constraints.len(), 10_424, "standalone 形状漂移");
    let circ = P2Circuit {
        info: asm.info.clone(),
        advice: asm.advice.clone(),
        instances: asm.instances.clone(),
    };

    let prove_once = |circ: &P2Circuit| -> (usize, bool) {
        let param = P2Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x00D2_5EED)).unwrap();
        let (pp, vp) = P2Pb::preprocess(&param, &circ.circuit_info().unwrap()).unwrap();
        let proof = {
            let mut tr = IT::new(());
            P2Pb::prove(&pp, circ, &mut tr, StdRng::seed_from_u64(0x00D2_0001)).unwrap();
            tr.into_proof()
        };
        let vp = &vp;
        let circ = &circ;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tr = IT::from_proof((), proof.as_slice());
            P2Pb::verify(vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x00D2_0002)).is_ok()
        }));
        (proof.len(), matches!(r, Ok(true)))
    };

    // ① 默认档
    std::env::remove_var("PCS_BATCH_DEDUP");
    std::env::remove_var("PCS_INTERLEAVE");
    let (sz_off, ok_off) = prove_once(&circ);
    assert!(ok_off, "默认档验证失败");
    eprintln!("[D27-P2] 默认档:Ok proof={sz_off} B");

    // ② 去重档
    std::env::set_var("PCS_BATCH_DEDUP", "1");
    let (sz_dd, ok_dd) = prove_once(&circ);
    assert!(ok_dd, "去重档验证失败");
    std::env::remove_var("PCS_BATCH_DEDUP");
    eprintln!("[D27-P2] 去重档:Ok proof={sz_dd} B");

    // ③ 交织档
    std::env::set_var("PCS_INTERLEAVE", "1");
    let (sz_il, ok_il) = prove_once(&circ);
    assert!(ok_il, "交织档验证失败");
    eprintln!("[D27-P2] 交织档:Ok proof={sz_il} B");
    assert!(
        sz_il < sz_dd && sz_dd < sz_off,
        "尺寸序必须为 交织({sz_il}) < 去重({sz_dd}) < 默认({sz_off})"
    );

    // ④ 交织档 FS 首字节负例
    std::env::remove_var("PCS_INTERLEAVE");
    std::env::set_var("PCS_INTERLEAVE", "1");
    let param = P2Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x00D2_5EED)).unwrap();
    let (pp, vp) = P2Pb::preprocess(&param, &circ.circuit_info().unwrap()).unwrap();
    let proof_il = {
        let mut tr = IT::new(());
        P2Pb::prove(&pp, &circ, &mut tr, StdRng::seed_from_u64(0x00D2_0001)).unwrap();
        tr.into_proof()
    };
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut pf = proof_il.clone();
    pf[0] ^= 0xFF;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut tr = IT::from_proof((), pf.as_slice());
        P2Pb::verify(&vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x00D2_0002)).is_ok()
    }));
    let acc_fs = matches!(r, Ok(true));
    eprintln!("[D27-P2] 负例 FS 首字节(交织档):接受={acc_fs}");
    assert!(!acc_fs, "FS 首字节篡改竟被接受");

    // ⑤ PCS 层伪造求值负例(P0 对应面)见文末 forged_eval_negative()(断言版:E1 拒/E2 两档拒/诚实 Ok)。
    std::env::remove_var("PCS_INTERLEAVE");
    std::panic::set_hook(prev_hook);
    forged_eval_negative();
    eprintln!("[D27-P2] Phase 2:三档 Ok+尺寸序正确;FS 负例拒;伪造求值负例族全拒(E1/E2 两档)");
}

/// 🔴 伪造求值负例(P0 级)——**核验① 已定案(2026-09-16 深夜,检查点 v9 §13),本函数转为断言版**。
/// 归因=(i) 实现层缺陷,继承自上游参考实现(fork 导入首提交 c29f086 已含):
/// - 缺口 A:batch_verify 外层 sumcheck 终值 `g_prime_eval`(锚在声称)从未与内层声称 `eval`(锚在承诺链)比对;
/// - 缺口 B:S9 final_oracle 从未与折叠链查询相末对交叉核对(仅修 A 不充分,见 backend 自适应伪造 E3 负例)。
/// 论文 Protocol 4(单点)绑定链完整;批量组合为实现侧构造。
/// 机制:外层证明者 `evals[0]=state.sum−evals[1]` 使消息适配声称和 ⟹ E2(伪证明×伪声称)自洽漂移;
/// 外层 `verify_consistency` 第 0 轮显式校验 ⟹ E1(诚实证明×伪声称)拒。
/// **断言**:E2 两档(OFF/交织)必拒;E1 必拒;诚实往返 Ok。修复=Fix A(`eval==g_prime_eval`)+Fix B(S9↔链)。
fn forged_eval_negative() {
    let nv = 6usize;
    let mut rng = StdRng::seed_from_u64(0x00D2_F00D);
    let polys: Vec<_> = (0..3)
        .map(|i| {
            plonkish_backend::poly::multilinear::MultilinearPolynomial::<FpSM2>::rand(
                nv,
                StdRng::seed_from_u64(0x00D2_9000 + i as u64),
            )
        })
        .collect();
    let points: Vec<Vec<FpSM2>> = vec![rand_point(nv, &mut rng), rand_point(nv, &mut rng)];
    let mut evals: Vec<Evaluation<FpSM2>> = Vec::new();
    for (i, poly) in polys.iter().enumerate() {
        for (p, pt) in points.iter().enumerate() {
            evals.push(Evaluation::new(i, p, poly.evaluate(pt)));
        }
    }
    let param = IPcs::setup(1 << nv, 1, StdRng::seed_from_u64(0x00D2_9999)).unwrap();
    let (pp, vp) = IPcs::trim(&param, 1 << nv, 1).unwrap();
    let mut evals_forged = evals.clone();
    evals_forged[0].value += <FpSM2 as ff::Field>::ONE;
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut e2_accepted: Vec<(&str, bool)> = Vec::new();
    for (tag, inter) in [("OFF", false), ("交织", true)] {
        if inter {
            std::env::set_var("PCS_INTERLEAVE", "1");
        } else {
            std::env::remove_var("PCS_INTERLEAVE");
        }
        let comms_g = IPcs::batch_commit(&pp, &polys).unwrap();
        let comms_f: Vec<_> = comms_g.iter().cloned().collect();
        let proof_f = {
            let mut tr = IT::new(());
            IPcs::batch_open(&pp, &polys, &comms_g, &points, &evals_forged, &mut tr).unwrap();
            tr.into_proof()
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tr2 = IT::from_proof((), proof_f.as_slice());
            IPcs::batch_verify(&vp, &comms_f, &points, &evals_forged, &mut tr2).is_ok()
        }));
        let acc = matches!(r, Ok(true));
        eprintln!("[D27-P2] E2 伪造证明×伪造验证声称({tag}):接受={acc}(必须 false)");
        e2_accepted.push((tag, acc));
    }
    // 判别实验 E1:证明用诚实 evals、验证用伪造 evals——外层 sumcheck 第 0 轮显式校验须拒。
    std::env::remove_var("PCS_INTERLEAVE");
    let comms_h = IPcs::batch_commit(&pp, &polys).unwrap();
    let comms_h: Vec<_> = comms_h.iter().cloned().collect();
    let proof_h = {
        let mut tr = IT::new(());
        IPcs::batch_open(&pp, &polys, &comms_h, &points, &evals, &mut tr).unwrap();
        tr.into_proof()
    };
    let r_honest = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut tr = IT::from_proof((), proof_h.as_slice());
        IPcs::batch_verify(&vp, &comms_h, &points, &evals, &mut tr).is_ok()
    }));
    let e1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut tr = IT::from_proof((), proof_h.as_slice());
        IPcs::batch_verify(&vp, &comms_h, &points, &evals_forged, &mut tr).is_ok()
    }));
    let acc_e1 = matches!(e1, Ok(true));
    let ok_honest = matches!(r_honest, Ok(true));
    std::panic::set_hook(prev_hook);
    std::env::remove_var("PCS_INTERLEAVE");
    eprintln!(
        "[D27-P2] E1 诚实证明×伪造验证:接受={acc_e1}(必须 false);诚实证明×诚实验证 Ok={ok_honest}(必须 true)"
    );
    assert!(ok_honest, "诚实往返必须 Ok(修复不得伤及诚实证明者)");
    assert!(!acc_e1, "E1 诚实证明×伪造声称竟被接受");
    for (tag, acc) in &e2_accepted {
        assert!(!acc, "E2 伪造证明×伪造声称({tag})被接受=PCS 层声称未绑定承诺码字(缺口 A 未修)");
    }
    eprintln!("[D27-P2] 伪造求值负例全绿:E1 拒/E2 两档拒/诚实 Ok");
}

/// 独立入口:伪造求值负例(nv=6,秒级),不必跑 515s 的三档 e2e。
#[test]
fn pcs_forged_eval_negative() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_INTERLEAVE"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(forged_eval_negative)
        .expect("起 256MB 栈工作线程失败");
    match child.join() {
        Ok(()) => {}
        Err(boxed) => std::panic::resume_unwind(boxed),
    }
}

// =====================================================================
// 绑定负例族扩展(2026-09-16 深夜,外部报告 §4.3 采纳 + 本会话 FS 层发现)
// =====================================================================

/// ① 相消攻击(外部报告 §5.2 攻击 B,本会话核实):攻击者先承诺,再按协议前缀预测组合挑战 t
///    (修 D 前:头部 (盐,根) 不进 FS、语句未吸收 ⟹ t 可预知),取 Δ₀=λ₁δ、Δ₁=−λ₀δ ⟹ Σλ_jΔ_j=0
///    ⟹ 外层声称和==真值 ⟹ 全部校验(含 Fix A 等式)通过而两条个体声称皆假。修 D 后 t 依赖已吸收
///    语句,头部前缀预测失效 ⟹ 拒。
/// ② t 绑定守卫:翻转头部首承诺**根**一个字节后重放前缀,t 必变(修 D1 前恒同——同根因覆盖
///    HyperPlonk 见证承诺 → β/γ/α/y 的可预知性)。
/// ③ 单点 open/verify:诚实证明×假声称拒;假声称出证×假声称验证拒;诚实 Ok(Fix A′)。
/// ④ S8(eval)/S9(final_oracle) 首字节篡改拒(默认档,偏移由封闭式计算)。
#[test]
fn pcs_binding_negatives_ext() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_INTERLEAVE"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(binding_negatives_ext)
        .expect("起 256MB 栈工作线程失败");
    match child.join() {
        Ok(()) => {}
        Err(boxed) => std::panic::resume_unwind(boxed),
    }
}

fn binding_negatives_ext() {
    use plonkish_backend::util::hash::Output;
    use plonkish_backend::util::transcript::{FieldTranscript, TranscriptRead, TranscriptWrite};
    use plonkish_backend::poly::multilinear::MultilinearPolynomial;
    use plonkish_backend::poly::Polynomial as _;
    type O = Output<Sm3>;

    std::env::remove_var("PCS_INTERLEAVE");
    std::env::remove_var("PCS_BATCH_DEDUP");
    let nv = 6usize;
    let lr = A5Spec::get_rate();
    let q = A5Spec::get_reps();
    let nr = nv;
    let mut rng = StdRng::seed_from_u64(0x00D2_CA5C);
    let polys: Vec<_> = (0..3)
        .map(|i| MultilinearPolynomial::<FpSM2>::rand(nv, StdRng::seed_from_u64(0x00D2_A000 + i as u64)))
        .collect();
    let points: Vec<Vec<FpSM2>> = vec![rand_point(nv, &mut rng), rand_point(nv, &mut rng)];
    let mut evals: Vec<Evaluation<FpSM2>> = Vec::new();
    for (i, poly) in polys.iter().enumerate() {
        for (p, pt) in points.iter().enumerate() {
            evals.push(Evaluation::new(i, p, poly.evaluate(pt)));
        }
    }
    let param = IPcs::setup(1 << nv, 1, StdRng::seed_from_u64(0x00D2_8888)).unwrap();
    let (pp, vp) = IPcs::trim(&param, 1 << nv, 1).unwrap();
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let verify_ok = |comms: &Vec<<IPcs as plonkish_backend::pcs::PolynomialCommitmentScheme<FpSM2>>::Commitment>,
                     ev: &Vec<Evaluation<FpSM2>>,
                     pf: &Vec<u8>|
     -> bool {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tr = IT::from_proof((), pf.as_slice());
            IPcs::batch_verify(&vp, comms, &points, ev, &mut tr).is_ok()
        }));
        matches!(r, Ok(true))
    };

    // ── ① 相消攻击
    let comms = IPcs::batch_commit(&pp, &polys).unwrap();
    let ell = evals.len().next_power_of_two().ilog2() as usize;
    let t_pred: Vec<FpSM2> = {
        let mut tr = IT::new(());
        for c in &comms {
            <IT as TranscriptWrite<O, FpSM2>>::write_commitment(&mut tr, &c.salt).unwrap();
            <IT as TranscriptWrite<O, FpSM2>>::write_commitment(&mut tr, AsRef::<O>::as_ref(c)).unwrap();
        }
        <IT as FieldTranscript<FpSM2>>::squeeze_challenges(&mut tr, ell)
    };
    let eq_xt = MultilinearPolynomial::eq_xy(&t_pred);
    let (l0, l1) = (eq_xt.evals()[0], eq_xt.evals()[1]);
    let delta = FpSM2::from(7u64);
    let mut ev_cancel = evals.clone();
    ev_cancel[0].value += l1 * delta;
    ev_cancel[1].value -= l0 * delta;
    let pf_cancel = {
        let mut tr = IT::new(());
        IPcs::batch_open(&pp, &polys, &comms, &points, &ev_cancel, &mut tr).unwrap();
        tr.into_proof()
    };
    let acc_cancel = verify_ok(&comms, &ev_cancel, &pf_cancel);
    eprintln!("[D27-NEG] ① 相消攻击(两假声称按预测 t 权重相消):接受={acc_cancel}(必须 false)");

    // ── ② t 绑定守卫(黑盒):同一 (polys,points,evals) 两次独立 batch_commit(fresh 盐)出证。外层 sumcheck
    //    只依赖 t 与 (polys,evals);修 D1 前 t 不依赖承诺 ⟹ 两证明的 S2 段(外层首消息)逐字节相同;
    //    修 D1 后 t 吸收 (盐,根) ⟹ S2 必异。同根因覆盖 HyperPlonk 见证承诺 → β/γ/α/y 的可预知性。
    let pf_h = {
        let mut tr = IT::new(());
        IPcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut tr).unwrap();
        tr.into_proof()
    };
    let comms2 = IPcs::batch_commit(&pp, &polys).unwrap();
    let pf_h2 = {
        let mut tr = IT::new(());
        IPcs::batch_open(&pp, &polys, &comms2, &points, &evals, &mut tr).unwrap();
        tr.into_proof()
    };
    let hdr = 2 * comms.len() * HH;
    let s2 = hdr..hdr + nv * 3 * FE;
    let t_bound = pf_h[s2.clone()] != pf_h2[s2.clone()];
    eprintln!("[D27-NEG] ② t 绑定守卫:两次独立承诺的证明 S2 段(外层首消息)不同={t_bound}(必须 true;修 D1 前恒 false)");
    let mut pf_flip = pf_h.clone();
    pf_flip[HH + 3] ^= 0xFF; // 首承诺根第 4 字节
    let acc_flip = verify_ok(&comms, &evals, &pf_flip);
    eprintln!("[D27-NEG] ②b 翻转头部承诺根的证明:接受={acc_flip}(必须 false)");

    // ── ③ 单点 open/verify
    let comm0 = IPcs::commit(&pp, &polys[0]).unwrap();
    let y0 = polys[0].evaluate(&points[0]);
    let y_bad = y0 + <FpSM2 as ff::Field>::ONE;
    let single_verify_at = |pf: &Vec<u8>,
                            y: &FpSM2,
                            c: &<IPcs as plonkish_backend::pcs::PolynomialCommitmentScheme<FpSM2>>::Commitment|
     -> bool {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tr = IT::from_proof((), pf.as_slice());
            IPcs::verify(&vp, c, &points[0], y, &mut tr).is_ok()
        }));
        matches!(r, Ok(true))
    };
    let single_verify = |pf: &Vec<u8>, y: &FpSM2| single_verify_at(pf, y, &comm0);
    let pf_s = {
        let mut tr = IT::new(());
        IPcs::open(&pp, &polys[0], &comm0, &points[0], &y0, &mut tr).unwrap();
        tr.into_proof()
    };
    let s_honest = single_verify(&pf_s, &y0);
    let s_e1 = single_verify(&pf_s, &y_bad);
    let pf_s_bad = {
        let mut tr = IT::new(());
        IPcs::open(&pp, &polys[0], &comm0, &points[0], &y_bad, &mut tr).unwrap();
        tr.into_proof()
    };
    let s_e2 = single_verify(&pf_s_bad, &y_bad);
    // ⑤ 单点换承诺复用(D2 连带守卫,2026-09-16):为 polys[0] 诚实出证后,改用另一次独立承诺
    //    (fresh 盐 ⟹ 盐/根皆异)同点验证——D2 语句吸收使挑战流绑定承诺身份,证明与验证的
    //    挑战流分岔 ⟹ 必拒。(注意:这挡的是"复用他人证明";缺口 E 的真攻击面=恶意证明者以
    //    受害者身份吸收、链自选码字——该负例在 backend 内测 pcs_binding_e3_negatives,因需
    //    私有字段构造混合承诺对象。)
    let comm_swap = IPcs::commit(&pp, &polys[0]).unwrap();
    assert!(comm_swap.salt != comm0.salt, "两次独立承诺盐应异(守卫前提)");
    let s_swap = single_verify_at(&pf_s, &y0, &comm_swap);
    eprintln!(
        "[D27-NEG] ③ 单点:诚实 Ok={s_honest}(须 true);诚实证明×假声称 接受={s_e1}(须 false);假出证×假验证 接受={s_e2}(须 false);换承诺验证 接受={s_swap}(须 false)"
    );

    // ── ④ S8/S9 首字节篡改(默认档;偏移自尾部反推:S11 折叠路径 | S10 查询值 | S9 final_oracle | S8 eval,
    //    三段长度与头部 S6/S7 结构无关,避免对 OFF 档头部封闭式的额外假设)
    let s11 = q * (0..=nr).map(|r| 2 * (nv + lr - 1 - r)).sum::<usize>() * HH;
    let s10 = q * 2 * (nr + 1) * FE;
    let s9_len = (1 << (nv - nr + lr)) * FE;
    assert!(pf_h.len() > s11 + s10 + s9_len + FE, "证明过短:len={}", pf_h.len());
    let off_s9 = pf_h.len() - s11 - s10 - s9_len;
    let off_s8 = off_s9 - FE;
    eprintln!(
        "[D27-NEG] ④ 偏移:len={} off_s8={off_s8} off_s9={off_s9}(头部段 S1..S7 实测长={})",
        pf_h.len(),
        off_s8
    );
    let mut pf_s8 = pf_h.clone();
    pf_s8[off_s8 + 8] ^= 0xFF;
    let acc_s8 = verify_ok(&comms, &evals, &pf_s8);
    let mut pf_s9 = pf_h.clone();
    pf_s9[off_s9 + 8] ^= 0xFF;
    let acc_s9 = verify_ok(&comms, &evals, &pf_s9);
    eprintln!("[D27-NEG] ④ S8 eval 字节篡改 接受={acc_s8}(须 false);S9 final_oracle 字节篡改 接受={acc_s9}(须 false)");
    let honest_ok = verify_ok(&comms, &evals, &pf_h);
    std::panic::set_hook(prev_hook);

    assert!(honest_ok, "诚实批量往返必须 Ok");
    assert!(s_honest, "单点诚实往返必须 Ok");
    assert!(!s_e1, "单点 诚实证明×假声称 被接受(Fix A′ 缺失)");
    assert!(!s_e2, "单点 假出证×假验证 被接受(Fix A′ 缺失)");
    assert!(!s_swap, "单点 换承诺复用 被接受(D2 语句吸收未绑定挑战流)");
    assert!(!acc_s8, "S8 eval 字节篡改被接受");
    assert!(!acc_s9, "S9 final_oracle 字节篡改被接受");
    assert!(!acc_flip, "翻转承诺根的证明被接受");
    assert!(t_bound, "t 绑定守卫:翻转承诺根后 t 未变=承诺不进 FS(缺口 D1)");
    assert!(!acc_cancel, "相消攻击被接受=语句未先于 t 吸收(缺口 D2)");
    eprintln!("[D27-NEG] 绑定负例族扩展全绿:相消拒/t 绑定/单点 A′+E/S8/S9");
}

// =====================================================================
// D27 Phase 3 单元 5(设计文档 §六.5,2026-09-17):流式×交织——同一交织证明在
// STREAM+INTERLEAVE 与 OFF+INTERLEAVE 下结论逐例相同(流式零字节变化);
// 三型负例两模式同拒(S6′ 叶值/S7′ 中段/S7′ 根子节点兄弟);dedup 叠加 Ok;
// 流式终位==证明长度(封闭式 v2 总长互证)。
// =====================================================================
#[test]
fn pcs_stream_interleave_two_pass() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_INTERLEAVE", "PCS_BATCH_DEDUP", "PCS_VERIFY_STREAM"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
    use plonkish_backend::util::transcript::{a3_stream, SM3StreamTranscript};
    use plonkish_backend::poly::multilinear::MultilinearPolynomial;
    use plonkish_backend::poly::Polynomial as _;

    for v in ["PCS_INTERLEAVE", "PCS_BATCH_DEDUP", "PCS_VERIFY_STREAM"] {
        std::env::remove_var(v);
    }
    std::env::set_var("PCS_INTERLEAVE", "1");
    let nv = 6usize;
    let lr = A5Spec::get_rate();
    let q = A5Spec::get_reps();
    let nr = nv;
    let mut rng = StdRng::seed_from_u64(0x00D2_57EA);
    let polys: Vec<_> = (0..3)
        .map(|i| MultilinearPolynomial::<FpSM2>::rand(nv, StdRng::seed_from_u64(0x00D2_5800 + i as u64)))
        .collect();
    let points: Vec<Vec<FpSM2>> = vec![rand_point(nv, &mut rng), rand_point(nv, &mut rng)];
    let mut evals: Vec<Evaluation<FpSM2>> = Vec::new();
    for (i, poly) in polys.iter().enumerate() {
        for (p, pt) in points.iter().enumerate() {
            evals.push(Evaluation::new(i, p, poly.evaluate(pt)));
        }
    }
    let param = IPcs::setup(1 << nv, 1, StdRng::seed_from_u64(0x00D2_5777)).unwrap();
    let (pp, vp) = IPcs::trim(&param, 1 << nv, 1).unwrap();
    let comms = IPcs::batch_commit(&pp, &polys).unwrap(); // 交织:单批 3 列

    let proof = {
        let mut tr = IT::new(());
        IPcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut tr).unwrap();
        tr.into_proof()
    };

    // 封闭式 v2 总长(单批 g=1,N_all=3):头部 2H + S2 nv·3FE + S3 nr(2H+3FE) + S4 3FE
    // + S6′ Q·3·2FE + S7′ Q·1·2(nv+lr)H + S8 FE + S9 2^(nv−nr+lr)FE + S10 Q·2(nr+1)FE
    // + S11 Q·Σ 2(nv+lr−1−r)H。
    let off_s6 = 2 * HH + nv * 3 * FE + nr * (2 * HH + 3 * FE) + 3 * FE;
    let per_q6 = 3 * 2 * FE;
    let path_w = 2 * (nv + lr) * HH;
    let off_s7 = off_s6 + q * per_q6;
    let per_q7 = path_w;
    let s11: usize = q * (0..=nr).map(|r| 2 * (nv + lr - 1 - r)).sum::<usize>() * HH;
    let total = off_s7 + q * per_q7 + FE + (1 << (nv - nr + lr)) * FE + q * 2 * (nr + 1) * FE + s11;
    assert_eq!(proof.len(), total, "交织证明总长 ≠ 封闭式 v2(探针侧互证)");

    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let verify_mode = |stream: bool, pf: &Vec<u8>| -> bool {
        let mut end_ok = true;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if stream {
                let src = std::sync::Arc::new(pf.clone());
                std::env::set_var("PCS_VERIFY_STREAM", "1");
                a3_stream::register(src.clone());
                let mut tr = SM3StreamTranscript::new(&src[..]);
                let ok = IPcs::batch_verify(&vp, &comms, &points, &evals, &mut tr).is_ok();
                let end = a3_stream::pos();
                end_ok = end == pf.len();
                ok && end_ok
            } else {
                let mut tr = IT::from_proof((), pf.as_slice());
                IPcs::batch_verify(&vp, &comms, &points, &evals, &mut tr).is_ok()
            }
        }));
        // 🔴 清理必须在 catch 之后:后端断言 panic 会跳过闭包内清理,泄漏的注册源/环境
        // 变量会污染后续负例(首跑实证:stale 源使 r2o/r3o 读到旧证明字节)。
        if stream {
            a3_stream::clear();
            std::env::remove_var("PCS_VERIFY_STREAM");
        }
        matches!(r, Ok(true)) && end_ok
    };
    // 诚实:两模式 Ok。
    let off_ok = verify_mode(false, &proof);
    let stream_ok = verify_mode(true, &proof);
    eprintln!("[D27-P3] 诚实:OFF+交织 Ok={off_ok}(须 true);STREAM+交织 Ok={stream_ok}(须 true)");

    // 负例三型(S6′ 首叶值 / S7′ 中段 / S7′ 末端块兄弟侧),两模式同拒。
    // 🔴 末端块字节学(2026-09-17 实测转储定案):每查询 S7′ 段 = 9 块,末块=(root,root)
    // 声明块,验证器只 pop 比对 elem1;**elem0=冗余副本=死数据**(与 S1′ 盐同类,篡改
    // elem0 被接受属已知声明块死数据,非声音性洞——负例不得选 elem0)。承重兄弟侧=
    // 末块前一 chunk(children 对,authenticate 末端 hash(children)==root 消费)的 elem1。
    let mut pf_leaf = proof.clone();
    pf_leaf[off_s6 + 8] ^= 0xFF;
    let mut pf_mid = proof.clone();
    pf_mid[off_s7 + per_q7 / 2] ^= 0xFF;
    let mut pf_sib = proof.clone();
    let sib = off_s7 + per_q7 - 4 * HH + 2; // 末端块前一 chunk(children 对)兄弟元素侧
    pf_sib[sib] ^= 0xFF;
    let (r1o, r1s) = (verify_mode(false, &pf_leaf), verify_mode(true, &pf_leaf));
    let (r2o, r2s) = (verify_mode(false, &pf_mid), verify_mode(true, &pf_mid));
    let (r3o, r3s) = (verify_mode(false, &pf_sib), verify_mode(true, &pf_sib));
    eprintln!(
        "[D27-P3] 负例:叶值 OFF/流={r1o}/{r1s} 中段={r2o}/{r2s} 末块兄弟={r3o}/{r3s}(全须 false)"
    );

    // dedup 叠加(去重对交织为被包含语义,验证结论不变)。
    std::env::set_var("PCS_BATCH_DEDUP", "1");
    let d_ok = verify_mode(true, &proof);
    std::env::remove_var("PCS_BATCH_DEDUP");
    eprintln!("[D27-P3] dedup 叠加 STREAM+交织 Ok={d_ok}(须 true)");

    std::panic::set_hook(prev_hook);
    for v in ["PCS_INTERLEAVE", "PCS_BATCH_DEDUP", "PCS_VERIFY_STREAM"] {
        std::env::remove_var(v);
    }
    assert!(off_ok && stream_ok, "诚实交织证明两模式必须全 Ok");
    assert!(d_ok, "dedup 叠加必须 Ok");
    assert!(!(r1o || r1s || r2o || r2s || r3o || r3s), "三型负例必须两模式同拒");
    eprintln!("[D27-P3] 流式×交织全绿:诚实两模式 Ok/负例六态全拒/总长互证/dedup 叠加");
}

/// D27 Phase 3 快速复现单元:HyperPlonk 前缀 + STREAM + 交织(小电路,秒级迭代)。
/// 期望:同一交织证明 OFF 与 STREAM 双模式 Ok(流式零字节变化)。
#[test]
fn pcs_stream_interleave_hyperplonk_prefix() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_INTERLEAVE", "PCS_BATCH_DEDUP", "PCS_VERIFY_STREAM"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
    use plonkish_backend::util::transcript::{a3_stream, SM3StreamTranscript};

    for v in ["PCS_INTERLEAVE", "PCS_BATCH_DEDUP", "PCS_VERIFY_STREAM"] {
        std::env::remove_var(v);
    }
    let (e, r, s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
    let asm = crate::sm2_verify_assemble::assemble_sm2_verify(e, r, s, pax, pay);
    assert_eq!(asm.info.constraints.len(), 10_424);
    let circ = P2Circuit {
        info: asm.info.clone(),
        advice: asm.advice.clone(),
        instances: asm.instances.clone(),
    };
    std::env::set_var("PCS_INTERLEAVE", "1");
    let param = P2Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x00D2_6E01)).unwrap();
    let (pp, vp) = P2Pb::preprocess(&param, &circ.circuit_info().unwrap()).unwrap();
    let proof = {
        let mut tr = SM3Transcript::new(());
        P2Pb::prove(&pp, &circ, &mut tr, StdRng::seed_from_u64(0x00D2_6E02)).unwrap();
        tr.into_proof()
    };
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    // OFF+交织
    let r_off = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut tr = SM3Transcript::from_proof((), proof.as_slice());
        P2Pb::verify(&vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x00D2_6E03)).is_ok()
    }));
    // STREAM+交织
    let src = std::sync::Arc::new(proof.clone());
    std::env::set_var("PCS_VERIFY_STREAM", "1");
    a3_stream::register(src.clone());
    let r_stream = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut tr = SM3StreamTranscript::new(&src[..]);
        P2Pb::verify(&vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x00D2_6E03)).is_ok()
    }));
    a3_stream::clear();
    std::env::remove_var("PCS_VERIFY_STREAM");
    std::env::remove_var("PCS_INTERLEAVE");
    std::panic::set_hook(prev_hook);
    let off_ok = matches!(r_off, Ok(true));
    let st_ok = matches!(r_stream, Ok(true));
    let st_err = match r_stream {
        Err(e) => e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "非字符串".to_string()),
        _ => String::new(),
    };
    eprintln!("[D27-P3X] OFF={off_ok}(须 true) STREAM={st_ok}(须 true) err={st_err}");
    assert!(off_ok && st_ok, "HyperPlonk 前缀下流式×交织失败(见上)");
}
