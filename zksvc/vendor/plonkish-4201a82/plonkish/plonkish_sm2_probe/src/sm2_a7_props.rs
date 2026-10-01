//! T4+T1 · (A7) 测试体系：公开输入全量扫描 + 随机见证属性测试（2026-09-14）
//!
//! T4（公开输入约束扫描）：枚举全部公开实例逐个篡改（±1/清零），断言两防线
//! 全部捕获——机器验证论文声称"π 经实例绑定到\emph{完整}公开向量——改写任一
//! 元素即验败"（\S4 Verify 段）无未钉绑面。
//! T1（随机见证属性测试）：关系保持随机化（sk/id/r/exp 随机、attrs 恒 PRED_TARGET
//! ——S5 等值谓词的语义要求），断言装配两防线零违约 ∧ 宿主 verify_replay 接受。
//! 计数纪律：T1 电路档成本 ~90s/见证（装配+防线），默认 N=8；万级档经
//! A7_T1_N 环境变量在批次跑批中放量。e12 两测试禁跑纪律继承。
use crate::sm3_compress::{check_parts_violations, check_subset_violations};
use crate::sm2_full_statement_assemble::{
    assemble_full_statement_with_hooks_bound,
};
use crate::FpSM2;
use ff::Field as _;
use plonkish_backend::backend::PlonkishCircuitInfo;

pub struct SplitMix(pub u64);
impl SplitMix {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// T4 · 公开实例全量扫描：每个实例 ±1 与（非零基线时的）清零篡改都必须被捕获。
#[test]
fn t4_public_instance_full_scan() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("t4_public_instance_full_scan", "T4; 22 instances x {+1,-1,0} tamper");
    let base = crate::sm2_full_statement_assemble::witness_from_with_exp(
        [0x0A1B_2C3D_4E5F_6071, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22],
        [7u8; 32],
        [0x33u64, 0, 0, 0x5EED],
        501,
    );
    let (asm, _) = assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
    let n_lists = asm.instances.len();
    assert_eq!(n_lists, 1, "公开实例列表数漂移（期望单列表 22 实例）");
    let n_inst = asm.instances[0].len();
    assert_eq!(n_inst, 22, "公开实例数漂移（论文口径：基础 12+有效期 7+上下文与谓词 2+epoch 1）");
    // 基线：未篡改零违约（两防线零违约基线纪律）
    let base_bad = check_parts_violations(&asm.info, &asm.advice, &asm.instances);
    assert!(base_bad.is_empty(), "诚实见证基线出现违约 = 装配自洽破坏");

    let mut caught_plus = 0usize;
    let mut caught_minus = 0usize;
    let mut caught_zero = 0usize;
    // 子集求值优化：篡改实例只影响引用实例列（poly 0）的约束——其余约束值
    // 不变（基线零违约下保持零）。静态收集该子集，66 次篡改的求值降为子集
    // 求值；首个篡改另做一次全量求值交叉验证（子集非空 ⟺ 全量非空）。
    let inst_cons = collect_inst_constraints(&asm.info);
    assert!(
        !inst_cons.is_empty(),
        "无任何约束消费公开实例列 = 实例未绑定（严重欠约束）"
    );
    let mut cross_checked = false;
    for i in 0..n_inst {
        // ±1 篡改
        for (tag, delta, counter) in [
            ("+1", FpSM2::ONE, &mut caught_plus),
            ("-1", -FpSM2::ONE, &mut caught_minus),
        ] {
            let mut inst = asm.instances.clone();
            inst[0][i] += delta;
            let bad = check_subset_violations(&asm.info, &asm.advice, &inst, &inst_cons);
            assert!(!bad.is_empty(), "公开实例[{i}] {tag} 篡改未被捕获 = 存在未钉绑公开输入面");
            if !cross_checked {
                let full = check_parts_violations(&asm.info, &asm.advice, &inst);
                assert_eq!(full.is_empty(), bad.is_empty(),
                    "子集求值与全量求值在实例篡改下不一致（交叉验证失败）");
                cross_checked = true;
            }
            *counter += 1;
        }
        // 清零篡改（基线本为零则跳过——与诚实值相同的平凡情形）
        if !(asm.instances[0][i] == FpSM2::ZERO) {
            let mut inst = asm.instances.clone();
            inst[0][i] = FpSM2::ZERO;
            let bad = check_subset_violations(&asm.info, &asm.advice, &inst, &inst_cons);
            assert!(!bad.is_empty(), "公开实例[{i}] 清零篡改未被捕获 = 存在未钉绑公开输入面");
            caught_zero += 1;
        }
    }
    eprintln!(
        "[T4] 公开实例 {n_inst} 个 × {{+1,−1,0}} 全量篡改扫描：+1 捕获 {caught_plus}、−1 捕获 {caught_minus}、清零捕获 {caught_zero}——零逃逸"
    );
}

/// 收集引用公开实例列（poly 0）的约束索引（T4/T1 共用的静态子集）。
fn collect_inst_constraints<F: Clone>(info: &PlonkishCircuitInfo<F>) -> Vec<usize> {
    let mut out = Vec::new();
    for (ci, expr) in info.constraints.iter().enumerate() {
        if expr.used_poly().contains(&0usize) {
            out.push(ci);
        }
    }
    out
}

/// per-poly 约束索引：poly 索引 → 引用该 poly 的约束清单（位翻转子集求值用）。
fn poly_constraint_index<F: Clone>(
    info: &PlonkishCircuitInfo<F>,
) -> std::collections::BTreeMap<usize, Vec<usize>> {
    let mut idx: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for (ci, expr) in info.constraints.iter().enumerate() {
        for p in expr.used_poly() {
            idx.entry(p).or_default().push(ci);
        }
    }
    idx
}

/// T1 · 随机见证属性测试（电路档）：关系保持随机见证 ⟹ 装配防线零违约
/// ∧ 实例篡改捕获 ∧ 随机格扰动两态断言（捕获或无害——接受集口径）。
/// 计数经 A7_T1_N 环境变量放量；万级档建议分批（电路档 ~90s/见证）。
#[test]
fn t1_random_witness_property() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("t1_random_witness_property", "T1 circuit; A7_T1_N env (default 8); epoch=500; seed=0x00A75EED");
    let n_target: usize = std::env::var("A7_T1_N").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let mut sm = SplitMix(0x00A7_5EED);
    let epoch: u32 = 500;
    let mut flips_total = 0usize;
    let mut flips_caught = 0usize;
    for i in 0..n_target {
        // 关系保持随机化：sk/id/r 全随机；attrs 由构造器固定 PRED_TARGET（S5 等值语义）；
        // exp_u 随机 ≥ epoch+1（S6 语义）。
        let sk = [sm.next(), sm.next(), sm.next(), sm.next() & 0x0FFF_FFFF];
        let id = {
            let mut v = [0u8; 32];
            for c in v.iter_mut() { *c = sm.next() as u8; }
            v
        };
        let r = [sm.next(), sm.next(), sm.next(), sm.next() & 0x0FFF_FFFF];
        let exp = epoch + 1 + (sm.next() % 100_000) as u32;
        let w = crate::sm2_full_statement_assemble::witness_from_with_exp(sk, id, r, exp);
        // 电路侧：装配 + 基线全量防线零违约（每见证一次全量，其余用子集）
        let (mut asm, _) = assemble_full_statement_with_hooks_bound(&w, FpSM2::ZERO, FpSM2::ZERO, epoch);
        let bad = check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(bad.is_empty(), "随机见证 #{i} 装配防线违约 {:?} 条：{:?}",
            bad.len(), bad.iter().take(3).map(|v| (v.constraint, asm.ctags[v.constraint])).collect::<Vec<_>>());
        // 静态子集（每见证构建——ctags 随 asm 重新分配，索引按 asm.info 不变可复用）
        let inst_cons = collect_inst_constraints(&asm.info);
        let poly_idx = poly_constraint_index(&asm.info);
        // 公开实例扫描抽验（每见证对末位实例 ±1 篡改——随机化复验，全量由 T4 覆盖）
        let mut inst = asm.instances.clone();
        let last = inst[0].len() - 1;
        inst[0][last] += FpSM2::ONE;
        let bad2 = check_subset_violations(&asm.info, &asm.advice, &inst, &inst_cons);
        assert!(!bad2.is_empty(), "随机见证 #{i} epoch 实例篡改未被捕获");
        // 随机格扰动（位翻转的格推广：布尔位格 +=1 即 0↔1 翻转）：每见证 3 格，
        // 断言两态之一——防线捕获（违约非空）或无害扰动（零违约，如实计数；
        // 与 T3 无自由列相容：被引用的列上具体格可不被敏感消费）。
        for _f in 0..3 {
            let col = (sm.next() as usize) % asm.advice.len();
            let row = (sm.next() as usize) % asm.advice[col].len();
            let orig = asm.advice[col][row];
            asm.advice[col][row] = orig + FpSM2::ONE;
            let np = asm.info.preprocess_polys.len();
            // 子集完备性：不引用 poly p 的约束值与 advice[p][*] 无关（基线零 ⟹
            // 扰动后仍零），引用者全在子集内 ⟹ 子集求值与全量在违约出现性上等价。
            let badf = match poly_idx.get(&(col + np + 1)) {
                Some(s) => check_subset_violations(&asm.info, &asm.advice, &asm.instances, s),
                None => Vec::new(), // 自由列（T3-A2 口径）：无约束引用，扰动必无害
            };
            if !badf.is_empty() {
                flips_caught += 1;
            }
            asm.advice[col][row] = orig;
            flips_total += 1;
        }
        eprintln!("[T1] 见证 #{i} 装配零违约 + epoch 篡改捕获 + 3 格扰动断言 ✓ (sk[0]={:016x})", sk[0]);
    }
    eprintln!("[T1] 属性测试完成：{n_target} 个随机见证全绿（电路档；格扰动 {flips_caught}/{flips_total} 被捕获，其余为按 poly 子集完备判定的无害扰动）");
}

/// T1 · 随机见证属性测试（宿主档，万级默认）：每个见证的构造器内部即含
/// 宿主 verify_replay 自检（签名数学重放，见 witness_from_with_exp 尾部
/// assert），本档再显式断言 GB/T 范围（r_s,s_s ∈ [1,n−1]；sk ∈ [1,n−2] 由
/// 构造域保证）。宿主档承载"随机见证 ⟹ 签名验证接受"的万级样本；电路档
/// （t1_random_witness_property）承载装配面，两档分账。计数经 A7_T1_HOST_N 放量。
#[test]
fn t1_host_random_witness_property() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("t1_host_random_witness_property", "T1 host; A7_T1_HOST_N env (default 10^4)");
    let n_target: usize = std::env::var("A7_T1_HOST_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let n = crate::sm2_params::n_limbs();
    let lt_limbs = |a: &[u64; 4]| -> bool {
        for i in (0..4).rev() {
            if a[i] != n[i] {
                return a[i] < n[i];
            }
        }
        false // == n
    };
    let is_zero = |a: &[u64; 4]| a.iter().all(|&x| x == 0);
    let mut sm = SplitMix(0x00A7_5057);
    for i in 0..n_target {
        let sk = [sm.next(), sm.next(), sm.next(), sm.next() & 0x0FFF_FFFF];
        let mut id = [0u8; 32];
        for c in id.iter_mut() {
            *c = sm.next() as u8;
        }
        let r = [sm.next(), sm.next(), sm.next(), sm.next() & 0x0FFF_FFFF];
        let exp = 501u32 + (sm.next() % 100_000) as u32;
        // 构造器内部：pk_u/apk 派生 + e 计算三块链 + sign + verify_replay 自检 assert
        let w = crate::sm2_full_statement_assemble::witness_from_with_exp(sk, id, r, exp);
        // GB/T 范围断言（签名分量 ∈ [1,n−1]）
        assert!(!is_zero(&w.r_s) && lt_limbs(&w.r_s), "见证 #{i} r_s 越界");
        assert!(!is_zero(&w.s_s) && lt_limbs(&w.s_s), "见证 #{i} s_s 越界");
        assert!(!is_zero(&sk) && lt_limbs(&sk), "见证 #{i} sk 越界");
    }
    eprintln!("[T1-host] 宿主档属性测试完成：{n_target} 个随机见证（构造内含 verify_replay 自检 + 范围断言）全绿");
}

