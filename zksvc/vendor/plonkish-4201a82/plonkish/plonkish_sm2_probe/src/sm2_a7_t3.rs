//! T3 · (A7) 测试体系：欠约束全量化（2026-09-14；2026-09-15 增动态逐行激活档）
//!
//! 波4 规格的静态全量实现（201,183 约束行全覆盖（2026-10 实测钉；旧 225,724 系 A1″ 历史值），O(表达式树) 级）：
//! - **A1 死约束扫描**：全部约束表达式中无 advice 引用（poly > np）者 =
//!   见证无关约束 = 候选死约束（不承重约束）。断言为零——若非零须逐条
//!   给出家族语义解释后方可放宽。
//! - **A2 自由列扫描**：未被任何约束表达式或复制环引用的 advice 列 =
//!   见证可自由取值而不触发任何防线的格 = 欠约束面。断言为零。
//!
//! **动态逐行激活（2026-09-15，波4 T3 原始规格的动态档）**：对全部 201,183（2026-10 实测；旧值 225,724）
//! 条约束行逐一构造定向扰动并断言家族防线（约束级对账 = check_subset_
//! violations 家族子集求值）捕获。设计口径：
//! - 扰动 = 该行自身引用的 advice 列上做整列加性 δ（虚拟求值——resolve 层
//!   叠加 δ，与 check_subset_violations 的求值闭包逐字同语义，零拷贝）。
//!   严格"仅违反该行"的单例扰动集在共享格电路一般不存在（同一 advice 格
//!   被多行经不同旋转消费）；本档证的是**激活**：每行都存在一个使其违反
//!   的负例，且该负例被家族子集求值捕获（行在子集内 ⟹ 行违约 ⊆ 子集违约）。
//! - 单列 δ 失败（如 s·(a·b−c) 型在见证 a=b=0、c 非格时的乘性退化）转
//!   双列 (δ₁,δ₂) 变体（δ₁δ₂≠0 ∧ δ₁≠δ₂ 防差分型对消）；双列仍失败 =
//!   抗性行（结构性发现，断言失败并报家族）。
//! - 逐家族抽样经**真实** check_subset_violations（实变异+回退）交叉核验
//!   家族防线捕获（防虚拟求值与生产线漂移）。
//! e12 禁跑纪律继承。
use crate::sm2_full_statement_assemble::assemble_full_statement_with_hooks_bound;
use crate::FpSM2;
use ff::Field as _;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn t3_underconstraint_full_quantification() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("t3_underconstraint_full_quantification", "T3 static; used_poly full scan 201,183; frozen 201183/11586（advice 旧 11663 已漂移）（旧 225724 在 db0bbb3 已漂移 201443——历史批次未回写；本次 −260 acc.chain 去重）");
    let base = crate::sm2_full_statement_assemble::witness_from_with_exp(
        [0x0A1B_2C3D_4E5F_6071, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22],
        [7u8; 32],
        [0x33u64, 0, 0, 0x5EED],
        501,
    );
    let (asm, _) = assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
    let np = asm.info.preprocess_polys.len();
    let n_cons = asm.info.constraints.len();
    assert_eq!(n_cons, 201_183, "约束总数漂移（2026-10-01 实测钉：A1″ 旧钉 225,724 在 db0bbb3 已漂移至 201,443——历史批次 legacy 面未回写；本次换代 −260=acc.chain 去重 4 窗×65）");
    assert_eq!(asm.advice.len(), 11_586, "advice 列数漂移（2026-10-01 实测钉：旧钉 11,663 在 db0bbb3 实测已漂移至 11,586——历史批次未回写；本批零列变动）");

    // A1 · 死约束扫描：无 advice 引用的约束（按 ctags 家族归集）
    let mut dead: Vec<usize> = Vec::new();
    // A2 · 被（约束表达式）引用的多项式集合
    let mut referenced: BTreeSet<usize> = BTreeSet::new();
    for (ci, expr) in asm.info.constraints.iter().enumerate() {
        let polys = expr.used_poly();
        let has_advice = polys.iter().any(|&p| p > np);
        if !has_advice {
            dead.push(ci);
        }
        referenced.extend(polys.iter().copied());
    }
    if !dead.is_empty() {
        let fams: BTreeSet<&str> = dead.iter().map(|&ci| asm.ctags[ci]).collect();
        eprintln!(
            "[T3-A1] advice-free 约束 {} 条，家族：{:?}",
            dead.len(),
            fams
        );
    }
    assert!(
        dead.is_empty(),
        "存在 {} 条见证无关（advice-free）约束 = 候选死约束（欠约束证据；须逐条家族解释后方可放宽）：首条 ci={} 家族={}",
        dead.len(),
        dead[0],
        asm.ctags[dead[0]]
    );

    // A2 · 自由列扫描：未被任何约束表达式或复制环引用的 advice 列。
    // 分档处置：全零列 = 工程冗余（不承载任何值——无泄漏面、无伪造面，
    // 如实计数并通过）；非零列 = 承载值却无任何约束消费 = 真欠约束面（失败）。
    let advice_ids: BTreeSet<usize> = (np + 1..=np + asm.advice.len()).collect();
    for (_, cyc) in asm.info.permutations.iter().enumerate() {
        for &(p, _pt) in cyc {
            referenced.insert(p);
        }
    }
    let free: Vec<usize> = advice_ids.difference(&referenced).copied().collect();
    let mut free_zero = 0usize;
    let mut free_nonzero: Vec<usize> = Vec::new();
    for &pid in &free {
        let col = pid - 1 - np;
        let nz = asm.advice[col]
            .iter()
            .filter(|v| **v != FpSM2::ZERO)
            .count();
        if nz == 0 {
            free_zero += 1;
        } else {
            free_nonzero.push(col);
            eprintln!(
                "[T3-A2] 自由列 advice[{col}] 非零格 {nz} 个（承载值却无约束消费）"
            );
        }
    }
    if !free.is_empty() {
        eprintln!(
            "[T3-A2] 自由列共 {} 条：全零 {}、非零 {}（advice 索引 {:?}）",
            free.len(),
            free_zero,
            free_nonzero.len(),
            free.iter().map(|&p| p - 1 - np).collect::<Vec<_>>()
        );
    }
    assert!(
        free_nonzero.is_empty(),
        "存在 {} 条承载非零值却未被任何约束/复制环引用的 advice 列 = 欠约束面：{:?}",
        free_nonzero.len(),
        free_nonzero
    );

    // 家族统计报告（覆盖面档案，非断言）
    let mut fam_count: BTreeMap<&str, usize> = BTreeMap::new();
    for &t in asm.ctags.iter() {
        *fam_count.entry(t).or_insert(0) += 1;
    }
    eprintln!(
        "[T3] 静态全量：{} 约束 × {} advice 列——死约束 0、非零自由列 0（全零冗余列 {}）；约束家族 {} 个（top: {:?}）",
        n_cons,
        asm.advice.len(),
        free_zero,
        fam_count.len(),
        fam_count.iter().max_by_key(|(_, c)| **c).map(|(t, c)| (t, c))
    );
}

// ═══════════════ 动态逐行激活（2026-09-15，波4 T3 原始规格的动态档） ═══════════════

/// 定向扰动的激活配置：整列加性 δ（全局 poly 索引）；`Pair` 覆盖乘性退化行。
#[derive(Clone, Copy, Debug)]
enum DeltaCfg {
    Single { poly: usize },
    Pair { pa: usize, pb: usize },
}

/// 虚拟列 δ 求值：与 `check_subset_violations` 的 resolve/evaluate 闭包逐字
/// 同语义（poly 0=实例 / ≤np=preprocess / >np=advice，旋转经 cube.rotate），
/// 唯一差异 = 指定 advice 列的读值叠加 δ。任一点非零即激活（早退）。
fn expr_activated_bridge(
    expr: &plonkish_backend::util::expression::Expression<FpSM2>,
    advice: &[Vec<FpSM2>],
    inst_at: &[FpSM2],
    pre: &[Vec<FpSM2>],
    np: usize,
    cube: &plonkish_backend::util::arithmetic::BooleanHypercube,
    cfg: &DeltaCfg,
    d1: FpSM2,
    d2: FpSM2,
) -> bool {
    use plonkish_backend::util::expression::CommonPolynomial;
    let (qa, qb) = match *cfg {
        DeltaCfg::Single { poly } => (poly, usize::MAX),
        DeltaCfg::Pair { pa, pb } => (pa, pb),
    };
    for point in cube.iter() {
        let val: FpSM2 = expr.evaluate(
            &|c| c,
            &|_: CommonPolynomial| panic!("动态激活未用到 CommonPolynomial"),
            &|q| {
                let pt = cube.rotate(point, q.rotation());
                if q.poly() == 0 {
                    inst_at[pt]
                } else if q.poly() <= np {
                    pre[q.poly() - 1][pt]
                } else {
                    let base = advice[q.poly() - 1 - np][pt];
                    if q.poly() == qa {
                        base + d1
                    } else if q.poly() == qb {
                        base + d2
                    } else {
                        base
                    }
                }
            },
            &|_: usize| panic!("单相电路无挑战"),
            &|v| -v,
            &|a, b| a + b,
            &|a, b| a * b,
            &|v, s| v * s,
        );
        if val != FpSM2::ZERO {
            return true;
        }
    }
    false
}

/// T3 动态档：201,183 约束行逐行定向扰动激活（2026-10 实测钉） + 家族防线捕获断言。
/// 抽样经 `A7_T3_DYN_EXTRA` 环境变量放量（默认 8 随机行单行子集核验）。
#[test]
fn t3_dynamic_per_row_activation() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("t3_dynamic_per_row_activation", "T3 dyn; A7_T3_DYN_EXTRA env (default 8); d1=0x5EED00A7 d2=0x0D15EA5E");
    use plonkish_backend::util::arithmetic::BooleanHypercube;

    let t0 = std::time::Instant::now();
    let base = crate::sm2_full_statement_assemble::witness_from_with_exp(
        [0x0A1B_2C3D_4E5F_6071, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22],
        [7u8; 32],
        [0x33u64, 0, 0, 0x5EED],
        501,
    );
    let (mut asm, _) =
        assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
    let np = asm.info.preprocess_polys.len();
    let n_cons = asm.info.constraints.len();
    assert_eq!(n_cons, 201_183, "约束总数漂移（2026-10-01 实测钉：A1″ 旧钉 225,724 在 db0bbb3 已漂移至 201,443——历史批次 legacy 面未回写；本次换代 −260=acc.chain 去重 4 窗×65）");
    assert_eq!(asm.advice.len(), 11_586, "advice 列数漂移（2026-10-01 实测钉：旧钉 11,663 在 db0bbb3 实测已漂移至 11,586——历史批次未回写；本批零列变动）");

    // 基线零违约（诚实见证——动态负例的对照基线）。
    let bad0 =
        crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
    assert!(bad0.is_empty(), "基线违约 {} 条（诚实见证必须零违约）", bad0.len());
    let t_base = t0.elapsed();

    // 实例面 → 点位（与 check_subset_violations 同法）。
    let mut inst_at = vec![FpSM2::ZERO; crate::sm3_compress::ROWS];
    for (ordinal, v) in asm.instances.iter().flat_map(|c| c.iter()).enumerate() {
        inst_at[crate::sm3_compress::row_mapping()[ordinal]] = *v;
    }
    let cube = BooleanHypercube::new(crate::sm3_compress::K);
    let pre_flat: Vec<Vec<FpSM2>> = asm.info.preprocess_polys.clone();

    // 家族分组（ctag）。
    let mut fams: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (ci, t) in asm.ctags.iter().enumerate() {
        fams.entry(t).or_default().push(ci);
    }

    // δ 常量：非零、互异、和差均非零（防差分型对消）。
    let d1 = FpSM2::from(0x5EED_00A7u64);
    let d2 = FpSM2::from(0x0D15_EA5Eu64);
    assert!(
        d1 != FpSM2::ZERO
            && d2 != FpSM2::ZERO
            && d1 != d2
            && d1 - d2 != FpSM2::ZERO
            && d1 + d2 != FpSM2::ZERO
    );

    // ── 逐行扫描（并行、只读、虚拟 δ）──
    let advice = &asm.advice;
    let constraints = &asm.info.constraints;
    let scan_row = |ci: usize| -> Option<DeltaCfg> {
        let expr = &constraints[ci];
        let polys: Vec<usize> =
            expr.used_poly().into_iter().filter(|&p| p > np).collect();
        if polys.is_empty() {
            return None; // 死行兜底（静态档已断言为零）
        }
        for &q in &polys {
            let cfg = DeltaCfg::Single { poly: q };
            if expr_activated_bridge(expr, advice, &inst_at, &pre_flat, np, &cube, &cfg, d1, d2) {
                return Some(cfg);
            }
        }
        for (ia, &qa) in polys.iter().enumerate() {
            for &qb in polys.iter().skip(ia + 1) {
                let cfg = DeltaCfg::Pair { pa: qa, pb: qb };
                if expr_activated_bridge(expr, advice, &inst_at, &pre_flat, np, &cube, &cfg, d1, d2) {
                    return Some(cfg);
                }
            }
        }
        None
    };
    let nt = std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
        .min(16);
    let chunk = n_cons.div_ceil(nt);
    let results: Vec<Option<DeltaCfg>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..nt)
            .map(|t| {
                let lo = (t * chunk).min(n_cons);
                let hi = ((t + 1) * chunk).min(n_cons);
                let scan = &scan_row;
                scope.spawn(move || (lo..hi).map(|ci| scan(ci)).collect::<Vec<_>>())
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("T3 动态扫描线程崩溃"))
            .collect()
    });

    let mut n_single = 0usize;
    let mut n_pair = 0usize;
    let mut resistant: Vec<(usize, &str)> = Vec::new();
    let mut fam_single: BTreeMap<&str, usize> = BTreeMap::new();
    let mut fam_pair: BTreeMap<&str, usize> = BTreeMap::new();
    for (ci, r) in results.iter().enumerate() {
        match r {
            Some(DeltaCfg::Single { .. }) => {
                n_single += 1;
                *fam_single.entry(asm.ctags[ci]).or_insert(0) += 1;
            }
            Some(DeltaCfg::Pair { .. }) => {
                n_pair += 1;
                *fam_pair.entry(asm.ctags[ci]).or_insert(0) += 1;
            }
            None => resistant.push((ci, asm.ctags[ci])),
        }
    }
    eprintln!(
        "[T3-DYN] 逐行激活：{n_cons} 行 = 单列 δ {n_single} + 双列 δ {n_pair} + 抗性 {}（家族 {} 个；基线 {:?} + 扫描 {:?}）",
        resistant.len(),
        fams.len(),
        t_base,
        t0.elapsed() - t_base
    );
    for (t, cis) in fams.iter() {
        eprintln!(
            "[T3-DYN]   家族 {t:<12} 行数 {:>6}（单列 {} / 双列 {} / 抗性 {}）",
            cis.len(),
            fam_single.get(*t).copied().unwrap_or(0),
            fam_pair.get(*t).copied().unwrap_or(0),
            resistant.iter().filter(|(_, ft)| *ft == *t).count()
        );
    }
    assert!(
        resistant.is_empty(),
        "存在 {} 条抗性行（单列+双列 δ 均无法激活 = 候选死约束/永 inactive 行）：{:?}",
        resistant.len(),
        &resistant[..resistant.len().min(10)]
    );

    // ── 家族防线交叉核验（真实 check_subset_violations + 实变异回退）──
    // 每家族首行用家族子集；追加 A7_T3_DYN_EXTRA（默认 8）随机行用单行子集。
    let n_extra: usize = std::env::var("A7_T3_DYN_EXTRA")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    let cross_family: Vec<(usize, DeltaCfg)> = fams
        .values()
        .map(|cis| (cis[0], results[cis[0]].expect("家族首行必已激活")))
        .collect();
    let mut sm = crate::sm2_a7_props::SplitMix(0x00A7_0D15);
    let mut cross_single: Vec<(usize, DeltaCfg)> = Vec::new();
    for _ in 0..n_extra {
        let ci = (sm.next() as usize) % n_cons;
        if let Some(cfg) = &results[ci] {
            cross_single.push((ci, *cfg));
        }
    }
    let apply = |asm: &mut crate::sm2_verify_assemble::Assembled,
                 cfg: &DeltaCfg,
                 sign: i32,
                 np: usize,
                 d1: FpSM2,
                 d2: FpSM2| {
        let (qa, qb) = match *cfg {
            DeltaCfg::Single { poly } => (poly, usize::MAX),
            DeltaCfg::Pair { pa, pb } => (pa, pb),
        };
        for (poly, d) in [(qa, d1), (qb, d2)] {
            if poly != usize::MAX && poly > np {
                let col = poly - 1 - np;
                if sign > 0 {
                    for v in asm.advice[col].iter_mut() {
                        *v = *v + d;
                    }
                } else {
                    for v in asm.advice[col].iter_mut() {
                        *v = *v - d;
                    }
                }
            }
        }
    };
    for (ci, cfg) in cross_family.iter() {
        apply(&mut asm, cfg, 1, np, d1, d2);
        let fam_subset = &fams[asm.ctags[*ci]];
        let bad = crate::sm3_compress::check_subset_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
            fam_subset,
        );
        assert!(
            bad.iter().any(|v| v.constraint == *ci),
            "家族 {} 首行 {ci} 的定向扰动未被家族子集防线捕获（违约 {} 条）",
            asm.ctags[*ci],
            bad.len()
        );
        apply(&mut asm, cfg, -1, np, d1, d2);
        let bad_after = crate::sm3_compress::check_subset_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
            &[*ci],
        );
        assert!(bad_after.is_empty(), "回退后行 {ci} 仍违约——变异污染");
    }
    for (ci, cfg) in cross_single.iter() {
        apply(&mut asm, cfg, 1, np, d1, d2);
        let bad = crate::sm3_compress::check_subset_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
            &[*ci],
        );
        assert!(
            !bad.is_empty(),
            "随机行 {ci}（家族 {}）的定向扰动未被单行子集防线捕获",
            asm.ctags[*ci]
        );
        apply(&mut asm, cfg, -1, np, d1, d2);
    }
    eprintln!(
        "[T3-DYN] 交叉核验：{} 个家族首行（家族子集）+ {} 随机行（单行子集）经真实 check_subset_violations 全捕获 ✓（总耗时 {:?}）",
        cross_family.len(),
        cross_single.len(),
        t0.elapsed()
    );
}
