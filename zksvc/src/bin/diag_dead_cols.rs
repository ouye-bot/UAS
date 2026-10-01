// 死列普查（2026-09-30 ZK 保底优化批）：对服务档 AUTH 装配做列触达分析——
// 约束/lookup 查询面与复制环面双零触达的 advice 列=死列（纯削减对象）。
// 口径与共享仓 bin/auth_census.rs ④面一致（vendor 快照 include_str 路径按
// 共享仓布局硬编码不可跑——本 bin 走 zksvc 服务装配路径，等价普查面）。
//
// 运行：cargo run --release --bin diag_dead_cols（装配 ~8s，零语义触碰）。

use std::collections::{BTreeMap, BTreeSet};

use plonkish_backend::util::expression::Expression;
use zksvc::assemble::assemble;

fn walk<F: ff::PrimeField>(e: &Expression<F>, out: &mut Vec<(usize, i64)>) {
    match e {
        Expression::Polynomial(q) => out.push((q.poly(), q.rotation().0 as i64)),
        Expression::Negated(a) => walk(a, out),
        Expression::DistributePowers(vs, a) => {
            for v in vs {
                walk(v, out);
            }
            walk(a, out);
        }
        Expression::Sum(a, b) | Expression::Product(a, b) => {
            walk(a, out);
            walk(b, out);
        }
        Expression::Scaled(a, _) => walk(a, out),
        _ => {}
    }
}

fn main() {
    std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");
    std::env::set_var("SM3_LUT", "1");
    let path = std::env::args().nth(1).unwrap_or_else(|| "tests/auth_canonical_spec.json".to_string());
    let text = std::fs::read_to_string(&path).expect("spec 不可读");
    let spec: zksvc::profile::JobSpec = serde_json::from_str(&text).expect("spec 损坏");
    let asm = assemble(&spec).expect("装配失败");
    let plonkish_sm2_probe::sm2_verify_assemble::Assembled { info, advice, ctags, tags, .. } = asm;
    let np = info.preprocess_polys.len();
    let ncols = advice.len();

    // ── 约束家族直方图 + 列分配账本（2026-09-30：进一步优化的归因面——
    //    剩余约束/列住在哪个 gadget 家族，决定后续手术的优先序）──
    let mut chist: BTreeMap<&'static str, usize> = BTreeMap::new();
    for t in &ctags {
        *chist.entry(t).or_insert(0) += 1;
    }
    let mut ch: Vec<(&'static str, usize)> = chist.into_iter().collect();
    ch.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    println!("== 约束家族直方图（前 15，合计 {}）==", ch.iter().map(|x| x.1).sum::<usize>());
    for (t, n) in ch.iter().take(15) {
        println!("  {:<30} {} ({:.1}%)", t, n, *n as f64 * 100.0 / info.constraints.len() as f64);
    }
    // （列按家族归因：本装配路径的 tags 字段与 ctags 同值（非列账本语义）——
    //  不打印误导面；列侧结论以死列/总列为准）
    println!("k={}（行域 {}）", info.k, 1usize << info.k);

    // 查询面：约束表达式 + lookup 表达式（⚠ lookup 列也是开口/求值消费面——
    // 死列判定必须含此面，否则误杀）
    let mut pairs: BTreeSet<(usize, i64)> = BTreeSet::new();
    for cc in info.constraints.iter() {
        for q in cc.used_query() {
            pairs.insert((q.poly(), q.rotation().0 as i64));
        }
    }
    for chan in &info.lookups {
        for (a, b) in chan {
            let mut refs = Vec::new();
            walk(a, &mut refs);
            walk(b, &mut refs);
            pairs.extend(refs);
        }
    }
    // 环面
    let mut col_ring: BTreeMap<usize, usize> = BTreeMap::new();
    for cyc in &info.permutations {
        for &(p, _) in cyc {
            if p > np + 1 {
                *col_ring.entry(p - 1 - np).or_insert(0) += 1;
            }
        }
    }
    let queried: BTreeSet<usize> = pairs.iter().filter(|&&(p, _)| p > np + 1).map(|&(p, _)| p - 1 - np).collect();
    let ringed: BTreeSet<usize> = col_ring.keys().copied().collect();
    let dead: Vec<usize> = (0..ncols).filter(|c| !queried.contains(c) && !ringed.contains(c)).collect();
    println!(
        "constraints={} advice(ncols)={} prep={} lookups={} rings={}",
        info.constraints.len(), ncols, np, info.lookups.len(), info.permutations.len()
    );
    println!(
        "查询列={} 环覆盖列={} 死列(双零触达)={} ({:.1}%)",
        queried.len(), ringed.len(), dead.len(), dead.len() as f64 * 100.0 / ncols as f64
    );
    if !dead.is_empty() {
        println!("死列清单（首 60）: {:?}", &dead[..dead.len().min(60)]);
        // 连续段压缩展示（死区形态一目了然）
        let mut runs: Vec<(usize, usize)> = Vec::new();
        for &c in &dead {
            match runs.last_mut() {
                Some(r) if r.1 + 1 == c => r.1 = c,
                _ => runs.push((c, c)),
            }
        }
        println!("死列连续段（start..end，共 {} 段）:", runs.len());
        for (s, e) in runs.iter().take(30) {
            println!("  {}..{}（{} 列）", s, e, e - s + 1);
        }
    }
}
