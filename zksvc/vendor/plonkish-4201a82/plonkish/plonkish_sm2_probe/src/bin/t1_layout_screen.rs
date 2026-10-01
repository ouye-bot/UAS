//! A4 · 窗口一前置：全语句电路布局变体筛查器（2026-09-15）。
//!
//! v3b 方法论的本地前置件（求解→施工→census 复测→归因回填）：
//! - **施工**：`A4_LETTER_OFF` 环境变量注入字母偏移变体（默认=现役 T4-lite 表）；
//!   布局变体只改行序——结构不变断言（201,183/11,663/370/1,957——2026-10 实测钉 + max|rot|≤K
//!   + 环审计零坏环）在每次施工后强制复验；`A4_LIGHT=1` 跳过全量约束对账
//!   （变体筛选用，默认全量）。
//! - **census 复测**：去重 (列, 旋转) 对全表 + 按距离直方图 + E +
//!   **逐列 e_c**（列 c 的 Σ 2^|d|，与论文 §7.7 同口径）。
//! - **位面感知代价项**：heavy 质量与 heavy 列数（e_c>11 的列——与泄漏位面
//!   （124 单比特列 + 288 位道列 + 奇偶垫词列）同族的开口面，B5 隐私布局
//!   与 A2 成本布局的共享筛选量）。
//! - **停机规则**（A-r2）：e_c≤11 归其余类；e_c>11 列入 halt 清单逐列报告
//!   （含约束家族归因）——变体若使 halt 清单恶化即淘汰。
//! 输出：人读报告 + 单行 JSON（`A4_JSON_LOG` 路径时追加,便于变体枚举聚合）。
//! 用法（变体枚举）：外层驱动循环设 A4_LETTER_OFF=<8 互异 0..16> 逐变体调用,
//! 聚合 JSON 筛选 ≤3 个候选进服务器窗口。

use plonkish_sm2_probe::sm2_full_statement_assemble::{
    assemble_full_statement_with_hooks_bound, witness_from_with_exp,
};
use ff::Field as _;
use plonkish_sm2_probe::FpSM2;
use std::collections::{BTreeMap, BTreeSet};

fn main() {
    let t0 = std::time::Instant::now();
    let variant = std::env::var("A4_LETTER_OFF").unwrap_or_else(|_| "default".into());
    let light = std::env::var("A4_LIGHT").map(|v| v == "1").unwrap_or(false);

    let base = witness_from_with_exp(
        [0x0A1B_2C3D_4E5F_6071, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22],
        [7u8; 32],
        [0x33u64, 0, 0, 0x5EED],
        501,
    );
    let (asm, _) = assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
    let np = asm.info.preprocess_polys.len();

    // ── 结构不变断言（布局只改行序；任何漂移=施工事故,当场爆）──
    assert_eq!(asm.info.constraints.len(), 201_183, "约束总数漂移（2026-10-01 实测钉：旧钉 225,724→db0bbb3 实测 201,443，本次 −260 acc.chain 去重）");
    assert_eq!(asm.advice.len(), 11_663, "advice 列数漂移");
    assert_eq!(asm.info.permutations.len(), 1_957, "复制环数漂移");
    assert_eq!(asm.num_selectors, 370, "选择子数漂移");
    let maxd = asm
        .info
        .constraints
        .iter()
        .map(|cc| cc.max_used_rotation_distance())
        .max()
        .unwrap_or(0);
    assert!(maxd <= plonkish_sm2_probe::sm3_compress::K, "max|rot|={maxd} 超预算");
    assert!(
        plonkish_sm2_probe::sm3_compress::audit_ring_values(&asm.info, &asm.advice).is_empty(),
        "环取值不一致（布局施工破坏环语义）"
    );
    if !light {
        let bad = plonkish_sm2_probe::sm3_compress::check_parts_violations(
            &asm.info, &asm.advice, &asm.instances,
        );
        assert!(bad.is_empty(), "诚实见证违约 {} 条（变体施工事故）", bad.len());
    }

    // ── census：去重 (poly, rot) 对 + 按距离直方图 + E ──
    let mut pairs: BTreeSet<(usize, i64)> = BTreeSet::new();
    for cc in &asm.info.constraints {
        for q in cc.used_query() {
            pairs.insert((q.poly(), q.rotation().0 as i64));
        }
    }
    let mut by_d: BTreeMap<i64, usize> = BTreeMap::new();
    for (_, d) in &pairs {
        *by_d.entry(d.abs()).or_insert(0) += 1;
    }
    let cur = *by_d.get(&0).unwrap_or(&0);
    let units: u128 = by_d
        .iter()
        .filter(|(&d, _)| d > 0)
        .map(|(&d, &n)| n as u128 * (1u128 << d))
        .sum();
    let e_total = cur as u128 + units;

    // ── 逐列 e_c + 停机规则分类 + 家族归因 ──
    let mut col_ec: BTreeMap<usize, u128> = BTreeMap::new(); // (poly-1-np) 局部列号
    for &(poly, d) in &pairs {
        if poly > np {
            *col_ec.entry(poly - 1 - np).or_insert(0) += 1u128 << d.abs();
        }
    }
    // 列 → 约束家族集（归因）
    let mut col_ctags: BTreeMap<usize, BTreeSet<&'static str>> = BTreeMap::new();
    for (ci, cc) in asm.info.constraints.iter().enumerate() {
        for q in cc.used_query() {
            if q.poly() > np {
                col_ctags
                    .entry(q.poly() - 1 - np)
                    .or_default()
                    .insert(asm.ctags[ci]);
            }
        }
    }
    let mut rest_cols = 0usize;
    let mut halt_cols: Vec<(usize, u128)> = Vec::new();
    for (&c, &ec) in &col_ec {
        if ec <= 11 {
            rest_cols += 1;
        } else {
            halt_cols.push((c, ec));
        }
    }
    halt_cols.sort_by_key(|(_, ec)| std::cmp::Reverse(*ec));
    // 位面感知代价项：heavy 质量 = Σ e_c(e_c>11 列)（开口位面驱动的代理量）
    let heavy_mass: u128 = halt_cols.iter().map(|&(_, ec)| ec).sum();
    let heavy_count = halt_cols.len();

    println!(
        "[A4-SCREEN] variant={variant} 结构=201,183/11,663/370/1,957 ✓ max|rot|={maxd} cur={cur} units={units} E={e_total} heavy(count={heavy_count},mass={heavy_mass}) rest(e_c≤11)={rest_cols} 耗时{:?}",
        t0.elapsed()
    );
    println!(
        "[A4-SCREEN] by_d={:?}",
        by_d.iter().map(|(&d, &n)| (d, n)).collect::<Vec<_>>()
    );
    // halt 清单首 16 列逐列归因（e_c>11 停机规则;变体比对的核心表）
    for &(c, ec) in halt_cols.iter().take(16) {
        let tags: Vec<&str> = col_ctags.get(&c).map(|s| s.iter().copied().collect()).unwrap_or_default();
        println!("[A4-SCREEN]   halt col advice[{c}] e_c={ec} families={:?}", tags);
    }

    // ── 秩表转储(A4_DUMP_RANKS=1):rank→point 全表(求解器算术用)──
    if std::env::var("A4_DUMP_RANKS").map(|v| v == "1").unwrap_or(false) {
        let inv = plonkish_sm2_probe::sm3_compress::rank_inverse();
        for (rk, &pt) in inv.iter().enumerate() {
            println!("[A4-RANK] {} {}", rk, pt);
        }
    }

    // ── 边表转储(A4_EDGE_DUMP=1):全部 |rot|≥5 的 (列,rot,写点,读点) JSONL──
    if std::env::var("A4_EDGE_DUMP").map(|v| v == "1").unwrap_or(false) {
        use plonkish_sm2_probe::sm3_compress::ROWS as ROWS_N;
        let cube = plonkish_backend::util::arithmetic::BooleanHypercube::new(plonkish_sm2_probe::sm3_compress::K);
        let inv_rank2 = plonkish_sm2_probe::sm3_compress::rank_inverse();
        let mut p2r = vec![usize::MAX; ROWS_N];
        for (rk, &pt) in inv_rank2.iter().enumerate() {
            if pt < p2r.len() { p2r[pt] = rk; }
        }
        let np2 = asm.info.preprocess_polys.len();
        // 每列写点(单写点列才转储;多写点列标 MULTI)
        for &(poly, rot) in pairs.iter() {
            if rot.abs() < 5 { continue; }
            if poly <= np2 { continue; }
            let col = poly - 1 - np2;
            let nzw: Vec<usize> = asm.advice[col].iter().enumerate()
                .filter(|(_, v)| **v != FpSM2::ZERO).map(|(pt, _)| pt).collect();
            let tag = if nzw.len() == 1 { format!("pt{}", nzw[0]) } else { format!("MULTI{}", nzw.len()) };
            let (wpt, wrk) = if nzw.len() == 1 {
                (nzw[0].to_string(), format!("rk{}", p2r[nzw[0]]))
            } else { (tag.clone(), "NA".into()) };
            // at 点 = rotate(w, -rot)(单写点列);否则解码引用约束(真值)
            let at_info = if nzw.len() == 1 {
                let at = cube.rotate(nzw[0], plonkish_backend::util::expression::Rotation(-rot as i32));
                format!("at_pt{} at_rk{}", at, p2r[at])
            } else {
                let mut seen = 0usize;
                let mut desc = String::new();
                'cons: for (ci, cc) in asm.info.constraints.iter().enumerate() {
                    for q in cc.used_query() {
                        if q.poly() == poly && q.rotation().0 as i64 == rot {
                            let mut ats: Vec<String> = Vec::new();
                            for q2 in cc.used_query() {
                                if q2.rotation().0 == 0 && q2.poly() >= 1 && q2.poly() <= np2 + 1 {
                                    for (ptc, v) in asm.info.preprocess_polys[q2.poly() - 1].iter().enumerate() {
                                        if *v != FpSM2::ZERO && ats.len() < 3 {
                                            ats.push(format!("rk{}", p2r[ptc]));
                                        }
                                    }
                                }
                            }
                            desc = format!("ctag={} at[{}] #{}", asm.ctags[ci], ats.join(","), ci);
                            seen += 1;
                            if seen >= 1 { break 'cons; }
                        }
                    }
                }
                desc
            };
            println!("[A4-EDGE] {{\"col\":{},\"rot\":{},\"writer\":\"{}\",\"wrk\":\"{}\",\"{}\",\"ec\":{}}}",
                col, rot, wpt, wrk, at_info, col_ec.get(&col).copied().unwrap_or(0));
        }
    }

    // ── 驻点探针(A4_WRITER_PROBE=1):top halt 列的非零见证点(=写入行地面真值)──
    if std::env::var("A4_WRITER_PROBE").map(|v| v == "1").unwrap_or(false) {
        let inv_rank = plonkish_sm2_probe::sm3_compress::rank_inverse();
        let mut pt2rk = vec![usize::MAX; plonkish_sm2_probe::sm3_compress::ROWS];
        for (rk, &pt) in inv_rank.iter().enumerate() {
            if pt < pt2rk.len() {
                pt2rk[pt] = rk;
            }
        }
        for &(c, _ec) in halt_cols.iter().take(16) {
            let pts: Vec<String> = asm.advice[c]
                .iter()
                .enumerate()
                .filter(|(_, v)| **v != FpSM2::ZERO)
                .map(|(pt, _)| {
                    let rk = pt2rk[pt];
                    if rk == usize::MAX { format!("pt{pt}/rk?") } else { format!("pt{pt}/rk{rk}") }
                })
                .take(12)
                .collect();
            println!(
                "[A4-WRITER] advice[{c}] e_c={} families={:?} nonzero_pts(≤12)={}",
                col_ec[&c],
                col_ctags.get(&c).map(|x| x.iter().copied().collect::<Vec<_>>()).unwrap_or_default(),
                pts.join(" ")
            );
        }
    }

    // 单行 JSON（机器聚合;A4_JSON_LOG 设置时追加文件）
    let json = format!(
        "{{\"variant\":\"{}\",\"constraints\":225724,\"advice\":11663,\"selectors\":370,\"rings\":1957,\"max_rot\":{},\"cur\":{},\"units\":{},\"E\":{},\"heavy_count\":{},\"heavy_mass\":{},\"rest_cols\":{},\"secs\":{:.1}}}\n",
        variant.replace('\"', "'"),
        maxd, cur, units, e_total, heavy_count, heavy_mass, rest_cols,
        t0.elapsed().as_secs_f32()
    );
    if let Ok(path) = std::env::var("A4_JSON_LOG") {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = f.write_all(json.as_bytes());
        }
    }
    print!("[A4-JSON] {}", json);
}
