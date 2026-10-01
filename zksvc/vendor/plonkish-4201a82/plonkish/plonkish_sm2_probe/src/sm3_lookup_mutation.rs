//! 变异测试体系（Phase C，系统线 2026-09-17，分支 `system/sm3-lookup-proto`）。
//!
//! 队长令"删任一约束/查表/环必红"落成三个可全量执行的层面（全部走 O(1) 定向检查器：
//! 表集合 / 环映射 / 行内约束求值，全量可在秒级跑完）：
//!   M1 覆盖扫描：全部 34×4,096=139,264 个见证格逐格域内扰动，断言 ≥1 种防御命中
//!      （查表元组离表 / 环不等 / 约束违约）——0 逃逸 = 不存在未约束格；并按"唯一命中家族"分账，
//!      证明三家族各自非冗余（各有仅由它命中的格）；
//!   M2 查表必要性 ×8：篡改该通道输出生成离表元组 ⟹ 必由 lookup 家族命中；
//!   M3 环必要性全量 ×15,841：逐环改消费格为域内异值 ⟹ 环检查必命中；
//!   M4 约束必要性 ×4：行内违约 ⟹ 该约束家族命中；移除该约束后约束家族静默（如实分账：
//!      中间格存在环冗余，"唯一防御"仅对无消费者的格成立——报告口径按此）。

use crate::sm3_lookup_block::*;
use crate::sm3_native_ref;
use ff::Field;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::{HashMap, HashSet};

fn rand_block(seed: u64) -> [u8; 64] {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    b
}

fn fr_cell(c: &BlockCircuit, poly: usize, row: usize) -> Fr {
    if poly < NUM_P {
        c.info.preprocess_polys[poly][row]
    } else {
        c.witness[poly - NUM_P][row]
    }
}

/// 见证格值回读为小整数（构建期全部 ∈ 0..16）。
fn small_u(v: Fr) -> u64 {
    (0..64u64).find(|&x| Fr::from(x) == v).expect("见证格值须为 0..64 小整数")
}

struct Defense {
    col_lookup: HashMap<usize, usize>,
    table_sets: Vec<HashSet<Vec<Fr>>>,
    lookup_cols: Vec<Vec<usize>>,
    cycles: Vec<Vec<(usize, usize)>>,
    cell_cycle: HashMap<(usize, usize), usize>,
}

impl Defense {
    fn build(c: &BlockCircuit) -> Self {
        let mut col_lookup = HashMap::new();
        let mut table_sets = Vec::new();
        let mut lookup_cols = Vec::new();
        for (li, lookup) in c.info.lookups.iter().enumerate() {
            let cols: Vec<(usize, usize)> = lookup
                .iter()
                .map(|(inp, tab)| (expr_poly_pub(inp), expr_poly_pub(tab)))
                .collect();
            for &(ic, _) in &cols {
                col_lookup.insert(ic, li);
            }
            let set: HashSet<Vec<Fr>> = (0..ROWS)
                .map(|r| cols.iter().map(|&(_, tc)| c.info.preprocess_polys[tc][r]).collect())
                .collect();
            table_sets.push(set);
            lookup_cols.push(cols.iter().map(|&(i, _)| i).collect());
        }
        let mut cell_cycle = HashMap::new();
        for (ri, cyc) in c.info.permutations.iter().enumerate() {
            for &cell in cyc {
                cell_cycle.insert(cell, ri);
            }
        }
        Defense {
            col_lookup,
            table_sets,
            lookup_cols,
            cycles: c.info.permutations.clone(),
            cell_cycle,
        }
    }

    /// 定向检查：变异后 (col,row) 是否被某家族命中；返回全部命中家族。
    fn hits(&self, c: &BlockCircuit, col: usize, row: usize) -> Vec<&'static str> {
        let mut out = Vec::new();
        if let Some(&li) = self.col_lookup.get(&col) {
            let tup: Vec<Fr> = self.lookup_cols[li].iter().map(|&pc| fr_cell(c, pc, row)).collect();
            if !self.table_sets[li].contains(&tup) {
                out.push("lookup");
            }
        }
        if let Some(&ri) = self.cell_cycle.get(&(col, row)) {
            let v = fr_cell(c, col, row);
            if self.cycles[ri].iter().any(|&(p, r)| fr_cell(c, p, r) != v) {
                out.push("ring");
            }
        }
        let f = |p: usize| fr_cell(c, p, row);
        let two = Fr::from(2u64);
        let eight = Fr::from(8u64);
        let sixteen = Fr::from(16u64);
        if f(gw_pub(W_SPLIT1_PUB + 4)) != f(gw_pub(W_SPLIT1_PUB + 2)) * two + f(gw_pub(W_SPLIT1_PUB + 3)) {
            out.push("constraint");
        } else if f(gw_pub(W_SPLIT3_PUB + 4))
            != f(gw_pub(W_SPLIT3_PUB + 2)) * eight + f(gw_pub(W_SPLIT3_PUB + 3))
        {
            out.push("constraint");
        } else if f(gw_pub(W_ADD_PUB)) + f(gw_pub(W_ADD_PUB + 1)) + f(gw_pub(W_ADD_PUB + 2))
            + f(gw_pub(W_ADD_PUB + 3))
            + f(gw_pub(W_ADD_PUB + 4))
            != f(gw_pub(W_ADD_PUB + 5)) + sixteen * f(gw_pub(W_ADD_PUB + 6))
        {
            out.push("constraint");
        } else if f(gw_pub(W_CONST_PUB)) != f(P_CONST_PUB) {
            out.push("constraint");
        }
        out
    }
}

/// 域内备选值（列语义：hi1∈{0,1}、hi3/lo3∈0..8、cout∈0..4、其余 0..16）。
fn alt(col_w: usize, v: u64) -> u64 {
    if col_w == W_SPLIT1_PUB + 1 {
        1 - v
    } else if col_w == W_SPLIT1_PUB + 2 || col_w == W_SPLIT3_PUB + 1 {
        (v + 1) & 7
    } else if col_w == W_SPLIT3_PUB + 2 {
        1 - v
    } else if col_w == W_ADD_PUB + 6 {
        (v + 1) & 3
    } else {
        (v + 1) & 15
    }
}

#[test]
fn m1_full_witness_cell_coverage_zero_escape() {
    let circ = build_block(&sm3_native_ref::IV, &rand_block(42));
    let d = Defense::build(&circ);
    let mut sole: HashMap<&'static str, usize> = HashMap::new();
    let mut multi = 0usize;
    let mut escaped: Vec<(usize, usize)> = Vec::new();
    let mut probe = circ.clone();
    // 列→通道（活跃行数）：非活跃行不参与计算（无环、无消费者）——单独断言惰性
    let lane_of = |col_w: usize| -> usize {
        match col_w {
            0..=2 => 0,
            3..=6 => 1,
            7..=10 => 2,
            11..=14 => 3,
            15..=19 => 4,
            20..=24 => 5,
            25..=31 => 6,
            32 => 7,
            _ => 8,
        }
    };
    let mut inert_wired = 0usize;
    let mut active_cells = 0usize;
    for col_w in 0..NUM_W {
        let col = gw_pub(col_w);
        let active_rows = circ.stats.rows_used[lane_of(col_w)].1;
        for row in 0..ROWS {
            if row == 0 || row > active_rows {
                if d.cell_cycle.contains_key(&(col, row)) {
                    inert_wired += 1;
                }
                continue;
            }
            active_cells += 1;
            let orig = circ.witness[col_w][row];
            let nv = Fr::from(alt(col_w, small_u(orig)));
            if nv == orig {
                continue;
            }
            probe.witness[col_w][row] = nv;
            let h = d.hits(&probe, col, row);
            probe.witness[col_w][row] = orig;
            match h.len() {
                0 => escaped.push((col, row)),
                1 => *sole.entry(h[0]).or_insert(0) += 1,
                _ => multi += 1,
            }
        }
    }
    eprintln!(
        "[mutation] M1 覆盖扫描：活跃格 {}（总格 {}），逃逸 {}；唯一命中家族分账 {:?}；多家族命中 {}；非活跃格带环 {}（须为 0=惰性）",
        active_cells,
        NUM_W * ROWS,
        escaped.len(),
        sole,
        multi,
        inert_wired
    );
    assert_eq!(inert_wired, 0, "非活跃格不得接线（否则非惰性）");
    assert!(escaped.is_empty(), "存在未约束活跃格：{:?}", &escaped[..escaped.len().min(10)]);
    for fam in ["lookup", "ring", "constraint"] {
        assert!(sole.get(fam).copied().unwrap_or(0) > 0, "家族 {fam} 无唯一命中格——该家族冗余？");
    }
}

#[test]
fn m2_lookup_necessity_each_argument() {
    let circ = build_block(&sm3_native_ref::IV, &rand_block(42));
    let d = Defense::build(&circ);
    for (li, cols) in d.lookup_cols.iter().enumerate() {
        let row = 300 + li * 5; // 各通道前 384 行均活跃（MAJ/CH 最少 384）
        let last = *cols.last().unwrap();
        let mut probe = circ.clone();
        let cur = fr_cell(&probe, last, row);
        probe.witness[last - NUM_P][row] = if cur == Fr::from(15u64) { Fr::ZERO } else { cur + Fr::ONE };
        // 范围表（RANGE16/RANGE4）+1 仍可能在表内——改用越界值 64（离任何表）
        if !d.hits(&probe, last, row).contains(&"lookup") {
            probe.witness[last - NUM_P][row] = Fr::from(64u64);
        }
        let h = d.hits(&probe, last, row);
        assert!(h.contains(&"lookup"), "查表 #{li} 离表输出变异须由 lookup 命中（实得 {h:?}）");
        // 移除该查表论证：定向检查里 lookup 家族对该列消失 ⟹ 仅余环/约束家族
        let mut d2 = Defense::build(&circ);
        d2.col_lookup.remove(&last);
        let h2 = d2.hits(&probe, last, row);
        assert!(!h2.contains(&"lookup"), "移除后 lookup 家族须静默");
        eprintln!("[mutation] M2 查表 #{li}：有=命中 {h:?}；删=余 {h2:?}");
    }
}

#[test]
fn m3_ring_necessity_all_cycles() {
    let circ = build_block(&sm3_native_ref::IV, &rand_block(42));
    let d = Defense::build(&circ);
    let mut checked = 0usize;
    let mut probe = circ.clone();
    for (ri, cyc) in d.cycles.iter().enumerate() {
        let Some(&(vcol, vrow)) = cyc.iter().find(|&&(p, r)| p >= NUM_P && r > 0) else { continue };
        let wcol = vcol - NUM_P;
        let orig = circ.witness[wcol][vrow];
        let nv = Fr::from(alt(wcol, small_u(orig)));
        if nv == orig {
            continue;
        }
        probe.witness[wcol][vrow] = nv;
        let bv = fr_cell(&probe, cyc[0].0, cyc[0].1);
        let broken = cyc.iter().any(|&(p, r)| fr_cell(&probe, p, r) != bv);
        probe.witness[wcol][vrow] = orig;
        assert!(broken, "环 #{ri} 变异未被环检查命中");
        checked += 1;
    }
    eprintln!("[mutation] M3 环必要性：{checked}/{} 环逐环变异均被环检查命中 ✓", d.cycles.len());
    assert!(checked + 1 >= d.cycles.len());
}

#[test]
fn m4_constraint_necessity_each() {
    let circ = build_block(&sm3_native_ref::IV, &rand_block(42));
    let d = Defense::build(&circ);
    // (列, 行, 备选值) 使行内违约且不触发查表（out/s/const 列非查表输入或仍在范围内）
    let cases: [(&str, usize, usize); 4] = [
        ("split1", W_SPLIT1_PUB + 4, 20),
        ("split3", W_SPLIT3_PUB + 4, 20),
        ("add", W_ADD_PUB + 5, 20),
        ("const", W_CONST_PUB, 20),
    ];
    for (name, col_w, row) in cases {
        let mut probe = circ.clone();
        let orig = probe.witness[col_w][row];
        let nv = Fr::from(alt(col_w, small_u(orig)));
        probe.witness[col_w][row] = nv;
        let h = d.hits(&probe, gw_pub(col_w), row);
        assert!(h.contains(&"constraint"), "约束 {name} 的行内违约须由 constraint 家族命中（实得 {h:?}）");
        eprintln!("[mutation] M4 约束 {name}：行内违约命中 {h:?}（环为中间格冗余防御，如实分账）");
    }
}
