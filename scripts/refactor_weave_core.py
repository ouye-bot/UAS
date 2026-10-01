"""B3b：weave_wires 拆 core（一次性重构脚本，用后归档）。"""
from pathlib import Path

p = Path("plonkish/plonkish_sm2_probe/src/sm3_lookup_weave.rs")
t = p.read_text(encoding="utf-8")

old_sig = '''/// WIRES 相（先于全语句首条 push——环登记 assert_open 红线）：
/// 见证值播种 + 环翻译 + 消息/摘要桥接。
///
/// `circ` = proto BlockBuilder 链式计算的完整产物（宿主值/环账本/逐块消息格）。
pub fn weave_wires(
    bld: &mut Builder<FpSM2>,
    circ: &BlockCircuit,
    plan: &LutPlan,
    msg_roots: &[[(usize, usize); 16]],
    dgw_cols: &[usize; 8],
    row_ae: usize,
) {'''

core_fn = '''/// B3b（飞证）：WIRES core——见证值播种（等值类代表值制）+环翻译（重叠 proto
/// 环并查集合并）。对任意 BlockCircuit 通用（三体链/SMT 链共用——列号约定
/// 教训㊶单一事实源：vcol 公式只在此处）。
pub fn weave_core(bld: &mut Builder<FpSM2>, circ: &BlockCircuit, plan: &LutPlan) {
    let groups = circ.wit_u64.len() / NUM_W;
    assert_eq!(groups, plan.advice.len(), "组数与 PLAN 不符");

    // 列映射：proto 全局列 → vendor advice 局部号
    let vcol = |proto_col: usize| -> usize {
        let rel = proto_col - NUM_P;
        plan.advice[rel / NUM_W][rel % NUM_W]
    };

    let np_total = circ.wit_u64.len();
    let total_cells = np_total * crate::sm3_lookup_block::ROWS;
    let mut parent: Vec<usize> = (0..total_cells).collect();
    let cell_idx = |p: usize, r: usize| (p - NUM_P) * crate::sm3_lookup_block::ROWS + r;
    fn find(p: &mut Vec<usize>, x: usize) -> usize {
        if p[x] == x { x } else { let r = find(p, p[x]); p[x] = r; r }
    }
    for cyc in &circ.info.permutations {
        if cyc.len() < 2 { continue; }
        let (p0, r0) = cyc[0];
        let mut root = find(&mut parent, cell_idx(p0, r0));
        for &(p, r) in cyc.iter().skip(1) {
            let rr = find(&mut parent, cell_idx(p, r));
            if rr != root { parent[rr] = root; root = find(&mut parent, root); }
        }
    }
    let mut repr: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
    for ci in 0..np_total {
        for r in 0..crate::sm3_lookup_block::ROWS {
            let v = circ.wit_u64[ci][r];
            if v == 0 { continue; }
            let root = find(&mut parent, cell_idx(NUM_P + ci, r));
            repr.entry(root).or_insert(v);
        }
    }
    for ci in 0..np_total {
        for r in 0..crate::sm3_lookup_block::ROWS {
            let v = circ.wit_u64[ci][r];
            let root = find(&mut parent, cell_idx(NUM_P + ci, r));
            let final_v = repr.get(&root).copied().unwrap_or(v);
            if final_v != 0 {
                bld.set_cell_f(vcol(NUM_P + ci), r, FpSM2::from(final_v));
            }
        }
    }

    let n_cyc = circ.info.permutations.len();
    let mut parent: Vec<usize> = (0..n_cyc).collect();
    let mut cell_first: std::collections::HashMap<(usize, usize), usize> =
        std::collections::HashMap::new();
    for (i, cyc) in circ.info.permutations.iter().enumerate() {
        for &(p, r) in cyc.iter() {
            let key = (vcol(p), r);
            match cell_first.get(&key) {
                Some(&j) => {
                    let (mut ra, mut rb) = (j, i);
                    while parent[ra] != ra { parent[ra] = parent[parent[ra]]; ra = parent[ra]; }
                    while parent[rb] != rb { parent[rb] = parent[parent[rb]]; rb = parent[rb]; }
                    if ra != rb { parent[ra] = rb; }
                }
                None => { cell_first.insert(key, i); }
            }
        }
    }
    let mut classes: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    for i in 0..n_cyc {
        let mut r = i;
        while parent[r] != r { r = parent[r]; }
        classes.entry(r).or_default().push(i);
    }
    for (_root, idxs) in classes {
        let mut done: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
        let mut ring_id: Option<usize> = None;
        for &i in &idxs {
            for &(p, r) in circ.info.permutations[i].iter() {
                let vl = vcol(p);
                if !done.insert((vl, r)) { continue; }
                match ring_id {
                    None => ring_id = Some(bld.begin_relay_col(vl, r)),
                    Some(id) => bld.relay_to_col(id, vl, r),
                }
            }
        }
    }
}

/// WIRES 相（先于全语句首条 push——环登记 assert_open 红线）：
/// 见证值播种 + 环翻译 + 消息/摘要桥接。
///
/// `circ` = proto BlockBuilder 链式计算的完整产物（宿主值/环账本/逐块消息格）。
pub fn weave_wires(
    bld: &mut Builder<FpSM2>,
    circ: &BlockCircuit,
    plan: &LutPlan,
    msg_roots: &[[(usize, usize); 16]],
    dgw_cols: &[usize; 8],
    row_ae: usize,
) {'''

assert old_sig in t, "签名锚未中"
t = t.replace(old_sig, core_fn, 1)

# ①④ 段替换为 core 调用：从 "let groups" 到 ④ 段结尾（"    }\n\n    // ── ④b" 前）
start = t.index("    let groups = circ.wit_u64.len() / NUM_W;")
end_marker = "    // ── ④b：C 词格单例环"
end = t.index(end_marker)
old_body = t[start:end]
new_body = '''    let groups = circ.wit_u64.len() / NUM_W;
    assert_eq!(groups, plan.advice.len(), "组数与 PLAN 不符");
    assert_eq!(circ.inputs_per_block.len(), groups, "块数与组数不符");
    assert_eq!(msg_roots.len(), groups, "消息根组数不符");

    // 列映射：proto 全局列 → vendor advice 局部号
    let vcol = |proto_col: usize| -> usize {
        let rel = proto_col - NUM_P;
        plan.advice[rel / NUM_W][rel % NUM_W]
    };

    // ── ①④ 已抽为 weave_core（B3b 飞证：三体链/SMT 链共用，教训㊶单一事实源）──
    weave_core(bld, circ, plan);

'''
t = t[:start] + new_body + t[end:]
p.write_text(t, encoding="utf-8")
print("core 拆分完成")
