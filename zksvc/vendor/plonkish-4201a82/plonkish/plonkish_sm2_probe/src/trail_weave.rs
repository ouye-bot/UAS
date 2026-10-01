//! 飞证 B6：TRAIL 语句织入（proto 独立电路后处理——范围门/时间门/链头钉）。
//!
//! 语义（A5 收窄：「已锚定记录中的全部高度样本满足上限」）：
//! - 范围门：alt_i ≤ alt_max——δ′=alt_max−alt 域内 16 位分解+bool+recomb
//!   （读数源=每块消息词 9 高 16 位（alt BE2），θ 门同构机制）
//! - 时间门：t_{i+1}−t_i==500（2Hz 严格连续，n−1 个配对行）
//! - 链头钉：fold(末块摘要)==chain_head 实例（锚定面绑定——B6-d7：设备签
//!   名在链上锚定时验证并上链不可篡改，电路强制链头==锚定链头即完整性绑定）
//! - t_start 钉：首块词 8==t_start
//!
//! 编号纪律（后处理织入）：instance 占 poly 0（num_instances=[1] 单值，家点=
//! row_mapping()[0]=pt1，与链头影子行同点）；**选择器=preprocess 常量列**
//! （z_range/z_time/z_head/z_tstart——B6-d9 拍板：z 作 witness 是健全性漏洞，
//! 恶意证明者可置 z≡0 使全部 EMIT 门空转；prep=验证方可见锚定，AUTH 的
//! dgw/msg sel 同法先例）。proto prep 0 基/advice 24 基 → 标准 prep 1 基/
//! advice 29 基（+1 实例位 +4 z prep 位）。
//! 影子行法（教训㊿+10）：共享列×唯一样本行，limb 值经环桥等值进影子格；
//! 共享列形态下 16 bool+1 recomb 对全部样本行是同一表达式——全局一份即足
//! （per-sample 复制=冗余，B6-T2 实跑定谳后除）。
//!
//! 🔴 B6-T2 根治守卫（2026-09-21 定谳后固化的四道防线——错位类 bug 当场爆）：
//! ①host 差分：电路 digest 必须==host 链头（链语义漂移 fail-closed）；
//! ②编号基底断言（NP/NZ 常量==实际 prep 构成）；
//! ③桥接回读：每个环条目双方经标准号回读值必须==播种值（Query 号/witness
//!   实列错位——含 off-by-one——当场 panic）；
//! ④链头钉 Query 号清单==期望清单（EMIT 段演化引入编号错位的独立对账）。

use crate::sm3_lookup_block::NUM_W;
use crate::sm3_lookup_block::ROWS;
use crate::trail_host::TrailSamples;
use crate::FpSM2;
use plonkish_backend::util::expression::{Expression, Query, Rotation};

pub struct TrailCircuit {
    pub info: plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>,
    pub witness: Vec<Vec<FpSM2>>,
    pub instances: Vec<Vec<FpSM2>>,
}

pub struct TrailWiring {
    pub samples: TrailSamples,
    pub alt_max_cm: u16,
    pub t_start: u32,
    /// 锚定链头折叠值（诚实=末头折叠；负例=替换锚定头）。
    pub head_fold: FpSM2,
}

const W_INPUT: usize = 33;
const NP: usize = 24; // proto prep poly 数（P_CONST+23 表）
const NZ: usize = 6;  // z 选择器 prep poly 数（range/time/head/tstart/altpin/tstartpin）
                      // 2026-10 换代：+2 钉选择器（alt_max/t_start 约束常量→公开实例）。

fn shadow_row(kind: u16, i: usize) -> usize {
    match kind {
        0 => 64 + i,      // 范围行 64..192
        1 => 256 + i,     // 时间行 256..384
        _ => 400,         // 链头行
    }
}

/// EMIT 段约束布局（负例门专属断言/消费方对账用）：
/// [bool 起点, recomb, time, head, tstart, altpin, tstartpin]——proto 段=4n 条在前。
/// 2026-10 换代：+2 实例钉（altpin/tstartpin——alt_max/t_start 迁公开实例，
/// 参照 AUTH pin.bind 形态；头钉/负例门序号 0..4 不变）。
pub fn gate_layout(n: usize) -> [usize; 7] {
    let proto = 4 * n;
    [proto, proto + 16, proto + 17, proto + 18, proto + 19, proto + 20, proto + 21]
}

/// proto→标准编号规范化（双基底拆分）：proto prep 0 基→标准 1 基（+1）；
/// proto advice 24 基→标准 29 基（+1 实例位+NZ z prep 位）。
fn shift_poly_expr(e: &Expression<FpSM2>) -> Expression<FpSM2> {
    use plonkish_backend::util::expression::CommonPolynomial;
    let shift_q = |q: &Query| {
        let p = if q.poly() < NP { q.poly() + 1 } else { q.poly() + 1 + NZ };
        Query::new(p, q.rotation())
    };
    match e {
        Expression::Constant(c) => Expression::Constant(*c),
        Expression::CommonPolynomial(c) => Expression::CommonPolynomial(*c),
        Expression::Polynomial(q) => Expression::Polynomial(shift_q(q)),
        Expression::Challenge(c) => Expression::Challenge(*c),
        Expression::Negated(a) => Expression::Negated(Box::new(shift_poly_expr(a))),
        Expression::Sum(a, b) => {
            Expression::Sum(Box::new(shift_poly_expr(a)), Box::new(shift_poly_expr(b)))
        }
        Expression::Product(a, b) => {
            Expression::Product(Box::new(shift_poly_expr(a)), Box::new(shift_poly_expr(b)))
        }
        Expression::Scaled(a, s) => {
            Expression::Scaled(Box::new(shift_poly_expr(a)), *s)
        }
        Expression::DistributePowers(exprs, base) => Expression::DistributePowers(
            exprs.iter().map(shift_poly_expr).collect(),
            Box::new(shift_poly_expr(base)),
        ),
    }
}

/// 表达式 Query 号清单收集（守卫④用——独立于构造过程的对账）。
fn collect_queries(e: &Expression<FpSM2>, out: &mut Vec<(usize, i32)>) {
    match e {
        Expression::Polynomial(q) => out.push((q.poly(), q.rotation().0)),
        Expression::Negated(a) => collect_queries(a, out),
        Expression::Scaled(a, _) => collect_queries(a, out),
        Expression::Sum(a, b) | Expression::Product(a, b) => {
            collect_queries(a, out);
            collect_queries(b, out);
        }
        Expression::DistributePowers(es, base) => {
            for x in es.iter() {
                collect_queries(x, out);
            }
            collect_queries(base, out);
        }
        _ => {}
    }
}

/// 织入主入口。
pub fn weave_trail(circ: &crate::sm3_lookup_block::BlockCircuit, w: &TrailWiring) -> TrailCircuit {
    let n = w.samples.blocks.len();
    let groups = circ.wit_u64.len() / NUM_W;
    assert_eq!(groups, n, "组数==样本数");

    // ── 守卫①host 差分（fail-closed）：电路链头必须==host 单一事实源链头 ──
    // B6-T2 根因（chain_circuit 的 IV 链传语义误用）即被本行当场拦截。
    for k in 0..8usize {
        let wv = u32::from_be_bytes(
            w.samples.head[4 * k..4 * k + 4].try_into().expect("界内"),
        );
        assert_eq!(circ.digest[k], wv, "电路 digest word {k} ≠ host 链头——链语义漂移");
    }

    let mut info = circ.info.clone();
    // ── 守卫②编号基底：proto prep 构成断言（shift 双基底规则的前提） ──
    assert_eq!(NP, info.preprocess_polys.len(), "NP 常量与 proto prep poly 数漂移");

    // 编号规范化（prep +1；advice +1+NZ——instance 占 0、z prep 占 1+NP..1+NP+NZ）
    for c in info.constraints.iter_mut() {
        *c = shift_poly_expr(c);
    }
    for lk in info.lookups.iter_mut() {
        for (a, b) in lk.iter_mut() {
            *a = shift_poly_expr(a);
            *b = shift_poly_expr(b);
        }
    }
    for cyc in info.permutations.iter_mut() {
        for (p, r) in cyc.iter_mut() {
            *p += 1 + NZ; // 环条目全为 advice 格（proto col ≥ NUM_P）
            let _ = r;
        }
    }

    // ── z 选择器=preprocess 常量列（B6-d9：验证方可见锚定，堵 witness-z 空转） ──
    let range_rows: Vec<usize> = (0..n).map(|i| shadow_row(0, i)).collect();
    let time_rows: Vec<usize> = (0..n - 1).map(|i| shadow_row(1, i)).collect();
    let head_row = crate::sm3_compress::row_mapping()[0]; // 家点对齐（=点 1）
    let mut mk_sel = |ones: &[usize]| -> Vec<FpSM2> {
        let mut col = vec![FpSM2::from(0u64); ROWS];
        for &r in ones {
            col[r] = FpSM2::from(1u64);
        }
        col
    };
    let z_range_col = mk_sel(&range_rows);
    let z_time_col = mk_sel(&time_rows);
    let z_head_col = mk_sel(&[head_row]);
    let z_tstart_col = mk_sel(&[time_rows[0]]);
    // 2026-10 换代：alt_max/t_start 钉选择器（实例家点行——值落 row_mapping()[1/2]，
    // 与 shadow_row 影子带无碰撞，守卫断言在下方）。
    let alt_pin_row = crate::sm3_compress::row_mapping()[1];
    let tstart_pin_row = crate::sm3_compress::row_mapping()[2];
    assert!(
        !range_rows.contains(&alt_pin_row)
            && !time_rows.contains(&alt_pin_row)
            && alt_pin_row != head_row,
        "alt_max 钉行 {alt_pin_row} 撞影子/家点行——row_mapping 布局漂移"
    );
    assert!(
        !range_rows.contains(&tstart_pin_row)
            && !time_rows.contains(&tstart_pin_row)
            && tstart_pin_row != head_row,
        "t_start 钉行 {tstart_pin_row} 撞影子/家点行——row_mapping 布局漂移"
    );
    let z_altpin_col = mk_sel(&[alt_pin_row]);
    let z_tstartpin_col = mk_sel(&[tstart_pin_row]);
    info.preprocess_polys.push(z_range_col);
    info.preprocess_polys.push(z_time_col);
    info.preprocess_polys.push(z_head_col);
    info.preprocess_polys.push(z_tstart_col);
    info.preprocess_polys.push(z_altpin_col);
    info.preprocess_polys.push(z_tstartpin_col);
    let z_range = 0usize; // z poly 序（标准号=1+NP+zi）
    let z_time = 1usize;
    let z_head = 2usize;
    let z_tstart = 3usize;
    let z_altpin = 4usize;
    let z_tstartpin = 5usize;
    let np = info.preprocess_polys.len();
    assert_eq!(np, NP + NZ, "织入后 prep 构成漂移");

    let mut witness = circ.witness.clone();
    let zero = FpSM2::from(0u64);

    // ── PLAN：影子列（witness 追加=advice 编号零移位——z 已迁 prep） ──
    let mut alloc_w = |witness: &mut Vec<Vec<FpSM2>>| {
        witness.push(vec![zero; ROWS]);
        witness.len() - 1
    };
    let range_shadow: [usize; 4] = std::array::from_fn(|_| alloc_w(&mut witness));
    let delta_cols: [usize; 16] = std::array::from_fn(|_| alloc_w(&mut witness));
    let time_shadow: [usize; 16] = std::array::from_fn(|_| alloc_w(&mut witness));
    let head_shadow: [usize; 64] = std::array::from_fn(|_| alloc_w(&mut witness));
    // 2026-10 换代：实例值中继列 ×2（alt_max/t_start——约束常量迁公开实例，
    // 门的消费行与实例家点相距 >K 不可旋转 ⟹ 中继环缝合，AUTH rid_pred_pin
    // 同款先例）。
    let inst_relay: [usize; 2] = std::array::from_fn(|_| alloc_w(&mut witness));

    // proto 列/行映射
    let word_limb_row = |j: usize, k: usize| 1 + 8 * j + k;
    let pcol = |g: usize, lane: usize| 1 + NP + NZ + g * NUM_W + lane; // 标准号
    let msg_limb = |g: usize, j: usize, k: usize| -> u64 {
        circ.wit_u64[g * NUM_W + W_INPUT][word_limb_row(j, k)]
    };

    // ── WIRES+播种 ──
    // 守卫③桥接回读：环条目双方经「标准号→witness 实列」回读必须==播种值——
    // 任何 off-by-one/基底漂移当场 panic。
    let mut perms: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut bridge = |perms: &mut Vec<Vec<(usize, usize)>>,
                      proto: (usize, usize),
                      shadow_col: usize,
                      row: usize,
                      val: u64,
                      witness: &mut Vec<Vec<FpSM2>>| {
        witness[shadow_col][row] = FpSM2::from(val);
        let (pp, pr) = proto;
        assert!(pp > np, "桥接 proto 侧 poly {pp} 落进 instance/prep 段——编号错位");
        assert_eq!(
            witness[pp - 1 - np][pr],
            FpSM2::from(val),
            "桥接 proto 格 (poly {pp}, row {pr}) 标准号回读≠播种值——Query/witness 错位"
        );
        let sp = 1 + NP + NZ + shadow_col;
        assert_eq!(
            witness[sp - 1 - np][row],
            FpSM2::from(val),
            "桥接影子格 (poly {sp}, row {row}) 标准号回读≠播种值——编号错位"
        );
        perms.push(vec![proto, (sp, row)]);
    };

    let alt_max_e = FpSM2::from(u64::from(w.alt_max_cm));
    let t_start_e = FpSM2::from(u64::from(w.t_start));
    for i in 0..n {
        let r = range_rows[i];
        for (jj, k) in (4..8).enumerate() {
            let v = msg_limb(i, 9, k);
            bridge(&mut perms, (pcol(i, W_INPUT), word_limb_row(9, k)), range_shadow[jj], r, v, &mut witness);
        }
        // δ′=alt_max−alt（诚实态 <2^16；负例态为大数=位分解必败）
        let dv = u64::from(w.alt_max_cm).wrapping_sub(u64::from(w.samples.rows[i].1));
        for k in 0..16usize {
            witness[delta_cols[k]][r] = FpSM2::from((dv >> k) & 1);
        }
    }
    for i in 0..n - 1 {
        let r = time_rows[i];
        for (half, gi) in [(0usize, i), (1usize, i + 1)] {
            for jj in 0..8usize {
                let v = msg_limb(gi, 8, jj);
                bridge(&mut perms, (pcol(gi, W_INPUT), word_limb_row(8, jj)), time_shadow[half * 8 + jj], r, v, &mut witness);
            }
        }
    }
    for (k, word) in circ.digest_cells.iter().enumerate() {
        for (j, limb) in word.iter().enumerate() {
            let v = circ.wit_u64[limb.col - NP][limb.row];
            // 链头影子布局：影子列 k*8+j（64 格唯一）——fold 权重=2^{32k+4j}
            // proto 侧标准号=limb.col+1+NZ（digest_cells 的 col 是 proto 24 基）
            let sc = head_shadow[k * 8 + j];
            bridge(&mut perms, (limb.col + 1 + NZ, limb.row), sc, head_row, v, &mut witness);
        }
    }

    // ── 2026-10 换代：实例值中继环 ×2（alt_max/t_start 迁公开实例）──
    // 中继格=门消费行（值侧）+ 实例家点行（钉侧）同列复制环；守卫③同款
    // 回读断言（标准号回读==播种值）。钉侧约束见 EMIT ⑤⑥（z_altpin/
    // z_tstartpin 家点行单点门控 → q_inst）。
    let sp_relay = |c: usize| 1 + NP + NZ + c;
    {
        // alt_max：n 个范围行 + 家点行 rm[1]，单环 n+1 成员。
        let mut cyc: Vec<(usize, usize)> = Vec::with_capacity(n + 1);
        witness[inst_relay[0]][alt_pin_row] = alt_max_e;
        cyc.push((sp_relay(inst_relay[0]), alt_pin_row));
        for &r in &range_rows {
            witness[inst_relay[0]][r] = alt_max_e;
            cyc.push((sp_relay(inst_relay[0]), r));
        }
        for &(p, r) in &cyc {
            assert_eq!(
                witness[p - 1 - np][r],
                alt_max_e,
                "alt_max 中继格 (poly {p}, row {r}) 回读≠播种值——编号错位"
            );
        }
        perms.push(cyc);
    }
    {
        // t_start：首时间行 + 家点行 rm[2]，双成员环。
        let cyc = vec![
            (sp_relay(inst_relay[1]), tstart_pin_row),
            (sp_relay(inst_relay[1]), time_rows[0]),
        ];
        witness[inst_relay[1]][tstart_pin_row] = t_start_e;
        witness[inst_relay[1]][time_rows[0]] = t_start_e;
        for &(p, r) in &cyc {
            assert_eq!(
                witness[p - 1 - np][r],
                t_start_e,
                "t_start 中继格 (poly {p}, row {r}) 回读≠播种值——编号错位"
            );
        }
        perms.push(cyc);
    }
    info.permutations.extend(perms);

    // ── 守卫①b：64 影子格 vs digest limb 常开对拍 ──
    for idx in 0..64usize {
        let k = idx / 8;
        let j = idx % 8;
        let want = (circ.digest[k] >> (4 * j)) & 15;
        assert_eq!(
            witness[head_shadow[idx]][head_row],
            FpSM2::from(u64::from(want)),
            "链头影子 idx={idx} (k{k}j{j}) ≠ digest limb——播种漂移"
        );
    }

    // ── EMIT（z prep 门控；advice 全局号=1+NP+NZ+local）──
    let qa = |local: usize| Expression::<FpSM2>::Polynomial(Query::new(1 + NP + NZ + local, Rotation::cur()));
    let zq = |zi: usize| Expression::<FpSM2>::Polynomial(Query::new(1 + NP + zi, Rotation::cur()));
    let q_inst = || Expression::<FpSM2>::Polynomial(Query::new(0, Rotation::cur()));

    // ① 范围门：16 bool+1 recomp 全局一份（共享列+影子行——z_range=1 恰在
    // n 个样本行，同一表达式覆盖全部行；per-sample 复制=冗余已除）
    for k in 0..16usize {
        let b = qa(delta_cols[k]);
        info.constraints.push(
            zq(z_range) * (b.clone() * b.clone() - b.clone() - Expression::<FpSM2>::Constant(FpSM2::from(0u64))),
        );
    }
    {
        let mut rec = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
        for k in 0..16usize {
            rec = rec + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << k)) * qa(delta_cols[k]);
        }
        for (jj, col) in range_shadow.iter().enumerate() {
            rec = rec + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << (4 * jj))) * qa(*col);
        }
        // Σ2^k·δ′_k + Σ2^{4j}·shadow_j == alt_max（bool 位+域内等式 ⟹ δ′∈[0,2^16)
        // 且 δ′=alt_max−alt ⟹ alt ≤ alt_max；负例 alt>max ⟹ δ′ 为 2^64 域大数、
        // 低 16 位组装+alt ≠ alt_max ⟹违约）。2026-10 换代：alt_max 自公开实例
        // 1 经中继环读入（约束常量拆除——上限改由验证方实例面钉定）。
        rec = rec - qa(inst_relay[0]);
        info.constraints.push(zq(z_range) * rec);
    }
    // ② 时间门（1 条 ×(n−1) 配对行 z_time 门控）
    {
        let mut rec = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
        for jj in 0..8usize {
            let hi = qa(time_shadow[8 + jj]);
            let lo = qa(time_shadow[jj]);
            rec = rec + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << (4 * jj))) * (hi - lo);
        }
        rec = rec - Expression::<FpSM2>::Constant(FpSM2::from(500u64));
        info.constraints.push(zq(z_time) * rec);
    }
    // ③ 链头钉（fold==实例值；f_pow2 权威派生——教训㊿+15）
    let head_pin_full = {
        let mut rec = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
        for (idx, col) in head_shadow.iter().enumerate() {
            let k = idx / 8;
            let j = idx % 8;
            rec = rec
                + Expression::<FpSM2>::Constant(crate::sm2_params::f_pow2(32 * k + 4 * j))
                    * qa(*col);
        }
        zq(z_head) * (rec - q_inst())
    };
    // ── 守卫④：链头钉 Query 号清单==期望清单（独立于构造过程的对账） ──
    {
        let mut qs: Vec<(usize, i32)> = Vec::new();
        collect_queries(&head_pin_full, &mut qs);
        let mut expect: Vec<(usize, i32)> = vec![(0, 0), (1 + NP + z_head, 0)];
        expect.extend(head_shadow.iter().map(|&c| (1 + NP + NZ + c, 0)));
        qs.sort_unstable();
        expect.sort_unstable();
        assert_eq!(qs, expect, "链头钉 Query 号清单漂移——EMIT 编号错位");
    }
    info.constraints.push(head_pin_full);
    // ④ t_start 钉（首块词 8==t_start；z_tstart@time_rows[0]）。2026-10 换代：
    //    t_start 自公开实例 2 经中继环读入（约束常量拆除）。
    {
        let mut rec = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
        for jj in 0..8usize {
            rec = rec
                + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << (4 * jj))) * qa(time_shadow[jj]);
        }
        rec = rec - qa(inst_relay[1]);
        info.constraints.push(zq(z_tstart) * rec);
    }
    // ⑤ alt_max 实例钉（z_altpin@rm[1] 单点门控 → q_inst）——上限的公开面
    //    绑定（验证方实例向量改写即验败，AUTH pin.bind 形态）。
    info.constraints.push(zq(z_altpin) * (qa(inst_relay[0]) - q_inst()));
    // ⑥ t_start 实例钉（z_tstartpin@rm[2] 单点门控 → q_inst）。
    info.constraints.push(zq(z_tstartpin) * (qa(inst_relay[1]) - q_inst()));

    // 实例（head_fold/alt_max/t_start 三值——2026-10 换代；家点=row_mapping()
    // [0..2]，q_inst@影子行；backend instance_polys 同一落位约定）。
    let head_fold = w.head_fold;
    let instances = vec![vec![head_fold, alt_max_e, t_start_e]];
    info.num_instances = vec![3];
    // witness 计数同步（后端 prover 按 num_witness_polys 断言列数）
    info.num_witness_polys = vec![witness.len()];
    assert!(
        info.is_well_formed(),
        "织入后 info 未通过 well-formed"
    );

    TrailCircuit { info, witness, instances }
}

/// row_mapping 反查：point→ordinal（实例家点定位用）。
pub fn ordinal_of(point: usize) -> usize {
    let rm = crate::sm3_compress::row_mapping();
    rm.iter().position(|&p| p == point).expect("点在 row_mapping 中")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trail_host::{fold_words_be, genesis_head, honest_samples, sample_block, sample_hash};

    fn honest(n: usize) -> (TrailSamples, u16, u32) {
        let samples = honest_samples(n, 1_700_000_000, 12_000);
        (samples, 12_000, 1_700_000_000)
    }

    fn check(c: &TrailCircuit) -> Vec<crate::sm3_compress::Violation> {
        crate::sm3_compress::check_parts_violations(&c.info, &c.witness, &c.instances)
    }

    fn sorted(mut v: Vec<crate::sm3_compress::Violation>) -> Vec<crate::sm3_compress::Violation> {
        v.sort_by_key(|x| (x.constraint, x.point));
        v
    }

    /// 重链工具：改 rows 后重算 blocks/heads/head（负例同步污染语义面）。
    fn rechain(samples: &mut TrailSamples) {
        let mut h = genesis_head();
        let mut blocks = Vec::with_capacity(samples.rows.len());
        let mut heads = Vec::with_capacity(samples.rows.len());
        for (t, alt, lat, lon) in &samples.rows {
            blocks.push(sample_block(&h, *t, *alt, *lat, *lon));
            h = sample_hash(&h, *t, *alt, *lat, *lon);
            heads.push(h);
        }
        samples.blocks = blocks;
        samples.heads = heads;
        samples.head = h;
    }

    /// mock 门：诚实样本织入后 0 违约（B6 验收门 clause：差分/mock 面）。
    #[test]
    fn trail_weave_mock_honest_zero_violations() {
        let (samples, alt_max, t_start) = honest(16);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(
            &circ,
            &TrailWiring { samples, alt_max_cm: alt_max, t_start, head_fold },
        );
        let g = gate_layout(16);
        assert_eq!(c.info.constraints.len(), g[6] + 1, "约束布局（2026-10 换代：+alt/tstart 两实例钉）");
        assert_eq!(c.info.preprocess_polys.len(), NP + NZ, "prep 构成（z 选择器）");
        // 数值对拍（守卫①的 mock 面印证）：影子 64 格 Σ f_pow2·值 == 实例 0
        // （head_shadow=倒数第 66..2 列——2026-10 换代后其后再挂 2 个实例中继列）
        let head_row = crate::sm3_compress::row_mapping()[0];
        let hs0 = c.witness.len() - 64 - 2;
        let mut sum = FpSM2::from(0u64);
        for idx in 0..64usize {
            let k = idx / 8;
            let j = idx % 8;
            sum += crate::sm2_params::f_pow2(32 * k + 4 * j) * c.witness[hs0 + idx][head_row];
        }
        assert_eq!(sum, c.instances[0][0], "Σ影子≠实例（fold 口径漂移）");
        eprintln!(
            "[trail-mock] constraints={} polys={} prep={} instances={} rings={}",
            c.info.constraints.len(),
            c.info.num_poly(),
            c.info.preprocess_polys.len(),
            c.info.num_instances.len(),
            c.info.permutations.len()
        );
        let viol = check(&c);
        assert!(viol.is_empty(), "诚实 TRAIL 织入 mock 违约 {} 条: {:?}", viol.len(), viol.iter().take(3).collect::<Vec<_>>());
    }

    /// e2e 门：织入后全链 prove→verify（n=16 小档——含 instances/环/z prep 的
    /// 真实协议面）。负例=verify 必拒（换链头证明被验证方拒绝）。
    #[test]
fn trail_weave_e2e_n16_prove_verify() {
        run_e2e(16);
    }

    /// e2e 判决行（n=128 定档=64s 段@2Hz）：织入后全链 prove/verify——B6 验收门
    /// 服务器窗前置的本机基线。#[ignore]（release 复跑=--ignored --nocapture）。
    #[test]
    #[ignore = "B6 判决行档：prove 数分钟级"]
    fn trail_weave_e2e_n128_verdict() {
        run_e2e(128);
    }

    fn run_e2e(n: usize) {
        use plonkish_backend::backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit};
        use plonkish_backend::pcs::multilinear::Basefold;
        use plonkish_backend::util::hash::Sm3;
        use plonkish_backend::util::transcript::{InMemoryTranscript, SM3Transcript};
        use crate::sm3_lookup_proto::ProtoSpec;
        use rand::{rngs::StdRng, SeedableRng};
        use std::io::Cursor;
        use std::time::Instant;

        type Pcs = Basefold<FpSM2, Sm3, ProtoSpec>;
        type Pb = HyperPlonk<Pcs>;
        type Tr = SM3Transcript<Cursor<Vec<u8>>>;

        struct CircWrap(TrailCircuit);
        impl PlonkishCircuit<FpSM2> for CircWrap {
            fn circuit_info_without_preprocess(
                &self,
            ) -> Result<plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
                Ok(self.0.info.clone())
            }
            fn circuit_info(
                &self,
            ) -> Result<plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
                Ok(self.0.info.clone())
            }
            fn instances(&self) -> &[Vec<FpSM2>] {
                &self.0.instances
            }
            fn synthesize(
                &self,
                _round: usize,
                _challenges: &[FpSM2],
            ) -> Result<Vec<Vec<FpSM2>>, plonkish_backend::Error> {
                Ok(self.0.witness.clone())
            }
        }

        let (samples, alt_max, t_start) = honest(n);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(
            &circ,
            &TrailWiring { samples, alt_max_cm: alt_max, t_start, head_fold },
        );
        eprintln!(
            "[trail-e2e] n={n} constraints={} polys={} lookups={} rings={}",
            c.info.constraints.len(), c.info.num_poly(), c.info.lookups.len(), c.info.permutations.len()
        );
        let wrap = CircWrap(c);
        let t0 = Instant::now();
        let param = Pb::setup(&wrap.0.info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = Pb::preprocess(&param, &wrap.0.info).unwrap();
        let t1 = Instant::now();
        let proof = {
            let mut tr = Tr::new(());
            Pb::prove(&pp, &wrap, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let t2 = Instant::now();
        let ok = {
            let mut tr = Tr::from_proof((), proof.as_slice());
            Pb::verify(&vp, &wrap.0.instances.clone(), &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
        };
        let t3 = Instant::now();
        eprintln!(
            "[trail-e2e] n={n} preprocess={:.1}s prove={:.1}s verify={:.1}s proof={}B ok={}",
            (t1 - t0).as_secs_f64(), (t2 - t1).as_secs_f64(), (t3 - t2).as_secs_f64(), proof.len(), ok
        );
        assert!(ok, "TRAIL weave e2e n={n} verify FAILED");
    }

    /// 负例①：超限样本（alt 超过 alt_max）→**且仅**范围门 recomb 在该样本行违约
    /// （bool 位恒合法；链头/时间面不受污染——门专属断言=拒绝原因正确性）。
    #[test]
    fn trail_neg_over_limit_rejected() {
        let (mut samples, alt_max, t_start) = honest(16);
        samples.rows[9].1 = alt_max + 1000; // 超限
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &TrailWiring {
            samples, alt_max_cm: alt_max, t_start, head_fold,
        });
        let g = gate_layout(16);
        let viol = sorted(check(&c));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[1], point: 64 + 9 }];
        assert_eq!(viol, expect, "超限样本必须恰在范围 recomb 拒——实得 {:?}", viol);
    }

    /// 负例②：时间空隙（Δt=501≠500）→**且仅**时间钉在受影响的两个配对行违约。
    #[test]
    fn trail_neg_time_gap_rejected() {
        let (mut samples, alt_max, t_start) = honest(16);
        samples.rows[7].0 += 1; // 空隙 1ms
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &TrailWiring {
            samples, alt_max_cm: alt_max, t_start, head_fold,
        });
        let g = gate_layout(16);
        let viol = sorted(check(&c));
        let expect = vec![
            crate::sm3_compress::Violation { constraint: g[2], point: 256 + 6 }, // (t7−t6)=501
            crate::sm3_compress::Violation { constraint: g[2], point: 256 + 7 }, // (t8−t7)=499
        ];
        assert_eq!(viol, expect, "时间空隙必须恰在时间钉两行拒——实得 {:?}", viol);
    }

    /// 负例③：换链头（提交的锚定头≠链算出的头）→**且仅**链头钉违约。
    #[test]
    fn trail_neg_wrong_head_rejected() {
        let (samples, alt_max, t_start) = honest(16);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let mut fake = samples.head;
        fake[0] ^= 0x01;
        let c = weave_trail(&circ, &TrailWiring {
            samples, alt_max_cm: alt_max, t_start, head_fold: fold_words_be(&fake),
        });
        let g = gate_layout(16);
        let viol = sorted(check(&c));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[3], point: 1 }];
        assert_eq!(viol, expect, "换链头必须恰在链头钉拒——实得 {:?}", viol);
    }

    /// 负例④a：genesis 篡改（链从被换的起点起算）——builder 层防御语义钉定：
    /// trail_chain_circuit 将 genesis 常量钉进块 0 消息词（bind_input_word 环），
    /// tampered 块的词值被常量吸收 ⟹ digest==**标准** genesis 链头≠tampered 头
    /// （真实协议面：环强制块 0 词==genesis 常量，换起点结构性不可证明；
    /// 终局兜底=链头钉——任何起点变化改变末头，锚定头实例不变即拒）。
    #[test]
    fn trail_neg_genesis_tamper_absorbed_by_const_pin() {
        let (samples, alt_max, _t) = honest(16);
        let mut g2 = genesis_head();
        g2[31] ^= 0x01;
        let mut h = g2;
        let mut blocks = Vec::with_capacity(samples.rows.len());
        for (t, alt, lat, lon) in &samples.rows {
            blocks.push(sample_block(&h, *t, *alt, *lat, *lon));
            h = sample_hash(&h, *t, *alt, *lat, *lon);
        }
        // 标准链（同 rows、真 genesis）
        let (std, _am, _ts) = honest(16);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&blocks);
        for k in 0..8usize {
            let wv = u32::from_be_bytes(std.head[4 * k..4 * k + 4].try_into().expect("界内"));
            assert_eq!(circ.digest[k], wv, "digest word {k} 必须==标准 genesis 链头（常量钉吸收）");
        }
        let tampered_head_word0 = u32::from_be_bytes(h[0..4].try_into().expect("界内"));
        let std_word0 = u32::from_be_bytes(std.head[0..4].try_into().expect("界内"));
        assert_ne!(tampered_head_word0, std_word0, "负例前提：tampered 头≠标准头");
        let _ = alt_max;
    }

    /// 负例④：t_start 篡改（声明起始时间≠记录首样本）→**且仅** t_start 钉违约。
    #[test]
    fn trail_neg_tstart_rejected() {
        let (samples, alt_max, _t) = honest(16);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &TrailWiring {
            samples, alt_max_cm: alt_max, t_start: 1_700_000_000 + 7,
            head_fold,
        });
        let g = gate_layout(16);
        let viol = sorted(check(&c));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[4], point: 256 }];
        assert_eq!(viol, expect, "t_start 篡改必须恰在起始钉拒——实得 {:?}", viol);
    }
}
