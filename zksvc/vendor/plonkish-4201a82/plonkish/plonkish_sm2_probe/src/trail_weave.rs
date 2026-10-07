//! 飞证 B6：TRAIL 语句织入（proto 独立电路后处理——范围门/时间门/链头钉/围栏门）。
//!
//! 语义（A5 收窄 + 二批换代 2026-10：空域合规进电路）：
//! - 范围门：alt_i ≤ alt_max——δ′=alt_max−alt 域内 16 位分解+bool+recomb
//!   （读数源=每块消息词 9 高 16 位（alt BE2），θ 门同构机制）
//! - 时间门：t_{i+1}−t_i==sample_period_ms（**周期迁公开实例 3**——1Hz/2Hz/4Hz
//!   录制器同电路可验，Δt 语义由电路逐对强制，周期声明被实例面钉定）
//! - 链头钉：fold(末块摘要)==chain_head 实例（锚定面绑定——B6-d7：设备签
//!   名在链上锚定时验证并上链不可篡改，电路强制链头==锚定链头即完整性绑定）
//! - t_start 钉：首块词 8==t_start
//! - **围栏门族（矩形 4 半平面，2026-10 二批）**：min_lat ≤ lat_i ≤ max_lat ∧
//!   min_lon ≤ lon_i ≤ max_lon——lat/lon i32×1e7 **偏置编码** e=(v+2^31) mod 2^32
//!   （负纬度=南半球 SITL 原点合法域，偏置后 [0,2^32) 全序保持）；每半平面
//!   δ 分解（32 bool+recomb，影子行法共享列——alt 范围门同形态）；
//!   围栏参数=公开实例 4..7（偏置 u32），采样周期=公开实例 3。
//!
//! 编号纪律（后处理织入）：instance 占 poly 0（num_instances=[1] 单实例
//! poly 8 值，家点=row_mapping()[0..7]，与链头影子行同点）；**选择器=preprocess
//! 常量列**（z_range/z_time/z_head/z_tstart/z_altpin/z_tstartpin + 二批
//! z_periodpin/z_latminpin/z_latmaxpin/z_lonminpin/z_lonmaxpin——B6-d9 拍板：
//! z 作 witness 是健全性漏洞，恶意证明者可置 z≡0 使全部 EMIT 门空转；prep=
//! 验证方可见锚定，AUTH 的 dgw/msg sel 同法先例）。proto prep 0 基/advice 24 基
//! → 标准 prep 1 基/advice 30 基（+1 实例位 +11 z prep 位）。
//! 影子行法（教训㊿+10）：共享列×唯一样本行，limb 值经环桥等值进影子格；
//! 共享列形态下 bool+recomb 对全部样本行是同一表达式——全局一份即足。
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

/// 矩形围栏参数（i32×1e7——负值=南/西半球合法域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceRect {
    pub min_lat: i32,
    pub max_lat: i32,
    pub min_lon: i32,
    pub max_lon: i32,
}

/// i32 → 偏置 u32：e=(v+2^31) mod 2^32 ∈ [0,2^32)（全序保持——负纬度
/// 偏置后仍小于正纬度；实例/门两侧同式，单一事实源）。
pub fn bias_u32(v: i32) -> u32 {
    (v as i64).wrapping_add(1 << 31) as u32
}

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
    /// 采样周期 ms（二批换代：时间门 Δt 实例钉——1Hz=1000/2Hz=500/4Hz=250）。
    pub sample_period_ms: u32,
    /// 矩形围栏（二批换代：4 半平面公开实例 4..7——偏置编码入实例）。
    pub fence: FenceRect,
}

const W_INPUT: usize = 33;
const NP: usize = 24; // proto prep poly 数（P_CONST+23 表）
const NZ: usize = 11; // z 选择器 prep poly 数（range/time/head/tstart/altpin/tstartpin
                      // + period/latmin/latmax/lonmin/lonmax pin）
                      // 2026-10 换代：+2 钉选择器（alt_max/t_start 约束常量→公开实例）。
                      // 2026-10 二批：+5 钉选择器（周期+围栏 4 界→公开实例）。

/// 偏置基数 B=2^31（电路内常量——e=raw+B 与实例偏置值同域比较）。
const BIAS: u64 = 1 << 31;

fn shadow_row(kind: u16, i: usize) -> usize {
    match kind {
        0 => 64 + i,      // 范围行 64..192
        1 => 256 + i,     // 时间行 256..384
        _ => 400,         // 链头行
    }
}

/// EMIT 段约束布局（负例门专属断言/消费方对账用）——proto 段在前。
/// ⑦代换代：proto 段=lane×band 门数（原 per-group 4n 条；调用方传
/// `constraints.len() - EMIT_CONSTRAINTS` 或等效实得值）。
/// 槽序（2026-10 二批换代：既有 0..6 号不变=既有 5 负例语义钉定；新门族全
/// 部追加在后）：
/// [0] alt bool 起（16 条）[1] alt recomb [2] time [3] head [4] tstart
/// [5] altpin [6] tstartpin [7] periodpin
/// [8] 围栏 bool 起（4 界×32 位 δ + 2 轴×4 符号位=136 条）
/// [9] lat 符号 tie（符号位==词顶 nibble——proto 绑定面）
/// [10] lon 符号 tie
/// [11] lat_min [12] lat_max [13] lon_min [14] lon_max（4 半平面 recomb）
/// [15] latmin_pin [16] latmax_pin [17] lonmin_pin [18] lonmax_pin；
/// 总条数=g[18]+1。
/// EMIT 段固定条数（proto 段之后追加的全部门）。
pub const EMIT_CONSTRAINTS: usize = 169;
pub fn gate_layout(proto_len: usize) -> [usize; 19] {
    let proto = proto_len;
    [
        proto,
        proto + 16,
        proto + 17,
        proto + 18,
        proto + 19,
        proto + 20,
        proto + 21,
        proto + 22,
        proto + 23,
        proto + 159,
        proto + 160,
        proto + 161,
        proto + 162,
        proto + 163,
        proto + 164,
        proto + 165,
        proto + 166,
        proto + 167,
        proto + 168,
    ]
}

/// proto→标准编号规范化（双基底拆分）：proto prep 0 基→标准 1 基（+1）；
/// proto advice 24 基→标准 30 基（+1 实例位+NZ z prep 位）。
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
        Expression::Scaled(a, s) => Expression::Scaled(Box::new(shift_poly_expr(a)), *s),
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
    assert!(w.sample_period_ms >= 1, "采样周期须 ≥1ms（0=时间门退化）");

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

    // ── ⑦代：组列共享+查表通道合并（lane 带复用）——proto 段重建 ──
    // n 组原各占 34 列/8 通道；换代为 lane band 列池+每 lane×band 一条通道。
    // 语义/表内容/绑定关系逐字不变（行带错开=并集；详见 sm3_lookup_weave ⑦）。
    // packed witness 列在此分配（后续影子列 push 续接同一编号空间）。
    let zero = FpSM2::from(0u64);
    let mut packed_wit: Vec<Vec<FpSM2>> = Vec::new();
    let pack = crate::sm3_lookup_weave::pack_lanes(
        &[crate::sm3_lookup_weave::PackCircuit { base: 0, circ }],
        groups,
        || {
            packed_wit.push(vec![zero; ROWS]);
            packed_wit.len() - 1
        },
    );
    // 值播种：proto 非零格 → pack 物理格（零格由列初始化天然为零）。
    for (g, wit_g) in circ.wit_u64.chunks_exact(NUM_W).enumerate() {
        for (rel, col) in wit_g.iter().enumerate() {
            for (r, &v) in col.iter().enumerate() {
                if v != 0 {
                    let (c, pr) = pack.cell(g, rel, r).expect("非零格必锚（pack 扫描缺口）");
                    packed_wit[c][pr] = FpSM2::from(v);
                }
            }
        }
    }
    // proto 段约束/查表按 lane×band 重建 + 环按 pack 重路由（proto 编号：
    // advice=NP+packed 列；表=poly 0..22、pconst=23——经既有 shift 规范化）。
    {
        let (cons, lks) = crate::sm3_lookup_weave::proto_lane_gates_exprs(&pack);
        info.constraints = cons;
        info.lookups = lks;
        info.num_witness_polys = vec![pack.total_cols()];
        info.permutations = circ
            .info
            .permutations
            .iter()
            .map(|cyc| {
                cyc.iter()
                    .map(|&(p, r)| {
                        let ci = p - NP;
                        let (c, pr) = pack
                            .cell(ci / NUM_W, ci % NUM_W, r)
                            .expect("环格必锚（pack 扫描面）");
                        (NP + c, pr)
                    })
                    .collect()
            })
            .collect();
    }

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
            *p += 1 + NZ; // 环条目全为 advice 格（proto col ≥ NP）
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
    // 实例家点行（row_mapping 序=实例序）：0=链头 1=alt_max 2=t_start
    // 3=周期 4..7=围栏 min_lat/max_lat/min_lon/max_lon（偏置 u32）。
    // 2026-10 二批换代：+5 钉行（rm[3..7]）。
    let alt_pin_row = crate::sm3_compress::row_mapping()[1];
    let tstart_pin_row = crate::sm3_compress::row_mapping()[2];
    let period_pin_row = crate::sm3_compress::row_mapping()[3];
    let latmin_pin_row = crate::sm3_compress::row_mapping()[4];
    let latmax_pin_row = crate::sm3_compress::row_mapping()[5];
    let lonmin_pin_row = crate::sm3_compress::row_mapping()[6];
    let lonmax_pin_row = crate::sm3_compress::row_mapping()[7];
    for (name, row) in [
        ("alt_max", alt_pin_row),
        ("t_start", tstart_pin_row),
        ("period", period_pin_row),
        ("min_lat", latmin_pin_row),
        ("max_lat", latmax_pin_row),
        ("min_lon", lonmin_pin_row),
        ("max_lon", lonmax_pin_row),
    ] {
        // 家点行禁入时间影子带/链头行（时间带中继环未去重+head 行有 digest
        // 家点语义）；范围影子带允许撞（rm[6]=64/rm[7]=128——二批 8 实例的
        // LFSR 家点序固有），中继环构造对家点行去重（见下方 fence relay 段）。
        assert!(
            !time_rows.contains(&row) && row != head_row,
            "{name} 钉行 {row} 撞时间影子/家点行——row_mapping 布局漂移"
        );
    }
    let z_altpin_col = mk_sel(&[alt_pin_row]);
    let z_tstartpin_col = mk_sel(&[tstart_pin_row]);
    let z_periodpin_col = mk_sel(&[period_pin_row]);
    let z_latminpin_col = mk_sel(&[latmin_pin_row]);
    let z_latmaxpin_col = mk_sel(&[latmax_pin_row]);
    let z_lonminpin_col = mk_sel(&[lonmin_pin_row]);
    let z_lonmaxpin_col = mk_sel(&[lonmax_pin_row]);
    info.preprocess_polys.push(z_range_col);
    info.preprocess_polys.push(z_time_col);
    info.preprocess_polys.push(z_head_col);
    info.preprocess_polys.push(z_tstart_col);
    info.preprocess_polys.push(z_altpin_col);
    info.preprocess_polys.push(z_tstartpin_col);
    info.preprocess_polys.push(z_periodpin_col);
    info.preprocess_polys.push(z_latminpin_col);
    info.preprocess_polys.push(z_latmaxpin_col);
    info.preprocess_polys.push(z_lonminpin_col);
    info.preprocess_polys.push(z_lonmaxpin_col);
    let z_range = 0usize; // z poly 序（标准号=1+NP+zi）
    let z_time = 1usize;
    let z_head = 2usize;
    let z_tstart = 3usize;
    let z_altpin = 4usize;
    let z_tstartpin = 5usize;
    let z_periodpin = 6usize;
    let z_latminpin = 7usize;
    let z_latmaxpin = 8usize;
    let z_lonminpin = 9usize;
    let z_lonmaxpin = 10usize;
    let np = info.preprocess_polys.len();
    assert_eq!(np, NP + NZ, "织入后 prep 构成漂移");

    // ⑦代：witness 基面=packed 列（组列共享后的 SM3 体）；影子列续接其后。
    let mut witness = packed_wit;
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
    // 实例值中继列（2026-10 换代 alt_max/t_start + 二批 周期/围栏 4 界——约束
    // 常量迁公开实例，门的消费行与实例家点相距 >K 不可旋转 ⟹ 中继环缝合，
    // AUTH rid_pred_pin 同款先例）。
    let inst_relay: [usize; 7] = std::array::from_fn(|_| alloc_w(&mut witness));
    const R_ALTPIN: usize = 0;
    const R_TSTART: usize = 1;
    const R_PERIOD: usize = 2;
    const R_LATMIN: usize = 3;
    const R_LATMAX: usize = 4;
    const R_LONMIN: usize = 5;
    const R_LONMAX: usize = 6;
    // 围栏影子列（二批换代）：lat=词9低16位(高半)‖词10高16位(低半)；
    // lon=词10低16位(高半)‖词11高16位(低半)——消息词 9..11 首次入消费。
    // 轴顶 nibble（raw 位 28..31）改 4 独立位（符号位 31 供偏置回绕项，
    // tie 约束绑回 proto 绑定的 nib[7]——见 EMIT ⑧）。
    let lat_nib: [usize; 8] = std::array::from_fn(|_| alloc_w(&mut witness));
    let lon_nib: [usize; 8] = std::array::from_fn(|_| alloc_w(&mut witness));
    let lat_top_bits: [usize; 4] = std::array::from_fn(|_| alloc_w(&mut witness));
    let lon_top_bits: [usize; 4] = std::array::from_fn(|_| alloc_w(&mut witness));
    // 围栏 δ 位分解列（4 界×32 位——偏置域 [0,2^32) 全量程）。
    let latmin_bits: [usize; 32] = std::array::from_fn(|_| alloc_w(&mut witness));
    let latmax_bits: [usize; 32] = std::array::from_fn(|_| alloc_w(&mut witness));
    let lonmin_bits: [usize; 32] = std::array::from_fn(|_| alloc_w(&mut witness));
    let lonmax_bits: [usize; 32] = std::array::from_fn(|_| alloc_w(&mut witness));

    // proto 列/行映射（⑦代：msg 格物理定位经 pack INPUT 带——标准号=1+NP+NZ+
    // packed 列；值仍读 proto wit 单一事实源）。
    let word_limb_row = |j: usize, k: usize| 1 + 8 * j + k;
    let msg_cell = |g: usize, j: usize, k: usize| -> (usize, usize) {
        let (c, r) = pack
            .cell(g, W_INPUT, word_limb_row(j, k))
            .expect("msg limb 格必锚（INPUT 带值/环面）");
        (1 + NP + NZ + c, r)
    };
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
    let period_e = FpSM2::from(u64::from(w.sample_period_ms));
    let latmin_e = FpSM2::from(u64::from(bias_u32(w.fence.min_lat)));
    let latmax_e = FpSM2::from(u64::from(bias_u32(w.fence.max_lat)));
    let lonmin_e = FpSM2::from(u64::from(bias_u32(w.fence.min_lon)));
    let lonmax_e = FpSM2::from(u64::from(bias_u32(w.fence.max_lon)));
    for i in 0..n {
        let r = range_rows[i];
        for (jj, k) in (4..8).enumerate() {
            let v = msg_limb(i, 9, k);
            bridge(&mut perms, msg_cell(i, 9, k), range_shadow[jj], r, v, &mut witness);
        }
        // δ′=alt_max−alt（诚实态 <2^16；负例态为大数=位分解必败）
        let dv = u64::from(w.alt_max_cm).wrapping_sub(u64::from(w.samples.rows[i].1));
        for k in 0..16usize {
            witness[delta_cols[k]][r] = FpSM2::from((dv >> k) & 1);
        }
        // ── 二批换代：围栏影子行播种（lat/lon 首次入消费）──
        // lat: 高半=词9 k=0..3（低16位）、低半=词10 k=4..7（高16位）；
        // lon: 高半=词10 k=0..3、低半=词11 k=4..7。偏置域 δ 位同步播种。
        // 轴顶 4 位（raw 28..31）独立播种（位 31=符号位——偏置回绕项）。
        for k in 0..4usize {
            let v9 = msg_limb(i, 9, k);
            bridge(&mut perms, msg_cell(i, 9, k), lat_nib[k], r, v9, &mut witness);
            let v10h = msg_limb(i, 10, k);
            bridge(&mut perms, msg_cell(i, 10, k), lon_nib[k], r, v10h, &mut witness);
        }
        for k in 4..8usize {
            let v10l = msg_limb(i, 10, k);
            bridge(&mut perms, msg_cell(i, 10, k), lat_nib[k], r, v10l, &mut witness);
            let v11h = msg_limb(i, 11, k);
            bridge(&mut perms, msg_cell(i, 11, k), lon_nib[k], r, v11h, &mut witness);
        }
        // raw u32（消息词 BE 字节的无符号解释）——与影子列同一批播种值。
        let lat_raw = (0..4).fold(0u64, |acc, k| acc | (msg_limb(i, 9, k) << (16 + 4 * k)))
            | (4..8).fold(0u64, |acc, k| acc | (msg_limb(i, 10, k) << (4 * k - 16)));
        let lon_raw = (0..4).fold(0u64, |acc, k| acc | (msg_limb(i, 10, k) << (16 + 4 * k)))
            | (4..8).fold(0u64, |acc, k| acc | (msg_limb(i, 11, k) << (4 * k - 16)));
        let lat_b = ((lat_raw as u32).wrapping_add(BIAS as u32)) as u32;
        let lon_b = ((lon_raw as u32).wrapping_add(BIAS as u32)) as u32;
        let dmin_lat = lat_b.wrapping_sub(bias_u32(w.fence.min_lat));
        let dmax_lat = bias_u32(w.fence.max_lat).wrapping_sub(lat_b);
        let dmin_lon = lon_b.wrapping_sub(bias_u32(w.fence.min_lon));
        let dmax_lon = bias_u32(w.fence.max_lon).wrapping_sub(lon_b);
        for k in 0..32usize {
            witness[latmin_bits[k]][r] = FpSM2::from(u64::from((dmin_lat >> k) & 1));
            witness[latmax_bits[k]][r] = FpSM2::from(u64::from((dmax_lat >> k) & 1));
            witness[lonmin_bits[k]][r] = FpSM2::from(u64::from((dmin_lon >> k) & 1));
            witness[lonmax_bits[k]][r] = FpSM2::from(u64::from((dmax_lon >> k) & 1));
        }
        // 轴顶 4 位（raw 位 28..31=高词 limb3 的 4 位——tie 约束绑回桥接
        // nib[3]；位 31=i32 符号位——偏置回绕项）。
        for j in 0..4usize {
            witness[lat_top_bits[j]][r] = FpSM2::from((msg_limb(i, 9, 3) >> j) & 1);
            witness[lon_top_bits[j]][r] = FpSM2::from((msg_limb(i, 10, 3) >> j) & 1);
        }
    }
    for i in 0..n - 1 {
        let r = time_rows[i];
        for (half, gi) in [(0usize, i), (1usize, i + 1)] {
            for jj in 0..8usize {
                let v = msg_limb(gi, 8, jj);
                bridge(&mut perms, msg_cell(gi, 8, jj), time_shadow[half * 8 + jj], r, v, &mut witness);
            }
        }
    }
    for (k, word) in circ.digest_cells.iter().enumerate() {
        for (j, limb) in word.iter().enumerate() {
            let v = circ.wit_u64[limb.col - NP][limb.row];
            // 链头影子布局：影子列 k*8+j（64 格唯一）——fold 权重=2^{32k+4j}
            // ⑦代：proto 侧经 pack 物理格（标准号=1+NP+NZ+packed 列）
            let sc = head_shadow[k * 8 + j];
            let (dc, dr) = pack
                .cell((limb.col - NP) / NUM_W, (limb.col - NP) % NUM_W, limb.row)
                .expect("digest limb 格必锚（值面）");
            bridge(&mut perms, (1 + NP + NZ + dc, dr), sc, head_row, v, &mut witness);
        }
    }

    // ── 实例值中继环（alt_max/t_start + 二批 周期/围栏 4 界）──
    // 中继格=门消费行（值侧）+ 实例家点行（钉侧）同列复制环；守卫③同款
    // 回读断言（标准号回读==播种值）。钉侧约束见 EMIT ⑤⑥⑦+围栏钉（z 钉
    // 家点行单点门控 → q_inst）。
    let sp_relay = |c: usize| 1 + NP + NZ + c;
    {
        // alt_max：n 个范围行 + 家点行 rm[1]（家点撞带时去重——环内格唯一）。
        let mut cyc: Vec<(usize, usize)> = Vec::with_capacity(n + 1);
        witness[inst_relay[R_ALTPIN]][alt_pin_row] = alt_max_e;
        cyc.push((sp_relay(inst_relay[R_ALTPIN]), alt_pin_row));
        for &r in &range_rows {
            if r == alt_pin_row {
                continue;
            }
            witness[inst_relay[R_ALTPIN]][r] = alt_max_e;
            cyc.push((sp_relay(inst_relay[R_ALTPIN]), r));
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
            (sp_relay(inst_relay[R_TSTART]), tstart_pin_row),
            (sp_relay(inst_relay[R_TSTART]), time_rows[0]),
        ];
        witness[inst_relay[R_TSTART]][tstart_pin_row] = t_start_e;
        witness[inst_relay[R_TSTART]][time_rows[0]] = t_start_e;
        for &(p, r) in &cyc {
            assert_eq!(
                witness[p - 1 - np][r],
                t_start_e,
                "t_start 中继格 (poly {p}, row {r}) 回读≠播种值——编号错位"
            );
        }
        perms.push(cyc);
    }
    // 二批换代：周期（时间行消费——n−1 行+家点）、围栏 4 界（范围行消费）。
    {
        let mut cyc: Vec<(usize, usize)> = Vec::with_capacity(n);
        witness[inst_relay[R_PERIOD]][period_pin_row] = period_e;
        cyc.push((sp_relay(inst_relay[R_PERIOD]), period_pin_row));
        for &r in &time_rows {
            if r == period_pin_row {
                continue;
            }
            witness[inst_relay[R_PERIOD]][r] = period_e;
            cyc.push((sp_relay(inst_relay[R_PERIOD]), r));
        }
        for &(p, r) in &cyc {
            assert_eq!(
                witness[p - 1 - np][r],
                period_e,
                "period 中继格 (poly {p}, row {r}) 回读≠播种值——编号错位"
            );
        }
        perms.push(cyc);
    }
    for (relay, pin_row, val, name) in [
        (inst_relay[R_LATMIN], latmin_pin_row, latmin_e, "min_lat"),
        (inst_relay[R_LATMAX], latmax_pin_row, latmax_e, "max_lat"),
        (inst_relay[R_LONMIN], lonmin_pin_row, lonmin_e, "min_lon"),
        (inst_relay[R_LONMAX], lonmax_pin_row, lonmax_e, "max_lon"),
    ] {
        // 家点行可能恰在范围影子带（rm[6]=64/rm[7]=128——LFSR 家点序固有）：
        // 环内家点格只进一次（去重），该格同时充当钉侧与门消费侧——门在该行
        // 读中继值==实例值语义不变。
        let mut cyc: Vec<(usize, usize)> = Vec::with_capacity(n + 1);
        witness[relay][pin_row] = val;
        cyc.push((sp_relay(relay), pin_row));
        for &r in &range_rows {
            if r == pin_row {
                continue;
            }
            witness[relay][r] = val;
            cyc.push((sp_relay(relay), r));
        }
        for &(p, r) in &cyc {
            assert_eq!(
                witness[p - 1 - np][r],
                val,
                "{name} 中继格 (poly {p}, row {r}) 回读≠播种值——编号错位"
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
    let cst = |v: u64| Expression::<FpSM2>::Constant(FpSM2::from(v));

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
        rec = rec - qa(inst_relay[R_ALTPIN]);
        info.constraints.push(zq(z_range) * rec);
    }
    // ② 时间门（1 条 ×(n−1) 配对行 z_time 门控）。二批换代：Δt 自公开实例 3
    //    经中继环读入（约束常量 500 拆除——采样率参数化，1Hz/2Hz/4Hz 同电路）。
    {
        let mut rec = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
        for jj in 0..8usize {
            let hi = qa(time_shadow[8 + jj]);
            let lo = qa(time_shadow[jj]);
            rec = rec + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << (4 * jj))) * (hi - lo);
        }
        rec = rec - qa(inst_relay[R_PERIOD]);
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
        rec = rec - qa(inst_relay[R_TSTART]);
        info.constraints.push(zq(z_tstart) * rec);
    }
    // ⑤ alt_max 实例钉（z_altpin@rm[1] 单点门控 → q_inst）——上限的公开面
    //    绑定（验证方实例向量改写即验败，AUTH pin.bind 形态）。
    info.constraints.push(zq(z_altpin) * (qa(inst_relay[R_ALTPIN]) - q_inst()));
    // ⑥ t_start 实例钉（z_tstartpin@rm[2] 单点门控 → q_inst）。
    info.constraints.push(zq(z_tstartpin) * (qa(inst_relay[R_TSTART]) - q_inst()));
    // ⑦ 周期实例钉（z_periodpin@rm[3] 单点门控 → q_inst）——二批换代。
    info.constraints.push(zq(z_periodpin) * (qa(inst_relay[R_PERIOD]) - q_inst()));
    // ⑧ 围栏门族（二批换代——矩形 4 半平面，z_range 与 alt 范围门同行集门控；
    //    门号=g[8..15]，负例纪律=恰在对应门约束号拒绝）。
    //    偏置域：e=raw+B−sign·2^32（raw=消息词 32 位 BE 重组、B=2^31 域常量、
    //    sign=raw 位 31——负纬度 raw≥2^31 时回绕项使 e==真偏置值∈[0,2^32)；
    //    sign 绑定=4 个轴顶位（bool+Σ2^j·b_j==桥接 nib[7] tie），消息面全绑定）。
    //    min 门：δmin+e_min−e==0（δmin≥0 ⟺ e≥e_min）；max 门：e+δmax−e_max==0
    //    （δmax≥0 ⟺ e≤e_max）；δ∈[0,2^32) 32 bool——出界 ⟹ 真差为负、域内
    //    大数（≥p−2^32）超 32 位预算 ⟹ 恰在该半平面 recomb 拒。
    //    bool 面：4 界×32 位 δ + 2 轴×4 符号位，全局一份（共享列+影子行）。
    for cols in [&latmin_bits, &latmax_bits, &lonmin_bits, &lonmax_bits] {
        for k in 0..32usize {
            let b = qa(cols[k]);
            info.constraints.push(zq(z_range) * (b.clone() * b.clone() - b.clone()));
        }
    }
    for cols in [&lat_top_bits, &lon_top_bits] {
        for k in 0..4usize {
            let b = qa(cols[k]);
            info.constraints.push(zq(z_range) * (b.clone() * b.clone() - b.clone()));
        }
    }
    // 轴 raw 重组（wrap 感知）：位 0..15 自低半 nib[4..7]（桥接 proto 格，
    // 权重 2^{4k−16}）、位 16..27 自高半 nib[0..2]（权重 2^{16+4k}）、
    // 位 28..31 自符号位组（tie 绑回 nib[3]）、−sign·2^31 偏置回绕。
    let axis_raw = |nib: &[usize; 8], top: &[usize; 4]| {
        let mut rec = cst(0);
        for k in 0..3usize {
            rec = rec + cst(1u64 << (16 + 4 * k)) * qa(nib[k]);
        }
        for k in 4..8usize {
            rec = rec + cst(1u64 << (4 * k - 16)) * qa(nib[k]);
        }
        for (j, col) in top.iter().enumerate() {
            rec = rec + cst(1u64 << (28 + j)) * qa(*col);
        }
        // 偏置回绕：e=raw+2^31−sign·2^32（sign=1 ⟹ raw+2^31 溢出回绕）。
        rec + cst(BIAS) - cst(1u64 << 32) * qa(top[3])
    };
    {
        // 符号位 tie：Σ2^j·b_j == nib[3]（高词 limb3=raw 顶 nibble——proto
        // 绑定面，消息自由度清零）。
        for (nib, top) in [(&lat_nib, &lat_top_bits), (&lon_nib, &lon_top_bits)] {
            let mut tie = cst(0);
            for (j, col) in top.iter().enumerate() {
                tie = tie + cst(1u64 << j) * qa(*col);
            }
            tie = tie - qa(nib[3]);
            info.constraints.push(zq(z_range) * tie);
        }
    }
    let halfplane = |bits: &[usize; 32]| {
        let mut rec = cst(0);
        for k in 0..32usize {
            rec = rec + cst(1u64 << k) * qa(bits[k]);
        }
        rec
    };
    {
        // lat：min 门 + max 门（e==真偏置值∈[0,2^32)——δ 32 位预算自洽）
        let raw = axis_raw(&lat_nib, &lat_top_bits);
        let min_rec = halfplane(&latmin_bits) + qa(inst_relay[R_LATMIN]) - raw.clone();
        info.constraints.push(zq(z_range) * min_rec);
        let max_rec = raw + halfplane(&latmax_bits) - qa(inst_relay[R_LATMAX]);
        info.constraints.push(zq(z_range) * max_rec);
    }
    {
        // lon：min 门 + max 门
        let raw = axis_raw(&lon_nib, &lon_top_bits);
        let min_rec = halfplane(&lonmin_bits) + qa(inst_relay[R_LONMIN]) - raw.clone();
        info.constraints.push(zq(z_range) * min_rec);
        let max_rec = raw + halfplane(&lonmax_bits) - qa(inst_relay[R_LONMAX]);
        info.constraints.push(zq(z_range) * max_rec);
    }
    // ⑨ 围栏实例钉 ×4（家点 rm[4..7] 单点门控 → q_inst）——围栏的公开面绑定
    //    （验证方实例向量改写任一界即验败；授权面由引擎绑定签名供给——
    //    FZ-TRAIL-BIND2 扩域，证明者不可自报）。
    info.constraints.push(zq(z_latminpin) * (qa(inst_relay[R_LATMIN]) - q_inst()));
    info.constraints.push(zq(z_latmaxpin) * (qa(inst_relay[R_LATMAX]) - q_inst()));
    info.constraints.push(zq(z_lonminpin) * (qa(inst_relay[R_LONMIN]) - q_inst()));
    info.constraints.push(zq(z_lonmaxpin) * (qa(inst_relay[R_LONMAX]) - q_inst()));

    // 实例（链头‖alt_max‖t_start‖周期‖围栏 4 界偏置——二批换代 3→8 值；
    // 家点=row_mapping()[0..7]，q_inst@家点行；backend instance_polys 同一
    // 落位约定）。
    let head_fold = w.head_fold;
    let instances = vec![vec![
        head_fold, alt_max_e, t_start_e, period_e,
        latmin_e, latmax_e, lonmin_e, lonmax_e,
    ]];
    info.num_instances = vec![8];
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

    /// 演示空域围栏（与政策面 FENCE_RECTS 同域——诚实样本全在界内）。
    pub const FENCE: FenceRect = FenceRect {
        min_lat: 300_000_000,
        max_lat: 320_000_000,
        min_lon: 1_200_000_000,
        max_lon: 1_220_000_000,
    };
    pub const PERIOD_MS: u32 = 500;

    fn honest(n: usize) -> (TrailSamples, u16, u32) {
        let samples = honest_samples(n, 1_700_000_000, 12_000);
        (samples, 12_000, 1_700_000_000)
    }

    fn wiring(samples: TrailSamples, alt_max: u16, t_start: u32, head_fold: FpSM2) -> TrailWiring {
        TrailWiring {
            samples,
            alt_max_cm: alt_max,
            t_start,
            head_fold,
            sample_period_ms: PERIOD_MS,
            fence: FENCE,
        }
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
        let c = weave_trail(&circ, &wiring(samples, alt_max, t_start, head_fold));
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
        assert_eq!(c.info.constraints.len(), g[18] + 1, "约束布局（二批换代：+周期钉+围栏 136 bool+2 tie+4 recomb+4 钉）");
        assert_eq!(c.info.preprocess_polys.len(), NP + NZ, "prep 构成（z 选择器）");
        // 数值对拍（守卫①的 mock 面印证）：影子 64 格 Σ f_pow2·值 == 实例 0
        // （head_shadow 后挂 7 中继+8 lat nib+8 lon nib+128 位分解列——切片
        // =witness.len()−64−151）
        let head_row = crate::sm3_compress::row_mapping()[0];
        let hs0 = c.witness.len() - 64 - 159;
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
        let c = weave_trail(&circ, &wiring(samples, alt_max, t_start, head_fold));
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
    /// （bool 位恒合法；链头/时间/围栏面不受污染——门专属断言=拒绝原因正确性）。
    #[test]
    fn trail_neg_over_limit_rejected() {
        let (mut samples, alt_max, t_start) = honest(16);
        samples.rows[9].1 = alt_max + 1000; // 超限
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &wiring(samples, alt_max, t_start, head_fold));
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
        let viol = sorted(check(&c));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[1], point: 64 + 9 }];
        assert_eq!(viol, expect, "超限样本必须恰在范围 recomb 拒——实得 {:?}", viol);
    }

    /// 负例②：时间空隙（Δt=501≠周期）→**且仅**时间钉在受影响的两个配对行违约。
    #[test]
    fn trail_neg_time_gap_rejected() {
        let (mut samples, alt_max, t_start) = honest(16);
        samples.rows[7].0 += 1; // 空隙 1ms
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &wiring(samples, alt_max, t_start, head_fold));
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
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
        let c = weave_trail(&circ, &wiring(samples, alt_max, t_start, fold_words_be(&fake)));
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
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
        let mut w = wiring(samples, alt_max, 1_700_000_000 + 7, head_fold);
        w.t_start = 1_700_000_000 + 7;
        let c = weave_trail(&circ, &w);
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
        let viol = sorted(check(&c));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[4], point: 256 }];
        assert_eq!(viol, expect, "t_start 篡改必须恰在起始钉拒——实得 {:?}", viol);
    }

    // ── 二批换代：围栏门族负例（出界方向×4+负纬度+角点恰在界上） ──

    /// 负例⑥：出东界（lon > max_lon）→**且仅** lon_max 半平面 recomb 在该样本行
    /// 违约（高度/时间/链头/其余三界不受污染——门专属断言）。
    #[test]
    fn trail_neg_fence_east_rejected() {
        let (mut samples, alt_max, t_start) = honest(16);
        samples.rows[9].3 = FENCE.max_lon + 1; // 出东界 1e-7 度
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &wiring(samples, alt_max, t_start, head_fold));
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
        let viol = sorted(check(&c));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[14], point: 64 + 9 }];
        assert_eq!(viol, expect, "出东界必须恰在 lon_max 门拒——实得 {:?}", viol);
    }

    /// 负例⑦：出西界（lon < min_lon）→**且仅** lon_min 半平面 recomb 违约。
    #[test]
    fn trail_neg_fence_west_rejected() {
        let (mut samples, alt_max, t_start) = honest(16);
        samples.rows[9].3 = FENCE.min_lon - 1; // 出西界
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &wiring(samples, alt_max, t_start, head_fold));
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
        let viol = sorted(check(&c));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[13], point: 64 + 9 }];
        assert_eq!(viol, expect, "出西界必须恰在 lon_min 门拒——实得 {:?}", viol);
    }

    /// 负例⑧：出北界（lat > max_lat）→**且仅** lat_max 半平面 recomb 违约。
    #[test]
    fn trail_neg_fence_north_rejected() {
        let (mut samples, alt_max, t_start) = honest(16);
        samples.rows[9].2 = FENCE.max_lat + 1; // 出北界
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &wiring(samples, alt_max, t_start, head_fold));
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
        let viol = sorted(check(&c));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[12], point: 64 + 9 }];
        assert_eq!(viol, expect, "出北界必须恰在 lat_max 门拒——实得 {:?}", viol);
    }

    /// 负例⑨（负纬度）：南半球围栏（lat 全负——SITL 南半球原点原像）+出南界
    /// →诚实对照 0 违约（偏置编码正确容纳负纬度），出南界样本**恰在**
    /// lat_min 半平面 recomb 违约（偏置域全序保持的红测面）。
    #[test]
    fn trail_neg_fence_south_negative_latitude() {
        // 负纬度样本族（SITL 南半球原点 lat=−31e7 同形）
        let mut samples = honest_samples(16, 1_700_000_000, 12_000);
        for (i, row) in samples.rows.iter_mut().enumerate() {
            row.2 = -310_000_000i32 + (i as i32) * 13;
        }
        rechain(&mut samples);
        let fence = FenceRect {
            min_lat: -320_000_000,
            max_lat: -300_000_000,
            min_lon: FENCE.min_lon,
            max_lon: FENCE.max_lon,
        };
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        // 诚实对照：负纬度全在界内 ⟹ 0 违约（偏置编码不误伤南半球）
        let c0 = weave_trail(
            &circ,
            &TrailWiring {
                samples: clone_samples(&samples),
                alt_max_cm: 12_000,
                t_start: 1_700_000_000,
                head_fold,
                sample_period_ms: PERIOD_MS,
                fence,
            },
        );
        assert!(check(&c0).is_empty(), "负纬度诚实样本必须 0 违约（偏置编码正确性）");
        // 出南界：样本 9 越过 min_lat（更南）
        let mut samples_bad = clone_samples(&samples);
        samples_bad.rows[9].2 = fence.min_lat - 1;
        rechain(&mut samples_bad);
        let circ_bad = crate::sm3_lookup_weave::trail_chain_circuit(&samples_bad.blocks);
        let head_bad = fold_words_be(&samples_bad.head);
        let c1 = weave_trail(
            &circ_bad,
            &TrailWiring {
                samples: samples_bad,
                alt_max_cm: 12_000,
                t_start: 1_700_000_000,
                head_fold: head_bad,
                sample_period_ms: PERIOD_MS,
                fence,
            },
        );
        let g = gate_layout(c1.info.constraints.len() - EMIT_CONSTRAINTS);
        let viol = sorted(check(&c1));
        let expect = vec![crate::sm3_compress::Violation { constraint: g[11], point: 64 + 9 }];
        assert_eq!(viol, expect, "出南界（负纬度域）必须恰在 lat_min 门拒——实得 {:?}", viol);
    }

    /// 负例⑩（角点恰在界上=通过）：样本分别压在 4 界上（东西南北各一样本）
    /// ⟹ 0 违约——半平面闭区间语义（≤/≥）红测面。
    #[test]
    fn trail_corner_on_boundary_passes() {
        let mut samples = honest_samples(16, 1_700_000_000, 12_000);
        samples.rows[0].2 = FENCE.min_lat; // 恰在南界
        samples.rows[1].2 = FENCE.max_lat; // 恰在北界
        samples.rows[2].3 = FENCE.min_lon; // 恰在西界
        samples.rows[3].3 = FENCE.max_lon; // 恰在东界
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let c = weave_trail(&circ, &wiring(samples, 12_000, 1_700_000_000, head_fold));
        let viol = check(&c);
        assert!(viol.is_empty(), "界上角点必须通过（闭区间语义）——实得 {:?}", viol.iter().take(4).collect::<Vec<_>>());
    }

    /// 正例（改动2 周期实例化）：1Hz 录制（Δt=1000）+ 周期实例 1000 ⟹ 0 违约
    /// ——不同采样率的记录同一电路可验（时间门常量 500 拆除的红绿面）。
    #[test]
    fn trail_period_1hz_honest_passes() {
        let mut samples = honest_samples(16, 1_700_000_000, 12_000);
        for (i, row) in samples.rows.iter_mut().enumerate() {
            row.0 = 1_700_000_000 + (i as u32) * 1000; // 1Hz 网格
        }
        rechain(&mut samples);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let mut w = wiring(samples, 12_000, 1_700_000_000, head_fold);
        w.sample_period_ms = 1000;
        let c = weave_trail(&circ, &w);
        let viol = check(&c);
        assert!(viol.is_empty(), "1Hz 诚实记录（周期实例 1000）必须 0 违约——实得 {:?}", viol.iter().take(4).collect::<Vec<_>>());
    }

    /// 负例⑪（改动2 周期钉）：声明周期 400 ≠ 记录网格 500 ⟹ 时间门在全部
    /// 配对行违约（周期不可谎报——电路逐对强制）。
    #[test]
    fn trail_neg_period_mismatch_rejected() {
        let (samples, alt_max, t_start) = honest(16);
        let circ = crate::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
        let head_fold = fold_words_be(&samples.head);
        let mut w = wiring(samples, alt_max, t_start, head_fold);
        w.sample_period_ms = 400; // 声明 ≠ 记录网格 500
        let c = weave_trail(&circ, &w);
        let g = gate_layout(c.info.constraints.len() - EMIT_CONSTRAINTS);
        let viol = sorted(check(&c));
        let expect: Vec<crate::sm3_compress::Violation> = (0..15)
            .map(|j| crate::sm3_compress::Violation { constraint: g[2], point: 256 + j })
            .collect();
        assert_eq!(viol, expect, "周期谎报必须恰在时间钉全配对行拒——实得 {:?}", viol.iter().take(4).collect::<Vec<_>>());
    }

    fn clone_samples(s: &TrailSamples) -> TrailSamples {
        TrailSamples {
            rows: s.rows.clone(),
            head: s.head,
            blocks: s.blocks.clone(),
            heads: s.heads.clone(),
        }
    }
}
