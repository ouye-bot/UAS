//! P2 SM3_LUT 织入层（system/sm3-lookup-full，系统线 2026-09-18）：
//! 把链式查表 SM3 体（[`crate::sm3_lookup_block`]）重放到全语句 vendor Builder。
//!
//! 接口契约（探针定谳 2026-09-18，设计稿 §一/一b）：
//! - 消息入口：`msg_roots[b][j] = (advice 列, 行)`——全语句 E 系列已写值的 32 位词格；
//!   LUT 输入是 4 位限位格 ⟹ 桥接 = 每词 8 个 msg-limb 格（落在 msg_root 同行，
//!   共 8 列/组按词分行）+ 选择器门控 recomp 线性约束（Σ2^{4k}·limb_k == 词值）+
//!   msg-limb ↔ W_INPUT 复制环；
//! - 摘要出口：末块摘要词格追加进 (dgw_cols[k], row_ae) 所在环——E7 大折叠读口零改动；
//! - 链 soundness：块间摘要→初态复制环（proto compress_entry 语义，电路内强制）；
//! - 谓词/验签面零改动：本层只替换 SM3 体（布尔 181,660 约束 → 查表 12+24）。
//!
//! ⑦代（2026-10-06）：**SM3 组列共享+查表通道合并**（深度分析性价比之王项）。
//! 各组原各占独立 34 列 advice（组间行带全同——纯列冗余）；换代后按 **lane
//! 带复用** 共享物理列：34 列被 4 线性门+8 查表通道钉成 9 个**列角色**（lane），
//! 每条 lane 复制出 ⌈Σ组行需求/4095⌉ 个 band 列组，各组行带错开复用；查表
//! 通道按同表同类合并到每 lane×band 一条。**查表论证的语义、表内容、绑定
//! 关系逐字不变**——只消灭物理列与通道的重复占用：
//! - 7 条查表 lane（XOR2/XOR3/MAJ/CH/SPLIT1/SPLIT3/ADD）：anchor 行（值非零
//!   ∨ 环成员）细粒度行槽错开；全零无环行不占物理格（零元组在全部表内，
//!   线性门全点成立——proto「非活跃行全零」纪律的推广）；
//! - INPUT lane：组内行带连续（SMT mux 面按组单列读口不变），first-fit 跨组
//!   错开复用；
//! - CONST lane：每电路 1 根 identity 列（`col==pconst` 全点门——值随行钉死
//!   不可搬行；跨组值恒同 pconst，多组写自然合并）；
//! - 门/通道发射从 per-group（4 门+8 通道/组）收敛为 per-lane×per-band——
//!   同 band 列组上所有组的行共用同一表达式集（逐行独立求值，行带错开即
//!   语义并集）。深度报告「全组共享 1 套 34 列」的估算按扁平行带推得，忽略
//!   了列角色对齐约束（一物理列承载两角色格 ⟹ 查表元组/线性门跨角色混载
//!   必违约，结构上不可行）；实测收益以 census 为准（见 zksvc 结构锚）。
//!
//! 🔴 纪律：SM3_LUT≠1 时本模块零调用（legacy 发布锚字节级行为保证）。

use crate::sm3_compress::Builder;
use crate::sm3_lookup_block::{
    BlockBuilder, BlockCircuit, W_ADD, W_CH, W_CONST, W_INPUT, W_MAJ, W_SPLIT1, W_SPLIT3,
    W_XOR2, W_XOR3, NUM_W, NUM_P, ROWS,
};
use crate::FpSM2;
use ff::Field as _;
use plonkish_backend::util::expression::{Expression, Query, Rotation};

pub const SM3_LUT_ENV: &str = "SM3_LUT";

/// SM3_LUT 部署默认（切 pin 仪式①，2026-09-19 队长拍板 A）：
/// 未显式设置时置 "1"（查表化 SM3 体为部署构型）；显式 "0"=legacy（发布锚
/// 字节级历史行为——与 PCS_INTERLEAVE 同款边界语义）。
/// 判决行 [实测 SV-4 服务器]：LUT pred 19,213,192B/prove 49.36s（verdict 内
/// 31.93s）/RSS 20.3GiB vs legacy 34,211,552B/122.17s/25.0GiB；verify 3.17s；
/// 负例 sumcheck 数学拒绝；门 2 双绿+门 3 e2e OK。
pub fn apply_sm3_lut_deployment_default() {
    if std::env::var_os(SM3_LUT_ENV).is_none() {
        std::env::set_var(SM3_LUT_ENV, "1");
    }
}

pub fn sm3_lut_enabled() -> bool {
    std::env::var(SM3_LUT_ENV).ok().as_deref() == Some("1")
}

fn q_advice(bld: &Builder<FpSM2>, local: usize) -> Expression<FpSM2> {
    bld.q(local, Rotation::cur())
}

fn q_prep(prep_global: usize) -> Expression<FpSM2> {
    Expression::Polynomial(Query::new(prep_global, Rotation::cur()))
}

// ═══════════════ ⑦代：lane 带复用布局（组列共享+通道合并的几何层） ═══════════════

/// lane（列角色）数：XOR2/XOR3/MAJ/CH/SPLIT1/SPLIT3/ADD/CONST/INPUT。
pub const LANE_N: usize = 9;
pub const L_XOR2: usize = 0;
pub const L_XOR3: usize = 1;
pub const L_MAJ: usize = 2;
pub const L_CH: usize = 3;
pub const L_SPLIT1: usize = 4;
pub const L_SPLIT3: usize = 5;
pub const L_ADD: usize = 6;
pub const L_CONST: usize = 7;
pub const L_INPUT: usize = 8;
/// (组内相对列基, 列宽) per lane——与 proto W_* 布局单一事实源对齐。
pub const LANE_GEOM: [(usize, usize); LANE_N] = [
    (W_XOR2, 3),
    (W_XOR3, 4),
    (W_MAJ, 4),
    (W_CH, 4),
    (W_SPLIT1, 5),
    (W_SPLIT3, 5),
    (W_ADD, 7),
    (W_CONST, 1),
    (W_INPUT, 1),
];

/// 相对列号 → lane 号（列角色）。
pub fn lane_of(rel: usize) -> usize {
    let mut l = 0;
    for (i, &(base, _)) in LANE_GEOM.iter().enumerate() {
        if rel >= base {
            l = i;
        }
    }
    debug_assert!(rel < LANE_GEOM[l].0 + LANE_GEOM[l].1, "相对列 {rel} 越界");
    l
}

/// 每 band 可用行数（行 0=LFSR 吸收态，禁入环/选择器/槽位）。
pub const BAND_ROWS: usize = ROWS - 1;
/// 未锚定标记（全零无环行——无物理格）。
pub const NO_SLOT: u32 = u32::MAX;

/// 组列共享布局（⑦代核心产物）：
/// - `bands[lane][band][w]` = 物理列号（AUTH=vendor advice 局部号；
///   TRAIL=packed witness 实列号——列号语义由 alloc 闭包决定）；
/// - 7 查表 lane 行槽细粒度错开；INPUT 按组连续行带；CONST 每电路 identity 列。
pub struct LanePack {
    pub bands: Vec<Vec<Vec<usize>>>,
    /// [组][查表 lane 0..7][proto 行] → 行槽号（NO_SLOT=未锚定）。
    slots: Vec<[Vec<u32>; 7]>,
    /// [组] INPUT lane 落位 (band, 行偏移)。
    input_at: Vec<(usize, usize)>,
    /// [组] 所在电路的 CONST 列。
    const_col_of: Vec<usize>,
}

/// pack 输入：电路与其在全语句组序中的基组号。
pub struct PackCircuit<'a> {
    pub base: usize,
    pub circ: &'a BlockCircuit,
}

/// lane 带复用布局构造（PLAN 相/织入前调用一次；列分配经 `alloc_col` 闭包）。
///
/// 行预算断言（既有机制延续，fail-closed）：
/// - band 数 = ⌈组数×lane 需求上界/4095⌉——需求上界取 `stats.rows_used`
///   （**分配**口径，数据无关 ⟹ band 数/列数/约束数对同形状语句确定）；
/// - anchor 槽总数 ≤ band 容量、INPUT 单组 ≤ 2^12 行——越界即 panic。
pub fn pack_lanes(
    circs: &[PackCircuit<'_>],
    total_groups: usize,
    mut alloc_col: impl FnMut() -> usize,
) -> LanePack {
    assert!(!circs.is_empty(), "pack 需要至少一个电路");
    let mut covered = vec![false; total_groups];

    // ── lane 需求上界（分配口径=末组 stats.rows_used；链式 INPUT 192>128 取 max）──
    let mut demand = [0usize; LANE_N];
    for pc in circs {
        for l in 0..LANE_N {
            if l == L_CONST {
                continue; // identity 列——不走行槽
            }
            demand[l] = demand[l].max(pc.circ.stats.rows_used[l].1);
        }
    }

    // ── anchor 标记：值非零 ∨ 环成员（环格=等值类载体，必须物理在场）──
    let mut marked: Vec<[Vec<bool>; 7]> =
        vec![std::array::from_fn(|_| vec![false; ROWS]); total_groups];
    let mut input_mark: Vec<Vec<bool>> = vec![vec![false; ROWS]; total_groups];
    for pc in circs {
        let g_n = pc.circ.wit_u64.len() / NUM_W;
        assert!(pc.base + g_n <= total_groups, "电路组数越出 PLAN 总组数");
        for lg in 0..g_n {
            covered[pc.base + lg] = true;
        }
        for (lg, wit_g) in pc.circ.wit_u64.chunks_exact(NUM_W).enumerate() {
            for (rel, col) in wit_g.iter().enumerate() {
                let lane = lane_of(rel);
                for (r, &v) in col.iter().enumerate() {
                    if v != 0 {
                        if lane == L_INPUT {
                            input_mark[pc.base + lg][r] = true;
                        } else if lane != L_CONST {
                            marked[pc.base + lg][lane][r] = true;
                        }
                    }
                }
            }
        }
        for cyc in &pc.circ.info.permutations {
            for &(p, r) in cyc.iter() {
                let ci = p - NUM_P;
                let lg = ci / NUM_W;
                let lane = lane_of(ci % NUM_W);
                if lane == L_INPUT {
                    input_mark[pc.base + lg][r] = true;
                } else if lane != L_CONST {
                    marked[pc.base + lg][lane][r] = true;
                }
            }
        }
    }
    assert!(covered.iter().all(|c| *c), "存在未被任何电路覆盖的组号");

    // ── 7 查表 lane 行槽（组↑行↑——确定性；行带互不重叠由槽号单源保证）──
    let mut slots: Vec<[Vec<u32>; 7]> =
        vec![std::array::from_fn(|_| vec![NO_SLOT; ROWS]); total_groups];
    let mut lane_next = [0u64; 7];
    for g in 0..total_groups {
        for l in 0..7 {
            for r in 0..ROWS {
                if marked[g][l][r] {
                    slots[g][l][r] = lane_next[l] as u32;
                    lane_next[l] += 1;
                }
            }
        }
    }

    // ── INPUT：组内行带连续 first-fit（mux 面按组单列读口——组内行序保持）──
    let mut input_at: Vec<(usize, usize)> = vec![(0, 0); total_groups];
    let mut band_cursor: Vec<usize> = Vec::new();
    for g in 0..total_groups {
        let dmax = input_mark[g].iter().rposition(|b| *b).map_or(0, |i| i + 1);
        assert!(
            dmax <= demand[L_INPUT] + 1,
            "INPUT 行需求越 stats 上界（组 {g}：{dmax} > {}）",
            demand[L_INPUT]
        );
        let mut placed = false;
        for (b, cur) in band_cursor.iter_mut().enumerate() {
            if *cur + dmax <= ROWS {
                input_at[g] = (b, *cur);
                *cur += dmax;
                placed = true;
                break;
            }
        }
        if !placed {
            assert!(dmax <= ROWS, "INPUT 行预算溢出 K=12（单组 {dmax} 行）");
            input_at[g] = (band_cursor.len(), 0);
            band_cursor.push(dmax);
        }
    }

    // ── 列分配（确定性序：lane↑ band↑ w↑）+ 行预算断言 ──
    let mut bands: Vec<Vec<Vec<usize>>> = Vec::with_capacity(LANE_N);
    for l in 0..7 {
        let need = total_groups as u64 * demand[l] as u64;
        let n_bands = usize::try_from(need.div_ceil(BAND_ROWS as u64)).unwrap_or(usize::MAX);
        assert!(
            lane_next[l] <= n_bands as u64 * BAND_ROWS as u64,
            "lane {l} 行预算越界：anchor {} > band 容量（stats 口径缺口）",
            lane_next[l]
        );
        bands.push(
            (0..n_bands)
                .map(|_| (0..LANE_GEOM[l].1).map(|_| alloc_col()).collect())
                .collect(),
        );
    }
    // CONST：每电路 1 根 identity 列（col==pconst 全点门钉值；跨组值恒同）。
    let const_cols: Vec<usize> = circs.iter().map(|_| alloc_col()).collect();
    let const_col_of: Vec<usize> = {
        let mut m = vec![0usize; total_groups];
        for (ci, pc) in circs.iter().enumerate() {
            let g_n = pc.circ.wit_u64.len() / NUM_W;
            for lg in 0..g_n {
                m[pc.base + lg] = const_cols[ci];
            }
        }
        m
    };
    bands.push(const_cols.iter().map(|&c| vec![c]).collect());
    // INPUT band 列。
    bands.push((0..band_cursor.len()).map(|_| vec![alloc_col()]).collect());

    LanePack { bands, slots, input_at, const_col_of }
}

impl LanePack {
    pub fn n_groups(&self) -> usize {
        self.slots.len()
    }
    pub fn n_bands(&self, lane: usize) -> usize {
        self.bands[lane].len()
    }
    /// 组 g 的 INPUT lane 物理列（SMT mux 读口）。
    pub fn input_col(&self, g: usize) -> usize {
        self.bands[L_INPUT][self.input_at[g].0][0]
    }
    /// 组 g INPUT lane proto 行 → 物理行。
    pub fn input_row(&self, g: usize, r: usize) -> usize {
        r + self.input_at[g].1
    }
    /// proto 格（组 g，相对列 rel，行 r）→ 物理格 (列, 行)。
    /// None=未锚定（全零且无环——无物理格；非零/环格查询缺失即上游 bug）。
    pub fn cell(&self, g: usize, rel: usize, r: usize) -> Option<(usize, usize)> {
        let lane = lane_of(rel);
        match lane {
            L_CONST => Some((self.const_col_of[g], r)),
            L_INPUT => Some((self.input_col(g), self.input_row(g, r))),
            _ => {
                let s = self.slots[g][lane][r];
                (s != NO_SLOT).then(|| {
                    let band = (s as usize) / BAND_ROWS;
                    let row = 1 + (s as usize) % BAND_ROWS;
                    (self.bands[lane][band][rel - LANE_GEOM[lane].0], row)
                })
            }
        }
    }
    /// packed 列总数（census/TRAIL witness 面）。
    pub fn total_cols(&self) -> usize {
        self.bands.iter().flat_map(|b| b.iter()).map(|w| w.len()).sum()
    }
    /// 逐 lane band 数（census 诊断面）。
    pub fn band_profile(&self) -> [usize; LANE_N] {
        std::array::from_fn(|l| self.bands[l].len())
    }
}

/// PLAN 相产物：全部列号（表/常量预处理列=全局号；advice=局部号）。
pub struct LutPlan {
    /// 23 个表列全局号（下标 = proto P_* 索引 0..22）。
    pub prep_globals: Vec<usize>,
    /// pconst 预处理列全局号。
    pub pconst_global: usize,
    /// ⑦代 lane 带复用布局（advice 面全部经 `plan.pack.cell(g, rel, r)` 映射）。
    pub pack: LanePack,
    /// 每组 128 个 msg-limb 列引用（词 j limb k → [j*8+k]；⑦代改动2：经
    /// 行去重 first-fit 并置——多词共享物理列，接口逐字不变）。
    pub msg_limb_cols: Vec<Vec<usize>>,
    /// 每组 16 个 recomp 选择器（全局号）。
    pub msg_sels: Vec<Vec<usize>>,
    /// 末块摘要 8 词 × 8 limb 的影子列（@row_ae）——dgw 词值格的分解面
    ///（⑦代改动2：与 msg-limb 同池并置）。
    pub dgw_shadow_cols: [[usize; 8]; 8],
    /// dgw 影子 recomp 选择器（8 个，@row_ae）。
    pub dgw_sels: [usize; 8],
}

/// PLAN 相：分配 LUT 体全部列（必须在全语句首条款束前调用——冻结守卫纪律）。
/// `circs` = 全语句全部 SM3 电路（含基组号；三体 0..、C 块、SN 块、SMT 链续接）；
/// `msg_word_rows[g][j]` = msg 组 g 词 j 的根行（limb 列 packing 的行去重条件）；
/// `dgw_row` = dgw 影子行。SMT 组 lane 化零 msg-limb 需求（不进 msg_word_rows）。
pub fn weave_alloc(
    bld: &mut Builder<FpSM2>,
    circs: &[PackCircuit<'_>],
    msg_word_rows: &[[usize; 16]],
    dgw_row: usize,
    pconst: &[u64],
) -> LutPlan {
    let total_groups: usize = circs.iter().map(|c| c.circ.wit_u64.len() / NUM_W).sum();
    assert!(msg_word_rows.len() <= total_groups, "msg-limb 组数超总组数");
    let pack = pack_lanes(circs, total_groups, || bld.alloc_col());
    let tables = BlockBuilder::lut_tables();
    let mut prep_globals = Vec::with_capacity(23);
    for t in tables.iter().take(23) {
        prep_globals.push(bld.alloc_const_poly(t.clone()));
    }
    let pconst_global =
        bld.alloc_const_poly(pconst.iter().map(|&v| FpSM2::from(v)).collect());

    // ── ⑦代改动2：msg-limb/dgw 影子列 packing（各列仅 1 行活跃 ⟹ 行复用并置）。
    // 8 条物理列成一 set（limb k → set[k]）；词↔set first-fit 行去重——同 set
    // 内词根行必异（撞行 panic=fail-closed；跨组/跨族（msg↔dgw）共享同池）。
    let mut set_rows: Vec<Vec<bool>> = Vec::new();
    fn pick_set(set_rows: &mut Vec<Vec<bool>>, row: usize) -> usize {
        assert_ne!(row, 0, "limb 列 packing 行 0 禁用（LFSR 吸收态）");
        for (s, used) in set_rows.iter_mut().enumerate() {
            if !used[row] {
                used[row] = true;
                return s;
            }
        }
        let mut u = vec![false; ROWS];
        u[row] = true;
        set_rows.push(u);
        set_rows.len() - 1
    }
    let msg_groups = msg_word_rows.len();
    let mut msg_set_of: Vec<Vec<usize>> = Vec::with_capacity(msg_groups);
    for g in 0..msg_groups {
        msg_set_of.push((0..16).map(|j| pick_set(&mut set_rows, msg_word_rows[g][j])).collect());
    }
    let dgw_sets: [usize; 8] = std::array::from_fn(|k| pick_set(&mut set_rows, dgw_row));
    let sets: Vec<[usize; 8]> =
        (0..set_rows.len()).map(|_| std::array::from_fn(|_| bld.alloc_col())).collect();
    let mut msg_limb_cols: Vec<Vec<usize>> = Vec::with_capacity(msg_groups);
    for set_of in msg_set_of.iter() {
        let mut cols = vec![0usize; 128];
        for j in 0..16 {
            for k in 0..8 {
                cols[j * 8 + k] = sets[set_of[j]][k];
            }
        }
        msg_limb_cols.push(cols);
    }
    let dgw_shadow_cols: [[usize; 8]; 8] =
        std::array::from_fn(|k| std::array::from_fn(|j| sets[dgw_sets[k]][j]));
    let mut msg_sels: Vec<Vec<usize>> = Vec::with_capacity(msg_groups);
    for _ in 0..msg_groups {
        msg_sels.push((0..16).map(|_| bld.alloc_selector(&[])).collect());
    }
    LutPlan { prep_globals, pconst_global, pack, msg_limb_cols, msg_sels, dgw_shadow_cols, dgw_sels: std::array::from_fn(|_| bld.alloc_selector(&[])) }
}

/// B3b（飞证）：WIRES core——见证值播种（等值类代表值制）+环翻译（重叠 proto
/// 环并查集合并）。对任意 BlockCircuit 通用（三体链/SMT 链共用——列号约定
/// 教训㊶单一事实源：vcell 公式只在此处）。⑦代：物理格经 [`LanePack`] 映射
///（`base` = 电路首组在全语句组序中的基组号）。
pub fn weave_core(bld: &mut Builder<FpSM2>, circ: &BlockCircuit, plan: &LutPlan, base: usize) {
    let groups = circ.wit_u64.len() / NUM_W;
    assert!(base + groups <= plan.pack.n_groups(), "电路组数越出 PLAN 总组数");

    // 物理 cell 映射：proto 全局列 → (vendor advice 局部号, 物理行)
    let vcell = |p: usize, r: usize| -> (usize, usize) {
        let rel = p - NUM_P;
        let g = base + rel / NUM_W;
        plan.pack.cell(g, rel % NUM_W, r).unwrap_or_else(|| {
            panic!(
                "⑦代 pack 锚缺失：组 {g} 相对列 {rel} 行 {r}——非零/环格未被 anchor 扫描覆盖"
            )
        })
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
                let (c, pr) = vcell(NUM_P + ci, r);
                bld.set_cell_f(c, pr, FpSM2::from(final_v));
            }
        }
    }

    let n_cyc = circ.info.permutations.len();
    let mut parent: Vec<usize> = (0..n_cyc).collect();
    let mut cell_first: std::collections::HashMap<(usize, usize), usize> =
        std::collections::HashMap::new();
    for (i, cyc) in circ.info.permutations.iter().enumerate() {
        for &(p, r) in cyc.iter() {
            let key = vcell(p, r);
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
                let vl = vcell(p, r);
                if !done.insert(vl) { continue; }
                match ring_id {
                    None => ring_id = Some(bld.begin_relay_col(vl.0, vl.1)),
                    Some(id) => bld.relay_to_col(id, vl.0, vl.1),
                }
            }
        }
    }
}

/// ⑦代：lane 门+查表通道按 band 全局发射（CONSTRAINTS 相；每语句恰一次——
/// 覆盖全部电路的全部组）。语义与 per-group 发射逐字等价：band 列组上所有
/// 组的行带错开（槽位单源），表达式逐行独立求值 ⟹ 并集语义；零填充行在
/// 全部表内/线性门恒成立（proto「非活跃行全零」纪律）。
pub fn emit_lane_gates(bld: &mut Builder<FpSM2>, plan: &LutPlan) {
    let a = |b: &Builder<FpSM2>, lane: usize, band: usize, w: usize| {
        q_advice(b, plan.pack.bands[lane][band][w])
    };
    for band in 0..plan.pack.n_bands(L_SPLIT1) {
        bld.push(
            "lut.split1",
            a(bld, L_SPLIT1, band, 4)
                - (Expression::Constant(FpSM2::from(2u64)) * a(bld, L_SPLIT1, band, 2)
                    + a(bld, L_SPLIT1, band, 3)),
        );
    }
    for band in 0..plan.pack.n_bands(L_SPLIT3) {
        bld.push(
            "lut.split3",
            a(bld, L_SPLIT3, band, 4)
                - (Expression::Constant(FpSM2::from(8u64)) * a(bld, L_SPLIT3, band, 2)
                    + a(bld, L_SPLIT3, band, 3)),
        );
    }
    for band in 0..plan.pack.n_bands(L_ADD) {
        bld.push(
            "lut.add",
            a(bld, L_ADD, band, 0)
                + a(bld, L_ADD, band, 1)
                + a(bld, L_ADD, band, 2)
                + a(bld, L_ADD, band, 3)
                + a(bld, L_ADD, band, 4)
                - a(bld, L_ADD, band, 5)
                - Expression::Constant(FpSM2::from(16u64)) * a(bld, L_ADD, band, 6),
        );
    }
    for band in 0..plan.pack.n_bands(L_CONST) {
        bld.push("lut.const", a(bld, L_CONST, band, 0) - q_prep(plan.pconst_global));
    }
    // 查表通道合并：每 lane×band 一条（表列序=PREP_TAB；ADD band 双通道
    // RANGE16/RANGE4）。
    let pair = |b: &Builder<FpSM2>, lane: usize, band: usize, w0: usize, n: usize, p_idx: usize| {
        (0..n)
            .map(|j| (a(b, lane, band, w0 + j), q_prep(plan.prep_globals[p_idx + j])))
            .collect::<Vec<_>>()
    };
    for band in 0..plan.pack.n_bands(L_XOR2) {
        bld.emit_lookup(pair(bld, L_XOR2, band, 0, 3, 0));
    }
    for band in 0..plan.pack.n_bands(L_XOR3) {
        bld.emit_lookup(pair(bld, L_XOR3, band, 0, 4, 3));
    }
    for band in 0..plan.pack.n_bands(L_MAJ) {
        bld.emit_lookup(pair(bld, L_MAJ, band, 0, 4, 7));
    }
    for band in 0..plan.pack.n_bands(L_CH) {
        bld.emit_lookup(pair(bld, L_CH, band, 0, 4, 11));
    }
    for band in 0..plan.pack.n_bands(L_SPLIT1) {
        bld.emit_lookup(pair(bld, L_SPLIT1, band, 0, 3, 15));
    }
    for band in 0..plan.pack.n_bands(L_SPLIT3) {
        bld.emit_lookup(pair(bld, L_SPLIT3, band, 0, 3, 18));
    }
    for band in 0..plan.pack.n_bands(L_ADD) {
        bld.emit_lookup(vec![(a(bld, L_ADD, band, 5), q_prep(plan.prep_globals[21]))]);
        bld.emit_lookup(vec![(a(bld, L_ADD, band, 6), q_prep(plan.prep_globals[22]))]);
    }
}

/// ⑦代：proto 编号版 lane 门+查表通道（TRAIL 织入消费——advice=NUM_P+packed
/// 列；表=poly 0..22、pconst=poly 23）。几何/系数与 [`emit_lane_gates`] 单一
/// 事实源对齐（两处表达式树形态不同：vendor Builder q vs 裸 poly）。
pub fn proto_lane_gates_exprs(
    pack: &LanePack,
) -> (
    Vec<Expression<FpSM2>>,
    Vec<Vec<(Expression<FpSM2>, Expression<FpSM2>)>>,
) {
    let poly = |i: usize| Expression::Polynomial(Query::new(i, Rotation::cur()));
    let adv = |lane: usize, band: usize, w: usize| poly(NUM_P + pack.bands[lane][band][w]);
    let cst = |v: u64| Expression::Constant(FpSM2::from(v));
    let mut cons = Vec::new();
    for band in 0..pack.n_bands(L_SPLIT1) {
        cons.push(
            adv(L_SPLIT1, band, 4)
                - (cst(2) * adv(L_SPLIT1, band, 2) + adv(L_SPLIT1, band, 3)),
        );
    }
    for band in 0..pack.n_bands(L_SPLIT3) {
        cons.push(
            adv(L_SPLIT3, band, 4)
                - (cst(8) * adv(L_SPLIT3, band, 2) + adv(L_SPLIT3, band, 3)),
        );
    }
    for band in 0..pack.n_bands(L_ADD) {
        cons.push(
            adv(L_ADD, band, 0)
                + adv(L_ADD, band, 1)
                + adv(L_ADD, band, 2)
                + adv(L_ADD, band, 3)
                + adv(L_ADD, band, 4)
                - adv(L_ADD, band, 5)
                - cst(16) * adv(L_ADD, band, 6),
        );
    }
    for band in 0..pack.n_bands(L_CONST) {
        cons.push(adv(L_CONST, band, 0) - poly(23));
    }
    let pair = |lane: usize, band: usize, w0: usize, n: usize, p0: usize| {
        (0..n).map(|j| (adv(lane, band, w0 + j), poly(p0 + j))).collect::<Vec<_>>()
    };
    let mut lks = Vec::new();
    for band in 0..pack.n_bands(L_XOR2) {
        lks.push(pair(L_XOR2, band, 0, 3, 0));
    }
    for band in 0..pack.n_bands(L_XOR3) {
        lks.push(pair(L_XOR3, band, 0, 4, 3));
    }
    for band in 0..pack.n_bands(L_MAJ) {
        lks.push(pair(L_MAJ, band, 0, 4, 7));
    }
    for band in 0..pack.n_bands(L_CH) {
        lks.push(pair(L_CH, band, 0, 4, 11));
    }
    for band in 0..pack.n_bands(L_SPLIT1) {
        lks.push(pair(L_SPLIT1, band, 0, 3, 15));
    }
    for band in 0..pack.n_bands(L_SPLIT3) {
        lks.push(pair(L_SPLIT3, band, 0, 3, 18));
    }
    for band in 0..pack.n_bands(L_ADD) {
        lks.push(vec![(adv(L_ADD, band, 5), poly(21))]);
        lks.push(vec![(adv(L_ADD, band, 6), poly(22))]);
    }
    (cons, lks)
}

/// WIRES 相（先于全语句首条 push——环登记 assert_open 红线）：
/// 见证值播种 + 环翻译（经 weave_core）+ 消息/摘要桥接（三体链专用面）。
pub fn weave_wires(
    bld: &mut Builder<FpSM2>,
    circ: &BlockCircuit,
    plan: &LutPlan,
    msg_roots: &[[(usize, usize); 16]],
    dgw_cols: &[usize; 8],
    row_ae: usize,
) {
    let groups = circ.wit_u64.len() / NUM_W;
    assert_eq!(circ.inputs_per_block.len(), groups, "块数与组数不符");
    assert_eq!(msg_roots.len(), groups, "消息根组数不符");

    // ── ①④ 已抽为 weave_core（三体链=全语句组序首段，base=0）──
    weave_core(bld, circ, plan, 0);

    // ── ④b：C 词格单例环——batch2 S7 z-plan（电路内算 C=SM3(salt‖attrs) 的
    // 第 4 块，保持布尔）经 ring_of(b2_c) 追加 z 出口格；LUT 模式下布尔链体被
    // 替换，须由织入预开单例环供 S7 挂接（单例环无成员时 finalize 过滤）。──
    for j in 0..8usize {
        let (mcol, mrow) = msg_roots[1][j];
        bld.begin_relay_col(mcol, mrow);
    }

    // ── ⑤ 桥接一：消息词（msg-limb 格入 W_INPUT 格所在环 + recomp 约束）──
    // ⑦代：msg-limb 物理列经 packing 并置（plan.msg_limb_cols 接口不变）；
    // W_INPUT 物理格经 pack（组 g=三体本地组号）。
    for (g, words) in circ.inputs_per_block.iter().enumerate() {
        for (j, word) in words.iter().enumerate() {
            let (mcol, mrow) = msg_roots[g][j];
            // 环桥接：msg-limb 格 ↔ W_INPUT 格。🔴 W_INPUT 相对列号必须按组
            // 经 pack 映射（此前漏组基使三组 msg-limb 全挂组0 环——104 坏环
            // 的病灶，探针定谳）。
            for k in 0..8 {
                // 🔴 limb 行必须 = mrow（recomp 在该点求值）；🔴 W_INPUT proto
                // 全局列须剥组基（%NUM_W——组号 g 由 enumerate 给出，教训㊷同款）
                let limb_local = plan.msg_limb_cols[g][j * 8 + k];
                let limb_row = mrow;
                let w_in = word[k];
                let (wc, wr) = plan
                    .pack
                    .cell(g, (w_in.col - NUM_P) % NUM_W, w_in.row)
                    .expect("W_INPUT 格必锚（消费环面）");
                let val = circ.wit_u64[w_in.col - NUM_P][w_in.row];
                bld.set_cell_f(limb_local, limb_row, FpSM2::from(val));
                let id = bld
                    .ring_of(wc, wr)
                    .expect("W_INPUT 格必属生产环");
                bld.relay_to_col(id, limb_local, limb_row);
            }
        }
    }

    // ── ⑥ 桥接二：末块摘要 → dgw@row_ae。摘要格=4 位限位格而 dgw 格=32 位
    // 词值格——不能直接环等：每 limb 一个影子格@row_ae（环等值）+ 选择器门控
    // Σ2^{4j}·shadow == 词值约束（影子值经 ① 播种/dgw 写入双面一致）。──
    for (k, word) in circ.digest_cells.iter().enumerate() {
        for (j, limb) in word.iter().enumerate() {
            let shadow = plan.dgw_shadow_cols[k][j];
            let val = circ.wit_u64[limb.col - NUM_P][limb.row];
            bld.set_cell_f(shadow, row_ae, FpSM2::from(val));
            // 末块摘要 limb 格可能无消费者（无环）——新开环挂影子格
            let rel = limb.col - NUM_P;
            let g = rel / NUM_W;
            let (lc, lr) = plan
                .pack
                .cell(g, rel % NUM_W, limb.row)
                .expect("摘要 limb 格必锚（值面）");
            let id = match bld.ring_of(lc, lr) {
                Some(id) => id,
                None => bld.begin_relay_col(lc, lr),
            };
            bld.relay_to_col(id, shadow, row_ae);
        }
    }

}

/// CONSTRAINTS 相（替换 assemble_chained_bodies 布尔体发射点）：
/// recomp 桥接约束（三体）+ **全语句 lane 门/查表通道全局发射**（⑦代：
/// emit_lane_gates 一次覆盖三体/C/SN/SMT 全部组——per-group 门/通道消灭）。
pub fn weave_constraints(
    bld: &mut Builder<FpSM2>,
    circ: &BlockCircuit,
    plan: &LutPlan,
    msg_roots: &[[(usize, usize); 16]],
    dgw_cols: &[usize; 8],
    row_ae: usize,
) {
    let groups = circ.wit_u64.len() / NUM_W;
    assert!(groups <= plan.msg_limb_cols.len(), "三体组数超 msg 组面");
    // dgw 影子 recomp（8 词各一条，选择器门控 @row_ae；⑦代影子列 packing 透明）
    for k in 0..8 {
        bld.extend_selector(plan.dgw_sels[k], &[row_ae]);
        let mut fold = q_advice(bld, dgw_cols[k]);
        for j in 0..8 {
            let shadow_e = q_advice(bld, plan.dgw_shadow_cols[k][j]);
            fold = fold
                - Expression::Constant(FpSM2::from(1u64 << (4 * j))) * shadow_e;
        }
        bld.push("lut.dgw.recomp", bld.sel(plan.dgw_sels[k]) * fold);
    }
    // 消息 recomp 约束（每组 16 条，选择器门控 @msg 行；limb 列 packing 透明）
    for (g, words) in circ.inputs_per_block.iter().enumerate() {
        for (j, word) in words.iter().enumerate() {
            let (mcol, mrow) = msg_roots[g][j];
            bld.extend_selector(plan.msg_sels[g][j], &[mrow]);
            let mut recomp = q_advice(bld, mcol);
            for k in 0..8 {
                let limb_e = q_advice(bld, plan.msg_limb_cols[g][j * 8 + k]);
                recomp = recomp
                    - Expression::Constant(FpSM2::from(1u64 << (4 * k))) * limb_e;
            }
            bld.push("lut.msg.recomp", bld.sel(plan.msg_sels[g][j]) * recomp);
        }
    }
    // ⑦代：lane 门+查表通道按 band 全局发射（全部电路共用——per-group 重复占用消灭）。
    emit_lane_gates(bld, plan);
}

/// R3-3.1（飞证 2026-09-24）：承诺 C 单块织入——WIRES 相。
///
/// 承诺块（C=SM3(salt‖preimage)，auth 55B/pred 48B 单块）以第 `g` 组消费
/// LutPlan（AUTH 组序：三体 0..2 → C 块 3 → SN 块 4 → SMT 5..）。pconst 复用
/// 三体组预处理列——消息无关性由常驻守卫测试 [`tests::pconst_is_message_independent`] 钉死。
///
/// 与三体 [`weave_wires`] 同构，差异两点：
/// ① 独立 [`BlockCircuit`]（fresh IV 单块——不与三体链共享电路，chain_circuit
///    单块调用即得；digest=SM3 标准语义 == host commit_c_words_auth）；
/// ② 摘要出口影子落 `row_c`（c_cols@row_c 的 recomp 分解源），非 row_ae。
pub fn weave_commit_block_wires(
    bld: &mut Builder<FpSM2>,
    circ: &BlockCircuit,
    plan: &LutPlan,
    g: usize,
    msg_roots: &[(usize, usize); 16],
    shadow_cols: &[[usize; 8]; 8],
    row_c: usize,
) {
    assert_eq!(circ.wit_u64.len(), NUM_W, "承诺块必须=单组电路");
    assert!(g < plan.pack.n_groups(), "承诺组号越界");
    // core：值播种+环翻译（单组电路 @base g）
    weave_core(bld, circ, plan, g);

    // ⑤ msg 桥接：limb 格 ↔ W_INPUT 环（与 weave_wires ⑤ 同构——limb 行=
    // 词根行；⑦代 W_INPUT 物理格经 pack 组 g 映射）。
    for (j, word) in circ.inputs_per_block[0].iter().enumerate() {
        let (_, mrow) = msg_roots[j];
        for k in 0..8 {
            let limb_local = plan.msg_limb_cols[g][j * 8 + k];
            let w_in = word[k];
            let rel = w_in.col - NUM_P; // 单组电路：rel=相对号
            let (wc, wr) = plan
                .pack
                .cell(g, rel, w_in.row)
                .expect("W_INPUT 格必锚（消费环面）");
            let val = circ.wit_u64[rel][w_in.row];
            bld.set_cell_f(limb_local, mrow, FpSM2::from(val));
            let id = bld
                .ring_of(wc, wr)
                .expect("W_INPUT 格必属生产环");
            bld.relay_to_col(id, limb_local, mrow);
        }
    }

    // ⑥ 摘要影子：C 摘要 limb ↔ 影子格 @row_c（约束相 recomp 绑 c_cols 词；
    // 摘要 limb 格电路内无消费者——begin_relay_col 开环，dgw ⑥ 同法）。
    for (k, word) in circ.digest_cells.iter().enumerate() {
        for (j, limb) in word.iter().enumerate() {
            let shadow = shadow_cols[k][j];
            let val = circ.wit_u64[limb.col - NUM_P][limb.row];
            bld.set_cell_f(shadow, row_c, FpSM2::from(val));
            let rel = limb.col - NUM_P;
            let (lc, lr) = plan
                .pack
                .cell(g, rel, limb.row)
                .expect("摘要 limb 格必锚（值面）");
            let id = match bld.ring_of(lc, lr) {
                Some(id) => id,
                None => bld.begin_relay_col(lc, lr),
            };
            bld.relay_to_col(id, shadow, row_c);
        }
    }
}

/// R3-3.1：承诺 C 单块织入——CONSTRAINTS 相（recomp 桥接面）。
/// `sels` = 8 条摘要影子 recomp 选择器（调用方 PLAN 相分配）。
///
/// ⑦代：4 门+8 查表通道的 per-group 发射已收敛进 [`emit_lane_gates`] 全局
/// 发射（weave_constraints 调用点）——本函数只保留 recomp 桥接约束
///（8×`lut.c.dg.recomp` + 16×`lut.c.msg.recomp`）。三体 [`weave_constraints`]
/// 手写面语义零触碰。
pub fn weave_commit_block_constraints(
    bld: &mut Builder<FpSM2>,
    circ: &BlockCircuit,
    plan: &LutPlan,
    g: usize,
    msg_roots: &[(usize, usize); 16],
    c_cols: &[usize; 8],
    row_c: usize,
    shadow_cols: &[[usize; 8]; 8],
    sels: &[usize; 8],
) {
    assert_eq!(circ.wit_u64.len(), NUM_W, "承诺块必须=单组电路");

    // 摘要影子 recomp ×8（@row_c 选择器门控）。
    for k in 0..8 {
        bld.extend_selector(sels[k], &[row_c]);
        let mut fold = q_advice(bld, c_cols[k]);
        for j in 0..8 {
            let shadow_e = q_advice(bld, shadow_cols[k][j]);
            fold = fold
                - Expression::Constant(FpSM2::from(1u64 << (4 * j))) * shadow_e;
        }
        bld.push("lut.c.dg.recomp", bld.sel(sels[k]) * fold);
    }

    // 消息 recomp ×16（@词根行）：Σ2^{4k}·limb == 根格词值。
    for (j, _word) in circ.inputs_per_block[0].iter().enumerate() {
        let (mcol, mrow) = msg_roots[j];
        bld.extend_selector(plan.msg_sels[g][j], &[mrow]);
        let mut recomp = q_advice(bld, mcol);
        for k in 0..8 {
            let limb_e = q_advice(bld, plan.msg_limb_cols[g][j * 8 + k]);
            recomp = recomp
                - Expression::Constant(FpSM2::from(1u64 << (4 * k))) * limb_e;
        }
        bld.push("lut.c.msg.recomp", bld.sel(plan.msg_sels[g][j]) * recomp);
    }
}

/// R2-SMT 修复（2026-09-23）的⑦代收编：SMT 链 proto 门全量翻译
///（[`crate::smt_weave::weave_smt_wires`] 内 weave_core 的值/环面）之上的
/// 约束/查表强制，已由 [`emit_lane_gates`] 的 **lane×band 全局发射**统一承载
///——SMT 组的行槽与三体/C/SN 组错开共享同一批 band 列组，其查表论证由同
/// 一组通道逐行覆盖（行带错开即并集语义）。per-group 逐条翻译发射已删除
///（物理列与通道的重复占用消灭；负例面 `auth_smt_forged_root_vacuity_red`
/// 红线测试继续钉死该强制在案）。

/// 链式三块查表体的宿主计算（见证值/环账本/逐块消息格）——P2 织入的计算引擎。
/// `blocks` = 全语句 M′ 的三块（host.blocks，165B 报文的 SM3 填充分块）。
/// B3b 飞证：块数泛化（三体=3、SMT 链=33——同机制块串行复用行域）。
/// 🔴 语义边界（B6-T2 定谳）：本函数=**IV 链传**（v=dg 逐块下传——SM3 标准
/// 多块报文/SMT 数据块+padding 块的语义）。TRAIL 的单块样本链**不得**用本函数：
/// h_{i+1}=SM3(h_i‖遥测四元组) 每块 fresh IV、链在消息前 32B——用
/// [`trail_chain_circuit`]。
pub fn chain_circuit(blocks: &[[u8; 64]]) -> BlockCircuit {
    let mut bb = BlockBuilder::new();
    let mut v = crate::sm3_native_ref::IV;
    let mut prev: Option<[crate::sm3_lookup_block::Word; 8]> = None;
    let mut last: [crate::sm3_lookup_block::Word; 8] =
        std::array::from_fn(|_| std::array::from_fn(|_| crate::sm3_lookup_block::Cell { col: 0, row: 0 }));
    for b in blocks {
        let (cells, dg) = bb.compress_entry(prev.as_ref(), &v, b);
        v = dg;
        prev = Some(cells);
        last = cells;
    }
    bb.finalize(v, last)
}

/// B6 飞证 TRAIL：**消息级链式**（trail_host 单一事实源语义）。
///
/// 每样本块=完整单块 SM3（46B 消息+padding），h_i 作为消息词 0..7 进块——
/// IV 恒为标准常量（prev=None 走 const 通道，pconst 同步），链 soundness 由
/// 消息词复制环强制：
///   块 0   词 0..7 ← genesis 常量词（SM3(b"FZ-TEL-GENESIS")，公开常量钉）
///   块 i+1 词 0..7 ← 块 i 摘要词（bind_input_word 环等值）
/// 与 fence.py sample_hash 同构；digest 出口==host 链头（差分门
/// `trail_chain_circuit_digest_matches_host` 钉死）。
pub fn trail_chain_circuit(blocks: &[[u8; 64]]) -> BlockCircuit {
    use crate::sm3_lookup_block::Word;
    let mut bb = BlockBuilder::new();
    let iv = crate::sm3_native_ref::IV;
    let genesis = crate::trail_host::genesis_head();
    // genesis 常量词：组 0 CONST 通道（const_word 同步 pconst+wit，const_c 全点
    // 成立；进环合法——Tj 常量词即先例）。锚定记录链从公开常量起步（B6-d8）。
    let gen_words: [Word; 8] = std::array::from_fn(|k| {
        let wv = u32::from_be_bytes(genesis[4 * k..4 * k + 4].try_into().expect("界内"));
        bb.const_word(wv)
    });
    let mut prev: Option<[Word; 8]> = None;
    let mut last: [Word; 8] =
        std::array::from_fn(|_| std::array::from_fn(|_| crate::sm3_lookup_block::Cell { col: 0, row: 0 }));
    let mut dg_last = iv;
    for (i, b) in blocks.iter().enumerate() {
        let binds: Vec<(usize, &Word)> = match prev.as_ref() {
            None => (0..8).map(|k| (k, &gen_words[k])).collect(),
            Some(p) => (0..8).map(|k| (k, &p[k])).collect(),
        };
        let _ = i;
        let (cells, dg) = bb.compress_entry_binds(None, &iv, b, &binds);
        prev = Some(cells);
        last = cells;
        dg_last = dg;
    }
    bb.finalize(dg_last, last)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm3_lookup_weave::chain_circuit;

    /// R3-3.1 前置守卫（2026-09-24 定谳）：任意电路实例的 pconst **内容恒定**
    /// （块级常量词与消息无关——T_j 旋转常量族）。承诺块查表化（R3-3.1）
    /// 依赖此性质：C 单块组可复用三体组的 pconst 预处理列（单一事实源）。
    /// 若未来 BlockBuilder 改变 pconst 生成语义，此测试当场爆掉。
    #[test]
    fn pconst_is_message_independent() {
        let blk_a: [[u8; 64]; 1] = [core::array::from_fn(|i| (i as u8).wrapping_mul(13) ^ 0x5E)];
        let mut blk_b: [[u8; 64]; 2] = [
            core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x3C),
            core::array::from_fn(|i| (i as u8).wrapping_mul(11) ^ 0xA1),
        ];
        blk_b[1][55] = 0x80; // 差异化第二块（含 padding 字节——排除巧合）
        let a = chain_circuit(&blk_a).pconst;
        let b = chain_circuit(&blk_b).pconst;
        assert_eq!(a, b, "pconst 随消息漂移——R3-3.1 的单 pconst 复用前提失效");
        // 非零健全性（全零=常量通道没接对——探针实证非零）
        assert!(a.iter().any(|&v| v != 0), "pconst 全零——常量通道异常");
    }

    // ═══════════ ⑦代负例矩阵扩型（通道合并形态——只增不减） ═══════════

    /// pack 几何守卫：34 列被 lane 几何无缝覆盖（无空洞/无重叠）。
    #[test]
    fn lane_geometry_partitions_34_columns() {
        for rel in 0..NUM_W {
            let lane = lane_of(rel);
            let (base, width) = LANE_GEOM[lane];
            assert!(rel >= base && rel < base + width, "rel {rel} 未被 lane {lane} 覆盖");
        }
        let total: usize = LANE_GEOM.iter().map(|(_, w)| w).sum();
        assert_eq!(total, NUM_W, "lane 列宽合计 != 34");
    }

    /// 跨组行带污染负例①（通道合并形态）：A 组行带的查表值被改写为离表元组
    ///（模拟把 A 组行带值错喂到共享 band 列上 B 组的行选择）——合并后的
    /// 单条通道按行逐查 ⟹ 元组离表必须被查表论证拒绝（mock 口径）。
    #[test]
    fn pack_cross_group_band_pollution_offtable_rejected() {
        // 两块链电路（组 0/1）→ pack 成共享 band 布局（proto 编号表达式树）
        let blk: [[u8; 64]; 2] = [
            core::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ 0xA7),
            core::array::from_fn(|i| (i as u8).wrapping_mul(31) ^ 0x5B),
        ];
        let circ = chain_circuit(&blk);
        let mut next_col = 0usize;
        let pack = pack_lanes(
            &[PackCircuit { base: 0, circ: &circ }],
            2,
            || {
                next_col += 1;
                next_col - 1
            },
        );
        // packed witness + 门/通道表达式（proto 编号）
        let mut wit: Vec<Vec<FpSM2>> = (0..pack.total_cols())
            .map(|_| vec![FpSM2::ZERO; ROWS])
            .collect();
        for (g, wit_g) in circ.wit_u64.chunks_exact(NUM_W).enumerate() {
            for (rel, col) in wit_g.iter().enumerate() {
                for (r, &v) in col.iter().enumerate() {
                    if v != 0 {
                        let (c, pr) = pack.cell(g, rel, r).expect("非零格必锚");
                        wit[c][pr] = FpSM2::from(v);
                    }
                }
            }
        }
        // 组 0 与组 1 的行带在同一 band 列上必须互不重叠（跨组污染的前提排查：
        // 行带重叠=pack 槽位冲突——槽号单源保证不重叠，此处实证）
        {
            let mut seen = std::collections::HashSet::new();
            for g in 0..2 {
                for r in 0..ROWS {
                    if let Some((c, pr)) = pack.cell(g, W_XOR2, r) {
                        assert!(seen.insert((c, pr)), "跨组行带重叠：组 {g} XOR2 行 {r}");
                    }
                }
            }
        }
        // 攻击：定位组 0 的某 XOR2 anchor 行（band 列上），把输出格 c 改成
        // 与 (a,b) 不匹配的离表值——合并通道逐行查 ⟹ 该行元组离表必拒。
        let (victim_col_local, victim_row) = (0..ROWS)
            .find_map(|r| pack.cell(0, W_XOR2 + 2, r))
            .expect("组 0 XOR2 输出格必锚");
        let vals: Vec<u64> = (0..3)
            .map(|w| {
                let (c, pr) = pack.cell(0, W_XOR2 + w, victim_row).expect("同行三格必锚");
                let v = wit[c][pr];
                (0..16u64).find(|x| FpSM2::from(*x) == v).expect("limb 值 ∈ 0..16")
            })
            .collect();
        let cur = vals[2];
        let bad = if cur == 15 { 0u64 } else { cur + 1 };
        // 语义守卫：篡改值确为离表（a⊕b 不变式被破坏）
        assert_ne!(bad, vals[0] ^ vals[1], "篡改值仍在表内——负例失真");
        wit[victim_col_local][victim_row] = FpSM2::from(bad);
        // mock 查表论证：受污染行元组离表必红
        let mut bad_rows = 0usize;
        for lk in proto_lane_gates_exprs(&pack).1.iter() {
            // 取通道内 (输入 poly, 表 poly) 对；对 XOR2 通道逐行复核
            let polys: Vec<(usize, usize)> = lk
                .iter()
                .filter_map(|(a, b)| match (a, b) {
                    (Expression::Polynomial(qa), Expression::Polynomial(qb)) => {
                        Some((qa.poly(), qb.poly()))
                    }
                    _ => None,
                })
                .collect();
            if polys.len() == 3 && polys.iter().all(|&(_, t)| t < NUM_P) && polys[0].1 == 0 {
                // XOR2 表通道：表元组集
                let table: std::collections::HashSet<Vec<u64>> = (0..256usize)
                    .map(|i| {
                        let (a, b) = ((i >> 4) as u64, (i & 15) as u64);
                        vec![a, b, a ^ b]
                    })
                    .collect();
                for r in 1..ROWS {
                    let tup: Vec<u64> = polys
                        .iter()
                        .map(|&(inp, _)| {
                            let v = wit[inp - NUM_P][r];
                            (0..16u64).find(|x| FpSM2::from(*x) == v).unwrap_or(u64::MAX)
                        })
                        .collect();
                    if !table.contains(&tup) {
                        bad_rows += 1;
                    }
                }
            }
        }
        assert!(bad_rows > 0, "跨组行带污染（离表元组）未被合并通道击中——查表论证失守");
    }

    /// 跨组行带污染负例②（错误行选择路由）：把 B 组行带的合法值整体路由到
    /// A 组的环成员格（行选择路由错位形态）——环等值类被破坏，环审计必红。
    #[test]
    fn pack_cross_group_ring_route_misrouted_rejected() {
        let blk: [[u8; 64]; 2] = [
            core::array::from_fn(|i| (i as u8).wrapping_mul(17) ^ 0x33),
            core::array::from_fn(|i| (i as u8).wrapping_mul(19) ^ 0x77),
        ];
        let circ = chain_circuit(&blk);
        let mut next_col = 0usize;
        let pack = pack_lanes(
            &[PackCircuit { base: 0, circ: &circ }],
            2,
            || {
                next_col += 1;
                next_col - 1
            },
        );
        let mut wit: Vec<Vec<FpSM2>> = (0..pack.total_cols())
            .map(|_| vec![FpSM2::ZERO; ROWS])
            .collect();
        for (g, wit_g) in circ.wit_u64.chunks_exact(NUM_W).enumerate() {
            for (rel, col) in wit_g.iter().enumerate() {
                for (r, &v) in col.iter().enumerate() {
                    if v != 0 {
                        let (c, pr) = pack.cell(g, rel, r).expect("非零格必锚");
                        wit[c][pr] = FpSM2::from(v);
                    }
                }
            }
        }
        // 基线：proto 环在 packed 布局下环内等值全成立（pack 环路由正解）
        for cyc in circ.info.permutations.iter() {
            if cyc.len() < 2 {
                continue;
            }
            let v0 = {
                let (p, r) = cyc[0];
                let ci = p - NUM_P;
                let (c, pr) = pack.cell(ci / NUM_W, ci % NUM_W, r).expect("环格必锚");
                wit[c][pr]
            };
            for &(p, r) in cyc.iter() {
                let ci = p - NUM_P;
                let (c, pr) = pack.cell(ci / NUM_W, ci % NUM_W, r).expect("环格必锚");
                assert_eq!(wit[c][pr], v0, "基线环等值失败——pack 环路由错位");
            }
        }
        // 攻击：取组 0 的一个多成员环，把末成员格值改为组 1 行带的某查表值
        //（合法值、错误行选择路由——洗白形态：值本身在表内）。
        let cyc = circ
            .info
            .permutations
            .iter()
            .find(|c| {
                c.len() >= 3
                    && c.iter().all(|&(p, _)| {
                        let ci = p - NUM_P;
                        lane_of(ci % NUM_W) != L_CONST
                    })
            })
            .expect("存在跨列多成员环（xor/add 消费环）");
        let &(p_last, r_last) = cyc.last().unwrap();
        let ci_last = p_last - NUM_P;
        let (tc, tr) = pack
            .cell(ci_last / NUM_W, ci_last % NUM_W, r_last)
            .expect("环格必锚");
        // 组 1 行带的在表值（污染载荷——取组 1 非 0 XOR2 输出 limb）
        let payload = (1..ROWS)
            .find_map(|r| pack.cell(1, W_XOR2 + 2, r).filter(|_| circ.wit_u64[NUM_W + W_XOR2 + 2][r] != 0))
            .map(|(c, pr)| wit[c][pr])
            .expect("组 1 行带在表值存在");
        wit[tc][tr] = payload;
        // 环等值被破坏 ⟹ 路由错位形态被置换论证拒绝
        let v0 = {
            let (p, r) = cyc[0];
            let ci = p - NUM_P;
            let (c, pr) = pack.cell(ci / NUM_W, ci % NUM_W, r).expect("环格必锚");
            wit[c][pr]
        };
        assert_ne!(
            {
                let &(p, r) = cyc.last().unwrap();
                let ci = p - NUM_P;
                let (c, pr) = pack.cell(ci / NUM_W, ci % NUM_W, r).expect("环格必锚");
                wit[c][pr]
            },
            v0,
            "污染载荷恰等于环值——负例失真"
        );
    }

    /// 错误行选择路由负例③（fail-closed 面）：limb 列 packing 同 set 撞行
    ///（两词同根行进同 set=错误行选择）——packer 必 panic（焊死在构造期）。
    #[test]
    fn pack_limb_set_row_conflict_fails_closed() {
        let blk: [[u8; 64]; 1] = [core::array::from_fn(|i| (i as u8).wrapping_mul(23) ^ 0x11)];
        let circ = chain_circuit(&blk);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut bld = crate::sm3_compress::Builder::<FpSM2>::new(1);
            weave_alloc(
                &mut bld,
                &[PackCircuit { base: 0, circ: &circ }],
                &[[7usize; 16], [7usize; 16]], // 两 msg 组词 0 同根行 7
                9,
                &circ.pconst,
            );
        }));
        assert!(
            outcome.is_err(),
            "同 set 撞行必须构造期 panic（错误行选择被 fail-closed 拒）"
        );
    }

    /// 行预算断言负例（fail-closed 面）：band 容量越界（anchor>stats 上界口径
    /// 的容量）不可达——此处焊死 stats 口径与槽总量的一致性守卫：对多电路
    /// pack 后逐 lane 槽位 ≤ band 容量（构造期 assert 已内建，测试再实证）。
    #[test]
    fn pack_row_budget_assertion_holds_multicircuit() {
        let blk3: Vec<[u8; 64]> = (0..3)
            .map(|g| core::array::from_fn(|i| (i as u8).wrapping_mul(7 + g) ^ 0x9D))
            .collect();
        let c3 = chain_circuit(&blk3);
        let blk1: [[u8; 64]; 1] = [core::array::from_fn(|i| (i as u8).wrapping_mul(13) ^ 0xC3)];
        let c1 = chain_circuit(&blk1);
        let mut next_col = 0usize;
        let pack = pack_lanes(
            &[PackCircuit { base: 0, circ: &c3 }, PackCircuit { base: 3, circ: &c1 }],
            4,
            || {
                next_col += 1;
                next_col - 1
            },
        );
        // 槽位密度实证：每 lane 物理列数显著少于 per-group 34 列基线
        let total = pack.total_cols();
        assert!(total < 4 * NUM_W, "packing 未生效（{total} ≥ {}）", 4 * NUM_W);
        eprintln!(
            "[⑦代-pack] 4 组 packed 列={} band 剖面={:?}（per-group 基线 {}）",
            total,
            pack.band_profile(),
            4 * NUM_W
        );
        // band 数确定性：同形状重跑逐位一致
        let pack2 = pack_lanes(
            &[PackCircuit { base: 0, circ: &c3 }, PackCircuit { base: 3, circ: &c1 }],
            4,
            || {
                next_col += 1;
                next_col - 1
            },
        );
        assert_eq!(pack.band_profile(), pack2.band_profile(), "band 数漂移（数据无关口径失效）");
    }
}
