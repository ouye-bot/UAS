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
//! 🔴 纪律：SM3_LUT≠1 时本模块零调用（legacy 发布锚字节级行为保证）。

use crate::sm3_compress::Builder;
use crate::sm3_lookup_block::{
    BlockBuilder, BlockCircuit, W_ADD, W_CH, W_CONST, W_INPUT, W_MAJ, W_SPLIT1, W_SPLIT3,
    W_XOR2, W_XOR3, NUM_W, NUM_P,
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

/// PLAN 相产物：全部列号（表/常量预处理列=全局号；advice=局部号）。
pub struct LutPlan {
    /// 23 个表列全局号（下标 = proto P_* 索引 0..22）。
    pub prep_globals: Vec<usize>,
    /// pconst 预处理列全局号。
    pub pconst_global: usize,
    /// 每组 34 个 advice 局部号（[组][通道相对列]）。
    pub advice: Vec<Vec<usize>>,
    /// 每组 128 个 msg-limb 列（16 词 × 8 limb，词 j limb k → [j*8+k]）。
    pub msg_limb_cols: Vec<Vec<usize>>,
    /// 每组 16 个 recomp 选择器（全局号）。
    pub msg_sels: Vec<Vec<usize>>,
    /// 末块摘要 8 词 × 8 limb 的影子列（@row_ae）——dgw 词值格的分解面。
    pub dgw_shadow_cols: [[usize; 8]; 8],
    /// dgw 影子 recomp 选择器（8 个，@row_ae）。
    pub dgw_sels: [usize; 8],
}

/// PLAN 相：分配 LUT 体全部列（必须在全语句首条款束前调用——冻结守卫纪律）。
/// `msg_groups` = 需要 msg-limb 桥接列/选择器的组数（三体=3；SMT 组 lane 化
/// 后零 msg-limb 需求——避免 128 空列/组=4096 无消费 advice poly）。
pub fn weave_alloc(bld: &mut Builder<FpSM2>, groups: usize, msg_groups: usize, pconst: &[u64]) -> LutPlan {
    assert!(msg_groups <= groups, "msg-limb 组数超总组数");
    let tables = BlockBuilder::lut_tables();
    let mut prep_globals = Vec::with_capacity(23);
    for t in tables.iter().take(23) {
        prep_globals.push(bld.alloc_const_poly(t.clone()));
    }
    let pconst_global =
        bld.alloc_const_poly(pconst.iter().map(|&v| FpSM2::from(v)).collect());
    let mut advice = Vec::with_capacity(groups);
    let mut msg_limb_cols = Vec::with_capacity(msg_groups);
    let mut msg_sels = Vec::with_capacity(msg_groups);
    for g in 0..groups {
        advice.push((0..NUM_W).map(|_| bld.alloc_col()).collect());
        if g < msg_groups {
            msg_limb_cols.push((0..128).map(|_| bld.alloc_col()).collect());
            msg_sels.push((0..16).map(|_| bld.alloc_selector(&[])).collect());
        }
    }
    let dgw_shadow_cols: [[usize; 8]; 8] = std::array::from_fn(|_| std::array::from_fn(|_| bld.alloc_col()));
    let dgw_sels = std::array::from_fn(|_| bld.alloc_selector(&[]));
    LutPlan { prep_globals, pconst_global, advice, msg_limb_cols, msg_sels, dgw_shadow_cols, dgw_sels }
}

/// B3b（飞证）：WIRES core——见证值播种（等值类代表值制）+环翻译（重叠 proto
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

    // ── ①④ 已抽为 weave_core（B3b 飞证：三体链/SMT 链共用，教训㊶单一事实源）──
    // 三体链占 plan 前 3 组（SMT 组续接——core 只见自己的组切片）
    let sub = LutPlan {
        prep_globals: plan.prep_globals.clone(),
        pconst_global: plan.pconst_global,
        advice: plan.advice[..3].to_vec(),
        msg_limb_cols: plan.msg_limb_cols[..3].to_vec(),
        msg_sels: plan.msg_sels[..3].to_vec(),
        dgw_shadow_cols: plan.dgw_shadow_cols,
        dgw_sels: plan.dgw_sels,
    };
    weave_core(bld, circ, &sub);

    // 列映射（⑤⑥ 段消费：proto 全局列 → vendor advice 局部号——三体前 3 组）
    let vcol = |proto_col: usize| -> usize {
        let rel = proto_col - NUM_P;
        plan.advice[rel / NUM_W][rel % NUM_W]
    };

    // ── ④b：C 词格单例环——batch2 S7 z-plan（电路内算 C=SM3(salt‖attrs) 的
    // 第 4 块，保持布尔）经 ring_of(b2_c) 追加 z 出口格；LUT 模式下布尔链体被
    // 替换，须由织入预开单例环供 S7 挂接（单例环无成员时 finalize 过滤）。──
    for j in 0..8usize {
        let (mcol, mrow) = msg_roots[1][j];
        bld.begin_relay_col(mcol, mrow);
    }

    // ── ⑤ 桥接一：消息词（msg-limb 格入 W_INPUT 格所在环 + recomp 约束）──
    for (g, words) in circ.inputs_per_block.iter().enumerate() {
        for (j, word) in words.iter().enumerate() {
            let (mcol, mrow) = msg_roots[g][j];
            // 环桥接：msg-limb 格 ↔ W_INPUT 格。🔴 W_INPUT 局部号必须含组基
            //（vcol(word 的 proto col)）——此前漏组基使三组 msg-limb 全挂组0 环
            //（104 坏环的病灶，探针定谳）。
            for k in 0..8 {
                // 🔴 limb 行必须 = mrow（recomp 在该点求值）；每词独立列避免同点冲突
                let limb_local = plan.msg_limb_cols[g][j * 8 + k];
                let limb_row = mrow;
                let w_in = word[k];
                let w_in_local = vcol(w_in.col);
                let val = circ.wit_u64[w_in.col - NUM_P][w_in.row];
                bld.set_cell_f(limb_local, limb_row, FpSM2::from(val));
                let id = bld
                    .ring_of(w_in_local, w_in.row)
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
            let id = match bld.ring_of(vcol(limb.col), limb.row) {
                Some(id) => id,
                None => bld.begin_relay_col(vcol(limb.col), limb.row),
            };
            bld.relay_to_col(id, shadow, row_ae);
        }
    }

}

/// CONSTRAINTS 相（替换 assemble_chained_bodies 布尔体发射点）：
/// 4×组 全点线性约束 + 8×组 查表论证。
pub fn weave_constraints(
    bld: &mut Builder<FpSM2>,
    circ: &BlockCircuit,
    plan: &LutPlan,
    msg_roots: &[[(usize, usize); 16]],
    dgw_cols: &[usize; 8],
    row_ae: usize,
) {
    let groups = circ.wit_u64.len() / NUM_W;
    // B3b：三体链只消费自己的组切片（plan 可能含 SMT 续接组）——构造受限视图
    let plan = &LutPlan {
        prep_globals: plan.prep_globals.clone(),
        pconst_global: plan.pconst_global,
        advice: plan.advice[..groups].to_vec(),
        msg_limb_cols: plan.msg_limb_cols[..groups].to_vec(),
        msg_sels: plan.msg_sels[..groups].to_vec(),
        dgw_shadow_cols: plan.dgw_shadow_cols,
        dgw_sels: plan.dgw_sels,
    };
    assert_eq!(groups, plan.advice.len(), "组数与 PLAN 不符");
    // dgw 影子 recomp（每组……非——按 8 词各一条，选择器门控 @row_ae）
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
    // 消息 recomp 约束（每组 16 条，选择器门控 @msg 行）
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
    for g in 0..groups {
        let a = |b: &Builder<FpSM2>, rel: usize| q_advice(b, plan.advice[g][rel]);
        // SPLIT 的 2^k 系数为域常数（proto cst(1<<k) 同语义）
        bld.push(
            "lut.split1",
            a(bld, W_SPLIT1 + 4)
                - (Expression::Constant(FpSM2::from(2u64)) * a(bld, W_SPLIT1 + 2)
                    + a(bld, W_SPLIT1 + 3)),
        );
        bld.push(
            "lut.split3",
            a(bld, W_SPLIT3 + 4)
                - (Expression::Constant(FpSM2::from(8u64)) * a(bld, W_SPLIT3 + 2)
                    + a(bld, W_SPLIT3 + 3)),
        );
        bld.push(
            "lut.add",
            a(bld, W_ADD)
                + a(bld, W_ADD + 1)
                + a(bld, W_ADD + 2)
                + a(bld, W_ADD + 3)
                + a(bld, W_ADD + 4)
                - a(bld, W_ADD + 5)
                - Expression::Constant(FpSM2::from(16u64)) * a(bld, W_ADD + 6),
        );
        bld.push("lut.const", a(bld, W_CONST) - q_prep(plan.pconst_global));
    }

    // ── ③ 查表论证（每组 8 通道）──
    for g in 0..groups {
        // 按通道序发射（表列下标对齐 PREP_TAB 顺序）
        let pair = |b: &Builder<FpSM2>, w0: usize, n: usize, p_idx: usize| {
            (0..n)
                .map(|j| {
                    (
                        q_advice(b, plan.advice[g][w0 + j]),
                        q_prep(plan.prep_globals[p_idx + j]),
                    )
                })
                .collect::<Vec<_>>()
        };
        bld.emit_lookup(pair(bld, W_XOR2, 3, 0));
        bld.emit_lookup(pair(bld, W_XOR3, 4, 3));
        bld.emit_lookup(pair(bld, W_MAJ, 4, 7));
        bld.emit_lookup(pair(bld, W_CH, 4, 11));
        bld.emit_lookup(pair(bld, W_SPLIT1, 3, 15));
        bld.emit_lookup(pair(bld, W_SPLIT3, 3, 18));
        bld.emit_lookup(vec![(
            q_advice(bld, plan.advice[g][W_ADD + 5]),
            q_prep(plan.prep_globals[21]),
        )]);
        bld.emit_lookup(vec![(
            q_advice(bld, plan.advice[g][W_ADD + 6]),
            q_prep(plan.prep_globals[22]),
        )]);
    }

}

/// R3-3.1（飞证 2026-09-24）：承诺 C 单块织入——WIRES 相。
///
/// 承诺块（C=SM3(salt‖preimage)，auth 55B/pred 48B 单块）以第 `g` 组消费
/// LutPlan（三体 3 组之后的独立单组——`weave_alloc(groups=4+smt,
/// msg_groups=4)` 的组 3；SMT 组续接 4..）。pconst 复用三体组预处理列——
/// 消息无关性由常驻守卫测试 [`tests::pconst_is_message_independent`] 钉死。
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
    assert!(g < plan.advice.len(), "承诺组号越界");
    // core：值播种+环翻译（单组切片视图——weave_core 组数断言=1 ✓）
    let sub = LutPlan {
        prep_globals: plan.prep_globals.clone(),
        pconst_global: plan.pconst_global,
        advice: plan.advice[g..g + 1].to_vec(),
        msg_limb_cols: plan.msg_limb_cols[g..g + 1].to_vec(),
        msg_sels: plan.msg_sels[g..g + 1].to_vec(),
        dgw_shadow_cols: plan.dgw_shadow_cols,
        dgw_sels: plan.dgw_sels,
    };
    weave_core(bld, circ, &sub);

    let vcol = |proto_col: usize| -> usize {
        let rel = proto_col - NUM_P;
        plan.advice[g][rel % NUM_W]
    };

    // ⑤ msg 桥接：limb 格 ↔ W_INPUT 环（与 weave_wires ⑤ 同构——limb 行=
    // 词根行；组基由单组索引天然含，教训㊷ 病灶结构上不可达）。
    for (j, word) in circ.inputs_per_block[0].iter().enumerate() {
        let (_, mrow) = msg_roots[j];
        for k in 0..8 {
            let limb_local = plan.msg_limb_cols[g][j * 8 + k];
            let w_in = word[k];
            let w_in_local = vcol(w_in.col);
            let val = circ.wit_u64[w_in.col - NUM_P][w_in.row];
            bld.set_cell_f(limb_local, mrow, FpSM2::from(val));
            let id = bld
                .ring_of(w_in_local, w_in.row)
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
            let id = match bld.ring_of(vcol(limb.col), limb.row) {
                Some(id) => id,
                None => bld.begin_relay_col(vcol(limb.col), limb.row),
            };
            bld.relay_to_col(id, shadow, row_c);
        }
    }
}

/// R3-3.1：承诺 C 单块织入——CONSTRAINTS 相（recomp + 4 门 + 8 查表）。
/// `sels` = 8 条摘要影子 recomp 选择器（调用方 PLAN 相分配）。
///
/// 语句增量：8×`lut.c.dg.recomp`（Σ2^{4j}·shadow == c_cols[k]@row_c）+
/// 16×`lut.c.msg.recomp` + 4 门 + 8 通道。三体 [`weave_constraints`] 手写面
/// 零触碰（发布锚字节级）；本函数=第 4 组的镜像发射。
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

    // 4 线性门（split1/split3/add/const——weave_constraints 组体同构）。
    let a = |b: &Builder<FpSM2>, rel: usize| q_advice(b, plan.advice[g][rel]);
    bld.push(
        "lut.c.split1",
        a(bld, W_SPLIT1 + 4)
            - (Expression::Constant(FpSM2::from(2u64)) * a(bld, W_SPLIT1 + 2)
                + a(bld, W_SPLIT1 + 3)),
    );
    bld.push(
        "lut.c.split3",
        a(bld, W_SPLIT3 + 4)
            - (Expression::Constant(FpSM2::from(8u64)) * a(bld, W_SPLIT3 + 2)
                + a(bld, W_SPLIT3 + 3)),
    );
    bld.push(
        "lut.c.add",
        a(bld, W_ADD)
            + a(bld, W_ADD + 1)
            + a(bld, W_ADD + 2)
            + a(bld, W_ADD + 3)
            + a(bld, W_ADD + 4)
            - a(bld, W_ADD + 5)
            - Expression::Constant(FpSM2::from(16u64)) * a(bld, W_ADD + 6),
    );
    bld.push(
        "lut.c.const",
        a(bld, W_CONST) - q_prep(plan.pconst_global),
    );

    // 8 查表通道（表列序=PREP_TAB，与 weave_constraints 同序）。
    let pair = |b: &Builder<FpSM2>, w0: usize, n: usize, p_idx: usize| {
        (0..n)
            .map(|j| {
                (
                    q_advice(b, plan.advice[g][w0 + j]),
                    q_prep(plan.prep_globals[p_idx + j]),
                )
            })
            .collect::<Vec<_>>()
    };
    bld.emit_lookup(pair(bld, W_XOR2, 3, 0));
    bld.emit_lookup(pair(bld, W_XOR3, 4, 3));
    bld.emit_lookup(pair(bld, W_MAJ, 4, 7));
    bld.emit_lookup(pair(bld, W_CH, 4, 11));
    bld.emit_lookup(pair(bld, W_SPLIT1, 3, 15));
    bld.emit_lookup(pair(bld, W_SPLIT3, 3, 18));
    bld.emit_lookup(vec![(
        q_advice(bld, plan.advice[g][W_ADD + 5]),
        q_prep(plan.prep_globals[21]),
    )]);
    bld.emit_lookup(vec![(
        q_advice(bld, plan.advice[g][W_ADD + 6]),
        q_prep(plan.prep_globals[22]),
    )]);
}

/// R2-SMT 修复（2026-09-23）：**proto 查表门全量翻译**——把 BlockCircuit
/// 自带的逐组 4 约束（split1/split3/add/const）+ 8 lookup 通道按列映射
/// 翻译进 Builder。B3b 缺口定谳：auth 装配只翻译了 SMT proto 的环与见证
/// 值（weave_core），proto 约束/lookup 被丢弃 ⟹ SMT 链 64 组的 SM3 压缩
/// 函数电路内零强制——伪造见证红线测试
/// `auth_smt_forged_root_vacuity_red` 实锤（假兄弟+真根 mock 零违约）。
///
/// TRAIL 先例 = proto 约束经 shift 直接合并（trail_weave::weave_trail，
/// lookups=1,024 全约束）；本函数=Builder 版同构。三体组不经过此口
/// （weave_constraints 手写面=发布锚零触碰）。
///
/// 前提（proto 语义，sm3_lookup_block::finalize 定谳）：
/// ① 查询全 cur 旋转；② prep 索引 0..=22=表列（prep_globals 同序）、
/// 23=P_CONST（pconst_global）；③ advice 局部号=proto 全局−NUM_P，
/// 组宽 NUM_W（34）；④ 见证值已由 weave_core 全行播种（proto witness
/// 全行自洽，约束/查表在全部 4,096 行成立）。
pub fn weave_proto_gates(bld: &mut Builder<FpSM2>, circ: &BlockCircuit, plan: &LutPlan) {
    use crate::sm3_lookup_block::{NUM_P, NUM_W};

    let groups = circ.wit_u64.len() / NUM_W;
    assert_eq!(groups, plan.advice.len(), "组数与 PLAN 不符");
    debug_assert_eq!(plan.msg_limb_cols.len(), 0, "proto 门翻译不消费 msg-limb 面");

    // proto 全局 poly 号 → vendor 列（prep=表全局号；advice=局部号经 bld.q）
    fn vexpr(bld: &Builder<FpSM2>, e: &Expression<FpSM2>, plan: &LutPlan) -> Expression<FpSM2> {
        use crate::sm3_lookup_block::{NUM_P, NUM_W};
        match e {
            Expression::Constant(c) => Expression::Constant(*c),
            Expression::CommonPolynomial(c) => Expression::CommonPolynomial(*c),
            Expression::Polynomial(q) => {
                debug_assert_eq!(q.rotation().0, 0, "proto 查询应全 cur");
                let p = q.poly();
                if p < NUM_P {
                    let g = if p == 23 { plan.pconst_global } else { plan.prep_globals[p] };
                    q_prep(g)
                } else {
                    let ci = p - NUM_P;
                    q_advice(bld, plan.advice[ci / NUM_W][ci % NUM_W])
                }
            }
            Expression::Challenge(_) => panic!("proto 无 challenge 查询"),
            Expression::Negated(a) => Expression::Negated(Box::new(vexpr(bld, a, plan))),
            Expression::Sum(a, b) => Expression::Sum(
                Box::new(vexpr(bld, a, plan)),
                Box::new(vexpr(bld, b, plan)),
            ),
            Expression::Product(a, b) => Expression::Product(
                Box::new(vexpr(bld, a, plan)),
                Box::new(vexpr(bld, b, plan)),
            ),
            Expression::Scaled(a, s) => Expression::Scaled(Box::new(vexpr(bld, a, plan)), *s),
            Expression::DistributePowers(vs, base) => Expression::DistributePowers(
                vs.iter().map(|v| vexpr(bld, v, plan)).collect(),
                Box::new(vexpr(bld, base, plan)),
            ),
        }
    }

    // 逐组 4 约束（顺序=proto finalize：split1/split3/add/const——ctag 对齐）
    const GATE_TAGS: [&str; 4] =
        ["smt.lut.split1", "smt.lut.split3", "smt.lut.add", "smt.lut.const"];
    assert_eq!(circ.info.constraints.len(), groups * 4, "proto 约束数=组数×4");
    for (ci, cc) in circ.info.constraints.iter().enumerate() {
        bld.push(GATE_TAGS[ci % 4], vexpr(bld, cc, plan));
    }
    // 逐组 8 lookup 通道
    for chan in &circ.info.lookups {
        let pairs: Vec<(Expression<FpSM2>, Expression<FpSM2>)> = chan
            .iter()
            .map(|(a, b)| (vexpr(bld, a, plan), vexpr(bld, b, plan)))
            .collect();
        bld.emit_lookup(pairs);
    }
}

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
}
