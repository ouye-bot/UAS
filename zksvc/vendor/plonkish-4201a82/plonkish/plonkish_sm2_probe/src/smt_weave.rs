//! 飞证 B3b：SM3-SMT 撤销累加器织入（深度 32，键=子凭证出示公钥 x 坐标 pk′.x）。
//!
//! 语义（与 uas/backend/app/ra/smt.py 同构单一事实源——B3b 叶语义修正版）：
//! - 非成员验证起点 cur_0 = SM3(b"FZ-SMT-EMPTY")（空叶默认——常量锚）
//! - 内节点 = SM3(左 ‖ 右)（64B 整块，fresh IV；左右按路径位 bit 选边）
//! - 链：cur_{g+1} = bit_g ? SM3(sib_g‖cur_g) : SM3(cur_g‖sib_g)，
//!   末块摘要词序折叠 == rev_root 实例钉。
//! - 洗白封堵：32 路径位格 bool+recomb==pkx 词值（键=证明者自己的出示公钥，
//!   E8 [sk′]G=pk′ 电路内绑定）+每 limb mux（msgL/msgR∈{cur,sib} 按 bit——
//!   bit 进约束=路径位被电路消费）。根钉锁死消息自由度（SM3 抗碰撞）。
//!
//! 相位纪律（冻结守卫 assert_open）：alloc_cols+wires（环登记）在 PLAN 相
//! （首条 push 前），emit（mux/recomb/fold push+实例钉）在 EMIT 相。

use plonkish_backend::util::expression::{Expression, Rotation};

use crate::sm3_compress::Builder;
use crate::sm3_lookup_block::{BlockBuilder, NUM_P, NUM_W, W_INPUT};
use crate::sm3_lookup_weave::{weave_core, LutPlan};
use crate::sm3_native_ref;
use crate::FpSM2;

pub const SMT_DEPTH: usize = 32;
/// proto 组数=深度×2（B3b-d7：标准 SM3 语义——每内节点=数据块+padding 块）。
pub const SMT_GROUPS: usize = 2 * SMT_DEPTH;
pub const EMPTY_LABEL: &[u8] = b"FZ-SMT-EMPTY";

/// 空叶值（非成员验证起点）。
pub fn empty_leaf() -> [u8; 32] {
    sm3_native_ref::hash(EMPTY_LABEL)
}

/// 空树非成员见证（兄弟=叶→根序 DEFAULT 链；根=DEFAULT[0]；bits=键位）。
/// DEFAULT[d]=SM3(DEFAULT[d+1]‖DEFAULT[d+1])，DEFAULT[32]=空叶值。
/// 链自洽性（B3b 定谳）：cur_0=空叶=DEFAULT[32]、每层兄弟=DEFAULT[32-i]——
/// cur 恒=兄弟同值 ⟹ 对称链闭合到 DEFAULT[0] ✓。
pub fn smt_default_witness() -> (
    [[u8; 32]; SMT_DEPTH],
    [u8; 32],
    [u8; SMT_DEPTH],
) {
    let empty = empty_leaf();
    let mut defaults = vec![empty; SMT_DEPTH + 1];
    for d in (0..SMT_DEPTH).rev() {
        let mut two = Vec::with_capacity(64);
        two.extend_from_slice(&defaults[d + 1]);
        two.extend_from_slice(&defaults[d + 1]);
        defaults[d] = sm3_native_ref::hash(&two);
    }
    let siblings: [[u8; 32]; SMT_DEPTH] = std::array::from_fn(|i| defaults[SMT_DEPTH - i]);
    let bits = [0u8; SMT_DEPTH];
    (siblings, defaults[0], bits)
}

/// 词序折叠（fold_digest_fp 同式——与 M_A 的 e 口径一致）。
pub fn fold_words_be(root: &[u8; 32]) -> FpSM2 {
    let mut e = FpSM2::from(0u64);
    for k in 0..8 {
        let wv = u32::from_be_bytes(root[4 * k..4 * k + 4].try_into().expect("界内"));
        e += FpSM2::from(u64::from(wv)) * crate::sm2_params::f_pow2(32 * k);
    }
    e
}

/// SMT 链块消息组装（bit 选边）：返回 (32 块消息, 期望根)。
pub fn smt_blocks(
    key_be: &[u8; 32],
    siblings: &[[u8; 32]; SMT_DEPTH],
) -> (Vec<[u8; 64]>, [u8; 32]) {
    let mut bits = [0u8; SMT_DEPTH];
    let v = u32::from_be_bytes(key_be[..4].try_into().expect("界内"));
    // R3-0.1：叶层（g=0）消费 LSB——host smt.py verify_non_membership 同序
    for i in 0..SMT_DEPTH {
        bits[i] = ((v >> i) & 1) as u8;
    }
    assemble_chain(&empty_leaf(), siblings, &bits)
}

fn assemble_chain(
    cur0: &[u8; 32],
    siblings: &[[u8; 32]; SMT_DEPTH],
    bits: &[u8; SMT_DEPTH],
) -> (Vec<[u8; 64]>, [u8; 32]) {
    let mut blocks = Vec::with_capacity(SMT_DEPTH);
    let mut cur = *cur0;
    for g in 0..SMT_DEPTH {
        let mut blk = [0u8; 64];
        if bits[g] == 0 {
            blk[..32].copy_from_slice(&cur);
            blk[32..].copy_from_slice(&siblings[g]);
        } else {
            blk[..32].copy_from_slice(&siblings[g]);
            blk[32..].copy_from_slice(&cur);
        }
        cur = sm3_native_ref::hash(&blk);
        blocks.push(blk);
    }
    (blocks, cur)
}

/// SMT 链 proto 计算：32 块消息词落格（mux 自由度在织入层）。
pub fn smt_chain_circuit(
    key_be: &[u8; 32],
    siblings: &[[u8; 32]; SMT_DEPTH],
) -> (
    crate::sm3_lookup_block::BlockCircuit,
    [u32; 8],
    Vec<[[crate::sm3_lookup_block::Word; 8]; 2]>,
    Vec<[crate::sm3_lookup_block::Word; 8]>,
    Vec<[u32; 8]>,
) {
    let (blocks, _root) = smt_blocks(key_be, siblings);
    let mut bb = BlockBuilder::new();
    let iv = crate::sm3_native_ref::IV;
    let mut last_dg = [0u32; 8];
    let mut last_cells: Option<[crate::sm3_lookup_block::Word; 8]> = None;
    let mut msg_words: Vec<[[crate::sm3_lookup_block::Word; 8]; 2]> = Vec::new();
    let mut out_cells: Vec<[crate::sm3_lookup_block::Word; 8]> = Vec::new();
    let mut digest_words: Vec<[u32; 8]> = Vec::new();
    for b in &blocks {
        // 🔴 先切组再落词（dump 定谳：词与压缩体必须同组，否则 weave 组切片
        // vcol 全体错位——对齐 compress_entry_binds 时序）
        bb.begin_block();
        let mut pair: [[crate::sm3_lookup_block::Word; 8]; 2] = std::array::from_fn(|_half| {
            std::array::from_fn(|_j| std::array::from_fn(|_k| crate::sm3_lookup_block::Cell {
                col: 0,
                row: 0,
            }))
        });
        for half in 0..2usize {
            for j in 0..8usize {
                let v = u32::from_be_bytes([
                    b[(half * 8 + j) * 4],
                    b[(half * 8 + j) * 4 + 1],
                    b[(half * 8 + j) * 4 + 2],
                    b[(half * 8 + j) * 4 + 3],
                ]);
                pair[half][j] = bb.input_word(v);
            }
        }
        msg_words.push(pair);
        // B3b-d7：标准 SM3 语义（与 smt.py 同构）——64B 输入 ⟹ 数据块+padding
        // 块两段压缩（hash(64B)=compress(compress(IV,blk),PAD)）。数据块
        // fresh IV；padding 块链式（prev=数据块摘要 cells，复制环强制）。
        let (cells1, _dg1) = bb.compress_entry_with_words(None, &iv, &pair);
        bb.begin_block();
        let mut pad: [[crate::sm3_lookup_block::Word; 8]; 2] = std::array::from_fn(|_half| {
            std::array::from_fn(|_j| std::array::from_fn(|_k| crate::sm3_lookup_block::Cell {
                col: 0,
                row: 0,
            }))
        });
        // SM3 padding 对 64B 定长消息：0x80 ‖ 55×0 ‖ BE64(512)——
        // 词 0=0x8000_0000、词 1..14=0、词 15=0x200（全常数，零 mux 面）
        for half in 0..2usize {
            for j in 0..8usize {
                let wi = half * 8 + j;
                let v = match wi {
                    0 => 0x8000_0000u32,
                    15 => 0x0000_0200u32,
                    _ => 0u32,
                };
                pad[half][j] = bb.input_word(v);
            }
        }
        let (cells, dg) = bb.compress_entry_with_words(Some(&cells1), &iv, &pad);
        last_dg = dg;
        last_cells = Some(cells.clone());
        out_cells.push(cells);
        digest_words.push(dg);
    }
    let circ = bb.finalize(last_dg, last_cells.expect("链非空"));
    (circ, last_dg, msg_words, out_cells, digest_words)
}

/// 键前 32bit 路径位（**LSB-at-leaf**——与 host `app/ra/smt.py` 权威位序
/// 一致：verify_non_membership 叶层消费 (leaf_pos>>0)&1，根层 bit31。
/// R3-0.1 位序统一（2026-09-24）：旧实现叶层吃 MSB 与 host 镜像，非默认树
/// 链根必分叉（红线测试 smt_host_circuit_root_parity_nondefault_tree 实证
/// 27d8508f… ≠ e75d815d…）。
pub fn key_bits_of(key_be: &[u8; 32]) -> [u8; SMT_DEPTH] {
    let v = u32::from_be_bytes(key_be[..4].try_into().expect("界内"));
    std::array::from_fn(|i| ((v >> i) & 1) as u8)
}

/// SmtWiring：装配层喂给织入的定位/语义参数。
pub struct SmtWiring {
    /// 路径位桥接目标：pkx 词格 0（全局列, 行）（E8 row_pk 行——键=pk′.x 词 0）。
    pub pkx_word_cell: (usize, usize),
    /// 末块摘要折叠影子行（row_mapping()[23]——ordinal 0-based）。
    pub row_rev: usize,
    /// 宿主根折叠值（实例 23 值）。
    pub root_fold: FpSM2,
    /// 键前 32bit（MSB 优先——路径位见证值）。
    pub key_bits: [u8; SMT_DEPTH],
    /// 各块兄弟词（32B BE——mux 的 sib 侧见证值）。
    pub sib_words: Vec<[u8; 32]>,
    /// 各块出口摘要词（8×u32——mux 的 cur 侧影子播种值）。
    pub digest_words: Vec<[u32; 8]>,
}

/// SmtPlan：织入三段共用的列/选择器账本（PLAN 相产物）。
///
/// lane 化布局（dump 定谳后的结构修正）：proto input_word 每 limb 一行 ⟹
/// mux 求值行=块内 128 行分散——**per-limb 约束在共享选择器的其他激活行必
/// 违约**。正解=三操作数 lane 化（每块 cur/sib/bit 各 1 列，行=limb 语义，
/// 值按行播种），约束收敛为 2 条/块（l/r 半各一）；块 0 的 cur=EMPTY 用
/// 预处理列钉死（advice 播种可伪造=「成员叶起链」洗白通道——cur_0 必须
/// 电路强制）。
pub struct SmtPlan {
    /// 32 路径位格（全局列，@row_pk 行——recomb 求值点）。
    pub bit_cols: [usize; SMT_DEPTH],
    /// 各块 cur lane（1 列/块；[0] 占位不用——块 0 走 EMPTY 预处理列）。
    pub cur_lanes: Vec<usize>,
    /// 各块 sib lane（1 列/块——自由见证，根钉锁死）。
    pub sib_lanes: Vec<usize>,
    /// 各块 bit lane（1 列/块——128 行同值播种+全行环桥 bit_cols）。
    pub bit_lanes: Vec<usize>,
    /// EMPTY 常量 limb 序预处理列（行 r_c = EMPTY 词 j limb k——块 0 的 cur）。
    pub empty_prep: usize,
    /// 各块消息 limb 的 vendor 局部列（[g]——proto W_INPUT 通道列经 vcol
    /// 映射；词 j limb k 同列不同行，emit 的 mux 读 msg_q 用，proto 相对号
    /// ≠vendor 局部号）。
    pub msg_in_cols: Vec<usize>,
    /// 折叠影子列 8 词×8 limb（@row_rev）。
    pub shadow_cols: [[usize; 8]; 8],
    pub bit_bool_sel: usize,
    pub bit_recomb_sel: usize,
    /// mux 左/右半选择器 per-block（左半 64 行/右半 64 行）。
    pub mux_l_sels: Vec<usize>,
    pub mux_r_sels: Vec<usize>,
    pub fold_sel: usize,
}

/// PLAN 相：全部列/选择器分配（先于全语句首条 push——冻结守卫）。
/// `msg_words` = SMT 链各块消息 limb 格（EMPTY 预处理列的行值映射源）。
pub fn weave_smt_alloc_cols(
    bld: &mut Builder<FpSM2>,
    plan: &LutPlan,
    offset: usize,
    msg_words: &[[[crate::sm3_lookup_block::Word; 8]; 2]],
) -> SmtPlan {
    let bit_cols: [usize; SMT_DEPTH] = std::array::from_fn(|_| bld.alloc_col());
    let cur_lanes: Vec<usize> = (0..SMT_DEPTH)
        .map(|g| if g == 0 { 0 } else { bld.alloc_col() })
        .collect();
    let sib_lanes: Vec<usize> = (0..SMT_DEPTH).map(|_| bld.alloc_col()).collect();
    let bit_lanes: Vec<usize> = (0..SMT_DEPTH).map(|_| bld.alloc_col()).collect();
    // EMPTY 预处理列：行 r_c = EMPTY 词 j limb k（c=half*64+j*8+k——半无关，
    // cur 侧左右半同一 EMPTY 32B）；未消费行填 0
    let empty = empty_leaf();
    let mut empty_vals = vec![FpSM2::from(0u64); crate::sm3_compress::ROWS];
    for g in 0..SMT_DEPTH {
        for half in 0..2usize {
            for j in 0..8usize {
                for k in 0..8usize {
                    let r = msg_words[g][half][j][k].row;
                    let wv = u32::from_be_bytes(
                        empty[j * 4..j * 4 + 4].try_into().expect("界内"),
                    );
                    empty_vals[r] = FpSM2::from(u64::from((wv >> (4 * k)) & 15));
                }
            }
        }
    }
    let empty_prep = bld.alloc_const_poly(empty_vals);
    let shadow_cols: [[usize; 8]; 8] =
        std::array::from_fn(|_| std::array::from_fn(|_| bld.alloc_col()));
    let bit_bool_sel = bld.alloc_selector(&[]);
    let bit_recomb_sel = bld.alloc_selector(&[]);
    let mux_l_sels: Vec<usize> = (0..SMT_DEPTH).map(|_| bld.alloc_selector(&[])).collect();
    let mux_r_sels: Vec<usize> = (0..SMT_DEPTH).map(|_| bld.alloc_selector(&[])).collect();
    let fold_sel = bld.alloc_selector(&[]);
    let msg_in_cols: Vec<usize> = (0..SMT_DEPTH)
        .map(|g| plan.advice[offset + 2 * g][W_INPUT])
        .collect();
    SmtPlan {
        bit_cols,
        cur_lanes,
        sib_lanes,
        bit_lanes,
        empty_prep,
        msg_in_cols,
        shadow_cols,
        bit_bool_sel,
        bit_recomb_sel,
        mux_l_sels,
        mux_r_sels,
        fold_sel,
    }
}

/// WIRES 相（环登记+播种——先于首条 push：环首键 E-H① 红线）。
#[allow(clippy::too_many_arguments)]
pub fn weave_smt_wires(
    bld: &mut Builder<FpSM2>,
    circ: &crate::sm3_lookup_block::BlockCircuit,
    plan: &LutPlan,
    offset: usize,
    w: &SmtWiring,
    sp: &SmtPlan,
    msg_words: &[[[crate::sm3_lookup_block::Word; 8]; 2]],
    out_cells: &[[crate::sm3_lookup_block::Word; 8]],
) {
    let groups = circ.wit_u64.len() / NUM_W;
    // SMT 组零 msg-limb 需求（lane 化）——sub 的 msg 面为空切片
    let sub = LutPlan {
        prep_globals: plan.prep_globals.clone(),
        pconst_global: plan.pconst_global,
        advice: plan.advice[offset..offset + groups].to_vec(),
        msg_limb_cols: Vec::new(),
        msg_sels: Vec::new(),
        dgw_shadow_cols: plan.dgw_shadow_cols,
        dgw_sels: plan.dgw_sels,
    };
    weave_core(bld, circ, &sub);

    let vcol = |proto_col: usize| -> usize {
        let rel = proto_col - NUM_P;
        sub.advice[rel / NUM_W][rel % NUM_W]
    };
    let empty = empty_leaf();

    // 出口折叠影子：末块摘要 limb↔影子列环（@row_rev）
    for (k, word) in circ.digest_cells.iter().enumerate() {
        for (j, limb) in word.iter().enumerate() {
            let col = sp.shadow_cols[k][j];
            let val = circ.wit_u64[limb.col - NUM_P][limb.row];
            bld.set_cell_f(col, w.row_rev, FpSM2::from(val));
            let id = match bld.ring_of(vcol(limb.col), limb.row) {
                Some(id) => id,
                None => bld.begin_relay_col(vcol(limb.col), limb.row),
            };
            bld.relay_to_col(id, col, w.row_rev);
        }
    }

    // mux lane 播种+环登记（全部在 PLAN 相——冻结守卫 backtrace 定谳）。
    // lane 布局：每块 cur/sib/bit 各 1 列，行=limb 语义（c=half*64+j*8+k 的
    // msg 行 r_c），值按行播种——约束（emit 段 2 条/块）在本行读三 lane。
    // 组序（B3b-d7 双块）：数据块 g 的组=sub 相对 2g；mux 面只覆盖数据块。
    let n_data = circ.wit_u64.len() / NUM_W / 2;
    for g in 0..n_data {
        // bit lane：128 行同值播种 + 全行环桥 + bit_cols[g]@row_pk（跨行等值
        // 强制——bit 可逐行伪造=洗白通道；环=全局置换无旋转的标准解）
        let bit_val = FpSM2::from(u64::from(w.key_bits[g]));
        let mut bit_ring: Option<usize> = None;
        // bit 位格播种（环等值面+recomb/bool 求值面双消费——dump 定谳：
        // 缺播种时 bit_cols@row_pk 恒 0 与影子值不等=环审计违约）
        bld.set_cell_f(sp.bit_cols[g], w.pkx_word_cell.1, bit_val);
        for half in 0..2usize {
            for j in 0..8usize {
                for k in 0..8usize {
                    let msg_row = msg_words[g][half][j][k].row;
                    // sib lane 本行播种（值=兄弟词 limb——自由见证，根钉锁死）
                    let sib_be = &w.sib_words[g];
                    let cv =
                        u32::from_be_bytes(sib_be[j * 4..j * 4 + 4].try_into().expect("界内"));
                    bld.set_cell_f(
                        sp.sib_lanes[g],
                        msg_row,
                        FpSM2::from(u64::from((cv >> (4 * k)) & 15)),
                    );
                    // bit lane 本行播种+环桥
                    bld.set_cell_f(sp.bit_lanes[g], msg_row, bit_val);
                    match bit_ring {
                        None => {
                            let id = bld.begin_relay_col(sp.bit_lanes[g], msg_row);
                            bld.relay_to_col(id, sp.bit_cols[g], w.pkx_word_cell.1);
                            bit_ring = Some(id);
                        }
                        Some(id) => bld.relay_to_col(id, sp.bit_lanes[g], msg_row),
                    }
                    // cur lane（g≥1）：本行播种上块摘要 limb 值+环桥出口 limb
                    // （链 soundness=cur 非自由值；g=0 走 EMPTY 预处理列）
                    if g > 0 {
                        let out_limb = out_cells[g - 1][j][k];
                        let dval = w.digest_words[g - 1][j];
                        bld.set_cell_f(
                            sp.cur_lanes[g],
                            msg_row,
                            FpSM2::from(u64::from((dval >> (4 * k)) & 15)),
                        );
                        let id = match bld.ring_of(vcol(out_limb.col), out_limb.row) {
                            Some(id) => id,
                            None => bld.begin_relay_col(vcol(out_limb.col), out_limb.row),
                        };
                        bld.relay_to_col(id, sp.cur_lanes[g], msg_row);
                    }
                    // mux 选择器激活：左半/右半行（l/r 各 64 行/块）
                    if half == 0 {
                        bld.extend_selector(sp.mux_l_sels[g], &[msg_row]);
                    } else {
                        bld.extend_selector(sp.mux_r_sels[g], &[msg_row]);
                    }
                }
            }
        }
    }
}

/// EMIT 相：bit bool+recomb（@row_pk）+逐 limb mux（影子引用）+根折叠+实例 23。
#[allow(clippy::too_many_arguments)]
pub fn weave_smt_emit(
    bld: &mut Builder<FpSM2>,
    msg_words: &[[[crate::sm3_lookup_block::Word; 8]; 2]],
    w: &SmtWiring,
    sp: &SmtPlan,
) {
    // ① 路径位：32 bit 格 bool + recomb==pkx 词 0 值（两 sel 激活 @row_pk——
    // 选择器无激活点=约束真空=洗白封堵失效，dump 定谳前的负例假绿源）
    let (pkx_col, _pkx_row) = w.pkx_word_cell;
    bld.extend_selector(sp.bit_bool_sel, &[w.pkx_word_cell.1]);
    bld.extend_selector(sp.bit_recomb_sel, &[w.pkx_word_cell.1]);
    for &col in sp.bit_cols.iter() {
        bld.emit_bool(sp.bit_bool_sel, col);
    }
    let mut acc2 = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
    for (g, &col) in sp.bit_cols.iter().enumerate() {
        // bit_g=键位 LSB-at-leaf（与 smt_blocks/key_bits_of/host smt.py 同源）
        // ⟹ 系数 2^g（Σ2^g·bit_g==pkx 词 0 原像，R3-0.1 位序统一）
        acc2 = acc2
            + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << g))
                * bld.q(col, Rotation::cur());
    }
    acc2 = acc2 - bld.q(pkx_col, Rotation::cur());
    bld.push("smt.bit.recomb", bld.sel(sp.bit_recomb_sel) * acc2);

    // ② lane 化 mux（每块 2 条，度 2；三操作数=wires 段按行播种的 lane 列）：
    //   L（左半 64 行）：(msg − cur) − bit·(sib − cur) = 0
    //   R（右半 64 行）：(msg − sib) + bit·(sib − cur) = 0
    //   g=0 的 cur=EMPTY 预处理列（电路强制非成员起点——成员叶起链=洗白）
    for g in 0..msg_words.len() {
        let msg_q = bld.q(sp.msg_in_cols[g], Rotation::cur());
        let bit_q = bld.q(sp.bit_lanes[g], Rotation::cur());
        let sib_q = bld.q(sp.sib_lanes[g], Rotation::cur());
        let cur_expr = if g == 0 {
            bld.prep_cur(sp.empty_prep)
        } else {
            bld.q(sp.cur_lanes[g], Rotation::cur())
        };
        bld.push(
            "smt.mux.l",
            bld.sel(sp.mux_l_sels[g])
                * ((msg_q.clone() - cur_expr.clone())
                    - bit_q.clone() * (sib_q.clone() - cur_expr.clone())),
        );
        bld.push(
            "smt.mux.r",
            bld.sel(sp.mux_r_sels[g])
                * ((msg_q - sib_q.clone()) + bit_q * (sib_q - cur_expr)),
        );
    }

    // ③ 根折叠：Σ2^{32k}·(Σ2^{4j}·shadow) == root_fold + 实例 23
    // （🔴 系数一律 f_pow2 权威派生——1u64<<(32k) 对 k≥2 溢出 u64，release
    // 下 x86 SHL 掩码使 1u64<<64=1，词 2..7 系数全体 wrap=域内错值——B3
    // 收官 §1.2"折叠系数禁手抄"教训的直接重演，dump+Python 对拍定谳）
    let sel = sp.fold_sel;
    bld.extend_selector(sel, &[w.row_rev]);
    let mut total = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
    for (k, word) in sp.shadow_cols.iter().enumerate() {
        let mut wsum = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
        for (j, &col) in word.iter().enumerate() {
            wsum = wsum
                + Expression::<FpSM2>::Constant(crate::sm2_params::f_pow2(4 * j))
                    * bld.q(col, Rotation::cur());
        }
        total = total
            + Expression::<FpSM2>::Constant(crate::sm2_params::f_pow2(32 * k)) * wsum;
    }
    total = total - bld.q_inst(Rotation::cur());
    bld.push("smt.root.fold", bld.sel(sel) * total);
    bld.set_instance(23, w.root_fold);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R3-0.1 红线测试（2026-09-24）：host（app/ra/smt.py 权威）↔ 电路链位序
    /// 对拍——**非默认树**（单成员、u32 bit0 叶层分叉——位序最敏感形态）。
    ///
    /// 期望根 = Python `smt_root([k_other])` 实测钉死（e75d815d…23f2fa，
    /// non_membership_witness 验证 True）；钉死空树根 4035cafe…（对称链
    /// 位序不可见——历史 Py↔电路对拍恰被此掩盖）。
    ///
    /// 判据：smt_blocks（电路链）根 == host 根。修复前电路叶层吃 MSB ⟹
    /// 本测试红（两根分叉=错位实证）；修复后（叶层吃 LSB，与 host
    /// verify_non_membership 的 (leaf_pos>>shift)&1 消费序一致）转绿。
    #[test]
    fn smt_host_circuit_root_parity_nondefault_tree() {
        // 与 Python 锚脚本逐字节一致（key0 与 k_other 仅 u32 bit0 分叉）
        let key0: [u8; 32] = [
            0x62, 0x1d, 0x14, 0x0f, 0x06, 0x01, 0x38, 0x33, 0x2a, 0x25, 0xdc, 0xd7, 0xce, 0xc9,
            0xc0, 0xfb, 0xf2, 0xed, 0xe4, 0x9f, 0x96, 0x91, 0x88, 0x83, 0xba, 0xb5, 0xac, 0xa7,
            0x5e, 0x59, 0x50, 0x4b,
        ];
        let mut k_other = key0;
        k_other[3] ^= 0x01;
        let host_root: [u8; 32] = [
            0xe7, 0x5d, 0x81, 0x5d, 0xa1, 0x5e, 0xc7, 0xce, 0x03, 0x7a, 0x33, 0xbc, 0xf2, 0xbb,
            0x33, 0x92, 0x30, 0xaa, 0x56, 0xb5, 0xf7, 0xa3, 0x90, 0x59, 0xa5, 0x97, 0x25, 0xc1,
            0xae, 0x23, 0xf2, 0xfa,
        ];

        // 单成员树非成员见证（host 语义）：siblings[0]=成员叶哈希，其余=DEFAULT[31..1]
        let mut defaults = vec![[0u8; 32]; SMT_DEPTH + 1];
        defaults[SMT_DEPTH] = empty_leaf();
        for d in (0..SMT_DEPTH).rev() {
            let mut two = Vec::with_capacity(64);
            two.extend_from_slice(&defaults[d + 1]);
            two.extend_from_slice(&defaults[d + 1]);
            defaults[d] = crate::sm3_native_ref::hash(&two);
        }
        let mut siblings = [[0u8; 32]; SMT_DEPTH];
        siblings[0] = crate::sm3_native_ref::hash(&[b"FZ-SMT-LEAF|".as_slice(), k_other.as_slice()].concat());
        for g in 1..SMT_DEPTH {
            siblings[g] = defaults[SMT_DEPTH - g];
        }

        // ① 空树根不变（对称链位序不可见——钉死防止顺手破坏历史锚）
        let (_b, empty_root) = smt_blocks(&key0, &{
            let mut s = [[0u8; 32]; SMT_DEPTH];
            for g in 0..SMT_DEPTH {
                s[g] = defaults[SMT_DEPTH - g];
            }
            s
        });
        assert_eq!(
            empty_root,
            defaults[0],
            "空树根漂移（DEFAULT[0]=4035cafe… 锚破坏）"
        );

        // ② 非默认树对拍（判决位）：电路链根必须==host 权威根
        let (_, circuit_root) = smt_blocks(&key0, &siblings);
        assert_eq!(
            hex(&circuit_root),
            hex(&host_root),
            "host↔电路位序错位：电路链根 {} ≠ host 根 {}（单成员树叶层分叉实证）",
            hex(&circuit_root),
            hex(&host_root)
        );
    }

    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
