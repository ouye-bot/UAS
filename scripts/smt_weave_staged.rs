//! 飞证 B3b：SM3-SMT 撤销累加器织入（深度 32，键=子凭证出示公钥 x 坐标 pk′.x）。
//!
//! 语义（与 uas/backend/app/ra/smt.py 同构单一事实源）：
//! - 叶哈希 = SM3( b"FZ-SMT-LEAF|" ‖ pk′.x )（44B 单块）
//! - 内节点 = SM3( 左32B ‖ 右32B )（64B 整块，fresh IV——链在消息不在状态）
//! - 非成员证明 = 32 个兄弟子树根（叶→根序）+根；电路重算：内节点 g 消息
//!   左半 = 上层摘要（compress_entry_binds 同粒度 4bit limb wire——零重组），
//!   右半 = 兄弟（自由见证），末块摘要词序折叠 == rev_root 实例 24 钉。
//! - 洗白封堵：叶消息 pk′.x 段经 msg-limb 桥接绑定 pkx 词格（E8 换根绑定
//!   [sk′]G=pk′）——键被电路内强制为证明者自己的出示公钥；换键=换 sk′=M_A
//!   验签拒绝。根钉锁死其余自由度（SM3 抗碰撞）。
//!
//! 相位纪律（冻结守卫 assert_open）：alloc_cols + wires（环登记）在 PLAN 相
//! （首条 push 前），emit（recomb/fold push+实例钉）在 EMIT 相。

use plonkish_backend::util::expression::{Expression, Rotation};

use crate::sm3_compress::Builder;
use crate::sm3_lookup_block::{BlockBuilder, NUM_P, NUM_W};
use crate::sm3_lookup_weave::{weave_core, LutPlan};
use crate::sm3_native_ref;
use crate::FpSM2;

pub const SMT_DEPTH: usize = 32;
pub const SMT_GROUPS: usize = SMT_DEPTH + 1; // 叶+32 内节点
pub const LEAF_LABEL: &[u8] = b"FZ-SMT-LEAF|";

/// 叶哈希 host（键=pk′.x）。
pub fn smt_leaf(pk_x_be: &[u8; 32]) -> [u8; 32] {
    let mut m = Vec::with_capacity(44);
    m.extend_from_slice(LEAF_LABEL);
    m.extend_from_slice(pk_x_be);
    sm3_native_ref::hash(&m)
}

/// 空树非成员见证（兄弟=叶→根序 DEFAULT 链；根=DEFAULT[0]）。
/// DEFAULT[d]=SM3(DEFAULT[d+1]‖DEFAULT[d+1])，DEFAULT[32]=SM3(b"FZ-SMT-EMPTY")。
pub fn smt_default_witness() -> ([[u8; 32]; SMT_DEPTH], [u8; 32]) {
    let mut defaults = vec![sm3_native_ref::hash(b"FZ-SMT-EMPTY"); SMT_DEPTH + 1];
    for d in (0..SMT_DEPTH).rev() {
        let mut two = Vec::with_capacity(64);
        two.extend_from_slice(&defaults[d + 1]);
        two.extend_from_slice(&defaults[d + 1]);
        defaults[d] = sm3_native_ref::hash(&two);
    }
    let siblings: [[u8; 32]; SMT_DEPTH] = std::array::from_fn(|i| defaults[SMT_DEPTH - i]);
    (siblings, defaults[0])
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

/// SMT 链块消息组装：0=叶块（44B+pad）、g=内节点（摘要_{g-1}‖sib_{g-1} 64B）。
pub fn smt_blocks(pk_x_be: &[u8; 32], siblings: &[[u8; 32]; SMT_DEPTH]) -> Vec<[u8; 64]> {
    let mut blocks = Vec::with_capacity(SMT_GROUPS);
    let mut leaf = [0u8; 64];
    leaf[..12].copy_from_slice(LEAF_LABEL);
    leaf[12..44].copy_from_slice(pk_x_be);
    leaf[44] = 0x80;
    leaf[56..].copy_from_slice(&352u64.to_be_bytes()); // 44B=352bit
    blocks.push(leaf);
    let mut prev = sm3_native_ref::hash(&leaf[..44]);
    for sib in siblings {
        let mut blk = [0u8; 64];
        blk[..32].copy_from_slice(&prev);
        blk[32..].copy_from_slice(sib);
        prev = sm3_native_ref::hash(&blk);
        blocks.push(blk);
    }
    blocks
}

/// SMT 链 proto 计算（fresh IV；内节点左半 bind 上层摘要——环强制）。
pub fn smt_chain_circuit(
    pk_x_be: &[u8; 32],
    siblings: &[[u8; 32]; SMT_DEPTH],
) -> (crate::sm3_lookup_block::BlockCircuit, [u32; 8]) {
    let blocks = smt_blocks(pk_x_be, siblings);
    let mut bb = BlockBuilder::new();
    let iv = crate::sm3_native_ref::IV;
    let mut prev_words: Option<[crate::sm3_lookup_block::Word; 8]> = None;
    let mut last_dg = [0u32; 8];
    let mut last_cells: Option<[crate::sm3_lookup_block::Word; 8]> = None;
    for (g, b) in blocks.iter().enumerate() {
        let (cells, dg) = if g == 0 {
            bb.compress_entry(None, &iv, b)
        } else {
            let pw = prev_words.as_ref().expect("g>0 必有上层摘要词");
            let binds: Vec<(usize, &crate::sm3_lookup_block::Word)> =
                (0..8).map(|j| (j, &pw[j])).collect();
            bb.compress_entry_binds(None, &iv, b, &binds)
        };
        last_dg = dg;
        last_cells = Some(cells.clone());
        prev_words = Some(cells);
    }
    let circ = bb.finalize(last_dg, last_cells.expect("至少叶块"));
    (circ, last_dg)
}

/// SmtWiring：装配层喂给织入的定位/语义参数。
pub struct SmtWiring {
    /// 叶消息词 3..10 的桥接目标：pkx 词格 (全局列, 行)（E8 row_pk 行）。
    pub pkx_word_cells: [(usize, usize); 8],
    /// 末块摘要折叠影子行（row_mapping()[24]）。
    pub row_rev: usize,
    /// 宿主根折叠值（实例 24 值）。
    pub root_fold: FpSM2,
}

/// SmtPlan：织入三段共用的列/选择器账本（PLAN 相产物）。
pub struct SmtPlan {
    /// 叶块 8 词×8 limb 的全局列号（桥接 wire 与 recomb 共用单一事实源）。
    pub leaf_limb_cols: [usize; 64],
    pub shadow_cols: [[usize; 8]; 8],
    pub leaf_recomb_sels: [usize; 8],
    pub fold_sel: usize,
}

/// PLAN 相：全部列/选择器分配（先于全语句首条 push——冻结守卫）。
pub fn weave_smt_alloc_cols(bld: &mut Builder<FpSM2>, plan: &LutPlan, offset: usize) -> SmtPlan {
    let leaf_limb_cols: [usize; 64] = std::array::from_fn(|i| plan.msg_limb_cols[offset][i]);
    let shadow_cols: [[usize; 8]; 8] =
        std::array::from_fn(|_| std::array::from_fn(|_| bld.alloc_col()));
    let leaf_recomb_sels: [usize; 8] = std::array::from_fn(|_| bld.alloc_selector(&[]));
    let fold_sel = bld.alloc_selector(&[]);
    SmtPlan { leaf_limb_cols, shadow_cols, leaf_recomb_sels, fold_sel }
}

/// WIRES 相（环登记+播种——仍先于首条 push：环首键 E-H① 红线）。
pub fn weave_smt_wires(
    bld: &mut Builder<FpSM2>,
    circ: &crate::sm3_lookup_block::BlockCircuit,
    plan: &LutPlan,
    offset: usize,
    w: &SmtWiring,
    sp: &SmtPlan,
) {
    let groups = circ.wit_u64.len() / NUM_W;
    let sub = LutPlan {
        prep_globals: plan.prep_globals.clone(),
        pconst_global: plan.pconst_global,
        advice: plan.advice[offset..offset + groups].to_vec(),
        msg_limb_cols: plan.msg_limb_cols[offset..offset + groups].to_vec(),
        msg_sels: plan.msg_sels[offset..offset + groups].to_vec(),
        dgw_shadow_cols: plan.dgw_shadow_cols,
        dgw_sels: plan.dgw_sels,
    };
    weave_core(bld, circ, &sub);

    let vcol = |proto_col: usize| -> usize {
        let rel = proto_col - NUM_P;
        sub.advice[rel / NUM_W][rel % NUM_W]
    };

    // 叶消息 pk′.x 段 limb↔W_INPUT 环（教训㊶组基=vcol 含 SMT 组偏移）
    let leaf_words = &circ.inputs_per_block[0];
    for (wi, word) in leaf_words.iter().enumerate().skip(3).take(8) {
        let (_pkx_col, pkx_row) = w.pkx_word_cells[wi - 3];
        for k in 0..8 {
            let limb_local = sp.leaf_limb_cols[(wi - 3) * 8 + k];
            let w_in = word[k];
            let w_in_local = vcol(w_in.col);
            let val = circ.wit_u64[w_in.col - NUM_P][w_in.row];
            bld.set_cell_f(limb_local, pkx_row, FpSM2::from(val));
            let id = bld
                .ring_of(w_in_local, w_in.row)
                .expect("W_INPUT 格必属生产环");
            bld.relay_to_col(id, limb_local, pkx_row);
        }
    }

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
}

/// EMIT 相：叶 recomb×8 + 根折叠 + 实例 24（零分配纪律）。
pub fn weave_smt_emit(bld: &mut Builder<FpSM2>, w: &SmtWiring, sp: &SmtPlan) {
    for wi in 0..8usize {
        let (pkx_col, pkx_row) = w.pkx_word_cells[wi];
        let sel = sp.leaf_recomb_sels[wi];
        bld.extend_selector(sel, &[pkx_row]);
        let mut rec = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
        for k in 0..8 {
            let limb_local = sp.leaf_limb_cols[wi * 8 + k];
            rec = rec
                + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << (4 * k)))
                    * bld.q(limb_local, Rotation::cur());
        }
        rec = rec - bld.q(pkx_col, Rotation::cur());
        bld.push("smt.leaf.recomb", bld.sel(sel) * rec);
    }

    let sel = sp.fold_sel;
    bld.extend_selector(sel, &[w.row_rev]);
    let mut acc = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
    for (k, word) in sp.shadow_cols.iter().enumerate() {
        let mut wsum = Expression::<FpSM2>::Constant(FpSM2::from(0u64));
        for (j, &col) in word.iter().enumerate() {
            wsum = wsum
                + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << (4 * j)))
                    * bld.q(col, Rotation::cur());
        }
        acc = acc + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << (32 * k))) * wsum;
    }
    acc = acc - bld.q_inst(Rotation::cur());
    bld.push("smt.root.fold", bld.sel(sel) * acc);
    bld.set_instance(24, w.root_fold);
}
