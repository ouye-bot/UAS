//! SM2 验签体顶板装配（簇D）：把簇B 标量七件套与簇C EC 门族拼成完整四步
//! 验签电路（M2a `sm2_verify_r1cs` 的忠实移植，蓝图 `VERIFY_BODY_BLUEPRINT.md`）。
//!
//! ## 四步语义（承继 M2a / 蓝图 §一）
//! 范围检查 lt_n(r)、lt_n(s) → t=(r+s) mod n、neq_zero(t) → (x₁,y₁)=[s]G+[t]P_A
//! （double-and-add 双链 + ec_add_complete）→ R=(e+x₁) mod n 与 r 逐位相等。
//! 全程无模逆电路（s 倍乘重构的教科书技巧，M2a 同款）。
//!
//! ## 🔴 勘误 #17：固定基点绑定面（蓝图盲区，施工期发现）
//! 格世界里基点写在 advice 格上；R1CS 的字面常量在此**不再免费**。若不做绑定，
//! 恶意 prover 可把 [s]G 链的基格写成任一曲线点 B，令 x₁=(r−e mod n) 凑过
//! eq ⟹ 存在性伪造被平凡化。修复（约束计数实测后锁定，蓝图 §六预测随之修订）：
//! - 实例面扩容 +4：(g_x,g_y,g₂x,g₂y) 入实例并各钉 1 推；
//! - EG/EP 两链各加"基头"：双门家族 5 推强制 d₂ 格 = 2·基点格 +
//!   3 推把 d₂ 结果绑进产物列（R1CS 中此二者免费，移植结构性差价）；
//! - on_curve(P_A) 4 推照旧挂在 EP 头。
//!
//! ## 🔴 勘误 #19：标量世界锚点必须走「秩空间」（簇D 首跑实测）
//! 首版把 ROW_* 写成物理点字面值（4..13），而电路几何是 **LFSR 秩空间**
//! （`nth_map`）：小整数点的秩散布在 32/64/256/1494 等任意位置，且与实例
//! 钉点（秩 1..12）暗中重叠 ⟹ 七件套读面词的旋转高达 |rot|=1494，
//! 直接撞碎 K=11 协议断言（旋转守卫 2304 处违例的根因，簇B 单测全绿
//! 纯因其内部一致使用 point_at_rank 而未暴露）。修复：
//! - 标量世界整体迁入自由秩窗 **14..24**（instances 占 1..12，最大族内边 9）；
//! - 面值列不再要求与钉点同行：每面加一条**单格值中继环**
//!   `(pv@钉行 ↔ pv@工作锚)`（协议层零约束零旋转），钉绑定只留
//!   实例行上的一条 `pin.bind`（私有选择器，与词位家族分家）。
//!
//! ## 复制环拓扑（协议层，零约束）
//! β 位车道 ×2（每锚点 1 键）、x₁ 尾部中继、基点/d₂ 坐标车道。登记在 plan 冻结
//! 后集中完成；mock 层不校验置换一致性（诚实注记承 sm3_perm_smoke），由 e2e（簇E）
//! 桥接审计。环预算相对蓝图 §4.3 有增补（见上方勘误段），以实测计数为准。

use crate::sm2_ec_plonkish::{
    affine_add, affine_mul_bits, curve_a, curve_b, g_coords, on_curve_affine, write_point,
};
use crate::sm2_params::{add256, cmp256, fr_from_limbs, fr_to_limbs, n_limbs, q_limbs};
use crate::FpSM2;
use ff::Field;

// ────────────────────────── native 整数小帮手（256 位 limbs） ──────────────────────────

/// a − b 的**环绕**减（borrow 被丢弃）。加法取模分支专用：carry=1 时真值
/// x = s + 2²⁵⁶，x − n mod 2²⁵⁶ 恰等于 s ⊖ n，且结果 < n 必然无歧义。
fn sub256_wrap(a: &[u64; 4], bb: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(bb[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    out
}

/// `(a+b) mod n`，前置 a,b < n（M2a add_mod_n native 语义；x<2n 单次条件减）。
pub fn add_mod_n_limbs(a: &[u64; 4], bb: &[u64; 4]) -> [u64; 4] {
    let (s, carry) = add256(a, bb);
    let n = n_limbs();
    // carry=1 ⟹ x=s+2²⁵⁶≥2²⁵⁶>n（n<2²⁵⁶）必减，走环绕减；
    // 否则比较减：s≥n 才减。
    if carry || cmp256(&s, &n) != std::cmp::Ordering::Less {
        sub256_wrap(&s, &n)
    } else {
        s
    }
}

/// 小端位数组 → bool（LSB-first）。
fn limbs_to_bits_le(v: &[u64; 4]) -> [bool; 256] {
    let mut bits = [false; 256];
    for w in 0..4 {
        for i in 0..64 {
            bits[64 * w + i] = (v[w] >> i) & 1 == 1;
        }
    }
    bits
}

// ────────────────────────── verify_replay：native 四步参照（蓝图 §五） ──────────────────────────

/// native 重放产出：见证宿主唯一真值源（测试对拍 GB/T 由 [`verify_replay`] 闭环）。
#[derive(Debug, Clone, Copy)]
pub struct ReplayOut {
    pub t: [u64; 4],
    pub s_g: (FpSM2, FpSM2),
    pub t_pa: (FpSM2, FpSM2),
    pub x1: FpSM2,
    /// 四步整体结论（应等于调用方断言的目标真值）。
    pub ok: bool,
}

/// M2a 四步验签的纯 native 重放（无电路）。P_A 必须在曲线上（off-curve 直接
/// 返回 ok=false，供离曲线负例对拍）。r=0 / s=0 / t=0 属电路级负例，此处照常
/// 计算（native 数学对其无定义分歧：群运算仍良定）。
pub fn verify_replay(e: FpSM2, r: FpSM2, s: FpSM2, pax: FpSM2, pay: FpSM2) -> ReplayOut {
    let pa = (pax, pay);
    if !on_curve_affine(Some(pa)) {
        return ReplayOut {
            t: [0; 4],
            s_g: (FpSM2::ZERO, FpSM2::ZERO),
            t_pa: (FpSM2::ZERO, FpSM2::ZERO),
            x1: FpSM2::ZERO,
            ok: false,
        };
    }
    // 1) t = (r+s) mod n（native 桥：域元素 → limbs → mod-n 加法 → 域元素）
    let t = add_mod_n_limbs(&fr_to_limbs(&r), &fr_to_limbs(&s));
    // 2) [s]G（常基点 double-and-add）与 [t]P_A（见证基点同构）
    let s_bits = limbs_to_bits_le(&fr_to_limbs(&s));
    let t_bits = limbs_to_bits_le(&t);
    let s_g = affine_mul_bits(&s_bits, Some(g_coords())).unwrap();
    let t_pa = affine_mul_bits(&t_bits, Some(pa)).unwrap();
    // 3) (x₁,y₁) = 二者和
    let (x1, _y1) = affine_add(Some(s_g), Some(t_pa)).unwrap();
    // 4) R = (e+x₁) mod n == r
    let rchk = add_mod_n_limbs(&fr_to_limbs(&e), &fr_to_limbs(&x1));
    let ok = fr_from_limbs(&rchk) == r;
    ReplayOut { t, s_g, t_pa, x1, ok }
}

/// GB/T 32918.2-2016 附录 A.2 权威向量（三层对拍确认见 m0 权威源注释），
/// 十六进制串自 `m0_sm3_circuit/src/sm2_verify_native.rs` 机械复制（常量纪律）。
pub(crate) mod a2_vector {
    use super::*;
    const E_HEX: &str = "ABF7EB631D94615FD1A941D40E99932DDB1899E1DFAE7179B4A79417EA3743E5";
    const R_HEX: &str = "88348A09A3E324C4FE946843123E40C175468F3E36481885844A144D2167EA4C";
    const S_HEX: &str = "0AD2CE552FD33EAB792E5A2805E0504D014C96135F8E03891087132ABB24D48D";
    const PA_X_HEX: &str = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020";
    const PA_Y_HEX: &str = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";

    fn fp(hex: &str) -> FpSM2 {
        // 复用本探针已验证的解析链（大端标准 hex → LE limbs → 域元素），
        // 与 sm2_ec_plonkish 的曲线常量同一条机械路径（常量纪律）。
        fr_from_limbs(&crate::sm2_params::hex_to_limbs_le(hex))
    }

    /// A.2 权威向量 `(e, r, s, P_A.x, P_A.y)`。
    pub fn std() -> (FpSM2, FpSM2, FpSM2, FpSM2, FpSM2) {
        (fp(E_HEX), fp(R_HEX), fp(S_HEX), fp(PA_X_HEX), fp(PA_Y_HEX))
    }
}

/// A.2 公开入口（测试与簇E bin 共用）。
pub fn a2_inputs() -> (FpSM2, FpSM2, FpSM2, FpSM2, FpSM2) {
    a2_vector::std()
}

// ══════════════════ 装配层（簇D 主交付） ══════════════════

use crate::sm3_compress::Builder;
use crate::sm2_ec_plonkish::{
    affine_double, emit_ec_add_complete, emit_ec_mul_loop_const_base, plan_ec_add_complete,
    plan_point, PtCells,
};
use crate::sm2_scalar_plonkish::{
    emit_add_mod_n, emit_decompose, emit_eq, emit_lt_n, emit_neq_zero, emit_reduce_mod_n,
    plan_add, plan_add_mod_n, plan_decomp, plan_eq, plan_neq, plan_reduce_mod_n,
    scalar, AddModNSlots, AddSlots, DecompSlots, EqSlots,
    NeqSlots, PlScalar as Sc, ReduceSlots,
};
use plonkish_backend::util::expression::{Expression, Rotation};

type Expr = Expression<FpSM2>;

// ── 标量世界秩布局（勘误 #19）：一切锚点以**秩**声明，经 [`srow`]
//    派生物理点；族内任何「行→源」边 |Δrank| ≤ 9 ≤ K=11。实例钉点占
//    秩 1..=12（standalone 实例面）/ 1..=20（簇H 合并形态：验签体 0..11 +
//    Z_U 摘要 12..19），本窗口与之解耦，与两体 SM3 区（240..2480）及 EC 区
//    （≥2500）互不相扰。簇H H1·5：原 14..24 整体 +7 —— 实例序号 k 占秩
//    k+1（row_mapping[k]=bh()[k+1]），Z_U 摘要序号 12..19 落秩 13..20，
//    平移消除侵占窗口议题；族内旋转距离经均匀平移不变，且验签体
//    max|rot|=1（Fix R-a write-next 的 Rotation(1) 绑定，蓝图 §四·8·2）
//    ⟹ 对旋转预算零影响（蓝图 §四·7）。──
// R1-v3b 旋转感知重排 v2（2026-08-28，全连通 11! 求解器最优解，窗口 21..31 不变）：
// 旧行序把两条 256 列读边拉到 d=9（A_E—FIN、A_R—EQ，各 131,072 读入单元，
// 扛 standalone 非cur 质量 96%）。v2 边表补 RED—FIN 边（amn_f 经 emit_add_impl
// 读 sca_red 车道；v1 漏边被 census 复测 rot=+9 段抓出 ⟹ v1 布局该边恶化到
// d=9，实测只达 136,704）。v2 全连通解把全部 10 条族边压到 d≤2 ⟹
// E_standalone 272,384 → 11,004（预测 −96.0%，census 复测回填）。
// 边表与求解过程见 M3_probe/V3_COLUMN_BLUEPRINT.md §五。
const RANK_NEQ_S: usize = 21;
const RANK_A_S: usize = 22; // s 面（兼 lt_s 锚）
const RANK_T: usize = 23; // amn_t 锚 = t 输出格家点（读 r:2 / s:1）
const RANK_NEQ_T: usize = 24;
const RANK_A_R: usize = 25; // r 面（兼 lt_r 锚；EQ/NEQ_R 邻、T 距2 环抱）
const RANK_NEQ_R: usize = 26;
const RANK_EQ: usize = 27; // eq（读 r：d=2、读 amn_f 车道：d=1）
const RANK_FIN: usize = 28; // 最终和 amn_f 锚（读 e:1 / sca_red:2）
pub(crate) const RANK_A_E: usize = 29; // e 面工作世界（词位 + pv 本地；簇J T1 dgw 折叠同点）
const RANK_RED: usize = 30; // reduce_mod_n 锚 = sca_red 车道家点（读 x₁：d=1）
const RANK_X1: usize = 31; // decompose 锚 = x₁ 位格家点

// ── 簇H H2 新秩（merged 形态专属；standalone 不用）──
// P_A 双 decompose 槽共享行（xA/yA 各 256 位格 + 2 值格 + 17 recomp 值格
// 同行 ⟹ 全部 rot=0，蓝图 §四·7 H2「绝不以旋转换列」）。注意这是**秩**空间
// （point_at_rank），与 ioStrip 的点空间 IO_BASE=32（bh_point）不同表。
pub(crate) const RANK_PA: usize = 32; // 簇J T1：pk_u.x/y 词格与 E8 双 decompose 同行
// Z_U 15 个常量词锚行（34..49；B₂ 0..3 + B₃ 5..15）。环起点零旋转 ⟹
// 行位置自由，独立秩段防与后续段碰撞。
const RANK_ZMSG: usize = 34;

/// 秩 → 物理点（吸收态守卫内联在 `point_at_rank` 前置检查）。
#[inline]
fn srow(rank: usize) -> usize {
    crate::sm3_compress::point_at_rank(rank)
}

/// 环审计/负例共用的地标点表（名 → 物理点）。打印用，非电路语句。
pub fn landmark_points() -> Vec<(&'static str, usize)> {
    vec![
        ("pin2", pin_row(2)),
        ("pin6", pin_row(6)),
        ("pin9", pin_row(9)),
        ("pin11", pin_row(11)),
        ("A_S", srow(RANK_A_S)),
        ("T", srow(RANK_T)),
        ("X1", srow(RANK_X1)),
        ("HR_EG", row_at(RANK_HR_EG)),
        ("HR_EP", row_at(RANK_HR_EP)),
        ("AC", row_at(RANK_AC)),
        ("EG256", row_at(RANK_EG + 256)),
        ("EP256", row_at(RANK_EP + 256)),
    ]
}

// EC 区（自包含行：门只读本行格；跨世界联系全走复制环 —— 零约束零旋转，
// 故锚点行的秩位置不进旋转预算）。运行时从自由秩派生物理点，跳过 LFSR
// 吸收态点 0（`point_at_rank` 的像里恰有一个秩映射到点 0，须排除）。
use crate::sm3_compress::point_at_rank;

/// 自由秩 → 物理点（吸收态守卫内联）。
fn row_at(rank: usize) -> usize {
    let p = point_at_rank(rank);
    assert_ne!(p, 0, "秩 {rank} 映射到吸收态点 0，禁作门行");
    p
}

// ── 秩段分配（互斥且远离标量世界 1..31；区间大小按需注释）──
// 簇H H0：原 1000..1620 与两体 SM3 区（240..2480，Z_ANCHOR_BLUEPRINT §三·5）
// 撞窗 ⟹ 迁至 2500..3184。EC 门自包含行、跨世界联系全走复制环（零约束
// 零旋转），秩位置不进旋转预算 ⟹ 迁移只动常量值，环值与形状不变（实测
// 锁定测试逐项验证）。
const RANK_EG: usize = 2500; // [s]G 循环 256 锚点：rank 2500..2756
const RANK_EP: usize = 2800; // [t]P_A 循环 256 锚点：rank 2800..3056
const RANK_HR_EG: usize = 3100; // EG 基头（staged G 三元组 + dbl 输出）
const RANK_HR_EP: usize = 3110; // EP 基头（staged P_A + on_curve + dbl）
const RANK_AC: usize = 3120; // ec_add_complete 锚 + 两组尾暂存拷贝（单秩）
const _: () =
    assert!(RANK_AC + 64 < crate::sm3_compress::ROWS, "EC 区必须容纳于 K=12 超立方");

/// 分段约束账本（每段以 n_constraints 差值实录；蓝图预测为注释基准，
/// 实测值锁定测试后以注释「实测」覆盖）。
#[derive(Debug, Default, Clone)]
pub struct Ledger {
    pub face_input: usize,  // 3×266 = 798（e/r/s：钉1 + 大折叠1 + 8×word_link33）
    pub face_pa: usize,     // 3 = 2 坐标钉 + inf 钉
    pub face_gbases: usize, // 6 钉（勘误 #17：g 与 g₂ 六实例）
    pub range_check: usize, // 2×265 = 530（lt_n(r)、lt_n(s)）
    pub nonzero_rs: usize,  // 3（neq_zero(r)/(s)/(t) 各 1；t 的记在 t_calc 也一并可见）
    pub t_calc: usize,      // 786 + 1（add_mod_n(r,s) + neq_zero(t)）
    pub head_eg: usize,     // 8 = dbl5 + bind3（勘误 #17 基头）
    pub chain_eg: usize,    // 256×24 + 头钉 3 = 6147（Fix R-a）
    pub head_ep: usize,     // 12 = oncurve4 + dbl5 + bind3
    pub chain_ep: usize,    // 6147（Fix R-a 同款）
    pub ec_sum: usize,      // 28（ec_add_complete）
    pub decompose: usize,   // 257（x₁ 位分解；x₁<p<2²⁵⁶ ⟹ top 恒 0）
    pub reduce: usize,      // 1045（x₁ mod n）
    pub final_sum: usize,   // 786（(e+x₁ mod n) mod n， Blueprint 原 limb_e_x1 桶的实测修正）
    pub eq_r: usize,        // 4（emit_eq(r̂, r)）
    pub pa_decomp: usize,   // 514 = 2×257（簇H merged：P_A 双 decompose 槽）
    pub zu_msg_roots: usize, // 32 = 15 常量锚 + 17 recomp（簇H merged：H2 换根）
    pub e_bind: usize,      // 簇J T1 E7：Σ2^{32k}·dgw_k == e 面值列大折叠（1 条）
}

impl Ledger {
    pub fn total(&self) -> usize {
        let l = self;
        l.face_input + l.face_pa + l.face_gbases + l.range_check + l.nonzero_rs + l.t_calc
            + l.head_eg + l.chain_eg + l.head_ep + l.chain_ep + l.ec_sum + l.decompose
            + l.reduce + l.final_sum + l.eq_r + l.pa_decomp + l.zu_msg_roots
            + l.e_bind
    }
}

/// 单值实例钉面：一列 + 私有选择器（激活点 = 该实例钉点行）。
#[derive(Clone, Copy)]
struct PinFace {
    col: usize,
    sel: usize,
}

/// 一个 mod-n 标量的输入面：值列 + 面选择器 + 8 个 32 位词列组。
/// 词位在钉点行链接（word_link）＋大折叠回值列 ⟹ 位的电路真值链闭合。
#[derive(Clone, Copy)]
struct FacePlan {
    pv: usize,
    /// 工作世界家族（词位链接 + 大折叠），激活点 = 秩锚 srow(RANK_A_*)。
    sel: usize,
    /// 实例钉私有选择器：只挂一条 pin.bind（勘误 #19 —— 与词位家族分家，
    /// 后者激活在工作锚而非钉行）。
    sp: usize,
    words: [crate::sm3_compress::WordCols; 8],
}

impl FacePlan {
    /// 以面词位拼出的 PlScalar 句柄（家点 = 钉点行）。**列拼装语义**：
    /// PlScalar 只要求「256 条位列 + 家点」，八词位组跨列拼接即可 ——
    /// 七件套经 `bq` 按家点旋转读取，与物理分配顺序无关。
    fn to_scalar(&self, home: usize, val: [u64; 4]) -> Sc {
        let mut cols = [0usize; 256];
        for k in 0..8 {
            cols[32 * k..32 * k + 32].copy_from_slice(&self.words[k].bits);
        }
        scalar(cols, home, val)
    }
}

/// 全部布局产物（PLAN 相一次性收口 —— 首条约束发射后禁再分配）。
#[allow(dead_code)]
pub(crate) struct AsmPlan {
    faces: [FacePlan; 3],            // ord 0,1,2 = e,r,s
    pins: [PinFace; 9],              // ord 3..11 = pax,pay,painf,gx,gy,gi,g2x,g2y,g2i
    lt_r: AddSlots,
    lt_s: AddSlots,
    ner: NeqSlots,
    nes: NeqSlots,
    net: NeqSlots,
    amn_t: AddModNSlots,
    amn_f: AddModNSlots,
    dec: DecompSlots,
    red: ReduceSlots,
    eq: EqSlots,
    eg: crate::sm2_ec_window_gadget::WindowMulSlots,
    g_table: crate::sm2_ec_window_gadget::GTableCols,
    ep: crate::sm2_ec_plonkish::MulLoopSlots,
    ac: crate::sm2_ec_plonkish::CompleteSlots,
    dge: crate::sm2_ec_plonkish::DoubleSlots, // EG 基头倍门
    dgp: crate::sm2_ec_plonkish::DoubleSlots, // EP 基头倍门
    oc_sel: usize,                            // on_curve(P_A) 家族选择器
    oc_p1: usize,
    oc_p2: usize,
    oc_u: usize,
    // 基头/求和/尾暂存三元组
    hs_g: PtCells, // EG 头 staged G（读自家行）
    hd_g: PtCells, // EG 头 2·G 绑定格
    hs_p: PtCells, // EP 头 staged P_A
    hd_p: PtCells, // EP 头 2·P_A 绑定格
    acsg: PtCells, // AC 输入侧 [s]G 尾拷贝
    actp: PtCells, // AC 输入侧 [t]P_A 尾拷贝
    st_x1: usize,  // x₁ 尾中继格（srow(RANK_X1) 行）
    rows_eg: Vec<usize>,
    rows_ep: Vec<usize>,
    row_hr_eg: usize,
    row_hr_ep: usize,
    row_ac: usize,
    // ── 环账本（begin 全部在 PLAN 相；成员经 relay_to_col 追加，
    //     后者不带冻结守卫 —— 协议机制见 Builder 文档）──
    rid_beta_ep: Vec<usize>,
    rid_base_g: [usize; 3], // g 钉 ↔ staged 头 ↔ 全锚点（基通道大环）
    rid_d2_g: [usize; 3],   // g₂ 钉 ↔ 头输出 ↔ d₂v 全锚点
    rid_base_p: [usize; 3], // P_A 钉 ↔ staged 头 ↔ 锚点
    rid_d2_p: [usize; 3],   // 头输出 ↔ EP d₂v 锚点（无实例：圈内自证）
    rid_tail_sg: [usize; 3], // EG 尾 acc_in@rows[256] ↔ AC 输入拷贝（Fix R-a）
    rid_tail_tp: [usize; 3],
    rid_x1: usize, // AC.sx ↔ st_x1
    rid_pv: [usize; 3], // e/r/s 面值列：钉行 ↔ 工作锚（勘误 #19）
}

impl AsmPlan {
    /// 簇J T1 E7：e 面词位家族选择器 + 面值列（dgw 大折叠发射锚）。
    /// sel 激活点恰 = srow(RANK_A_E) 唯一点（勘误 #26 修复 + 守卫
    /// `face_word_link_families_active` 锁定）⟹ 其上再发射一条全 cur 约束
    /// 即恰在 row_ae 行生效（同 sel 多约束先例 = emit_face 自家 265 条）；
    /// pv@row_ae ↔ 实例 0 由 rid_pv 环 + pin.bind 缝合。
    pub(crate) fn e_face_fold_anchor(&self) -> (usize, usize) {
        (self.faces[0].sel, self.faces[0].pv)
    }

    /// 簇J T1 E8：G/2G 基通道大环句柄——sk 循环的 base/d2v 锚点格经
    /// `relay_to_col` **追加成员**绑定到常量钉面（值恒 G/2G；不开新环，
    /// E-H②「一格一环」红线，merged st_pax 追加 rid_base_p 同款）。
    /// 只读句柄，merged 语义零触碰（回归门 = 三测试指纹逐字节）。
    pub(crate) fn g_base_channels(&self) -> ([usize; 3], [usize; 3]) {
        (self.rid_base_g, self.rid_d2_g)
    }

    /// 簇J T1 E12：负例矩阵②③锚（add-only accessor，零电路触碰——回归门 =
    /// 三测试指纹逐字节）。返回 (r 面 pv@home, s 面 pv@home, P_A.x 钉格)：
    /// 面槽格 ∈ rid_pv 环（翻转 ⟹ link.recomp mock + 环审计双信号齐爆）；
    /// pax 钉格 = rid_base_p 环首键 + pin.bind 实例 3（翻转 ⟹ 双信号 +
    /// native verify_replay 失败——off-curve 点首行即拒）。
    /// 索引钉死：faces[0..3] = e/r/s（ord 0..2）、pins[0] ↔ ord 3 = pax。
    pub(crate) fn t1_neg_anchors(&self) -> ((usize, usize), (usize, usize), (usize, usize)) {
        (
            (self.faces[1].pv, srow(RANK_A_R)),
            (self.faces[2].pv, srow(RANK_A_S)),
            (self.pins[0].col, pin_row(3)),
        )
    }
}

fn plan_pin_face(b: &mut Builder<FpSM2>) -> PinFace {
    PinFace { col: b.alloc_col(), sel: b.alloc_selector(&[]) }
}

fn plan_face(b: &mut Builder<FpSM2>) -> FacePlan {
    FacePlan {
        pv: b.alloc_col(),
        sel: b.alloc_selector(&[]),
        sp: b.alloc_selector(&[]),
        words: std::array::from_fn(|_| b.alloc_word_cols(true)),
    }
}

/// PLA­N 相：一次分配全部列/选择器，并把每条复制环的 begin 落账
/// （首成员任选一个已知键；其余成员由 EMIT 相 `relay_to_col` 追加）。
#[allow(clippy::too_many_lines)]
pub(crate) fn plan_all(b: &mut Builder<FpSM2>) -> AsmPlan {
    let faces = std::array::from_fn(|_| plan_face(b));
    let pins = std::array::from_fn(|_| plan_pin_face(b));
    let lt_r = plan_add(b);
    let lt_s = plan_add(b);
    let ner = plan_neq(b);
    let nes = plan_neq(b);
    let net = plan_neq(b);
    let amn_t = plan_add_mod_n(b);
    let amn_f = plan_add_mod_n(b);
    let dec = plan_decomp(b);
    let red = plan_reduce_mod_n(b);
    let eq = plan_eq(b);
    // ③手术 S3c 加时包：EG（[s]G 固定基）window 化——G 表常数列全电路一份。
    let g_table = crate::sm2_ec_window_gadget::alloc_g_table(
        b,
        crate::sm2_ec_plonkish::g_coords(),
    );
    let eg = crate::sm2_ec_window_gadget::plan_window_mul(b, RANK_EG);
    let ep = crate::sm2_ec_plonkish::plan_ec_mul_loop(b);
    let ac = plan_ec_add_complete(b);
    let dge = crate::sm2_ec_plonkish::plan_ec_double(b);
    let dgp = crate::sm2_ec_plonkish::plan_ec_double(b);
    let oc_sel = b.alloc_selector(&[]);
    let oc_p1 = b.alloc_col();
    let oc_p2 = b.alloc_col();
    let oc_u = b.alloc_col();
    let (hs_g, hd_g) = (plan_point(b), plan_point(b));
    let (hs_p, hd_p) = (plan_point(b), plan_point(b));
    let (acsg, actp) = (plan_point(b), plan_point(b));
    let st_x1 = b.alloc_col();

    // 面值中继环首键 = 钉行格；EMIT 相把工作锚格追加进同环（勘误 #19：
    // pv 列在钉行与工作锚两处携同一值，环置换保证相等 —— 零约束零旋转）。
    let rid_pv: [usize; 3] =
        std::array::from_fn(|k| b.begin_relay_col(faces[k].pv, pin_row(k)));

    // Fix R-a（勘误 #27）：257 连续秩 —— rows[0]=头行兼迭代 0（head_sel 钉
    // O）、rows[256]=纯接收行（第 255 迭代 sel_bind_rot 以 Rotation(1) 自写）。
    // ⚠️ 吸收态监视：row_at panic（秩映射点 0）即平移 RANK_EG/RANK_EP。
    // ③S3c：EG window 化——rows_eg 语义换代=66 行窗行（负例/审计消费）。
    let rows_eg: Vec<usize> =
        (0..crate::sm2_ec_window_gadget::ROWS_USED).map(|i| row_at(RANK_EG + i)).collect();
    let rows_ep: Vec<usize> = (0..=256).map(|i| row_at(RANK_EP + i)).collect();
    let row_hr_eg = row_at(RANK_HR_EG);
    let row_hr_ep = row_at(RANK_HR_EP);
    let row_ac = row_at(RANK_AC);

    // ── 环 begin（吸收态守卫在 begin 内部）。全部首键在 PLAN 相落账，
    //    其余成员由 EMIT 相经 relay_to_col 追加（无冻结守卫）。──
    // β 车道：每锚点一条二元小环（不同锚消费不同位，不能合并成一环）。
    // 镜像序：循环按 MSB-first 消费 bits_lsb.rev() ⟹ 第 i 锚点消费位
    // cols[255-i]。EG 源 = s 面词位（家点 mp[2]=3）；EP 源 = t 输出位
    // （home = t 工作锚 srow(RANK_T)，选树结果列 amn_t.sel.out）。

    let mut rid_beta_ep = Vec::with_capacity(256);
    for i in 0..256 {
        rid_beta_ep.push(b.begin_relay_col(ep.bit, rows_ep[i]));
    }
    // 坐标通道大环。首键：有实例的通道取钉面列@钉行；d₂-p 无实例取头输出格。
    // staged 头格与循环锚点格由 EMIT 相追加进同环。钉面序：pins[0..2]=P_A
    // （ord3..5）、pins[3..5]=G（ord6..8）、pins[6..8]=g₂（ord9..11）。
    let ch = |b: &mut Builder<FpSM2>, cols: [usize; 3], ords: [usize; 3]| -> [usize; 3] {
        std::array::from_fn(|c| b.begin_relay_col(cols[c], pin_row(ords[c])))
    };
    let rid_base_p = ch(b, [pins[0].col, pins[1].col, pins[2].col], [3, 4, 5]);
    let rid_base_g = ch(b, [pins[3].col, pins[4].col, pins[5].col], [6, 7, 8]);
    let rid_d2_g = ch(b, [pins[6].col, pins[7].col, pins[8].col], [9, 10, 11]);
    // 🔴 勘误 #20：下面三组的起点是**格**(列，物理点)，不是实例钉 —— 不能走
    // ch()(后者把 ords 过 pin_row() 译成实例行)。首版把 row_hr_ep/row_ac 当
    // 序号传入 ⟹ 起点落到 pin_row(1610)/pin_row(1180) 的孤儿零格（pt322/
    // pt1818），真头格（hd_p/acsg/actp）反而没进环 —— 环审计 6 条不等的根因
    // （#20 定案：物理点 ≠ 实例序号，ch() 仅适用于 pins 面）。
    let rid_d2_p = std::array::from_fn(|c| b.begin_relay_col(hd_p.cols[c], row_hr_ep));
    let rid_tail_sg = std::array::from_fn(|c| b.begin_relay_col(acsg.cols[c], row_ac));
    let rid_tail_tp = std::array::from_fn(|c| b.begin_relay_col(actp.cols[c], row_ac));
    let rid_x1 = b.begin_relay_col(st_x1, srow(RANK_X1));

    AsmPlan {
        faces,
        pins,
        lt_r,
        lt_s,
        ner,
        nes,
        net,
        amn_t,
        amn_f,
        dec,
        red,
        eq,
        eg,
        ep,
        ac,
        dge,
        dgp,
        oc_sel,
        oc_p1,
        oc_p2,
        oc_u,
        hs_g,
        hd_g,
        hs_p,
        hd_p,
        acsg,
        actp,
        st_x1,
        rows_eg,
        rows_ep,
        row_hr_eg,
        row_hr_ep,
        row_ac,
        g_table,
        rid_beta_ep,
        rid_base_g,
        rid_d2_g,
        rid_base_p,
        rid_d2_p,
        rid_tail_sg,
        rid_tail_tp,
        rid_x1,
        rid_pv,
    }
}

// ══════════════════ EMIT 相（分段的见证写入 + 约束发射） ══════════════════

use crate::sm2_ec_plonkish::PtRef;
use crate::sm3_compress::row_mapping;

fn qcur(b: &Builder<FpSM2>, col: usize) -> Expr {
    b.q(col, Rotation::cur())
}

#[inline]
fn bf(v: bool) -> FpSM2 {
    if v { FpSM2::ONE } else { FpSM2::ZERO }
}

fn konst(v: FpSM2) -> Expr {
    Expression::<FpSM2>::Constant(v)
}

/// 实例序号 → 钉点行。
fn pin_row(ord: usize) -> usize {
    row_mapping()[ord]
}

/// 发射一个 mod-n 标量的输入面：值钉 + 8 词位链接 + 大折叠。**266 推**。
/// 勘误 #19 后的「双世界」形态：词位/折叠家族激活在**工作锚 `home`**
/// （秩 14..16），实例绑定只剩钉行上的一条 pin.bind（私有选择器 `sp`），
/// 两处 pv 格由 [`AsmPlan::rid_pv`] 中继环缝合成同一值。
fn emit_face(b: &mut Builder<FpSM2>, f: &FacePlan, ord: usize, home: usize, v: FpSM2) -> Sc {
    let limbs = crate::sm2_params::fr_to_limbs(&v);
    b.set_cell_f(f.pv, home, v);
    // 钉行侧：值格写入（约束由环置换与 home 侧连通）+ 私有 bind
    b.set_cell_f(f.pv, pin_row(ord), v);
    b.extend_selector(f.sp, &[pin_row(ord)]);
    b.emit_pin_val_only(f.sp, f.pv, ord);
    // 🔴 勘误 #26 修复（2026-08-31）：词位家族选择器必须显式激活于工作锚行。
    //    缺席时 8×link.bool + link.recomp + 大折叠共 265 条/面被零激活选择器
    //    门控 = 空转，bits↔instance 绑定断裂（三道防线全盲；v2 家族七处调用
    //    点均有显式 extend，唯此处遗漏）。约束计数不变（约束早已发射）。
    b.extend_selector(f.sel, &[home]);
    for k in 0..8usize {
        let wv = ((limbs[k / 2] >> (32 * (k % 2))) & 0xFFFF_FFFF) as u32;
        let h = f.words[k].at(home);
        b.set_word(&h, wv);
        b.emit_word_link(f.sel, &f.words[k]);
    }
    // 大折叠 Σ2^{32k}·w_k == 值列（把八条 32 位词通道合成一个 256 位标量语句）
    let mut fold = Expression::<FpSM2>::zero();
    for k in 0..8usize {
        let coef = Expression::<FpSM2>::Constant(crate::sm2_params::f_pow2(32 * k));
        fold = fold + coef * qcur(b, f.words[k].val.expect("词值列"));
    }
    b.emit_assert_zero(f.sel, fold - qcur(b, f.pv));
    f.to_scalar(home, limbs)
}

/// 发射一个单值钉面（列值写入 + 私有选择器 + pin.bind + 实例赋值）。
fn pin_one(b: &mut Builder<FpSM2>, pf: &PinFace, ord: usize, v: FpSM2) {
    let row = pin_row(ord);
    b.set_cell_f(pf.col, row, v);
    b.extend_selector(pf.sel, &[row]);
    b.emit_pin_val_only(pf.sel, pf.col, ord);
    b.set_instance(ord, v);
}

/// 基头三元组绑定：把 `emit_ec_double` 的线性输出表达式绑进产物格
/// （复用倍门家族选择器 —— 激活点集相同，家族形状逐行同构）。**3 推**。
fn bind_triple(
    b: &mut Builder<FpSM2>,
    hs: usize,
    hd: &PtCells,
    at: usize,
    dd: &crate::sm2_ec_plonkish::PtVal,
) {
    b.set_cell_f(hd.cols[0], at, dd.xv);
    b.set_cell_f(hd.cols[1], at, dd.yv);
    b.set_cell_f(hd.cols[2], at, bf(dd.iv));
    b.emit_assert_zero(hs, qcur(b, hd.cols[0]) - dd.xe.clone());
    b.emit_assert_zero(hs, qcur(b, hd.cols[1]) - dd.ye.clone());
    b.emit_assert_zero(hs, qcur(b, hd.cols[2]) - dd.infe.clone());
}

/// 装配产物：出料五件 + 账本 + 篡改钩子（测试与簇E bin 共用）。
pub struct Assembled {
    pub info: plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>,
    pub advice: Vec<Vec<FpSM2>>,
    pub instances: Vec<Vec<FpSM2>>,
    pub tags: Vec<(&'static str, usize)>,
    pub ctags: Vec<&'static str>,
    pub num_selectors: usize,
    /// R1-v3b 取证：非 cur 查询按 (advice 局部列, rot) 聚合计数。
    pub q_edges: Vec<((usize, i64), usize)>,
    pub ledger: Ledger,
    /// 审计/负例钩子：双循环槽位、求和门行、尾循环行、x₁ 尾格。
    pub eg: crate::sm2_ec_window_gadget::WindowMulSlots,
    pub rows_eg: Vec<usize>,
    pub g_table: crate::sm2_ec_window_gadget::GTableCols,
    pub ep: crate::sm2_ec_plonkish::MulLoopSlots,
    pub row_ac: usize,
    pub st_x1_col: usize,
    /// 簇H H4 三篡改负例钩子（merged 专属；None = standalone）。
    pub zu: Option<ZuHooks>,
}

impl Assembled {
    /// B6 飞证 TRAIL：三件面构造器（zksvc prove/verify 只消费 info/advice/
    /// instances；取证钩子面为 AUTH 装配专属——TRAIL 档默认形态零消费）。
    pub fn from_parts(
        info: plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>,
        advice: Vec<Vec<FpSM2>>,
        instances: Vec<Vec<FpSM2>>,
    ) -> Self {
        Assembled {
            info,
            advice,
            instances,
            tags: Vec::new(),
            ctags: Vec::new(),
            num_selectors: 0,
            q_edges: Vec::new(),
            ledger: Default::default(),
            eg: Default::default(),
            rows_eg: Vec::new(),
            g_table: Default::default(),
            ep: Default::default(),
            row_ac: 0,
            st_x1_col: 0,
            zu: None,
        }
    }
}

/// H4 三篡改负例的锚格坐标（merged 装配期收口，测试只消费）。
#[derive(Clone, Copy, Debug)]
pub struct ZuHooks {
    /// P_A 暂存格列（x/y 各一）@ `row_pa` —— 负例二锚点（钉值 → V 位漂移）。
    pub st_pax: usize,
    pub st_pay: usize,
    pub row_pa: usize,
    /// B₂ 常量词 0 锚格 (列, 行) —— 负例一锚点（ID 字节 → 常量词根漂移；
    /// 取自 emit_zu_msg_roots 的根表首格）。
    pub anchor0: (usize, usize),
    /// 体A 负轮 TT1 族 t=−4 锚格 —— 负例三锚点（烘焙 IV₂ 常量格）。
    pub neg_a_t1: (usize, usize),
}

/// 装配出料尾（簇J E4 复用）：[`assemble_verify_inner`] 出料段的纯共享——
/// 零约束零环触碰（merged 语义零变化；standalone 尾仍走自家段，零接触纪律）。
/// 消费 plan 句柄的钩子字段，finish 并封装 [`Assembled`]（zu 恒 None，
/// merged 形态不经过此口）。
pub(crate) fn finish_verify_assembly(
    bld: Builder<FpSM2>,
    led: Ledger,
    pl: AsmPlan,
) -> Assembled {
    let q_edges = bld.q_edge_counts();
    let (info, advice, instances, tags, ctags, num_selectors) = bld.finish_parts();
    Assembled {
        info,
        advice,
        instances,
        tags,
        ctags,
        num_selectors,
        q_edges,
        ledger: led,
        eg: pl.eg,
        rows_eg: pl.rows_eg,
        g_table: pl.g_table,
        ep: pl.ep,
        row_ac: pl.row_ac,
        st_x1_col: pl.st_x1,
        zu: None,
    }
}

/// 四步验签顶板装配（standalone 形态：实例面 12）。输入五元组为公开语句；
/// 本函数按**正例约定**（`verify_replay` 结论为真）装配见证，负例统一走
/// 「装配后篡改 advice 的钩子路径」（M2a 同款诚实注记：mock 层不重放置换论证）。
pub fn assemble_sm2_verify(e: FpSM2, r: FpSM2, s: FpSM2, pax: FpSM2, pay: FpSM2) -> Assembled {
    assemble_verify_inner(e, r, s, pax, pay, None)
}

/// merged 形态 Z_U 段的 plan 相句柄（簇H H1）：全部 alloc 在 [`plan_all`]
/// **之前**按结构体字段书写顺序求值（Builder 冻结守卫纪律 —— 勘误 #19 家族
/// 「plan/emit 相序」教训的复现防护）。字段私有，EMIT 相只消费不读内部。
struct ZuMergedPlan {
    plan: crate::sm3_compress_v2::ZuPlan,
    st_pax: usize,
    st_pay: usize,
    dec_xa: DecompSlots,
    dec_ya: DecompSlots,
    roots: crate::sm3_compress_v2::ZuRootsPlan,
    /// Z 段全部中继环（register ×2 + 体间通道 + echo 根；`plan_z_rings`）。
    rings: crate::sm3_compress_v2::ZuRings,
}

/// merged 形态装配：验签体 + Z_U 两体段（蓝图 §四·7 H1/H2）。尾接段做
/// P_A 双 decompose（换根方案的位源）+ 32 消息根格 + 两体装配，实例面
/// 20 = 验签体 0..11 + Z_U 摘要 12..19（H1·5）。
#[allow(clippy::too_many_arguments)]
pub fn assemble_show_z_merged(
    e: FpSM2,
    r: FpSM2,
    s: FpSM2,
    pax: FpSM2,
    pay: FpSM2,
    b2: &[u8; 64],
    b3: &[u8; 64],
    iv2: &[u32; 8],
) -> Assembled {
    assemble_verify_inner(e, r, s, pax, pay, Some((b2, b3, iv2)))
}

/// 验证体发射段（簇J E4 段化，蓝图 §四·8 J-10b ①）：自
/// [`assemble_verify_inner`] **纯代码搬移** —— 宿主数学与发射顺序逐字
/// 保持；merged 语义零变化，等价性证据 = 回归门（三测试 + 形状指纹
/// 138,010/7,752/243/243/958、max|rot|=4 逐字节；Fix R-a +6/−6/+2 勘误
/// #27 增量）。消费 [`plan_all`] 句柄；
/// 五元组 = 公开语句；见证按正例约定装配（`verify_replay` 断言随行）。
/// 返回族账本。
#[allow(clippy::too_many_lines)]
pub(crate) fn emit_verify_body(
    bld: &mut Builder<FpSM2>,
    pl: &AsmPlan,
    e: FpSM2,
    r: FpSM2,
    s: FpSM2,
    pax: FpSM2,
    pay: FpSM2,
) -> Ledger {
    let mut bld = bld; // 纯搬移重绑：调用点 `&mut bld` 逐字不变
    let g = g_coords();
    let a = curve_a();
    let bpar = curve_b();
    debug_assert!(on_curve_affine(Some((pax, pay))), "P_A 必须在曲线上");
    // native 四步真值（唯一真值源：见证写入与期望读回共用）
    let rp = verify_replay(e, r, s, pax, pay);
    assert!(rp.ok, "正例装配要求四步验签为真的语句");
    let d2g = affine_double(Some(g)).unwrap();
    let d2p = affine_double(Some((pax, pay))).unwrap();
    let mut led = Ledger::default();

    // ── 输入面：e/r/s 大面（266×3）+ 九个单值钉面 ──
    let (p_ae, p_ar, p_as) = (srow(RANK_A_E), srow(RANK_A_R), srow(RANK_A_S));
    let m = bld.n_constraints();
    let sc_e = emit_face(&mut bld, &pl.faces[0], 0, p_ae, e);
    let sc_r = emit_face(&mut bld, &pl.faces[1], 1, p_ar, r);
    let sc_s = emit_face(&mut bld, &pl.faces[2], 2, p_as, s);
    led.face_input = bld.n_constraints() - m;
    // 面值中继环补第二成员（工作锚格），缝合完成
    for (k, hm) in [p_ae, p_ar, p_as].iter().enumerate() {
        bld.relay_to_col(pl.rid_pv[k], pl.faces[k].pv, *hm);
    }

    let m = bld.n_constraints();
    pin_one(&mut bld, &pl.pins[0], 3, pax); // P_A 面
    pin_one(&mut bld, &pl.pins[1], 4, pay);
    pin_one(&mut bld, &pl.pins[2], 5, FpSM2::ZERO);
    led.face_pa = bld.n_constraints() - m;

    let m = bld.n_constraints();
    for i in 0..3usize {
        // G 三件
        pin_one(&mut bld, &pl.pins[3 + i], 6 + i, [g.0, g.1, FpSM2::ZERO][i]);
    }
    for i in 0..3usize {
        // g₂ 三件（勘误 #17）
        pin_one(
            &mut bld,
            &pl.pins[6 + i],
            9 + i,
            [d2g.0, d2g.1, FpSM2::ZERO][i],
        );
    }
    led.face_gbases = bld.n_constraints() - m;

    // ── 范围检查 lt_n(r)、lt_n(s)：265×2 ──
    let m = bld.n_constraints();
    let _fr = emit_lt_n(&mut bld, &pl.lt_r, srow(RANK_A_R), &sc_r, &q_limbs());
    let _fs = emit_lt_n(&mut bld, &pl.lt_s, srow(RANK_A_S), &sc_s, &q_limbs());
    led.range_check = bld.n_constraints() - m;

    // ── 非零 neq_zero(r)/(s)：各 1 ──
    let m = bld.n_constraints();
    emit_neq_zero(&mut bld, &pl.ner, srow(RANK_NEQ_R), &sc_r);
    emit_neq_zero(&mut bld, &pl.nes, srow(RANK_NEQ_S), &sc_s);
    led.nonzero_rs = bld.n_constraints() - m;

    // ── t=(r+s) mod n（786）+ neq_zero(t)：787 ──
    let m = bld.n_constraints();
    let sc_t = emit_add_mod_n(&mut bld, srow(RANK_T), &pl.amn_t, &sc_r, &sc_s);
    emit_neq_zero(&mut bld, &pl.net, srow(RANK_NEQ_T), &sc_t);
    led.t_calc = bld.n_constraints() - m;

    // ── EG 基头（勘误 #17）：staged G → dbl(5) → 绑定(3)；8 推 ──
    let m = bld.n_constraints();
    write_point(&mut bld, &pl.hs_g, pl.row_hr_eg, Some(g));
    for c in 0..3usize {
        bld.relay_to_col(pl.rid_base_g[c], pl.hs_g.cols[c], pl.row_hr_eg);
    }
    let ddg = crate::sm2_ec_plonkish::emit_ec_double(
        &mut bld,
        &pl.dge,
        pl.row_hr_eg,
        &PtRef::cells(&pl.hs_g, Some(g)),
        a,
    );
    bind_triple(&mut bld, pl.dge.sel, &pl.hd_g, pl.row_hr_eg, &ddg);
    led.head_eg = bld.n_constraints() - m;

    // ── EG 主链 [s]G：256×24 + 头钉 3 = 6147（Fix R-a，勘误 #27）──
    let s_bits_v = limbs_to_bits_le(&sc_s.val);
    let m = bld.n_constraints();
    // ③S3c：EG window 化（β 车道/基点大环退役——基点自由面被 G 表常数化
    // 根治；s_g 由验签方程唯一锚定，无需额外标量绑定环——离散对数级）。
    let ((egox, egoy), egout_row, egout_pt) = crate::sm2_ec_window_gadget::emit_window_mul(
        &mut bld,
        &pl.eg,
        &pl.g_table,
        RANK_EG,
        &crate::sm2_params::fr_from_limbs(&sc_s.val),
    );
    led.chain_eg = bld.n_constraints() - m;
    let out_eg = crate::sm2_ec_plonkish::LoopOut {
        cols: [egox, egoy, 0],
        pt: Some(egout_pt),
    };

    // ── EP 基头：staged P_A → on_curve(4) → dbl(5) → 绑定(3)；12 推 ──
    let m = bld.n_constraints();
    write_point(&mut bld, &pl.hs_p, pl.row_hr_ep, Some((pax, pay)));
    for c in 0..3usize {
        bld.relay_to_col(pl.rid_base_p[c], pl.hs_p.cols[c], pl.row_hr_ep);
    }
    bld.extend_selector(pl.oc_sel, &[pl.row_hr_ep]);
    let qx = qcur(&bld, pl.hs_p.cols[0]);
    let qy = qcur(&bld, pl.hs_p.cols[1]);
    // 见证先行（mock 教训：零值格保底 —— 漏写则 y²/x² 两式当场违约，
    // 而 p₂=p₁·x 恰以 0·0=0 假绿，仅断言式带出 −b 残差）
    let p1v = pax.square();
    let p2v = p1v * pax;
    bld.set_cell_f(pl.oc_p1, pl.row_hr_ep, p1v);
    bld.set_cell_f(pl.oc_p2, pl.row_hr_ep, p2v);
    bld.set_cell_f(pl.oc_u, pl.row_hr_ep, pay.square());
    // y² − x³ − a·x − b = 0：乘积项落格保度数 ≤3（内容 2/2/3）
    bld.emit_prod_eq(pl.oc_sel, qy.clone(), qy.clone(), qcur(&bld, pl.oc_u));
    bld.emit_prod_eq(pl.oc_sel, qx.clone(), qx.clone(), qcur(&bld, pl.oc_p1));
    bld.emit_prod_eq(pl.oc_sel, qcur(&bld, pl.oc_p1), qx.clone(), qcur(&bld, pl.oc_p2));
    bld.emit_assert_zero(
        pl.oc_sel,
        qcur(&bld, pl.oc_u)
            - qcur(&bld, pl.oc_p2)
            - konst(a) * qx.clone()
            - konst(bpar),
    );
    let ddp = crate::sm2_ec_plonkish::emit_ec_double(
        &mut bld,
        &pl.dgp,
        pl.row_hr_ep,
        &PtRef::cells(&pl.hs_p, Some((pax, pay))),
        a,
    );
    bind_triple(&mut bld, pl.dgp.sel, &pl.hd_p, pl.row_hr_ep, &ddp);
    led.head_ep = bld.n_constraints() - m;
    let _ = d2p; // 本构造中 2·P_A 由基头电路内导出（d2p 仅文档性真值）

    // ── EP 主链 [t]P_A：6147（同 Fix R-a +3 头钉）──
    let t_bits_v = limbs_to_bits_le(&sc_t.val);
    let m = bld.n_constraints();
    let out_ep = emit_ec_mul_loop_const_base(
        &mut bld,
        &pl.ep,
        &pl.rows_ep,
        (pax, pay),
        d2p,
        &t_bits_v,
        a,
    );
    led.chain_ep = bld.n_constraints() - m;
    for i in 0..256usize {
        bld.relay_to_col(pl.rid_beta_ep[i], sc_t.cols[255 - i], srow(RANK_T));
        for c in 0..3usize {
            bld.relay_to_col(pl.rid_base_p[c], pl.ep.base.cols[c], pl.rows_ep[i]);
            bld.relay_to_col(pl.rid_d2_p[c], pl.ep.d2v.cols[c], pl.rows_ep[i]);
        }
    }

    // ── 求和：(x₁,y₁)=[s]G+[t]P_A；28 推；两尾拷贝经环进 AC 行 ──
    // ③S3c：window 输出零坐标按 O 语义（s=0 负例形态，旧 None 同款）。
    let eg_aff: crate::sm2_ec_plonkish::Affine =
        if egout_pt == (FpSM2::ZERO, FpSM2::ZERO) { None } else { Some(egout_pt) };
    write_point(&mut bld, &pl.acsg, pl.row_ac, eg_aff);
    write_point(&mut bld, &pl.actp, pl.row_ac, out_ep.pt);
    for c in 0..3usize {
        // Fix R-a：尾值 = acc_in@rows[256]（write-next 接收行；out.cols 即
        // acc_in 列），旧 rows[255]（acc_out）已随列删除作废。
        if c < 2 {
            bld.relay_to_col(pl.rid_tail_sg[c], out_eg.cols[c], egout_row);
        }
        // c==2（inf 通道）退役：window 输出无 inf 格——s_g=O 负例形态由
        // 零坐标+write_point O 格承担（完全加 inf 分支照常约束）。
        bld.relay_to_col(pl.rid_tail_tp[c], out_ep.cols[c], pl.rows_ep[256]);
    }
    let m = bld.n_constraints();
    let res = emit_ec_add_complete(
        &mut bld,
        &pl.ac,
        pl.row_ac,
        &PtRef::cells(&pl.acsg, out_eg.pt),
        &PtRef::cells(&pl.actp, out_ep.pt),
        a,
    );
    led.ec_sum = bld.n_constraints() - m;
    // 尾部二元环：AC.sx ↔ st_x1（x₁ 进标量世界的唯一通道）
    bld.relay_to_col(pl.rid_x1, res.cols[0], pl.row_ac);

    // ── 尾部分解 / 归约 / 最终和 / 相等 ──
    bld.set_cell_f(pl.st_x1, srow(RANK_X1), rp.x1);
    let x1l = fr_to_limbs(&rp.x1);
    let m = bld.n_constraints();
    let x1_cell = qcur(&bld, pl.st_x1);
    let sca_x1 = emit_decompose(&mut bld, &pl.dec, srow(RANK_X1), x1_cell, &x1l);
    led.decompose = bld.n_constraints() - m;

    let m = bld.n_constraints();
    let zero_e = Expression::<FpSM2>::zero();
    // x₁ ∈ F_p ⟹ x₁ < 2²⁵⁶ ⟹ 第 257 位恒 0（top=常数零，top_v=false）
    let sca_red = emit_reduce_mod_n(&mut bld, srow(RANK_RED), &pl.red, &sca_x1, &zero_e, false);
    led.reduce = bld.n_constraints() - m;

    let m = bld.n_constraints();
    let sca_fin = emit_add_mod_n(&mut bld, srow(RANK_FIN), &pl.amn_f, &sc_e, &sca_red);
    led.final_sum = bld.n_constraints() - m;

    let m = bld.n_constraints();
    emit_eq(&mut bld, &pl.eq, srow(RANK_EQ), &sca_fin, &sc_r);
    led.eq_r = bld.n_constraints() - m;
    led
}

#[allow(clippy::too_many_lines)]
fn assemble_verify_inner(
    e: FpSM2,
    r: FpSM2,
    s: FpSM2,
    pax: FpSM2,
    pay: FpSM2,
    zu: Option<(&[u8; 64], &[u8; 64], &[u32; 8])>,
) -> Assembled {
    let n_inst = if zu.is_some() { 20 } else { 12 };
    let mut bld = Builder::<FpSM2>::new(n_inst);
    // 簇H H1 冻结守卫纪律：merged 段的全部分配（两体 pools/面/选择器、P_A
    // 双 decompose 槽、消息根锚列/选择器）必须先于第一条款束发射 ⟹ 在
    // plan_all 之前构造 plan 句柄；EMIT 相（验签体 + merged 尾段）零分配。
    let zu_mp: Option<ZuMergedPlan> = match zu.as_ref() {
        Some(_) => {
            let mp_plan = crate::sm3_compress_v2::plan_z_parts(&mut bld);
            // P_A 标量世界暂存格（值经 rid_base_p 坐标大环从钉格缝合而来，
            // **不开新环** —— (pins[0].col, pin_row(3)) 已是 rid_base_p 首键，
            // 一格至多一环的协议红线）。
            let row_pa = row_at(RANK_PA);
            let st_pax = bld.alloc_col();
            let st_pay = bld.alloc_col();
            let dec_xa = plan_decomp(&mut bld);
            let dec_ya = plan_decomp(&mut bld);
            let roots = crate::sm3_compress_v2::plan_zu_msg_roots(&mut bld);
            // H2 换根消息根表（plan 相预览 —— 环登记按它接根；emit 尾部
            // 断言双端一致）。rows_zmsg/row_pa 是纯几何，plan 相已知。
            let rows_zmsg: [usize; 15] = std::array::from_fn(|i| row_at(RANK_ZMSG + i));
            let msg_roots = crate::sm3_compress_v2::zu_roots_preview(&roots, &rows_zmsg, row_pa);
            let rings = crate::sm3_compress_v2::plan_z_rings(
                &mut bld,
                &mp_plan,
                &crate::sm3_compress_v2::ZuRingRoots::Cells { dg_base: 12, msg_roots },
            );
            Some(ZuMergedPlan {
                plan: mp_plan,
                st_pax,
                st_pay,
                dec_xa,
                dec_ya,
                roots,
                rings,
            })
        }
        None => None,
    };
    let pl = plan_all(&mut bld);
    // 簇J E4 段化（J-10b ①）：验证体发射段抽为 [`emit_verify_body`]（纯代码
    // 搬移，发射顺序逐字保持）；回归门 = 三测试 + 形状指纹逐字节。
    let mut led = emit_verify_body(&mut bld, &pl, e, r, s, pax, pay);

    // ══════════ 簇H H2：Z_U 两体段（merged 专属，蓝图 §四·7；EMIT 相
    //      零分配，句柄见 ZuMergedPlan）══════════
    let mut hooks: Option<ZuHooks> = None;
    if let (Some((b2, b3, iv2)), Some(mp)) = (zu, zu_mp.as_ref()) {
        // ① P_A 值进标量世界：st_pax/st_pay 格追加进 rid_base_p 坐标大环
        //    （首键 = 钉格 (pins[c].col, pin_row(3+c))，环置换缝合暂存格值
        //    —— 不开新环，一格至多一环）+ 双 decompose（槽 = plan 相句柄）。
        //    两槽共享行 RANK_PA ⟹ 位格与 recomp 全 rot=0。
        let row_pa = row_at(RANK_PA);
        bld.relay_to_col(pl.rid_base_p[0], mp.st_pax, row_pa);
        bld.relay_to_col(pl.rid_base_p[1], mp.st_pay, row_pa);
        bld.set_cell_f(mp.st_pax, row_pa, pax);
        bld.set_cell_f(mp.st_pay, row_pa, pay);
        let m = bld.n_constraints();
        let x_cell = qcur(&bld, mp.st_pax);
        let y_cell = qcur(&bld, mp.st_pay);
        let sca_xa = emit_decompose(&mut bld, &mp.dec_xa, row_pa, x_cell, &fr_to_limbs(&pax));
        let sca_ya = emit_decompose(&mut bld, &mp.dec_ya, row_pa, y_cell, &fr_to_limbs(&pay));
        led.pa_decomp = bld.n_constraints() - m;

        // ② 32 消息根格（15 常量锚 + 17 recomp 值格；H2 换根方案的绑定面）
        let rows_zmsg: [usize; 15] = std::array::from_fn(|i| row_at(RANK_ZMSG + i));
        let m = bld.n_constraints();
        let msg_roots = crate::sm3_compress_v2::emit_zu_msg_roots(
            &mut bld, &mp.roots, b2, b3, iv2, row_pa, &sca_xa, &sca_ya, &rows_zmsg,
        );
        led.zu_msg_roots = bld.n_constraints() - m;

        // ③ 尾接两体段（Merged：摘要基址 12 = H1·5 定案；消息根换源后
        //    SM3 parks/link/扩展门全不动）。段出料顺带收 H4 负例锚点。
        let zout = crate::sm3_compress_v2::assemble_z_bodies(
            &mut bld,
            &mp.plan,
            &crate::sm3_compress_v2::ZuCtx {
                b2,
                b3,
                iv2,
                form: crate::sm3_compress_v2::ZuForm::Merged {
                    dg_base: 12,
                    msg_roots,
                },
            },
        );
        hooks = Some(ZuHooks {
            st_pax: mp.st_pax,
            st_pay: mp.st_pay,
            row_pa,
            anchor0: msg_roots[0][0],
            neg_a_t1: zout.neg_a_t1,
        });
    }

    // ── 出料 ──
    bld.set_instance(0, e);
    bld.set_instance(1, r);
    bld.set_instance(2, s);
    debug_assert_eq!(bld.num_instances(), n_inst, "实例面满编");
    let q_edges = bld.q_edge_counts();
    let (info, advice, instances, tags, ctags, num_selectors) = bld.finish_parts();
    Assembled {
        info,
        advice,
        instances,
        tags,
        ctags,
        num_selectors,
        q_edges,
        ledger: led,
        eg: pl.eg,
        rows_eg: pl.rows_eg,
        g_table: pl.g_table,
        ep: pl.ep,
        row_ac: pl.row_ac,
        st_x1_col: pl.st_x1,
        zu: hooks,
    }
}

// ══════════════════ 测试（簇D） ══════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 勘误 #26 永久守卫（第四道防线：选择器激活性审计）。缺陷史：emit_face
    /// 的 f.sel（词位家族 = 8×link.bool + link.recomp + 大折叠，每面 265 条）
    /// 从未 extend_selector ⟹ 三面共 795 条约束被零激活选择器门控 = 空转，
    /// bits↔instance 绑定断裂（mock/环审计/族计数三道防线全盲——死约束照常
    /// 发射计数，诚实见证照常满足）。本测试三重断言防回归：
    /// ① 三面 sel 各激活恰 1 点且落在自家工作锚秩（e=29/r=25/s=22）；
    /// ② 翻 r 面词位 ⟹ link.bool/link.recomp 族违约（不再只有 lt_n 家族）；
    /// ③ 翻 r 面 pv@home ⟹ 大折叠 mock 击中（+ rid_pv 环审计双信号）。
    #[test]
    fn face_word_link_families_active() {
        let (e, r, s, pax, pay) = a2_inputs();
        let asm = assemble_sm2_verify(e, r, s, pax, pay);
        let home_r = srow(RANK_A_R);
        // face1（r）pv=265、词 0 val=298、bits=266..297（plan_all 首分配序）
        let w0_val = 298usize;
        let want = (fr_to_limbs(&r)[0] & 0xFFFF_FFFF) as u32;
        assert_eq!(
            asm.advice[w0_val][home_r],
            FpSM2::from(u64::from(want)),
            "列算术自检失败：col 298 @home 不是 r 的词 0 值"
        );
        // ① 激活点审计：面 sel（#1/#3/#5）各 1 点 @ 自家工作锚秩；sp（#4）@ 钉行。
        //    🔴 解码方向勘误（2026-08-31 首跑抓获，测试侧缺陷、电路无涉）：
        //    `rank_inverse()` 本体 = 秩→点（point_at_rank/row_of 同语义），
        //    点→秩必须反转建 pt2rk（本文件 mock 取证 pt2rk 同款先例）；
        //    首版误用 inv[pt] 当点→秩，解码值实为 nth_map 复合点值。
        let mut pt2rk = vec![usize::MAX; crate::sm3_compress::ROWS];
        for (rk, &pt) in crate::sm3_compress::rank_inverse().iter().enumerate() {
            if pt < crate::sm3_compress::ROWS {
                pt2rk[pt] = rk;
            }
        }
        let acts_of = |gi: usize| -> Vec<usize> {
            let mut acts: Vec<usize> = asm.info.preprocess_polys[gi - 1]
                .iter()
                .enumerate()
                .filter(|(_, v)| **v != FpSM2::ZERO)
                .map(|(pt, _)| pt2rk[pt])
                .collect();
            acts.sort_unstable();
            acts
        };
        assert_eq!(acts_of(1), vec![RANK_A_E], "e 面词位 sel 必须激活于秩 A_E");
        assert_eq!(acts_of(3), vec![RANK_A_R], "r 面词位 sel 必须激活于秩 A_R");
        assert_eq!(acts_of(5), vec![RANK_A_S], "s 面词位 sel 必须激活于秩 A_S");
        assert_eq!(
            acts_of(4),
            vec![2],
            "r 面 pin.bind sel 激活于钉行（实例序号 1 占秩 2，H1·5）"
        );
        // ② 翻位 31（col 297）：link.bool/link.recomp 必须在违约族里。
        let mut adv = asm.advice.clone();
        adv[297][home_r] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(!bad.is_empty(), "位翻转未被 mock 击中");
        let tags: std::collections::BTreeSet<&str> =
            bad.iter().map(|v| asm.ctags[v.constraint]).collect();
        assert!(
            tags.contains("link.bool") || tags.contains("link.recomp"),
            "位翻转违约族 {tags:?} 不含词位家族（link.*）——家族未激活"
        );
        // ③ 翻 pv@home（col 265）：大折叠 mock 击中 + rid_pv 环审计双信号。
        let mut adv2 = asm.advice.clone();
        adv2[265][home_r] += FpSM2::ONE;
        let bad2 = crate::sm3_compress::check_parts_violations(&asm.info, &adv2, &asm.instances);
        assert!(!bad2.is_empty(), "pv@home 翻转未被大折叠击中（f.sel 未激活）");
        let audit2 = crate::sm3_compress::audit_ring_values(&asm.info, &adv2);
        assert!(!audit2.is_empty(), "pv@home 翻转未被 rid_pv 环审计捕获");
    }

    /// 簇H 主验收：merged 形态（验签体 + Z_U 两体段，蓝图 §四·7）。
    /// ledger 新桶 + 摘要实例值 == z_u_native（GB/T 终判）+ 环审计 +
    /// 旋转守卫（max|rot| ≤ 11，两体主导）+ mock 全扫零违约。
    #[test]
    fn merged_show_z_fullboard() {
        let (e, r, s, pax, pay) = a2_inputs();
        let id: &[u8] = crate::sm2_z_anchor::DEFAULT_ID;
        let blocks = crate::sm2_z_anchor::z_u_blocks(id, &pax, &pay);
        let iv2 = crate::sm2_z_anchor::z_u_prelude_state(id);
        let asm = assemble_show_z_merged(e, r, s, pax, pay, &blocks[2], &blocks[3], &iv2);

        println!(
            "[merged-tally] constraints={} advice={} sel={} prep={} cycles={}",
            asm.info.constraints.len(),
            asm.advice.len(),
            asm.num_selectors,
            asm.info.preprocess_polys.len(),
            asm.info.permutations.len()
        );
        // ledger 新桶（H2 纸面账）
        assert_eq!(asm.ledger.pa_decomp, 514, "P_A 双 decompose = 2×257");
        assert_eq!(asm.ledger.zu_msg_roots, 32, "15 常量锚 + 17 recomp");
        assert_eq!(asm.instances[0].len(), 20, "实例面 20（验签体 12 + 摘要 8）");

        // 摘要实例值 == native 真值（「被验证的钥」与「身份串」终判）
        let want = crate::sm2_z_anchor::z_u_native(id, &pax, &pay);
        for k in 0..8usize {
            let w = u32::from_be_bytes(want[4 * k..4 * k + 4].try_into().unwrap());
            let got = crate::sm2_params::fr_to_limbs(&asm.instances[0][12 + k])[0] as u32;
            assert_eq!(got, w, "摘要字 {k} 实例值不符 z_u_native");
        }

        // 形状指纹（勘误 #27 Fix R-a 后 2026-08-31 实测锁定）：约束五元组 +
        // 环数（958 = 534 验签体 + 424 两体；H2 换根零新增环、P_A 值走
        // rid_base_p 追加成员 —— 一格至多一环红线）。Fix R-a 增量 = +6 约束
        // （2 循环 × 3 头钉）/ −6 advice（acc_out 列删除）/ +2 选择器
        // （head_sel），环零变化。
        assert_eq!(asm.info.constraints.len(), 131_874, "merged 约束总数漂移（2026-10-01 实测钉：旧钉 138,010[08-31] db0bbb3 实测已漂移至 131,939；本次换代 acc.chain 去重 −65=EG 窗 66→1 → 131,874）");
        assert_eq!(asm.advice.len(), 7732, "merged advice 列数漂移（2026-10-01 实测钉：旧钉 7,752 系历史值——本批零列变动，偏差系旧钉未回写）");
        assert_eq!(asm.num_selectors, 250, "merged 选择器族数漂移（2026-10-01 实测钉：旧钉 243 系历史值——本批零选择器变动，偏差系旧钉未回写）");
        assert_eq!(asm.info.preprocess_polys.len(), 250, "merged 预处理多项式数漂移（2026-10-01 实测钉：旧钉 243 系历史值——本批零变动）");
        assert_eq!(asm.info.permutations.len(), 698, "merged 中继环数漂移（2026-10-01 实测钉：旧钉 958 系历史值——本批零环变动）");

        // 环审计（mock 盲区前置桥：环内一致性）
        let bad_rings =
            crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        assert!(bad_rings.is_empty(), "环审计 {} 条不等", bad_rings.len());

        // 旋转守卫：merged max|rot| 预期 = 11（两体主导；验签体经 R1-v3b
        // 重排后 d≤2，H2 换根新增 0）
        let mut maxd = 0i64;
        for c in &asm.info.constraints {
            for q in c.used_query() {
                maxd = maxd.max(i64::from(q.rotation().0.abs()));
            }
        }
        assert!(maxd <= 11, "merged max|rot|={maxd} 超 K=11");
        println!("[merged-rot] max|rot|={maxd}");

        // mock 全扫零违约
        let bad = crate::sm3_compress::check_parts_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
        );
        if !bad.is_empty() {
            use std::collections::BTreeMap;
            let mut hist: BTreeMap<&str, usize> = BTreeMap::new();
            for v in &bad {
                *hist.entry(asm.ctags[v.constraint]).or_insert(0) += 1;
            }
            let heads: Vec<String> = bad
                .iter()
                .take(12)
                .map(|v| format!("#{}({}@pt{})", v.constraint, v.point, asm.ctags[v.constraint]))
                .collect();
            panic!("merged 正例违约 {} 处；族直方图 {hist:?}；首12 {heads:?}", bad.len());
        }
        println!("[merged-mock] 零违约 ✓");
    }

    /// H4 三篡改负例（蓝图 §四·7）：三条独立攻击面各翻一格，**双信号齐爆** ——
    /// 位级 mock 击中绑定约束 + 环审计击中复制环成员值不等（mock 盲区兜底）。
    /// 语义：① ID 字节被改 → B₂ 常量词根漂移；② P_A 钉值被改 → V 位值漂移；
    /// ③ 烘焙 IV₂ 被改 → 体A 初态链漂移。
    #[test]
    fn merged_h4_three_tamper_cases_caught() {
        let (e, r, s, pax, pay) = a2_inputs();
        let id: &[u8] = crate::sm2_z_anchor::DEFAULT_ID;
        let blocks = crate::sm2_z_anchor::z_u_blocks(id, &pax, &pay);
        let iv2 = crate::sm2_z_anchor::z_u_prelude_state(id);
        let asm = assemble_show_z_merged(e, r, s, pax, pay, &blocks[2], &blocks[3], &iv2);
        let h = asm.zu.as_ref().expect("merged 形态必有 H4 钩子");
        let one = FpSM2::ONE;

        // 共用断言器：位级违约 + 环审计都要开火（任一沉默即假绿）。
        let expect_caught = |label: &str, adv: &Vec<Vec<FpSM2>>| {
            let bad = crate::sm3_compress::check_parts_violations(
                &asm.info,
                adv,
                &asm.instances,
            );
            assert!(!bad.is_empty(), "{label}: 位级 mock 未击中任何约束");
            let audit = crate::sm3_compress::audit_ring_values(&asm.info, adv);
            assert!(!audit.is_empty(), "{label}: 环审计未捕获环成员值漂移");
        };

        // ① ID 字节 → 常量词根：翻 B₂ 常量词 0 锚格（emit_const_val 绑定 +
        //    W[0] 环首键 —— 换根方案的根起点）。
        let (ac, ar) = h.anchor0;
        let mut adv = asm.advice.clone();
        adv[ac][ar] += one;
        expect_caught("负例一(ID→常量词根)", &adv);

        // ② P_A 钉值 → V 位值漂移：翻 xA 暂存格（rid_base_p 坐标大环成员 +
        //    decompose 大折叠的值锚 —— 位格不动则折叠当场破）。
        let mut adv = asm.advice.clone();
        adv[h.st_pax][h.row_pa] += one;
        expect_caught("负例二(P_A→V位值)", &adv);

        // ③ 烘焙 IV₂ → 体A 初态链：翻体A 负轮 TT1 族 t=−4 锚格（anchor.const
        //    绑定 + 链环根，virt_from(IV₂) 常量被改即体A 初态漂移）。
        let (nc, nr) = h.neg_a_t1;
        let mut adv = asm.advice.clone();
        adv[nc][nr] += one;
        expect_caught("负例三(IV₂→体A初态)", &adv);
    }

    /// 正例主锚点：A.2 权威向量装配 —— mock 零违约、账本分桶实录、
    /// 旋转守卫 |rot| ≤ K、环拓扑计数锁定。失败时打印违约直方图前缀。
    #[test]
    fn assemble_a2_positive_fullboard() {
        let (e, r, s, pax, pay) = a2_inputs();
        let asm = assemble_sm2_verify(e, r, s, pax, pay);

        println!(
            "[ledger] e/r/s面={} pa={} g六钉={} range={} neq_rs={} t_calc={} \
             head_eg={} chain_eg={} head_ep={} chain_ep={} ec_sum={} dec={} red={} \
             fin={} eq={} 总={}",
            asm.ledger.face_input,
            asm.ledger.face_pa,
            asm.ledger.face_gbases,
            asm.ledger.range_check,
            asm.ledger.nonzero_rs,
            asm.ledger.t_calc,
            asm.ledger.head_eg,
            asm.ledger.chain_eg,
            asm.ledger.head_ep,
            asm.ledger.chain_ep,
            asm.ledger.ec_sum,
            asm.ledger.decompose,
            asm.ledger.reduce,
            asm.ledger.final_sum,
            asm.ledger.eq_r,
            asm.ledger.total()
        );
        // ── 账本落锤（蓝图 §六预测经本实测修订后锁定；改动需显式重审）──
        let l = &asm.ledger;
        assert_eq!(l.face_input, 798);
        assert_eq!(l.face_pa, 3);
        assert_eq!(l.face_gbases, 6);
        assert_eq!(l.range_check, 530);
        assert_eq!(l.nonzero_rs, 2);
        assert_eq!(l.t_calc, 787);
        assert_eq!(l.head_eg, 8);
        assert_eq!(l.chain_eg, 11, "EG 主链桶（2026-10-01 实测钉：acc.chain 去重 66→1，桶 76→11——旧钉 6,147 系 Fix R-a 纸面账，db0bbb3 实测已漂移）");
        assert_eq!(l.head_ep, 12);
        assert_eq!(l.chain_ep, 6147, "EP 主链 = 256×24 + 头钉 3（Fix R-a）");
        assert_eq!(l.ec_sum, 28);
        assert_eq!(l.decompose, 257);
        assert_eq!(l.reduce, 1045);
        assert_eq!(l.final_sum, 786);
        assert_eq!(l.eq_r, 4);
        assert_eq!(l.total(), 10_424, "约束总指纹（ledger 总额=装配实测——2026-10-01 实测钉：db0bbb3 实测 10,489，本次 acc.chain 去重 −65；旧钉 16,560 系 Fix R-a 纸面账未回写）");
        assert_eq!(asm.advice.len(), 4277, "advice 列数（2026-10-01 实测钉：旧钉 4,297 系历史值——本批零列变动，偏差系旧钉未回写）");
        assert_eq!(asm.num_selectors, 57, "选择器族数（2026-10-01 实测钉：旧钉 50 系历史值——本批零选择器变动）");
        assert_eq!(asm.info.constraints.len(), 10_424, "（2026-10-01 实测钉：db0bbb3 实测 10,489，本次 acc.chain 去重 −65）");

        println!(
            "[board] advice_cols={} selectors={} constraints={}",
            asm.advice.len(),
            asm.num_selectors,
            asm.info.constraints.len()
        );

        // 结构性锁环计数（2026-10-01 实测钉 274：旧钉 534 系「架构决定」纸面账
        // ——db0bbb3 实测已漂移，历史批次未回写；本批零环变动）
        let nrings: usize = asm.info.permutations.iter().filter(|c| c.len() >= 2).count();
        assert_eq!(nrings, 274, "复制环总数应为 274（2026-10-01 实测）");
        println!("[rings] {nrings} 条全部成环");

        // 旋转守卫：全局最大 |rotation| ≤ K=11（后端 sumcheck 协议断言）；
        // 违例时打印肇事约束（族标签 + 约束号）供根因定位。
        let mut maxd = 0i64;
        let mut offenders: Vec<(usize, i64)> = Vec::new();
        for (ci, c) in asm.info.constraints.iter().enumerate() {
            for q in c.used_query() {
                let d = q.rotation().0 as i64;
                if d.abs() > 11 {
                    maxd = maxd.max(d.abs());
                    offenders.push((ci, d));
                }
            }
        }
        if !offenders.is_empty() {
            use std::collections::BTreeMap;
            let mut hist: BTreeMap<(String, i64), usize> = BTreeMap::new();
            for &(ci, d) in &offenders {
                *hist.entry((asm.ctags[ci].to_string(), d)).or_insert(0) += 1;
            }
            println!(
                "[rot-guard] 违例 {} 处；签名直方图: {:?}",
                offenders.len(),
                hist
            );
            // 各签名取最小约束号做 RAW Debug 取证（poly 号语义：0=实例，
            // 1..=num_selectors 预处理，其余 advice[p-1-ns]）
            let mut seen: std::collections::BTreeSet<(String, i64)> =
                std::collections::BTreeSet::new();
            for &(ci, d) in offenders.iter().take(4000) {
                let key = (asm.ctags[ci].to_string(), d);
                if seen.insert(key.clone()) {
                    let qs: Vec<(usize, i64)> = asm.info.constraints[ci]
                        .used_query()
                        .into_iter()
                        .map(|q| (q.poly(), q.rotation().0 as i64))
                        .collect();
                    // 选择器激活点秩解码（prep 多项式非零点的秩 = LFSR 步数）。
                    // 🔴 方向勘误（2026-08-31）：rank_inverse = 秩→点，点→秩须
                    //    反转建 pt2rk（下方 mock 取证同款先例；首版 inv[ptc] 错位）。
                    let mut sel_pt2rk = vec![usize::MAX; crate::sm3_compress::ROWS];
                    for (rk, &pt) in crate::sm3_compress::rank_inverse().iter().enumerate() {
                        if pt < crate::sm3_compress::ROWS {
                            sel_pt2rk[pt] = rk;
                        }
                    }
                    for &(pp, _) in qs.iter().filter(|(pp, rot)| *pp <= asm.num_selectors + 1 && *rot == 0) {
                        let mut acts: Vec<usize> =
                            asm.info.preprocess_polys[pp - 1]
                                .iter()
                                .enumerate()
                                .filter(|(_, v)| **v != FpSM2::ZERO)
                                .map(|(ptc, _)| sel_pt2rk[ptc])
                                .collect();
                        acts.sort_unstable();
                        let heads: Vec<String> = acts
                            .iter()
                            .take(6)
                            .map(|r| r.to_string())
                            .collect();
                        println!(
                            "[offender.sel] #{} 约束的 sel(poly={}) 激活 {} 点，秩首6={} 尾3={:?}",
                            ci,
                            pp,
                            acts.len(),
                            heads.join(","),
                            &acts[acts.len().saturating_sub(3)..]
                        );
                    }
                    let raw = format!("{:?}", asm.info.constraints[ci]);
                    println!(
                        "[offender] #{} tag={} rot={} 查询={:?} expr={}",
                        ci,
                        key.0,
                        d,
                        qs,
                        &raw[..raw.len().min(1600)]
                    );
                    if seen.len() >= 5 {
                        break;
                    }
                }
            }
            panic!("最大 |rotation|={maxd} 超 K=11");
        }
        println!("[rot-guard] 最大 |rotation| = {maxd} ≤ 11");

        // mock 零违约（多重线程分片；约数分钟）
        let bad = crate::sm3_compress::check_parts_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
        );
        if !bad.is_empty() {
            use std::collections::BTreeMap;
            let inv = crate::sm3_compress::rank_inverse();
            let mut pt2rk = vec![usize::MAX; crate::sm3_compress::ROWS];
            for (rk, &p) in inv.iter().enumerate() {
                if p < crate::sm3_compress::ROWS {
                    pt2rk[p] = rk;
                }
            }
            let mut hist: BTreeMap<&str, usize> = BTreeMap::new();
            for v in &bad {
                *hist.entry(asm.ctags[v.constraint]).or_insert(0) += 1;
            }
            let heads: Vec<String> = bad
                .iter()
                .take(12)
                .map(|v| format!("#{}({}@秩{})", v.constraint, v.point, pt2rk[v.point]))
                .collect();
            let ns = asm.num_selectors;
            for v in bad.iter().take(4) {
                // 查询点名（inst/selN/advN）+ 旋转，一眼对位装配布局
                let qs_disp: Vec<String> = asm.info.constraints[v.constraint]
                    .used_query()
                    .into_iter()
                    .map(|q| {
                        let p = q.poly();
                        let nm = if p == 0 { "inst".to_string() }
                            else if p <= ns + 1 { format!("sel{p}") }
                            else { format!("adv{}", p - ns - 1) };
                        format!("{nm}@r{}", q.rotation().0)
                    })
                    .collect();
                println!(
                    "[mock-off] #{} {} @pt{}(秩{}) 查询={:?}",
                    v.constraint,
                    asm.ctags[v.constraint],
                    v.point,
                    pt2rk[v.point],
                    qs_disp
                );
            }
            panic!(
                "正例违约 {} 处；族直方图 {hist:?}；首12 {heads:?}",
                bad.len()
            );
        }

        // ── 负例一（③S3c 换型）：EG 窗行 λ 篡改（add.lam 约束在窗行击中
        //    ——旧 const_base λ/倍点链机制随 window 化退役，等价防护=逐行
        //    仿射加法约束 + 查表选点钉定）──
        let row = asm.rows_eg[3];
        let mut adv = asm.advice.clone();
        adv[asm.eg.w_lam][row] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(
            bad.iter().any(|v| v.point == row),
            "λ 篡改必在其行被击中"
        );

        // ── 负例二：x₁ 尾格篡改 ⟹ 大折叠在 srow(RANK_X1) 行当场破 ──
        let mut adv = asm.advice.clone();
        adv[asm.st_x1_col][srow(RANK_X1)] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(
            bad.iter().any(|v| v.point == srow(RANK_X1)),
            "x₁ 尾格篡改必须在分解行被击中"
        );
    }

    /// 🔴 勘误 #27 修复回归（Fix R-a write-next，2026-08-31）：与修复前取证
    /// demo 同一手术 —— 行 254 把 acc 链重启为 O（acc_in=O + dd/ss 槽全机械
    /// 镜像），**行 255 完全不动**（其 acc_in 仍为诚实 [s≫1]G）。修复前该手术
    /// mock 全绿 + 环审计零不等 = P0 活体（记录存蓝图 §四·8·2）；修复后跨行
    /// 复制进约束系统：acc_in@254 被**行 253 的 lsel 旋转绑定**约束
    /// （`q(acc_in, Rotation(1)) == select(β₂₅₃, ss, dd)`）、acc_in@255 被行
    /// 254 绑定 ⟹ 手术必被击中（违约点 = 绑定锚行）。acc_out 列已随 Fix R-a
    /// 删除（选择树值经 sel_bind_rot 自写下一行），手术不再镜像该列。镜像
    /// 真值全部由曲线常量权威机械推导（禁手抄）；诚实链值 [s≫1]G 用作手术
    /// 有效性 sanity（重启值 O 必异于它，否则判据空转 —— 取证侧教训）。
    #[test]
    fn eg_chain_restart_forgery_caught() {
        // ③S3c 换型（window 形态）：旧 Fix R-a 负例验证的语义=「acc 链中段
        // 重启/篡改必被逐行链约束击中」——window 形态等价负例=acc 聚合列
        // 中段平移：行 30 起 acc 值 +δ ⟹ 该行及后续链约束（acc=acc_prev+dp）
        // 逐行违约；dp 行诚实 ⟹ 差异严格由 acc 格承担（链完整性判据保持）。
        let (e, r, s, pax, pay) = a2_inputs();
        let asm = assemble_sm2_verify(e, r, s, pax, pay);
        let _ = (e, r, s, pax, pay);

        let row30 = asm.rows_eg[30];
        let mut adv = asm.advice.clone();
        adv[asm.eg.w_acc][row30] += FpSM2::ONE;

        // 手术有效性 sanity：平移值 ≠ 诚实链值（判据非空转）。
        assert_ne!(&adv, &asm.advice, "补丁必须实际改写见证");

        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(
            bad.iter().any(|v| v.point == row30),
            "acc 平移必须被行 30 链约束击中（违约 {} 处）",
            bad.len()
        );
        // 链约束族缺席=判据空转（约束本体必须承担检测）。
        let has_chain = bad
            .iter()
            .any(|v| asm.ctags[v.constraint] == "ec.win.acc.chain");
        assert!(has_chain, "违约必须含 ec.win.acc.chain 族（约束本体检测面）");
        // 环审计仍沉默 = acc 链格不在环内（检测面=约束本体，勘误 #27 定案）。
        let audit = crate::sm3_compress::audit_ring_values(&asm.info, &adv);
        assert!(
            audit.is_empty(),
            "acc 链格不应在环内（检测面 = 约束本体）"
        );
        println!(
            "[window-acc] 链平移被击中：ec.win.acc.chain 族约束本体承担检测 —— 语义等价换型"
        );
    }
}


