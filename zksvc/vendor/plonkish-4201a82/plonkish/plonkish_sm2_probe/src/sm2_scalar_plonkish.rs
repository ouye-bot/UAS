//! SM2 标量域 F_n 外来域算术的 **Plonkish 移植**（M2a `m0_sm3_circuit/src/sm2_scalar.rs`
//! → 自研 Builder 门原语）。理论依据全部承继 M2a 设计 §3：
//!
//! - **为什么必须外来域**：r,s,t,e ∈ F_n，基域 F_p；2n > p ⟹ F_p 加法 wrap 后
//!   减 n ≠ 整数语义。一切 mod-n 走 256 位整数 limbs 方案。
//! - **健全性核心**：位布尔性 + 「值 < 2^k ⟹ 分解唯一」线性等式 —— 任何优化
//!   不得破坏该结构。
//! - **约束计价对照表**（逐件锁指纹，蓝图 §六）：limb 加 66/limb、256 位加 264、
//!   加常数 264、lt_n 265、or 2、and 1、select 位 1/位、add_mod_n 786、
//!   reduce_mod_n 1045、decompose_native 257、eq 4、neq_zero 1。
//!
//! ## 结构约定（相对 R1CS 版的三处显式差异）
//! 1. **两相接口**：Builder 冻结纪律（首推后禁 alloc）⟹ 每 gadget 拆 `plan_*`
//!    （分配列/选择器）与 `emit_*`（发约束+写真值）。顶板装配器先跑完全部
//!    plan 再进入发射段；gadget 内部绝不 alloc。
//! 2. **派生布尔走表达式流转**：进位链、top2 等未物化派生量直接以 `Expression`
//!    参与下游约束 —— 约束数与 M2a 严格一致，省的是无用 witness 格。
//! 3. **标量 = 位横排**：[`PlScalar`] 256 条位 advice 列 × 单一家点；跨行读取经
//!    `rot_between` 自动求旋，近距排布下开口代价 ≈ cur（乘数定律口径）。
//!
//! ## 类型语义
//! `PlScalar.val` 是 256 位整数小端**目击真值**（非规约，中间量可 ≥ p，F 无法
//! 承载）。电路语义只由位布尔性 + 线性等式钉死；`.val` 仅服务目击写入与测试。
//! 负例一律走「装配后篡改格」路径（M2a 同款），emit 层永远写真话见证。

use crate::sm2_params::{add256, fr_from_limbs, pow2_table, q_limbs};
use crate::sm3_compress::{rot_between, Builder};
use crate::FpSM2;
use ff::Field;
use plonkish_backend::util::expression::{Expression, Rotation};

type Fr = FpSM2;

// ══════════════════ 标量表示 ══════════════════

/// 一个 256 位标量的物理形态：256 条位 advice 列 × 家点 `home`（LSB-first 连续），
/// 第 k 个 limb = 位 `[64k, 64k+64)`。
#[derive(Clone, Copy)]
pub struct PlScalar {
    pub cols: [usize; 256],
    pub home: usize,
    /// 目击真值（LSB limbs）。
    pub val: [u64; 4],
}

/// 分配一个标量的 256 条位列（plan 相；家点与真值在 emit 时给定）。
pub fn plan_scalar(b: &mut Builder<Fr>) -> [usize; 256] {
    std::array::from_fn(|_| b.alloc_col())
}

/// 组装句柄。
pub fn scalar(cols: [usize; 256], home: usize, val: [u64; 4]) -> PlScalar {
    PlScalar { cols, home, val }
}

/// 把 `.val` 的位写入全部位列（装配器必须调用：val ↔ 格一致性的唯一入口）。
pub fn write_scalar_bits(b: &mut Builder<Fr>, s: &PlScalar) {
    for i in 0..256 {
        let bit = ((s.val[i / 64] >> (i % 64)) & 1) as u32;
        b.set_cell_u32(s.cols[i], s.home, bit);
    }
}

/// 空 plan 用的选择器（激活点延后 extend）。
pub fn plan_sel(b: &mut Builder<Fr>) -> usize {
    b.alloc_selector(&[])
}

// ══════════════════ 表达式辅助 ══════════════════

/// 在激活行 `at` 上读源标量第 i 位（跨行自动求旋）。
fn bq(b: &Builder<Fr>, s: &PlScalar, i: usize, at: usize) -> Expression<Fr> {
    b.q(s.cols[i], rot_between(at, s.home))
}

/// 本行 @at 的格查询（调用方保证该格写入于同一行）。
fn cq(b: &Builder<Fr>, col: usize) -> Expression<Fr> {
    b.q(col, Rotation::cur())
}

/// Σ_{k<len} 2^(lo+k)·bit_{lo+k}：源标量片段的展开 LC（在 at 上求值）。
fn lc_range(b: &Builder<Fr>, s: &PlScalar, lo: usize, len: usize, at: usize) -> Expression<Fr> {
    let t = pow2_table();
    let mut acc = Expression::<Fr>::zero();
    for k in 0..len {
        acc = acc + Expression::<Fr>::Constant(t[lo + k].clone()) * bq(b, s, lo + k, at);
    }
    acc
}

/// 全 256 位展开 LC。
fn lc_full(b: &Builder<Fr>, s: &PlScalar, at: usize) -> Expression<Fr> {
    lc_range(b, s, 0, 256, at)
}

fn put_bit(b: &mut Builder<Fr>, col: usize, at: usize, bit: bool) {
    b.set_cell_u32(col, at, bit as u32);
}

// ══════════════════ 小门（or / and） ══════════════════

/// OR 的槽：积格 p + 输出格 o（都布了 bool 于 emit 内 —— p 由代数强制 ∈{0,1}，
/// 与 M2a 一致不给额外布尔化之外的形式……实际上为稳妥两者都过 emit_bool：
/// 这正是 2 约束口径的一部分？不——M2a 计数 or=2（积+线性），不加第三条。
/// 故 o/p 不单独发布尔约束，其 ∈{0,1} 完全由代数保证（M2a 设计 §3 论证承继）。
#[derive(Clone, Copy)]
pub struct OrSlots {
    pub sel: usize,
    pub p: usize,
    pub o: usize,
}

pub fn plan_or(b: &mut Builder<Fr>) -> OrSlots {
    OrSlots { sel: plan_sel(b), p: b.alloc_col(), o: b.alloc_col() }
}

/// 发射 OR：`p=a·b`（积）与 `a+b=o+p`（线性），共 2 推；返回 o 的表达式。
pub fn emit_or(
    b: &mut Builder<Fr>,
    sl: &OrSlots,
    at: usize,
    a: &Expression<Fr>,
    av: bool,
    y: &Expression<Fr>,
    yv: bool,
) -> Expression<Fr> {
    b.extend_selector(sl.sel, &[at]);
    put_bit(b, sl.p, at, av && yv);
    put_bit(b, sl.o, at, av || yv);
    // p = a·b
    b.emit_prod_eq(sl.sel, a.clone(), y.clone(), cq(b, sl.p));
    // a + b − o − p = 0
    b.emit_assert_zero(
        sl.sel,
        a.clone() + y.clone() - cq(b, sl.o) - cq(b, sl.p),
    );
    cq(b, sl.o)
}

/// AND 的槽：结果物化一位（作 o 之外的系数用更直观；M2a 只回表达式，
/// 这里物化的代价只是 1 列，消费端表达式统一走格查询）。
#[derive(Clone, Copy)]
pub struct AndSlots {
    pub sel: usize,
    pub t: usize,
}

pub fn plan_and(b: &mut Builder<Fr>) -> AndSlots {
    AndSlots { sel: plan_sel(b), t: b.alloc_col() }
}

/// 发射 AND：单推积等式；返回 t 表达式。
pub fn emit_and(
    b: &mut Builder<Fr>,
    sl: &AndSlots,
    at: usize,
    a: &Expression<Fr>,
    av: bool,
    y: &Expression<Fr>,
    yv: bool,
) -> Expression<Fr> {
    b.extend_selector(sl.sel, &[at]);
    put_bit(b, sl.t, at, av && yv);
    b.emit_prod_eq(sl.sel, a.clone(), y.clone(), cq(b, sl.t));
    cq(b, sl.t)
}

// ══════════════════ 256 位带进位加法（含加常数形态） ══════════════════

/// 进位链加法的槽：输出标量 + 逐 limb 进位格（首个 cin 恒为常数 0，无格）。
#[derive(Clone, Copy)]
pub struct AddSlots {
    pub sel: usize,
    pub out: [usize; 256],
    pub couts: [usize; 4],
}

pub fn plan_add(b: &mut Builder<Fr>) -> AddSlots {
    AddSlots {
        sel: plan_sel(b),
        out: plan_scalar(b),
        couts: std::array::from_fn(|_| b.alloc_col()),
    }
}

/// 第二操作数：标量引用 或 常数 limbs。
enum Src<'a> {
    Scalar(&'a PlScalar),
    Const(&'a [u64; 4]),
}

impl<'a> Src<'a> {
    fn val(&self) -> [u64; 4] {
        match self {
            Src::Scalar(s) => s.val,
            Src::Const(k) => **k,
        }
    }
}

/// 统一发射：`A + B + cin₀ = S + 2⁶⁴·c₄`（每 limb 一条线性等式 + 64 条输出
/// 位布尔 + 1 条进位布尔 = 66 推，×4 = **264**）。首个 cin 为常数 0。
/// 见证永远写真话（由 a.val/b.val 逐步重算），负例一律走装配后篡改路径。
/// 返回 (输出标量, 顶层进位表达式, 顶层进位真值)。
fn emit_add_impl(
    b: &mut Builder<Fr>,
    sl: &AddSlots,
    at: usize,
    a: &PlScalar,
    second: Src<'_>,
) -> (PlScalar, Expression<Fr>, bool) {
    b.extend_selector(sl.sel, &[at]);
    let (sum, cout_top) = add256(&a.val, &second.val());
    let mut cin = Expression::<Fr>::zero();
    let mut cin_v = false;
    for k in 0..4 {
        // 本 limb 输出进位真值：独立重算，不依赖链中间量（防推导漂移）。
        let wide = a.val[k] as u128 + second.val()[k] as u128 + cin_v as u128;
        let cw = (wide >> 64) == 1;
        // 和数位格见证必须显式写入（M2a 中由 add_limb_with_carry 分配变量承担）
        for j in 0..64 {
            put_bit(b, sl.out[64 * k + j], at, (sum[k] >> j) & 1 == 1);
        }
        put_bit(b, sl.couts[k], at, cw);

        // limb 线性等式：lcA_k + lcB_k + cin − lcS_k − 2⁶⁴·c_{k+1} = 0。
        // 权重必须用 **limb 局部幂 t[j]**（M2a 链单位语义：cin 是裸格读，
        // 只有跨 limb 进位以 2⁶⁴ 进位）。若误用全局位幂 t[64k+j]，等于把
        // 第 k 条方程错乘 2⁶⁴ᵏ 而 cin 不动 —— 凡 cin 或 cout 项非零的 limb
        // 必然违约（b2 装配实测抓到；256 位大折叠场景才用全局幂，见
        // emit_decompose / emit_neq_zero 的 lc_full）。
        let t = pow2_table();
        let ra = rot_between(at, a.home);
        let mut la = Expression::<Fr>::zero();
        for j in 0..64 {
            la = la
                + Expression::<Fr>::Constant(t[j].clone()) * b.q(a.cols[64 * k + j], ra);
        }
        let mut lb = Expression::<Fr>::zero();
        match &second {
            Src::Scalar(s2) => {
                let rb = rot_between(at, s2.home);
                for j in 0..64 {
                    lb = lb
                        + Expression::<Fr>::Constant(t[j].clone())
                            * b.q(s2.cols[64 * k + j], rb);
                }
            }
            Src::Const(c) => {
                for j in 0..64 {
                    if (c[k] >> j) & 1 == 1 {
                        lb = lb + Expression::<Fr>::Constant(t[j].clone());
                    }
                }
            }
        }
        let mut ls = Expression::<Fr>::zero();
        for j in 0..64 {
            ls = ls
                + Expression::<Fr>::Constant(t[j].clone())
                    * cq(b, sl.out[64 * k + j]);
        }
        let w64 = Expression::<Fr>::Constant(t[64].clone());
        b.emit_assert_zero(sl.sel, la + lb + cin - ls - w64 * cq(b, sl.couts[k]));

        for j in 0..64 {
            b.emit_bool(sl.sel, sl.out[64 * k + j]);
        }
        b.emit_bool(sl.sel, sl.couts[k]);

        cin = cq(b, sl.couts[k]);
        cin_v = cw;
    }
    (scalar(sl.out, at, sum), cq(b, sl.couts[3]), cout_top)
}

/// 标量 + 标量（M2a `limb_add` 同构）：**264** 推。
pub fn limb_add(
    b: &mut Builder<Fr>,
    sl: &AddSlots,
    at: usize,
    a: &PlScalar,
    b2: &PlScalar,
) -> (PlScalar, Expression<Fr>, bool) {
    emit_add_impl(b, sl, at, a, Src::Scalar(b2))
}

/// 标量 + 常数 limbs（M2a 加 q / 加 n 形态）：**264** 推。
pub fn add_const(
    b: &mut Builder<Fr>,
    sl: &AddSlots,
    at: usize,
    a: &PlScalar,
    k: &[u64; 4],
) -> (PlScalar, Expression<Fr>, bool) {
    emit_add_impl(b, sl, at, a, Src::Const(k))
}

// ══════════════════ 按位选择（256 推） ══════════════════

/// 选择门的槽：256 个结果位格。条件位不在此物化 —— 直接收表达式
/// （典型来源是 [`emit_or`] 的返回值），其布尔真值由调用方经 `cv` 传入。
#[derive(Clone, Copy)]
pub struct SelSlots {
    pub sel: usize,
    pub out: [usize; 256],
}

pub fn plan_sel_bits(b: &mut Builder<Fr>) -> SelSlots {
    SelSlots { sel: plan_sel(b), out: plan_scalar(b) }
}

/// 发射按位选择 `out = fls + cond·(tru − fls)`：每位一条二次积等式
/// `cond·(t_j − f_j) = out_j − f_j`，共 **256** 推。out 的布尔性由
/// cond ∈ {0,1} 与两侧位布尔代数蕴含（M2a `select_scalar` 同构，不加第三条）。
pub fn emit_select(
    b: &mut Builder<Fr>,
    sl: &SelSlots,
    at: usize,
    cond: &Expression<Fr>,
    cv: bool,
    tru: &PlScalar,
    fls: &PlScalar,
) -> PlScalar {
    b.extend_selector(sl.sel, &[at]);
    let picked = if cv { tru.val } else { fls.val };
    for j in 0..256 {
        put_bit(b, sl.out[j], at, (picked[j / 64] >> (j % 64)) & 1 == 1);
        let tj = bq(b, tru, j, at);
        let fj = bq(b, fls, j, at);
        let ov = cq(b, sl.out[j]);
        b.emit_prod_eq(sl.sel, cond.clone(), tj - fj.clone(), ov - fj);
    }
    scalar(sl.out, at, picked)
}

/// lt_n 门：断言 `x + q` 不溢出 256 位（q = 2²⁵⁶ − n ⟹ 无溢出 ⟺ x < n），
/// 即在 [`add_const`] 的 264 之上追加「顶层进位恒零」单推 = **265**。
/// 返回 (和标量, flag = 1 − 溢出进位)：flag 为 M2a 返回形态的保真移植，
/// 当前验签流不消费它，留给需要显式谓词位的组装者。违规即不可满足
/// （诚实见证由真值重算，x ≥ n 时顶层进位必为 1）。
pub fn emit_lt_n(
    b: &mut Builder<Fr>,
    sl: &AddSlots,
    at: usize,
    x: &PlScalar,
    q: &[u64; 4],
) -> (PlScalar, Expression<Fr>) {
    let (sum_s, top_e, _top_v) = add_const(b, sl, at, x, q);
    let flag = Expression::<Fr>::one() - top_e.clone();
    b.emit_assert_zero(sl.sel, top_e);
    (sum_s, flag)
}

/// `t = (a+b) mod n`：limb_add(264) + add_const(q)(264) + or(2) + select(256)
/// = **786** 推。前置 a,b < n；结构保证 t ∈ [0,n)（分情形论证承继 M2a §3.4：
/// c4=1 ⟹ S_lo<n、c4=0∧cT=1 ⟹ t=S−n、c4=0∧cT=0 ⟹ t=S）。
/// `add_or` 槽服务第一条 limb_add，`const_or` 服务加 q，`or` 装 o 位，
/// `sel` 出结果 —— 四槽须由 plan 方预分配并在此传齐。
pub struct AddModNSlots {
    pub add_a: AddSlots,
    pub add_q: AddSlots,
    pub or: OrSlots,
    pub sel: SelSlots,
}

pub fn plan_add_mod_n(b: &mut Builder<Fr>) -> AddModNSlots {
    AddModNSlots {
        add_a: plan_add(b),
        add_q: plan_add(b),
        or: plan_or(b),
        sel: plan_sel_bits(b),
    }
}

pub fn emit_add_mod_n(
    b: &mut Builder<Fr>,
    at: usize,
    sl: &AddModNSlots,
    a: &PlScalar,
    bb: &PlScalar,
) -> PlScalar {
    let (s_lo, c4_e, c4_v) = limb_add(b, &sl.add_a, at, a, bb);
    let (t_lo, ct_e, ct_v) = add_const(b, &sl.add_q, at, &s_lo, &q_limbs());
    let o_e = emit_or(b, &sl.or, at, &c4_e, c4_v, &ct_e, ct_v);
    emit_select(b, &sl.sel, at, &o_e, c4_v || ct_v, &t_lo, &s_lo)
}

/// `R = (S + top·2^256) mod n`：两步条件减 = add(264)+or(2)+sel(256)+and(1)
/// +add(264)+or(2)+sel(256) = **1045** 推。前置 S < 2^256、top ∈ {0,1}。
/// **top2 = top ∧ c1_raw 修正项必须保留**（M2a 设计 §3.5）：缺它时
/// 「S ≥ n 且 top=1」情形（需减两次 n）给出错误残差。
pub struct ReduceSlots {
    pub add_q1: AddSlots,
    pub or1: OrSlots,
    pub sel1: SelSlots,
    pub and_: AndSlots,
    pub add_q2: AddSlots,
    pub or2: OrSlots,
    pub sel2: SelSlots,
}

pub fn plan_reduce_mod_n(b: &mut Builder<Fr>) -> ReduceSlots {
    ReduceSlots {
        add_q1: plan_add(b),
        or1: plan_or(b),
        sel1: plan_sel_bits(b),
        and_: plan_and(b),
        add_q2: plan_add(b),
        or2: plan_or(b),
        sel2: plan_sel_bits(b),
    }
}

pub fn emit_reduce_mod_n(
    b: &mut Builder<Fr>,
    at: usize,
    sl: &ReduceSlots,
    s: &PlScalar,
    top: &Expression<Fr>,
    top_v: bool,
) -> PlScalar {
    // Step A：c1 = c1_raw ∨ top ⟺ V = S + top·2^256 ≥ n；R1 = V − n（mod 2^256）
    let (t1_lo, c1r_e, c1r_v) = add_const(b, &sl.add_q1, at, s, &q_limbs());
    let c1_e = emit_or(b, &sl.or1, at, &c1r_e, c1r_v, top, top_v);
    let r1 = emit_select(b, &sl.sel1, at, &c1_e, c1r_v || top_v, &t1_lo, s);
    // Step B：V−n 的第 257 位仅当 top=1 ∧ S≥n 出现（top2），再条件减一次
    let top2_e = emit_and(b, &sl.and_, at, top, top_v, &c1r_e, c1r_v);
    let (t2_lo, c2r_e, c2r_v) = add_const(b, &sl.add_q2, at, &r1, &q_limbs());
    let c2_e = emit_or(b, &sl.or2, at, &c2r_e, c2r_v, &top2_e, top_v && c1r_v);
    emit_select(b, &sl.sel2, at, &c2_e, c2r_v || (top_v && c1r_v), &t2_lo, &r1)
}

// ══════════════════ 分解 / 相等 / 非零 ══════════════════

/// 分解槽：输出 256 位标量格 + 布尔/折叠共用选择器。
#[derive(Clone, Copy)]
pub struct DecompSlots {
    pub sel: usize,
    pub out: [usize; 256],
}

pub fn plan_decomp(b: &mut Builder<Fr>) -> DecompSlots {
    DecompSlots { sel: plan_sel(b), out: plan_scalar(b) }
}

/// 把线性表达式 `x` 分解为 256 位标量：256 条位布尔 + 1 条大折叠
/// Σ bits·2^i − x = 0，共 **257** 推。bits 已布尔 ⟹ 折叠等式解唯一
/// （系数 ∈ {−1,0,1} 无 wrap 分解，M2a 论证承继）。前置 x < p。
pub fn emit_decompose(
    b: &mut Builder<Fr>,
    sl: &DecompSlots,
    at: usize,
    x: Expression<Fr>,
    xv: &[u64; 4],
) -> PlScalar {
    b.extend_selector(sl.sel, &[at]);
    let t = pow2_table();
    let mut fold = Expression::<Fr>::zero();
    for i in 0..256 {
        put_bit(b, sl.out[i], at, (xv[i / 64] >> (i % 64)) & 1 == 1);
        b.emit_bool(sl.sel, sl.out[i]);
        fold = fold + Expression::<Fr>::Constant(t[i].clone()) * cq(b, sl.out[i]);
    }
    b.emit_assert_zero(sl.sel, fold - x);
    scalar(sl.out, at, *xv)
}

/// 相等断言槽（仅选择器）。
#[derive(Clone, Copy)]
pub struct EqSlots {
    pub sel: usize,
}

pub fn plan_eq(b: &mut Builder<Fr>) -> EqSlots {
    EqSlots { sel: plan_sel(b) }
}

/// 断言两标量逐 limb 相等：4 条线性差恒零 = **4** 推。位均已布尔 ⟹
/// 每条差的解唯一为该 limb 逐位相等（值 < 2^64 < p，无 wrap）。
pub fn emit_eq(b: &mut Builder<Fr>, sl: &EqSlots, at: usize, a: &PlScalar, bb: &PlScalar) {
    b.extend_selector(sl.sel, &[at]);
    for k in 0..4 {
        let da = lc_range(b, a, 64 * k, 64, at);
        let db = lc_range(b, bb, 64 * k, 64, at);
        b.emit_assert_zero(sl.sel, da - db);
    }
}

/// 非零断言槽：逆元见证列 + 选择器。
#[derive(Clone, Copy)]
pub struct NeqSlots {
    pub sel: usize,
    pub inv: usize,
}

pub fn plan_neq(b: &mut Builder<Fr>) -> NeqSlots {
    NeqSlots { sel: plan_sel(b), inv: b.alloc_col() }
}

/// 断言标量非零：lc_full(x)·inv = 1，**1** 推。x = 0 时无逆 ⟹ witness 侧写
/// inv = 0 后约束不可满足（乘法逆不存在的代数事实，承继 M2a）。
/// inv 以 F 元素承载（要求 x < p；此前提下 F_p 求逆与整数求逆一致）。
pub fn emit_neq_zero(b: &mut Builder<Fr>, sl: &NeqSlots, at: usize, x: &PlScalar) {
    b.extend_selector(sl.sel, &[at]);
    let xf = fr_from_limbs(&x.val);
    let inv_val = xf.invert().unwrap_or(Fr::ZERO);
    b.set_cell_f(sl.inv, at, inv_val);
    b.emit_prod_eq(
        sl.sel,
        lc_full(b, x, at),
        cq(b, sl.inv),
        Expression::<Fr>::one(),
    );
}

// ══════════════════ 测试（边界矩阵逐条承继 M2a；负例 = 直接喂坏值，
//                       见证诚实推导 ⟹ 对应约束自然不可满足） ══════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_params::n_limbs;
    use crate::sm3_compress::point_at_rank;

    const TWO_POW_255: [u64; 4] = [0, 0, 0, 0x8000_0000_0000_0000];
    const MAX256: [u64; 4] = [u64::MAX; 4];

    fn sub1(a: [u64; 4]) -> [u64; 4] {
        let mut v = a;
        for l in v.iter_mut() {
            if *l > 0 {
                *l -= 1;
                return v;
            }
            *l = u64::MAX;
        }
        v
    }

    /// 在秩 r 的点布置一个输入标量（写位见证，零约束）。
    fn scalar_at(b: &mut Builder<Fr>, rank: usize, val: &[u64; 4]) -> PlScalar {
        let cols = plan_scalar(b);
        let s = scalar(cols, point_at_rank(rank), *val);
        write_scalar_bits(b, &s);
        s
    }

    /// 出料后读回一个标量的位见证真值。
    fn read_scalar(advice: &[Vec<Fr>], s: &PlScalar) -> [u64; 4] {
        let mut v = [0u64; 4];
        for i in 0..256 {
            if advice[s.cols[i]][s.home] == Fr::ONE {
                v[i / 64] |= 1 << (i % 64);
            }
        }
        v
    }

    fn expect_clean(
        info: &plonkish_backend::backend::PlonkishCircuitInfo<Fr>,
        advice: &[Vec<Fr>],
        instances: &[Vec<Fr>],
    ) {
        let bad = crate::sm3_compress::check_parts_violations(info, advice, instances);
        assert!(bad.is_empty(), "正例不得有违约，首条 {bad:?}");
    }

    // ── limb_add 三态 ──

    #[test]
    fn port_limb_add_no_carry() {
        let mut b = Builder::<Fr>::new(0);
        let ga = scalar_at(&mut b, 1, &[5, 0, 0, 0]);
        let gb = scalar_at(&mut b, 2, &[7, 0, 0, 0]);
        let slots = plan_add(&mut b);
        let (s, _c, cv) = limb_add(&mut b, &slots, point_at_rank(6), &ga, &gb);
        assert_eq!(s.val, [12, 0, 0, 0]);
        assert!(!cv);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
    }

    #[test]
    fn port_limb_add_full_wrap() {
        // 2^256−1 + 1 = 0，顶层进位 1（256 位环绕）
        let mut b = Builder::<Fr>::new(0);
        let ga = scalar_at(&mut b, 1, &MAX256);
        let gb = scalar_at(&mut b, 2, &[1, 0, 0, 0]);
        let slots = plan_add(&mut b);
        let (s, _c, cv) = limb_add(&mut b, &slots, point_at_rank(6), &ga, &gb);
        assert_eq!(s.val, [0; 4]);
        assert!(cv);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
    }

    #[test]
    fn port_limb_add_cross_limb_carry() {
        // limb0 溢出 → limb1 收进位
        let mut b = Builder::<Fr>::new(0);
        let ga = scalar_at(&mut b, 1, &[u64::MAX, 0x1234, 0, 0]);
        let gb = scalar_at(&mut b, 2, &[1, 0, 0, 0]);
        let slots = plan_add(&mut b);
        let (s, _c, cv) = limb_add(&mut b, &slots, point_at_rank(6), &ga, &gb);
        assert_eq!(s.val, [0, 0x1235, 0, 0], "进位必须进到 limb1");
        assert!(!cv);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
    }

    #[test]
    fn port_limb_add_constraint_count_264() {
        let mut b = Builder::<Fr>::new(0);
        let ga = scalar_at(&mut b, 1, &[1, 2, 3, 4]);
        let gb = scalar_at(&mut b, 2, &[5, 6, 7, 8]);
        let slots = plan_add(&mut b);
        let e0 = b.n_constraints();
        let _ = limb_add(&mut b, &slots, point_at_rank(6), &ga, &gb);
        assert_eq!(b.n_constraints() - e0, 264, "limb_add = 4×66");
    }

    // ── add_const 形态（经 lt_n 覆盖其计数与正确性） ──

    #[test]
    fn port_lt_n_accepts_below_and_zero_counts_265() {
        let mut b = Builder::<Fr>::new(0);
        let gn1 = scalar_at(&mut b, 1, &sub1(n_limbs()));
        let gz = scalar_at(&mut b, 2, &[0; 4]);
        // 两套槽先于发射分配（冻结纪律）
        let s1 = plan_add(&mut b);
        let s2 = plan_add(&mut b);
        let e0 = b.n_constraints();
        let (_t1, f1) = emit_lt_n(&mut b, &s1, point_at_rank(6), &gn1, &q_limbs());
        let (_t2, f2) = emit_lt_n(&mut b, &s2, point_at_rank(7), &gz, &q_limbs());
        assert_eq!(b.n_constraints() - e0, 530, "两次 lt_n = 265×2");
        let _ = (f1, f2);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
    }

    #[test]
    fn port_lt_n_rejects_equal_n() {
        // x = n ⟹ x + q 溢出 ⟹ 顶层进位=1 与恒零断言冲突
        let mut b = Builder::<Fr>::new(0);
        let gx = scalar_at(&mut b, 1, &n_limbs());
        let slots = plan_add(&mut b);
        let _ = emit_lt_n(&mut b, &slots, point_at_rank(6), &gx, &q_limbs());
        let (info, advice, inst, _, _, _) = b.finish_parts();
        let bad = crate::sm3_compress::check_parts_violations(&info, &advice, &inst);
        assert!(!bad.is_empty(), "x = n 必须被拒");
    }

    #[test]
    fn port_lt_n_top_carry_truth_honest_below_n() {
        // n−1 的加 q 无溢出：顶层进位真值必须为 false（返回值面核对）
        let mut b = Builder::<Fr>::new(0);
        let gn1 = scalar_at(&mut b, 1, &sub1(n_limbs()));
        let slots = plan_add(&mut b);
        let (_, _c_e, c_v) = add_const(&mut b, &slots, point_at_rank(6), &gn1, &q_limbs());
        assert!(!c_v);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
    }

    // ── add_mod_n 四例 ──

    #[test]
    fn port_add_mod_n_simple_and_wraps() {
        let mut b = Builder::<Fr>::new(0);
        let ga = scalar_at(&mut b, 1, &[5, 0, 0, 0]);
        let gb = scalar_at(&mut b, 2, &[3, 0, 0, 0]);
        let nm1 = scalar_at(&mut b, 3, &sub1(n_limbs()));
        // 两个调用各一套槽，先全部分配再发射
        let sl1 = plan_add_mod_n(&mut b);
        let sl2 = plan_add_mod_n(&mut b);
        let t1 = emit_add_mod_n(&mut b, point_at_rank(6), &sl1, &ga, &gb);
        assert_eq!(t1.val, [8, 0, 0, 0]);
        // (n−1)+(n−1) = 2n−2 ≥ p（基域会 wrap）→ 必须 n−2（mod-n 关键用例）
        let t2 = emit_add_mod_n(&mut b, point_at_rank(7), &sl2, &nm1, &nm1);
        assert_eq!(t2.val, sub1(sub1(n_limbs())), "(n−1)+(n−1) mod n = n−2");
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
    }

    #[test]
    fn port_add_mod_n_zero_and_past_2pow256() {
        let mut b = Builder::<Fr>::new(0);
        let nm1 = scalar_at(&mut b, 1, &sub1(n_limbs()));
        let one = scalar_at(&mut b, 2, &[1, 0, 0, 0]);
        let p255 = scalar_at(&mut b, 3, &TWO_POW_255);
        let sl1 = plan_add_mod_n(&mut b);
        let sl2 = plan_add_mod_n(&mut b);
        let t1 = emit_add_mod_n(&mut b, point_at_rank(6), &sl1, &nm1, &one);
        assert_eq!(t1.val, [0; 4], "(n−1)+1 mod n = 0");
        // 2^255+2^255 = 2^256 → c4=1（S_lo=0），t = q
        let t2 = emit_add_mod_n(&mut b, point_at_rank(7), &sl2, &p255, &p255);
        assert_eq!(t2.val, q_limbs(), "2^256 mod n = q");
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
    }

    #[test]
    fn port_add_mod_n_constraint_count_786() {
        let mut b = Builder::<Fr>::new(0);
        let ga = scalar_at(&mut b, 1, &[1, 2, 3, 4]);
        let gb = scalar_at(&mut b, 2, &[5, 6, 7, 8]);
        let sl = plan_add_mod_n(&mut b);
        let e0 = b.n_constraints();
        let _ = emit_add_mod_n(&mut b, point_at_rank(6), &sl, &ga, &gb);
        assert_eq!(b.n_constraints() - e0, 786, "264+264+2+256");
    }

    // ── reduce_mod_n 八边界（M2a 显式断言表全量承继）──

    #[test]
    fn port_reduce_boundaries_exact_table_and_count_1045() {
        let q = q_limbs();
        let n = n_limbs();

        let mut b = Builder::<Fr>::new(0);
        let inputs: Vec<[u64; 4]> = vec![
            sub1(n),
            sub1(n),
            [0; 4],
            MAX256,
            n,
            sub1(add256(&n, &n).0),
            add256(&n, &n).0,
            MAX256,
        ];
        let tops = [false, true, true, true, false, true, true, false];
        let scalars: Vec<PlScalar> = inputs
            .iter()
            .enumerate()
            .map(|(i, v)| scalar_at(&mut b, 1 + i % 4, v))
            .collect();
        let all_slots: Vec<ReduceSlots> =
            (0..inputs.len()).map(|_| plan_reduce_mod_n(&mut b)).collect();

        // 期望值表（承继 M2a 注释）
        let qm1 = sub1(q);
        let wants: Vec<[u64; 4]> = vec![
            sub1(n),                 // n−1
            qm1,                     // n−1+2^256 = q−1
            q,                       // 2^256 = q
            sub1(add256(&q, &q).0),  // 2^257−1 = 2q−1（两步上限）
            [0; 4],                  // n = 0
            sub1(n),                 // 2n−1 = n−1
            [0; 4],                  // 2n = 0
            qm1,                     // 2^256−1 = q−1
        ];

        let e0 = b.n_constraints();
        for i in 0..inputs.len() {
            let top = tops[i];
            let top_e = Expression::<Fr>::Constant(Fr::from(top as u64));
            let r =
                emit_reduce_mod_n(&mut b, point_at_rank(9), &all_slots[i], &scalars[i], &top_e, top);
            assert_eq!(r.val, wants[i], "case {i}: S={:?} top={top}", inputs[i]);
        }
        assert_eq!(
            b.n_constraints() - e0,
            inputs.len() * 1045,
            "每调用恰 1045（2×264 + 2×256 + 2×or + and）"
        );
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
    }

    // ── select 方向核对 ──

    #[test]
    fn port_select_picks_requested_branch_both_ways() {
        let mut b = Builder::<Fr>::new(0);
        let gt = scalar_at(&mut b, 1, &[0xAABB, 1, 2, 3]);
        let gf = scalar_at(&mut b, 2, &[0x1122, 4, 5, 6]);
        let c_true = Expression::<Fr>::Constant(Fr::ONE);
        let c_false = Expression::<Fr>::Constant(Fr::ZERO);
        let s1 = plan_sel_bits(&mut b);
        let s2 = plan_sel_bits(&mut b);
        let o1 = emit_select(&mut b, &s1, point_at_rank(6), &c_true.clone(), true, &gt, &gf);
        let o2 = emit_select(&mut b, &s2, point_at_rank(7), &c_false.clone(), false, &gt, &gf);
        assert_eq!(o1.val, gt.val);
        assert_eq!(o2.val, gf.val);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
        assert_eq!(read_scalar(&advice, &o1), gt.val, "true 支路");
        assert_eq!(read_scalar(&advice, &o2), gf.val, "false 支路");
    }

    // ── or / and 计数与正确性 ──

    #[test]
    fn port_or_and_counts_and_truth() {
        let mut b = Builder::<Fr>::new(0);
        // 纪律（本测试的目的之一）：每个门调用一套槽、单点家族 —— 输入列是
        // 调用专属的，跨锚点共享家族会在异行读到空输入格（结构性误用）。
        let po1 = plan_or(&mut b);
        let po2 = plan_or(&mut b);
        let pa = plan_and(&mut b);
        // 输入位格：三行各一对（x,y）∈ {(1,0),(1,1),(0,1)}
        let xr = [point_at_rank(3), point_at_rank(4), point_at_rank(5)];
        let xcols: Vec<(usize, usize)> = (0..3)
            .map(|i| {
                let cx = b.alloc_col();
                let cy = b.alloc_col();
                write_bit_pair(&mut b, cx, cy, xr[i], [(true, false), (true, true), (false, true)][i]);
                (cx, cy)
            })
            .collect();
        let e0 = b.n_constraints();
        // 借用纪律：表达式先落局部量，再交 &mut 调用（E0502 回避）
        let xy00 = b.q(xcols[0].0, Rotation::cur());
        let xy01 = b.q(xcols[0].1, Rotation::cur());
        let xy10 = b.q(xcols[1].0, Rotation::cur());
        let xy11 = b.q(xcols[1].1, Rotation::cur());
        let xy20 = b.q(xcols[2].0, Rotation::cur());
        let xy21 = b.q(xcols[2].1, Rotation::cur());
        let _o1 = emit_or(&mut b, &po1, xr[0], &xy00, true, &xy01, false);
        let _o2 = emit_or(&mut b, &po2, xr[1], &xy10, true, &xy11, true);
        let _a1 = emit_and(&mut b, &pa, xr[2], &xy20, false, &xy21, true);
        assert_eq!(b.n_constraints() - e0, 5, "or×2 各 2 推、and 单推");
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
        // 单点家族自检：三个选择器各恰 1 个激活点
        for g in [po1.sel, po2.sel, pa.sel] {
            let acts = info.preprocess_polys[g - 1]
                .iter()
                .filter(|v| **v != Fr::ZERO)
                .count();
            assert_eq!(acts, 1, "sel#{g} 必须单点激活");
        }
        // 真值从输出格读回：or(1,0)=1、or(1,1)=1、and(0,1)=0
        assert_eq!(advice[po1.o][xr[0]], Fr::ONE);
        assert_eq!(advice[po2.o][xr[1]], Fr::ONE);
        assert_eq!(advice[pa.t][xr[2]], Fr::ZERO);
    }

    /// 在某点写一对输入位见证。
    fn write_bit_pair(b: &mut Builder<Fr>, cx: usize, cy: usize, at: usize, xy: (bool, bool)) {
        put_bit(b, cx, at, xy.0);
        put_bit(b, cy, at, xy.1);
    }

    // ── decompose / eq / neq_zero ──

    #[test]
    fn port_decompose_native_folds_exactly_257() {
        let mut b = Builder::<Fr>::new(0);
        let cx = b.alloc_col();
        let xv = n_limbs(); // n < p 可承载为 F 元素
        let at = point_at_rank(6);
        b.set_cell_f(cx, at, fr_from_limbs(&xv));
        let dsc = plan_decomp(&mut b);
        let xe = b.q(cx, Rotation::cur());
        let e0 = b.n_constraints();
        let ds = emit_decompose(&mut b, &dsc, at, xe, &xv);
        assert_eq!(b.n_constraints() - e0, 257, "256 位布尔 + 1 折叠");
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
        assert_eq!(read_scalar(&advice, &ds), xv);
    }

    #[test]
    fn port_eq_holds_and_rejects() {
        let v = [0x1234_5678, 0x9abc_def0, 0xdead_beef, 1];
        let vd = [0x1234_5678, 0x9abc_def0, 0xdead_beef, 2];
        let mut b = Builder::<Fr>::new(0);
        let ga = scalar_at(&mut b, 1, &v);
        let gb = scalar_at(&mut b, 2, &vd);
        // 冻结纪律：两个选择器都在任何发射前分配
        let se = plan_eq(&mut b);
        let se2 = plan_eq(&mut b);
        let e0 = b.n_constraints();
        emit_eq(&mut b, &se, point_at_rank(6), &ga, &ga);
        assert_eq!(b.n_constraints() - e0, 4);
        // 不同 limb 必拒（第二次断言发生在另一行）
        emit_eq(&mut b, &se2, point_at_rank(7), &ga, &gb);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        let bad = crate::sm3_compress::check_parts_violations(&info, &advice, &inst);
        assert!(!bad.is_empty(), "不同低 limb 必须被拒");
        // 对称性抽查：同一 builder 上相等断言未受第二次影响（差发生在 sel2 行）
        assert!(bad.iter().all(|x| x.point == point_at_rank(7)));
    }

    #[test]
    fn port_neq_zero_accept_and_reject() {
        let mut b = Builder::<Fr>::new(0);
        let g42 = scalar_at(&mut b, 1, &[42, 0, 0, 0]);
        let g0 = scalar_at(&mut b, 2, &[0; 4]);
        let sn = plan_neq(&mut b);
        let sn2 = plan_neq(&mut b);
        let e0 = b.n_constraints();
        emit_neq_zero(&mut b, &sn, point_at_rank(6), &g42);
        assert_eq!(b.n_constraints() - e0, 1);
        emit_neq_zero(&mut b, &sn2, point_at_rank(7), &g0);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        let bad = crate::sm3_compress::check_parts_violations(&info, &advice, &inst);
        assert!(!bad.is_empty(), "x=0 无逆必须不可满足");
        assert!(bad.iter().all(|x| x.point == point_at_rank(7)));
    }
}
