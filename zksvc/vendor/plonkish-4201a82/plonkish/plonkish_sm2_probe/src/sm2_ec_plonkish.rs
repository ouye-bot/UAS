//! SM2 椭圆曲线门的 Plonkish 移植（簇C）：
//! double(5) / add_fixed(16) / add_complete(28) / 标量乘双循环（24/迭代；
//! 常基点 6147、见证基点 6156，均含勘误 #27 Fix R-a 的 +3 头钉）。
//! 计数指纹承继 M2a `sm2_ec_r1cs.rs`，
//! 蓝图 `VERIFY_BODY_BLUEPRINT.md` §二·§四·§七-簇C。
//!
//! ## 表示层对应（本模块的核心设计决定）
//! M2a 的 R1CS 里每次 `mul(cs,a,b,v)` 引入一个新见证变量并以 `a·b=v` 钉住；
//! 中间线性组合免费组合。直译到 Builder：**每条 mul 输出 = 一个 advice 格**
//! （`emit_prod_eq`），线性结果保持为 `Expression` 流转。度数核算（选择器
//! 因子外乘后内容度须 ≤3）：
//! - λ 等 mul 输出一律先落格，避免 `(含 lamsq 的表达式)²` 度数爆炸；
//! - 循环级 acc 由 3 条 loop-sel 以 Rotation(1) 绑到**下一行** acc_in 格
//!   （勘误 #27 Fix R-a write-next：跨行链进约束系统），另付头钉 3 推；
//! - dd（当轮倍点输出）保持 deg-1 表达式进入同轮 add_fixed，其 is_zero /
//!   条件求逆 / λ 的积都恰为内容度 1–3。
//!
//! ## 常量纪律（[[never-handcopy-curve-constants]]）
//! a ≡ −3 (mod p) 由域运算机械推导，零手抄；b / Gx / Gy 从 GB/T 32918.5-2017
//! 参数节标准十六进制机械解析（复用 [`crate::sm2_params::hex_to_limbs_le`]）。
//! 正确性由测试三重锚定：① on_curve(G)；② n·G = O（阶侧）；③ dA 附录 A
//! 向量点仍在曲线上——任何抄写错误必在三关之一爆炸。
//!
//! ## 原生参照层（本文件上半部）
//! 仿射群运算直接写在自研 [`crate::FpSM2`] 上（ff 0.13 Field），替代 M2a 的
//! ark 参照：`None` 表示无穷远点 O。仅供测试对拍与电路见证真值推导。

use crate::sm2_params::{fr_from_limbs, hex_to_limbs_le};
use crate::sm3_compress::Builder;
use crate::FpSM2;
use ff::Field;
use plonkish_backend::util::expression::{Expression, Rotation};

/// 表达式别名。
type E = Expression<FpSM2>;

// ────────────────────────── 门原语层小工具 ──────────────────────────

fn qc(b: &Builder<FpSM2>, col: usize) -> E {
    b.q(col, Rotation::cur())
}

fn konst(v: FpSM2) -> E {
    Expression::<FpSM2>::Constant(v)
}

/// 常数 1 的表达式（小帮手；显式函数而非闭包转 fn 指针的 const 初始化）。
#[inline]
fn k_one() -> E {
    Expression::<FpSM2>::one()
}

/// 点的三列物理形态：x / y / inf（inf ∈ {0,1}，布尔性由消费门代数保证，
/// 与 M2a 相同——只作为乘子/被减项出现，不需独立布尔化约束）。
#[derive(Default, Clone, Copy)]
pub struct PtCells {
    pub cols: [usize; 3],
}

/// 计划一个点的三列。
pub fn plan_point(b: &mut Builder<FpSM2>) -> PtCells {
    PtCells { cols: std::array::from_fn(|_| b.alloc_col()) }
}

/// 写入点格见证。
pub fn write_point(b: &mut Builder<FpSM2>, pc: &PtCells, at: usize, v: Affine) {
    match v {
        None => {
            b.set_cell_f(pc.cols[0], at, FpSM2::ZERO);
            b.set_cell_f(pc.cols[1], at, FpSM2::ZERO);
            b.set_cell_f(pc.cols[2], at, FpSM2::ONE);
        }
        Some((x, y)) => {
            b.set_cell_f(pc.cols[0], at, x);
            b.set_cell_f(pc.cols[1], at, y);
            b.set_cell_f(pc.cols[2], at, FpSM2::ZERO);
        }
    }
}

/// 值束：三坐标的表达式 + Rust 侧真值（装配期同步推导，禁二次重算漂移）。
///
/// 🔴 生命周期契约（C2 实测教训）：列查询的全局编号 = `1 + 查询当时的
/// 选择器数 + local`，而终局布局把**全部选择器/预处理多项式排在全部
/// advice 之前** ⟹ 在任何 `alloc_selector` 之前捕获的表达式，会随后续
/// 选择器入列而整体错位（失败签名：凡引用预建表达式的约束全挂、纯后
/// 分配槽格的约束全过）。因此 PtVal 只作为门的**输出**（构造发生于发射
/// 段，布局已收口，天然安全）；门**输入**一律经 [`PtRef`]——Cells 变体
/// （格句柄 + 真值三元组）由门在发射段自查询，Val 变体仅限同轮直连。
pub struct PtVal {
    pub xe: E,
    pub ye: E,
    pub infe: E,
    pub xv: FpSM2,
    pub yv: FpSM2,
    pub iv: bool,
}

/// 门输入点束的统一词汇表。两变体各自的生命周期合法性由构造时机保证：
///
/// - [`PtRef::Cells`]：计划期点格句柄 + 真值。**任何时刻合法**（消费门在
///   发射段经全局编号稳定的查询取表达式，见上方契约注释）。
/// - [`PtRef::Val`]：同轮发射段的中间点产物（如倍点的 dd）。其坐标表达
///   式各乘积核均已落格 ⟹ 内容度恒 ≤1，链入下游门的乘积后内容度 ≤2
///   （再加选择器因子 ≤3 达标）。**仅可在当前门发射段内消费**，禁止跨轮。
///
/// 该枚举恢复蓝图原义："dd 保持 deg-1 表达式进入同轮 add_fixed"，避免为
/// 中间点付额外的落格绑定推。
#[derive(Clone)]
pub enum PtRef<'a> {
    Cells(&'a PtCells, FpSM2, FpSM2, bool),
    Val {
        xe: E,
        ye: E,
        ie: E,
        xv: FpSM2,
        yv: FpSM2,
        iv: bool,
    },
}

impl<'a> PtRef<'a> {
    /// 从已写好的点格 + 真值构造 Cells 束（真值必须与 write_point 一致；
    /// O 坐标约定 (0,0)、inf 位 = 1）。
    pub fn cells(pc: &'a PtCells, v: Affine) -> Self {
        match v {
            None => PtRef::Cells(pc, FpSM2::ZERO, FpSM2::ZERO, true),
            Some((x, y)) => PtRef::Cells(pc, x, y, false),
        }
    }

    /// 真值三元组 (x, y, inf)。
    #[inline]
    pub fn txyz(&self) -> (FpSM2, FpSM2, bool) {
        match self {
            PtRef::Cells(_, x, y, i) => (*x, *y, *i),
            PtRef::Val { xv, yv, iv, .. } => (*xv, *yv, *iv),
        }
    }

    /// 坐标 x 的表达式（Cells 发射段自查询 / Val 直连克隆）。
    #[inline]
    pub fn ex(&self, b: &Builder<FpSM2>) -> E {
        match self {
            PtRef::Cells(pc, ..) => qc(b, pc.cols[0]),
            PtRef::Val { xe, .. } => xe.clone(),
        }
    }

    /// 坐标 y 的表达式。
    #[inline]
    pub fn ey(&self, b: &Builder<FpSM2>) -> E {
        match self {
            PtRef::Cells(pc, ..) => qc(b, pc.cols[1]),
            PtRef::Val { ye, .. } => ye.clone(),
        }
    }

    /// inf 位表达式。
    #[inline]
    pub fn ei(&self, b: &Builder<FpSM2>) -> E {
        match self {
            PtRef::Cells(pc, ..) => qc(b, pc.cols[2]),
            PtRef::Val { ie, .. } => ie.clone(),
        }
    }
}

/// 把一个值束选入新格：`s·(out − (B + C·(A−B))) = 0`，单推。
/// 返回该格的 cur 表达式（真值由调用方随束传递）。
fn sel_bind(
    b: &mut Builder<FpSM2>,
    sg: usize,
    at: usize,
    out: usize,
    c: E,
    cv: bool,
    a: E,
    av: FpSM2,
    bb: E,
    bv: FpSM2,
) -> E {
    let ov = if cv { av } else { bv };
    b.set_cell_f(out, at, ov);
    let oe = qc(b, out);
    b.emit_assert_zero(sg, oe.clone() - (bb.clone() + c * (a - bb)));
    oe
}

/// 把一个值束以**旋转绑定**写进秩后继行：`s·(q(out, Rotation(1)) − (B + C·(A−B))) = 0`，
/// 见证自写 `out@秩后继(at)`（勘误 #27 Fix R-a「write-next」原语）。约束锚在
/// `at` 行（选择器激活点）；`Rotation(1)` 按 `rot_between` 语义读**秩后继**格
/// （旋转 = 秩差 ⟹ 读 `point_at_rank(rank(at)+1)`）——LFSR 序中秩后继 ≠
/// 整数+1，见证必须写进同一格（首跑实测教训：整数+1 写法令 24/行全族违约，
/// 签名 = 违约点散布于循环行）。调用方必须保证锚行序列为**连续秩**（发射点
/// 自带断言兜底）。度数与 [`sel_bind`] 同构：rotated 查询仍是线性查询。
fn sel_bind_rot(
    b: &mut Builder<FpSM2>,
    sg: usize,
    at: usize,
    out: usize,
    c: E,
    cv: bool,
    a: E,
    av: FpSM2,
    bb: E,
    bv: FpSM2,
) {
    let ov = if cv { av } else { bv };
    let next_rank = crate::sm3_compress::nth_map()[at] + 1;
    assert!(
        next_rank < crate::sm3_compress::ROWS,
        "秩 {next_rank} 越界（wrap 不支持；锚行须避开秩空间末端）"
    );
    b.set_cell_f(out, crate::sm3_compress::point_at_rank(next_rank), ov);
    let oe = b.q(out, Rotation(1));
    b.emit_assert_zero(sg, oe - (bb.clone() + c * (a - bb)));
}

// ────────────────────────── ec_double（5 推，M2a 保真移植） ──────────────────────────

/// 倍点槽：五个中间量格（xsq / 1/(2y)=u / λ / λ² / λ(x−x₃)=prod）+ 单点选择器。
#[derive(Default, Clone, Copy)]
pub struct DoubleSlots {
    pub sel: usize,
    pub xsq: usize,
    pub u: usize,
    pub lam: usize,
    pub lamsq: usize,
    pub prod: usize,
}

pub fn plan_ec_double(b: &mut Builder<FpSM2>) -> DoubleSlots {
    DoubleSlots {
        sel: b.alloc_selector(&[]),
        xsq: b.alloc_col(),
        u: b.alloc_col(),
        lam: b.alloc_col(),
        lamsq: b.alloc_col(),
        prod: b.alloc_col(),
    }
}

/// 发射倍点（完整语义：O → O；仿射点 y≠0 由 SM2 群结构 h=1 保证）：
/// ① xsq=x·x；② (2y)·u = 1−inf；③ λ=(3xsq+a)·u；④ λsq=λ·λ；⑤ λ·(3x−λsq)=prod。
///
/// 输入取 [`PtRef`]（Cells 发射段自查询 / Val 同轮直连）；输出坐标保持
/// **线性表达式**（各乘积核均已落格 ⟹ 度恒为 1），仅可在同轮（plan 收口
/// 后的发射段）消费；跨轮传递经循环级 sel 落格。
pub fn emit_ec_double(
    b: &mut Builder<FpSM2>,
    sl: &DoubleSlots,
    at: usize,
    p: &PtRef<'_>,
    a: FpSM2,
) -> PtVal {
    b.extend_selector(sl.sel, &[at]);

    // ── 真值链（唯一真值源；见证写入与约束共用，禁二次重算漂移）──
    let (px, py, pi) = p.txyz();
    let xsq_v = px.square();
    let uv = if pi {
        FpSM2::ZERO // O：RHS = 1−inf = 0，u 任取 0
    } else {
        (py + py).invert().unwrap()
    };
    let lam_v = (FpSM2::from(3u64) * xsq_v + a) * uv;
    let lamsq_v = lam_v.square();
    let xd_v = lamsq_v - px - px;
    let diff_v = px - xd_v;
    let prod_v = lam_v * diff_v;
    let yd_v = prod_v - py;

    // ── 见证写入 ──
    b.set_cell_f(sl.xsq, at, xsq_v);
    b.set_cell_f(sl.u, at, uv);
    b.set_cell_f(sl.lam, at, lam_v);
    b.set_cell_f(sl.lamsq, at, lamsq_v);
    b.set_cell_f(sl.prod, at, prod_v);

    // ── 表达式材料：输入发射段自查询/直连 ＋ 槽格查询；
    //     复用点一律显式 clone，移动只发生在最后一次使用 ──
    let ex = p.ex(b);
    let ey = p.ey(b);
    let einf = p.ei(b);
    let qx = qc(b, sl.xsq);
    let qu = qc(b, sl.u);
    let qlam = qc(b, sl.lam);
    let qlsq = qc(b, sl.lamsq);
    let qprod = qc(b, sl.prod);
    let k3 = konst(FpSM2::from(3u64));
    let k2 = konst(FpSM2::from(2u64));

    // ① xsq = x·x
    b.emit_prod_eq(sl.sel, ex.clone(), ex.clone(), qx.clone());
    // ② (y+y)·u = 1 − inf
    b.emit_prod_eq(sl.sel, ey.clone() + ey.clone(), qu.clone(), k_one() - einf.clone());
    // ③ λ = (3·xsq + a)·u
    b.emit_prod_eq(sl.sel, k3.clone() * qx.clone() + konst(a), qu, qlam.clone());
    // ④ λsq = λ·λ
    b.emit_prod_eq(sl.sel, qlam.clone(), qlam.clone(), qlsq.clone());
    // ⑤ prod = λ·(x − x₃)，diff = x − (λsq − 2x) = 3x − λsq
    b.emit_prod_eq(sl.sel, qlam.clone(), k3 * ex.clone() - qlsq.clone(), qprod.clone());

    PtVal {
        xe: qlsq - k2 * ex,
        ye: qprod - ey,
        infe: einf,
        xv: xd_v,
        yv: yd_v,
        iv: pi,
    }
}

// ────────────────────────── ec_add_fixed（16 推，M2a 保真移植） ──────────────────────────

/// 累加器 + 固定基点的完整加法槽。约束计账（对照 M2a，共 **16**）：
/// is_zero ×2（各 2）＋ 条件求逆 1 ＋ λ/λ²/prod 各 1 ＋ u / c_od 各 1
/// ＋ 选择树 6（tx,mx,sx / ty,my,sy 各 1）。输出 = (sx, sy, c_od) 三列。
#[derive(Default, Clone, Copy)]
pub struct FixedSlots {
    pub sel: usize,
    pub t1: usize,
    pub z1: usize,
    pub t2: usize,
    pub z2: usize,
    pub tc: usize,
    pub lam: usize,
    pub lsq: usize,
    pub prod: usize,
    pub u: usize,
    pub c_od: usize,
    pub tx: usize,
    pub mx: usize,
    pub sx: usize,
    pub ty: usize,
    pub my: usize,
    pub sy: usize,
}

pub fn plan_ec_add_fixed(b: &mut Builder<FpSM2>) -> FixedSlots {
    FixedSlots {
        sel: b.alloc_selector(&[]),
        t1: b.alloc_col(),
        z1: b.alloc_col(),
        t2: b.alloc_col(),
        z2: b.alloc_col(),
        tc: b.alloc_col(),
        lam: b.alloc_col(),
        lsq: b.alloc_col(),
        prod: b.alloc_col(),
        u: b.alloc_col(),
        c_od: b.alloc_col(),
        tx: b.alloc_col(),
        mx: b.alloc_col(),
        sx: b.alloc_col(),
        ty: b.alloc_col(),
        my: b.alloc_col(),
        sy: b.alloc_col(),
    }
}

/// 循环级最终输出的格句柄 + 真值。`pt = None` 表示无穷远（此时坐标格
/// 选树已选到 O 叶子 0，仍写 0 值格保持行完备）。
///
/// `sxv/syv/finf` 给出两格**实际写入的叶子值**与 inf 标志：无论结果是否
/// 为 O 都有确定数值 —— 循环位选择需要 S/D 两侧分支的具体数值，不能依
/// 赖"O 时坐标为垃圾"的约定。
pub struct FixedOut {
    pub cols: [usize; 3],
    pub pt: Affine,
    /// sx/sy 格实际写入的叶子值（pt=None 时可能是无意义叶，配合 finf 消费）。
    pub sxv: FpSM2,
    pub syv: FpSM2,
    /// 结果 inf 标志（= od_truth）。
    pub finf: bool,
}

/// 发射 `S = D + P`（D 带 inf 标志，P/D₂ 为输入束）：全情形选择树，
/// 分情形论证承继 M2a —— D=O → P；D=P（→[预计算]2P）；D=−P → O；
/// 一般 → 仿射加核。**16 推**。输入取 [`PtRef`]（Cells 自查询 / Val 同轮
/// 直连——循环内 dd 即经 Val 进入本门，免除落格绑定推）。
///
/// 选择树（每坐标 3 层、每层单推绑定到新格）：
/// `S = sel(inf_D, P, sel(a1, sel(a2, 2P, O), general))`
/// 注：D=P 与 D=−P 由 a2 一层自动区分（M2a 原注）。
pub fn emit_ec_add_fixed(
    b: &mut Builder<FpSM2>,
    sl: &FixedSlots,
    at: usize,
    d: &PtRef<'_>,
    base: &PtRef<'_>,
    d2: &PtRef<'_>,
) -> FixedOut {
    b.extend_selector(sl.sel, &[at]);

    // ── 真值链（Val 变体的 xv 与其表达式 xe 恒同步：xe 各核已落格保证）──
    let (d_x, d_y, d_i) = d.txyz();
    let (b_x, b_y, _) = base.txyz();
    let (t2_x, t2_y, _) = d2.txyz();
    let dxv = d_x - b_x;
    let a1v = dxv == FpSM2::ZERO;
    let syv = d_y - b_y;
    let a2v = syv == FpSM2::ZERO;
    let tv = if a1v { FpSM2::ZERO } else { dxv.invert().unwrap() };
    let t2v = if a2v { FpSM2::ZERO } else { syv.invert().unwrap() };
    let lam_v = syv * tv;
    let lsq_v = lam_v.square();
    let xg_v = lsq_v - d_x - b_x;
    let diff_v = d_x - xg_v;
    let prod_v = lam_v * diff_v;
    let yg_v = prod_v - d_y;
    let u_truth = !d_i && a1v;
    let od_truth = u_truth && !a2v;

    // ── 见证写入（含零值格保底：每个计划格都必须有行值，家族全局求值才健全；
    //     t₁/t₂ 复用真值链的 tv/t2v —— is_zero 伪逆与条件逆同构，禁二次重算）──
    let z1v = if a1v { FpSM2::ONE } else { FpSM2::ZERO };
    let z2v = if a2v { FpSM2::ONE } else { FpSM2::ZERO };
    b.set_cell_f(sl.t1, at, tv);
    b.set_cell_f(sl.z1, at, z1v);
    b.set_cell_f(sl.t2, at, t2v);
    b.set_cell_f(sl.z2, at, z2v);
    b.set_cell_f(sl.tc, at, tv);
    b.set_cell_f(sl.lam, at, lam_v);
    b.set_cell_f(sl.lsq, at, lsq_v);
    b.set_cell_f(sl.prod, at, prod_v);
    let uv = if u_truth { FpSM2::ONE } else { FpSM2::ZERO };
    b.set_cell_f(sl.u, at, uv);
    b.set_cell_f(sl.c_od, at, if od_truth { FpSM2::ONE } else { FpSM2::ZERO });

    // ── 表达式材料：输入自查询/直连 ＋ 槽格查询（post-plan 安全）──
    let qdx = d.ex(b);
    let qdy = d.ey(b);
    let qdi = d.ei(b);
    let qbx = base.ex(b);
    let qby = base.ey(b);
    let qx2 = d2.ex(b);
    let qy2 = d2.ey(b);
    let dx_e = qdx.clone() - qbx.clone();
    let dy_e = qdy.clone() - qby.clone();
    let qt1 = qc(b, sl.t1);
    let qz1 = qc(b, sl.z1);
    let qt2 = qc(b, sl.t2);
    let qz2 = qc(b, sl.z2);
    let qtc = qc(b, sl.tc);
    let qlam = qc(b, sl.lam);
    let qlsq = qc(b, sl.lsq);
    let qprod = qc(b, sl.prod);
    let qu = qc(b, sl.u);
    let qod = qc(b, sl.c_od);

    // is_zero(dx)：w·t = 1−z、w·z = 0（各 1 推）
    b.emit_prod_eq(sl.sel, dx_e.clone(), qt1, k_one() - qz1.clone());
    b.emit_prod_eq(sl.sel, dx_e.clone(), qz1.clone(), konst(FpSM2::ZERO));
    // is_zero(sy)
    b.emit_prod_eq(sl.sel, dy_e.clone(), qt2, k_one() - qz2.clone());
    b.emit_prod_eq(sl.sel, dy_e.clone(), qz2.clone(), konst(FpSM2::ZERO));
    // 条件求逆：dx·t = 1 − a1
    b.emit_prod_eq(sl.sel, dx_e, qtc.clone(), k_one() - qz1.clone());
    // 一般加核
    b.emit_prod_eq(sl.sel, dy_e, qtc, qlam.clone());
    b.emit_prod_eq(sl.sel, qlam.clone(), qlam.clone(), qlsq.clone());
    let xg_e = qlsq.clone() - qdx.clone() - qbx.clone();
    b.emit_prod_eq(sl.sel, qlam, qdx.clone() - xg_e.clone(), qprod.clone());
    let yg_e = qprod - qdy.clone();
    // 条件位：u = ¬inf_D · a1；c_od = u · ¬a2
    b.emit_prod_eq(sl.sel, k_one() - qdi.clone(), qz1.clone(), qu.clone());
    b.emit_prod_eq(sl.sel, qu.clone(), k_one() - qz2.clone(), qod.clone());

    // ── 坐标选择树（每坐标 3 层、每层单推绑新格；叶子混合格查询与线性表达式皆可）：
    //     S = sel(i_d, P, sel(a₁, sel(a₂, 2P, O), general))
    //     分支真值逐层同步推导，供见证格写入（与约束同源，防漂移）。──
    let tx_t = if a2v { t2_x } else { FpSM2::ZERO };
    let ty_t = if a2v { t2_y } else { FpSM2::ZERO };
    let qtx =
        sel_bind(b, sl.sel, at, sl.tx, qz2.clone(), a2v, qx2.clone(), t2_x, konst(FpSM2::ZERO), FpSM2::ZERO);
    let qty =
        sel_bind(b, sl.sel, at, sl.ty, qz2.clone(), a2v, qy2.clone(), t2_y, konst(FpSM2::ZERO), FpSM2::ZERO);
    let mx_t = if a1v { tx_t } else { xg_v };
    let my_t = if a1v { ty_t } else { yg_v };
    let qmx = sel_bind(b, sl.sel, at, sl.mx, qz1.clone(), a1v, qtx, tx_t, xg_e.clone(), xg_v);
    let qmy = sel_bind(b, sl.sel, at, sl.my, qz1.clone(), a1v, qty, ty_t, yg_e.clone(), yg_v);
    let sx_t = if d_i { b_x } else { mx_t };
    let sy_t = if d_i { b_y } else { my_t };
    let _qsx = sel_bind(b, sl.sel, at, sl.sx, qdi.clone(), d_i, qbx.clone(), b_x, qmx, mx_t);
    let _qsy = sel_bind(b, sl.sel, at, sl.sy, qdi, d_i, qby, b_y, qmy, my_t);

    FixedOut {
        cols: [sl.sx, sl.sy, sl.c_od],
        pt: if od_truth { None } else { Some((sx_t, sy_t)) },
        sxv: sx_t,
        syv: sy_t,
        finf: od_truth,
    }
}


// ────────────────────────── ec_add_complete（28 推，M2a 保真移植） ──────────────────────────

/// 布尔值 → 域元素。
#[inline]
fn bitf(v: bool) -> FpSM2 {
    if v { FpSM2::ONE } else { FpSM2::ZERO }
}

/// 完整点加（两输入均为带 inf 标志的点束）：全情形 `O / P=Q / P=−Q / 一般`。
/// 约束计账（对照 M2a `ec_add_complete`，共 **28**）：
/// is_zero(dx/sy) 各 2 ＋ 条件求逆 1 ＋ λ/λ²/prod 各 1 ＋ 内嵌 2P 5
/// ＋ 条件位六积（c₂/a/u/c_dbl/c_od/i₁i₂）各 1 ＋ i₃ 线性 1
/// ＋ 双坐标选择树 4×2。
///
/// 条件位语义（承继 M2a 注释）：一般情形（dx≠0）由选择树默认叶覆盖，
/// 无需单独标志；`i₃ = i₁i₂ + c_od`（两者互斥，和为布尔）。
#[derive(Clone, Copy)]
pub struct CompleteSlots {
    pub sel: usize,
    pub t1: usize,
    pub z1: usize,
    pub t2: usize,
    pub z2: usize,
    pub lam: usize,
    pub lsq: usize,
    pub prod: usize,
    /// 内嵌倍点（P=Q 分支的 2P 输入），每门一套（家族纪律）。
    pub dbl: DoubleSlots,
    pub c2: usize,
    pub ab: usize,
    pub ub: usize,
    pub cdbl: usize,
    pub cod: usize,
    pub i1i2: usize,
    pub i3: usize,
    pub tx1: usize,
    pub tx2: usize,
    pub tx3: usize,
    pub sx: usize,
    pub ty1: usize,
    pub ty2: usize,
    pub ty3: usize,
    pub sy: usize,
}

pub fn plan_ec_add_complete(b: &mut Builder<FpSM2>) -> CompleteSlots {
    CompleteSlots {
        sel: b.alloc_selector(&[]),
        t1: b.alloc_col(),
        z1: b.alloc_col(),
        t2: b.alloc_col(),
        z2: b.alloc_col(),
        lam: b.alloc_col(),
        lsq: b.alloc_col(),
        prod: b.alloc_col(),
        dbl: plan_ec_double(b),
        c2: b.alloc_col(),
        ab: b.alloc_col(),
        ub: b.alloc_col(),
        cdbl: b.alloc_col(),
        cod: b.alloc_col(),
        i1i2: b.alloc_col(),
        i3: b.alloc_col(),
        tx1: b.alloc_col(),
        tx2: b.alloc_col(),
        tx3: b.alloc_col(),
        sx: b.alloc_col(),
        ty1: b.alloc_col(),
        ty2: b.alloc_col(),
        ty3: b.alloc_col(),
        sy: b.alloc_col(),
    }
}

/// 输出三列：(sx, sy, i3)。`pt = None` 表示无穷远（坐标格已被树选到 O 叶 0，
/// inf 性由 i₃ 格代数钉住）。
pub struct CompleteOut {
    pub cols: [usize; 3],
    pub pt: Affine,
}

/// 发射 `R = P + Q`（P/Q 均带 inf 标志）。**28 推**。
/// 树序：`S = sel(i₁, Q, sel(c₂, P, sel(c_dbl, 2P, sel(c_od, O, general))))`。
pub fn emit_ec_add_complete(
    b: &mut Builder<FpSM2>,
    sl: &CompleteSlots,
    at: usize,
    p: &PtRef<'_>,
    q: &PtRef<'_>,
    a: FpSM2,
) -> CompleteOut {
    b.extend_selector(sl.sel, &[at]);

    // ── 真值链（唯一真值源）──
    let (p_x, p_y, p_i) = p.txyz();
    let (q_x, q_y, q_i) = q.txyz();
    let dxv = p_x - q_x;
    let a1v = dxv == FpSM2::ZERO;
    let syv = p_y - q_y;
    let a2v = syv == FpSM2::ZERO;
    let tv = if a1v { FpSM2::ZERO } else { dxv.invert().unwrap() };
    let t2v = if a2v { FpSM2::ZERO } else { syv.invert().unwrap() };
    let lam_v = syv * tv;
    let lsq_v = lam_v.square();
    let xg_v = lsq_v - p_x - q_x;
    let diff_v = p_x - xg_v;
    let prod_v = lam_v * diff_v;
    let yg_v = prod_v - p_y;
    // 条件位真值：c₂ = i₂(1−i₁)；a = (1−i₁)(1−i₂)；u = a·a₁；
    // c_dbl = u·a₂（P=Q）；c_od = u·¬a₂（P=−Q）；i₃ = i₁i₂ + c_od。
    let c2_t = q_i && !p_i;
    let ab_t = !p_i && !q_i;
    let u_t = ab_t && a1v;
    let cdbl_t = u_t && a2v;
    let cod_t = u_t && !a2v;

    // ── 见证写入（含零值保底）──
    b.set_cell_f(sl.t1, at, tv);
    b.set_cell_f(sl.z1, at, bitf(a1v));
    b.set_cell_f(sl.t2, at, t2v);
    b.set_cell_f(sl.z2, at, bitf(a2v));
    b.set_cell_f(sl.lam, at, lam_v);
    b.set_cell_f(sl.lsq, at, lsq_v);
    b.set_cell_f(sl.prod, at, prod_v);
    b.set_cell_f(sl.c2, at, bitf(c2_t));
    b.set_cell_f(sl.ab, at, bitf(ab_t));
    b.set_cell_f(sl.ub, at, bitf(u_t));
    b.set_cell_f(sl.cdbl, at, bitf(cdbl_t));
    b.set_cell_f(sl.cod, at, bitf(cod_t));
    b.set_cell_f(sl.i1i2, at, bitf(p_i && q_i));
    // i₃ 见证（零值格保底：漏写则所有 i₃=1 的正例整体违约 —— 实测教训）
    b.set_cell_f(sl.i3, at, bitf((p_i && q_i) || cod_t));

    // ── 表达式材料（发射段自查询/直连，post-plan 安全）──
    let qpx = p.ex(b);
    let qpy = p.ey(b);
    let qi1 = p.ei(b);
    let qqx = q.ex(b);
    let qqy = q.ey(b);
    let qi2 = q.ei(b);
    let dqx = qpx.clone() - qqx.clone();
    let dqy = qpy.clone() - qqy.clone();
    let qt1 = qc(b, sl.t1);
    let qz1 = qc(b, sl.z1);
    let qt2 = qc(b, sl.t2);
    let qz2 = qc(b, sl.z2);
    let qlam = qc(b, sl.lam);
    let qlsq = qc(b, sl.lsq);
    let qprod = qc(b, sl.prod);
    let q_c2 = qc(b, sl.c2);
    let q_ab = qc(b, sl.ab);
    let q_u = qc(b, sl.ub);
    let q_cd = qc(b, sl.cdbl);
    let q_od = qc(b, sl.cod);
    let q_12 = qc(b, sl.i1i2);
    let q_i3 = qc(b, sl.i3);

    // is_zero(dx)：dqx·t₁ = 1−z₁、dqx·z₁ = 0
    b.emit_prod_eq(sl.sel, dqx.clone(), qt1.clone(), k_one() - qz1.clone());
    b.emit_prod_eq(sl.sel, dqx.clone(), qz1.clone(), konst(FpSM2::ZERO));
    // is_zero(sy)
    b.emit_prod_eq(sl.sel, dqy.clone(), qt2, k_one() - qz2.clone());
    b.emit_prod_eq(sl.sel, dqy.clone(), qz2.clone(), konst(FpSM2::ZERO));
    // 条件求逆：dqx·t₁ = 1−z₁（t₁ 兼任伪逆与条件逆，同值同格）
    b.emit_prod_eq(sl.sel, dqx, qt1, k_one() - qz1.clone());
    // 一般加核
    b.emit_prod_eq(sl.sel, dqy, qc(b, sl.t1), qlam.clone());
    b.emit_prod_eq(sl.sel, qlam.clone(), qlam.clone(), qlsq.clone());
    let xg_e = qlsq.clone() - qpx.clone() - qqx.clone();
    b.emit_prod_eq(sl.sel, qlam, qpx.clone() - xg_e.clone(), qprod.clone());
    let yg_e = qprod - qpy.clone();

    // 内嵌 2P（P=Q 分支输入）：复用门原语，返回 PtVal（发射段安全）
    let dv = emit_ec_double(b, &sl.dbl, at, p, a);

    // 条件位六积
    b.emit_prod_eq(sl.sel, qi2.clone(), k_one() - qi1.clone(), q_c2.clone());
    b.emit_prod_eq(
        sl.sel,
        k_one() - qi1.clone(),
        k_one() - qi2.clone(),
        q_ab.clone(),
    );
    b.emit_prod_eq(sl.sel, q_ab.clone(), qz1.clone(), q_u.clone());
    b.emit_prod_eq(sl.sel, q_u.clone(), qz2.clone(), q_cd.clone());
    b.emit_prod_eq(sl.sel, q_u.clone(), k_one() - qz2.clone(), q_od.clone());
    b.emit_prod_eq(sl.sel, qi1.clone(), qi2.clone(), q_12.clone());
    // i₃ = i₁i₂ + c_od（单线性推）
    b.emit_assert_zero(sl.sel, q_i3.clone() - q_12.clone() - q_od.clone());

    // ── 坐标选择树（每坐标 4 层单推绑新格；叶真值先全量推导再发射，与
    //     见证写入同源防漂移）：
    //     S = sel(i₁, Q, sel(c₂, P, sel(c_dbl, 2P, sel(c_od, O, general))))──
    let tx1_v = if cod_t { FpSM2::ZERO } else { xg_v };
    let ty1_v = if cod_t { FpSM2::ZERO } else { yg_v };
    let tx2_v = if cdbl_t { dv.xv } else { tx1_v };
    let ty2_v = if cdbl_t { dv.yv } else { ty1_v };
    let tx3_v = if c2_t { p_x } else { tx2_v };
    let ty3_v = if c2_t { p_y } else { ty2_v };

    let tx1 = sel_bind(
        b, sl.sel, at, sl.tx1,
        q_od.clone(), cod_t,
        konst(FpSM2::ZERO), FpSM2::ZERO,
        xg_e, xg_v,
    );
    let tx2 = sel_bind(
        b, sl.sel, at, sl.tx2,
        q_cd.clone(), cdbl_t,
        dv.xe, dv.xv,
        tx1, tx1_v,
    );
    let tx3 = sel_bind(
        b, sl.sel, at, sl.tx3,
        q_c2.clone(), c2_t,
        qpx, p_x,
        tx2, tx2_v,
    );
    let _qsx = sel_bind(
        b, sl.sel, at, sl.sx,
        qi1.clone(), p_i,
        qqx, q_x,
        tx3, tx3_v,
    );
    let ty1 = sel_bind(
        b, sl.sel, at, sl.ty1,
        q_od, cod_t,
        konst(FpSM2::ZERO), FpSM2::ZERO,
        yg_e, yg_v,
    );
    let ty2 = sel_bind(
        b, sl.sel, at, sl.ty2,
        q_cd, cdbl_t,
        dv.ye, dv.yv,
        ty1, ty1_v,
    );
    let ty3 = sel_bind(
        b, sl.sel, at, sl.ty3,
        q_c2, c2_t,
        qpy, p_y,
        ty2, ty2_v,
    );
    let _qsy = sel_bind(
        b, sl.sel, at, sl.sy,
        qi1, p_i,
        qqy, q_y,
        ty3, ty3_v,
    );

    // 输出真值（与约束同源见证链；树叶子已含全部分支语义）
    let i3_t = (p_i && q_i) || cod_t;
    let pt = if i3_t {
        None
    } else if p_i {
        Some((q_x, q_y)) // i₁ 单独为 1：结果取 Q
    } else {
        Some((tx3_v, ty3_v))
    };

    CompleteOut { cols: [sl.sx, sl.sy, sl.i3], pt }
}

// ────────────────────────── 标量乘双循环（24/迭代，M2a 保真移植） ──────────────────────────

/// 循环级槽位：双门家族**跨迭代共享**（连线逐行同构 ⟹ 每族一个选择器、
/// 激活点数 = 迭代数），加上基点/2P 常量三列与循环 acc 六列。
/// 列经济：~31 advice 列即承载任意轮数（对比逐调用家族的 22×N 爆炸）；
/// 约束计数不受共享影响，仍为 **24/迭代**。
///
/// 🔴 位格纪律（256 迭代实测教训）：位选择不得把逐行 bit 烘成 konst——
/// 家族共享下，第 0 迭代发射的约束是带其专属常数的全局多项式，却在所有
/// 激活行求值，凡实际位不同的行必爆（失败签名：违约坍缩到单一绑定约束、
/// 点集弥散于整个 rank 排列）。故 bit 落成独立 advice 格，约束以格查询
/// β 表达 `out = D + β·(S−D)`；β 的布尔性由上游分解件预付（簇B decompose
/// 的 256 位布尔性已在其计数内锁定；本门只消费查询，恒保持 24/迭代指纹
/// ——测试路径写入 Rust bool 值，装配层改挂 decompose 输出列即可，语义
/// 不变）。`dd.iv` 同理取 `acc_in.inf` 格查询而非常量。
#[derive(Default, Clone, Copy)]
pub struct MulLoopSlots {
    pub dbl: DoubleSlots,
    pub fixed: FixedSlots,
    /// 常量基点三列（每迭代行写入常量值 —— 家族只在激活行读格）。
    pub base: PtCells,
    /// 2·base 三列（同上）。
    pub d2v: PtCells,
    /// 循环 acc 三列 (x, y, inf)：行 i 存「第 i 迭代输入」（本轮 double 的
    /// cur 读源）；行 i+1 的值由第 i 迭代的 lsel 三推以 Rotation(1) 写入并
    /// 绑定（勘误 #27 Fix R-a write-next：read/write 同格，跨行链由旋转
    /// 绑定约束传递——旧 read/write 双格 acc_out 形态跨行复制零约束，
    /// 已被取证证明可存在性伪造，蓝图 §四·8·2）。
    pub acc_in: PtCells,
    /// 本轮标量位 β（见上方位格纪律：布尔性由分解件预付，此处仅消费）。
    pub bit: usize,
    /// 位选择选择器（每迭代 3 推：本行选择树值以 Rotation(1) 绑到下一行
    /// acc_in）。
    pub lsel: usize,
    /// 头钉选择器（只激活 rows[0]：3 推钉 acc_in@rows[0]=(0,0,1)=O，
    /// 链初值进入约束系统 —— Fix R-a 新增）。
    pub head_sel: usize,
}

pub fn plan_ec_mul_loop(b: &mut Builder<FpSM2>) -> MulLoopSlots {
    let dbl = plan_ec_double(b);
    let fixed = plan_ec_add_fixed(b);
    MulLoopSlots {
        dbl,
        fixed,
        base: plan_point(b),
        d2v: plan_point(b),
        acc_in: plan_point(b),
        bit: b.alloc_col(),
        lsel: b.alloc_selector(&[]),
        head_sel: b.alloc_selector(&[]),
    }
}

/// 循环最终输出的格句柄 + 真值（语义同 [`FixedOut`] / [`CompleteOut`]）。
pub struct LoopOut {
    pub cols: [usize; 3],
    pub pt: Affine,
}

/// 常基点标量乘内循环：`R = [k]·base`，MSB-first double-and-add。
/// **24 推/迭代** = double(acc)(5) + add_fixed(dd, base, d2)(16) +
/// 位三坐标选择(3)。`bits_lsb` 为小端位序的原生 bool，逐行写入 `sl.bit`
/// 格后以查询参与绑定（位格纪律：布尔性由上游分解件预付——测试路径为
/// Rust 真值写入，装配层改挂 decompose 输出列即承接同一纪律）。
/// 计数锁定：256 位 ×24 + 头钉 3 = **6,147**（不付 on-curve(4)/2P 预计算(5)，
/// 二者属见证基点变体，合计 6,156，见簇D 装配）。
///
/// **acc 跨行链（勘误 #27 Fix R-a「write-next」，2026-08-31）**：行 i 的
/// lsel 三推把本行选择树值以 `Rotation(1)` 绑到**下一行** `acc_in`（约束
/// `q(acc_in, Rot(1)) == select(β,ss,dd)`，见证自写 rows[i+1]）；`rows[0]`
/// 由 head_sel 3 推钉死 acc_in=(0,0,1)=O。纸面语句→约束映射（第五道防线·
/// 语义级对账）：链初值 O=头钉 3 条、256 次跨行传递=256 迭代 ×3 推、终值
/// =rows[256] 的 acc_in（LoopOut 读口）——状态链 257 格与电路约束语句
/// 一一对应，不存在无约束的跨行复制。旧形态（acc_out 同行绑定 + 宿主
/// 复制写下一行 acc_in）跨行复制零约束，已被
/// `eg_chain_restart_forgery_pre_fix_demo` 活体取证（mock/环审计双盲区
/// 下的存在性伪造，蓝图 §四·8·2）。`rows` 必须 257 个**连续秩**（断言在
/// 发射点强制；rows[0]=头行兼迭代 0、rows[256]=纯接收行），互异且未被
/// 其他门占用。
pub fn emit_ec_mul_loop_const_base(
    b: &mut Builder<FpSM2>,
    sl: &MulLoopSlots,
    rows: &[usize],
    base_v: (FpSM2, FpSM2),
    d2_v: (FpSM2, FpSM2),
    bits_lsb: &[bool],
    a: FpSM2,
) -> LoopOut {
    assert_eq!(
        rows.len(),
        bits_lsb.len() + 1,
        "257 连续秩 = 256 迭代 + 1 尾接收行（Fix R-a）"
    );
    // 连续秩断言（Rotation(1) 绑定语义的前提；点→秩按勘误 #20 反转建）。
    {
        let inv = crate::sm3_compress::rank_inverse();
        let mut pt2rk = vec![usize::MAX; crate::sm3_compress::ROWS];
        for (rk, &pt) in inv.iter().enumerate() {
            if pt < pt2rk.len() {
                pt2rk[pt] = rk;
            }
        }
        assert!(
            rows.windows(2).all(|w| pt2rk[w[1]] != usize::MAX
                && pt2rk[w[0]] != usize::MAX
                && pt2rk[w[1]] == pt2rk[w[0]] + 1),
            "rows 必须是连续秩（rows[i]+1 的秩 = rows[i+1]），否则旋转绑定落错格"
        );
    }
    // 循环真值链（Rust 侧镜像电路 acc 传递）
    let mut ax = FpSM2::ZERO;
    let mut ay = FpSM2::ZERO;
    let mut ai = true;
    let base_pt = Some(base_v);
    let d2_pt = Some(d2_v);

    // 头行：acc_in@rows[0] = O（见证 + head_sel 3 推钉死 —— Fix R-a：
    // 链初值必须进约束系统，否则初值同样是纯见证）。
    write_point(b, &sl.acc_in, rows[0], None);
    b.extend_selector(sl.head_sel, &[rows[0]]);
    {
        let qx = qc(b, sl.acc_in.cols[0]);
        let qy = qc(b, sl.acc_in.cols[1]);
        let qi = qc(b, sl.acc_in.cols[2]);
        b.emit_assert_zero(sl.head_sel, qx - konst(FpSM2::ZERO));
        b.emit_assert_zero(sl.head_sel, qy - konst(FpSM2::ZERO));
        b.emit_assert_zero(sl.head_sel, qi - k_one());
    }

    for (i, &bit) in bits_lsb.iter().rev().enumerate() {
        let row = rows[i];
        // 本行写入两组常量见证（acc 上轮结果已由上一迭代的 sel_bind_rot
        // 自写 —— Fix R-a write-next，宿主不再写 acc_in）；门 cur 读 in、
        // lsel 以 Rotation(1) 绑下一行 in（旧「同行异格」已废）。
        let acc_aff: Affine = if ai { None } else { Some((ax, ay)) };
        write_point(b, &sl.base, row, base_pt);
        write_point(b, &sl.d2v, row, d2_pt);

        // dd = 2·acc（同轮 PtVal，直连进入 add_fixed）
        let pin_acc = PtRef::cells(&sl.acc_in, acc_aff);
        let dd = emit_ec_double(b, &sl.dbl, row, &pin_acc, a);
        let dd_ref = PtRef::Val {
            xe: dd.xe,
            ye: dd.ye,
            ie: dd.infe,
            xv: dd.xv,
            yv: dd.yv,
            iv: dd.iv,
        };

        // ss = dd + base（固定基点全情形树）
        let ss = emit_ec_add_fixed(
            b,
            &sl.fixed,
            row,
            &dd_ref,
            &PtRef::cells(&sl.base, base_pt),
            &PtRef::cells(&sl.d2v, d2_pt),
        );

        // R' = sel(β, S, D)：3 推以 Rotation(1) 绑到**下一行** acc_in 格
        // （勘误 #27 Fix R-a write-next：跨行链进约束系统，见证自写
        // rows[i+1]）。β 与 acc_in.inf 均以格查询进入约束（家族形状逐行
        // 同构 —— 位格纪律），真值仅供见证写入。
        b.set_cell_f(sl.bit, row, bitf(bit));
        b.extend_selector(sl.lsel, &[row]);
        let qbit = qc(b, sl.bit);
        let q_in_i = qc(b, sl.acc_in.cols[2]);
        let e_sx = qc(b, ss.cols[0]);
        let e_sy = qc(b, ss.cols[1]);
        let e_si = qc(b, ss.cols[2]);
        sel_bind_rot(
            b, sl.lsel, row, sl.acc_in.cols[0],
            qbit.clone(), bit, e_sx.clone(), ss.sxv, dd_ref.ex(b), dd_ref.txyz().0,
        );
        sel_bind_rot(
            b, sl.lsel, row, sl.acc_in.cols[1],
            qbit.clone(), bit, e_sy.clone(), ss.syv, dd_ref.ey(b), dd_ref.txyz().1,
        );
        sel_bind_rot(
            b, sl.lsel, row, sl.acc_in.cols[2],
            qbit, bit, e_si, bitf(ss.finf), q_in_i, bitf(ai),
        );

        ax = if bit { ss.sxv } else { dd.xv };
        ay = if bit { ss.syv } else { dd.yv };
        ai = if bit { ss.finf } else { dd.iv };
    }

    LoopOut {
        cols: sl.acc_in.cols,
        pt: if ai { None } else { Some((ax, ay)) },
    }
}

// ────────────────────────── 曲线常量（[核查] 机械解析） ──────────────────────────

/// 曲线参数 b 的标准十六进制（GB/T 32918.5-2017 §5.2.4）。
const B_HEX: &str = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
/// 基点 Gx。
const GX_HEX: &str = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
/// 基点 Gy。
const GY_HEX: &str = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

/// 曲线参数 a ≡ −3 (mod p)：从 p 域内机械推导（SM2 标准 a = p − 3）。
pub fn curve_a() -> FpSM2 {
    FpSM2::ZERO - FpSM2::from(3u64)
}

/// 曲线参数 b ∈ F_p。
pub fn curve_b() -> FpSM2 {
    fr_from_limbs(&hex_to_limbs_le(B_HEX))
}

/// 基点 G 坐标。
pub fn g_coords() -> (FpSM2, FpSM2) {
    (
        fr_from_limbs(&hex_to_limbs_le(GX_HEX)),
        fr_from_limbs(&hex_to_limbs_le(GY_HEX)),
    )
}

// ────────────────────────── 原生仿射参照 ──────────────────────────

/// 仿射点；`None` 为无穷远点 O。
pub type Affine = Option<(FpSM2, FpSM2)>;

/// 点在曲线上：y² = x³ + ax + b（O 恒真）。
pub fn on_curve_affine(p: Affine) -> bool {
    match p {
        None => true,
        Some((x, y)) => y.square() == x.square() * x + curve_a() * x + curve_b(),
    }
}

/// 点加（P==Q 走倍点；P+(−P)=O；含无穷远）。
pub fn affine_add(p: Affine, q: Affine) -> Affine {
    match (p, q) {
        (None, r) | (r, None) => r,
        (Some((x1, y1)), Some((x2, y2))) => {
            if x1 == x2 {
                if y1 == y2 {
                    affine_double(Some((x1, y1)))
                } else {
                    None
                }
            } else {
                let lam = (y2 - y1) * (x2 - x1).invert().unwrap();
                let x3 = lam.square() - x1 - x2;
                let y3 = lam * (x1 - x3) - y1;
                Some((x3, y3))
            }
        }
    }
}

/// 倍点（P ≠ O 且 y ≠ 0；O → O）。
pub fn affine_double(p: Affine) -> Affine {
    match p {
        None => None,
        Some((x, y)) => {
            debug_assert!(!bool::from(y.invert().is_none()), "2P=O for y=0");
            let lam = (FpSM2::from(3u64) * x.square() + curve_a())
                * (FpSM2::from(2u64) * y).invert().unwrap();
            let x3 = lam.square() - FpSM2::from(2u64) * x;
            let y3 = lam * (x - x3) - y;
            Some((x3, y3))
        }
    }
}

/// 标量乘（MSB-first double-and-add，`k_bits_le` 为小端位序）。全零位 → O。
pub fn affine_mul_bits(k_bits_le: &[bool], p: Affine) -> Affine {
    let mut acc: Affine = None;
    for i in (0..k_bits_le.len()).rev() {
        acc = affine_double(acc);
        if k_bits_le[i] {
            acc = affine_add(acc, p);
        }
    }
    acc
}

// ────────────────────────── 测试：常量三重锚定 + 群律 ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_params::n_limbs;
    use crate::sm3_compress::point_at_rank;

    /// 十进制字符串 → 小端位（附录 A 私钥解析用；num-bigint 仅测试面）。
    fn dec_to_bits_le(dec: &str) -> Vec<bool> {
        let v: num_bigint::BigUint = dec.parse().unwrap();
        let mut bits = Vec::new();
        for i in 0..v.bits() {
            bits.push(v.bit(i as u64));
        }
        while bits.len() < 256 {
            bits.push(false);
        }
        bits
    }

    /// SM2 标准示例用户 A 私钥 dA（GB/T 32918.2-2016 附录 A；十进制
    /// 与 m0 权威测试同源，该处注明经 Python 从标准 hex 换算并复核）。
    const DA_DEC: &str =
        "25903969540838461028817876707684319023187220463912685245116602391520054068664";

    #[test]
    fn curve_constants_triple_anchor() {
        // ① a ≡ −3 由域运算机械推导（对照标准 hex p−3 的最低 limb 抽查）
        let a = curve_a();
        assert_eq!(a, FpSM2::ZERO - FpSM2::from(3u64));
        // ② 基点在曲线上 —— 同时锚定 b / Gx / Gy 的每一比特：
        //    任一位抄错，方程 y²=x³+ax+b 必不成立。
        let g = g_coords();
        assert!(on_curve_affine(Some(g)), "标准基点必须在曲线上");
        // ③ 曲线非退化：b ≠ 0 且 4a³b ≠ 0（非奇异），此处抽查前件
        assert!(!bool::from(curve_b().invert().is_none()), "b 非零");
    }

    #[test]
    fn generator_order_is_n() {
        // n·G = O（阶侧锚定，与 N_HEX 解析互证）
        let n_bits = {
            let n = n_limbs();
            let mut v = Vec::with_capacity(256);
            for l in n.iter() {
                for i in 0..64 {
                    v.push((l >> i) & 1 == 1);
                }
            }
            v
        };
        assert_eq!(affine_mul_bits(&n_bits, Some(g_coords())), None, "n·G=O");
        // (n−1)·G = −G
        let mut nm1 = n_limbs();
        nm1[0] -= 1;
        let mut bits = Vec::new();
        for l in nm1.iter() {
            for i in 0..64 {
                bits.push((l >> i) & 1 == 1);
            }
        }
        let r = affine_mul_bits(&bits, Some(g_coords())).unwrap();
        let (gx, gy) = g_coords();
        assert_eq!((r.0, r.1), (gx, FpSM2::ZERO - gy), "(n−1)·G=−G");
    }

    #[test]
    fn d_a_vector_on_curve_and_group_law() {
        // 附录 A 向量：PA = dA·G 在曲线上、非平凡
        let pa = affine_mul_bits(&dec_to_bits_le(DA_DEC), Some(g_coords())).unwrap();
        assert!(on_curve_affine(Some(pa)), "PA=dA·G 必须在曲线上");
        assert_ne!(pa.0, FpSM2::ZERO);
        // 群律抽查：[7]G 与 [3]G+[4]G 一致
        let seven: Vec<bool> = {
            let mut v = vec![false; 256];
            v[0] = true;
            v[1] = true;
            v[2] = true;
            v
        };
        let three: Vec<bool> = {
            let mut v = vec![false; 256];
            v[0] = true;
            v[1] = true;
            v
        };
        let four: Vec<bool> = {
            let mut v = vec![false; 256];
            v[2] = true;
            v
        };
        let l = affine_mul_bits(&three, Some(g_coords()));
        let r = affine_mul_bits(&four, Some(g_coords()));
        let sum = affine_add(l, r);
        let direct = affine_mul_bits(&seven, Some(g_coords()));
        assert_eq!(sum, direct, "[3]G+[4]G=[7]G");
    }

    // ── 簇C-C2：ec_double / ec_add_fixed 门级对拍（计数锁定；负例 = 装配后篡改格）──

    fn expect_clean(
        info: &plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>,
        advice: &[Vec<FpSM2>],
        instances: &[Vec<FpSM2>],
    ) {
        let bad = crate::sm3_compress::check_parts_violations(info, advice, instances);
        assert!(bad.is_empty(), "正例不得有违约，首条 {bad:?}");
    }

    /// 在行 `at` 布置点见证并取输入束 [`PtIn`]。约定：门输入全 cur 读，
    /// 输入坐标必须写在门的激活行上（同轮直读 —— 模块头「表示层对应」
    /// 的设计决定）。真值由 PtIn 携带，与所写见证同源。
    fn point_val<'a>(b: &mut Builder<FpSM2>, cols: &'a PtCells, at: usize, v: Affine) -> PtRef<'a> {
        write_point(b, cols, at, v);
        PtRef::cells(cols, v)
    }

    fn native_lam(x: FpSM2, y: FpSM2) -> FpSM2 {
        (FpSM2::from(3u64) * x.square() + curve_a())
            * (y + y).invert().unwrap()
    }

    #[test]
    fn port_ec_double_matches_native_count_5() {
        let mut b = Builder::<FpSM2>::new(0);
        let g = g_coords();
        let at = point_at_rank(6);
        let pc = plan_point(&mut b);
        let pv = point_val(&mut b, &pc, at, Some(g));
        let sl = plan_ec_double(&mut b);
        let e0 = b.n_constraints();
        let out = emit_ec_double(&mut b, &sl, at, &pv, curve_a());
        assert_eq!(b.n_constraints() - e0, 5, "ec_double = 5 推");
        let want = affine_double(Some(g)).unwrap();
        assert_eq!(out.xv, want.0, "x");
        assert_eq!(out.yv, want.1, "y");
        assert!(!out.iv, "仿射结果");
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
        // 中间量格读回与原生一致（见证链绑定核对）
        assert_eq!(advice[sl.xsq][at], g.0.square());
        assert_eq!(advice[sl.lam][at], native_lam(g.0, g.1));
    }

    #[test]
    fn port_ec_double_o_case_preserves_infinity() {
        let mut b = Builder::<FpSM2>::new(0);
        let at = point_at_rank(6);
        let pc = plan_point(&mut b);
        let pv = point_val(&mut b, &pc, at, None);
        let sl = plan_ec_double(&mut b);
        let e0 = b.n_constraints();
        let out = emit_ec_double(&mut b, &sl, at, &pv, curve_a());
        assert_eq!(b.n_constraints() - e0, 5, "O 输入同样 5 推");
        assert!(out.iv, "O → O");
        assert_eq!(out.xv, FpSM2::ZERO);
        assert_eq!(out.yv, FpSM2::ZERO);
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
        // O 的见证面：u 任取 0（RHS = 1 − inf = 0），各乘积格同步为 0
        assert_eq!(advice[sl.u][at], FpSM2::ZERO);
    }

    #[test]
    fn port_ec_double_tamper_lambda_rejected() {
        let mut b = Builder::<FpSM2>::new(0);
        let g = g_coords();
        let at = point_at_rank(6);
        let pc = plan_point(&mut b);
        let pv = point_val(&mut b, &pc, at, Some(g));
        let sl = plan_ec_double(&mut b);
        let _ = emit_ec_double(&mut b, &sl, at, &pv, curve_a());
        let (info, mut advice, inst, _, _, _) = b.finish_parts();
        advice[sl.lam][at] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&info, &advice, &inst);
        assert!(!bad.is_empty(), "篡改 λ 必须违约（③④⑤ 三式联动）");
    }

    #[test]
    fn port_ec_add_fixed_all_cases_count_16_each() {
        let mut b = Builder::<FpSM2>::new(0);
        let g = g_coords();
        let ng = (g.0, FpSM2::ZERO - g.1);
        let g2 = affine_double(Some(g)).unwrap();
        let g3 = affine_add(Some(g2), Some(g)).unwrap();
        let cases: [(&str, Affine); 4] =
            [("D=O", None), ("D=P", Some(g)), ("D=-P", Some(ng)), ("general", Some(g3))];
        // 期望输出（原生参照）：D=O→P；D=P→2P；D=−P→O；一般 → D+P
        let wants: [Affine; 4] =
            [Some(g), Some(g2), None, affine_add(Some(g3), Some(g))];

        // 冻结纪律：四情形的全部 plan 与输入见证必须先于首个发射完成。
        // PtIn 借用点格句柄，故 Phase1 只存句柄，Phase2 再建束发射
        // （生命周期契约：PtIn 含 &'a PtCells，不能跨出存放循环）。
        let mut prepped: Vec<(usize, FixedSlots, PtCells, PtCells, PtCells)> = Vec::new();
        for (i, (_, dv)) in cases.iter().enumerate() {
            let at = point_at_rank(6 + i);
            let pcd = plan_point(&mut b);
            let pcb = plan_point(&mut b);
            let pc2 = plan_point(&mut b);
            write_point(&mut b, &pcd, at, *dv);
            write_point(&mut b, &pcb, at, Some(g));
            write_point(&mut b, &pc2, at, Some(g2));
            let sl = plan_ec_add_fixed(&mut b); // 每调用一套槽（家族纪律）
            prepped.push((at, sl, pcd, pcb, pc2));
        }

        let mut outs = Vec::new();
        for ((name, dv), (at, sl, pcd, pcb, pc2)) in cases.iter().zip(prepped.iter()) {
            let pin_d = PtRef::cells(pcd, *dv);
            let pin_b = PtRef::cells(pcb, Some(g));
            let pin_2 = PtRef::cells(pc2, Some(g2));
            let e0 = b.n_constraints();
            let o = emit_ec_add_fixed(&mut b, sl, *at, &pin_d, &pin_b, &pin_2);
            assert_eq!(b.n_constraints() - e0, 16, "{name}: 每调用恰 16 推");
            outs.push((*name, *at, *sl, o.pt));
        }

        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
        for (_, _, sl, _) in &outs {
            let acts = info.preprocess_polys[sl.sel - 1]
                .iter()
                .filter(|v| **v != FpSM2::ZERO)
                .count();
            assert_eq!(acts, 1, "sel#{} 必须单点激活", sl.sel);
        }
        for (i, (name, at, sl, pt)) in outs.into_iter().enumerate() {
            assert_eq!(pt, wants[i], "{name}: 输出真值对拍原生");
            match pt {
                None => assert_eq!(advice[sl.c_od][at], FpSM2::ONE, "{name}: inf 标志"),
                Some((x, y)) => {
                    assert_eq!(advice[sl.c_od][at], FpSM2::ZERO, "{name}: inf 标志");
                    assert_eq!(advice[sl.sx][at], x, "{name}: sx 格读回");
                    assert_eq!(advice[sl.sy][at], y, "{name}: sy 格读回");
                }
            }
        }
    }

    #[test]
    fn port_ec_add_fixed_minus_p_tamper_od_rejected() {
        // D = −P：c_od 代数强制为 1（u·¬a₂），篡改为 0 必违约
        let mut b = Builder::<FpSM2>::new(0);
        let g = g_coords();
        let at = point_at_rank(6);
        let pcd = plan_point(&mut b);
        let pcb = plan_point(&mut b);
        let pc2 = plan_point(&mut b);
        let vd = point_val(&mut b, &pcd, at, Some((g.0, FpSM2::ZERO - g.1)));
        let vb = point_val(&mut b, &pcb, at, Some(g));
        let v2 = point_val(&mut b, &pc2, at, Some(affine_double(Some(g)).unwrap()));
        let sl = plan_ec_add_fixed(&mut b);
        let _ = emit_ec_add_fixed(&mut b, &sl, at, &vd, &vb, &v2);
        let (info, mut advice, inst, _, _, _) = b.finish_parts();
        advice[sl.c_od][at] = FpSM2::ZERO;
        let bad = crate::sm3_compress::check_parts_violations(&info, &advice, &inst);
        assert!(!bad.is_empty(), "D=−P 的 c_od 改 0 必须被击中");
    }

    #[test]
    fn port_ec_add_complete_all_cases_count_28_each() {
        let mut b = Builder::<FpSM2>::new(0);
        let g = g_coords();
        let ng = (g.0, FpSM2::ZERO - g.1);
        let g2 = affine_double(Some(g)).unwrap();
        let g3 = affine_add(Some(g2), Some(g)).unwrap();
        let cases: [(&str, Affine, Affine); 6] = [
            ("O+O", None, None),
            ("O+G", None, Some(g)),
            ("G+O", Some(g), None),
            ("G+(-G)", Some(g), Some(ng)),
            ("G+G", Some(g), Some(g)), // P=Q：c_dbl 分支（走内嵌 2P 叶）
            ("general", Some(g2), Some(g)),
        ];
        // 期望输出（原生参照 affine_add，与门语义同源对拍）
        let wants: [Affine; 6] =
            [None, Some(g), Some(g), None, Some(g2), Some(g3)];

        // 冻结纪律：全部 plan 与输入见证先于首个发射；PtIn 借句柄，
        // Phase1 只存句柄（生命周期契约），Phase2 建束顺序发射。
        let mut prepped: Vec<(usize, CompleteSlots, PtCells, PtCells)> = Vec::new();
        for (i, (_, pv, qv)) in cases.iter().enumerate() {
            let at = point_at_rank(20 + i);
            let pcp = plan_point(&mut b);
            let pcq = plan_point(&mut b);
            write_point(&mut b, &pcp, at, *pv);
            write_point(&mut b, &pcq, at, *qv);
            let sl = plan_ec_add_complete(&mut b); // 每调用一套槽（家族纪律）
            prepped.push((at, sl, pcp, pcq));
        }

        let mut outs = Vec::new();
        for ((name, pv, qv), (at, sl, pcp, pcq)) in cases.iter().zip(prepped.iter()) {
            let pin_p = PtRef::cells(pcp, *pv);
            let pin_q = PtRef::cells(pcq, *qv);
            let e0 = b.n_constraints();
            let o = emit_ec_add_complete(&mut b, sl, *at, &pin_p, &pin_q, curve_a());
            assert_eq!(b.n_constraints() - e0, 28, "{name}: 每调用恰 28 推");
            outs.push((*name, *at, *sl, o.pt));
        }

        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
        // 家族自检：主选择器与内嵌倍点选择器都必须单点激活
        for (_, _, sl, _) in &outs {
            for s in [sl.sel, sl.dbl.sel] {
                let acts = info.preprocess_polys[s - 1]
                    .iter()
                    .filter(|v| **v != FpSM2::ZERO)
                    .count();
                assert_eq!(acts, 1, "sel#{s} 必须单点激活");
            }
        }
        for (i, (name, at, sl, pt)) in outs.into_iter().enumerate() {
            assert_eq!(pt, wants[i], "{name}: 输出真值对拍原生");
            match pt {
                None => assert_eq!(advice[sl.i3][at], FpSM2::ONE, "{name}: i₃=1"),
                Some((x, y)) => {
                    assert_eq!(advice[sl.i3][at], FpSM2::ZERO, "{name}: i₃=0");
                    assert_eq!(advice[sl.sx][at], x, "{name}: sx 格读回");
                    assert_eq!(advice[sl.sy][at], y, "{name}: sy 格读回");
                }
            }
        }
    }

    #[test]
    fn port_ec_add_complete_minus_q_tamper_cod_rejected() {
        // G + (−G)：c_od 由 u·¬a₂ 代数强制为 1，篡改为 0 必违约
        let mut b = Builder::<FpSM2>::new(0);
        let g = g_coords();
        let ng = (g.0, FpSM2::ZERO - g.1);
        let at = point_at_rank(40);
        let pcp = plan_point(&mut b);
        let pcq = plan_point(&mut b);
        write_point(&mut b, &pcp, at, Some(g));
        write_point(&mut b, &pcq, at, Some(ng));
        let sl = plan_ec_add_complete(&mut b);
        let pin_p = PtRef::cells(&pcp, Some(g));
        let pin_q = PtRef::cells(&pcq, Some(ng));
        let out = emit_ec_add_complete(&mut b, &sl, at, &pin_p, &pin_q, curve_a());
        assert_eq!(out.pt, None, "G+(−G) 必须为 O");
        let (info, mut advice, inst, _, _, _) = b.finish_parts();
        advice[sl.cod][at] = FpSM2::ZERO;
        let bad = crate::sm3_compress::check_parts_violations(&info, &advice, &inst);
        assert!(!bad.is_empty(), "P=−Q 的 c_od 改 0 必须被击中");
    }

    #[test]
    fn port_ec_mul_loop_const_base_count_6147() {
        let mut b = Builder::<FpSM2>::new(0);
        let g = g_coords();
        let d2 = affine_double(Some(g)).unwrap();
        let bits = dec_to_bits_le(DA_DEC); // 256 位小端
        let n = bits.len();
        // Fix R-a：257 连续秩（rows[0]=头行兼迭代 0、rows[n]=纯接收行）
        let rows: Vec<usize> = (0..=n).map(|i| point_at_rank(1000 + i)).collect();
        let sl = plan_ec_mul_loop(&mut b);
        let e0 = b.n_constraints();
        let out =
            emit_ec_mul_loop_const_base(&mut b, &sl, &rows, g, d2, &bits, curve_a());
        assert_eq!(
            b.n_constraints() - e0,
            24 * n + 3,
            "常基点循环 = 256×24 + 头钉 3 = 6147 锁定（Fix R-a）"
        );
        let want = affine_mul_bits(&bits, Some(g)).unwrap();
        assert_eq!(out.pt, Some(want), "[dA]G 对拍原生 double-and-add");
        let (info, advice, inst, _, _, _) = b.finish_parts();
        expect_clean(&info, &advice, &inst);
        // 家族共享自检：三族选择器激活点数均 = 迭代数；头钉选择器 = 1
        for s in [sl.dbl.sel, sl.fixed.sel, sl.lsel] {
            let acts = info.preprocess_polys[s - 1]
                .iter()
                .filter(|v| **v != FpSM2::ZERO)
                .count();
            assert_eq!(acts, n, "sel#{s} 激活点数应 = 迭代数 {n}");
        }
        {
            let acts = info.preprocess_polys[sl.head_sel - 1]
                .iter()
                .filter(|v| **v != FpSM2::ZERO)
                .count();
            assert_eq!(acts, 1, "head_sel#{ } 必须单点激活（rows[0]）", sl.head_sel);
        }
        // Fix R-a：末轮输出读 acc_in@rows[n]（尾接收行，由第 n−1 迭代
        // sel_bind_rot 以 Rotation(1) 自写）
        let last = rows[n];
        assert_eq!(advice[sl.acc_in.cols[0]][last], want.0, "末轮 acc_in.x 读回");
        assert_eq!(advice[sl.acc_in.cols[1]][last], want.1, "末轮 acc_in.y 读回");
        assert_eq!(
            advice[sl.acc_in.cols[2]][last],
            FpSM2::ZERO,
            "末轮 inf 标志"
        );
        // 头行钉死读回：acc_in@rows[0] = O（head_sel 3 推的面）
        assert_eq!(
            advice[sl.acc_in.cols[2]][rows[0]],
            FpSM2::ONE,
            "头行 inf=1"
        );
    }

    #[test]
    fn port_ec_mul_loop_tamper_lambda_rejected() {
        // 极小例 [1]G 亦须可证：中途篡改任一中间格必违约
        let mut b = Builder::<FpSM2>::new(0);
        let g = g_coords();
        let d2 = affine_double(Some(g)).unwrap();
        let bits = [true];
        // Fix R-a：1 迭代 + 1 接收行 = 2 连续秩（257 连续秩的 n=1 缩影）
        let rows = [point_at_rank(1000), point_at_rank(1001)];
        let sl = plan_ec_mul_loop(&mut b);
        emit_ec_mul_loop_const_base(&mut b, &sl, &rows, g, d2, &bits, curve_a());
        let (info, mut advice, inst, _, _, _) = b.finish_parts();
        advice[sl.dbl.lam][rows[0]] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&info, &advice, &inst);
        assert!(!bad.is_empty(), "λ 篡改必须被击中（倍点链联动）");
    }
}
