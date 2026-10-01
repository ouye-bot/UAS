//! L2b 固定基窗口乘 · 主装配 Builder 化（③手术 S1b，2026-09-26）。
//!
//! 原型 sm2_ec_window_proto.rs（独立电路 verify OK）的方法移植到
//! sm3_compress::Builder 生产装配：G 的 4bit 窗口表（64 窗×16 选点+末减点
//! =1,026 项）为常数预处理列（六循环共享一张表），单标量乘=65 行×
//! 8 见证列+7 门控约束+1 查表通道。
//!
//! 与原型逐条对齐的已验形态（[实测] 见原型模块头）：
//! - 数字集 1..16 偏移表示：k′=k+offset，d_i∈1..16，[k]G=[k′]G−[offset]G，
//!   末减点=−Σ_{i} [16^i]G；
//! - 查表输入=d′（数字+1 的偏移表示，纯见证列——复合输入 [实测] 触发
//!   sumcheck 不一致）；表项 (窗口号 idx, d′, x, y) 联合 4 列查表；
//! - 沿行仿射累加（distinct-x 概率性假设）：λ(x−sx′)=y−sy′；
//!   sx=λ²−sx′−x；sy=λ(sx′−sx)−sy′；倍点斜率含 a=p−3（漏加 [实测] 失配）；
//! - 行相关常数列 QIDX 钉窗口号（Builder 化=alloc_const_poly，原型
//!   pre[P_QIDX] 同式）。
//!
//! 红线：表点/累加链全部装配期宿主真值直填（与 const_base 循环同纪律）；
//! 电路仅强制「选点∈本行该窗口的表 + 累加链自洽」；负例矩阵四形态见
//! 手术方案 §二.5（表项篡改/位移不一致/末减点遗漏/idx 错窗）。

use ff::{Field, PrimeField};

use crate::sm2_ec_plonkish::{affine_add, affine_double, Affine};
use crate::sm2_params::fr_to_limbs;
use crate::FpSM2;

/// 窗口数 65：SM2 阶 n≈16^64·(1−2^−32)，k′=k+offset（offset=Σ_{i=0..64}16^i）
/// < 16^65 ⟹ 需 65 个 4bit 数字穷尽且全非零；U256 容器在高位 k 下溢出
/// （[实测] window_host_matches_native_mul_32rand 首探即红）——容器升 5 limb。
pub const WINDOWS: usize = 65;
/// 每标量乘行占用：65 窗口行 + 1 末减行。
pub const ROWS_USED: usize = WINDOWS + 1;
/// 表项数：65 窗×16 选点 + 1 末减点。
pub const TABLE_ENTRIES: usize = WINDOWS * 16 + 1;

type Pt = (FpSM2, FpSM2);

// ─────────────── U288 宽容器（5 limb——k+offset 需 65 nibble） ───────────────

#[derive(Clone, Copy)]
struct U288([u64; 5]);

impl U288 {
    fn add(self, o: U288) -> U288 {
        let mut r = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..5 {
            let t = self.0[i] as u128 + o.0[i] as u128 + carry;
            r[i] = t as u64;
            carry = t >> 64;
        }
        assert_eq!(carry, 0, "U288 溢出");
        U288(r)
    }
    fn sub_small(self, v: u64) -> U288 {
        let mut r = self.0;
        let mut borrow = (r[0] < v) as u64;
        r[0] = r[0].wrapping_sub(v);
        let mut i = 1;
        while borrow > 0 && i < 5 {
            borrow = (r[i] == 0) as u64;
            r[i] = r[i].wrapping_sub(1);
            i += 1;
        }
        assert_eq!(borrow, 0, "U288 负数");
        U288(r)
    }
    fn shr4(self) -> U288 {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] >> 4;
            if i + 1 < 5 {
                r[i] |= self.0[i + 1] << 60;
            }
        }
        U288(r)
    }
    fn low4(self) -> u64 {
        self.0[0] & 0xF
    }
    fn is_zero(self) -> bool {
        self.0 == [0u64; 5]
    }
}

/// offset 的域元素形态（绑定约束常数项；调用面单点门发射用）。
pub fn offset_fq() -> FpSM2 {
    let mut acc = FpSM2::ZERO;
    let mut pw = FpSM2::ONE;
    for _ in 0..WINDOWS {
        acc += FpSM2::ONE * pw;
        pw *= FpSM2::from(16u64);
    }
    acc
}

/// offset = Σ_{i=0..64} 16^i（65 nibble 全 1：limbs[0..4]=0x1111…1，limbs[4]=1）。
fn offset_u288() -> U288 {
    U288([
        0x1111_1111_1111_1111,
        0x1111_1111_1111_1111,
        0x1111_1111_1111_1111,
        0x1111_1111_1111_1111,
        1,
    ])
}

/// 标量 → 65 个 4bit 数字（1..16 偏移表示，窗口 0=低位）。
pub fn digits_1_16(k: &FpSM2) -> [u8; WINDOWS] {
    digits_1_16_limbs(&fr_to_limbs(k))
}

/// limbs 形态入口（宿主对拍与装配层共用）。
pub fn digits_1_16_limbs(l: &[u64; 4]) -> [u8; WINDOWS] {
    let mut rem = U288([l[0], l[1], l[2], l[3], 0]).add(offset_u288());
    let mut out = [0u8; WINDOWS];
    for d in out.iter_mut() {
        let m = rem.low4();
        *d = if m == 0 { 16 } else { m as u8 };
        rem = rem.sub_small(*d as u64).shr4();
    }
    assert!(rem.is_zero(), "65 数字须穷尽 k+offset");
    out
}

// ─────────────── 宿主真值（表+累加链） ───────────────

/// G 的窗口表宿主形态：tables[i][j] = [16^i·(j+1)]G（j=0..15），
/// bases[i] = [16^i]G，neg_off = −Σ_{i} bases[i]。
pub struct GTableHost {
    pub tables: Vec<[Pt; 16]>,
    pub bases: Vec<Pt>,
    pub neg_off: Pt,
}

/// 宿主算表（装配期一次；g 固定 ⟹ 全循环共享）。
pub fn host_g_table(g: Pt) -> GTableHost {
    let mut base = Some(g);
    let mut tables = Vec::with_capacity(WINDOWS);
    let mut bases = Vec::with_capacity(WINDOWS);
    for _ in 0..WINDOWS {
        let b = base.expect("基点非 O");
        let mut row: [Pt; 16] = [(FpSM2::ZERO, FpSM2::ZERO); 16];
        row[0] = b;
        row[1] = affine_double(Some(b)).expect("2P=O 概率 0");
        for j in 2..16 {
            row[j] = affine_add(Some(row[j - 1]), Some(b))
                .expect("distinct-x 概率性假设（同原型）");
        }
        tables.push(row);
        bases.push(b);
        for _ in 0..4 {
            base = affine_double(base);
        }
    }
    let mut off_pt: Affine = Some(bases[0]);
    for b in &bases[1..] {
        off_pt = affine_add(off_pt, Some(*b));
    }
    let off = off_pt.expect("offset 和非 O（概率 0）");
    GTableHost { tables, bases, neg_off: (off.0, -off.1) }
}

/// 累加链宿主真值：链行 r=1..65 的 (选点, 累加后 x, 累加后 y) 与终点。
/// 终点 Option：r=0（或离散窗）时末步为 O——负例合法形态（旧循环 None
/// 同语义；O 情形 sx/sy 写零格保环一致）。中间步碰 O 仍 panic（distinct-x
/// 概率性假设——宿主对拍面）。
pub fn host_chain(digits: &[u8; WINDOWS], t: &GTableHost) -> (Vec<(Pt, Pt)>, Affine) {
    let mut chain = Vec::with_capacity(ROWS_USED);
    let mut acc: Affine = None;
    for r in 1..=ROWS_USED {
        let pt = if r <= WINDOWS {
            t.tables[r - 1][digits[r - 1] as usize - 1]
        } else {
            t.neg_off
        };
        acc = if r == 1 { Some(pt) } else { affine_add(acc, Some(pt)) };
        if r < ROWS_USED {
            let a = acc.expect("累加链中间碰 O（distinct-x 概率性假设）");
            chain.push((pt, a));
        } else {
            let a = acc.unwrap_or((FpSM2::ZERO, FpSM2::ZERO));
            chain.push((pt, a));
        }
    }
    (chain, acc)
}

/// 宿主对拍锚：L2b 终点 == affine_mul_bits 真值（native 权威同源）。
pub fn host_mul_g(k: &FpSM2, g: Pt) -> Option<Pt> {
    let digits = digits_1_16(k);
    let t = host_g_table(g);
    let (_chain, out) = host_chain(&digits, &t);
    out
}

// ─────────────── Builder 集成（主装配 gadget，两相） ───────────────

use crate::sm3_compress::{row_mapping, Builder};

/// G 窗口表的共享常数列（四列全电路一份；表项填自然行 0..1026——查表表列
/// 多重集语义位置无关，原型同式）。
pub struct GTableCols {
    pub c_idx: usize,
    pub c_d: usize,
    pub c_x: usize,
    pub c_y: usize,
    pub host: GTableHost,
}

impl Default for GTableCols {
    fn default() -> Self {
        GTableCols { c_idx: 0, c_d: 0, c_x: 0, c_y: 0, host: GTableHost {
            tables: Vec::new(), bases: Vec::new(), neg_off: (FpSM2::ZERO, FpSM2::ZERO),
        } }
    }
}

/// 分配并填充 G 窗口表（每电路一次；调用方保管，六循环共享）。
pub fn alloc_g_table(b: &mut Builder<FpSM2>, g: Pt) -> GTableCols {
    let host = host_g_table(g);
    let mut c_idx = vec![FpSM2::ZERO; crate::sm3_compress::ROWS];
    let mut c_d = vec![FpSM2::ZERO; crate::sm3_compress::ROWS];
    let mut c_x = vec![FpSM2::ZERO; crate::sm3_compress::ROWS];
    let mut c_y = vec![FpSM2::ZERO; crate::sm3_compress::ROWS];
    let mut trow = 0usize;
    for i in 0..WINDOWS {
        for j in 0..16usize {
            c_idx[trow] = FpSM2::from(i as u64);
            c_d[trow] = FpSM2::from((j + 2) as u64);
            c_x[trow] = host.tables[i][j].0;
            c_y[trow] = host.tables[i][j].1;
            trow += 1;
        }
    }
    c_idx[trow] = FpSM2::from(WINDOWS as u64);
    c_d[trow] = FpSM2::ONE;
    c_x[trow] = host.neg_off.0;
    c_y[trow] = host.neg_off.1;
    trow += 1;
    assert!(trow < crate::sm3_compress::ROWS, "表项超出行预算");
    GTableCols {
        c_idx: b.alloc_const_poly(c_idx),
        c_d: b.alloc_const_poly(c_d),
        c_x: b.alloc_const_poly(c_x),
        c_y: b.alloc_const_poly(c_y),
        host,
    }
}

#[derive(Default)]
/// 单窗口乘的槽位（8 见证列+1 窗口号常数列+3 选择器——全部 PLAN 相分配；
/// 冻结守卫 J-10b ⑤：alloc 必须先于首条款束，rank_base 由此必须在 plan
/// 时给定）。
pub struct WindowMulSlots {
    pub w_idx: usize,
    pub w_d: usize,
    pub w_dshift: usize,
    pub w_x: usize,
    pub w_y: usize,
    pub w_lam: usize,
    pub w_sx: usize,
    pub w_sy: usize,
    pub q_idx_const: usize,
    pub qinit: usize,
    pub qadd: usize,
    pub row_sel: usize,
    /// 标量聚合列：acc@窗行 r = Σ_{i≤r} d_i·16^{i−1}（链约束逐行传递；
    /// 行 0 钉 0——head 锚定聚合的绝对值，防整链平移的绑定空转）。
    pub w_acc: usize,
    /// 位移积格：dp@行 r = d_r·16^{r−1}（witness 自由——由约束 A
    /// dp=d·qK 与行相关常数列钉定。🔴 逐行不同常数不得进共享选择器的
    /// 全局约束——S2 实测 4,290 违约的根因）。
    pub w_dpw: usize,
    /// 窗常数列（行相关常数）：qK@行 r = 16^{r−1}（alloc_const_poly——
    /// QIDX 同族；全循环不可共享——rank 窗不同）。
    pub q_k: usize,
    pub acc0_sel: usize,
    /// 差值格（acc@末行 − offset = [k]G 的标量 k）+ 其单点门。
    pub diff_col: usize,
    pub diff_sel: usize,
}

/// PLAN 相：分配全部槽位（常数列值/选择器激活点由 rank_base 确定）。
pub fn plan_window_mul(b: &mut Builder<FpSM2>, rank_base: usize) -> WindowMulSlots {
    let rm = row_mapping();
    let at = |r: usize| {
        let p = rm[rank_base + r];
        assert_ne!(p, 0, "秩映射到吸收态点 0");
        p
    };
    let mut qidx = vec![FpSM2::ZERO; crate::sm3_compress::ROWS];
    let mut pts_init = Vec::with_capacity(1);
    let mut pts_add = Vec::with_capacity(ROWS_USED - 1);
    let mut pts_act = Vec::with_capacity(ROWS_USED);
    for r in 1..=ROWS_USED {
        let p = at(r);
        qidx[p] = FpSM2::from((r - 1) as u64);
        pts_act.push(p);
        if r == 1 {
            pts_init.push(p);
        } else {
            pts_add.push(p);
        }
    }
    WindowMulSlots {
        w_idx: b.alloc_col(),
        w_d: b.alloc_col(),
        w_dshift: b.alloc_col(),
        w_x: b.alloc_col(),
        w_y: b.alloc_col(),
        w_lam: b.alloc_col(),
        w_sx: b.alloc_col(),
        w_sy: b.alloc_col(),
        q_idx_const: b.alloc_const_poly(qidx),
        qinit: b.alloc_selector(&pts_init),
        qadd: b.alloc_selector(&pts_add),
        row_sel: b.alloc_selector(&pts_act),
        w_acc: b.alloc_col(),
        w_dpw: b.alloc_col(),
        q_k: {
            let mut qk = vec![FpSM2::ZERO; crate::sm3_compress::ROWS];
            let mut pw = FpSM2::ONE;
            for r in 1..=ROWS_USED {
                qk[at(r)] = pw;
                pw *= FpSM2::from(16u64);
            }
            b.alloc_const_poly(qk)
        },
        acc0_sel: b.alloc_selector(&[at(0)]),
        diff_col: b.alloc_col(),
        diff_sel: b.alloc_selector(&[at(ROWS_USED)]),
    }
}

/// EMIT 相：给定秩基址与标量真值，填见证、发 7 门控约束+1 查表通道。
/// 返回输出格 ((sx_col, sy_col), 物理末行点)——[k]G 的仿射坐标。
/// 纪律：rank 窗 [rank_base+1, rank_base+65] 须由布局方预留给本 gadget。
pub fn emit_window_mul(
    b: &mut Builder<FpSM2>,
    sl: &WindowMulSlots,
    tbl: &GTableCols,
    rank_base: usize,
    k: &FpSM2,
) -> ((usize, usize), usize, Pt) {
    let rm = row_mapping();
    let at = |r: usize| {
        let p = rm[rank_base + r];
        assert_ne!(p, 0, "秩映射到吸收态点 0");
        p
    };
    let digits = digits_1_16(k);
    let (chain, out_opt) = host_chain(&digits, &tbl.host);

    // 见证直填（宿主真值——与 const_base 循环同纪律）。
    for (r, (pt, acc)) in chain.iter().enumerate() {
        let p = at(r + 1);
        let d = if r < WINDOWS { digits[r] as u64 } else { 0 };
        b.set_cell_f(sl.w_idx, p, FpSM2::from(r as u64));
        b.set_cell_f(sl.w_d, p, FpSM2::from(d));
        b.set_cell_f(sl.w_dshift, p, FpSM2::from(d + 1));
        b.set_cell_f(sl.w_x, p, pt.0);
        b.set_cell_f(sl.w_y, p, pt.1);
        if r > 0 {
            let lam = (pt.1 - chain[r - 1].1 .1) * (pt.0 - chain[r - 1].1 .0).invert().expect("distinct-x");
            b.set_cell_f(sl.w_lam, p, lam);
        }
        b.set_cell_f(sl.w_sx, p, acc.0);
        b.set_cell_f(sl.w_sy, p, acc.1);
    }

    // 表达式（witness 列一律走 b.q——局部号→全局号转换；🔴 直构 Query 用
    // 局部号=列错位，sumcheck 求值不匹配 [S2 实测]）。prep 列本就全局号。
    use plonkish_backend::util::expression::{Expression, Rotation};
    let (idx, d, dsh) = (b.q(sl.w_idx, Rotation::cur()), b.q(sl.w_d, Rotation::cur()), b.q(sl.w_dshift, Rotation::cur()));
    let (x, y) = (b.q(sl.w_x, Rotation::cur()), b.q(sl.w_y, Rotation::cur()));
    let (lam, sx, sy) = (b.q(sl.w_lam, Rotation::cur()), b.q(sl.w_sx, Rotation::cur()), b.q(sl.w_sy, Rotation::cur()));
    let sxp = b.q(sl.w_sx, Rotation(-1));
    let syp = b.q(sl.w_sy, Rotation(-1));
    let one = Expression::<FpSM2>::Constant(FpSM2::ONE);

    // 查表（4 列联合；d′=数字+1 偏移表示）。
    b.emit_lookup(vec![
        (idx.clone(), b.prep_cur(tbl.c_idx)),
        (dsh.clone(), b.prep_cur(tbl.c_d)),
        (x.clone(), b.prep_cur(tbl.c_x)),
        (y.clone(), b.prep_cur(tbl.c_y)),
    ]);

    // 标量聚合链（绑定约束的正确形态——跨行求和不能用单行表达式）：
    // 行 r（r=1..65）：acc_r = acc_{r−1} + d_r·16^{r−1}（Rotation(-1) 读前
    // 行；行 0 由 acc0_sel 钉 0——锚定绝对值）。末行 acc = k′ = k+offset。
    let mut acc_run = FpSM2::ZERO; // 宿主聚合真值：Σ_{i≤r} d_i·16^{i−1}
    for r in 1..=ROWS_USED {
        let p = at(r);
        // 行 1..65=窗口行（d=digits）；行 66=末减行（d=0——减点不进聚合，
        // k = acc@末行 − offset 由 diff 约束承担）。
        let dval = if r <= WINDOWS { FpSM2::from(digits[r - 1] as u64) } else { FpSM2::ZERO };
        let dpv = dval * {
            let mut pw = FpSM2::ONE;
            for _ in 1..r {
                pw *= FpSM2::from(16u64);
            }
            pw
        };
        acc_run += dpv;
        b.set_cell_f(sl.w_dpw, p, dpv);
        b.set_cell_f(sl.w_acc, p, acc_run);
    }
    // 约束 A（位移积钉定）：dp = d·qK（行相关常数列——同表达式处处成立）。
    b.emit_assert_zero_tagged(
        "ec.win.dpw",
        sl.row_sel,
        b.q(sl.w_dpw, Rotation::cur())
            - b.q(sl.w_d, Rotation::cur()) * b.prep_cur(sl.q_k),
    );
    // 约束 B（聚合链）：acc = acc_prev + dp（常数进 witness 格——行无关表达式）。
    // 2026-10 冗余消除（ec.win.acc.chain 66→1/窗）：旧 for r 循环体逐字全同
    // （行坐标算出即弃——`let _ = p;`），66 条全同约束在 row_sel∈{0,1} 门控
    // 下域上等价于 1 条（66·E=0 ⟺ E=0）。删循环、单次发射，同 tag/同 sel/
    // 同表达式；篡改语义不变——acc 中段一格 +δ ⟹ 本行 (+δ) 与下一行 (−δ)
    // 两处违约（row_sel 门控整组窗行），acc.head 行 0 钉零防整链平移不变。
    b.emit_assert_zero_tagged(
        "ec.win.acc.chain",
        sl.row_sel,
        b.q(sl.w_acc, Rotation::cur())
            - b.q(sl.w_acc, Rotation(-1))
            - b.q(sl.w_dpw, Rotation::cur()),
    );
    // 行 0 钉 0（聚合头锚——防整链平移的绑定空转）。
    b.emit_assert_zero_tagged(
        "ec.win.acc.head",
        sl.acc0_sel,
        b.q(sl.w_acc, Rotation::cur()),
    );
    // 差值：diff = acc@末行 − offset = k（诚实 witness 直填标量真值；环等值
    // 到调用面的 val 格——与 r 位世界 recomp 锚定闭合）。
    b.emit_assert_zero_tagged(
        "ec.win.diff",
        sl.diff_sel,
        b.q(sl.diff_col, Rotation::cur()) - b.q(sl.w_acc, Rotation::cur())
            + Expression::<FpSM2>::Constant(offset_fq()),
    );
    b.set_cell_f(sl.diff_col, at(ROWS_USED), *k);

    // 7 门控约束（原型逐条；家族标签=负例可具名）。
    b.emit_assert_zero_tagged("ec.win.dshift", sl.row_sel, dsh.clone() - d.clone() - one);
    b.emit_assert_zero_tagged("ec.win.idx", sl.row_sel, idx.clone() - b.prep_cur(sl.q_idx_const));
    b.emit_assert_zero_tagged("ec.win.init.x", sl.qinit, sx.clone() - x.clone());
    b.emit_assert_zero_tagged("ec.win.init.y", sl.qinit, sy.clone() - y.clone());
    b.emit_assert_zero_tagged(
        "ec.win.add.lam",
        sl.qadd,
        lam.clone() * (x.clone() - sxp.clone()) - (y.clone() - syp.clone()),
    );
    b.emit_assert_zero_tagged(
        "ec.win.add.sx",
        sl.qadd,
        sx.clone() - lam.clone() * lam.clone() + sxp.clone() + x.clone(),
    );
    b.emit_assert_zero_tagged(
        "ec.win.add.sy",
        sl.qadd,
        sy.clone() - lam * (sxp - sx) + syp,
    );

    // 终点 O（r=0 负例形态）→ 零坐标正常返回（旧循环 None 同语义——对拍面
    // 两侧同为 None；验证拒绝由 r∈[1,n−1] 门承担，装配不 panic）。
    ((sl.w_sx, sl.w_sy), at(ROWS_USED), out_opt.unwrap_or((FpSM2::ZERO, FpSM2::ZERO)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_ec_plonkish::affine_mul_bits;
    use crate::sm2_params::fr_from_limbs;

    fn g_coords() -> Pt {
        // SM2 生成元（与 sm2_verify_assemble 同源）。
        let gx = crate::sm2_params::hex_to_limbs_le(
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
        );
        let gy = crate::sm2_params::hex_to_limbs_le(
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
        );
        (fr_from_limbs(&gx), fr_from_limbs(&gy))
    }

    /// 数学面对拍：窗口法终点 == affine_mul_bits 真值（随机 32 标量）。
    #[test]
    fn window_host_matches_native_mul() {
        let g = g_coords();
        let mut seed = 0x9E3779B97F4A7C15u64;
        for case in 0..32u32 {
            let limbs: [u64; 4] = [
                seed_mix(&mut seed),
                seed_mix(&mut seed),
                seed_mix(&mut seed),
                seed_mix(&mut seed),
            ];
            let k = fr_from_limbs(&limbs);
            let want = affine_mul_bits(&bits_le(&k), Some(g)).expect("非 O");
            let got = host_mul_g(&k, g);
            assert_eq!(want, got.expect("非 O"), "case {case} 窗口法失配");
        }
    }

    fn seed_mix(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    fn bits_le(k: &FpSM2) -> Vec<bool> {
        let l = fr_to_limbs(k);
        (0..256).map(|i| ((l[i / 64] >> (i % 64)) & 1) == 1).collect()
    }
}
