//! L2b 原型：SM2 **固定基点**标量乘的 4 位窗口化——单表查表选点 + 沿行仿射累加（系统线
//! 2026-09-17，分支 `system/sm3-lookup-proto`，不入论文线）。
//!
//! 构造（全部落在 K=12，仅用 65 行）：
//! - 数字集 1..16 偏移表示（offset=Σ16^i，[k]G=[k']G−[offset]G，d_i ∈ 1..16）；
//! - 单表四元组 (窗口号 idx, d′, x, y)：行 0 哨兵 + 窗口点 (i, j+2, x, y) + 末减点
//!   (64, 1, x_off, −y_off)，共 1,026 项 < 4,096；
//! - 行打包：行 r=1..64 = 窗口 r−1 选点 (idx=r−1, d′=d+1)，行 65 = 末减点；idx 固定列钉死；
//! - 查表输入=纯见证列 d′（复合输入 [实测] 触发 sumcheck 不一致）；位移 d′=d+qact 受约束；
//! - 累加沿行：λ(x−sx′)=y−sy′；sx=λ²−sx′−x；sy=λ(sx′−sx)−sy′（distinct-x 概率性假设）；
//! - SM2 倍点斜率必须含曲线参数 a=p−3 [实测：漏加=与权威 affine_mul_bits 不一致]。
//! 形状：固定列 8 + 见证列 8 = 16 多项式；1 查表；7 约束；行占用 65。

use ff::{Field, PrimeField};
use plonkish_backend::{
    backend::{PlonkishCircuit, PlonkishCircuitInfo},
    util::expression::{Expression, Query, Rotation},
    Error,
};

pub type Fr = crate::FpSM2;
pub const K: usize = 12;
pub const ROWS: usize = 1 << K;
pub const WINDOWS: usize = 64;

// 固定列
const P_QIDX: usize = 0;
const P_QINIT: usize = 1;
const P_QADD: usize = 2;
const P_QACT: usize = 3;
const P_TIDX: usize = 4;
const P_TD: usize = 5;
const P_TX: usize = 6;
const P_TY: usize = 7;
// L2b verify 定谳（2026-09-18，系统线差分实测）：真根因 = 旋转行序（见 build 内 row_mapping
// 注）。论文线两条假设——①列 8–22 十五列全零未引用空洞 ②num_challenges=0——经差分逐一
// 否证：仅修①②（无行序修复）仍 InvalidSnark；行序修复后单独恢复①（NUM_P=24）或②（0 挑战）
// 均 verify OK。此处紧凑列空间（移除从未引用的 P_CONST，NUM_P=8）与下方 num_challenges=1
// 仅为与论文线 builder 约定对齐的卫生项，非修复本体。
const NUM_P: usize = 8;
// 见证列（相对）
const W_IDX: usize = 0;
const W_D: usize = 1;
const W_DSHIFT: usize = 2;
const W_X: usize = 3;
const W_Y: usize = 4;
const W_LAM: usize = 5;
const W_SX: usize = 6;
const W_SY: usize = 7;
const NUM_W: usize = 8;

fn gw(i: usize) -> usize {
    NUM_P + i
}

fn poly(idx: usize) -> Expression<Fr> {
    Expression::Polynomial(Query::new(idx, Rotation(0)))
}
fn qprev(idx: usize) -> Expression<Fr> {
    Expression::Polynomial(Query::new(idx, Rotation(-1)))
}
fn q(idx: usize) -> Expression<Fr> {
    poly(idx)
}
fn c(v: u64) -> Expression<Fr> {
    Expression::Constant(Fr::from(v))
}

// 原生仿射 EC（SM2 曲线 a = p−3 已入倍点斜率）。
// 2026-10-06 缺陷 B 同根完备化（与 sm2_ec_window_gadget::affine_row_slope 同源）：
// 零避数字重编码的构造性等值（低位数字 (16,1) ⟹ 相邻两窗选点同为 16·16^i·G，
// 每随机标量 ≈0.435%）使累加链出现 P=Q 行——仿射加法按倍点完备化，P=−Q（O）
// 原型不承载、精确报错。
pub fn ec_add((x1, y1): (Fr, Fr), (x2, y2): (Fr, Fr)) -> (Fr, Fr) {
    if x1 == x2 {
        assert_eq!(y1, y2, "P+(−P)=O：原型不承载无穷远点");
        return ec_double((x1, y1));
    }
    let lam = (y2 - y1) * (x2 - x1).invert().unwrap();
    let x3 = lam * lam - x1 - x2;
    (x3, lam * (x1 - x3) - y1)
}

pub fn ec_double((x, y): (Fr, Fr)) -> (Fr, Fr) {
    let a = -Fr::from(3u64);
    let lam = (x * x + x * x + x * x + a) * (y + y).invert().unwrap();
    let x3 = lam * lam - x - x;
    (x3, lam * (x - x3) - y)
}

// 256 位小整数（LE 4 limbs）
#[derive(Clone, Copy)]
struct U256([u64; 4]);

impl U256 {
    fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }
    fn add(self, o: U256) -> U256 {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = self.0[i] as u128 + o.0[i] as u128 + carry;
            r[i] = s as u64;
            carry = s >> 64;
        }
        assert_eq!(carry, 0, "U256 溢出");
        U256(r)
    }
    fn sub_small(self, v: u64) -> U256 {
        let mut r = self.0;
        let mut borrow = v as u128;
        for limb in r.iter_mut() {
            let cur = *limb as u128;
            if cur >= borrow {
                *limb = (cur - borrow) as u64;
                borrow = 0;
                break;
            }
            *limb = (cur + (1u128 << 64) - borrow) as u64;
            borrow = 1;
        }
        assert_eq!(borrow, 0, "U256 负数");
        U256(r)
    }
    fn shr4(self) -> U256 {
        let mut r = [0u64; 4];
        for i in 0..4 {
            r[i] = self.0[i] >> 4;
            if i < 3 {
                r[i] |= self.0[i + 1] << 60;
            }
        }
        U256(r)
    }
    fn low4(self) -> u64 {
        self.0[0] & 15
    }
    fn is_zero(self) -> bool {
        self.0.iter().all(|&l| l == 0)
    }
}

fn offset_u256() -> U256 {
    U256([0x1111_1111_1111_1111; 4])
}

pub fn digits_1_16(k: u64) -> [u8; WINDOWS] {
    let mut rem = U256::from_u64(k).add(offset_u256());
    let mut out = [0u8; WINDOWS];
    for d in out.iter_mut() {
        let m = rem.low4();
        *d = if m == 0 { 16 } else { m as u8 };
        rem = rem.sub_small(*d as u64).shr4();
    }
    assert!(rem.is_zero(), "64 数字须穷尽 k+offset");
    out
}

#[derive(Clone, Debug)]
pub struct WindowCircuit {
    pub info: PlonkishCircuitInfo<Fr>,
    pub witness: Vec<Vec<Fr>>,
    /// 行 65 累加值 = [k]G
    pub result: (Fr, Fr),
    pub rows_used: usize,
}

/// 构造：标量 k（u64 测试域；生产形态 256 位同式）× 基点 g。
pub fn build(k: u64, g: (Fr, Fr)) -> WindowCircuit {
    let digits = digits_1_16(k);
    let mut base = g;
    let mut tables: Vec<[(Fr, Fr); 16]> = Vec::with_capacity(WINDOWS);
    let mut bases: Vec<(Fr, Fr)> = Vec::with_capacity(WINDOWS);
    for _ in 0..WINDOWS {
        let mut row = [(Fr::ZERO, Fr::ZERO); 16];
        row[0] = base;
        row[1] = ec_double(base);
        for j in 2..16 {
            row[j] = ec_add(row[j - 1], base);
        }
        tables.push(row);
        bases.push(base);
        base = ec_double(ec_double(ec_double(ec_double(base))));
    }
    let mut off_pt = bases[0];
    for b in &bases[1..] {
        off_pt = ec_add(off_pt, *b);
    }
    let neg_off = (off_pt.0, -off_pt.1);

    // 🔴 行序定谳（2026-09-18，系统线实测）：后端 Rotation(-1) = bh().prev（LFSR 循环序），
    // 不是自然下标 r−1。累加链用 qprev 读前一步，故位置相关列（选择子+见证）必须按
    // 论文线 builder 同款 row_mapping()[k]（bh 循环序第 k 点）落物理行；查表表列为多重集
    // 语义、位置无关，仍按自然行填。物理行 0 是旋转固定点=rm[ROWS−1]，链不触碰。
    let rm = crate::sm3_compress::row_mapping();
    let at = |r: usize| rm[r];

    let mut pre = vec![vec![Fr::ZERO; ROWS]; NUM_P];
    for r in 1..=WINDOWS {
        pre[P_QIDX][at(r)] = Fr::from((r - 1) as u64);
    }
    pre[P_QIDX][at(WINDOWS + 1)] = Fr::from(WINDOWS as u64);
    pre[P_QINIT][at(1)] = Fr::ONE;
    for r in 2..=WINDOWS + 1 {
        pre[P_QADD][at(r)] = Fr::ONE;
    }
    for r in 1..=WINDOWS + 1 {
        pre[P_QACT][at(r)] = Fr::ONE;
    }
    let mut trow = 0usize;
    for col in 0..4 {
        pre[P_TIDX + col][0] = Fr::ZERO;
    }
    for i in 0..WINDOWS {
        for j in 0..16usize {
            pre[P_TIDX][trow] = Fr::from(i as u64);
            pre[P_TD][trow] = Fr::from((j + 2) as u64);
            pre[P_TX][trow] = tables[i][j].0;
            pre[P_TY][trow] = tables[i][j].1;
            trow += 1;
        }
    }
    pre[P_TIDX][trow] = Fr::from(WINDOWS as u64);
    pre[P_TD][trow] = Fr::ONE;
    pre[P_TX][trow] = neg_off.0;
    pre[P_TY][trow] = neg_off.1;
    trow += 1;
    assert!(trow < ROWS, "表项 {trow} 超出 K=12 行预算");

    let mut wit = vec![vec![Fr::ZERO; ROWS]; NUM_W];
    let mut acc = (Fr::ZERO, Fr::ZERO);
    for r in 1..=WINDOWS + 1 {
        let (idx, d, pt) = if r <= WINDOWS {
            let i = r - 1;
            let d = digits[i];
            (i as u64, d as u64, tables[i][d as usize - 1])
        } else {
            (WINDOWS as u64, 0u64, neg_off)
        };
        wit[W_IDX][at(r)] = Fr::from(idx);
        wit[W_D][at(r)] = Fr::from(d);
        wit[W_DSHIFT][at(r)] = Fr::from(d + 1); // d′ = 数字 + 1（查表输入=纯见证列）
        wit[W_X][at(r)] = pt.0;
        wit[W_Y][at(r)] = pt.1;
        if r == 1 {
            acc = pt;
        } else {
            // 缺陷 B 同根完备化（2026-10-06）：P=Q 行（零避重编码构造性等值）取
            // 倍点斜率——原型七约束在 λ=λ_d、(sx,sy)=2P 处自洽（与 gadget 同式
            // 逐式核验）；P=−Q 行 O 无表示、精确报错。
            let lam = if pt.0 != acc.0 {
                (pt.1 - acc.1) * (pt.0 - acc.0).invert().expect("distinct-x")
            } else if pt.1 == acc.1 {
                let a = -Fr::from(3u64);
                ((pt.0 * pt.0 + pt.0 * pt.0 + pt.0 * pt.0) + a)
                    * (pt.1 + pt.1).invert().expect("2y≠0（奇阶曲线）")
            } else {
                panic!("累加行遇 P+(−P)=O（原型不承载 O）")
            };
            wit[W_LAM][at(r)] = lam;
            acc = ec_add(acc, pt);
        }
        wit[W_SX][at(r)] = acc.0;
        wit[W_SY][at(r)] = acc.1;
    }
    let result = acc;

    // 约束
    let (idx, dsh, x, y, lam, sx, sy) = (
        poly(gw(W_IDX)),
        poly(gw(W_DSHIFT)),
        poly(gw(W_X)),
        poly(gw(W_Y)),
        poly(gw(W_LAM)),
        poly(gw(W_SX)),
        poly(gw(W_SY)),
    );
    let (qidx, qinit, qadd, qact) = (q(P_QIDX), q(P_QINIT), q(P_QADD), q(P_QACT));
    let (sxp, syp) = (qprev(gw(W_SX)), qprev(gw(W_SY)));
    let constraints = vec![
        dsh.clone() - poly(gw(W_D)) - qact.clone(),
        idx.clone() - qidx,
        qinit.clone() * (sx.clone() - x.clone()),
        qinit * (sy.clone() - y.clone()),
        qadd.clone()
            * (lam.clone() * (x.clone() - sxp.clone()) - (y.clone() - syp.clone())),
        qadd.clone() * (sx.clone() - lam.clone() * lam.clone() + sxp.clone() + x.clone()),
        qadd * (sy.clone() - lam * (sxp.clone() - sx.clone()) + syp.clone()),
    ];
    let lookups = vec![vec![
        (idx, q(P_TIDX)),
        (dsh, q(P_TD)),
        (x, q(P_TX)),
        (y, q(P_TY)),
    ]];
    let info = PlonkishCircuitInfo::<Fr> {
        k: K,
        num_instances: Vec::new(),
        preprocess_polys: pre,
        num_witness_polys: vec![NUM_W],
        num_challenges: vec![1],
        constraints,
        lookups,
        permutations: Vec::new(),
        max_degree: Some(4),
    };
    assert!(info.is_well_formed(), "L2b info 未通过 well-formed");
    WindowCircuit { info, witness: wit, result, rows_used: WINDOWS + 1 }
}

impl PlonkishCircuit<Fr> for WindowCircuit {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<Fr>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<Fr>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<Fr>] {
        &[]
    }
    fn synthesize(&self, round: usize, challenges: &[Fr]) -> Result<Vec<Vec<Fr>>, Error> {
        assert!(round == 0 && challenges.is_empty());
        Ok(self.witness.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_ec_plonkish;
    use crate::sm3_lookup_proto::ProtoSpec;
    use plonkish_backend::{
        backend::{hyperplonk::HyperPlonk, PlonkishBackend},
        pcs::multilinear::Basefold,
        util::{
            hash::Sm3,
            transcript::{InMemoryTranscript, SM3Transcript},
        },
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::io::Cursor;
    use std::time::Instant;

    type Pcs = Basefold<Fr, Sm3, ProtoSpec>;
    type Pb = HyperPlonk<Pcs>;
    type T = SM3Transcript<Cursor<Vec<u8>>>;

    fn fly(c: &WindowCircuit) -> (bool, f64, f64, usize) {
        let param = Pb::setup(&c.info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = Pb::preprocess(&param, &c.info).unwrap();
        let t = Instant::now();
        let proof = {
            let mut tr = T::new(());
            Pb::prove(&pp, c, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let prove_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let ok = {
            let mut tr = T::from_proof((), proof.as_slice());
            let r = Pb::verify(&vp, &[], &mut tr, StdRng::seed_from_u64(0x5EED + 2));
            eprintln!("[l2b-dbg] verify = {:?}", r);
            r.is_ok()
        };
        (ok, prove_s, t.elapsed().as_secs_f64(), proof.len())
    }

    #[test]
    fn l2b_differential_vs_affine_mul_bits() {
        let g = sm2_ec_plonkish::g_coords();
        for &k in &[1u64, 2, 0x0123_4567_89ab_cdef, u64::MAX - 7, u64::MAX] {
            let c = build(k, g);
            let bits: [bool; 256] = std::array::from_fn(|i| i < 64 && (k >> i) & 1 == 1);
            let auth = sm2_ec_plonkish::affine_mul_bits(&bits, Some(g)).expect("[k]G 非无穷远");
            assert_eq!(c.result, auth, "k={k:#x}: 窗口累加 ≠ affine_mul_bits");
        }
        eprintln!("[l2b] 差分：5 标量窗口累加 == affine_mul_bits ✓");
    }

    #[test]
    fn l2b_flight_shape_and_negatives() {
        let g = sm2_ec_plonkish::g_coords();
        let c = build(0x0123_4567_89ab_cdef, g);
        let (ok, p, v, sz) = fly(&c);
        eprintln!(
            "[l2b] 固定基 4 位窗口（行打包）：polys={} (P={} W={}) constraints={} lookups={} rows_used={} prove={p:.2}s verify={v:.3}s proof={sz}B ok={ok}",
            c.info.num_poly(), NUM_P, NUM_W, c.info.constraints.len(), c.info.lookups.len(), c.rows_used
        );
        assert!(ok, "L2b 诚实电路 VERIFY FAILED");
        // 负例落在链的物理行（row_mapping 序），与 build 同口径
        let rm = crate::sm3_compress::row_mapping();
        let mut n1 = c.clone();
        n1.witness[W_D][rm[3]] = Fr::ZERO;
        n1.witness[W_DSHIFT][rm[3]] = Fr::ONE;
        let r1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fly(&n1)));
        assert!(!matches!(r1, Ok((true, ..))), "数字 0 被静默接受！");
        let mut n2 = c.clone();
        n2.witness[W_SX][rm[10]] = n2.witness[W_SX][rm[10]] + Fr::ONE;
        let r2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fly(&n2)));
        assert!(!matches!(r2, Ok((true, ..))), "累加篡改被静默接受！");
        eprintln!("[l2b] 两负例均被拒 ✓");
    }
}
