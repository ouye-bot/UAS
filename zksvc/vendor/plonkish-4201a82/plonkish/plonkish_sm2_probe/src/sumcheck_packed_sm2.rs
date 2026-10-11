//! FpSM2 外层 sumcheck 的 packed（AVX2 u64x4 lane）+ SoA 批量求值通道
//! （2026-10-11，路线甲：同域向量化——零语句/零语义/零电路）。
//!
//! 🔴 红线与语义锚：
//! - **零语义**：本模块只替换「求值怎么算」，不改证明系统任何协议面。packed
//!   蒙哥马利逐 limb 复刻 ff_derive 0.13 对 FpSM2（5 limb）生成的语义——
//!   `mul` = schoolbook 10 limb + SOS mont_reduce + 末尾条件减 p（结果∈[0,p)）；
//!   `add` = adc 链（无最终进位出域，输入恒 <2p）+ 条件减 p（结果∈[0,2p)）；
//!   `sub` = b>a 时先加 p 再相借链（无归约）；`neg` = 非零判后 p−v 相借链
//!   （先算链后按零测掩码）。同 lazy 代表元位型 ⟹ 与标量路径**逐 limb 同**，
//!   由 `packed_sm2_differ`（随机批差分）与 sumcheck roundtrip 双测试锁死。
//! - **零语句/零电路**：只挂接在 `ClassicSumCheck<EvaluationsProver>` 的求值
//!   内环；转录字节、轮消息语义、公开实例与证明尺寸零变化（同见证逐字节锚）。
//! - 差分位：`FZ_ZK_PACKED_SUMCHECK=0` ⟹ 回退标量路径（同输入可对拍）。
//! - 运行时门：AVX2 缺失 ⟹ 自动回退标量（`ENABLED` 常真但执行前置门回 false）。
//! - SoA 布局：cache 槽位 = `[slot][limb][4 lane]`，槽步长 160B=5×32B ⟹
//!   32B 对齐向量加载；calc 槽经活跃区间线性扫描复用（槽位复用=数据流不变）。

use core::arch::x86_64::{
    __m256i, _mm256_add_epi64, _mm256_and_si256, _mm256_cmpgt_epi64, _mm256_cmpeq_epi64,
    _mm256_loadu_si256, _mm256_mul_epu32, _mm256_or_si256, _mm256_set1_epi64x,
    _mm256_slli_epi64, _mm256_srli_epi64, _mm256_storeu_si256, _mm256_sub_epi64,
    _mm256_xor_si256,
};
use ff::{Field as _, PrimeField};
use plonkish_backend::piop::sum_check::classic::packed::{
    register_packed, ExecThunk, PackedProgram, POp, PackedRegistration, ProverStatePublic,
    RegistryPublic,
};
use plonkish_backend::piop::sum_check::classic::Evaluations;
use plonkish_backend::util::{
    arithmetic::{div_ceil, BooleanHypercube},
    expression::Rotation,
    parallel::{num_threads, parallelize_iter},
};
use std::sync::OnceLock;

use crate::FpSM2;

pub(crate) const LIMBS: usize = 5;
pub(crate) const LANES: usize = 4;

/// 启用门（进程级一次性）：🔴 **缺省关闭**——`FZ_ZK_PACKED_SUMCHECK=1` 显式
/// 启用且 AVX2 可用才注册 packed 通道。性能判决 [实测 2026-10-11 AUTH
/// canonical 生产构型]：正确性三测试+同见证逐字节锚全过，但求值段 3.08s→
/// 172s（~56×反向）——α^i 常量区（33k 槽/5.5MiB 每 chunk）随机访问打穿
/// 缓存层级，病态根因（指令级 vs 缓存带宽）未定谳前**不得默认上路**（实测
/// 纪律：估算≠定谳）。标量路径（含 next_round 批量化）为生产缺省。
pub(crate) fn packed_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var("FZ_ZK_PACKED_SUMCHECK").as_deref() != Ok("1") {
            return false;
        }
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::is_x86_feature_detected!("avx2")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    })
}

/// 域参数打包（modulus 5 limb 向量 + INV 广播）。
pub(crate) struct PackedParams {
    modulus: [__m256i; LIMBS],
    inv: __m256i,
}

impl PackedParams {
    pub(crate) fn of() -> Self {
        // ff_derive 对本结构生成的固有常量：MODULUS_LIMBS=limb 形态域元、INV=u64。
        // ff_derive 展开于 crate 根的模块级私有常量（子模块经 super:: 可见）。
        let m = super::MODULUS_LIMBS.0;
        debug_assert_eq!(m[4], 0, "SM2 素数 <2^256：第 5 limb 恒零");
        let modulus = core::array::from_fn(|l| unsafe { splat(m[l]) });
        let inv = unsafe { splat(super::INV) };
        Self { modulus, inv }
    }
}

// ── 基元（全部 unsafe + AVX2；lane = 独立域元素，通道=同 limb 跨 4 元素） ──

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn splat(v: u64) -> __m256i {
    _mm256_set1_epi64x(v as i64)
}

#[inline]
pub(crate) unsafe fn v_zero() -> __m256i {
    _mm256_set1_epi64x(0)
}

#[inline]
unsafe fn v_one() -> __m256i {
    _mm256_set1_epi64x(1)
}

const BIAS_U64: u64 = 0x8000_0000_0000_0000;
const ONES_U64: u64 = u64::MAX;

/// 无符号 a<b（按 lane）→ 全一/全零掩码。
#[inline]
unsafe fn v_lt(a: __m256i, b: __m256i) -> __m256i {
    _mm256_cmpgt_epi64(
        _mm256_xor_si256(b, splat(BIAS_U64)),
        _mm256_xor_si256(a, splat(BIAS_U64)),
    )
}

/// 进/借位出（0/1 per lane）：s=a+x 的进出 ⟺ s<a。
#[inline]
pub(crate) unsafe fn v_carry01(s: __m256i, a: __m256i) -> __m256i {
    _mm256_and_si256(v_lt(s, a), v_one())
}

/// lt 0/1 lane 版。
#[inline]
unsafe fn v_lt01(a: __m256i, b: __m256i) -> __m256i {
    _mm256_and_si256(v_lt(a, b), v_one())
}

/// sbb：d = a − b − bin（bin 为 0/1 lane），返回 (d, bout)。
/// 🔴 bout = lt(a,b) | ((a−b==0)&bin)——`a<d` 恒等式在 b+bin==2^64（b 全 F 且
/// bin=1）时坍缩为 d==a 无信号（vendor differ limb3 +1 实锤后根修）。
#[inline]
unsafe fn v_sbb(a: __m256i, b: __m256i, bin: __m256i) -> (__m256i, __m256i) {
    let t = _mm256_sub_epi64(a, b);
    let c1 = v_lt01(a, b);
    let t_is_zero = _mm256_cmpeq_epi64(t, v_zero());
    let c2 = _mm256_and_si256(t_is_zero, _mm256_and_si256(bin, v_one()));
    let d = _mm256_sub_epi64(t, bin);
    (d, _mm256_or_si256(c1, c2))
}

/// adc：d = a + b + cin（cin 为字宽 lane），返回 (d, cout)。
/// cout = carry(a+b) | carry((a+b)+cin)——两段分解精确（c1∧c2 不可能同时为 1）。
#[inline]
unsafe fn v_adc(a: __m256i, b: __m256i, cin: __m256i) -> (__m256i, __m256i) {
    let t = _mm256_add_epi64(a, b);
    let c1 = v_carry01(t, a);
    let t2 = _mm256_add_epi64(t, cin);
    let c2 = v_carry01(t2, t);
    (t2, _mm256_or_si256(c1, c2))
}

/// mac：(d, cout) = a + b*c + cin 的低字与进位字（ff::derive::mac 全序同构）。
/// 🔴 cout 是字宽（=hi+c1+c2+c3 可到 hi+3）——不能按 0/1 OR 塌缩（v_adc 的
/// OR 只对「三输入相加」的出位成立，mac 是「加 128 位积」的进位字）。
#[inline]
unsafe fn v_mac(a: __m256i, b: __m256i, c: __m256i, cin: __m256i) -> (__m256i, __m256i) {
    let (lo, hi) = mul_wide_pre(
        _mm256_and_si256(b, splat(0xFFFF_FFFF)),
        _mm256_srli_epi64(b, 32),
        _mm256_and_si256(c, splat(0xFFFF_FFFF)),
        _mm256_srli_epi64(c, 32),
    );
    // 低字 = a + lo + cin（hi 属高字不入低）；cout = hi + c1 + c2（各 0/1，
    // 和 <2^64——与 ff::derive::mac 的 tot>>64 逐位同）。
    let s1 = _mm256_add_epi64(a, lo);
    let c1 = v_carry01(s1, a);
    let s2 = _mm256_add_epi64(s1, cin);
    let c2 = v_carry01(s2, s1);
    (s2, _mm256_add_epi64(hi, _mm256_add_epi64(c1, c2)))
}

/// 低字乘（x·y mod 2^64）。
#[inline]
unsafe fn mul_lo(x: __m256i, y: __m256i) -> __m256i {
    let m32 = splat(0xFFFF_FFFF);
    let x_lo = _mm256_and_si256(x, m32);
    let x_hi = _mm256_srli_epi64(x, 32);
    let y_lo = _mm256_and_si256(y, m32);
    let y_hi = _mm256_srli_epi64(y, 32);
    let ll = _mm256_mul_epu32(x_lo, y_lo);
    let lh = _mm256_mul_epu32(x_lo, y_hi);
    let hl = _mm256_mul_epu32(x_hi, y_lo);
    let mid32 = _mm256_add_epi64(_mm256_and_si256(lh, m32), _mm256_and_si256(hl, m32));
    _mm256_add_epi64(ll, _mm256_slli_epi64(_mm256_and_si256(mid32, m32), 32))
}

/// 条件减 p（ff_derive `reduce`：v≥p 才减一次；掩码化逐 lane）。
/// 🔴 掩码减作用于原 v（borrow 链只做 ≥p 判定，其副本不入结果——对 d 减=双减 p，
/// vendor 单测 differ 实锤后根修）。
pub(crate) unsafe fn ff_reduce(v: &mut [__m256i; LIMBS], p: &PackedParams) {
    let mut borrow = v_zero();
    for l in 0..LIMBS {
        let (t2, b) = v_sbb(v[l], p.modulus[l], borrow); // b=1 ⟺ v<p
        borrow = b;
    }
    let ones = _mm256_cmpeq_epi64(_mm256_sub_epi64(v_one(), borrow), v_one());
    let mut bb = v_zero();
    for l in 0..LIMBS {
        let pm = _mm256_and_si256(p.modulus[l], ones);
        let (t2, b) = v_sbb(v[l], pm, bb);
        bb = b; // 🔴 掩码减的借位链必须推进（丢弃=各 limb 独立减 p——differ 实锤）
        v[l] = t2;
    }
}

/// ff add：adc 链（首 limb 进位入 0；无 limb-4 进位出——输入 <2p 不变式）+
/// 条件减 p。逐 lane 独立。
pub(crate) unsafe fn ff_add(a: &[__m256i; LIMBS], b: &[__m256i; LIMBS], p: &PackedParams) -> [__m256i; LIMBS] {
    let mut s = [v_zero(); LIMBS];
    let mut c = v_zero();
    for l in 0..LIMBS {
        let (t2, cout) = v_adc(a[l], b[l], c);
        s[l] = t2;
        c = cout;
    }
    ff_reduce(&mut s, p);
    s
}

/// ff sub：b>a 先加 p（不归约）再相借链减（无最终借位——与 ff_derive 同式）。
pub(crate) unsafe fn ff_sub(a: &[__m256i; LIMBS], b: &[__m256i; LIMBS], p: &PackedParams) -> [__m256i; LIMBS] {
    let mut borrow = v_zero();
    for l in 0..LIMBS {
        let (_, b) = v_sbb(b[l], a[l], borrow); // b=1 ⟺ b<a
        borrow = b;
    }
    let ones = _mm256_cmpeq_epi64(_mm256_sub_epi64(v_one(), borrow), v_one());
    let mut d = [v_zero(); LIMBS];
    let mut c = v_zero();
    for l in 0..LIMBS {
        let pm = _mm256_and_si256(p.modulus[l], ones);
        let (t2, cout) = v_adc(a[l], pm, c);
        c = cout;
        d[l] = t2;
    }
    let mut bb = v_zero();
    for l in 0..LIMBS {
        let (t2, b) = v_sbb(d[l], b[l], bb);
        bb = b; // 🔴 借位链推进（同 ff_reduce 根修）
        d[l] = t2;
    }
    d
}

/// ff neg：非零判后 p−v 相借链（ff_derive 同式：先整链后按零测掩码）。
pub(crate) unsafe fn ff_neg(a: &[__m256i; LIMBS], p: &PackedParams) -> [__m256i; LIMBS] {
    let mut z = v_zero();
    for l in 0..LIMBS {
        z = _mm256_or_si256(z, a[l]);
    }
    let is_zero = _mm256_cmpeq_epi64(z, v_zero());
    let ones = _mm256_xor_si256(is_zero, splat(ONES_U64));
    let mut d = [v_zero(); LIMBS];
    let mut bb = v_zero();
    for l in 0..LIMBS {
        let (t2, b) = v_sbb(p.modulus[l], a[l], bb);
        bb = b;
        d[l] = _mm256_and_si256(t2, ones);
    }
    d
}

/// ff mul：schoolbook 5×5→10 limb + SOS mont_reduce + 条件减 p（ff_derive 全
/// 序复刻——进位字语义、carry2 跨 i 链、j==0 的零进位 mac 同构）。
pub(crate) unsafe fn ff_mul(a: &[__m256i; LIMBS], b: &[__m256i; LIMBS], p: &PackedParams) -> [__m256i; LIMBS] {
    let mut t = [v_zero(); 2 * LIMBS];
    for i in 0..LIMBS {
        let mut carry = v_zero();
        let (ai_lo, ai_hi) = {
            let m32 = splat(0xFFFF_FFFF);
            (_mm256_and_si256(a[i], m32), _mm256_srli_epi64(a[i], 32))
        };
        for j in 0..LIMBS {
            // (t[i+j], carry) = mac(t[i+j], a[i], b[j], carry)——字宽进位链。
            let (s3, cout) = v_mac(t[i + j], a[i], b[j], carry);
            t[i + j] = s3;
            carry = cout;
        }
        t[i + LIMBS] = carry;
    }
    // mont_reduce（SOS）。
    let mut carry2 = v_zero();
    for i in 0..LIMBS {
        let kk = mul_lo(t[i], p.inv);
        let m32 = splat(0xFFFF_FFFF);
        let k_lo = _mm256_and_si256(kk, m32);
        let k_hi = _mm256_srli_epi64(kk, 32);
        let mut carry = v_zero();
        for j in 0..LIMBS {
            let tt = if j == 0 { t[i] } else { t[i + j] };
            let cin = if j == 0 { v_zero() } else { carry };
            let (s3, cout) = v_mac(tt, kk, p.modulus[j], cin);
            carry = cout;
            if j == 0 {
                t[i] = s3;
            } else {
                t[i + j] = s3;
            }
        }
        // r[i+5] = adc(r[i+5], (i==0?0:carry2), carry)
        let cin = if i == 0 { v_zero() } else { carry2 };
        let (s, cout2) = v_adc(t[i + LIMBS], carry, cin);
        carry2 = cout2;
        t[i + LIMBS] = s;
    }
    let mut r = [v_zero(); LIMBS];
    for l in 0..LIMBS {
        r[l] = t[LIMBS + l];
    }
    ff_reduce(&mut r, p);
    r
}

/// 已拆半版全积（mont_reduce 内环热点免重复拆半）。
#[inline]
unsafe fn mul_wide_pre(
    a_lo: __m256i,
    a_hi: __m256i,
    b_lo: __m256i,
    b_hi: __m256i,
) -> (__m256i, __m256i) {
    let ll = _mm256_mul_epu32(a_lo, b_lo);
    let lh = _mm256_mul_epu32(a_lo, b_hi);
    let hl = _mm256_mul_epu32(a_hi, b_lo);
    let hh = _mm256_mul_epu32(a_hi, b_hi);
    let m32 = splat(0xFFFF_FFFF);
    let mid32 = _mm256_add_epi64(_mm256_and_si256(lh, m32), _mm256_and_si256(hl, m32));
    let addend = _mm256_slli_epi64(_mm256_and_si256(mid32, m32), 32);
    let lo = _mm256_add_epi64(ll, addend);
    let c_lo = v_carry01(lo, ll);
    let hi = _mm256_add_epi64(
        _mm256_add_epi64(hh, _mm256_add_epi64(_mm256_srli_epi64(lh, 32), _mm256_srli_epi64(hl, 32))),
        _mm256_add_epi64(_mm256_srli_epi64(mid32, 32), c_lo),
    );
    (lo, hi)
}

/// mul_wide 的「已拆半 b」适配器（schoolbook 内环：b[j] 每轮重拆、a[i] 一轮一拆）。
#[inline]
unsafe fn mul_wide(a_lo: __m256i, a_hi: __m256i, b: __m256i) -> (__m256i, __m256i) {
    let m32 = splat(0xFFFF_FFFF);
    let b_lo = _mm256_and_si256(b, m32);
    let b_hi = _mm256_srli_epi64(b, 32);
    mul_wide_pre(a_lo, a_hi, b_lo, b_hi)
}

// ── SoA cache 通道 ──

#[repr(align(32))]
struct Align32(Vec<u64>);

impl Align32 {
    fn new(n: usize) -> Self {
        Self(vec![0u64; n])
    }
}

/// (slot, limb) → SoA 平铺偏移（u64 元素数）。槽步长 5×4×8B=160B（32B 对齐）。
#[inline]
fn off(slot: usize, limb: usize) -> usize {
    (slot * LIMBS + limb) * LANES
}

/// 从 SoA 槽读单 lane 元素。
#[inline]
fn read_lane(buf: &[u64], slot: usize, lane: usize) -> FpSM2 {
    let mut limbs = [0u64; LIMBS];
    for l in 0..LIMBS {
        limbs[l] = buf[off(slot, l) + lane];
    }
    FpSM2(limbs)
}

/// 向 SoA 槽写单 lane 元素。
#[inline]
fn write_lane(buf: &mut [u64], slot: usize, lane: usize, v: &FpSM2) {
    for l in 0..LIMBS {
        buf[off(slot, l) + lane] = v.0[l];
    }
}

/// 输入槽构建（复刻 evaluate_polys_next 的 IS_FIRST_POINT 语义，逐 lane）。
///
/// ev0=第一评估点（x=1）值：identity=state.identity+(2^r+b·2^(r+1))、
/// lagrange 特例、eq_xy/poly=poly[b_1]；step=poly[b_1]−poly[b_0]（j>1 逐轮
/// ev0+=step，与标量路径同一推进代数）。
///
/// `write_constants`：常量槽全 lane 同值且跨 group 恒不变 ⟹ 仅 chunk 首组
/// 写入一次（AUTH registry 常量面=α^i 折叠权重，数千槽 × 每 group 重写是
/// 纯损）；非常量槽每 group 重算（跨 group 值不同）。
unsafe fn build_inputs<const IS_FIRST_ROUND: bool>(
    view: &ProverStatePublic<FpSM2>,
    reg: &RegistryPublic<FpSM2>,
    b0: usize,
    cache: &mut [u64],
    step: &mut [u64],
    write_constants: bool,
) {
    let round = view.round;
    let offsets = reg.offsets;
    // 常量槽（[0..constants.len())）：全 lane 同值；chunk 内首组写一次。
    if write_constants {
        for (k, c) in reg.constants.iter().enumerate() {
            for lane in 0..LANES {
                write_lane(cache, k, lane, c);
            }
        }
    }
    // identity 槽。
    {
        let slot = offsets.identity();
        let step_v = FpSM2::from(1u64 << round);
        for lane in 0..LANES {
            let b = b0 + lane;
            let v = view.identity
                + FpSM2::from(((1usize << round) + (b << (round + 1))) as u64);
            write_lane(cache, slot, lane, &v);
            write_lane(step, slot, lane, &step_v);
        }
    }
    // lagrange 槽（特例语义逐字复刻）。
    for (k, i) in reg.lagranges.iter().enumerate() {
        let slot = offsets.lagranges() + k;
        let lagrange = &view.lagranges[i];
        for lane in 0..LANES {
            let b = b0 + lane;
            let zero = FpSM2::ZERO;
            if b == lagrange.0 >> 1 {
                if (lagrange.0 & 1) == 0 {
                    write_lane(cache, slot, lane, &zero);
                    write_lane(step, slot, lane, &-lagrange.1);
                } else {
                    write_lane(cache, slot, lane, &lagrange.1);
                    write_lane(step, slot, lane, &lagrange.1);
                }
            } else {
                write_lane(cache, slot, lane, &zero);
                write_lane(step, slot, lane, &zero);
            }
        }
    }
    // eq_xy 槽（恒 cur 旋转位 (b<<1, (b<<1)+1)）。
    for (k, idx) in reg.eq_xys.iter().enumerate() {
        let slot = offsets.eq_xys() + k;
        let eq = &view.eq_xys[*idx];
        for lane in 0..LANES {
            let b = b0 + lane;
            let e1 = eq[(b << 1) + 1];
            let e0 = eq[b << 1];
            let st = e1 - e0;
            write_lane(cache, slot, lane, &e1);
            write_lane(step, slot, lane, &st);
        }
    }
    // poly 槽：registry 顺序（(query, rotation 槽号)）；FIRST 轮 bs 走 bh.rotate，
    // 其余轮槽位 = num_vars + rot.0、位 (b<<1,(b<<1)+1)。
    let bh = BooleanHypercube::new(view.num_vars);
    let rot_bs = |rotation: Rotation, b: usize| -> (usize, usize) {
        (
            bh.rotate(b << 1, rotation),
            bh.rotate((b << 1) + 1, rotation),
        )
    };
    for (k, (query, rot_slot)) in reg.polys.iter().enumerate() {
        let slot = offsets.polys() + k;
        let (b_0, b_1): (Vec<usize>, Vec<usize>) = if IS_FIRST_ROUND {
            let rotation = reg.rotations[*rot_slot];
            (0..LANES).map(|lane| rot_bs(rotation, b0 + lane)).unzip()
        } else {
            (
                (0..LANES).map(|lane| (b0 + lane) << 1).collect(),
                (0..LANES).map(|lane| ((b0 + lane) << 1) + 1).collect(),
            )
        };
        let poly: &plonkish_backend::poly::multilinear::MultilinearPolynomial<FpSM2> =
            if IS_FIRST_ROUND {
                &view.polys[query.poly()][view.num_vars]
            } else {
                let rotation = (view.num_vars as i32 + query.rotation().0) as usize;
                &view.polys[query.poly()][rotation]
            };
        for lane in 0..LANES {
            let e1 = poly[b_1[lane]];
            let e0 = poly[b_0[lane]];
            let st = e1 - e0;
            write_lane(cache, slot, lane, &e1);
            write_lane(step, slot, lane, &st);
        }
    }
}

/// 输入槽推进一轮（ev0 += step；🔴 仅 identity 起的非常量槽——标量路径
/// IS_FIRST_POINT=false 只推进 identity/lagrange/eq_xy/poly，常量槽不推进；
/// 常量槽的 step 恒 0 且值跨 group 不变，跳过=同语义免 19k 槽 × 每 group
/// 的零加）。全部向量化域加。
unsafe fn step_inputs(
    cache: &mut [u64],
    step: &[u64],
    first_movable_slot: usize,
    input_slots: usize,
    p: &PackedParams,
) {
    for slot in first_movable_slot..input_slots {
        let mut a = [v_zero(); LIMBS];
        let mut b = [v_zero(); LIMBS];
        for l in 0..LIMBS {
            a[l] = _mm256_loadu_si256(cache[off(slot, l)..].as_ptr() as *const __m256i);
            b[l] = _mm256_loadu_si256(step[off(slot, l)..].as_ptr() as *const __m256i);
        }
        let s = ff_add(&a, &b, p);
        for l in 0..LIMBS {
            _mm256_storeu_si256(cache[off(slot, l)..].as_mut_ptr() as *mut __m256i, s[l]);
        }
    }
}

/// 编译操作流走一遍（全部向量化；输出槽=末条操作 out）。
unsafe fn walk(program: &PackedProgram, cache: &mut [u64], p: &PackedParams) {
    let base = cache.as_mut_ptr();
    for op in &program.ops {
        match *op {
            POp::Mul(a, b, o) => {
                let (a, b, o) = (a as usize, b as usize, o as usize);
                let mut va = [v_zero(); LIMBS];
                let mut vb = [v_zero(); LIMBS];
                for l in 0..LIMBS {
                    va[l] = _mm256_loadu_si256(base.add(off(a, l)) as *const __m256i);
                    vb[l] = _mm256_loadu_si256(base.add(off(b, l)) as *const __m256i);
                }
                let r = ff_mul(&va, &vb, p);
                for l in 0..LIMBS {
                    _mm256_storeu_si256(base.add(off(o, l)) as *mut __m256i, r[l]);
                }
            }
            POp::Add(a, b, o) => {
                let (a, b, o) = (a as usize, b as usize, o as usize);
                let mut va = [v_zero(); LIMBS];
                let mut vb = [v_zero(); LIMBS];
                for l in 0..LIMBS {
                    va[l] = _mm256_loadu_si256(base.add(off(a, l)) as *const __m256i);
                    vb[l] = _mm256_loadu_si256(base.add(off(b, l)) as *const __m256i);
                }
                let r = ff_add(&va, &vb, p);
                for l in 0..LIMBS {
                    _mm256_storeu_si256(base.add(off(o, l)) as *mut __m256i, r[l]);
                }
            }
            POp::Sub(a, b, o) => {
                let (a, b, o) = (a as usize, b as usize, o as usize);
                let mut va = [v_zero(); LIMBS];
                let mut vb = [v_zero(); LIMBS];
                for l in 0..LIMBS {
                    va[l] = _mm256_loadu_si256(base.add(off(a, l)) as *const __m256i);
                    vb[l] = _mm256_loadu_si256(base.add(off(b, l)) as *const __m256i);
                }
                let r = ff_sub(&va, &vb, p);
                for l in 0..LIMBS {
                    _mm256_storeu_si256(base.add(off(o, l)) as *mut __m256i, r[l]);
                }
            }
            POp::Neg(a, o) => {
                let (a, o) = (a as usize, o as usize);
                let mut va = [v_zero(); LIMBS];
                for l in 0..LIMBS {
                    va[l] = _mm256_loadu_si256(base.add(off(a, l)) as *const __m256i);
                }
                let r = ff_neg(&va, p);
                for l in 0..LIMBS {
                    _mm256_storeu_si256(base.add(off(o, l)) as *mut __m256i, r[l]);
                }
            }
        }
    }
}

unsafe fn evals_packed_avx2<const IS_FIRST_ROUND: bool>(
    view: &ProverStatePublic<FpSM2>,
    reg: &RegistryPublic<FpSM2>,
    program: &PackedProgram,
    evals: &mut Evaluations<FpSM2>,
    points: usize,
    p: &PackedParams,
) {
    let calc_base = reg.offsets.calculations();
    let first_movable_slot = reg.offsets.identity();
    let input_slots = calc_base;
    let cache_slots = calc_base + program.scratch;
    let groups = points >> 2;
    let out_slot = program.ops.last().unwrap().out() as usize;
    let nt = num_threads();
    let chunk = div_ceil(groups, nt).max(1);
    let n_chunks = div_ceil(groups, chunk);
    // 跨线程零共享写：每 chunk 独占自己的 acc 槽（Join 后保序合并）。
    let mut chunk_acc: Vec<Vec<[FpSM2; LANES]>> = (0..n_chunks)
        .map(|_| vec![[FpSM2::ZERO; LANES]; view.degree + 1])
        .collect();
    // chunk 独占槽地址过线程边界（ci 互斥 ⟹ 每 ci 恰一线程写自己的槽，无竞争）。
    let acc_ptr_addr = chunk_acc.as_mut_ptr() as usize;
    // 只读共享引用以 usize 地址过线程边界（原生只读并行零竞争）；evals 指针
    // 仅在串行合并段使用。
    let (view_addr, reg_addr, program_addr) = (view as *const _ as usize, reg as *const _ as usize, program as *const _ as usize);
    parallelize_iter(0..n_chunks, move |ci| {
        let view = &*(view_addr as *const ProverStatePublic<FpSM2>);
        let reg = &*(reg_addr as *const RegistryPublic<FpSM2>);
        let program = &*(program_addr as *const PackedProgram);
        let g_lo = ci * chunk;
        let g_hi = (g_lo + chunk).min(groups);
        let mut cache = Align32::new(cache_slots * LIMBS * LANES);
        let mut step = Align32::new(input_slots * LIMBS * LANES);
        let p = PackedParams::of();
        let acc = unsafe { &mut *((acc_ptr_addr as *mut Vec<[FpSM2; LANES]>).add(ci)) };
        for g in g_lo..g_hi {
            let b0 = g * LANES;
            build_inputs::<IS_FIRST_ROUND>(
                view, reg, b0, &mut cache.0, &mut step.0, g == g_lo,
            );
            for j in 1..=view.degree {
                if j > 1 {
                    step_inputs(&mut cache.0, &step.0, first_movable_slot, input_slots, &p);
                }
                walk(program, &mut cache.0, &p);
                for lane in 0..LANES {
                    acc[j][lane] += read_lane(&cache.0, out_slot, lane);
                }
            }
        }
    });
    for acc in chunk_acc.iter() {
        for j in 1..=view.degree {
            for lane in 0..LANES {
                evals[j] += &acc[j][lane];
            }
        }
    }
}

/// 注册门（幂等）：AVX2 运行时检测 + 差分位（FZ_ZK_PACKED_SUMCHECK=0 不注册）。
/// 由服务壳（zksvc）在 prove 前调用一次；未注册=backend 全标量路径零变化。
pub fn ensure_registered() {
    static DONE: OnceLock<bool> = OnceLock::new();
    let _ = DONE.get_or_init(|| {
        if !packed_enabled() {
            return true; // 视为已处理：不注册（差分位/无 AVX2）
        }
        let m = super::MODULUS_LIMBS.0;
        register_packed(PackedRegistration {
            field: std::any::TypeId::of::<FpSM2>(),
            modulus: m,
            inv: super::INV,
            exec: packed_exec_entry,
        });
        true
    });
}

/// F-erased 执行体入口：TypeId 门已在 backend 侧放行 ⟹ thunk 还原为
/// FpSM2 具体类型的同一重解释（sound）。
fn packed_exec_entry(erased: *const u8) {
    let thunk = unsafe { &*(erased as *const ExecThunk<FpSM2>) };
    let first = thunk.first_round;
    let evals = unsafe { &mut *thunk.evals };
    let p = PackedParams::of();
    unsafe {
        if first {
            evals_packed_avx2::<true>(thunk.view, thunk.reg, thunk.program, evals, thunk.points, &p);
        } else {
            evals_packed_avx2::<false>(thunk.view, thunk.reg, thunk.program, evals, thunk.points, &p);
        }
    }
}

