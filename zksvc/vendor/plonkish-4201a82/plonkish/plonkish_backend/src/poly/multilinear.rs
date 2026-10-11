use crate::{
    poly::Polynomial,
    util::{
        arithmetic::{div_ceil, usize_from_bits_le, BooleanHypercube, Field},
        expression::Rotation,
        impl_index,
        parallel::{num_threads, parallelize, parallelize_iter},
        BitIndex, Deserialize, Itertools, Serialize,
    },
};
use num_integer::Integer;
use rand::RngCore;
use std::{
    borrow::Cow,
    iter::{self, Sum},
    mem,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultilinearPolynomial<F> {
    pub evals: Vec<F>,
    num_vars: usize,
}

impl<F> Default for MultilinearPolynomial<F> {
    fn default() -> Self {
        MultilinearPolynomial::zero()
    }
}

impl<F> MultilinearPolynomial<F> {
    pub fn new(evals: Vec<F>) -> Self {
        let num_vars = if evals.is_empty() {
            0
        } else {
            let num_vars = evals.len().ilog2() as usize;
            assert_eq!(evals.len(), 1 << num_vars);
            num_vars
        };

        Self { evals, num_vars }
    }

    pub const fn zero() -> Self {
        Self {
            evals: Vec::new(),
            num_vars: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.num_vars == 0
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn iter(&self) -> impl Iterator<Item = &F> {
        self.evals.iter()
    }
    
}

impl<F: Field> Polynomial<F> for MultilinearPolynomial<F> {
    type Point = Vec<F>;

    fn from_evals(evals: Vec<F>) -> Self {
        Self::new(evals)
    }

    fn into_evals(self) -> Vec<F> {
        self.evals
    }

    fn evals(&self) -> &[F] {
        self.evals.as_slice()
    }

    fn evaluate(&self, point: &Self::Point) -> F {
        MultilinearPolynomial::evaluate(self, point.as_slice())
    }
}

impl<F: Field> MultilinearPolynomial<F> {
    pub fn eq_xy(y: &[F]) -> Self {
        if y.is_empty() {
            return Self::zero();
        }

        let expand_serial = |next_evals: &mut [F], evals: &[F], y_i: &F| {
            for (next_evals, eval) in next_evals.chunks_mut(2).zip(evals.iter()) {
                next_evals[1] = *eval * y_i;
                next_evals[0] = *eval - &next_evals[1];
            }
        };

        let mut evals = vec![F::ONE];
        for y_i in y.iter().rev() {
            let mut next_evals = vec![F::ZERO; 2 * evals.len()];
            if evals.len() < 32 {
                expand_serial(&mut next_evals, &evals, y_i);
            } else {
                let mut chunk_size = div_ceil(evals.len(), num_threads());
                if chunk_size.is_odd() {
                    chunk_size += 1;
                }
                parallelize_iter(
                    next_evals
                        .chunks_mut(chunk_size)
                        .zip(evals.chunks(chunk_size >> 1)),
                    |(next_evals, evals)| expand_serial(next_evals, evals, y_i),
                );
            }
            evals = next_evals;
        }

        Self {
            evals,
            num_vars: y.len(),
        }
    }

    pub fn rand(num_vars: usize, mut rng: impl RngCore) -> Self {
        Self::new(
            iter::repeat_with(|| F::random(&mut rng))
                .take(1 << num_vars)
                .collect(),
        )
    }

    pub fn split(&self, log_num_chunks:usize) -> Vec<Self>{
        let row_len = 1 << (self.num_vars - log_num_chunks);
        (row_len..(1 << self.num_vars) + 1).step_by(row_len).map(|row_end|{
            let new_evals =
            self.evals
            .iter()
            .enumerate()
            .filter_map(|(i,x)| 
                if i < row_end && i >= (row_end - row_len) { 
                    return Some(*x); 
                } 
                else { return None;})
            .collect::<Vec<_>>();
            Self::new(new_evals)
        }).collect::<Vec<_>>()
    }
    pub fn evaluate(&self, x: &[F]) -> F {
        assert_eq!(x.len(), self.num_vars);

        let mut evals = Cow::Borrowed(self.evals());
        let mut bits = Vec::new();
        let mut buf = Vec::with_capacity(self.evals.len() >> 1);
        for x_i in x.iter() {
            if x_i == &F::ZERO || x_i == &F::ONE {
                bits.push(x_i == &F::ONE);
                continue;
            }

            let distance = bits.len() + 1;
            let skip = usize_from_bits_le(&bits);
            merge_in_place(&mut evals, x_i, distance, skip, &mut buf);
            bits.clear();
        }

        evals[usize_from_bits_le(&bits)]
    }

    pub fn fix_last_vars(&self, x: &[F]) -> Self {
        assert!(!x.is_empty() && x.len() <= self.num_vars);

        let mut output = self.evals.clone();
        for (x_i, len) in x.iter().rev().zip((1..).map(|i| 1 << (self.num_vars - i))) {
            let (lo, hi) = output.split_at_mut(len);
            let chunk_size = div_ceil(len, num_threads());
            parallelize_iter(
                lo.chunks_mut(chunk_size).zip(hi.chunks(chunk_size)),
                |(lo, hi)| {
                    lo.iter_mut()
                        .zip(hi.iter())
                        .for_each(|(lo, hi)| *lo += (*hi - lo as &_) * x_i);
                },
            );
        }

        output.truncate(1 << (self.num_vars - x.len()));
        Self::new(output)
    }

    pub fn fix_var(&self, x_i: &F) -> Self {
        let mut output = Vec::with_capacity(1 << (self.num_vars - 1));
        merge_into(&mut output, self.evals(), x_i, 1, 0);
        Self::new(output)
    }

    /// 串行版 fix_var（2026-10-11 批量求值批）：与 `fix_var` 逐位同（同一
    /// merge 公式与遍历序），仅去掉函数体内 parallelize——并行粒度上移到
    /// 调用方跨 poly 批量（sumcheck next_round 的 spawn 风暴根修）。
    pub fn fix_var_serial(&self, x_i: &F) -> Self {
        let mut output = Vec::with_capacity(1 << (self.num_vars - 1));
        merge_into_serial(&mut output, self.evals(), x_i, 1, 0);
        Self::new(output)
    }

    /// 串行版 fix_var_in_place（同上——供批量并行任务体内调用）。
    pub fn fix_var_in_place_serial(&mut self, x_i: &F, buf: &mut Self) {
        merge_into_serial(&mut buf.evals, self.evals(), x_i, 1, 0);
        buf.num_vars = self.num_vars - 1;
        mem::swap(self, buf);
    }

    pub fn fix_var_in_place(&mut self, x_i: &F, buf: &mut Self) {
        merge_into(&mut buf.evals, self.evals(), x_i, 1, 0);
        buf.num_vars = self.num_vars - 1;
        mem::swap(self, buf);
    }

    pub fn evaluate_for_rotation(&self, x: &[F], rotation: Rotation) -> Vec<F> {
        assert_eq!(x.len(), self.num_vars);
        if rotation == Rotation::cur() {
            return vec![self.evaluate(x)];
        }

        // ── ②站中继化（2026-10-10，零语义：输出与旧逐节点独立全量 merge
        //    路径逐位同——等价性由多线性折叠的结合律保证，行为锁=
        //    evaluate_for_rotation / evaluate_for_rotation_relay_matches_point_evals
        //    双测试）。
        // 旧路径对 2^d 个节点各自从原列做 nv 轮全量 merge（≈2^d·2N 域操作）；
        // 中继化先按「变量分组」把全部节点取值相同的公共变量折叠一次（≈N），
        // 再在 ≤2^(d+翻转位) 的小表上逐节点插值（d=1 服务档 ≈4× 提速，
        // 探针 evals-13799 段 4.28s → ~1.1s [推得，完工实测定谳]）。
        // 分派边界：distance ≥ 4 时节点数/分叉位多，中继化的逐节点小折叠链
        // 分配开销反超收益（nv 全距离穷举测试实测 307s vs 旧 0.53s）⟹ 回退
        // legacy 路径（双路径共用全部行为锁；生产档 AUTH 查询面 distance≤2）。
        if rotation.distance() >= 4 {
            return self.evaluate_for_rotation_legacy(x, rotation);
        }
        let distance = rotation.distance();
        let num_x = self.num_vars - distance;
        let next = rotation > Rotation::cur();
        let pattern = if next {
            rotation_eval_point_pattern::<true>(self.num_vars, distance)
        } else {
            rotation_eval_point_pattern::<false>(self.num_vars, distance)
        };
        let num_nodes = 1usize << distance;

        // 节点 k 在变量 j 上的坐标（与 rotation_eval_points 的 chain 顺序同构，
        // 免中间 Vec<Vec<F>> 分配）：
        //   next：j<d=布尔(pat.nth_bit(j))；j=d+idx=nth_bit(idx+d)? 1−x[idx] : x[idx]
        //   prev：idx<num_x 处=nth_bit(idx)? 1−x[idx+d] : x[idx+d]；num_x+j=布尔
        let coord = |j: usize, k: usize| -> F {
            let pat = pattern[k];
            if next {
                if j < distance {
                    bit_to_field(pat.nth_bit(j))
                } else {
                    let idx = j - distance;
                    if pat.nth_bit(idx + distance) {
                        flip(&x[idx])
                    } else {
                        x[idx]
                    }
                }
            } else if j < num_x {
                if pat.nth_bit(j) {
                    flip(&x[j + distance])
                } else {
                    x[j + distance]
                }
            } else {
                // prev 布尔位（对齐 rotation_eval_points：nth_bit(idx + num_x)，
                // j = num_x + idx ⟹ 即 nth_bit(j)）。
                bit_to_field(pat.nth_bit(j))
            }
        };

        // 变量分组：公共位（全部节点同值）/ 分叉位（保序）。
        let mut common: Vec<(usize, F)> = Vec::with_capacity(self.num_vars);
        let mut split: Vec<usize> = Vec::new();
        for j in 0..self.num_vars {
            let v0 = coord(j, 0);
            if (1..num_nodes).all(|k| coord(j, k) == v0) {
                common.push((j, v0));
            } else {
                split.push(j);
            }
        }

        // 全列位折叠原语：out[b'] = (hi−lo)·v + lo，覆盖位 p 的全部 len/2 个对
        // （位 <bit 保持、位 ≥bit 右移一位）。v4（2026-10-10 probe 三版实测教训）：
        // ①首折直接吃借用切片（旧路径首合并零拷贝——to_vec 整表拷贝是纯损）；
        // ②输出缓冲 set_len 免零填充（resize 的 memset 随后被整段覆盖=双倍写）。
        //   声音性：F 为纯数据域元素（无 Drop、任意位型合法），扩容后 [0,out_len)
        //   每槽位在本函数内先写后读、并行写块两两不相交。
        // ③大表 parallelize、小表标量（rayon fork-join 固定开销在小表上是纯损失）。
        fn fold_bit<F: Field>(src: &[F], buf: &mut Vec<F>, bit: usize, val: &F) {
            let stride = 1usize << bit;
            let out_len = src.len() >> 1;
            if buf.len() < out_len {
                buf.reserve(out_len - buf.len());
            }
            // SAFETY: 见上——纯数据类型 + 先写后读全覆盖 + 不相交写块。
            unsafe { buf.set_len(out_len) };
            if src.len() >= 8192 {
                let out = &mut buf[..];
                parallelize(out, |(out, start)| {
                    for (i, out) in (start..).zip(out.iter_mut()) {
                        let src_idx = ((i >> bit) << (bit + 1)) | (i & (stride - 1));
                        let lo = src[src_idx];
                        let hi = src[src_idx | stride];
                        *out = (hi - &lo) * val + &lo;
                    }
                });
            } else {
                for (i, out) in buf.iter_mut().enumerate() {
                    let src_idx = ((i >> bit) << (bit + 1)) | (i & (stride - 1));
                    let lo = src[src_idx];
                    let hi = src[src_idx | stride];
                    *out = (hi - &lo) * val + &lo;
                }
            }
        }

        // 公共位折叠：live 位序表实时跟踪剩余变量，折叠顺序数学上任意
        // （多线性结合律）；取升序=先折低位。首折借用源零拷贝，后续 buf 交替。
        let mut folded: Vec<F> = Vec::new();
        let mut buf: Vec<F> = Vec::new();
        let mut live: Vec<usize> = (0..self.num_vars).collect();
        for &(j, v) in common.iter() {
            let pos = live.iter().position(|&l| l == j).expect("live var");
            let src: &[F] = if folded.is_empty() {
                self.evals()
            } else {
                &folded
            };
            fold_bit(src, &mut buf, pos, &v);
            mem::swap(&mut folded, &mut buf);
            live.remove(pos);
        }
        if folded.is_empty() {
            folded = self.evals().to_vec();
        }

        // 分叉小表插值：live 升序迭代 ⟹ 每步折叠的都是当前表位 0（前序折叠
        // 使后续变量位号顺移）⟹ 就地成对插值即可（写 i 读 2i/2i+1，读位恒在
        // 写头之后=未覆盖区），零分配零零填充；small 跨节点复用仅 memcpy。
        let mut small: Vec<F> = folded.clone();
        let mut results = Vec::with_capacity(num_nodes);
        for k in 0..num_nodes {
            small.copy_from_slice(&folded);
            let mut len = small.len();
            for &j in live.iter() {
                let v = coord(j, k);
                for i in 0..(len >> 1) {
                    let lo = small[i << 1];
                    let hi = small[(i << 1) + 1];
                    small[i] = (hi - &lo) * &v + &lo;
                }
                len >>= 1;
            }
            results.push(small[0]);
        }
        results
    }

    /// ②站中继化的回退路径（distance ≥ 4）＝上游原实现逐字节保留
    /// （节点维 parallelize + last_buf 缓冲复用——大节点数下的分配形态最优）。
    fn evaluate_for_rotation_legacy(&self, x: &[F], rotation: Rotation) -> Vec<F> {
        let distance = rotation.distance();
        let num_x = self.num_vars - distance;
        let mut evals = vec![F::ZERO; 1 << distance];
        let chunk_size = div_ceil(evals.len(), num_threads());
        if rotation < Rotation::cur() {
            let x = &x[distance..];
            let flipped_x = x.iter().map(flip).collect_vec();
            let pattern = rotation_eval_point_pattern::<false>(self.num_vars, distance);
            let offset_mask = (1 << self.num_vars) - (1 << num_x);
            parallelize_iter(
                evals.chunks_mut(chunk_size).zip(pattern.chunks(chunk_size)),
                |(evals, pattern)| {
                    let mut buf = Vec::with_capacity(1 << (num_x - 1));
                    let mut last_buf = Some(Vec::with_capacity(1 << (num_x - 1)));
                    for (eval, pat) in evals.iter_mut().zip(pattern.iter()) {
                        let offset = pat & offset_mask;
                        let mut evals = Cow::Borrowed(&self[offset..offset + (1 << num_x)]);
                        for (idx, (x_i, flipped_x_i)) in x.iter().zip(flipped_x.iter()).enumerate()
                        {
                            let x_i = if pat.nth_bit(idx) { flipped_x_i } else { x_i };
                            merge_into(&mut buf, &evals, x_i, 1, 0);
                            if let Cow::Owned(_) = evals {
                                mem::swap(evals.to_mut(), &mut buf);
                            } else {
                                evals = mem::replace(&mut buf, last_buf.take().unwrap()).into();
                            }
                        }
                        *eval = evals[0];
                        last_buf = Some(evals.into_owned());
                    }
                },
            );
        } else {
            let x = &x[..num_x];
            let flipped_x = x.iter().map(flip).collect_vec();
            let pattern = rotation_eval_point_pattern::<true>(self.num_vars, distance);
            let skip_mask = (1 << distance) - 1;
            parallelize_iter(
                evals.chunks_mut(chunk_size).zip(pattern.chunks(chunk_size)),
                |(evals, pattern)| {
                    let mut buf = Vec::with_capacity(1 << (num_x - 1));
                    let mut last_buf = Some(Vec::with_capacity(1 << (num_x - 1)));
                    for (eval, pat) in evals.iter_mut().zip(pattern.iter()) {
                        let mut evals = Cow::Borrowed(self.evals());
                        let skip = pat & skip_mask;
                        let x_0 = if pat.nth_bit(distance) {
                            &flipped_x[0]
                        } else {
                            &x[0]
                        };
                        merge_into(&mut buf, &evals, x_0, distance + 1, skip);
                        evals = mem::replace(&mut buf, last_buf.take().unwrap()).into();

                        for ((x_i, flipped_x_i), idx) in
                            x.iter().zip(flipped_x.iter()).zip(distance..).skip(1)
                        {
                            let x_i = if pat.nth_bit(idx) { flipped_x_i } else { x_i };
                            merge_in_place(&mut evals, x_i, 1, 0, &mut buf);
                        }
                        *eval = evals[0];
                        last_buf = Some(evals.into_owned());
                    }
                },
            );
        }
        evals
    }
}

impl<'lhs, 'rhs, F: Field> Add<&'rhs MultilinearPolynomial<F>> for &'lhs MultilinearPolynomial<F> {
    type Output = MultilinearPolynomial<F>;

    fn add(self, rhs: &'rhs MultilinearPolynomial<F>) -> MultilinearPolynomial<F> {
        let mut output = self.clone();
        output += rhs;
        output
    }
}

impl<'rhs, F: Field> AddAssign<&'rhs MultilinearPolynomial<F>> for MultilinearPolynomial<F> {
    fn add_assign(&mut self, rhs: &'rhs MultilinearPolynomial<F>) {
        match (self.is_zero(), rhs.is_zero()) {
            (_, true) => {}
            (true, false) => *self = rhs.clone(),
            (false, false) => {
                assert_eq!(self.num_vars, rhs.num_vars);

                parallelize(&mut self.evals, |(lhs, start)| {
                    for (lhs, rhs) in lhs.iter_mut().zip(rhs[start..].iter()) {
                        *lhs += rhs;
                    }
                });
            }
        }
    }
}

impl<'rhs, F: Field> AddAssign<(&'rhs F, &'rhs MultilinearPolynomial<F>)>
    for MultilinearPolynomial<F>
{
    fn add_assign(&mut self, (scalar, rhs): (&'rhs F, &'rhs MultilinearPolynomial<F>)) {
        match (self.is_zero(), rhs.is_zero() | (scalar == &F::ZERO)) {
            (_, true) => {}
            (true, false) => {
                *self = rhs.clone();
                *self *= scalar;
            }
            (false, false) => {
                assert_eq!(self.num_vars, rhs.num_vars);

                if scalar == &F::ONE {
                    *self += rhs;
                } else if scalar == &-F::ONE {
                    *self -= rhs;
                } else {
                    parallelize(&mut self.evals, |(lhs, start)| {
                        for (lhs, rhs) in lhs.iter_mut().zip(rhs[start..].iter()) {
                            *lhs += &(*scalar * rhs);
                        }
                    });
                }
            }
        }
    }
}

impl<'lhs, 'rhs, F: Field> Sub<&'rhs MultilinearPolynomial<F>> for &'lhs MultilinearPolynomial<F> {
    type Output = MultilinearPolynomial<F>;

    fn sub(self, rhs: &'rhs MultilinearPolynomial<F>) -> MultilinearPolynomial<F> {
        let mut output = self.clone();
        output -= rhs;
        output
    }
}

impl<'rhs, F: Field> SubAssign<&'rhs MultilinearPolynomial<F>> for MultilinearPolynomial<F> {
    fn sub_assign(&mut self, rhs: &'rhs MultilinearPolynomial<F>) {
        match (self.is_zero(), rhs.is_zero()) {
            (_, true) => {}
            (true, false) => {
                *self = rhs.clone();
                *self *= &-F::ONE;
            }
            (false, false) => {
                assert_eq!(self.num_vars, rhs.num_vars);

                parallelize(&mut self.evals, |(lhs, start)| {
                    for (lhs, rhs) in lhs.iter_mut().zip(rhs[start..].iter()) {
                        *lhs -= rhs;
                    }
                });
            }
        }
    }
}

impl<'rhs, F: Field> SubAssign<(&'rhs F, &'rhs MultilinearPolynomial<F>)>
    for MultilinearPolynomial<F>
{
    fn sub_assign(&mut self, (scalar, rhs): (&'rhs F, &'rhs MultilinearPolynomial<F>)) {
        *self += (&-*scalar, rhs);
    }
}

impl<'lhs, 'rhs, F: Field> Mul<&'rhs F> for &'lhs MultilinearPolynomial<F> {
    type Output = MultilinearPolynomial<F>;

    fn mul(self, rhs: &'rhs F) -> MultilinearPolynomial<F> {
        let mut output = self.clone();
        output *= rhs;
        output
    }
}

impl<'rhs, F: Field> MulAssign<&'rhs F> for MultilinearPolynomial<F> {
    fn mul_assign(&mut self, rhs: &'rhs F) {
        if rhs == &F::ZERO {
            self.evals = vec![F::ZERO; self.evals.len()]
        } else if rhs == &-F::ONE {
            parallelize(&mut self.evals, |(evals, _)| {
                for eval in evals.iter_mut() {
                    *eval = -*eval;
                }
            });
        } else if rhs != &F::ONE {
            parallelize(&mut self.evals, |(lhs, _)| {
                for lhs in lhs.iter_mut() {
                    *lhs *= rhs;
                }
            });
        }
    }
}

impl<'a, F: Field> Sum<&'a MultilinearPolynomial<F>> for MultilinearPolynomial<F> {
    fn sum<I: Iterator<Item = &'a MultilinearPolynomial<F>>>(
        mut iter: I,
    ) -> MultilinearPolynomial<F> {
        let init = match (iter.next(), iter.next()) {
            (Some(lhs), Some(rhs)) => lhs + rhs,
            (Some(lhs), None) => return lhs.clone(),
            _ => unreachable!(),
        };
        iter.fold(init, |mut acc, poly| {
            acc += poly;
            acc
        })
    }
}

impl<F: Field> Sum<MultilinearPolynomial<F>> for MultilinearPolynomial<F> {
    fn sum<I: Iterator<Item = MultilinearPolynomial<F>>>(iter: I) -> MultilinearPolynomial<F> {
        iter.reduce(|mut acc, poly| {
            acc += &poly;
            acc
        })
        .unwrap()
    }
}

impl<F: Field> Sum<(F, MultilinearPolynomial<F>)> for MultilinearPolynomial<F> {
    fn sum<I: Iterator<Item = (F, MultilinearPolynomial<F>)>>(
        mut iter: I,
    ) -> MultilinearPolynomial<F> {
        let (scalar, mut poly) = iter.next().unwrap();
        poly *= &scalar;
        iter.fold(poly, |mut acc, (scalar, poly)| {
            acc += (&scalar, &poly);
            acc
        })
    }
}

impl_index!(MultilinearPolynomial, evals);

pub fn rotation_eval<F: Field>(x: &[F], rotation: Rotation, evals_for_rotation: &[F]) -> F {
    if rotation == Rotation::cur() {
        assert!(evals_for_rotation.len() == 1);
        return evals_for_rotation[0];
    }

    let num_vars = x.len();
    let distance = rotation.distance();
    assert!(evals_for_rotation.len() == 1 << distance);
    assert!(distance <= num_vars);

    let (pattern, nths, x) = if rotation < Rotation::cur() {
        (
            rotation_eval_coeff_pattern::<false>(num_vars, distance),
            (1..=distance).rev().collect_vec(),
            x[0..distance].iter().rev().collect_vec(),
        )
    } else {
        (
            rotation_eval_coeff_pattern::<true>(num_vars, distance),
            (num_vars - 1..).take(distance).collect(),
            x[num_vars - distance..].iter().collect(),
        )
    };
    x.into_iter().zip(nths).enumerate().fold(
        Cow::Borrowed(evals_for_rotation),
        |evals, (idx, (x_i, nth))| {
            pattern
                .iter()
                .step_by(1 << idx)
                .map(|pat| pat.nth_bit(nth))
                .zip(zip_self!(evals.iter()))
                .map(|(bit, (eval_0, eval_1))| {
                    if bit {
                        (*eval_0 - eval_1) * x_i + eval_1
                    } else {
                        (*eval_1 - eval_0) * x_i + eval_0
                    }
                })
                .collect_vec()
                .into()
        },
    )[0]
}

pub fn rotation_eval_points<F: Field>(x: &[F], rotation: Rotation) -> Vec<Vec<F>> {
    if rotation == Rotation::cur() {
        return vec![x.to_vec()];
    }

    let distance = rotation.distance();
    let num_x = x.len() - distance;
    if rotation < Rotation::cur() {
        let pattern = rotation_eval_point_pattern::<false>(x.len(), distance);
        let x = &x[distance..];
        let flipped_x = x.iter().map(flip).collect_vec();
        pattern
            .iter()
            .map(|pat| {
                iter::empty()
                    .chain((0..num_x).map(|idx| {
                        if pat.nth_bit(idx) {
                            flipped_x[idx]
                        } else {
                            x[idx]
                        }
                    }))
                    .chain((0..distance).map(|idx| bit_to_field(pat.nth_bit(idx + num_x))))
                    .collect_vec()
            })
            .collect()
    } else {
        let pattern = rotation_eval_point_pattern::<true>(x.len(), distance);
        let x = &x[..num_x];
        let flipped_x = x.iter().map(flip).collect_vec();
        pattern
            .iter()
            .map(|pat| {
                iter::empty()
                    .chain((0..distance).map(|idx| bit_to_field(pat.nth_bit(idx))))
                    .chain((0..num_x).map(|idx| {
                        if pat.nth_bit(idx + distance) {
                            flipped_x[idx]
                        } else {
                            x[idx]
                        }
                    }))
                    .collect_vec()
            })
            .collect()
    }
}

pub(crate) fn rotation_eval_point_pattern<const NEXT: bool>(
    num_vars: usize,
    distance: usize,
) -> Vec<usize> {
    let bh = BooleanHypercube::new(num_vars);
    let remainder = if NEXT { bh.primitive() } else { bh.x_inv() };
    let mut pattern = vec![0; 1 << distance];
    for depth in 0..distance {
        for (e, o) in zip_self!(0..pattern.len(), 1 << (distance - depth)) {
            let rotated = if NEXT {
                pattern[e] << 1
            } else {
                pattern[e] >> 1
            };
            pattern[o] = rotated ^ remainder;
            pattern[e] = rotated;
        }
    }
    pattern
}

pub(crate) fn rotation_eval_coeff_pattern<const NEXT: bool>(
    num_vars: usize,
    distance: usize,
) -> Vec<usize> {
    let bh = BooleanHypercube::new(num_vars);
    let remainder = if NEXT {
        bh.primitive() - (1 << num_vars)
    } else {
        bh.x_inv() << distance
    };
    let mut pattern = vec![0; 1 << (distance - 1)];
    for depth in 0..distance - 1 {
        for (e, o) in zip_self!(0..pattern.len(), 1 << (distance - depth - 1)) {
            let rotated = if NEXT {
                pattern[e] << 1
            } else {
                pattern[e] >> 1
            };
            pattern[o] = rotated ^ remainder;
            pattern[e] = rotated;
        }
    }
    pattern
}

fn flip<F: Field>(x: &F) -> F {
    F::ONE - x
}

fn bit_to_field<F: Field>(bit: bool) -> F {
    if bit {
        F::ONE
    } else {
        F::ZERO
    }
}

fn merge_in_place<F: Field>(
    evals: &mut Cow<[F]>,
    x_i: &F,
    distance: usize,
    skip: usize,
    buf: &mut Vec<F>,
) {
    merge_into(buf, evals, x_i, distance, skip);
    if let Cow::Owned(_) = evals {
        mem::swap(evals.to_mut(), buf);
    } else {
        *evals = mem::replace(buf, Vec::with_capacity(buf.len() >> 1)).into();
    }
}

pub(crate) fn merge_into<F: Field>(
    target: &mut Vec<F>,
    evals: &[F],
    x_i: &F,
    distance: usize,
    skip: usize,
) {
    assert!(target.capacity() >= evals.len() >> distance);
    target.resize(evals.len() >> distance, F::ZERO);

    let step = 1 << distance;
    parallelize(target, |(target, start)| {
        let start = (start << distance) + skip;
        for (target, (eval_0, eval_1)) in
            target.iter_mut().zip(zip_self!(evals.iter(), step, start))
        {
            *target = (*eval_1 - eval_0) * x_i + eval_0;
        }
    });
}

/// 串行 merge（2026-10-11 外层 sumcheck 批量求值批）：与 `merge_into` 逐元素
/// 同式同序（`(eval_1 − eval_0)·x + eval_0`，自 skip 起步距 step），仅去除
/// 函数体内的 parallelize——并行粒度上移到调用方（跨 poly 批量），消除
/// 「每 poly 一次 rayon scope × 每线程一份小切片」的 spawn 风暴（②站教训：
/// 并行粒度上移才是钥匙）。逐位同：算子与遍历序完全一致。
pub(crate) fn merge_into_serial<F: Field>(
    target: &mut Vec<F>,
    evals: &[F],
    x_i: &F,
    distance: usize,
    skip: usize,
) {
    assert!(target.capacity() >= evals.len() >> distance);
    target.resize(evals.len() >> distance, F::ZERO);

    let step = 1 << distance;
    let start = skip;
    for (target, (eval_0, eval_1)) in
        target.iter_mut().zip(zip_self!(evals.iter(), step, start))
    {
        *target = (*eval_1 - eval_0) * x_i + eval_0;
    }
}

macro_rules! zip_self {
    (@ $iter:expr, $step:expr, $skip:expr) => {
        $iter.skip($skip).step_by($step).zip($iter.skip($skip + ($step >> 1)).step_by($step))
    };
    ($iter:expr) => {
        zip_self!(@ $iter, 2, 0)
    };
    ($iter:expr, $step:expr) => {
        zip_self!(@ $iter, $step, 0)
    };
    ($iter:expr, $step:expr, $skip:expr) => {
        zip_self!(@ $iter, $step, $skip)
    };
}

pub(crate) use zip_self;

#[cfg(test)]
mod test {
    use crate::{
        poly::{
            multilinear::{rotation_eval, rotation_eval_points, zip_self, MultilinearPolynomial},
            Polynomial,
        },
        util::{
            arithmetic::{BooleanHypercube, Field},
            expression::Rotation,
            test::rand_vec,
            Itertools,
        },
    };
    use halo2_curves::bn256::Fr;
    use rand::{rngs::OsRng, RngCore};
    use std::iter;

    fn fix_vars<F: Field>(evals: &[F], x: &[F]) -> Vec<F> {
        x.iter().fold(evals.to_vec(), |evals, x_i| {
            zip_self!(evals.iter())
                .map(|(eval_0, eval_1)| (*eval_1 - eval_0) * x_i + eval_0)
                .collect_vec()
        })
    }

    // R2-fix 探针 v2（B3 前置）：rotation_eval 的输出是否恒等于多项式在某公开点
    // （每维 x_j 或 flip(x_j)）的求值——m 单值能否用「点求值」接口做 PCS 绑定。
    #[test]
    fn probe_rotation_eval_is_point_eval() {
        use crate::poly::multilinear::rotation_eval_points;
        use crate::util::arithmetic::BooleanHypercube;
        use crate::util::BitIndex;
        use ff::PrimeField;
        let nv = 5usize;
        let x: Vec<Fr> = (0..nv).map(|i| Fr::from_u128(3 + 7 * i as u128)).collect_vec();
        let eval_at = |evals: &[Fr], pt: &[Fr]| -> Fr {
            let bh = BooleanHypercube::new(nv);
            let mut acc = Fr::zero();
            for (b, &v) in bh.iter().zip(evals.iter()) {
                let mut w = Fr::one();
                for j in 0..nv {
                    w *= if b.nth_bit(j) { pt[j] } else { Fr::one() - pt[j] };
                }
                acc += w * v;
            }
            acc
        };
        for rot in [
            Rotation::cur(),
            Rotation::next(),
            Rotation::prev(),
            Rotation::from(2),
            Rotation::from(-2),
        ] {
            let pts = rotation_eval_points(&x, rot);
            let m1 = MultilinearPolynomial::rand(nv, OsRng);
            let m2 = MultilinearPolynomial::rand(nv, OsRng);
            let e1: Vec<Fr> = pts.iter().map(|pt| eval_at(m1.evals(), pt)).collect_vec();
            let e2: Vec<Fr> = pts.iter().map(|pt| eval_at(m2.evals(), pt)).collect_vec();
            let s1 = rotation_eval(&x, rot, &e1);
            let s2 = rotation_eval(&x, rot, &e2);
            let mut hit: Option<Vec<Fr>> = None;
            for mask in 0..(1usize << nv) {
                let pt: Vec<Fr> = x
                    .iter()
                    .enumerate()
                    .map(|(j, &xj)| if (mask >> j) & 1 == 1 { Fr::one() - xj } else { xj })
                    .collect_vec();
                if eval_at(m1.evals(), &pt) == s1 && eval_at(m2.evals(), &pt) == s2 {
                    hit = Some(pt);
                    break;
                }
            }
            assert!(hit.is_some(), "{:?}: rotation_eval NOT a point-evaluation", rot);
        }
    }

    #[test]
    fn fix_var() {
        let rand_x_i = || match OsRng.next_u32() % 3 {
            0 => Fr::zero(),
            1 => Fr::one(),
            2 => Fr::random(OsRng),
            _ => unreachable!(),
        };
        for num_vars in 0..16 {
            for _ in 0..10 {
                let poly = MultilinearPolynomial::rand(num_vars, OsRng);
                let x = iter::repeat_with(rand_x_i).take(num_vars).collect_vec();
                let eval = fix_vars(poly.evals(), &x)[0];
                assert_eq!(poly.evaluate(&x), eval);
                assert_eq!(x.iter().fold(poly, |poly, x_i| poly.fix_var(x_i))[0], eval);
            }
        }
    }

    #[test]
    fn evaluate_for_rotation() {
        let mut rng = OsRng;
        for num_vars in 0..16 {
            let bh = BooleanHypercube::new(num_vars);
            let rotate = |f: &Vec<Fr>| {
                (0..1 << num_vars)
                    .map(|idx| f[bh.rotate(idx, Rotation::next())])
                    .collect_vec()
            };
            let f = rand_vec(1 << num_vars, &mut rng);
            let fs = iter::successors(Some(f), |f| Some(rotate(f)))
                .map(MultilinearPolynomial::new)
                .take(num_vars)
                .collect_vec();
            let x = rand_vec::<Fr>(num_vars, &mut rng);

            for rotation in -(num_vars as i32) + 1..num_vars as i32 {
                let rotation = Rotation(rotation);
                let (f, f_rotated) = if rotation < Rotation::cur() {
                    (fs.last().unwrap(), &fs[fs.len() - rotation.distance() - 1])
                } else {
                    (fs.first().unwrap(), &fs[rotation.distance()])
                };
                assert_eq!(
                    rotation_eval(&x, rotation, &f.evaluate_for_rotation(&x, rotation)),
                    f_rotated.evaluate(&x),
                );
            }
        }
    }

    /// ②站中继化行为锁（2026-10-10）：evaluate_for_rotation 的输出必须与
    /// 「f 在 rotation_eval_points 各点的规范多线性求值」逐位相等——这是中继化
    /// 重写（公共位折叠+分叉位插值）与旧「逐节点独立全量 merge」路径等价性的
    /// 第二锚点（与既有 evaluate_for_rotation 测试互补：那个锚 LFSR 旋转语义且
    /// 全距离穷举，这个锚逐点规范求值；服务档 nv=12 在列，rotation 抽样控制
    /// 基准侧时长）。
    #[test]
    fn evaluate_for_rotation_relay_matches_point_evals() {
        let mut rng = OsRng;
        for num_vars in 2..13usize {
            let f = MultilinearPolynomial::new(rand_vec(1 << num_vars, &mut rng));
            let x = rand_vec::<Fr>(num_vars, &mut rng);
            let nv = num_vars as i32;
            let mut rotations: Vec<i32> = vec![-1, 1, -2, 2];
            if nv > 4 {
                rotations.extend([-(nv / 2), nv / 2, -(nv - 1), nv - 1]);
            }
            for rot in rotations.into_iter().filter(|&r| r > -nv && r < nv) {
                let rotation = Rotation(rot);
                let expect: Vec<Fr> = rotation_eval_points(&x, rotation)
                    .iter()
                    .map(|point| f.evaluate(point))
                    .collect();
                let got = f.evaluate_for_rotation(&x, rotation);
                assert_eq!(
                    got, expect,
                    "nv={num_vars} rot={rot}: 中继化节点值≠逐点规范求值"
                );
            }
        }
    }
}
