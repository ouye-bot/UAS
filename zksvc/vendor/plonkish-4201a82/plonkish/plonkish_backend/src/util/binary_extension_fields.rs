 use rand_chacha::ChaCha8Rng;
use crate::util::avx_int_types::BlazeField;
use core::simd::u64x2;
use num_traits::One;
use serde::Deserializer;
use serde::Serializer;
use core::simd::u8x16;
use num_traits::Zero;
use std::simd::i64x2;
use std::simd::Simd;
use crate::util::{arithmetic::Field, BigUint};
// 跨架构（2026-09-28 wasm 尖峰）：x86 glob 门控——非 x86 走 gf128_mul_portable
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::fmt;
use core::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use ff::{BatchInvert, PrimeFieldBits};
use halo2_curves::ff::PrimeField;
use rand::RngCore;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::ops::{BitAnd, Shr};
use std::time::Instant;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
//Type II: d, a, b, c
const onetwentyeight_mod_poly: [i32; 4] = [127, 1, 3, 7];
#[derive(Copy, Clone, fmt::Debug, Serialize, Deserialize)]
pub struct B128 {
    //this is base-64, little endian, i.e. 1 is [1,0] = 000..001, 2 is [2,0] = 00..000..10, [2,2] = [0..0010][0000..00010]
    pub value: [u64;2],
}


impl B128{
    unsafe fn new(el: [u64;2]) -> Self{
        Self{
            value: el
        }
    }

    fn inverse(&self) -> Self{
        assert_eq!(num_traits::Zero::is_zero(self),false);
        let mut element = self.clone();
        let mut result = B128::zero();
        for i in 0..=6{
            let mut b = element.clone();
            for j in 0..(1 << i){
                b = b*b;
            }
            element = element * b;
            if i == 0{
                result = b;
            }
            else{
                result = result * b;
            }
        }
        result
    }
}
impl  Default for B128{
    // Required method
    fn default() -> Self{
        todo!()
    }
}

impl Mul for B128 {
    type Output = Self;
   /*Direct translation of the C code below from libff

        --  const __m128i a = _mm_loadu_si128((const __m128i*) &(this->value_));
        --  const __m128i b = _mm_loadu_si128((const __m128i*) &(other.value_));
        -- const __m128i modulus = _mm_loadl_epi64((const __m128i*) &(libff::gf128::modulus_));

          /* compute the 256-bit result of a * b with the 64x64-bit multiplication
             intrinsic */
          __m128i mul256_high = _mm_clmulepi64_si128(a, b, 0x11); /* high of both */
          __m128i mul256_low = _mm_clmulepi64_si128(a, b, 0x00); /* low of both */

          __m128i mul256_mid1 = _mm_clmulepi64_si128(a, b, 0x01); /* low of a, high of b */
          __m128i mul256_mid2 = _mm_clmulepi64_si128(a, b, 0x10); /* high of a, low of b */

          /* Add the 4 terms together */
          __m128i mul256_mid = _mm_xor_si128(mul256_mid1, mul256_mid2);
          /* lower 64 bits of mid don't intersect with high, and upper 64 bits don't intersect with low */
          mul256_high = _mm_xor_si128(mul256_high, _mm_srli_si128(mul256_mid, 8));
          mul256_low = _mm_xor_si128(mul256_low, _mm_slli_si128(mul256_mid, 8));

          /* done computing mul256_low and mul256_high, time to reduce */

          /* reduce w.r.t. high half of mul256_high */
          __m128i tmp = _mm_clmulepi64_si128(mul256_high, modulus, 0x01);
          mul256_low = _mm_xor_si128(mul256_low, _mm_slli_si128(tmp, 8));
          mul256_high = _mm_xor_si128(mul256_high, _mm_srli_si128(tmp, 8));

          /* reduce w.r.t. low half of mul256_high */
          tmp = _mm_clmulepi64_si128(mul256_high, modulus, 0x00);
          mul256_low = _mm_xor_si128(mul256_low, tmp);

          _mm_storeu_si128((__m128i*) this->value_, mul256_low);

          return (*this);
          */
    #[allow(clippy::cast_possible_truncation)]
    fn mul(self, rhs: Self) -> Self::Output{
        #[cfg(not(target_arch = "x86_64"))]
        {
            // 可移植 GF(2^128) 乘法：机械转写 libff gf128 C 算法（clmul 逐位
            // 模拟+字节移位+规约——与 x86 内联体逐指令对应，双路一致性测试钉定）
            return Self { value: gf128_mul_portable(self.value, rhs.value) };
        }
        #[cfg(target_arch = "x86_64")]
             unsafe{
        let a: __m128i = __m128i::from(u64x2::from_array(self.value)); // _mm_lddqu_si128(&self.value.unwrap());
        let b: __m128i = __m128i::from(u64x2::from_array(rhs.value)); // _mm_lddqu_si128(&rhs.value.unwrap());

        //hardcode modulus later
        //x
        let modulus_vec:[i64;2] = [0b10000111, 0];
        let modulus_m128: *const __m128i = &__m128i::from(Simd::from(modulus_vec));

        let modulus: __m128i = _mm_loadl_epi64(modulus_m128);
        let mut mul256_high:__m128i  = _mm_clmulepi64_si128(a, b, 0x11);

        let mut mul256_low: __m128i = _mm_clmulepi64_si128(a, b, 0x00); /* low of both */

        let mul256_mid1 = _mm_clmulepi64_si128(a, b, 0x01); /* low of a, high of b */
        let  mul256_mid2 = _mm_clmulepi64_si128(a, b, 0x10); /* high of a, low of b */

          /* Add the 4 terms together */
        let mul256_mid = _mm_xor_si128(mul256_mid1, mul256_mid2);
          /* lower 64 bits of mid don't intersect with high, and upper 64 bits don't intersect with low */
          mul256_high = _mm_xor_si128(mul256_high, _mm_srli_si128(mul256_mid, 8));
          mul256_low = _mm_xor_si128(mul256_low, _mm_slli_si128(mul256_mid, 8));

          /* done computing mul256_low and mul256_high, time to reduce */

          /* reduce w.r.t. high half of mul256_high */
         let mut tmp = _mm_clmulepi64_si128(mul256_high, modulus, 0x01);
          mul256_low = _mm_xor_si128(mul256_low, _mm_slli_si128(tmp, 8));
          mul256_high = _mm_xor_si128(mul256_high, _mm_srli_si128(tmp, 8));

          /* reduce w.r.t. low half of mul256_high */
          tmp = _mm_clmulepi64_si128(mul256_high, modulus, 0x00);
          mul256_low = _mm_xor_si128(mul256_low, tmp);

          let value:*mut __m128i = &mut a.clone();//TODO: check that this is correct

          _mm_storeu_si128(value, mul256_low);



            return Self{
                value: *u64x2::from(*value).as_array()
            };
    }


    }
}

impl Zero for B128{
    fn zero() -> B128{
        Self { value: [0u64,0u64] }
    }
    fn is_zero(&self) -> bool { 
        if self.value == [0,0]{ //when Eq is implemented, change this
            return true;
        }
        else{
            return false;
        }
    }
}



/*  Co
de from libff:
 assert(!this->is_zero());
    gf128 a(*this);

    gf128 result(0);
    for (size_t i = 0; i <= 6; ++i)
    {
        /* entering the loop a = el^{2^{2^i}-1} */
        gf128 b = a;
        for (size_t j = 0; j < (1UL<<i); ++j)
        {
            b.square();
        }
        /* after the loop b = a^{2^i} = el^{2^{2^i}*(2^{2^i}-1)} */
        a *= b;
        /* now a = el^{2^{2^{i+1}}-1} */

        if (i == 0)
        {
            result = b;
        }
        else
        {
            result *= b;
        }
    }
    /* now result = el^{2^128-2} */
    return result;
*/


impl PartialEq for B128{
    fn eq(&self, other:&Self) -> bool{
       self.value == other.value
    }
}

impl Eq for B128{}


 #[test]
    fn test_mul(){
        unsafe{
        let one = B128::new([1,u64::MAX]);
        let two = B128::new([u64::MAX,u64::MAX]);

        println!("two * four {:?}", (one * two).value);
    }
}
    #[test]
    fn test_inv(){
        unsafe{
        let test = B128::new([4u64,3u64]);
        let inv = test.inverse();
        let inv_inv = inv.inverse();
        assert_eq!(test, inv_inv);

        let test2 = B128::new([100u64, 1234u64]);
        let inv = test2.inverse();
        let inv_inv = inv.inverse();
        assert_eq!(inv_inv, test2); }
    }

impl ConstantTimeEq for B128 {
    fn ct_eq(&self, other: &Self) -> Choice {
        if self == other {
            return Choice::from(1u8);
        } else {
            return Choice::from(0u8);
        }
    }
}

impl ConditionallySelectable for B128 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = Self::zero();
        if choice.unwrap_u8() == 0 {
            res = *a;
        } else {
            res = *b;
        }
        res
    }
}


impl Ord for B128 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd for B128 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for B128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl Add for B128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self{ value: [self.value[0] ^ rhs.value[0], self.value[1] ^ rhs.value[1]]}
       //unsafe{ Self{ value: Some(_mm_xor_si128(self.value.unwrap(),rhs.value.unwrap())) } }
    }
}

impl<'r> Add<&'r B128> for B128 {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self {
        self + *rhs
    }
}

impl AddAssign for B128 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'r> AddAssign<&'r B128> for B128 {
    fn add_assign(&mut self, rhs: &'r Self) {
        *self = *self + *rhs;
    }
}

impl<'r> Product<&'r B128> for B128 {
    fn product<I: Iterator<Item = &'r Self>>(iter: I) -> Self {
        todo!()
    }
}

impl Product for B128 {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        todo!()
        //iter.reduce(|x, y| x * y).unwrap_or(Self::one())
    }
}


impl<'r> Sum<&'r B128> for B128 {
    fn sum<I: Iterator<Item = &'r Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a,b| a + b)
    }
}

impl Sum for B128 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::ZERO)
    }
}
impl Sub for B128{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self{ value: [self.value[0] ^ rhs.value[0], self.value[1] ^ rhs.value[1]] }
    }
}

impl<'r> Sub<&'r B128> for B128 {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self {
        self - *rhs
    }
}

impl SubAssign for B128 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'r> SubAssign<&'r B128> for B128 {
    fn sub_assign(&mut self, rhs: &'r Self) {
        *self = *self - *rhs;
    }
}

impl Neg for B128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
       Self::zero() - self
    }
}

impl<'r> Mul<&'r B128> for B128 {
    type Output = Self;

    #[allow(clippy::cast_possible_truncation)]
    fn mul(self, rhs: &Self) -> Self {
        self * *rhs
    }
}

impl<'r> MulAssign<&'r B128> for B128 {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * *rhs;
    }
}

impl MulAssign for B128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for B128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.invert().unwrap()
    }
}

impl DivAssign for B128 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self * rhs.invert().unwrap();
    }
}

impl<'r> DivAssign<&'r B128> for B128 {
    fn div_assign(&mut self, rhs: &Self) {
        *self = *self * rhs.invert().unwrap();
    }
}
#[test]
fn test_rand(){
    let mut rng = ChaCha8Rng::from_entropy();
    assert_ne!(B128::random(&mut rng), B128::random(&mut rng));
}

#[test]
fn test_one(){
    type F = B128;
    let mut rng = ChaCha8Rng::from_entropy();
    let rand_el = B128::random(&mut rng);
    let one = B128{ value: [1,0]};
    assert_eq!(rand_el, rand_el + F::ZERO);
    assert_eq!(rand_el, rand_el * one);
}
impl Field for B128 {
   const ZERO: B128 = Self { value: [0,0]};//todo!();//Self{ value: None };
   const ONE: B128 = Self { value: [0,1]}; //todo!();//Self{ value: None };

   //todo, change this to use the rng it is being passed and do something directly 
    fn random(mut rng: impl RngCore) -> Self {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut bytes = [0u8;8];
        rng.fill_bytes(&mut bytes);
        let x = u64::from_le_bytes(bytes);
        let mut bytes = [0u8;8];
        rng.fill_bytes(&mut bytes);
        let y = u64::from_le_bytes(bytes);
        Self{ value:[ x,y]}
    }


    fn double(&self) -> Self {
        *self + *self
    }

    fn square(&self) -> Self {
        *self * *self
    }
    fn invert(&self) -> CtOption<Self> {
           CtOption::new(
                Self::inverse(self),
                Choice::from(1u8),
            )
       }

    fn sqrt(&self) -> CtOption<Self> {
        todo!()
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        todo!()
    }
}

impl PrimeField for B128 {
    type Repr = [u8; 16];
    const MODULUS: &'static str = "1FFFFFFFFFFFFFFF";
    const NUM_BITS: u32 = 128;
    const CAPACITY: u32 = 128;
    const TWO_INV: Self = todo!();//Self{ value: None }; //todo;
    const MULTIPLICATIVE_GENERATOR: Self = todo!();//Self{ value: None }; //todo

    const S: u32 = 3;

    const ROOT_OF_UNITY: Self = todo!(); //todo

    const ROOT_OF_UNITY_INV: Self = todo!(); //todo

    const DELTA: Self = todo!(); //todo
    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        let bytes1 = repr[0..8].try_into().unwrap();
        let bytes2 = repr[8..16].try_into().unwrap();
        let word1 = u64::from_le_bytes(bytes1);
        let word2 = u64::from_le_bytes(bytes2);
        CtOption::new(
            Self { value: [word1,word2]},
            Choice::from(1u8)

            )
    }

    fn to_repr(&self) -> Self::Repr {
        let mut res: [u8;16] = [0u8;16];
        for (j,el) in self.value.iter().enumerate(){
            let bytes = el.to_le_bytes();
            for (i,byte) in bytes.into_iter().enumerate(){
                res[i + j * 8] = byte
            }
        }
        res
    }

    fn is_odd(&self) -> Choice {
        todo!()
    }
}
impl From<u64> for B128 {
    fn from(val: u64) -> Self {
        Self{ value: [0,val]}
    }
}


/// `_mm_clmulepi64_si128` 的纯 u64 逐位模拟（64 位 lane 内 LSB-first 无进位乘）
/// ——返回 [lo64, hi64] 小端对。
fn clmul64_emul(a: u64, b: u64) -> [u64; 2] {
    let mut hi = 0u64;
    let mut lo = 0u64;
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            lo ^= a.wrapping_shl(i as u32);
            hi ^= if i == 0 { 0 } else { a.wrapping_shr(64 - i as u32) };
        }
    }
    [lo, hi]
}

/// 可移植 GF(2^128) 乘法（modulus x^128+x^7+x^2+x+1）——libff gf128 C 算法
/// 的机械转写，与 x86 内联体逐指令对应；x86 原生路径由双路一致性测试互证。
fn gf128_mul_portable(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    let modulus_lo = 0b10000111u64; // x^7+x^2+x+1
    let l = clmul64_emul(a[0], b[0]); // 低位×低位
    let h = clmul64_emul(a[1], b[1]); // 高位×高位
    let m1 = clmul64_emul(a[0], b[1]); // a.lo×b.hi（imm 0x01）
    let m2 = clmul64_emul(a[1], b[0]); // a.hi×b.lo（imm 0x10）
    let mid = [m1[0] ^ m2[0], m1[1] ^ m2[1]];
    let mut high = [h[0], h[1]];
    let mut low = [l[0], l[1]];
    // mid 的字节移位并入：>>8B 取 mid 高 64 位入 low 位段；<<8B 取 mid 低 64 位入 high 位段
    high[0] ^= mid[1];
    low[1] ^= mid[0];
    // 规约 I（imm 0x01：high.hi × modulus.lo）
    let t = clmul64_emul(high[1], modulus_lo);
    low[1] ^= t[0];
    high[0] ^= t[1];
    // 规约 II（imm 0x00：high.lo × modulus.lo）
    let t2 = clmul64_emul(high[0], modulus_lo);
    low[0] ^= t2[0];
    low[1] ^= t2[1];
    low
}

#[cfg(all(test, target_arch = "x86_64"))]
mod gf128_portable_tests {
    /// 双路一致性测试：随机输入下可移植实现 ≡ x86 PCLMUL 内联体（逐位）。
    #[test]
    fn gf128_portable_matches_intrinsic() {
        use super::{gf128_mul_portable, B128};
        use rand::RngCore;
        use rand_chacha::ChaCha8Rng;
        use rand::SeedableRng;
        let mut rng = ChaCha8Rng::from_seed([7u8; 32]);
        for _ in 0..200 {
            let mut av = [0u64; 2];
            let mut bv = [0u64; 2];
            rng.fill_bytes(unsafe {
                std::slice::from_raw_parts_mut(av.as_mut_ptr() as *mut u8, 16)
            });
            rng.fill_bytes(unsafe {
                std::slice::from_raw_parts_mut(bv.as_mut_ptr() as *mut u8, 16)
            });
            let x = B128 { value: av };
            let y = B128 { value: bv };
            let native = x * y; // x86 路径（内联体）
            let ported = gf128_mul_portable(av, bv);
            assert_eq!(native.value, ported, "可移植实现与内联体不一致: {:?}×{:?}", av, bv);
        }
    }
}
