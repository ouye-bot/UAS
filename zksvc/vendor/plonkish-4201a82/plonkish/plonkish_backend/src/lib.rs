#![feature(portable_simd)]
#![allow(clippy::op_ref)]
#![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))] // 跨架构（wasm 尖峰）：x86 专属 feature 门控
pub mod accumulation;
pub mod backend;
pub mod frontend;
pub mod pcs;
pub mod piop;
pub mod poly;
pub mod util;

pub use halo2_curves;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    InvalidSumcheck(String),
    InvalidPcsParam(String),
    InvalidPcsOpen(String),
    InvalidSnark(String),
    Serialization(String),
    Transcript(std::io::ErrorKind, String),
}
