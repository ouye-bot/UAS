use crate::util::avx_int_types::BlazeField;
use crate::util::arithmetic::PrimeField;
use blake2b_simd::{
    many::{hash_many, HashManyJob},
    Hash as BHash, Params, State, OUTBYTES,
};
use generic_array::GenericArray;
use plonky2_util::log2_strict;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use sha3::digest::{Digest, FixedOutput, HashMarker, OutputSizeUser, Reset};
pub use sha3::{
    digest::{FixedOutputReset, Output, Update},
    Keccak256,
};
use std::fmt::Debug;
use std::time::Instant;

pub use blake2::Blake2s256;
pub use sm3::Sm3;
use generic_array::{
    typenum::{U128, U16, U32, U64},
    ArrayLength,
};
pub use poseidon::{self, Poseidon};

pub trait Hash:
    'static + Sized + Clone + Debug + FixedOutputReset + Default + Update + HashMarker
{
    fn new() -> Self {
        Self::default()
    }

    fn update_blaze_field<F:BlazeField>(&mut self, el: &F) {
        Digest::update(self, el.to_le_bytes());
    }
    fn update_field_element(&mut self, field: &impl PrimeField) {
        Digest::update(self, field.to_repr());
    }

    fn update_consec_field_pairs(values: &Vec<impl PrimeField>) -> Vec<Output<Self>> {
        let log_v = log2_strict(values.len());
        let mut hashes = vec![Output::<Self>::default(); (values.len() >> 1)];
        hashes.par_iter_mut().enumerate().for_each(|(i, mut hash)| {
            let mut hasher = Self::new();
            hasher.update_field_element(&values[i + i]);
            hasher.update_field_element(&values[i + i + 1]);
            *hash = hasher.finalize_fixed();
        });
        hashes
    }

    fn update_consec_hash_pairs(values: &Vec<Output<Self>>) -> Vec<Output<Self>> {
        let log_v = log2_strict(values.len());
        let oracle = values
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = Self::new();
                let mut hash = Output::<Self>::default();
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect::<Vec<_>>();
        oracle
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut hasher = Self::default();
        hasher.update(data.as_ref());
        hasher.finalize()
    }
}

impl Hash for Keccak256 {}

impl Hash for Blake2s256 {}

/// 国密 SM3（GB/T 32905-2016）：标准向量正确性由 `tests::sm3_digest_matches_gbt32905_vectors`
/// 锁定（向量源自 m0_sm3_circuit 的 OpenSSL 三层对拍参照）。
impl Hash for Sm3 {}

impl Hash for Blake2s {
    fn update_consec_field_pairs(values: &Vec<impl PrimeField>) -> Vec<Output<Self>> {
        let v = values
            .par_chunks_exact(2)
            .map(|c| [c[0].to_repr().as_ref(), c[1].to_repr().as_ref()].concat())
            .collect::<Vec<Vec<u8>>>();
        let mut params = Params::new();
        params.hash_length(Self::OUTPUTLEN);
        let mut jobs = v
            .iter()
            .map(|v| HashManyJob::new(&params, v))
            .collect::<Vec<HashManyJob>>();

        hash_many(jobs.iter_mut());
        let mut output = Vec::with_capacity(v.len());
        for job in jobs.iter() {
            output.push(*GenericArray::from_slice(job.to_hash().as_bytes()));
        }
        output
    }
    fn new() -> Self {
        Self::default()
    }

    fn update_field_element(&mut self, field: &impl PrimeField) {
        Digest::update(self, field.to_repr());
    }

    fn update_consec_hash_pairs(values: &Vec<Output<Self>>) -> Vec<Output<Self>> {
        let v = values
            .par_chunks_exact(2)
            .map(|c| [c[0], c[1]].concat())
            .collect::<Vec<Vec<u8>>>();

        let mut params = Params::new();
        params.hash_length(Self::OUTPUTLEN);
        let now = Instant::now();
        let mut jobs = v
            .iter()
            .map(|v| HashManyJob::new(&params, v))
            .collect::<Vec<HashManyJob>>();

        hash_many(jobs.iter_mut());

        let outputs: Vec<Output<Self>> = jobs
            .iter()
            .map(|job| *GenericArray::from_slice(job.to_hash().as_bytes()))
            .collect();

        outputs
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut state = State::new();
        state.update(data.as_ref());
        *GenericArray::from_slice(state.finalize().as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Blake2s {
    state: State,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// GB/T 32905-2016 附录 A 标准向量 + OpenSSL 交叉验证。
    /// 向量来源：`m0_sm3_circuit/src/sm3_native.rs`（M0/M2b 已三层对拍验证的可信参照）。
    #[test]
    fn sm3_digest_matches_gbt32905_vectors() {
        let cases: [(&[u8], &str); 4] = [
            (b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
            (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
            (
                b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
            ),
            (
                b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcda",
                "0d24d8847bb36d29b998d0e191a65e4c39a311303e7b8332fe7fec8341169ad7",
            ),
        ];
        for (msg, want) in cases {
            assert_eq!(<Sm3 as Hash>::digest(msg).as_slice(), hex(want).as_slice());
        }
    }
}

impl Blake2s {
    const OUTPUTLEN: usize = 32;
    fn new() -> Self {
        let mut params = Params::new();
        params.hash_length(Self::OUTPUTLEN);
        Self {
            state: params.to_state(),
        }
    }
}
impl Default for Blake2s {
    fn default() -> Self {
        Self::new()
    }
}

impl HashMarker for Blake2s {}

impl FixedOutputReset for Blake2s {
    /// Write result into provided array and reset the hasher state.
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let output = self.state.finalize();
        *out = *GenericArray::from_slice(output.as_bytes());
        *self = Self::new();
    }
}

impl Reset for Blake2s {
    fn reset(&mut self) {
        let mut params = Params::new();
        params.hash_length(Self::OUTPUTLEN);
        *self = Self::new();
    }
}

impl FixedOutput for Blake2s {
    fn finalize_into(self, out: &mut Output<Self>) {
        let output = self.state.finalize();
        *out = *GenericArray::from_slice(output.as_bytes());
    }
}

impl Update for Blake2s {
    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
}

impl OutputSizeUser for Blake2s {
    type OutputSize = U32;
    fn output_size() -> usize {
        return Self::OUTPUTLEN;
    }
}
