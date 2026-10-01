use crate::{
    util::{
        arithmetic::{fe_mod_from_le_bytes, Coordinates, CurveAffine, PrimeField},
        hash::{Hash, Keccak256, Update, Blake2s256, Blake2s, Sm3},
        Itertools,
    },
    Error,
};

/// A3(2026-09-16):哈希块转录类型公开别名——流式两遍解析器与差分测试需
/// 具名(Output<H> = GenericArray<u8,32> for Sm3;此前为私有 use,外部无法
/// 为 read_commitment 的返回值标注类型)。
pub use crate::util::hash::Output;

use halo2_curves::{bn256, grumpkin, pasta};
use std::{
    fmt::Debug,
    io::{self, Cursor},
};

pub trait FieldTranscript<F> {
    fn squeeze_challenge(&mut self) -> F;

    fn squeeze_challenges(&mut self, n: usize) -> Vec<F> {
        (0..n).map(|_| self.squeeze_challenge()).collect()
    }

    fn common_field_element(&mut self, fe: &F) -> Result<(), Error>;

    fn common_field_elements(&mut self, fes: &[F]) -> Result<(), Error> {
        fes.iter()
            .map(|fe| self.common_field_element(fe))
            .try_collect()
    }
}

pub trait FieldTranscriptRead<F>: FieldTranscript<F> {
    fn read_field_element(&mut self) -> Result<F, Error>;

    fn read_field_elements(&mut self, n: usize) -> Result<Vec<F>, Error> {
        (0..n).map(|_| self.read_field_element()).collect()
    }
}

pub trait FieldTranscriptWrite<F>: FieldTranscript<F> {
    fn write_field_element(&mut self, fe: &F) -> Result<(), Error>;

    fn write_field_elements<'a>(
        &mut self,
        fes: impl IntoIterator<Item = &'a F>,
    ) -> Result<(), Error>
    where
        F: 'a,
    {
        for fe in fes.into_iter() {
            self.write_field_element(fe)?;
        }
        Ok(())
    }
}

pub trait Transcript<C, F>: FieldTranscript<F> {
    fn common_commitment(&mut self, comm: &C) -> Result<(), Error>;

    fn common_commitments(&mut self, comms: &[C]) -> Result<(), Error> {
        comms
            .iter()
            .map(|comm| self.common_commitment(comm))
            .try_collect()
    }
}

pub trait TranscriptRead<C, F>: Transcript<C, F> + FieldTranscriptRead<F> {
    fn read_commitment(&mut self) -> Result<C, Error>;

    fn read_commitments(&mut self, n: usize) -> Result<Vec<C>, Error> {
        (0..n).map(|_| self.read_commitment()).collect()
    }
}

pub trait TranscriptWrite<C, F>: Transcript<C, F> + FieldTranscriptWrite<F> {
    fn write_commitment(&mut self, comm: &C) -> Result<(), Error>;

    fn write_commitments<'a>(&mut self, comms: impl IntoIterator<Item = &'a C>) -> Result<(), Error>
    where
        C: 'a,
    {
        for comm in comms.into_iter() {
            self.write_commitment(comm)?;
        }
        Ok(())
    }
}

pub trait InMemoryTranscript {
    type Param: Clone + Debug;

    fn new(param: Self::Param) -> Self;

    fn into_proof(self) -> Vec<u8>;

    fn from_proof(param: Self::Param, proof: &[u8]) -> Self;
}

pub type Keccak256Transcript<S> = FiatShamirTranscript<Keccak256, S>;

pub type Blake2sTranscript<S> = FiatShamirTranscript<Blake2s, S>;

pub type Blake2s256Transcript<S> = FiatShamirTranscript<Blake2s256, S>;

pub type SM3Transcript<S> = FiatShamirTranscript<Sm3, S>;

#[derive(Debug, Default)]
pub struct FiatShamirTranscript<H, S> {
    state: H,
    stream: S,
}

impl<H: Hash> InMemoryTranscript for FiatShamirTranscript<H, Cursor<Vec<u8>>> {
    type Param = ();

    fn new(_: Self::Param) -> Self {
        Self::default()
    }

    fn into_proof(self) -> Vec<u8> {
        self.stream.into_inner()
    }

    fn from_proof(_: Self::Param, proof: &[u8]) -> Self {
        Self {
            state: H::default(),
            stream: Cursor::new(proof.to_vec()),
        }
    }
}

impl<H: Hash> FiatShamirTranscript<H, Cursor<Vec<u8>>> {
    /// A3 流式验证器地基（2026-09-15）：当前读位置（字节）——两遍流式验证的
    /// 第一遍用此标记大段（个体开口值/路径）的字节区间，第二遍带区间回放。
    pub fn stream_position(&self) -> usize {
        self.stream.position() as usize
    }
}

impl<'a, H: Hash> FiatShamirTranscript<H, Cursor<&'a [u8]>> {
    /// A3 流式验证器地基（2026-09-15）：当前读位置（字节）——两遍流式验证的
    /// 第一遍用此标记大段（个体开口值/路径）的字节区间，第二遍带区间回放。
    pub fn stream_position(&self) -> usize {
        self.stream.position() as usize
    }

    /// A3 地基：零拷贝读侧构造——`from_proof` 会 `to_vec()` 整份复制（ℓ=448
    /// 全语句 113GB 级证明下即 113GB 峰值）；分相验证（PROOF_LOAD）与两遍
    /// 流式（PCS_VERIFY_STREAM）以借用态起手。生命周期 `'a` = 证明借用期
    /// （借用法即流式法：transcript 不得长于证明缓冲）。
    pub fn from_proof_ref(_: (), proof: &'a [u8]) -> Self {
        FiatShamirTranscript {
            state: H::default(),
            stream: Cursor::new(proof),
        }
    }
}

impl<H: Hash, F: PrimeField, S> FieldTranscript<F> for FiatShamirTranscript<H, S> {
    fn squeeze_challenge(&mut self) -> F {
        let hash = self.state.finalize_fixed_reset();
        self.state.update(&hash);
        fe_mod_from_le_bytes(hash)
    }

    fn common_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.state.update_field_element(fe);
        Ok(())
    }
}

impl<H: Hash, F: PrimeField, R: io::Read> FieldTranscriptRead<F> for FiatShamirTranscript<H, R> {
    fn read_field_element(&mut self) -> Result<F, Error> {
        let mut repr = <F as PrimeField>::Repr::default();
	
        self.stream
            .read_exact(repr.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        repr.as_mut().reverse();
        let fe = F::from_repr_vartime(repr).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid field element encoding in proof".to_string(),
            )
        })?;
        self.common_field_element(&fe)?;
        Ok(fe)
    }
}

impl<H: Hash, F: PrimeField, W: io::Write> FieldTranscriptWrite<F> for FiatShamirTranscript<H, W> {
    fn write_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.common_field_element(fe)?;
        let mut repr = fe.to_repr();
        repr.as_mut().reverse();
	let el = repr.as_ref();
//	println!("field el length {:?}", el.len());
        self.stream
            .write_all(repr.as_ref())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}

macro_rules! impl_fs_transcript_curve_commitment {
    ($($curve:ty),*$(,)?) => {
        $(
            impl<H: Hash, S> Transcript<$curve, <$curve as CurveAffine>::ScalarExt> for FiatShamirTranscript<H, S> {
                fn common_commitment(&mut self, comm: &$curve) -> Result<(), Error> {
                    let coordinates =
                        Option::<Coordinates<_>>::from(comm.coordinates()).ok_or_else(|| {
                            Error::Transcript(
                                io::ErrorKind::Other,
                                "Invalid elliptic curve point encoding".to_string(),
                            )
                        })?;
                    self.state.update_field_element(coordinates.x());
                    self.state.update_field_element(coordinates.y());
                    Ok(())
                }
            }

            impl<H: Hash, R: io::Read> TranscriptRead<$curve, <$curve as CurveAffine>::ScalarExt>
                for FiatShamirTranscript<H, R>
            {
                fn read_commitment(&mut self) -> Result<$curve, Error> {
                    let mut reprs = [<<$curve as CurveAffine>::Base as PrimeField>::Repr::default(); 2];
                    for repr in &mut reprs {
                        self.stream
                            .read_exact(repr.as_mut())
                            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
                        repr.as_mut().reverse();
                    }
                    let [x, y] =
                        reprs.map(<<$curve as CurveAffine>::Base as PrimeField>::from_repr_vartime);
                    let ec_point = x
                        .zip(y)
                        .and_then(|(x, y)| CurveAffine::from_xy(x, y).into())
                        .ok_or_else(|| {
                            Error::Transcript(
                                io::ErrorKind::Other,
                                "Invalid elliptic curve point encoding in proof".to_string(),
                            )
                        })?;
                    self.common_commitment(&ec_point)?;
                    Ok(ec_point)
                }
            }

            impl<H: Hash, W: io::Write> TranscriptWrite<$curve, <$curve as CurveAffine>::ScalarExt>
                for FiatShamirTranscript<H, W>
            {
                fn write_commitment(&mut self, ec_point: &$curve) -> Result<(), Error> {
                    self.common_commitment(ec_point)?;
                    let coordinates = ec_point.coordinates().unwrap();
                    for coordinate in [coordinates.x(), coordinates.y()] {
                        let mut repr = coordinate.to_repr();
                        repr.as_mut().reverse();
                        self.stream
                            .write_all(repr.as_ref())
                            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
                    }
                    Ok(())
                }
            }
        )*
    };
}

impl_fs_transcript_curve_commitment!(
    bn256::G1Affine,
    grumpkin::G1Affine,
    pasta::EpAffine,
    pasta::EqAffine,
);

/// 哈希型承诺（Merkle root / 中间哈希）的 transcript 读写，按 `H: Hash` 泛型化——
/// Keccak256、SM3、Blake2s 同走此 impl（原为 Keccak256 特化，#28 泛化）。
impl<H: Hash, F: PrimeField, S> Transcript<Output<H>, F> for FiatShamirTranscript<H, S> {
    fn common_commitment(&mut self, comm: &Output<H>) -> Result<(), Error> {
        self.state.update(comm);
        Ok(())
    }
}

impl<H: Hash, F: PrimeField, R: io::Read> TranscriptRead<Output<H>, F> for FiatShamirTranscript<H, R> {
    fn read_commitment(&mut self) -> Result<Output<H>, Error> {
        let mut hash = Output::<H>::default();
        self.stream
            .read_exact(hash.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(hash)
    }
}

impl<H: Hash, F: PrimeField, W: io::Write> TranscriptWrite<Output<H>, F> for FiatShamirTranscript<H, W> {
    fn write_commitment(&mut self, hash: &Output<H>) -> Result<(), Error> {
        self.stream
            .write_all(hash)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(())
    }
}

/// A3 两遍流式(2026-09-16):零 trait 变更的侧信道。
///
/// 泛型 `batch_verify(transcript: &mut impl TranscriptRead<..>)` 无法观测读位置、也拿不到原始
/// 证明字节;流式档(`PCS_VERIFY_STREAM=1`)经本线程局部取得 **PCS 段起点**(由 `StreamTranscript`
/// 每次读后发布的位置)与 **回放源**(调用方注册的 `Arc<Vec<u8>>`,与转录借用同一缓冲,零拷贝)。
/// 默认档(env 未设)不读不写此处,历史行为字节级不变。
pub mod a3_stream {
    use std::cell::{Cell, RefCell};
    use std::sync::Arc;

    thread_local! {
        static PROOF: RefCell<Option<Arc<Vec<u8>>>> = RefCell::new(None);
        static POS: Cell<usize> = Cell::new(0);
    }

    /// 流式档开关(默认关)。
    pub fn enabled() -> bool {
        std::env::var("PCS_VERIFY_STREAM").map(|v| v == "1").unwrap_or(false)
    }

    /// 注册回放源(验证前;与 `StreamTranscript::new(&proof[..])` 借用同一缓冲)。
    pub fn register(proof: Arc<Vec<u8>>) {
        PROOF.with(|p| *p.borrow_mut() = Some(proof));
        POS.with(|c| c.set(0));
    }

    /// 清除注册(验证后)。
    pub fn clear() {
        PROOF.with(|p| *p.borrow_mut() = None);
        POS.with(|c| c.set(0));
    }

    /// 取回放源(流式 batch_verify 用;未注册即 panic——流式档必须显式注册)。
    pub fn proof() -> Arc<Vec<u8>> {
        PROOF
            .with(|p| p.borrow().clone())
            .expect("PCS_VERIFY_STREAM=1 需先 a3_stream::register(proof) 并使用 StreamTranscript")
    }

    /// 发布当前读位置(StreamTranscript 每次读后调用)。
    pub fn publish_pos(pos: usize) {
        POS.with(|c| c.set(pos));
    }

    /// 最近发布的读位置。
    pub fn pos() -> usize {
        POS.with(|c| c.get())
    }
}

/// A3 流式转录:`FiatShamirTranscript<H, Cursor<&[u8]>>` 的委托包装,每次读后把读位置发布到
/// `a3_stream`(泛型验证函数据此定位 PCS 段起点并做封闭式偏移交叉核对)。FS 语义逐字委托、零拷贝。
pub struct StreamTranscript<'a, H> {
    inner: FiatShamirTranscript<H, Cursor<&'a [u8]>>,
}

pub type SM3StreamTranscript<'a> = StreamTranscript<'a, Sm3>;

impl<'a, H: Hash> StreamTranscript<'a, H> {
    pub fn new(proof: &'a [u8]) -> Self {
        a3_stream::publish_pos(0);
        StreamTranscript {
            inner: FiatShamirTranscript::<H, Cursor<&'a [u8]>>::from_proof_ref((), proof),
        }
    }

    pub fn stream_position(&self) -> usize {
        self.inner.stream_position()
    }
}

impl<H: Hash, F: PrimeField> FieldTranscript<F> for StreamTranscript<'_, H> {
    fn squeeze_challenge(&mut self) -> F {
        FieldTranscript::<F>::squeeze_challenge(&mut self.inner)
    }

    fn common_field_element(&mut self, fe: &F) -> Result<(), Error> {
        FieldTranscript::<F>::common_field_element(&mut self.inner, fe)
    }
}

impl<H: Hash, F: PrimeField> FieldTranscriptRead<F> for StreamTranscript<'_, H> {
    fn read_field_element(&mut self) -> Result<F, Error> {
        let v = FieldTranscriptRead::<F>::read_field_element(&mut self.inner)?;
        a3_stream::publish_pos(self.inner.stream_position());
        Ok(v)
    }
}

impl<H: Hash, F: PrimeField> Transcript<Output<H>, F> for StreamTranscript<'_, H> {
    fn common_commitment(&mut self, comm: &Output<H>) -> Result<(), Error> {
        Transcript::<Output<H>, F>::common_commitment(&mut self.inner, comm)
    }
}

impl<H: Hash, F: PrimeField> TranscriptRead<Output<H>, F> for StreamTranscript<'_, H> {
    fn read_commitment(&mut self) -> Result<Output<H>, Error> {
        let v = TranscriptRead::<Output<H>, F>::read_commitment(&mut self.inner)?;
        a3_stream::publish_pos(self.inner.stream_position());
        Ok(v)
    }
}


