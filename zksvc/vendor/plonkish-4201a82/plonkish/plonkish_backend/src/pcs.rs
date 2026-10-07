use crate::{
    poly::Polynomial,
    util::{
        arithmetic::{variable_base_msm, Curve, CurveAffine, Field},
        transcript::{TranscriptRead, TranscriptWrite},
        DeserializeOwned, Itertools, Serialize,
    },
    Error,
};
use rand::RngCore;
use std::fmt::Debug;

pub mod multilinear;
pub mod univariate;

pub type Point<F, P> = <P as Polynomial<F>>::Point;

pub type Commitment<F, Pcs> = <Pcs as PolynomialCommitmentScheme<F>>::Commitment;

pub type CommitmentChunk<F, Pcs> = <Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk;

pub trait PolynomialCommitmentScheme<F: Field>: Clone + Debug {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type ProverParam: Clone + Debug + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Debug + Serialize + DeserializeOwned;
    type Polynomial: Polynomial<F> + Serialize + DeserializeOwned;
    type Commitment: Clone
        + Debug
        + Default
        + AsRef<[Self::CommitmentChunk]>
        + Serialize
        + DeserializeOwned;
    type CommitmentChunk: Clone + Debug + Default;

    fn setup(poly_size: usize, batch_size: usize, rng: impl RngCore) -> Result<Self::Param, Error>;

    /// R1 内存优化（2026-09-21）：承诺的验证面视图（默认=整体克隆）。验证方
    /// 只消费承诺身份子集（Basefold=盐/根/组位）——重载以避免 verifier 参数
    /// 克隆全量证明侧载荷（码字/bh）。证明/验证语义零变化。
    fn commitment_verifier_view(comm: &Self::Commitment) -> Self::Commitment {
        comm.clone()
    }

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error>;

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error>;

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Self::Commitment, Error> {
        let comm = Self::commit(pp, poly)?;

        transcript.write_commitments(comm.as_ref())?;

        Ok(comm)
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a;

    /// 公共（预处理）多项式的批量承诺（2026-09-16 分相修复）：承诺随机性（盐）须由 setup 种子
    /// 确定性派生——透明 setup 的公共参数（预处理承诺=验证密钥的一部分）必须跨进程可复现，
    /// 验证方据同一种子重建；`domain` 区分同一 setup 下的多次公共承诺调用（防盐链重叠）。
    /// 默认实现=`batch_commit`（新鲜盐；仅对无盐化承诺的 PCS 恰当）。
    /// 🔴 见证多项式禁用本路径：见证承诺盐必须新鲜（防跨出示指纹链接，T1.3b 定案）。
    fn batch_commit_public<'a>(
        pp: &Self::ProverParam,
        _domain: u64,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a,
    {
        Self::batch_commit(pp, polys)
    }

    fn batch_commit_and_write<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a,
    {
        let comms = Self::batch_commit(pp, polys)?;
        for comm in comms.iter() {
            transcript.write_commitments(comm.as_ref())?;
        }
        Ok(comms)
    }

    /// A2 掩蔽列惰性化（组合 A，2026-10-06）：见证批次的掩蔽承诺入口——
    /// 证明侧以「明文列全集 + 共享 m + 逐列 λ」描述 ṽ=v+λ·m，**不整份物化**
    /// 掩蔽列；PCS 在编码消费点逐列即时取值。语义红线（拍板纪律）：与物化
    /// ṽ 后走 `batch_commit_and_write` 逐位同——承诺/转录字节零变化（域算术
    /// 精确等值：ṽ_i = v_i + λ_i·m_i 逐元素）。
    /// λ 表与 polys 逐位平行（长度相等）；mask=None 即纯明文（等价既有路径）。
    /// 默认实现（非掩蔽感知 PCS）：mask=None 等价既有路径；mask=Some 显式
    /// fail-loud 拒绝——绝不静默退化为明文承诺（掩蔽语义红线）。
    fn batch_commit_and_write_masked<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        mask: Option<(&'a Self::Polynomial, &'a [F])>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a,
    {
        assert!(
            mask.is_none(),
            "该 PCS 未实现 A2 掩蔽惰性承诺（拒绝静默退化明文）"
        );
        Self::batch_commit_and_write(pp, polys, transcript)
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>;

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>
    where
        Self::Polynomial: 'a,
        Self::Commitment: 'a;

    /// A2 掩蔽列惰性化（组合 A，2026-10-06）：开口批的掩蔽入口——polys 为
    /// **明文**全集（掩蔽槽位上=明文 v），`masked` 标出 (槽位, λ) 与共享 m。
    /// PCS 在 g_prime 组合/求值消费点按线性性即时折叠：c·ṽ = c·v + (c·λ)·m，
    /// 不物化任何整份 ṽ。语义红线：组合多项式/内层 sumcheck/证明字节与
    /// 「物化 ṽ 后走 batch_open」逐位同（域算术精确：Σcᵢ·ṽᵢ = Σcᵢ·vᵢ +
    /// (Σcᵢ·λᵢ)·m 作为多项式函数恒等 ⟹ 转录序列逐位一致）。
    fn batch_open_masked<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        masked: Option<(&'a Self::Polynomial, &'a [(usize, F)])>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>
    where
        Self::Polynomial: 'a,
        Self::Commitment: 'a,
    {
        assert!(
            masked.is_none(),
            "该 PCS 未实现 A2 掩蔽惰性开口（拒绝静默退化明文）"
        );
        Self::batch_open(pp, polys, comms, points, evals, transcript)
    }

    fn read_commitment(
        vp: &Self::VerifierParam,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Self::Commitment, Error> {
        let comms = Self::read_commitments(vp, 1, transcript)?;
        assert_eq!(comms.len(), 1);
        Ok(comms.into_iter().next().unwrap())
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error>;

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>;

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a;
}

#[derive(Clone, Debug)]
pub struct Evaluation<F> {
    pub poly: usize,
    pub point: usize,
    pub value: F,
}

impl<F> Evaluation<F> {
    pub fn new(poly: usize, point: usize, value: F) -> Self {
        Self { poly, point, value }
    }

    pub fn poly(&self) -> usize {
        self.poly
    }

    pub fn point(&self) -> usize {
        self.point
    }

    pub fn value(&self) -> &F {
        &self.value
    }
}

pub trait AdditiveCommitment<F: Field>: Debug + Default + PartialEq + Eq {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a F> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self
    where
        Self: 'a;
}

impl<C: CurveAffine> AdditiveCommitment<C::Scalar> for C {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a C::Scalar> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self {
        let scalars = scalars.into_iter().collect_vec();
        let bases = bases.into_iter().collect_vec();
        assert_eq!(scalars.len(), bases.len());

        variable_base_msm(scalars, bases).to_affine()
    }
}
