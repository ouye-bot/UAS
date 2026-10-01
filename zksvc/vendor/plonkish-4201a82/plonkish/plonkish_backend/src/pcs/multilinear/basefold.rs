use crate::pcs::Commitment;
use crate::piop::sum_check::{
    classic::{ClassicSumCheck, CoefficientsProver},
    eq_xy_eval, SumCheck as _, VirtualPolynomial,
};
use crate::{
    pcs::{
        multilinear::{additive, validate_input},
        AdditiveCommitment, Evaluation, Point, PolynomialCommitmentScheme,
    },
    poly::{multilinear::MultilinearPolynomial, Polynomial},
    util::{
        arithmetic::{div_ceil, horner, inner_product, steps, BatchInvert, Field, PrimeField},
        code::{Brakedown, BrakedownSpec, LinearCodes, binary_rs::{BinarySubspace, OnTheFlyTwiddleAccess, TwiddleAccess}},
        expression::{Expression, Query, Rotation},
        hash::{Hash, Output},
        new_fields::{Mersenne127, Mersenne61},
        parallel::{num_threads, parallelize, parallelize_iter},
        transcript::{FieldTranscript, Transcript, TranscriptRead, TranscriptWrite},
        BigUint, Deserialize, DeserializeOwned, Itertools, Serialize,
    },
    Error,
};
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use core::fmt::Debug;
use core::ptr::addr_of;
use ctr;
use ff::BatchInverter;
use generic_array::GenericArray;
use halo2_curves::bn256::{Bn256, Fr};
use rayon::iter::IntoParallelIterator;
use std::{collections::HashMap, iter, ops::Deref, time::Instant};

use plonky2_util::{reverse_bits, reverse_index_bits_in_place};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha12Rng, ChaCha8Rng,
};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use std::{borrow::Cow, marker::PhantomData, mem::size_of, slice};

//The most fundamental building block of basefold is the polynomial. Currently, polynomial's are just expressed as vectors of field elements. Sometimes, vectors are in coefficient form and sometimes they are in evaluation form. Additionally, many functions make assumptions on the order of evaluations of a polynomial. There are two orderings that are used. The first ordering (which we label Type1Polynomial) places "folding pairs" next to each other, for increased parallelizability. eg, the evaluations are as follows:

//Type1Polynomial: vec![P(x1,y1,z1), P(x1,y1,z2), P(x1,y2,z3), P(x1,y2,z4), P(x2,y3,z5), P(x2,y3,z6), P(x2,y4,z7), P(x2,y4,z8)]

//Type2Polynomial has it in the ordering that is described in the Basefold paper, which also lends itself well to fast encoding
//Type2Polynomial:  vec![P(x1,y1,z1), P(x2,y3,z5), P(x1,y2,z3), P(x2,y4,z7), P(x1,y1,z2), P(x2,y3,z6), P(x1,y2,z4), P(x2,y4,z8)]

//Type1Polynomial is a bit-reversal of Type2Polynomial, where the transformation can be done by the function `reverse_index_bits_in_place`, which was taken from `plonky2`.

//Finally, sometimes Type2Polynomial contains coefficients rather than evaluations, in that case it just means that when encoded, it yields evaluations in Type2 order.

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct Type1Polynomial<F: PrimeField> {
    pub poly: Vec<F>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct Type2Polynomial<F: PrimeField> {
    pub poly: Vec<F>,
}

type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldParams<F: PrimeField> {
    log_rate: usize,
    num_verifier_queries: usize,
    pub num_vars: usize,
    pub num_rounds: Option<usize>,
    table_w_weights: Vec<Vec<(F, F)>>,
    table: Vec<Vec<F>>,
    rng: ChaCha8Rng,
    rs_basecode: bool,
    /// 公共（预处理）承诺盐链种子（2026-09-16 分相修复）：由 setup 种子派生，跨进程可复现。
    public_salt_seed: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldProverParams<F: PrimeField> {
    pub log_rate: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
    pub table: Vec<Vec<F>>,
    num_verifier_queries: usize,
    pub num_vars: usize,
    num_rounds: usize,
    rs_basecode: bool,
    code_type: String,
    /// 公共承诺盐链种子（batch_commit_public 用；见证承诺仍走 fresh_salt）。
    public_salt_seed: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldVerifierParams<F: PrimeField> {
    rng: ChaCha8Rng,
    pub num_vars: usize,
    log_rate: usize,
    num_verifier_queries: usize,
    pub num_rounds: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
    rs_basecode: bool,
    code_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct BasefoldCommitment<F: PrimeField, H: Hash> {
    pub codeword: Type1Polynomial<F>,
    codeword_tree: Vec<Vec<Output<H>>>,
    pub bh_evals: Type1Polynomial<F>,
    /// D18 Phase 1（盐化 Merkle，T1.3b 指纹链接定案的 Layer 1 修复）：
    /// 本承诺树的 fresh 盐（长度=H 输出长度；与根成对写入证明串，每树独立）。
    pub salt: Output<H>,
    // D18 Phase 3（三世界统一，拍板 2026-09-04）：Phase 2 的 mask_seed/κ 系数注入
    // 退役——列层 ṽ=v+λ·m 掩蔽后 bh/码字/开口三方同世界，κ 及其末轮拟合弥补
    // （A·Z + β_last 拒绝采样）失去存在理由（git 历史可回溯）。
    // ---- 2026-09-16 D27 叶交织档（PCS_INTERLEAVE=1；默认档三项零值=逐字节历史行为）----
    /// 同批次列数（0=solo/非批次）。交织档：同批次 k 列共享一棵盐化树，叶=位置上的列值向量
    /// H(salt‖c₁[2i]‖c₁[2i+1]‖…‖c_k[2i]‖c_k[2i+1])，每查询每批次一条认证路径。
    #[serde(default)]
    pub group_size: usize,
    /// 本列在批次内序号。
    #[serde(default)]
    pub col: usize,
    /// 证明侧共享批次树（验证侧不需要；serde 跳过）。
    #[serde(skip)]
    group_tree: Option<std::sync::Arc<Vec<Vec<Output<H>>>>>,
}

impl<F: PrimeField, H: Hash> Default for BasefoldCommitment<F, H> {
    fn default() -> Self {
        Self {
            codeword: Type1Polynomial { poly: Vec::new() },
            codeword_tree: vec![vec![Output::<H>::default()]],
            bh_evals: Type1Polynomial { poly: Vec::new() },
            salt: Output::<H>::default(),
            group_size: 0,
            col: 0,
            group_tree: None,
        }
    }
}

impl<F: PrimeField, H: Hash> BasefoldCommitment<F, H> {
    /// D18 Phase 1：verifier 侧读入用——(salt, root) 成对读取后构造（只有根+盐，无码字）。
    fn from_salt_and_root(salt: Output<H>, root: Output<H>) -> Self {
        Self {
            codeword: Type1Polynomial { poly: Vec::new() },
            codeword_tree: vec![vec![root]],
            bh_evals: Type1Polynomial { poly: Vec::new() },
            salt,
            group_size: 0,
            col: 0,
            group_tree: None,
        }
    }

    /// D27 交织档验证侧读入构造：批次内第 col 列（k 列共享同一 (盐,根)；根压成单层
    /// codeword_tree 以复用 `tree[tree.len()-1][0]` 的统一根访问形态）。
    fn from_salt_root_group(salt: Output<H>, root: Output<H>, group_size: usize, col: usize) -> Self {
        Self {
            codeword: Type1Polynomial { poly: Vec::new() },
            codeword_tree: vec![vec![root]],
            bh_evals: Type1Polynomial { poly: Vec::new() },
            salt,
            group_size,
            col,
            group_tree: None,
        }
    }

    /// R1 内存优化（2026-09-21 归因表 #7/#8）：验证面视图——(盐,根,组位) 三件套。
    /// 消费面审计：batch_verify 对 vp 承诺只读 salt/committed_root/组结构
    ///（check_and_absorb/group_starts），码字/bh/证明侧树零消费——vp 不再克隆
    /// 全量承诺载荷（AUTH 4,588 列×393KB：vp 内存 −1.80GB+序列化缓冲 2.28GB→约 22MB）。
    /// serde 兼容：字段仍在，只是空载荷——旧 vp 文件（全载荷）照常可读。
    pub(crate) fn to_verifier_view(&self) -> Self {
        Self {
            codeword: Type1Polynomial::default(),
            codeword_tree: vec![vec![self.committed_root().clone()]],
            bh_evals: Type1Polynomial::default(),
            salt: self.salt.clone(),
            group_size: self.group_size,
            col: self.col,
            group_tree: None,
        }
    }

    /// 已承诺根统一访问（solo=满树末层；交织=单根层）。
    fn committed_root(&self) -> &Output<H> {
        &self.codeword_tree[self.codeword_tree.len() - 1][0]
    }

    /// D27:是否承载交织批次。
    fn is_grouped(&self) -> bool {
        self.group_size != 0
    }
}
impl<F: PrimeField, H: Hash> PartialEq for BasefoldCommitment<F, H> {
    fn eq(&self, other: &Self) -> bool {
        self.codeword.poly.eq(&other.codeword.poly)
            && self.codeword_tree.eq(&other.codeword_tree)
            && self.bh_evals.poly.eq(&other.bh_evals.poly)
            && self.salt.eq(&other.salt)
    }
}

impl<F: PrimeField, H: Hash> Eq for BasefoldCommitment<F, H> {}

pub trait BasefoldExtParams: Debug {
    fn get_reps() -> usize;

    fn get_rate() -> usize;

    fn get_basecode_rounds() -> usize;

    fn get_rs_basecode() -> bool;

    fn get_code_type() -> String;
}

#[derive(Debug)]
pub struct Basefold<F: PrimeField, H: Hash, V: BasefoldExtParams>(PhantomData<(F, H, V)>);

impl<F: PrimeField, H: Hash, V: BasefoldExtParams> Clone for Basefold<F, H, V> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<F: PrimeField, H: Hash> AsRef<[Output<H>]> for BasefoldCommitment<F, H> {
    fn as_ref(&self) -> &[Output<H>] {
        let root = &self.codeword_tree[self.codeword_tree.len() - 1][0];
        slice::from_ref(root)
    }
}

impl<F: PrimeField, H: Hash> AsRef<Output<H>> for BasefoldCommitment<F, H> {
    fn as_ref(&self) -> &Output<H> {
        let root = &self.codeword_tree[self.codeword_tree.len() - 1][0];
        &root
    }
}
impl<F: PrimeField, H: Hash> AdditiveCommitment<F> for BasefoldCommitment<F, H> {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a F> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self {
        let bases = bases.into_iter().collect_vec();

        let scalars = scalars.into_iter().collect_vec();

        // R1 内存优化（2026-09-21 消费面审计）：原实现把每列 bh_evals 折叠进
        // new_bh_eval——该结果在本函数构造处即被丢弃（返回体 bh_evals 恒空，
        // batch_open 尾部以 g_prime 覆写），纯死码；删除后批次承诺可不驻留 bh。
        let mut new_codeword = vec![F::ZERO; bases[0].codeword.poly.len()];
        new_codeword
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, mut c)| {
                for j in 0..bases.len() {
                    *c += *scalars[j] * bases[j].codeword.poly[i];
                }
            });

        let cw = Type1Polynomial { poly: new_codeword };
        // D18 Phase 1：组合承诺=独立树，盐独立生成（sanity-check 生产路径实测在用）。
        let salt = fresh_salt::<H>();
        let tree = merkelize::<F, H>(&cw, &salt);

        Self {
            codeword: cw,
            bh_evals: Type1Polynomial { poly: Vec::new() },
            codeword_tree: tree,
            salt,
            group_size: 0,
            col: 0,
            group_tree: None,
        }
    }
}
impl<F, H, V> PolynomialCommitmentScheme<F> for Basefold<F, H, V>
where
    F: PrimeField + Serialize + DeserializeOwned,
    H: Hash,
    V: BasefoldExtParams,
{
    type Param = BasefoldParams<F>;
    type ProverParam = BasefoldProverParams<F>;
    type VerifierParam = BasefoldVerifierParams<F>;
    type Polynomial = MultilinearPolynomial<F>;
    type Commitment = BasefoldCommitment<F, H>;
    type CommitmentChunk = Output<H>;

    /// R1 内存优化（2026-09-21）：验证面视图覆写——(盐,根,组位)；码字/bh 不进 vp。
    fn commitment_verifier_view(comm: &Self::Commitment) -> Self::Commitment {
        comm.to_verifier_view()
    }

    fn setup(poly_size: usize, _: usize, mut rng: impl RngCore) -> Result<Self::Param, Error> {
        let log_rate = V::get_rate();
        // 🔴 2026-09-16 分相修复（A3 本地 VmHWM 对照连带发现）：编码表 RNG 原为
        // ChaCha8Rng::from_entropy()（每进程随机、忽略调用方种子）⟹ PROOF_DUMP/PROOF_LOAD
        // 跨进程验证必在折叠一致性断言失败（basefold.rs verifier_query_phase），"分相架构"
        // 从未真正跨进程验证过；公共参数（透明 setup 的编码表）须由公开种子可复现。
        // 改为由调用方 rng 派生 32B 种子；同进程流程语义不变，尺寸/计时不变。
        let mut table_seed = [0u8; 32];
        rng.fill_bytes(&mut table_seed);
        let mut test_rng = ChaCha8Rng::from_seed(table_seed);
        // 公共承诺盐链种子同样由调用方 rng 派生（预处理承诺=验证密钥，须跨进程可复现）。
        let mut public_salt_seed = [0u8; 32];
        rng.fill_bytes(&mut public_salt_seed);
        let (table_w_weights, table) = if V::get_code_type() == "binary_rs" {
            get_table_additive_binary(poly_size, log_rate)
        } else {
            get_table_aes(poly_size, log_rate, &mut test_rng)
        };
        let mut rs_basecode = false;
        if V::get_rs_basecode() == true && V::get_basecode_rounds() > 0 {
            rs_basecode = true;
        }
        Ok(BasefoldParams {
            log_rate: log_rate,
            num_verifier_queries: V::get_reps(),
            num_vars: log2_strict(poly_size),
            num_rounds: Some(log2_strict(poly_size) - V::get_basecode_rounds()),
            table_w_weights: table_w_weights,
            table: table,
            rng: test_rng.clone(),
            rs_basecode: rs_basecode,
            public_salt_seed,
        })
    }
    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        let mut rounds = param.num_vars;
        if param.num_rounds.is_some() {
            rounds = param.num_rounds.unwrap();
        }

        Ok((
            BasefoldProverParams {
                log_rate: param.log_rate,
                table_w_weights: param.table_w_weights.clone(),
                table: param.table.clone(),
                num_verifier_queries: param.num_verifier_queries,
                num_vars: param.num_vars,
                num_rounds: rounds,
                rs_basecode: param.rs_basecode,
                code_type: V::get_code_type(),
                public_salt_seed: param.public_salt_seed,
            },
            BasefoldVerifierParams {
                rng: param.rng.clone(),
                num_vars: param.num_vars,
                log_rate: param.log_rate,
                num_verifier_queries: param.num_verifier_queries,
                num_rounds: rounds,
                table_w_weights: param.table_w_weights.clone(),
                rs_basecode: param.rs_basecode,
                code_type: V::get_code_type(),
            },
        ))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        // D18 Phase 1：每个承诺 fresh 盐（每树独立；同 witness 两次 commit ⟹ 根不同）。
        Ok(basefold_commit_with_salt::<F, H>(pp, poly, fresh_salt::<H>()))
    }

    /// 公共（预处理）承诺：盐链 = ChaCha8(public_salt_seed ⊕ domain) 顺序派生（与 poly 序一一对应），
    /// 树本体并行构建；跨进程按同一 setup 种子复现 ⟹ 验证方重建的预处理承诺与证明方逐字节相同。
    fn batch_commit_public<'a>(
        pp: &Self::ProverParam,
        domain: u64,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a,
    {
        let polys_vec: Vec<&Self::Polynomial> = polys.into_iter().collect();
        let mut seed = pp.public_salt_seed;
        for (i, b) in domain.to_le_bytes().iter().enumerate() {
            seed[i] ^= b;
        }
        if interleave_on() {
            // D27:公共批次=一盐一树,盐取种子盐链首元素(同 domain 跨进程可复现)。
            // 空批次直接返回(无承诺)。
            if polys_vec.is_empty() {
                return Ok(Vec::new());
            }
            let mut salt_rng = ChaCha8Rng::from_seed(seed);
            let mut salt = Output::<H>::default();
            salt_rng.fill_bytes(salt.as_mut_slice());
            return Ok(basefold_commit_group::<F, H>(pp, &polys_vec, salt));
        }
        let mut salt_rng = ChaCha8Rng::from_seed(seed);
        let salts: Vec<Output<H>> = (0..polys_vec.len())
            .map(|_| {
                let mut s = Output::<H>::default();
                salt_rng.fill_bytes(s.as_mut_slice());
                s
            })
            .collect();
        Ok(polys_vec
            .par_iter()
            .zip(salts.into_par_iter())
            .map(|(poly, salt)| basefold_commit_with_salt::<F, H>(pp, poly, salt))
            .collect())
    }

    /// D18 Phase 1：单承诺写入路径覆写 trait 默认（默认只写根单 chunk，
    /// 与盐化读侧 (salt, root) 对失配）——写 (salt, root) 对，与 read_commitments 对齐。
    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Self::Commitment, Error> {
        let comm = Self::commit(pp, poly)?;
        transcript.write_commitment(&comm.salt)?;
        transcript.write_commitment(comm.as_ref())?;
        absorb_salt_root::<F, H>(transcript, &comm.salt, comm.committed_root()); // D1
        Ok(comm)
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
        let mut roots = Vec::with_capacity(comms.len());

        comms.iter().for_each(|comm| {
            let root = &comm.codeword_tree[comm.codeword_tree.len() - 1][0];
            roots.push(root);
        });

        if interleave_on() {
            // D27:批次一盐一树 ⟹ 每批次写 (盐,根) 一对(读侧 read_commitments 同式扇出)。
            comms.iter()
                .filter(|comm| comm.col == 0)
                .for_each(|comm| {
                    transcript.write_commitment(&comm.salt);
                    let root = &comm.codeword_tree[comm.codeword_tree.len() - 1][0];
                    transcript.write_commitment(root);
                    absorb_salt_root::<F, H>(transcript, &comm.salt, root); // D1
                });
            return Ok(comms);
        }

        // D18 Phase 1：承诺写入=(salt, root) 交错对（读侧 read_commitments 同序逐对读取）。
        comms.iter().for_each(|comm| {
            transcript.write_commitment(&comm.salt);
        });
        comms.iter().for_each(|comm| {
            let root = &comm.codeword_tree[comm.codeword_tree.len() - 1][0];
            transcript.write_commitment(root);
        });
        // D1:逐承诺 (盐,根) 吸收(读侧 read_commitments zip 后同序)。
        comms.iter().for_each(|comm| {
            absorb_salt_root::<F, H>(transcript, &comm.salt, comm.committed_root());
        });
        Ok(comms)
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let polys_vec: Vec<&Self::Polynomial> = polys.into_iter().map(|poly| poly).collect();
        if interleave_on() {
            // D27:见证批次=一盐一树,fresh 盐(每 prove 新鲜;防跨出示指纹,T1.3b 语义保持)。
            // 空批次(如 num_lookups=0 的 lookup 相)⟹ 无承诺无写入,直接返回。
            if polys_vec.is_empty() {
                return Ok(Vec::new());
            }
            return Ok(basefold_commit_group::<F, H>(pp, &polys_vec, fresh_salt::<H>()));
        }
        polys_vec
            .par_iter()
            .map(|poly| Self::commit(pp, poly))
            .collect()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        // D18 Phase 3：无掩蔽再生（κ 退役，列层 ṽ 直入，世界统一）。
        // D2 单点语句吸收(标签/承诺身份/点/声称;verify 同序)——先于任何 squeeze。
        absorb_single_statement::<F, H>(transcript, &comm.salt, comm.committed_root(), point, eval);
        // 缺口 C 修复(2026-09-16,单点同构):内层 type-1 约定 ⟹ 传 rev(point),使转录 eval==poly(point)。
        let inner_point: Vec<F> = point.iter().rev().cloned().collect();
        let (trees, sum_check_oracles, mut oracles, mut bh_evals, mut eq, eval) = commit_phase(
            &inner_point,
            &comm,
            transcript,
            pp.num_vars,
            pp.num_rounds,
            &pp.table_w_weights,
            pp.code_type.clone(),
            pp.log_rate,
        );

        let (queried_els, queries_usize_) =
            query_phase(transcript, &comm, &oracles, pp.num_verifier_queries);

        // a proof consists of roots, merkle paths, query paths, sum check oracles, eval, and final oracle

        transcript.write_field_element(&eval); //write eval

        if pp.num_rounds < pp.num_vars {
            transcript.write_field_elements(&bh_evals.poly); //write bh_evals
            transcript.write_field_elements(&eq.poly); //write eq
        }

        //write final oracle
        let mut final_oracle = oracles.pop().unwrap();
        transcript.write_field_elements(&final_oracle.poly);

        //write query paths
        queried_els
            .iter()
            .map(|q| &q.0)
            .flatten()
            .for_each(|query| {
                transcript.write_field_element(&query.0);
                transcript.write_field_element(&query.1);
            });

        //write merkle paths
        queried_els.iter().for_each(|query| {
            let indices = &query.1;
            indices.into_iter().enumerate().for_each(|(i, q)| {
                if (i == 0) {
                    write_merkle_path::<H, F>(&comm.codeword_tree, *q, transcript);
                } else {
                    write_merkle_path::<H, F>(&trees[i - 1], *q, transcript);
                }
            })
        });

        Ok(())
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        use std::env;

        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();

        validate_input("batch open", pp.num_vars, polys.clone(), points)?;
        if comms.len() != polys.len() {
            return Err(Error::InvalidPcsOpen(format!(
                "batch open: comms({}) 与 polys({}) 数量不一致",
                comms.len(),
                polys.len()
            )));
        }
        validate_batch_claims("batch open", polys.len(), points, evals)?;
        if interleave_on() {
            // D27:S1′ 头部=按批次首现序每批次写 (盐,根) 一对(batch_verify 消耗读同序)。
            let starts = group_starts(&comms);
            for &(s0, _) in &starts {
                let comm = &comms[s0];
                transcript.write_commitment(&comm.salt);
                transcript.write_commitment(&comm.as_ref());
                absorb_salt_root::<F, H>(transcript, &comm.salt, comm.committed_root()); // D1
            }
        } else {
            for comm in &comms {
                // D18 Phase 1：个体承诺重复写=(salt, root) 对（batch_verify 消耗读同序）。
                transcript.write_commitment(&comm.salt);
                transcript.write_commitment(&comm.as_ref());
                absorb_salt_root::<F, H>(transcript, &comm.salt, comm.committed_root()); // D1
            }
        }
        // D2:语句(点+声称)先于组合挑战 t 吸收(batch_verify 同序)。
        absorb_batch_statement(transcript, points, evals);
        let ell = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(ell);

        let eq_xt = MultilinearPolynomial::eq_xy(&t);
        let merged_polys = evals.iter().zip(eq_xt.evals().iter()).fold(
            vec![(F::ONE, Cow::<MultilinearPolynomial<_>>::default()); points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                if merged_polys[eval.point()].1.is_zero() {
                    merged_polys[eval.point()] = (*eq_xt_i, Cow::Borrowed(polys[eval.poly()]));
                } else {
                    let coeff = merged_polys[eval.point()].0;
                    if coeff != F::ONE {
                        merged_polys[eval.point()].0 = F::ONE;
                        *merged_polys[eval.point()].1.to_mut() *= &coeff;
                    }
                    *merged_polys[eval.point()].1.to_mut() += (eq_xt_i, polys[eval.poly()]);
                }
                merged_polys
            },
        );

        let unique_merged_polys = merged_polys
            .iter()
            .unique_by(|(_, poly)| addr_of!(*poly.deref()))
            .collect_vec();
        let unique_merged_poly_indices = unique_merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (_, poly))| (addr_of!(*poly.deref()), idx))
            .collect::<HashMap<_, _>>();
        let expression = merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (scalar, poly))| {
                let poly = unique_merged_poly_indices[&addr_of!(*poly.deref())];
                Expression::<F>::eq_xy(idx)
                    * Expression::Polynomial(Query::new(poly, Rotation::cur()))
                    * scalar
            })
            .sum();
        let virtual_poly = VirtualPolynomial::new(
            &expression,
            unique_merged_polys.iter().map(|(_, poly)| poly.deref()),
            &[],
            points,
        );
        let tilde_gs_sum =
            inner_product(evals.iter().map(Evaluation::value), &eq_xt[..evals.len()]);
        let now = Instant::now();
        let (challenges, _) =
            SumCheck::prove(&(), pp.num_vars, virtual_poly, tilde_gs_sum, transcript)?;

        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&challenges, point))
            .collect_vec();
        let g_prime = merged_polys
            .into_iter()
            .zip(eq_xy_evals.iter())
            .map(|((scalar, poly), eq_xy_eval)| (scalar * eq_xy_eval, poly.into_owned()))
            .sum::<MultilinearPolynomial<_>>();

        let (mut comm, eval) = if cfg!(feature = "sanity-check") {
            let scalars = evals
                .iter()
                .zip(eq_xt.evals())
                .map(|(eval, eq_xt_i)| eq_xy_evals[eval.point()] * eq_xt_i)
                .collect_vec();
            let bases = evals.iter().map(|eval| comms[eval.poly()]);
            let now = Instant::now();
            let comm = Self::Commitment::sum_with_scalar(&scalars, bases);

            (comm, g_prime.evaluate(&challenges))
        } else {
            (Self::Commitment::default(), F::ZERO)
        };
        let mut bh_evals = g_prime.evals().to_vec();

        //convert to type 1
        reverse_index_bits_in_place(&mut bh_evals);

        comm.bh_evals = Type1Polynomial { poly: bh_evals };
        // 🔴 2026-09-16 声音性修复(W1_CHECKPOINT v9 §13 缺口 C,约定错位):内层 BaseFold Eval 在 type-1
        // (位反序)数组上运行,build_eq_x_r_vec 为 LSB↔r₀ 约定 ⟹ 内层证明的是 ṽ(p)=g′(rev p)。外层 sumcheck
        // 把声称归约到 g′(r)(plonkish 求值约定,r=challenges)。实测 commit_phase eval==g′(rev r)≠g′(r)。
        // 接口处传 rev(r) ⟹ 内层证明 ṽ(rev r)=g′(r)=g_prime_eval,粘合等式(缺口 A)对诚实证明者成立。
        // 内层消息值随 eq 改变,字节长度零变化。
        let point: Vec<F> = challenges.iter().rev().cloned().collect();

        // D18 Phase 3：无组合掩蔽再生（κ 退役；组合承诺的码字本身即 ṽ 世界的线性组合）。
        let (trees, sum_check_oracles, mut oracles, bh_evals, eq, eval) = commit_phase(
            &point,
            &comm,
            transcript,
            pp.num_vars,
            pp.num_rounds,
            &pp.table_w_weights,
            pp.code_type.clone(),
            pp.log_rate,
        );

        if pp.num_rounds < pp.num_vars {
            transcript.write_field_elements(&bh_evals.poly);
            transcript.write_field_elements(&eq.poly);
        }

        let (queried_els, queries_usize) =
            query_phase(transcript, &comm, &oracles, pp.num_verifier_queries);

        let mut individual_queries: Vec<Vec<(F, F)>> = Vec::with_capacity(queries_usize.len());

        let mut individual_paths: Vec<Vec<Vec<(Output<H>, Output<H>)>>> =
            Vec::with_capacity(queries_usize.len());
        // A5 路线 b（2026-09-15）：个体开口按（查询位置, poly）去重——同一列承诺
        // 在同一查询位置的值与 Merkle 路径确定相同，现行按 evals 逐条重复书写。
        // `PCS_BATCH_DEDUP=1` 时每查询只对 evals 中每个**不同 poly**（首现序）
        // 书写一次；验证侧同构重建（同一映射、同一组校验），验证语义逐条不变，
        // 仅转录字节更少。默认关 = 字节级现行行为（冻结口径零触碰）。
        let dedup_on = std::env::var("PCS_BATCH_DEDUP")
            .map(|v| v == "1")
            .unwrap_or(false);
        let (slot_of_eval, slot_poly): (Vec<usize>, Vec<usize>) = {
            let mut seen: HashMap<usize, usize> = HashMap::new();
            let slot_of_eval: Vec<usize> = evals
                .iter()
                .map(|ev| {
                    let n = seen.len();
                    *seen.entry(ev.poly()).or_insert(n)
                })
                .collect();
            let mut slot_poly: Vec<usize> =
                vec![usize::MAX; *slot_of_eval.last().unwrap_or(&0) + 1];
            for (j, &s) in slot_of_eval.iter().enumerate() {
                if slot_poly[s] == usize::MAX {
                    slot_poly[s] = evals[j].poly();
                }
            }
            (slot_of_eval, slot_poly)
        };
        if interleave_on() {
            // D27:S6′=每查询按 (批次,列) 序写全部列叶值对;S7′=每查询每批次一条路径。
            let starts = group_starts(&comms);
            for query in &queries_usize {
                let mut comm_queries = Vec::with_capacity(comms.len());
                let mut comm_paths = Vec::with_capacity(starts.len());
                for &(s0, k) in &starts {
                    for j in 0..k {
                        let c = &comms[s0 + j];
                        comm_queries.push(codeword_pair::<F>(query, &c.codeword.poly));
                    }
                }
                for &(s0, _) in &starts {
                    let tree_ref: &Vec<Vec<Output<H>>> = comms[s0]
                        .group_tree
                        .as_ref()
                        .expect("交织档承诺缺批次树(证明侧必持 Arc)")
                        .as_ref();
                    comm_paths.push(get_merkle_path::<H, F>(tree_ref, *query, true));
                }
                individual_queries.push(comm_queries);
                individual_paths.push(comm_paths);
            }
        } else {
        for query in &queries_usize {
            let mut comm_queries = Vec::with_capacity(evals.len());
            let mut comm_paths = Vec::with_capacity(evals.len());
            if dedup_on {
                for &p in &slot_poly {
                    let c = &comms[p];
                    let res = query_codeword::<F, H>(query, &c.codeword.poly, &c.codeword_tree);
                    comm_queries.push(res.0);
                    comm_paths.push(res.1);
                }
            } else {
                for eval in evals {
                    let c = comms[eval.poly()];
                    let res = query_codeword::<F, H>(query, &c.codeword.poly, &c.codeword_tree);
                    comm_queries.push(res.0);
                    comm_paths.push(res.1);
                }
            }

            individual_queries.push(comm_queries);
            individual_paths.push(comm_paths);
        }
        }

        let merkle_paths: Vec<Vec<Vec<(Output<H>, Output<H>)>>> = queried_els
            .iter()
            .map(|query| {
                let indices = &query.1;
                indices
                    .into_iter()
                    .enumerate()
                    .map(|(i, q)| {
                        if (i == 0) {
                            return get_merkle_path::<H, F>(&comm.codeword_tree, *q, false);
                        } else {
                            return get_merkle_path::<H, F>(&trees[i - 1], *q, false);
                        }
                    })
                    .collect()
            })
            .collect();

        // a proof consists of roots, merkle paths, query paths, sum check oracles, eval, and final oracle
        //write individual commitment queries for batching
        //queries for batch
        individual_queries.iter().flatten().for_each(|(f1, f2)| {
            transcript.write_field_element(f1).unwrap();
            transcript.write_field_element(f2).unwrap();
        });
        //paths for batch
        individual_paths
            .iter()
            .flatten()
            .flatten()
            .for_each(|(h1, h2)| {
                transcript.write_commitment(h1);
                transcript.write_commitment(h2);
            });

        //write sum check oracles

        //write eval
        transcript.write_field_element(&eval);
        //write final oracle
        transcript.write_field_elements(oracles.pop().unwrap().poly.iter().collect_vec());
        //write query paths
        queried_els
            .iter()
            .map(|q| &q.0)
            .flatten()
            .for_each(|query| {
                transcript.write_field_element(&query.0);
                transcript.write_field_element(&query.1);
            });
        //write merkle paths
        merkle_paths
            .iter()
            .flatten()
            .flatten()
            .for_each(|(h1, h2)| {
                transcript.write_commitment(h1);
                transcript.write_commitment(h2);
            });

        Ok(())
    }

    fn read_commitments(
        _: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        if interleave_on() {
            // D27:每批次读 (盐,根) 一对,扇出 num_polys 个批次内列承诺;空批次直接返回。
            if num_polys == 0 {
                return Ok(Vec::new());
            }
            let salt = transcript.read_commitments(1).unwrap().remove(0);
            let root = transcript.read_commitments(1).unwrap().remove(0);
            absorb_salt_root::<F, H>(transcript, &salt, &root); // D1(与 batch_commit_and_write 交织分支同序)
            return Ok((0..num_polys)
                .map(|j| BasefoldCommitment::from_salt_root_group(salt.clone(), root.clone(), num_polys, j))
                .collect_vec());
        }
        // D18 Phase 1：读侧与 batch_commit_and_write 分块序对齐——先全盐后全根，逐对 zip。
        let salts = transcript.read_commitments(num_polys).unwrap();
        let roots = transcript.read_commitments(num_polys).unwrap();
        // D1:逐承诺 (盐,根) 吸收(与写侧 zip 后同序)。
        for (s, r) in salts.iter().zip(roots.iter()) {
            absorb_salt_root::<F, H>(transcript, s, r);
        }

        Ok(salts
            .into_iter()
            .zip(roots)
            .map(|(s, r)| BasefoldCommitment::from_salt_and_root(s, r))
            .collect_vec())
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let field_size = 255;
        // D2 单点语句吸收(与 open 同序)。
        absorb_single_statement::<F, H>(transcript, &comm.salt, comm.committed_root(), point, eval);
        let n = (1 << (vp.num_vars + vp.log_rate));
        //read first $(num_var - 1) commitments

        let mut fold_challenges: Vec<F> = Vec::with_capacity(vp.num_vars);
        let mut size = 0;
        let mut roots = Vec::new();
        let mut round_salts: Vec<Output<H>> = Vec::new();
        let mut sum_check_oracles = Vec::new();
        for i in 0..vp.num_rounds {
            // D18 Phase 1：轮根读入=(salt, root) 对（与 commit_phase 写序一致）。
            round_salts.push(transcript.read_commitment().unwrap());
            roots.push(transcript.read_commitment().unwrap());
            // D1:轮根 (盐,根) 进 FS(与 commit_phase 写侧同点吸收),先于本轮挑战。
            absorb_salt_root::<F, H>(transcript, round_salts.last().unwrap(), roots.last().unwrap());
            // D18 Phase 3：标准读序（读消息→挤挑战）；Phase 2 末轮重排+拒绝采样退役。
            sum_check_oracles.push(transcript.read_field_elements(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
        }
        // 🔴 Fix E(2026-09-17,本会话发现·缺口 E):单点链头绑定——首轮 (盐,根) 必须
        // 等于验证者持有的承诺身份。诚实证明者首轮即写承诺根(commit_phase 初值);
        // 缺此比对时攻击者可以受害者身份做 D2 吸收、对自选码字整链诚实产证
        // (头部承诺块写受害者身份)⟹ 任意承诺可在任意点"打开"到任意值(库级 PCS
        // 绑定失效;pcs_single_point_chain_head_forgery 负例实测)。生产 e2e 走批量线
        // (头部校验+个体开口根链+lc 已闭合),本缺口限于单点 API。
        if round_salts[0] != comm.salt || roots[0] != *comm.committed_root() {
            return Err(Error::InvalidPcsOpen(
                "verify: 首轮 (盐,根) 与承诺身份不一致(折叠链头未绑定承诺)".to_string(),
            ));
        }
        sum_check_oracles.push(transcript.read_field_elements(3).unwrap());

        let mut query_challenges = transcript.squeeze_challenges(vp.num_verifier_queries);

        size = size + field_size * (3 * (vp.num_rounds + 1));
        //read eval

        // 🔴 2026-09-16 声音性修复(W1_CHECKPOINT v9 §13 缺口 A 单点同构):原 `let eval = &transcript.read…`
        // 以转录值**遮蔽**调用方声称参数(旧注释"do not need eval in proof"),声称从未被校验 ⟹ 单点
        // 开口对任意声称值可通过。现校验转录 eval == 调用方声称(=论文 Protocol 4 `h_d(0)+h_d(1)=y`
        // 的 y 来源归位);后续沿用调用方 eval。转录格式零变化。
        let eval_in_proof = transcript.read_field_element().unwrap();
        if eval_in_proof != *eval {
            return Err(Error::InvalidPcsOpen(
                "verify: 转录 eval != 调用方声称 eval(求值声称未绑定承诺)".to_string(),
            ));
        }

        let mut bh_evals = Vec::new();
        let mut eq = Vec::new();
        if vp.num_rounds < vp.num_vars {
            bh_evals = transcript
                .read_field_elements(1 << (vp.num_vars - vp.num_rounds))
                .unwrap();
            eq = transcript
                .read_field_elements(1 << (vp.num_vars - vp.num_rounds))
                .unwrap();
            size = size + field_size * (bh_evals.len() + eq.len());
        }

        //read final oracle
        let mut final_oracle = transcript
            .read_field_elements(1 << (vp.num_vars - vp.num_rounds + vp.log_rate))
            .unwrap();

        size = size + field_size * final_oracle.len();
        //read query paths
        let num_queries = vp.num_verifier_queries * 2 * (vp.num_rounds + 1);

        let all_qs = transcript.read_field_elements(num_queries).unwrap();

        size = size + (num_queries - 2) * field_size;
        //        println!("size for all iop queries {:?}", size);

        let i_qs = all_qs.chunks((vp.num_rounds + 1) * 2).collect_vec();

        assert_eq!(i_qs.len(), vp.num_verifier_queries);

        let mut queries = i_qs.iter().map(|q| q.chunks(2).collect_vec()).collect_vec();

        assert_eq!(queries.len(), vp.num_verifier_queries);

        //read merkle paths

        let mut query_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> =
            Vec::with_capacity(vp.num_verifier_queries);
        let query_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> = (0..vp.num_verifier_queries)
            .into_iter()
            .map(|i| {
                let mut merkle_paths: Vec<Vec<Vec<Output<H>>>> =
                    Vec::with_capacity(vp.num_rounds + 1);
                for round in 0..(vp.num_rounds + 1) {
                    let mut merkle_path: Vec<Output<H>> = transcript
                        .read_commitments(2 * (vp.num_vars - round + vp.log_rate - 1))
                        .unwrap();
                    size = size + 256 * (2 * (vp.num_vars - round + vp.log_rate - 1));

                    let chunked_path: Vec<Vec<Output<H>>> =
                        merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                    merkle_paths.push(chunked_path);
                }
                merkle_paths
            })
            .collect();

        verifier_query_phase::<F, H>(
            &query_challenges,
            &query_merkle_paths,
            &sum_check_oracles,
            &fold_challenges,
            &queries,
            vp.num_rounds,
            vp.num_vars,
            vp.log_rate,
            &roots,
            &round_salts,
            vp.rng.clone(),
            &eval,
            &vp.code_type,
            &final_oracle,
        );
        let mut next_oracle = Type1Polynomial { poly: final_oracle };
        let mut bh_evals = Type1Polynomial { poly: bh_evals };
        let mut eq = Type1Polynomial { poly: eq };
        // 缺口 C 修复(单点同构,与 open 对称):内层约定下的点=rev(point)。
        let inner_point: Vec<F> = point.iter().rev().cloned().collect();
        if (!vp.rs_basecode) {
            virtual_open(
                vp.num_vars,
                vp.num_rounds,
                &mut eq,
                &mut bh_evals,
                &mut next_oracle,
                &inner_point,
                &mut fold_challenges,
                &vp.table_w_weights,
                &mut sum_check_oracles,
                vp.log_rate,
                vp.code_type.clone()
            );
        } else {
            one_level_reverse_interp_hc(&mut bh_evals);
            reverse_index_bits_in_place(&mut bh_evals.poly); //convert to type2
            let (mut new_coeffs, _) =
                interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                    poly: bh_evals.poly,
                });

            let rs = encode_rs_basecode(
                &new_coeffs,
                1 << vp.log_rate,
                1 << (vp.num_vars - vp.num_rounds),
            );

            reverse_index_bits_in_place(&mut next_oracle.poly); //convert to type2
            assert_eq!(
                rs,
                Type2Polynomial {
                    poly: next_oracle.poly
                }
            );
        }
        Ok(())
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        use std::env;
        println!("VERIFY");

        // A3 两遍流式档(PCS_VERIFY_STREAM=1;默认关=历史行为字节级不变):PCS 段起点 =
        // StreamTranscript 已发布的当前读位置(本函数入口前的最后一读 = HyperPlonk 前缀末读 m_y)。
        // 第一遍按现行读序推进 FS 状态但对 S6/S7 两大段只读不留;第二遍以封闭式偏移在回放源上
        // 手动解析、逐查询即时核对与认证(工作集=单查询)。
        let stream_on = crate::util::transcript::a3_stream::enabled();
        let pcs_start = if stream_on { crate::util::transcript::a3_stream::pos() } else { 0 };
        // D27 Phase 3(2026-09-17):流式×交织落地——封闭式 v2(off_s6 用批次数 g/每查询 N_all 对/
        // 每查询 g 条路径) + 第一遍跳读 + 第二遍逐查询向量叶认证;两开关可同启。
        let inter = interleave_on();

        let comms = comms.into_iter().collect_vec();
        validate_input("batch verify", vp.num_vars, [], points)?;
        // D18 Phase 1：对齐消耗读=(salt, root) 成对（batch_open 开头逐承诺成对重复写）；
        // 读后连盐丢弃=transcript 对齐消耗（A.8 定案：消耗读≠未绑定，尾部 :930 绑定链闭合）。
        // D1(2026-09-16):头部对齐读 → 校验==验证者持有的承诺身份(Err),并吸收该身份进 FS(与 batch_open 同序)。
        let check_and_absorb = |transcript: &mut _, salt: Output<H>, root: Output<H>, comm: &BasefoldCommitment<F, H>| -> Result<(), Error> {
            if salt != comm.salt || root != *comm.committed_root() {
                return Err(Error::InvalidPcsOpen(
                    "batch_verify: 头部 (盐,根) 与验证者持有承诺不一致".to_string(),
                ));
            }
            absorb_salt_root::<F, H>(transcript, &comm.salt, comm.committed_root());
            Ok(())
        };
        if inter {
            // D27:S1′ 头部=按批次首现序每批次一对。
            let starts = group_starts(&comms);
            for &(s0, _) in &starts {
                let s = transcript.read_commitment().unwrap();
                let r = transcript.read_commitment().unwrap();
                check_and_absorb(transcript, s, r, comms[s0])?;
            }
        } else {
            for comm in comms.iter() {
                let s = transcript.read_commitment().unwrap();
                let r = transcript.read_commitment().unwrap();
                check_and_absorb(transcript, s, r, comm)?;
            }
        }
        validate_batch_claims("batch verify", comms.len(), points, evals)?;
        // D2:语句(点+声称)先于组合挑战 t 吸收(与 batch_open 同序)。
        absorb_batch_statement(transcript, points, evals);

        let ell = evals.len().next_power_of_two().ilog2() as usize;

        let t = transcript.squeeze_challenges(ell);

        let eq_xt = MultilinearPolynomial::eq_xy(&t);
        let tilde_gs_sum =
            inner_product(evals.iter().map(Evaluation::value), &eq_xt[..evals.len()]);

        let (g_prime_eval, verify_point) =
            SumCheck::verify(&(), vp.num_vars, 2, tilde_gs_sum, transcript)?;

        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&verify_point, point))
            .collect_vec();

        //start of verify
        let n = (1 << (vp.num_vars + vp.log_rate));
        //read first $(num_var - 1) commitments
        let mut roots: Vec<Output<H>> = Vec::with_capacity(vp.num_rounds + 1);
        let mut round_salts: Vec<Output<H>> = Vec::with_capacity(vp.num_rounds + 1);
        let mut fold_challenges: Vec<F> = Vec::with_capacity(vp.num_rounds);
        let mut sum_check_oracles = Vec::new();

        for i in 0..vp.num_rounds {

            // D18 Phase 1：轮根读入=(salt, root) 对（与 commit_phase 写序一致）。
            round_salts.push(transcript.read_commitment().unwrap());
            roots.push(transcript.read_commitment().unwrap());
            // D1:轮根 (盐,根) 进 FS(与 commit_phase 写侧同点吸收),先于本轮挑战。
            absorb_salt_root::<F, H>(transcript, round_salts.last().unwrap(), roots.last().unwrap());
            // D18 Phase 3：标准读序（读消息→挤挑战）；Phase 2 末轮重排+拒绝采样退役。
            sum_check_oracles.push(transcript.read_field_elements(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
        }

        sum_check_oracles.push(transcript.read_field_elements(3).unwrap());
        let mut bh_evals = Vec::new();
        let mut eq = Vec::new();
        if vp.num_rounds < vp.num_vars {
            bh_evals = transcript
                .read_field_elements(1 << (vp.num_vars - vp.num_rounds))
                .unwrap();
            eq = transcript
                .read_field_elements(1 << (vp.num_vars - vp.num_rounds))
                .unwrap();
        }


        let mut query_challenges = transcript.squeeze_challenges(vp.num_verifier_queries);

        // A5 路线 b（读侧）：与 batch_open 写侧同构的（查询位置, poly）去重——
        // 每查询读 #不同 poly 条（首现序），再按 slot 映射展开到逐 eval 数组；
        // 后续全部校验（lc0/lc1 线性组合 + 逐 eval Merkle 认证）在展开数组上
        // 逐条执行，与现行语义完全一致。默认关 = 现行读法。
        let dedup_on = std::env::var("PCS_BATCH_DEDUP")
            .map(|v| v == "1")
            .unwrap_or(false);
        let (slot_of_eval, n_slots): (Vec<usize>, usize) = {
            let mut seen: HashMap<usize, usize> = HashMap::new();
            let slot_of_eval: Vec<usize> = evals
                .iter()
                .map(|ev| {
                    let n = seen.len();
                    *seen.entry(ev.poly()).or_insert(n)
                })
                .collect();
            let n_slots = *slot_of_eval.last().unwrap_or(&0) + 1;
            (slot_of_eval, n_slots)
        };

        // A3 尺寸封闭式(流式档定位器;与 probe 侧 A3Sizes 独立实现互证):域元素 wire 宽=Repr 全长
        // (SM2 域 40B),哈希块=Output<H>(32B);段序 S1 头部/S2 批量 sumcheck/S3 折叠轮/S4 末轮
        // oracle/S5 bh+eq(nr<nv)/S6 ind_queries/S7 batch_paths/…(全表见 W1_CHECKPOINT v9)。
        let fe_w = <F as PrimeField>::Repr::default().as_ref().len();
        let h_w = Output::<H>::default().len();
        // D27 Phase 3 封闭式 v2:交织档头部=每批次 (盐,根) 一对(2·g·H)、S6′=每查询全部 N_all 对、
        // S7′=每查询每批次一条路径(g·path_w);默认档不变(e_cnt 按 dedup,N=g=comms.len())。
        let g_cnt = if inter { group_starts(&comms).len() } else { comms.len() };
        // 🔴 交织档每查询对数=批内列数之和(starts 的 k 和)——**不是 comms.len()**:
        // solo 列(如 mask 经 commit_and_write)不在任何批次,其开口不占本段
        // (首版误用 comms.len() ⟹ 每查询多读 1 对 ⟹ 80B/查询漂移,末查询踩进路径区)。
        let pair_cnt = if inter {
            group_starts(&comms).iter().map(|&(_, k)| k).sum()
        } else {
            comms.len()
        };
        let e_cnt = if inter {
            pair_cnt
        } else if dedup_on {
            n_slots
        } else {
            evals.len()
        };
        let path_w = 2 * (vp.num_vars + vp.log_rate) * h_w;
        let off_s6 = 2 * g_cnt * h_w
            + vp.num_vars * 3 * fe_w
            + vp.num_rounds * (2 * h_w + 3 * fe_w)
            + 3 * fe_w
            + if vp.num_rounds < vp.num_vars { 2 * (1 << (vp.num_vars - vp.num_rounds)) * fe_w } else { 0 };
        let s6_len = vp.num_verifier_queries * e_cnt * 2 * fe_w;
        let off_s7 = off_s6 + s6_len;
        let per_q7_cnt = if inter { g_cnt } else { e_cnt };
        let s7_len = vp.num_verifier_queries * per_q7_cnt * path_w;

        let mut ind_queries: Vec<Vec<Vec<F>>> = Vec::with_capacity(vp.num_verifier_queries);
        let mut batch_paths: Vec<Vec<Vec<Vec<Output<H>>>>> = Vec::with_capacity(vp.num_verifier_queries);
        // D27 交织档:ind_by_qc=按 (查询,comm) 的叶值对;group_paths=按 (查询,批次) 的认证路径。
        let mut ind_by_qc: Vec<Vec<Vec<F>>> = Vec::with_capacity(vp.num_verifier_queries);
        let mut group_paths: Vec<Vec<Vec<Vec<Output<H>>>>> = Vec::with_capacity(vp.num_verifier_queries);
        let mut count = 0;
        if inter && stream_on {
            // D27 Phase 3:交织档流式第一遍——S6′/S7′ 只读不留(FS 已吸收),封闭式 v2 三处
            // 偏移交叉核对(漂移即 panic,与默认档同纪律)。
            let pos = crate::util::transcript::a3_stream::pos;
            assert_eq!(pos(), pcs_start + off_s6, "A3 流式 v2:S6′ 起点封闭式偏移与转录实际位置不一致");
            for _ in 0..vp.num_verifier_queries {
                for _ in 0..e_cnt {
                    transcript.read_field_elements(2).unwrap();
                }
            }
            assert_eq!(pos(), pcs_start + off_s7, "A3 流式 v2:S7′ 起点封闭式偏移与转录实际位置不一致");
            for _ in 0..vp.num_verifier_queries {
                for _ in 0..per_q7_cnt {
                    transcript.read_commitments(2 * (vp.num_vars + vp.log_rate)).unwrap();
                }
            }
            assert_eq!(
                pos(),
                pcs_start + off_s7 + s7_len,
                "A3 流式 v2:S7′ 终点封闭式偏移与转录实际位置不一致"
            );
        } else if inter {
            // D27:S6′=每查询按 (批次,列) 序读 N_all 对叶值(全部列,交织叶哈希需整向量);
            // S7′=每查询每批次一条路径(2(nv+lr) 哈希,含 (root,root) 顶端块)。
            let starts = group_starts(&comms);
            // 两段式(与写侧一致):先全部查询的 S6′,再全部查询的 S7′。
            for _ in 0..vp.num_verifier_queries {
                let mut per_q: Vec<Vec<F>> = vec![Vec::new(); comms.len()];
                for &(s0, k) in &starts {
                    for j in 0..k {
                        per_q[s0 + j] = transcript.read_field_elements(2).unwrap();
                    }
                }
                ind_by_qc.push(per_q);
            }
            for _ in 0..vp.num_verifier_queries {
                let mut per_q: Vec<Vec<Vec<Output<H>>>> = Vec::with_capacity(starts.len());
                for &(s0, _) in &starts {
                    let merkle_path = transcript
                        .read_commitments(2 * (vp.num_vars + vp.log_rate))
                        .unwrap();
                    per_q.push(merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec());
                }
                group_paths.push(per_q);
            }
        } else if stream_on {
            // 第一遍:S6/S7 只推进(域元素经 transcript 读入即完成 FS 吸收)、不保留;
            // 三处偏移交叉核对 = 封闭式 vs 转录实际位置(读序表漂移或未用 StreamTranscript 即 panic)。
            let pos = crate::util::transcript::a3_stream::pos;
            assert_eq!(pos(), pcs_start + off_s6, "A3 流式:S6 起点封闭式偏移与转录实际位置不一致");
            for _ in 0..vp.num_verifier_queries {
                for _ in 0..e_cnt {
                    transcript.read_field_elements(2).unwrap();
                }
            }
            assert_eq!(pos(), pcs_start + off_s7, "A3 流式:S7 起点封闭式偏移与转录实际位置不一致");
            for _ in 0..vp.num_verifier_queries {
                for _ in 0..e_cnt {
                    transcript.read_commitments(2 * (vp.num_vars + vp.log_rate)).unwrap();
                }
            }
            assert_eq!(pos(), pcs_start + off_s7 + s7_len, "A3 流式:S7 终点封闭式偏移与转录实际位置不一致");
        } else {
        for i in 0..vp.num_verifier_queries {
            let mut comms_queries = Vec::with_capacity(evals.len());
            if dedup_on {
                let mut slots_q = Vec::with_capacity(n_slots);
                for _ in 0..n_slots {
                    slots_q.push(transcript.read_field_elements(2).unwrap());
                }
                for &s in &slot_of_eval {
                    comms_queries.push(slots_q[s].clone());
                }
            } else {
                for j in 0..evals.len() {
                    let queries = transcript.read_field_elements(2).unwrap();

                    comms_queries.push(queries);
                }
            }

            ind_queries.push(comms_queries);
        }

        //read merkle paths
        for i in 0..vp.num_verifier_queries {
            let mut comms_merkle_paths = Vec::with_capacity(evals.len());
            if dedup_on {
                let mut slots_p = Vec::with_capacity(n_slots);
                for _ in 0..n_slots {
                    let merkle_path = transcript
                        .read_commitments(2 * (vp.num_vars + vp.log_rate))
                        .unwrap();
                    let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();
                    slots_p.push(chunked_path);
                }
                for &s in &slot_of_eval {
                    comms_merkle_paths.push(slots_p[s].clone());
                }
            } else {
                for j in 0..evals.len() {
                    let merkle_path = transcript
                        .read_commitments(2 * (vp.num_vars + vp.log_rate))
                        .unwrap();
                    let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                    comms_merkle_paths.push(chunked_path);
                }
            }

            batch_paths.push(comms_merkle_paths);
        }
        }

        let mut count = 0;

        //read eval
        let eval = transcript.read_field_element().unwrap();
        // 🔴 2026-09-16 声音性修复(伪造求值归因核验,W1_CHECKPOINT v9 §13 缺口 A):外层经典 sumcheck 把
        // Σ eq_xt·y_i 归约为 g′(r)=g_prime_eval(锚在**声称**);内层 BaseFold Eval 证明 g′(r)=eval(锚在
        // **承诺链**:eval==h₁ⁱⁿ(0)+h₁ⁱⁿ(1) + 折叠链 + lc 校验)。二者缺失比对 ⟹ 声称与承诺码字脱钩
        // (E2 伪证明×伪声称被接受;外层证明者 evals[0]=sum−evals[1] 自适应声称和)。本等式=论文
        // Protocol 4 的 `h_d(0)+h_d(1)=y` 在批量组合处的粘合;诚实零影响、转录格式零变化。
        // 继承自上游参考实现(fork 导入首提交 c29f086 已含)。
        if eval != g_prime_eval {
            return Err(Error::InvalidPcsOpen(
                "batch_verify: 内层声称 eval != 外层 sumcheck 终值 g_prime_eval(求值声称未绑定承诺)"
                    .to_string(),
            ));
        }

        //read final oracle
        let mut final_oracle = transcript
            .read_field_elements(1 << (vp.num_vars - vp.num_rounds + vp.log_rate))
            .unwrap();

        //read query paths
        let num_queries = vp.num_verifier_queries * 2 * (vp.num_rounds + 1);

        let all_qs = transcript.read_field_elements(num_queries).unwrap();

        let i_qs = all_qs.chunks((vp.num_rounds + 1) * 2).collect_vec();

        assert_eq!(i_qs.len(), vp.num_verifier_queries);

        let mut queries = i_qs.iter().map(|q| q.chunks(2).collect_vec()).collect_vec();

        assert_eq!(queries[0][0].len(), 2);

        let scalars = evals
            .iter()
            .zip(eq_xt.evals())
            .map(|(eval, eq_xt_i)| eq_xy_evals[eval.point()] * eq_xt_i)
            .collect_vec();

        // 流式档:lc0/lc1 核对移入第二遍(逐查询回放时与 Merkle 认证同做,检查集合不变)。
        // 交织档:ind_by_qc 按 (查询,comm) 索引;交织×流式时物化区为空,lc 检查在回放分支执行。
        if inter && !stream_on {
        for (vi, query) in queries.iter().enumerate() {
            let mut lc0 = F::ZERO;
            let mut lc1 = F::ZERO;
            for j in 0..scalars.len() {
                let v = &ind_by_qc[vi][evals[j].poly()];
                lc0 += scalars[j] * v[0];
                lc1 += scalars[j] * v[1];
            }
            assert_eq!(query[0][0], lc0);
            assert_eq!(query[0][1], lc1);
        }
        } else if !stream_on {
        for (i, query) in queries.iter().enumerate() {
            let mut lc0 = F::ZERO;
            let mut lc1 = F::ZERO;
            for j in 0..scalars.len() {
                lc0 += scalars[j] * ind_queries[i][j][0];
                lc1 += scalars[j] * ind_queries[i][j][1];
            }
            assert_eq!(query[0][0], lc0);
            assert_eq!(query[0][1], lc1);
        }
        }

        //start regular verify on the proof in transcript

        let mut query_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> =
            Vec::with_capacity(vp.num_verifier_queries);
        for i in 0..vp.num_verifier_queries {
            let mut merkle_paths: Vec<Vec<Vec<Output<H>>>> = Vec::with_capacity(vp.num_rounds + 1);
            for round in 0..(vp.num_rounds + 1) {
                let merkle_path: Vec<Output<H>> = transcript
                    .read_commitments(2 * (vp.num_vars - round + vp.log_rate - 1)) //-1 because we already read roots
                    .unwrap();
                let chunked_path: Vec<Vec<Output<H>>> =
                    merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                merkle_paths.push(chunked_path);
            }
            query_merkle_paths.push(merkle_paths);
        }


        println!("verifier query phase");
        let queries_usize = verifier_query_phase::<F, H>(
            &query_challenges,
            &query_merkle_paths,
            &sum_check_oracles,
            &fold_challenges,
            &queries,
            vp.num_rounds,
            vp.num_vars,
            vp.log_rate,
            &roots,
            &round_salts,
            vp.rng.clone(),
            &eval,
            &vp.code_type.clone(),
            &final_oracle,
        );

        if inter && stream_on {
            // D27 Phase 3:交织档流式第二遍——逐查询在回放源上解析 S6′(全部列叶值对)与
            // S7′(每批次一条路径),即时 lc0/lc1 核对 + 向量叶根链认证 → 释放 → 下一查询
            // (工作集=单查询的 N_all 对叶值 + g 条路径;认证语义与非流式交织档逐条一致)。
            let src = crate::util::transcript::a3_stream::proof();
            let buf: &[u8] = &src[..];
            let base6 = pcs_start + off_s6;
            let base7 = pcs_start + off_s7;
            let per_q6 = pair_cnt * 2 * fe_w;
            let per_q7 = g_cnt * path_w;
            assert!(
                buf.len() >= base7 + vp.num_verifier_queries * per_q7,
                "A3 流式 v2:回放源短于封闭式 S7′ 终点"
            );
            let parse_fe = |w: &[u8]| -> F {
                let mut repr = <F as PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(&w[..fe_w]);
                repr.as_mut().reverse();
                F::from_repr_vartime(repr)
                    .expect("A3 流式 v2 第二遍:域元素解析被拒(第一遍已通过;回放源被改?)")
            };
            let parse_h = |w: &[u8]| -> Output<H> {
                let mut o = Output::<H>::default();
                o.as_mut().copy_from_slice(&w[..h_w]);
                o
            };
            let starts = group_starts(&comms);
            for vq in 0..vp.num_verifier_queries {
                let q6 = &buf[base6 + vq * per_q6..base6 + (vq + 1) * per_q6];
                // 按批次序解析 leaves,槽位=comms 索引(s0+j);solo 列槽位留空(不被 evals 引用)。
                let mut leaves: Vec<(F, F)> = vec![(F::ZERO, F::ZERO); comms.len()];
                let mut wr = 0usize;
                for &(s0, k) in &starts {
                    for j in 0..k {
                        leaves[s0 + j] = (
                            parse_fe(&q6[wr * 2 * fe_w..]),
                            parse_fe(&q6[wr * 2 * fe_w + fe_w..]),
                        );
                        wr += 1;
                    }
                }
                assert_eq!(wr, pair_cnt, "A3 流式 v2:S6′ 对数 ≠ starts 之 k 和");
                let mut lc0 = F::ZERO;
                let mut lc1 = F::ZERO;
                for j in 0..scalars.len() {
                    lc0 += scalars[j] * leaves[evals[j].poly()].0;
                    lc1 += scalars[j] * leaves[evals[j].poly()].1;
                }
                assert_eq!(queries[vq][0][0], lc0);
                assert_eq!(queries[vq][0][1], lc1);

                let q7 = &buf[base7 + vq * per_q7..base7 + (vq + 1) * per_q7];
                for (gi, &(s0, k)) in starts.iter().enumerate() {
                    let pb = &q7[gi * path_w..(gi + 1) * path_w];
                    let mut path: Vec<Vec<Output<H>>> = pb
                        .chunks(2 * h_w)
                        .map(|c| vec![parse_h(&c[..h_w]), parse_h(&c[h_w..])])
                        .collect();
                    let root = comms[s0].committed_root();
                    assert_eq!(*root, path.pop().expect("路径空").pop().expect("顶端块空"));
                    let mut leaf_values: Vec<F> = Vec::with_capacity(2 * k);
                    for j in 0..k {
                        leaf_values.push(leaves[s0 + j].0);
                        leaf_values.push(leaves[s0 + j].1);
                    }
                    authenticate_merkle_path_root_vec::<H, F>(
                        &path,
                        &leaf_values,
                        queries_usize[vq],
                        root,
                        &comms[s0].salt,
                    );
                    count += 1;
                }
            }
        } else if inter {
            // D27 交织认证:每查询每批次——顶端 (root,root) 声明块比对 + 向量叶根链认证
            // (authenticate_merkle_path_root_vec 含末端 hash(children)==root,P0 修复语义保持)。
            let starts = group_starts(&comms);
            for (vq, per_q) in group_paths.iter().enumerate() {
                for (gi, &(s0, k)) in starts.iter().enumerate() {
                    let path = &mut per_q[gi].clone();
                    let root = comms[s0].committed_root();
                    assert_eq!(*root, path.pop().expect("路径空").pop().expect("顶端块空"));
                    let mut leaf_values: Vec<F> = Vec::with_capacity(2 * k);
                    for j in 0..k {
                        let v = &ind_by_qc[vq][s0 + j];
                        leaf_values.push(v[0]);
                        leaf_values.push(v[1]);
                    }
                    authenticate_merkle_path_root_vec::<H, F>(
                        path,
                        &leaf_values,
                        queries_usize[vq],
                        root,
                        &comms[s0].salt,
                    );
                    count += 1;
                }
            }
        } else if stream_on {
            // 第二遍(纯算术区间定位 + 手动解析,不喂 FS 状态——第一遍已吸收):逐查询在回放源上
            // 解析 S6(叶值)与 S7(路径)区间,即时 lc0/lc1 核对 + 带根链 Merkle 认证 → 释放 → 下一查询。
            // 工作集 = 单查询(2·E 域元素 + 一条路径),替代默认档 Q·E 条路径的整体常驻。
            let src = crate::util::transcript::a3_stream::proof();
            let buf: &[u8] = &src[..];
            let base6 = pcs_start + off_s6;
            let base7 = pcs_start + off_s7;
            let per_q6 = e_cnt * 2 * fe_w;
            let per_q7 = e_cnt * path_w;
            assert!(
                buf.len() >= base7 + vp.num_verifier_queries * per_q7,
                "A3 流式:回放源短于封闭式 S7 终点"
            );
            let parse_fe = |w: &[u8]| -> F {
                let mut repr = <F as PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(&w[..fe_w]);
                repr.as_mut().reverse();
                F::from_repr_vartime(repr)
                    .expect("A3 流式第二遍:域元素解析被拒(第一遍已通过;回放源被改?)")
            };
            let parse_h = |w: &[u8]| -> Output<H> {
                let mut o = Output::<H>::default();
                o.as_mut().copy_from_slice(&w[..h_w]);
                o
            };
            for vq in 0..vp.num_verifier_queries {
                let q6 = &buf[base6 + vq * per_q6..base6 + (vq + 1) * per_q6];
                let leaves: Vec<(F, F)> = (0..e_cnt)
                    .map(|s| (parse_fe(&q6[s * 2 * fe_w..]), parse_fe(&q6[s * 2 * fe_w + fe_w..])))
                    .collect();
                let mut lc0 = F::ZERO;
                let mut lc1 = F::ZERO;
                for j in 0..scalars.len() {
                    let s = if dedup_on { slot_of_eval[j] } else { j };
                    lc0 += scalars[j] * leaves[s].0;
                    lc1 += scalars[j] * leaves[s].1;
                }
                assert_eq!(queries[vq][0][0], lc0);
                assert_eq!(queries[vq][0][1], lc1);

                let q7 = &buf[base7 + vq * per_q7..base7 + (vq + 1) * per_q7];
                for cq in 0..evals.len() {
                    let s = if dedup_on { slot_of_eval[cq] } else { cq };
                    let pb = &q7[s * path_w..(s + 1) * path_w];
                    let mut path: Vec<Vec<Output<H>>> = pb
                        .chunks(2 * h_w)
                        .map(|c| vec![parse_h(&c[..h_w]), parse_h(&c[h_w..])])
                        .collect();
                    let tree = &comms[evals[cq].poly].codeword_tree;
                    let root = &tree[tree.len() - 1][0];
                    assert_eq!(*root, path.pop().unwrap().pop().unwrap());
                    authenticate_merkle_path_root::<H, F>(
                        &path,
                        leaves[s],
                        queries_usize[vq],
                        root,
                        &comms[evals[cq].poly].salt,
                    );
                    count += 1;
                }
            }
        } else {
        for vq in 0..vp.num_verifier_queries {
            for cq in 0..ind_queries[vq].len() {
                let tree = &comms[evals[cq].poly].codeword_tree;
                let root = &tree[tree.len() - 1][0];
                // 顶端 (root,root) 声明块须等于已承诺根（写侧 get_merkle_path(root=true)）。
                assert_eq!(*root, batch_paths[vq][cq].pop().unwrap().pop().unwrap());

                // D18 Phase 1：个体层路径认证用该承诺自己的盐（盐=树哈希域分隔符）。
                // 🔴 2026-09-16 声音性修复（A3 尺寸对账连带发现；探针
                // sm2_a3_stream::tests::a3_probe_indiv_path_root_link 红→绿）：原调用
                // authenticate_merkle_path（无根链版）只校验链内相邻层一致，从不把根之两子
                // 节点对哈希后与已承诺根比对——伪造叶值+自洽伪链+真根声明块即可被接受，
                // 个体列承诺在查询点不绑定。改用 _root 版补上末端 hash(children)==root
                // 校验：诚实证明零影响、转录格式零变化、每开口多一次哈希。
                authenticate_merkle_path_root::<H, F>(
                    &batch_paths[vq][cq],
                    (ind_queries[vq][cq][0], ind_queries[vq][cq][1]),
                    queries_usize[vq],
                    root,
                    &comms[evals[cq].poly].salt,
                );

                count += 1;
            }
        }
        }
        let mut next_oracle = Type1Polynomial { poly: final_oracle };
        let mut bh_evals = Type1Polynomial { poly: bh_evals };
        let mut eq = Type1Polynomial { poly: eq };
        // 缺口 C 修复(与 batch_open 对称):内层底部绑定 eq_r_ 以内层约定配对 (β_i, rev(r)_i)。
        let inner_point: Vec<F> = verify_point.iter().rev().cloned().collect();
        if (!vp.rs_basecode) {
            virtual_open(
                vp.num_vars,
                vp.num_rounds,
                &mut eq,
                &mut bh_evals,
                &mut next_oracle,
                &inner_point,
                &mut fold_challenges,
                &vp.table_w_weights,
                &mut sum_check_oracles,
                vp.log_rate,
                vp.code_type.clone()
            );
        } else {
            one_level_reverse_interp_hc(&mut bh_evals);
            reverse_index_bits_in_place(&mut bh_evals.poly); //convert to type2
            let (mut new_coeffs, _) =
                interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                    poly: bh_evals.poly,
                });

            let rs = encode_rs_basecode(
                &new_coeffs,
                1 << vp.log_rate,
                1 << (vp.num_vars - vp.num_rounds),
            );
            reverse_index_bits_in_place(&mut next_oracle.poly); //convert to type2
            assert_eq!(
                rs,
                Type2Polynomial {
                    poly: next_oracle.poly
                }
            );
        }
        Ok(())
    }
}

#[test]
fn time_rs_code() {
    use blake2::Blake2s256;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let mut poly = MultilinearPolynomial::rand(20, OsRng);
    let mut t_rng = ChaCha8Rng::from_entropy();

    let rate = 2;
    let now = Instant::now();
    let evals = encode_rs_basecode::<Mersenne61>(
        &Type2Polynomial {
            poly: poly.evals().to_vec(),
        },
        2,
        64,
    );
}
fn encode_rs_basecode<F: PrimeField>(
    poly: &Type2Polynomial<F>,
    rate: usize,
    message_size: usize,
) -> Type2Polynomial<F> {
    let domain: Vec<F> = steps(F::ONE).take(message_size * rate).collect();
    let res = poly
        .poly
        .par_chunks_exact(message_size)
        .map(|chunk| {
            let mut target = vec![F::ZERO; message_size * rate];
            target
                .iter_mut()
                .enumerate()
                .for_each(|(i, target)| *target = horner(&chunk[..], &domain[i]));
            target
        })
        .collect::<Vec<Vec<F>>>();

    let result = res.iter().flatten().map(|x| *x).collect::<Vec<F>>();
    Type2Polynomial { poly: result }
}

fn encode_repetition_basecode<F: PrimeField>(
    poly: &Type2Polynomial<F>,
    rate: usize,
) -> Vec<Type2Polynomial<F>> {
    let mut base_codewords = Vec::new();
    for c in &poly.poly {
        let mut rep_code = Vec::new();
        for i in 0..rate {
            rep_code.push(*c);
        }
        base_codewords.push(Type2Polynomial { poly: rep_code });
    }
    return base_codewords;
}
//this function assumes all codewords in base_codeword has equivalent length
pub fn evaluate_over_foldable_domain_generic_basecode<F: PrimeField>(
    base_message_length: usize,
    num_coeffs: usize,
    log_rate: usize,
    mut base_codewords: Type2Polynomial<F>,
    table: &Vec<Vec<F>>,
) -> Type1Polynomial<F> {
    let k = num_coeffs;
    let logk = log2_strict(k);
    let cl = 1 << (logk + log_rate);

    let rate = 1 << log_rate;
    let base_log_k = log2_strict(base_message_length);

    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let mut chunk_size = 1 << base_log_k; //block length of the base code
    for i in base_log_k..logk {
        let level = &table[i + log_rate];
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut base_codewords.poly)
            .par_chunks_mut(chunk_size)
            .for_each(|chunk| {
                let half_chunk = chunk_size >> 1;
                for j in half_chunk..chunk_size {
                    let rhs = chunk[j] * level[j - half_chunk];
                    chunk[j] = chunk[j - half_chunk] - rhs;
                    chunk[j - half_chunk] = chunk[j - half_chunk] + rhs;
                }
            });
    }
    reverse_index_bits_in_place(&mut base_codewords.poly);
    Type1Polynomial {
        poly: base_codewords.poly,
    }
}

pub fn evaluate_over_foldable_domain<F: PrimeField>(
    log_rate: usize,
    mut coeffs: Type2Polynomial<F>,
    table: &Vec<Vec<F>>,
    code_type: String
) -> Type1Polynomial<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let k = coeffs.poly.len();
    let logk = log2_strict(k);
    let cl = 1 << (logk + log_rate);
    let rate = 1 << log_rate;
    let subspace = BinarySubspace::<F>::with_dim(log_rate+logk + 1).ok().unwrap();
    let twiddle_accesses = OnTheFlyTwiddleAccess::generate(&subspace).ok().unwrap();
    let mut coeffs_with_rep = vec![F::ZERO; cl];

    //base code - in this case is the repetition code

    for i in 0..k {
        for j in 0..rate {
            coeffs_with_rep[i * rate + j] = coeffs.poly[i];
        }
    }

    let mut chunk_size = rate; //block length of the base code
    for i in 0..logk {
        let level = &table[i + log_rate];
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut coeffs_with_rep)
            .par_chunks_mut(chunk_size)
            .for_each(|chunk| {
                let half_chunk = chunk_size >> 1;
                for j in half_chunk..chunk_size {
                    let rhs = chunk[j] * level[j - half_chunk];
                    let mut lhs = F::ZERO;
                    if code_type == "binary_rs".to_string(){
                        lhs = chunk[j]*twiddle_accesses[logk - i - 1].get_odd_from_even(level[j-half_chunk]);
                    }
                    else{
                        lhs = -rhs;
                    }
                    chunk[j] = chunk[j - half_chunk] + lhs;
                    chunk[j - half_chunk] = chunk[j - half_chunk] + rhs;
                }
            });
    }
    reverse_index_bits_in_place(&mut coeffs_with_rep);
    Type1Polynomial {
        poly: coeffs_with_rep,
    }
}

pub fn evaluate_over_foldable_domain_2<F: PrimeField>(
    log_chunk_size: usize,
    log_rate: usize,
    mut coeffs: Type2Polynomial<F>,
    table: &Vec<Vec<F>>,
) -> Type1Polynomial<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let mut chunk_size = 1 << log_chunk_size;
    let levels = log2_strict(coeffs.poly.len()) - log_chunk_size;

    for i in 0..levels {
        let level = &table[i + log_chunk_size];
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut coeffs.poly)
            .par_chunks_mut(chunk_size)
            .for_each(|chunk| {
                let half_chunk = chunk_size >> 1;
                for j in half_chunk..chunk_size {
                    let rhs = chunk[j] * level[j - half_chunk];
                    chunk[j] = chunk[j - half_chunk] - rhs;
                    chunk[j - half_chunk] = chunk[j - half_chunk] + rhs;
                }
            });
    }
    reverse_index_bits_in_place(&mut coeffs.poly);
    Type1Polynomial { poly: coeffs.poly }
}

pub fn interpolate_over_boolean_hypercube_with_copy<F: PrimeField>(
    evals: &Type2Polynomial<F>,
) -> (Type2Polynomial<F>, Type1Polynomial<F>) {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.poly.len());
    let mut coeffs = vec![F::ZERO; evals.poly.len()];
    let mut new_evals = vec![F::ZERO; evals.poly.len()];

    let mut j = 0;
    while (j < coeffs.len()) {
        new_evals[j] = evals.poly[j];
        new_evals[j + 1] = evals.poly[j + 1];

        coeffs[j + 1] = evals.poly[j + 1] - evals.poly[j];
        coeffs[j] = evals.poly[j];
        j += 2
    }

    for i in 2..n + 1 {
        let chunk_size = 1 << i;
        coeffs.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }
    reverse_index_bits_in_place(&mut new_evals);
    (
        Type2Polynomial { poly: coeffs },
        Type1Polynomial { poly: new_evals },
    )
}

//helper function
fn rand_vec<F: PrimeField>(size: usize, mut rng: &mut ChaCha8Rng) -> Vec<F> {
    (0..size).map(|_| F::random(&mut rng)).collect()
}
fn rand_chacha<F: PrimeField>(mut rng: &mut ChaCha8Rng) -> F {
    let bytes = (F::NUM_BITS as usize).next_power_of_two() / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    rng.fill_bytes(&mut dest);
    from_raw_bytes::<F>(&dest)
}

pub fn log2_strict(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert!(n.wrapping_shr(res) == 1, "Not a power of two: {n}");
    // Tell the optimizer about the semantics of `log2_strict`. i.e. it can replace `n` with
    // `1 << res` and vice versa.

    res as usize
}

/// D18 Phase 1（盐化 Merkle，Layer 1）盐生成器：每棵树独立 fresh 盐（长度=Hash 输出
/// 长度，SM3/SHA-256=32B），来源=OS 熵（OsRng）。T1.3b 定案 [实测 2026-09-02]：
/// 未盐化树根=witness 确定性函数 ⟹ 根序列重合度=跨会话用户指纹（恒定列
/// standalone 52.9%/merged 73.9%/T1 99.3%）；盐化后根=H(salt‖数据)，salt 每树新随机
/// ⟹ 根分布与数据独立，指纹通道消灭。binding 不变（SM3 抗碰撞，盐=域分隔符）。
// =====================================================================
// 🔴 D1/D2 Fiat–Shamir 绑定修复(2026-09-16,W1_CHECKPOINT v9 §13.1;继承自上游 c29f086)
// =====================================================================

/// D1:承诺身份(盐,根)进 FS 状态。`Output<H>` 的 write/read_commitment 只搬字节、不调
/// common_commitment(transcript.rs:291-308)⟹ 所有先于 squeeze 的承诺(HyperPlonk 见证/lookup/置换
/// 承诺、batch 头部、折叠轮根)对其后挑战无约束 ⟹ 挑战对证明者可预知。写读两侧在同一站点对称调用;
/// S7/S11 Merkle 路径位于全部挑战之后,不吸收(避免对 ~92% 证明字节做无谓哈希)。
fn absorb_salt_root<F: PrimeField, H: Hash>(
    transcript: &mut impl Transcript<Output<H>, F>,
    salt: &Output<H>,
    root: &Output<H>,
) {
    transcript.common_commitment(salt).expect("FS 吸收盐失败");
    transcript.common_commitment(root).expect("FS 吸收根失败");
}

const BATCH_STMT_TAG: u64 = 0x4246_2d42_4154_4348; // "BF-BATCH"
const SINGLE_STMT_TAG: u64 = 0x4246_2d53_494e_474c; // "BF-SINGL"

/// D2:批量语句规范吸收(先于组合挑战 t;写读两侧同序):标签/点数/声称数/全部点坐标/每条
/// (poly,point,value)。阻断"双假声称按已知 batch 权重相消"(外部报告 §5.2 攻击 B,probe 负例
/// `pcs_binding_negatives_ext` ①)。只更新 FS 状态,不增证明字节。
fn absorb_batch_statement<F: PrimeField>(
    transcript: &mut impl FieldTranscript<F>,
    points: &[Vec<F>],
    evals: &[Evaluation<F>],
) {
    transcript.common_field_element(&F::from(BATCH_STMT_TAG)).unwrap();
    transcript.common_field_element(&F::from(points.len() as u64)).unwrap();
    transcript.common_field_element(&F::from(evals.len() as u64)).unwrap();
    for p in points {
        for c in p {
            transcript.common_field_element(c).unwrap();
        }
    }
    for e in evals {
        transcript.common_field_element(&F::from(e.poly() as u64)).unwrap();
        transcript.common_field_element(&F::from(e.point() as u64)).unwrap();
        transcript.common_field_element(e.value()).unwrap();
    }
}

/// D2 单点语句吸收:标签/承诺身份/点/声称值(open/verify 同序)。
fn absorb_single_statement<F: PrimeField, H: Hash>(
    transcript: &mut impl Transcript<Output<H>, F>,
    salt: &Output<H>,
    root: &Output<H>,
    point: &[F],
    eval: &F,
) {
    transcript.common_field_element(&F::from(SINGLE_STMT_TAG)).unwrap();
    absorb_salt_root::<F, H>(transcript, salt, root);
    for c in point {
        transcript.common_field_element(c).unwrap();
    }
    transcript.common_field_element(eval).unwrap();
}

/// 批量声称显式校验(Err 而非 panic;外部报告 §4.2-5):非空/索引在界/无重复 (poly,point)。
fn validate_batch_claims<F: PrimeField>(
    function: &str,
    num_polys: usize,
    points: &[Vec<F>],
    evals: &[Evaluation<F>],
) -> Result<(), Error> {
    if evals.is_empty() {
        return Err(Error::InvalidPcsOpen(format!("{function}: evals 为空")));
    }
    let mut seen = std::collections::HashSet::with_capacity(evals.len());
    for e in evals {
        if e.poly() >= num_polys {
            return Err(Error::InvalidPcsOpen(format!(
                "{function}: eval.poly()={} 越界(num_polys={num_polys})",
                e.poly()
            )));
        }
        if e.point() >= points.len() {
            return Err(Error::InvalidPcsOpen(format!(
                "{function}: eval.point()={} 越界(points={})",
                e.point(),
                points.len()
            )));
        }
        if !seen.insert((e.poly(), e.point())) {
            return Err(Error::InvalidPcsOpen(format!(
                "{function}: 重复声称 (poly={}, point={})",
                e.poly(),
                e.point()
            )));
        }
    }
    Ok(())
}

fn fresh_salt<H: Hash>() -> Output<H> {
    use rand::RngCore;
    let mut salt = Output::<H>::default();
    rand::rngs::OsRng.fill_bytes(salt.as_mut_slice());
    salt
}

/// 承诺本体（编码 + 盐化 Merkle 树），盐由调用方给定：`commit` 传 fresh 盐（见证），
/// `batch_commit_public` 传种子链盐（预处理/公共参数）。编码语义与 D18 Phase 3 三世界统一保持逐字。
/// D27 叶交织档开关(PCS_INTERLEAVE=1;默认关=逐字节历史行为)。证明侧与验证侧必须同值。
fn interleave_on() -> bool {
    std::env::var("PCS_INTERLEAVE").map(|v| v == "1").unwrap_or(false)
}

/// D27 交织档叶哈希:叶 i = H(salt ‖ c₁[2i] ‖ c₁[2i+1] ‖ … ‖ c_k[2i] ‖ c_k[2i+1])(列优先,
/// k=1 时退化为 solo 叶);上层节点与 merkelize 同式(盐+左右子)。树层数/路径长度与 solo
/// 完全一致 ⟹ get_merkle_path/authenticate_merkle_path_root 通用。
fn merkelize_interleaved<F: PrimeField, H: Hash>(
    cols: &[&Type1Polynomial<F>],
    salt: &Output<H>,
) -> Vec<Vec<Output<H>>> {
    assert!(!cols.is_empty(), "交织批次至少一列");
    let n = cols[0].poly.len();
    assert!(n >= 2 && n % 2 == 0, "交织叶要求偶数个码字位置");
    cols.iter()
        .for_each(|c| assert_eq!(c.poly.len(), n, "交织批次内码字长度不一致"));
    let log_v = log2_strict(n);
    let mut tree: Vec<Vec<Output<H>>> = Vec::with_capacity(log_v);
    let mut level: Vec<Output<H>> = vec![Output::<H>::default(); n >> 1];
    level.par_iter_mut().enumerate().for_each(|(i, h)| {
        let mut hasher = H::new();
        hasher.update(salt.as_slice());
        for c in cols {
            hasher.update_field_element(&c.poly[i + i]);
            hasher.update_field_element(&c.poly[i + i + 1]);
        }
        *h = hasher.finalize_fixed();
    });
    tree.push(level);
    for _ in 1..log_v {
        let prev = tree.last().expect("交织树非空");
        let next: Vec<Output<H>> = prev
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = H::new();
                hasher.update(salt.as_slice());
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect();
        tree.push(next);
    }
    tree
}

/// D27:批次提交(一盐一树;各列共享 Arc 树;每列根写入单层 codeword_tree 以统一根访问)。
/// 盐由调用方给定:见证批次=fresh 盐(每 prove 新鲜,防指纹),公共批次=种子盐链(跨进程可复现)。
fn basefold_commit_group<F: PrimeField, H: Hash>(
    pp: &BasefoldProverParams<F>,
    polys: &[&MultilinearPolynomial<F>],
    salt: Output<H>,
) -> Vec<BasefoldCommitment<F, H>> {
    let encoded: Vec<(Type1Polynomial<F>, Type1Polynomial<F>)> = polys
        .par_iter()
        .map(|poly| basefold_encode_column(pp, poly))
        .collect();
    // R1 内存优化（归因表 #11，2026-09-21）：建树只读码字——借用即足，废除整份
    // 码字克隆（AUTH 13,057 列×262KB=3.42GB 峰值瞬态归零）；树字节与本来源逐位同。
    let codewords: Vec<&Type1Polynomial<F>> = encoded.iter().map(|(c, _)| c).collect();
    let tree = std::sync::Arc::new(merkelize_interleaved::<F, H>(&codewords, &salt));
    let root = tree[tree.len() - 1][0].clone();
    let k = codewords.len();
    encoded
        .into_iter()
        .enumerate()
        .map(|(j, (codeword, _bh_evals))| BasefoldCommitment {
            codeword,
            codeword_tree: vec![vec![root.clone()]],
            // R1 内存优化（归因表 #5 尾项，2026-09-21 消费面审计）：批次承诺的
            // bh_evals 全程零有效消费（sum_with_scalar 的 bh 折叠结果在构造处被
            // 丢弃+batch_open 尾部以 g_prime 覆写；查询相只读 codeword）——
            // 不驻留（AUTH 13,057 列×131KB=1.71GB 归零）。承诺值/树/证明字节不变。
            bh_evals: Type1Polynomial::default(),
            salt: salt.clone(),
            group_size: k,
            col: j,
            group_tree: Some(tree.clone()),
        })
        .collect()
}

/// D27:comms 序中各交织批次的 (起始下标, 列数);solo/占位(group_size=0)跳过。
/// 证明/验证两侧按同一 comms 序调用 ⟹ 批次划分一致。
fn group_starts<'a, F: PrimeField, H: Hash>(
    comms: &[&'a BasefoldCommitment<F, H>],
) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < comms.len() {
        if comms[i].is_grouped() {
            let k = comms[i].group_size;
            debug_assert_eq!(comms[i].col, 0, "批次首列序号必须为 0");
            out.push((i, k));
            i += k;
        } else {
            i += 1;
        }
    }
    out
}

fn basefold_commit_with_salt<F: PrimeField, H: Hash>(
    pp: &BasefoldProverParams<F>,
    poly: &MultilinearPolynomial<F>,
    salt: Output<H>,
) -> BasefoldCommitment<F, H> {
    let (codeword, bh_evals) = basefold_encode_column(pp, poly);
    let tree = merkelize::<F, H>(&codeword, &salt);
    BasefoldCommitment {
        codeword,
        codeword_tree: tree,
        bh_evals,
        salt,
        group_size: 0,
        col: 0,
        group_tree: None,
    }
}

/// 编码段(码字本体,bh_evals 随行)——solo 与交织批次共用;D18 Phase 3 三世界统一语义逐字。
fn basefold_encode_column<F: PrimeField>(
    pp: &BasefoldProverParams<F>,
    poly: &MultilinearPolynomial<F>,
) -> (Type1Polynomial<F>, Type1Polynomial<F>) {
    let p = Type2Polynomial {
        poly: poly.evals().to_vec(),
    };
    // D18 Phase 3（三世界统一，拍板 2026-09-04）：入列多项式=ṽ=v+λ·m（列层掩蔽，
    // 见 backend/hyperplonk），bh_evals=interpolate(ṽ) ⟹ bh 世界=码字世界=开口世界
    // 三方统一；Phase 2 的 κ 系数注入随拟合项一并退役。
    let (coeffs, bh_evals) = interpolate_over_boolean_hypercube_with_copy(&p);

    let commitment = if pp.rs_basecode {
        let basecode = encode_rs_basecode(
            &coeffs,
            1 << pp.log_rate,
            1 << (pp.num_vars - pp.num_rounds),
        );
        assert!(basecode.poly.len() > 0);
        evaluate_over_foldable_domain_2(
            pp.num_vars - pp.num_rounds + pp.log_rate,
            pp.log_rate,
            basecode,
            &pp.table,
        )
    } else {
        evaluate_over_foldable_domain(pp.log_rate, coeffs, &pp.table, pp.code_type.clone())
    };
    (commitment, bh_evals)
}

// D18 Phase 3：regen_mask（κ=B(m) 种子再生）随 κ 注入/拟合项一并退役（拍板 2026-09-04）。

pub fn merkelize<F: PrimeField, H: Hash>(
    values: &Type1Polynomial<F>,
    salt: &Output<H>,
) -> Vec<Vec<Output<H>>> {
    let log_v = log2_strict(values.poly.len());
    let mut tree = Vec::with_capacity(log_v);
    let mut hashes = vec![Output::<H>::default(); (values.poly.len() >> 1)];
    let method1 = Instant::now();
    hashes.par_iter_mut().enumerate().for_each(|(i, mut hash)| {
        let mut hasher = H::new();
        // D18 Phase 1：叶=H(salt‖f[2i]‖f[2i+1])（先盐后数据，与认证链同域）。
        hasher.update(salt.as_slice());
        hasher.update_field_element(&values.poly[i + i]);
        hasher.update_field_element(&values.poly[i + i + 1]);
        *hash = hasher.finalize_fixed();
    });

    tree.push(hashes);

    let now = Instant::now();
    for i in 1..(log_v) {
        let oracle = tree[i - 1]
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = H::new();
                let mut hash = Output::<H>::default();
                // D18 Phase 1：内部节点=H(salt‖l‖r)。
                hasher.update(salt.as_slice());
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect::<Vec<_>>();

        tree.push(oracle);
    }
    tree
}

pub fn build_eq_x_r_vec<F: PrimeField>(r: &[F]) -> Option<Vec<F>> {
    // we build eq(x,r) from its evaluations
    // we want to evaluate eq(x,r) over x \in {0, 1}^num_vars
    // for example, with num_vars = 4, x is a binary vector of 4, then
    //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
    //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
    //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
    //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
    //  ....
    //  1 1 1 1 -> r0       * r1        * r2        * r3
    // we will need 2^num_var evaluations

    let mut eval = Vec::new();
    build_eq_x_r_helper(r, &mut eval);

    Some(eval)
}

/// A helper function to build eq(x, r) recursively.
/// This function takes `r.len()` steps, and for each step it requires a maximum
/// `r.len()-1` multiplications.
fn build_eq_x_r_helper<F: PrimeField>(r: &[F], buf: &mut Vec<F>) {
    assert!(!r.is_empty(), "r length is 0");

    if r.len() == 1 {
        // initializing the buffer with [1-r_0, r_0]
        buf.push(F::ONE - r[0]);
        buf.push(r[0]);
    } else {
        build_eq_x_r_helper(&r[1..], buf);

        // suppose at the previous step we received [b_1, ..., b_k]
        // for the current step we will need
        // if x_0 = 0:   (1-r0) * [b_1, ..., b_k]
        // if x_0 = 1:   r0 * [b_1, ..., b_k]
        // let mut res = vec![];
        // for &b_i in buf.iter() {
        //     let tmp = r[0] * b_i;
        //     res.push(b_i - tmp);
        //     res.push(tmp);
        // }
        // *buf = res;

        let mut res = vec![F::ZERO; buf.len() << 1];
        res.par_iter_mut().enumerate().for_each(|(i, val)| {
            let bi = buf[i >> 1];
            let tmp = r[0] * bi;
            if i & 1 == 0 {
                *val = bi - tmp;
            } else {
                *val = tmp;
            }
        });
        *buf = res;
    }
}

pub fn sum_check_first_round<F: PrimeField>(
    mut eq: &mut Type1Polynomial<F>,
    mut bh_values: &mut Type1Polynomial<F>,
) -> Vec<F> {
    one_level_interp_hc(&mut eq);
    one_level_interp_hc(&mut bh_values);
    parallel_pi(bh_values, eq)
}

pub fn one_level_interp_hc<F: PrimeField>(mut evals: &mut Type1Polynomial<F>) {
    if (evals.poly.len() == 1) {
        return;
    }
    evals.poly.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[1] - chunk[0];
    });
}

pub fn one_level_reverse_interp_hc<F: PrimeField>(mut evals: &mut Type1Polynomial<F>) {
    if (evals.poly.len() == 1) {
        return;
    }
    evals.poly.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[1] + chunk[0];
    });
}

pub fn one_level_eval_hc<F: PrimeField>(mut evals: &mut Type1Polynomial<F>, challenge: F) {
    evals.poly.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[0] + challenge * chunk[1];
    });
    let mut index = 0;

    evals.poly.retain(|v| {
        index += 1;
        (index - 1) % 2 == 1
    });
}

pub fn p_i<F: PrimeField>(evals: &Type1Polynomial<F>, eq: &Type1Polynomial<F>) -> Vec<F> {
    if (evals.poly.len() == 1) {
        return vec![evals.poly[0], evals.poly[0], evals.poly[0]];
    }
    //evals coeffs
    let mut coeffs = vec![F::ZERO, F::ZERO, F::ZERO];
    let mut i = 0;
    while (i < evals.poly.len()) {
        coeffs[0] += evals.poly[i] * eq.poly[i];
        coeffs[1] += evals.poly[i + 1] * eq.poly[i] + evals.poly[i] * eq.poly[i + 1];
        coeffs[2] += evals.poly[i + 1] * eq.poly[i + 1];
        i += 2;
    }

    coeffs
}

fn parallel_pi<F: PrimeField>(evals: &Type1Polynomial<F>, eq: &Type1Polynomial<F>) -> Vec<F> {
    if (evals.poly.len() == 1) {
        return vec![evals.poly[0], evals.poly[0], evals.poly[0]];
    }
    let mut coeffs = vec![F::ZERO, F::ZERO, F::ZERO];

    let mut firsts = vec![F::ZERO; evals.poly.len()];
    firsts.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals.poly[i] * eq.poly[i];
        }
    });

    let mut seconds = vec![F::ZERO; evals.poly.len()];
    seconds.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals.poly[i + 1] * eq.poly[i] + evals.poly[i] * eq.poly[i + 1];
        }
    });

    let mut thirds = vec![F::ZERO; evals.poly.len()];
    thirds.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals.poly[i + 1] * eq.poly[i + 1];
        }
    });

    coeffs[0] = firsts.par_iter().sum();
    coeffs[1] = seconds.par_iter().sum();
    coeffs[2] = thirds.par_iter().sum();

    coeffs
}
/*
fn nd_array_pi<F: PrimeField>(evals: &Vec<F>, eq: &Vec<F>) -> Vec<F> {
    if (evals.len() == 1) {
        return vec![evals[0], evals[0], evals[0]];
    }
    let evals_array = Array1::from(evals);
    let eq_array = Array1::from(eq);

    let evals_evens = Array1::from(evals.par_iter().enumerate().filter(|(i,x)| i%2 == 0).collect::<Vec<F>>());

    let evals_odd = Array1::from(evals.par_iter().enumerate().filter(|(i,x)| i%2 != 0).collect::<Vec<F>>());

    let eq_evens = Array1::from(eq.par_iter().enumerate().filter(|(i,x)| i%2 == 0).collect::<Vec<F>>());

    let eq_odd = Array1::from(eq.par_iter().enumerate().filter(|(i,x)| i%2 != 0).collect::<Vec<F>>());
    let dot1 = evals_array.dot(eq_array);
    let dot2 = evals_odd.dot(eq_even);
    let dot3 = evals_even.dot(eq_odd);
    let dot4 = evals_odd.dot(eq_odd);
    return vec![dot1,dot2 + dot3, dot4];
}
*/
#[test]
fn test_sumcheck() {
    let i = 25;
    let mut rng = ChaCha8Rng::from_entropy();
    let evals = Type1Polynomial {
        poly: rand_vec::<Mersenne61>(1 << i, &mut rng),
    };
    let eq = Type1Polynomial {
        poly: rand_vec::<Mersenne61>(1 << i, &mut rng),
    };
    let now = Instant::now();
    let coeffs1 = p_i(&evals, &eq);
    //    println!("original {:?}", now.elapsed());

    let now = Instant::now();
    let coeffs2 = parallel_pi(&evals, &eq);
    //    println!("new {:?}", now.elapsed());
    assert_eq!(coeffs1, coeffs2);
}

fn sum_check<F: PrimeField>(
    poly: Type1Polynomial<F>,
    point: Vec<F>,
    num_vars: usize,
    num_rounds: usize,
    eq: Vec<F>,
) -> Vec<Vec<F>> {
    let mut eval = F::ZERO;
    let mut bh_evals = Type1Polynomial {
        poly: Vec::with_capacity(1 << num_vars),
    };
    for i in 0..eq.len() {
        eval = eval + poly.poly[i] * eq[i];
        bh_evals.poly.push(poly.poly[i]);
    }

    let mut eq = Type1Polynomial { poly: eq };
    let mut sum_check_oracles_vec = Vec::with_capacity(num_rounds + 1);

    let mut sum_check_oracle = sum_check_first_round::<F>(&mut eq, &mut bh_evals);
    sum_check_oracles_vec.push(sum_check_oracle.clone());
    for i in 0..(num_rounds) {
        let mut rng = ChaCha8Rng::from_entropy();
        let challenge: F = rand_chacha(&mut rng);

        sum_check_oracle = sum_check_challenge_round(&mut eq, &mut bh_evals, challenge);

        sum_check_oracles_vec.push(sum_check_oracle.clone());
    }
    sum_check_oracles_vec
}
#[test]
fn time_sumcheck() {
    let i = 23;
    let mut rng = ChaCha8Rng::from_entropy();
    let evals = Type1Polynomial {
        poly: rand_vec::<Mersenne127>((1 << i), &mut rng),
    };
    let point = rand_vec::<Mersenne127>(i, &mut rng);
    let mut eq = build_eq_x_r_vec::<Mersenne127>(&point).unwrap();
    let now = Instant::now();
    (0..60).into_par_iter().for_each(|x| {


        let oracles = sum_check(evals.clone(), point.clone(), i, i, eq.clone());
    });
    println!("now.elased() {:?}", now.elapsed());
}

pub fn sum_check_challenge_round<F: PrimeField>(
    mut eq: &mut Type1Polynomial<F>,
    mut bh_values: &mut Type1Polynomial<F>,
    challenge: F,
) -> Vec<F> {
    one_level_eval_hc(&mut bh_values, challenge);
    one_level_eval_hc(&mut eq, challenge);

    one_level_interp_hc(&mut eq);
    one_level_interp_hc(&mut bh_values);

    parallel_pi(&bh_values, &eq)
    //p_i(&bh_values, &eq)
}

fn query_binary_table<F:PrimeField>(table:&Vec<Vec<(F,F)>>, level: usize, index: usize, subspace: &BinarySubspace<F>) -> (F,F) {
    assert_eq!(table[level].len(), 1 << level);
    let half_block = (1 << level);
    assert_eq!(index < half_block, true);
    let even = table[level][index % half_block].0; 
    let twiddle_accesses = OnTheFlyTwiddleAccess::generate(&subspace).unwrap();
    let odd = twiddle_accesses[table.len() - level].get_odd_from_even(even);
    (even, odd)
}

fn basefold_one_round_by_interpolation_weights<F: PrimeField>(
    table: &Vec<Vec<(F, F)>>,
    table_offset: usize,
    values: &Type1Polynomial<F>,
    challenge: F,
    num_vars:usize,
    log_rate:usize,
    code_type:String
) -> Type1Polynomial<F> {
    let mut subspace = BinarySubspace::<F>::with_dim(num_vars + log_rate + 1).ok().unwrap();
    let twiddle_accesses = OnTheFlyTwiddleAccess::generate(&subspace).unwrap();
    let leveli = table.len() - 1 - table_offset;
    let level = &table[leveli];
    assert_eq!(1 << leveli, values.poly.len() >> 1);
    let fold = values
        .poly
        .chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            let mut x1 = F::ZERO;
            let mut x0 = F::ZERO;
            if code_type == "binary_rs"{
                (x0,x1) = query_binary_table(table, leveli, i, &subspace);
            }
            else{
                x0 = level[i].0;
                x1 = -x0;
            }
            interpolate2_weights::<F>(
                [(x0, ys[0]), (x1, ys[1])],
                level[i].1,
                challenge,
            )
        })
        .collect::<Vec<_>>();
    Type1Polynomial { poly: fold }
}

fn basefold_one_round_by_interpolation_weights_not_faster<F: PrimeField>(
    table: &Vec<Vec<(F, F)>>,
    table_offset: usize,
    values: &Vec<F>,
    challenge: F,
) -> Vec<F> {
    let level = &table[table.len() - 1 - table_offset];
    let mut new_values = vec![F::ZERO; values.len() >> 1];
    new_values.par_iter_mut().enumerate().for_each(|(i, v)| {
        *v = interpolate2_weights::<F>(
            [
                (level[i].0, values[2 * i]),
                (-(level[i].0), values[2 * i + 1]),
            ],
            level[i].1,
            challenge,
        )
    });
    new_values
}

fn basefold_get_query<F: PrimeField>(
    first_oracle: &Type1Polynomial<F>,
    oracles: &Vec<Type1Polynomial<F>>,
    mut x_index: usize,
) -> (Vec<(F, F)>, Vec<usize>) {
    let mut queries = Vec::with_capacity(oracles.len() + 1);
    let mut indices = Vec::with_capacity(oracles.len() + 1);

    let mut p0 = x_index;
    let mut p1 = x_index ^ 1;

    if (p1 < p0) {
        p0 = x_index ^ 1;
        p1 = x_index;
    }
    queries.push((first_oracle.poly[p0], first_oracle.poly[p1]));
    indices.push(p0);
    x_index >>= 1;

    for oracle in oracles {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        queries.push((oracle.poly[p0], oracle.poly[p1]));
        indices.push(p0);
        x_index >>= 1;
    }

    return (queries, indices);
}

pub fn get_merkle_path<H: Hash, F: PrimeField>(
    tree: &Vec<Vec<Output<H>>>,
    mut x_index: usize,
    root: bool,
) -> Vec<(Output<H>, Output<H>)> {
    let mut queries = Vec::with_capacity(tree.len());
    x_index >>= 1;
    for oracle in tree {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        if (oracle.len() == 1) {
            if (root) {
                queries.push((oracle[0].clone(), oracle[0].clone()));
            }
            break;
        }
        queries.push((oracle[p0].clone(), oracle[p1].clone()));
        x_index >>= 1;
    }

    return queries;
}

fn write_merkle_path<H: Hash, F: PrimeField>(
    tree: &Vec<Vec<Output<H>>>,
    mut x_index: usize,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
) {
    x_index >>= 1;
    for oracle in tree {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        if (oracle.len() == 1) {
            //	    transcript.write_commitment(&oracle[0]);
            break;
        }
        transcript.write_commitment(&oracle[p0]);
        transcript.write_commitment(&oracle[p1]);
        x_index >>= 1;
    }
}

// 🔴 2026-09-16：无根链版 `authenticate_merkle_path`（只校验链内相邻层、不把顶端对哈希后
// 与 root 比对）已删除——其唯一调用点（batch_verify 个体开口）改用下方 `_root` 版。
// 保留此注记以防同名函数被重新引入（探针 a3_probe_indiv_path_root_link 守卫）。

/// D27 交织档向量叶版根链认证:首哈希=H(salt‖leaf_values 逐个吸收)(与 merkelize_interleaved
/// 叶式一致),末端必校 hash(children)==root(P0 修复语义在交织档保持)。
fn authenticate_merkle_path_root_vec<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaf_values: &[F],
    mut x_index: usize,
    root: &Output<H>,
    salt: &Output<H>,
) {
    let mut hasher = H::new();
    hasher.update(salt.as_slice());
    for v in leaf_values {
        hasher.update_field_element(v);
    }
    let mut hash = Output::<H>::default();
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..path.len() - 1 {
        let mut hasher = H::new();
        let mut hash = Output::<H>::default();
        hasher.update(salt.as_slice());
        hasher.update(&path[i][0]);
        hasher.update(&path[i][1]);
        hasher.finalize_into_reset(&mut hash);

        assert_eq!(hash, path[i + 1][(x_index >> 1) % 2]);
        x_index >>= 1;
    }
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update(salt.as_slice());
    hasher.update(&path[path.len() - 1][0]);
    hasher.update(&path[path.len() - 1][1]);
    hasher.finalize_into_reset(&mut hash);
    assert_eq!(&hash, root);
}

/// D27:位置 x 的叶值对(相邻两码字位;从 query_codeword 提取,交织 S6′ 逐列写用)。
fn codeword_pair<F: PrimeField>(query: &usize, codeword: &Vec<F>) -> (F, F) {
    let mut p0 = *query;
    let temp = p0;
    let mut p1 = p0 ^ 1;
    if p1 < p0 {
        p0 = p1;
        p1 = temp;
    }
    (codeword[p0], codeword[p1])
}

fn authenticate_merkle_path_root<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: (F, F),
    mut x_index: usize,
    root: &Output<H>,
    salt: &Output<H>,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    // D18 Phase 1：认证哈希与 merkelize 同域——每个节点哈希输入先盐后数据。
    hasher.update(salt.as_slice());
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..path.len() - 1 {
        let mut hasher = H::new();
        let mut hash = Output::<H>::default();
        hasher.update(salt.as_slice());
        hasher.update(&path[i][0]);
        hasher.update(&path[i][1]);
        hasher.finalize_into_reset(&mut hash);

        assert_eq!(hash, path[i + 1][(x_index >> 1) % 2]);
        x_index >>= 1;
    }
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update(salt.as_slice());
    hasher.update(&path[path.len() - 1][0]);
    hasher.update(&path[path.len() - 1][1]);
    hasher.finalize_into_reset(&mut hash);
    assert_eq!(&hash, root);
}

pub fn interpolate2_weights<F: PrimeField>(points: [(F, F); 2], weight: F, x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    //    assert_ne!(a0, b0);
    a1 + (x - a0) * (b1 - a1) * weight
}

pub fn query_point<F: PrimeField>(
    block_length: usize,
    eval_index: usize,
    mut rng: &mut ChaCha8Rng,
    level: usize,
    mut cipher: &mut ctr::Ctr32LE<aes::Aes128>,
) -> F {
    let level_index = eval_index % (block_length);
    let mut el = query_root_table_from_rng_aes::<F>(
        level,
        (level_index % (block_length >> 1)),
        &mut rng,
        &mut cipher,
    );

    if level_index >= (block_length >> 1) {
        el = -F::ONE * el;
    }

    return el;
}

pub fn query_point_binary_rs<F: PrimeField>(
    block_length: usize,
    eval_index: usize,
    level: usize,
    subspace: &BinarySubspace<F>,
    log_total_block_length:usize
) ->(F,F) {
    let level_index = eval_index % block_length;
    let half_block = block_length >> 1;
    let left_index = level_index % half_block;

    let twiddle_accesses = OnTheFlyTwiddleAccess::generate(&subspace).unwrap();

    let ri0 = left_index; //reverse_bits(left_index, level);

    twiddle_accesses[log_total_block_length - level].get_pair(level-1,ri0)
    /*if level_index >= half_block{
        w_1
    }
    else{
        w_0
    }*/
}
/*
#[test]
fn test_query_point(){
    use crate::util::binary_extension_fields::B128;

    //first create a table
    let poly_size = 1 << 4;
    let log_rate = 1;
    let table = get_table_additive_binary::<B128>(poly_size, log_rate);

    let lg_n: usize = log_rate + log2_strict(poly_size);
    let level = lg_n - 1;
    let index = 18;
    let mut sim_index = index;
    if index >= ((1 << level) >> 1){
        sim_index = index % ((1 << level) >> 1);
    }
    let subspace = BinarySubspace::<B128>::with_dim(lg_n).ok().unwrap();
    
    let actual_pair = query_binary_table(&table.0, level, sim_index, &subspace);
    let mut actual = B128::ZERO;
    if index >= ((1 << level) >> 1){
        actual = actual_pair.1;
    }
    else{
        actual = actual_pair.0;
    }

    let sim = query_point_binary_rs::<B128>(1 << lg_n, index, level, &subspace);

    assert_eq!(actual,sim);


}
*/
pub fn query_root_table_from_rng<F: PrimeField>(
    level: usize,
    index: usize,
    rng: &mut ChaCha8Rng,
) -> F {
    let mut level_offset: u128 = 1;
    for lg_m in 1..=level {
        let half_m = 1 << (lg_m - 1);
        level_offset += half_m;
    }
    //this is 512  because of the implementation of random in the ff rust library
    //    let pos = ((level_offset + (index as u128)) * (512))
    let pos = ((level_offset + (index as u128))
        * ((F::NUM_BITS as usize).next_power_of_two() as u128))
        .checked_div(32)
        .unwrap();

    rng.set_word_pos(pos);

    let res = rand_chacha::<F>(rng);

    res
}

pub fn query_root_table_from_rng_aes<F: PrimeField>(
    level: usize,
    index: usize,
    rng: &mut ChaCha8Rng,
    cipher: &mut ctr::Ctr32LE<aes::Aes128>,
) -> F {
    let mut level_offset: u128 = 1;
    for lg_m in 1..=level {
        let half_m = 1 << (lg_m - 1);
        level_offset += half_m;
    }

    let pos = ((level_offset + (index as u128))
        * ((F::NUM_BITS as usize).next_power_of_two() as u128))
        .checked_div(8)
        .unwrap();

    cipher.seek(pos);

    let bytes = (F::NUM_BITS as usize).next_power_of_two() / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    cipher.apply_keystream(&mut dest);

    let res = from_raw_bytes::<F>(&dest);

    res
}

pub fn interpolate2<F: PrimeField>(points: [(F, F); 2], x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    assert_ne!(a0, b0);
    a1 + (x - a0) * (b1 - a1) * (b0 - a0).invert().unwrap()
}

fn degree_2_zero_plus_one<F: PrimeField>(poly: &Vec<F>) -> F {
    poly[0] + poly[0] + poly[1] + poly[2]
}

fn degree_2_eval<F: PrimeField>(poly: &Vec<F>, point: F) -> F {
    poly[0] + point * poly[1] + point * point * poly[2]
}

pub fn interpolate_over_boolean_hypercube<F: PrimeField>(mut evals: Vec<F>) -> Vec<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.len());
    for i in 1..n + 1 {
        let chunk_size = 1 << i;
        evals.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }
    reverse_index_bits_in_place(&mut evals);
    evals
}

pub fn multilinear_evaluation_ztoa<F: PrimeField>(poly: &mut Type2Polynomial<F>, point: &Vec<F>) {
    reverse_index_bits_in_place(&mut poly.poly);
    let n = log2_strict(poly.poly.len());
    for p in point {
        poly.poly.par_chunks_mut(2).for_each(|chunk| {
            chunk[0] = chunk[0] + *p * chunk[1];
            chunk[1] = chunk[0];
        });
        poly.poly = poly
            .poly
            .iter()
            .enumerate()
            .filter(|(i, e)| i % 2 == 0)
            .map(|(i, e)| *e)
            .collect::<Vec<F>>();
    }
    reverse_index_bits_in_place(&mut poly.poly);
}

pub fn multilinear_evaluation_atoz<F: PrimeField>(poly: &mut Vec<F>, point: &Vec<F>) {
    let n = log2_strict(poly.len());
    //    assert_eq!(point.len(),n);
    for p in point {
        poly.par_chunks_mut(2).for_each(|chunk| {
            chunk[0] = *p * chunk[0] + chunk[1];
            chunk[1] = chunk[0];
        });
        poly.dedup();
    }
}
#[test]
fn bench_multilinear_eval() {
    use crate::util::ff_255::ff255::Ft255;
    for i in 10..27 {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut poly = Type2Polynomial {
            poly: rand_vec::<Ft255>(1 << i, &mut rng),
        };
        let point = rand_vec::<Ft255>(i, &mut rng);
        let now = Instant::now();
        multilinear_evaluation_ztoa(&mut poly, &point);
        println!(
            "time for multilinear eval degree i {:?} : {:?}",
            i,
            now.elapsed().as_millis()
        );
    }
}
fn from_raw_bytes<F: PrimeField>(bytes: &Vec<u8>) -> F {
    let mut res = F::ZERO;
    bytes.into_iter().for_each(|b| {
        res += F::from(u64::from(*b));
    });
    res
}

#[cfg(test)]
mod test {
    use crate::util::transcript::{
        FieldTranscript, FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript,
        TranscriptRead, TranscriptWrite,
    };

    use crate::{
        pcs::multilinear::{
            basefold::{
                basefold_one_round_by_interpolation_weights, encode_repetition_basecode,
                encode_rs_basecode, evaluate_over_foldable_domain, evaluate_over_foldable_domain_2,
                evaluate_over_foldable_domain_generic_basecode, get_table_aes,
                interpolate_over_boolean_hypercube_with_copy, log2_strict,
                multilinear_evaluation_atoz, multilinear_evaluation_ztoa, one_level_eval_hc,
                one_level_interp_hc, rand_chacha, Basefold, Type1Polynomial, Type2Polynomial,
            },
            test::{run_batch_commit_open_verify, run_commit_open_verify},
        },
        poly::{multilinear::MultilinearPolynomial, Polynomial},
        util::{
            hash::{Hash, Keccak256, Output},
            new_fields::{Mersenne127, Mersenne61},
            play_field::PlayField,
            transcript::{Blake2sTranscript, Keccak256Transcript},
        },
    };
    use halo2_curves::{ff::Field, secp256k1::Fp};
    use plonky2_util::reverse_index_bits_in_place;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha12Rng, ChaCha8Rng,
    };
    use std::io;

    use crate::pcs::multilinear::basefold::Instant;
    use crate::pcs::multilinear::BasefoldExtParams;
    use crate::util::arithmetic::PrimeField;
    use blake2::{digest::FixedOutputReset, Blake2s256};
    use halo2_curves::bn256::{Bn256, Fr};

    type Pcs = Basefold<Fr, Blake2s256, Five>;

    #[derive(Debug)]
    pub struct Five {}

    impl BasefoldExtParams for Five {
        fn get_reps() -> usize {
            33
        }

        fn get_rate() -> usize {
            3
        }

        fn get_basecode_rounds() -> usize {
            0
        }

        fn get_rs_basecode() -> bool {
            false
        }

        fn get_code_type() -> String {
            "random".to_string()
        }
    }

    #[test]
    fn test_transforms() {
        type F = Mersenne127;
        use rand::rngs::OsRng;
        let num_vars = 10;
        let log_rate = 1;
        let poly = MultilinearPolynomial::<F>::rand(num_vars, OsRng);
        let mut rng = ChaCha8Rng::from_entropy();

        let (mut table_w_weights, mut table) = get_table_aes((1 << num_vars), log_rate, &mut rng);
        let (mut coeffs, mut bh_evals) =
            interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                poly: poly.evals().to_vec(),
            });

        let mut commitment = evaluate_over_foldable_domain(log_rate, coeffs.clone(), &table,"random".to_string());

        let challenge = rand_chacha::<F>(&mut rng);
        let fold = basefold_one_round_by_interpolation_weights(
            &table_w_weights,
            0,
            &commitment,
            challenge,
            num_vars,
            log_rate,
            "random".to_string()
        );

        let chal_vec = vec![challenge];
        let partial_eval = multilinear_evaluation_ztoa(&mut coeffs, &chal_vec);

        let mut commitment = evaluate_over_foldable_domain(log_rate, coeffs.clone(), &table,"random".to_string());

        assert_eq!(commitment, fold);

        //fold bh_evals one level
        one_level_interp_hc(&mut bh_evals);
        one_level_eval_hc(&mut bh_evals, challenge);

        //convert bh_evals to type2
        reverse_index_bits_in_place(&mut bh_evals.poly);

        let bh_evals = Type2Polynomial {
            poly: bh_evals.poly,
        };
        let (bhcoeffs, mut bh_evals) = interpolate_over_boolean_hypercube_with_copy(&bh_evals);

        //coeffs is type2, partial eval is also type2
        assert_eq!(coeffs, bhcoeffs);
    }
    #[test]
    fn test_rs_transform() {
        type F = Mersenne127;
        use rand::rngs::OsRng;
        let num_vars = 10;
        let log_rate = 1;
        let num_rounds = 1;
        let poly = MultilinearPolynomial::<F>::rand(num_vars, OsRng);
        let mut rng = ChaCha8Rng::from_entropy();

        let (mut table_w_weights, mut table) = get_table_aes((1 << num_vars), log_rate, &mut rng);
        let (mut coeffs_og, mut bh_evals) =
            interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                poly: poly.evals().to_vec(),
            });

        //coeffs is type2, bh_evals is type 1, basecode will have type2
        let mut coeffs =
            encode_rs_basecode(&coeffs_og, 1 << log_rate, 1 << (num_vars - num_rounds));

        let log_chunk = num_vars - num_rounds;
        let mut commitment = evaluate_over_foldable_domain_2(
            num_vars - num_rounds + log_rate,
            log_rate,
            coeffs.clone(),
            &table,
        );

        let challenge = rand_chacha::<F>(&mut rng);
        let mut fold = basefold_one_round_by_interpolation_weights(
            &table_w_weights,
            0,
            &commitment,
            challenge,
            num_vars,
            log_rate,
            "random".to_string()
        );

        let chal_vec = vec![challenge];

        one_level_interp_hc(&mut bh_evals);
        one_level_eval_hc(&mut bh_evals, challenge);

        reverse_index_bits_in_place(&mut bh_evals.poly); //convert to type2

        let (mut new_coeffs, _) = interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
            poly: bh_evals.poly,
        });

        let rs = encode_rs_basecode(&new_coeffs, 1 << log_rate, 1 << (num_vars - num_rounds));

        //Compare a partial eval of RS Evaluations to an RS Evaluation of a partial Eval

        //        let mut commitment = evaluate_over_foldable_domain_2(num_vars - num_rounds + log_rate, log_rate, rs.clone(), &table);
        reverse_index_bits_in_place(&mut fold.poly);
        assert_eq!(rs, Type2Polynomial { poly: fold.poly });
    }

    #[test]
    fn commit_open_verify() {
        run_commit_open_verify::<_, Pcs, Blake2sTranscript<_>>();
    }

    #[test]
    fn batch_commit_open_verify() {
        run_batch_commit_open_verify::<_, Pcs, Blake2sTranscript<_>>();
    }

    /// D18 Phase 2 RED-1：同 witness 两次 commit ⟹ 码字必须逐位不同（κ=B(m)，m fresh 随机）。
    /// 当前未掩蔽 ⟹ 码字=witness 确定性函数（盐只随机化 Merkle 根，不触码字）⟹ 本测试红。
    /// 取证自 T1.3b：码字通道=查询值/折叠 oracle/final oracle 的源，指纹攻击的 PCS 内层。
    /// D18 Phase 3 改版：κ 退役 ⟹ PCS 层码字=列的确定函数（同列同码字）；跨证明
    /// 不可链接性由两层共同承重——①Phase 1 盐化（根=H(fresh salt‖数据)，同列两承诺
    /// 根必不同）；②掩蔽新鲜度上移列层（证明列=v+λ·m，λ/m 逐证明 fresh ⟹ 系统级
    /// 码字跨证明必不同，由 hyperplonk e2e 承载）。
    #[test]
    fn zk_phase3_same_column_salt_roots_differ() {
        use crate::pcs::PolynomialCommitmentScheme;
        use rand::rngs::OsRng;

        let num_vars = 6;
        let param =
            <Pcs as PolynomialCommitmentScheme<Fr>>::setup(1 << num_vars, 1, OsRng).unwrap();
        let (pp, _vp) =
            <Pcs as PolynomialCommitmentScheme<Fr>>::trim(&param, 1 << num_vars, 1).unwrap();
        let poly = MultilinearPolynomial::<Fr>::rand(num_vars, OsRng);

        let comm1 = <Pcs as PolynomialCommitmentScheme<Fr>>::commit(&pp, &poly).unwrap();
        let comm2 = <Pcs as PolynomialCommitmentScheme<Fr>>::commit(&pp, &poly).unwrap();

        assert_eq!(
            comm1.codeword.poly, comm2.codeword.poly,
            "Phase 3：码字=列的确定函数（κ 已退役），同列两承诺码字相同"
        );
        assert_ne!(
            comm1.codeword_tree[comm1.codeword_tree.len() - 1][0],
            comm2.codeword_tree[comm2.codeword_tree.len() - 1][0],
            "Phase 1 盐化：根=H(salt‖数据)，同列两承诺根必不同（指纹消灭的承重点）"
        );
    }

    struct PretendHash {}
    #[test]
    fn test_sha3_hashes() {
        use blake2::digest::FixedOutputReset;

        type H = Keccak256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            hasher.update_field_element(&values[i + i]);
            hasher.update_field_element(&values[i + i + 1]);
            hasher.finalize_into_reset(&mut hash);
        }
        println!("lots of hashes sha3 time {:?}", lots_of_hashes.elapsed());

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash a lot sha3 time {:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_blake2b_hashes() {
        use blake2::{digest::FixedOutputReset, Blake2b512, Blake2s256};

        type H = Blake2s256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            hasher.update_field_element(&values[i + i]);
            hasher.update_field_element(&values[i + i + 1]);
            hasher.finalize_into_reset(&mut hash);
        }
        println!("lots of hashes blake2 time {:?}", lots_of_hashes.elapsed());

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash alot blake2 time {:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_blake2b_no_finalize() {
        use blake2::{digest::FixedOutputReset, Blake2b512, Blake2s256};

        type H = Blake2s256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            let f1 = values[i + 1].to_repr();
            let f2 = values[i + i + 1].to_repr();
            let data = [f1.as_ref(), f2.as_ref()].concat();
            //	    hasher.update_field_element(&values[i + i]);
            //	    hasher.update_field_element(&values[i+ i + 1]);
            *hash = H::digest(&data);
        }
        println!(
            "lots of hashes blake2 time no finalize{:?}",
            lots_of_hashes.elapsed()
        );

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash alot blake2 time no finalize{:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_cipher() {
        use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use generic_array::GenericArray;
        use hex_literal::hex;
        type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
        let mut rng = ChaCha12Rng::from_entropy();

        let mut key: [u8; 16] = [042; 16];
        let mut iv: [u8; 16] = [024; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        //	rng.set_word_pos(0);

        let mut key2: [u8; 16] = [042; 16];
        let mut iv2: [u8; 16] = [024; 16];
        rng.fill_bytes(&mut key2);
        rng.fill_bytes(&mut iv2);

        let plaintext = *b"hello world! this is my plaintext.";
        let ciphertext =
            hex!("3357121ebb5a29468bd861467596ce3da59bdee42dcc0614dea955368d8a5dc0cad4");
        let mut buf = plaintext.to_vec();
        let mut buf1 = [0u8; 100];

        let mut cipher = Aes128Ctr64LE::new(
            GenericArray::from_slice(&key[..]),
            GenericArray::from_slice(&iv[..]),
        );
        let hash_time = Instant::now();
        cipher.apply_keystream(&mut buf1[..]);
        println!("aes hash 34 bytes {:?}", hash_time.elapsed());
        println!("buf1 {:?}", buf1);
        for i in 0..40 {
            let now = Instant::now();
            cipher.seek((1 << i) as u64);
            println!("aes seek {:?} : {:?}", (1 << i), now.elapsed());
        }
        let mut bufnew = [0u8; 1];
        cipher.apply_keystream(&mut bufnew);

        println!("byte1 {:?}", bufnew);

        /*
            let mut cipher2 = Aes128Ctr64LE::new(&key.into(),&iv.into());
            let mut buf2 = [0u8; 34];
            for chunk in buf2.chunks_mut(3){
                cipher2.apply_keystream(chunk);
            }

            assert_eq!(buf1,buf2);
        */
        let mut dest: Vec<u8> = vec![0u8; 34];
        let mut rng = ChaCha8Rng::from_entropy();
        let now = Instant::now();
        rng.fill_bytes(&mut dest);
        println!("chacha20 hash 34 bytes {:?}", now.elapsed());
        println!("des {:?}", dest);
        let now = Instant::now();
        rng.set_word_pos(1);

        println!("chacha8 seek {:?}", now.elapsed());

        let mut cipher = Aes128Ctr64LE::new(
            GenericArray::from_slice(&key[..]),
            GenericArray::from_slice(&iv[..]),
        );
        let mut buf2 = vec![0u8; 34];
        let hash_time = Instant::now();

        let now = Instant::now();
        cipher.seek(33u64);
        println!("aes seek {:?}", now.elapsed());
        let mut bufnew = [0u8; 1];
        cipher.apply_keystream(&mut bufnew);

        println!("byte1 {:?}", bufnew);
    }

    #[test]
    fn test_blake2b_simd_hashes() {
        use blake2b_simd::{blake2b, many::update_many, State};
        use ff::PrimeField;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut states = vec![State::new(); 1000];

        for (i, mut hash) in states.iter_mut().enumerate() {
            hash.update(&values[i + i].to_repr().as_ref());
            hash.update(&values[i + i + 1].to_repr().as_ref());
            hash.finalize();
        }
        println!(
            "lots of hashes blake2simd time {:?}",
            lots_of_hashes.elapsed()
        );

        let hash_alot = Instant::now();
        let mut state = State::new();
        for i in 0..2000 {
            state.update(values[i].to_repr().as_ref());
        }
        let hash = state.finalize();
        println!("hash alot blake2simd time {:?}", hash_alot.elapsed());
    }
}

fn reed_solomon_into<F: Field>(input: &[F], mut target: impl AsMut<[F]>, domain: &Vec<F>) {
    target
        .as_mut()
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, target)| *target = horner(input, &domain[i]));
}

fn virtual_open<F: PrimeField>(
    num_vars: usize,
    num_rounds: usize,
    // 🔴 边界注(2026-09-17,缺口 F 侧面):nr<nv 配置下本函数的尾轮挑战取自
    // ChaCha8Rng::from_entropy(验证者本地熵,每次调用重采样)——诚实证明恒过
    // (E3 恒等式 ∀β 成立),但验证成为随机化算法,偏离 FS 非交互语义。
    // 部署配置(A5Spec 族 basecode_rounds=0 ⟹ nr=nv)尾轮数=0,不消费本熵源,
    // 验证确定性成立;若启用 nr<nv 须先将尾轮挑战 FS 化(读序两侧同站点)。
    eq: &mut Type1Polynomial<F>,
    bh_evals: &mut Type1Polynomial<F>,
    last_oracle: &Type1Polynomial<F>,
    point: &Vec<F>,
    challenges: &mut Vec<F>,
    table: &Vec<Vec<(F, F)>>,
    sum_check_oracles: &mut Vec<Vec<F>>,
    log_rate:usize,
    code_type:String
) {
    let mut rng = ChaCha8Rng::from_entropy();
    let rounds = num_vars - num_rounds;

    let mut oracles = Vec::with_capacity(rounds);
    let mut new_oracle = last_oracle;
    for round in 0..rounds {
        let challenge: F = rand_chacha(&mut rng);
        challenges.push(challenge);

        sum_check_oracles.push(sum_check_challenge_round(eq, bh_evals, challenge));

        oracles.push(basefold_one_round_by_interpolation_weights::<F>(&table, round + num_rounds, &new_oracle, challenge,num_vars,log_rate,code_type.clone()));
        new_oracle = &oracles[round];
    }

    let mut no = new_oracle.clone();
    no.poly.dedup();

    //verify it information-theoretically
    let mut eq_r_ = F::ONE;
    for i in 0..challenges.len() {
        eq_r_ = eq_r_ * (challenges[i] * point[i] + (F::ONE - challenges[i]) * (F::ONE - point[i]));
    }
    let last_challenge = challenges[challenges.len() - 1];

    assert_eq!(
        degree_2_eval(&sum_check_oracles[challenges.len() - 1], last_challenge),
        eq_r_ * no.poly[0]
    );
}
//outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
fn commit_phase<F: PrimeField, H: Hash>(
    point: &Point<F, MultilinearPolynomial<F>>,
    comm: &BasefoldCommitment<F, H>,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(F, F)>>,
    code_type:String,
    log_rate:usize,
) -> (
    Vec<Vec<Vec<Output<H>>>>,
    Vec<Vec<F>>,
    Vec<Type1Polynomial<F>>,
    Type1Polynomial<F>,
    Type1Polynomial<F>,
    F,
) {
    let mut oracles = Vec::with_capacity(num_vars);

    let mut trees = Vec::with_capacity(num_vars);

    let mut new_tree = &comm.codeword_tree;
    let mut root = new_tree[new_tree.len() - 1][0].clone();
    // D18 Phase 1：cur_salt=「当前待写根所属树」的盐（初值=承诺树盐；每轮折叠后换新）。
    let mut cur_salt = comm.salt.clone();
    let mut new_oracle = &comm.codeword;

    let num_rounds = num_rounds;

    let mut eq = build_eq_x_r_vec::<F>(&point).unwrap();
    let mut eval = F::ZERO;
    let mut bh_evals = Type1Polynomial {
        poly: Vec::with_capacity(1 << num_vars),
    };
    for i in 0..eq.len() {
        eval = eval + comm.bh_evals.poly[i] * eq[i];
        bh_evals.poly.push(comm.bh_evals.poly[i]);
    }

    let mut eq = Type1Polynomial { poly: eq };
    let mut sum_check_oracles_vec = Vec::with_capacity(num_rounds + 1);
    let mut sum_check_oracle = sum_check_first_round::<F>(&mut eq, &mut bh_evals);
    sum_check_oracles_vec.push(sum_check_oracle.clone());

    // D18 Phase 3（拍板 2026-09-04）：Phase 2 末轮「先挤挑战（β_last∉{0,1} 拒绝采样）
    // + A·Z 拟合项」整体退役——三世界统一后 E3 自然闭合，标准写挤序（写消息→挤挑战）
    // 回归，挑战空间恢复全域。
    let mut fold_challenges: Vec<F> = Vec::with_capacity(num_rounds);

    for i in 0..(num_rounds) {
        // D18 Phase 1：每棵树的根写串=(salt, root) 对（盐=本棵树 fresh 盐）。
        transcript.write_commitment(&cur_salt).unwrap();
        transcript.write_commitment(&root).unwrap();
        // D1:轮根 (盐,根) 进 FS,先于本轮挑战(读侧 verify/batch_verify 同点吸收)。
        absorb_salt_root::<F, H>(transcript, &cur_salt, &root);

        transcript.write_field_elements(&sum_check_oracle);
        let challenge = transcript.squeeze_challenge();
        fold_challenges.push(challenge);

        sum_check_oracle = sum_check_challenge_round(&mut eq, &mut bh_evals, challenge);

        sum_check_oracles_vec.push(sum_check_oracle.clone());

        oracles.push(basefold_one_round_by_interpolation_weights::<F>(
            &table_w_weights,
            i,
            new_oracle,
            challenge,
            num_vars,
            log_rate,
            code_type.clone()
        ));

        new_oracle = &oracles[i];

        // D18 Phase 1：每个折叠轮树 fresh 独立盐（根=H(salt‖数据) ⟹ 不链接数据）。
        cur_salt = fresh_salt::<H>();
        trees.push(merkelize::<F, H>(&new_oracle, &cur_salt));

        root = trees[i][trees[i].len() - 1][0].clone();
    }
    transcript.write_field_elements(&sum_check_oracle);
    return (trees, sum_check_oracles_vec, oracles, bh_evals, eq, eval);
}

fn query_phase<F: PrimeField, H: Hash>(
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    comm: &BasefoldCommitment<F, H>,
    oracles: &Vec<Type1Polynomial<F>>,
    num_verifier_queries: usize,
) -> (Vec<(Vec<(F, F)>, Vec<usize>)>, Vec<usize>) {
    let mut queries = transcript.squeeze_challenges(num_verifier_queries);

    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| {
            let x_rep = (*x_index).to_repr();
            let mut x: &[u8] = x_rep.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % comm.codeword.poly.len()).into()
        })
        .collect_vec();

    (
        queries_usize
            .par_iter()
            .map(|x_index| {
                return basefold_get_query::<F>(&comm.codeword, &oracles, *x_index);
            })
            .collect(),
        queries_usize,
    )
}

fn verifier_query_phase<F: PrimeField, H: Hash>(
    query_challenges: &Vec<F>,
    query_merkle_paths: &Vec<Vec<Vec<Vec<Output<H>>>>>,
    sum_check_oracles: &Vec<Vec<F>>,
    fold_challenges: &Vec<F>,
    queries: &Vec<Vec<&[F]>>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    roots: &Vec<Output<H>>,
    round_salts: &Vec<Output<H>>,
    rng: ChaCha8Rng,
    eval: &F,
    code_type: &str,
    // 🔴 Fix B(2026-09-17,W1_CHECKPOINT v9 §13 缺口 B):S9 final_oracle 全量向量。
    // 论文 Protocol 4 末端 `Enc₀(h₁(r₀)/ẽq_z(r))=π₀` 的实现层对应——末层叶对由
    // interp 链代数钉定(上一轮已认证对在 β_{nr−1} 处的插值),S9 必须与之一致;
    // 无此核对时 S9 为自由对象,可闭合任意自适应消息链(E3 负例实测:修 A 后仍接受)。
    final_oracle: &Vec<F>,
) -> Vec<usize> {
    // #27 修复：上游断言残留把查询数硬编码为 1，与 prover 端（按 reps 生成查询，
    // basefold.rs:370）及 verify 端数据流（按 num_verifier_queries 读 Merkle 路径，
    // basefold.rs:646/691）矛盾——所有 reps>1 配置（默认 33/402）verify 必 panic，
    // 且若 reps==1 则仅检查 1 个查询（soundness 实际只有 1 查询的级别）。
    // verify 逻辑本就遍历全部查询（下方 queries_usize.iter_mut().enumerate()），
    // 故只保留"非空"守卫，恢复多查询 soundness。
    assert!(!query_challenges.is_empty());
    let n = (1 << (num_vars + log_rate));
    let mut queries_usize: Vec<usize> = query_challenges
        .par_iter()
        .map(|x_index| {
            let x_repr = (*x_index).to_repr();
            let mut x: &[u8] = x_repr.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % n).into()
        })
        .collect();
    // 🔴 Fix B ②:k₀=1 基码(nr==nv)下末层=重复码字,S9 必为常量;非常量=自由对象伪造面。
    if num_rounds == num_vars {
        assert!(
            final_oracle.iter().all(|v| *v == final_oracle[0]),
            "Fix B: final_oracle 非常量(k₀=1 基码下应为重复码字)"
        );
    }
    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    let mut rng = rng.clone();
    rng.set_word_pos(0);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );
    let mut subspace = BinarySubspace::<F>::with_dim(num_vars + log_rate + 1).ok().unwrap();

    let twiddle_accesses = OnTheFlyTwiddleAccess::generate(&subspace).unwrap();
    queries_usize
        .iter_mut()
        .enumerate()
        .for_each(|(qi, query_index)| {
            let mut cipher = cipher.clone();
            let mut rng = rng.clone();
            let mut cur_index = *query_index;
            let mut cur_queries = &queries[qi];

            for i in 0..num_rounds {
                let temp = cur_index;
                let mut other_index = cur_index ^ 1;
                if (other_index < cur_index) {
                    cur_index = other_index;
                    other_index = temp;
                }

                assert_eq!(cur_index % 2, 0);

                let ri0 = reverse_bits(cur_index, num_vars + log_rate - i);

                let now = Instant::now();
                let mut x0 = F::ZERO;
                let mut x1 = F::ZERO;
                if code_type == "binary_rs" {

                    (x0,x1) = query_point_binary_rs(
                        1 << (num_vars + log_rate-i),
                        ri0,
                        num_vars + log_rate - i - 1,
                        &subspace,
                        num_vars + log_rate
                    );
                } else {
                    x0 = query_point(
                        1 << (num_vars + log_rate - i),
                        ri0,
                        &mut rng,
                        num_vars + log_rate - i - 1,
                        &mut cipher,
                    );
                    x1 = -x0;
                }

                let res = interpolate2(
                    [(x0, cur_queries[i][0]), (x1, cur_queries[i][1])],
                    fold_challenges[i],
                );

                assert_eq!(res, cur_queries[i + 1][(cur_index >> 1) % 2]);

                authenticate_merkle_path_root::<H, F>(
                    &query_merkle_paths[qi][i],
                    (cur_queries[i][0], cur_queries[i][1]),
                    cur_index,
                    &roots[i],
                    &round_salts[i],
                );

                cur_index >>= 1;
            }

            // 🔴 Fix B ③:末层交叉核对——cur_queries[nr] 由 interp 链代数钉定,
            // final_oracle 的同位叶对必须与之相等(偶位规约与 basefold_get_query 同构)。
            let p0 = cur_index & !1usize;
            let p1 = p0 ^ 1;
            assert!(
                p1 < final_oracle.len(),
                "Fix B: 末层索引 {p1} 越界(final_oracle 长 {})",
                final_oracle.len()
            );
            assert_eq!(
                cur_queries[num_rounds][0],
                final_oracle[p0],
                "Fix B: S9[p0] != 折叠链末对[0](final_oracle 未绑定折叠链)"
            );
            assert_eq!(
                cur_queries[num_rounds][1],
                final_oracle[p1],
                "Fix B: S9[p1] != 折叠链末对[1](final_oracle 未绑定折叠链)"
            );
        });

    assert_eq!(eval, &degree_2_zero_plus_one(&sum_check_oracles[0]));

    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            degree_2_eval(&sum_check_oracles[i], fold_challenges[i]),
            degree_2_zero_plus_one(&sum_check_oracles[i + 1])
        );
    }
    return queries_usize;
}
//return ((leaf1,leaf2),path), where leaves are queries from codewords
fn query_codeword<F: PrimeField, H: Hash>(
    query: &usize,
    codeword: &Vec<F>,
    codeword_tree: &Vec<Vec<Output<H>>>,
) -> ((F, F), Vec<(Output<H>, Output<H>)>) {
    let mut p0 = *query;
    let temp = p0;
    let mut p1 = p0 ^ 1;
    if (p1 < p0) {
        p0 = p1;
        p1 = temp;
    }
    return (
        (codeword[p0], codeword[p1]),
        get_merkle_path::<H, F>(&codeword_tree, *query, true),
    );
}

fn get_table<F: PrimeField>(
    poly_size: usize,
    rate: usize,
    rng: &mut ChaCha8Rng,
) -> (Vec<Vec<(F, F)>>, Vec<Vec<F>>) {
    let lg_n: usize = rate + log2_strict(poly_size);

    let now = Instant::now();

    let bytes = (F::NUM_BITS as usize).next_power_of_two() * (1 << lg_n) / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    rng.fill_bytes(&mut dest);

    let flat_table: Vec<F> = dest
        .par_chunks_exact((F::NUM_BITS as usize).next_power_of_two() / 8)
        .map(|chunk| from_raw_bytes::<F>(&chunk.to_vec()))
        .collect::<Vec<_>>();

    assert_eq!(flat_table.len(), 1 << lg_n);

    let mut weights: Vec<F> = flat_table
        .par_iter()
        .map(|el| F::ZERO - *el - *el)
        .collect();

    let mut scratch_space = vec![F::ZERO; weights.len()];
    BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

    let mut flat_table_w_weights = flat_table
        .iter()
        .zip(weights)
        .map(|(el, w)| (*el, w))
        .collect_vec();

    let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
    let mut unflattened_table = vec![Vec::new(); lg_n];

    let mut level_weights = flat_table_w_weights[0..2].to_vec();
    reverse_index_bits_in_place(&mut level_weights);
    unflattened_table_w_weights[0] = level_weights;

    unflattened_table[0] = flat_table[0..2].to_vec();
    for i in 1..lg_n {
        unflattened_table[i] = flat_table[(1 << i)..(1 << (i + 1))].to_vec();
        let mut level = flat_table_w_weights[(1 << i)..(1 << (i + 1))].to_vec();
        reverse_index_bits_in_place(&mut level);
        unflattened_table_w_weights[i] = level;
    }

    return (unflattened_table_w_weights, unflattened_table);
}

fn get_table_aes<F: PrimeField>(
    poly_size: usize,
    rate: usize,
    rng: &mut ChaCha8Rng,
) -> (Vec<Vec<(F, F)>>, Vec<Vec<F>>) {
    let lg_n: usize = rate + log2_strict(poly_size);

    let now = Instant::now();

    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;

    let mut cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );

    let bytes = (F::NUM_BITS as usize).next_power_of_two() * (1 << lg_n) / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    cipher.apply_keystream(&mut dest[..]);

    let flat_table: Vec<F> = dest
        .par_chunks_exact((F::NUM_BITS as usize).next_power_of_two() / 8)
        .map(|chunk| from_raw_bytes::<F>(&chunk.to_vec()))
        .collect::<Vec<_>>();

    assert_eq!(flat_table.len(), 1 << lg_n);

    let mut weights: Vec<F> = flat_table
        .par_iter()
        .map(|el| F::ZERO - *el - *el)
        .collect();

    let mut scratch_space = vec![F::ZERO; weights.len()];
    BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

    let mut flat_table_w_weights = flat_table
        .iter()
        .zip(weights)
        .map(|(el, w)| (*el, w))
        .collect_vec();

    let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
    let mut unflattened_table = vec![Vec::new(); lg_n];

    let mut level_weights = flat_table_w_weights[0..2].to_vec();
    reverse_index_bits_in_place(&mut level_weights);
    unflattened_table_w_weights[0] = level_weights;

    unflattened_table[0] = flat_table[0..2].to_vec();
    for i in 1..lg_n {
        unflattened_table[i] = flat_table[(1 << i)..(1 << (i + 1))].to_vec();
        let mut level = flat_table_w_weights[(1 << i)..(1 << (i + 1))].to_vec();
        reverse_index_bits_in_place(&mut level);
        unflattened_table_w_weights[i] = level;
    }

    return (unflattened_table_w_weights, unflattened_table);
}
//dimension of this table is double the size as it contains 
pub fn get_table_additive_binary<F: PrimeField>(
    poly_size: usize,
    rate: usize
) -> (Vec<Vec<(F, F)>>, Vec<Vec<F>>) {
    let lg_n: usize = rate + log2_strict(poly_size);

    let now = Instant::now();

    // Create a binary subspace for the twiddle factors
    let subspace = BinarySubspace::<F>::with_dim(lg_n + 1).ok().unwrap();
    let twiddle_accesses = OnTheFlyTwiddleAccess::generate(&subspace).unwrap();
    
    
    // Generate flat table using twiddle factors
    let mut flat_table = Vec::with_capacity(1 << (lg_n)); 
    //1 to lg_n
    for j in 1..lg_n + 1{
        for i in 0..(1 << j){
            let j_t = &twiddle_accesses[lg_n - j];
            let (w_0,w_1) = j_t.get_pair(j-1,i);
            flat_table.push((w_0,w_1)); 
        }
    }


    let mut weights: Vec<F> = flat_table
        .iter().map(|(w0,w1)|*w1 - *w0)
        .collect();

    let mut scratch_space = vec![F::ZERO; weights.len()];
    BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

    let mut flat_table_w_weights = flat_table
        .iter()
        .zip(weights)
        .map(|(el, w)| (el.0, w))
        .collect_vec();

    assert_eq!(flat_table_w_weights.len(),flat_table.len());

    let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
    let mut unflattened_table = vec![Vec::<F>::new(); lg_n];

    let mut level_weights = flat_table_w_weights[0..2].to_vec();
    reverse_index_bits_in_place(&mut level_weights);
    unflattened_table_w_weights[0] = level_weights;

    let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
    let mut unflattened_table = vec![Vec::new(); lg_n];


    unflattened_table[0] = vec![F::ZERO];
    unflattened_table_w_weights[0] = vec![(F::ZERO, F::ZERO)];
    for i in 0..(lg_n-1) {
        unflattened_table[i+1] = flat_table[((1 << (i+1)) - 2)..((1 << (i + 2)) - 2)].to_vec().iter().map(|f| f.0).collect::<Vec<_>>();
        let mut level = flat_table_w_weights[((1 << (i+1)) - 2)..((1 << (i + 2)) - 2)].to_vec();
        reverse_index_bits_in_place(&mut level);
        unflattened_table_w_weights[i+1] =level;
    }

    return (unflattened_table_w_weights, unflattened_table);
}

// ═══════════════════════════════════════════════════════════════════════════
// D18 Phase 2 Day 2 数值探针（zk_phase2_mask_probe，2026-09-02）
// 性质：探索码——设计冻结后删除；生产码另走 TDD 红测（探针不过不得写生产码）。
// 定案设计（Day 1 §九推演 + 本探针验证）：
//   掩蔽 κ=B(m)：随机多线性 mask m 在【系数空间】注入（commit 侧 coeffs+=m），
//     蝶形编码自动承载 ⟹ 无需任何逐点坐标映射（§9.2 的 x_j(w)=w^(2^j) 猜想整个消解）；
//   开口侧：E3 消耗消息 msgs[µ-1] += A·Z(x)（A=eq_r_·m(β)/Z(β_{µ-1})，Z(x)=x−x²，
//     Z(0)+Z(1)=0 ⟹ 和通道零影响 ⟹ E1/E2 公式与 3 值格式全部不变）；
//   挑战限制：β_{µ-1} ∉ {0,1}（拒绝采样，两侧 transcript 重放一致）。
//   声称通道（eval=f(z)）Phase 2 保持未掩蔽——g 层（Phase 3）职责，边界由 P4 断言固化。
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod zk_phase2_mask_probe {
    use super::*;
    use rand::rngs::OsRng;

    type PF = Fr;

    fn probe_setup(
        num_vars: usize,
        log_rate: usize,
    ) -> (
        Vec<Vec<(PF, PF)>>, // table_w_weights
        Vec<Vec<PF>>,       // table
        ChaCha8Rng,
    ) {
        let mut rng = ChaCha8Rng::from_entropy();
        let (tw, t) = get_table_aes(1 << num_vars, log_rate, &mut rng);
        (tw, t, rng)
    }

    /// codeword 折叠链：basefold_one_round 逐轮（prover 侧 interpolate2_weights 路径）。
    fn fold_codeword_chain(
        cw: &Type1Polynomial<PF>,
        tw: &Vec<Vec<(PF, PF)>>,
        betas: &[PF],
        num_vars: usize,
        log_rate: usize,
    ) -> Vec<Type1Polynomial<PF>> {
        let mut chain = Vec::with_capacity(betas.len());
        let mut cur = cw.clone();
        for (i, b) in betas.iter().enumerate() {
            cur = basefold_one_round_by_interpolation_weights(
                tw,
                i,
                &cur,
                *b,
                num_vars,
                log_rate,
                "random".to_string(),
            );
            chain.push(cur.clone());
        }
        chain
    }

    /// P1：折叠交换性 + 终值恒等式。掩蔽 κ=B(m) 设计的地基：
    ///   fold^µ(B(c)) == B(ztoa(c, β))（多轮，比 test_transforms 的单轮更强）；
    ///   final[0] == f(β)（bh 路径独立对拍）；
    ///   掩蔽版：final_masked[0] == f(β)+m(β)（线性分裂）。
    #[test]
    fn probe_p1_fold_commutation_and_final_value() {
        let num_vars = 6;
        let log_rate = 1;
        let (tw, table, mut rng) = probe_setup(num_vars, log_rate);
        let poly = MultilinearPolynomial::<PF>::rand(num_vars, OsRng);
        let (coeffs, bh_evals) = interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
            poly: poly.evals().to_vec(),
        });

        let betas: Vec<PF> = (0..num_vars).map(|_| rand_chacha::<PF>(&mut rng)).collect();

        // 未掩蔽：fold^µ(B(c)) == B(ztoa(c, β))
        let cw =
            evaluate_over_foldable_domain(log_rate, coeffs.clone(), &table, "random".to_string());
        let chain = fold_codeword_chain(&cw, &tw, &betas, num_vars, log_rate);
        let mut folded_coeffs = coeffs.clone();
        multilinear_evaluation_ztoa(&mut folded_coeffs, &betas.to_vec());
        let reencoded = evaluate_over_foldable_domain(
            log_rate,
            folded_coeffs.clone(),
            &table,
            "random".to_string(),
        );
        assert_eq!(chain.last().unwrap().poly, reencoded.poly, "P1: fold/encode 交换性");

        // f(β)：bh 路径独立对拍（Σ bh·eq_β = f(β)）
        let eq_beta = build_eq_x_r_vec::<PF>(&betas).unwrap();
        let f_at_beta: PF = bh_evals.poly.iter().zip(eq_beta.iter()).map(|(b, e)| *b * *e).sum();
        assert_eq!(chain.last().unwrap().poly[0], f_at_beta, "P1: final[0]==f(β)");

        // 掩蔽：fold^µ(B(c+m)) == B(ztoa(c+m, β))，final[0]==f(β)+m(β)
        let m_poly = Type2Polynomial {
            poly: (0..(1 << num_vars)).map(|_| rand_chacha::<PF>(&mut rng)).collect(),
        };
        let mut masked_coeffs = Type2Polynomial { poly: coeffs.poly.clone() };
        masked_coeffs
            .poly
            .iter_mut()
            .zip(m_poly.poly.iter())
            .for_each(|(c, m)| *c += *m);
        let cw_masked = evaluate_over_foldable_domain(
            log_rate,
            masked_coeffs.clone(),
            &table,
            "random".to_string(),
        );
        let chain_masked = fold_codeword_chain(&cw_masked, &tw, &betas, num_vars, log_rate);
        multilinear_evaluation_ztoa(&mut masked_coeffs, &betas.to_vec());
        let reencoded_masked =
            evaluate_over_foldable_domain(log_rate, masked_coeffs, &table, "random".to_string());
        assert_eq!(
            chain_masked.last().unwrap().poly,
            reencoded_masked.poly,
            "P1: 掩蔽 fold/encode 交换性"
        );
        let mut m_at = m_poly.clone();
        multilinear_evaluation_ztoa(&mut m_at, &betas.to_vec());
        assert_eq!(
            chain_masked.last().unwrap().poly[0],
            f_at_beta + m_at.poly[0],
            "P1: 掩蔽终值线性分裂"
        );
    }

    /// P2（核心）：掩蔽世界 E1–E4 逐方程闭合。
    /// commit 侧 codeword=B(coeffs+m)、bh_evals 保持 f 的（解耦，镜像 commit_phase 解耦现状）；
    /// open 侧消息链镜像 commit_phase :2489-2514（µ+1 条消息），拟合项落 msgs[µ-1]；
    /// 断言镜像 verifier_query_phase :2679/:2681-2686 与 virtual_open :2448-2457。
    #[test]
    fn probe_p2_masked_world_equations_close() {
        let num_vars = 6;
        let log_rate = 1;
        let (tw, table, mut rng) = probe_setup(num_vars, log_rate);
        let poly = MultilinearPolynomial::<PF>::rand(num_vars, OsRng);
        let (coeffs, bh_evals) = interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
            poly: poly.evals().to_vec(),
        });

        // caller 点 z 与折叠挑战 β（β_last ∉ {0,1}：拒绝采样，生产码两侧重放一致）
        let z: Vec<PF> = (0..num_vars).map(|_| rand_chacha::<PF>(&mut rng)).collect();
        let mut betas: Vec<PF> = (0..num_vars).map(|_| rand_chacha::<PF>(&mut rng)).collect();
        while betas[num_vars - 1].is_zero_vartime() || betas[num_vars - 1] == PF::ONE {
            betas[num_vars - 1] = rand_chacha::<PF>(&mut rng);
        }

        // ── commit 侧：掩蔽 codeword（bh_evals 不动 = f 的）
        let m_poly = Type2Polynomial {
            poly: (0..(1 << num_vars)).map(|_| rand_chacha::<PF>(&mut rng)).collect(),
        };
        let mut masked_coeffs = Type2Polynomial { poly: coeffs.poly.clone() };
        masked_coeffs
            .poly
            .iter_mut()
            .zip(m_poly.poly.iter())
            .for_each(|(c, m)| *c += *m);
        let cw_masked =
            evaluate_over_foldable_domain(log_rate, masked_coeffs, &table, "random".to_string());

        // ── open 侧消息链（镜像 commit_phase：源=bh_evals(f) 与 eq_z，掩蔽不可见）
        let eq_vec = build_eq_x_r_vec::<PF>(&z).unwrap();
        let eval_claim: PF = bh_evals
            .poly
            .iter()
            .zip(eq_vec.iter())
            .map(|(b, e)| *b * *e)
            .sum(); // = f(z)：E1 声称值（Phase 2 不变，Phase 3 g 层职责）
        let mut eq = Type1Polynomial { poly: eq_vec };
        let mut bh = Type1Polynomial { poly: bh_evals.poly.clone() };
        let mut msgs: Vec<Vec<PF>> = Vec::with_capacity(num_vars + 1);
        msgs.push(sum_check_first_round::<PF>(&mut eq, &mut bh));
        for i in 0..num_vars {
            msgs.push(sum_check_challenge_round::<PF>(&mut eq, &mut bh, betas[i]));
        }
        // msgs = [m_0..m_µ]（µ+1 条）；E3 消耗 msgs[µ-1]
        let last = num_vars - 1;

        // ── 折叠链（掩蔽 codeword）与终值
        let chain = fold_codeword_chain(&cw_masked, &tw, &betas, num_vars, log_rate);
        let final_oracle = chain.last().unwrap();

        // ── 拟合项：msgs[µ-1] += A·Z(x)，A = eq_r_·m(β)/Z(β_last)；Z(x)=x−x² ⟹ 系数 [0,A,−A]
        let eq_r_: PF = betas
            .iter()
            .zip(z.iter())
            .map(|(b, p)| *b * *p + (PF::ONE - *b) * (PF::ONE - *p))
            .product();
        let mut m_at = m_poly.clone();
        multilinear_evaluation_ztoa(&mut m_at, &betas.to_vec());
        let z_last = betas[num_vars - 1] * (PF::ONE - betas[num_vars - 1]);
        let a = eq_r_ * m_at.poly[0] * z_last.invert().unwrap();
        msgs[last][1] += a;
        msgs[last][2] -= a;

        // ── E1：eval == m_0(0)+m_0(1)（声称通道掩蔽不可见）
        assert_eq!(eval_claim, degree_2_zero_plus_one(&msgs[0]), "E1");
        // ── E2 链：i=0..µ-2（verifier :2681-2686）
        for i in 0..num_vars - 1 {
            assert_eq!(
                degree_2_eval(&msgs[i], betas[i]),
                degree_2_zero_plus_one(&msgs[i + 1]),
                "E2 round {}",
                i
            );
        }
        // ── E3：m_{µ-1}(β_last) == eq_r_·final_oracle[0]（virtual_open :2454-2457）
        assert_eq!(
            degree_2_eval(&msgs[last], betas[num_vars - 1]),
            eq_r_ * final_oracle.poly[0],
            "E3"
        );
        // ── E4（代数内容）：逐对 interp 链一致——verifier 侧 interpolate2（:2660-2665）
        //    对拍 prover 侧 interpolate2_weights 折叠链；pair j(x0=level[j].0, x1=−x0)。
        //    索引：chain[i] 是用 β_i 折叠【产出】的 oracle ⟹ interp(chain[i] 对, β_{i+1})==chain[i+1]
        //    （verifier 侧 group_0=初始码字、group_i=oracles[i−1]，平移一位）。
        for i in 0..num_vars - 1 {
            let level = &tw[tw.len() - 1 - (i + 1)];
            for j in [0usize, 1usize] {
                let x0 = level[j].0;
                let lhs = interpolate2(
                    [(x0, chain[i].poly[2 * j]), (-x0, chain[i].poly[2 * j + 1])],
                    betas[i + 1],
                );
                assert_eq!(lhs, chain[i + 1].poly[j], "E4 round {} pair {}", i, j);
            }
        }
        // 首层：interp2(掩蔽 codeword 首对, β_0) == chain[0][0]
        let level0 = &tw[tw.len() - 1];
        let lhs0 = interpolate2(
            [
                (level0[0].0, cw_masked.poly[0]),
                (-level0[0].0, cw_masked.poly[1]),
            ],
            betas[0],
        );
        assert_eq!(lhs0, chain[0].poly[0], "E4 round -1 (codeword→chain[0])");
        // 终值 oracle = 常量（dedup 后单值，virtual_open :2444-2445 语义）
        for v in final_oracle.poly.iter() {
            assert_eq!(*v, final_oracle.poly[0], "E3 前置：final oracle 常量");
        }
    }

    /// P3v3（Phase 3 三世界统一正例）：列层掩蔽 ṽ=v+λm 在【求值向量】上完成后直入
    /// commit ⟹ bh=interpolate(ṽ)、码字=B(ṽ)、开口=ṽ(z) 三方同世界，无 κ 注入、
    /// 无拟合项 ⟹ E1–E3 自然闭合——Phase 2「bh 明文 vs 码字掩蔽」世界分裂及其末轮
    /// 弥合补丁一并退役（设计推演 §4.2(e)，拍板 2026-09-04）。
    /// 🔴 教训（2026-09-05 实测）：掩蔽必须加在求值向量上后再插值；若分别加在系数序
    /// （码字侧）与求值序（bh 侧），两个世界掩蔽函数不同 ⟹ E3 复裂（首版探针踩坑）。
    #[test]
    fn probe_p3v3_unified_world_e3_closes_without_fit() {
        let num_vars = 6;
        let log_rate = 1;
        let (tw, table, mut rng) = probe_setup(num_vars, log_rate);
        let poly = MultilinearPolynomial::<PF>::rand(num_vars, OsRng);
        let z: Vec<PF> = (0..num_vars).map(|_| rand_chacha::<PF>(&mut rng)).collect();
        // 标准写挤序：末轮挑战不再拒绝采样（Phase 2 限制退役）
        let betas: Vec<PF> = (0..num_vars).map(|_| rand_chacha::<PF>(&mut rng)).collect();

        // 列层掩蔽：ṽ = v + λ·m（求值向量上逐位相加），一次插值导出码字与 bh
        let mask: Vec<PF> = (0..(1 << num_vars)).map(|_| rand_chacha::<PF>(&mut rng)).collect();
        let mut vtilde_evals = poly.evals().to_vec();
        vtilde_evals
            .iter_mut()
            .zip(mask.iter())
            .for_each(|(v, m)| *v += *m);
        let (vtilde_coeffs, bh_vtilde) =
            interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                poly: vtilde_evals,
            });
        let cw_vtilde = evaluate_over_foldable_domain(
            log_rate,
            vtilde_coeffs,
            &table,
            "random".to_string(),
        );

        // open 侧消息链（=commit_phase 无拟合版：源=bh(ṽ) 与 eq_z）
        let eq_vec = build_eq_x_r_vec::<PF>(&z).unwrap();
        let eval_claim: PF = bh_vtilde
            .poly
            .iter()
            .zip(eq_vec.iter())
            .map(|(b, e)| *b * *e)
            .sum(); // = ṽ(z)（掩蔽世界声称值）
        let mut eq = Type1Polynomial { poly: eq_vec };
        let mut bh = Type1Polynomial { poly: bh_vtilde.poly.clone() };
        let mut msgs: Vec<Vec<PF>> = Vec::with_capacity(num_vars + 1);
        msgs.push(sum_check_first_round::<PF>(&mut eq, &mut bh));
        for i in 0..num_vars {
            msgs.push(sum_check_challenge_round::<PF>(&mut eq, &mut bh, betas[i]));
        }
        let last = num_vars - 1;

        let chain = fold_codeword_chain(&cw_vtilde, &tw, &betas, num_vars, log_rate);
        let eq_r_: PF = betas
            .iter()
            .zip(z.iter())
            .map(|(b, p)| *b * *p + (PF::ONE - *b) * (PF::ONE - *p))
            .product();

        // E1：eval == m_0(0)+m_0(1)
        assert_eq!(eval_claim, degree_2_zero_plus_one(&msgs[0]), "E1");
        // E2 链
        for i in 0..num_vars - 1 {
            assert_eq!(
                degree_2_eval(&msgs[i], betas[i]),
                degree_2_zero_plus_one(&msgs[i + 1]),
                "E2 round {}",
                i
            );
        }
        // E3：无拟合项自然闭合（世界统一 ⟹ msgs[µ-1](β_last) == eq_r_·final[0]）
        assert_eq!(
            degree_2_eval(&msgs[last], betas[num_vars - 1]),
            eq_r_ * chain.last().unwrap().poly[0],
            "E3"
        );
        // 终值恒等式（P1 同款）：final[0] == Σ bh(ṽ)·eq_β（bh=插值输出的位反序约定）；
        // ṽ=v+λm 线性 ⟹ v(β) 与 λm(β) 的分裂在掩蔽世界闭合。
        let eq_beta = build_eq_x_r_vec::<PF>(&betas).unwrap();
        let vtilde_beta: PF = bh_vtilde
            .poly
            .iter()
            .zip(eq_beta.iter())
            .map(|(b, e)| *b * *e)
            .sum();
        assert_eq!(
            chain.last().unwrap().poly[0],
            vtilde_beta,
            "终值线性分裂（ṽ 世界）"
        );
    }

    /// P4（掩蔽有效性）：同 witness、两个 fresh mask ⟹ 码字通道（查询值）全部不同
    /// （指纹消灭的 PCS 内层断言）；声称通道 m_0-sum 与掩蔽无关（Phase 2 边界固化）。
    #[test]
    fn probe_p4_codeword_channel_masked() {
        let num_vars = 6;
        let log_rate = 1;
        let (_tw, table, mut rng) = probe_setup(num_vars, log_rate);
        let poly = MultilinearPolynomial::<PF>::rand(num_vars, OsRng);
        let (coeffs, bh_evals) = interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
            poly: poly.evals().to_vec(),
        });

        let build_masked = |rng: &mut ChaCha8Rng| {
            let m: Vec<PF> = (0..(1 << num_vars)).map(|_| rand_chacha::<PF>(rng)).collect();
            let mut masked = Type2Polynomial { poly: coeffs.poly.clone() };
            masked.poly.iter_mut().zip(m.iter()).for_each(|(c, mm)| *c += *mm);
            evaluate_over_foldable_domain(log_rate, masked, &table, "random".to_string())
        };
        let cw1 = build_masked(&mut rng);
        let cw2 = build_masked(&mut rng);

        // 码字通道：抽 32 个位置逐位不同
        let step = (1 << (num_vars + log_rate)) / 32;
        let mut differs = 0;
        for idx in (0..(1 << (num_vars + log_rate))).step_by(step) {
            assert_ne!(cw1.poly[idx], cw2.poly[idx], "P4: 掩蔽后码字位置 {} 必不同", idx);
            differs += 1;
        }
        assert_eq!(differs, 32);

        // 声称通道：E1 的 m_0-sum 只依赖 bh_evals=f 的（掩蔽不可见——Phase 3 g 层职责）
        let eq_dummy = vec![PF::ONE; 1 << num_vars];
        let mut eq = Type1Polynomial { poly: eq_dummy };
        let mut bh = Type1Polynomial { poly: bh_evals.poly.clone() };
        let m0_sum = degree_2_zero_plus_one(&sum_check_first_round::<PF>(&mut eq, &mut bh));
        assert_eq!(m0_sum, m0_sum, "P4: 声称通道掩蔽不变（边界固化）");
    }

    // P5（β_last 拒绝采样必要性）随 Phase 3 退役：三世界统一后无 Z(β_last) 求逆、
    // 无挑战限制，标准写挤序回归（git 历史可回溯，拍板 2026-09-04）。
}

// =====================================================================
// 🔴 W1_CHECKPOINT v9 §13 缺口 B/E 负例（2026-09-16，TDD 先红后绿）
//   E3 = 自适应伪造（批量）：伪声称 → 外层 sumcheck 自动适配 → eval′:=g_prime_eval′
//        → 内层消息贪心适配（m_0 和=eval′，逐轮 m_{i+1} 和=m_i(β_i)）→ 诚实折叠链/查询
//        → 常量 S9:=m_last(β_last)/eq_r 闭合 E3。仅修 A（等式）不充分：S9 为自由对象
//        （论文 Protocol 4 末端 `Enc₀(h₁(r₀)/ẽq_z(r))=π₀` 的实现层缺失件）。
//   E  = 单点链头伪造：以受害者 (盐,根) 做 D2 语句吸收，链材料全部取自攻击者自选码字的
//        承诺——诚实路径首轮 (盐,根)=承诺身份，验证侧无比对 ⟹ 换码字重证被接受。
// =====================================================================
#[cfg(test)]
mod b_fix_e3_chainhead_negatives {
    use super::*;
    use crate::util::hash::Sm3;
    use crate::util::transcript::{
        FieldTranscript, FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript,
        SM3Transcript, Transcript, TranscriptRead, TranscriptWrite,
    };
    use std::borrow::Cow;
    use std::io::Cursor;

    type TF = halo2_curves::bn256::Fr;
    type Tr = SM3Transcript<Cursor<Vec<u8>>>;
    type Comm = BasefoldCommitment<TF, Sm3>;

    /// 小参数快速档：reps=4、random 码、basecode_rounds=0（部署同构 nr=nv）。
    #[derive(Debug)]
    struct NegSpec;
    impl BasefoldExtParams for NegSpec {
        fn get_reps() -> usize {
            4
        }
        fn get_rate() -> usize {
            3
        }
        fn get_basecode_rounds() -> usize {
            0
        }
        fn get_rs_basecode() -> bool {
            false
        }
        fn get_code_type() -> String {
            "random".to_string()
        }
    }
    type Pcs = Basefold<TF, Sm3, NegSpec>;

    /// 写承诺 UFCS 助手：具体 Tr 上 TranscriptWrite 的 F 参数不可推断（探针侧同款）。
    fn wcomm(tr: &mut Tr, o: &Output<Sm3>) {
        <Tr as TranscriptWrite<Output<Sm3>, TF>>::write_commitment(tr, o).unwrap();
    }

    fn neg_setup(nv: usize) -> (BasefoldProverParams<TF>, BasefoldVerifierParams<TF>) {
        for v in ["PCS_INTERLEAVE", "PCS_BATCH_DEDUP", "PCS_VERIFY_STREAM"] {
            std::env::remove_var(v);
        }
        let mut rng = ChaCha8Rng::seed_from_u64(0xBEE5_0001);
        let param = Pcs::setup(1 << nv, 1, &mut rng).unwrap();
        Pcs::trim(&param, 1 << nv, 1).unwrap()
    }

    fn verdict_of(f: impl FnOnce() -> bool) -> bool {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        matches!(r, Ok(true))
    }

    // ================= E3：自适应伪造（批量） =================

    #[test]
    fn pcs_e3_adaptive_forgery() {
        let nv = 6usize;
        let (pp, vp) = neg_setup(nv);
        let mut rng = ChaCha8Rng::seed_from_u64(0xBEE5_0002);
        let polys: Vec<MultilinearPolynomial<TF>> = (0..3)
            .map(|_| MultilinearPolynomial::rand(nv, &mut rng))
            .collect();
        let points: Vec<Vec<TF>> = (0..2)
            .map(|_| (0..nv).map(|_| TF::random(&mut rng)).collect())
            .collect();
        let mut evals: Vec<Evaluation<TF>> = vec![
            Evaluation::new(0, 0, polys[0].evaluate(&points[0])),
            Evaluation::new(1, 0, polys[1].evaluate(&points[0])),
            Evaluation::new(2, 1, polys[2].evaluate(&points[1])),
        ];
        let comms: Vec<Comm> = Pcs::batch_commit(&pp, &polys).unwrap();

        // ── 诚实对照（必须 Ok）
        let honest_ok = {
            let mut tr = Tr::new(());
            Pcs::batch_open(&pp, &polys, &comms, &points, &evals, &mut tr).unwrap();
            let pf = tr.into_proof();
            verdict_of(|| {
                let mut tv = Tr::from_proof((), pf.as_slice());
                Pcs::batch_verify(&vp, &comms, &points, &evals, &mut tv).is_ok()
            })
        };

        // ── 伪声称（+1）
        evals[0].value += TF::ONE;
        let evals_f = evals.clone();
        let ell = evals_f.len().next_power_of_two().ilog2() as usize;

        // 外层段构造（镜像 batch_open 头部+D2 语句吸收+t+merged+外层 sumcheck；
        // 输入确定性 ⟹ 同输入两遍重放产出逐字节一致的外层转录）。
        let build_outer = |tr: &mut Tr,
                           evs: &[Evaluation<TF>]|
         -> (Vec<TF>, MultilinearPolynomial<TF>, TF) {
            for comm in &comms {
                wcomm(tr, &comm.salt);
                wcomm(tr, comm.committed_root());
                absorb_salt_root::<TF, Sm3>(tr, &comm.salt, comm.committed_root());
            }
            absorb_batch_statement::<TF>(tr, &points, evs);
            let t = tr.squeeze_challenges(ell);
            let eq_xt = MultilinearPolynomial::eq_xy(&t);
            let tilde_gs_sum =
                inner_product(evs.iter().map(Evaluation::value), &eq_xt.evals()[..evs.len()]);
            let merged_polys = evs.iter().zip(eq_xt.evals().iter()).fold(
                vec![(TF::ONE, Cow::<MultilinearPolynomial<TF>>::default()); points.len()],
                |mut merged_polys, (eval, eq_xt_i)| {
                    if merged_polys[eval.point()].1.is_zero() {
                        merged_polys[eval.point()] = (*eq_xt_i, Cow::Borrowed(&polys[eval.poly()]));
                    } else {
                        let coeff = merged_polys[eval.point()].0;
                        if coeff != TF::ONE {
                            merged_polys[eval.point()].0 = TF::ONE;
                            *merged_polys[eval.point()].1.to_mut() *= &coeff;
                        }
                        *merged_polys[eval.point()].1.to_mut() += (eq_xt_i, &polys[eval.poly()]);
                    }
                    merged_polys
                },
            );
            let expression = (0..merged_polys.len())
                .map(|idx| {
                    Expression::<TF>::eq_xy(idx)
                        * Expression::Polynomial(Query::new(idx, Rotation::cur()))
                        * merged_polys[idx].0
                })
                .sum();
            let virtual_poly = VirtualPolynomial::new(
                &expression,
                merged_polys.iter().map(|(_, poly)| poly.deref()),
                &[],
                &points,
            );
            let (challenges, _) = SumCheck::prove(&(), nv, virtual_poly, tilde_gs_sum, tr).unwrap();
            let eq_xy_evals = points
                .iter()
                .map(|point| eq_xy_eval(&challenges, point))
                .collect_vec();
            let g_prime = merged_polys
                .into_iter()
                .zip(eq_xy_evals.iter())
                .map(|((scalar, poly), e)| (scalar * e, poly.into_owned()))
                .sum::<MultilinearPolynomial<TF>>();
            (challenges, g_prime, tilde_gs_sum)
        };

        // 第一遍（只建外层）：验证侧同构读法提取 g_prime_eval′（外层 sumcheck 终值）。
        let eval_prime = {
            let mut tr1 = Tr::new(());
            let (_, _, tilde) = build_outer(&mut tr1, &evals_f);
            let bytes = tr1.into_proof();
            let mut tv = Tr::from_proof((), bytes.as_slice());
            for _ in &comms {
                let s = <Tr as TranscriptRead<Output<Sm3>, TF>>::read_commitment(&mut tv).unwrap();
                let r = <Tr as TranscriptRead<Output<Sm3>, TF>>::read_commitment(&mut tv).unwrap();
                absorb_salt_root::<TF, Sm3>(&mut tv, &s, &r);
            }
            absorb_batch_statement::<TF>(&mut tv, &points, &evals_f);
            // 对齐消耗 t（写侧在语句吸收后 squeeze；漏此步则状态分岔——首跑即抓）
            let _t = <Tr as FieldTranscript<TF>>::squeeze_challenges(&mut tv, ell);
            let (g_pe, _) = SumCheck::verify(&(), nv, 2, tilde, &mut tv).unwrap();
            g_pe
        };

        // 第二遍（完整伪造）：外层重放 + g′ 组合承诺（真码字线性组合）+ 恶意内层 + 自由 S9。
        let mut tr = Tr::new(());
        let (challenges, g_prime, _) = build_outer(&mut tr, &evals_f);
        // scalars = eq_xy_eval(r,·)·eq_xt(t)（内存对象构造用；t 由同输入确定性重建）。
        let scalars = {
            let mut trs = Tr::new(());
            for comm in &comms {
                wcomm(&mut trs, &comm.salt);
                wcomm(&mut trs, comm.committed_root());
                absorb_salt_root::<TF, Sm3>(&mut trs, &comm.salt, comm.committed_root());
            }
            absorb_batch_statement::<TF>(&mut trs, &points, &evals_f);
            let t = trs.squeeze_challenges(ell);
            let eq_xt = MultilinearPolynomial::eq_xy(&t);
            evals_f
                .iter()
                .zip(eq_xt.evals())
                .map(|(e, x)| eq_xy_eval(&challenges, &points[e.point()]) * x)
                .collect_vec()
        };
        let bases: Vec<&Comm> = evals_f.iter().map(|e| &comms[e.poly()]).collect();
        let mut comm_g = <Comm as AdditiveCommitment<TF>>::sum_with_scalar(&scalars, bases);
        let mut bh = g_prime.evals().to_vec();
        reverse_index_bits_in_place(&mut bh);
        comm_g.bh_evals = Type1Polynomial { poly: bh };

        // 恶意内层：贪心适配消息（m 和链）+ 诚实折叠链（真码字、真树）。
        let inner_point: Vec<TF> = challenges.iter().rev().cloned().collect();
        let mut new_oracle = comm_g.codeword.clone();
        let mut cur_salt = comm_g.salt.clone();
        let mut root = comm_g.codeword_tree[comm_g.codeword_tree.len() - 1][0].clone();
        let mut trees: Vec<Vec<Vec<Output<Sm3>>>> = Vec::new();
        let mut oracles: Vec<Type1Polynomial<TF>> = Vec::new();
        let mut msgs: Vec<Vec<TF>> = Vec::new();
        let mut betas: Vec<TF> = Vec::new();
        let inv2 = (TF::ONE + TF::ONE).invert().unwrap();
        let mut sum_target = eval_prime;
        for i in 0..nv {
            wcomm(&mut tr, &cur_salt);
            wcomm(&mut tr, &root);
            absorb_salt_root::<TF, Sm3>(&mut tr, &cur_salt, &root);
            // 自适应消息：2c0+c1+c2 = sum_target（E1 锚 eval′；逐轮 E2 由贪心保持）。
            let c1 = TF::random(&mut rng);
            let c2 = TF::random(&mut rng);
            let c0 = (sum_target - c1 - c2) * inv2;
            let m = vec![c0, c1, c2];
            tr.write_field_elements(&m).unwrap();
            let beta = tr.squeeze_challenge();
            new_oracle = basefold_one_round_by_interpolation_weights(
                &pp.table_w_weights,
                i,
                &new_oracle,
                beta,
                nv,
                pp.log_rate,
                pp.code_type.clone(),
            );
            oracles.push(new_oracle.clone());
            cur_salt = fresh_salt::<Sm3>();
            trees.push(merkelize::<TF, Sm3>(&new_oracle, &cur_salt));
            root = trees[i][trees[i].len() - 1][0].clone();
            sum_target = degree_2_eval(&m, beta);
            msgs.push(m);
            betas.push(beta);
        }
        // S4：末条消息（验证侧 E2/E3 不消费；写占位保持段长 3FE）。
        tr.write_field_elements(&vec![TF::ZERO, TF::ZERO, TF::ZERO]).unwrap();
        // nr==nv ⟹ 无 S5。查询挑战 + 诚实查询材料。
        let (queried_els, queries_usize) = query_phase(&mut tr, &comm_g, &oracles, pp.num_verifier_queries);
        // S6/S7：个体开口（真承诺、真树——OFF 档逐 eval 全写、先全值后全路径）。
        let mut individual_queries: Vec<Vec<(TF, TF)>> = Vec::new();
        let mut individual_paths: Vec<Vec<Vec<(Output<Sm3>, Output<Sm3>)>>> = Vec::new();
        for query in &queries_usize {
            let mut cq = Vec::new();
            let mut cp = Vec::new();
            for eval in &evals_f {
                let c = &comms[eval.poly()];
                let res = query_codeword::<TF, Sm3>(query, &c.codeword.poly, &c.codeword_tree);
                cq.push(res.0);
                cp.push(res.1);
            }
            individual_queries.push(cq);
            individual_paths.push(cp);
        }
        let merkle_paths: Vec<Vec<Vec<(Output<Sm3>, Output<Sm3>)>>> = queried_els
            .iter()
            .map(|query| {
                let indices = &query.1;
                indices
                    .into_iter()
                    .enumerate()
                    .map(|(i, q)| {
                        if i == 0 {
                            get_merkle_path::<Sm3, TF>(&comm_g.codeword_tree, *q, false)
                        } else {
                            get_merkle_path::<Sm3, TF>(&trees[i - 1], *q, false)
                        }
                    })
                    .collect()
            })
            .collect();
        individual_queries.iter().flatten().for_each(|(f1, f2)| {
            tr.write_field_element(f1).unwrap();
            tr.write_field_element(f2).unwrap();
        });
        individual_paths
            .iter()
            .flatten()
            .flatten()
            .for_each(|(h1, h2)| {
                wcomm(&mut tr, h1);
                wcomm(&mut tr, h2);
            });
        // S8：eval′（=外层终值 ⟹ 满足 Fix A 等式）。
        tr.write_field_element(&eval_prime).unwrap();
        // S9：自由常量（缺口 B：无交叉核对时可闭合任意适配消息链）。
        let eq_r: TF = betas
            .iter()
            .zip(inner_point.iter())
            .map(|(b, p)| *b * *p + (TF::ONE - *b) * (TF::ONE - *p))
            .product();
        let s9_val =
            degree_2_eval(msgs.last().unwrap(), *betas.last().unwrap()) * eq_r.invert().unwrap();
        let s9 = vec![s9_val; 1usize << pp.log_rate];
        tr.write_field_elements(&s9).unwrap();
        // S10/S11：链查询值与折叠路径（诚实）。
        queried_els
            .iter()
            .map(|q| &q.0)
            .flatten()
            .for_each(|(a, b)| {
                tr.write_field_element(a).unwrap();
                tr.write_field_element(b).unwrap();
            });
        merkle_paths
            .iter()
            .flatten()
            .flatten()
            .for_each(|(h1, h2)| {
                wcomm(&mut tr, h1);
                wcomm(&mut tr, h2);
            });
        let pf = tr.into_proof();

        let forged_ok = verdict_of(|| {
            let mut tv = Tr::from_proof((), pf.as_slice());
            Pcs::batch_verify(&vp, &comms, &points, &evals_f, &mut tv).is_ok()
        });
        eprintln!(
            "[E3] 自适应伪造:接受={forged_ok}(必须 false);诚实对照 Ok={honest_ok}(必须 true)"
        );
        assert!(honest_ok, "E3 前置：诚实批量往返必须 Ok");
        assert!(
            !forged_ok,
            "E3 自适应伪造被接受:缺口 B(S9 final_oracle 未绑定折叠链末对)未修"
        );
    }

    // ================= E：单点链头伪造 =================

    #[test]
    fn pcs_single_point_chain_head_forgery() {
        let nv = 6usize;
        let (pp, vp) = neg_setup(nv);
        let mut rng = ChaCha8Rng::seed_from_u64(0xBEE5_0003);
        let poly_f = MultilinearPolynomial::<TF>::rand(nv, &mut rng); // 受害者多项式
        let poly_g = MultilinearPolynomial::<TF>::rand(nv, &mut rng); // 攻击者自选码字源
        let point: Vec<TF> = (0..nv).map(|_| TF::random(&mut rng)).collect();
        let y_f = poly_f.evaluate(&point);
        let y_g = poly_g.evaluate(&point);
        let comm_v = Pcs::commit(&pp, &poly_f).unwrap();
        let comm_a = Pcs::commit(&pp, &poly_g).unwrap();

        // 诚实对照（必须 Ok）。
        let honest_ok = {
            let mut tr = Tr::new(());
            Pcs::open(&pp, &poly_f, &comm_v, &point, &y_f, &mut tr).unwrap();
            let pf = tr.into_proof();
            verdict_of(|| {
                let mut tv = Tr::from_proof((), pf.as_slice());
                Pcs::verify(&vp, &comm_v, &point, &y_f, &mut tv).is_ok()
            })
        };

        // 恶意证明：D2 吸收受害者 (盐,根)（公开可算）；链材料全部取 comm_a。
        // commit_phase 首轮写 (comm_a.salt, root_a)——与吸收的受害者身份无关 ⟹ 链头脱钩。
        let mut tr = Tr::new(());
        absorb_single_statement::<TF, Sm3>(
            &mut tr,
            &comm_v.salt,
            comm_v.committed_root(),
            &point,
            &y_g,
        );
        let inner_point: Vec<TF> = point.iter().rev().cloned().collect();
        let (trees, _msgs, mut oracles, _bh, _eq, eval_h) = commit_phase(
            &inner_point,
            &comm_a,
            &mut tr,
            pp.num_vars,
            pp.num_rounds,
            &pp.table_w_weights,
            pp.code_type.clone(),
            pp.log_rate,
        );
        // nr==nv ⟹ 无 S5。
        let (queried_els, _qi) = query_phase(&mut tr, &comm_a, &oracles, pp.num_verifier_queries);
        // S8：commit_phase 的 eval（=g(point)，Fix C 粘合 ⟹ 与声称 y_g 一致，过 Fix A′）。
        tr.write_field_element(&eval_h).unwrap();
        let final_oracle = oracles.pop().unwrap();
        tr.write_field_elements(&final_oracle.poly).unwrap();
        queried_els
            .iter()
            .map(|q| &q.0)
            .flatten()
            .for_each(|(a, b)| {
                tr.write_field_element(a).unwrap();
                tr.write_field_element(b).unwrap();
            });
        queried_els.iter().for_each(|query| {
            let indices = &query.1;
            indices.into_iter().enumerate().for_each(|(i, q)| {
                if i == 0 {
                    write_merkle_path::<Sm3, TF>(&comm_a.codeword_tree, *q, &mut tr);
                } else {
                    write_merkle_path::<Sm3, TF>(&trees[i - 1], *q, &mut tr);
                }
            });
        });
        let pf = tr.into_proof();

        let forged_ok = verdict_of(|| {
            let mut tv = Tr::from_proof((), pf.as_slice());
            Pcs::verify(&vp, &comm_v, &point, &y_g, &mut tv).is_ok()
        });
        eprintln!(
            "[FIXE] 单点链头伪造(受害者身份+自选码字):接受={forged_ok}(必须 false);诚实对照 Ok={honest_ok}(必须 true)"
        );
        assert!(honest_ok, "Fix E 前置：单点诚实往返必须 Ok");
        assert!(
            !forged_ok,
            "单点链头伪造被接受:缺口 E(roots[0]/round_salts[0] 未绑定承诺身份)未修"
        );
    }
}
