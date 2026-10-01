#![allow(warnings, unused)]
use crate::{
    backend::{
        hyperplonk::{
            preprocessor::{batch_size, compose_masked, permutation_polys, MaskLayout},
            prover::{
                instance_polys, lookup_compressed_polys, lookup_h_polys, lookup_m_polys,
                permutation_z_polys, prove_zero_check,
            },
            verifier::verify_zero_check,
        },
        PlonkishBackend, PlonkishCircuit, PlonkishCircuitInfo, WitnessEncoding,
    },
    pcs::PolynomialCommitmentScheme,
    poly::multilinear::MultilinearPolynomial,
    util::{
        arithmetic::{powers, BooleanHypercube, PrimeField},
        end_timer,
        expression::Expression,
        start_timer,
        transcript::{TranscriptRead, TranscriptWrite},
        Deserialize, DeserializeOwned, Itertools, Serialize,
    },
    Error,
};
use std::time::Instant;
use rand::RngCore;
use std::{fmt::Debug, hash::Hash, iter, marker::PhantomData};

pub mod preprocessor;
pub(crate) mod prover;
pub(crate) mod verifier;

#[cfg(any(test, feature = "benchmark"))]
pub mod util;

#[derive(Clone, Debug)]
pub struct HyperPlonk<Pcs>(PhantomData<Pcs>);

impl<F, Pcs> HyperPlonkVerifierParam<F, Pcs>
where
    F: PrimeField + serde::Serialize,
    Pcs: PolynomialCommitmentScheme<F>,
{
    /// R1 内存归因探针：vp 各字段 bincode 尺寸（仅诊断打印——证明/验证路径零参与）。
    pub fn debug_field_sizes(&self) -> String {
        fn sz(v: &impl serde::Serialize) -> usize {
            bincode::serialize(v).map(|b| b.len()).unwrap_or(usize::MAX)
        }
        format!(
            "pcs={} expression={} mask_lambda={} preprocess_comms={} permutation_comms={} \
             num_inst={} wit={} chall={} lookups={} nz={} nv={}",
            sz(&self.pcs),
            sz(&self.expression),
            sz(&self.mask_layout),
            sz(&self.preprocess_comms),
            sz(&self.permutation_comms),
            sz(&self.num_instances),
            sz(&self.num_witness_polys),
            sz(&self.num_challenges),
            sz(&self.num_lookups),
            sz(&self.num_permutation_z_polys),
            sz(&self.num_vars),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HyperPlonkProverParam<F, Pcs>
where
    F: PrimeField,
    Pcs: PolynomialCommitmentScheme<F>,
{
    pub(crate) pcs: Pcs::ProverParam,
    pub(crate) num_instances: Vec<usize>,
    pub(crate) num_witness_polys: Vec<usize>,
    pub(crate) num_challenges: Vec<usize>,
    pub(crate) lookups: Vec<Vec<(Expression<F>, Expression<F>)>>,
    pub(crate) num_permutation_z_polys: usize,
    pub(crate) num_vars: usize,
    pub(crate) expression: Expression<F>,
    pub(crate) mask_layout: MaskLayout,
    pub(crate) preprocess_polys: Vec<MultilinearPolynomial<F>>,
    pub(crate) preprocess_comms: Vec<Pcs::Commitment>,
    pub(crate) permutation_polys: Vec<(usize, MultilinearPolynomial<F>)>,
    pub(crate) permutation_comms: Vec<Pcs::Commitment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HyperPlonkVerifierParam<F, Pcs>
where
    F: PrimeField,
    Pcs: PolynomialCommitmentScheme<F>,
{
    pub(crate) pcs: Pcs::VerifierParam,
    pub(crate) num_instances: Vec<usize>,
    pub(crate) num_witness_polys: Vec<usize>,
    pub(crate) num_challenges: Vec<usize>,
    pub(crate) num_lookups: usize,
    pub(crate) num_permutation_z_polys: usize,
    pub(crate) num_vars: usize,
    pub(crate) expression: Expression<F>,
    pub(crate) mask_layout: MaskLayout,
    pub(crate) preprocess_comms: Vec<Pcs::Commitment>,
    pub(crate) permutation_comms: Vec<(usize, Pcs::Commitment)>,
}

impl<F, Pcs> PlonkishBackend<F> for HyperPlonk<Pcs>
where
    F: PrimeField + Hash + Serialize + DeserializeOwned,
    Pcs: PolynomialCommitmentScheme<F, Polynomial = MultilinearPolynomial<F>>,
{
    type Pcs = Pcs;
    type ProverParam = HyperPlonkProverParam<F, Pcs>;
    type VerifierParam = HyperPlonkVerifierParam<F, Pcs>;

    fn setup(
        circuit_info: &PlonkishCircuitInfo<F>,
        rng: impl RngCore,
    ) -> Result<Pcs::Param, Error> {
        assert!(circuit_info.is_well_formed());

        let num_vars = circuit_info.k;
        let poly_size = 1 << num_vars;
        let batch_size = batch_size(circuit_info);
        Pcs::setup(poly_size, batch_size, rng)
    }

    fn preprocess(
        param: &Pcs::Param,
        circuit_info: &PlonkishCircuitInfo<F>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        assert!(circuit_info.is_well_formed());

        let num_vars = circuit_info.k;
        let poly_size = 1 << num_vars;
        let batch_size = batch_size(circuit_info);
        let (pcs_pp, pcs_vp) = Pcs::trim(param, poly_size, batch_size)?;


        // Compute preprocesses comms
        let preprocess_polys = circuit_info
            .preprocess_polys
            .iter()
            .cloned()
            .map(MultilinearPolynomial::new)
            .collect_vec();


        // 2026-09-16 分相修复：预处理承诺=验证密钥的一部分，盐由 setup 种子确定性派生
        // （batch_commit_public，domain 0/1 分离两条盐链）⟹ 验证进程可按同一种子重建；
        // 见证相承诺（prove 内 batch_commit_and_write）盐保持新鲜，不走此路径。
        let preprocess_comms = Pcs::batch_commit_public(&pcs_pp, 0, &preprocess_polys)?;


        // Compute permutation polys and comms
        let permutation_polys = permutation_polys(
            num_vars,
            &circuit_info.permutation_polys(),
            &circuit_info.permutations,
        );
        let permutation_comms = Pcs::batch_commit_public(&pcs_pp, 1, &permutation_polys)?;

        // Compose `VirtualPolynomialInfo`
        // D18 Phase 3：表达式追加 ρ·eq·m 掩蔽项，并给出 m 列/λ 槽位布局。
        let (num_permutation_z_polys, expression, mask_layout) = compose_masked(circuit_info);
        // R1 内存优化（2026-09-21 归因表 #7/#8）：vp 承诺=验证面视图（盐+根+组位），
        // 不克隆码字/bh 载荷——batch_verify 消费面只读根（审计在案）；vp 序列化
        // 缓冲与驻留双省（AUTH：vp 文件 2.28GB→约 22MB、内存 −1.80GB）。
        // pp 保留全量承诺（batch_open 查询相消费码字）。
        let vp = HyperPlonkVerifierParam {
            pcs: pcs_vp,
            num_instances: circuit_info.num_instances.clone(),
            num_witness_polys: circuit_info.num_witness_polys.clone(),
            num_challenges: circuit_info.num_challenges.clone(),
            num_lookups: circuit_info.lookups.len(),
            num_permutation_z_polys,
            num_vars,
            expression: expression.clone(),
            mask_layout: mask_layout.clone(),
            preprocess_comms: preprocess_comms
                .iter()
                .map(|comm| Pcs::commitment_verifier_view(comm))
                .collect(),
            permutation_comms: circuit_info
                .permutation_polys()
                .into_iter()
                .zip(permutation_comms.iter().map(|comm| Pcs::commitment_verifier_view(comm)))
                .collect(),
        };
        let pp = HyperPlonkProverParam {
            pcs: pcs_pp,
            num_instances: circuit_info.num_instances.clone(),
            num_witness_polys: circuit_info.num_witness_polys.clone(),
            num_challenges: circuit_info.num_challenges.clone(),
            lookups: circuit_info.lookups.clone(),
            num_permutation_z_polys,
            num_vars,
            expression,
            mask_layout,
            preprocess_polys,
            preprocess_comms,
            permutation_polys: circuit_info
                .permutation_polys()
                .into_iter()
                .zip(permutation_polys)
                .collect(),
            permutation_comms,
        };
        Ok((pp, vp))
    }

    fn prove(
        pp: &Self::ProverParam,
        circuit: &impl PlonkishCircuit<F>,
        transcript: &mut impl TranscriptWrite<Pcs::CommitmentChunk, F>,
        _rng: impl RngCore,
    ) -> Result<(), Error> {
        // 🔴 D18 Phase 3 熵源纪律（T1.3b 同族教训，2026-09-05 首版缺陷当场修正）：
        // λ/m 必须用【内部独立熵源 OsRng】，不得用调用方 rng——生产调用方传固定
        // 种子（如 StdRng::seed_from_u64(0x5317_0002)）⟹ λ 向量明文写转录、跨证明
        // 恒同 ⟹ 全局可链接（比未盐化指纹更糟）。Phase 2 mask_seed 的「必须独立
        // 熵源」教训逐字适用：PRG(调用方 rng)=指纹回归。
        let instance_polys = {
            let instances = circuit.instances();
            for (num_instances, instances) in pp.num_instances.iter().zip_eq(instances) {
                assert_eq!(instances.len(), *num_instances);
                for instance in instances.iter() {
                    transcript.common_field_element(instance)?;
                }
            }
            instance_polys(pp.num_vars, instances)
        };

        // D18 Phase 3（协议层 HVZK，拍板 2026-09-04）：λ_i fresh 生成并先行上链
        //（纯随机量零泄漏），m 列 fresh 生成并独立承诺。两者先于全部 witness
        // 承诺与 β/γ/α/y/ρ 挤出 ⟹ FS 链「承诺先于挑战」，敌手无法事后适配。
        use ff::Field;
        // #13 掩蔽消融开关（ablation/mask-toggle 分支，srv A/B 专用）：
        // MASK_OFF 置位 ⟹ λ_i≡0 且 m≡0 ⟹ ṽ=v（承诺=明文见证）。
        // 证明布局/尺寸/验证路径与掩蔽态逐字节同构，验证方零改动；
        // 消融测量值=prove 时间差（尺寸差恒为 0 由布局同构保证）。
        let mask_off = std::env::var("MASK_OFF").is_ok();
        let mut mask_rng = rand::rngs::OsRng;
        let mut lambdas = Vec::with_capacity(pp.mask_layout.num_masked);
        for _ in 0..pp.mask_layout.num_masked {
            lambdas.push(if mask_off { F::ZERO } else { F::random(&mut mask_rng) });
        }
        transcript.write_field_elements(&lambdas)?;
        let mask_poly = if mask_off {
            MultilinearPolynomial::new(vec![F::ZERO; 1 << pp.num_vars])
        } else {
            MultilinearPolynomial::rand(pp.num_vars, &mut mask_rng)
        };
        let mask_comm = Pcs::batch_commit_and_write(&pp.pcs, [&mask_poly], transcript)?;

        // witness 列承诺=掩蔽世界 ṽ=v+λ_i·m；明文列仅入 sumcheck，不入任何开口。
        let mut witness_polys = Vec::with_capacity(pp.num_witness_polys.iter().sum());
        let mut witness_masked_polys = Vec::with_capacity(witness_polys.len());
        let mut witness_comms = Vec::with_capacity(witness_polys.len());
        let mut challenges = Vec::with_capacity(pp.num_challenges.iter().sum::<usize>() + 4);
        let mut lambda_slot = 0;
        for (round, (num_witness_polys, num_challenges)) in pp
            .num_witness_polys
            .iter()
            .zip_eq(pp.num_challenges.iter())
            .enumerate()
        {
            let timer = start_timer(|| format!("witness_collector-{round}"));
            let polys = circuit
                .synthesize(round, &challenges)?
                .into_iter()
                .map(MultilinearPolynomial::new)
                .collect_vec();
            assert_eq!(polys.len(), *num_witness_polys);
            end_timer(timer);

            let masked = polys
                .iter()
                .zip(lambdas[lambda_slot..].iter())
                .map(|(v, l)| v + &(&mask_poly * l))
                .collect_vec();
            lambda_slot += masked.len();
            witness_comms.extend(Pcs::batch_commit_and_write(&pp.pcs, &masked, transcript)?);
            witness_polys.extend(polys);
            witness_masked_polys.extend(masked);
            challenges.extend(transcript.squeeze_challenges(*num_challenges));
        }
        let polys = iter::empty()
            .chain(instance_polys.iter())
            .chain(pp.preprocess_polys.iter())
            .chain(witness_polys.iter())
            .collect_vec();

        // Round n

        let beta = transcript.squeeze_challenge();

        let timer = start_timer(|| format!("lookup_compressed_polys-{}", pp.lookups.len()));
        let lookup_compressed_polys = {
            let max_lookup_width = pp.lookups.iter().map(Vec::len).max().unwrap_or_default();
            let betas = powers(beta).take(max_lookup_width).collect_vec();
            lookup_compressed_polys(&pp.lookups, &polys, &challenges, &betas)
        };
        end_timer(timer);

        let timer = start_timer(|| format!("lookup_m_polys-{}", pp.lookups.len()));
        let lookup_m_polys = lookup_m_polys(&lookup_compressed_polys)?;
        end_timer(timer);

        // D18 Phase 3：lookup m 列同为 witness 派生 ⟹ 掩蔽承诺。
        let lookup_m_masked = lookup_m_polys
            .iter()
            .zip(lambdas[lambda_slot..].iter())
            .map(|(v, l)| v + &(&mask_poly * l))
            .collect_vec();
        lambda_slot += lookup_m_masked.len();
        let lookup_m_comms = Pcs::batch_commit_and_write(&pp.pcs, &lookup_m_masked, transcript)?;

        // Round n+1

        let gamma = transcript.squeeze_challenge();

        let timer = start_timer(|| format!("lookup_h_polys-{}", pp.lookups.len()));
        let lookup_h_polys = lookup_h_polys(&lookup_compressed_polys, &lookup_m_polys, &gamma);
        end_timer(timer);

        let timer = start_timer(|| format!("permutation_z_polys-{}", pp.permutation_polys.len()));
        let permutation_z_polys = permutation_z_polys(
            pp.num_permutation_z_polys,
            &pp.permutation_polys,
            &polys,
            &beta,
            &gamma,
        );
        end_timer(timer);

        // D18 Phase 3：lookup h 列与置换 z 列同为 witness 派生 ⟹ 掩蔽承诺
        //（z 开口是 witness 的确定性泛函，不去掩则跨出示累积泄漏通道不闭，§三）。
        let lookup_h_permutation_z_polys = iter::empty()
            .chain(lookup_h_polys.iter())
            .chain(permutation_z_polys.iter())
            .collect_vec();
        let lookup_h_permutation_z_masked = lookup_h_polys
            .iter()
            .chain(permutation_z_polys.iter())
            .zip(lambdas[lambda_slot..].iter())
            .map(|(v, l)| v + &(&mask_poly * l))
            .collect_vec();
        lambda_slot += lookup_h_permutation_z_masked.len();
        assert_eq!(lambda_slot, pp.mask_layout.num_masked);
        let lookup_h_permutation_z_comms =
            Pcs::batch_commit_and_write(&pp.pcs, &lookup_h_permutation_z_masked, transcript)?;

        // Round n+2

        let alpha = transcript.squeeze_challenge();
        let y = transcript.squeeze_challenges(pp.num_vars);

        let polys = iter::empty()
            .chain(polys)
            .chain(pp.permutation_polys.iter().map(|(_, poly)| poly))
            .chain(lookup_m_polys.iter())
            .chain(lookup_h_permutation_z_polys)
            .chain([&mask_poly])
            .collect_vec();
        let open_polys = iter::empty()
            .chain(instance_polys.iter())
            .chain(pp.preprocess_polys.iter())
            .chain(witness_masked_polys.iter())
            .chain(pp.permutation_polys.iter().map(|(_, poly)| poly))
            .chain(lookup_m_masked.iter())
            .chain(lookup_h_permutation_z_masked.iter())
            .chain([&mask_poly])
            .collect_vec();
        challenges.extend([beta, gamma, alpha]);
	let sumcheck_time = Instant::now();

        // D18 Phase 3：m(y) 先行上链（先于 ρ 挤出）⟹ sumcheck 初始和=ρ·m(y)
        // 由承诺 m 在点 y 的开口钉死，敌手无法为零和通道虚配掩蔽值。
        let m_y = mask_poly.evaluate(&y);
        transcript.write_field_element(&m_y)?;
        let rho = transcript.squeeze_challenge();
        challenges.push(rho);

        let (points, evals) = prove_zero_check(
            pp.num_instances.len(),
            &pp.expression,
            &polys,
            &open_polys,
            rho * m_y,
            challenges,
            y,
            m_y,
            pp.mask_layout.mask_poly,
            transcript,
        )?;

        // PCS open（全部在掩蔽世界：开口列=ṽ/m，承诺=对应掩蔽承诺+m 承诺）

        let dummy_comm = Pcs::Commitment::default();
        let comms = iter::empty()
            .chain(iter::repeat(&dummy_comm).take(pp.num_instances.len()))
            .chain(&pp.preprocess_comms)
            .chain(&witness_comms)
            .chain(&pp.permutation_comms)
            .chain(&lookup_m_comms)
            .chain(&lookup_h_permutation_z_comms)
            .chain(mask_comm.iter())
            .collect_vec();
        let timer = start_timer(|| format!("pcs_batch_open-{}", evals.len()));
	let now = Instant::now();
        Pcs::batch_open(&pp.pcs, open_polys, comms, &points, &evals, transcript)?;

        end_timer(timer);

        Ok(())
    }

    fn verify(
        vp: &Self::VerifierParam,
        instances: &[Vec<F>],
        transcript: &mut impl TranscriptRead<Pcs::CommitmentChunk, F>,
        _: impl RngCore,
    ) -> Result<(), Error> {
        for (num_instances, instances) in vp.num_instances.iter().zip_eq(instances) {
            assert_eq!(instances.len(), *num_instances);
            for instance in instances.iter() {
                transcript.common_field_element(instance)?;
            }
        }

        // D18 Phase 3：λ 读入 + m 列承诺读入（与 prove 写序逐位对齐）。
        let lambdas = transcript.read_field_elements(vp.mask_layout.num_masked)?;
        let mask_comms = Pcs::read_commitments(&vp.pcs, 1, transcript)?;

        // Round 0..n

        let mut witness_comms = Vec::with_capacity(vp.num_witness_polys.iter().sum());
        let mut challenges = Vec::with_capacity(vp.num_challenges.iter().sum::<usize>() + 4);
        for (num_polys, num_challenges) in
            vp.num_witness_polys.iter().zip_eq(vp.num_challenges.iter())
        {
            witness_comms.extend(Pcs::read_commitments(&vp.pcs, *num_polys, transcript)?);
            challenges.extend(transcript.squeeze_challenges(*num_challenges));
        }

        // Round n

        let beta = transcript.squeeze_challenge();

        let lookup_m_comms = Pcs::read_commitments(&vp.pcs, vp.num_lookups, transcript)?;

        // Round n+1

        let gamma = transcript.squeeze_challenge();

        let lookup_h_permutation_z_comms = Pcs::read_commitments(
            &vp.pcs,
            vp.num_lookups + vp.num_permutation_z_polys,
            transcript,
        )?;

        // Round n+2

        let alpha = transcript.squeeze_challenge();
        let y = transcript.squeeze_challenges(vp.num_vars);

        challenges.extend([beta, gamma, alpha]);

        // D18 Phase 3：m(y) 先行读入（先于 ρ）⟹ sumcheck 初始和由承诺 m 钉死。
        let m_y = transcript.read_field_element()?;
        let rho = transcript.squeeze_challenge();
        challenges.push(rho);

        let (points, evals) = verify_zero_check(
            vp.num_vars,
            &vp.expression,
            instances,
            &challenges,
            &y,
            rho * m_y,
            &lambdas,
            m_y,
            &vp.mask_layout,
            transcript,
        )?;

        // PCS verify（承诺链尾接 m 承诺，与 prove 的 batch_open 顺序一致）

        let dummy_comm = Pcs::Commitment::default();
        let comms = iter::empty()
            .chain(iter::repeat(&dummy_comm).take(vp.num_instances.len()))
            .chain(&vp.preprocess_comms)
            .chain(&witness_comms)
            .chain(vp.permutation_comms.iter().map(|(_, comm)| comm))
            .chain(&lookup_m_comms)
            .chain(&lookup_h_permutation_z_comms)
            .chain(mask_comms.iter())
            .collect_vec();
        Pcs::batch_verify(&vp.pcs, comms, &points, &evals, transcript)?;
        let mut waste = 0;
	while(transcript.read_commitment().is_ok()){
		waste = waste + 1;
	}

        Ok(())
    }
}

impl<Pcs> WitnessEncoding for HyperPlonk<Pcs> {
    fn row_mapping(k: usize) -> Vec<usize> {
        BooleanHypercube::new(k).iter().skip(1).chain([0]).collect()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        backend::{
            hyperplonk::{
                util::{rand_vanilla_plonk_circuit, rand_vanilla_plonk_with_lookup_circuit},
                HyperPlonk,
            },
            test::run_plonkish_backend,
        },
        pcs::{
            multilinear::{
                Gemini, MultilinearBrakedown, MultilinearHyrax, MultilinearIpa, MultilinearKzg,
                Zeromorph, Basefold
            },
            univariate::UnivariateKzg,
        },
        util::{
            code::BrakedownSpec6, hash::Keccak256, test::seeded_std_rng,
            transcript::Keccak256Transcript,
        },
    };
    use halo2_curves::{
        bn256::{self, Bn256},
        grumpkin,
    };

    macro_rules! tests {
        ($name:ident, $pcs:ty, $num_vars_range:expr) => {
            paste::paste! {
                #[test]
                fn [<$name _hyperplonk_vanilla_plonk>]() {
                    run_plonkish_backend::<_, HyperPlonk<$pcs>, Keccak256Transcript<_>, _>($num_vars_range, |num_vars| {
                        rand_vanilla_plonk_circuit(num_vars, seeded_std_rng(), seeded_std_rng())
                    });
                }

                #[test]
                fn [<$name _hyperplonk_vanilla_plonk_with_lookup>]() {
                    run_plonkish_backend::<_, HyperPlonk<$pcs>, Keccak256Transcript<_>, _>($num_vars_range, |num_vars| {
                        rand_vanilla_plonk_with_lookup_circuit(num_vars, seeded_std_rng(), seeded_std_rng())
                    });
                }
            }
        };
        ($name:ident, $pcs:ty) => {
            tests!($name, $pcs, 2..16);
        };
    }

//    tests!(basefold, Basefold<bn256::Fr, Keccak256>);
    // D18 Phase 3：掩蔽层 e2e 门（小规模档 2..9；vanilla plonk 含置换 ⟹ z 列掩蔽
    // 路径同测，with_lookup 变体 ⟹ lookup m/h 列掩蔽路径同测）。
    #[derive(Debug)]
    pub struct Phase3Spec {}
    impl crate::pcs::multilinear::BasefoldExtParams for Phase3Spec {
        fn get_reps() -> usize { 2 }
        fn get_rate() -> usize { 1 }
        fn get_basecode_rounds() -> usize { 0 }
        fn get_rs_basecode() -> bool { false }
        fn get_code_type() -> String { "random".to_string() }
    }
    tests!(basefold_phase3, Basefold<bn256::Fr, Keccak256, Phase3Spec>, 2..9);
//    tests!(brakedown, MultilinearBrakedown<bn256::Fr, Keccak256, BrakedownSpec6>);

    // ── D18 Phase 3 §五#6：sumcheck 轮消息线性余量对拍（同挑战重放逐位相等）──
    // 轮消息 = L(v) + ρ·G(m)（对 m 列线性、对 witness 列仿射）。固定挑战
    // transcript 下四组重放：msgs(v,m) − msgs(v,0) == msgs(0,m) − msgs(0,0)
    // == ρ·G(m) 对任意 witness 逐位成立 ⟹ 轮消息对 witness 的依赖可被均匀
    // fresh m 的贡献完全覆盖（模拟器=诚实 prover 于 witness-0+fresh mask，
    // 正文 HVZK 混合步轮消息面支柱的机械对应物）。
    // ── D18 Phase 3 §五#1：跨证明掩蔽新鲜度门（固定种子双证明对拍）──
    // 生产调用方传固定种子 rng（pilink e2e 同款）⟹ λ/m 若取自调用方 rng 则
    // 转录中 λ 明文段跨证明恒同 = 全局可链接（T1.3b 同族缺陷）。本门强制：
    // 同 witness、同固定种子两次 prove，转录前段（实例+λ 区，先于任何盐化
    // 承诺）必须不同 ⟹ λ/m 来自内部独立熵源。
    #[test]
    fn phase3_mask_freshness_fixed_seed_two_proofs() {
        use crate::{
            backend::{PlonkishBackend, PlonkishCircuit},
            pcs::multilinear::Basefold,
            util::{
                hash::Keccak256,
                test::seeded_std_rng,
                transcript::{InMemoryTranscript, Keccak256Transcript},
            },
        };
        use halo2_curves::bn256::Fr;
        use rand::SeedableRng;

        let num_vars = 3;
        let (circuit_info, circuit) =
            rand_vanilla_plonk_circuit(num_vars, seeded_std_rng(), seeded_std_rng());
        type F3 = Basefold<Fr, Keccak256, Phase3Spec>;
        type T3 = Keccak256Transcript<std::io::Cursor<Vec<u8>>>;
        let param = <HyperPlonk<F3> as PlonkishBackend<Fr>>::setup(
            &circuit_info,
            rand::rngs::StdRng::seed_from_u64(7),
        )
        .unwrap();
        let (pp, vp) = <HyperPlonk<F3> as PlonkishBackend<Fr>>::preprocess(
            &param, &circuit_info,
        )
        .unwrap();
        // λ 段前布局：实例 2 值 ×32B；λ = num_masked ×32B（wit 3 + z 1，vanilla plonk 无 lookup）
        let num_masked = pp.mask_layout.num_masked;
        assert_eq!(num_masked, 4, "vanilla plonk@3 掩蔽列 = wit 3 + z 1");
        let early_region = 2 * 32 + num_masked * 32;

        let prove_once = || {
            let mut tr = T3::new(());
            <HyperPlonk<F3> as PlonkishBackend<Fr>>::prove(
                &pp,
                &circuit,
                &mut tr,
                rand::rngs::StdRng::seed_from_u64(0x5317_0002u64), // 生产同款固定种子
            )
            .unwrap();
            tr.into_proof()
        };
        let p1 = prove_once();
        let p2 = prove_once();
        assert_ne!(p1, p2, "两次证明必须不同");
        let first_diff = p1
            .iter()
            .zip(p2.iter())
            .position(|(a, b)| a != b)
            .expect("proofs differ");
        assert!(
            first_diff < early_region,
            "首差异位于 {first_diff}，但须落在实例+λ 区（<{early_region}）⟹ λ 跨证明恒同=指纹回归"
        );
        // 双证明均须验证通过（掩蔽路径正确性不受新鲜度门影响）
        for proof in [&p1, &p2] {
            let result = <HyperPlonk<F3> as PlonkishBackend<Fr>>::verify(
                &vp,
                circuit.instances(),
                &mut T3::from_proof((), proof.as_slice()),
                rand::rngs::StdRng::seed_from_u64(99),
            );
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn phase3_sumcheck_msgs_linear_residual() {
        use crate::{
            poly::multilinear::MultilinearPolynomial,
            util::{
                expression::{Expression, Query, Rotation},
                transcript::{FieldTranscript, FieldTranscriptWrite},
            },
        };
        use ff::Field;
        use halo2_curves::bn256::Fr;

        struct MockTr<F> {
            challenge: F,
            sink: Vec<F>,
        }
        impl<F: Field> crate::util::transcript::FieldTranscript<F> for MockTr<F> {
            fn squeeze_challenge(&mut self) -> F {
                self.challenge
            }
            fn common_field_element(&mut self, _fe: &F) -> Result<(), crate::Error> {
                Ok(())
            }
        }
        impl<F: Field> FieldTranscriptWrite<F> for MockTr<F> {
            fn write_field_element(&mut self, fe: &F) -> Result<(), crate::Error> {
                self.sink.push(*fe);
                Ok(())
            }
        }

        let num_vars = 3;
        let rand_poly = || MultilinearPolynomial::<Fr>::rand(num_vars, seeded_std_rng());

        // 表达式 = (w_l·w_r − w_o)·eq + ρ·eq·m；polys=[w_l, w_r, w_o, m]
        let q = |i: usize| Expression::<Fr>::Polynomial(Query::new(i, Rotation::cur()));
        let expression = ((q(0) * q(1)) - q(2)) * Expression::eq_xy(0)
            + Expression::<Fr>::Challenge(0) * Expression::eq_xy(0) * q(3);
        let stride = expression.degree() + 1;

        let y: Vec<Fr> = (0..num_vars)
            .map(|i| Fr::from(7u64 + i as u64))
            .collect();
        let rho = Fr::from(123456789u64);
        let fixed_challenge = Fr::from(424242u64); // 固定挑战：四组重放逐位可比

        let run = |v: Vec<MultilinearPolynomial<Fr>>,
                   m: &MultilinearPolynomial<Fr>|
         -> Vec<Vec<Fr>> {
            let m_y = m.evaluate(&y);
            let mut polys_refs: Vec<&MultilinearPolynomial<Fr>> = v.iter().collect();
            polys_refs.push(m);
            let mut tr = MockTr {
                challenge: fixed_challenge,
                sink: Vec::new(),
            };
            super::prover::prove_zero_check(
                0,
                &expression,
                &polys_refs,
                &polys_refs,
                rho * m_y,
                vec![rho],
                y.clone(),
                m_y,
                3,
                &mut tr,
            )
            .unwrap();
            tr.sink[..num_vars * stride]
                .chunks(stride)
                .map(<[Fr]>::to_vec)
                .collect()
        };

        let zero_poly = || MultilinearPolynomial::<Fr>::new(vec![Fr::ZERO; 1 << num_vars]);
        let v_a: Vec<_> = (0..3).map(|_| rand_poly()).collect();
        let v_b: Vec<_> = (0..3).map(|_| rand_poly()).collect();
        let m = rand_poly();
        let zero_m = zero_poly();

        let s_a_m = run(v_a.clone(), &m);
        let s_a_0 = run(v_a, &zero_m);
        let s_b_m = run(v_b.clone(), &m);
        let s_b_0 = run(v_b, &zero_m);
        let s_0_m = run(vec![zero_poly(), zero_poly(), zero_poly()], &m);
        let s_0_0 = run(vec![zero_poly(), zero_poly(), zero_poly()], &zero_m);

        // 恒等式：msgs(v,m) − msgs(v,0) == msgs(0,m) − msgs(0,0)（== ρ·G(m)）
        for round in 0..num_vars {
            let mut nonzero_seen = false;
            for j in 0..stride {
                let resid_a = s_a_m[round][j] - s_a_0[round][j];
                let resid_b = s_b_m[round][j] - s_b_0[round][j];
                let resid_0 = s_0_m[round][j] - s_0_0[round][j];
                assert_eq!(
                    resid_a, resid_b,
                    "round {} pos {}: m-余量与 witness 无关",
                    round, j
                );
                assert_eq!(
                    resid_a, resid_0,
                    "round {} pos {}: m-余量=零 witness 重放",
                    round, j
                );
                nonzero_seen |= resid_a != Fr::ZERO;
            }
            assert!(
                nonzero_seen,
                "round {}: ρG(m) 整轮为零（G 非零性破坏 ⟹ 无 ZK 覆盖力）",
                round
            );
        }
    }
//    tests!(hyrax, MultilinearHyrax<grumpkin::G1Affine>, 5..16);
//    tests!(ipa, MultilinearIpa<grumpkin::G1Affine>);
//    tests!(kzg, MultilinearKzg<Bn256>);
//    tests!(gemini_kzg, Gemini<UnivariateKzg<Bn256>>);
//    tests!(zeromorph_kzg, Zeromorph<UnivariateKzg<Bn256>>);
}
