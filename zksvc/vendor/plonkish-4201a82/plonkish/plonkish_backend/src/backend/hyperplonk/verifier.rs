use crate::{
    backend::hyperplonk::preprocessor::MaskLayout,
    pcs::Evaluation,
    piop::sum_check::{
        classic::{ClassicSumCheck, EvaluationsProver},
        evaluate, lagrange_eval, SumCheck,
    },
    poly::multilinear::{rotation_eval, rotation_eval_points},
    util::{
        arithmetic::{inner_product, BooleanHypercube, PrimeField},
        expression::{Expression, Query, Rotation},
        transcript::FieldTranscriptRead,
        Itertools,
    },
    Error,
};
use std::collections::{BTreeSet, HashMap};

#[allow(clippy::type_complexity)]
pub(super) fn verify_zero_check<F: PrimeField>(
    num_vars: usize,
    expression: &Expression<F>,
    instances: &[Vec<F>],
    challenges: &[F],
    y: &[F],
    sum: F,
    lambdas: &[F],
    m_y: F,
    mask_layout: &MaskLayout,
    transcript: &mut impl FieldTranscriptRead<F>,
) -> Result<(Vec<Vec<F>>, Vec<Evaluation<F>>), Error> {
    // D18 Phase 3（协议层 HVZK）：sumcheck 初始和=ρ·m(y)（m(y) 先行上链钉死）；
    // 读得掩蔽世界开口后按 λ 去掩重建明文世界，再核 E6（语义逐字保持）。
    let mask_poly = mask_layout.mask_poly;
    let (x_eval, x) = ClassicSumCheck::<EvaluationsProver<_>>::verify(
        &(),
        num_vars,
        expression.degree(),
        sum,
        transcript,
    )?;

    let pcs_query = pcs_query_with_mask(expression, instances.len(), mask_poly);
    let (evals_for_rotation, claimed_at_x): (Vec<Vec<F>>, Vec<(Query, F)>) = pcs_query
        .iter()
        .map(|query| {
            let evals_for_rotation =
                transcript.read_field_elements(1 << query.rotation().distance())?;
            let eval = rotation_eval(&x, query.rotation(), &evals_for_rotation);
            Ok((evals_for_rotation, (*query, eval)))
        })
        .try_collect::<_, Vec<_>, _>()?
        .into_iter()
        .unzip::<_, _, Vec<_>, Vec<_>>();

    // m 列在各旋转点的原始开口（去掩基准）。
    let mut m_raw: HashMap<Rotation, &Vec<F>> = HashMap::new();
    for (query, evals_for_rotation) in pcs_query.iter().zip(evals_for_rotation.iter()) {
        if query.poly() == mask_poly {
            m_raw.insert(query.rotation(), evals_for_rotation);
        }
    }

    // λ 去掩重建：w_i(·) = ṽ_i(·) − λ_i·m(·)（rotation_eval 对开口值线性 ⟹
    // 先插值后相减与先相减后插值等价）；公开列与 m 列本体直通。
    let mut adjusted = Vec::with_capacity(claimed_at_x.len());
    for (query, claimed) in claimed_at_x.iter() {
        if query.poly() == mask_poly {
            adjusted.push((*query, *claimed));
            continue;
        }
        let slot = match mask_layout.lambda_of_poly.get(query.poly()) {
            Some(Some(slot)) => *slot,
            _ => {
                adjusted.push((*query, *claimed));
                continue;
            }
        };
        let m_eval = rotation_eval(
            &x,
            query.rotation(),
            m_raw.get(&query.rotation()).expect("mask mirror eval"),
        );
        adjusted.push((*query, *claimed - lambdas[slot] * m_eval));
    }

    let evals = instance_evals(num_vars, expression, instances, &x)
        .into_iter()
        .chain(adjusted)
        .collect();
    if evaluate(expression, num_vars, &evals, challenges, &[y], &x) != x_eval {
        return Err(Error::InvalidSnark(
            "Unmatched between sum_check output and query evaluation".to_string(),
        ));
    }

    // m(y) 开口（写在全部逐查询开口之后）与先行上链的 m(y) 同值互证。
    let m_y_claim = transcript.read_field_element()?;
    if m_y_claim != m_y {
        return Err(Error::InvalidSnark("Unmatched mask eval at y".to_string()));
    }

    let point_offset = point_offset(&pcs_query);
    let mut evals: Vec<Evaluation<F>> = pcs_query
        .iter()
        .zip(evals_for_rotation)
        .flat_map(|(query, evals_for_rotation)| {
            (point_offset[&query.rotation()]..)
                .zip(evals_for_rotation)
                .map(|(point, eval)| Evaluation::new(query.poly(), point, eval))
        })
        .collect();
    let mut points = points(&pcs_query, &x);
    let y_point = points.len();
    points.push(y.to_vec());
    evals.push(Evaluation::new(mask_poly, y_point, m_y_claim));
    Ok((points, evals))
}

/// 非掩蔽通用 sumcheck 验证（protostar accumulation 路径专用；主 HyperPlonk
/// 后端走 verify_zero_check 的 Phase 3 掩蔽版）。
#[allow(clippy::type_complexity)]
pub(crate) fn verify_sum_check<F: PrimeField>(
    num_vars: usize,
    expression: &Expression<F>,
    sum: F,
    instances: &[Vec<F>],
    challenges: &[F],
    y: &[F],
    transcript: &mut impl FieldTranscriptRead<F>,
) -> Result<(Vec<Vec<F>>, Vec<Evaluation<F>>), Error> {
    let (x_eval, x) = ClassicSumCheck::<EvaluationsProver<_>>::verify(
        &(),
        num_vars,
        expression.degree(),
        sum,
        transcript,
    )?;

    let pcs_query = pcs_query(expression, instances.len());
    let (evals_for_rotation, evals) = pcs_query
        .iter()
        .map(|query| {
            let evals_for_rotation =
                transcript.read_field_elements(1 << query.rotation().distance())?;
            let eval = rotation_eval(&x, query.rotation(), &evals_for_rotation);
            Ok((evals_for_rotation, (*query, eval)))
        })
        .try_collect::<_, Vec<_>, _>()?
        .into_iter()
        .unzip::<_, _, Vec<_>, Vec<_>>();

    let evals = instance_evals(num_vars, expression, instances, &x)
        .into_iter()
        .chain(evals)
        .collect();
    if evaluate(expression, num_vars, &evals, challenges, &[y], &x) != x_eval {
        return Err(Error::InvalidSnark(
            "Unmatched between sum_check output and query evaluation".to_string(),
        ));
    }

    let point_offset = point_offset(&pcs_query);
    let evals = pcs_query
        .iter()
        .zip(evals_for_rotation)
        .flat_map(|(query, evals_for_rotation)| {
            (point_offset[&query.rotation()]..)
                .zip(evals_for_rotation)
                .map(|(point, eval)| Evaluation::new(query.poly(), point, eval))
        })
        .collect();
    Ok((points(&pcs_query, &x), evals))
}

fn instance_evals<F: PrimeField>(
    num_vars: usize,
    expression: &Expression<F>,
    instances: &[Vec<F>],
    x: &[F],
) -> Vec<(Query, F)> {
    let mut instance_query = expression.used_query();
    instance_query.retain(|query| query.poly() < instances.len());

    let lagranges = {
        let mut lagranges = instance_query.iter().fold(0..0, |range, query| {
            let i = -query.rotation().0;
            range.start.min(i)..range.end.max(i + instances[query.poly()].len() as i32)
        });
        if lagranges.start < 0 {
            lagranges.start -= 1;
        }
        if lagranges.end > 0 {
            lagranges.end += 1;
        }
        lagranges
    };

    let bh = BooleanHypercube::new(num_vars).iter().collect_vec();
    let lagrange_evals = lagranges
        .filter_map(|i| {
            (i != 0).then(|| {
                let b = bh[i.rem_euclid(1 << num_vars as i32) as usize];
                (i, lagrange_eval(x, b))
            })
        })
        .collect::<HashMap<_, _>>();

    instance_query
        .into_iter()
        .map(|query| {
            let is = if query.rotation() > Rotation::cur() {
                (-query.rotation().0..0)
                    .chain(1..)
                    .take(instances[query.poly()].len())
                    .collect_vec()
            } else {
                (1 - query.rotation().0..)
                    .take(instances[query.poly()].len())
                    .collect_vec()
            };
            let eval = inner_product(
                &instances[query.poly()],
                is.iter().map(|i| lagrange_evals.get(i).unwrap()),
            );
            (query, eval)
        })
        .collect()
}

pub(super) fn pcs_query<F: PrimeField>(
    expression: &Expression<F>,
    num_instance_poly: usize,
) -> BTreeSet<Query> {
    let mut used_query = expression.used_query();
    used_query.retain(|query| query.poly() >= num_instance_poly);
    used_query
}

/// D18 Phase 3：在表达式既有查询面之上，为 m 列补充全部既有旋转点的镜像开口
/// （prover/verifier 两侧同此构造 ⟹ 声称面逐位一致）。去掩重建需要 m 在每个
/// 掩蔽列开口点的取值。
pub(super) fn pcs_query_with_mask<F: PrimeField>(
    expression: &Expression<F>,
    num_instance_poly: usize,
    mask_poly: usize,
) -> BTreeSet<Query> {
    let mut pcs_query = pcs_query(expression, num_instance_poly);
    let rotations: BTreeSet<Rotation> = pcs_query.iter().map(|q| q.rotation()).collect();
    for rotation in rotations {
        pcs_query.insert(Query::new(mask_poly, rotation));
    }
    pcs_query
}

pub(super) fn points<F: PrimeField>(pcs_query: &BTreeSet<Query>, x: &[F]) -> Vec<Vec<F>> {
    pcs_query
        .iter()
        .map(Query::rotation)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .flat_map(|rotation| rotation_eval_points(x, rotation))
        .collect_vec()
}

pub(crate) fn point_offset(pcs_query: &BTreeSet<Query>) -> HashMap<Rotation, usize> {
    let rotations = pcs_query
        .iter()
        .map(Query::rotation)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect_vec();
    rotations.windows(2).fold(
        HashMap::from_iter([(rotations[0], 0)]),
        |mut point_offset, rotations| {
            let last_rotation = rotations[0];
            let offset = point_offset[&last_rotation] + (1 << last_rotation.distance());
            point_offset.insert(rotations[1], offset);
            point_offset
        },
    )
}
