//! ③手术 S2 诊断：诚实 witness 上逐约束求值，定位非零（不一致）约束族。

use zksvc::assemble::assemble;

#[test]
fn auth_window_constraint_eval_diag() {
    std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");
    let text = std::fs::read_to_string("tests/auth_canonical_spec.json").expect("spec");
    let spec: zksvc::profile::JobSpec = serde_json::from_str(&text).expect("损坏");
    let asm = assemble(&spec).expect("装配失败");
    let plonkish_sm2_probe::sm2_verify_assemble::Assembled {
        info,
        advice,
        instances,
        ctags,
        ..
    } = asm;
    let viols = plonkish_sm2_probe::sm3_compress::check_parts_violations(&info, &advice, &instances);
    println!("[diag] 违约总数 = {}", viols.len());
    let mut by_tag: std::collections::BTreeMap<String, usize> = Default::default();
    for v in &viols {
        let tag = ctags.get(v.constraint).copied().unwrap_or("?");
        *by_tag.entry(tag.to_string()).or_default() += 1;
        if by_tag[&tag.to_string()] <= 2 {
            println!("[diag] 首样: idx={} tag={tag} point={}", v.constraint, v.point);
        }
    }
    for (t, c) in &by_tag {
        println!("[diag] 族 {t}: {c}");
    }
    assert!(viols.is_empty(), "诚实 witness 上存在违约约束——见上表");
}

/// 负例（R4 手术方案 §二.5，存在性形态）：window 窗行上任意一格篡改必被
/// 约束网抓到（精确列锚负例在 S3 铺开时经 hooks 机制迁移——E8 sk 位锚同款）。
#[test]
fn auth_window_forgeries_caught() {
    use plonkish_sm2_probe::sm3_compress::{check_parts_violations, row_mapping};
    std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");
    let text = std::fs::read_to_string("tests/auth_canonical_spec.json").expect("spec");
    let spec: zksvc::profile::JobSpec = serde_json::from_str(&text).expect("损坏");
    let asm = assemble(&spec).expect("装配失败");
    let plonkish_sm2_probe::sm2_verify_assemble::Assembled {
        info, advice, instances, ..
    } = asm;
    // 基线：诚实 witness 零违约
    assert!(check_parts_violations(&info, &advice, &instances).is_empty());

    // 篡改：C₁ 窗末行（rank 3184+66）每列逐一 +7——任何一列被抓即防线存在。
    let pt = row_mapping()[3184 + plonkish_sm2_probe::sm2_ec_window_gadget::ROWS_USED];
    let ncols = advice.len();
    let mut caught_by = None;
    for c in 0..ncols {
        let mut adv = advice.clone();
        adv[c][pt] += FpSM2::from(7u64);
        if !check_parts_violations(&info, &adv, &instances).is_empty() {
            caught_by = Some(c);
            break;
        }
    }
    assert!(caught_by.is_some(), "窗行篡改全部漏网——window 防护网失效");
}

use plonkish_sm2_probe::FpSM2;
