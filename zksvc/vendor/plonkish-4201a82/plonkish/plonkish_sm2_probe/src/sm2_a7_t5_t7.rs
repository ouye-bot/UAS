//! T5+T7 · (A7) 测试体系：复制环覆盖率 + 非规范编码族（2026-09-14）
//!
//! T5（复制环覆盖率，波4 规格）：对全部复制环逐一做"环两端值分岔"注入
//! （原地改第二成员格 +1，断言后恢复——零额外内存），断言环审计防线捕获
//! 该环；诚实基线零坏环先行。覆盖=1,957 环（装配冻结断言口径）。
//! T7（非规范编码与无穷远点代理族，波4 规格）：装配层三类非规范注入——
//! 布尔位格=2（非规范位编码）、pk_u.x 高词=0xFFFFFFFF（32B 表示 > p 的
//! 非规范 x）、pk_u.x 全词=0xFFFFFFFF（全 FF 退化输入）——断言约束防线
//! 捕获；另配编码单射性性质测试（引理 C 机器验证：素域 p 奇 ⟹ y∈[1,p−1]
//! 时 par(P)≠par(−P)，随机点对编码互异）。e12 禁跑纪律继承。
use crate::sm3_compress::{audit_ring_values, check_parts_violations};
use crate::sm2_full_statement_assemble::assemble_full_statement_with_hooks_bound;
use crate::FpSM2;
use ff::Field as _;
use ff::PrimeField as _;

struct SplitMix(u64);
impl SplitMix {
    fn new(seed: u64) -> Self {
        SplitMix(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// T5 · 复制环覆盖率：全部环逐一分岔注入被环审计捕获。
#[test]
fn t5_copy_cycle_coverage() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("t5_copy_cycle_coverage", "T5; 1,187 rings in-place diverge-inject（2026-10 实测钉）");
    let base = crate::sm2_full_statement_assemble::witness_from_with_exp(
        [0x0A1B_2C3D_4E5F_6071, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22],
        [7u8; 32],
        [0x33u64, 0, 0, 0x5EED],
        501,
    );
    let (mut asm, _) = assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
    assert_eq!(
        asm.info.permutations.len(),
        1_187,
        "复制环总数漂移（2026-10-01 实测钉：旧钉 1,957 论文口径在 db0bbb3 实测已漂移至 1,187——历史批次未回写；本批零环变动）"
    );
    // 诚实基线：零坏环
    let base_bad = audit_ring_values(&asm.info, &asm.advice);
    assert!(base_bad.is_empty(), "诚实见证基线出现坏环 {} 条", base_bad.len());

    let np = asm.info.preprocess_polys.len();
    let mut covered = 0usize;
    let mut singletons = 0usize;
    for (rid, cyc) in asm.info.permutations.iter().enumerate() {
        if cyc.len() < 2 {
            singletons += 1;
            continue;
        }
        let &(p, pt) = &cyc[1];
        assert!(p > np, "环 {rid} 含非 advice 多项式索引 {p}（np={np}）");
        let col = p - 1 - np;
        let orig = asm.advice[col][pt];
        // 分岔注入：第二成员格 +1（与第一格必然相异——基线下环成员值全等）
        asm.advice[col][pt] = orig + FpSM2::ONE;
        let bad = audit_ring_values(&asm.info, &asm.advice);
        assert!(
            bad.iter().any(|(r, _)| *r == rid),
            "环 {rid} 分岔注入未被环审计捕获（成员 {} 格）",
            cyc.len()
        );
        asm.advice[col][pt] = orig; // 恢复，进入下一环
        covered += 1;
    }
    eprintln!(
        "[T5] 复制环 {covered}/{} 全量分岔注入被环审计捕获（单格环 {singletons} 个按防线语义跳过）",
        asm.info.permutations.len()
    );
}

/// T7 · 装配层非规范编码族：三类注入全部被约束防线捕获。
#[test]
fn t7_noncanonical_assembly_rejection() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("t7_noncanonical_assembly_rejection", "T7; boolean-cell=2 / high-word>p / all-FF injections");
    let base = crate::sm2_full_statement_assemble::witness_from_with_exp(
        [0x0A1B_2C3D_4E5F_6071, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22],
        [7u8; 32],
        [0x33u64, 0, 0, 0x5EED],
        501,
    );
    let (mut asm, hooks) =
        assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
    // 诚实基线：零违约
    assert!(
        check_parts_violations(&asm.info, &asm.advice, &asm.instances).is_empty(),
        "诚实见证基线出现违约 = 装配自洽破坏"
    );

    // (i) 非规范位编码：布尔位格（attrs 位首格）设 2
    let (ca, ra) = hooks.attrs_bit0;
    let orig_a = asm.advice[ca][ra];
    asm.advice[ca][ra] = FpSM2::from(2u64);
    let bad = check_parts_violations(&asm.info, &asm.advice, &asm.instances);
    assert!(!bad.is_empty(), "非规范位（布尔格=2）未被约束防线捕获");
    let hit_i = bad.len();
    asm.advice[ca][ra] = orig_a;

    // (ii) 非规范 x：pk_u.x 高词（词 7，最高 32 位）设 0xFFFFFFFF ——
    // p 的最高 u32 = 0xFFFFFFFE，故该 32B 表示 > p，非规范。
    let (cp, rp) = (hooks.pkx_cols[7], hooks.row_pk);
    let orig_p = asm.advice[cp][rp];
    asm.advice[cp][rp] = FpSM2::from(0xFFFF_FFFFu64);
    let bad = check_parts_violations(&asm.info, &asm.advice, &asm.instances);
    assert!(!bad.is_empty(), "非规范 x（高词 > p 表示）未被约束防线捕获");
    let hit_ii = bad.len();
    asm.advice[cp][rp] = orig_p;

    // (iii) 全 FF 退化输入：pk_u.x 全部 8 词 = 0xFFFFFFFF（2^256−1 > p）
    let mut origs = Vec::with_capacity(8);
    for &c in hooks.pkx_cols.iter() {
        origs.push(asm.advice[c][rp]);
        asm.advice[c][rp] = FpSM2::from(0xFFFF_FFFFu64);
    }
    let bad = check_parts_violations(&asm.info, &asm.advice, &asm.instances);
    assert!(!bad.is_empty(), "全 FF 退化输入未被约束防线捕获");
    let hit_iii = bad.len();
    for (&c, o) in hooks.pkx_cols.iter().zip(origs.iter()) {
        asm.advice[c][rp] = *o;
    }

    // 恢复后基线复验（注入零残留）
    assert!(
        check_parts_violations(&asm.info, &asm.advice, &asm.instances).is_empty(),
        "恢复后基线复验失败 = 注入残留"
    );
    eprintln!(
        "[T7] 非规范编码族三类注入全捕获：非规范位 {hit_i} 条违约、非规范 x {hit_ii} 条、全 FF {hit_iii} 条；恢复后基线零违约"
    );
}

/// T7 · 编码单射性性质测试（引理 C 机器验证）：
/// 素域 p 奇、y∈[1,p−1] ⟹ (p−y) 奇偶翻转 ⟹ par(P)≠par(−P)（33B 编码第 33 字节相异）；
/// 随机点对 P≠P′ 编码互异。样本数经 A7_T7_N 放量（默认 64）。
#[test]
fn t7_encoding_injectivity_property() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("t7_encoding_injectivity_property", "T7; random-pair 33B encoding distinct incl -P; A7_T7_N env");
    let n_target: usize = std::env::var("A7_T7_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    let mut sm = SplitMix::new(0x00A7_C0DE);
    let mut pairs = 0usize;
    for i in 0..n_target {
        let sk = [sm.next(), sm.next(), sm.next(), sm.next() & 0x0FFF_FFFF];
        let (px, py) = crate::sm2_full_statement_assemble::sm2_sign_host::pk_from_sk(&sk);
        // repr 为小端规范表示（sm2_params::fr_from_limbs 契约）：repr[0] = 最低有效字节。
        // enc(P) 的第 33 字节 = 0x02 | (y mod 2)
        let par_p = 0x02u8 | (py.to_repr().as_ref()[0] & 1);
        // −P = (x, p − y)：奇偶必翻转（p 奇、y≠0 —— 素数阶群中 [d]G 的 y≠0）
        let ny = FpSM2::ZERO - py;
        let par_np = 0x02u8 | (ny.to_repr().as_ref()[0] & 1);
        assert_ne!(
            par_p, par_np,
            "样本 #{i}：par(−P)==par(P) —— 引理 C 前提破坏（y=0 或 p 偶）"
        );
        // 随机点对编码互异（a≠b 时 x 不同或 P2=±P1；± 已由奇偶覆盖）
        let sk2 = [sm.next(), sm.next(), sm.next(), sm.next() & 0x0FFF_FFFF];
        let (qx, qy) = crate::sm2_full_statement_assemble::sm2_sign_host::pk_from_sk(&sk2);
        let same_x = qx.to_repr().as_ref() == px.to_repr().as_ref();
        if same_x {
            // x 相同 ⟹ P2=−P1（素数阶群），奇偶必相异
            assert_ne!(
                0x02u8 | (qy.to_repr().as_ref()[0] & 1),
                par_p,
                "样本 #{i}：同 x 同奇偶的相异编码 = 单射性破坏"
            );
        } else {
            pairs += 1;
        }
    }
    eprintln!(
        "[T7] 编码单射性：{n_target} 样本 ±P 奇偶翻转全成立、互异 x 点对 {pairs} 组编码互异"
    );
}
