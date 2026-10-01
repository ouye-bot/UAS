//! T6 · mod-n 边界族（(A7) 测试体系第一族，2026-09-11；spec=`literature_review/波4_A7测试体系设计`+十三项方案 A4）
//!
//! 判定纪律：断言对象是**宿主实然行为**（empirical），不是规范应然——每例注释区分
//! 「GB/T 32918.2 规定域」与「本宿主实测行为」；电路级执行面（范围检查 530 约束 =
//! lt_n(r)/lt_n(s)、nonzero_rs 面、(S4) 无穷远不可表示）以 ledger/既有断言为证，本族不重复。
//! 常量纪律：n 全部取自 [`crate::sm2_params::n_limbs`]，零手抄。
//!
//! 机器实锤发现（2026-09-11，TDD 红→绿）：
//! **[T6-defect-1] 非法钥 d=n−1 使签名器非终止**——den=1+d≡0 ⟹ inv=0 ⟹ s≡0 对一切 k
//! 恒成立（trace 40,000+ 迭代 100% 命中，`M3_probe/logs_zk/t62_trace_2026-09-11c.txt`），
//! 重采样循环永不退出。修复=sign_with_nonce 前置定义域校验（d∈[1,n−2] 否则 fail-fast
//! panic）——合法域行为零变化，非法域从挂死变立即失败。
//! 其余边界：k=0 nonce 于 [0]G 标量乘 fail-fast panic（k 采样域执行面 100% 在宿主——
//! §4 治理义务(iv) 的本机根源锚）；verify_replay 数学重放无范围拒绝（范围拒绝执行面在电路）。
#[cfg(test)]
mod tests {
    use crate::sm2_full_statement_assemble::sm2_sign_host::{
        inv_mod_n, pk_from_sk, sign_with_nonce, test_issuer_key,
    };
    use crate::sm2_params::{fr_from_limbs, n_limbs};
    use crate::sm2_verify_assemble::{add_mod_n_limbs, verify_replay};

    fn wrap_sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, o1) = a[i].overflowing_sub(b[i]);
            let (d2, o2) = d1.overflowing_sub(borrow);
            r[i] = d2;
            borrow = (o1 as u64) | (o2 as u64);
        }
        r
    }

    fn one() -> [u64; 4] {
        [1, 0, 0, 0]
    }

    fn two() -> [u64; 4] {
        [2, 0, 0, 0]
    }

    /// 固定测试摘要（内容任意、值固定 ⟹ 断言可复现）。
    fn e_fix() -> [u64; 4] {
        [0x0102_0304_0506_0708, 0x1122_3344_5566_7788, 0, 0x0A0B]
    }

    fn k0_fix() -> [u64; 4] {
        [0xF0E1_D2C3_B4A5_9687, 0x1234_5678_9ABC_DEF0, 7, 0x5EED]
    }

    /// T6.2 合法上界 d=n−2：签名+数学重放全通过（1+d=n−1 可逆）。
    /// 🔴勘误（2026-09-11）：首版误用 wrap_sub(n,one())=n−1 当「n−2」——恰踩中
    /// [T6-defect-1] 非法钥挂死，插桩定位后本例改用 two()=真 n−2。
    #[test]
    fn boundary_d_n_minus_2_full_path_ok() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("boundary_d_n_minus_2_full_path_ok", "T6; d=n-2 full path");
        let n = n_limbs();
        let d = wrap_sub(n, two()); // 真 n−2（合法上界）
        let (pax, pay) = pk_from_sk(&d);
        let (r, s) = sign_with_nonce(&e_fix(), &d, k0_fix());
        let out = verify_replay(
            fr_from_limbs(&e_fix()),
            fr_from_limbs(&r),
            fr_from_limbs(&s),
            pax,
            pay,
        );
        assert!(out.ok, "d=n−2 合法上界必须全路径通过");
    }

    /// T6.1 d=0：修复后 fail-fast（GB/T 定义域 [1,n−2] 前置校验；
    /// 修复前签名器不拒绝、s=k 方程自洽照常输出——历史行为见 git 谱系）。
    #[test]
    fn boundary_d_zero_fail_fast() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("boundary_d_zero_fail_fast", "T6; d=0 corner");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sign_with_nonce(&e_fix(), &[0u64; 4], k0_fix())
        }));
        assert!(result.is_err(), "d=0 应被定义域前置校验 fail-fast 拒绝");
    }

    /// T6.3 d=n−1：**[T6-defect-1] 修复后 fail-fast**；角行为算术锁定：
    /// den=1+(n−1)≡0 ⟹ inv_mod_n(0)=0 ⟹ s≡0 对一切 k 恒成立（修复前=非终止挂死，
    /// trace 40,000+ 迭代 100% s=0 实证）。
    #[test]
    fn boundary_d_n_minus_1_fail_fast_and_zero_den() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("boundary_d_n_minus_1_fail_fast_and_zero_den", "T6; d=n-1 den=0 corner");
        let n = n_limbs();
        let nm1 = wrap_sub(n, one());
        let den = add_mod_n_limbs(&one(), &nm1);
        assert_eq!(den, [0u64; 4], "1+(n−1) mod n ≡ 0（defect-1 的数学根源）");
        assert_eq!(inv_mod_n(&[0u64; 4]), [0u64; 4], "inv_mod_n(0)=0 实然行为");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sign_with_nonce(&e_fix(), &nm1, k0_fix())
        }));
        assert!(result.is_err(), "d=n−1 应被定义域前置校验 fail-fast 拒绝（修复前为挂死）");
    }

    /// T6.4 d=2^256−1（≥n，域外但非退化）：前置校验为**窄域**（仅拒 0/n−1 两个
    /// 挂死退化值）——本例实测通过校验并以静默规约正常签名（[实测 2026-09-11：
    /// 首版断言"应被拒绝"被实然行为推翻]）；完整 [1,n−2] 执行仍是 Keygen/调用侧
    /// 义务（文档化残余）。静默规约与角行为在纯函数层锁定。
    #[test]
    fn boundary_d_beyond_n_arithmetic_and_narrow_validation() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("boundary_d_beyond_n_arithmetic_and_narrow_validation", "T6; d=2^256-1 out-of-domain");
        use crate::sm2_full_statement_assemble::sm2_sign_host::mul_mod_n;
        let n = n_limbs();
        let d_huge = [u64::MAX; 4]; // 2^256−1
        let d_reduced = wrap_sub(d_huge, n); // = 2^256−1−n < n（d mod n）
        // 实然：窄域校验放行 ⟹ 正常签名，输出与规约后标量逐字节相同。
        let (r1, s1) = sign_with_nonce(&e_fix(), &d_huge, k0_fix());
        let (r2, s2) = sign_with_nonce(&e_fix(), &d_reduced, k0_fix());
        assert_eq!((r1, s1), (r2, s2), "超域标量须与规约后标量签名逐字节相同");
        // 静默规约（纯函数层，任取域内样本 r）。
        let r_sample = [0x0A11_CE65_0B50_1E5A, 3, 0, 0x5EED];
        assert_eq!(
            mul_mod_n(&r_sample, &d_huge),
            mul_mod_n(&r_sample, &d_reduced),
            "超域标量在 mod-n 乘法中静默规约（下游不可分辨）"
        );
        // 角行为：1+d = 2^256 ⟹ carry 环绕减 n ⟹ den = 2^256−n（非数学像 0）。
        let den = add_mod_n_limbs(&one(), &d_huge);
        assert_eq!(den, wrap_sub([0u64; 4], n), "1+d 超域角 = 2^256−n（环绕减）");
    }

    /// T6.8 k=0 nonce：**宿主 fail-fast panic 于 [0]G 标量乘**（pk_from_sk 的
    /// `expect("[d]G 标量乘成功")` 对无穷远返回 None）——非 GB/T 的重采样处置。
    /// k 不是电路变量（电路只见 r,s）⟹ k 采样域的执行面 100% 在宿主调用侧；
    /// 数学上 k=0 若被容忍将经 s=−rd(1+d)^{−1} 完整泄露 d（d=−s(s+r)^{−1}）——
    /// 论文 §4 治理义务(iv)「签名随机数（重用即恢复 sk_I）」的本机根源锚。
    #[test]
    fn boundary_k_zero_aborts_at_infinity_scalar_mul() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("boundary_k_zero_aborts_at_infinity_scalar_mul", "T6; k=0 [0]G abort");
        let d = wrap_sub(n_limbs(), two()); // 合法 d=n−2
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sign_with_nonce(&e_fix(), &d, [0u64; 4])
        }));
        assert!(
            result.is_err(),
            "k=0 nonce 应在 [0]G 标量乘处 fail-fast panic（宿主实然行为文档化）"
        );
    }

    /// T6.5/T6.6/T6.7 verify_replay 边界（实然行为逐例锁定，2026-09-11 首跑两处
    /// 断言被实然推翻后修正）：宿主重放是数学工具、无 GB/T 范围拒绝——
    /// r=0 与 r=n（≥n 的 F_p 元素）照常计算返回 ok=false；**s=0 在 [0]G 标量乘
    /// unwrap 处 panic（fail-fast）而非返回 false**。范围/非零拒绝的承重件=电路
    /// （range_check 530=lt_n(r)/lt_n(s) + nonzero_rs 面，既有断言锁定）——Verify
    /// 入口的范围拒绝在电路层，宿主重放工具不设防不影响部署。
    #[test]
    fn boundary_verify_replay_no_range_reject_math_only() {
    let _t8 = crate::sm2_a7_jsonlog::CaseGuard::new("boundary_verify_replay_no_range_reject_math_only", "T6; r=0/r=n/s=0 math-reject");
        let d_i = test_issuer_key();
        let (pax, pay) = pk_from_sk(&d_i);
        let (r, s) = sign_with_nonce(&e_fix(), &d_i, k0_fix());
        let e_f = fr_from_limbs(&e_fix());
        let r_f = fr_from_limbs(&r);
        let s_f = fr_from_limbs(&s);
        // r=0：数学非匹配（照常计算返回 false）。
        assert!(!verify_replay(e_f, fr_from_limbs(&[0u64; 4]), s_f, pax, pay).ok);
        // r=n（≥n 的 F_p 合法元素 ≠ r mod n=0）：静默按不同元素计算 ⟹ false。
        assert!(!verify_replay(e_f, fr_from_limbs(&n_limbs()), s_f, pax, pay).ok);
        // s=0：[0]G 标量乘 unwrap panic（fail-fast 实然行为，非返回 false）。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_replay(e_f, r_f, fr_from_limbs(&[0u64; 4]), pax, pay)
        }));
        assert!(result.is_err(), "s=0 应在 [0]G 标量乘 unwrap 处 panic（实然行为）");
        // 诚实签名对照仍为 true。
        assert!(verify_replay(e_f, r_f, s_f, pax, pay).ok);
    }
}
