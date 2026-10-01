//! SM2 基域 F_p 的 `ff::PrimeField` 实现（供 plonkish_backend 透明 SNARK 探针）。
//!
//! p = 2^256 − 2^224 − 2^96 + 2^64 − 1（GB/T 32918 国密 SM2 基域，M1a 已五源交叉验证）。
//! 关键性质：v₂(p−1) = 1（无 radix-2 子群）→ 本探针验证 Brakedown 类透明 PCS 在
//! 非光滑域上仍可运行。
//!
//! 生成元 g=13 与 p−1 素分解均为**本探针 [实测] 计算**（非手抄）：
//!   p−1 = 2 × 43 × 30223 × 348253387243 × 4641351449027 × 417514796639753
//!         × 66013261729388519804782124120027
//! 各因子 Miller-Rabin 验证为素数，g=13 对每个素因子 q 满足 g^((p−1)/q) ≠ 1。

use ff::PrimeField; // ff 0.13：derive 宏 + trait
use serde::{Deserialize, Serialize};

/// SM2 基域 F_p。`[u64; 5]`：ff_derive 要求 2·p 也放进表示（256-bit 域 → 需 5 limbs，
/// 即 5×64=320 ≥ 257 bits）。小端（ff_derive 标准范式，同 crate 内 Mersenne127 示例）。
#[derive(PrimeField, Serialize, Deserialize, Hash)]
#[PrimeFieldModulus = "115792089210356248756420345214020892766250353991924191454421193933289684991999"]
#[PrimeFieldGenerator = "13"]
#[PrimeFieldReprEndianness = "little"]
pub struct FpSM2([u64; 5]);

/// SM3 模加门 spike：mod-2^32 加法 + 字节范围查找（lookup + BaseFold + FpSM2 首次）。
pub mod sm3_gates;
/// 原生 SM3 参照实现（自 m0 已验证代码机械复制；1.1b witness 真值来源）。
pub mod sm3_native_ref;
/// 1.1b SM3 压缩函数 Plonkish 电路：b1 门原语层（XOR/MAJ/CHOOSE/ADD/ROTL/FF）。
pub mod sm3_compress;
/// 1.1b-b4 管线化 v2（复制环传输，勘误 #16；单证明满足后端旋转预算）。
pub mod sm3_compress_v2;
/// 后端置换（复制约束）机制端到端冒烟——v2 路线的前置去风险飞行。
pub mod sm3_perm_smoke;

// ── 1.1c 验签体 Plonkish 移植（蓝图 M3_probe/VERIFY_BODY_BLUEPRINT.md）──
pub mod sm2_params;
pub mod sm2_scalar_plonkish;
pub mod sm2_ec_plonkish;
pub mod sm2_verify_assemble;
/// 1.1d 锚点绑定簇F：Z_U native 层（蓝图 M3_probe/Z_ANCHOR_BLUEPRINT.md）。
pub mod sm2_z_anchor;
/// 簇J T1 全语句 (S1)–(S5) 装配器（蓝图 §四·8；merged (S6) 线零接触）。
pub mod sm2_full_statement_assemble;
/// T2.2：无经销者分布式密钥生成（Pedersen/Gennaro 型委员会侧协议仿真；apk=Y_i 结构不变、零电路改动）。
pub mod sm2_dkg;
/// T2.4：摘要签名加入协议主机层（签发者视图不含 Id_u/M——陷害标量来源③切断；π_link=Schnorr Σ 主机层实现）。
pub mod sm2_join;
/// T6：mod-n 边界族（(A7) 测试体系；宿主实然行为断言——k=0 钥泄露方程/d 静默规约/inv(1+d) 角行为）。
pub mod sm2_a7_boundary;
/// 🔍T6 根因二分探针（d=n−2 s≡0 不变量的定位件；BigUint 对照，定位后归档）。
pub mod sm2_a7_probe;
/// T2 · 参考实现 B（净室二写：GB/T SM3/SM2 验证直译，BigUint 异构算术栈；(A7) 差分第二族）。
pub mod sm2_ref_b;
/// T4+T1 · 公开输入全量扫描 + 随机见证属性测试（(A7) 第三/一族；计数经 A7_T1_N 放量）。
pub mod sm2_a7_props;
/// T5+T7 · 复制环覆盖率 + 非规范编码族（(A7) 第四/七族；单射性样本经 A7_T7_N 放量）。
pub mod sm2_a7_t5_t7;
/// T3 · 欠约束全量化（(A7) 第五族静态全量：死约束/advice-free 扫描 + 自由列扫描）。
pub mod sm2_a7_t3;
/// T8 · 机器可读 JSONL 日志（波4 规格：用例名/输入哈希/判定/耗时；`A7_JSON_LOG` 门控）。
pub mod sm2_a7_jsonlog;
/// A5 · 批量开启路线 b(个体开口按 (查询, poly) 去重;PCS_BATCH_DEDUP=1 门控,TDD 件)。
pub mod sm2_a5_route_b;
/// A3 · 流式验证器(两遍设计;手动解析器+差分对拍,地基=from_proof_ref/stream_position)。
pub mod sm2_a3_stream;
/// D27 · 叶交织承诺(批次一盐一树,叶=列值向量;PCS_INTERLEAVE=1 门控,Phase 1 TDD 件)。
pub mod sm2_pcs_interleave;
/// 跨线委托任务 B · 范围门档(merged 级):属性数值谓词块(零触增量扩展;评审门 2026-09-14 放行)。
pub mod sm2_predicate_range;
// 系统线 2026-09-17：SM3 查表化原型（分支 system/sm3-lookup-proto，立项判据用；不入论文线）
pub mod sm3_lookup_proto;
pub mod sm3_lookup_block;
pub mod sm3_lookup_weave;
pub mod sm2_ec_window_proto;

pub mod sm2_ec_window_gadget;

pub(crate) mod test_env {
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        touched: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&'static str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let touched = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
            Self { _lock: lock, touched }
        }
        /// 声明本测试要翻转的变量集（Drop 恢复进入前值）。
        pub(crate) fn toggle(keys: &[&'static str]) -> Self {
            Self::acquire(keys)
        }
        /// 只依赖缺省态（进入时清空声明集，Drop 恢复）。
        pub(crate) fn defaults(keys: &[&'static str]) -> Self {
            let g = Self::acquire(keys);
            for (k, _) in &g.touched {
                std::env::remove_var(k);
            }
            g
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.touched {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }
}

pub mod sm2_auth_assemble;
pub mod smt_weave;
/// 飞证 B6 · TRAIL 轨迹合规语句（host 单一事实源；与 uas gcs/bridge fence.py 同构）。
pub mod trail_host;
/// 飞证 B6 · TRAIL 织入（范围门/时间门/链头钉——proto 后处理零移位）。
pub mod trail_weave;
#[cfg(test)]
mod sm3_lookup_mutation;

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use num_bigint::BigUint;

    #[test]
    fn field_params_correct() {
        // ff_derive 的 MODULUS 常量以十六进制输出；其值必须 = 国密 SM2 p 的标准十六进制写法
        // （GB/T 32918-2016 附录：fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff），
        // 以此交叉验证 derive 对十进属性解析正确。
        assert_eq!(
            FpSM2::MODULUS,
            "0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"
        );
        // 十进制核对（防十六进制笔误）
        assert_eq!(
            BigUint::parse_bytes(FpSM2::MODULUS.trim_start_matches("0x").as_bytes(), 16)
                .unwrap()
                .to_string(),
            "115792089210356248756420345214020892766250353991924191454421193933289684991999"
        );
        // v2(p-1) = 1（S=1）
        assert_eq!(FpSM2::S, 1);
        // ROOT_OF_UNITY = g^((p-1)/2) 应 = -1（ff 0.13 Field 用关联常量 ZERO/ONE）
        let minus_one = FpSM2::ZERO - FpSM2::ONE;
        assert_eq!(FpSM2::ROOT_OF_UNITY, minus_one);
        assert_eq!(FpSM2::ROOT_OF_UNITY_INV, minus_one);
        assert_eq!(FpSM2::MULTIPLICATIVE_GENERATOR, FpSM2::from(13u64));
    }

    #[test]
    fn generator_is_primitive_root() {
        // g=13 为 F_p^* 原根：[实测] 标准检验——对 p−1 的**每个**素因子 q，g^((p−1)/q) ≠ 1。
        // p−1 素分解（Pollard rho 求得，各因子 Miller-Rabin 验证为素数）：
        //   2 × 43 × 30223 × 348253387243 × 4641351449027 × 417514796639753
        //     × 66013261729388519804782124120027
        let p: num_bigint::BigUint =
            BigUint::parse_bytes(FpSM2::MODULUS.trim_start_matches("0x").as_bytes(), 16)
                .unwrap();
        let pm1 = &p - 1u32;
        let primes: Vec<num_bigint::BigUint> = vec![
            "2".parse().unwrap(),
            "43".parse().unwrap(),
            "30223".parse().unwrap(),
            "348253387243".parse().unwrap(),
            "4641351449027".parse().unwrap(),
            "417514796639753".parse().unwrap(),
            "66013261729388519804782124120027".parse().unwrap(),
        ];
        // 乘积 = p−1 自检（防素分解笔误）
        assert_eq!(primes.iter().product::<num_bigint::BigUint>(), pm1);
        let g = FpSM2::from(13u64);
        let one = FpSM2::ONE;
        for q in &primes {
            let e = &pm1 / q;
            assert_ne!(pow_biguint(g, &e), one, "g^((p-1)/{q}) == 1 → 13 非原根");
        }
    }

    fn pow_biguint(base: FpSM2, e: &num_bigint::BigUint) -> FpSM2 {
        // 逐位平方-乘（e 为 BigUint 大端字节）
        let bytes = e.to_bytes_be();
        let mut acc = FpSM2::ONE;
        let mut started = false;
        for byte in bytes {
            for i in (0..8).rev() {
                acc = acc.square();
                if (byte >> i) & 1 == 1 {
                    if started {
                        acc *= base;
                    } else {
                        acc = base;
                        started = true;
                    }
                }
            }
        }
        acc
    }

    #[test]
    fn field_arithmetic_smoke() {
        let a = FpSM2::from(5u64);
        let b = FpSM2::from(7u64);
        assert_eq!((a * b).to_repr(), FpSM2::from(35u64).to_repr());
        // -1 语义：(-1)^2 = 1，(-1)+1 = 0
        let minus_one = FpSM2::ZERO - FpSM2::ONE;
        assert_eq!(minus_one.square(), FpSM2::ONE);
        assert_eq!(minus_one + FpSM2::ONE, FpSM2::ZERO);
    }

    // ── D18 Phase 1（盐化 Merkle）指纹消灭门禁（真实栈 FpSM2+Sm3）──────────────
    // T1.3b 定案：未盐化时同 witness 两次 commit 的根逐位复现=跨会话用户确定性
    // 指纹（恒定列 standalone 52.9%/merged 73.9%/T1 99.3% [实测 2026-09-02]）。
    // 盐化后：每树独立 OsRng 盐 ⟹ 根必不同。常驻全量门禁（92→93）。
    #[test]
    fn zk_phase1_fingerprint_gate_fp_sm2_sm3() {
        use plonkish_backend::pcs::PolynomialCommitmentScheme;
        use plonkish_backend::pcs::multilinear::{Basefold, BasefoldExtParams};
        use plonkish_backend::poly::multilinear::MultilinearPolynomial;
        use plonkish_backend::util::hash::{Output, Sm3};
        use rand_core::OsRng;

        #[derive(Debug)]
        struct SaltGateSpec;
        impl BasefoldExtParams for SaltGateSpec {
            fn get_reps() -> usize {
                2
            }
            fn get_rate() -> usize {
                1
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
        type Pcs = Basefold<FpSM2, Sm3, SaltGateSpec>;
        let num_vars = 8;
        let poly_size = 1 << num_vars;
        let (pp, _) = {
            let param = Pcs::setup(poly_size, 1, &mut OsRng).unwrap();
            Pcs::trim(&param, poly_size, 1).unwrap()
        };
        let poly = MultilinearPolynomial::rand(num_vars, OsRng);
        let c1 = Pcs::commit(&pp, &poly).unwrap();
        let c2 = Pcs::commit(&pp, &poly).unwrap();
        let r1 = AsRef::<Output<Sm3>>::as_ref(&c1).clone();
        let r2 = AsRef::<Output<Sm3>>::as_ref(&c2).clone();
        assert_ne!(
            r1, r2,
            "同 witness 两次 commit 根逐位相同=确定性指纹未消灭（真实栈 FpSM2+Sm3）"
        );
    }
}
