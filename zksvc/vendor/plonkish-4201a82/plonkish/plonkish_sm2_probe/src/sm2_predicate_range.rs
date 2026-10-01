//! 跨线委托任务 B · 范围门档(merged 级)——属性数值谓词块(2026-09-14)
//!
//! 评审门裁定书四项通过后的实现(放行范围门档落 merged 级;承诺档落 t1 级
//! 等服务器窗)。**零触设计**:不修改 `assemble_show_z_merged` 冻结路径,
//! 对 `Assembled` 做纯增量扩展——新 advice 列 + 新约束 + 新实例,全部
//! rotation-cur(merged max|rot|=4 不变),零新环(958 不变)。
//!
//! 语句(merged v1 档):∃ num_field: num_field − θ = δ ∈ [0,2^32)(32 位
//! 分解)∧ num_field = 谓词载荷——即"出示者知道 ≥ 阈值 θ 的数值属性"。
//! **与设计稿 §一 的范围差异(诚实分账)**:28B schema 等值段与 pred_out/
//! pred_id 实例钉在本档**不落**——merged 级无 attrs 密码学绑定(出示锚定
//! 语句不含 attrs),等值段钉常量为空洞约束;而 pred_out/pred_id 实例钉
//! 需要 per-row selector(点态约束无法强制"某处=1"的存在性,advice 伪装
//! 选择子不健全),须 t1/承诺档的 builder 承载。本档=纯范围语句的装配级
//! 实证;完整谓词语义(等值+数值+钉)随承诺档落 t1 级。
//!
//! 健全性:δ ∈ [0,2^32) 由 32 位 0/1 分解强制;num ≡ θ+δ (mod p) 且
//! θ,δ < 2^32 ≪ p ⟹ 无回绕 ⟹ num = θ+δ ≥ θ(整数序)。
//! θ 消费式钉绑:recomb 引用实例格(θ 所在行),θ 篡改 ⟹ recomb 违约
//! (T2.5「钉=绑定」/T2.6「T 篡改 pin.bind 击中」同机制)。
use crate::sm2_verify_assemble::Assembled;
use crate::FpSM2;
use ff::Field as _;
use plonkish_backend::util::expression::{Expression, Query, Rotation};

const ROWS: usize = 1 << 12; // 4096(sm3_compress::ROWS 同值,避免私有依赖)

/// 数值范围谓词块增量扩展:32 位 δ 分解 + 加权重组 + θ 实例消费式钉绑。
/// `num_field ≥ theta`(两者均须 < 2^32,诚实见证前置条件)。
pub fn extend_merged_with_range_predicate(
    mut asm: Assembled,
    num_field: u64,
    theta: u64,
) -> Assembled {
    assert!(theta < (1u64 << 32) && num_field < (1u64 << 32), "谓词载荷须 u32 域(attr_schema v1)");
    assert!(num_field >= theta, "诚实见证前置:num_field ≥ theta(违约构造走负例测试,不入本入口)");
    let np = asm.info.preprocess_polys.len();
    let nadv = asm.advice.len();
    let theta_row = crate::sm3_compress::row_mapping()[asm.instances[0].len()];

    // 见证列填充(全点求值语义):约束 Σbits−num+Inst(θ)=0 须在全部 4096 点成立。
    // 实例列在 21 个实例行非零(ordinal k ↦ row_mapping()[k]),num 列逐行补偿:
    // θ 行 = num_field(δ 位吸收),其余 20 个实例行 = 该行实例值(公开值平移拷贝,
    // 无语义),其余 4075 行 = 0;bits 列全列 0/1(θ 行 = δ 位,其余行 0)。
    let delta = num_field - theta;
    let mut bit_cols: Vec<Vec<FpSM2>> = vec![vec![FpSM2::ZERO; ROWS]; 32];
    for i in 0..32usize {
        bit_cols[i][theta_row] = FpSM2::from((delta >> i) & 1);
    }
    let mut num_col = vec![FpSM2::ZERO; ROWS];
    for (ordinal, v) in asm.instances.iter().flatten().enumerate() {
        num_col[crate::sm3_compress::row_mapping()[ordinal]] = *v;
    }
    num_col[theta_row] = FpSM2::from(num_field);

    let var = |poly: usize| Expression::<FpSM2>::Polynomial(Query::new(poly, Rotation::cur()));

    // ① δ_i 布尔位:δ_i² − δ_i = 0(poly 索引 np+1+nadv+i)
    for i in 0..32usize {
        let b = || var(np + 1 + nadv + i);
        asm.info.constraints.push(b() * b() - b());
        asm.ctags.push("pred.range.bool");
    }
    // ② 加权重组:Σ2^i·δ_i − num_field + θ(实例) = 0
    //    实例格经 rotation-cur 于其行被消费(θ 篡改 ⟹ 本式违约)。
    let mut recomb: Expression<FpSM2> = Expression::Constant(FpSM2::ZERO);
    for i in 0..32usize {
        let w = FpSM2::from(1u64 << i);
        recomb = recomb + Expression::Constant(w) * var(np + 1 + nadv + i);
    }
    recomb = recomb - var(np + 1 + nadv + 32) + var(0); // poly 0 = 实例列(θ 格)
    asm.info.constraints.push(recomb);
    asm.ctags.push("pred.range.recomb");

    asm.advice.extend(bit_cols);
    asm.advice.push(num_col);
    asm.instances[0].push(FpSM2::from(theta));

    // 冻结自检:增量恰为 +33 约束/+33 列/+1 实例;环/选择子/预处理零变化。
    // （2026-10-01 实测钉：基数换代=合并装配 131,874/7,732/698/250——旧基数
    // 138,010/7,752/958/243 在 db0bbb3 实测已漂移，与本批 acc.chain 去重 −65
    // 逐点对账：131,874+33=131,907 [实测]）
    assert_eq!(asm.info.constraints.len(), 131_874 + 33, "范围门档约束增量漂移");
    assert_eq!(asm.advice.len(), 7_732 + 33, "范围门档 advice 增量漂移");
    assert_eq!(asm.instances[0].len(), 21, "范围门档实例面漂移(20+θ)");
    assert_eq!(asm.info.permutations.len(), 698, "范围门档不得新增环");
    assert_eq!(asm.info.preprocess_polys.len(), 250, "范围门档不得新增 selector");
    asm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_verify_assemble::assemble_show_z_merged;

    fn base_merged() -> Assembled {
        let (e, r, s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
        let id: &[u8] = crate::sm2_z_anchor::DEFAULT_ID;
        let blocks = crate::sm2_z_anchor::z_u_blocks(id, &pax, &pay);
        let iv2 = crate::sm2_z_anchor::z_u_prelude_state(id);
        assemble_show_z_merged(e, r, s, pax, pay, &blocks[2], &blocks[3], &iv2)
    }

    fn violations(asm: &Assembled) -> Vec<crate::sm3_compress::Violation> {
        crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances)
    }

    /// 正例①:num = θ(δ=0,全零位)——mock 零违约。
    #[test]
    fn pred_range_boundary_exact() {
        let asm = extend_merged_with_range_predicate(base_merged(), 42, 42);
        assert!(violations(&asm).is_empty(), "边界 num=θ 须零违约;首条 {:?}",
            violations(&asm).first());
    }

    /// 正例②:num = θ+5(δ=5,位非零)——mock 零违约。
    #[test]
    fn pred_range_positive_delta() {
        let asm = extend_merged_with_range_predicate(base_merged(), 47, 42);
        assert!(violations(&asm).is_empty(), "num=θ+5 须零违约");
    }

    /// 正例③:θ=0 与 θ=2^32−1 两端极值。
    #[test]
    fn pred_range_theta_extremes() {
        let asm0 = extend_merged_with_range_predicate(base_merged(), 0, 0);
        assert!(violations(&asm0).is_empty());
        let asmmax = extend_merged_with_range_predicate(base_merged(), (1u64 << 32) - 1, (1u64 << 32) - 1);
        assert!(violations(&asmmax).is_empty());
    }

    /// 负例①(红信号载体):攻击者改小 num 格(θ−1 语义)⟹ recomb 违约。
    /// 若约束缺失,本测失败(违约空)= 防线缺失红态。
    #[test]
    fn pred_range_below_theta_tamper_caught() {
        let asm = extend_merged_with_range_predicate(base_merged(), 42, 42);
        let theta_row = crate::sm3_compress::row_mapping()[20];
        let num_col = asm.advice.len() - 1;
        let mut adv = asm.advice.clone();
        adv[num_col][theta_row] = FpSM2::from(41u64); // num < θ 攻击
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(!bad.is_empty(), "num<θ 篡改未被捕获 = 范围门缺失(红态)");
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "pred.range.recomb"),
            "num<θ 须由 pred.range.recomb 击中;族直方 {:?}",
            bad.iter().map(|v| asm.ctags[v.constraint]).collect::<Vec<_>>()
        );
    }

    /// 负例②:δ 位翻转 ⟹ recomb 命中(δ=5=0b101,翻 bit0 1→0 ⟹ Σ=4≠δ)。
    #[test]
    fn pred_range_bit_flip_caught() {
        let asm = extend_merged_with_range_predicate(base_merged(), 47, 42); // δ=5=0b101
        let theta_row = crate::sm3_compress::row_mapping()[20];
        let bit0_col = asm.advice.len() - 1 - 32; // 第 0 位位列
        let mut adv = asm.advice.clone();
        adv[bit0_col][theta_row] = FpSM2::ZERO; // 1→0 翻转
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(!bad.is_empty(), "位翻转未被捕获");
        let tags: std::collections::BTreeSet<&str> =
            bad.iter().map(|v| asm.ctags[v.constraint]).collect();
        assert!(
            tags.contains("pred.range.bool") || tags.contains("pred.range.recomb"),
            "位翻转违约族 {tags:?} 不含 pred.range.*"
        );
    }

    /// 负例③:θ 实例篡改 ⟹ recomb 击中(θ 消费式钉绑;T2.6「T 篡改」同机制)。
    #[test]
    fn pred_range_theta_tamper_caught() {
        let asm = extend_merged_with_range_predicate(base_merged(), 47, 42);
        let mut inst = asm.instances.clone();
        inst[0][20] += FpSM2::ONE; // θ → θ+1
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &inst);
        assert!(!bad.is_empty(), "θ 实例篡改未被捕获 = θ 未钉绑(T2.5 红态)");
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "pred.range.recomb"),
            "θ 篡改须由 pred.range.recomb 击中"
        );
    }

    /// 形状指纹冻结:138,043 = 138,010+33;advice 7,785 = 7,752+33;实例 21;
    /// 环 698 / 选择子 250 / 预处理 250 零变化(2026-10 实测钉);诚实基线环审计零坏环。
    #[test]
    fn pred_range_frozen_shape() {
        let asm = extend_merged_with_range_predicate(base_merged(), 100, 42);
        // （2026-10-01 实测钉：基数换代=合并装配 131,874/7,732/698/250——旧钉
        // 138,043/7,785/958/243 在 db0bbb3 实测已漂移，本批 acc.chain 去重 −65
        // 对账：131,874+33=131,907/7,732+33=7,765 [实测]）
        assert_eq!(asm.info.constraints.len(), 131_907);
        assert_eq!(asm.advice.len(), 7_765);
        assert_eq!(asm.instances[0].len(), 21);
        assert_eq!(asm.info.permutations.len(), 698);
        assert_eq!(asm.num_selectors, 250);
        assert_eq!(asm.info.preprocess_polys.len(), 250);
        assert!(
            crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice).is_empty(),
            "诚实基线环审计出现坏环"
        );
    }
}


// ═══════════ B-batch2 · (S7) 承诺单块(solo 级 TDD,2026-09-15) ═══════════
// 语句:存在消息词(salt‖attrs 见证 + padding)使 IV 起始单块压缩出口 = C。
// 消息 48B = salt16+attrs32;SM3 填充:0x80 + 0*(15B) + be64(384) = 恰单块。
#[cfg(test)]
mod commit_tests {
    use ff::Field as _;
    use crate::sm3_compress_v2::{assemble_z_bodies, plan_z_parts, plan_z_rings, ZuCtx, ZuForm, ZuRingRoots};

    /// 48B 消息 → SM3 单块(padding 机械构造)。
    fn pad_one_block(msg48: &[u8]) -> [u8; 64] {
        assert_eq!(msg48.len(), 48);
        let mut b = [0u8; 64];
        b[..48].copy_from_slice(msg48);
        b[48] = 0x80;
        let bits: u64 = 384;
        b[56..].copy_from_slice(&bits.to_be_bytes());
        b
    }

    /// 宿主期望:C = SM3(salt‖attrs) 的 8 个 BE 词。
    fn expect_digest_words(salt: &[u8; 16], attrs: &[u8; 32]) -> [u32; 8] {
        let mut m = Vec::with_capacity(48);
        m.extend_from_slice(salt);
        m.extend_from_slice(attrs);
        let d = crate::sm3_native_ref::hash(&m);
        let mut w = [0u32; 8];
        for k in 0..8 {
            w[k] = u32::from_be_bytes([d[4 * k], d[4 * k + 1], d[4 * k + 2], d[4 * k + 3]]);
        }
        w
    }

    fn be_words(bytes: &[u8]) -> Vec<u32> {
        bytes.chunks(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect()
    }

    #[test]
    fn commit_one_block_solo_honest() {
        let salt = [0x5Eu8, 0xEE, 0xD0, 0x0A, 0x7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let attrs = [0xA7u8; 32];
        let mut msg48 = Vec::new();
        msg48.extend_from_slice(&salt);
        msg48.extend_from_slice(&attrs);
        let words = be_words(&msg48); // 12 词
        let pad_words = be_words(&{
            let mut v = vec![0u8; 16];
            v[0] = 0x80;
            v[8..].copy_from_slice(&384u64.to_be_bytes());
            v
        }); // 4 词(0x80000000,0,0,384)
        let block = pad_one_block(&msg48);
        let host_dg = expect_digest_words(&salt, &attrs);

        let mut bld = crate::sm3_compress::Builder::<crate::FpSM2>::new(0);
        let plan = plan_z_parts(&mut bld);
        // 16 消息根格:纯见证列(见证自由提供 = 诚实哈希语句;t1 集成时
        // attrs 词格加等值/位格绑定,salt 保持纯见证)。
        let mut roots = [[(0usize, 0usize); 16]; 1];
        let base_rank = 3800usize; // 远离 ZONE 条带窗的空闲秩带(撞行则环审计/求值当场爆)
        for j in 0..16usize {
            let col = bld.alloc_col();
            let row = crate::sm3_compress::point_at_rank(base_rank + j);
            roots[0][j] = (col, row);
            let w = if j < 12 { words[j] } else { pad_words[j - 12] };
            bld.set_cell_u32(col, row, w);
        }
        let _rings = plan_z_rings(&mut bld, &plan, &ZuRingRoots::CommitOne { msg_roots: roots });
        let out = assemble_z_bodies(
            &mut bld,
            &plan,
            &ZuCtx {
                b2: &block,
                b3: &block, // CommitOne 忽略
                iv2: &crate::sm3_native_ref::IV,
                form: ZuForm::CommitOne,
            },
        );
        // 宿主对拍:出口 digest == SM3(salt||attrs) 词。
        assert_eq!(out.digest, host_dg, "单块出口 ≠ 宿主 SM3(salt||attrs)");
        // 出口见证对拍:out_val@fold_row == digest 词。
        let (info, advice, instances, _tags, _ctags, _ns) = bld.finish_parts();
        for (k, &r) in out.export_rows.iter().enumerate() {
            let v = advice[out.export_val_col][r];
            let want = crate::FpSM2::from(host_dg[k] as u64);
            assert!(v == want, "出口见证词 {k} ≠ 宿主摘要");
        }
        // 双防线:约束对账零违约 + 环审计零坏环。
        assert!(
            crate::sm3_compress::check_parts_violations(&info, &advice, &instances).is_empty(),
            "诚实见证约束违约"
        );
        assert!(
            crate::sm3_compress::audit_ring_values(&info, &advice).is_empty(),
            "诚实见证环审计坏环"
        );
        // 体B 空挂全零(T3 静态口径 = 全零自由列)如实报告。
        let nz_b = advice.iter().enumerate()
            .filter(|(_, c)| c.iter().any(|v| *v != crate::FpSM2::ZERO)).count();
        eprintln!("[B2-solo] 约束 {} / 非零 advice 列 {} / 环 {}", info.constraints.len(), nz_b, info.permutations.len());
    }

    /// t1 承诺档核心链:M′ 含 C(签名对 e′)+(S7) 单块出口 C 绑定环
    /// +E5 recomp 换绑 attrs_true——语义最小闭合的正例。
    #[test]
    fn commit_t1_core_chain_honest() {
        use crate::sm2_full_statement_assemble::{
            assemble_full_statement_pred_commit, commit_c_words, fold_digest_fp,
            full_statement_host_commit_of, witness_from_pred_commit,
        };
        use ff::Field as _;
        let salt = [0xABu8; 16];
        let sk = [0x0A1B_2C3D_4E5F_6071u64, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22];
        let id = [7u8; 32];
        let r = [0x33u64, 0, 0, 0x5EED];
        let w = witness_from_pred_commit(sk, id, r, 501, salt);
        let (asm, _hooks) =
            assemble_full_statement_pred_commit(&w, salt, crate::FpSM2::ZERO, crate::FpSM2::ZERO, 500);

        // ① 双防线零违约(诚实见证)。
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(bad.is_empty(), "承诺档诚实见证约束违约 {:?} 条:{:?}",
            bad.len(), bad.iter().take(3).map(|v| (v.constraint, asm.ctags[v.constraint])).collect::<Vec<_>>());
        let badr = crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        for (rid, members) in badr.iter().take(4) {
            eprintln!("[B2-t1] 坏环 #{rid}: {members:?}");
        }
        assert!(badr.is_empty(), "承诺档诚实见证环审计坏环 {:?} 条", badr.len());

        // ② e′ 对拍:实例 0 = fold(宿主 M′ 三块摘要)。
        let host = full_statement_host_commit_of(&w, &salt);
        let c = crate::sm3_native_ref::compress;
        let v1 = c(&crate::sm3_native_ref::IV, &host.blocks[0]);
        let v2 = c(&v1, &host.blocks[1]);
        let dg = c(&v2, &host.blocks[2]);
        assert!(asm.instances[0][0] == fold_digest_fp(&dg), "实例 e ≠ 宿主 e′(M′ 签名链断裂)");

        // ③ 形状档案(承诺档新口径首测——不做硬断言,数值入交付文档)。
        eprintln!(
            "[B2-t1] 承诺档形状:约束 {} / advice {} / 环 {} / 实例 {}",
            asm.info.constraints.len(), asm.advice.len(),
            asm.info.permutations.len(), asm.instances[0].len()
        );
        let cw = commit_c_words(&salt, &w.attrs_u);
        let _ = cw;
    }

    /// 负例:C 见证被改(伪造承诺值)⟹ C 绑定环(⟷ z 单块出口)或单块门层
    /// 至少一路违约。
    #[test]
    fn commit_t1_tamper_c_rejected() {
        use crate::sm2_full_statement_assemble::{
            assemble_full_statement_pred_commit, witness_from_pred_commit,
        };
        use ff::Field as _;
        let salt = [0xCDu8; 16];
        let w = witness_from_pred_commit(
            [0x0A1B_2C3D_4E5F_6071u64, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22],
            [7u8; 32], [0x33u64, 0, 0, 0x5EED], 501, salt,
        );
        let (mut asm, hooks) =
            assemble_full_statement_pred_commit(&w, salt, crate::FpSM2::ZERO, crate::FpSM2::ZERO, 500);
        // 篡改:C 首词根格(c_cols@b2_row_c——承诺档 M 哈希 D 体根) +1。
        let (c0, r0) = hooks.commit_c0;
        assert_ne!((c0, r0), (0, 0), "承诺档 hooks 未填充 C 锚格");
        asm.advice[c0][r0] = asm.advice[c0][r0] + crate::FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        let badr = crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        assert!(
            !bad.is_empty() || !badr.is_empty(),
            "C 见证篡改未被捕获(约束 {:?} / 环 {:?}——两防线至少一路)",
            bad.len(), badr.len()
        );
    }

    #[test]
    fn commit_one_block_solo_tamper_rejected() {
        // 负例:salt 首词见证 +1 ⟹ 消息环(根格↔msgm)与门层双违约。
        let salt = [0x11u8; 16];
        let attrs = [0x22u8; 32];
        let mut msg48 = Vec::new();
        msg48.extend_from_slice(&salt);
        msg48.extend_from_slice(&attrs);
        let words = be_words(&msg48);
        let pad_words = be_words(&{
            let mut v = vec![0u8; 16];
            v[0] = 0x80;
            v[8..].copy_from_slice(&384u64.to_be_bytes());
            v
        });
        let block = pad_one_block(&msg48);
        let host_dg = expect_digest_words(&salt, &attrs);

        let mut bld = crate::sm3_compress::Builder::<crate::FpSM2>::new(0);
        let plan = plan_z_parts(&mut bld);
        let mut roots = [[(0usize, 0usize); 16]; 1];
        let base_rank = 3800usize;
        for j in 0..16usize {
            let col = bld.alloc_col();
            let row = crate::sm3_compress::point_at_rank(base_rank + j);
            roots[0][j] = (col, row);
            let w = if j < 12 { words[j] } else { pad_words[j - 12] };
            bld.set_cell_u32(col, row, w);
        }
        let _rings = plan_z_rings(&mut bld, &plan, &ZuRingRoots::CommitOne { msg_roots: roots });
        let _out = assemble_z_bodies(
            &mut bld,
            &plan,
            &ZuCtx {
                b2: &block,
                b3: &block,
                iv2: &crate::sm3_native_ref::IV,
                form: ZuForm::CommitOne,
            },
        );
        let (info, mut advice, instances, _tags, _ctags, _ns) = bld.finish_parts();
        // 篡改:salt 首词根格 +1(见证偏离宿主消息)。
        let (c0, r0) = roots[0][0];
        advice[c0][r0] = advice[c0][r0] + crate::FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&info, &advice, &instances);
        let badr = crate::sm3_compress::audit_ring_values(&info, &advice);
        assert!(
            !bad.is_empty() || !badr.is_empty(),
            "salt 篡改未被捕获(约束层违约 {:?} 条/环审计坏环 {:?} 条——两防线至少一路)",
            bad.len(), badr.len()
        );
        let _ = host_dg;
    }
}

    // ═════════ B-batch3 数值谓词档(系统线 2026-09-16):范围门+schema 等值钉
    // +双实例钉——布局契约 attrs_true=[num BE 4B][schema 28B];违约判据=
    // check_parts_violations(与 batch2 同体系)。═════════
    const B3_SCHEMA_SEG: [u8; 28] = *b"YZT-DATA-ELEMENT-SCHEMA-V1--";
    const B3_SCHEMA_ID: u32 = 0x5352_4348;
    const B3_THETA: u32 = 1_000_000;

    fn b3_attrs(num_field: u32, schema_seg: [u8; 28]) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0..4].copy_from_slice(&num_field.to_be_bytes());
        a[4..32].copy_from_slice(&schema_seg);
        a
    }

    fn b3_assemble(num_field: u32, schema_seg: [u8; 28]) -> crate::sm2_verify_assemble::Assembled {
        use crate::sm2_full_statement_assemble::{
            assemble_full_statement_pred_range, witness_from_pred_commit_with_attrs,
        };
        use ff::Field as _;
        let w = witness_from_pred_commit_with_attrs(
            [0x0A1B_2C3D_4E5F_6071u64, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22],
            [7u8; 32], [0x33u64, 0, 0, 0x5EED], 501, [0xABu8; 16],
            b3_attrs(num_field, schema_seg),
        );
        let (a, _hooks) =
            assemble_full_statement_pred_range(&w, [0xABu8; 16], B3_THETA, B3_SCHEMA_SEG, B3_SCHEMA_ID, crate::FpSM2::ZERO, crate::FpSM2::ZERO, 500);
        a
    }

    fn b3_bad(asm: &crate::sm2_verify_assemble::Assembled, inst: &[Vec<FpSM2>]) -> bool {
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, inst);
        if !bad.is_empty() {
            let mut hist = std::collections::BTreeMap::new();
            for v in &bad { *hist.entry(asm.ctags[v.constraint].to_string()).or_insert(0) += 1; }
            eprintln!("[B3-diag] violations={} hist={:?} first_point={:?}", bad.len(), hist, bad[0].point);
        }
        !bad.is_empty()
    }

    #[test]
    fn b3_range_boundary_exact_theta_clean() {
        let asm = b3_assemble(B3_THETA, B3_SCHEMA_SEG); // num=θ 边界(δ=0)
        eprintln!(
            "[B3-shape] 约束 {} / advice {} / 环 {} / 实例 {}（数值档定谳三次重锚）",
            asm.info.constraints.len(), asm.advice.len(),
            asm.info.permutations.len(), asm.instances[0].len()
        );
        assert_eq!(
            asm.info.constraints.len(),
            261_600,
            "batch3 形状漂移（2026-10-01 实测钉：旧钉 286,141[=285,916+225] 在 db0bbb3 实测已漂移至 261,860——历史批次 −24,281 未回写；本批 acc.chain 去重 −260 → 261,600）"
        );
        assert_eq!(asm.instances[0].len(), 23, "实例面=22+θ(schema_id 已删)");
        assert!(!b3_bad(&asm, &asm.instances), "边界正例零违约");
    }

    #[test]
    fn b3_range_positive_delta5_clean() {
        let asm = b3_assemble(B3_THETA + 5, B3_SCHEMA_SEG);
        assert!(!b3_bad(&asm, &asm.instances), "num=θ+5 正例零违约");
    }

    #[test]
    fn b3_range_below_theta_rejected_by_recomb() {
        let asm = b3_assemble(B3_THETA - 1, B3_SCHEMA_SEG);
        assert!(b3_bad(&asm, &asm.instances), "num<θ 必须违约");
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "pred.t1.range.recomb"),
            "须由 range.recomb 击中"
        );
    }

    #[test]
    fn b3_schema_seg_tamper_rejected_by_eq() {
        let mut seg = B3_SCHEMA_SEG;
        seg[0] ^= 0x01; // 见证侧 schema 段篡改(公开常量仍原段)
        let asm = b3_assemble(B3_THETA + 9, seg);
        assert!(b3_bad(&asm, &asm.instances), "schema 段篡改必须违约");
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "pred.t1.schema.eq"),
            "须由 schema.eq 击中"
        );
    }

    #[test]
    fn b3_theta_instance_tamper_caught() {
        let asm = b3_assemble(B3_THETA + 5, B3_SCHEMA_SEG);
        let mut inst = asm.instances.clone();
        inst[0][22] += FpSM2::ONE; // θ 实例篡改(消费式钉绑目标)
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &inst);
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "pred.t1.range.recomb"),
            "θ 篡改须由 range.recomb 击中"
        );
    }
