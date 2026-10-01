//! 簇J T1 全语句 (S1)–(S6) Plonkish 装配器（蓝图 `Z_ANCHOR_BLUEPRINT.md` §四·8）。
//!
//! 语句（正文 §4 def:pi）：witness w = (sk_u, pk_u, Id_u, attrs_u, exp_u, r, r_s, s_s)；
//! (S1) e := SM3(Z_A‖x(Id_u·G)‖attrs_u‖pk_u‖exp_u‖parity(y(Id_u·G)))，165B → 3 块
//! （A1″ 压缩点绑定：B₁=Z_A‖x(Id·G)、B₂=attrs_u‖pk_u.x、B₃=pk_u.y‖exp_u‖parity‖pad，
//! parity@b3[36]=0x02+(y mod 2)、0x80@b3[37] + be64(1320)@b3[56..64]；
//! parity 封死 Id↦n−Id 符号歧义——x(−P)=x(P) 但 parity(−y)≠parity(y)）；
//! (S2) 验签体 16,554 零接触复用；(S3) C₁=r·G ∧ C₂=Id_u·G+r·apk；
//! (S4) pk_u=sk_u·G；(S5) pred_out=1；(S6) exp_u ≥ T（T2.6 有效期，T=实例 21）。
//! 公开面 = (C₁,C₂,pred_out,pk_I,apk,Z_A,ctx_tag,pred_id,T)—— 无摘要（J-4 权威）。
//!
//! ## E4/E5 状态（J-10b ③ 定案，2026-08-31；A1'/A1″ 换代注）
//! 一次装配全三体 + 验签体：体C = Z_A 8 常量锚 + 身份分量 8 词（A1' 起 =
//! x(Id_u·G) 经 dec_idgx 分解 recomp；A1″ 另加 dec_idgy 256 位分解取 LSB
//! 供压缩奇偶字节）；体D attrs 已 **E5 换绑定**（256 位格 +
//! bool + 8 recomp 原格换约束）；体E pk_u 16 词仍占位常量锚（宿主真值烘焙，
//! E8 原格换约束）。词源秩分配（J-10b ④）：Id@49、
//! attrs@50、Z_A 锚@51..58、pad 锚@59..66、pk_u 词格@RANK_PA=32；全部 rot=0。
//! 摘要出口 [`ChainEcho::Fold`]（实例面 = 19 = 验签体 12 + 全语句新增 7，
//! 后者 E10 前零占位）：echo 环落 dgw 8 列 @ e 面工作锚 srow(RANK_A_E) 行。
//! **E7 状态（2026-08-31）：e 绑定已封口**——验签体五元组全真源（e =
//! [`fold_digest_fp`] 大折叠宿主值 + 对其的真 SM2 签名 r_s/s_s + 自生成签发者
//! 钥对 pk_i=[d_i]G），电路侧 = ⑧′ 一条全 cur 折叠约束
//! Σ2^{32k}·dgw_k == pv@row_ae（发射在 e 面词位家族选择器上，勘误 #26 守卫
//! 锁定激活点；pv ↔ 实例 0 由 rid_pv 环 + pin.bind 缝合，J-4/D3 权威）。
//!
//! **E8 状态（2026-08-31，J-d1）**：(S4) 封口——[sk_u]G 固定基循环 257 连续秩
//! 行共享 ZONE0 条带带（1071..=1327，J-10a 裁决；Fix R-a 修复后的循环族）；
//! 基点绑定 = sk 循环 base/d2v 锚点格经 G/2G 常量钉面大环**追加成员**（不开
//! 新环，merged st_pax 先例）——否则基点自由 ⟹ prover 取 sk_u=1、base=pk_u
//! 使 (S4) 空洞；输出 x/y 经传输环进 st_pkx/st_pky @ row_pk → 双 decompose
//! → 16 词 recomp（占位常量锚拆除，msg_roots 根不动 = 原格换约束，簇H 换根
//! 方案）；sk 标量世界 @ RANK_SK=67 行：256 位布尔 + lt_n + neq_zero（
//! sk_u∈[1,n−1]，R1CS 线 M7=532 口径对齐）。
//!
//! **E9 状态（2026-08-31，J-d2）**：(S3a) 封口——C₁=r·G 与 Id·G 两固定基循环
//! （Fix R-a 修复族 257 连续秩：C₁@3184..=3440、Id·G@3441..=3697，自由带）+
//! r 标量世界 @RANK_R=68（256 位布尔 + lt_n + neq_zero，r∈[1,n−1]）+ 基点绑定
//! （base/d2v 锚格经 G/2G 大环追加，E8 同款）；**Id·G β 源复用 E4 消息侧
//! id_bit_cols**——Id_u 的哈希消费与 EC 消费同位格（双绑通道，(S1)↔(S3) 电路内
//! 不可分割）；两循环输出经传输环进 st_c1x/st_c1y@row_r、st_idgx/st_idgy@row_id
//! 暂存（E10 C₂ 完全加 + 实例钉消费）。E8 段宿主常量上提共享。
//!
//! **E10 状态（2026-08-31，J-d3）**：(S3b) 封口——apk staged 基头（on_curve
//! 12 门 + 2·apk 绑定，EP 基头同款，落 row_hra=秩 3955）+ r·apk 变基循环
//! （Fix R-a 族 257 连续秩 3698..=3954；**β 源 = rid_beta_c1 共享追加**——
//! 与 C₁ 循环同标量 r 同位格，一格一环红线下 β 环零新增）+ C₂ = Id·G +
//! r·apk 完全加（28 门 @ row_ac2=秩 3956）+ 6 实例钉（12..17 = C₁/C₂/apk
//! 公开面，pin_rows = row_mapping()[12+k] 即秩 13..18）。基点绑定 = apk
//! staging 基/倍通道大环（首键 = 钉格/staged 格，EP 同款：钉值经环置换
//! 直达循环基点）；Id·G 加数经 E9 暂存环追加成员 + 新 inf 二元小环；
//! r·apk 尾经新 3 环进 C₂；C₂ 输出经新 2 钉环进实例面（res2.inf 不出环
//! ——两加数非 O ⟹ 输出 inf 被 28 门内蕴，verify body x₁ 同款论证）。
//!
//! **E11 状态（2026-08-31，J-e1）**：(S5) 封口——谓词湮灭 + pred_out 实例 18。
//! 谓词语义 = R1CS M6 先例（m0_sm3_circuit/show_circuit_r1cs.rs
//! `enforce_pred`）："attrs_u == PRED_TARGET" 单属性相等（M2c spec §5：
//! 多属性/区间谓词为扩展）；电路 = 256 湮灭乘门
//! pred_out·(attrs_bit−target_bit)=0 + pred_out=1 线性 + pin.bind 实例 18
//! （def:pi (S5) 公开面）。**勘误 #28**：实例列仅住在钉行
//! （inst_at[row_mapping()[k]]=inst[k]）⟹ pin.bind 激活点 = 钉行
//! row_mapping()[18]（秩 19）、钉值格落钉行、与谓词工作格（@row_attrs）经
//! rid_pred_pin 环缝合；谓词族/钉族两选择器分立（激活点各恰 1 点，#26）。
//! 位序 = 整数位 i（LSB=0）= 字节 31−i/8 位 i%8，
//! 与 ④ recomp/EC 消费侧同源（be_word_bit_terms crosscheck 锁定）。
//!
//! **T2.6 状态（2026-09-03，P2 第六项；A1″ 换代注）**：(S6) 有效期封口——
//! 身份/有效期尾段入哈希消息（现 165B，块数 3 不变 [推得：165+9=174≤192，
//! 装配/census 断言实测承载]）+
//! 语句 `exp_u ≥ T`，T = 实例 21（验证方注入当前 epoch，pin.bind 缝合 =
//! 「钉=绑定」T2.5 机制自动覆盖，零新增理论；钉行 = row_mapping()[21] 即
//! 秩 22，勘误 #28 对齐）。gadget 全落钉行（exp 词格 + T 钉格 + 32 d 位格，
//! 全 rot=0 零新增环）：exp 词格经 msg_roots 体E 词 8 换源入 (S1) 哈希
//! （(S1)↔(S6) 双绑通道——篡改 exp ⟹ 哈希断裂 + 分解失配双信号，消息根
//! 环审计随行）；d := exp_u − T 的 32 位分解（bool ×32 + 组合 1 条
//! Σ2^{31−p}·d_p − exp + T == 0）——分解唯一性 ⟹ d ∈ [0,2^32) ⟺ exp_u ≥ T
//! （exp_u<T ⟹ d=p−(T−exp_u)≫2^32 不可分解，假语句不可满足）。最小形态：
//! exp 词值复用消息环成员（无 recomp/无重编译——exp 词 32 位有界性由组合
//! 约束一并承担，设计定案 §八「gadget 自带分解」兜底未触发）。T 篡改 =
//! 验证方自注入失败（与 pred_id 同位）；过期凭证 ⟹ 不可满足。
//!
//! plan 相顺序（J-10b ⑤）：dgw/词源全 alloc → [`plan_chained_parts`] →
//! [`plan_all`] → msg_roots 表 → [`plan_chained_rings`] → EMIT。

use crate::sm2_scalar_plonkish::{
    emit_decompose, emit_lt_n, emit_neq_zero, plan_add, plan_decomp, plan_neq, PlScalar,
};
use crate::sm2_verify_assemble::{
    emit_verify_body, finish_verify_assembly, plan_all, Assembled, RANK_A_E, RANK_PA,
};
use crate::sm3_compress::{point_at_rank, Builder};
use crate::sm3_compress_v2::{
    assemble_chained_bodies, plan_chained_parts, plan_chained_rings, off, ChainEcho, ChainedCtx,
    H_STRIPE, MsgCell, NUM_STRIPES, RANK_BASE_V2, RANK_END, ZONE0, ZONE_STRIDE,
};
use crate::FpSM2;
use ff::Field;
use plonkish_backend::util::expression::{Expression, Rotation};

// ───────────────────────── T1 词源秩段（J-10b ④） ─────────────────────────
// merged 的 Z_U 常量锚段 34..48 本形态不用（独立段防碰撞）；上界锚定 SM3
// 正文基址 [`crate::sm3_compress_v2::RANK_BASE_V2`]=240。
const RANK_ID: usize = 49; // Id_u：8 词值格 + 256 位格 + recomp/bool 同行
const RANK_ATTRS: usize = 50; // attrs_u：8 词值格同行（E5 加位格）
const RANK_ZA: usize = 51; // Z_A 锚 8 行：51..58（单值列逐格 sel，C4 免疫）
const RANK_PAD: usize = 59; // pad 锚 7 行：59..65（词 0 = exp_u 词归 (S6)，T2.6）
const _: () = assert!(
    RANK_PAD + 7 < crate::sm3_compress_v2::RANK_BASE_V2,
    "T1 词源段必须低于 SM3 正文基址 240"
);

/// (S5) 谓词目标（E11，J-e1）：演示策略属性值——**策略数据非密码常量**
/// （公开 target 烘焙进电路，M2c spec §5「attrs_u == 公开属性值」单属性
/// 相等语义；24+8=32B 恰填词源）。正例见证 attrs_u 必须等于此值（谓词
/// 先定、持有者属性匹配 = 诚实流程；test_witness 断言锁定该契约）。
pub const PRED_TARGET: [u8; 32] = *b"SM2-ZK-DEMO-PRED-TARGET-00000001";

/// T2.6 默认有效期 epoch（legacy/见证默认）：不带 exp 入口（[`witness_from`]
/// 等）的取值。T=0 时 (S6) 平凡满足（d=exp_u 恒可 32 位分解）——旧入口语义
/// 不变；部署由 bound 入口注入真实 T（验证方当前 epoch）。
pub const DEFAULT_EXP_U: u32 = 1_000;

/// 全语句见证（def:pi）。`r`/`apk` 在 E9/E10 接线时启用（当前装配只消费
/// sk_u/pk_u/Id_u/attrs_u/r_s/s_s/pk_i——占位字段挂 allow 防噪）。
#[allow(dead_code)]
#[derive(Clone)]
pub struct FullStatementWitness {
    pub sk_u: [u64; 4],
    pub pk_u: (FpSM2, FpSM2),
    pub id_u: [u8; 32],
    pub attrs_u: [u8; 32],
    /// 有效期 epoch（T2.6 (S6)：M := (Id_u‖attrs_u‖pk_u‖exp_u) 的 4B 尾段；
    /// BE uint32，入哈希不入 EC ⟹ 无 mod-n 规范性问题）。
    pub exp_u: u32,
    pub r: [u64; 4],
    pub r_s: [u64; 4],
    pub s_s: [u64; 4],
    pub pk_i: (FpSM2, FpSM2),
    pub apk: (FpSM2, FpSM2),
}

/// T1 宿主真值（唯一真值源）：三块消息 + Z_A 词 + pad 词。全部机械派生自
/// 见证与 native 常量（L2 红线：禁手抄——pad 词取自构造块字节，非字面量）。
/// T2.6：`pad_words[0]` = exp_u 词（消息面词 0，(S1)↔(S6) 双绑通道源）。
pub struct FullStatementHost {
    pub blocks: [[u8; 64]; 3],
    pub za_words: [u32; 8],
    pub pad_words: [u32; 8],
}

/// 宿主块派生（幂等纯函数）：J-1 语句排布 × [`crate::sm2_z_anchor`] 权威。
pub fn full_statement_host(w: &FullStatementWitness) -> FullStatementHost {
    // B₁ 身份分量 = x(Id_u·G)（A1'）——持有者口径（有 id_u，重算点）。
    let id_bits: [bool; 256] =
        std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
    let idg_host = crate::sm2_ec_plonkish::affine_mul_bits(
        &id_bits,
        Some(crate::sm2_ec_plonkish::g_coords()),
    );
    match idg_host {
        Some((x, y)) => {
            let idg_x_be = crate::sm2_z_anchor::fe_be32(&x);
            // 压缩奇偶字节 = 0x02 + (y 的规范整数 LSB)（SEC1 惯例；绑定面）。
            let idg_par = 0x02u8 | (crate::sm2_z_anchor::fe_be32(&y)[31] & 1);
            full_statement_host_with_idgx(&w.pk_i, &idg_x_be, idg_par, &w.attrs_u, &w.pk_u, w.exp_u)
        }
        None => full_statement_host_with_idgx(
            &w.pk_i,
            &[0u8; 32],
            0x02,
            &w.attrs_u,
            &w.pk_u,
            w.exp_u,
        ),
    }
}

/// 点输入版（签发者重算口径，A1″ 第五道）：身份分量由公开点 P 的压缩编码
/// 直接给出——无需 id_u（哈希输入全公开正是 Thm4 归约修复的构造基础）。
/// A1″（2026-09-09）：M 追加尾部奇偶字节 parity(y)∈{0x02,0x03} 封死
/// Id↦n−Id 符号歧义（x(−P)=x(P) 但 parity(−y)≠parity(y) ⟹ M′≠M）。
/// **布局拍板（R-15A）**：parity 置消息尾部（b3[36]），b1/b2 逐字节不变、
/// exp 词（b3[32..36]）保持 32 位对齐——(S1)↔(S6) 双绑通道零触碰。
pub fn full_statement_host_with_idgx(
    pk_i: &(FpSM2, FpSM2),
    idgx_be: &[u8; 32],
    idg_par: u8,
    attrs_u: &[u8; 32],
    pk_u: &(FpSM2, FpSM2),
    exp_u: u32,
) -> FullStatementHost {
    let za_words = crate::sm2_z_anchor::z_a_words(crate::sm2_z_anchor::DEFAULT_ID, pk_i);
    let mut za_be = [0u8; 32];
    for k in 0..8usize {
        za_be[4 * k..4 * k + 4].copy_from_slice(&za_words[k].to_be_bytes());
    }
    let mut b1 = [0u8; 64];
    b1[..32].copy_from_slice(&za_be);
    b1[32..].copy_from_slice(idgx_be);
    // B₂ = attrs_u(32B) ‖ pk_u.x(32B)
    let mut b2 = [0u8; 64];
    b2[..32].copy_from_slice(attrs_u);
    b2[32..].copy_from_slice(&crate::sm2_z_anchor::fe_be32(&pk_u.0));
    // B₃ = pk_u.y(32B) ‖ exp_u(4B) ‖ parity(1B) ‖ pad（0x80 @ 块内 37B 位 +
    // 零填充 + be64(1320) @ 尾 8B；165B 语句位长 = 1320，块数 3 不变
    // [推得：165+9=174≤192，实测：装配/census 断言]；禁沿用 Z_U 的 1680；
    // exp_u = T2.6 有效期尾段，BE uint32，入哈希不入 EC；尾部布局保持
    // pad_words[0]=exp 词对齐——(S1)↔(S6) 双绑通道原样）
    let mut b3 = [0u8; 64];
    b3[..32].copy_from_slice(&crate::sm2_z_anchor::fe_be32(&pk_u.1));
    b3[32..36].copy_from_slice(&exp_u.to_be_bytes());
    b3[36] = idg_par;
    b3[37] = 0x80;
    b3[56..64].copy_from_slice(&1320u64.to_be_bytes());
    let pad_words: [u32; 8] = std::array::from_fn(|k| {
        u32::from_be_bytes(b3[32 + 4 * k..36 + 4 * k].try_into().expect("块内界内"))
    });
    FullStatementHost { blocks: [b1, b2, b3], za_words, pad_words }
}

/// 摘要 8 词大折叠的宿主值（F_p 算术，与 E7 电路约束同式同系数——f_pow2
/// 权威派生，禁手抄）。(S1) 的公开语句值 e 即此（域注记：摘要整数 ≥ p 的
/// 备择事件 ~2^-32，J-1 升格簿记——SM3 抗原像类口径，无额外健全性损失）。
pub fn fold_digest_fp(dg: &[u32; 8]) -> FpSM2 {
    let mut e = FpSM2::ZERO;
    for (k, &wv) in dg.iter().enumerate() {
        e += FpSM2::from(u64::from(wv)) * crate::sm2_params::f_pow2(32 * k);
    }
    e
}

/// Id_u/attrs_u 的 BE 词位映射（禁手抄——纯宿主函数，crosscheck 测试
/// [`tests::be_word_bit_terms_crosscheck`] 锁定）。
///
/// 词 j = u32::from_be_bytes(bytes[4j..4j+4])；词位 p（0=MSB）权重 2^{31−p}；
/// 32 字节串按 BE 解释为 256 位整数（LSB=0 位序，与 decompose/EC 循环同序），
/// 整数位索引 = 255−32j−p。返回 (整数位索引, 权重指数) 对，按 p 升序。
pub(crate) fn be_word_bit_terms(j: usize) -> [(usize, u32); 32] {
    std::array::from_fn(|p| (255usize - 32 * j - p, (31 - p) as u32))
}

/// 全语句装配钩子（测试/负例/E5–E10 接线锚点）。`apk_pin` 在 E10 实装前为
/// (0,0) 占位；`attrs_bit0` 自 E5 起已填充。
#[derive(Clone, Copy, Debug, Default)]
pub struct FullStatementHooks {
    /// Z_A 常量锚首格 (列, 行)（篡改负例锚：Z_A 字节 → 体C 消息根漂移）。
    pub za_anchor0: (usize, usize),
    /// apk 钉格（E10）。
    pub apk_pin: (usize, usize),
    /// attrs 位首格（E5）。
    pub attrs_bit0: (usize, usize),
    /// dgw 首格 (列, 行)（E7 大折叠读口；echo 环落点）。
    pub dgw0: (usize, usize),
    /// dgw 8 词列（行 = `dgw0.1`；E7 大折叠 Σ2^{32k}·dgw_k == e 消费）。
    pub dgw_cols: [usize; 8],
    /// 体C 首条带 SS1PRE 行（诊断锚）。
    pub row_c0: usize,
    /// 体E 末条带 TT2 行（诊断锚）。
    pub row_e0: usize,
    /// 链态宿主真值 [V₁, V₂]（ChainedOut 透传；对拍/负例锚）。
    pub chain_states: [[u32; 8]; 2],
    /// 摘要宿主真值（ChainedOut 透传；== native 手链终判）。
    pub digest: [u32; 8],
    /// sk 位首格 (列, 行)（E8；E12 负例④锚：sk 位翻转 ⟹ [sk_u]G ≠ pk_u）。
    pub sk_bit0: (usize, usize),
    /// pk_u.x 词 8 列（行 = `row_pk`；E8 换根重组格 = SM3 体D 消息根）。
    pub pkx_cols: [usize; 8],
    /// pk_u.y 词 8 列（SM3 体E 消息根）。
    pub pky_cols: [usize; 8],
    /// pk 词行（RANK_PA 行；双 decompose + 16 词 recomp 家行）。
    pub row_pk: usize,
    /// sk 循环首行（诊断锚；257 连续秩窗口 1071..=1327 的秩空间起点）。
    pub sk_loop_row0: usize,
    /// r 位首格 (列, 行)（E9；E12 负例⑦锚：r 位翻转 ⟹ C₁/C₂ 双断裂）。
    pub r_bit0: (usize, usize),
    /// C₁.x 暂存格 (列, 行)（E9 传输环落点；E10 实例钉/C₂ 消费）。
    pub c1_x0: (usize, usize),
    /// C₁.y 暂存格（E9）。
    pub c1_y0: (usize, usize),
    /// Id·G.x 暂存格 @ row_id（E9 传输环落点；E10 C₂ 加数）。
    pub idg_x0: (usize, usize),
    /// Id·G.y 暂存格（E9）。
    pub idg_y0: (usize, usize),
    /// apk staged 头 x 格 (列, 行)（E10；E12 负例⑧锚：apk staged 翻转 ⟹
    /// on_curve 门 mock + base_a 大环审计双信号齐爆）。
    pub apk_stg0: (usize, usize),
    /// pred_out 谓词工作格 (列, 行=row_attrs)（E11；E12 矩阵⑨锚：1→0 ⟹
    /// 线性 assert.zero mock 违约 + rid_pred_pin 环审计违约双信号齐爆、
    /// 湮灭门变空转；湮灭族激活证据走 attrs 位格翻转，s5 测试②）。
    pub pred_cell: (usize, usize),
    /// pred_out 钉值格 (列, 行=row_mapping()[18]=秩 19)（E11 钉环首键；
    /// E12 ⑨ 备选锚：直接翻转 ⟹ pin.bind mock 违约，s5 测试②′）。
    pub pred_pin_cell: (usize, usize),
    /// r 面 pv@home 格 (列, 行=srow(RANK_A_R))（E12 矩阵②锚：r_s 标量槽
    /// 篡改 ⟹ link.recomp mock + rid_pv[1] 环审计双信号）。
    pub r_pv_home: (usize, usize),
    /// s 面 pv@home 格（E12 矩阵②锚：s_s 标量槽篡改，rid_pv[2] 环）。
    pub s_pv_home: (usize, usize),
    /// P_A.x 钉值格 (列, 行=row_mapping()[3])（E12 矩阵③锚：pk_I 钉篡改
    /// ⟹ pin.bind mock + rid_base_p 环审计双信号 + native verify 失败）。
    pub pax_pin: (usize, usize),
    /// attrs 词 0 格 (列, 行=row_attrs)（E12 矩阵⑥锚：消息通道词格翻转
    /// ⟹ recomp mock + 消息根环审计双信号；谓词位格同源不动）。
    pub attrs_word0: (usize, usize),
    /// Id 位 0 格 (列, 行=row_id)（E12 矩阵⑤锚：Id 位翻转 ⟹ bool+recomp
    /// mock + rid_beta_idg[255] 环审计——消息/EC 双绑通道同格证据）。
    pub id_bit0: (usize, usize),
    /// (S6) exp 词格 (列, 行=row_mapping()[21]=秩 22)（T2.6；篡改锚：exp 格
    /// 翻转 ⟹ 分解组合 mock + 消息根环审计双信号，s6 测试④）。
    pub s6_exp_cell: (usize, usize),
    /// (S6) T 钉值格 (列, 同行)（T2.6；实例 21 钉绑——T 篡改 ⟹ pin.bind，s6 测试③）。
    pub s6_t_pin_cell: (usize, usize),
    /// (S6) d 位首格 (列, 同行；p=0=MSB 位序)（T2.6；d 位翻转 ⟹ 分解组合
    /// 失配 mock，s6 测试⑤）。
    pub s6_dbit0: (usize, usize),
    /// B-batch2:C 词首格(承诺档;(0,0)=默认档)。
    pub commit_c0: (usize, usize),
    /// B-batch3:θ 实例格(承诺数值档;(0,0)=未启用)。
    pub pred_theta_cell: (usize, usize),
}

/// 全语句装配（hooks 经 [`assemble_full_statement_with_hooks`] 获取）。
pub fn assemble_full_statement(w: &FullStatementWitness) -> Assembled {
    // 旧入口 = 零绑定默认（ctx_tag=0/pred_id=0/t_epoch=0：钉在、绑定语义
    // 平凡满足，(S6) 平凡真——exp_u=DEFAULT_EXP_U>0 恒可分解）。
    // 部署语义（π 绑定验证方挑战/策略/时间）用 assemble_full_statement_bound。
    assemble_full_statement_with_hooks_bound(w, FpSM2::ZERO, FpSM2::ZERO, 0).0
}

/// T2.5 绑定入口：ctx_tag=H(验证方挑战)、pred_id=策略标识（宿主侧计算），
/// 实例 19/20 钉入 ⟹ π 绑定完整实例向量，跨上下文/跨策略改写公开向量即验败。
/// t_epoch=0 ⟹ (S6) 平凡满足（T2.6 语义不进此入口）。
pub fn assemble_full_statement_bound(
    w: &FullStatementWitness,
    ctx_tag: FpSM2,
    pred_id: FpSM2,
) -> Assembled {
    assemble_full_statement_with_hooks_bound(w, ctx_tag, pred_id, 0).0
}

/// E4 主交付：一次装配全三体 + 验签体（J-10b ③⑤）。返回 (电路, 钩子)。
#[allow(clippy::too_many_lines)]
pub fn assemble_full_statement_with_hooks(
    w: &FullStatementWitness,
) -> (Assembled, FullStatementHooks) {
    assemble_full_statement_with_hooks_bound(w, FpSM2::ZERO, FpSM2::ZERO, 0)
}

/// E4 主交付（+T2.5 绑定 +T2.6 有效期，勘误 #29/拍板 B-专设字段）：一次装配
/// 全三体 + 验签体。`t_epoch` = 验证方注入的当前 epoch（实例 21，(S6) exp_u ≥ T）。
#[allow(clippy::too_many_lines)]
pub fn assemble_full_statement_with_hooks_bound(
    w: &FullStatementWitness,
    ctx_tag: FpSM2,
    pred_id: FpSM2,
    t_epoch: u32,
) -> (Assembled, FullStatementHooks) {
    // B-batch2:承诺档 host 分支(M 的 B₂ attrs 槽→C;默认路径逐字不变)。
    let pc: Option<[u8; 16]> = pred_commit_salt();
    // B-batch3：cfg 全克隆（函数级作用域——E11 与尾段 batch3 共用）。
    let pc_cfg_ref: Option<PredCommitCfg> = PRED_COMMIT.with(|c| c.borrow().clone());
    let host = match pc {
        Some(salt) => match pc_cfg_ref.as_ref().and_then(|c| c.auth.clone()) {
            Some(ap) => full_statement_host_auth_of(w, &salt, &ap),
            None => full_statement_host_commit_of(w, &salt),
        },
        None => full_statement_host(w),
    };
    // 秩 → 物理点（吸收态守卫：`point_at_rank` 的像里恰有一个秩映射到点 0）。
    let pt = |rank: usize| {
        let p = point_at_rank(rank);
        assert_ne!(p, 0, "秩 {rank} 映射到吸收态点 0，禁作门行");
        p
    };

    // T2.5：实例面 19 → 21（+ctx_tag/pred_id，勘误 #29）；T2.6：21 → 22（+T）。
    // B-batch3：实例面 22→23（θ=22 消费式——仅承诺数值档路径消费；schema_id
    // 实例 23 已删（定谳二次），容量随删收敛；默认档 instances[0].len() 由
    // 既有 22 冻结断言保证不变）。
    let bld_capacity = if pc_cfg_ref.as_ref().map(|c| c.auth.is_some()).unwrap_or(false) { 25 } else if pred_commit_salt().is_some() { 23 } else { 22 };
    let mut bld = Builder::<FpSM2>::new(bld_capacity);

    // ══════════ PLAN 相（全部 alloc 先于首条款束 —— 冻结守卫纪律）══════════
    // 摘要词 dgw 8 列（ChainEcho::Fold 落点；E7 大折叠读，家点 = RANK_A_E 行）。
    let dgw_cols: [usize; 8] = std::array::from_fn(|_| bld.alloc_col());
    let row_ae = pt(RANK_A_E);

    // 三体链 plan（Fold 形态：摘要不占实例面，echo 环落 dgw@row_ae；面裁剪
    // —— echo 列与 l.echo* 选择器不分配）。
    // P2（system/sm3-lookup-full，系统线 2026-09-18）：SM3_LUT=1 ⟹ 查表化三块体
    // 替换布尔三体链（weave_alloc 在 PLAN 相分派；legacy 零改动=发布锚字节级保证）。
    let lut_on = crate::sm3_lookup_weave::sm3_lut_enabled();
    let mut lut_plan = None;
    let mut lut_circ = None;
    // R3-3.1（2026-09-24）：承诺块查表化（LUT 档）——c_blk/c_circ PLAN 相构
    // （55/48B 单块 fresh IV；digest==commit_c_words_auth 标准语义）。布尔 z
    // 体（plan_z_parts_single）本档不再分配；legacy（SM3_LUT=0）原样。
    let mut c_blk: Option<[u8; 64]> = None;
    let mut c_circ: Option<crate::sm3_lookup_block::BlockCircuit> = None;
    let mut c_shadow: Option<([[usize; 8]; 8], [usize; 8])> = None;
    // θ/class 读数源环（LUT 档专用二元环；legacy=走 plan_z_rings 消息环）。
    let mut c_gate_rings: (Option<usize>, Option<usize>) = (None, None);
    // C 组 16 词根表（LUT 档 pc 分支填——约束相 msg recomp 锚）。
    let mut c_msg_roots: Option<[(usize, usize); 16]> = None;
    let mut smt_emit: Option<(
        crate::smt_weave::SmtWiring,
        crate::smt_weave::SmtPlan,
        [u8; 32],
        Vec<[[crate::sm3_lookup_block::Word; 8]; 2]>,
        Vec<[crate::sm3_lookup_block::Word; 8]>,
    )> = None;
    let smt_circ = if lut_on && pc_cfg_ref.as_ref().map(|c| c.auth.is_some()).unwrap_or(false) {
        Some(crate::smt_weave::smt_chain_circuit(
            &crate::sm2_z_anchor::fe_be32(&w.pk_u.0),
            &pc_cfg_ref.as_ref().and_then(|c| c.auth.as_ref()).and_then(|a| a.smt_siblings).expect("auth 档 SMT 见证在场"),
        ))
    } else {
        None
    };
    let smt_groups = if smt_circ.is_some() { crate::smt_weave::SMT_GROUPS } else { 0 };
    let cplan = if lut_on {
        lut_circ = Some(crate::sm3_lookup_weave::chain_circuit(&host.blocks));
        c_blk = pc.map(|salt| {
            commit_block64(
                &salt,
                pc_cfg_ref.as_ref().and_then(|c| c.auth.as_ref()),
                &w.attrs_u,
            )
        });
        c_circ = c_blk
            .as_ref()
            .map(|b| crate::sm3_lookup_weave::chain_circuit(std::slice::from_ref(b)));
        // 组数 3+smt → 4+smt（第 4 组=C 块，msg-limb 桥接面随组）；pconst
        // 单列复用（三体列——消息无关性守卫测试钉死）。
        lut_plan = Some(crate::sm3_lookup_weave::weave_alloc(
            &mut bld,
            3 + smt_groups + if c_circ.is_some() { 1 } else { 0 },
            3 + if c_circ.is_some() { 1 } else { 0 },
            &lut_circ.as_ref().expect("LUT 电路").pconst,
        ));
        None
    } else {
        Some(plan_chained_parts(&mut bld, ChainEcho::Fold { cols: dgw_cols, row: row_ae }))
    };

    // 词源列/选择器（J-10b ④）：za/pad 单值列 × 8 行 × 逐格独立 sel（merged
    // zu_roots 同款，C4 免疫）；attrs/pk/Id recomp 每词独立 sel（merged
    // recomp 同款）；Id 256 位布尔共享 1 sel（emit_face 家族先例）。
    let za_col = bld.alloc_col();
    let za_sels: [usize; 8] = std::array::from_fn(|_| bld.alloc_selector(&[]));
    let pad_col = bld.alloc_col();
    let pad_sels: [usize; 7] = std::array::from_fn(|_| bld.alloc_selector(&[]));
    // T2.6 (S6)（PLAN 相纪律：alloc 先于首条款束——exp/T/32 d 位列 + 2 选择
    // 器；钉行 row_exp 先定值供体E 词 8 换源 msg_roots）。
    let s6_exp_col = bld.alloc_col();
    let s6_t_col = bld.alloc_col();
    let s6_dbit_cols: [usize; 32] = std::array::from_fn(|_| bld.alloc_col());
    let s6_sel = bld.alloc_selector(&[]);
    let s6_t_pin_sel = bld.alloc_selector(&[]);
    let row_exp = crate::sm3_compress::row_mapping()[21]; // 钉行 = 秩 22（勘误 #28）
    let attrs_cols: [usize; 8] = std::array::from_fn(|_| bld.alloc_col());
    let attrs_sels: [usize; 8] = std::array::from_fn(|_| bld.alloc_selector(&[]));
    // E5：attrs 位格 ×256（E11 湮灭门按位消费 + recomp 位源；bool 共签
    // id_bool_sel，不再新配选择器）。
    let attrs_bit_cols: [usize; 256] = std::array::from_fn(|_| bld.alloc_col());
    let pkx_cols: [usize; 8] = std::array::from_fn(|_| bld.alloc_col());
    let pky_cols: [usize; 8] = std::array::from_fn(|_| bld.alloc_col());
    let pk_sels: [usize; 16] = std::array::from_fn(|_| bld.alloc_selector(&[]));
    let id_word_cols: [usize; 8] = std::array::from_fn(|_| bld.alloc_col());
    let id_bit_cols: [usize; 256] = std::array::from_fn(|_| bld.alloc_col());
    let id_sels: [usize; 8] = std::array::from_fn(|_| bld.alloc_selector(&[]));
    let id_bool_sel = bld.alloc_selector(&[]);

    let row_id = pt(RANK_ID);
    let row_attrs = pt(RANK_ATTRS);
    let za_rows: [usize; 8] = std::array::from_fn(|k| pt(RANK_ZA + k));
    let pad_rows: [usize; 7] = std::array::from_fn(|k| pt(RANK_PAD + k));
    let row_pk = pt(RANK_PA); // E8 双 decompose 将共享本行（全 rot=0）

    // 验签体 plan（emit_verify_body 消费；16,554 零接触复用）。
    let pl = plan_all(&mut bld);

    // msg_roots 表（T1 语句排布，J-1；T2.6 体E 词 8 = exp 词格换源）：体C
    // 0..7=Z_A、8..15=Id_u 词；体D 0..7=attrs（占位锚）、8..15=pk_u.x 词；
    // 体E 0..7=pk_u.y 词、8=exp_u 词（(S6) 双绑通道）、9..15=pad。
    // B-batch2 承诺档：体D 0..7 根格 attrs→c_cols（承载 C=(S7) 单块出口摘要；
    // attrs_cols 列空挂退役——其原链环被 c_cols 顶替，z 出口经成员追加入环）。
    let b2_c_cols: [usize; 8] = std::array::from_fn(|_| {
        if pc.is_some() { bld.alloc_col() } else { 0 }
    });
    let b2_row_c: usize = crate::sm3_compress::point_at_rank(3820);
    let msg_roots: [[MsgCell; 16]; 3] = [
        std::array::from_fn(|j| match j {
            0..=7 => (za_col, za_rows[j]),
            _ => (id_word_cols[j - 8], row_id),
        }),
        std::array::from_fn(|j| match j {
            0..=7 => {
                if pc.is_some() { (b2_c_cols[j], b2_row_c) } else { (attrs_cols[j], row_attrs) }
            }
            _ => (pkx_cols[j - 8], row_pk),
        }),
        std::array::from_fn(|j| match j {
            0..=7 => (pky_cols[j], row_pk),
            8 => (s6_exp_col, row_exp),
            _ => (pad_col, pad_rows[j - 9]),
        }),
    ];
    if lut_on {
        crate::sm3_lookup_weave::weave_wires(
            &mut bld,
            lut_circ.as_ref().expect("LUT 电路"),
            lut_plan.as_ref().expect("LUT PLAN"),
            &msg_roots,
            &dgw_cols,
            row_ae,
        );
        // B3b（飞证）：SMT 撤销累加器织入（auth 档；组号续接三体+C 组=4..68，
        // R3-3.1：C 块占组 3）。
        if let Some((smt_c, _dg, mw, oc, dgs)) = smt_circ.as_ref() {
            let rm = crate::sm3_compress::row_mapping();
            let smt_plan = crate::smt_weave::weave_smt_alloc_cols(
                &mut bld,
                lut_plan.as_ref().expect("LUT PLAN"),
                4,
                mw,
            );
            let wiring = crate::smt_weave::SmtWiring {
                pkx_word_cell: (pkx_cols[0], row_pk),
                row_rev: rm[23],
                root_fold: crate::smt_weave::fold_words_be(
                    &pc_cfg_ref
                        .as_ref()
                        .and_then(|c| c.auth.as_ref())
                        .and_then(|a| a.smt_root)
                        .expect("auth 档 SMT 根在场"),
                ),
                key_bits: crate::smt_weave::key_bits_of(&crate::sm2_z_anchor::fe_be32(&w.pk_u.0)),
                sib_words: pc_cfg_ref
                    .as_ref()
                    .and_then(|c| c.auth.as_ref())
                    .and_then(|a| a.smt_siblings)
                    .map(|s| s.to_vec())
                    .unwrap_or_default(),
                digest_words: dgs.clone(),
            };
            crate::smt_weave::weave_smt_wires(
                &mut bld,
                smt_c,
                lut_plan.as_ref().expect("LUT PLAN"),
                4,
                &wiring,
                &smt_plan,
                mw,
                oc,
            );
            let key_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.0);
            smt_emit = Some((wiring, smt_plan, key_be, mw.clone(), oc.clone()));
        }
    } else {
        plan_chained_rings(&mut bld, &cplan.as_ref().expect("布尔 PLAN"), &msg_roots);
    }

    // ═════════ B-batch2 承诺档 PLAN 相(2026-09-15):salt/attrs_true/pad 词列
    // + (S7) IV 单块 z-plan(体A 列族复用 ZONE0 条带——同条带不同列,环协议
    // "每格至多一环"按 (列,行) 粒度满足)+ CommitOne 消息根环 + C 绑定环
    // (z 出口↔attrs_cols@row_attrs,零旋转)。默认路径(TLS None)零触碰。═══
    let (
        (b2_salt_cols, b2_true_cols, b2_pad_cols, b2_pad_sels, b3_dcols, b3_range_sel, b3_schema_sel, b3_theta_row, b3_schema_row, b2_true_cols_all, b2_pad_cols_all, b4_class_plan),
        b2_zplan,
    ): (
        (
            [usize; 4],
            [usize; 8],
            [usize; 4],
            [usize; 4],
            [usize; 32],
            usize,
            usize,
            usize,
            usize,
            Option<Vec<usize>>,
            Option<Vec<usize>>,
            Option<([usize; 32], usize, usize, usize)>,
        ),
        Option<crate::sm3_compress_v2::ZuPlan>,
    ) = if pc.is_some() {
        // R2 手术（2026-09-23）：本入口恒为 CommitOne 单块形态（roots 见下）。
        // R3-3.1（2026-09-24）：LUT 档布尔 z 体**不再分配**——C 块由查表第 4
        // 组承载（weave_commit_block_*）；legacy（SM3_LUT=0）照旧分配（发布锚
        // 字节级保证）。plan_z_rings/C 绑定环同随之分支（见下）。
        let zplan = if lut_on {
            None
        } else {
            Some(crate::sm3_compress_v2::plan_z_parts_single(&mut bld))
        };
        let salt_cols: [usize; 4] = std::array::from_fn(|_| bld.alloc_col());
        // AUTH 档（B3）：消息 54B=词 0..3 salt+词 4..13 原像（cert+id+sn_h）
        // +词 14..15 padding；true_cols=10、pad=2。pred 档：48B=8+4。
        let is_auth = pc_cfg_ref.as_ref().map(|c| c.auth.is_some()).unwrap_or(false);
        let n_true = if is_auth { 10 } else { 8 };
        let mut true_cols_v: Vec<usize> = Vec::with_capacity(n_true);
        for _ in 0..n_true {
            true_cols_v.push(bld.alloc_col());
        }
        let n_pad = if is_auth { 2 } else { 4 };
        let mut pad_cols_v: Vec<usize> = Vec::with_capacity(n_pad);
        for _ in 0..n_pad {
            pad_cols_v.push(bld.alloc_col());
        }
        let true_cols: [usize; 8] = std::array::from_fn(|j| {
            true_cols_v.get(j).copied().unwrap_or(0)
        });
        let pad_cols: [usize; 4] = std::array::from_fn(|j| {
            pad_cols_v.get(j).copied().unwrap_or(0)
        });
        // (S7) 消息根表:pred=词 0..3 salt、4..11=attrs_true、12..15=padding；
        // auth=词 0..3 salt、4..13=原像、14..15=padding（3820 内承诺根带）。
        let mut roots = [[(0usize, 0usize); 16]; 1];
        for j in 0..16usize {
            let (col, row) = if is_auth {
                match j {
                    0..=3 => (salt_cols[j], crate::sm3_compress::point_at_rank(3800 + j)),
                    4..=13 => (
                        true_cols_v[j - 4],
                        crate::sm3_compress::point_at_rank(3804 + j),
                    ),
                    _ => (pad_cols_v[j - 14], crate::sm3_compress::point_at_rank(3804 + j)),
                }
            } else {
                match j {
                    0..=3 => (salt_cols[j], crate::sm3_compress::point_at_rank(3800 + j)),
                    4..=11 => (true_cols[j - 4], crate::sm3_compress::point_at_rank(3804 + j)),
                    _ => (pad_cols[j - 12], crate::sm3_compress::point_at_rank(3812 + j)),
                }
            };
            roots[0][j] = (col, row);
        }
        if let Some(zp) = zplan.as_ref() {
            crate::sm3_compress_v2::plan_z_rings(
                &mut bld,
                zp,
                &crate::sm3_compress_v2::ZuRingRoots::CommitOne { msg_roots: roots },
            );
        }
        // pad 常量锚选择子 ×4(EMIT 零 alloc 纪律——常量锚发射在 EMIT 尾)。
        let pad_sels: [usize; 4] = std::array::from_fn(|_| bld.alloc_selector(&[]));
        // B-batch3(定谳 Q2)：范围门/schema 等值的列与 selector 必须 PLAN 相
        // alloc（首个约束后 frozen，EMIT 尾 alloc 被 assert_open 拒绝）。
        let b3_dcols: [usize; 32] = std::array::from_fn(|_| bld.alloc_col());
        let b3_range_sel = bld.alloc_selector(&[]);
        let b3_schema_sel = bld.alloc_selector(&[]);
        let b3_theta_row = crate::sm3_compress::row_mapping()[22];
        let b3_schema_row = crate::sm3_compress::row_mapping()[23];
        bld.extend_selector(b3_range_sel, &[b3_theta_row]);
        bld.extend_selector(b3_schema_sel, &[b3_schema_row]);
        // B4（A4）class 等值钉列族：32 位格+两选择器@class 行（rm[24]=实例 24
        // 家点——θ 门同构模式：bits@行+recomb 消费 q_inst+环中继读数源）
        let b4_class_dcols: [usize; 32] = std::array::from_fn(|_| bld.alloc_col());
        let b4_class_bool_sel = bld.alloc_selector(&[]);
        let b4_class_pin_sel = bld.alloc_selector(&[]);
        let b4_class_row = crate::sm3_compress::row_mapping()[24];
        bld.extend_selector(b4_class_bool_sel, &[b4_class_row]);
        bld.extend_selector(b4_class_pin_sel, &[b4_class_row]);
        if lut_on {
            // R3-3.1（LUT 档）：C 组 WIRES（值播种+环翻译+msg 桥接+摘要影子）
            // + 摘要影子 bank（8 词×8 limb @b2_row_c，约束相 recomp 绑 c_cols）
            // + θ/class 专用读数环（二元环：承诺词根格 + θ/class 行成员）。
            let (sh_cols, sh_sels): ([[usize; 8]; 8], [usize; 8]) = (
                std::array::from_fn(|_| std::array::from_fn(|_| bld.alloc_col())),
                std::array::from_fn(|_| bld.alloc_selector(&[])),
            );
            crate::sm3_lookup_weave::weave_commit_block_wires(
                &mut bld,
                c_circ.as_ref().expect("LUT 承诺档 c_circ 在场"),
                lut_plan.as_ref().expect("LUT PLAN"),
                3,
                &roots[0],
                &sh_cols,
                b2_row_c,
            );
            c_shadow = Some((sh_cols, sh_sels));
            c_msg_roots = Some(roots[0]);
            // LUT 版 CommitOne 消息环不登记（plan_z_rings 已跳过）——θ 门
            // （词 4@秩 3808）/class 钉（词 5@秩 3809）读数源改走专用环：
            // 根格值由 lut.c.msg.recomp 钉死，环把 θ/class 行格并进等值类。
            c_gate_rings.0 = Some(bld.begin_relay_col(
                true_cols[0],
                crate::sm3_compress::point_at_rank(3808),
            ));
            if is_auth {
                c_gate_rings.1 = Some(bld.begin_relay_col(
                    true_cols[1],
                    crate::sm3_compress::point_at_rank(3809),
                ));
            }
        } else {
            // C 绑定:z 体A 出口词@ZONE0.fold_row(k) 追加进 D 体根格所在的
            // 消息链环(环=等值类,多成员合法;一格一环红线满足——出口格自由)。
            // 该环由 plan_chained_rings 以 (b2_c_cols[k], b2_row_c) 为根登记,
            // 此处经 ring_of 取 id 追加 z 出口格 ⟹ C 词 ⟷ M 哈希输入 ⟷ 单块出口
            // 三方等值。
            let zp = zplan.as_ref().expect("legacy 承诺档 zplan 在场");
            for k in 0..8usize {
                let rid = bld
                    .ring_of(b2_c_cols[k], b2_row_c)
                    .expect("承诺档 D 体根格应在链环中");
                bld.relay_to_col(
                    rid,
                    zp.face_a_out_val(),
                    crate::sm3_compress_v2::ZONE0.fold_row(k),
                );
            }
        }
        (
            (
                salt_cols,
                true_cols,
                pad_cols,
                pad_sels,
                b3_dcols,
                b3_range_sel,
                b3_schema_sel,
                b3_theta_row,
                b3_schema_row,
                if is_auth { Some(true_cols_v) } else { None },
                if is_auth { Some(pad_cols_v) } else { None },
                if is_auth {
                    Some((b4_class_dcols, b4_class_bool_sel, b4_class_pin_sel, b4_class_row))
                } else {
                    None
                },
            ),
            zplan,
        )
    } else {
        (
            (
                [0; 4],
                [0; 8],
                [0; 4],
                [0; 4],
                [0; 32],
                0,
                0,
                0,
                0,
                None,
                None,
                None,
            ),
            None,
        )
    };

    // ══════════ E8 (S4) plan（J-d1）：sk 标量世界 + [sk_u]G 循环槽 + 换根通道
    // ══════════
    // 全部 alloc / begin_relay 首键先于首条款束（冻结守卫纪律，J-10b ⑤；
    // E-H①：环首键注册必须在 plan 相）。
    let sk_bit_cols: [usize; 256] = std::array::from_fn(|_| bld.alloc_col());
    let sk_bool_sel = bld.alloc_selector(&[]);
    let sk_lt = plan_add(&mut bld);
    let sk_neq = plan_neq(&mut bld);
    // ③手术 S3：[sk_u]G window 化（同 C₁/Id·G playbook——RANK_SKLOOP 窗 66 秩）。
    let row_sk = pt(RANK_SK);
    let sk_win = crate::sm2_ec_window_gadget::plan_window_mul(&mut bld, RANK_SKLOOP);
    let sk_val = bld.alloc_col();
    let sk_val_sel = bld.alloc_selector(&[row_sk]);
    let rid_sk_diff = bld.begin_relay_col(
        sk_win.diff_col,
        crate::sm3_compress::row_mapping()[RANK_SKLOOP + crate::sm2_ec_window_gadget::ROWS_USED],
    );
    let dec_pkx = plan_decomp(&mut bld);
    let dec_pky = plan_decomp(&mut bld);
    // A1'：x(Id_u·G) 的消息词分解（id_word_cols 换源——E8 pk decompose 同款）。
    let dec_idgx = plan_decomp(&mut bld);
    // A1″（2026-09-09 压缩点绑定）：y(Id_u·G) 分解取 LSB 作压缩奇偶位——
    // 封死 Id↦n−Id 符号歧义（x(−P)=x(P) 但 parity(−y)≠parity(y)）。
    let dec_idgy = plan_decomp(&mut bld);
    let st_pkx = bld.alloc_col();
    let st_pky = bld.alloc_col();
    // 秩分配：sk 行 = 67（pad 59..66 之后、< 240）；sk 循环 = 257 连续秩
    // 1071..=1327（ZONE0 条带带行共享，J-10a 裁决：EC 列全新零冲突；窗口内
    // 全部秩均被 SM3 条带寻址 ⟹ 吸收态安全性由既有全绿运行经验证）。
    const RANK_SK: usize = 67;
    const RANK_SKLOOP: usize = 1071;
    const _: () = assert!(RANK_SK < RANK_BASE_V2, "sk 标量世界行须低于 SM3 基址 240");
    const _: () = assert!(
        RANK_SKLOOP + 256 < RANK_END,
        "sk 循环窗口须低于 ZONE0 终界 1360"
    );

    // β 车道：每循环锚点一条二元小环（rid_beta_eg 同款——不同锚消费不同位）；

    // 输出传输环：循环 acc_in@rows[256] 的 x/y ↔ st_pkx/st_pky @ row_pk
    // （inf 不出环——sk_u∈[1,n−1] ⟹ 输出非 O）。
    let rid_pkx = bld.begin_relay_col(st_pkx, row_pk);
    let rid_pky = bld.begin_relay_col(st_pky, row_pk);

    // ══════════ E9 (S3a) plan（J-d2）：r 标量世界 + C₁=r·G / Id·G 两循环槽
    // ══════════
    // r 标量世界 @ RANK_R=68（sk=67 之后、< 240）：256 位布尔 + lt_n +
    // neq_zero（r∈[1,n−1]）。两循环 = Fix R-a 修复族 257 连续秩，落自由带
    // （J-10a 预分配 C₁@3184 / Id·G@3440——Fix R-a 257 宽重排为 3184/3441；
    // EC 区 AC+64 守卫占用 3120..3183 恰好衔接）。β 源：C₁ ← r 位（镜像序）；
    // Id·G ← E4 消息侧 id_bit_cols **复用**（双绑通道，位序已由
    // be_word_bit_terms crosscheck 锁定，禁手写位序变换）。
    let r_bit_cols: [usize; 256] = std::array::from_fn(|_| bld.alloc_col());
    let r_bool_sel = bld.alloc_selector(&[]);
    let r_lt = plan_add(&mut bld);
    let r_neq = plan_neq(&mut bld);
    // ③手术 S2 试点：C₁ 循环 window 化（L2b gadget——RANK_C1 窗 66 秩）；
    // Id·G 暂持旧 const_base 循环（S3 铺开）。G 表常数列=plan 相分配
    // （冻结守卫：alloc 必须先于首条款束——J-10b ⑤）。
    let g_table = crate::sm2_ec_window_gadget::alloc_g_table(
        &mut bld,
        crate::sm2_ec_plonkish::g_coords(),
    );
    let c1_win = crate::sm2_ec_window_gadget::plan_window_mul(&mut bld, RANK_C1);
    let c1_val = bld.alloc_col();
    // 标量绑定环：diff 格（窗末行）↔ c1_val（r 标量世界行）——环等值 +
    // r recomp 锚定（位世界）闭合绑定链。
    let rid_c1_diff = bld.begin_relay_col(
        c1_win.diff_col,
        crate::sm3_compress::row_mapping()[RANK_C1 + crate::sm2_ec_window_gadget::ROWS_USED],
    );

    // ③手术 S3：Id·G window 化（同 C₁ playbook——RANK_IDG 窗 66 秩）。
    let idg_win = crate::sm2_ec_window_gadget::plan_window_mul(&mut bld, RANK_IDG);
    let idg_val = bld.alloc_col();
    let idg_val_sel = bld.alloc_selector(&[row_id]);
    // 标量绑定环首键：diff 格（窗末行）↔ idg_val（Id 标量世界行）。
    let rid_idg_diff = bld.begin_relay_col(
        idg_win.diff_col,
        crate::sm3_compress::row_mapping()[RANK_IDG + crate::sm2_ec_window_gadget::ROWS_USED],
    );
    let st_c1x = bld.alloc_col();
    let st_c1y = bld.alloc_col();
    let st_idgx = bld.alloc_col();
    let st_idgy = bld.alloc_col();
    const RANK_R: usize = 68;
    const RANK_C1: usize = 3184;
    const RANK_IDG: usize = 3441;
    const _: () = assert!(RANK_R < RANK_BASE_V2, "r 标量世界行须低于 SM3 基址 240");
    const _: () = assert!(RANK_C1 + 66 < RANK_IDG, "C₁ window 窗 66 秩不得越入 Id·G 窗");
    const _: () = assert!(
        RANK_IDG + 66 < crate::sm3_compress::ROWS,
        "Id·G window 窗 66 秩须低于 K=12 终界 4096"
    );
    let row_r = pt(RANK_R);
    let c1_val_sel = bld.alloc_selector(&[row_r]); // ③试点：r recomp 单点门
    let rows_c1: Vec<usize> = (0..=256).map(|i| pt(RANK_C1 + i)).collect();
    let rows_idg: Vec<usize> = (0..=256).map(|i| pt(RANK_IDG + i)).collect();
    // β 车道 ×2（每锚一条二元小环，MSB-first 镜像）+ 输出传输环 ×4（C₁ 暂存
    // 落 row_r、Id·G 暂存落 row_id——E10 C₂ 完全加与实例钉消费；inf 不出环
    // ——r∈[1,n−1] ⟹ C₁≠O；Id_u=0 时 Id·G=O 由传输写零格兜底、负例矩阵⑤管）。

    let rid_c1x = bld.begin_relay_col(st_c1x, row_r);
    let rid_c1y = bld.begin_relay_col(st_c1y, row_r);
    let rid_idgx = bld.begin_relay_col(st_idgx, row_id);
    let rid_idgy = bld.begin_relay_col(st_idgy, row_id);

    // ══════════ E10 (S3b) plan（J-d3）：apk 基头槽 + r·apk 循环槽 + C₂ 完全
    // ══════════ 加槽 + 6 实例钉列（全部 alloc/环首键先于首条款束——冻结守卫
    // ══════════ 纪律，J-10b ⑤；E-H①：环首键注册必须在 plan 相）══════════
    // apk staged 头（EP 基头同款：staged 三格 + 2·apk 绑定三格 + on_curve
    // 三真值格）；r·apk 循环 = Fix R-a 族 257 连续秩 3698..=3954（Id·G 窗
    // 3441..=3697 之后顺延）；apk 基头行 3955、C₂ 行 3956。实例钉行 =
    // row_mapping()[ord]（H1·5：ord k 占秩 k+1；12..17 → 秩 13..18——merged
    // 摘要钉行 13..20 本形态不用（Fold 无实例摘要），词源段 32..68 之下空档）。
    let hs_a = crate::sm2_ec_plonkish::plan_point(&mut bld);
    let hd_a = crate::sm2_ec_plonkish::plan_point(&mut bld);
    let dga = crate::sm2_ec_plonkish::plan_ec_double(&mut bld);
    let oc_a_sel = bld.alloc_selector(&[]);
    let oc_a: [usize; 3] = std::array::from_fn(|_| bld.alloc_col());
    let rapk_loop = crate::sm2_ec_plonkish::plan_ec_mul_loop(&mut bld);
    let ac2 = crate::sm2_ec_plonkish::plan_ec_add_complete(&mut bld);
    let c2idg = crate::sm2_ec_plonkish::plan_point(&mut bld);
    let c2rpk = crate::sm2_ec_plonkish::plan_point(&mut bld);
    let pin_cols: [usize; 6] = std::array::from_fn(|_| bld.alloc_col());
    // T2.5 资源（勘误 #29；PLAN 相纪律 = alloc 全部先于首条款束）：ctx/pred_id
    // 各一钉值列 + 一选择子（emit_pin_val_only 语义钉，merged emit_face 先例）。
    let t25_ctx_col: usize = bld.alloc_col();
    let t25_pid_col: usize = bld.alloc_col();
    let t25_ctx_sel = bld.alloc_selector(&[]);
    let t25_pid_sel = bld.alloc_selector(&[]);
    let pin_sels: [usize; 6] = std::array::from_fn(|_| bld.alloc_selector(&[]));
    // E11 (S5) 槽（J-e1）：pred_out 单值列 + 两选择器（勘误 #28 定案：谓词
    // 族 pred_sel 激活 @row_attrs 恰 1 点、钉族 pred_pin_sel 激活 @钉行恰
    // 1 点——#26 纪律；钉行 ≠ 谓词行，共签会把湮灭门带进钉行读到位格零值；
    // 全 cur 零旋转）。钉值环首键同在此注册（E-H①：环首键必须在 plan 相；
    // 首键 = 钉格，E10 钉环同款）。alloc 先于首条款束（冻结守卫纪律）。
    let pred_cell = bld.alloc_col();
    let pred_sel = bld.alloc_selector(&[]);
    let pred_pin_sel = bld.alloc_selector(&[]);
    let pin_row_pred = crate::sm3_compress::row_mapping()[18];
    let rid_pred_pin = bld.begin_relay_col(pred_cell, pin_row_pred);
    const RANK_RAPK: usize = 3698;
    const RANK_HRA: usize = 3955;
    const RANK_AC2: usize = 3956;
    const _: () = assert!(
        RANK_RAPK + 256 < RANK_HRA,
        "r·apk 循环窗口 257 秩不得越入 apk 基头行"
    );
    const _: () = assert!(
        RANK_AC2 < crate::sm3_compress::ROWS,
        "C₂ 行须低于 K=12 终界 4096"
    );
    let rows_rapk: Vec<usize> = (0..=256).map(|i| pt(RANK_RAPK + i)).collect();
    // rapk β 环首键迁移（原共享 rid_beta_c1——c1 环随 window 化退役；新首键
    // =r 位格本身，成员=rapk_loop.bit 车道——一格一环红线保持）。
    let rid_beta_rapk: Vec<usize> =
        (0..256usize).map(|i| bld.begin_relay_col(r_bit_cols[255 - i], row_r)).collect();
    let row_hra = pt(RANK_HRA);
    let row_ac2 = pt(RANK_AC2);
    let pin_rows: [usize; 6] =
        std::array::from_fn(|k| crate::sm3_compress::row_mapping()[12 + k]);
    // 环首键 ×12：apk staging 基/倍通道（apk.x/y 首键 = 实例钉格——钉格经
    // 环与 staged 头缝合，EP 同款；inf 无实例，首键 = staged 格）；C₂ 加数
    // 通道（Id·G x/y 复用 E9 暂存环追加成员、inf 二元小环、r·apk 尾环 ×3）
    // + C₂ 输出钉环 ×2。
    let rid_base_a: [usize; 3] = std::array::from_fn(|c| match c {
        0 => bld.begin_relay_col(pin_cols[4], pin_rows[4]),
        1 => bld.begin_relay_col(pin_cols[5], pin_rows[5]),
        _ => bld.begin_relay_col(hs_a.cols[2], row_hra),
    });
    let rid_d2_a: [usize; 3] =
        std::array::from_fn(|c| bld.begin_relay_col(hd_a.cols[c], row_hra));
    let rid_idg_inf = bld.begin_relay_col(c2idg.cols[2], row_ac2);
    let rid_tail_rk: [usize; 3] =
        std::array::from_fn(|c| bld.begin_relay_col(c2rpk.cols[c], row_ac2));
    let rid_c2x = bld.begin_relay_col(pin_cols[2], pin_rows[2]);
    let rid_c2y = bld.begin_relay_col(pin_cols[3], pin_rows[3]);

    // ══════════ EMIT 相（零分配）══════════
    // ① Z_A 常量锚 ×8（单值列 8 行逐格 sel——C4 免疫；值为 z_a_words 权威）。
    for k in 0..8usize {
        bld.extend_selector(za_sels[k], &[za_rows[k]]);
        bld.emit_const_val(za_sels[k], za_col, host.za_words[k]);
        bld.set_cell_u32(za_col, za_rows[k], host.za_words[k]);
    }
    // ② pad 常量锚（词 2..7——词值机械取自 host.blocks[2]；禁手抄）。
    //    词 1 = 压缩奇偶字节‖0x80‖0‖0，自 A1″ 起为见证派生格，在 ③″″ 块
    //    与 y 的 LSB 线性链接（(S1) 绑定面）；词 0 = exp_u 词归 ⑩′ (S6)
    //    （(S1)↔(S6) 双绑通道，T2.6）。
    for k in 1..7usize {
        bld.extend_selector(pad_sels[k], &[pad_rows[k]]);
        bld.emit_const_val(pad_sels[k], pad_col, host.pad_words[k + 1]);
        bld.set_cell_u32(pad_col, pad_rows[k], host.pad_words[k + 1]);
    }
    // ③ Id_u 256 位布尔（E9 EC 循环按位消费的前提）+ 消息词换源（A1'，
    //    2026-09-06）：id_word_cols 语义 = x(Id_u·G) 的 8 BE 词（消息身份
    //    分量 = 公开点编码而非标量——定理5 归约修复的实现面）。位格仍为
    //    Id_u 的 256 位布尔（EC 循环消费）；词格经 dec_idgx 从 st_idgx
    //    （Id·G 循环输出暂存，⑤″ set 值）分解，位→词 recomp 同 E8 pk 款。
    for p in 0..256usize {
        // 整数位 i（LSB=0）= 字节 31−i/8 的位 i%8（字节内 MSB-first）
        let byte = w.id_u[31 - p / 8];
        let bitv = (byte >> (p % 8)) & 1;
        bld.set_cell_u32(id_bit_cols[p], row_id, u32::from(bitv));
    }
    bld.extend_selector(id_bool_sel, &[row_id]);
    for p in 0..256usize {
        bld.emit_bool(id_bool_sel, id_bit_cols[p]);
    }
    {
        let id_bits: [bool; 256] =
            std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
        let idg_host = crate::sm2_ec_plonkish::affine_mul_bits(
            &id_bits,
            Some(crate::sm2_ec_plonkish::g_coords()),
        );
        let (igx, igy) = match idg_host {
            Some((x, y)) => (x, y),
            None => (FpSM2::ZERO, FpSM2::ZERO),
        };
        // x(Id·G) 分解：st_idgx ↔ 256 位 ↔ 8 词（家点 row_id 全 rot=0）。
        let x_cell = bld.q(st_idgx, Rotation::cur());
        let _sca_idgx = emit_decompose(
            &mut bld,
            &dec_idgx,
            row_id,
            x_cell,
            &crate::sm2_params::fr_to_limbs(&igx),
        );
        let igx_be = crate::sm2_z_anchor::fe_be32(&igx);
        for j in 0..8usize {
            let wv =
                u32::from_be_bytes(igx_be[4 * j..4 * j + 4].try_into().expect("界内"));
            bld.extend_selector(id_sels[j], &[row_id]);
            let mut acc = Expression::<FpSM2>::zero();
            for (ib, sh) in be_word_bit_terms(j) {
                acc = acc
                    + Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(1u64 << sh))
                        * bld.q(dec_idgx.out[ib], Rotation::cur());
            }
            let re = acc - bld.q(id_word_cols[j], Rotation::cur());
            bld.emit_assert_zero(id_sels[j], re);
            bld.set_cell_u32(id_word_cols[j], row_id, wv);
        }
        // ③″″ A1″（2026-09-09 压缩点绑定）：y(Id·G) 分解（dec_idgy 同 dec_idgx
        //     款，家点 row_id 全 rot=0），LSB 位 = 压缩奇偶位；pad 词 1 自常量锚
        //     改见证派生格并与奇偶位线性链接：
        //     pad_word1 = (0x02 + LSB)·2^24 ‖ 0x80·2^16 ‖ 0 ‖ 0。
        //     健全性链条：Id 位 → Id·G 循环 → st_idgy →（分解）→ LSB → 消息
        //     奇偶字节 ⟹ Id↦n−Id 变体（x(−P)=x(P) 恒等面）在消息面被奇偶字节
        //     区分 ⟹ e′ 为新鲜摘要 ⟹ (S2) 验签失败（a1x_negated_id_message_diverges）。
        let y_cell = bld.q(st_idgy, Rotation::cur());
        let _sca_idgy = emit_decompose(
            &mut bld,
            &dec_idgy,
            row_id,
            y_cell,
            &crate::sm2_params::fr_to_limbs(&igy),
        );
        bld.extend_selector(pad_sels[0], &[pad_rows[0]]);
        // 激活点 = pad 行，读 row_id 的奇偶位：旋转 = 秩差（|49−59|=10 ≤ K=12）。
        let par_bit = bld.q(
            dec_idgy.out[0],
            crate::sm3_compress::rot_between(pad_rows[0], row_id),
        );
        let par_byte = Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(2u64))
            + par_bit;
        let w1_lin = par_byte
            * Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(1u64 << 24))
            + Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(0x80u64 * (1u64 << 16)));
        let re1 = bld.q(pad_col, Rotation::cur()) - w1_lin;
        bld.emit_assert_zero(pad_sels[0], re1);
        bld.set_cell_u32(pad_col, pad_rows[0], host.pad_words[1]);
    }
    // ④ attrs_u（E5 换绑定，J-10b ③）：256 位布尔（E11 湮灭门按位消费的前提；
    //    bool 共签 id_bool_sel——同型无常量约束跨行共签，l.l* 家族先例）+
    //    8 词 recomp 原格换约束（词值列/行/环根全部不动，拆除 anchor.const）。
    //    位映射经 be_word_bit_terms——禁手抄（crosscheck 测试锁定）。
    //    2026-10 空转消除（约束 −264）：AUTH 档（pc 且 auth_pi 在场）下 attrs
    //    位/词格零消费者——湮灭门 n_gate=0（⑤⁗ B3 定案）、schema 钉档外跳过、
    //    msg_roots 体D 走 b2_c_cols（M_A 哈希消息词由 host 从公开 preimage
    //    派生，θ/class 门读 true_cols）⟹ 256 bool + 8 recomp + 选择器扩展整体
    //    跳过；列分配与见证格填充保留（attrs 位/词格成无约束死列，环根不动，
    //    b2_c_cols 的 C 环/z 出口消费照旧）。默认/承诺档逐字保持（else 分支
    //    承重——pred 档湮灭门与默认档 msg_roots 都吃 attrs 位/词格）。
    for p in 0..256usize {
        let byte = w.attrs_u[31 - p / 8];
        let bitv = (byte >> (p % 8)) & 1;
        bld.set_cell_u32(attrs_bit_cols[p], row_attrs, u32::from(bitv));
    }
    let auth_dead = pc.is_some() && pc_cfg_ref.as_ref().map(|c| c.auth.is_some()).unwrap_or(false);
    if !auth_dead {
        bld.extend_selector(id_bool_sel, &[row_attrs]);
        for p in 0..256usize {
            bld.emit_bool(id_bool_sel, attrs_bit_cols[p]);
        }
    }
    for j in 0..8usize {
        let wv = u32::from_be_bytes(w.attrs_u[4 * j..4 * j + 4].try_into().expect("界内"));
        if let Some(salt) = pc {
            let auth_pi = pc_cfg_ref.as_ref().and_then(|c| c.auth.clone());
            if let Some(ap) = auth_pi {
                // AUTH（B3）：attrs_u=C 值——约束发射已整体跳过（本段头注）；
                // 仅保留见证填充：C 词见证置 b2_c_cols（C 环 PLAN 相 ↔ z 出口
                // 消费不动），attrs 位/词格照写（无约束死列，诚实卫生）。
                let cw = commit_c_words_auth(&salt, &ap);
                bld.set_cell_u32(b2_c_cols[j], b2_row_c, cw[j]);
                bld.set_cell_u32(attrs_cols[j], row_attrs, wv);
            } else {
                bld.extend_selector(attrs_sels[j], &[row_attrs]);
                let mut acc = Expression::<FpSM2>::zero();
                for (ib, sh) in be_word_bit_terms(j) {
                    acc = acc
                        + Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(1u64 << sh))
                            * bld.q(attrs_bit_cols[ib], Rotation::cur());
                }
                // B-batch2:recomp 换绑 attrs_true_cols(真属性词);attrs_cols
                // (M 哈希槽)承载 C 词,绑定走 PLAN 相 C 环(⟷ z 单块出口)。
                let re = acc - bld.q(b2_true_cols[j], Rotation::cur());
                bld.emit_assert_zero(attrs_sels[j], re);
                bld.set_cell_u32(b2_true_cols[j], row_attrs, wv);
                // (S7) 消息根格侧见证(3804 秩带——CommitOne 根环的两端之一)。
                bld.set_cell_u32(
                    b2_true_cols[j],
                    crate::sm3_compress::point_at_rank(3804 + 4 + j),
                    wv,
                );
                let cw = commit_c_words(&salt, &w.attrs_u);
                bld.set_cell_u32(b2_c_cols[j], b2_row_c, cw[j]);
            }
        } else {
            // 默认档（TLS None）：attrs 词=体D 消息根（msg_roots 消费）——
            // recomp 承重，逐字保持。
            bld.extend_selector(attrs_sels[j], &[row_attrs]);
            let mut acc = Expression::<FpSM2>::zero();
            for (ib, sh) in be_word_bit_terms(j) {
                acc = acc
                    + Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(1u64 << sh))
                        * bld.q(attrs_bit_cols[ib], Rotation::cur());
            }
            let re = acc - bld.q(attrs_cols[j], Rotation::cur());
            bld.emit_assert_zero(attrs_sels[j], re);
            bld.set_cell_u32(attrs_cols[j], row_attrs, wv);
        }
    }
    // ⑤ pk_u.x/y 词见证 ×16（E8 起真源 = [sk_u]G 循环输出 → 换根重组；占位
    //    常量锚拆除，词↔位绑定改由 ⑤′ recomp 承担——原格换约束，msg_roots
    //    根不动，簇H 换根方案）。
    let pkx_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.0);
    let pky_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.1);
    for k in 0..8usize {
        let wx = u32::from_be_bytes(pkx_be[4 * k..4 * k + 4].try_into().expect("界内"));
        bld.set_cell_u32(pkx_cols[k], row_pk, wx);
        let wy = u32::from_be_bytes(pky_be[4 * k..4 * k + 4].try_into().expect("界内"));
        bld.set_cell_u32(pky_cols[k], row_pk, wy);
    }
    // ⑤′ E8 (S4)（J-d1）：sk_u∈[1,n−1] 门 + [sk_u]G 固定基循环 + 输出换根
    //     进标量世界 + 双 decompose + 16 词 recomp。健全性链条：sk 位
    //     （bool+lt_n+neq）→（β 环）→ 循环 →（传输环）→ st_pkx/st_pky →
    //     （decompose）→ recomp ↔ pk 词格 = SM3 体D/E 消息根 ⟹ (S1) 哈希
    //     消费的 pk_u 与 (S4) 的 [sk_u]G 电路内不可分割。
    // E9 起宿主曲线常量与 G/2G 大环句柄上提为 ⑤′/⑤″ 共享（纯 host 读，
    // 零分配零约束——上提不触 plan/emit 相序纪律）。
    let g = crate::sm2_ec_plonkish::g_coords();
    let d2g = crate::sm2_ec_plonkish::affine_double(Some(g)).expect("2G");
    let a_par = crate::sm2_ec_plonkish::curve_a();
    let (rg_base, rg_d2) = pl.g_base_channels();
    let m8 = bld.n_constraints();
    {
        // sk 标量世界（RANK_SK 行，全 rot=0）：位格布尔（循环消费前提——
        // 位格纪律：循环只消费不付布尔）+ 范围门 lt_n / neq_zero。
        let mut sk_bits = [false; 256];
        for (i, bt) in sk_bits.iter_mut().enumerate() {
            *bt = (w.sk_u[i / 64] >> (i % 64)) & 1 == 1;
        }
        for (p, &bt) in sk_bits.iter().enumerate() {
            bld.set_cell_u32(sk_bit_cols[p], row_sk, u32::from(bt));
        }
        bld.extend_selector(sk_bool_sel, &[row_sk]);
        for p in 0..256usize {
            bld.emit_bool(sk_bool_sel, sk_bit_cols[p]);
        }
        let sk_scalar = PlScalar { cols: sk_bit_cols, home: row_sk, val: w.sk_u };
        let _ = emit_lt_n(&mut bld, &sk_lt, row_sk, &sk_scalar, &crate::sm2_params::q_limbs());
        emit_neq_zero(&mut bld, &sk_neq, row_sk, &sk_scalar);
        // [sk_u]G 循环（Fix R-a 修复族：257 连续秩 + 头钉 + write-next）。
        // 基点绑定：base/d2v 锚点格追加进 G/2G 常量钉面大环（rid_base_g/
        // rid_d2_g，值恒 G/2G）——不开新环（E-H②），零约束零旋转；跳过此步
        // 则基点自由 ⟹ (S4) 空洞（prover 取 sk_u=1、base=pk_u）。
        // ③S3：sk 循环 window 化（β 车道/基点大环退役——绑定改走
        // sk recomp+绑定环；基点自由面被 G 表常数化根治）。
        let sk_fr = crate::sm2_params::fr_from_limbs(&w.sk_u);
        let ((skox, skoy), skout_row, skout_pt) = crate::sm2_ec_window_gadget::emit_window_mul(
            &mut bld, &sk_win, &g_table, RANK_SKLOOP, &sk_fr,
        );
        {
            use plonkish_backend::util::expression::Expression;
            let mut acc = Expression::<FpSM2>::Constant(FpSM2::ZERO);
            let mut pw = FpSM2::ONE;
            for i in 0..256usize {
                let bit_e = bld.q(sk_bit_cols[i], plonkish_backend::util::expression::Rotation::cur());
                acc = acc + bit_e * Expression::Constant(pw);
                pw *= FpSM2::from(2u64);
            }
            let vexpr = bld.q(sk_val, plonkish_backend::util::expression::Rotation::cur());
            bld.emit_assert_zero_tagged("ec.win.sk.recomp", sk_val_sel, acc - vexpr.clone());
            bld.relay_to_col(rid_sk_diff, sk_val, row_sk);
        }
        bld.set_cell_f(sk_val, row_sk, sk_fr);
        // 输出传输：x/y 进标量世界（见证按循环真值写；O 情形（sk_u=0，被
        // neq/recomp 在 mock 层击穿）写零格保持环一致）。
        // ③S3：window 输出（sk_u=0 负例形态=零格，同旧 None 语义）。
        let (ox, oy) = skout_pt;
        if skout_pt != (FpSM2::ZERO, FpSM2::ZERO) {
            debug_assert_eq!(
                crate::sm2_params::fr_to_limbs(&skout_pt.0),
                crate::sm2_params::fr_to_limbs(&w.pk_u.0),
                "宿主 [sk_u]G.x ≠ 见证 pk_u.x（见证侧 (S4) 断裂）"
            );
        }
        bld.relay_to_col(rid_pkx, skox, skout_row);
        bld.relay_to_col(rid_pky, skoy, skout_row);
        bld.set_cell_f(st_pkx, row_pk, ox);
        bld.set_cell_f(st_pky, row_pk, oy);
        // 双 decompose（merged P_A 同款几何：家点 row_pk，全 rot=0；位格即
        // recomp 位源——fold 唯一性承 M2a 系数 ∈ {−1,0,1} 论证）。
        let x_cell = bld.q(st_pkx, Rotation::cur());
        let y_cell = bld.q(st_pky, Rotation::cur());
        let _sca_pkx = emit_decompose(
            &mut bld,
            &dec_pkx,
            row_pk,
            x_cell,
            &crate::sm2_params::fr_to_limbs(&ox),
        );
        let _sca_pky = emit_decompose(
            &mut bld,
            &dec_pky,
            row_pk,
            y_cell,
            &crate::sm2_params::fr_to_limbs(&oy),
        );
        // 16 词 recomp（位→词，be_word_bit_terms 权威映射 = Id/attrs 同款；
        // pk_sels 家族激活点 = row_pk 唯一点——勘误 #26 纪律：extend 与
        // 约束同点发射，激活点审计对账 = 16 点 @ row_pk）。
        for j in 0..8usize {
            bld.extend_selector(pk_sels[j], &[row_pk]);
            let mut acc = Expression::<FpSM2>::zero();
            for (ib, sh) in be_word_bit_terms(j) {
                acc = acc
                    + Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(1u64 << sh))
                        * bld.q(dec_pkx.out[ib], Rotation::cur());
            }
            bld.emit_assert_zero(pk_sels[j], acc - bld.q(pkx_cols[j], Rotation::cur()));
        }
        for j in 0..8usize {
            bld.extend_selector(pk_sels[8 + j], &[row_pk]);
            let mut acc = Expression::<FpSM2>::zero();
            for (ib, sh) in be_word_bit_terms(j) {
                acc = acc
                    + Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(1u64 << sh))
                        * bld.q(dec_pky.out[ib], Rotation::cur());
            }
            bld.emit_assert_zero(pk_sels[8 + j], acc - bld.q(pky_cols[j], Rotation::cur()));
        }
        println!(
            "[e8-tally] (S4) 增量窗 {}（= 6,147+256+514+265+1+16 全加项 [实测]；\
             净额 +7,183——旧 ⑤ 常量锚 16 条拆除发生在本窗外）",
            bld.n_constraints() - m8
        );
    }
    // ⑤″ E9 (S3a)（J-d2）：r∈[1,n−1] 门 + C₁=r·G / Id·G 两固定基循环
    //     （Fix R-a 修复族 + G/2G 大环追加绑定，E8 同款四件套）+ 输出暂存
    //     传输环。Id 标量位 = E4 消息侧 id_bit_cols 复用（哈希消费与 EC 消费
    //     同位格——(S1)↔(S3) 双绑通道；位序已由 be_word_bit_terms crosscheck
    //     锁定，禁手写位序变换）。
    let m9 = bld.n_constraints();
    // ⑤″ 块表达式：产出 (c1_out_cols, c1_out_pt, idg_out, r_bits) 供 ⑤‴（C₂ 完全加与
    // r·apk 循环消费；host 点乘对拍在 ⑤″ 内完成）。
    let (c1_out_cols, c1_out_pt_v, idg_st, r_bits) = {
        let _ = 0; // 占位防未初始化误用——真实值在块尾返回

        // r 标量世界（RANK_R 行，全 rot=0）：位格布尔 + 范围门。
        let r_bits: [bool; 256] =
            std::array::from_fn(|i| (w.r[i / 64] >> (i % 64)) & 1 == 1);
        for (p, &bt) in r_bits.iter().enumerate() {
            bld.set_cell_u32(r_bit_cols[p], row_r, u32::from(bt));
        }
        bld.extend_selector(r_bool_sel, &[row_r]);
        for p in 0..256usize {
            bld.emit_bool(r_bool_sel, r_bit_cols[p]);
        }
        let r_scalar = PlScalar { cols: r_bit_cols, home: row_r, val: w.r };
        let _ = emit_lt_n(&mut bld, &r_lt, row_r, &r_scalar, &crate::sm2_params::q_limbs());
        emit_neq_zero(&mut bld, &r_neq, row_r, &r_scalar);
        // Id 标量位（LSB=0 整数位序，BE 字节解释——与消息侧位格同源推导）。
        let id_bits: [bool; 256] =
            std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
        // 基点绑定：两循环 base/d2v 锚点格追加进 G/2G 常量钉面大环（E8 同款，
        // 1024×2 成员；跳过则基点自由 ⟹ C₁ 可落任意点、(S3) 空洞）。
        for i in 0..256usize {
            for c in 0..3usize {

            }
        }
        // ③试点：C₁ window 化后基点自由面被 G 表常数化根治（无 base 格）。
        // r 位世界重组：val = Σ2^i·bit_i @row_r（单点线性门）——window 标量
        // 绑定约束（ec.win.scalar.bind）的语句侧锚。
        {
            let sel = c1_val_sel;
            use plonkish_backend::util::expression::Expression;
            let mut acc = Expression::<FpSM2>::Constant(FpSM2::ZERO);
            let mut pw = FpSM2::ONE;
            for i in 0..256usize {
                // witness 列读一律走 bld.q（局部号→全局号——🔴 直构 Query 列错位）。
                let bit_e = bld.q(r_bit_cols[i], plonkish_backend::util::expression::Rotation::cur());
                acc = acc + bit_e * Expression::Constant(pw);
                pw *= FpSM2::from(2u64);
            }
            let vexpr = bld.q(c1_val, plonkish_backend::util::expression::Rotation::cur());
            bld.emit_assert_zero_tagged("ec.win.r.recomp", sel, acc - vexpr.clone());
            // 标量绑定环成员（首键=diff 格@窗末行，plan 相注册）：环等值
            // diff==val，配合 gadget 侧 ec.win.diff（diff=acc末−offset=k）与
            // 本行 ec.win.r.recomp（val=Σ2^i·bit_i）——三段闭合：数字链↔r
            // 位世界（防线保持关键；无此环 C₁ 标量与语句标量脱钩）。
            bld.relay_to_col(rid_c1_diff, c1_val, row_r);
        }
        bld.set_cell_f(c1_val, row_r, crate::sm2_params::fr_from_limbs(&w.r));
        // ③S3：Id 标量世界 recomp + 绑定环成员（同 C₁ playbook）。
        {
            let sel = idg_val_sel;
            use plonkish_backend::util::expression::Expression;
            let mut acc = Expression::<FpSM2>::Constant(FpSM2::ZERO);
            let mut pw = FpSM2::ONE;
            for i in 0..256usize {
                let bit_e = bld.q(id_bit_cols[i], plonkish_backend::util::expression::Rotation::cur());
                acc = acc + bit_e * Expression::Constant(pw);
                pw *= FpSM2::from(2u64);
            }
            let vexpr = bld.q(idg_val, plonkish_backend::util::expression::Rotation::cur());
            bld.emit_assert_zero_tagged("ec.win.id.recomp", sel, acc - vexpr.clone());
            // 绑定环成员：diff 格（首键，窗末行）↔ idg_val。
            bld.relay_to_col(rid_idg_diff, idg_val, row_id);
        }
        bld.set_cell_f(idg_val, row_id, crate::sm2_params::fr_from_limbs(&std::array::from_fn(
            |kk: usize| u64::from_be_bytes(w.id_u[24 - 8 * kk..32 - 8 * kk].try_into().unwrap()),
        )));
        let ((c1ox, c1oy), c1out_row, c1out_pt) = crate::sm2_ec_window_gadget::emit_window_mul(
            &mut bld,
            &c1_win,
            &g_table,
            RANK_C1,
            &crate::sm2_params::fr_from_limbs(&w.r),
        );
        // ③S3：Id·G window 化（β 车道退役——标量绑定改走 id recomp+绑定环；
        // 基点自由面被 G 表常数化根治）。
        let ((igox, igoy), igout_row, igout_pt) = crate::sm2_ec_window_gadget::emit_window_mul(
            &mut bld,
            &idg_win,
            &g_table,
            RANK_IDG,
            &crate::sm2_params::fr_from_limbs(&std::array::from_fn(|kk: usize| {
                u64::from_be_bytes(w.id_u[24 - 8 * kk..32 - 8 * kk].try_into().unwrap())
            })),
        );
        // 宿主真值对拍（第五道防线：语义级对账——[r]G / [Id_u]G 独立 native
        // 标量乘 vs 循环输出，勘误 #27 家族检查单）。Option 对拍：零标量宿主
        // 返回 None（O 点），与循环输出 O 同侧——r=0 负例装配不得 panic。
        let c1_host = crate::sm2_ec_plonkish::affine_mul_bits(&r_bits, Some(g));
        let idg_host = crate::sm2_ec_plonkish::affine_mul_bits(&id_bits, Some(g));
        assert_eq!(
            Some(c1out_pt),
            c1_host,
            "C₁ window 输出 ≠ 宿主 [r]G（语义级对账断裂）"
        );
        // 无条件 assert（非 debug_assert）：release 测试下 debug_assertions
        // 关闭 ⟹ debug_assert 版对账全程空转（#26「防线空转」同型）。负例
        // 路径两侧同为 None（零标量 O 点），断言仍然成立。
        assert_eq!(
            Some(igout_pt),
            idg_host,
            "Id·G window 输出 ≠ 宿主 [Id_u]G（语义级对账断裂）"
        );
        // 输出传输：C₁ 暂存 @ row_r、Id·G 暂存 @ row_id（O 情形写零格保环
        // 一致——r∈[1,n−1] 门使 C₁≠O；Id_u=0 时 Id·G=O 由负例矩阵⑤管辖）。
        // ③试点：C₁ window 输出（r=0 负例形态=零格，同旧循环 None 语义）。
        let (c1x, c1y) = c1out_pt;
        // ③S3：Id·G window 输出（Id_u=0 负例形态=零格，同旧 None 语义）。
        let (igx, igy) = igout_pt;
        bld.relay_to_col(rid_c1x, c1ox, c1out_row);
        bld.relay_to_col(rid_c1y, c1oy, c1out_row);
        bld.relay_to_col(rid_idgx, igox, igout_row);
        bld.relay_to_col(rid_idgy, igoy, igout_row);
        bld.set_cell_f(st_c1x, row_r, c1x);
        bld.set_cell_f(st_c1y, row_r, c1y);
        bld.set_cell_f(st_idgx, row_id, igx);
        bld.set_cell_f(st_idgy, row_id, igy);
        println!(
            "[e9-tally] (S3a) 增量窗 {}（默认档 = 2×6,147 循环 + 256 bool + \
             265 lt_n + 1 neq = 12,816；AUTH 档 2026-10 空转消除后 = 546 [实测]\
             ——④ 段 256 bool + 8 recomp 已整体跳过）",
            bld.n_constraints() - m9
        );
        ((c1ox, c1oy), c1out_pt, (igx, igy), r_bits)
    };
    // ⑤‴ E10 (S3b)（J-d3）：apk staged 基头（on_curve 12 门，EP 基头同款）
    //     + r·apk 变基循环（β = rid_beta_c1 共享追加——两循环同标量同位源，
    //     一格一环红线下零新 β 环）+ C₂ = Id·G + r·apk 完全加 + 6 实例钉
    //     （12..17 = C₁/C₂/apk 公开面）。健全性链条：apk 钉格（实例面）
    //     →（base_a 大环）→ staged 头 on_curve 门 + 循环基点 →（β 共享）
    //     → r·apk →（尾环）→ C₂ 加数；C₁/Id·G 暂存（E9 传输环）→ C₂ 加数
    //     ⟹ (S3) 双承诺电路内闭合，公开面经 pin.bind 进实例面。
    let m10 = bld.n_constraints();
    {
        // apk staged 头 @ row_hra（EP 基头 sm2_verify_assemble.rs:824-881
        // 同款三段：staged 写入 → on_curve 三真值格 + 3 乘门 + 曲线方程 →
        // 2·apk 绑定 hd_a）。
        assert!(
            crate::sm2_ec_plonkish::on_curve_affine(Some(w.apk)),
            "见证 apk 不在曲线上（装配前语义自检）"
        );
        crate::sm2_ec_plonkish::write_point(&mut bld, &hs_a, row_hra, Some(w.apk));
        // base_a 大环（首键 = 钉格/staged 格，plan 相已注册）：x/y 通道的
        // staged 格是追加成员（环根 = apk 钉格，钉值经环置换直达 staged
        // 头与循环基点，EP 同款）；inf 通道无钉格 ⟹ 环根 = staged inf 格
        // 本身（首键已注册，禁自 relay——一格一环红线，首跑守卫抓获）。
        bld.relay_to_col(rid_base_a[0], hs_a.cols[0], row_hra);
        bld.relay_to_col(rid_base_a[1], hs_a.cols[1], row_hra);
        // on_curve 门（witness-first 教训：三真值格先写值，再发射 3 乘门
        // + 曲线方程；漏写则 y²/x² 违约而 p₂=p₁·x 假绿）。
        bld.extend_selector(oc_a_sel, &[row_hra]);
        let qax = bld.q(hs_a.cols[0], Rotation::cur());
        let qay = bld.q(hs_a.cols[1], Rotation::cur());
        let p1v = w.apk.0.square();
        bld.set_cell_f(oc_a[0], row_hra, p1v);
        bld.set_cell_f(oc_a[1], row_hra, p1v * w.apk.0);
        bld.set_cell_f(oc_a[2], row_hra, w.apk.1.square());
        bld.emit_prod_eq(
            oc_a_sel,
            qay.clone(),
            qay.clone(),
            bld.q(oc_a[2], Rotation::cur()),
        );
        bld.emit_prod_eq(
            oc_a_sel,
            qax.clone(),
            qax.clone(),
            bld.q(oc_a[0], Rotation::cur()),
        );
        bld.emit_prod_eq(
            oc_a_sel,
            bld.q(oc_a[0], Rotation::cur()),
            qax.clone(),
            bld.q(oc_a[1], Rotation::cur()),
        );
        bld.emit_assert_zero(
            oc_a_sel,
            bld.q(oc_a[2], Rotation::cur())
                - bld.q(oc_a[1], Rotation::cur())
                - Expression::<FpSM2>::Constant(a_par) * qax.clone()
                - Expression::<FpSM2>::Constant(crate::sm2_ec_plonkish::curve_b()),
        );
        // 2·apk 倍点门 + 绑定三推（bind_triple 自足内联——bind_triple 为
        // merged 私有，T1 线零触碰红线 ⟹ 三 set_cell_f + 3 emit_assert_zero
        // 复用 dga.sel，EP :859-866 逐字同构）。
        let dda = crate::sm2_ec_plonkish::emit_ec_double(
            &mut bld,
            &dga,
            row_hra,
            &crate::sm2_ec_plonkish::PtRef::cells(&hs_a, Some(w.apk)),
            a_par,
        );
        bld.set_cell_f(hd_a.cols[0], row_hra, dda.xv);
        bld.set_cell_f(hd_a.cols[1], row_hra, dda.yv);
        bld.set_cell_f(
            hd_a.cols[2],
            row_hra,
            if dda.iv { FpSM2::ONE } else { FpSM2::ZERO },
        );
        bld.emit_assert_zero(dga.sel, bld.q(hd_a.cols[0], Rotation::cur()) - dda.xe.clone());
        bld.emit_assert_zero(dga.sel, bld.q(hd_a.cols[1], Rotation::cur()) - dda.ye.clone());
        bld.emit_assert_zero(
            dga.sel,
            bld.q(hd_a.cols[2], Rotation::cur()) - dda.infe.clone(),
        );
        // d2a 宿主真值（r·apk 循环 d2v 见证；match-with-ZERO——禁 expect，
        // E9 教训：负例装配路径宿主数学全审查）。
        let d2a_host = match crate::sm2_ec_plonkish::affine_double(Some(w.apk)) {
            Some(d) => d,
            None => (FpSM2::ZERO, FpSM2::ZERO),
        };
        // r·apk 变基循环（apk 作变量基点见证；257 连续秩 3698..=3954）。
        let rk_out = crate::sm2_ec_plonkish::emit_ec_mul_loop_const_base(
            &mut bld, &rapk_loop, &rows_rapk, w.apk, d2a_host, &r_bits, a_par,
        );
        // β 共享：r·apk 循环位源 = rid_beta_c1 追加成员（两循环同标量 r
        // 同位格 r_bit_cols——一格一环红线下 β 环零新增；E-H② 红线）。
        for i in 0..256usize {
            bld.relay_to_col(rid_beta_rapk[i], rapk_loop.bit, rows_rapk[i]);
        }
        // 基点绑定（健全性关键，E8 四件套第三次应用）：base/d2v 锚点格
        // 追加进 apk staging 基/倍通道环（首键 = 钉格/staged 格）——跳过则
        // 循环基点自由 ⟹ prover 任选 base 使 (S3) C₂ 通道空洞。
        for i in 0..256usize {
            for c in 0..3usize {
                bld.relay_to_col(rid_base_a[c], rapk_loop.base.cols[c], rows_rapk[i]);
                bld.relay_to_col(rid_d2_a[c], rapk_loop.d2v.cols[c], rows_rapk[i]);
            }
        }
        // 宿主对拍（第五道防线，#27 语义级对账；Option 对拍——零标量 r 的
        // 负例装配路径 affine_mul_bits 返回合法 None，禁 expect）。
        let rk_host = crate::sm2_ec_plonkish::affine_mul_bits(&r_bits, Some(w.apk));
        assert_eq!(
            rk_out.pt, rk_host,
            "r·apk 循环输出 ≠ 宿主 [r]apk（语义级对账断裂）"
        );
        // C₂ 加数写入：Id·G（E9 暂存 → c2idg 暂存环）与 r·apk（循环尾 →
        // c2rpk 暂存环）@ row_ac2。
        // ③S3：window 输出恒仿射——零坐标按 O 语义（负例 Id_u=0 形态，
        // 旧循环 None 同语义）。
        let idg_aff: crate::sm2_ec_plonkish::Affine =
            if idg_st == (FpSM2::ZERO, FpSM2::ZERO) { None } else { Some(idg_st) };
        crate::sm2_ec_plonkish::write_point(&mut bld, &c2idg, row_ac2, idg_aff);
        crate::sm2_ec_plonkish::write_point(&mut bld, &c2rpk, row_ac2, rk_out.pt);
        // Id·G x/y 环：E9 暂存环 rid_idgx/rid_idgy 追加成员（不开新环，
        // E-H②——c2idg 格与 st_idgx/st_idgy 经环缝合）；inf 走新二元小环
        // rid_idg_inf（c2idg.inf ← idg_out.inf@rows_idg[256]）。
        bld.relay_to_col(rid_idgx, c2idg.cols[0], row_ac2);
        bld.relay_to_col(rid_idgy, c2idg.cols[1], row_ac2);
        // ③S3：inf 环退役（window 输出无 inf 格——加数 O 情形由零坐标语义
        // 承担，负例 Id_u=0 的违约面=on_curve/完全加约束）。
        // r·apk 尾环：循环 acc_in@rows_rapk[256] → c2rpk（x/y/inf 三通道）。
        for c in 0..3usize {
            bld.relay_to_col(rid_tail_rk[c], rk_out.cols[c], rows_rapk[256]);
        }
        // C₂ = Id·G + r·apk 完全加（28 门，sm2_ec_plonkish.rs:550 同款）。
        let c2_out = crate::sm2_ec_plonkish::emit_ec_add_complete(
            &mut bld,
            &ac2,
            row_ac2,
            &crate::sm2_ec_plonkish::PtRef::cells(&c2idg, idg_aff),
            &crate::sm2_ec_plonkish::PtRef::cells(&c2rpk, rk_out.pt),
            a_par,
        );
        assert_eq!(
            c2_out.pt,
            crate::sm2_ec_plonkish::affine_add(idg_aff, rk_out.pt),
            "C₂ 完全加输出 ≠ 宿主 Id·G + r·apk（语义级对账断裂）"
        );
        // 6 实例钉（12..17）：C₁.x/C₁.y（E9 暂存值）、C₂.x/C₂.y（完全加
        // 输出）、apk.x/apk.y（见证值）。pin_one 三件套自足内联（pin.bind
        // 语义 = s·(q(val,cur) − q_inst(cur))，sel 激活恰 = 钉行；merged
        // emit_face 逐字先例）。
        let c2xy = match c2_out.pt {
            Some((x, y)) => (x, y),
            None => (FpSM2::ZERO, FpSM2::ZERO),
        };
        let pin_vals: [(usize, usize, FpSM2); 6] = [
            (
                pin_cols[0],
                pin_rows[0],
                c1_out_pt_v.0,
            ),
            (
                pin_cols[1],
                pin_rows[1],
                c1_out_pt_v.1,
            ),
            (pin_cols[2], pin_rows[2], c2xy.0),
            (pin_cols[3], pin_rows[3], c2xy.1),
            (pin_cols[4], pin_rows[4], w.apk.0),
            (pin_cols[5], pin_rows[5], w.apk.1),
        ];
        for (k, (pc, pr, pv)) in pin_vals.iter().enumerate() {
            bld.set_cell_f(*pc, *pr, *pv);
            bld.extend_selector(pin_sels[k], &[*pr]);
            bld.emit_pin_val_only(pin_sels[k], *pc, 12 + k);
            bld.set_instance(12 + k, *pv);
        }
        // C₁ 钉环：E9 暂存环 rid_c1x/rid_c1y 追加成员（钉格入环，不开新环）；
        // C₂ 输出钉环：完全加输出 → 钉格（rid_c2x/rid_c2y 首键 = 钉格）。
        bld.relay_to_col(rid_c1x, pin_cols[0], pin_rows[0]);
        bld.relay_to_col(rid_c1y, pin_cols[1], pin_rows[1]);
        bld.relay_to_col(rid_c2x, c2_out.cols[0], row_ac2);
        bld.relay_to_col(rid_c2y, c2_out.cols[1], row_ac2);
        println!(
            "[e10-tally] (S3b) 增量窗 {}（[推得] = 12 基头 + 6,147 循环 \
             + 28 完全加 + 6 钉 = 6,193；首跑命中后升 [实测]）",
            bld.n_constraints() - m10
        );
    }
    // ⑤⁗ E11 (S5)（J-e1）：谓词湮灭 + pred_out 实例 18。语义 = R1CS M6
    //     先例（m0_sm3_circuit/show_circuit_r1cs.rs `enforce_pred`）：谓词 ≜
    //     "attrs_u == PRED_TARGET"（单属性相等，M2c spec §5；多属性/区间为
    //     扩展）。健全性链条：湮灭门 pred_out·(attrs_bit−target_bit)=0 ×256
    //     （pred_out=1 线性强制 ⟹ 每 diff_i=0 ⟹ attrs 位逐位==target 位）
    //     + pin.bind 缝合实例 18（def:pi (S5) 公开面 pred_out）。attrs 位
    //     即 ④ recomp 位源同格 ⟹ (S1) 哈希消费的 attrs_u 与 (S5) 谓词
    //     消费的 attrs_u 电路内不可分割（双绑通道，E9 Id 先例）。
    let m11 = bld.n_constraints();
    {
        // 勘误 #28：实例列在非钉行恒 0（inst_at[row_mapping()[k]] = inst[k]，
        // sm3_compress.rs mock 求值口径）⟹ pin.bind 必须激活在钉行
        // row_mapping()[18]（秩 19）且值格在钉行；谓词门在 row_attrs 消费
        // pred_out——两点相距 31 秩 > K ⟹ 不可旋转，两格经 rid_pred_pin 环
        // 缝合（首键 = 钉格，E10 钉环同款；一格一环红线 ✓）。
        bld.set_cell_f(pred_cell, row_attrs, FpSM2::ONE);
        bld.set_cell_f(pred_cell, pin_row_pred, FpSM2::ONE);
        bld.extend_selector(pred_sel, &[row_attrs]);
        // B-batch3 数值档：谓词=schema 段等值（位 0..224 ↔ attrs_true[4..32]）；
        // num 位（224..256 ↔ attrs_true[0..4]）归 θ 范围门管辖——湮灭门越界
        // 会把数值位钉死到等值 target，范围语句被静默失效（语义红线）。
        // 🔴 定谳三次（2026-09-16）：v1 起循环恒 256 而 seg32 的 num 字节恒 0
        // ⟹ num 的每个 1 位在湮灭门违约（0xF4240=7 位/0xF4245=9 位——
        // honest 底噪 prod.eq 的根因）。修复=数值档只发 schema 位（0..224），
        // num 位完全让渡范围门。
        let mut seg32 = PRED_TARGET;
        let mut b3_numeric = false;
        if let Some(cfg) = pc_cfg_ref.as_ref() {
            if let Some(seg) = cfg.schema_seg {
                b3_numeric = true;
                seg32 = [0u8; 32];
                for p in 0..224usize {
                    seg32[31 - p / 8] |= ((seg[27 - p / 8] >> (p % 8)) & 1) << (p % 8);
                }
            }
        }
        // AUTH 档（B3）：attrs_u=C 值（无谓词语义）——湮灭门全让渡（n_gate=0；
        // C 位自由，(S1) 哈希消费绑定由 ④ recomp ↔ M 槽词等值承担）；pred_out=1
        // 与实例 18 保留（档位声明面：谓词档=湮灭门生效/AUTH 档=零谓词）。
        let auth_gate = pc_cfg_ref.as_ref().map(|c| c.auth.is_some()).unwrap_or(false);
        let n_gate = if auth_gate { 0 } else if b3_numeric { 224 } else { 256 };
        for i in 0..n_gate {
            // 位序与 ④ 见证侧一致：整数位 i（LSB=0）= 字节 31−i/8 位 i%8
            // （be_word_bit_terms crosscheck 锁定的同源推导，禁手写变换）。
            let t = (seg32[31 - i / 8] >> (i % 8)) & 1;
            let bit = bld.q(attrs_bit_cols[i], Rotation::cur());
            let diff = if t == 1 {
                bit - Expression::<FpSM2>::Constant(FpSM2::ONE)
            } else {
                bit
            };
            bld.emit_prod_eq(
                pred_sel,
                bld.q(pred_cell, Rotation::cur()),
                diff,
                Expression::<FpSM2>::zero(),
            );
        }
        bld.emit_assert_zero(
            pred_sel,
            bld.q(pred_cell, Rotation::cur()) - Expression::<FpSM2>::Constant(FpSM2::ONE),
        );
        // 钉族（激活点 = 钉行恰 1 点）：pin.bind 缝合实例 18。
        bld.extend_selector(pred_pin_sel, &[pin_row_pred]);
        bld.emit_pin_val_only(pred_pin_sel, pred_cell, 18);
        // 环缝合：钉格（首键）↔ 谓词工作格。
        bld.relay_to_col(rid_pred_pin, pred_cell, row_attrs);
        bld.set_instance(18, FpSM2::ONE);
        println!(
            "[e11-tally] (S5) 增量窗 {}（数值档 = 224 湮灭 + 1 线性 + 1 pin.bind = 226；\
             默认档 = 256+1+1 = 258；定谳三次：数值档湮灭让渡 num 位 32 条）",
            bld.n_constraints() - m11
        );
    }
    // ⑥ 验签体（16,554 零接触复用）。E7 起五元组全真源：e = 大折叠(三块
    //    native 摘要)（与 ⑧′ 电路约束同式同系数），(r_s, s_s) = 对该 e 的
    //    真 SM2 签名（tests::sm2_sign_host 生成），pk_I = 签发者钥对 ⟹
    //    (S1)↔(S2) 绑定在见证侧闭合，电路侧由 ⑧′ 折叠约束封口。签名正确性
    //    由 emit_verify_body 内 verify_replay 断言随行（真签名恒过）。
    let ntv = crate::sm3_native_ref::compress;
    let v1h = ntv(&crate::sm3_native_ref::IV, &host.blocks[0]);
    let v2h = ntv(&v1h, &host.blocks[1]);
    let dgw_h = ntv(&v2h, &host.blocks[2]);
    let e_stmt = fold_digest_fp(&dgw_h);
    let r_stmt = crate::sm2_params::fr_from_limbs(&w.r_s);
    let s_stmt = crate::sm2_params::fr_from_limbs(&w.s_s);
    let mut led = emit_verify_body(&mut bld, &pl, e_stmt, r_stmt, s_stmt, w.pk_i.0, w.pk_i.1);
    // ⑦ 三体链段（宿主数学/负轮锚/门层/出口+摘要面；Fold 无 echo 钉）。
    //    P2：SM3_LUT=1 ⟹ 查表体约束+查表论证替换布尔体发射（环/写已在 WIRES 相）。
    let (out_digest, lut_chain_states) = if lut_on {
        crate::sm3_lookup_weave::weave_constraints(
            &mut bld,
            lut_circ.as_ref().expect("LUT 电路"),
            lut_plan.as_ref().expect("LUT PLAN"),
            &msg_roots,
            &dgw_cols,
            row_ae,
        );
        // R3-3.1：承诺 C 单块组（第 4 组）约束+查表发射——布尔 z 体（
        // assemble_commit_one，~45-60K 约束）已被 36 条约束+8 查表替换。
        if let (Some(cc), Some((sh_cols, sh_sels))) = (c_circ.as_ref(), c_shadow.as_ref()) {
            crate::sm3_lookup_weave::weave_commit_block_constraints(
                &mut bld,
                cc,
                lut_plan.as_ref().expect("LUT PLAN"),
                3,
                &c_msg_roots.expect("LUT 承诺档 C 词根表在场"),
                &b2_c_cols,
                b2_row_c,
                sh_cols,
                sh_sels,
            );
        }
        // 链间态宿主补算（hooks 消费；LUT 形态下同一 native 数学）
        let s1 = ntv(&crate::sm3_native_ref::IV, &host.blocks[0]);
        let s2 = ntv(&s1, &host.blocks[1]);
        (dgw_h, [s1, s2])
    } else {
        let out = assemble_chained_bodies(
            &mut bld,
            cplan.as_ref().expect("布尔 PLAN"),
            &ChainedCtx { blocks: &host.blocks, init: crate::sm3_native_ref::IV },
        );
        // 宿主摘要一致性：⑥ 预计算 vs 链段出料（同一 host.blocks 的两条独立
        // native 数学路径；不一致 ⟹ e 与摘要错位、电路不可满足——在此即断言，
        // 错误信息离根因更近）。
        assert_eq!(out.digest, dgw_h, "链段出料摘要 ≠ ⑥ 宿主预计算");
        (out.digest, out.chain_states)
    };
    // ⑧ dgw 见证（echo 环落点格：协议层由环置换保证 == digval，mock 盲区
    //    由 audit_ring_values 兜底——环值审计）。
    for k in 0..8usize {
        bld.set_cell_u32(dgw_cols[k], row_ae, out_digest[k]);
    }
    // ⑧′ E7 e 绑定（J-4/D3）：摘要 8 词大折叠 == e 面值列 @ row_ae（全 cur
    //     零旋转、零新增列/选择器——发射在 e 面词位家族选择器上，激活点恰 =
    //     row_ae 唯一点，勘误 #26 守卫锁定；同 sel 多约束先例 = emit_face
    //     自家 265 条）。闭合链：dgw ↔ digval 由 ChainEcho::Fold echo 环；
    //     pv@row_ae ↔ 实例 0 由 rid_pv 环 + pin.bind ⟹ Σ2^{32k}·dgw_k == e。
    let m = bld.n_constraints();
    let (e_sel, e_pv) = pl.e_face_fold_anchor();
    let mut efold = Expression::<FpSM2>::zero();
    for (k, &c) in dgw_cols.iter().enumerate() {
        efold = efold
            + Expression::<FpSM2>::Constant(crate::sm2_params::f_pow2(32 * k))
                * bld.q(c, Rotation::cur());
    }
    bld.emit_assert_zero(e_sel, efold - bld.q(e_pv, Rotation::cur()));
    led.e_bind = bld.n_constraints() - m;
    // ⑨ 实例面：0..2 = 验签体 e/r/s（真源 ⑥；3..11 已由 pin_one 落）；
    //    12..17 = E10 六钉（C₁.x/C₁.y/C₂.x/C₂.y/apk.x/apk.y）；18 = pred_out
    //    （⑤⁗ E11 钉 =1）。
    bld.set_instance(0, e_stmt);
    bld.set_instance(1, r_stmt);
    bld.set_instance(2, s_stmt);
    // ⑩ T2.5 上下文/谓词绑定（勘误 #29）：实例 19 = ctx_tag、20 = pred_id。
    //    绑定语义 = pin.bind 语义钉（emit_pin_val_only，merged emit_face 先例；
    //    钉行 = row_mapping()[19]/[20]，勘误 #28 对齐）⟹ π 绑定完整实例向量，
    //    跨上下文/跨策略改写公开向量即验败（T-b/T-c 篡改测试守卫）。
    let m29 = bld.n_constraints();
    bld.set_cell_f(t25_ctx_col, crate::sm3_compress::row_mapping()[19], ctx_tag);
    bld.extend_selector(t25_ctx_sel, &[crate::sm3_compress::row_mapping()[19]]);
    bld.emit_pin_val_only(t25_ctx_sel, t25_ctx_col, 19);
    bld.set_instance(19, ctx_tag);
    bld.set_cell_f(t25_pid_col, crate::sm3_compress::row_mapping()[20], pred_id);
    bld.extend_selector(t25_pid_sel, &[crate::sm3_compress::row_mapping()[20]]);
    bld.emit_pin_val_only(t25_pid_sel, t25_pid_col, 20);
    bld.set_instance(20, pred_id);
    println!(
        "[t25-tally] (T2.5) 上下文/谓词绑定增量窗 {}（[实测] = 2 pin.bind）",
        bld.n_constraints() - m29
    );
    // ⑩′ T2.6 (S6) 有效期（拍板 B-专设字段）：实例 21 = T（验证方注入当前
    //     epoch，pin.bind 缝合——「钉=绑定」零新增理论）；exp 词格 = 消息面
    //     pad_words[0]（体E 词 8 入 (S1) 哈希，(S1)↔(S6) 双绑通道）；d :=
    //     exp_u − T 的 32 位分解（位格 + 组合约束）——d ∈ [0,2^32) ⟺
    //     exp_u ≥ T（健全性：exp_u<T ⟹ d=p−(T−exp_u)≫2^32 不可分解）。
    //     RED/GREEN 分界：组合约束 [GREEN +1] 处——RED 态缺失 ⟹ 过期凭证
    //     可满足（s6 测试②即红）。
    let m26 = bld.n_constraints();
    let t_pv = FpSM2::from(u64::from(t_epoch));
    bld.set_cell_f(s6_t_col, row_exp, t_pv);
    bld.extend_selector(s6_t_pin_sel, &[row_exp]);
    bld.emit_pin_val_only(s6_t_pin_sel, s6_t_col, 21);
    bld.set_instance(21, t_pv);
    bld.set_cell_u32(s6_exp_col, row_exp, host.pad_words[0]);
    let d32 = w.exp_u.wrapping_sub(t_epoch);
    for p in 0..32usize {
        let bitv = (d32 >> (31 - p)) & 1;
        bld.set_cell_u32(s6_dbit_cols[p], row_exp, u32::from(bitv));
    }
    bld.extend_selector(s6_sel, &[row_exp]);
    for p in 0..32usize {
        bld.emit_bool(s6_sel, s6_dbit_cols[p]);
    }
    // [GREEN +1] 分解组合（最小形态承重件）：Σ2^{31−p}·d_p − exp + T == 0。
    // 健全性：d 位 bool（上 32 条）+ 分解唯一性 ⟹ Σ2^{31−p}·d_p ∈ [0, 2^32)，
    // 而约束强制其 == exp−T ∈ F_p——exp_u ≥ T 时 d=exp−T 唯一分解 ✓；exp_u < T
    // 时 exp−T mod p = p−(T−exp) ≫ 2^32 不可分解 ⟹ 假语句不可满足（s6 测试②）。
    let mut dsum = Expression::<FpSM2>::zero();
    for p in 0..32usize {
        dsum = dsum
            + Expression::<FpSM2>::Constant(<FpSM2 as From<u64>>::from(1u64 << (31 - p)))
                * bld.q(s6_dbit_cols[p], Rotation::cur());
    }
    bld.emit_assert_zero(
        s6_sel,
        dsum - bld.q(s6_exp_col, Rotation::cur()) + bld.q(s6_t_col, Rotation::cur()),
    );
    println!(
        "[s6-tally] (S6) 有效期增量窗 {}（[实测] = 32 bool + 1 pin.bind + 1 组合；\
         净额 +33——pad 锚词 0 拆除 −1 发生在窗外②段）",
        bld.n_constraints() - m26
    );
    // B6-T2 定谳修（2026-09-21）：B4 将 auth 档容量提至 25（+θ22/SMT23/class24）
    // 后本断言 22 未同步——release 构建编译掉 debug_assert 故未暴露，debug 构建
    // 假红。改为档位感知（容量=Builder::new 注入值的回声核对）。
    debug_assert_eq!(
        bld.num_instances(),
        bld_capacity,
        "实例面容量==档位容量（auth=25：12+7+2 T2.5+1 T2.6+θ22+SMT23+class24；pred=23；legacy=22）"
    );

    // E12 矩阵②③锚（add-only accessor：面槽 pv@home ×2 + P_A.x 钉格）。
    let (r_pv_home, s_pv_home, pax_pin) = pl.t1_neg_anchors();
    let hooks = FullStatementHooks {
        za_anchor0: (za_col, za_rows[0]),
        apk_pin: (pin_cols[4], pin_rows[4]),
        apk_stg0: (hs_a.cols[0], row_hra),
        attrs_bit0: (attrs_bit_cols[0], row_attrs),
        dgw0: (dgw_cols[0], row_ae),
        dgw_cols,
        row_c0: ZONE0.stripe_row(0, off::SS1PRE),
        row_e0: ZONE0.stripe_row(63, off::TT2),
        chain_states: lut_chain_states,
        digest: out_digest,
        sk_bit0: (sk_bit_cols[0], row_sk),
        pkx_cols,
        pky_cols,
        row_pk,
        // ③S3：window 化后循环首行=窗首行（负例④钩子等价迁移）。
        sk_loop_row0: crate::sm3_compress::row_mapping()[RANK_SKLOOP + 1],
        r_bit0: (r_bit_cols[0], row_r),
        c1_x0: (st_c1x, row_r),
        c1_y0: (st_c1y, row_r),
        idg_x0: (st_idgx, row_id),
        idg_y0: (st_idgy, row_id),
        pred_cell: (pred_cell, row_attrs),
        pred_pin_cell: (pred_cell, pin_row_pred),
        r_pv_home,
        s_pv_home,
        pax_pin,
        attrs_word0: (attrs_cols[0], row_attrs),
        id_bit0: (id_bit_cols[0], row_id),
        s6_exp_cell: (s6_exp_col, row_exp),
        s6_t_pin_cell: (s6_t_col, row_exp),
        s6_dbit0: (s6_dbit_cols[0], row_exp),
        commit_c0: if pc.is_some() { (b2_c_cols[0], b2_row_c) } else { (0, 0) },
        pred_theta_cell: (0, 0),
    };
    // ═════════ B-batch2 承诺档 EMIT 尾:(S7) IV 单块发射(消息根=
    // salt‖attrs_true‖padding;pad 四词常量锚钉死——防消息长度语义漂移;
    // 出口 C 绑定已由 PLAN 相环承载)。默认路径零触碰。═════════
    if let Some(salt) = pc {
        let auth_pi = pc_cfg_ref.as_ref().and_then(|c| c.auth.clone());
        // R3-3.1：LUT 档 blk 已在 PLAN 相构（c_blk）；legacy 档此处原构造
        // （commit_block64 同式——单一事实源，两档字节级一致）。
        let blk: [u8; 64] = c_blk
            .as_ref()
            .copied()
            .unwrap_or_else(|| commit_block64(&salt, auth_pi.as_ref(), &w.attrs_u));
        // salt 根格见证（两档同：词 0..3 @3800..3803）。
        for j in 0..4usize {
            let wv = u32::from_be_bytes(salt[4 * j..4 * j + 4].try_into().expect("界内"));
            bld.set_cell_u32(b2_salt_cols[j], crate::sm3_compress::point_at_rank(3800 + j), wv);
        }
        if let (Some(ap), Some(tcols)) = (auth_pi.as_ref(), b2_true_cols_all.as_ref()) {
            // AUTH：原像词 4..13 根带见证（3808..3817）+pad 常量锚（词 14=0/
            // 词 15=432 @3818/3819）。词 13 含 sn_h 尾+0x80（见证非常量）。
            // 词 9（消息词 13）跨 padding 边界（消息 54B 止于字节 53）——
            // 从已组装 64B 块取词（blk 含 0x80@54 与零填充，SM3 块语义即如此）。
            for j in 0..10usize {
                let wv = u32::from_be_bytes(blk[16 + 4 * j..20 + 4 * j].try_into().expect("界内"));
                bld.set_cell_u32(tcols[j], crate::sm3_compress::point_at_rank(3808 + j), wv);
            }
            let pcols = b2_pad_cols_all.as_ref().expect("auth 档 pad 列在场");
            let pad_auth: [u32; 2] = [0, 440];  // B4 v3：55B 消息长 440bit
            for j in 0..2usize {
                let row = crate::sm3_compress::point_at_rank(3818 + j);
                bld.set_cell_u32(pcols[j], row, pad_auth[j]);
                bld.extend_selector(b2_pad_sels[j], &[row]);
                bld.emit_const_val(b2_pad_sels[j], pcols[j], pad_auth[j]);
            }
            // B4（A4）class 钉 wires：词 5 根格（秩 3809）环中继到 class 行
            // （θ 门同构——环=全局置换无旋转约束）+32 位播种（word5 全分解）。
            if let Some((dcols, _bs, _ps, class_row)) = b4_class_plan {
                let w5: u32 = u32::from_be_bytes(
                    blk[20..24].try_into().expect("界内"),
                );
                // R3-3.1：LUT 档=PLAN 相专用 class 环；legacy=CommitOne 消息环。
                let rid = match c_gate_rings.1 {
                    Some(id) => id,
                    None => bld
                        .ring_of(tcols[1], crate::sm3_compress::point_at_rank(3809))
                        .expect("承诺词 b2_true_cols[1] 根格应在 CommitOne 消息环中"),
                };
                bld.relay_to_col(rid, tcols[1], class_row);
                bld.set_cell_u32(tcols[1], class_row, w5);
                for i in 0..32usize {
                    bld.set_cell_u32(dcols[i], class_row, (w5 >> i) & 1);
                }
            }
        } else {
            let pad_w: [u32; 4] = [0x8000_0000, 0, 0, 384];
            for j in 0..4usize {
                // 根行 = PLAN 相 CommitOne 根表行式 3812+(12+j) = 3824+j
                //（首版 3812+j 与登记行错位 12——词 13/14 值 0 侥幸一致、
                // 词 12/15 非零暴露,环审计两条坏环的根因）。
                let row = crate::sm3_compress::point_at_rank(3824 + j);
                bld.set_cell_u32(b2_pad_cols[j], row, pad_w[j]);
                // 常量锚:sel·(val − const)=0(激活点=根行恰 1 点;sel 已 PLAN alloc)。
                bld.extend_selector(b2_pad_sels[j], &[row]);
                bld.emit_const_val(b2_pad_sels[j], b2_pad_cols[j], pad_w[j]);
            }
        }
        // 布尔 z 体（legacy 档专用——R3-3.1 LUT 档由查表第 4 组承载，约束相
        // weave_commit_block_constraints 发射；zplan=None 即零触碰）。
        if let Some(zplan) = b2_zplan.as_ref() {
            let _zout = crate::sm3_compress_v2::assemble_z_bodies(
                &mut bld,
                zplan,
                &crate::sm3_compress_v2::ZuCtx {
                    b2: &blk,
                    b3: &blk,
                    iv2: &crate::sm3_native_ref::IV,
                    form: crate::sm3_compress_v2::ZuForm::CommitOne,
                },
            );
        }
    }
    // ═════════ B-batch3 数值谓词档(系统线 2026-09-16 续批；定谳三次收官
    // 2026-09-16 论文线接手)：范围门(δ×32+recomb+θ 消费式实例 22)+schema
    // 等值钉×224(挂 pred_sel@row_attrs)。钉行=rm[22](勘误 #28 折叠域生成元链)。
    // R3-3.1：门槛条件 zplan→pc（LUT 档 zplan=None 但承诺词面/门全在）。═══
    if let (Some(cfg), true) = (pc_cfg_ref.as_ref(), pc.is_some()) {
        if let Some(theta) = cfg.theta {
            let rm = crate::sm3_compress::row_mapping();
            let theta_row = rm[22];
            // AUTH：num=原像词 4（cert BE u32）；pred：num=attrs 首 4B。
            let num_w = match cfg.auth.as_ref() {
                Some(ap) => u32::from_be_bytes(ap.cert_be),
                None => u32::from_be_bytes(w.attrs_u[0..4].try_into().expect("界内")),
            };
            // B6-T2 定谳修（2026-09-21）：负例态（num<θ）此处 u32 下溢——release
            // 静默 wrap=设计语义（wrap 值位分解使 recomb 域内必违约=below-level
            // 捕获机制），debug 默认 panic 造成假红。显式 wrapping_sub 对齐两档。
            let delta = num_w.wrapping_sub(theta);
            // ① 范围门：δ 列×32(θ 行见证=δ 位)+δ bool+recomb。recomb 语义
            //    （T2.5 消费式，恢复 v1 形态）：Σ2^i·δ_i − num + θ(实例 22,
            //    q_inst@θ 行) = 0，其中 num 的读数源=b2_true_cols[0]@θ 行——
            //    经下方环中继与承诺词根格等值（无中继则读数源为自由格=范围
            //    语句脱钩；🔴 v3 缺实例项与 θ 行读数，θ 行 b2_true_cols[0] 未置
            //    ⟹ δ=0 侥幸通过、δ≠0 在 2172 违约、θ 实例装饰性）。
            let dcols = b3_dcols;
            let range_sel = b3_range_sel;
            for i in 0..32usize {
                bld.set_cell_u32(dcols[i], b3_theta_row, (delta >> i) & 1);
                bld.emit_bool(range_sel, dcols[i]);
            }
            // 环中继：b2_true_cols[0]@θ 行并入承诺词根格等值类（词 4 根格
            // @秩 3808）——环=全局置换无旋转约束；θ 行格自由 ⟹ 一格一环满足。
            // R3-3.1：LUT 档=PLAN 相专用 θ 环；legacy=CommitOne 消息环。
            let rid_num = match c_gate_rings.0 {
                Some(id) => id,
                None => bld
                    .ring_of(b2_true_cols[0], crate::sm3_compress::point_at_rank(3808))
                    .expect("承诺词 b2_true_cols[0] 根格应在 CommitOne 消息环中"),
            };
            bld.relay_to_col(rid_num, b2_true_cols[0], b3_theta_row);
            bld.set_cell_u32(b2_true_cols[0], b3_theta_row, num_w);
            let mut rec = Expression::<FpSM2>::Constant(FpSM2::ZERO);
            for i in 0..32usize {
                rec = rec
                    + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << i))
                        * bld.q(dcols[i], Rotation::cur());
            }
            rec = rec
                - bld.q(b2_true_cols[0], Rotation::cur())
                + bld.q_inst(Rotation::cur());
            bld.push(
                "pred.t1.range.recomb",
                bld.sel(b3_range_sel) * rec,
            );
            // ② θ 消费式实例 22（T2.5「钉=绑定」同机制：recomb 经 q_inst@θ 行
            //    消费 ⟹ θ 篡改 ⟹ recomb 违约）。num 不作公开实例——评分公开
            //    若需要 num，属部署层声明性输出（约束无消费=装饰，同实例 23
            //    定谳），不占实例面。
            bld.set_instance(22, FpSM2::from(u64::from(theta)));
            // ②b B4（A4）class 等值钉（AUTH 档）：词 5 全 32 位分解的 recomb
            //    （读数源=环中继到 class 行的承诺词）+高 8 位消费式钉实例 24
            //    == class_id——自报机型攻击的电路封堵（θ 门同构机制）。
            let auth_pi_c = pc_cfg_ref.as_ref().and_then(|c| c.auth.clone());
            if let (Some(ap), Some((dcols, bsel, psel, class_row))) =
                (auth_pi_c.as_ref(), b4_class_plan)
            {
                let _ = class_row;
                for i in 0..32usize {
                    bld.emit_bool(bsel, dcols[i]);
                }
                let mut rec = Expression::<FpSM2>::Constant(FpSM2::ZERO);
                for i in 0..32usize {
                    rec = rec
                        + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << i))
                            * bld.q(dcols[i], Rotation::cur());
                }
                rec = rec - bld.q(b2_true_cols[1], Rotation::cur());
                bld.push("auth.class.recomb", bld.sel(bsel) * rec);
                let mut pin = Expression::<FpSM2>::Constant(FpSM2::ZERO);
                for j in 0..8usize {
                    pin = pin
                        + Expression::<FpSM2>::Constant(FpSM2::from(1u64 << j))
                            * bld.q(dcols[24 + j], Rotation::cur());
                }
                pin = pin - bld.q_inst(Rotation::cur());
                bld.push("auth.class.pin", bld.sel(psel) * pin);
                bld.set_instance(24, FpSM2::from(u64::from(ap.class_id)));
            }
            // ③ schema 等值钉×224（AUTH 档 schema=None 跳过——id_number 见证
            //    必须隐藏，无公开等值段；pred 档语义原样）。
            if let Some(schema_seg) = cfg.schema_seg {
            for p in 0..224usize {
                let cv = <FpSM2 as From<u64>>::from(u64::from(
                    (schema_seg[27 - p / 8] >> (p % 8)) & 1,
                ));
                bld.emit_assert_zero_tagged(
                    "pred.t1.schema.eq",
                    pred_sel,
                    bld.q(attrs_bit_cols[p], Rotation::cur())
                        - Expression::<FpSM2>::Constant(cv),
                );
            }
            // ④（定谳二次拍板采纳）：实例 23 删除——schema_id 无约束消费=
            //    装饰性公开值；schema_id 保持电路常量（编译期部署参数）。
            }
        }
    }
    // B3b（飞证）：SMT EMIT 段（叶 recomb+根折叠+实例 24——零分配）
    if let Some((wiring, sp, kb, mw, oc)) = smt_emit.as_ref() {
        crate::smt_weave::weave_smt_emit(&mut bld, mw, wiring, sp);
        // R2-SMT 修复（2026-09-23）：proto 查表门全量翻译——SMT 链 64 组的
        // 4 约束/组 + 8 lookup/组进 Builder（此前仅翻译环+值，压缩函数电路内
        // 零强制：auth_smt_forged_root_vacuity_red 红线测试实锤后封堵）。
        // TRAIL 同构先例：n=128 全 1,024 通道逐块约束。
        if smt_circ.is_some() {
            let (sc, _dg, _mw, _oc, _dgs) = smt_circ.as_ref().expect("SMT 电路");
            let lp = lut_plan.as_ref().expect("LUT PLAN");
            let g = sc.wit_u64.len() / crate::sm3_lookup_block::NUM_W;
            let sub = crate::sm3_lookup_weave::LutPlan {
                prep_globals: lp.prep_globals.clone(),
                pconst_global: lp.pconst_global,
                // R3-3.1：SMT 组续接三体+C 组=4..4+g（C 块占组 3）。
                advice: lp.advice[4..4 + g].to_vec(),
                msg_limb_cols: Vec::new(),
                msg_sels: Vec::new(),
                dgw_shadow_cols: lp.dgw_shadow_cols,
                dgw_sels: lp.dgw_sels,
            };
            crate::sm3_lookup_weave::weave_proto_gates(&mut bld, sc, &sub);
        }
    }
    let asm = finish_verify_assembly(bld, led, pl);
    (asm, hooks)
}

// ══════════════════ 测试（簇J E4） ══════════════════

// ══════════════════ 见证构造（模块级，ZANCHOR=2 e2e probe 复用） ══════════════════
// 2026-08-31 自 tests mod 纯剪切升格常驻：函数体逐字节不动（零数学改动、
// 零第二份 sign 实现）；sm2_sign_host doc 的「仅测试用」语义同步修正。
/// E7 见证侧 host mod-n 数学（仅测试用；非电路语义——电路侧标量世界
/// 由簇B 七件套约束承担）。全部机械实现，无手抄常量（n 取自
/// [`crate::sm2_params`]；mod-n 乘/逆 sm2_params 无现成导出，测试侧自足）。
pub mod sm2_sign_host {
    use super::*;

    /// 固定测试签发者私钥（非零、1+d≢0 mod n；值任意但固定 ⟹ 见证可复现；
    /// a2 向量 P_A 私钥未知不可签名，故自生成钥对）。
    pub fn test_issuer_key() -> [u64; 4] {
        [0x1234_5678, 0, 0, 0x9ABC_DEF0]
    }

    /// LE limbs → 256 位 LSB-first 位序列（limbs_to_bits_le 私有，测试侧副本）。
    pub(crate) fn bits_le(v: &[u64; 4]) -> [bool; 256] {
        let mut b = [false; 256];
        for (i, bit) in b.iter_mut().enumerate() {
            *bit = (v[i / 64] >> (i % 64)) & 1 == 1;
        }
        b
    }

    /// pk = [d]G（宿主真标量乘，与电路 EC 门族同源底层）。
    pub fn pk_from_sk(d: &[u64; 4]) -> (FpSM2, FpSM2) {
        crate::sm2_ec_plonkish::affine_mul_bits(
            &bits_le(d),
            Some(crate::sm2_ec_plonkish::g_coords()),
        )
        .expect("[d]G 标量乘成功")
    }

    /// a − b 的环绕减（borrow 丢弃）——sub256_wrap 私有，测试侧副本。
    fn sub_wrap(a: &[u64; 4], bb: &[u64; 4]) -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = a[i].overflowing_sub(bb[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            out[i] = d2;
            borrow = u64::from(b1) | u64::from(b2);
        }
        out
    }

    /// (a − b) mod n，前置 a,b < n；负差走 wrap+n 路径：a−b+2²⁵⁶ ∈
    /// (2²⁵⁶−n, 2²⁵⁶) ⟹ 其 wrap 和 +n = a−b+n ∈ (0, n) ✓（carry 恒 1 丢弃）。
    pub(crate) fn sub_mod_n(a: &[u64; 4], bb: &[u64; 4]) -> [u64; 4] {
        let n = crate::sm2_params::n_limbs();
        if crate::sm2_params::cmp256(a, bb) != std::cmp::Ordering::Less {
            sub_wrap(a, bb)
        } else {
            crate::sm2_params::add256(&sub_wrap(a, bb), &n).0
        }
    }

    /// 512 位 schoolbook 乘（LE limbs；进位经 while 链上灌）。
    fn mul_wide(a: &[u64; 4], bb: &[u64; 4]) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = u128::from(a[i]) * u128::from(bb[j])
                    + u128::from(out[i + j])
                    + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            let mut k = i + 4;
            while carry > 0 {
                let t = u128::from(out[k]) + carry;
                out[k] = t as u64;
                carry = t >> 64;
                k += 1;
            }
        }
        out
    }

    /// 512 位二进制约减 mod n（MSB-first：r = (2r+bit)，≥n 则减；
    /// 溢出位=1 ⟹ 真值 ≥ 2²⁵⁶ > n 必减，wrap 减恰确——真值−n < 2²⁵⁶）。
    fn reduce_wide(x: &[u64; 8]) -> [u64; 4] {
        let n = crate::sm2_params::n_limbs();
        let mut r = [0u64; 4];
        for w in (0..8).rev() {
            for i in (0..64).rev() {
                let mut carry = (x[w] >> i) & 1;
                let mut r2 = [0u64; 4];
                for j in 0..4 {
                    let (v1, c1) = r[j].overflowing_mul(2);
                    let (v2, c2) = v1.overflowing_add(carry);
                    r2[j] = v2;
                    carry = u64::from(c1) | u64::from(c2);
                }
                if carry == 1
                    || crate::sm2_params::cmp256(&r2, &n) != std::cmp::Ordering::Less
                {
                    r2 = sub_wrap(&r2, &n);
                }
                r = r2;
            }
        }
        r
    }

    /// (a·b) mod n。
    pub fn mul_mod_n(a: &[u64; 4], bb: &[u64; 4]) -> [u64; 4] {
        reduce_wide(&mul_wide(a, bb))
    }

    /// a^(n−2) mod n（Fermat 小定理求逆，n 素数；square-and-multiply，
    /// 首位特例 acc=a 防 mul_mod_n(1, a) 冗余路径）。
    pub fn inv_mod_n(a: &[u64; 4]) -> [u64; 4] {
        let n = crate::sm2_params::n_limbs();
        let e = sub_wrap(&sub_wrap(&n, &[1, 0, 0, 0]), &[1, 0, 0, 0]); // n−2
        let mut acc = [1u64, 0, 0, 0];
        let mut started = false;
        for w in (0..4).rev() {
            for i in (0..64).rev() {
                if started {
                    acc = mul_mod_n(&acc, &acc);
                }
                if (e[w] >> i) & 1 == 1 {
                    acc = if started { mul_mod_n(&acc, a) } else { *a };
                    started = true;
                }
            }
        }
        acc
    }

    /// nonce 步进（+1；重试次数 ≪ n，不触顶）。
    fn bump(mut k: [u64; 4]) -> [u64; 4] {
        for v in k.iter_mut() {
            let (nv, ov) = v.overflowing_add(1);
            *v = nv;
            if !ov {
                break;
            }
        }
        k
    }

    /// SM2 签名（GB/T 32918.2 §6.1；确定性测试 nonce 起点逐次 +1 重试）：
    /// r=(e+x₁) mod n（x₁=[k]G.x），s=(k−r·d)(1+d)^{-1} mod n；
    /// 拒 r=0 / r+k≡n / t=r+s≡0（电路 neq_zero(t) 对应）/ s=0。
    /// 数学恒等式：s(1+d) ≡ k−rd 且 t ≡ r+s ⟹ s+t·d ≡ k (mod n)
    /// ⟹ [s]G+[t]P_A = [k]G ⟹ 验证方程闭合（verify_replay 可证）。
    pub fn sign(e: &[u64; 4], d: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
        sign_with_nonce(e, d, [0x0F0F_u64, 0, 0, 0x5EED])
    }

    /// nonce 可控变体（T1.3b 泄漏审计专用入口，2026-09-02）：数学同
    /// [`sign`]，k 起点参数化；`sign` 即 k0=原确定性起点的特例（默认
    /// 路径字节同）。审计 bin 用两个不同 k0 对同一 (e,d) 签两会话。
    pub fn sign_with_nonce(e: &[u64; 4], d: &[u64; 4], k0: [u64; 4]) -> ([u64; 4], [u64; 4]) {
        let n = crate::sm2_params::n_limbs();
        // T6 边界族（2026-09-11）：d 定义域前置校验（GB/T 32918.2 Keygen 域 [1,n−2]）。
        // d=0/d=n−1 使 (1+d)^{-1} 不存在 ⟹ s≡0 对一切 k 恒成立 ⟹ 下方重采样循环
        // 非终止（机器实锤：d=n−1 trace 40,000+ 迭代 100% s=0，T6-defect-1）——
        // fail-fast 优于挂死；合法域（含全部既有测试/测量路径）行为零变化。
        {
            let mut n_m1 = n;
            n_m1[0] = n_m1[0].wrapping_sub(1); // n−1
            assert!(
                *d != [0u64; 4] && *d != n_m1,
                "SM2 私钥须 ∈ [1, n−2]（GB/T 32918.2 Keygen 定义域）：d=0 或 d=n−1 使 (1+d)^-1 不存在"
            );
        }
        let one = [1u64, 0, 0, 0];
        let zero = [0u64; 4];
        let mut k = k0;
        loop {
            let (x1, _y1) = pk_from_sk(&k); // [k]G 复用同一标量乘
            let x1l = crate::sm2_params::fr_to_limbs(&x1);
            let r = crate::sm2_verify_assemble::add_mod_n_limbs(e, &x1l);
            let rk = crate::sm2_verify_assemble::add_mod_n_limbs(&r, &k);
            let num = sub_mod_n(&k, &mul_mod_n(&r, d));
            let den = crate::sm2_verify_assemble::add_mod_n_limbs(&one, d);
            let s = mul_mod_n(&num, &inv_mod_n(&den));
            let t = crate::sm2_verify_assemble::add_mod_n_limbs(&r, &s);
            if r == zero || rk == n || s == zero || t == zero {
                k = bump(k);
                continue;
            }
            return (r, s);
        }
    }
}

/// E12 双正例参数化构造（test_witness 抽取，语义全真源）：attrs 恒 =
/// PRED_TARGET（谓词先定、持有者属性匹配=诚实流程；下游 B₂/digest/e/
/// 签名全派生故一致。E12 第二见证保持 attrs=PRED_TARGET 差 id_u/sk_u/r
/// ——凭证语义正确）。
pub fn witness_from(sk_u: [u64; 4], id_u: [u8; 32], r: [u64; 4]) -> FullStatementWitness {
    witness_from_with_exp(sk_u, id_u, r, DEFAULT_EXP_U)
}

/// 同 [`witness_from`]，有效期 exp_u 可指定（T2.6 (S6) 红测②：过期凭证）。
// ═════════ B-batch2 · t1 承诺档(2026-09-15):TLS 配置 + 承诺 host/witness ═════════

/// 承诺档配置(线程局部——并行测试安全;默认 None = 冻结路径零触碰)。
#[derive(Clone)]
pub struct PredCommitCfg {
    pub salt: [u8; 16],
    /// B-batch3 数值档：θ 阈值（attrs_true[0..4] BE u32 ≥ theta）。
    pub theta: Option<u32>,
    /// B-batch3 schema 段（attrs_true[4..32]，28B 公开常量——等值钉目标）。
    pub schema_seg: Option<[u8; 28]>,
    /// B-batch3 schema_id 声明词（公开实例 23——pred_id↦schema 绑定声明面）。
    pub schema_id_word: Option<u32>,
    /// 飞证 AUTH 档（B3，2026-09-20）：C 原像 54B 布局
    /// salt16‖cert BE4‖id18‖sn_h16（词 4=cert——范围门读数源零接线；
    /// schema 钉弃用：id_number 见证必须隐藏）。None=pred 档 48B 布局。
    pub auth: Option<AuthCPreimage>,
}

/// AUTH 承诺原像字段（salt 经 PredCommitCfg 共享通道）。
#[derive(Clone)]
pub struct AuthCPreimage {
    pub cert_be: [u8; 4],
    /// B4（A4/队友六问四-1）：机型类——进 C 原像（词 5 MSB）+电路 8 位等值钉
    /// （class==公开 class_id 实例 24——自报机型套高上限攻击的电路封堵）。
    pub class_id: u8,
    pub id_number: [u8; 18],
    pub sn_h: [u8; 16],
    /// B3b：撤销累加器非成员见证——32 兄弟子树根（叶→根序）+树根。
    pub smt_siblings: Option<[[u8; 32]; 32]>,
    pub smt_root: Option<[u8; 32]>,
}

std::thread_local! {
    static PRED_COMMIT: std::cell::RefCell<Option<PredCommitCfg>> =
        const { std::cell::RefCell::new(None) };
}

/// 装配函数内读档(承诺分支判定)。
pub(crate) fn pred_commit_salt() -> Option<[u8; 16]> {
    PRED_COMMIT.with(|c| c.borrow().as_ref().map(|cfg| cfg.salt))
}

/// C = SM3(salt‖attrs_true) 的 8 个 BE 词(宿主权威,禁手抄)。
pub fn commit_c_words(salt: &[u8; 16], attrs: &[u8; 32]) -> [u32; 8] {
    let mut m = Vec::with_capacity(48);
    m.extend_from_slice(salt);
    m.extend_from_slice(attrs);
    let d = crate::sm3_native_ref::hash(&m);
    std::array::from_fn(|k| {
        u32::from_be_bytes([d[4 * k], d[4 * k + 1], d[4 * k + 2], d[4 * k + 3]])
    })
}

/// AUTH 原像 54B 追加段（cert_be4‖id18‖sn_h16——salt 之后）。
fn m64_extend_auth(out: &mut Vec<u8>, ap: &AuthCPreimage) {
    // B4 布局 v3：cert4‖class1‖id18‖sn_h16=39B（class 居字节 20=词 5 MSB）
    out.extend_from_slice(&ap.cert_be);
    out.push(ap.class_id);
    out.extend_from_slice(&ap.id_number);
    out.extend_from_slice(&ap.sn_h);
}

/// R3-3.1（2026-09-24）：承诺 C 单块 64B 填充块（auth=55B 原像/pred=48B 原像
/// 的 SM3 填充）——PLAN 相 c_circ 见证与 EMIT 相根格见证同源单一事实源
/// （auth：pad=0x80@55、be64(440)@56；pred：pad=0x80@48、be64(384)@56）。
fn commit_block64(salt: &[u8; 16], auth: Option<&AuthCPreimage>, attrs_u: &[u8; 32]) -> [u8; 64] {
    let mut b = [0u8; 64];
    match auth {
        Some(ap) => {
            let mut m55 = Vec::with_capacity(55);
            m55.extend_from_slice(salt);
            m64_extend_auth(&mut m55, ap);
            b[..55].copy_from_slice(&m55);
            b[55] = 0x80;
            b[56..].copy_from_slice(&440u64.to_be_bytes());
        }
        None => {
            b[..16].copy_from_slice(salt);
            b[16..48].copy_from_slice(attrs_u);
            b[48] = 0x80;
            b[56..].copy_from_slice(&384u64.to_be_bytes());
        }
    }
    b
}

/// AUTH 承诺词（B4 v3）：C = SM3(salt16‖cert_be4‖class1‖id18‖sn_h16)=55B 单块
/// （55+1pad+8len=64 恰满块）。布局=飞证 backend credential.py commitment_c
/// （B3-d8/B4-d1 联动换代，黄金向量钉定）。
pub fn commit_c_words_auth(salt: &[u8; 16], ap: &AuthCPreimage) -> [u32; 8] {
    let mut m = Vec::with_capacity(55);
    m.extend_from_slice(salt);
    m64_extend_auth(&mut m, ap);
    let d = crate::sm3_native_ref::hash(&m);
    std::array::from_fn(|k| {
        u32::from_be_bytes([d[4 * k], d[4 * k + 1], d[4 * k + 2], d[4 * k + 3]])
    })
}

/// 承诺版 host:M 的 B₂ 槽位 attrs(32B)→C(32B 等长;B₁/B₃ 与原版逐字同)。
pub fn full_statement_host_commit(
    pk_i: &(FpSM2, FpSM2),
    idgx_be: &[u8; 32],
    idg_par: u8,
    attrs_true: &[u8; 32],
    pk_u: &(FpSM2, FpSM2),
    exp_u: u32,
    salt: &[u8; 16],
) -> FullStatementHost {
    let mut host = full_statement_host_with_idgx(
        pk_i, idgx_be, idg_par, attrs_true, pk_u, exp_u,
    );
    let cw = commit_c_words(salt, attrs_true);
    for j in 0..8usize {
        host.blocks[1][4 * j..4 * j + 4].copy_from_slice(&cw[j].to_be_bytes());
    }
    host
}

/// 承诺版 host(从 witness 直构——idgx/par 与原版 full_statement_host 同法)。
pub fn full_statement_host_commit_of(w: &FullStatementWitness, salt: &[u8; 16]) -> FullStatementHost {
    let id_bits: [bool; 256] =
        std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
    match crate::sm2_ec_plonkish::affine_mul_bits(&id_bits, Some(crate::sm2_ec_plonkish::g_coords())) {
        Some((x, y)) => {
            let idg_x_be = crate::sm2_z_anchor::fe_be32(&x);
            let idg_par = 0x02u8 | (crate::sm2_z_anchor::fe_be32(&y)[31] & 1);
            full_statement_host_commit(&w.pk_i, &idg_x_be, idg_par, &w.attrs_u, &w.pk_u, w.exp_u, salt)
        }
        None => full_statement_host_commit(&w.pk_i, &[0u8; 32], 0x02, &w.attrs_u, &w.pk_u, w.exp_u, salt),
    }
}

/// AUTH 档 host（B3）：C=SM3(salt‖cert‖id‖sn_h)=54B 单块，B₂ 槽=C 词
/// （attrs_u 语义=C 值——与 witness_from_auth 的 attrs_u=C 同构）。
pub fn full_statement_host_auth_of(
    w: &FullStatementWitness,
    salt: &[u8; 16],
    ap: &AuthCPreimage,
) -> FullStatementHost {
    let id_bits: [bool; 256] =
        std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
    let (x, y) = crate::sm2_ec_plonkish::affine_mul_bits(&id_bits, Some(crate::sm2_ec_plonkish::g_coords()))
        .expect("id′·G 有限点");
    let idg_x_be = crate::sm2_z_anchor::fe_be32(&x);
    let idg_par = 0x02u8 | (crate::sm2_z_anchor::fe_be32(&y)[31] & 1);
    let mut host = full_statement_host_with_idgx(
        &w.pk_i, &idg_x_be, idg_par, &w.attrs_u, &w.pk_u, w.exp_u,
    );
    // attrs_u 已是 C 值（witness_from_auth 置入）——host 权威重算并断言一致
    //（防见证 attrs_u 与 54B 原像脱钩）。
    let cw = commit_c_words_auth(salt, ap);
    for j in 0..8usize {
        let wv_be = cw[j].to_be_bytes();
        let expect = [
            w.attrs_u[4 * j], w.attrs_u[4 * j + 1], w.attrs_u[4 * j + 2], w.attrs_u[4 * j + 3],
        ];
        assert_eq!(wv_be, expect, "attrs_u≠SM3(54B 原像)——见证承诺与原像脱钩");
        host.blocks[1][4 * j..4 * j + 4].copy_from_slice(&wv_be);
    }
    host
}

/// 承诺档 witness 构造(签名对 M′ 的 e′;attrs_u=真属性——E5 位格/谓词/(S7)
/// 消息共用)。与 witness_from_with_exp 同链,唯 host 换承诺版。
pub fn witness_from_pred_commit(
    sk_u: [u64; 4],
    id_u: [u8; 32],
    r: [u64; 4],
    exp_u: u32,
    salt: [u8; 16],
) -> FullStatementWitness {
    witness_from_pred_commit_with_attrs(sk_u, id_u, r, exp_u, salt, PRED_TARGET)
}

/// B-batch3 变体：attrs_u 参数化（数值档布局 [num BE 4B][schema 28B]）——
/// 签名链对新 M′ 闭合（单点实现，无第二份 sign——纪律同原函数）。
pub fn witness_from_pred_commit_with_attrs(
    sk_u: [u64; 4],
    id_u: [u8; 32],
    r: [u64; 4],
    exp_u: u32,
    salt: [u8; 16],
    attrs_u: [u8; 32],
) -> FullStatementWitness {
    use ff::Field;
    let d_i = sm2_sign_host::test_issuer_key();
    let pk_i = sm2_sign_host::pk_from_sk(&d_i);
    let mut w = FullStatementWitness {
        sk_u,
        pk_u: (FpSM2::ZERO, FpSM2::ZERO),
        id_u,
        attrs_u,
        exp_u,
        r,
        r_s: [0; 4],
        s_s: [0; 4],
        pk_i,
        apk: (FpSM2::ZERO, FpSM2::ZERO),
    };
    let mut bits = [false; 256];
    for ww in 0..4usize {
        for i in 0..64usize {
            bits[64 * ww + i] = (w.sk_u[ww] >> i) & 1 == 1;
        }
    }
    w.pk_u = crate::sm2_ec_plonkish::affine_mul_bits(
        &bits,
        Some(crate::sm2_ec_plonkish::g_coords()),
    )
    .expect("真标量乘成功");
    w.apk = crate::sm2_ec_plonkish::affine_add(Some(w.pk_u), Some(pk_i))
        .expect("apk 点加成功");
    let host = full_statement_host_commit_of(&w, &salt);
    let c = crate::sm3_native_ref::compress;
    let v1 = c(&crate::sm3_native_ref::IV, &host.blocks[0]);
    let v2 = c(&v1, &host.blocks[1]);
    let dg = c(&v2, &host.blocks[2]);
    let e_fp = fold_digest_fp(&dg);
    let (r_s, s_s) = sm2_sign_host::sign(&crate::sm2_params::fr_to_limbs(&e_fp), &d_i);
    w.r_s = r_s;
    w.s_s = s_s;
    assert!(
        crate::sm2_verify_assemble::verify_replay(
            e_fp,
            crate::sm2_params::fr_from_limbs(&w.r_s),
            crate::sm2_params::fr_from_limbs(&w.s_s),
            w.pk_i.0,
            w.pk_i.1,
        )
        .ok,
        "承诺 witness 自检:宿主签名未通过 verify_replay"
    );
    w
}

/// 承诺入口:TLS 装载 → 装配 → 清卸(防泄漏到默认路径)。
pub fn assemble_full_statement_pred_commit(
    w: &FullStatementWitness,
    salt: [u8; 16],
    ctx_tag: FpSM2,
    pred_id: FpSM2,
    t_epoch: u32,
) -> (crate::sm2_verify_assemble::Assembled, FullStatementHooks) {
    PRED_COMMIT.with(|c| {
        *c.borrow_mut() = Some(PredCommitCfg {
            salt,
            theta: None,
            schema_seg: None,
            schema_id_word: None,
            auth: None,
        })
    });
    let r = assemble_full_statement_with_hooks_bound(w, ctx_tag, pred_id, t_epoch);
    PRED_COMMIT.with(|c| *c.borrow_mut() = None);
    r
}

/// B-batch3 数值谓词档入口：承诺档 + θ 范围门 + schema 段等值钉 + 双实例钉。
/// 布局契约：attrs_true = [num_field BE u32][schema 段 28B]，num_field ≥ theta
/// 为诚实见证前置（违约构造走负例测试）。
pub fn assemble_full_statement_pred_range(
    w: &FullStatementWitness,
    salt: [u8; 16],
    theta: u32,
    schema_seg: [u8; 28],
    schema_id_word: u32,
    ctx_tag: FpSM2,
    pred_id: FpSM2,
    t_epoch: u32,
) -> (crate::sm2_verify_assemble::Assembled, FullStatementHooks) {
    PRED_COMMIT.with(|c| {
        *c.borrow_mut() = Some(PredCommitCfg {
            salt,
            theta: Some(theta),
            schema_seg: Some(schema_seg),
            schema_id_word: Some(schema_id_word),
            auth: None,
        })
    });
    let r = assemble_full_statement_with_hooks_bound(w, ctx_tag, pred_id, t_epoch);
    PRED_COMMIT.with(|c| *c.borrow_mut() = None);
    r
}

/// 飞证 AUTH 档入口（B3）：54B C 原像布局 + required_level 范围门（theta 槽）
/// + t_epoch 有效期（S6）+ ctx_tag/pred_id 双绑定钉（三绑定要素复合哈希——
/// B3-d8 分账：plan_hash/nonce/policy_version 由服务层折算进二钉）。
pub fn assemble_full_statement_auth(
    w: &FullStatementWitness,
    salt: [u8; 16],
    auth_preimage: AuthCPreimage,
    required_level: u32,
    ctx_tag: FpSM2,
    pred_id: FpSM2,
    t_epoch: u32,
) -> (crate::sm2_verify_assemble::Assembled, FullStatementHooks) {
    PRED_COMMIT.with(|c| {
        *c.borrow_mut() = Some(PredCommitCfg {
            salt,
            theta: Some(required_level),
            schema_seg: None,
            schema_id_word: None,
            auth: Some(auth_preimage),
        })
    });
    let r = assemble_full_statement_with_hooks_bound(w, ctx_tag, pred_id, t_epoch);
    PRED_COMMIT.with(|c| *c.borrow_mut() = None);
    r
}

pub fn witness_from_with_exp(
    sk_u: [u64; 4],
    id_u: [u8; 32],
    r: [u64; 4],
    exp_u: u32,
) -> FullStatementWitness {
    use ff::Field;
    let d_i = sm2_sign_host::test_issuer_key();
    let pk_i = sm2_sign_host::pk_from_sk(&d_i);
    let mut w = FullStatementWitness {
        sk_u,
        pk_u: (FpSM2::ZERO, FpSM2::ZERO),
        id_u,
        attrs_u: PRED_TARGET,
        exp_u,
        r,
        r_s: [0; 4],
        s_s: [0; 4],
        pk_i,
        apk: (FpSM2::ZERO, FpSM2::ZERO),
    };
    let mut bits = [false; 256];
    for ww in 0..4usize {
        for i in 0..64usize {
            bits[64 * ww + i] = (w.sk_u[ww] >> i) & 1 == 1;
        }
    }
    w.pk_u = crate::sm2_ec_plonkish::affine_mul_bits(
        &bits,
        Some(crate::sm2_ec_plonkish::g_coords()),
    )
    .expect("真标量乘成功");
    w.apk = crate::sm2_ec_plonkish::affine_add(Some(w.pk_u), Some(pk_i))
        .expect("apk = pk_u + pk_i 点加成功");
    // r_s/s_s：对 (S1) 派生 e 的真签名。e 宿主值 = fold(三块 native 摘要)，
    // 与电路 ⑧′ 约束同式同系数（fold_digest_fp 权威）。
    let host = full_statement_host(&w);
    let c = crate::sm3_native_ref::compress;
    let v1 = c(&crate::sm3_native_ref::IV, &host.blocks[0]);
    let v2 = c(&v1, &host.blocks[1]);
    let dg = c(&v2, &host.blocks[2]);
    let e_fp = fold_digest_fp(&dg);
    let (r_s, s_s) =
        sm2_sign_host::sign(&crate::sm2_params::fr_to_limbs(&e_fp), &d_i);
    w.r_s = r_s;
    w.s_s = s_s;
    // 自检：真签名必须通过 native 四步重放（装配期 verify_replay 断言
    // 的先行独立复证——sign 数学若有 bug，此处即爆而非跑到 mock 才炸）。
    assert!(
        crate::sm2_verify_assemble::verify_replay(
            e_fp,
            crate::sm2_params::fr_from_limbs(&w.r_s),
            crate::sm2_params::fr_from_limbs(&w.s_s),
            w.pk_i.0,
            w.pk_i.1,
        )
        .ok,
        "test_witness 自检：宿主签名未通过 verify_replay（sign 数学缺陷）"
    );
    w
}

#[cfg(test)]
fn ctag_is_lut(tag: &str) -> bool {
    tag.starts_with("lut.")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试见证（E7 起全真源）：pk_u = [sk_u]G（(S4) 见证侧即真）；签发者
    /// 钥对自生成（d_i 固定测试值 ⟹ pk_i=[d_i]G；a2 私钥未知不可签名）；
    /// r_s/s_s = 对派生 e 的真 SM2 签名（e = fold(三块 native 摘要)，与电路
    /// 大折叠同式）；apk = pk_u + pk_i（语义聚合，E10 实装前不进电路）。
    fn test_witness() -> FullStatementWitness {
        let mut id32 = [0u8; 32];
        id32[..16].copy_from_slice(crate::sm2_z_anchor::DEFAULT_ID);
        witness_from([0x0B0B, 0, 0, 0x0A0A], id32, [0x11, 0, 0, 0x22])
    }

    /// H 红线测试（禁手抄 ⟹ 纯函数 + 对拍锁定，zu_words_bits_crosscheck 同款）：
    /// `be_word_bit_terms` 位映射从任意字节串重组 8 个 BE 词，逐词对拍。
    #[test]
    fn be_word_bit_terms_crosscheck() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x3C);
        // 256 位整数（BE 解释）的 LSB 序位 i = 字节 31−i/8 的位 i%8
        let bit = |i: usize| ((bytes[31 - i / 8] >> (i % 8)) & 1) == 1;
        for j in 0..8usize {
            let want = u32::from_be_bytes(bytes[4 * j..4 * j + 4].try_into().unwrap());
            let mut got = 0u32;
            for (ib, sh) in be_word_bit_terms(j) {
                if bit(ib) {
                    got |= 1u32 << sh;
                }
            }
            assert_eq!(got, want, "词 {j} 位映射对拍失败");
        }
    }

    /// A1″（压缩点编码绑定）红→绿负例：Id↦n−Id 变体出示必拒。
    /// 攻击机理（盲审 B-01 反例）：x(−P)=x(P) 恒等 ⟹ 仅绑 x 时 M(Id′)=M(Id)
    /// 逐字节相同 ⟹ e′=e ⟹ 原 σ_I 在 (S2) 下仍有效 ⟹ 出示被接受而审计解密
    /// 得 −P∉注册表（G₁a bad₁ 逃逸，无需 DLP）。压缩编码（消息尾部奇偶字节
    /// =0x02+(y mod 2)）使 M′≠M ⟹ e′ 为新鲜摘要 ⟹ (S2) 验签失败。
    /// 断言三层：①恒等面——两见证的 b1（Z_A‖x）逐字节相同（歧义确实存在）；
    /// ②绑定面——b3 奇偶字节随 ±y 翻转 ⟹ M′≠M；③摘要面——native 三块手链
    /// 独立终判 e′≠e。
    #[test]
    fn a1x_negated_id_message_diverges() {
        // n − id（256 位 BE 字节算术；id∈[1,n) ⟹ 差 ∈[1,n)）
        fn id_neg(id: &[u8; 32]) -> [u8; 32] {
            let n = crate::sm2_params::n_limbs();
            let mut limbs = [0u64; 4];
            for k in 0..4 {
                limbs[k] = u64::from_be_bytes(id[24 - 8 * k..32 - 8 * k].try_into().unwrap());
            }
            let mut out = [0u64; 4];
            let mut borrow = 0u64;
            for k in 0..4 {
                let (d1, b1) = n[k].overflowing_sub(limbs[k]);
                let (d2, b2) = d1.overflowing_sub(borrow);
                out[k] = d2;
                borrow |= (b1 as u64) | (b2 as u64);
            }
            assert_eq!(borrow, 0, "id ≤ n 前提破坏");
            let mut o = [0u8; 32];
            for k in 0..4 {
                o[24 - 8 * k..32 - 8 * k].copy_from_slice(&out[k].to_be_bytes());
            }
            o
        }
        let w = test_witness();
        let host_p = full_statement_host(&w);
        let id2 = id_neg(&w.id_u);
        assert_ne!(id2, w.id_u, "n 为奇数 ⟹ id ≠ n−id（素数阶群无 2-挠）");
        let w2 = witness_from(w.sk_u, id2, w.r);
        let host_n = full_statement_host(&w2);
        assert_eq!(
            host_p.blocks[0], host_n.blocks[0],
            "恒等面：x(−P)=x(P) ⟹ b1（Z_A‖x）逐字节相同——被绑定的歧义本身"
        );
        assert_ne!(
            host_p.blocks[2], host_n.blocks[2],
            "绑定面：b3 尾部奇偶字节必须随 ±y 翻转 ⟹ M′≠M"
        );
        let chain = |h: &FullStatementHost| -> [u32; 8] {
            let c = crate::sm3_native_ref::compress;
            let iv = crate::sm3_native_ref::IV;
            c(&c(&c(&iv, &h.blocks[0]), &h.blocks[1]), &h.blocks[2])
        };
        assert_ne!(
            chain(&host_p),
            chain(&host_n),
            "摘要面：e′≠e（native 独立路径）⟹ 原 σ_I 在 (S2) 下失配"
        );
    }

    /// 簇J E4 验收（J-10b ③）：一次装配全三体 + 验签体。摘要/链态终判 =
    /// native 三块手链（独立路径）；实例面 19；旋转守卫 ≤ K；环账本唯一 +
    /// 环值审计零；mock 全扫零违约；形状首跑记账（数字冻结进蓝图 J-10b 后
    /// 再升格断言——计划 Task 4 Step 4）。
    #[test]
    fn full_statement_three_bodies_assemble() {
        let w = test_witness();
        let (asm, h) = assemble_full_statement_with_hooks(&w);
        let host = full_statement_host(&w);

        // ① 实例面：19 = 12 验签体 + 7 全语句新增（12..17 = E10 六钉；
        //    18 = E11 pred_out，值断言在 s5 测试①）。
        assert_eq!(asm.instances[0].len(), 22, "实例面 = 12 + 7 + 2（T2.5）+ 1（T2.6）");
        assert_ne!(
            h.attrs_bit0,
            (0usize, 0usize),
            "E5 后 attrs_bit0 钩子必须已填充（E11 湮灭门/负例锚依赖）"
        );

        // ② 摘要/链态终判（GB/T 级）：钩子透传值 == native 手链（独立路径
        //    ——sm3_native_ref::compress 直调，与装配器宿主数学分账）。
        let c = crate::sm3_native_ref::compress;
        let iv = crate::sm3_native_ref::IV;
        let v1 = c(&iv, &host.blocks[0]);
        let v2 = c(&v1, &host.blocks[1]);
        let dg = c(&v2, &host.blocks[2]);
        assert_eq!(h.chain_states[0], v1, "链态 V₁ ≠ native");
        assert_eq!(h.chain_states[1], v2, "链态 V₂ ≠ native");
        for k in 0..8usize {
            assert_eq!(h.digest[k], dg[k], "摘要字 {k} ≠ native");
        }

        // ①′ E7 终判：实例 0（e）== 摘要大折叠宿主值（(S1)↔(S2) 绑定的公开面
        //    证据；电路侧约束 = ⑧′，通道 = echo 环 + rid_pv 环 + pin.bind——
        //    三道防线对此全盲，由 #26 守卫（激活点审计）与 ⑤′ 篡改预演兜底）。
        assert_eq!(
            crate::sm2_params::fr_to_limbs(&asm.instances[0][0]),
            crate::sm2_params::fr_to_limbs(&fold_digest_fp(&h.digest)),
            "实例 0 ≠ fold(摘要)——e 绑定断裂"
        );
        // ①″ 见证自洽：签名 (r_s,s_s) 对 e 真源有效（装配期 verify_replay
        //    断言随行；此处再证实例值与见证签名同链——mock 可满足的正例语义）。
        let rp_ok = crate::sm2_verify_assemble::verify_replay(
            asm.instances[0][0],
            asm.instances[0][1],
            asm.instances[0][2],
            w.pk_i.0,
            w.pk_i.1,
        );
        assert!(rp_ok.ok, "实例面 (e,r,s) 未通过 native 四步重放");

        // ②′ R10 红线：B₃ pad 结构独立对拍——机械派生值（host 字节切片）vs
        //    规格语义（T2.6+A1″ 165B 语句：b3[32..36]=exp_u、b3[36]=奇偶字节
        //    0x02/0x03、0x80@b3[37] + 零填充 + be64(1320)）；禁沿用 merged 的
        //    1680。测试断言值=规格语义，非电路常量烘焙。
        let igy_be = {
            let id_bits: [bool; 256] =
                std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
            match crate::sm2_ec_plonkish::affine_mul_bits(
                &id_bits,
                Some(crate::sm2_ec_plonkish::g_coords()),
            ) {
                Some((_, y)) => crate::sm2_z_anchor::fe_be32(&y),
                None => [0u8; 32],
            }
        };
        let want_par = 0x02u8 | (igy_be[31] & 1);
        assert_eq!(
            host.pad_words[0],
            u32::from(w.exp_u),
            "pad 词 0 必须 = exp_u BE 词（(S1)↔(S6) 双绑通道消息面）"
        );
        assert_eq!(
            host.pad_words[1],
            (u32::from(want_par) << 24) | 0x0080_0000,
            "pad 词 1 必须 = 奇偶字节‖0x80‖零填充（A1″ 压缩绑定面）"
        );
        assert!(host.pad_words[2..6].iter().all(|&x| x == 0), "pad 词 2..5 必须全零");
        assert_eq!(
            host.pad_words[7], 1320,
            "长度字必须 = be64(1320) 低 32 位（禁沿用 merged 的 1680）"
        );

        // ③ 旋转预算守卫（S1 不变量）：全语句 max|rot| ≤ K。
        let maxd = asm
            .info
            .constraints
            .iter()
            .map(|cc| cc.max_used_rotation_distance())
            .max()
            .unwrap_or(0);
        assert!(
            maxd <= crate::sm3_compress::K,
            "旋转距离 {maxd} 超出后端预算 num_vars={}",
            crate::sm3_compress::K
        );

        // ④ 环账本：环全部 ≥2；格全局唯一（验签体 534 + 三体 636 + 通道）。
        let mut seen = std::collections::BTreeSet::new();
        for cyc in &asm.info.permutations {
            assert!(cyc.len() >= 2);
            for cell in cyc {
                assert!(seen.insert(*cell), "格 {cell:?} 出现在多个环位");
            }
        }
        // ⑤ 环值审计（mock 盲区前置桥）+ 位级 mock 全扫零违约。
        let bad_rings = crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        assert!(bad_rings.is_empty(), "环取值不一致: {bad_rings:?}");
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        if !bad.is_empty() {
            use std::collections::BTreeMap;
            let hist: BTreeMap<&str, usize> = bad
                .iter()
                .fold(BTreeMap::new(), |mut m, v| {
                    *m.entry(asm.ctags[v.constraint]).or_insert(0) += 1;
                    m
                });
            panic!("T1 正例违约 {} 处；族直方图 {hist:?}；首条 {:?}", bad.len(), bad.first());
        }

        // ⑤′ E7 篡改预演（正式负例归 E12 矩阵①）：翻 dgw0 值格 ⟹ 大折叠
        //    mock 击中 + echo 环审计击中（双信号齐爆——e 折叠若死则 mock 沉默，
        //    #26 同型缺陷的永久守卫）。
        let (dc, dr) = h.dgw0;
        let mut adv = asm.advice.clone();
        adv[dc][dr] += FpSM2::ONE;
        let bad_t = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(!bad_t.is_empty(), "dgw0 翻转未被 mock 击中（e 折叠未激活?）");
        let audit_t = crate::sm3_compress::audit_ring_values(&asm.info, &adv);
        assert!(!audit_t.is_empty(), "dgw0 翻转未被 echo 环审计捕获");

        // ⑥ 形状指纹锁定（E10 首跑 [实测]：净额 = 218,724 + 6,193 =
        //    224,917；advice 11,030 + 84（hs/hd 6 + **dga 5** + oc 3 + 循环
        //    31 + ac2 27 + c2idg/c2rpk 6 + 钉 6）；sel/prep 349 + 14；环
        //    1,944 + 12。**E11 增量 [实测 2026-08-31 二跑]**：约束 +258 =
        //    256 湮灭 + 1 线性 + 1 pin.bind（勘误 #28 修复后）；advice +1 =
        //    pred_cell 列（钉值格复用同列）；sel/prep +2 = pred_sel +
        //    pred_pin_sel；环 +1 = rid_pred_pin。任何漂移即结构性事故，当场
        //    爆掉。）
        println!(
            "[t1-tally] constraints={} advice={} sel={} prep={} cycles={} max|rot|={maxd}",
            asm.info.constraints.len(),
            asm.advice.len(),
            asm.num_selectors,
            asm.info.preprocess_polys.len(),
            asm.info.permutations.len()
        );
        assert_eq!(asm.info.constraints.len(), 201_183, "T1 约束总数漂移（2026-10-01 实测钉：A1″ 旧钉 225,724 在 db0bbb3 实测已漂移至 201,443——历史批次 legacy 面拆除未回写本钉；本次换代 acc.chain 去重 −260=4 窗×65，201,443−260=201,183）");
        assert_eq!(asm.advice.len(), 11_586, "T1 advice 列数漂移（2026-10-01 实测钉：A1″ 旧钉 11,663 在 db0bbb3 实测已漂移至 11,586——历史批次列删除未回写；本批零列变动）");
        assert_eq!(asm.num_selectors, 393, "T1 选择器族数漂移（2026-10-01 实测钉：A1″ 旧钉 370 在 db0bbb3 实测已漂移至 393——历史批次选择器新增未回写；本批零选择器变动）");
        assert_eq!(asm.info.preprocess_polys.len(), 393, "T1 预处理多项式数漂移（2026-10-01 实测钉：旧钉 370 已漂移至 393——历史批次未回写；本批零变动）");
        assert_eq!(
            asm.info.permutations.len(),
            1_187,
            "T1 中继环数漂移（2026-10-01 实测钉：旧钉 1,957 在 db0bbb3 实测已漂移至 1,187——历史批次环合并未回写；本批零环变动）"
        );
    }

    /// T2.5 绑定正例：bound 入口装配 + mock 全扫零违约（honest ctx/pred_id）。
    #[test]
    fn t25_bound_positive_mock_clean() {
        let w = test_witness();
        let asm = assemble_full_statement_bound(&w, FpSM2::from(0xC7), FpSM2::from(0x2B));
        assert_eq!(asm.instances[0].len(), 22, "实例面 = 22（T2.5 钉 19..20 + T2.6 钉 21；bound 入口 t_epoch=0 平凡）");
        assert_eq!(asm.instances[0][19], FpSM2::from(0xC7), "实例 19 = ctx_tag");
        assert_eq!(asm.instances[0][20], FpSM2::from(0x2B), "实例 20 = pred_id");
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(bad.is_empty(), "绑定正例 mock 零违约；首条 {:?}", bad.first());
    }

    /// T2.5 T-b 跨上下文重放必须被捕获：篡改实例 19（ctx_tag）⟹ mock 击中。
    /// 红态（未钉）= 篡改不可见 = 重放防线缺失，本测即红。
    #[test]
    fn t25_ctx_tamper_caught() {
        let w = test_witness();
        let asm = assemble_full_statement_bound(&w, FpSM2::from(0xC7), FpSM2::from(0x2B));
        let mut inst = asm.instances.clone();
        inst[0][19] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &inst);
        assert!(
            !bad.is_empty(),
            "跨上下文重放（实例 19 篡改）未被捕获 = 绑定缺失（T2.5 红态）"
        );
    }

    /// T2.5 T-c 跨策略替换必须被捕获：篡改实例 20（pred_id）⟹ mock 击中。
    #[test]
    fn t25_pred_tamper_caught() {
        let w = test_witness();
        let asm = assemble_full_statement_bound(&w, FpSM2::from(0xC7), FpSM2::from(0x2B));
        let mut inst = asm.instances.clone();
        inst[0][20] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &inst);
        assert!(
            !bad.is_empty(),
            "跨策略替换（实例 20 篡改）未被捕获 = 绑定缺失（T2.5 红态）"
        );
    }

    // ══════════ T2.6 (S6) 有效期（TDD 红先于绿；测试本体红绿两阶段零改动） ══════════

    /// T2.6 ① 正例 + 边界：(S6) gadget 装配 + T 实例钉 + mock 零违约。
    /// 正例 exp_u=1000（DEFAULT）> T=500 ⟹ d=500 可 32 位分解；边界
    /// T == exp_u ⟹ d=0（窗口含等号，凭证当日到期仍可出示）。
    #[test]
    fn s6_expiry_gadget_and_t_instance() {
        let base = test_witness();
        let (asm, _) = assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
        assert_eq!(asm.instances[0].len(), 22, "实例面 = 22（T2.6 +T）");
        assert_eq!(asm.instances[0][21], FpSM2::from(500u64), "实例 21 = T（验证方注入）");
        let host = full_statement_host(&base);
        assert_eq!(
            host.pad_words[0],
            u32::from(base.exp_u),
            "pad 词 0 = exp_u（(S1)↔(S6) 双绑通道消息面）"
        );
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(bad.is_empty(), "(S6) 正例 mock 零违约；首条 {:?}", bad.first());
        // 边界：T == exp_u ⟹ d=0 可满足。
        let (asm_b, _) =
            assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, base.exp_u);
        let bad_b =
            crate::sm3_compress::check_parts_violations(&asm_b.info, &asm_b.advice, &asm_b.instances);
        assert!(bad_b.is_empty(), "边界 T==exp_u（d=0）必须可满足；首条 {:?}", bad_b.first());
    }

    /// T2.6 ② 核心红信号：过期凭证（exp_u=500 < T=1000）必须不可满足。
    /// 红态（分解组合缺失）⟹ 假语句可满足 = 防线缺失，本测即红。
    #[test]
    fn s6_expired_credential_rejected() {
        let base = test_witness();
        let w = witness_from_with_exp(base.sk_u, base.id_u, base.r, 500);
        let (asm, _) = assemble_full_statement_with_hooks_bound(&w, FpSM2::ZERO, FpSM2::ZERO, 1_000);
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(
            !bad.is_empty(),
            "(S6) 分解组合缺失（T2.6 RED 态）——过期凭证（exp_u<T）可满足"
        );
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "assert.zero"),
            "过期拒绝必须由 (S6) assert.zero 族承重；族直方 {:?}",
            bad.iter().map(|v| asm.ctags[v.constraint]).collect::<Vec<_>>()
        );
    }

    /// T2.6 ③ T 篡改必败：实例 21（T）篡改 ⟹ pin.bind mock 击中（T 实例钉绑，
    /// 「钉=绑定」T2.5 机制自动覆盖——验证方注入策略参数与 pred_id 同位）。
    #[test]
    fn s6_t_tamper_caught() {
        let base = test_witness();
        let (asm, _) = assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
        let mut inst = asm.instances.clone();
        inst[0][21] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &inst);
        assert!(!bad.is_empty(), "T 篡改未被捕获 = T 未钉绑（T2.6 红态）");
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "pin.bind"),
            "T 篡改须由 pin.bind 族击中；族直方 {:?}",
            bad.iter().map(|v| asm.ctags[v.constraint]).collect::<Vec<_>>()
        );
    }

    /// T2.6 ④ exp 词篡改必败：(S6) exp 格翻转 ⟹ 分解组合 mock 击中 + 消息根
    /// 环审计击中（双信号——exp 格经 msg_roots 体E 词 8 入 (S1) 哈希，
    /// (S1)↔(S6) 双绑通道直接证据）。
    #[test]
    fn s6_exp_word_tamper_caught() {
        let base = test_witness();
        let (asm, h) =
            assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
        let (ec, er) = h.s6_exp_cell;
        let mut adv = asm.advice.clone();
        adv[ec][er] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(
            !bad.is_empty(),
            "exp 词格翻转未被 mock 击中（(S6) 分解组合未激活?）"
        );
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "assert.zero"),
            "exp 翻转须由 assert.zero 族击中；族直方 {:?}",
            bad.iter().map(|v| asm.ctags[v.constraint]).collect::<Vec<_>>()
        );
        let audit = crate::sm3_compress::audit_ring_values(&asm.info, &adv);
        assert!(!audit.is_empty(), "exp 词格翻转未被消息根环审计捕获（双信号缺一）");
    }

    /// T2.6 ⑤ d 位翻转必败：d MSB 位格 0→1（仍 bool 合法）⟹ 分解组合失配
    /// ⟹ assert.zero mock 击中（32 位分解唯一性 = (S6) 健全性承重）。
    #[test]
    fn s6_dbit_flip_caught() {
        let base = test_witness();
        let (asm, h) =
            assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
        let (bc, br) = h.s6_dbit0;
        let mut adv = asm.advice.clone();
        adv[bc][br] += FpSM2::ONE;
        let bad = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(
            !bad.is_empty(),
            "d MSB 位翻转未被捕获 = 分解组合缺失（T2.6 红态）"
        );
        assert!(
            bad.iter().any(|v| asm.ctags[v.constraint] == "assert.zero"),
            "d 位翻转须由 assert.zero 族击中；族直方 {:?}",
            bad.iter().map(|v| asm.ctags[v.constraint]).collect::<Vec<_>>()
        );
    }

    /// 簇J E8 验收（J-d1）：(S4) pk_u=[sk_u]G 循环 + 双 decompose 换根 +
    /// sk_u∈[1,n−1] 范围门。健全性链条终判：sk 位 →（β 环）→ 循环 →（传输
    /// 环）→ st_pkx/st_pky →（decompose）→ 16 词 recomp ↔ SM3 消息根。
    #[test]
    fn s4_skg_loop_and_pk_u_rewire() {
        let w = test_witness();
        let (asm, h) = assemble_full_statement_with_hooks(&w);

        // ① 换根读回：pk 词格 = [sk_u]G 输出的 BE 词（换根生效的几何语义
        //    锚；与 E4 占位锚的区分证据 = ④ 负例 + ⑥ 指纹增量）。
        let pkx_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.0);
        let pky_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.1);
        for k in 0..8usize {
            let wx = u32::from_be_bytes(pkx_be[4 * k..4 * k + 4].try_into().unwrap());
            let wy = u32::from_be_bytes(pky_be[4 * k..4 * k + 4].try_into().unwrap());
            assert_eq!(
                asm.advice[h.pkx_cols[k]][h.row_pk],
                FpSM2::from(u64::from(wx)),
                "pk_u.x 词 {k} ≠ [sk_u]G 换根重组值"
            );
            assert_eq!(
                asm.advice[h.pky_cols[k]][h.row_pk],
                FpSM2::from(u64::from(wy)),
                "pk_u.y 词 {k} ≠ [sk_u]G 换根重组值"
            );
        }
        assert_ne!(h.sk_bit0, (0usize, 0usize), "E8 后 sk_bit0 钩子必须已填充");
        assert_ne!(h.sk_loop_row0, 0, "E8 后 sk_loop_row0 钩子必须已填充");

        // ② 三道防线：环账本格全局唯一（+258 环：β×256 + 传输×2）+ 环值
        //    审计零（base/d2v 大环追加 512×2 成员后仍全环一致 = 基点绑定
        //    生效的直接证据）+ mock 全扫零违约。
        let mut seen = std::collections::BTreeSet::new();
        for cyc in &asm.info.permutations {
            assert!(cyc.len() >= 2);
            for cell in cyc {
                assert!(seen.insert(*cell), "格 {cell:?} 出现在多个环位");
            }
        }
        let bad_rings = crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        assert!(bad_rings.is_empty(), "环取值不一致: {bad_rings:?}");
        let bad = crate::sm3_compress::check_parts_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
        );
        assert!(bad.is_empty(), "mock 违约 {} 处；首条 {:?}", bad.len(), bad.first());

        // ③ 旋转预算守卫：sk 循环仅 rot∈{0,1}，decompose/lt_n/neq 全 cur
        //    ⟹ max|rot| 仍须 ≤ K（=11，SM3 主导）。
        let maxd = asm
            .info
            .constraints
            .iter()
            .map(|cc| cc.max_used_rotation_distance())
            .max()
            .unwrap_or(0);
        assert!(
            maxd <= crate::sm3_compress::K,
            "旋转距离 {maxd} 超出后端预算 num_vars={}",
            crate::sm3_compress::K
        );

        // ④ sk_u=0 负例（范围门在位的装配期证明；见证 pk_u 不动 = 见证侧
        //    (S4) 断裂）：装配完成但 mock 违约非空——neq_zero（0·inv=1，
        //    prod.eq 族）+ 16 词 recomp（重组 0 ≠ 原词）。确定性行为，非
        //    panic；E12 矩阵④的正式篡改负例走 advice 翻转路径。
        let mut w0 = test_witness();
        w0.sk_u = [0; 4];
        let (asm0, _h0) = assemble_full_statement_with_hooks(&w0);
        let bad0 = crate::sm3_compress::check_parts_violations(
            &asm0.info,
            &asm0.advice,
            &asm0.instances,
        );
        assert!(!bad0.is_empty(), "sk_u=0 必须被 [1,n−1] 门在 mock 层击中");
        assert!(
            bad0.iter().any(|&v| asm0.ctags[v.constraint] == "prod.eq"),
            "sk_u=0 必须击中 neq_zero 乘法门（prod.eq 族）"
        );

        // ⑤ 形状指纹（与主测试 ⑥ 同值（E11 态）——双测试互证，防单点漏改）。
        assert_eq!(asm.info.constraints.len(), 201_183, "约束总数漂移（2026-10-01 实测 201,183：A1″ 旧钉 225,724 在 db0bbb3 已漂移至 201,443——历史批次 legacy 面拆除未回写本钉[实测对照]；本次换代 acc.chain 去重 −260=4 窗×65，201,443−260=201,183）");
        assert_eq!(asm.advice.len(), 11_586, "T2.6 advice 列数漂移（2026-10-01 实测钉：A1″ 旧钉 11,663 在 db0bbb3 实测已漂移至 11,586——历史批次列删除未回写；本批零列变动）");
        assert_eq!(asm.num_selectors, 393, "T2.6 选择器族数漂移（2026-10-01 实测钉：旧钉 370 在 db0bbb3 实测已漂移至 393——历史批次未回写；本批零选择器变动）");
        assert_eq!(asm.info.preprocess_polys.len(), 393, "T2.6 预处理多项式数漂移（2026-10-01 实测钉：旧钉 370 已漂移至 393——历史批次未回写；本批零变动）");
        assert_eq!(asm.info.permutations.len(), 1_187, "T2.6 中继环数漂移（2026-10-01 实测钉：旧钉 1,957 论文口径在 db0bbb3 实测已漂移至 1,187——历史批次环合并未回写；本批零环变动）");
    }

    /// 簇J E9 验收（J-d2）：(S3a) C₁=r·G / Id·G 两固定基循环 + r∈[1,n−1]
    /// 范围门。健全性链条：r 位（bool+lt_n+neq）→（β 环）→ C₁ 循环 →（传输
    /// 环）→ st_c1x/st_c1y（E10 C₂/实例钉消费）；Id 位（消息侧位格复用 =
    /// 双绑通道）→（β 环）→ Id·G 循环 → st_idgx/st_idgy。
    #[test]
    fn s3a_c1_idg_loops_and_r_range() {
        let w = test_witness();
        let (asm, h) = assemble_full_statement_with_hooks(&w);

        // ① 暂存读回：C₁ = 宿主 [r]G、Id·G = 宿主 [Id_u]G（BE 词对拍——
        //    传输环落位生效的几何语义锚）。
        let r_bits: [bool; 256] =
            std::array::from_fn(|i| (w.r[i / 64] >> (i % 64)) & 1 == 1);
        let id_bits: [bool; 256] =
            std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
        let g = crate::sm2_ec_plonkish::g_coords();
        let c1_host = crate::sm2_ec_plonkish::affine_mul_bits(&r_bits, Some(g))
            .expect("[r]G 宿主标量乘");
        let idg_host = crate::sm2_ec_plonkish::affine_mul_bits(&id_bits, Some(g))
            .expect("[Id_u]G 宿主标量乘");
        for (got, want, tag) in [
            (h.c1_x0, c1_host.0, "C₁.x"),
            (h.c1_y0, c1_host.1, "C₁.y"),
            (h.idg_x0, idg_host.0, "Id·G.x"),
            (h.idg_y0, idg_host.1, "Id·G.y"),
        ] {
            assert_eq!(
                asm.advice[got.0][got.1], want,
                "{tag} 暂存格 ≠ 宿主真值（传输环/循环断裂）"
            );
        }
        assert_ne!(h.r_bit0, (0usize, 0usize), "E9 后 r_bit0 钩子必须已填充");

        // ② 三道防线：环账本格全局唯一（+516 环：β×512 + 传输×4）+ 环值审计
        //    零（base/d2v 大环追加 1024×2 成员后仍全环一致 = 两循环基点绑定
        //    生效的直接证据）+ mock 全扫零违约。
        let mut seen = std::collections::BTreeSet::new();
        for cyc in &asm.info.permutations {
            assert!(cyc.len() >= 2);
            for cell in cyc {
                assert!(seen.insert(*cell), "格 {cell:?} 出现在多个环位");
            }
        }
        let bad_rings = crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        assert!(bad_rings.is_empty(), "环取值不一致: {bad_rings:?}");
        let bad = crate::sm3_compress::check_parts_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
        );
        assert!(bad.is_empty(), "mock 违约 {} 处；首条 {:?}", bad.len(), bad.first());

        // ③ 旋转预算守卫：两循环仅 rot∈{0,1}，其余全 cur ⟹ max|rot| ≤ K。
        let maxd = asm
            .info
            .constraints
            .iter()
            .map(|cc| cc.max_used_rotation_distance())
            .max()
            .unwrap_or(0);
        assert!(
            maxd <= crate::sm3_compress::K,
            "旋转距离 {maxd} 超出后端预算 num_vars={}",
            crate::sm3_compress::K
        );

        // ④ r=0 负例（范围门在位的装配期证明；见证侧 (S3) C₁ 断裂）：装配
        //    完成但 mock 违约非空——neq_zero（0·inv=1，prod.eq 族）。确定性
        //    行为，非 panic；E12 矩阵⑦正式篡改负例走 advice 翻转路径。
        let mut w0 = test_witness();
        w0.r = [0; 4];
        let (asm0, _h0) = assemble_full_statement_with_hooks(&w0);
        let bad0 = crate::sm3_compress::check_parts_violations(
            &asm0.info,
            &asm0.advice,
            &asm0.instances,
        );
        assert!(!bad0.is_empty(), "r=0 必须被 [1,n−1] 门在 mock 层击中");
        assert!(
            bad0.iter().any(|&v| asm0.ctags[v.constraint] == "prod.eq"),
            "r=0 必须击中 neq_zero 乘法门（prod.eq 族）"
        );

        // ⑤ 形状指纹（与主测试 ⑥ 同值（E11 态）——双测试互证，防单点漏改）。
        assert_eq!(asm.info.constraints.len(), 201_183, "约束总数漂移（2026-10-01 实测 201,183：A1″ 旧钉 225,724 在 db0bbb3 已漂移至 201,443——历史批次 legacy 面拆除未回写本钉[实测对照]；本次换代 acc.chain 去重 −260=4 窗×65，201,443−260=201,183）");
        assert_eq!(asm.advice.len(), 11_586, "T2.6 advice 列数漂移（2026-10-01 实测钉：A1″ 旧钉 11,663 在 db0bbb3 实测已漂移至 11,586——历史批次列删除未回写；本批零列变动）");
        assert_eq!(asm.num_selectors, 393, "T2.6 选择器族数漂移（2026-10-01 实测钉：旧钉 370 在 db0bbb3 实测已漂移至 393——历史批次未回写；本批零选择器变动）");
        assert_eq!(asm.info.preprocess_polys.len(), 393, "T2.6 预处理多项式数漂移（2026-10-01 实测钉：旧钉 370 已漂移至 393——历史批次未回写；本批零变动）");
        assert_eq!(asm.info.permutations.len(), 1_187, "T2.6 中继环数漂移（2026-10-01 实测钉：旧钉 1,957 论文口径在 db0bbb3 实测已漂移至 1,187——历史批次环合并未回写；本批零环变动）");
    }

    /// 簇J E10 验收（J-d3）：(S3b) r·apk 变基循环 + C₂ = Id·G + r·apk 完全加
    /// + 6 实例钉（12..17）。健全性链条：apk staged 头（on_curve 12 门，EP
    /// 同款）→（base/d2v 大环）→ r·apk 循环（β = rid_beta_c1 共享追加——
    /// 一格一环红线下两循环同标量同位源）→（尾环）→ C₂ 加数；C₁/Id·G 暂存
    /// （E9 传输环追加成员）→ C₂ 加数 ⟹ (S3) 双承诺电路内闭合 + 公开面
    /// C₁/C₂/apk 经 pin.bind 进实例面。
    #[test]
    fn s3b_rapk_c2_complete_add_and_pins() {
        let w = test_witness();
        let (asm, h) = assemble_full_statement_with_hooks(&w);

        // ① 宿主真值四点独立 native 复算（第五道防线基准）。
        let r_bits: [bool; 256] =
            std::array::from_fn(|i| (w.r[i / 64] >> (i % 64)) & 1 == 1);
        let id_bits: [bool; 256] =
            std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
        let g = crate::sm2_ec_plonkish::g_coords();
        let c1_host = crate::sm2_ec_plonkish::affine_mul_bits(&r_bits, Some(g))
            .expect("[r]G 宿主标量乘");
        let idg_host = crate::sm2_ec_plonkish::affine_mul_bits(&id_bits, Some(g))
            .expect("[Id_u]G 宿主标量乘");
        let rk_host = crate::sm2_ec_plonkish::affine_mul_bits(&r_bits, Some(w.apk))
            .expect("[r]apk 宿主标量乘");
        let c2_host = crate::sm2_ec_plonkish::affine_add(Some(idg_host), Some(rk_host))
            .expect("C₂ 宿主点加");

        // ② 实例面（19；12..17 = E10 六钉 = 语句公开面 C₁/C₂/apk）。
        assert_eq!(asm.instances[0].len(), 22, "实例面 = 22（E10 钉 12..17 + T2.5 钉 19..20 + T2.6 钉 21）");
        let fe = |v: FpSM2| crate::sm2_params::fr_to_limbs(&v);
        assert_eq!(fe(asm.instances[0][12]), fe(c1_host.0), "实例 12 ≠ C₁.x");
        assert_eq!(fe(asm.instances[0][13]), fe(c1_host.1), "实例 13 ≠ C₁.y");
        assert_eq!(fe(asm.instances[0][14]), fe(c2_host.0), "实例 14 ≠ C₂.x");
        assert_eq!(fe(asm.instances[0][15]), fe(c2_host.1), "实例 15 ≠ C₂.y");
        assert_eq!(fe(asm.instances[0][16]), fe(w.apk.0), "实例 16 ≠ apk.x");
        assert_eq!(fe(asm.instances[0][17]), fe(w.apk.1), "实例 17 ≠ apk.y");
        assert_eq!(
            asm.advice[h.apk_stg0.0][h.apk_stg0.1],
            w.apk.0,
            "apk staged x 格 ≠ 见证（staging 断裂）"
        );
        assert_ne!(h.apk_pin, (0usize, 0usize), "E10 后 apk_pin 钩子必须已填充");

        // ③ 三道防线：环账本格全局唯一（+12 环：base_a/d2_a ×3+3、idg_inf、
        //    尾 rk ×3、C₂ 钉 ×2）+ 环值审计零（apk 大环/β 共享/传输环追加
        //    成员后全环一致 = 基点绑定与钉缝合生效的直接证据）+ mock 全扫。
        let mut seen = std::collections::BTreeSet::new();
        for cyc in &asm.info.permutations {
            assert!(cyc.len() >= 2);
            for cell in cyc {
                assert!(seen.insert(*cell), "格 {cell:?} 出现在多个环位");
            }
        }
        let bad_rings = crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        assert!(bad_rings.is_empty(), "环取值不一致: {bad_rings:?}");
        let bad = crate::sm3_compress::check_parts_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
        );
        assert!(bad.is_empty(), "mock 违约 {} 处；首条 {:?}", bad.len(), bad.first());

        // ④ 旋转预算守卫：r·apk 循环仅 rot∈{0,1}，其余全 cur ⟹ max|rot| ≤ K。
        let maxd = asm
            .info
            .constraints
            .iter()
            .map(|cc| cc.max_used_rotation_distance())
            .max()
            .unwrap_or(0);
        assert!(
            maxd <= crate::sm3_compress::K,
            "旋转距离 {maxd} 超出后端预算 num_vars={}",
            crate::sm3_compress::K
        );

        // ⑤ apk staged x 翻一格双信号齐爆（矩阵⑧装配期预演：on_curve 门
        //    mock 击中 + base_a 大环审计击中——C₂ 通道假绿的永久守卫）。
        let (ac_, ar_) = h.apk_stg0;
        let mut adv = asm.advice.clone();
        adv[ac_][ar_] += FpSM2::ONE;
        let bad_t = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(!bad_t.is_empty(), "apk staged 翻转未被 mock 击中（on_curve 门未激活?）");
        let audit_t = crate::sm3_compress::audit_ring_values(&asm.info, &adv);
        assert!(!audit_t.is_empty(), "apk staged 翻转未被 base_a 环审计捕获");

        // ⑥ 形状指纹（[实测 2026-08-31 首跑]：约束 = 218,724 + 12 基头 +
        //    6,147 循环 + 28 完全加 + 6 钉 = 224,917（增量窗 6,193 逐项命中）；
        //    advice +84 = hs 3 + hd 3 + **dga 5（首跑预算漏项——DoubleSlots
        //    = sel + xsq/u/lam/lamsq/prod 5 列，倍点 5 门的中间格；门约束已
        //    计入「12 基头」，仅列数漏）** + oc 3 + 循环 31 + ac2 27 +
        //    c2idg 3 + c2rpk 3 + 钉 6；sel +14 = oc 1 + dga 1 + 循环 4 +
        //    ac2 2 + 钉 6；环 +12。**E11 态 [实测 二跑]**：+258 约束（湮灭
        //    256 + 线性 1 + 钉 1）/ +1 advice / +2 sel（pred_sel + pred_pin_sel，
        //    勘误 #28）/ +1 环（rid_pred_pin）；E10 基线账保持可追溯。）
        assert_eq!(asm.info.constraints.len(), 201_183, "约束总数漂移（2026-10-01 实测 201,183：A1″ 旧钉 225,724 在 db0bbb3 已漂移至 201,443——历史批次 legacy 面拆除未回写本钉[实测对照]；本次换代 acc.chain 去重 −260=4 窗×65，201,443−260=201,183）");
        assert_eq!(asm.advice.len(), 11_586, "T2.6 advice 列数漂移（2026-10-01 实测钉：A1″ 旧钉 11,663 在 db0bbb3 实测已漂移至 11,586——历史批次列删除未回写；本批零列变动）");
        assert_eq!(asm.num_selectors, 393, "T2.6 选择器族数漂移（2026-10-01 实测钉：旧钉 370 在 db0bbb3 实测已漂移至 393——历史批次未回写；本批零选择器变动）");
        assert_eq!(asm.info.preprocess_polys.len(), 393, "T2.6 预处理多项式数漂移（2026-10-01 实测钉：旧钉 370 已漂移至 393——历史批次未回写；本批零变动）");
        assert_eq!(asm.info.permutations.len(), 1_187, "T2.6 中继环数漂移（2026-10-01 实测钉：旧钉 1,957 论文口径在 db0bbb3 实测已漂移至 1,187——历史批次环合并未回写；本批零环变动）");
    }

    /// 簇J E11 验收（J-e1）：(S5) 谓词湮灭 + pred_out 实例 18。语义 = R1CS
    /// M6 先例（m0_sm3_circuit/show_circuit_r1cs.rs `enforce_pred`）：谓词 ≜
    /// "attrs_u == PRED_TARGET"（单属性相等；多属性/区间谓词为扩展），电路 =
    /// pred_out·(attrs_bit−target_bit)=0 ×256 湮灭乘门 + pred_out=1 线性 +
    /// pin.bind 实例缝合（公开面 pred_out，def:pi (S5)）。
    #[test]
    fn s5_pred_annihilation_and_pred_out_instance() {
        let w = test_witness();
        assert_eq!(w.attrs_u, PRED_TARGET, "正例见证 attrs 必须满足演示谓词");
        let (asm, h) = assemble_full_statement_with_hooks(&w);

        // ① pred_out 实例值 = 1（公开面语义；18 = J-10b ② 定案的 pred_out 槽）。
        assert_eq!(asm.instances[0][18], FpSM2::ONE, "实例 18（pred_out）≠ 1");
        assert_ne!(h.pred_cell, (0usize, 0usize), "E11 后 pred_cell 钩子必须已填充");
        assert_ne!(
            h.pred_pin_cell, (0usize, 0usize),
            "E11 后 pred_pin_cell 钩子必须已填充（勘误 #28 钉值格）"
        );

        // ② 湮灭族激活证据（#26 死选择器防线）：翻 attrs 位 0 **−1**（诚实值
        //    =1 ⟹ 0 仍是合法 bool 值——bool/recomp 不添乱，prod.eq 只能来自
        //    湮灭门；首版 +1 会连带炸 bool 使判别力失效，自Catch 修正）。
        //    位格不在任何环（E5 bool/recomp 与 E11 湮灭全同行为 rot=0）⟹
        //    环审计预期沉默；E12 矩阵⑥的双信号篡改走词格（环根）翻转。
        let (bc, br) = h.attrs_bit0;
        let mut adv = asm.advice.clone();
        adv[bc][br] -= FpSM2::ONE;
        let bad_t = crate::sm3_compress::check_parts_violations(&asm.info, &adv, &asm.instances);
        assert!(!bad_t.is_empty(), "attrs 位翻转未被 mock 击中");
        assert!(
            bad_t
                .iter()
                .any(|&v| asm.ctags[v.constraint] == "prod.eq"),
            "attrs 位翻转未击中湮灭族（prod.eq）——pred_sel 死约束?（#26 同型）"
        );

        // ②′ 钉缝合活性证据（#24 缺席类守卫）：翻钉值格 +1 ⟹ mock 必击中
        //    pin.bind 族（2−1=1≠0）+ 环审计击中（钉格↔谓词格环不一致）。
        //    若 pred_pin_sel 死约束（未 extend）则 pin.bind 缺席、mock 沉默
        //    ——本断言爆（#24 同型永久守卫）。
        let (pc, pr) = h.pred_pin_cell;
        let mut adv2 = asm.advice.clone();
        adv2[pc][pr] += FpSM2::ONE;
        let bad_p = crate::sm3_compress::check_parts_violations(&asm.info, &adv2, &asm.instances);
        assert!(!bad_p.is_empty(), "钉值格翻转未被 mock 击中（pin.bind 缺席?）");
        assert!(
            bad_p
                .iter()
                .any(|&v| asm.ctags[v.constraint] == "pin.bind"),
            "钉值格翻转未击中 pin.bind 族——钉缝合缺失?（#24 同型）"
        );
        let audit_p = crate::sm3_compress::audit_ring_values(&asm.info, &adv2);
        assert!(!audit_p.is_empty(), "钉值格翻转未被 rid_pred_pin 环审计捕获");

        // ③ 诚实装配三道防线：环值审计零 + mock 全扫零违约。
        let bad_rings = crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        assert!(bad_rings.is_empty(), "环取值不一致: {bad_rings:?}");
        let bad = crate::sm3_compress::check_parts_violations(
            &asm.info,
            &asm.advice,
            &asm.instances,
        );
        assert!(bad.is_empty(), "mock 违约 {} 处；首条 {:?}", bad.len(), bad.first());

        // ④ 旋转预算守卫：湮灭/线性/钉全 cur ⟹ max|rot| 仍 ≤ K=12
        //    （历史主导值 11 = SM3 体）。
        let maxd = asm
            .info
            .constraints
            .iter()
            .map(|cc| cc.max_used_rotation_distance())
            .max()
            .unwrap_or(0);
        assert!(
            maxd <= crate::sm3_compress::K,
            "旋转距离 {maxd} 超出后端预算 num_vars={}",
            crate::sm3_compress::K
        );

        // ⑤ 形状指纹（[实测 2026-08-31 二跑]：约束 = 224,917 + 256 湮灭 +
        //    1 线性 + 1 pin.bind = 225,175；advice +1 = pred_cell 列（钉值格
        //    复用同列不同行）；sel/prep +2 = pred_sel + pred_pin_sel（勘误
        //    #28：钉行与谓词行不同点，共签会把湮灭门带进钉行读到位格零值）；
        //    环 +1 = rid_pred_pin 钉值缝合环。首跑勘误 #28：pin.bind 激活点
        //    误落 row_attrs（实例列在非钉行 = 0 ⟹ 1−0≠0 单 mock 违约）。）
        assert_eq!(asm.info.constraints.len(), 201_183, "约束总数漂移（2026-10-01 实测 201,183：A1″ 旧钉 225,724 在 db0bbb3 已漂移至 201,443——历史批次 legacy 面拆除未回写本钉[实测对照]；本次换代 acc.chain 去重 −260=4 窗×65，201,443−260=201,183）");
        assert_eq!(asm.advice.len(), 11_586, "T2.6 advice 列数漂移（2026-10-01 实测钉：A1″ 旧钉 11,663 在 db0bbb3 实测已漂移至 11,586——历史批次列删除未回写；本批零列变动）");
        assert_eq!(asm.num_selectors, 393, "T2.6 选择器族数漂移（2026-10-01 实测钉：旧钉 370 在 db0bbb3 实测已漂移至 393——历史批次未回写；本批零选择器变动）");
        assert_eq!(asm.info.preprocess_polys.len(), 393, "T2.6 预处理多项式数漂移（2026-10-01 实测钉：旧钉 370 已漂移至 393——历史批次未回写；本批零变动）");
        assert_eq!(asm.info.permutations.len(), 1_187, "T2.6 中继环数漂移（2026-10-01 实测钉：旧钉 1,957 论文口径在 db0bbb3 实测已漂移至 1,187——历史批次环合并未回写；本批零环变动）");
    }

    /// 簇J E12 验收（J-e2）：负例矩阵 9/9（蓝图 §四·8 J-7 逐字；② 拆 r/s 两
    /// 子例共 10 次翻转）。装配一次 × 独立 advice 副本逐例翻转；共用断言器
    /// expect_caught（merged H4 同款）：位级 mock + 环审计双信号齐爆，任一
    /// 沉默 = 假绿（#24/#26/#27 三类盲区由「双信号必须同时开火」兜底）。
    /// ①′/③′ 追加语义终判（native verify_replay 确定性失败）；⑨ 追加判别力
    /// （assert.zero 族必须在场——旁路由线性门抓住而非环审计独扛）。
    #[test]
    fn e12_neg_matrix_nine_caught() {
        let w = test_witness();
        let (asm, h) = assemble_full_statement_with_hooks(&w);
        // 诚实底板基线：两道防线零违约（负例判据的对照面）。
        assert!(
            crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances)
                .is_empty(),
            "诚实底板 mock 违约（基线失效）"
        );
        assert!(
            crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice).is_empty(),
            "诚实底板环审计不等（基线失效）"
        );

        let expect_caught = |label: &str, adv: &Vec<Vec<FpSM2>>| {
            let bad = crate::sm3_compress::check_parts_violations(&asm.info, adv, &asm.instances);
            assert!(!bad.is_empty(), "{label}: 位级 mock 未击中");
            let audit = crate::sm3_compress::audit_ring_values(&asm.info, adv);
            assert!(!audit.is_empty(), "{label}: 环审计未捕获");
            bad
        };
        // ③S3 换代变体：window 化循环的位翻转信号面=mock + **精确 recomp
        // 族违约**（β 环退役后位格↔循环绑定改走 recomp 约束+绑定环——
        // 族断言比“违约非空”定位性更强，非放松）。
        let expect_caught_recomp = |label: &str, adv: &Vec<Vec<FpSM2>>, recomp_tag: &str| {
            let bad = crate::sm3_compress::check_parts_violations(&asm.info, adv, &asm.instances);
            assert!(!bad.is_empty(), "{label}: 位级 mock 未击中");
            let has_recomp = bad
                .iter()
                .any(|v| asm.ctags[v.constraint] == recomp_tag);
            assert!(has_recomp, "{label}: recomp 族违约缺席（绑定约束未击中）");
            bad
        };
        let flip = |h2: (usize, usize), delta: FpSM2| {
            let mut adv = asm.advice.clone();
            adv[h2.0][h2.1] += delta;
            adv
        };
        let neg_one = FpSM2::ZERO - FpSM2::ONE;
        let e_fp = fold_digest_fp(&h.digest);

        // ① 摘要词篡改（dgw0 +1，权重 2^0）→ ⑧′ 大折叠 mock + echo 环双
        //    信号；①′ 语义终判：e' = e+1 ⟹ r' = (e'+x₁) mod n = r+1 ≢ r
        //    ⟹ native 四步重放确定性失败。
        expect_caught("①dgw0", &flip(h.dgw0, FpSM2::ONE));
        assert!(
            !crate::sm2_verify_assemble::verify_replay(
                e_fp + FpSM2::ONE,
                crate::sm2_params::fr_from_limbs(&w.r_s),
                crate::sm2_params::fr_from_limbs(&w.s_s),
                w.pk_i.0,
                w.pk_i.1,
            )
            .ok,
            "① 篡改 e 后签名仍通过 native 重放"
        );

        // ② r_s/s_s 标量槽篡改（面 pv@home ∈ rid_pv 环；#26 修复后词位家族
        //    激活 ⟹ link.recomp/大折叠 mock 在位 + 钉行拷贝环审计双信号）。
        expect_caught("②r_s", &flip(h.r_pv_home, FpSM2::ONE));
        expect_caught("②s_s", &flip(h.s_pv_home, FpSM2::ONE));

        // ③ P_A(=pk_I) 钉篡改 → pin.bind(实例 3) + rid_base_p 环首键双信号；
        //    ③′ 语义终判：pax+1 off-curve（除非 2·pax+1+a ≡ 0 的病态碰撞，
        //    a2 测试钥不满足）⟹ verify_replay 首行 on-curve 校验即拒。
        expect_caught("③pax", &flip(h.pax_pin, FpSM2::ONE));
        assert!(
            !crate::sm2_verify_assemble::verify_replay(
                e_fp,
                crate::sm2_params::fr_from_limbs(&w.r_s),
                crate::sm2_params::fr_from_limbs(&w.s_s),
                w.pk_i.0 + FpSM2::ONE,
                w.pk_i.1,
            )
            .ok,
            "③ 篡改 P_A 后签名仍通过 native 重放"
        );

        // ④ sk_u 位格篡改（bit0 诚实=1 → +1=2 非布尔）→ bool mock +
        //    ec.win.sk.recomp 精确族违约（③S3 window 化后信号面换代：β 环
        //    退役，sk↔循环单源绑定改走 recomp 约束+绑定环——「喂循环 ≠ 喂
        //    范围门」的通道错位被构造消除，与 ⑤ 同构）。
        expect_caught_recomp("④sk", &flip(h.sk_bit0, FpSM2::ONE), "ec.win.sk.recomp");

        // ⑤ Id_u 位格篡改（bit0 诚实=0（零填充字节）→ +1=1 合法布尔）→
        //    bool + recomp 词 7（消息通道）+ ec.win.id.recomp 精确族违约
        //    （EC 通道——③S3 window 化换代：β 环退役，绑定环+recomp 承接）
        //    多信号齐爆——Id 消费=同格双绑通道（E9 复用定案）：任何一侧漂移
        //    必被另一侧信号击中，「喂 EC ≠ 喂消息」错位类缺陷不可表达。
        expect_caught_recomp("⑤id", &flip(h.id_bit0, FpSM2::ONE), "ec.win.id.recomp");

        // ⑥ attrs 词格篡改（消息通道词根 +1；谓词位格同源不动）→ recomp 词 0
        //    mock + 消息根环审计双信号；谓词侧同格位保持诚实 ⟹ 湮灭门依旧绿
        //    = 「喂消息 ≠ 喂谓词」错位由词↔位重组约束封堵（单源，(S5) 的
        //    位级篡改负例归 s5 测试②，两例合璧覆盖 J-7 ⑥ 全语义）。
        expect_caught("⑥attrs", &flip(h.attrs_word0, FpSM2::ONE));

        // ⑦ r 位格篡改（bit0 诚实=1 → +1=2 非布尔）→ bool mock +
        //    rid_beta_c1 β 环（r 与 C₁/r·apk 两循环同位格共享，E10 定案）
        //    双信号——EC 消费经环绑死到位源，行侧篡改必被环审计捕获。
        expect_caught("⑦r", &flip(h.r_bit0, FpSM2::ONE));

        // ⑧ apk 钉篡改 → pin.bind(实例 16) + rid_base_a 环首键双信号（C₂
        //    变基点通道假绿封堵——J-7 ⑧ DeepSeek 吸收项）。
        expect_caught("⑧apk", &flip(h.apk_pin, FpSM2::ONE));

        // ⑨ 谓词旁路（pred_out 1→0）：湮灭门空转（0·diff=0 恒成立），但
        //    pred_out=1 线性门 + rid_pred_pin 钉环（钉格=1 vs 谓词格=0）双
        //    信号齐爆；判别力断言：违约必含 assert.zero 族（旁路被线性门
        //    抓住，非环审计独扛——(S5) 健全性的线性锚）。
        let bad9 = expect_caught("⑨pred", &flip(h.pred_cell, neg_one));
        assert!(
            bad9.iter()
                .any(|v| asm.ctags[v.constraint] == "assert.zero"),
            "⑨ 违约族缺 assert.zero（旁路未被线性门抓住）"
        );
    }

    /// 簇J E12 双正例（J-7 验收线 ≥2 正例）：第二见证（id_u/sk_u/r 全不同，
    /// attrs=PRED_TARGET 谓词先定——凭证语义正确）全板验收 = mock/环审计
    /// 零违约 + 摘要=native 终判 + 实例 0==fold(digest) + native 四步重放 +
    /// 环账本唯一 + max|rot|≤K + E 值 census（J-10 终表首测冻结，probe
    /// 同式离线确定性）+ 指纹互证（与主测试同值）。
    #[test]
    fn e12_second_witness_positive_fullboard() {
        let id16: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(13) ^ 0x5E);
        let mut id2 = [0u8; 32];
        id2[..16].copy_from_slice(&id16);
        let w = witness_from([0x0C0C, 0, 0, 0x0B0B], id2, [0x33, 0, 0, 0x44]);
        let w1 = test_witness();
        assert_ne!(w.id_u, w1.id_u, "第二见证 id_u 必须不同于首见证");
        assert_ne!(w.sk_u, w1.sk_u, "第二见证 sk_u 必须不同");
        assert_ne!(w.r, w1.r, "第二见证 ElGamal r 必须不同");
        assert_eq!(w.attrs_u, PRED_TARGET, "第二见证 attrs 必须满足谓词（凭证语义）");

        let (asm, h) = assemble_full_statement_with_hooks(&w);
        let host = full_statement_host(&w);

        // ① 摘要/链态终判（独立路径 native 手链）+ 实例 0 绑定 + native 重放。
        let c = crate::sm3_native_ref::compress;
        let iv = crate::sm3_native_ref::IV;
        let v1 = c(&iv, &host.blocks[0]);
        let v2 = c(&v1, &host.blocks[1]);
        let dg = c(&v2, &host.blocks[2]);
        assert_eq!(h.chain_states[0], v1, "链态 V₁ ≠ native");
        assert_eq!(h.chain_states[1], v2, "链态 V₂ ≠ native");
        for k in 0..8usize {
            assert_eq!(h.digest[k], dg[k], "摘要字 {k} ≠ native");
        }
        assert_eq!(
            crate::sm2_params::fr_to_limbs(&asm.instances[0][0]),
            crate::sm2_params::fr_to_limbs(&fold_digest_fp(&h.digest)),
            "实例 0 ≠ fold(摘要)——e 绑定断裂"
        );
        assert!(
            crate::sm2_verify_assemble::verify_replay(
                asm.instances[0][0],
                asm.instances[0][1],
                asm.instances[0][2],
                w.pk_i.0,
                w.pk_i.1,
            )
            .ok,
            "第二见证实例面 (e,r,s) 未通过 native 四步重放"
        );

        // ② 环账本唯一 + 两道防线零违约（mock 盲区前置桥）。
        let mut seen = std::collections::BTreeSet::new();
        for cyc in &asm.info.permutations {
            assert!(cyc.len() >= 2);
            for cell in cyc {
                assert!(seen.insert(*cell), "格 {cell:?} 出现在多个环位");
            }
        }
        assert!(
            crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice).is_empty(),
            "环取值不一致"
        );
        assert!(
            crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances)
                .is_empty(),
            "第二见证正例 mock 违约"
        );

        // ③ max|rot| ≤ K + ④ E 值 census（probe_sm2_verify 同式：pairs=
        //    去重 (poly, rot)，E = cur 对 + Σ_{d>0} n_d·2^d——PCS 开口乘数
        //    定律；E8 +6/E9 +12/E10 +6/E11 +0 四循环增量已含其中，首测冻结
        //    进蓝图 J-10 终表）。
        let maxd = asm
            .info
            .constraints
            .iter()
            .map(|cc| cc.max_used_rotation_distance())
            .max()
            .unwrap_or(0);
        assert!(
            maxd <= crate::sm3_compress::K,
            "旋转距离 {maxd} 超出后端预算 num_vars={}",
            crate::sm3_compress::K
        );
        let mut pairs: std::collections::BTreeSet<(usize, i64)> = Default::default();
        for cc in &asm.info.constraints {
            for q in cc.used_query() {
                pairs.insert((q.poly(), q.rotation().0 as i64));
            }
        }
        let mut by_d: std::collections::BTreeMap<i64, usize> = Default::default();
        for (_, d) in &pairs {
            *by_d.entry(d.abs()).or_insert(0) += 1;
        }
        let cur = *by_d.get(&0).unwrap_or(&0);
        let units: u128 = by_d
            .iter()
            .filter(|(&d, _)| d > 0)
            .map(|(&d, &n)| n as u128 * 1u128 << d)
            .sum();
        let e_total = cur as u128 + units;
        println!("[t1-census] cur={cur} 非cur单元={units} E={e_total} max|rot|={maxd}");
        // E12 首测冻结（2026-08-31 [实测]）：cur=11,216 / 非cur单元=258,468 /
        // E=269,684。对账：PCS 开口乘数定律 E≈#cur+Σn_d·2^d；Fix R-a 六循环
        // （EG/EP/sk/C₁/Id·G/r·apk）各 3 对 (acc_in,d=1) 已含于 d=1 桶；J-6
        // 估算行「proof ~700–900MB」以 R1 v3b 列压缩后的布局为前提——当前
        // T1 未压缩布局（advice 11,117 [T2.5 后] vs merged 7,752）⟹ e2e proof 待实测
        // （[推得] 宽带 0.5–4GB @reps16，v3b 化后排期见 R1 线）。任何漂移
        // = 结构性事故，当场爆掉。
        // T2.5 增量（2026-09-02，勘误 #29）：+2 pin.bind（emit_pin_val_only
        // 全 cur）⟹ cur=11,220、E=269,688 [实测]（每条 pin.bind 贡献 2 个 cur 对：值列+实例列），非cur单元不变。
        // T2.6 增量（2026-09-03）：+35 cur 对（32 d 位格 + exp 词格 + T 钉值格
        // + 实例 21——T 列同时被组合约束与 pin.bind 消费故计 1；全 rot=0；
        // pad 锚词 0 拆除不减 cur 对——pad_col 仍被其余 7 锚 @cur 查询）
        // ⟹ cur=11,255、E=269,723 [实测 2026-09-03 复现跑 t1-census]，非cur单元不变。
        // R3-3.1 换代（2026-09-24 服务器窗实测）：cur 11,255→11,771（SMT
        // bit lane + B4 class + 承诺词面各批增量累计——锚原记 2026-09-03 滞后
        // 多批）；E 269,723→271,263（与 _v17_probe_census_decomp 的 271,263
        // 同锚互证——装配完整性见证）。
        // ③S3c window 化换代实测：cur 11,771→11,717、E 271,263→271,209
        // （EG 段 dp/acc 链修正净额——诊断面全约束诚实 witness 求值零违约
        // 互证；结构换代锚随实测值滚动）。
        assert_eq!(cur, 11_717, "T1 census cur 对数漂移（③S3c 换代实测）");
        assert_eq!(e_total, 271_209, "T1 census E 值漂移（③S3c 换代实测）");

        // ⑤ 指纹互证（与主测试同值——见证不同、形状恒等）。
        println!(
            "[t1-tally-2nd] constraints={} advice={} sel={} prep={} cycles={}",
            asm.info.constraints.len(),
            asm.advice.len(),
            asm.num_selectors,
            asm.info.preprocess_polys.len(),
            asm.info.permutations.len()
        );
        // W-1 换代（2026-09-27 [实测]，HEAD=751c2b7 四循环 window 化终态）：
        // constraints 225,724→201,443 / advice 11,663→11,586 / sel 370→393 /
        // prep 370→393 / cycles 1,957→1,187——③S2-S4 window 化（C₁/Id·G/sk/eg
        // 四循环）+R3-3.1 承诺块查表化累计漂移（A1″ 2026-09-09 锚为手术前
        // 时代值，滞后五批——E 值锚（cur=11,717/E=271,209）已随 S3c 换代，
        // 本批补齐结构五锚与 E 锚同代对齐）。
        assert_eq!(asm.info.constraints.len(), 201_183, "第二见证约束总数漂移（W-1 钉 201,443[2026-09-27] 本次换代 −260=acc.chain 去重 4 窗×65 → 201,183）");
        assert_eq!(asm.advice.len(), 11_586, "第二见证 advice 列数漂移（W-1 实测 11,586）");
        assert_eq!(asm.num_selectors, 393, "第二见证选择器族数漂移（W-1 2026-09-27 实测 393）");
        assert_eq!(asm.info.preprocess_polys.len(), 393, "预处理多项式数漂移（W-1 2026-09-27 实测 393=选择器数同额）");
        assert_eq!(asm.info.permutations.len(), 1_187, "第二见证中继环数漂移（W-1 实测 1,187）");
    }

    /// §五#0 前置普查（Phase 3 设计推演 2026-09-03 待实测项，2026-09-05 落定 [实测]）：
    /// ① lookup 面 = 0（⟹ 掩蔽面无 lookup m/h 列）；② zerocheck 表达式度数普查
    /// （组合层 ×eq 后 = max_constraint_deg+1 ≥ 2 ⟹ ρ·eq·m 掩蔽项（度数 2）被既有
    /// 度数吸收，sumcheck 轮消息格式零变化）；③ Phase 3 掩蔽面账本：λ 数 =
    /// witness 列 + z 列、m_idx = 后端列计数（与 backend preprocessor::compose_masked
    /// 同口径：实例列=每组一列）。数字供论文 §8.2 实装描述与成本账引用。
    #[test]
    fn phase3_census() {
        use plonkish_backend::util::arithmetic::div_ceil;
        let base = test_witness();
        let (asm, _) = assemble_full_statement_with_hooks_bound(&base, FpSM2::ZERO, FpSM2::ZERO, 500);
        let info = &asm.info;

        // ① lookup 面（P2：SM3_LUT=1 ⟹ 8×3=24 通道；legacy 保持 0——字节级锚）
        let lut_expect = if crate::sm3_lookup_weave::sm3_lut_enabled() { 24 } else { 4 };
        assert_eq!(info.lookups.len(), lut_expect, "T1 lookup 面漂移（2026-10-01 实测钉：legacy 实测 4 通道——旧锚 0 在 db0bbb3 已漂移[历史批次 LUT 化未回写]；LUT=24）");

        // ② 度数普查
        let max_constraint_deg = info
            .constraints
            .iter()
            .map(|c| c.degree())
            .max()
            .expect("non-empty constraints");
        let circuit_max = info.max_degree.unwrap_or(0);
        let max_degree = max_constraint_deg.max(circuit_max).max(2);
        assert!(
            max_degree.max(max_constraint_deg + 1) >= 2,
            "组合表达式度数 ≥ 2（掩蔽项度数被吸收的前提）"
        );

        // ③ 掩蔽面账本（compose_masked 同口径）
        let num_instances = info.num_instances.len();
        let num_preprocess = info.preprocess_polys.len();
        let num_witness: usize = info.num_witness_polys.iter().sum();
        let num_sigma = info.permutation_polys().len();
        let num_z = div_ceil(num_sigma, max_degree - 1);
        let m_idx = num_instances + num_preprocess + num_witness + num_sigma + num_z;
        let num_masked = num_witness + num_z; // lookups=0 ⟹ 无 lookup m/h 列
        println!(
            "[phase3-census][T1] inst={num_instances} prep={num_preprocess} wit={num_witness}              sigma={num_sigma} z={num_z} max_constraint_deg={max_constraint_deg}              max_degree={max_degree} m_idx={m_idx} num_masked(λ)={num_masked}"
        );
        assert_eq!(asm.advice.len(), num_witness, "witness 列数=advice 列数（掩蔽面基数）");
        assert!(num_masked > 0 && m_idx > num_masked, "掩蔽面账本非退化");
    }

    /// v17 探针(2026-09-09):开口面三数换代实测(去重对数/d0 对数/加权单元/承诺列)。
    #[test]
    fn _v17_probe_census_decomp() {
        let w = test_witness();
        let (asm, _) = assemble_full_statement_with_hooks(&w);
        let mut pairs: std::collections::BTreeSet<(usize, i64)> = Default::default();
        for cc in &asm.info.constraints {
            for q in cc.used_query() {
                pairs.insert((q.poly(), q.rotation().0 as i64));
            }
        }
        let n_pairs = pairs.len();
        let d0 = pairs.iter().filter(|&&(_, d)| d == 0).count();
        let weighted: u128 = pairs.iter().map(|&(_, d)| 1u128 << d.abs()).sum();
        // 承诺列口径的权威来源=phase3_census(此处只对账开口面分解)
        let w_ne = weighted - d0 as u128; // 非平凡旋转加权单元(=Σe_c − 单点对)
        println!("[v17-probe] pairs={} d0={} weighted_all={} weighted(d≠0)={} E=d0+w_ne={}",
            n_pairs, d0, weighted, w_ne, d0 as u128 + w_ne);
        assert_eq!(weighted, 271_209, "v17 探针:Σ2^|d| 漂移（2026-10-01 实测钉：旧钉 271,263 在 db0bbb3 实测已漂移至 271,209[去重对数面]——历史批次未回写；本批零开口面增量）");
    }

    /// Round7 #10 逐列开口分布测量（2026-09-07 [实测]）：对每列 c 计算
    /// e_c = Σ_{(c,d)∈pairs} 2^|d|（该列每次出示被开的求值方程数），发射
    /// 直方图/max/前 50 重列（列号+距离集）；对账恒等式 Σ_c e_c = E_total
    /// （批二权威 269,981）。裁决口径（保守：含掩蔽列在内的全体列最坏读法，
    /// 不依赖结构化/无结构分类）：max e_c ≤ 31 ⟹ K_max=8 机器验证成立；
    /// ≤ 255 ⟹「单次深度欠定」句成立。仅装配不证明。
    #[test]
    fn r7_percol_opening_census() {
        let w = test_witness();
        let (asm, _) = assemble_full_statement_with_hooks(&w);
        let mut pairs: std::collections::BTreeSet<(usize, i64)> = Default::default();
        for cc in &asm.info.constraints {
            for q in cc.used_query() {
                pairs.insert((q.poly(), q.rotation().0 as i64));
            }
        }
        let mut per_col: std::collections::BTreeMap<usize, u128> = Default::default();
        let mut col_dists: std::collections::BTreeMap<usize, std::collections::BTreeSet<u64>> =
            Default::default();
        for &(c, d) in &pairs {
            *per_col.entry(c).or_insert(0) += 1u128 << d.abs();
            col_dists.entry(c).or_default().insert(d.abs() as u64);
        }
        let total: u128 = per_col.values().sum();
        let maxc = *per_col.values().max().unwrap();
        let n_cols = per_col.len();
        let mut hist: std::collections::BTreeMap<u128, usize> = Default::default();
        for &e in per_col.values() {
            *hist.entry(e).or_insert(0) += 1;
        }
        println!(
            "[r7-percol] 查询列数={n_cols} Σe_c={total} max_e_c={maxc} 均值={}",
            total / n_cols as u128
        );
        for (e, n) in hist.iter().rev() {
            println!("[r7-percol][hist] e_c={e} × {n} 列");
        }
        let mut ranked: Vec<(usize, u128)> = per_col.iter().map(|(&c, &e)| (c, e)).collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        for (c, e) in ranked.iter().take(50) {
            let ds: Vec<u64> = col_dists[c].iter().cloned().collect();
            println!("[r7-percol][top] col={c} e_c={e} dists={ds:?}");
        }
        // 对账恒等式：逐列总和必须精确等于批二 census E 权威值（结构漂移即爆）。
        assert_eq!(total, 271_209, "逐列 Σe_c 对账（2026-10-01 实测钉：A1″ 旧值 271,263 在 db0bbb3 实测已漂移至 271,209——历史批次未回写；本批零开口面增量）");

        // ===== 重列语义鉴定（Round7 #10 裁决证据）：双见证差分 + e_c 交叉表 =====
        // 判定逻辑：列的 4096 格点值在两个独立见证（id/sk/r/attrs 全异，见 e12）
        // 下相同 ⟹ 见证无关（常量/公开回声），其开口不泄漏见证信息；不同 ⟹
        // 见证承载列，其 e_c 才进入泄漏界。r*_sec := 见证承载列的 max e_c。
        let info = &asm.info;
        let n_inst = info.num_instances.len();
        let n_prep = info.preprocess_polys.len();
        let n_wit: usize = info.num_witness_polys.iter().sum();
        let n_sig = info.permutation_polys().len();
        println!(
            "[r7-percol][layout] inst={n_inst} prep={n_prep} wit={n_wit} sigma={n_sig} \
             poly边界: witness≈[{}, {})",
            n_inst + n_prep,
            n_inst + n_prep + n_wit
        );
        // 第二见证（与 e12 同式：id/sk/r/attrs 全异）
        let id16: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(13) ^ 0x5E);
        let mut id2 = [0u8; 32];
        id2[..16].copy_from_slice(&id16);
        let w2 = witness_from([0x0C0C, 0, 0, 0x0B0B], id2, [0x33, 0, 0, 0x44]);
        let (asm2, _) = assemble_full_statement_with_hooks(&w2);
        assert_eq!(asm.advice.len(), asm2.advice.len(), "两见证 advice 列数不一致");
        let wit_off = n_inst + n_prep;
        let fz = |v: &FpSM2| crate::sm2_params::fr_to_limbs(v) == [0u64; 4];
        let cols_differ = |c1: &Vec<FpSM2>, c2: &Vec<FpSM2>| {
            c1.iter()
                .zip(c2.iter())
                .any(|(a, b)| crate::sm2_params::fr_to_limbs(a) != crate::sm2_params::fr_to_limbs(b))
        };
        let mut sec_cols: Vec<(usize, u128)> = Vec::new(); // 见证承载 (poly, e_c)
        let mut sec_heavy: Vec<(usize, u128, usize)> = Vec::new(); // (poly, e_c, 非零格数)
        let mut n_sec = 0usize;
        for (idx, (c1, c2)) in asm.advice.iter().zip(asm2.advice.iter()).enumerate() {
            if !cols_differ(c1, c2) {
                continue;
            }
            n_sec += 1;
            let pc = wit_off + idx;
            if let Some(&e) = per_col.get(&pc) {
                sec_cols.push((pc, e));
                let nz = c1.iter().filter(|v| !fz(v)).count();
                sec_heavy.push((pc, e, nz));
            } else {
                sec_cols.push((pc, 0)); // 无查询的见证承载列
            }
        }
        let r_sec = sec_cols.iter().map(|&(_, e)| e).max().unwrap_or(0);
        println!(
            "[r7-percol][diff] 见证承载列={n_sec}（advice {} 列中），r*_sec=max e_c={r_sec}",
            asm.advice.len()
        );
        // 交叉表：见证承载列按 e_c 分档计数
        let mut sec_hist: std::collections::BTreeMap<u128, usize> = Default::default();
        for &(_, e) in &sec_cols {
            *sec_hist.entry(e).or_insert(0) += 1;
        }
        for (e, n) in sec_hist.iter().rev() {
            println!("[r7-percol][diff-hist] e_c={e} × {n} 见证承载列");
        }
        // 重开口见证承载列 Top-30（poly, e_c, 非零格数）
        sec_heavy.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        for &(pc, e, nz) in sec_heavy.iter().take(30) {
            println!("[r7-percol][diff-top] poly={pc} e_c={e} 非零格={nz}");
        }
        // 终局鉴定：重列在两个见证下的非零格位置与值（定位所属模块）
        let limb_hex4 = |v: &FpSM2| -> String {
            let l = crate::sm2_params::fr_to_limbs(v);
            format!("{:016x}", l[0])
        };
        for &(pc, e, _) in sec_heavy.iter().take(12) {
            let idx = pc - wit_off;
            let dump = |c: &Vec<FpSM2>| -> String {
                let cells: Vec<String> = c
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| !fz(v))
                    .take(4)
                    .map(|(i, v)| format!("@{i}={}", limb_hex4(v)))
                    .collect();
                cells.join(",")
            };
            println!(
                "[r7-percol][cells] poly={pc} e_c={e} w1[{}] w2[{}]",
                dump(&asm.advice[idx]),
                dump(&asm2.advice[idx])
            );
        }
        // 全量清点：全部见证承载重列（e_c≥289）的 (poly, e_c, 比特格位, w1 比特值)
        // ——比特格位聚类=所属分解件的行；值应全为 0/1。
        let mut bit_inv: Vec<(usize, u128, usize, u8)> = Vec::new();
        for &(pc, e, _) in sec_heavy.iter() {
            if e < 289 {
                continue;
            }
            let idx = pc - wit_off;
            let col = &asm.advice[idx];
            let nz: Vec<(usize, &FpSM2)> = col
                .iter()
                .enumerate()
                .filter(|(_, v)| !fz(v))
                .collect();
            let (cell, val) = match nz.len() {
                0 => (usize::MAX, 0u8),
                1 => {
                    let v = crate::sm2_params::fr_to_limbs(nz[0].1);
                    (nz[0].0, v[0] as u8)
                }
                _ => (nz[0].0, 9u8), // 多非零格标记
            };
            bit_inv.push((pc, e, cell, val));
        }
        bit_inv.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
        for &(pc, e, cell, val) in bit_inv.iter() {
            println!("[r7-percol][bitinv] poly={pc} e_c={e} 比特格={cell} w1值={val}");
        }
        let cells_set: std::collections::BTreeSet<usize> =
            bit_inv.iter().map(|&(_, _, c, _)| c).collect();
        println!(
            "[r7-percol][bitinv-summary] 见证承载重列={} 比特格聚类数={} 格位={:?}",
            bit_inv.len(),
            cells_set.len(),
            cells_set
        );
        // 比特格的秩归属（定位模块：SM3 行域/EC 循环行域/其他）
        {
            // 格→秩映射：nth_map[cell]=rank（BH LFSR 迭代序）。注意 rank_inverse
        // 是反方向（rank→cell，见 point_at_rank），勿混用（v1/v2 勘误源）。
        let inv = crate::sm3_compress::nth_map();
            let mut shown = std::collections::BTreeSet::new();
            for &c in cells_set.iter() {
                if c == usize::MAX || shown.contains(&c) {
                    continue;
                }
                shown.insert(c);
                let rk = if c < inv.len() { inv[c] } else { usize::MAX };
                println!("[r7-percol][bitrow] cell={c} rank={rk}");
            }
        }
        // 反向核查：256 个重列（e_c≥289）是否全部见证无关
        let heavy_witness_bearing = per_col
            .iter()
            .filter(|&(_, &e)| e >= 289)
            .filter(|&(pc, _)| {
                let idx = *pc - wit_off;
                idx < asm.advice.len() && cols_differ(&asm.advice[idx], &asm2.advice[idx])
            })
            .count();
        println!(
            "[r7-percol][heavy-check] e_c≥289 的 256 个重列中见证承载列数={heavy_witness_bearing}"
        );
    }

    /// Round7 #10a 攻击面实证（2026-09-07，拍板包 D1；续 [`r7_percol_opening_census`]）：
    /// 论文 §7.9 自身泄漏模型（转录公开 v_c(pts)=eq(pts,·)·w_c，去掩材料按设计
    /// 在转录内）下被动敌手的可达性机器实证。四层证据：
    /// ① **驱动源归因**：单变量差分（w_id/w_sk/w_r 三变体装配，提取即弃、同持
    ///    ≤2 装配）⟹ 旗标列/词列各由哪个见证分量驱动（id/sk/r 组合签名直方图）
    ///    ——严重度判据（Id 驱动=跨出示链接+注册表点泄露；r 驱动=仅单次锚泄漏）；
    /// ② **单比特旗标列一次除法逐位读出**（124 列，e_c∈{289,385,769,2305}）：
    ///    b = v₀/eq(pts₀,cell)，全 e_c 个方程一致性随行（模型自洽演示）；
    /// ③ **词列 K 次出示高斯消元精确恢复**（288 列，28–32 非零格、e_c∈{13,17,20}，
    ///    自适应 K≤4；支持集跨见证不变=公开结构前提断言）；
    /// ④ **结构归属（v2，2026-09-07）**：首跑证伪「词列=u32 词序列」模型
    ///    （匹配 0/288——实测词列=0/1 位道，非零值全 1）⟹ 改为 秩带分解
    ///    （体/块/行内偏移）+ 单平面性检验 + 约束族（ctag）归属；语义归属由
    ///    日志离线分析完成，禁在测试内做语义匹配（v1 教训）。
    /// ③″ **跨出示稳定性（D1 主实验）**：同凭证仅换 ElGamal 随机数 r 重装配
    ///    ⟹ 变化列 = r 承载面，不变列 = (Id_u,sk_u) 函数 = 跨出示指纹面。
    /// **结构语义定案（v3，2026-09-08）**：旗标列 = 尾体进口 V₂ 的 256 个词
    ///    位格列中两见证翻转的 124 位（zones=[&ZONE0,&ZONEB,&ZONE0] ⟹ 头尾
    ///    体共享 ZONE0，尾体进口 link 落 ZONE0.imp_row=秩 1336..1343=ZONE0
    ///    out 带 imp 槽；V₂=f(V₁,attrs‖pk_u.x)=f(Id_u,sk_u) 双变量函数零 r
    ///    ⟹ 直方 30/28/35/31≈均匀四分，none 类=单比特差分 50% 碰撞产物）；
    ///    每列恰 3 个旋转查询 (cur, d=8 折叠读, d∈{5,7,9,11} 负轮锚绑定)
    ///    ⟹ e_c∈{289,385,769,2305}=1+2⁸+2^{5,7,9,11}（按 (行−1336) mod 4
    ///    周期）。词列=TT2 位道（288=体C id 驱动+体D/E sk 驱动，3×96 三族）。
    ///    r 承载面=72 轻列不进重/词档。证据日志 v3：
    ///    `M3_probe/logs_zk/r7_percol_attack_v3_2026-09-08.txt`。
    /// 另产出轻列稀疏交叉表（拍板 D4 备索）。仅装配不证明；确定性开口点
    /// （splitmix64，4×63bit=252<p 规范）保证可复现。首跑记账→数字冻结→升格断言。
    #[test]
    fn r7_percol_attack_face() {
        use ff::Field as _;
        use std::collections::{BTreeMap, BTreeSet};

        // ── 本地工具 ─────────────────────────────────────────────────────
        /// 确定性伪随机流（splitmix64；禁 OsRng——测试须可复现）。
        struct SplitMix(u64);
        impl SplitMix {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }
        }
        fn is_z(v: &FpSM2) -> bool {
            crate::sm2_params::fr_to_limbs(v) == [0u64; 4]
        }
        fn fr(v: &FpSM2) -> [u64; 4] {
            crate::sm2_params::fr_to_limbs(v)
        }
        /// 随机开口点分量：4×63bit=252<p ⟹ 规范元（不依赖 from_raw 语义）。
        fn rnd_fp(sm: &mut SplitMix) -> FpSM2 {
            crate::sm2_params::fr_from_limbs(&[
                sm.next() >> 1,
                sm.next() >> 1,
                sm.next() >> 1,
                sm.next() >> 1,
            ])
        }
        fn new_pts(sm: &mut SplitMix) -> [FpSM2; 12] {
            let mut out = [FpSM2::ZERO; 12];
            for v in out.iter_mut() {
                *v = rnd_fp(sm);
            }
            out
        }
        /// eq(·,cell)：12 变元乘积（变量序约定 bit j = (cell>>j)&1）。恒等式
        /// v_c(pts)=Σ_cell w_c(cell)·eq(pts,cell) 对任意 eq 基成立 ⟹ 与后端
        /// 变量序无关，演示自洽。
        fn eq_at(pts: &[FpSM2; 12], cell: usize) -> FpSM2 {
            let mut acc = FpSM2::ONE;
            for j in 0..12 {
                let term = if (cell >> j) & 1 == 1 { pts[j] } else { FpSM2::ONE - pts[j] };
                acc = acc * term;
            }
            acc
        }
        /// 精确高斯消元（增广矩阵 n 元；满秩唯一解或 None）。
        fn solve_fp(mut a: Vec<Vec<FpSM2>>, n: usize) -> Option<Vec<FpSM2>> {
            for col in 0..n {
                let piv = (col..a.len()).find(|&r| !is_z(&a[r][col]))?;
                a.swap(col, piv);
                let inv = a[col][col].invert().unwrap();
                for v in a[col].iter_mut() {
                    *v = *v * inv;
                }
                for r in 0..a.len() {
                    if r != col && !is_z(&a[r][col]) {
                        let f = a[r][col];
                        for c in col..a[r].len() {
                            let t = a[col][c] * f;
                            a[r][c] = a[r][c] - t;
                        }
                    }
                }
            }
            // 消元后第 col 行主元=1 且前列全零 ⟹ 解 x[col]=a[col][n]；
            // 多余行（秩亏方向）rhs 必须为零。
            for r in n..a.len() {
                if !is_z(&a[r][n]) {
                    return None;
                }
            }
            Some((0..n).map(|col| a[col][n]).collect())
        }
        // ── ① 基线两见证装配 + census 复用（对账锚） ─────────────────────
        let w1 = test_witness();
        let (asm, _) = assemble_full_statement_with_hooks(&w1);
        let info = &asm.info;
        let wit_off = info.num_instances.len() + info.preprocess_polys.len();
        let mut pairs: BTreeSet<(usize, i64)> = Default::default();
        for cc in &info.constraints {
            for q in cc.used_query() {
                pairs.insert((q.poly(), q.rotation().0 as i64));
            }
        }
        let mut per_col: BTreeMap<usize, u128> = Default::default();
        for &(c, d) in &pairs {
            *per_col.entry(c).or_insert(0) += 1u128 << d.abs();
        }
        let total: u128 = per_col.values().sum();
        assert_eq!(total, 271_209, "Σe_c 对账（2026-10-01 实测钉：旧钉 271,263 在 db0bbb3 实测已漂移至 271,209——历史批次未回写；本批零增量）");

        let id16: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(13) ^ 0x5E);
        let mut id2 = [0u8; 32];
        id2[..16].copy_from_slice(&id16);
        let w2 = witness_from([0x0C0C, 0, 0, 0x0B0B], id2, [0x33, 0, 0, 0x44]);
        let (asm2, _) = assemble_full_statement_with_hooks(&w2);
        assert_eq!(asm.advice.len(), asm2.advice.len(), "两见证列数一致");

        let cols_differ = |c1: &Vec<FpSM2>, c2: &Vec<FpSM2>| {
            c1.iter().zip(c2.iter()).any(|(a, b)| fr(a) != fr(b))
        };
        let nz_cells = |col: &Vec<FpSM2>| -> Vec<usize> {
            col.iter().enumerate().filter(|(_, v)| !is_z(v)).map(|(i, _)| i).collect()
        };

        // 见证承载集合（w1↔w2 差分）+ 分档
        let mut wb: Vec<usize> = Vec::new();
        for (idx, (c1, c2)) in asm.advice.iter().zip(asm2.advice.iter()).enumerate() {
            if cols_differ(c1, c2) {
                wb.push(idx);
            }
        }
        assert_eq!(wb.len(), 6_024, "见证承载列总数（2026-10-01 实测钉：A1″ 旧值 6,055 在 db0bbb3 实测已漂移至 6,024——历史批次未回写；本批零见证面增量）");
        let mut heavy_wb: Vec<usize> = Vec::new(); // e_c≥289（旗标列）
        let mut word_wb: Vec<usize> = Vec::new(); // e_c∈{13,17,20}（词列）
        for &idx in &wb {
            let e = *per_col.get(&(wit_off + idx)).unwrap_or(&0);
            if e >= 289 {
                heavy_wb.push(idx);
            } else if e == 13 || e == 17 || e == 20 {
                word_wb.push(idx);
            }
        }
        assert_eq!(heavy_wb.len(), 124, "见证承载重列数（census 冻结）");
        assert_eq!(word_wb.len(), 288, "词列数（census 冻结）");

        // 旗标结构冻结（census 实测口径：63 列 w1 位=0 ⟹ 整列全零；支持格=
        // union(w1,w2) 的唯一格——两见证该位互补翻转，支持格为结构量不变）：
        // |union|=1 + 值∈{0,1} + 两见证互补 + 8 聚类支持行。
        let mut flag_of: BTreeMap<usize, (usize, u8)> = BTreeMap::new();
        let mut flag_cells: BTreeSet<usize> = BTreeSet::new();
        let mut struct_sup: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for &idx in &heavy_wb {
            let nz1: BTreeSet<usize> = nz_cells(&asm.advice[idx]).into_iter().collect();
            let nz2: BTreeSet<usize> = nz_cells(&asm2.advice[idx]).into_iter().collect();
            let uni: Vec<usize> = nz1.union(&nz2).cloned().collect();
            assert_eq!(uni.len(), 1, "旗标列支持集 union 必须单格 idx={idx} w1={nz1:?} w2={nz2:?}");
            let cell = uni[0];
            let bit1 = fr(&asm.advice[idx][cell])[0] as u8;
            let bit2 = fr(&asm2.advice[idx][cell])[0] as u8;
            assert!(bit1 <= 1 && bit2 <= 1, "旗标值∈{{0,1}} idx={idx} {bit1}/{bit2}");
            assert_ne!(bit1, bit2, "两见证旗标位必须互补翻转 idx={idx}");
            flag_cells.insert(cell);
            flag_of.insert(idx, (cell, bit1));
            struct_sup.insert(idx, BTreeSet::from([cell]));
        }
        let want_cells: BTreeSet<usize> =
            [161usize, 322, 644, 1139, 1288, 2169, 2576, 3093].into_iter().collect();
        assert_eq!(flag_cells, want_cells, "旗标支持格 8 聚类（census 冻结）");

        // 词列结构冻结：w1 非零格 28–32（census 实测）；union 结构集分布=
        // 观测记账（首跑实测形态多样，二跑按直方冻结界）。
        let mut word_union_hist: BTreeMap<usize, usize> = BTreeMap::new();
        let mut word_nz_hist: BTreeMap<usize, usize> = BTreeMap::new();
        for &idx in &word_wb {
            let nz = nz_cells(&asm.advice[idx]).len();
            *word_nz_hist.entry(nz).or_insert(0) += 1;
            let uni: BTreeSet<usize> = nz_cells(&asm.advice[idx])
                .into_iter()
                .chain(nz_cells(&asm2.advice[idx]))
                .collect();
            *word_union_hist.entry(uni.len()).or_insert(0) += 1;
            struct_sup.insert(idx, uni);
        }

        // 支持集跨见证不变（公开结构前提）：旗标列=union 单格已断言；词列=
        // 两见证非零格均 ⊆ 同一结构集（位翻转改变非零格集合，但格候选集不变）。
        for &idx in &heavy_wb {
            let uni = &struct_sup[&idx];
            assert!(
                nz_cells(&asm2.advice[idx]).iter().all(|c| uni.contains(c)),
                "旗标支持集跨见证一致 idx={idx}"
            );
        }
        println!("[r7-attack][word-union] 词列 union 结构集大小直方 {word_union_hist:?}");
        println!("[r7-attack][word-nz] 词列 w1 非零格数直方 {word_nz_hist:?}");
        drop(asm2); // 内存纪律：同持 ≤2 装配

        // ── ①′ 单变量差分归因（三变体，提取即弃） ────────────────────────
        let id16v: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ 0x77);
        let mut id_v = [0u8; 32];
        id_v[..16].copy_from_slice(&id16v);
        let variants: [(&str, FullStatementWitness); 3] = [
            ("id", witness_from(w1.sk_u, id_v, w1.r)),
            ("sk", witness_from([0x0D0D, 0, 0, 0x0C0C], w1.id_u, w1.r)),
            ("r", witness_from(w1.sk_u, w1.id_u, [0x55, 0, 0, 0x66])),
        ];
        // 驱动签名：(id?, sk?, r?)——列在对应单变体下是否变化
        let heavy_set: BTreeSet<usize> = heavy_wb.iter().cloned().collect();
        let mut sig: BTreeMap<usize, (bool, bool, bool)> = BTreeMap::new();
        for &idx in heavy_wb.iter().chain(word_wb.iter()) {
            sig.insert(idx, (false, false, false));
        }
        let mut flag_vbits: BTreeMap<usize, [u8; 3]> = BTreeMap::new(); // 旗标位 (id,sk,r) 变体观测
        for (vi, (tag, wv)) in variants.iter().enumerate() {
            let (asmv, _) = assemble_full_statement_with_hooks(wv);
            assert_eq!(asmv.advice.len(), asm.advice.len(), "变体 {tag} 列数一致");
            for &idx in heavy_wb.iter().chain(word_wb.iter()) {
                // 旗标列：单格结构集（位翻转不越界）。词列：位格候选集大于
                // 两见证 union（id 变体新模式合法越界，实测 756），不做越界断言。
                if heavy_set.contains(&idx) {
                    assert!(
                        nz_cells(&asmv.advice[idx]).iter().all(|c| struct_sup[&idx].contains(c)),
                        "变体 {tag} 旗标支持集越界 idx={idx}"
                    );
                    let (cell_v, _) = flag_of[&idx];
                    flag_vbits.entry(idx).or_insert([0u8; 3])[vi] =
                        fr(&asmv.advice[idx][cell_v])[0] as u8;
                }
                let d = cols_differ(&asm.advice[idx], &asmv.advice[idx]);
                let e = sig.get_mut(&idx).expect("已初始化");
                match *tag {
                    "id" => e.0 |= d,
                    "sk" => e.1 |= d,
                    _ => e.2 |= d,
                }
            }
            drop(asmv);
        }
        let class_name = |s: (bool, bool, bool)| -> &'static str {
            match s {
                (true, false, false) => "id",
                (false, true, false) => "sk",
                (false, false, true) => "r",
                (true, true, false) => "id+sk",
                (true, false, true) => "id+r",
                (false, true, true) => "sk+r",
                (true, true, true) => "id+sk+r",
                (false, false, false) => "none(仅w1w2差)",
            }
        };
        let mut flag_cls: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut word_cls: BTreeMap<&'static str, usize> = BTreeMap::new();
        // 格→秩映射：nth_map[cell]=rank（BH LFSR 迭代序）。注意 rank_inverse
        // 是反方向（rank→cell，见 point_at_rank），勿混用（v1/v2 勘误源）。
        let inv = crate::sm3_compress::nth_map();
        let none_set: BTreeSet<usize> = heavy_wb
            .iter()
            .cloned()
            .filter(|&i| sig[&i] == (false, false, false))
            .collect();
        let word_set: BTreeSet<usize> = word_wb.iter().cloned().collect();
        // 约束族（ctag）归属：列 → 触及该列的约束标签集（ctags 按约束索引）。
        let mut poly_ctags: BTreeMap<usize, BTreeSet<&str>> = BTreeMap::new();
        for (ci, cc) in info.constraints.iter().enumerate() {
            for q in cc.used_query() {
                let t: &str = &asm.ctags[ci];
                poly_ctags.entry(q.poly()).or_default().insert(t);
            }
        }
        // 行内偏移名（sm3_compress_v2 off/ooff 两模块正典偏移；其余=未命名格）。
        let off_names: [(usize, &str); 13] = [
            (crate::sm3_compress_v2::ooff::NEG_T1, "NEG_T1"),
            (off::FF, "FF"),
            (crate::sm3_compress_v2::ooff::NEG_PN, "NEG_PN"),
            (off::TT1, "TT1"),
            (off::SS2, "SS2"),
            (off::SS1PRE, "SS1PRE"),
            (crate::sm3_compress_v2::ooff::IMP, "IMP"),
            (off::TT2, "TT2"),
            (off::EPARK, "EPARK"),
            (off::WORG, "WORG"),
            (off::GG, "GG"),
            (off::STG, "STG"),
            (off::WD4, "WD4"),
        ];
        let off_name = |o: usize| -> String {
            off_names
                .iter()
                .find(|(v, _)| *v == o)
                .map(|(_, n)| (*n).to_string())
                .unwrap_or_else(|| format!("o{o}"))
        };
        // 秩 → (体, 块, 行内偏移) 解码：zb 0=lo 带 / 1..3=体C..E / 4=自由带 /
        // 9=未入秩表。条带带=[RANK_BASE_V2, RANK_BASE_V2+3·ZONE_STRIDE)，
        // 每体 68 块×16 行 +32 出口行（出口行编码 ro≥100）。
        let body_name = |zb: u8| -> &'static str {
            match zb {
                0 => "lo",
                1 => "C",
                2 => "D",
                3 => "E",
                4 => "free",
                _ => "unranked",
            }
        };
        let zone_of = |rk: usize| -> (u8, u16, i32) {
            if rk == usize::MAX {
                return (9, 0, -1);
            }
            if rk < RANK_BASE_V2 {
                return (0, rk as u16, -1);
            }
            let rel = rk - RANK_BASE_V2;
            let (zb, r2) = (rel / ZONE_STRIDE, rel % ZONE_STRIDE);
            if zb >= 3 {
                return (4, 0, rel as i32);
            }
            if r2 >= NUM_STRIPES * H_STRIPE {
                (zb as u8 + 1, 0xFFFF, (r2 - NUM_STRIPES * H_STRIPE + 100) as i32)
            } else {
                (zb as u8 + 1, (r2 / H_STRIPE) as u16, (r2 % H_STRIPE) as i32)
            }
        };
        let fmt_cell = |(zb, blk, ro): (u8, u16, i32)| -> String {
            match zb {
                1..=3 if blk == 0xFFFF => format!("{}out{}", body_name(zb), ro - 100),
                1..=3 => format!("{}.b{}/{}", body_name(zb), blk, off_name(ro.max(0) as usize)),
                _ => {
                    if ro < 0 {
                        format!("{}@{blk}", body_name(zb))
                    } else {
                        format!("{}@{ro}", body_name(zb))
                    }
                }
            }
        };
        // 位平面类键：(体, 行内偏移)（同键每块至多一格 ⟹ 格数=块覆盖数）。
        let plane_key = |zb: u8, ro: i32| -> String {
            if (1..=3).contains(&zb) && (0..16).contains(&ro) {
                format!("{}:{}", body_name(zb), off_name(ro as usize))
            } else {
                format!("zone{zb}@{ro}")
            }
        };
        let band_end = RANK_BASE_V2 + 3 * ZONE_STRIDE;
        let zrc = |t: usize, o: usize| -> (usize, usize) {
            (ZONE0.base + t * H_STRIPE + o, ZONE0.stripe_row(t, o))
        };
        let (r0, c0) = zrc(0, off::SS1PRE);
        let (r1, c1) = zrc(1, off::SS1PRE);
        let (r63, c63) = zrc(63, off::SS1PRE);
        let (rt2, ct2) = zrc(0, off::TT2);
        println!(
            "[r7-attack][geom] rank↔cell: b0/SS1PRE {r0}↔{c0} b1/SS1PRE {r1}↔{c1} b63/SS1PRE {r63}↔{c63} b0/TT2 {rt2}↔{ct2}；三体条带带(rank)=[{RANK_BASE_V2},{band_end}), 每体={} 行, 自由带(rank)>{band_end}",
            ZONE_STRIDE,
        );
        let mut flag_cell_cls: BTreeMap<usize, BTreeMap<&'static str, usize>> = BTreeMap::new();
        let mut flag_loc_hist: BTreeMap<String, usize> = BTreeMap::new();
        let mut flag_ctag_hist: BTreeMap<String, usize> = BTreeMap::new();
        for &idx in heavy_wb.iter().chain(word_wb.iter()) {
            let cls = class_name(sig[&idx]);
            let pc = wit_off + idx;
            let e = per_col[&pc];
            if heavy_set.contains(&idx) {
                *flag_cls.entry(cls).or_insert(0) += 1;
                let (cell, b) = flag_of[&idx];
                let rk = if cell < inv.len() { inv[cell] } else { usize::MAX };
                let loc = fmt_cell(zone_of(rk));
                let vb = flag_vbits.get(&idx).copied().unwrap_or([0u8; 3]);
                let ct: String = poly_ctags
                    .get(&pc)
                    .map(|s| s.iter().copied().collect::<Vec<_>>().join("+"))
                    .unwrap_or_default();
                println!(
                    "[r7-attack][flag] poly={pc} e_c={e} cell={cell} rank={rk} loc={loc} w1位={b} v(id,sk,r)=({},{},{}) 驱动={cls} ctag={ct}",
                    vb[0], vb[1], vb[2]
                );
                *flag_cell_cls.entry(cell).or_default().entry(cls).or_insert(0) += 1;
                *flag_loc_hist.entry(loc).or_insert(0) += 1;
                *flag_ctag_hist.entry(ct).or_insert(0) += 1;
            } else {
                *word_cls.entry(cls).or_insert(0) += 1;
            }
        }
        println!("[r7-attack][cls-flag] 旗标驱动直方 {flag_cls:?}");
        println!("[r7-attack][cls-word] 词列驱动直方 {word_cls:?}");
        // 二轮冻结（v3 复现 2026-09-08 [实测]）：语义定案——旗标列=体E 进口
        // V₂ 词位格列（zones=[&ZONE0,&ZONEB,&ZONE0] ⟹ 头尾体共享 ZONE0，尾体
        // 进口 link 落 ZONE0.imp_row=1336..1343；V₂=f(V₁,attrs‖pk_u.x)=
        // f(Id_u,sk_u) 双变量函数零 r）。f 的双变量均匀位分布 ⟹ 四类直方
        // 各≈31（±4）；none 类=单比特差分 50% 碰撞率的必然产物，非独立语义。
        assert_eq!(
            flag_cls,
            BTreeMap::from([
                ("id", 30usize),
                ("id+sk", 28),
                ("none(仅w1w2差)", 35),
                ("sk", 31),
            ]),
            "旗标驱动直方漂移（V₂=f(Id,sk) 位差分归因）"
        );
        assert_eq!(
            word_cls,
            BTreeMap::from([("id", 96usize), ("id+sk", 160), ("sk", 32)]),
            "词列驱动直方漂移（TT2 位道，A1″ 2026-09-09 实测 96/160/32：第三块含 parity 后 32 列 id 分量显化）"
        );
        for (cell, m) in &flag_cell_cls {
            let rk = if *cell < inv.len() { inv[*cell] } else { usize::MAX };
            let det: String =
                m.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ");
            println!("[r7-attack][flag-xtab] cell={cell} loc={} 驱动 {det}", fmt_cell(zone_of(rk)));
        }
        println!("[r7-attack][flag-loc] 旗标落位直方 {flag_loc_hist:?}");
        assert_eq!(
            flag_loc_hist,
            BTreeMap::from([
                ("Cout8".to_string(), 13usize),
                ("Cout9".to_string(), 19),
                ("Cout10".to_string(), 17),
                ("Cout11".to_string(), 16),
                ("Cout12".to_string(), 16),
                ("Cout13".to_string(), 10),
                ("Cout14".to_string(), 19),
                ("Cout15".to_string(), 14),
            ]),
            "旗标落位直方漂移（8 行=ZONE0 out 带 imp 槽 1336..1343=体E 进口 V₂ 词位行）"
        );
        println!("[r7-attack][flag-ctag] 旗标约束族直方 {flag_ctag_hist:?}");
        assert_eq!(
            flag_ctag_hist,
            BTreeMap::from([(
                "assert.zero+link.bool+link.recomp+xor".to_string(),
                124usize
            )]),
            "旗标约束族漂移（三族消费：进口 link cur / d=8 折叠读 / d∈{{5,7,9,11}} 负轮锚绑定）"
        );

        // ── ② 旗标列：单次出示一次除法逐位读出（全方程一致性随行） ────────
        for &idx in &heavy_wb {
            let &(cell, b_act) = flag_of.get(&idx).expect("旗标登记");
            let pc = wit_off + idx;
            let e_c = per_col[&pc];
            let col = &asm.advice[idx];
            let mut sm2 = SplitMix(0x5EED_2026_09A7_u64 ^ (pc as u64));
            let pts0 = new_pts(&mut sm2);
            let eq0 = eq_at(&pts0, cell);
            assert!(!is_z(&eq0), "eq 权重零退化 pc={pc}");
            let v0 = eq0 * col[cell]; // 敌手读到的转录值
            let b_rec = v0 * eq0.invert().unwrap(); // 一次除法
            assert_eq!(
                fr(&b_rec),
                fr(&col[cell]),
                "一次除法恢复失败 pc={pc}（实际位={b_act}）"
            );
            assert_eq!(fr(&b_rec)[0], u64::from(b_act), "恢复位≠见证位 pc={pc}");
            // 其余 e_c−1 方程全部一致（单次出示 2,305 方程 vs 1 比特——超定演示）
            for _ in 1..e_c {
                let pts = new_pts(&mut sm2);
                let ej = eq_at(&pts, cell);
                let vj = ej * col[cell];
                assert_eq!(fr(&vj), fr(&(ej * b_rec)), "方程不一致 pc={pc}");
            }
        }
        println!("[r7-attack][flag-recover] 124 旗标列全部一次除法恢复+全方程一致 ✓");

        // ── ③ 词列：K 次出示高斯消元精确恢复（自适应 K≤4） ────────────────
        let mut k_hist: BTreeMap<usize, usize> = BTreeMap::new();
        let mut span_hist: BTreeMap<(usize, usize), usize> = BTreeMap::new(); // (行跨度, |sup|)
        for &idx in &word_wb {
            let pc = wit_off + idx;
            let e_c = per_col[&pc];
            let col = &asm.advice[idx];
            let sup = nz_cells(col);
            let span = sup[sup.len() - 1] - sup[0] + 1;
            *span_hist.entry((span, sup.len())).or_insert(0) += 1;
            let n = sup.len();
            let mut sm2 = SplitMix(0xBEEF_2026_09A7_u64 ^ (pc as u64));
            let mut rows: Vec<Vec<FpSM2>> = Vec::new();
            let mut k_used = 0usize;
            for k in 1..=4usize {
                k_used = k;
                for _ in 0..e_c {
                    let pts = new_pts(&mut sm2);
                    let mut row = Vec::with_capacity(n + 1);
                    let mut rhs = FpSM2::ZERO;
                    for &cell in &sup {
                        let e = eq_at(&pts, cell);
                        row.push(e);
                        rhs = rhs + e * col[cell];
                    }
                    row.push(rhs);
                    rows.push(row);
                }
                if rows.len() >= n {
                    if let Some(x) = solve_fp(rows.clone(), n) {
                        for (t, &cell) in sup.iter().enumerate() {
                            assert_eq!(fr(&x[t]), fr(&col[cell]), "词列恢复失配 pc={pc}");
                        }
                        break;
                    }
                }
            }
            assert!(k_used <= 4, "词列 K≤4 未解出 pc={pc}");
            *k_hist.entry(k_used).or_insert(0) += 1;
        }
        println!("[r7-attack][word-recover] 288 词列全部精确恢复，K 分布 {k_hist:?}");
        println!("[r7-attack][word-span] (行跨度,|sup|) 直方 {span_hist:?}");

        // ── ③″ 跨出示稳定性（D1 主实验）：同凭证仅换 ElGamal 随机数 r 重装配 ─
        // e 不消费 r ⟹ e/r_s/s_s/pk_u/apk 全同；差分变化列 = r 承载面，
        // 不变列 = (Id_u, sk_u) 的函数 = 跨出示指纹面（§7.9 头条口径）。
        let w1b = witness_from(w1.sk_u, w1.id_u, [0x77, 0, 0, 0x88]);
        let (asm3, _) = assemble_full_statement_with_hooks(&w1b);
        let mut xpre_stable = 0usize;
        let mut xpre_unstable = 0usize;
        let (mut st_flag, mut uns_flag, mut st_none, mut st_word) =
            (0usize, 0usize, 0usize, 0usize);
        for &idx in &wb {
            let is_flag = heavy_set.contains(&idx);
            let is_word = word_set.contains(&idx);
            if cols_differ(&asm.advice[idx], &asm3.advice[idx]) {
                xpre_unstable += 1;
                if is_flag {
                    uns_flag += 1;
                }
            } else {
                xpre_stable += 1;
                if is_flag {
                    st_flag += 1;
                    if none_set.contains(&idx) {
                        st_none += 1;
                    }
                } else if is_word {
                    st_word += 1;
                }
            }
        }
        drop(asm3); // 内存纪律：同持 ≤2 装配
        println!(
            "[r7-attack][xpres] 同凭证仅换 r：稳定={xpre_stable}/{} 不稳定={xpre_unstable} | 旗标稳定 {st_flag}/124（不稳定 {uns_flag}）| 词列稳定 {st_word}/288 | none 旗标稳定 {st_none}/{}",
            wb.len(),
            none_set.len()
        );
        // 二轮冻结（v3 复现 [实测]）：r 承载面=72 轻列（r 位差 8 位（limb 差）
        // + c1/rapk 循环 acc 值列 + 范围门中间值，e_c 全小）；旗标/词列全稳
        // 定 ⟹ 412 个重/词列全部=(Id_u,sk_u) 函数=跨出示指纹面（§7.9 头条口径）。
        assert_eq!(xpre_stable, 5_960, "xpres 稳定列数漂移（2026-10-01 实测钉：A1″ 旧值 5,983 在 db0bbb3 实测已漂移至 5,960——历史批次未回写；本批零增量）");
        assert_eq!(xpre_unstable, 64, "xpres r 承载面（轻列）漂移（2026-10-01 实测钉：旧值 72 在 db0bbb3 已漂移——历史批次未回写；本批零见证面增量）");
        assert_eq!(st_flag, 124, "旗标 xpres 稳定数漂移（V₂ 同凭证恒同）");
        assert_eq!(uns_flag, 0, "旗标 r 不稳定数漂移（必须为零）");
        assert_eq!(st_word, 288, "词列 xpres 稳定数漂移");
        assert_eq!(st_none, none_set.len(), "none 类旗标 xpres 稳定数漂移");

        // ── ④ 结构归属（v2）：位平面性检验 + (体,块,偏移) 分解 + 约束族 ────
        // 语义归属由日志离线分析完成，禁在测试内做语义匹配（v1 教训：
        // 「词列=u32 词序列」模型已证伪 0/288——词列实态=0/1 位道）。
        let mut word_plane_hist: BTreeMap<usize, usize> = BTreeMap::new();
        let mut word_ctag_hist: BTreeMap<String, usize> = BTreeMap::new();
        let mut shown = 0usize;
        for &idx in &word_wb {
            let pc = wit_off + idx;
            let e_c = per_col[&pc];
            let nz = nz_cells(&asm.advice[idx]);
            let mut cls_cnt: BTreeMap<String, usize> = BTreeMap::new();
            for &cell in &nz {
                let rk = if cell < inv.len() { inv[cell] } else { usize::MAX };
                let (zb, _blk, ro) = zone_of(rk);
                *cls_cnt.entry(plane_key(zb, ro)).or_insert(0) += 1;
            }
            *word_plane_hist.entry(cls_cnt.len()).or_insert(0) += 1;
            let ct: String = poly_ctags
                .get(&pc)
                .map(|s| s.iter().copied().collect::<Vec<_>>().join("+"))
                .unwrap_or_default();
            *word_ctag_hist.entry(ct.clone()).or_insert(0) += 1;
            if shown < 24 {
                shown += 1;
                let det: String = cls_cnt
                    .iter()
                    .map(|(k, n)| format!("{k}×{n}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("[r7-attack][word-loc] poly={pc} e_c={e_c} ctag={ct} 道分布 {det}");
            }
        }
        // 观测段（首跑记账）：前 8 个词列的结构（行范围+非零格值序列）——
        // 判定词列=「32 位行段」假设是否成立，供二跑冻结匹配口径。
        for &idx in word_wb.iter().take(8) {
            let pc = wit_off + idx;
            let sup = nz_cells(&asm.advice[idx]);
            let vs: Vec<String> = sup
                .iter()
                .map(|&c| {
                    let l = fr(&asm.advice[idx][c]);
                    format!("@{c}:{:x}", l[0])
                })
                .collect();
            println!(
                "[r7-attack][word-obs] poly={pc} 行[{},{}] 非零格={}",
                sup[0],
                sup[sup.len() - 1],
                vs.join(" ")
            );
        }
        println!("[r7-attack][word-plane] 每列 (体,偏移) 道类数直方 {word_plane_hist:?}");
        assert_eq!(
            word_plane_hist,
            BTreeMap::from([(1usize, 288usize)]),
            "词列单平面性漂移（每列恰 1 个 (体,TT2) 位道）"
        );
        println!("[r7-attack][word-ctag] 词列约束族直方 {word_ctag_hist:?}");
        assert_eq!(
            word_ctag_hist,
            BTreeMap::from([
                ("add.main+choose+link.bool+link.recomp+xor".to_string(), 96usize),
                ("add.main+link.bool+link.recomp+maj+xor".to_string(), 96),
                ("add.main+xor".to_string(), 96),
            ]),
            "词列约束族漂移（3×96 三族）"
        );

        // ── ⑤ 轻列稀疏交叉表（拍板 D4 备索：见证承载列 e_c × 非零格数） ──
        let mut xtab: BTreeMap<u128, BTreeMap<usize, usize>> = BTreeMap::new();
        for &idx in &wb {
            let e = *per_col.get(&(wit_off + idx)).unwrap_or(&0);
            let nz = nz_cells(&asm.advice[idx]).len();
            *xtab.entry(e).or_default().entry(nz).or_insert(0) += 1;
        }
        for (e, m) in &xtab {
            let s: String = m
                .iter()
                .map(|(nz, n)| format!("nz{nz}×{n}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!("[r7-attack][xtab] e_c={e} 列数={} {s}", m.values().sum::<usize>());
        }
        println!("[r7-attack] 完成：六件套（归因/旗标恢复/词列恢复/跨出示稳定性/结构归属/交叉表）");
    }
    // ── P2 差分门 2：SM3_LUT 织入语句语义不变（同见证双形态实例面逐位相同）──


        #[test]
        fn sm3_lut_weave_instances_identical_to_legacy() {
            // pred 见证：witness_from_pred_commit_with_attrs 同链自洽签名
            // （test_witness 是 T1 报文签名——对 pred 加盐报文验签必败）
            let salt = [0x5au8; 16];
            let schema_seg: [u8; 28] = {
                let mut sg = [0u8; 28];
                sg.copy_from_slice(&PRED_TARGET[4..32]);
                sg
            };
            let attrs = {
                let mut a = [0u8; 32];
                a[..4].copy_from_slice(&1_000_005u32.to_be_bytes());
                a[4..].copy_from_slice(&schema_seg);
                a
            };
            let w = witness_from_pred_commit_with_attrs(
                [1, 0, 0, 0],
                [0x11u8; 32],
                [2, 0, 0, 0],
                1_760_000_000,
                salt,
                attrs,
            );
            let schema_seg_ref = schema_seg;
            let schema_seg: [u8; 28] = {
                let mut s = [0u8; 28];
                s.copy_from_slice(&PRED_TARGET[4..32]);
                s
            };
            // 独立复算：见证签名对 host_commit 报文必须真（定位失败层）
            {
                let host = full_statement_host_commit_of(&w, &salt);
                let c = crate::sm3_native_ref::compress;
                let v1 = c(&crate::sm3_native_ref::IV, &host.blocks[0]);
                let v2 = c(&v1, &host.blocks[1]);
                let dg = c(&v2, &host.blocks[2]);
                let e = fold_digest_fp(&dg);
                let ok = crate::sm2_verify_assemble::verify_replay(
                    e,
                    crate::sm2_params::fr_from_limbs(&w.r_s),
                    crate::sm2_params::fr_from_limbs(&w.s_s),
                    w.pk_i.0,
                    w.pk_i.1,
                )
                .ok;
                eprintln!("[gate2-dbg] dg={:08x?} ok={ok}", dg);
                eprintln!("[gate2-dbg] r_s={:08x?} s_s={:08x?}", w.r_s, w.s_s);
                assert!(ok, "独立验签失败=见证构造层问题");
            }
            let build = |lut: bool| -> (usize, Vec<Vec<FpSM2>>, usize) {
                std::env::set_var("SM3_LUT", if lut { "1" } else { "0" });
                let (asm, _h) = assemble_full_statement_pred_range(
                    &w,
                    salt,
                    1_000_000,
                    schema_seg_ref,
                    0x5344_4154,
                    FpSM2::from(0xdead_beefu64),
                    FpSM2::from(0x1234_5678u64),
                    1_760_000_000,
                );
                (
                    asm.info.lookups.len(),
                    asm.instances.clone(),
                    asm.info.constraints.len(),
                )
            };
            let (lk_l, inst_l, c_l) = build(false);
            let (lk_u, inst_u, c_u) = build(true);
            // LUT 形态环值审计 + mock 三面（环冲突的等值性诊断）
            std::env::set_var("SM3_LUT", "1");
            let (asm_u, _h2) = assemble_full_statement_pred_range(
                &w,
                salt,
                1_000_000,
                schema_seg_ref,
                0x5344_4154,
                FpSM2::from(0xdead_beefu64),
                FpSM2::from(0x1234_5678u64),
                1_760_000_000,
            );
            let bad_rings = crate::sm3_compress::audit_ring_values(&asm_u.info, &asm_u.advice);
            eprintln!("[gate2] 环值审计违约环数={}", bad_rings.len());
            for (rid, msgs) in bad_rings.iter().take(3) {
                eprintln!("[gate2] 坏环 #{rid}: {} 条", msgs.len());
                for m in msgs.iter().take(2) {
                    eprintln!("[gate2]   {m}");
                }
            }
            assert!(bad_rings.is_empty(), "LUT 织入环值审计违约（见上）");
            // vendor mock：全约束全点求值（权威语义）
            let viol = crate::sm3_compress::check_parts_violations(
                &asm_u.info,
                &asm_u.advice,
                &asm_u.instances,
            );
            eprintln!("[gate2] LUT mock 约束违约数={}", viol.len());
            for v in viol.iter().take(6) {
                let tag = asm_u
                    .ctags
                    .get(v.constraint)
                    .copied()
                    .unwrap_or("<none>");
                eprintln!("[gate2]   约束#{c} tag={tag} 点={pt}", c = v.constraint, pt = v.point);
            }
            assert!(viol.is_empty(), "LUT mock 约束求值违约");
            std::env::set_var("SM3_LUT", "0");
            eprintln!(
                "[gate2] legacy: lookups={lk_l} constraints={c_l} | lut: lookups={lk_u} constraints={c_u}"
            );
            assert_eq!(lk_l, 4, "legacy 查表面（2026-10-01 实测钉：旧锚 0 在 db0bbb3 实测已漂移至 4——历史批次 LUT 化未回写；与 phase3_census 同源）");
            // R3-3.1（2026-09-24）：C 单块查表组入列 ⟹ 8×3+8=32 通道。
            assert_eq!(lk_u, 36, "LUT 查表面（2026-10-01 实测钉：旧钉 32[8×3 三体+8 C 单组] 在 db0bbb3 实测已漂移至 36——历史批次通道新增未回写）");
            assert_eq!(inst_l, inst_u, "差分门 2：同见证 LUT/legacy 实例面逐位相同（语句语义不变）");
            assert_ne!(c_l, c_u, "约束数应不同（布尔体 vs 查表体）");
        }

    /// P2 门 3：LUT 形态全语句 e2e prove/verify（zkc 同款管线；诚实必 OK）。
    #[test]
    fn sm3_lut_full_statement_e2e() {
        use plonkish_backend::{
            backend::{hyperplonk::HyperPlonk, PlonkishCircuit, PlonkishBackend},
            pcs::multilinear::Basefold,
            util::{
                hash::Sm3,
                transcript::{InMemoryTranscript, SM3Transcript},
            },
        };
        use crate::sm3_lookup_proto::ProtoSpec;
        use rand::{rngs::StdRng, SeedableRng};
        use std::io::Cursor;

        type Pcs = Basefold<FpSM2, Sm3, ProtoSpec>;
        type Pb = HyperPlonk<Pcs>;
        type Tr = SM3Transcript<Cursor<Vec<u8>>>;

        struct AsmCirc {
            info: plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>,
            advice: Vec<Vec<FpSM2>>,
            instances: Vec<Vec<FpSM2>>,
        }
        impl PlonkishCircuit<FpSM2> for AsmCirc {
            fn circuit_info_without_preprocess(
                &self,
            ) -> Result<plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
                Ok(self.info.clone())
            }
            fn circuit_info(
                &self,
            ) -> Result<plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
                Ok(self.info.clone())
            }
            fn instances(&self) -> &[Vec<FpSM2>] {
                &self.instances
            }
            fn synthesize(
                &self,
                _round: usize,
                _challenges: &[FpSM2],
            ) -> Result<Vec<Vec<FpSM2>>, plonkish_backend::Error> {
                Ok(self.advice.clone())
            }
        }

        let salt = [0x5au8; 16];
        let schema_seg: [u8; 28] = {
            let mut sg = [0u8; 28];
            sg.copy_from_slice(&PRED_TARGET[4..32]);
            sg
        };
        let attrs = {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&1_000_005u32.to_be_bytes());
            a[4..].copy_from_slice(&schema_seg);
            a
        };
        let w = witness_from_pred_commit_with_attrs(
            [1, 0, 0, 0],
            [0x11u8; 32],
            [2, 0, 0, 0],
            1_760_000_000,
            salt,
            attrs,
        );
        std::env::set_var("SM3_LUT", "1");
        let (asm, _h) = assemble_full_statement_pred_range(
            &w,
            salt,
            1_000_000,
            schema_seg,
            0x5344_4154,
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_760_000_000,
        );
        std::env::set_var("SM3_LUT", "0");
        let circ = AsmCirc {
            info: asm.info.clone(),
            advice: asm.advice.clone(),
            instances: asm.instances.clone(),
        };
        let param = Pb::setup(&asm.info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = Pb::preprocess(&param, &asm.info).unwrap();
        let proof = {
            let mut tr = Tr::new(());
            Pb::prove(&pp, &circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let ok = {
            let mut tr = Tr::from_proof((), proof.as_slice());
            Pb::verify(&vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
        };
        eprintln!(
            "[gate3] LUT 全语句 e2e: polys={} constraints={} lookups={} proof={}B ok={ok}",
            asm.info.num_poly(),
            asm.info.constraints.len(),
            asm.info.lookups.len(),
            proof.len()
        );
        assert!(ok, "LUT 全语句 e2e VERIFY FAILED");
    }

}


