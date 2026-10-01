//! 1.1b-b4 管线化 SM3 单块压缩电路（v2，复制环传输形态）。
//!
//! 背景：v1（[`crate::sm3_compress`]）秩窗口布局在端到端首跑中被后端协议级
//! 旋转预算拒收（记忆 [[backend-rotation-budget-boundary]]：verifier 为每个
//! (列,旋转) 对读 `2^|d|` 个域元素、sumcheck 断言 |d|≤num_vars；v1 实测最大
//! |d|=826、超阈 640 对）。拍板路线为分块链式证明；实现取证发现后端完整存在
//! halo2 式复制约束机制（`PlonkishCircuitInfo.permutations` 置换环 + 积论证，
//! 语义见 [`crate::sm3_perm_smoke`] 冒烟），于是 b4 的落地形态升级为：
//!
//! **保留 v1 条带布局；一切跨条带引用改为「远读处本地复制词 + 复制环」传输，
//! 零长旋转、单证明。**
//!
//! 复制以「值列环」而非按位环落地（勘误 #16）：每条环只含值列格 —— 协议层
//! 零约束零旋转；位形态在消费方用 [`Builder::emit_word_link`] 本地重构
//! （Σ2^i·bit_i=val + 32 位布尔）。选择理由：置换涉及的每个多项式都要作为
//! 预处理置换多项式提交并参与开口，证明大小与提交多项式数成正比 —— 按位环会
//! 卷入数百 bit 列，值列方案仅 ~30 列。
//!
//! **协议红线**：同一格至多出现在一个环的一个位置（表交换语义）；扇出消费
//! 全部串进同一条根环。等式的健全性由积论证（新鲜 β/γ）保证，
//! mock-prover 只能验证本地位级部分 —— 见注释与测试中的诚实说明。
//!
//! 公开语句面（实例）= 16 个消息字 W[0..15] + 8 个摘要字：中间量不再进实例层
//! （旧 pi-pin 方案的 220 序号表作废）。链上负轮（T1/PNXT 的 IV 前延）退化为
//! out 带上的常数锚行，由 8 组专用常量门钉住，消费者从锚行取复制。
//!
//! ═══════════ 结构不变量（评审锚点） ═══════════
//! S1 一切查询旋转 |d| ≤ 23 < K=11·2 的条带内跨度（回归守卫：
//!    tests::rotation_budget_guard 以 max_used_rotation_distance 硬断言 ≤ K）；
//!    跨条带等式一律走中继环。
//! S2 数值唯一真相源 = [`compute_round_vals`]（勘误 #11 承续）＋消息扩展封闭式
//!    （v1 同款）；GB/T 锚定由测试对拍 `sm3_native_ref::compress` 承担。
//! S3 每个正典词恰好一个环（ledger 键唯一断言强制）。

use crate::sm3_compress::{
    compute_round_vals, rank_inverse, tj_value, Builder, CarryPair, RoundVals, SlotRef, WordCols,
    WordHandle, NUM_BLOCKS, NUM_ROUNDS, ROWS,
};
use plonkish_backend::{backend::PlonkishCircuit, backend::PlonkishCircuitInfo};

type Fr_ = crate::FpSM2;

// ───────────────────────── 布局常量 ─────────────────────────

/// 正文条带秩基址。低秩区分两段使用：`row_mapping()[0..24)` 是实例钉点
/// （后端硬性放置），消息正典直接落户其上；秩 32..64 为 ioStrip
/// （摘要折叠 park 带）。正文从 [`RANK_BASE_V2`] 开始。
pub const RANK_BASE_V2: usize = 240;
/// 条带宽：六个轮核行 + WORG/WD4 + 八字母独立点 + 扩展三行，16 个占用偏移
/// （T4-lite 后用满；见 off 模块；条带内任意用点对距离 ≤ 8 « num_vars）。
pub const H_STRIPE: usize = 16;
/// out 带行数（负轮锚 8 行占 ooff，其余留白）。
pub const H_OUT: usize = 32;
/// 条带数 = 扩展字数 = 68。
pub const NUM_STRIPES: usize = NUM_BLOCKS;
/// ioStrip（摘要侧 park/折叠带）秩基址。
pub const IO_BASE: usize = 32;
pub const RANK_END: usize = RANK_BASE_V2 + NUM_STRIPES * H_STRIPE + H_OUT;

const _: () = assert!(RANK_END < ROWS, "v2 秩窗必须容纳于超立方");
const _: () = assert!(IO_BASE + 8 <= RANK_BASE_V2, "ioStrip 必须低于正文基址");

/// 条带内偏移（R1-v3b T4-lite 重排，2026-08-28 拍板施工；全宽 16）。
/// **距离账本**：min-linear-arrangement 求解器精确解（互异 off，|Δ|≤8），
/// Σ2^d×w 32,320→3,328（−89.7%，蓝图 §5.6）；字母 park 单点（LPARK）
/// 拆为 [`LETTER_OFF`] 八独立点。最大残边 TT1→TT2 d=4。扩展簇
/// EP/TP/STG 互距 1 不动（EP/STG 与 WORG/GG 同点异列——列族全局唯一
/// ⟹ 同点无冲突）。跨簇不发生直接查询（扩展源一律经 E* 环复制）。
pub mod off {
    pub const SS1PRE: usize = 7;
    pub const SS2: usize = 6;
    pub const FF: usize = 2; // j<16 复用为 xor_a 行
    pub const GG: usize = 12; // j<16 复用为 xor_b 行；与 STG 同点异列
    pub const TT1: usize = 5; // 链正典 T1 行
    pub const TT2: usize = 9; // TT2 输出 + PNXT 正典 + WP′ 词 同点异列
    /// W_j 自用复制（TT2 加法项直读本行距 2）。根在消息映射点或上游 STG。
    pub const WORG: usize = 11; // 与 TPARK 同点异列
    /// W_{j+4} 复制（W′ 源二），环接入。
    pub const WD4: usize = 13;
    /// 扩展源 park 点：W_{j∓{3,6,9,13,16}} 五组同点异列（E3..E16）。
    pub const EPARK: usize = 10; // 与 LE 同点异列
    /// 扩展中间量 m1/x/t/p1/m3 park 点；扩展门全部激活于此。
    pub const TPARK: usize = 11;
    /// 扩展结果 W_j 正典点（j≥16；只作中继根）。
    pub const STG: usize = 12;
}
/// 八字母独立偏移（T4-lite：LA..LH；取代原 LPARK 单 park 点）。
/// 消费结构 [求解器边表]：LA←SS1PRE/SS2/FF、LB/LC←FF、LD←TT1、
/// LE←SS1PRE/GG、LF/LG←GG、LH←TT2。
pub const LETTER_OFF: [usize; 8] = [4, 0, 1, 3, 10, 14, 15, 8];

/// A4 布局变体接缝（2026-09-15，窗口一前置）：A4_LETTER_OFF 环境变量
/// （8 个逗号分隔 0..16 整数）覆盖字母偏移表用于变体枚举筛查——布局
/// 变体只改行序（约束/列/环/选择子结构不变），施工后必经 census 复测
/// （R1-v3b 方法论：求解→施工→census 复测→归因回填）。未设环境变量时
/// 与 LETTER_OFF 常量逐值一致（默认路径零变化）。
pub fn letter_off_var() -> [usize; 8] {
    static CACHE: std::sync::OnceLock<[usize; 8]> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        match std::env::var("A4_LETTER_OFF") {
            Ok(v) => {
                let parts: Vec<usize> = v.split(',').filter_map(|t| t.trim().parse().ok()).collect();
                if parts.len() == 8 && parts.iter().all(|&x| x < 17) && {
                    let mut s = parts.clone(); s.sort(); s.dedup();
                    s.len() == 8
                } {
                    let mut a = [0usize; 8]; a.copy_from_slice(&parts); a
                } else {
                    panic!("A4_LETTER_OFF 非法（须 8 个互异 0..16 整数）: {v}")
                }
            }
            Err(_) => LETTER_OFF,
        }
    })
}

/// A4 会话 B(2026-09-15):**体 B 独立**字母偏移表——`A4_LETTER_OFF_B` 环境
/// 变体只动体 B 的字母行(体 A 保持默认表)。解耦动机 [实测 2026-09-15]:
/// 全局 `A4_LETTER_OFF` 同移写/读两端 ⟹ 距离不变(34 变体扫描 −0.14% 平坦);
/// 长距边(rot 8/9/11,384 对=88% 加权开口)写方=体 B 条带行,单端移动才能
/// 压缩点空间距离。
pub fn letter_off_var_b() -> [usize; 8] {
    static CACHE: std::sync::OnceLock<[usize; 8]> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        match std::env::var("A4_LETTER_OFF_B") {
            Ok(v) => {
                let parts: Vec<usize> = v.split(',').filter_map(|t| t.trim().parse().ok()).collect();
                if parts.len() == 8 && parts.iter().all(|&x| x < 17) && {
                    let mut s = parts.clone(); s.sort(); s.dedup();
                    s.len() == 8
                } {
                    let mut a = [0usize; 8]; a.copy_from_slice(&parts); a
                } else {
                    panic!("A4_LETTER_OFF_B 非法（须 8 个互异 0..16 整数）: {v}")
                }
            }
            Err(_) => LETTER_OFF,
        }
    })
}

/// 按区选字母偏移表:体 B 用独立表(解耦),体 A/其他区用全局表。
#[inline]
pub fn letter_off_for(zp: &'static Zone) -> [usize; 8] {
    if std::ptr::eq(zp, &ZONEB) {
        letter_off_var_b()
    } else {
        letter_off_var()
    }
}
/// out 带 / ioStrip 偏移。
pub mod ooff {
    /// 负轮锚：TT1 族 t∈−4..−1 各一行（vir 公式常数；同时是环根）。
    pub const NEG_T1: usize = 0;
    /// 负轮锚：PNXT 族 t∈−4..−1（ioStrip 也借用 out 带编址起点不同，见 io_row）。
    pub const NEG_PN: usize = 4;
    /// 体B 的 V_A 进口 park 行基（簇G 两体化）：VA[0..8] 依序各占一行
    /// （out 带 8..16）。与负轮锚成对查询距离 ≤11、与折叠行距离恒 8——
    /// 全部 < K=12 预算（纸面核算见蓝图 §四·5 G2）。
    pub const IMP: usize = 8;
    /// 折叠 park 行基（两体路径的带内版）：fold_k @ out 带 16+k；digest 面
    /// 与 V_A 出口面共点发射。单块路径仍走 ioStrip（等价迁移零变化）。
    pub const FOLD_BAND: usize = 16;
    /// 摘要折叠 park（ioStrip 版，单块路径专用遗产编址）。
    pub const IO_FOLD: usize = 0;
}

fn bh_point(rank: usize) -> usize {
    rank_inverse()[rank]
}

/// out 带编址表（R1-v3b T2，2026-08-28）：把 NEG/IMP/FOLD 四族行的带内
/// 偏移参数化 ⟹ 体A 沿用簇G 原编址、体B 用三星交错压读距离。
/// 语义不变量：`canon_home/fold_row/imp_row` 是唯一消费口，off 常量
/// （[`ooff`]）只作 [`LAYOUT_G`] 的字面来源与文档锚。
pub struct ZoneLayout {
    pub neg_t1: [usize; 4],
    pub neg_pn: [usize; 4],
    /// 仅体B 消费（体A 无进口面）。
    pub imp: [usize; 8],
    pub fold: [usize; 8],
}

/// 簇G 原编址（体A；等价迁移零变化）。
pub static LAYOUT_G: ZoneLayout = ZoneLayout {
    neg_t1: [0, 1, 2, 3],
    neg_pn: [4, 5, 6, 7],
    imp: [8, 9, 10, 11, 12, 13, 14, 15],
    fold: [16, 17, 18, 19, 20, 21, 22, 23],
};

/// 体B 三星交错（R1-v3b T2）：每个进口词 k 与其全部旋转读伙伴挤进连续
/// 3 偏移 [FOLD_k, IMP_k, 锚]，全配对距离 =1。配对结构 [实测 edge-at
/// 机械归因]：IMP_k 被 FOLD_k（摘要折叠门 view 读，旧 d=8）与
/// T1_{3−k}/PN_{7−k}（负轮锚 lin_rotl 绑定，旧 d∈{11,9,7,5}）读。
/// 8 组×3=24 偏移恰好用满（H_OUT=32，24..31 空闲）。
pub static LAYOUT_STAR: ZoneLayout = ZoneLayout {
    // 组 k 占偏移 3k..3k+2；锚：k=0..3 → T1_{3−k}，k=4..7 → PN_{7−k}
    fold: [0, 3, 6, 9, 12, 15, 18, 21],
    imp: [1, 4, 7, 10, 13, 16, 19, 22],
    // neg_t1[k] = T1_k 的偏移：T1_3=2(组0)、T1_2=5、T1_1=8、T1_0=11(组3)
    neg_t1: [11, 8, 5, 2],
    // neg_pn[k] = PN_k 的偏移：PN_3=14(组4)、PN_2=17、PN_1=20、PN_0=23(组7)
    neg_pn: [23, 20, 17, 14],
};

/// 区基址句柄（蓝图 Z_ANCHOR §四·5 G0）：两体共址的最小参数化。
/// 体A = [`ZONE0`]（既有布局等价迁移），体B 由簇G/G2 以独立基址构造；
/// ioStrip 折叠面（[`io_row`]）专属末块摘要，不属于区。
pub struct Zone {
    pub base: usize,
    pub layout: &'static ZoneLayout,
}

impl Zone {
    /// 条带 t 内 offset 的行点值。
    pub fn stripe_row(&self, t: usize, offset: usize) -> usize {
        assert!(t < NUM_STRIPES);
        bh_point(self.base + t * H_STRIPE + offset)
    }

    /// out 带 offset 的行点值。
    pub fn out_row(&self, offset: usize) -> usize {
        bh_point(self.base + NUM_STRIPES * H_STRIPE + offset)
    }

    /// 有符号轮号 t∈−4..63 的链族锚行（见自由函数 `canon_home` 文档）。
    pub fn canon_home(&self, t: i64, pnxt: bool) -> usize {
        debug_assert!((-4..=63).contains(&t));
        if t >= 0 {
            self.stripe_row(t as usize, if pnxt { off::TT2 } else { off::TT1 })
        } else {
            let k = (t + 4) as usize;
            let off = if pnxt {
                self.layout.neg_pn[k]
            } else {
                self.layout.neg_t1[k]
            };
            self.out_row(off)
        }
    }

    /// 折叠 park 行（带内版，簇G）：fold_k @ 编址表 fold[k]。
    /// digest 面与体A 出口面共点发射于本行。
    pub fn fold_row(&self, k: usize) -> usize {
        assert!(k < 8);
        self.out_row(self.layout.fold[k])
    }

    /// 体B 的 V_A 进口行：VA[idx] @ 编址表 imp[idx]（idx∈0..8）。
    pub fn imp_row(&self, idx: usize) -> usize {
        assert!(idx < 8);
        self.out_row(self.layout.imp[idx])
    }
}

/// 单块区（既有布局等价迁移；base = [`RANK_BASE_V2`]）。
pub static ZONE0: Zone = Zone { base: RANK_BASE_V2, layout: &LAYOUT_G };

/// 区宽（条带 + out 带）：两体并排的步距。
pub const ZONE_STRIDE: usize = NUM_STRIPES * H_STRIPE + H_OUT;
/// 体B 区基址：紧贴体A 之后（决策 #23 秩账 2480 < 4096，K=12 实测护栏）。
pub const ZB_BASE: usize = RANK_BASE_V2 + ZONE_STRIDE;
/// 两体布局总终点。
pub const TWO_BODY_END: usize = ZB_BASE + ZONE_STRIDE;
const _: () = assert!(
    TWO_BODY_END < ROWS,
    "两体总窗必须容纳于超立方（K=12: 2480 < 4096）"
);

/// 体B 区（簇G 双体装配的第二个 zone；R1-v3b T2 起用三星交错布局）。
pub static ZONEB: Zone = Zone { base: ZB_BASE, layout: &LAYOUT_STAR };

/// A4 窗口一(2026-09-15):体 C 专属区——**与体 A 同基座(条带行共用),out 带
/// 用 LAYOUT_STAR**。动机 [实测 a4_edges2]:链式三体的体 C 进口词(imp@ZONE0
/// out 带 1336..1343)被体 C 自身 fold 门(d=8)与负轮锚 lin_rotl(d=11/9/7/5)
/// 以 LAYOUT_G 偏置读取,513 边=239,616 单元=92% 非 cur 开口;合并线同构问题
/// 已由 LAYOUT_STAR 三星交错求解(配对距离=1)。`A4_ZONEC_STAR=1` 时链式体 C
/// 切换本区(体 A 恒 ZONE0=merged/standalone 口径零触碰)。
pub static ZONEC: Zone = Zone { base: RANK_BASE_V2, layout: &LAYOUT_STAR };

/// 链式体 C 的区选择(A4_ZONEC_STAR 门控;默认 = 历史行为 ZONE0)。
pub fn zonec() -> &'static Zone {
    if std::env::var("A4_ZONEC_STAR").map(|v| v == "1").unwrap_or(false) {
        &ZONEC
    } else {
        &ZONE0
    }
}

/// 条带 t 内 offset 的行点值（委托 [`ZONE0`] —— 等价迁移，零行为变化）。
#[inline]
pub fn stripe_row(t: usize, offset: usize) -> usize {
    ZONE0.stripe_row(t, offset)
}

/// out 带 offset 的行点值（委托 [`ZONE0`]）。
#[inline]
pub fn out_row(offset: usize) -> usize {
    ZONE0.out_row(offset)
}

/// ioStrip（摘要侧）offset k∈0..8 的行点值 —— F_k 折叠 park 行。
#[inline]
pub fn io_row(k: usize) -> usize {
    assert!(k < 8);
    bh_point(IO_BASE + k)
}

// ───────────────────────── 实例序号表（公开语句面） ─────────────────────────

/// 公开语句 = 消息字 16 + 摘要字 8。中间量不进实例层：链正典值由计算门
/// （从被钉消息逐级推出）与负轮常数锚共同唯一决定，远端消费走中继环。
pub mod ord {
    // —— 遗产常量（单块路径语义，勿动）：消息 0..15、摘要 16..23、共 24 ——
    pub const N_MSG: usize = 16;
    pub const N_DG: usize = 8;
    pub const BASE_MSG: usize = 0;
    pub const BASE_DG: usize = BASE_MSG + N_MSG;
    pub const TOTAL: usize = BASE_DG + N_DG;

    // —— 簇G 两体新增：体B 消息 16..31、两体摘要 32..39，语句面共 40 ——
    /// 体B 消息字基址。
    pub const BASE_MSG_B: usize = 16;
    /// 两体路径的摘要字基址（Z_U 摘要 8 字）。
    pub const BASE_DG_TWO: usize = BASE_MSG_B + N_MSG;
    /// 两体语句面：B₂ 消息 16 + B₃ 消息 16 + Z_U 摘要 8（蓝图 §四·5 G3；
    /// 变量字改走 relay 的簇H 重映射在此阶段之前，先按公开实例钉点交付 mock 验收）。
    pub const TOTAL_TWO: usize = BASE_DG_TWO + N_DG;
}

/// 有符号轮号 t∈−4..63 的链族锚行：t≥0 取该条带 TT1/TT2 行的正典列；
/// t<0 取 out 带负轮锚行。返回（列组, 家点）。**调用方约定**：正典 T1 写入
/// `tt1` 池在条带 t·off::TT1 的格；PNXT 写入 `pnxt` 池同条带 off::TT2 ——
/// 与 v1 的 ChainPools 家点公式一致（勘误 #12 承续）。
/// 有符号轮号 t∈−4..63 的链族锚行：t≥0 取该条带 TT1/TT2 行的正典列；
/// t<0 取 out 带负轮锚行。返回（列组, 家点）。**调用方约定**：正典 T1 写入
/// `tt1` 池在条带 t·off::TT1 的格；PNXT 写入 `pnxt` 池同条带 off::TT2 ——
/// 与 v1 的 ChainPools 家点公式一致（勘误 #12 承续）。
///
/// （G0 等价迁移：委托 [`ZONE0`]；体B 版走 `Zone::canon_home`。）
pub fn canon_home(t: i64, pnxt: bool) -> usize {
    ZONE0.canon_home(t, pnxt)
}

/// 负号锚行存储值＝v1 vir_values() 同款推导（TT1 族 rotr9、PNXT 族 rotr19 前延），
/// 对**任意初态**成立（簇G 两体化：体A 传 IV₂ 特例；体B 的初态是变量——锚值改为
/// 环接入 + 线性折叠重建，见 build_two_bodies / bind_var_anchors）。
pub fn virt_from(state: &[u32; 8], t: i64, pnxt: bool) -> u32 {
    debug_assert!((-4..0).contains(&t));
    let k = (t + 4) as usize; // 0..3 ↔ t=−4..−1
    if pnxt {
        [state[7].rotate_right(19), state[6].rotate_right(19), state[5], state[4]][k]
    } else {
        [state[3].rotate_right(9), state[2].rotate_right(9), state[1], state[0]][k]
    }
}

/// 负号锚行存储值（IV 特例 —— 单块路径保持原语义）。
pub fn virt_cell(t: i64, pnxt: bool) -> u32 {
    virt_from(&crate::sm3_native_ref::IV, t, pnxt)
}

/// 有符号轮号 t 的链「声明值」（真实轮取计算值，负号取初态前延公式）。
pub fn chain_decl(init: &[u32; 8], t: i64, pnxt: bool, rvs: &[RoundVals]) -> u32 {
    if t >= 0 {
        let rv = &rvs[t as usize];
        if pnxt {
            crate::sm3_native_ref::p0(rv.t2)
        } else {
            rv.t1
        }
    } else {
        virt_from(init, t, pnxt)
    }
}

// ───────────────────────── 字母滞后映射（勘误 #7 承续） ─────────────────────────

const LETTER_LAGS: [usize; 8] = [1, 2, 3, 4, 1, 2, 3, 4];
const LETTER_PNXT: [bool; 8] = [false, false, false, false, true, true, true, true];
/// 字母行 = [`LETTER_OFF`] 八独立点（T4-lite；原 LPARK 单点 park 已拆）。
/// 门经 rotl 视图消费（`LETTER_ROTS`），任意字母↔消费门行 ≤ 4。
/// 字母视图的 rotl 量（c,d ⟨9⟩；g,h ⟨19⟩；a,b,e,f 直读）。
const LETTER_ROTS: [u32; 8] = [0, 0, 9, 9, 0, 0, 19, 19];

/// 条带 j 第 idx 号字母的链源有符号轮号（t = j − lag）。
#[inline]
fn letter_src_t(j: usize, idx: usize) -> i64 {
    j as i64 - LETTER_LAGS[idx] as i64
}

// ───────────────────────── v2 列组池 ─────────────────────────

/// 工作池（单一物理列组跨条带复用，格值按条带点区分 —— v1 同款模式）。
/// **值列配置铁律**：只有进入中继环的列组（根或落点）与摘要输出列才带值列 ——
/// 置换涉及的每个多项式都要提交并开口，证明大小与之成正比（模块文档）。
struct WorkPools {
    ss1pre: WordCols,
    /// TT2 输出词（emit_add 需值列；仅本条带内被 PNXT 门消费）。
    tt2: WordCols,
    ss2: WordCols,
    ff: WordCols,
    gg: WordCols,
    /// 链正典 T1（环根）。
    tt1: WordCols,
    /// 链正典 PNXT（环根；家点复用条带 off::TT2 行）。
    pnxt: WordCols,
    half: WordCols,
    xtmp_m1: WordCols,
    xtmp_x: WordCols,
    xtmp_t: WordCols,
    xtmp_p1: WordCols,
    xtmp_m3: WordCols,
    /// W_j 自用复制（TT2 加法项直读；根 = 消息映射点或上游 STG）。
    worg: WordCols,
    /// 扩展结果 W_j 正典行（j≥16 环根）。
    stg: WordCols,
    /// 消息词正典（v3 列压缩 P1a）：16 个消息实例钉点互不相同，改由
    /// **共享单值列**承载全部钉点格 —— 家点位格只喂过 pin.recomp，无门按位
    /// 消费；值的 <2^32 成员性由 EPARK 消费 link 兜底（健全性传递封闭）。
    /// emit_pin_val_only 保住 inst@cur 实例绑定，零旋转性质不变。
    msgm: usize,
    wd4: WordCols,
    e3: WordCols,
    e6: WordCols,
    e9: WordCols,
    e13: WordCols,
    e16: WordCols,
    xor_a: WordCols,
    xor_b: WordCols,
    wpword: WordCols,
    /// 八字母复制列组（各含值列，进环后本地重分解）。
    letters: [WordCols; 8],
    /// out 带：末状态字母复制 F0..F7（摘要源，各自进链尾环）。
    fold: [WordCols; 8],
    /// 负轮锚 TT1/PNXT 族（v3 列压缩 P1c）：锚值是编译期常数，改单值列 ——
    /// 一条 sel·(val−const)=0 取代「32 常量位 + link」；同时是链环根。
    /// （体B 变体：锚值改线性绑定到 V_A 进口位，见 build_two_bodies。）
    neg_t1: usize,
    neg_pn: usize,
}

impl WorkPools {
    fn alloc(b: &mut Builder<Fr_>) -> Self {
        let f = |b: &mut Builder<Fr_>| b.alloc_word_cols(false);
        WorkPools {
            // emit_add 的结果词必须有值列（ss1pre/tt1/tt2 都是加法输出）。
            ss1pre: b.alloc_word_cols(true),
            tt2: b.alloc_word_cols(true),
            ss2: f(b),
            ff: f(b),
            gg: f(b),
            tt1: b.alloc_word_cols(true),
            pnxt: b.alloc_word_cols(true),
            half: f(b),
            xtmp_m1: f(b),
            xtmp_x: f(b),
            xtmp_t: f(b),
            xtmp_p1: f(b),
            xtmp_m3: f(b),
            worg: b.alloc_word_cols(true),
            stg: b.alloc_word_cols(true),
            wd4: b.alloc_word_cols(true),
            e3: b.alloc_word_cols(true),
            e6: b.alloc_word_cols(true),
            e9: b.alloc_word_cols(true),
            e13: b.alloc_word_cols(true),
            e16: b.alloc_word_cols(true),
            xor_a: f(b),
            xor_b: f(b),
            // W′ 词只被本条带 TT1 门以位视图消费，不入环 —— 无需值列。
            wpword: f(b),
            msgm: b.alloc_col(),
            letters: std::array::from_fn(|_| b.alloc_word_cols(true)),
            fold: std::array::from_fn(|_| b.alloc_word_cols(true)),
            neg_t1: b.alloc_col(),
            neg_pn: b.alloc_col(),
        }
    }
}

// ───────────────────────── 面（簇G 面裁剪） ─────────────────────────
//
// 摘要/出口/进口列组自 WorkPools 拆出：三体形态各装所需面（solo=摘要面、
// 体A=出口面、体B=进口+摘要面），避免死列进证明。列序变化只置换全局多项式
// 号，电路语义与形状计数不受影响（solo 形状锁定 60212/1315/80/80/212 不变）。

/// 摘要面：摘要输出值列 + echo 钉点列（solo 与体B 各一份）。echo 列按
/// 形态裁剪（簇J `ChainEcho::Fold` 不设 echo —— 死列不进证明，簇G 纪律）。
struct DigestFace {
    /// 摘要输出值列（v1 emit_feedforward 的 o_val 同位；ioStrip/折叠行每行 1 格）。
    digval: usize,
    /// 摘要 echo（v3 列压缩 P1b）：单值列承载 8 个实例钉点格，经环从 digval
    /// 接入后 emit_pin_val_only 绑定 —— 与低秩钉点之间零旋转；位格需求为零
    /// （fold 侧 ff.out / XOR 门已按位出值）。Fold 形态为 None。
    echo: Option<usize>,
}

impl DigestFace {
    fn alloc(b: &mut Builder<Fr_>, with_echo: bool) -> Self {
        Self { digval: b.alloc_col(), echo: with_echo.then(|| b.alloc_col()) }
    }
}

/// 体A 出口面（簇G 两体化）：V_A 八字的共享出口值列（折叠行逐字 1 格）。
/// ff.out 门写值（O_k = fold_k ⊕ IV₂_k 线性形态），环根从此列开启、落点在
/// 体B 进口词值列。
struct ExportFace {
    out_val: usize,
}

impl ExportFace {
    fn alloc(b: &mut Builder<Fr_>) -> Self {
        Self { out_val: b.alloc_col() }
    }
}

/// 体B 进口面（簇G 两体化）：V_A 八词的本地复制词组（位+值 —— 环落点在值列，
/// link 重分解到位后供负轮锚线性绑定与摘要 XOR 门按位消费）+ 变量摘要输出
/// 位组（XOR 门出口，无值列 —— 值经线性重组进摘要面 digval）。
struct ImportFace {
    words: [WordCols; 8],
    digbits: WordCols,
}

impl ImportFace {
    fn alloc(b: &mut Builder<Fr_>) -> Self {
        Self {
            words: std::array::from_fn(|_| b.alloc_word_cols(true)),
            digbits: b.alloc_word_cols(false),
        }
    }
}

/// 门/link/pin/常量选择器 id 集。
struct SelIds(std::collections::HashMap<&'static str, usize>);

impl SelIds {
    fn alloc(b: &mut Builder<Fr_>, names: &[&'static str]) -> Self {
        SelIds(names.iter().map(|n| (*n, b.alloc_selector(&[]))).collect())
    }
    #[inline]
    fn g(&self, name: &str) -> usize {
        self.0[name]
    }
}

const SEL_NAMES: &[&str] = &[
    // 门族（跨条带共享家族选择器；激活点在装配期 extend）
    "g.ss1pre", "g.ss2", "g.ffmaj", "g.ffxor", "g.ggcho", "g.ggxor", "g.tt1", "g.tt2",
    "g.exm1", "g.exm2", "g.ext", "g.exp1", "g.exm3", "g.exw", "g.wp", "g.pnxt",
    // 复制落地 link（每组一签：约束只读本组 cur 格）
    "l.l0", "l.l1", "l.l2", "l.l3", "l.l4", "l.l5", "l.l6", "l.l7",
    "l.f0", "l.f1", "l.f2", "l.f3", "l.f4", "l.f5", "l.f6", "l.f7",
    "l.e3", "l.e6", "l.e9", "l.e13", "l.e16", "l.wd4", "l.worg",
    "l.msg0", "l.msg1", "l.msg2", "l.msg3", "l.msg4", "l.msg5", "l.msg6", "l.msg7",
    "l.msg8", "l.msg9", "l.msg10", "l.msg11", "l.msg12", "l.msg13", "l.msg14", "l.msg15",
    "l.echo0", "l.echo1", "l.echo2", "l.echo3", "l.echo4", "l.echo5", "l.echo6", "l.echo7",
    // 摘要折叠门（8 行独立签：各字母 rotl 视图与 IV 字不同）
    "d.d0", "d.d1", "d.d2", "d.d3", "d.d4", "d.d5", "d.d6", "d.d7",
    // 负轮常量锚（8 行独立签：各行常数不同不能共签）
    "n.t0", "n.t1", "n.t2", "n.t3",
    "n.p0", "n.p1", "n.p2", "n.p3",
];

// ───────────────────────── 数值预演 ─────────────────────────

/// 单块数值预演（唯一真相源 compute_round_vals 的纯宿主）。
struct Replay {
    w_all: [u32; NUM_BLOCKS],
    wp_all: Vec<u32>,
    rvs: Vec<RoundVals>,
    final_state: [u32; 8],
}

/// 单块数值预演（**指定初态**版 —— 簇G 两体化：体A 初态=IV₂、体B 初态=V_A）。
/// 更新序与 [`replay`] 完全一致（勘误 #7 / M2c 权威）。
fn replay_with_state(init: &[u32; 8], block64: &[u8; 64]) -> Replay {
    let mut w = [0u32; NUM_BLOCKS];
    for jj in 0..16 {
        w[jj] = u32::from_be_bytes([
            block64[4 * jj],
            block64[4 * jj + 1],
            block64[4 * jj + 2],
            block64[4 * jj + 3],
        ]);
    }
    for jj in 16..NUM_BLOCKS {
        let x = w[jj - 16] ^ w[jj - 9] ^ w[jj - 3].rotate_left(15);
        let p1 = x ^ x.rotate_left(15) ^ x.rotate_left(23);
        w[jj] = p1 ^ w[jj - 13].rotate_left(7) ^ w[jj - 6];
    }
    let wp: Vec<u32> = (0..NUM_ROUNDS).map(|jj| w[jj] ^ w[jj + 4]).collect();
    let mut st = *init;
    let mut rvs = Vec::with_capacity(NUM_ROUNDS);
    for j in 0..NUM_ROUNDS {
        let v = compute_round_vals(j, &st, w[j], wp[j]);
        // 更新序（勘误 #7 / M2c 权威）：A←T1; B←A_old; C←ROTL9(B_old); D←C_old;
        //                          E←P0(T2); F←E_old; G←ROTL19(F_old); H←G_old
        st = [
            v.t1,
            v.ins[0],
            v.ins[1].rotate_left(9),
            v.ins[2],
            crate::sm3_native_ref::p0(v.t2),
            v.ins[4],
            v.ins[5].rotate_left(19),
            v.ins[6],
        ];
        rvs.push(v);
    }
    Replay { w_all: w, wp_all: wp, rvs, final_state: st }
}

fn replay(block64: &[u8; 64]) -> Replay {
    replay_with_state(&crate::sm3_native_ref::IV, block64)
}

// ───────────────────────── 装配器 ─────────────────────────

/// v2 电路对象（复制环版）。
#[derive(Clone, Debug)]
pub struct Sm3V2Circuit {
    pub info: PlonkishCircuitInfo<Fr_>,
    pub advice: Vec<Vec<Fr_>>,
    pub instances: Vec<Vec<Fr_>>,
    pub tags: Vec<(&'static str, usize)>,
    /// 与 info.constraints 平行的家族标签。
    pub ctags: Vec<&'static str>,
    pub num_selectors: usize,
    /// 摘要真值（对拍/诊断）。
    pub digest: [u32; 8],
    /// 中继环长度账本（环数=vec.len()；单项环已滤除）。
    pub relay_census: Vec<usize>,
}

impl PlonkishCircuit<Fr_> for Sm3V2Circuit {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<Fr_>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<Fr_>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<Fr_>] {
        &self.instances
    }
    fn synthesize(&self, round: usize, challenges: &[Fr_]) -> Result<Vec<Vec<Fr_>>, Error> {
        assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
        Ok(self.advice.clone())
    }
}
use plonkish_backend::Error;

/// 扩展回看距离表（与 [`WorkPools`] 的 e16/e9/e13/e6/e3 字段序一致）。
const E_BACKS: [usize; 5] = [16, 9, 13, 6, 3];

fn pools_ext_group(pools: &WorkPools, gi: usize) -> &WordCols {
    match gi {
        0 => &pools.e16,
        1 => &pools.e9,
        2 => &pools.e13,
        3 => &pools.e6,
        _ => &pools.e3,
    }
}

const NEG_T_SELS: [&str; 4] = ["n.t0", "n.t1", "n.t2", "n.t3"];
const NEG_P_SELS: [&str; 4] = ["n.p0", "n.p1", "n.p2", "n.p3"];
const L_SELS: [&str; 8] = ["l.l0", "l.l1", "l.l2", "l.l3", "l.l4", "l.l5", "l.l6", "l.l7"];
const F_SELS: [&str; 8] = ["l.f0", "l.f1", "l.f2", "l.f3", "l.f4", "l.f5", "l.f6", "l.f7"];
const E_SELS: [&str; 5] = ["l.e16", "l.e9", "l.e13", "l.e6", "l.e3"];
const MSG_SELS: [&str; 16] = [
    "l.msg0", "l.msg1", "l.msg2", "l.msg3", "l.msg4", "l.msg5", "l.msg6", "l.msg7",
    "l.msg8", "l.msg9", "l.msg10", "l.msg11", "l.msg12", "l.msg13", "l.msg14", "l.msg15",
];
const DG_SELS: [&str; 8] = ["d.d0", "d.d1", "d.d2", "d.d3", "d.d4", "d.d5", "d.d6", "d.d7"];
const ECHO_SELS: [&str; 8] = [
    "l.echo0", "l.echo1", "l.echo2", "l.echo3", "l.echo4", "l.echo5", "l.echo6", "l.echo7",
];

#[inline]
fn s_row(j: usize, o: usize) -> usize {
    stripe_row(j, o)
}

/// 单值列句柄（v3 列压缩 P1a/b/c）：位场恒 0 占位，环/中继只读 `val` ——
/// 与 digval 环根同款先例（begin_relay 不读位列）。**禁止**对返回句柄调用
/// set_word / 按位门（位格是假号）。
#[inline]
fn vh(val_local: usize, home: usize) -> WordHandle {
    WordHandle {
        bits: [0usize; 32],
        val: Some(val_local),
        home,
    }
}

/// 摘要折叠视图的 rotl 量（末状态字母公式：a,b,e,f 直读；c,d⟨9⟩；g,h⟨19⟩）。
const DIG_ROTS: [u32; 8] = [0, 0, 9, 9, 0, 0, 19, 19];

/// 单体门层（扩展 / W′ / 64 轮压缩 / PNXT）——簇G 自 build_compress_v2 抽出的
/// 共享段（纯代码搬移，逐字等价：ZONE0 调用点替换为 `zp` 参数化寻址，其余
/// 包括约束发射顺序在内零变化）。数值唯一来源 [`Replay`]（勘误 #11 承续）。
#[allow(clippy::too_many_arguments)]
fn emit_round_gates(
    bld: &mut Builder<Fr_>,
    pools: &WorkPools,
    sel: &SelIds,
    cp: &CarryPair,
    tj_prep: usize,
    zp: &'static Zone,
    rep: &Replay,
) {
    // ---- 扩展（j∈16..68）：先发（链门读字母 park，顺序无关，但为读账清晰放前）----
    let temp_at = |j: usize| zp.stripe_row(j, off::TPARK);
    for j in 16..NUM_BLOCKS {
        let at = temp_at(j);
        let he16 = pools.e16.at(zp.stripe_row(j, off::EPARK));
        let he9 = pools.e9.at(zp.stripe_row(j, off::EPARK));
        let he3 = pools.e3.at(zp.stripe_row(j, off::EPARK));
        let he13 = pools.e13.at(zp.stripe_row(j, off::EPARK));
        let he6 = pools.e6.at(zp.stripe_row(j, off::EPARK));

        let hm1 = pools.xtmp_m1.at(at);
        let hx = pools.xtmp_x.at(at);
        let ht = pools.xtmp_t.at(at);
        let hp1 = pools.xtmp_p1.at(at);
        let hm3 = pools.xtmp_m3.at(at);

        let m1v = rep.w_all[j - 16] ^ rep.w_all[j - 9];
        let xv = m1v ^ rep.w_all[j - 3].rotate_left(15);
        let tv = xv ^ xv.rotate_left(15);
        let p1v = tv ^ xv.rotate_left(23);
        let m3v = p1v ^ rep.w_all[j - 13].rotate_left(7);
        let wjv = m3v ^ rep.w_all[j - 6];

        bld.extend_selector(sel.g("g.exm1"), &[at]);
        bld.emit_xor(sel.g("g.exm1"), &SlotRef::view(&he16), &SlotRef::view(&he9), &hm1, at);
        bld.extend_selector(sel.g("g.exm2"), &[at]);
        bld.emit_xor(sel.g("g.exm2"), &SlotRef::view(&hm1), &SlotRef::rotl(&he3, 15), &hx, at);
        bld.extend_selector(sel.g("g.ext"), &[at]);
        bld.emit_xor(sel.g("g.ext"), &SlotRef::view(&hx), &SlotRef::rotl(&hx, 15), &ht, at);
        bld.extend_selector(sel.g("g.exp1"), &[at]);
        bld.emit_xor(sel.g("g.exp1"), &SlotRef::view(&ht), &SlotRef::rotl(&hx, 23), &hp1, at);
        bld.extend_selector(sel.g("g.exm3"), &[at]);
        bld.emit_xor(sel.g("g.exm3"), &SlotRef::view(&hp1), &SlotRef::rotl(&he13, 7), &hm3, at);
        // 结果写入 STG 正典行（激活仍在 TPARK，距 1）。
        let stg_at = zp.stripe_row(j, off::STG);
        let hwj = pools.stg.at(stg_at);
        bld.extend_selector(sel.g("g.exw"), &[at]);
        bld.emit_xor(sel.g("g.exw"), &SlotRef::view(&hm3), &SlotRef::view(&he6), &hwj, at);

        bld.set_word(&hm1, m1v);
        bld.set_word(&hx, xv);
        bld.set_word(&ht, tv);
        bld.set_word(&hp1, p1v);
        bld.set_word(&hm3, m3v);
        bld.set_word(&hwj, wjv);
    }

    // ---- W′（全部 64 轮覆盖，勘误 #10 承续）----
    for j in 0..NUM_ROUNDS {
        let at = zp.stripe_row(j, off::WORG);
        let hw1 = pools.worg.at(zp.stripe_row(j, off::WORG));
        let hw2 = pools.wd4.at(zp.stripe_row(j, off::WD4));
        let hwp = pools.wpword.at(zp.stripe_row(j, off::TT2));
        bld.extend_selector(sel.g("g.wp"), &[at]);
        bld.emit_xor(sel.g("g.wp"), &SlotRef::view(&hw1), &SlotRef::view(&hw2), &hwp, at);
        bld.set_word(&hwp, rep.wp_all[j]);
    }

    // ---- 64 轮压缩（v1 emit_round 的条带化直译；数值全部取自 rvs）----
    for j in 0..NUM_ROUNDS {
        let rvj = rep.rvs[j];
        let l_slots: [SlotRef; 8] = std::array::from_fn(|idx| {
            let h = pools.letters[idx].at(zp.stripe_row(j, letter_off_for(zp)[idx]));
            if LETTER_ROTS[idx] == 0 {
                SlotRef::view(&h)
            } else {
                SlotRef::rotl(&h, LETTER_ROTS[idx])
            }
        });
        let (sa, sb, sc, sd) = (&l_slots[0], &l_slots[1], &l_slots[2], &l_slots[3]);
        let (se, sf, sg, sh) = (&l_slots[4], &l_slots[5], &l_slots[6], &l_slots[7]);

        let p_ss1pre = zp.stripe_row(j, off::SS1PRE);
        let p_ss2 = zp.stripe_row(j, off::SS2);
        let p_ff = zp.stripe_row(j, off::FF);
        let p_gg = zp.stripe_row(j, off::GG);
        let p_tt1 = zp.stripe_row(j, off::TT1);
        let p_tt2 = zp.stripe_row(j, off::TT2);

        bld.extend_selector(sel.g("g.ss1pre"), &[p_ss1pre]);
        bld.extend_selector(sel.g("g.ss2"), &[p_ss2]);
        if j >= 16 {
            bld.extend_selector(sel.g("g.ffmaj"), &[p_ff]);
            bld.extend_selector(sel.g("g.ggcho"), &[p_gg]);
        } else {
            bld.extend_selector(sel.g("g.ffxor"), &[p_ff]);
            bld.extend_selector(sel.g("g.ggxor"), &[p_gg]);
        }
        bld.extend_selector(sel.g("g.tt1"), &[p_tt1]);
        bld.extend_selector(sel.g("g.tt2"), &[p_tt2]);
        // PNXT 门同点激活 —— 已随 g.tt2 前缀扩展？不行：不同选择器。
        bld.extend_selector(sel.g("g.pnxt"), &[p_tt2]);

        let w_ss1pre = pools.ss1pre.at(p_ss1pre);
        let w_tt1 = pools.tt1.at(p_tt1);
        let w_tt2 = pools.tt2.at(p_tt2);
        let w_ss2 = pools.ss2.at(p_ss2);
        let w_ff = pools.ff.at(p_ff);
        let w_gg = pools.gg.at(p_gg);
        let w_half = pools.half.at(p_tt2);
        let w_pnx = pools.pnxt.at(p_tt2);

        // SS1PRE = rotl12(a)+e+T_j（a 槽位本身 n=0，rotl12 并入线性式）
        let tj_term = {
            use plonkish_backend::util::expression::{Expression, Query, Rotation};
            Expression::<Fr_>::Polynomial(Query::new(tj_prep, Rotation::cur()))
        };
        bld.emit_add(
            sel.g("g.ss1pre"),
            &[
                bld.lin_rotl(&sa.h, sa.n + 12, p_ss1pre),
                bld.lin_slot(se, p_ss1pre),
                tj_term,
            ],
            &w_ss1pre,
            cp,
            p_ss1pre,
        );
        // SS2 = rotl7(SS1PRE) ⊕ rotl12(a)
        bld.emit_xor(
            sel.g("g.ss2"),
            &SlotRef::rotl(&w_ss1pre, 7),
            &SlotRef::rotl(&sa.h, 12),
            &w_ss2,
            p_ss2,
        );
        // FF / GG 分支
        if j >= 16 {
            bld.emit_maj(sel.g("g.ffmaj"), sa, sb, sc, &w_ff, p_ff);
            bld.emit_choose(sel.g("g.ggcho"), se, sf, sg, &w_gg, p_gg);
        } else {
            let wt = pools.xor_a.at(p_ff);
            bld.set_word(&wt, rvj.ins[0] ^ rvj.ins[1]);
            bld.emit_xor(sel.g("g.ffxor"), sa, sb, &wt, p_ff);
            bld.emit_xor(sel.g("g.ffxor"), &SlotRef::view(&wt), sc, &w_ff, p_ff);

            let wu = pools.xor_b.at(p_gg);
            bld.set_word(&wu, rvj.ins[4] ^ rvj.ins[5]);
            bld.emit_xor(sel.g("g.ggxor"), se, sf, &wu, p_gg);
            bld.emit_xor(sel.g("g.ggxor"), &SlotRef::view(&wu), sg, &w_gg, p_gg);
        }
        // TT1 = FF + d + SS2 + W'[j]
        let w_wpj = pools.wpword.at(zp.stripe_row(j, off::TT2));
        bld.emit_add(
            sel.g("g.tt1"),
            &[
                bld.lin_slot(&SlotRef::view(&w_ff), p_tt1),
                bld.lin_slot(sd, p_tt1),
                bld.lin_slot(&SlotRef::view(&w_ss2), p_tt1),
                bld.lin_slot(&SlotRef::view(&w_wpj), p_tt1),
            ],
            &w_tt1,
            cp,
            p_tt1,
        );
        // TT2 = GG + h + rotl7(SS1PRE) + W[j]
        let w_worg = pools.worg.at(zp.stripe_row(j, off::WORG));
        bld.emit_add(
            sel.g("g.tt2"),
            &[
                bld.lin_slot(&SlotRef::view(&w_gg), p_tt2),
                bld.lin_slot(sh, p_tt2),
                bld.lin_rotl(&w_ss1pre, 7, p_tt2),
                bld.lin_slot(&SlotRef::view(&w_worg), p_tt2),
            ],
            &w_tt2,
            cp,
            p_tt2,
        );
        // PNXT：e'_{t+1}=P0(TT2)：half=TT2⊕rotl9(TT2)，PNXT=half⊕rotl17(TT2)
        let tt2_h = w_tt2;
        bld.emit_xor(
            sel.g("g.pnxt"),
            &SlotRef::view(&tt2_h),
            &SlotRef::rotl(&tt2_h, 9),
            &w_half,
            p_tt2,
        );
        bld.emit_xor(
            sel.g("g.pnxt"),
            &SlotRef::view(&w_half),
            &SlotRef::rotl(&tt2_h, 17),
            &w_pnx,
            p_tt2,
        );

        // 见证（数值唯一来源 rvs；carry 公式勘误 #15 承续）
        bld.set_word(&w_ss1pre, rvj.ss1pre);
        bld.set_word(&w_tt1, rvj.t1);
        bld.set_word(&w_tt2, rvj.t2);
        for i in 0..32usize {
            bld.set_cell_u32(pools.ss2.bits[i], p_ss2, (rvj.ss2 >> i) & 1);
            bld.set_cell_u32(pools.ff.bits[i], p_ff, (rvj.ffv >> i) & 1);
            bld.set_cell_u32(pools.gg.bits[i], p_gg, (rvj.ggv >> i) & 1);
            bld.set_cell_u32(pools.half.bits[i], p_tt2, ((rvj.t2 ^ rvj.t2.rotate_left(9)) >> i) & 1);
        }
        let tj = tj_value(j);
        bld.set_carries(
            cp,
            p_ss1pre,
            ((rvj.ins[0].rotate_left(12) as u64 + rvj.ins[4] as u64 + tj as u64) >> 32) as u32,
        );
        bld.set_carries(
            cp,
            p_tt1,
            ((rvj.ffv as u64 + rvj.ins[3] as u64 + rvj.ss2 as u64 + rep.wp_all[j] as u64) >> 32)
                as u32,
        );
        bld.set_carries(
            cp,
            p_tt2,
            ((rvj.ggv as u64 + rvj.ins[7] as u64 + rvj.ss1 as u64 + rep.w_all[j] as u64) >> 32)
                as u32,
        );
        bld.set_word(&w_half, rvj.t2 ^ rvj.t2.rotate_left(9));
        bld.set_word(&w_pnx, crate::sm3_native_ref::p0(rvj.t2));
    }
}

/// 单体中继登记（链根×2族 + W 根 + 字母/折叠/扩展源/wd4/worg parks 落点）——
/// 簇G 自 build_compress_v2 抽出的共享段（纯代码搬移：ZONE0 寻址替换为 `zp`
/// 参数化、消息基址 `msg_base` 参数化、折叠落点 `fold_pts` 参数化，登记顺序
/// 逐字保持）。echo/出口环的登记留给各 face 专属段（solo=摘要 echo、体A=V_A
/// 出口环）。返回 `(chain_root[2][68], w_root[68])`（环号表，登记后无人再读，
/// 仅为签名完整供诊断）。
#[allow(clippy::type_complexity)]
fn register_chain_rings(
    bld: &mut Builder<Fr_>,
    pools: &WorkPools,
    zp: &'static Zone,
    msg_base: usize,
    msg_roots: Option<&[MsgCell; 16]>,
    fold_pts: &[usize; 8],
) -> ([[usize; NUM_BLOCKS]; 2], [usize; NUM_BLOCKS]) {
    let rm = crate::sm3_compress::row_mapping();
    // 链正典根 t∈−4..63 × 两族。**列随符号切换**：t≥0 的正典在条带 TT1/TT2 行
    // （tt1/pnxt 池）；t<0 的正典在 out 带锚行（neg_t1/neg_pn 池）——首跑
    // e2e 抓到的缺陷：根若错挂到 tt1/pnxt 列，该格无写入恒 0，同环字母为
    // IV 前延真值 ⇒ 积论证当场拒绝（mock 看不到置换层，此教训记勘误）。
    let mut chain_root = [[0usize; NUM_BLOCKS]; 2];
    for flag in [false, true] {
        for tt in -4i64..=(NUM_ROUNDS as i64 - 1) {
            let pt = zp.canon_home(tt, flag);
            let h = match (flag, tt < 0) {
                (_, true) => vh(if flag { pools.neg_pn } else { pools.neg_t1 }, pt),
                (true, false) => pools.pnxt.at(pt),
                (false, false) => pools.tt1.at(pt),
            };
            chain_root[flag as usize][(tt + 4) as usize] = bld.begin_relay(&h);
        }
    }
    // 字母 park 落点（每轮条带 8 个）。
    for j in 0..NUM_ROUNDS {
        for idx in 0..8 {
            let tt = letter_src_t(j, idx);
            let id = chain_root[LETTER_PNXT[idx] as usize][(tt + 4) as usize];
            let home = zp.stripe_row(j, letter_off_for(zp)[idx]);
            bld.relay_to(id, &pools.letters[idx], home);
        }
    }
    // 折叠 park 落点（末状态字母滞后 1..4）。
    for (k, fl) in pools.fold.iter().enumerate() {
        let tt = (NUM_ROUNDS as i64 - 1) - (k % 4) as i64;
        let flag = k >= 4;
        let id = chain_root[flag as usize][(tt + 4) as usize];
        bld.relay_to(id, fl, fold_pts[k]);
    }

    // W 正典根：t<16 → 消息根（簇H H2 换根方案：None = 消息钉格（solo/
    // standalone），Some = 调用方格（常量锚格 / P_A decompose 重组值格）——
    // 只换根起点，parks/link/扩展门全不动，蓝图 §四·7）；t≥16 → STG 行。
    let mut w_root = [0usize; NUM_BLOCKS];
    for t in 0..NUM_BLOCKS {
        let h = if t < 16 {
            match msg_roots {
                None => vh(pools.msgm, rm[msg_base + t]),
                Some(cells) => vh(cells[t].0, cells[t].1),
            }
        } else {
            pools.stg.at(zp.stripe_row(t, off::STG))
        };
        w_root[t] = bld.begin_relay(&h);
    }
    // 扩展源落点（j∈16..68，五个回看）；wd4（W′ 远源）；worg 自用复制。
    for j in 16..NUM_BLOCKS {
        for (gi, back) in E_BACKS.iter().enumerate() {
            let id = w_root[j - back];
            bld.relay_to(id, pools_ext_group(pools, gi), zp.stripe_row(j, off::EPARK));
        }
    }
    for j in 0..NUM_ROUNDS {
        let id = w_root[j + 4];
        bld.relay_to(id, &pools.wd4, zp.stripe_row(j, off::WD4));
    }
    for j in 0..NUM_ROUNDS {
        let id = w_root[j];
        bld.relay_to(id, &pools.worg, zp.stripe_row(j, off::WORG));
    }
    (chain_root, w_root)
}

/// 公开钉点与复制落地 link（簇G 自 build_compress_v2 抽出的共享段，纯代码
/// 搬移）：消息钉（单值列 pin.bind）+ 字母/折叠/扩展源/wd4/worg link 与见证。
/// 面无关参数化：消息基址 `msg_base`、初态 `init`（solo/体A = 编译期常量数组，
/// 体B = V_A 宿主值 —— 负轮字母的链声明经 [`chain_decl`] 自动切换
/// [`virt_from`]）、折叠落点 `fold_pts`（solo=ioStrip、两体=out 带 FOLD_BAND）。
/// NEG 锚与摘要/出口面属形态专属段，不在此层（见各装配器）。
#[allow(clippy::too_many_arguments)]
fn emit_links_and_pins(
    bld: &mut Builder<Fr_>,
    pools: &WorkPools,
    sel: &SelIds,
    zp: &'static Zone,
    msg_base: usize,
    pin_msg: bool,
    init: &[u32; 8],
    fold_pts: &[usize; 8],
    rep: &Replay,
) {
    let rm = crate::sm3_compress::row_mapping();
    // 消息钉点（v3 P1a：单值列 pin.bind 一条约束；成员性由 EPARK link 兜底）。
    // merged 形态（pin_msg=false）拆除：消息词根已换源（H2），词值由常量锚 /
    // recomp 约束绑定，不再进实例面（蓝图 §四·7 H2 实例面收缩）。
    if pin_msg {
        for j in 0..16usize {
            let pt = rm[msg_base + j];
            let s_id = sel.g(MSG_SELS[j]);
            bld.extend_selector(s_id, &[pt]);
            bld.emit_pin_val_only(s_id, pools.msgm, msg_base + j);
            bld.set_cell_u32(pools.msgm, pt, rep.w_all[j]);
        }
    }
    // 字母 link（值↔位重分解 + 位布尔）+ 见证写入。
    for j in 0..NUM_ROUNDS {
        for idx in 0..8 {
            let home = zp.stripe_row(j, letter_off_for(zp)[idx]);
            bld.extend_selector(sel.g(L_SELS[idx]), &[home]);
            bld.emit_word_link(sel.g(L_SELS[idx]), &pools.letters[idx]);
            let tt = letter_src_t(j, idx);
            bld.set_word(
                &pools.letters[idx].at(home),
                chain_decl(init, tt, LETTER_PNXT[idx], &rep.rvs),
            );
        }
    }
    // 折叠 link + 见证。
    for k in 0..8usize {
        let home = fold_pts[k];
        bld.extend_selector(sel.g(F_SELS[k]), &[home]);
        bld.emit_word_link(sel.g(F_SELS[k]), &pools.fold[k]);
        let lag = (k % 4) + 1;
        let tt = (NUM_ROUNDS as i64) - lag as i64;
        let flag = k >= 4;
        bld.set_word(&pools.fold[k].at(home), chain_decl(init, tt, flag, &rep.rvs));
    }
    // 扩展源 link + 见证（五组都在 EPARK 同点异列）。
    for j in 16..NUM_BLOCKS {
        for (gi, back) in E_BACKS.iter().enumerate() {
            let home = zp.stripe_row(j, off::EPARK);
            let gsel = sel.g(E_SELS[gi]);
            bld.extend_selector(gsel, &[home]);
            bld.emit_word_link(gsel, pools_ext_group(pools, gi));
            bld.set_word(&pools_ext_group(pools, gi).at(home), rep.w_all[j - back]);
        }
    }
    // wd4 / worg link + 见证。
    for j in 0..NUM_ROUNDS {
        let home = zp.stripe_row(j, off::WD4);
        bld.extend_selector(sel.g("l.wd4"), &[home]);
        bld.emit_word_link(sel.g("l.wd4"), &pools.wd4);
        bld.set_word(&pools.wd4.at(home), rep.w_all[j + 4]);

        let home = zp.stripe_row(j, off::WORG);
        bld.extend_selector(sel.g("l.worg"), &[home]);
        bld.emit_word_link(sel.g("l.worg"), &pools.worg);
        bld.set_word(&pools.worg.at(home), rep.w_all[j]);
    }
}

/// 装配 SM3 单块压缩的 v2 电路。公开语句 = W[0..15] 与 8 个摘要字；
/// mock-prover 验证位级约束；跨条带等式由后端积论证在真实协议里成立。
pub fn build_compress_v2(block64: &[u8; 64]) -> Sm3V2Circuit {
    let rep = replay(block64);
    let iv_words = crate::sm3_native_ref::IV;
    let rm = crate::sm3_compress::row_mapping();

    let mut bld = Builder::<Fr_>::new(ord::TOTAL);
    let pools = WorkPools::alloc(&mut bld);
    let face = DigestFace::alloc(&mut bld, true);

    // T_j 预处理多项式（值在各轮 SS1PRE 行的点值上 —— 勘误 #14 承续）
    let mut tj_vals = vec![<Fr_ as From<u64>>::from(0u64); ROWS];
    for j in 0..NUM_ROUNDS {
        tj_vals[s_row(j, off::SS1PRE)] = <Fr_ as From<u64>>::from(tj_value(j) as u64);
    }
    let tj_prep = bld.alloc_const_poly(tj_vals);

    let sel = SelIds::alloc(&mut bld, SEL_NAMES);
    let cp = bld.alloc_carries();

    // ---- 公开语句面：16 消息 + 8 摘要（摘要值已知，直接入实例表）----
    for j in 0..16usize {
        bld.set_instance(
            ord::BASE_MSG + j,
            <Fr_ as From<u64>>::from(rep.w_all[j] as u64),
        );
    }
    for k in 0..8usize {
        bld.set_instance(
            ord::BASE_DG + k,
            <Fr_ as From<u64>>::from((rep.final_state[k] ^ iv_words[k]) as u64),
        );
    }

    // ══════════ 中继登记（root-major；先于约束无关，互不耦合）══════════
    // 协议红线：每格至多一环一位；所有同根消费串进同一条根环。
    // 簇G 抽出共享段：solo 传 ZONE0 / 消息基址 0 / ioStrip 折叠落点。
    let fold_pts_io: [usize; 8] = std::array::from_fn(io_row);
    let _rings =
        register_chain_rings(&mut bld, &pools, &ZONE0, ord::BASE_MSG, None, &fold_pts_io);

    // 摘要 echo 根：digval 列在 ioRow(k) 的格 → 单值列 echo @ 实例映射点（P1b）。
    for k in 0..8usize {
        let root_h = vh(face.digval, io_row(k));
        let id = bld.begin_relay(&root_h);
        bld.relay_to_col(id, face.echo.expect("摘要面需 echo 列"), rm[ord::BASE_DG + k]);
    }

    // ══════════ 常量锚 / 公开钉点 / 复制落地 link ══════════

    // 负轮锚（v3 P1c：两族单值列，各行独立签）：一条 sel·(val−const)=0
    // 直接把根值封死；见证格写同值。字母/折叠 park 的 link 负责下游重分解。
    for kk in 0..4i64 {
        let tt = kk - 4;
        // TT1 族
        let hs = sel.g(NEG_T_SELS[kk as usize]);
        let pt = canon_home(tt, false);
        bld.extend_selector(hs, &[pt]);
        bld.emit_const_val(hs, pools.neg_t1, virt_cell(tt, false));
        bld.set_cell_u32(pools.neg_t1, pt, virt_cell(tt, false));
        // PNXT 族
        let hp_s = sel.g(NEG_P_SELS[kk as usize]);
        let ppt = canon_home(tt, true);
        bld.extend_selector(hp_s, &[ppt]);
        bld.emit_const_val(hp_s, pools.neg_pn, virt_cell(tt, true));
        bld.set_cell_u32(pools.neg_pn, ppt, virt_cell(tt, true));
    }
    // 公开钉点与复制落地 link（簇G 第三层抽出共享段：solo 传 ZONE0 / BASE_MSG /
    // IV / ioStrip 折叠落点，发射顺序逐字保持）。
    emit_links_and_pins(
        &mut bld,
        &pools,
        &sel,
        &ZONE0,
        ord::BASE_MSG,
        true,
        &iv_words,
        &fold_pts_io,
        &rep,
    );
    // 摘要 echo pin（v3 P1b：单值列 pin.bind 一条约束）+ digval 格写值稍后于折叠门。
    for k in 0..8usize {
        let pt = rm[ord::BASE_DG + k];
        let s_id = sel.g(ECHO_SELS[k]);
        bld.extend_selector(s_id, &[pt]);
        bld.emit_pin_val_only(s_id, face.echo.expect("摘要面需 echo 列"), ord::BASE_DG + k);
    }

    // ══════════ 门层（簇G 抽出共享；solo 走 ZONE0，发射顺序逐字不变）══════════
    emit_round_gates(&mut bld, &pools, &sel, &cp, tj_prep, &ZONE0, &rep);

    // ---- 摘要折叠：O_k = fold_k⟨rot⟩ ⊕ IV_k 写入共享 digval 列 ----
    for k in 0..8usize {
        let at = io_row(k);
        let fl = pools.fold[k].at(at);
        let slot = if DIG_ROTS[k] == 0 {
            SlotRef::view(&fl)
        } else {
            SlotRef::rotl(&fl, DIG_ROTS[k])
        };
        bld.extend_selector(sel.g(DG_SELS[k]), &[at]);
        bld.emit_feedforward_val(sel.g(DG_SELS[k]), &slot, iv_words[k], face.digval, at);
        let want = rep.final_state[k] ^ iv_words[k];
        bld.set_cell_u32(face.digval, at, want);
        // echo 钉点见证（v3 P1b：单值列格写值，pin.bind 绑定实例）
        bld.set_cell_u32(face.echo.expect("摘要面需 echo 列"), rm[ord::BASE_DG + k], want);
    }

    // ---- 出料 ----
    let (info, advice, instances, tags, ctags, num_selectors) = bld.finish_parts();
    let relay_census: Vec<usize> = info.permutations.iter().map(|c| c.len()).collect();
    let digest = [
        rep.final_state[0] ^ iv_words[0],
        rep.final_state[1] ^ iv_words[1],
        rep.final_state[2] ^ iv_words[2],
        rep.final_state[3] ^ iv_words[3],
        rep.final_state[4] ^ iv_words[4],
        rep.final_state[5] ^ iv_words[5],
        rep.final_state[6] ^ iv_words[6],
        rep.final_state[7] ^ iv_words[7],
    ];
    Sm3V2Circuit {
        info,
        advice,
        instances,
        tags,
        ctags,
        num_selectors,
        digest,
        relay_census,
    }
}

// ───────────────────────── 两体装配器（簇G/G2，决策 #23） ─────────────────────────

/// Z_U 两体电路对象：体A(IV₂,B₂) → V_A → 体B(V_A,B₃) → Z_U 摘要。
#[derive(Clone, Debug)]
pub struct Sm3ZuCircuit {
    pub info: PlonkishCircuitInfo<Fr_>,
    pub advice: Vec<Vec<Fr_>>,
    pub instances: Vec<Vec<Fr_>>,
    pub tags: Vec<(&'static str, usize)>,
    /// 与 info.constraints 平行的家族标签。
    pub ctags: Vec<&'static str>,
    pub num_selectors: usize,
    /// Z_U 摘要真值（体B 摘要面宿主值）。
    pub digest: [u32; 8],
    /// 体间链值 V_A 宿主真值（对拍/篡改负例定位用）。
    pub va: [u32; 8],
    /// 中继环长度账本（环数=vec.len()；单项环已滤除）。
    pub relay_census: Vec<usize>,
    /// 篡改负例锚点（诊断出口）：进口词值列 ×8 与进口行 ×8、出口值列与
    /// 出口折叠行 ×8。环成员格 —— 改值必触发环审计 + 对侧 link/ff 门违约。
    pub imp_val_cols: [usize; 8],
    pub imp_rows: [usize; 8],
    pub export_val_col: usize,
    pub export_rows: [usize; 8],
    /// 体B 摘要 echo 列（pin.bind 绑定实例的唯一线索列；篡改负例锚）。
    pub echo_col: usize,
}

impl PlonkishCircuit<Fr_> for Sm3ZuCircuit {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<Fr_>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<Fr_>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<Fr_>] {
        &self.instances
    }
    fn synthesize(&self, round: usize, challenges: &[Fr_]) -> Result<Vec<Vec<Fr_>>, Error> {
        assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
        Ok(self.advice.clone())
    }
}

/// 体B 负轮锚的进口源映射与线性旋转量（P-a 精化）：TT1 族锚 k ↔ VA[3−k]
/// （rotr9 = lin_rotl⟨23⟩）；PNXT 族锚 k ↔ VA[4+(3−k)]（rotr19 = lin_rotl⟨13⟩）。
/// 与 [`virt_from`] 的数组序逐项对齐；查询距离账：R1-v3b T2 三星交错
/// （[`LAYOUT_STAR`]）后 |锚行 − 进步行| = 1（原簇G 编址下 d∈{11,9,7,5}，
/// edge-at 机械归因见蓝图 §五）。
const NEG_VAR_ANCHOR: [([usize; 4], [u32; 4]); 2] = [
    ([3, 2, 1, 0], [23, 23, 0, 0]), // TT1 族（锚行 out 带 0..4）
    ([7, 6, 5, 4], [13, 13, 0, 0]), // PNXT 族（锚行 out 带 4..8）
];

// ───────────────────── 两体装配器（簇G/G2 决策 #23；簇H H1 段化） ─────────────────────

/// 换根消息格：(列, 行)。merged 形态下 t<16 消息词环根的起点（蓝图 §四·7 H2
/// 换根方案：常量词 = 常量锚格、变量词 = P_A decompose 重组值格）。
pub type MsgCell = (usize, usize);

/// 两体装配形态（蓝图 §四·7 H1/H2）。
pub enum ZuForm {
    /// standalone（簇G 形状锁定形态）：消息词 32 = 实例钉（基址 0/16），
    /// 摘要 8 = 实例钉（基址 [`ord::BASE_DG_TWO`]）；消息根 = pools.msgm 钉格。
    Standalone,
    /// merged（簇H 形态）：消息词不进实例面、环根 = 调用方格
    /// （常量锚格 / P_A decompose 重组值格，[体A 16, 体B 16]）；摘要 8 =
    /// 实例钉（基址 dg_base，合并装配器 = 12，H1·5）。
    Merged {
        dg_base: usize,
        msg_roots: [[MsgCell; 16]; 2],
    },
    /// B-batch2 承诺档（2026-09-15）：IV 初态单块——消息根 = 调用方 16 格
    /// （salt‖attrs 见证词 + padding 常量词），摘要**不进实例面**（出口 =
    /// face_a.out_val @ ZONE0 折叠行，调用方经折叠==约束绑定，E7 先例零新环）。
    /// ZuCtx 的 b3 在本形态被忽略。
    CommitOne,
}

/// 两体装配上下文。
pub struct ZuCtx<'a> {
    pub b2: &'a [u8; 64],
    pub b3: &'a [u8; 64],
    /// IV₂ 由调用方从 `sm2_z_anchor::z_u_prelude_state` 机械取（禁手抄，L2 红线）。
    pub iv2: &'a [u32; 8],
    pub form: ZuForm,
}

/// 两体段装配产出（merged 装配器接线/负例所需的最小面）。
pub struct ZuBodyOut {
    /// 体间链值 V_A 宿主真值（篡改负例锚）。
    pub va: [u32; 8],
    /// Z_U 摘要宿主真值（merged：调用方 set_instance(dg_base+k) 已在本段完成）。
    pub digest: [u32; 8],
    /// 体B 摘要 echo 列（实例绑定列；篡改负例用）。
    pub echo_col: usize,
    /// 体A 出口值列与折叠行（链值通道源侧）。
    pub export_val_col: usize,
    pub export_rows: [usize; 8],
    /// 体B 进口词值列与进口行（链值通道汇侧；篡改负例锚）。
    pub imp_val_cols: [usize; 8],
    pub imp_rows: [usize; 8],
    /// 体A 负轮 TT1 族 t=−4 锚格 (列, 行)（簇H H4 负例三锚点：IV₂ 烘焙
    /// 常量格 —— emit_const_val 绑定 + 链环根，翻一格双信号齐爆）。
    pub neg_a_t1: (usize, usize),
}

/// merged 两体段的 plan 相句柄（簇H H1：Builder 冻结守卫要求全部分配先于
/// 第一条约束 ⟹ alloc 与 emit 拆两半；字段私有，调用方仅传递不读内部）。
pub struct ZuPlan {
    inner: ZpParts,
}

impl ZuPlan {
    /// B-batch2:体A 出口值列(承诺档 C 绑定环的 PLAN 相登记用——发射前
    /// 即需列号;等价于 ZuBodyOut.export_val_col 的发射前形态)。
    pub fn face_a_out_val(&self) -> usize {
        self.inner.face_a.out_val
    }
}

struct ZpParts {
    pools_a: WorkPools,
    /// R2 手术（2026-09-23）：CommitOne 单块形态零消费体B（死列普查定谳：
    /// 9121..10730 连续 1,609 列=体B 空挂全零，源注释自认）⟹ 单块 plan
    /// （[`plan_z_parts_single`]）不分配；两体形态（[`plan_z_parts`]）照旧。
    pools_b: Option<WorkPools>,
    face_a: ExportFace,
    face_b: Option<DigestFace>,
    imp: Option<ImportFace>,
    imp_sels: Option<[usize; 8]>,
    sel_a: SelIds,
    sel_b: Option<SelIds>,
    cp: CarryPair,
    tj_prep: usize,
}

/// plan 相：分配两体全套组件。必须在 Builder 第一条约束发射前调用
/// （standalone 薄壳与 merged 装配器共用；merged 在 plan_all 之前调用）。
pub fn plan_z_parts(bld: &mut Builder<Fr_>) -> ZuPlan {
    // 执行定案①：两体各 alloc 一套 WorkPools/SelIds（「共享选择器×烘焙 konst
    // 违约坍缩」免疫，P1s1-C4）；面按体裁剪：体A=出口面、体B=进口+摘要面。
    // 体A 的 echo 钉点不存在（出口面无 echo）⟹ 选择器表过滤 l.echo*，
    // 死预处理多项式不进证明（蓝图 §四·6 面裁剪纪律）。
    let pools_a = WorkPools::alloc(bld);
    let pools_b = WorkPools::alloc(bld);
    let face_a = ExportFace::alloc(bld);
    let face_b = DigestFace::alloc(bld, true);
    let imp = ImportFace::alloc(bld);
    let imp_sels: [usize; 8] = std::array::from_fn(|_| bld.alloc_selector(&[]));
    let names_a: Vec<&'static str> = SEL_NAMES
        .iter()
        .copied()
        .filter(|n| !n.starts_with("l.echo"))
        .collect();
    let sel_a = SelIds::alloc(bld, &names_a);
    let sel_b = SelIds::alloc(bld, SEL_NAMES);
    // 共享 carry 对：进位布尔约束按行选择器门控，两体行不相交，列复用合法。
    let cp = bld.alloc_carries();

    // T_j 预处理多项式一份覆盖两体 off1 点集（P-c：不同点不冲突，cur 查询
    // 全局成立）——省 1 份提交。
    let mut tj_vals = vec![<Fr_ as From<u64>>::from(0u64); ROWS];
    for j in 0..NUM_ROUNDS {
        tj_vals[ZONE0.stripe_row(j, off::SS1PRE)] = <Fr_ as From<u64>>::from(tj_value(j) as u64);
        tj_vals[ZONEB.stripe_row(j, off::SS1PRE)] = <Fr_ as From<u64>>::from(tj_value(j) as u64);
    }
    let tj_prep = bld.alloc_const_poly(tj_vals);
    ZuPlan {
        inner: ZpParts {
            pools_a,
            pools_b: Some(pools_b),
            face_a,
            face_b: Some(face_b),
            imp: Some(imp),
            imp_sels: Some(imp_sels),
            sel_a,
            sel_b: Some(sel_b),
            cp,
            tj_prep,
        },
    }
}

/// R2 手术（2026-09-23）：CommitOne 单块形态专用 plan——体B 全套不分配。
/// 收益 [实测 auth_census 死列普查]：advice −1,609 列（9121..10730 连续块
/// =体B 空挂全零）+ sel_b/imp_sels 选择器 prep 列若干；证明器四类成本
/// （掩蔽/承诺/开口/内存）随列数同比例下降。两体形态走 [`plan_z_parts`]
/// 零变化（T1/merged 发布锚不动）。分配序=plan_z_parts 的单块投影
/// （pools_a→face_a→sel_a→cp→tj_prep）。
pub fn plan_z_parts_single(bld: &mut Builder<Fr_>) -> ZuPlan {
    let pools_a = WorkPools::alloc(bld);
    let face_a = ExportFace::alloc(bld);
    let names_a: Vec<&'static str> = SEL_NAMES
        .iter()
        .copied()
        .filter(|n| !n.starts_with("l.echo"))
        .collect();
    let sel_a = SelIds::alloc(bld, &names_a);
    let cp = bld.alloc_carries();
    // T_j 预处理列：单块形态只消费 ZONE0 off1 点集（ZONEB 行值零消费，
    // 与两体共面取同式填充——1 份 prep 列，无面裁剪必要）。
    let mut tj_vals = vec![<Fr_ as From<u64>>::from(0u64); ROWS];
    for j in 0..NUM_ROUNDS {
        tj_vals[ZONE0.stripe_row(j, off::SS1PRE)] = <Fr_ as From<u64>>::from(tj_value(j) as u64);
        tj_vals[ZONEB.stripe_row(j, off::SS1PRE)] = <Fr_ as From<u64>>::from(tj_value(j) as u64);
    }
    let tj_prep = bld.alloc_const_poly(tj_vals);
    ZuPlan {
        inner: ZpParts {
            pools_a,
            pools_b: None,
            face_a,
            face_b: None,
            imp: None,
            imp_sels: None,
            sel_a,
            sel_b: None,
            cp,
            tj_prep,
        },
    }
}

/// 环登记的形态参数（簇H H1：`begin_relay*` 带冻结守卫 ⟹ 全部环首键注册
/// 必须在 plan 相完成，[`plan_z_rings`] 是 Z 段环的唯一登记口）。
pub enum ZuRingRoots {
    /// 消息词根 = pools.msgm 钉格（standalone；msg_base 0/16）。
    Pinned,
    /// 消息词根 = 调用方格（merged；H2 换根），摘要 echo 钉入 rm[dg_base+k]。
    Cells { dg_base: usize, msg_roots: [[MsgCell; 16]; 2] },
    /// B-batch2 承诺档（2026-09-15）：IV 初态**单块**——体A 消息根 = 调用方
    /// 16 格（salt‖attrs 见证词 + padding 常量词），无体B、无实例面、无 echo
    /// 环（出口绑定归调用方 E7 式折叠==约束，零新环）。体B 的列空挂全零
    /// （T3 静态口径 = 全零自由列，工程冗余如实计数）。
    CommitOne { msg_roots: [[MsgCell; 16]; 1] },
}

/// Z 段环登记账本（id 仅诊断用 —— 追加成员已在 plan 相随登记完成）。
#[allow(dead_code)]
pub struct ZuRings {
    /// 体A 链根 (TT1 族, PNXT 族) × 68。
    chain_a: [[usize; NUM_BLOCKS]; 2],
    /// 体B 链根。
    chain_b: [[usize; NUM_BLOCKS]; 2],
    /// 体A/体B W 正典根。
    w_a: [usize; NUM_BLOCKS],
    w_b: [usize; NUM_BLOCKS],
    /// 体间链值通道环 ×8（出口格 → 进口格）。
    channel: [usize; 8],
    /// 体B 摘要 echo 根环 ×8。
    echo: [usize; 8],
}

/// plan 相：Z 段全部中继环的首键注册 + 成员追加（`begin_relay*` 带冻结守卫
/// ⟹ 必须先于第一条款束；成员几何 plan 相已知，`relay_to/relay_to_col`
/// 无守卫本可延后，但同批完成使环拓扑单点收口）。登记顺序与
/// [`assemble_z_bodies`] 原内联段逐字一致（register_a → register_b →
/// 体间通道 → echo 根），standalone 形状不受影响。
pub fn plan_z_rings(bld: &mut Builder<Fr_>, plan: &ZuPlan, roots: &ZuRingRoots) -> ZuRings {
    let ZpParts { pools_a, pools_b, face_a, face_b, imp, .. } = &plan.inner;
    let fold_pts_a: [usize; 8] = std::array::from_fn(|k| ZONE0.fold_row(k));
    let fold_pts_b: [usize; 8] = std::array::from_fn(|k| ZONEB.fold_row(k));
    if let ZuRingRoots::CommitOne { msg_roots } = roots {
        // 单块：仅体A 消息根环；体B/通道/echo 零登记（R2 手术后体B 连分配
        // 都不存在——plan_z_parts_single pools_b=None）。
        let (chain_a, w_a) =
            register_chain_rings(bld, pools_a, &ZONE0, ord::BASE_MSG, Some(&msg_roots[0]), &fold_pts_a);
        return ZuRings { chain_a, chain_b: [[0; NUM_BLOCKS]; 2], w_a, w_b: [0; NUM_BLOCKS], channel: [0; 8], echo: [0; 8] };
    }
    let pools_b = pools_b.as_ref().expect("两体形态需体B（CommitOne 单块 plan 不可走此径）");
    let face_b = face_b.as_ref().expect("两体形态需摘要面");
    let imp = imp.as_ref().expect("两体形态需进口面");
    let (roots_a, roots_b, dg_base) = match roots {
        ZuRingRoots::Pinned => (None, None, ord::BASE_DG_TWO),
        ZuRingRoots::Cells { dg_base, msg_roots } => {
            (Some(&msg_roots[0]), Some(&msg_roots[1]), *dg_base)
        }
        ZuRingRoots::CommitOne { .. } => unreachable!("CommitOne 已提前返回"),
    };
    let (chain_a, w_a) =
        register_chain_rings(bld, pools_a, &ZONE0, ord::BASE_MSG, roots_a, &fold_pts_a);
    let (chain_b, w_b) =
        register_chain_rings(bld, pools_b, &ZONEB, ord::BASE_MSG_B, roots_b, &fold_pts_b);
    // 体间链值通道（决策 #23 ④）：体A 出口值列 @ 折叠行 → 环 → 体B 进口词
    // 值列 @ 进口行。改任一侧：环审计必报（mock 看不见置换层）+ 消费门违约。
    let channel: [usize; 8] = std::array::from_fn(|k| {
        let id = bld.begin_relay(&vh(face_a.out_val, ZONE0.fold_row(k)));
        bld.relay_to_col(id, imp.words[k].val.expect("进口词需值列"), ZONEB.imp_row(k));
        id
    });
    // 体B 摘要 echo 根：digval @ 折叠行 → 环 → echo @ rm[dg_base+k]（P1b）。
    let rm = crate::sm3_compress::row_mapping();
    let echo: [usize; 8] = std::array::from_fn(|k| {
        let root_h = vh(face_b.digval, ZONEB.fold_row(k));
        let id = bld.begin_relay(&root_h);
        bld.relay_to_col(id, face_b.echo.expect("摘要面需 echo 列"), rm[dg_base + k]);
        id
    });
    ZuRings { chain_a, chain_b, w_a, w_b, channel, echo }
}

/// 装配 Z_U 两体段到**既有** Builder（簇H H1 段化：build_two_bodies 主体抽出，
/// merged 装配器（sm2_verify_assemble）在自家 plan/emit 之后尾接本段，不再
/// 自建 Builder/finish）。公开语句按 [`ZuForm`]：standalone = B₂ 16 词 + B₃
/// 16 词 + Z_U 摘要 8 字（[`ord::TOTAL_TWO`]）；merged = 摘要 8 字（dg_base），
/// 消息词根换源、不进实例面。体间链值 V_A 经「出口环 → 进口环」中继（零旋转）；
/// 数值唯一来源 = [`replay_with_state`] × 2 + 宿主 XOR（勘误 #11 承续）。
pub fn assemble_z_bodies(mut bld: &mut Builder<Fr_>, plan: &ZuPlan, ctx: &ZuCtx) -> ZuBodyOut {
    use plonkish_backend::util::expression::Expression;
    use plonkish_backend::util::expression::Rotation;

    // B-batch2：单块形态短路（体A 全链 + 出口面；体B 零发射）——原两形态
    // 路径零触碰。
    if matches!(ctx.form, ZuForm::CommitOne) {
        return assemble_commit_one(bld, plan, ctx);
    }

    // ---- 宿主数学：两体数值链（体B 初态 = 体A 出口；compress 契约 = 返回值
    //      已含链接 XOR，摘要 = final_B ⊕ V_A，末端禁再 ⊕IV —— 簇F′ 教训）----
    let rep_a = replay_with_state(ctx.iv2, ctx.b2);
    let va_host: [u32; 8] = std::array::from_fn(|k| rep_a.final_state[k] ^ ctx.iv2[k]);
    let rep_b = replay_with_state(&va_host, ctx.b3);
    let digest_host: [u32; 8] = std::array::from_fn(|k| rep_b.final_state[k] ^ va_host[k]);
    let rm = crate::sm3_compress::row_mapping();

    // 形态参数折叠：摘要 ordinal 基址（H1·5：standalone=32 / merged=12）、
    // 消息根（standalone=钉格 / merged=调用方格）、消息钉开关。
    let dg_base = match &ctx.form {
        ZuForm::Standalone => ord::BASE_DG_TWO,
        ZuForm::Merged { dg_base, .. } => *dg_base,
        ZuForm::CommitOne => unreachable!("CommitOne 已在函数入口短路"),
    };
    let pin_msg = matches!(ctx.form, ZuForm::Standalone);
    // 布局产物自 plan 相句柄解构（簇H H1：全部 alloc 已前置到
    // [`plan_z_parts`]，此处零分配 —— Builder 冻结守卫合规；merged 装配器
    // 在自家 EMIT 之后才调用本段，plan 句柄在其 plan_all 之前构造）。
    let ZpParts { pools_a, pools_b, face_a, face_b, imp, imp_sels, sel_a, sel_b, cp, tj_prep } =
        &plan.inner;
    let pools_b = pools_b.as_ref().expect("两体形态需体B（CommitOne 单块 plan 不可走此径）");
    let face_b = face_b.as_ref().expect("两体形态需摘要面");
    let imp = imp.as_ref().expect("两体形态需进口面");
    let imp_sels = imp_sels.as_ref().expect("两体形态需进口选择器");
    let sel_b = sel_b.as_ref().expect("两体形态需体B 选择器");

    // ---- 公开语句面：standalone = B₂ 16 + B₃ 16 + 摘要 8；merged = 摘要 8
    //      （消息词值由常量锚 / recomp 约束绑定，不进实例面 —— H2 收缩）----
    if pin_msg {
        for j in 0..16usize {
            bld.set_instance(
                ord::BASE_MSG + j,
                <Fr_ as From<u64>>::from(rep_a.w_all[j] as u64),
            );
            bld.set_instance(
                ord::BASE_MSG_B + j,
                <Fr_ as From<u64>>::from(rep_b.w_all[j] as u64),
            );
        }
    }
    for k in 0..8usize {
        bld.set_instance(dg_base + k, <Fr_ as From<u64>>::from(digest_host[k] as u64));
    }

    // ══════════ 中继登记已整体迁入 plan 相（[`plan_z_rings`]，簇H H1：
    //      begin_relay* 带冻结守卫）——本函数不再触碰任何分配口 ══════════

    // ══════════ 负轮锚（体A 常量 / 体B 变量线性绑定）══════════
    // 体A：初态 IV₂ 是公开常量 ⟹ 锚 = sel·(val − virt_from(IV₂))，solo 同款。
    for kk in 0..4i64 {
        let tt = kk - 4;
        let hs = sel_a.g(NEG_T_SELS[kk as usize]);
        let pt = ZONE0.canon_home(tt, false);
        bld.extend_selector(hs, &[pt]);
        bld.emit_const_val(hs, pools_a.neg_t1, virt_from(ctx.iv2, tt, false));
        bld.set_cell_u32(pools_a.neg_t1, pt, virt_from(ctx.iv2, tt, false));

        let hp_s = sel_a.g(NEG_P_SELS[kk as usize]);
        let ppt = ZONE0.canon_home(tt, true);
        bld.extend_selector(hp_s, &[ppt]);
        bld.emit_const_val(hp_s, pools_a.neg_pn, virt_from(ctx.iv2, tt, true));
        bld.set_cell_u32(pools_a.neg_pn, ppt, virt_from(ctx.iv2, tt, true));
    }
    // 体B（P-a 精化）：初态 V_A 是变量 ⟹ 锚格用一条线性约束绑定到进口位
    // （旋转 = 位重排 = 纯线性，lin_rotl 视图），不设 XOR 门；锚格仍作链环根。
    for (fam, (srcs, rots)) in NEG_VAR_ANCHOR.iter().enumerate() {
        for kk in 0..4usize {
            let tt = kk as i64 - 4;
            let s_id = sel_b.g(if fam == 0 { NEG_T_SELS[kk] } else { NEG_P_SELS[kk] });
            let pt = ZONEB.canon_home(tt, fam == 1);
            let anchor_col = if fam == 0 { pools_b.neg_t1 } else { pools_b.neg_pn };
            bld.extend_selector(s_id, &[pt]);
            let va_h = imp.words[srcs[kk]].at(ZONEB.imp_row(srcs[kk]));
            let want = bld.q(anchor_col, Rotation::cur()) - bld.lin_rotl(&va_h, rots[kk], pt);
            bld.emit_assert_zero(s_id, want);
            bld.set_cell_u32(anchor_col, pt, virt_from(&va_host, tt, fam == 1));
        }
    }

    // ══════════ 公开钉点 / link（共享段 ×2）══════════
    let fold_pts_a: [usize; 8] = std::array::from_fn(|k| ZONE0.fold_row(k));
    let fold_pts_b: [usize; 8] = std::array::from_fn(|k| ZONEB.fold_row(k));
    emit_links_and_pins(
        &mut bld,
        pools_a,
        sel_a,
        &ZONE0,
        ord::BASE_MSG,
        pin_msg,
        ctx.iv2,
        &fold_pts_a,
        &rep_a,
    );
    emit_links_and_pins(
        &mut bld,
        pools_b,
        sel_b,
        &ZONEB,
        ord::BASE_MSG_B,
        pin_msg,
        &va_host,
        &fold_pts_b,
        &rep_b,
    );

    // 体B 进口 link（值↔位重分解 + 位布尔；环值 = 体A 出口 V_A）。
    for k in 0..8usize {
        let home = ZONEB.imp_row(k);
        bld.extend_selector(imp_sels[k], &[home]);
        bld.emit_word_link(imp_sels[k], &imp.words[k]);
        bld.set_word(&imp.words[k].at(home), va_host[k]);
    }

    // 体B 摘要 echo pin（v3 P1b：单值列 pin.bind 一条约束绑定实例）。**此段
    // 不可省**：pin.bind 是实例摘要值与电路线索的唯一绑定，缺它则 mock 与
    // 环审计双绿（见证恰好一致）但 prover 可伪造摘要语句 —— 首跑对账
    // pin.bind −8 抓获（勘误 #24）。
    for k in 0..8usize {
        let pt = rm[dg_base + k];
        let s_id = sel_b.g(ECHO_SELS[k]);
        bld.extend_selector(s_id, &[pt]);
        bld.emit_pin_val_only(s_id, face_b.echo.expect("摘要面需 echo 列"), dg_base + k);
    }

    // ══════════ 门层 ×2（簇G 抽出共享）══════════
    emit_round_gates(&mut bld, pools_a, sel_a, cp, *tj_prep, &ZONE0, &rep_a);
    emit_round_gates(&mut bld, pools_b, sel_b, cp, *tj_prep, &ZONEB, &rep_b);

    // ---- 体A 出口面：O_k = fold_k⟨rot⟩ ⊕ IV₂_k（feedforward 线性形态，
    //      solo 摘要门同款；出口值进共享 out_val 列并开环至体B 进口）----
    for k in 0..8usize {
        let at = ZONE0.fold_row(k);
        let fl = pools_a.fold[k].at(at);
        let slot = if DIG_ROTS[k] == 0 {
            SlotRef::view(&fl)
        } else {
            SlotRef::rotl(&fl, DIG_ROTS[k])
        };
        bld.extend_selector(sel_a.g(DG_SELS[k]), &[at]);
        bld.emit_feedforward_val(sel_a.g(DG_SELS[k]), &slot, ctx.iv2[k], face_a.out_val, at);
        bld.set_cell_u32(face_a.out_val, at, va_host[k]);
    }

    // ---- 体B 摘要面：O_k = fold_k⟨rot⟩ ⊕ VA_k（**真 XOR 门**——第二操作数
    //      是变量词，位格经进口 link 重分解）+ 线性重组进 digval + echo 见证。
    //      位布尔性由 XOR 门与输入位布尔性传递，无需额外 bool。----
    for k in 0..8usize {
        let at = ZONEB.fold_row(k);
        let fl = pools_b.fold[k].at(at);
        let x = if DIG_ROTS[k] == 0 {
            SlotRef::view(&fl)
        } else {
            SlotRef::rotl(&fl, DIG_ROTS[k])
        };
        let y = SlotRef::view(&imp.words[k].at(ZONEB.imp_row(k)));
        let o = imp.digbits.at(at);
        bld.extend_selector(sel_b.g(DG_SELS[k]), &[at]);
        bld.emit_xor(sel_b.g(DG_SELS[k]), &x, &y, &o, at);
        // 输出值重组：Σ2^i·o_i = digval（线性）。
        let mut recomp = Expression::<Fr_>::zero();
        for i in 0..32usize {
            recomp = recomp
                + Expression::<Fr_>::Constant(<Fr_ as From<u64>>::from(1u64 << i))
                    * bld.q(imp.digbits.bits[i], Rotation::cur());
        }
        let re = recomp - bld.q(face_b.digval, Rotation::cur());
        bld.emit_assert_zero(sel_b.g(DG_SELS[k]), re);
        let want = digest_host[k];
        bld.set_word(&o, want);
        bld.set_cell_u32(face_b.digval, at, want);
        bld.set_cell_u32(face_b.echo.expect("摘要面需 echo 列"), rm[dg_base + k], want);
    }

    // ---- 段出料：返回接线/负例所需最小面（Builder 归调用方 finish）----
    ZuBodyOut {
        va: va_host,
        digest: digest_host,
        echo_col: face_b.echo.expect("摘要面需 echo 列"),
        export_val_col: face_a.out_val,
        export_rows: std::array::from_fn(|k| ZONE0.fold_row(k)),
        imp_val_cols: std::array::from_fn(|k| imp.words[k].val.expect("进口词需值列")),
        imp_rows: std::array::from_fn(|k| ZONEB.imp_row(k)),
        neg_a_t1: (pools_a.neg_t1, ZONE0.canon_home(-4, false)),
    }
}

/// B-batch2 承诺档（2026-09-15）：IV 初态单块装配——体A 全链（负轮锚常量
/// + links + 轮门 + 出口面 feedforward⊕IV）。单块摘要 = CF(IV, b2) 的 8 词
/// （= 两体路径的 va_host 同型：final_state ⊕ IV），出口见证落 face_a.out_val
/// @ ZONE0.fold_row(k)，调用方（t1 承诺档）经折叠==约束绑定 C 词列（E7 先例）。
/// 体B 段零发射（列空挂全零）；实例面零占用。
fn assemble_commit_one(
    mut bld: &mut Builder<Fr_>,
    plan: &ZuPlan,
    ctx: &ZuCtx,
) -> ZuBodyOut {
    use plonkish_backend::util::expression::Rotation;

    // 宿主数学：单块压缩（replay 契约 = 返回值已含链接 XOR ⟹ 出口 = final ⊕ IV）。
    let rep_a = replay_with_state(ctx.iv2, ctx.b2);
    let digest_host: [u32; 8] =
        std::array::from_fn(|k| rep_a.final_state[k] ^ ctx.iv2[k]);

    let ZpParts { pools_a, face_a, sel_a, cp, tj_prep, .. } = &plan.inner;

    // 负轮锚（体A 形态：初态 IV 是公开常量 ⟹ sel·(val − const)=0 直接封死）。
    for kk in 0..4i64 {
        let tt = kk - 4;
        let hs = sel_a.g(NEG_T_SELS[kk as usize]);
        let pt = ZONE0.canon_home(tt, false);
        bld.extend_selector(hs, &[pt]);
        bld.emit_const_val(hs, pools_a.neg_t1, virt_from(ctx.iv2, tt, false));
        bld.set_cell_u32(pools_a.neg_t1, pt, virt_from(ctx.iv2, tt, false));

        let hp_s = sel_a.g(NEG_P_SELS[kk as usize]);
        let ppt = ZONE0.canon_home(tt, true);
        bld.extend_selector(hp_s, &[ppt]);
        bld.emit_const_val(hp_s, pools_a.neg_pn, virt_from(ctx.iv2, tt, true));
        bld.set_cell_u32(pools_a.neg_pn, ppt, virt_from(ctx.iv2, tt, true));
    }

    // links/pins（体A：消息不进实例面——根格由调用方环登记接线）+ 轮门。
    let fold_pts_a: [usize; 8] = std::array::from_fn(|k| ZONE0.fold_row(k));
    emit_links_and_pins(
        &mut bld,
        pools_a,
        sel_a,
        &ZONE0,
        ord::BASE_MSG,
        false,
        ctx.iv2,
        &fold_pts_a,
        &rep_a,
    );
    emit_round_gates(&mut bld, pools_a, sel_a, cp, *tj_prep, &ZONE0, &rep_a);

    // 出口面：O_k = fold_k⟨rot⟩ ⊕ IV_k（feedforward 线性；出口 = 单块摘要词）。
    for k in 0..8usize {
        let at = ZONE0.fold_row(k);
        let fl = pools_a.fold[k].at(at);
        let slot = if DIG_ROTS[k] == 0 {
            SlotRef::view(&fl)
        } else {
            SlotRef::rotl(&fl, DIG_ROTS[k])
        };
        bld.extend_selector(sel_a.g(DG_SELS[k]), &[at]);
        bld.emit_feedforward_val(
            sel_a.g(DG_SELS[k]),
            &slot,
            ctx.iv2[k],
            face_a.out_val,
            at,
        );
        bld.set_cell_u32(face_a.out_val, at, digest_host[k]);
    }

    ZuBodyOut {
        va: digest_host,
        digest: digest_host,
        echo_col: face_a.out_val,
        export_val_col: face_a.out_val,
        export_rows: std::array::from_fn(|k| ZONE0.fold_row(k)),
        imp_val_cols: [0; 8],
        imp_rows: [0; 8],
        neg_a_t1: (pools_a.neg_t1, ZONE0.canon_home(-4, false)),
    }
}

/// Z_U 预像**变量词**的位源映射（蓝图 §四·7 H2 字节切片账，机械推导禁手抄
/// ——L2 红线承 M0 教训；纯宿主侧，测试 [`tests::zu_words_bits_crosscheck`]
/// 以 replay 词值逐词对拍锁定）。
///
/// 推导：preimage = 常量前缀 146B + xA[0..32] + yA[0..32] + 0x80 + 零填充 +
/// be64(1680)；32 位 BE 词，词位 p（0=MSB）权重 2^(31−p)；decompose 位序
/// LSB=0 ⟹ 槽字节 b 的位 t（字节内 MSB first）= 整数位 255−8b−t。
/// 返回 [(槽 0=xA/1=yA, 整数位索引, 权重指数)]，按 p 升序。
fn zu_word_bits(body: usize, j: usize) -> Vec<(usize, usize, u32)> {
    let mut v = Vec::new();
    match (body, j) {
        // B₂ 词 4：高 16 位常量（调用方补常量段），低 16 位 = xA 高 16 位
        // ⟹ p=16..31 ⟹ xA_bit[271−p]（p=16 ⟹ 255=xA MSB 权 2^15 ✓）
        (0, 4) => {
            for p in 16..32usize {
                v.push((0usize, 271usize - p, (31 - p) as u32));
            }
        }
        // B₂ 词 5..11 全 xA：xA 字节起点 b0=4j−18 ⟹ p=0 ⟹ 399−32j
        (0, 5..=11) => {
            let base = 399usize - 32 * j;
            for p in 0..32usize {
                v.push((0usize, base - p, (31 - p) as u32));
            }
        }
        // B₂ 词 12 = xA[30,31]（高 16 位 ⟹ p=0..15 ⟹ xA_bit[15−p]）‖
        // yA[0,1]（低 16 位 ⟹ p=16..31 ⟹ yA_bit[271−p]）
        (0, 12) => {
            for p in 0..16usize {
                v.push((0usize, 15usize - p, (31 - p) as u32));
            }
            for p in 16..32usize {
                v.push((1usize, 271usize - p, (31 - p) as u32));
            }
        }
        // B₂ 词 13..15 全 yA：yA 字节起点 b0=4j−50 ⟹ p=0 ⟹ 655−32j
        (0, 13..=15) => {
            let base = 655usize - 32 * j;
            for p in 0..32usize {
                v.push((1usize, base - p, (31 - p) as u32));
            }
        }
        // B₃ 词 0..3 全 yA：yA 字节起点 b0=4j+14 ⟹ p=0 ⟹ 143−32j
        (1, 0..=3) => {
            let base = 143usize - 32 * j;
            for p in 0..32usize {
                v.push((1usize, base - p, (31 - p) as u32));
            }
        }
        // B₃ 词 4：高 16 = yA 低 16 位（15−p），低 16 = 常量 0x8000
        (1, 4) => {
            for p in 0..16usize {
                v.push((1usize, 15usize - p, (31 - p) as u32));
            }
        }
        _ => unreachable!("常量词 ({body},{j}) 不走位映射"),
    }
    v
}

/// 变量词的常量段（位映射未覆盖的高位，宿主词值掩出）。
fn zu_word_const(body: usize, j: usize, w: u32) -> u32 {
    match (body, j) {
        (0, 4) => w & 0xFFFF_0000,
        (1, 4) => 0x0000_8000,
        _ => 0,
    }
}

/// H2 换根方案的 plan 相句柄（簇H H1：alloc/emit 拆两半，字段私有）。
pub struct ZuRootsPlan {
    inner: ZrParts,
}

struct ZrParts {
    /// 15 个常量词的共享锚值列。
    anchor_col: usize,
    /// 常量词锚行私有选择器（遍历序 = body 0..2 × j 0..16 的常量词序）。
    anchor_sels: Vec<usize>,
    /// 变量词 (值列, 选择器)（同遍历序）。
    recomp: Vec<(usize, usize)>,
}

/// 词形态静态划分（与 emit 遍历序一致）：常量词 = B₂ 0..3 + B₃ 5..15。
fn zu_word_is_const(body: usize, j: usize) -> bool {
    matches!((body, j), (0, 0..=3) | (1, 5..=15))
}

/// 消息根格表的 plan 相预览：[`emit_zu_msg_roots`] 的返回值**完全**由
/// [`ZuRootsPlan`] + 纯几何（rows_zmsg/row_pa）+ 本静态划分决定，同一遍历序
/// （body 0..2 × j 0..16）。环登记（[`plan_z_rings`] 的 H2 换根）需要此表 ⟹
/// plan 相构造；emit 尾部断言其计算结果与本函数一致（双端漂移即炸）。
pub fn zu_roots_preview(
    rp: &ZuRootsPlan,
    rows_zmsg: &[usize; 15],
    row_pa: usize,
) -> [[MsgCell; 16]; 2] {
    let ZrParts { anchor_col, anchor_sels: _, recomp } = &rp.inner;
    let mut roots: [[MsgCell; 16]; 2] = [[(0usize, 0usize); 16]; 2];
    let mut ai = 0usize;
    let mut ri = 0usize;
    for body in 0..2usize {
        for j in 0..16usize {
            if zu_word_is_const(body, j) {
                roots[body][j] = (*anchor_col, rows_zmsg[ai]);
                ai += 1;
            } else {
                roots[body][j] = (recomp[ri].0, row_pa);
                ri += 1;
            }
        }
    }
    assert_eq!(ai, 15, "常量词锚数漂移（蓝图账 = 15）");
    assert_eq!(ri, 17, "变量词 recomp 数漂移（蓝图账 = 17）");
    roots
}

/// plan 相：分配 32 个消息词根的全部列/选择器（遍历序与 emit 严格一致，
/// 静态划分 [`zu_word_is_const`]）。必须在第一条款束发射前调用。
pub fn plan_zu_msg_roots(bld: &mut Builder<Fr_>) -> ZuRootsPlan {
    let anchor_col = bld.alloc_col();
    let mut anchor_sels = Vec::new();
    let mut recomp = Vec::new();
    for body in 0..2usize {
        for j in 0..16usize {
            if zu_word_is_const(body, j) {
                anchor_sels.push(bld.alloc_selector(&[]));
            } else {
                recomp.push((bld.alloc_col(), bld.alloc_selector(&[])));
            }
        }
    }
    ZuRootsPlan { inner: ZrParts { anchor_col, anchor_sels, recomp } }
}

/// H2 换根方案 merged 侧 emit 半（蓝图 §四·7）：发射 32 个消息词根格的绑定
/// 约束并返回 (列,行) 根表。常量词 15 个 = 单值列锚格（每行独立 sel 烘焙常量，
/// NEG 锚同款 ⟹ C4 免疫）；变量词 17 个 = recomp 值格（专用列 @ `row_pa`
/// 与 decomp 位格同秩行 ⟹ rot=0），线性重组约束绑到 P_A decompose 位格。
/// **不改 SM3 侧结构**：返回的 (列,行) 对作 [`ZuForm::Merged`] 的 msg_roots，
/// 环根起点换源（[`register_chain_rings`] 的 w_root 段），parks/link/扩展门
/// 全不动。正确性由 mock + [`tests::zu_words_bits_crosscheck`] + 三篡改负例
/// 三层锁定。
#[allow(clippy::too_many_arguments)]
pub fn emit_zu_msg_roots(
    bld: &mut Builder<Fr_>,
    rp: &ZuRootsPlan,
    b2: &[u8; 64],
    b3: &[u8; 64],
    iv2: &[u32; 8],
    row_pa: usize,
    xa: &crate::sm2_scalar_plonkish::PlScalar,
    ya: &crate::sm2_scalar_plonkish::PlScalar,
    rows_zmsg: &[usize; 15],
) -> [[MsgCell; 16]; 2] {
    use plonkish_backend::util::expression::{Expression, Rotation};
    let ZrParts { anchor_col, anchor_sels, recomp } = &rp.inner;

    // 宿主词值（与 assemble_z_bodies 同一宿主数学的独立重放——纯函数幂等）
    let rep_a = replay_with_state(iv2, b2);
    let va_host: [u32; 8] = std::array::from_fn(|k| rep_a.final_state[k] ^ iv2[k]);
    let rep_b = replay_with_state(&va_host, b3);
    let words = [rep_a.w_all, rep_b.w_all];

    let mut roots: [[MsgCell; 16]; 2] = [[(0usize, 0usize); 16]; 2];
    let mut anchor_i = 0usize;
    let mut recomp_n = 0usize;
    for (body, wv) in words.iter().enumerate() {
        for j in 0..16usize {
            if zu_word_is_const(body, j) {
                let pt = rows_zmsg[anchor_i];
                let s_id = anchor_sels[anchor_i];
                bld.extend_selector(s_id, &[pt]);
                bld.emit_const_val(s_id, *anchor_col, wv[j]);
                bld.set_cell_u32(*anchor_col, pt, wv[j]);
                roots[body][j] = (*anchor_col, pt);
                anchor_i += 1;
            } else {
                let (col, s_id) = recomp[recomp_n];
                bld.extend_selector(s_id, &[row_pa]);
                let mut acc = Expression::<Fr_>::Constant(<Fr_ as From<u64>>::from(
                    zu_word_const(body, j, wv[j]) as u64,
                ));
                for (slot, idx, sh) in zu_word_bits(body, j) {
                    let src = if slot == 0 { xa } else { ya };
                    acc = acc
                        + Expression::<Fr_>::Constant(<Fr_ as From<u64>>::from(1u64 << sh))
                            * bld.q(src.cols[idx], Rotation::cur());
                }
                let re = acc - bld.q(col, Rotation::cur());
                bld.emit_assert_zero(s_id, re);
                bld.set_cell_u32(col, row_pa, wv[j]);
                roots[body][j] = (col, row_pa);
                recomp_n += 1;
            }
        }
    }
    assert_eq!(anchor_i, 15, "常量词锚数漂移（蓝图账 = 15）");
    assert_eq!(recomp_n, 17, "变量词 recomp 数漂移（蓝图账 = 17）");
    assert_eq!(anchor_sels.len(), 15, "plan 相锚选择器数漂移");
    assert_eq!(recomp.len(), 17, "plan 相 recomp 数漂移");
    // 双端一致性：emit 结果必须与 plan 相预览逐格相同（环登记正是按预览表
    // 接的根 —— 漂移即环根错位，此处当场炸掉而非留给环审计）。
    assert_eq!(
        roots,
        zu_roots_preview(rp, rows_zmsg, row_pa),
        "emit 根表偏离 plan 相预览（环登记源）"
    );
    roots
}

/// standalone 两体电路薄壳（簇G API 保留）：自建 Builder（实例面
/// [`ord::TOTAL_TWO`]）+ [`plan_z_parts`] + [`assemble_z_bodies`]（Standalone
/// 形态）+ finish。merged 形态走 sm2_verify_assemble 的合并装配器
/// （蓝图 §四·7 H1；同样 plan 在前 emit 在后 —— 冻结守卫纪律）。
pub fn build_two_bodies(b2: &[u8; 64], b3: &[u8; 64], iv2: &[u32; 8]) -> Sm3ZuCircuit {
    let mut bld = Builder::<Fr_>::new(ord::TOTAL_TWO);
    let plan = plan_z_parts(&mut bld);
    // 环登记在 plan 相（begin_relay* 冻结守卫纪律，簇H H1）。
    let _rings = plan_z_rings(&mut bld, &plan, &ZuRingRoots::Pinned);
    let out = assemble_z_bodies(
        &mut bld,
        &plan,
        &ZuCtx { b2, b3, iv2, form: ZuForm::Standalone },
    );
    let (info, advice, instances, tags, ctags, num_selectors) = bld.finish_parts();
    let relay_census: Vec<usize> = info.permutations.iter().map(|c| c.len()).collect();
    Sm3ZuCircuit {
        info,
        advice,
        instances,
        tags,
        ctags,
        num_selectors,
        digest: out.digest,
        va: out.va,
        relay_census,
        imp_val_cols: out.imp_val_cols,
        imp_rows: out.imp_rows,
        export_val_col: out.export_val_col,
        export_rows: out.export_rows,
        echo_col: out.echo_col,
    }
}

// ───────────────────── 三体链式装配器（簇J T1；蓝图 §四·8 J-3） ─────────────────────
//
// **E3 施工定案（2026-08-30，蓝图 J-10a 记录）**：保守方案——两体路径
// （[`plan_z_parts`]/[`plan_z_rings`]/[`assemble_z_bodies`]）**零接触**（merged
// 138,004 指纹零漂移 by construction），另起三体专用装配复用四大共享原语
// （[`register_chain_rings`]/[`emit_links_and_pins`]/[`emit_round_gates`]/
// [`replay_with_state`]）。理由：两体非对称（体A=常量锚+出口面、体B=变量锚+
// 进口+摘要面），「抽象为体列表」并非机械循环改写，重构风险/收益不成比例；
// 计划 Task 3 预授权此保守方案（禁强行归因条款）。
//
// 体角色（簇J 三体，蓝图 J-3 表）：头体（初态=公开常量，负轮常量锚，出口面
// feedforward XOR const）→ 中间体（初态=前体出口经进口环，负轮变量锚，进口面
// +出口面真 XOR 门）→ 尾体（同中间体进口，摘要面真 XOR 门 + echo 实例钉）。
// 行共享：头/尾体同落 ZONE0（LAYOUT_G：体E 进口走 out 带 imp 偏移 8..15——
// 头体不消费，零冲突；距离账=旧簇G 体B 几何 d≤11），中间体落 ZONEB
// （LAYOUT_STAR 三星交错 d=1）。**carry 对逐体独立**（C/E 同区行带，行选择器
// 门控的 bool 约束若共列则同格双值冲突；+4 列零风险换确定性）。

/// 尾体摘要出口形态（蓝图 §四·8 J-10b ②，2026-08-31 定案）：摘要与公开面的
/// 绑定方式开关。
#[derive(Clone, Copy)]
pub enum ChainEcho {
    /// E3 standalone 形态（原样）：echo 单值列 @ `rm[dg_base+k]` 实例钉 +
    /// `set_instance` + pin.bind（勘误 #24 语义：实例与电路线索的唯一绑定）。
    Pins { dg_base: usize },
    /// T1 全语句形态：摘要不占实例 —— echo 环落调用方 8 个 dgw 新列 @ 指定行，
    /// 摘要绑定归 E7 大折叠 Σ2^{32k}·dgw_k == e（J-4 权威；def:pi 公开面
    /// 本就无 digest）。面裁剪：echo 列与 l.echo* 选择器不分配。
    Fold { cols: [usize; 8], row: usize },
}

/// 三体链装配上下文（簇J）。`init` = 头体初态（公开常量，簇J = SM3 标准 IV，
/// 调用方从 `sm3_native_ref::IV` 机械取，禁手抄）。
pub struct ChainedCtx<'a> {
    pub blocks: &'a [[u8; 64]; 3],
    pub init: [u32; 8],
}

/// 三体链装配产出（T1 装配器接线/负例所需最小面）。
pub struct ChainedOut {
    /// 链态宿主真值 [V₁, V₂]（负例①/④ 篡改锚；摘要 = 末体输出）。
    pub chain_states: [[u32; 8]; 2],
    /// 摘要宿主真值（实例已 `set_instance` 于 `dg_base..dg_base+8`）。
    pub digest: [u32; 8],
    /// 尾体 echo 列（Pins 形态 = 实例绑定唯一线索列、篡改负例锚；Fold = None）。
    pub echo_col: Option<usize>,
    /// 出口值格 (列, 行)（头/中体各 8 —— 链态篡改锚，环根侧）。
    pub export_cells: [[(usize, usize); 8]; 2],
    /// 进口词值格 (列, 行)（中/尾体各 8 —— 链态篡改锚，汇侧）。
    pub imp_val_cells: [[(usize, usize); 8]; 2],
    /// 尾体摘要值格 (列, 行)（digval @ 折叠行 —— 负例① 锚）。
    pub digval_cells: [(usize, usize); 8],
}

/// 三体链 plan 相句柄（全部 alloc 前置 —— 冻结守卫纪律，簇H H1 同款）。
pub struct ChainedPlan {
    inner: ChainedParts,
}

struct ChainedParts {
    pools: [WorkPools; 3],
    /// 头/中体出口面（尾体无出口面）。
    exp: [ExportFace; 2],
    /// 尾体摘要面（echo 列按 [`ChainEcho`] 形态裁剪）。
    dig: DigestFace,
    /// 中/尾体进口面。
    imp: [ImportFace; 2],
    /// 中/尾体进口 link 选择器（`alloc_selector` 独立分配，C4 免疫）。
    imp_sels: [[usize; 8]; 2],
    /// 逐体选择器集（头/中滤 l.echo*；Fold 形态尾体也滤 —— 面裁剪纪律）。
    sel: [SelIds; 3],
    /// carry 对逐体独立（C/E 同区行带 ⟹ 不可共列；R7 风险的确定性消除）。
    cp: [CarryPair; 3],
    /// T_j 预处理一份覆盖两 zone 点集（C/E 同区 ⟹ 与两体版同量）。
    tj_prep: usize,
    /// 摘要出口形态（环登记与 emit 相共用）。
    echo: ChainEcho,
}

/// plan 相：分配三体全套组件。必须在 Builder 第一条约束发射前调用。
/// `echo` = 摘要出口形态（J-10b ②）：Fold 形态不分配 echo 列与 l.echo*
/// 选择器（死预处理多项式不进证明）。
pub fn plan_chained_parts(bld: &mut Builder<Fr_>, echo: ChainEcho) -> ChainedPlan {
    let pools: [WorkPools; 3] = std::array::from_fn(|_| WorkPools::alloc(bld));
    let exp: [ExportFace; 2] = std::array::from_fn(|_| ExportFace::alloc(bld));
    let dig = DigestFace::alloc(bld, matches!(echo, ChainEcho::Pins { .. }));
    let imp: [ImportFace; 2] = std::array::from_fn(|_| ImportFace::alloc(bld));
    let imp_sels: [[usize; 8]; 2] =
        std::array::from_fn(|_| std::array::from_fn(|_| bld.alloc_selector(&[])));
    let sel: [SelIds; 3] = std::array::from_fn(|i| {
        if i < 2 || matches!(echo, ChainEcho::Fold { .. }) {
            let names: Vec<&'static str> = SEL_NAMES
                .iter()
                .copied()
                .filter(|n| !n.starts_with("l.echo"))
                .collect();
            SelIds::alloc(bld, &names)
        } else {
            SelIds::alloc(bld, SEL_NAMES)
        }
    });
    let cp: [CarryPair; 3] = std::array::from_fn(|_| bld.alloc_carries());
    // T_j 预处理：C/E 同区（ZONE0）+ D（ZONEB）⟹ 点集与两体版完全同量。
    let mut tj_vals = vec![<Fr_ as From<u64>>::from(0u64); ROWS];
    for j in 0..NUM_ROUNDS {
        tj_vals[ZONE0.stripe_row(j, off::SS1PRE)] = <Fr_ as From<u64>>::from(tj_value(j) as u64);
        tj_vals[ZONEB.stripe_row(j, off::SS1PRE)] = <Fr_ as From<u64>>::from(tj_value(j) as u64);
    }
    let tj_prep = bld.alloc_const_poly(tj_vals);
    ChainedPlan { inner: ChainedParts { pools, exp, dig, imp, imp_sels, sel, cp, tj_prep, echo } }
}

/// plan 相：三体链全部中继环的首键注册 + 成员追加（`begin_relay*` 冻结守卫
/// ⟹ 先于第一条款束；簇H H1 纪律）。逐体 `register_chain_rings`（消息根 =
/// 调用方格，Cells 形态——T1 消息词不进实例面）+ 两条体间通道（头→中、
/// 中→尾，各 8 环）+ 尾体摘要 echo 根环 ×8（落点按 `plan.inner.echo` 形态：
/// Pins = echo 列 @ rm[dg_base+k]，Fold = 调用方 dgw 列 @ 指定行）。
pub fn plan_chained_rings(bld: &mut Builder<Fr_>, plan: &ChainedPlan, msg_roots: &[[MsgCell; 16]; 3]) {
    let ChainedParts { pools, exp, dig, imp, .. } = &plan.inner;
    let zones: [&'static Zone; 3] = [&ZONE0, &ZONEB, crate::sm3_compress_v2::zonec()];
    for i in 0..3 {
        let fold_pts: [usize; 8] = std::array::from_fn(|k| zones[i].fold_row(k));
        let _ = register_chain_rings(bld, &pools[i], zones[i], 0, Some(&msg_roots[i]), &fold_pts);
    }
    // 体间链值通道 ×2（决策 #23 ④ 推广）：前体出口值列 @ 折叠行 → 环 →
    // 后体进口词值列 @ 进口行。
    for j in 0..2usize {
        for k in 0..8usize {
            let root = vh(exp[j].out_val, zones[j].fold_row(k));
            let id = bld.begin_relay(&root);
            bld.relay_to_col(id, imp[j].words[k].val.expect("进口词需值列"), zones[j + 1].imp_row(k));
        }
    }
    // 尾体摘要 echo 根：digval @ 折叠行 → 环 → 出口按形态（J-10b ②）。
    let rm = crate::sm3_compress::row_mapping();
    for k in 0..8usize {
        let root_h = vh(dig.digval, zones[2].fold_row(k));
        let id = bld.begin_relay(&root_h);
        match plan.inner.echo {
            ChainEcho::Pins { dg_base } => {
                let col = dig.echo.expect("Pins 形态需 echo 列");
                bld.relay_to_col(id, col, rm[dg_base + k]);
            }
            ChainEcho::Fold { cols, row } => bld.relay_to_col(id, cols[k], row),
        }
    }
}

/// 装配三体链段到**既有** Builder（簇J 主交付；emit 相零分配）。数值唯一
/// 来源 = [`replay_with_state`] × 3 + 宿主 XOR（勘误 #11 承续；compress 契约
/// = 返回已含链接 XOR，末端禁再 ⊕IV —— 簇F′ 教训）。
pub fn assemble_chained_bodies(
    mut bld: &mut Builder<Fr_>,
    plan: &ChainedPlan,
    ctx: &ChainedCtx,
) -> ChainedOut {
    use plonkish_backend::util::expression::Expression;
    use plonkish_backend::util::expression::Rotation;
    let ChainedParts { pools, exp, dig, imp, imp_sels, sel, cp, tj_prep, echo } = &plan.inner;
    let zones: [&'static Zone; 3] = [&ZONE0, &ZONEB, crate::sm3_compress_v2::zonec()];
    let rm = crate::sm3_compress::row_mapping();

    // ---- 宿主数学：三体数值链（后体初态 = 前体出口；摘要 = 末体输出）----
    let rep0 = replay_with_state(&ctx.init, &ctx.blocks[0]);
    let s1: [u32; 8] = std::array::from_fn(|k| rep0.final_state[k] ^ ctx.init[k]);
    let rep1 = replay_with_state(&s1, &ctx.blocks[1]);
    let s2: [u32; 8] = std::array::from_fn(|k| rep1.final_state[k] ^ s1[k]);
    let rep2 = replay_with_state(&s2, &ctx.blocks[2]);
    let dg_host: [u32; 8] = std::array::from_fn(|k| rep2.final_state[k] ^ s2[k]);
    // 逐体初态（states[i] = 体 i 的链初态；states[3] = 摘要）。
    let states: [&[u32; 8]; 3] = [&ctx.init, &s1, &s2];
    let reps: [&Replay; 3] = [&rep0, &rep1, &rep2];

    // 公开语句面（仅 Pins 形态）：摘要 8 字（消息词不进实例面 —— H2 收缩
    // 纪律）；Fold 形态摘要不占实例，绑定归调用方 E7 大折叠（J-10b ②）。
    let pins_dg: Option<usize> = match *echo {
        ChainEcho::Pins { dg_base } => Some(dg_base),
        ChainEcho::Fold { .. } => None,
    };
    if let Some(dg_base) = pins_dg {
        for k in 0..8usize {
            bld.set_instance(dg_base + k, <Fr_ as From<u64>>::from(dg_host[k] as u64));
        }
    }

    // ══════════ 负轮锚（头体常量 / 中尾体变量线性绑定）═══════════
    // 头体：初态 IV 是公开常量 ⟹ 锚 = sel·(val − virt_from(IV))，solo 同款。
    for kk in 0..4i64 {
        let tt = kk - 4;
        let hs = sel[0].g(NEG_T_SELS[kk as usize]);
        let pt = zones[0].canon_home(tt, false);
        bld.extend_selector(hs, &[pt]);
        bld.emit_const_val(hs, pools[0].neg_t1, virt_from(&ctx.init, tt, false));
        bld.set_cell_u32(pools[0].neg_t1, pt, virt_from(&ctx.init, tt, false));

        let hp_s = sel[0].g(NEG_P_SELS[kk as usize]);
        let ppt = zones[0].canon_home(tt, true);
        bld.extend_selector(hp_s, &[ppt]);
        bld.emit_const_val(hp_s, pools[0].neg_pn, virt_from(&ctx.init, tt, true));
        bld.set_cell_u32(pools[0].neg_pn, ppt, virt_from(&ctx.init, tt, true));
    }
    // 中/尾体（P-a 精化）：初态是变量 ⟹ 锚格线性绑定到进口位（lin_rotl 视图），
    // 不设 XOR 门；锚格仍作链环根。
    for i in 1..3usize {
        for (fam, (srcs, rots)) in NEG_VAR_ANCHOR.iter().enumerate() {
            for kk in 0..4usize {
                let tt = kk as i64 - 4;
                let s_id = sel[i].g(if fam == 0 { NEG_T_SELS[kk] } else { NEG_P_SELS[kk] });
                let pt = zones[i].canon_home(tt, fam == 1);
                let anchor_col = if fam == 0 { pools[i].neg_t1 } else { pools[i].neg_pn };
                bld.extend_selector(s_id, &[pt]);
                let va_h = imp[i - 1].words[srcs[kk]].at(zones[i].imp_row(srcs[kk]));
                let want = bld.q(anchor_col, Rotation::cur()) - bld.lin_rotl(&va_h, rots[kk], pt);
                bld.emit_assert_zero(s_id, want);
                bld.set_cell_u32(anchor_col, pt, virt_from(states[i], tt, fam == 1));
            }
        }
    }

    // ══════════ 公开钉点 / link（共享段 ×3）══════════
    for i in 0..3usize {
        let fold_pts: [usize; 8] = std::array::from_fn(|k| zones[i].fold_row(k));
        emit_links_and_pins(&mut bld, &pools[i], &sel[i], zones[i], 0, false, states[i], &fold_pts, reps[i]);
    }

    // 进口 link（中/尾体）：值↔位重分解 + 位布尔；环值 = 前体出口 V。
    for i in 1..3usize {
        for k in 0..8usize {
            let home = zones[i].imp_row(k);
            bld.extend_selector(imp_sels[i - 1][k], &[home]);
            bld.emit_word_link(imp_sels[i - 1][k], &imp[i - 1].words[k]);
            bld.set_word(&imp[i - 1].words[k].at(home), states[i][k]);
        }
    }

    // 尾体摘要 echo pin（仅 Pins 形态；v3 P1b：单值列 pin.bind 一条约束绑定
    // 实例；勘误 #24 教训 —— Pins 形态此段不可省，缺失 = 实例摘要与电路线索
    // 无绑定 = 健全性漏洞。Fold 形态 l.echo* 选择器未分配，走 sel[2].g 会
    // panic —— 形态门禁必须先行）。
    if let Some(dg_base) = pins_dg {
        let echo_col = dig.echo.expect("Pins 形态需 echo 列");
        for k in 0..8usize {
            let pt = rm[dg_base + k];
            let s_id = sel[2].g(ECHO_SELS[k]);
            bld.extend_selector(s_id, &[pt]);
            bld.emit_pin_val_only(s_id, echo_col, dg_base + k);
        }
    }

    // ══════════ 门层 ×3（共享段）══════════
    for i in 0..3usize {
        emit_round_gates(&mut bld, &pools[i], &sel[i], &cp[i], *tj_prep, zones[i], reps[i]);
    }

    // ---- 头体出口面：O_k = fold_k⟨rot⟩ ⊕ IV_k（feedforward 线性形态，体A 同款）----
    for k in 0..8usize {
        let at = zones[0].fold_row(k);
        let fl = pools[0].fold[k].at(at);
        let slot = if DIG_ROTS[k] == 0 {
            SlotRef::view(&fl)
        } else {
            SlotRef::rotl(&fl, DIG_ROTS[k])
        };
        bld.extend_selector(sel[0].g(DG_SELS[k]), &[at]);
        bld.emit_feedforward_val(sel[0].g(DG_SELS[k]), &slot, ctx.init[k], exp[0].out_val, at);
        bld.set_cell_u32(exp[0].out_val, at, s1[k]);
    }

    // ---- 中间体出口面：O_k = fold_k⟨rot⟩ ⊕ V₁_k（**真 XOR 门**——初态是
    //      变量词；位出口经 digbits 线性重组进出口值列，环根由此开启至尾体）----
    for k in 0..8usize {
        let at = zones[1].fold_row(k);
        let fl = pools[1].fold[k].at(at);
        let x = if DIG_ROTS[k] == 0 {
            SlotRef::view(&fl)
        } else {
            SlotRef::rotl(&fl, DIG_ROTS[k])
        };
        let y = SlotRef::view(&imp[0].words[k].at(zones[1].imp_row(k)));
        let o = imp[0].digbits.at(at);
        bld.extend_selector(sel[1].g(DG_SELS[k]), &[at]);
        bld.emit_xor(sel[1].g(DG_SELS[k]), &x, &y, &o, at);
        let mut recomp = Expression::<Fr_>::zero();
        for i in 0..32usize {
            recomp = recomp
                + Expression::<Fr_>::Constant(<Fr_ as From<u64>>::from(1u64 << i))
                    * bld.q(imp[0].digbits.bits[i], Rotation::cur());
        }
        let re = recomp - bld.q(exp[1].out_val, Rotation::cur());
        bld.emit_assert_zero(sel[1].g(DG_SELS[k]), re);
        bld.set_word(&o, s2[k]);
        bld.set_cell_u32(exp[1].out_val, at, s2[k]);
    }

    // ---- 尾体摘要面：O_k = fold_k⟨rot⟩ ⊕ V₂_k（真 XOR 门 + recomp 进 digval
    //      + echo 见证；位布尔性由 XOR 门与输入位布尔性传递）----
    for k in 0..8usize {
        let at = zones[2].fold_row(k);
        let fl = pools[2].fold[k].at(at);
        let x = if DIG_ROTS[k] == 0 {
            SlotRef::view(&fl)
        } else {
            SlotRef::rotl(&fl, DIG_ROTS[k])
        };
        let y = SlotRef::view(&imp[1].words[k].at(zones[2].imp_row(k)));
        let o = imp[1].digbits.at(at);
        bld.extend_selector(sel[2].g(DG_SELS[k]), &[at]);
        bld.emit_xor(sel[2].g(DG_SELS[k]), &x, &y, &o, at);
        let mut recomp = Expression::<Fr_>::zero();
        for i in 0..32usize {
            recomp = recomp
                + Expression::<Fr_>::Constant(<Fr_ as From<u64>>::from(1u64 << i))
                    * bld.q(imp[1].digbits.bits[i], Rotation::cur());
        }
        let re = recomp - bld.q(dig.digval, Rotation::cur());
        bld.emit_assert_zero(sel[2].g(DG_SELS[k]), re);
        bld.set_word(&o, dg_host[k]);
        bld.set_cell_u32(dig.digval, at, dg_host[k]);
        if let Some(dg_base) = pins_dg {
            bld.set_cell_u32(dig.echo.expect("Pins 形态需 echo 列"), rm[dg_base + k], dg_host[k]);
        }
    }

    // ---- 段出料：返回接线/负例所需最小面（Builder 归调用方 finish）----
    ChainedOut {
        chain_states: [s1, s2],
        digest: dg_host,
        echo_col: dig.echo,
        export_cells: [
            std::array::from_fn(|k| (exp[0].out_val, zones[0].fold_row(k))),
            std::array::from_fn(|k| (exp[1].out_val, zones[1].fold_row(k))),
        ],
        imp_val_cells: [
            std::array::from_fn(|k| {
                (imp[0].words[k].val.expect("进口词需值列"), zones[1].imp_row(k))
            }),
            std::array::from_fn(|k| {
                (imp[1].words[k].val.expect("进口词需值列"), zones[2].imp_row(k))
            }),
        ],
        digval_cells: std::array::from_fn(|k| (dig.digval, zones[2].fold_row(k))),
    }
}

/// 三体链 standalone 电路（簇J 机制测试薄壳）：自建 Builder（实例面 = 8 摘要
/// 字）+ 48 消息词全部常量锚（单值列 × 48、逐格独立 sel —— C4 免疫；行取
/// 自由秩带，zone 窗与实例钉行之外）+ [`plan_chained_parts`]/[`plan_chained_rings`]
/// /[`assemble_chained_bodies`] + finish。变量词换根在 T1 装配器（E5/E8）按
/// 簇H recomp 方案接入。
pub fn build_chained_bodies_const(
    blocks: [[u8; 64]; 3],
    init: [u32; 8],
    anchor_base_rank: usize,
) -> Sm3ChainedCircuit {
    let mut bld = Builder::<Fr_>::new(8);
    let plan = plan_chained_parts(&mut bld, ChainEcho::Pins { dg_base: 0 });
    // 48 常量锚格：列与 sel 分配（约束发射在环登记之后 —— 冻结守卫纪律）。
    let anchor_cols: Vec<usize> = (0..48).map(|_| bld.alloc_col()).collect();
    let anchor_sels: Vec<usize> = (0..48).map(|_| bld.alloc_selector(&[])).collect();
    let anchor_rows: Vec<usize> = (0..48).map(|j| bh_point(anchor_base_rank + j)).collect();
    // 宿主词值（消息 16 词 × 3 体；与 assemble_chained_bodies 同一宿主数学的
    // 独立重放 —— 纯函数幂等）。
    let rep0 = replay_with_state(&init, &blocks[0]);
    let s1: [u32; 8] = std::array::from_fn(|k| rep0.final_state[k] ^ init[k]);
    let rep1 = replay_with_state(&s1, &blocks[1]);
    let s2: [u32; 8] = std::array::from_fn(|k| rep1.final_state[k] ^ s1[k]);
    let rep2 = replay_with_state(&s2, &blocks[2]);
    let words = [rep0.w_all, rep1.w_all, rep2.w_all];
    // 锚约束 + 见证（环登记前发射约束会触发冻结守卫 ⟹ 先登记后锚）。
    let mut msg_roots: [[MsgCell; 16]; 3] = [[(0usize, 0usize); 16]; 3];
    for b in 0..3usize {
        for j in 0..16usize {
            let idx = b * 16 + j;
            let (col, row) = (anchor_cols[idx], anchor_rows[idx]);
            msg_roots[b][j] = (col, row);
        }
    }
    plan_chained_rings(&mut bld, &plan, &msg_roots);
    for b in 0..3usize {
        for j in 0..16usize {
            let idx = b * 16 + j;
            let (col, row) = msg_roots[b][j];
            let s_id = anchor_sels[idx];
            bld.extend_selector(s_id, &[row]);
            bld.emit_const_val(s_id, col, words[b][j]);
            bld.set_cell_u32(col, row, words[b][j]);
        }
    }
    let ctx = ChainedCtx { blocks: &blocks, init };
    let out = assemble_chained_bodies(&mut bld, &plan, &ctx);
    let (info, advice, instances, tags, ctags, num_selectors) = bld.finish_parts();
    let relay_census: Vec<usize> = info.permutations.iter().map(|c| c.len()).collect();
    Sm3ChainedCircuit {
        info,
        advice,
        instances,
        tags,
        ctags,
        num_selectors,
        digest: out.digest,
        chain_states: out.chain_states,
        echo_col: out.echo_col,
        export_cells: out.export_cells,
        imp_val_cells: out.imp_val_cells,
        digval_cells: out.digval_cells,
        relay_census,
    }
}

/// 三体链 standalone 电路出料（簇J 机制测试）。
pub struct Sm3ChainedCircuit {
    pub info: PlonkishCircuitInfo<Fr_>,
    pub advice: Vec<Vec<Fr_>>,
    pub instances: Vec<Vec<Fr_>>,
    pub tags: Vec<(&'static str, usize)>,
    /// 与 info.constraints 平行的家族标签。
    pub ctags: Vec<&'static str>,
    pub num_selectors: usize,
    /// 摘要真值（尾体摘要面宿主值）。
    pub digest: [u32; 8],
    /// 链态宿主真值 [V₁, V₂]。
    pub chain_states: [[u32; 8]; 2],
    /// 尾体 echo 列（Pins 形态；Fold = None）。
    pub echo_col: Option<usize>,
    /// 出口值格（头/中体）。
    pub export_cells: [[(usize, usize); 8]; 2],
    /// 进口词值格（中/尾体）。
    pub imp_val_cells: [[(usize, usize); 8]; 2],
    /// 尾体摘要值格。
    pub digval_cells: [(usize, usize); 8],
    /// 中继环长度账本。
    pub relay_census: Vec<usize>,
}

// ───────────────────────── 测试 ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    type Fr = crate::FpSM2;
    use crate::sm3_compress::check_parts_violations;
    use ff::Field;

    /// H2 红线测试（蓝图 §四·7：三层映射必须测试对拍锁定，禁手抄）：
    /// `zu_word_bits` 位映射从 P_A 坐标位重组 17 个变量词，与 replay 宿主
    /// 词值逐一对拍；常量段独立推导（preimage 字节）对拍 `zu_word_const`。
    /// 纯宿主侧，不依赖电路。
    #[test]
    fn zu_words_bits_crosscheck() {
        use crate::sm2_params::fr_to_limbs;
        let (_e, _r, _s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
        let id: &[u8] = crate::sm2_z_anchor::DEFAULT_ID;
        let blocks = crate::sm2_z_anchor::z_u_blocks(id, &pax, &pay);
        let iv2 = crate::sm2_z_anchor::z_u_prelude_state(id);
        let rep_a = replay_with_state(&iv2, &blocks[2]);
        let va: [u32; 8] = std::array::from_fn(|k| rep_a.final_state[k] ^ iv2[k]);
        let rep_b = replay_with_state(&va, &blocks[3]);
        let words = [rep_a.w_all, rep_b.w_all];

        // 常量段独立推导：(0,4) 高 16 位 = preimage[144..146]；(1,4) = 0x8000
        // （SM3 填充 0x80 落在 B₃ 词 4 第 3 字节 —— 结构性常量）。
        let pre = crate::sm2_z_anchor::z_u_preimage(id, &pax, &pay);
        let c04 = u32::from_be_bytes([pre[144], pre[145], 0, 0]) & 0xFFFF_0000;
        assert_eq!(pre.len(), 210, "预像长度（146 常量 + 64 变量）");
        assert_eq!(zu_word_const(0, 4, words[0][4]), c04, "(0,4) 常量段");
        assert_eq!(zu_word_const(1, 4, words[1][4]), 0x0000_8000, "(1,4) 常量段");

        // P_A 位源（fr_to_limbs LE limbs → LSB 序 256 位，与 decompose 同序）
        let xl = fr_to_limbs(&pax);
        let yl = fr_to_limbs(&pay);
        let bit = |sl: usize, i: usize| ((if sl == 0 { xl } else { yl })[i / 64] >> (i % 64)) & 1 == 1;

        let mut nvar = 0usize;
        for (body, wv) in words.iter().enumerate() {
            for j in 0..16usize {
                let expect = wv[j] as u64;
                if matches!((body, j), (0, 0..=3) | (1, 5..=15)) {
                    continue; // 常量词不走位映射（由锚格烘焙绑定）
                }
                let mut got = zu_word_const(body, j, wv[j]) as u64;
                for (slot, idx, sh) in zu_word_bits(body, j) {
                    if bit(slot, idx) {
                        got += 1u64 << sh;
                    }
                }
                assert_eq!(got, expect, "变量词 ({body},{j}) 位映射对拍失败");
                nvar += 1;
            }
        }
        assert_eq!(nvar, 17, "变量词数（蓝图 H2 账）");
    }

    fn one_block(msg: &[u8]) -> [u8; 64] {
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
        let mut blk = [0u8; 64];
        blk.copy_from_slice(&padded);
        blk
    }

    /// 正例锚点："abc" 单块：实例 = 原生参照逐字对拍 + 位级约束 mock 零违约 +
    /// 布局/环账本普查。
    #[test]
    fn v2_abc_end_to_end_matches_native() {
        let blk = one_block(b"abc");
        let expect = crate::sm3_native_ref::compress(&crate::sm3_native_ref::IV, &blk);
        let circ = build_compress_v2(&blk);

        assert_eq!(circ.instances[0].len(), ord::TOTAL, "实例数=16 消息+8 摘要");
        for k in 0..8 {
            let want = <Fr as From<u64>>::from(expect[k] as u64);
            assert_eq!(circ.instances[0][ord::BASE_DG + k], want, "摘要字 {k} 不符");
        }

        // 旋转预算守卫（S1 不变量）：一切约束查询距离 ≤ K（协议断言阈）。
        let maxd = circ
            .info
            .constraints
            .iter()
            .map(|c| c.max_used_rotation_distance())
            .max()
            .unwrap_or(0);
        assert!(
            maxd <= crate::sm3_compress::K,
            "旋转距离 {maxd} 超出后端预算 num_vars={}",
            crate::sm3_compress::K
        );

        // 环账本：环全部 ≥2；格全局唯一。
        let mut seen = std::collections::BTreeSet::new();
        for cyc in &circ.info.permutations {
            assert!(cyc.len() >= 2);
            for cell in cyc {
                assert!(seen.insert(*cell), "格 {cell:?} 出现在多个环位");
            }
        }
        println!(
            "[v2-tally] constraints={} advice_cols={} selectors={} perm_cycles={} \
             cycle_cells={} relay_census(前12)={:?}",
            circ.info.constraints.len(),
            circ.advice.len(),
            circ.num_selectors,
            circ.info.permutations.len(),
            seen.len(),
            &circ.relay_census[..circ.relay_census.len().min(12)]
        );

        let bad = check_parts_violations(&circ.info, &circ.advice, &circ.instances);
        if !bad.is_empty() {
            use std::collections::BTreeMap;
            let hist: BTreeMap<&str, usize> =
                bad.iter().fold(BTreeMap::new(), |mut m, v| {
                    *m.entry(circ.ctags[v.constraint]).or_insert(0) += 1;
                    m
                });
            panic!("正例 {} 处违约，按族 {hist:?}，首条 {:?}", bad.len(), bad.first());
        }
    }

    /// 负例 A（mock 可见）：字母复制位被篡改 → 该 park 行 link.recomp 击中。
    /// 注：若同时同步篡改值与位，位级 mock 不再可见 —— 那一层由后端积论证
    /// 在真实协议里拒绝（取证见 sm3_perm_smoke::broken_cycle_rejected）。
    #[test]
    fn v2_tampered_letter_bit_caught_locally() {
        let blk = one_block(b"abc");
        let mut circ = build_compress_v2(&blk);
        let want_pt = stripe_row(10, LETTER_OFF[0]); // 测试锚定默认表(变体筛查不经此测试)
        // 从环成员反查该 park 点上的一个值列（letters 组带值列）。
        let gcol = find_cycle_col_at(&circ, want_pt).expect("park 点应出现在环中");
        circ.advice[gcol][want_pt] += Fr::ONE;
        let bad = check_parts_violations(&circ.info, &circ.advice, &circ.instances);
        assert!(
            bad.iter().any(|v| v.point == want_pt),
            "位篡改未在 park 行触发违约"
        );
    }

    /// 负例 B（公开侧）：消息实例被改 → 消息钉点 pin.bind/recomp 触发。
    #[test]
    fn v2_tampered_message_instance_caught() {
        let blk = one_block(b"abc");
        let mut circ = build_compress_v2(&blk);
        let ordl = ord::BASE_MSG + 7;
        circ.instances[0][ordl] += Fr::ONE;
        let bad = check_parts_violations(&circ.info, &circ.advice, &circ.instances);
        let pt = crate::sm3_compress::row_mapping()[ordl];
        assert!(bad.iter().any(|v| v.point == pt), "实例篡改未在其映射行触发");
    }

    /// 负例 C（扩展正典）：STG 行 W 词位被翻 → 扩展最终 xor 门在 TPARK 激活点命中。
    #[test]
    fn v2_tampered_stg_word_breaks_ext_gate() {
        let blk = one_block(b"abc");
        let mut circ = build_compress_v2(&blk);
        let stg_pt = stripe_row(30, off::STG);
        let gcol = find_advice_nonzero_bit(&circ, stg_pt);
        circ.advice[gcol][stg_pt] += Fr::ONE;
        let bad = check_parts_violations(&circ.info, &circ.advice, &circ.instances);
        assert!(!bad.is_empty(), "STG 位篡改未被任何门捕获");
    }

    /// 工具：在给定点的环成员里取一个 advice 列的局部号（info→advice 下标换算）。
    fn find_cycle_col_at(circ: &Sm3V2Circuit, pt: usize) -> Option<usize> {
        let np_prep = circ.info.preprocess_polys.len();
        for cyc in &circ.info.permutations {
            for &(g, p) in cyc {
                if p == pt && g > np_prep {
                    return Some(g - 1 - np_prep);
                }
            }
        }
        None
    }

    /// 工具：给定点的任一非零 advice 列局部号（负例 C 用）。
    fn find_advice_nonzero_bit(circ: &Sm3V2Circuit, pt: usize) -> usize {
        for (li, colv) in circ.advice.iter().enumerate() {
            if colv[pt] != Fr::ZERO {
                return li;
            }
        }
        panic!("点 {pt} 无任何非零 advice");
    }

    /// **环见证一致性自检**（mock 与后端积论证之间的桥）：对每条环取全部
    /// (全局多项式号, 点) 的见证值，断言同环相等。协议在 prover.rs:327
    /// 拒绝时本测试先行给出逐环诊断 —— 位级 mock 看不见置换层。
    /// G0 形状锁定（蓝图四·5）：zone 化等价迁移前后单块电路的形状指纹
    /// 必须逐项不变；防 G2/G3 双区改造静默改形。2026-08-27 [实测] 基线。
    #[test]
    fn g0_single_block_shape_lock() {
        let blk = one_block(b"abc");
        let circ = build_compress_v2(&blk);
        // 数字来源：2026-08-27 G0 等价迁移当日实测（v3-P1 列压缩后形状；
        // 与 b4 记忆 61,516/2169 的差值 = 列压缩改动所致，见
        // pcs-evals-multiplicity-law 记忆 run12：2169→1315 列仅 −2.5% proof）。
        assert_eq!(circ.info.constraints.len(), 60212);
        assert_eq!(circ.advice.len(), 1315);
        assert_eq!(circ.num_selectors, 80);
        assert_eq!(circ.info.preprocess_polys.len(), 80);
        assert_eq!(circ.info.permutations.len(), 212);
    }

    /// (全局多项式号, 点) 的见证值，断言同环相等。协议在 prover.rs:327
    /// 拒绝时本测试先行给出逐环诊断 —— 位级 mock 看不见置换层。
    #[test]
    fn v2_permutation_cycles_hold_equal_witnesses() {
        use std::collections::BTreeMap;
        let blk = one_block(b"abc");
        let circ = build_compress_v2(&blk);
        let np = circ.info.preprocess_polys.len();
        // inst_at[point]：实例按 row_mapping 摊到全立方（与后端 resolve 同式）。
        let mut inst_at = vec![Fr::ZERO; crate::sm3_compress::ROWS];
        for (ordinal, v) in circ.instances.iter().flat_map(|c| c.iter()).enumerate() {
            inst_at[crate::sm3_compress::row_mapping()[ordinal]] = *v;
        }
        let cell = |&(g, p): &(usize, usize)| -> Fr {
            if g == 0 {
                inst_at[p]
            } else if g <= np {
                circ.info.preprocess_polys[g - 1][p]
            } else {
                circ.advice[g - 1 - np][p]
            }
        };
        // 秩解码（定位用）。
        let inv = rank_inverse();
        let decode = |(g, p): &(usize, usize)| -> String {
            let kind = if *g == 0 {
                "inst".to_string()
            } else if *g <= np {
                format!("prep{}", g - 1)
            } else {
                format!("adv{}", g - 1 - np)
            };
            match inv.iter().position(|&q| q == *p) {
                Some(rk) => format!("{kind}@rk{rk}"),
                None => format!("{kind}@pt{p}"),
            }
        };
        let mut bad_cycles = 0;
        for (ci, cyc) in circ.info.permutations.iter().enumerate() {
            let v0 = cell(&cyc[0]);
            let mism: Vec<&(usize, usize)> =
                cyc.iter().skip(1).filter(|c| cell(*c) != v0).collect();
            if !mism.is_empty() {
                bad_cycles += 1;
                if bad_cycles <= 5 {
                    println!(
                        "[cycle-audit] 环 #{ci} 长 {} 首格 {} ≠ 偏离格 {}",
                        cyc.len(),
                        decode(&cyc[0]),
                        mism
                            .iter()
                            .map(|c| decode(c))
                            .collect::<Vec<_>>()
                            .join(" , ")
                    );
                }
            }
        }
        assert_eq!(bad_cycles, 0, "{bad_cycles} 条环见证不一致");
        println!(
            "[cycle-audit] 全部 {} 条环（{} 格）见证值一致 ✔",
            circ.info.permutations.len(),
            circ.relay_census.iter().sum::<usize>()
        );
        // 附带：环键全局唯一再断言一次（编码勘误回归网）。
        let mut seen = BTreeMap::new();
        for (ci, cyc) in circ.info.permutations.iter().enumerate() {
            for c in cyc {
                assert!(seen.insert(*c, ci).is_none(), "格 {c:?} 出现在多个环");
            }
        }
    }

    // ═══════════ 两体（簇G/G2，决策 #23）验收 ═══════════

    /// A.2 夹具：四块 + IV₂ + native 摘要（全部程序化机械取，禁手抄 —— L2 红线）。
    fn zu_fixture() -> ([[u8; 64]; 4], [u32; 8], [u8; 32]) {
        let (_, _, _, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
        let id = crate::sm2_z_anchor::DEFAULT_ID;
        (
            crate::sm2_z_anchor::z_u_blocks(id, &pax, &pay),
            crate::sm2_z_anchor::z_u_prelude_state(id),
            crate::sm2_z_anchor::z_u_native(id, &pax, &pay),
        )
    }

    /// 正例（build-only 快档）：摘要 == z_u_native（GB/T 终判，蓝图 G4③）+
    /// 旋转守卫（S1）+ 环账本全局唯一 + 环值审计零（mock 盲区兜底）+ tally。
    #[test]
    fn zu_two_body_assembly_matches_native() {
        let (blocks, iv2, dg) = zu_fixture();
        let circ = build_two_bodies(&blocks[2], &blocks[3], &iv2);

        assert_eq!(circ.instances[0].len(), ord::TOTAL_TWO, "实例面=16+16+8");
        for k in 0..8usize {
            let want =
                u32::from_be_bytes([dg[4 * k], dg[4 * k + 1], dg[4 * k + 2], dg[4 * k + 3]]);
            assert_eq!(circ.digest[k], want, "摘要字 {k} 与 z_u_native 不符");
            assert_eq!(
                circ.instances[0][ord::BASE_DG_TWO + k],
                <Fr as From<u64>>::from(want as u64),
                "实例摘要字 {k} 不符"
            );
        }

        // 旋转预算守卫（S1 不变量）：体B 新增面（锚绑定/摘要 XOR/进口 link）
        // 的查询距离全部 ≤ K。
        let maxd = circ
            .info
            .constraints
            .iter()
            .map(|c| c.max_used_rotation_distance())
            .max()
            .unwrap_or(0);
        assert!(
            maxd <= crate::sm3_compress::K,
            "旋转距离 {maxd} 超出后端预算 num_vars={}",
            crate::sm3_compress::K
        );

        // 环账本：环全部 ≥2；格全局唯一（含体间 V_A 链值环）。
        let mut seen = std::collections::BTreeSet::new();
        for cyc in &circ.info.permutations {
            assert!(cyc.len() >= 2);
            for cell in cyc {
                assert!(seen.insert(*cell), "格 {cell:?} 出现在多个环位");
            }
        }
        // 环值审计（mock 看不见置换层 ⟹ 装配层前置自检；体间通道在此）。
        let bad_rings = crate::sm3_compress::audit_ring_values(&circ.info, &circ.advice);
        assert!(bad_rings.is_empty(), "环取值不一致: {bad_rings:?}");

        // 形状锁定（勘误 #24 的产物升格为永久守卫）：首跑对账曾抓获体B echo
        // 钉漏发（pin.bind −8，mock 与环审计双绿的真盲区）——此后任何族计数
        // 漂移都在本测试当场爆掉，不允许再靠肉眼对账。
        assert_eq!(circ.info.constraints.len(), 120936, "两体约束总数漂移");
        assert_eq!(circ.advice.len(), 2923, "两体 advice 列数漂移");
        assert_eq!(circ.info.preprocess_polys.len(), 159, "预处理多项式数漂移");
        assert_eq!(circ.info.permutations.len(), 424, "中继环数漂移");

        let solo = build_compress_v2(&one_block(b"abc"));
        let solo_tags: std::collections::BTreeMap<&str, usize> =
            solo.tags.iter().copied().collect();
        let two_tags: std::collections::BTreeMap<&str, usize> =
            circ.tags.iter().copied().collect();
        // 两体形态的**结构性预期差**（solo×2 基准上的逐族增量，全部有设计依据）：
        //   体B 负轮锚改线性绑定（anchor.const −8 / assert.zero +8）、体B 摘要面
        //   换真 XOR 门 + recomp（ff.out −8 / assert.zero +8 / xor +256）、体B
        //   进口面 link（link.bool +256 / link.recomp +8）、体A 无 echo 钉 +
        //   体B echo 钉 8（pin.bind 48→40）。
        const EXPECT_DIFF: [(&str, usize); 7] = [
            ("anchor.const", 8),
            ("assert.zero", 16),
            ("ff.out", 8),
            ("link.bool", 58368),
            ("link.recomp", 1824),
            ("pin.bind", 40),
            ("xor", 40704),
        ];
        for (t, want) in EXPECT_DIFF {
            assert_eq!(two_tags.get(t), Some(&want), "族 {t} 计数漂移");
        }
        for t in two_tags.keys() {
            // EXPECT_DIFF 内的族允许是两体新增（如 assert.zero：solo 无此族）。
            if EXPECT_DIFF.iter().any(|(dt, _)| dt == t) {
                continue;
            }
            assert!(solo_tags.contains_key(t), "两体新增族 {t} 未入锁定表");
        }
        for (t, n1) in &solo_tags {
            if EXPECT_DIFF.iter().all(|(dt, _)| dt != t) {
                assert_eq!(
                    two_tags.get(t),
                    Some(&(2 * n1)),
                    "族 {t} 偏离 solo×2（非预期结构性差）"
                );
            }
        }
        println!(
            "[zu-tally] constraints={} advice_cols={} preprocess={} cycles={} max|rot|={maxd} va={:08X?}",
            circ.info.constraints.len(),
            circ.advice.len(),
            circ.info.preprocess_polys.len(),
            circ.info.permutations.len(),
            circ.va
        );
    }

    /// 正例（mock 全扫）：两体全部位级约束零违约（~121k 约束 × 4096 点）。
    #[test]
    fn zu_two_body_mock_zero_violations() {
        let (blocks, iv2, _) = zu_fixture();
        let circ = build_two_bodies(&blocks[2], &blocks[3], &iv2);
        let bad = check_parts_violations(&circ.info, &circ.advice, &circ.instances);
        assert!(
            bad.is_empty(),
            "两体正例违约 {} 处，首条 {:?}",
            bad.len(),
            bad.first()
        );
    }

    /// 负例（决策 #23 ④ / 体间链值通道）：翻通道任一侧必挂。
    /// 进口侧：翻 VA[3] 进口值格 ⟹ 进口 link recomp 违约 + 环审计捕获
    /// 出口/进口不等；出口侧：翻 V_A[5] 出口值格 ⟹ ff.out 违约 + 环审计。
    /// （mock 只见位级层；置换层由 audit_ring_values 兜底 —— 双信号都要。）
    #[test]
    fn zu_two_body_tamper_link_channel_caught() {
        let (blocks, iv2, _) = zu_fixture();
        let circ = build_two_bodies(&blocks[2], &blocks[3], &iv2);
        let one = <Fr as From<u64>>::from(1u64);

        // —— 进口侧 ——
        let mut adv = circ.advice.clone();
        adv[circ.imp_val_cols[3]][circ.imp_rows[3]] += one;
        let bad = check_parts_violations(&circ.info, &adv, &circ.instances);
        assert!(!bad.is_empty(), "篡改进口 VA[3] 值格未被位级约束击中");
        let audit = crate::sm3_compress::audit_ring_values(&circ.info, &adv);
        assert!(!audit.is_empty(), "环审计未捕获进口/出口值不等");

        // —— 出口侧 ——
        let mut adv = circ.advice.clone();
        adv[circ.export_val_col][circ.export_rows[5]] += one;
        let bad = check_parts_violations(&circ.info, &adv, &circ.instances);
        assert!(!bad.is_empty(), "篡改出口 V_A[5] 值格未被位级约束击中");
        let audit = crate::sm3_compress::audit_ring_values(&circ.info, &adv);
        assert!(!audit.is_empty(), "环审计未捕获出口/进口值不等");
    }

    /// 簇J E3 机制测试：三体链 standalone（[`build_chained_bodies_const`]）。
    /// 块 = T1 真语句排布（B₁=Z_A‖Id_u、B₂=attrs‖pk_u.x、B₃=pk_u.y‖pad，
    /// 蓝图 §四·8 J-1/J-3）；全词常量锚（变量词换根在 T1 装配器 E5/E8 接入）；
    /// 摘要/链态终判 = native 三块手链（独立路径）。
    #[test]
    fn chained_three_bodies_match_native() {
        let (_e, _r, _s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
        let za = crate::sm2_z_anchor::z_a_words(crate::sm2_z_anchor::DEFAULT_ID, &(pax, pay));
        let za_be: Vec<u8> = za.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut id32 = [0u8; 32];
        id32[..16].copy_from_slice(crate::sm2_z_anchor::DEFAULT_ID);
        let attrs: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x5A);
        let pax_be = crate::sm2_z_anchor::fe_be32(&pax);
        let pay_be = crate::sm2_z_anchor::fe_be32(&pay);
        let mut b1 = [0u8; 64];
        b1[..32].copy_from_slice(&za_be);
        b1[32..].copy_from_slice(&id32);
        let mut b2 = [0u8; 64];
        b2[..32].copy_from_slice(&attrs);
        b2[32..].copy_from_slice(&pax_be);
        let mut b3 = [0u8; 64];
        b3[..32].copy_from_slice(&pay_be);
        b3[32] = 0x80; // 160B 语句第三块尾填充起点（J-1）
        b3[56..64].copy_from_slice(&1280u64.to_be_bytes()); // be64(1280)，禁沿用 1680

        // native 三块手链（独立终判路径）。
        let c = crate::sm3_native_ref::compress;
        let iv = crate::sm3_native_ref::IV;
        let v1 = c(&iv, &b1);
        let v2 = c(&v1, &b2);
        let dg = c(&v2, &b3);

        let circ = build_chained_bodies_const([b1, b2, b3], iv, 2500);

        // ① 摘要终判：电路摘要 == native 手链；实例钉值一致。
        for k in 0..8usize {
            assert_eq!(circ.digest[k], dg[k], "摘要字 {k} ≠ native");
            assert_eq!(
                circ.instances[0][k],
                <Fr as From<u64>>::from(dg[k] as u64),
                "实例摘要字 {k} 不符"
            );
        }
        // ② 链态终判：V₁/V₂ == native 中间态（compress 契约 = 已含链接 XOR）。
        assert_eq!(circ.chain_states[0], v1, "链态 V₁ ≠ native");
        assert_eq!(circ.chain_states[1], v2, "链态 V₂ ≠ native");
        // ③ 旋转预算守卫（S1 不变量）：C/E 同区行共享后三体全部 ≤ K。
        let maxd = circ
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
        // ④ 环账本：环全部 ≥2；格全局唯一（含两条体间通道 + echo 根环）。
        let mut seen = std::collections::BTreeSet::new();
        for cyc in &circ.info.permutations {
            assert!(cyc.len() >= 2);
            for cell in cyc {
                assert!(seen.insert(*cell), "格 {cell:?} 出现在多个环位");
            }
        }
        // ⑤ 环值审计 + 位级 mock（三道防线前两道）。
        let bad_rings = crate::sm3_compress::audit_ring_values(&circ.info, &circ.advice);
        assert!(bad_rings.is_empty(), "环取值不一致: {bad_rings:?}");
        let bad = check_parts_violations(&circ.info, &circ.advice, &circ.instances);
        assert!(bad.is_empty(), "mock 违约 {} 处", bad.len());
        // ⑥ 形状首跑记账（数字冻结进蓝图 J-10 后再升格为断言）。
        println!(
            "[chained-3body] constraints={} advice={} sel={} prep={} cycles={} max|rot|={}",
            circ.info.constraints.len(),
            circ.advice.len(),
            circ.num_selectors,
            circ.info.preprocess_polys.len(),
            circ.info.permutations.len(),
            maxd
        );
    }
}
