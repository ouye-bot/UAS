//! 1.1b SM3 压缩函数 Plonkish 电路 —— b1 门原语 + b2 单轮块 + b3 消息扩展
//! + 全压缩装配器（列池 / SlotRef 列流链值）。
//!
//! 设计蓝本：记忆 [[phase1-sm3-compress-plonkish-design]]；实现期勘误见模块末尾
//! 「勘误总账」与记忆 [[phase1-b1-gate-primitives]]。
//!
//! ═══════════ 行序与索引模型（后端事实，勿动） ═══════════
//! - 多项式按 GF(2^k) **点值**直接索引（hyperplonk.rs:116,200 无重排）；
//!   表达式在点 b 读 `polys[p][bh.rotate(b, rot)]`（prover.rs:109），
//!   `bh.rotate` 是 LFSR **秩序**步进（bh.rs:105）。
//! - 因此一切结构位移用**秩**表达：块区 = 连续秩窗口 [RANK_BASE, RANK_BASE+612)；
//!   跨区读取一律 `rot_between`（秩差），并有负向回归卫兵测试。
//! - 实例 #ordinal 放在 `row_mapping()[ordinal]`（= iter().skip(1).chain([0])）；
//!   点 0 是 LFSR 吸收态，禁止作为任何门行。

use plonkish_backend::{
    backend::{PlonkishCircuit, PlonkishCircuitInfo},
    util::{
        arithmetic::{BooleanHypercube, PrimeField},
        expression::{Expression, Query, Rotation},
    },
    Error,
};
use std::{
    collections::HashMap,
    sync::OnceLock,
};

// ───────────────────────── 常量与行序工具 ─────────────────────────

/// 电路规模 k（2^11 = 2048 行）。b4 路线决策（2026-08-27）：管线化 v2 布局每块
/// 条带加宽以容纳实例绑定的复制词家点（见 [[backend-rotation-budget-boundary]]：
/// 后端旋转预算迫使一切跨块引用走 pi 层），秩窗口随之扩到 ~1600，故 k 取 11。
/// v1 布局在新 k 下数学不变（秩窗只是更宽松），保留作回归基线。
pub const K: usize = 12;
/// 2^K。
pub const ROWS: usize = 1 << K;
/// 块区秩基址（真实块 0 的秩）。
pub const RANK_BASE: usize = 256;
/// 负号虚拟轮数：初始化寄存以 j′=−4..−1 的"虚拟轮"身份放在窗口正前方，
/// 其秩 = 真实块秩公式在负 j 处的线性延续。这保证任何滞后槽读取的
/// 「行→源」秩差对全部 j（含边界四轮）恒为常数——HyperPlonk 约束是全局
/// 表达式，共享选择器家族只有在恒等式处处成立时才健全（勘误 #13）。
pub const NUM_VIRT: i64 = 4;

/// 有符号轮号 → 窗口内点值。sj ∈ [−NUM_VIRT, NUM_BLOCKS)。
pub fn signed_row(sj: i64, offset: usize) -> usize {
    let rk = RANK_BASE as i64 + sj * ROWS_PER_BLOCK as i64 + offset as i64;
    assert!(rk >= 1 && rk < ROWS as i64, "signed_row({sj},{offset}) 越界秩 {rk}");
    rank_inverse()[rk as usize]
}
/// 压缩轮数（SM3 标准：64 轮；扩展字表才是 68）。
pub const NUM_ROUNDS: usize = 64;
/// 每块行数：off 0..8 恰好用满（0=ext-x/PNXT、1=SS1PRE、2=SS2、3=FF、4=TT1、
/// 5=GG、6=TT2、7=W[j]、8=W'[j]）。
pub const ROWS_PER_BLOCK: usize = 9;
/// 压缩轮数 = 扩展字数。
pub const NUM_BLOCKS: usize = 68;

fn bh() -> BooleanHypercube {
    BooleanHypercube::new(K)
}

pub fn nth_map() -> &'static Vec<usize> {
    static NTH: OnceLock<Vec<usize>> = OnceLock::new();
    NTH.get_or_init(|| bh().nth_map())
}

pub fn rank_inverse() -> &'static Vec<usize> {
    static INV: OnceLock<Vec<usize>> = OnceLock::new();
    INV.get_or_init(|| bh().iter().collect())
}

pub fn row_mapping() -> &'static Vec<usize> {
    static RM: OnceLock<Vec<usize>> = OnceLock::new();
    RM.get_or_init(|| bh().iter().skip(1).chain([0]).collect())
}

/// 块 b offset o 的行点值（数组下标 = 点值）。
pub fn row_of(block: usize, offset: usize) -> usize {
    rank_inverse()[RANK_BASE + block * ROWS_PER_BLOCK + offset]
}

/// 任意自由秩的点值（初始化条带等使用）。
pub fn point_at_rank(rank: usize) -> usize {
    rank_inverse()[rank]
}

/// 在 from 点上读 to 点所需的旋转 = 秩差。
pub fn rot_between(from: usize, to: usize) -> Rotation {
    let d = nth_map()[to] as i64 - nth_map()[from] as i64;
    assert!(d.abs() <= (ROWS - 1) as i64, "旋转 {d} 超出 2^k−1 循环");
    Rotation(d as i32)
}

/// rotl_n 视图：输出位 i ← 源位 (i−n) mod 32（= u32::rotate_left 定义）。
pub const fn rotl_src_index(i: usize, n: u32) -> usize {
    (i + 32 - (n % 32) as usize) % 32
}

/// 轮常数 T_j（T0/T1 来源 = sm3_native_ref 机械复制件）。
pub fn tj_value(j: usize) -> u32 {
    let t = if j < 16 {
        crate::sm3_native_ref::T0
    } else {
        crate::sm3_native_ref::T1
    };
    t.rotate_left(j as u32)
}

// ───────────────────────── 词柄 / 槽引用 / 列池 ─────────────────────────

/// 一个 32 位词的列组 + 家点（bits LSB-first）。
#[derive(Clone, Copy, Debug)]
pub struct WordHandle {
    pub bits: [usize; 32],
    pub val: Option<usize>,
    pub home: usize,
}

impl WordHandle {
    pub fn val_expect(&self) -> usize {
        self.val.expect("此词没有值列")
    }
}

/// 固定列组的词（跨块复用同一组 advice 列，家点按块变化）。
#[derive(Clone, Copy, Debug)]
pub struct WordCols {
    pub bits: [usize; 32],
    pub val: Option<usize>,
}

impl WordCols {
    /// 以家点实例化为句柄。n_bits 选择性收窄位数（W/W' 等全词 = None），
    /// 目前统一用满 32 位；保留参数为后续 message-block 常量折叠预留。
    pub fn at(&self, home: usize) -> WordHandle {
        WordHandle {
            bits: self.bits,
            val: self.val,
            home,
        }
    }
}

/// 槽引用 = 词的 rotl_n 视图（n=0 即直读）。链值寄存器的"纯重排零门"载体：
/// a_j=T1_{j−1}、c_j=rotl9(T1_{j−3})、g_j=rotl19(PNXT_{j−3}) 等。
///
/// **持有所有权而非借用**：WordHandle 是纯数据（[usize;32]+Option<usize>+usize，
/// 全 Copy），借用只会制造 E0515（池实例化临时值）与 unsafe 注册表之类的补丁。
pub struct SlotRef {
    pub h: WordHandle,
    pub n: u32,
}

impl SlotRef {
    /// 直读视图。
    pub fn view(h: &WordHandle) -> Self {
        Self { h: *h, n: 0 }
    }
    /// rotl_n 视图。
    pub fn rotl(h: &WordHandle, n: u32) -> Self {
        Self { h: *h, n }
    }
}

impl From<&WordHandle> for SlotRef {
    fn from(h: &WordHandle) -> Self {
        SlotRef::view(h)
    }
}

/// 共享 carry 对（b0/b1 两列全电路复用；布尔性由各 ADD 行的选择器约束）。
#[derive(Clone, Copy, Debug)]
pub struct CarryPair {
    pub b0: usize,
    pub b1: usize,
}

// ───────────────────────── Builder（门原语层） ─────────────────────────

/// 多项式全局索引约定（同 spike #1）：[0]=实例 → [1..1+S)=选择器 → 之后 advice。
/// 所有分配须在第一条约束前完成（此后布局冻结，assert 兜底）。
pub struct Builder<F: PrimeField> {
    num_instance_values: usize,
    advice_count: usize,
    selector_data: Vec<Vec<F>>,
    constraints: Vec<Expression<F>>,
    /// 家族聚合计数（诊断用）。
    pub tags: Vec<(&'static str, usize)>,
    /// 与 constraints 平行的逐条家族标签（诊断用）。
    ctag_of: Vec<&'static str>,
    writes: Vec<(usize, usize, F)>,
    instance_values: Vec<F>,
    pow2: Vec<F>,
    frozen: bool,
    /// 复制环账本（管线化 v2）：按登记顺序存环；`cycle_of` 保证每个格
    /// （值列全局号, 点值）全程至多属于一个环位（置换表交换语义的红线，
    /// 重复格会静默破坏积论证 —— 见 sm3_perm_smoke 取证）。
    cycles: Vec<Vec<(usize, usize)>>,
    cycle_of: HashMap<(usize, usize), usize>,
    /// R1-v3b 取证：全部非 cur 查询 (advice 局部列, rot) 流水（q() 热路径
    /// 一次装配期追加，装配后经 [`Self::q_edge_counts`] 聚合）。
    q_edges: std::cell::RefCell<Vec<(usize, i64)>>,
    /// P2（system/sm3-lookup-full，系统线 2026-09-18）：查表论证累积器——
    /// LUT 化 SM3 体的发射通道。legacy 路径不触碰（保持空向量=发布锚字节级
    /// 行为保证）；SM3_LUT 分派后按通道填充。
    lookups: Vec<Vec<(Expression<F>, Expression<F>)>>,
}

impl<F: PrimeField> Builder<F> {
    pub fn new(num_instance_values: usize) -> Self {
        Self {
            num_instance_values,
            advice_count: 0,
            selector_data: Vec::new(),
            constraints: Vec::new(),
            tags: Vec::new(),
            ctag_of: Vec::new(),
            writes: Vec::new(),
            instance_values: vec![F::ZERO; num_instance_values],
            pow2: (0..=32u32).map(|i| F::from(1u64 << i)).collect(),
            frozen: false,
            cycles: Vec::new(),
            cycle_of: HashMap::new(),
            q_edges: std::cell::RefCell::new(Vec::new()),
            lookups: Vec::new(),
        }
    }

    /// P2：发射一条查表论证（(输入表达式, 表项表达式) 对向量——logUp 每通道
    /// 一组）。仅 SM3_LUT 路径调用；legacy 零调用（lookups 保持空）。
    pub fn emit_lookup(&mut self, pairs: Vec<(Expression<F>, Expression<F>)>) {
        assert!(
            !pairs.is_empty(),
            "查表论证不得为空（空通道=无意义论证）"
        );
        self.lookups.push(pairs);
    }

    /// 非 cur 查询按 (局部列, rot) 聚合计数（升序）。布局审计用：
    /// local → 车道身份（列段模式），rot+车道 → (激活点, 家点) 归因。
    pub fn q_edge_counts(&self) -> Vec<((usize, i64), usize)> {
        let mut m: HashMap<(usize, i64), usize> = HashMap::new();
        for &k in self.q_edges.borrow().iter() {
            *m.entry(k).or_insert(0) += 1;
        }
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_unstable();
        v
    }

    // ---- 布局 ----

    fn assert_open(&self) {
        assert!(!self.frozen, "布局已冻结：分配必须先于第一条约束");
    }

    pub fn alloc_col(&mut self) -> usize {
        self.assert_open();
        let c = self.advice_count;
        self.advice_count += 1;
        c
    }

    pub fn alloc_word_at_home(&mut self, home: usize, with_value: bool) -> WordHandle {
        let bits = [(); 32].map(|_| self.alloc_col());
        let val = if with_value { Some(self.alloc_col()) } else { None };
        WordHandle { bits, val, home }
    }

    /// 分配一组可复用列（不含家点语义）。with_value=false 时省值列。
    pub fn alloc_word_cols(&mut self, with_value: bool) -> WordCols {
        let bits = [(); 32].map(|_| self.alloc_col());
        let val = if with_value { Some(self.alloc_col()) } else { None };
        WordCols { bits, val }
    }

    pub fn alloc_carries(&mut self) -> CarryPair {
        CarryPair {
            b0: self.alloc_col(),
            b1: self.alloc_col(),
        }
    }

    pub fn alloc_selector(&mut self, active_points: &[usize]) -> usize {
        self.assert_open();
        let mut poly = vec![F::ZERO; ROWS];
        for &p in active_points {
            assert_ne!(p, 0, "点 0 是 LFSR 吸收态");
            assert_eq!(poly[p], F::ZERO, "选择器激活点 {p} 重复");
            poly[p] = F::ONE;
        }
        let global = 1 + self.selector_data.len();
        self.selector_data.push(poly);
        global
    }

    /// 向已分配的选择器追加激活点。**允许在约束发射后调用**：选择器向量长度
    /// 在 alloc 时已定，此处只改格值、不改布局（b2 harness 同款用法）。
    pub fn extend_selector(&mut self, global_sel: usize, pts: &[usize]) {
        let poly = &mut self.selector_data[global_sel - 1];
        for &pt in pts {
            assert_ne!(pt, 0, "点 0 是 LFSR 吸收态");
            assert_eq!(poly[pt], F::ZERO, "选择器激活点 {pt} 重复");
            poly[pt] = F::ONE;
        }
    }

    pub fn advice_global(&self, local: usize) -> usize {
        1 + self.selector_data.len() + local
    }

    /// 追加一条**任意内容**的预处理多项式（选择器只是其特例）。全局编号与
    /// 选择器同段（advice 基址随之整体后移，故必须早于任何 advice 分配）。
    /// 典型用途：随行变化的轮常数 T_j（勘误 #14）——查询旋转一致、
    /// 值逐行不同、证明方不可篡改。
    pub fn alloc_const_poly(&mut self, values: Vec<F>) -> usize {
        self.assert_open();
        assert_eq!(values.len(), ROWS, "预处理多项式必须覆盖全超立方");
        // 全局号与 alloc_selector 同式：**push 前**取长度（保证首个多项式 = 1，
        // 0 号永久保留给实例列）。
        let global = 1 + self.selector_data.len();
        self.selector_data.push(values);
        global
    }

    /// 查询预处理多项式在当前行的值（`Rotation::cur()`）。
    pub fn prep_cur(&self, prep_g: usize) -> Expression<F> {
        Expression::Polynomial(Query::new(prep_g, Rotation::cur()))
    }

    pub fn q_inst(&self, rot: Rotation) -> Expression<F> {
        Expression::Polynomial(Query::new(0, rot))
    }

    pub fn q(&self, local: usize, rot: Rotation) -> Expression<F> {
        if rot.0 != 0 {
            self.q_edges.borrow_mut().push((local, rot.0 as i64));
        }
        Expression::Polynomial(Query::new(self.advice_global(local), rot))
    }

    pub fn sel(&self, global_sel: usize) -> Expression<F> {
        Expression::Polynomial(Query::new(global_sel, Rotation::cur()))
    }

    /// 系统线 2026-09-16 pub 化（原私有）：B-batch3 数值谓词档需要自定义
    /// **原样出口**：表达式不做任何加工（不乘 selector、不加门控）直接入表。
    /// 🔴 定谳二次教训：本方法与 emit_* 家族**不一致**——emit_assert_zero 等
    /// 会乘 sel；经 push 裸推=全点约束。需要「自定义族标签 + 门控」的调用方
    /// 用 [`Builder::emit_assert_zero_tagged`]，勿在此手拼。
    pub fn push(&mut self, tag: &'static str, c: Expression<F>) {
        if !self.frozen {
            self.frozen = true;
        }
        match self.tags.iter_mut().find(|(t, _)| *t == tag) {
            Some((_, n)) => *n += 1,
            None => self.tags.push((tag, 1)),
        }
        self.ctag_of.push(tag);
        self.constraints.push(c);
    }

    pub fn n_constraints(&self) -> usize {
        self.constraints.len()
    }

    // ---- 实例锚点 / 词绑定（管线化 v2 原语，勘误 #16 机制）----

    /// 当前已预留的实例值个数（v2 装配器做清单核对用）。
    pub fn num_instances(&self) -> usize {
        self.num_instance_values
    }

    /// 预留 n 个实例序号（必须发生在 finalize 前；返回基址）。管线化电路把
    /// 全部中间量（W/T1/PNXT/IV/digest）作为公开语句锚点，远程引用一律
    /// 「复制词 + 同序号绑定」传输，电路内零长旋转（勘误 #16 / 后端旋转预算）。
    pub fn reserve_instances(&mut self, n: usize) -> usize {
        self.assert_open();
        let base = self.num_instance_values;
        self.num_instance_values += n;
        base
    }

    /// 把一条词列组钉到实例 #ordinal：s·(val − inst)=0；Σ2^i·bit_i = val；
    /// 每位布尔。共 **34 条**（pin.bind/pin.recomp/pin.bool×32），全部 cur 旋转，
    /// 在 sel_g 的每个激活点求值 —— 激活点即钉行，家点语义由调用方保证
    /// 「列在该行的格 = 所钉值」。
    pub fn emit_pin_word(&mut self, sel_g: usize, wc: &WordCols, ordinal: usize) {
        assert!(ordinal < self.num_instance_values, "pin 序号 {ordinal} 未预留");
        let s = self.sel(sel_g);
        let r = Rotation::cur();
        let ve = self.q(wc.val.expect("pin 词必须有值列"), r);
        let mut recomposed = Expression::<F>::zero();
        for i in 0..32 {
            let be = self.q(wc.bits[i], r);
            recomposed = recomposed + self.lc(i, be.clone());
            let gb = s.clone() * be.clone() * (be - Expression::<F>::one());
            self.push("pin.bool", gb);
        }
        self.push("pin.recomp", s.clone() * (ve.clone() - recomposed));
        self.push("pin.bind", s * (ve - self.q_inst(r)));
    }

    /// 实例钉点的**单值列形态**（v3 列压缩 P1a/P1b）：只发 pin.bind 一条约束。
    /// 位重分解不在此层 —— 值的 <2^32 成员性由中继环消费点的
    /// [`Builder::emit_word_link`] 兜底（根点位格省略不损健全性）。
    pub fn emit_pin_val_only(&mut self, sel_g: usize, val_local: usize, ordinal: usize) {
        assert!(ordinal < self.num_instance_values, "pin 序号 {ordinal} 未预留");
        let s = self.sel(sel_g);
        let r = Rotation::cur();
        let ve = self.q(val_local, r);
        self.push("pin.bind", s * (ve - self.q_inst(r)));
    }

    /// 单列常数锚（v3 列压缩 P1c）：sel·(val − word)=0 直接封死格值，
    /// 取代「32 常量位 + link」的 33 约束/33 列形态。
    pub fn emit_const_val(&mut self, sel_g: usize, val_local: usize, word: u32) {
        let s = self.sel(sel_g);
        let ve = self.q(val_local, Rotation::cur());
        self.push(
            "anchor.const",
            s * (ve - Expression::<F>::Constant(F::from(word as u64))),
        );
    }

    // ---- 通用门原语（1.1c 验签体移植；蓝图 M3_probe/VERIFY_BODY_BLUEPRINT.md §七-簇A）----
    // 设计边界：这里只加「形状最泛、语义最小」的三条出口与一个写入器；
    // 具体外来域算术（mod-n 七件套）与 EC 公式的领域逻辑全部留在
    // sm2_scalar_plonkish / sm2_ec_plonkish 模块 —— 防止 Builder 被领域门淹没。

    /// 单格任意域元素见证写入（set_cell_u32 只能写 u32；验签体需要逆元、λ 等
    /// 大数值 witness）。写入同样延迟到 finish_parts 应用。
    pub fn set_cell_f(&mut self, col: usize, point: usize, v: F) {
        self.writes.push((col, point, v));
    }

    /// 2^k 常数表达式（k < 64）。SM3 自带 pow2 表只到 2^31；外来域 limb 加法
    /// 需要 2^64 缩放，且 1u64<<63 在 u64 内仍为正值可直接 F::from。
    pub fn const_pow2(&self, k: usize) -> Expression<F> {
        assert!(k < 64, "const_pow2 只承诺 < 2^64");
        Expression::<F>::Constant(F::from(1u64 << k))
    }

    /// 位布尔性：s·(b²−b)=0，单推。家族名独立于 link.bool —— Phase-2 若用
    /// 字节级 range lookup 批量替换布尔性（spike #1 已证栈兼容），可按本
    /// 标签整体计量与替换。
    pub fn emit_bool(&mut self, sel_g: usize, bit_local: usize) {
        let s = self.sel(sel_g);
        let b = self.q(bit_local, Rotation::cur());
        self.push("bool", s * (b.clone() * b.clone() - b));
    }

    /// 二次积等式：s·(a·b − r)=0，单推。R1CS mul / 条件求逆 `w·t = 1−z`
    /// / neq_zero `x·inv = 1` 的通用底座；度 2 ≪ 后端已验证的度 4 先例。
    pub fn emit_prod_eq(
        &mut self,
        sel_g: usize,
        a: Expression<F>,
        b: Expression<F>,
        r: Expression<F>,
    ) {
        let s = self.sel(sel_g);
        self.push("prod.eq", s * (a * b - r));
    }

    /// 任意表达式零断言：s·e=0，单推。线性等式（limb 加法链、Σbits=val 大折叠）、
    /// 选择树余项等领域约束的统一出口。调用方负责 e 的度数与健全性论证。
    pub fn emit_assert_zero(&mut self, sel_g: usize, e: Expression<F>) {
        let s = self.sel(sel_g);
        self.push("assert.zero", s * e);
    }

    /// 带自定义族标签的门控断言（定谳三次新增）：s·e=0，语义与
    /// [`Builder::emit_assert_zero`] 一致，仅族标签可指定（负例族断言
    /// 需要与 push 直发约束（如 pred.t1.range.recomb）同层的可具名家族）。
    pub fn emit_assert_zero_tagged(&mut self, tag: &'static str, sel_g: usize, e: Expression<F>) {
        let s = self.sel(sel_g);
        self.push(tag, s * e);
    }

    /// 把一个词的位格在本地重分解到其值列：s·(Σ2^i·bit_i − val)=0 加 32 条位布尔
    /// （复制词落地 = 值列环 + 本地 link，见 v2 模块文档；相比按位环省下的是
    /// **置换涉及的列数** —— 证明大小与提交多项式数成正比，bit 列方案会翻倍以上）。
    pub fn emit_word_link(&mut self, sel_g: usize, wc: &WordCols) {
        let s = self.sel(sel_g);
        let r = Rotation::cur();
        let ve = self.q(wc.val.expect("link 词必须有值列"), r);
        let mut recomposed = Expression::<F>::zero();
        for i in 0..32 {
            let be = self.q(wc.bits[i], r);
            recomposed = recomposed + self.lc(i, be.clone());
            let gb = s.clone() * be.clone() * (be - Expression::<F>::one());
            self.push("link.bool", gb);
        }
        self.push("link.recomp", s * (ve - recomposed));
    }

    // ---- 复制环中继（管线化 v2 核心；语义取证见 sm3_perm_smoke） ----

    /// 开启一条以 src 词值格为首位成员的中继环。**同一格全程至多属于一个环**
    /// （协议红线）：一个正典词只许 begin 一次，其余消费走 [`Builder::relay_to`]
    /// 追加进同一条环。
    ///
    /// 键编码勘误 #25（merged 形态首跑环审计 229 条不等抓到）：环键一律存
    /// **advice 局部列号** `(val_local, at)`，全局多项式号由 [`Builder::finish_parts`]
    /// 在 `selector_data` 冻结后统一解析（`1 + ns + local`）。此前键在**登记时**
    /// 即用 `advice_global()` 编码 —— 隐含前提「登记时选择器数 == 最终选择器数」，
    /// 既有电路全部满足故全绿；merged 装配器先注册 Z 段环、后 `plan_all` 补
    /// 验签体选择器 ⟹ 登记期编码的全局号全体偏移（置换绑错列，mock 与环审计
    /// 双盲）。局部号与选择器数无关 ⟹ 编码时点自由，缺陷类别整体消除。
    pub fn begin_relay(&mut self, src: &WordHandle) -> usize {
        self.assert_open();
        let key = (src.val_expect(), src.home);
        assert_ne!(src.home, 0, "点 0 是 LFSR 吸收态，禁入环");
        assert!(!self.cycle_of.contains_key(&key), "格 {key:?} 已在另一环中");
        let id = self.cycles.len();
        self.cycles.push(vec![key]);
        self.cycle_of.insert(key, id);
        id
    }

    /// 把 dst 词的值格（在点 `at`）追加进中继环 `id`。池列跨条带复用时落点
    /// 由装配期决定，故 here 显式给点。值等式由后端积论证保证（零约束、零旋转）；
    /// 位形态由调用方随后在 `at` 上发 [`Builder::emit_word_link`] 本地重构。
    pub fn relay_to(&mut self, id: usize, dst: &WordCols, at: usize) {
        let key = (dst.val.expect("relay 词需值列"), at);
        assert_ne!(at, 0, "点 0 是 LFSR 吸收态，禁入环");
        assert!(!self.cycle_of.contains_key(&key), "格 {key:?} 已在另一环中");
        self.cycle_of.insert(key, id);
        self.cycles[id].push(key);
    }

    /// 1.1c 簇D 配套新增：[`Builder::begin_relay`] 的单值列开环形态 —— 以
    /// 任意 advice 格 `(val_local, at)` 开启一条中继环（键编码同
    /// [`Builder::relay_to_col`]），供非词形载体（EC β 位车道、基点坐标车道）
    /// 复用同一置换机制。语义红线不变：一格至多属一环，0 号点禁入环。
    pub fn begin_relay_col(&mut self, val_local: usize, at: usize) -> usize {
        self.assert_open();
        let key = (val_local, at);
        assert_ne!(at, 0, "点 0 是 LFSR 吸收态，禁入环");
        assert!(!self.cycle_of.contains_key(&key), "格 {key:?} 已在另一环中");
        let id = self.cycles.len();
        self.cycles.push(vec![key]);
        self.cycle_of.insert(key, id);
        id
    }

    /// [`Builder::relay_to`] 的**单值列形态**（v3 列压缩：落点位格无需求时
    /// 直接以列号入环；键编码与位格世界完全一致）。
    pub fn relay_to_col(&mut self, id: usize, val_local: usize, at: usize) {
        let key = (val_local, at);
        assert_ne!(at, 0, "点 0 是 LFSR 吸收态，禁入环");
        assert!(!self.cycle_of.contains_key(&key), "格 {key:?} 已在另一环中");
        self.cycle_of.insert(key, id);
        self.cycles[id].push(key);
    }

    /// B-batch2：查询格 (val_local, at) 所在环 id（成员追加用——环=等值类，
    /// 多成员合法；None=自由格）。
    pub fn ring_of(&self, val_local: usize, at: usize) -> Option<usize> {
        self.cycle_of.get(&(val_local, at)).copied()
    }

    /// 已登记中继环数（测试/装配核对用）。
    pub fn num_relays(&self) -> usize {
        self.cycles.iter().filter(|c| c.len() >= 2).count()
    }


    // ---- 见证写入 ----

    pub fn set_word(&mut self, h: &WordHandle, v: u32) {
        for i in 0..32 {
            let bit = ((v >> i) & 1) as u64;
            self.writes.push((h.bits[i], h.home, F::from(bit)));
        }
        if let Some(val) = h.val {
            self.writes.push((val, h.home, F::from(v as u64)));
        }
    }

    pub fn set_cell_u32(&mut self, col: usize, point: usize, v: u32) {
        self.writes.push((col, point, F::from(v as u64)));
    }

    pub fn set_carries(&mut self, cp: &CarryPair, at: usize, carry: u32) {
        assert!(carry < 4);
        self.writes.push((cp.b0, at, F::from((carry & 1) as u64)));
        self.writes.push((cp.b1, at, F::from(((carry >> 1) & 1) as u64)));
    }

    pub fn set_instance(&mut self, ordinal: usize, v: F) {
        assert!(ordinal < self.num_instance_values);
        self.instance_values[ordinal] = v;
    }

    // ---- 线性式 ----

    /// 常系数缩放（后端无 F×Expression，须 Constant 包裹）。
    fn lc(&self, coef_idx: usize, e: Expression<F>) -> Expression<F> {
        Expression::Constant(self.pow2[coef_idx].clone()) * e
    }

    pub fn lin_bits(&self, h: &WordHandle, at: usize) -> Expression<F> {
        let rot = rot_between(at, h.home);
        let mut acc = Expression::<F>::zero();
        for i in 0..32 {
            acc = acc + self.lc(i, self.q(h.bits[i], rot));
        }
        acc
    }

    pub fn lin_rotl(&self, h: &WordHandle, n: u32, at: usize) -> Expression<F> {
        let rot = rot_between(at, h.home);
        let mut acc = Expression::<F>::zero();
        for i in 0..32 {
            acc = acc + self.lc(i, self.q(h.bits[rotl_src_index(i, n)], rot));
        }
        acc
    }

    /// 槽的位线性式（= lin_rotl 的槽记法）。
    pub fn lin_slot(&self, s: &SlotRef, at: usize) -> Expression<F> {
        self.lin_rotl(&s.h, s.n, at)
    }

    pub fn const_u32(&self, v: u32) -> Expression<F> {
        Expression::Constant(F::from(v as u64))
    }

    // ---- 门（度 ≤ 4 含选择器）----

    /// XOR（双输入视图）：s·(2·x⟨nx⟩·y⟨ny⟩ − x⟨nx⟩ − y⟨ny⟩ + o_i)=0 ×32。
    pub fn emit_xor(
        &mut self,
        sel_g: usize,
        x: &SlotRef,
        y: &SlotRef,
        o: &WordHandle,
        at: usize,
    ) {
        let s = self.sel(sel_g);
        let ro = rot_between(at, o.home);
        let rx = rot_between(at, x.h.home);
        let ry = rot_between(at, y.h.home);
        for i in 0..32 {
            let xv = self.q(x.h.bits[rotl_src_index(i, x.n)], rx);
            let yv = self.q(y.h.bits[rotl_src_index(i, y.n)], ry);
            let ov = self.q(o.bits[i], ro);
            let g =
                s.clone() * ((self.lc(1, xv.clone() * yv.clone())) - xv - yv + ov);
            self.push("xor", g);
        }
    }

    /// MAJ：s·(o_i − xy − xz − yz + 2xyz)=0 ×32（多线性唯一代表；
    /// 缺 2xyz 时在输入全 1 位不健全——勘误 #6）。
    pub fn emit_maj(&mut self, sel_g: usize, x: &SlotRef, y: &SlotRef, z: &SlotRef, o: &WordHandle, at: usize) {
        let s = self.sel(sel_g);
        let ro = rot_between(at, o.home);
        let rx = rot_between(at, x.h.home);
        let ry = rot_between(at, y.h.home);
        let rz = rot_between(at, z.h.home);
        for i in 0..32 {
            let xv = self.q(x.h.bits[rotl_src_index(i, x.n)], rx);
            let yv = self.q(y.h.bits[rotl_src_index(i, y.n)], ry);
            let zv = self.q(z.h.bits[rotl_src_index(i, z.n)], rz);
            let ov = self.q(o.bits[i], ro);
            let g = s.clone()
                * (ov - xv.clone() * yv.clone() - xv.clone() * zv.clone()
                    - yv.clone() * zv.clone()
                    + self.lc(1, xv * yv * zv));
            self.push("maj", g);
        }
    }

    /// CHOOSE：s·(o_i − z − x·(y−z)) = 0 ×32。
    pub fn emit_choose(&mut self, sel_g: usize, x: &SlotRef, y: &SlotRef, z: &SlotRef, o: &WordHandle, at: usize) {
        let s = self.sel(sel_g);
        let ro = rot_between(at, o.home);
        let rx = rot_between(at, x.h.home);
        let ry = rot_between(at, y.h.home);
        let rz = rot_between(at, z.h.home);
        for i in 0..32 {
            let xv = self.q(x.h.bits[rotl_src_index(i, x.n)], rx);
            let yv = self.q(y.h.bits[rotl_src_index(i, y.n)], ry);
            let zv = self.q(z.h.bits[rotl_src_index(i, z.n)], rz);
            let ov = self.q(o.bits[i], ro);
            let g = s.clone() * (ov - zv.clone() - xv * (yv - zv));
            self.push("choose", g);
        }
    }

    /// mod-2^32 加法：36 条（主方程 1 + 结果位布尔 32 + 值一致性 1 + carry 位布尔 2；
    /// 2 位 carry 覆盖 {0..3} ≥ 三/四项和真进位——勘误 #3/蓝图修正）。
    pub fn emit_add(
        &mut self,
        sel_g: usize,
        terms: &[Expression<F>],
        res: &WordHandle,
        cp: &CarryPair,
        at: usize,
    ) {
        let s = self.sel(sel_g);
        let rr = rot_between(at, res.home);
        let b0e = self.q(cp.b0, Rotation::cur());
        let b1e = self.q(cp.b1, Rotation::cur());

        let mut sum = Expression::<F>::zero();
        for t in terms {
            sum = sum + t.clone();
        }
        let ve = self.q(res.val_expect(), rr);

        let main = s.clone()
            * (sum - ve.clone() - self.lc(32, b0e.clone() + self.lc(1, b1e.clone())));
        self.push("add.main", main);

        let mut recomposed = Expression::<F>::zero();
        for i in 0..32 {
            let be = self.q(res.bits[i], rr);
            recomposed = recomposed + self.lc(i, be.clone());
            let gb = s.clone() * be.clone() * (be - Expression::<F>::one());
            self.push("add.bitbool", gb);
        }
        let gc = s.clone() * (ve - recomposed);
        self.push("add.vcon", gc);

        self.push(
            "add.c0bool",
            self.sel(sel_g) * b0e.clone() * (b0e - Expression::<F>::one()),
        );
        self.push(
            "add.c1bool",
            self.sel(sel_g) * b1e.clone() * (b1e - Expression::<F>::one()),
        );
    }

    /// feedforward 计算半件（v2 摘要用）：只把 O = last⟨n⟩ ⊕ IV 字 写入 o_val 列
    /// （ff.out），**不做实例绑定** —— v2 的绑定经 echo 复制回低秩钉点由
    /// [`Builder::emit_pin_word`] 完成（条带点不是实例映射点，ff.bind 在那里无语义）。
    pub fn emit_feedforward_val(
        &mut self,
        sel_g: usize,
        last: &SlotRef,
        iv_word: u32,
        o_val_local: usize,
        at: usize,
    ) {
        let s = self.sel(sel_g);
        let oe = self.q(o_val_local, Rotation::cur());
        let rl = rot_between(at, last.h.home);
        let mut acc = Expression::<F>::zero();
        for i in 0..32 {
            let le = self.q(last.h.bits[rotl_src_index(i, last.n)], rl);
            let raw = if (iv_word >> i) & 1 == 0 {
                le
            } else {
                Expression::<F>::one() - le
            };
            acc = acc + self.lc(i, raw);
        }
        self.push("ff.out", s * (oe - acc));
    }

    /// feedforward 输出对：O = fold(last⟨n⟩ ⊕ IV 字)；再 O == inst@cur 绑定。
    pub fn emit_feedforward_pair(
        &mut self,
        sel_g: usize,
        last: &SlotRef,
        iv_word: u32,
        o_val_local: usize,
        at: usize,
        ordinal: usize,
    ) {
        assert!(self.num_instance_values > ordinal);
        let s = self.sel(sel_g);
        let oe = self.q(o_val_local, Rotation::cur());
        let rl = rot_between(at, last.h.home);
        let mut acc = Expression::<F>::zero();
        for i in 0..32 {
            let le = self.q(last.h.bits[rotl_src_index(i, last.n)], rl);
            let raw = if (iv_word >> i) & 1 == 0 {
                le
            } else {
                Expression::<F>::one() - le
            };
            acc = acc + self.lc(i, raw);
        }
        self.push("ff.out", s.clone() * (oe.clone() - acc));
        self.push("ff.bind", s * (oe - self.q_inst(Rotation::cur())));
    }

    /// 把一个词的全部位格钉在常数上：s·(bit_i − c_i)=0 ×32（虚拟轮初始化用；
    /// 不需要值列——下游一律按位读取）。
    pub fn emit_const_word_bits(&mut self, sel_g: usize, h: &WordHandle, v: u32) {
        let s = self.sel(sel_g);
        let r = Rotation::cur();
        for i in 0..32 {
            let be = self.q(h.bits[i], r);
            let c = ((v >> i) & 1) as u64;
            let g = s.clone()
                * (be - Expression::<F>::Constant(F::from(c)));
            self.push("vir.const", g);
        }
    }

    // ---- 出料 ----

    /// 出料为裸部件（管线化 v2 装配器与 v1 finalize 共用的核心）。
    #[allow(clippy::type_complexity)]
    pub fn finish_parts(
        mut self,
    ) -> (
        PlonkishCircuitInfo<F>,
        Vec<Vec<F>>,
        Vec<Vec<F>>,
        Vec<(&'static str, usize)>,
        Vec<&'static str>,
        usize,
    ) {
        self.frozen = true;
        let mut advice = vec![vec![F::ZERO; ROWS]; self.advice_count];
        for (c, p, v) in std::mem::take(&mut self.writes) {
            advice[c][p] = v;
        }
        let selector_data = std::mem::take(&mut self.selector_data);
        let ns = selector_data.len();
        let constraints = std::mem::take(&mut self.constraints);
        let ctags = std::mem::take(&mut self.ctag_of);
        assert_eq!(ctags.len(), constraints.len());
        let tags = std::mem::take(&mut self.tags);

        for (idx, c) in constraints.iter().enumerate() {
            let d = c.degree();
            assert!(d <= 4, "约束 #{idx} 度 {d} > 4");
        }

        let info = PlonkishCircuitInfo {
            k: K,
            num_instances: vec![self.num_instance_values],
            preprocess_polys: selector_data,
            num_witness_polys: vec![self.advice_count],
            num_challenges: vec![0],
            lookups: std::mem::take(&mut self.lookups),
            // 复制环（管线化 v2）：单项环（只有根）丢弃 —— 后端按 ≥2 交换才有效。
            // 键编码勘误 #25：cycles 存的是 advice **局部**列号，此处 selector
            // 数已冻结 ⟹ 统一解析为全局多项式号 `1 + ns + local`（解析时点与
            // 环登记时点解耦，merged 形态先环后选择器的装配序合法）。
            permutations: std::mem::take(&mut self.cycles)
                .into_iter()
                .filter(|c| c.len() >= 2)
                .map(|c| c.into_iter().map(|(l, p)| (ns + 1 + l, p)).collect())
                .collect(),
            constraints,
            max_degree: Some(4),
        };
        for cycle in &info.permutations {
            assert!(cycle.len() >= 2, "环长 < 2 不构成约束");
            for &(poly, pt) in cycle {
                assert_ne!(pt, 0, "环含吸收态点 0");
                let np = info.num_poly();
                assert!(poly < np, "环引用多项式 {poly} 越界 (num_poly={np})");
            }
        }
        assert!(info.is_well_formed(), "info 未通过 well-formed");

        (
            info,
            advice,
            vec![std::mem::take(&mut self.instance_values)],
            tags,
            ctags,
            ns,
        )
    }

    pub fn finalize(self, meta: CircuitMeta) -> Sm3CompressCircuit<F> {
        let (info, advice, instances, tags, ctags, num_selectors) = self.finish_parts();
        Sm3CompressCircuit {
            info,
            advice,
            instances,
            tags,
            ctags,
            num_selectors,
            meta,
        }
    }
}

// ───────────────────────── 行偏移 / 轮族选择器 ─────────────────────────

/// 每块 9 个偏移的角色分配（全部占用，无空洞）。
pub mod off {
    pub const XTMP: usize = 0; // 扩展临时 x / PNXT 共行不同列族
    pub const SS1PRE: usize = 1;
    pub const SS2: usize = 2;
    pub const FF: usize = 3;
    pub const TT1: usize = 4;
    pub const GG: usize = 5;
    pub const TT2: usize = 6;
    pub const W: usize = 7; // W[j]
    pub const WP: usize = 8; // W'[j]
}

/// 一轮工作行点集合。
#[derive(Clone, Copy, Debug)]
pub struct BlockRows {
    pub p_ss1pre: usize,
    pub p_ss2: usize,
    pub p_ff: usize,
    pub p_tt1: usize,
    pub p_gg: usize,
    pub p_tt2: usize,
    pub p_xtmp: usize,
    pub p_w: usize,
    pub p_wp: usize,
}

impl BlockRows {
    pub fn new(block: usize) -> Self {
        Self {
            p_xtmp: row_of(block, off::XTMP),
            p_ss1pre: row_of(block, off::SS1PRE),
            p_ss2: row_of(block, off::SS2),
            p_ff: row_of(block, off::FF),
            p_tt1: row_of(block, off::TT1),
            p_gg: row_of(block, off::GG),
            p_tt2: row_of(block, off::TT2),
            p_w: row_of(block, off::W),
            p_wp: row_of(block, off::WP),
        }
    }
}

/// 轮族选择器组（全局共享，激活点经 extend_selector 累加）。
/// **分支变体分离**：同选择器无法部分行走 MAJ 部分行走 xor3（全局表达式）；
/// 未用变体保持空激活集（惰性）。
/// 轮族选择器组（全局共享，激活点经 extend_selector 累加）。
/// **分支变体分离**：同选择器无法部分行走 MAJ 部分行走 xor3（全局表达式）；
/// 未用变体保持空激活集（惰性）。
///
/// **轮常数 T_j 的处理（勘误 #14）**：T_j = T_base⟨j⟩ 随**全轮号**旋转
/// （非 mod 16 —— 原生参照 `sm3_native_ref::compress` 即如此，GB/T 向量
/// 锚定）。随行变化的常数既不能折叠进共享家族的约束实例，也不能靠残差
/// 分族（族内仍不同）—— 正确做法是把 T_j 写成**预处理多项式**
/// [`Builder::alloc_const_poly`] 在各行 off1 点上的值，门用统一旋转查询：
/// 每个激活行读到的都是自己的 T，全局性天然成立，且证明方不可篡改。
#[derive(Clone, Copy, Debug)]
pub struct SelSet {
    pub ss1pre: usize,
    /// T_j 预处理多项式的全局多项式号（非选择器；见模块头勘误 #14）。
    pub tj_prep: usize,
    pub ss2: usize,
    pub ff_maj: usize,
    pub ff_xor: usize,
    pub gg_choose: usize,
    pub gg_xor: usize,
    pub tt1: usize,
    pub tt2: usize,
    /// 扩展 m1 = W16 ⊕ W9（行 = off0）
    pub ext_m1: usize,
    /// 扩展 m2 = m1 ⊕ rotl15(W3)
    pub ext_m2: usize,
    /// 扩展 t = x ⊕ rotl15(x)
    pub ext_t: usize,
    /// 扩展 p1 = t ⊕ rotl23(x)
    pub ext_p1: usize,
    /// 扩展 m3 = p1 ⊕ rotl7(W13)
    pub ext_m3: usize,
    /// 扩展 W[j] = m3 ⊕ W6
    pub ext_w: usize,
    /// W'[j] = W[j] ⊕ W[j+4]（行 = off8）
    pub wp_xor: usize,
    /// PNXT 两连异或（e' = P0(TT2)，行 = off0）
    pub pnxt: usize,
    // 输出绑定不在此列：8 个输出字母的滞后深度各不相同（1..4 轮），
    // 行→源秩差不一致，共享一个选择器家族会在异轮求值时读取错位窗口
    // （同勘误 #13 的全局性要求）→ 每个字母独立选择器（见 build_compress
    // 的 `out_sels`）。
}

// ───────────────────────── 一轮发射（核心） ─────────────────────────

/// 一轮产出物句柄。
#[derive(Clone, Copy, Debug)]
pub struct RoundWords {
    pub ss1pre: WordHandle,
    pub tt1: WordHandle,
    pub tt2: WordHandle,
}

impl<F: PrimeField> Builder<F> {
    /// 发射一轮完整约束并写见证。**数值一律取自 [`RoundVals`]（唯一真值源，
    /// 本函数零重推导）**；输入为 8 个 [`SlotRef`] 视图（纯重排零门），T_j 折叠常数。
    #[allow(clippy::too_many_arguments)]
    pub fn emit_round(
        &mut self,
        sel: &SelSet,
        rows: &BlockRows,
        j: usize,
        cp: &CarryPair,
        ins: &[SlotRef; 8],
        rv: &RoundVals,
        wj: (&WordHandle, u32),
        wpj: (&WordHandle, u32),
        pools: &RoundPools,
    ) -> RoundWords {
        let (a, b, _c, d, e, f, _g, h) =
            (rv.ins[0], rv.ins[1], rv.ins[2], rv.ins[3], rv.ins[4], rv.ins[5], rv.ins[6], rv.ins[7]);

        let tj = tj_value(j);
        let w_ss1pre = pools.ss1pre.at(rows.p_ss1pre);
        let w_tt1 = pools.tt1.at(rows.p_tt1);
        let w_tt2 = pools.tt2.at(rows.p_tt2);

        let (aa, bb, cc, dd, ee, ffx, ggx, hh) =
            (&ins[0], &ins[1], &ins[2], &ins[3], &ins[4], &ins[5], &ins[6], &ins[7]);

        // SS1PRE = rotl12(a) + e + T_j —— 输入即槽：a 的 rotl12 并入槽视图本身。
        // T_j 走预处理多项式（逐行取值，统一旋转查询 —— 勘误 #14）
        let tj_term = self.prep_cur(sel.tj_prep);
        self.emit_add(
            sel.ss1pre,
            &[
                self.lin_rotl(&aa.h, aa.n + 12, rows.p_ss1pre),
                self.lin_slot(ee, rows.p_ss1pre),
                tj_term,
            ],
            &w_ss1pre,
            cp,
            rows.p_ss1pre,
        );

        // SS2 = rotl7(SS1PRE) ⊕ rotl12(a)
        self.emit_xor(
            sel.ss2,
            &SlotRef::rotl(&w_ss1pre, 7),
            &SlotRef::rotl(&aa.h, 12),
            &pools.ss2.at(rows.p_ss2),
            rows.p_ss2,
        );

        // FF / GG 分支
        if j >= 16 {
            self.emit_maj(sel.ff_maj, aa, bb, cc, &pools.ff.at(rows.p_ff), rows.p_ff);
            self.emit_choose(sel.gg_choose, ee, ffx, ggx, &pools.gg.at(rows.p_gg), rows.p_gg);
        } else {
            let wt = pools.xor_tmp_a.at(rows.p_ff);
            self.set_word(&wt, a ^ b);
            self.emit_xor(sel.ff_xor, aa, bb, &wt, rows.p_ff);
            self.emit_xor(sel.ff_xor, &SlotRef::view(&wt), cc, &pools.ff.at(rows.p_ff), rows.p_ff);

            let wu = pools.xor_tmp_b.at(rows.p_gg);
            self.set_word(&wu, e ^ f);
            self.emit_xor(sel.gg_xor, ee, ffx, &wu, rows.p_gg);
            self.emit_xor(sel.gg_xor, &SlotRef::view(&wu), ggx, &pools.gg.at(rows.p_gg), rows.p_gg);
        }

        // TT1 / TT2
        let w_ff = pools.ff.at(rows.p_ff);
        let w_gg = pools.gg.at(rows.p_gg);
        let w_ss2 = pools.ss2.at(rows.p_ss2);
        self.emit_add(
            sel.tt1,
            &[
                self.lin_slot(&SlotRef::view(&w_ff), rows.p_tt1),
                self.lin_slot(dd, rows.p_tt1),
                self.lin_slot(&SlotRef::view(&w_ss2), rows.p_tt1),
                self.lin_slot(&SlotRef::view(wpj.0), rows.p_tt1),
            ],
            &w_tt1,
            cp,
            rows.p_tt1,
        );
        self.emit_add(
            sel.tt2,
            &[
                self.lin_slot(&SlotRef::view(&w_gg), rows.p_tt2),
                self.lin_slot(hh, rows.p_tt2),
                self.lin_rotl(&w_ss1pre, 7, rows.p_tt2),
                self.lin_slot(&SlotRef::view(wj.0), rows.p_tt2),
            ],
            &w_tt2,
            cp,
            rows.p_tt2,
        );

        // 见证（数值全部来自 rv）
        self.set_word(&w_ss1pre, rv.ss1pre);
        self.set_word(&w_tt1, rv.t1);
        self.set_word(&w_tt2, rv.t2);
        for i in 0..32 {
            self.set_cell_u32(pools.ss2.bits[i], rows.p_ss2, (rv.ss2 >> i) & 1);
            self.set_cell_u32(pools.ff.bits[i], rows.p_ff, (rv.ffv >> i) & 1);
            self.set_cell_u32(pools.gg.bits[i], rows.p_gg, (rv.ggv >> i) & 1);
        }
        // 勘误 #15：SS1PRE = rotl12(a)+e+T_j —— carry 的被加数必须是 rotl12 后的 a，
        // 否则凡两种进位不同的轮（实测 "abc" 块恰 20 轮）主方程必差 ±2^32。
        self.set_carries(
            cp,
            rows.p_ss1pre,
            ((a.rotate_left(12) as u64 + e as u64 + tj as u64) >> 32) as u32,
        );
        self.set_carries(
            cp,
            rows.p_tt1,
            ((rv.ffv as u64 + d as u64 + rv.ss2 as u64 + wpj.1 as u64) >> 32) as u32,
        );
        self.set_carries(
            cp,
            rows.p_tt2,
            ((rv.ggv as u64 + h as u64 + rv.ss1 as u64 + wj.1 as u64) >> 32) as u32,
        );

        RoundWords { ss1pre: w_ss1pre, tt1: w_tt1, tt2: w_tt2 }
    }

    /// 发射消息扩展一步（16 ≤ j < 68）：
    ///   m1 = W[j−16] ⊕ W[j−9]；x = m1 ⊕ rotl15(W[j−3])；
    ///   P1(x) = x ⊕ rotl15(x) ⊕ rotl23(x)；m3 = P1(x) ⊕ rotl7(W[j−13])；
    ///   W[j] = m3 ⊕ W[j−6]。
    /// 结果**直接写入 `pools.w` 表块 j/off7**（单一真相）；四个中间量各占
    /// 独立列池，禁混叠。
    pub fn emit_extension(
        &mut self,
        sel: &SelSet,
        rows: &BlockRows,
        j: usize,
        pools: &ExtPools,
        wprev: &[u32; NUM_BLOCKS],
    ) -> u32 {
        let w16v = wprev[j - 16];
        let w9v = wprev[j - 9];
        let w3v = wprev[j - 3];
        let w13v = wprev[j - 13];
        let w6v = wprev[j - 6];

        let m1v = w16v ^ w9v;
        let xv = m1v ^ w3v.rotate_left(15);
        let tv = xv ^ xv.rotate_left(15); // P1 前半
        let p1v = tv ^ xv.rotate_left(23);
        let m3v = p1v ^ w13v.rotate_left(7);
        let wjv = m3v ^ w6v;

        let wx16 = pools.w.at(row_of(j - 16, off::W));
        let wx9 = pools.w.at(row_of(j - 9, off::W));
        let wx3 = pools.w.at(row_of(j - 3, off::W));
        let wx13 = pools.w.at(row_of(j - 13, off::W));
        let wx6 = pools.w.at(row_of(j - 6, off::W));

        let hx = pools.x.at(rows.p_xtmp);
        let ht = pools.t.at(rows.p_xtmp);
        let hp1 = pools.p1.at(rows.p_xtmp);
        let hm1 = pools.m1.at(rows.p_xtmp);
        let hm3 = pools.m3.at(rows.p_xtmp);
        let hwj = pools.w.at(rows.p_w);

        self.emit_xor(sel.ext_m1, &SlotRef::view(&wx16), &SlotRef::view(&wx9), &hm1, rows.p_xtmp);
        self.emit_xor(sel.ext_m2, &SlotRef::view(&hm1), &SlotRef::rotl(&wx3, 15), &hx, rows.p_xtmp);
        self.emit_xor(sel.ext_t, &SlotRef::view(&hx), &SlotRef::rotl(&hx, 15), &ht, rows.p_xtmp);
        self.emit_xor(sel.ext_p1, &SlotRef::view(&ht), &SlotRef::rotl(&hx, 23), &hp1, rows.p_xtmp);
        self.emit_xor(sel.ext_m3, &SlotRef::view(&hp1), &SlotRef::rotl(&wx13, 7), &hm3, rows.p_xtmp);
        self.emit_xor(sel.ext_w, &SlotRef::view(&hm3), &SlotRef::view(&wx6), &hwj, rows.p_w);

        // 见证（每个池只写一次：m1/x/t/p1/m3 与结果 W[j]）
        self.set_word(&hm1, m1v);
        self.set_word(&hx, xv);
        self.set_word(&ht, tv);
        self.set_word(&hp1, p1v);
        self.set_word(&hm3, m3v);
        self.set_word(&hwj, wjv);
        wjv
    }

    /// 发射并约束 W'[j] = W[j] ⊕ W[j+4]，随附见证。**全部 j∈0..NUM_ROUNDS**
    /// 都必须走这里（勘误 #10：W'[0..16] 若只写见证不约束 → TT1 可被伪造，
    /// 不健全）。前提：两源块 j、j+4 均在表内（≤67），因此 j ≤ 63 恰好封闭。
    pub fn emit_wp(&mut self, sel_wp: usize, j: usize, pools: &ExtPools, wpv: u32) {
        let wa = pools.w.at(row_of(j, off::W));
        let wb = pools.w.at(row_of(j + 4, off::W));
        let hw = pools.wp.at(row_of(j, off::WP));
        let at = row_of(j, off::WP);
        self.emit_xor(sel_wp, &SlotRef::view(&wa), &SlotRef::view(&wb), &hw, at);
        self.set_word(&hw, wpv);
    }
}

/// 一轮内部工作词的列池（列跨 68 块复用；家点每轮换）。
#[derive(Clone, Copy, Debug)]
pub struct RoundPools {
    pub ss1pre: WordCols,
    pub ss2: WordCols,
    pub ff: WordCols,
    pub gg: WordCols,
    pub tt1: WordCols,
    pub tt2: WordCols,
    pub xor_tmp_a: WordCols,
    pub xor_tmp_b: WordCols,
}

/// 扩展区列池。**单一 W 表语义**（勘误 #8）：扩展门 j 的输出直接写进
/// `w` 池在块 j/off7 的格——未来轮与后续扩展读到的就是这份被约束的值；
/// 不允许另设"结果表"造成读写两份真相。
#[derive(Clone, Copy, Debug)]
pub struct ExtPools {
    /// W 全表（W[0..16] 为见证自由变量，即公开语句的消息字）—— 家点 off7
    pub w: WordCols,
    /// W'[j] = W[j] ⊕ W[j+4]，全部 j∈0..64 均受约束 —— 家点 off8
    pub wp: WordCols,
    pub m1: WordCols,
    pub x: WordCols,
    pub t: WordCols,
    pub p1: WordCols,
    /// m3 = P1(x) ⊕ rotl7(W[j−13]) 的专用存储。不可混叠回 m1/x/t 任一池
    /// （勘误 #9：同行的既有量仍被各自门选择器钉住，二次覆写同一格必然违约）。
    pub m3: WordCols,
}

/// 链值物理存储池：TT1/PNXT 两族列跨**全有符号轮号** t∈−4..63 使用。
/// 负号区（勘误 #13 的"虚拟轮"）不另设列——直接把初始化常量写进同一对
/// 池列在延续秩点（[`signed_row`]）的格子。这样边界轮与稳态轮的每个约束
/// 实例读完全相同的列集合、相同的旋转差 —— 共享选择器家族全局求值时
/// 读到的都是"滑动窗口故事"，健全性成立的关键结构。
#[derive(Clone, Copy, Debug)]
pub struct ChainPools {
    pub tt1: WordCols,
    pub pnxt: WordCols,
}

impl ChainPools {
    /// 有符号轮 t 的 TT1 链词句柄（家点秩 = RANK_BASE + 9t + [`off::TT1`]，全域同式）。
    pub fn t1_at(&self, t: i64) -> WordHandle {
        WordHandle {
            bits: self.tt1.bits,
            val: self.tt1.val,
            home: signed_row(t, off::TT1),
        }
    }
    /// 有符号轮 t 的 PNXT 链词句柄（家点秩 = RANK_BASE + 9t + [`off::TT2`]）。
    pub fn pnxt_at(&self, t: i64) -> WordHandle {
        WordHandle {
            bits: self.pnxt.bits,
            val: self.pnxt.val,
            home: signed_row(t, off::TT2),
        }
    }
}

/// 虚拟轮存储值的唯一真值表：下标 k 对应有符号轮 t=k−4（见 [`NUM_VIRT`]），
/// 存储值 = 把 TT1/PNXT 链向前延伸到负轮后的寄存词。推导（并用多组交叉
/// 消费关系验证自洽）：稳态字母公式 a=T1⟨t⟩、c=rotl9(T1⟨t⟩) 等对边界轮
/// 同样成立，只要
///   TT1 族: t=−1→IV0, −2→IV1, −3→rotr9(IV2), −4→rotr9(IV3)
///   PNXT 族: t=−1→IV4, −2→IV5, −3→rotr19(IV6), −4→rotr19(IV7)
/// 例：c₀ 真值 = IV2（装入态无旋转历史），公式给 rotl9(cell(t=−3))
/// ⇒ cell=rotr9(IV2)；d₁ 真值同样是 IV2 且消费同一格 —— 需求重合而非冲突。
pub fn vir_values() -> ([u32; 4], [u32; 4]) {
    let r9 = |x: u32| x.rotate_right(9);
    let r19 = |x: u32| x.rotate_right(19);
    let iv = crate::sm3_native_ref::IV;
    (
        [r9(iv[3]), r9(iv[2]), iv[1], iv[0]],
        [r19(iv[7]), r19(iv[6]), iv[5], iv[4]],
    )
}

// ───────────────────────── 全压缩装配器 ─────────────────────────

// （占位注释行，保持区域分隔；slot_sources 死代码已删除——滞后映射的唯一权威
//   实现是下方 reg_slots_for_round。）

/// 单轮数值真值。电路侧所有见证（轮中间量、PNXT、输出）都必须由此取数，
/// 禁止在装配代码里二次推导同一量（勘误 #11：装配期多份手写同构循环是漂移温床）。
#[derive(Clone, Copy)]
pub struct RoundVals {
    /// 进入本轮的八字。
    pub ins: [u32; 8],
    pub ss1pre: u32,
    #[allow(dead_code)]
    pub ss1: u32,
    pub ss2: u32,
    pub ffv: u32,
    pub ggv: u32,
    pub t1: u32,
    pub t2: u32,
    /// 更新后的状态：(T1, A, rotl9(B), C, P0(T2), E, rotl19(F), G)。
    nxt: [u32; 8],
}

/// 单轮数值真值计算（v1/v2 装配器共用的唯一真相源）。
pub fn compute_round_vals(j: usize, st: &[u32; 8], wj: u32, wpj: u32) -> RoundVals {
    let (a, b, c, d, e, f, g, h) = (st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]);
    let tj = tj_value(j);
    let ss1pre = a.rotate_left(12).wrapping_add(e).wrapping_add(tj);
    let ss1 = ss1pre.rotate_left(7);
    let ss2 = ss1 ^ a.rotate_left(12);
    let ffv = if j < 16 { a ^ b ^ c } else { (a & b) | (a & c) | (b & c) };
    let ggv = if j < 16 { e ^ f ^ g } else { (e & f) | (!e & g) };
    let t1 = ffv.wrapping_add(d).wrapping_add(ss2).wrapping_add(wpj);
    let t2 = ggv.wrapping_add(h).wrapping_add(ss1).wrapping_add(wj);
    RoundVals {
        ins: *st,
        ss1pre,
        ss1,
        ss2,
        ffv,
        ggv,
        t1,
        t2,
        nxt: [
            t1,
            a,
            b.rotate_left(9),
            c,
            crate::sm3_native_ref::p0(t2),
            e,
            f.rotate_left(19),
            g,
        ],
    }
}

/// 装配完整 SM3 单块压缩电路：8 实例 = V'(k) = 状态k ⊕ IV[k]。
/// witness 数值完全原生推导；GB/T 锚定由调用方向量测试承担。
pub fn build_compress(block64: &[u8; 64]) -> Sm3CompressCircuit<FpSM2Type> {
    type Fr_ = FpSM2Type;

    // ---- 数值预演：W 表与每轮真值统一出自 compute_round_vals（唯一真值源）----
    let (w_all, wp_all) = {
        let mut wtmp = [0u32; NUM_BLOCKS];
        for jj in 0..16 {
            wtmp[jj] = u32::from_be_bytes([
                block64[4 * jj],
                block64[4 * jj + 1],
                block64[4 * jj + 2],
                block64[4 * jj + 3],
            ]);
        }
        for jj in 16..NUM_BLOCKS {
            let xx = wtmp[jj - 16] ^ wtmp[jj - 9] ^ wtmp[jj - 3].rotate_left(15);
            let p1x = xx ^ xx.rotate_left(15) ^ xx.rotate_left(23);
            wtmp[jj] = p1x ^ wtmp[jj - 13].rotate_left(7) ^ wtmp[jj - 6];
        }
        let wptmp: Vec<u32> = (0..NUM_ROUNDS).map(|jj| wtmp[jj] ^ wtmp[jj + 4]).collect();
        (wtmp, wptmp)
    };

    let mut st = crate::sm3_native_ref::IV;
    let mut rvs: Vec<RoundVals> = Vec::with_capacity(NUM_ROUNDS);
    for j in 0..NUM_ROUNDS {
        let v = compute_round_vals(j, &st, w_all[j], wp_all[j]);
        rvs.push(v);
        st = v.nxt;
    }
    let final_state = st;

    // ---- 布局 ----
    let mut bld = Builder::<Fr_>::new(8);
    let round_pools = RoundPools {
        ss1pre: bld.alloc_word_cols(true),
        ss2: bld.alloc_word_cols(false),
        ff: bld.alloc_word_cols(false),
        gg: bld.alloc_word_cols(false),
        tt1: bld.alloc_word_cols(true),
        tt2: bld.alloc_word_cols(true),
        xor_tmp_a: bld.alloc_word_cols(false),
        xor_tmp_b: bld.alloc_word_cols(false),
    };
    let ext_pools = ExtPools {
        w: bld.alloc_word_cols(false),
        wp: bld.alloc_word_cols(false),
        m1: bld.alloc_word_cols(false),
        x: bld.alloc_word_cols(false),
        t: bld.alloc_word_cols(false),
        p1: bld.alloc_word_cols(false),
        m3: bld.alloc_word_cols(false),
    };
    // PNXT 家点复用块 off6 行（同点异列族）；half 为 P0 第一连 XOR 的中间量
    let pnxt_cols = bld.alloc_word_cols(false);
    let half_pool = bld.alloc_word_cols(false);
    let chain = ChainPools {
        tt1: round_pools.tt1,
        pnxt: pnxt_cols,
    };

    let o_val = bld.alloc_col(); // 单值列即可：8 个输出共用一列不同点
    let cp = bld.alloc_carries();

    // T_j 预处理多项式（勘误 #14）：多项式按**点值**索引 —— 第 j 轮常数必须
    // 写在该轮 off1 行的点值上（0..64 的朴素下标是错的）。必须先于任何
    // 约束发射分配（它决定 advice 全局基址）。
    let mut tj_vals = vec![<Fr_ as From<u64>>::from(0u64); ROWS];
    for j in 0..NUM_ROUNDS {
        tj_vals[row_of(j, off::SS1PRE)] = <Fr_ as From<u64>>::from(tj_value(j) as u64);
    }
    let tj_prep = bld.alloc_const_poly(tj_vals);

    let sel = SelSet {
        ss1pre: bld.alloc_selector(&[]),
        tj_prep,
        ss2: bld.alloc_selector(&[]),
        ff_maj: bld.alloc_selector(&[]),
        ff_xor: bld.alloc_selector(&[]),
        gg_choose: bld.alloc_selector(&[]),
        gg_xor: bld.alloc_selector(&[]),
        tt1: bld.alloc_selector(&[]),
        tt2: bld.alloc_selector(&[]),
        ext_m1: bld.alloc_selector(&[]),
        ext_m2: bld.alloc_selector(&[]),
        ext_t: bld.alloc_selector(&[]),
        ext_p1: bld.alloc_selector(&[]),
        ext_m3: bld.alloc_selector(&[]),
        ext_w: bld.alloc_selector(&[]),
        wp_xor: bld.alloc_selector(&[]),
        pnxt: bld.alloc_selector(&[]),
    };
    // 输出绑定：每个字母一个私有选择器（激活点 = row_mapping()[k]），
    // 分配必须留在布局段（第一条约束发射后 alloc 会 panic）。
    let out_sels: [usize; 8] = std::array::from_fn(|_| bld.alloc_selector(&[]));

    // ---- 虚拟轮初始化：把链值前延常量写进**链值池列**在延续秩点的格子，
    //      并用专用选择器钉住（约束侧勘误 #13：无绑定则初态可伪造）。列复用
    //      是全局健全性的核心——边界轮与稳态轮的约束实例因此读同一组列。
    //      随后 W[0..16] 直拷（语句自由变量，受约性由摘要链间接成立）。----
    let iv_words = crate::sm3_native_ref::IV;
    let (vt1v, vpv) = vir_values();
    // 先分配全部 8 个选择器（emit 一旦发生布局即冻结，禁止再 alloc），再统一发射
    let mut vir_sels = [0usize; 8];
    for vs in vir_sels.iter_mut() {
        *vs = bld.alloc_selector(&[]);
    }
    for k in 0..4i64 {
        let t = k - 4;
        let h_t1 = chain.t1_at(t);
        bld.extend_selector(vir_sels[k as usize], &[h_t1.home]);
        bld.emit_const_word_bits(vir_sels[k as usize], &h_t1, vt1v[k as usize]);
        bld.set_word(&h_t1, vt1v[k as usize]);

        let h_pn = chain.pnxt_at(t);
        bld.extend_selector(vir_sels[4 + k as usize], &[h_pn.home]);
        bld.emit_const_word_bits(vir_sels[4 + k as usize], &h_pn, vpv[k as usize]);
        bld.set_word(&h_pn, vpv[k as usize]);
    }
    for j in 0..16 {
        let h = ext_pools.w.at(row_of(j, off::W));
        bld.set_word(&h, w_all[j]);
    }

    // ---- 第一遍：64 轮。每轮 = 轮电路 + PNXT 两连 XOR（存于块 off6 同点异列）。
    //      数值一律读 rvs[j]，装配零重推导。----
    let mut rounds: Vec<Option<RoundWords>> = vec![None; NUM_ROUNDS];

    for j in 0..NUM_ROUNDS {
        let rows = BlockRows::new(j);
        let rvj = rvs[j];

        let slots_ref = reg_slots_for_round(j, &chain);

        bld.extend_selector(sel.ss1pre, &[rows.p_ss1pre]);
        bld.extend_selector(sel.ss2, &[rows.p_ss2]);
        if j >= 16 {
            bld.extend_selector(sel.ff_maj, &[rows.p_ff]);
            bld.extend_selector(sel.gg_choose, &[rows.p_gg]);
        } else {
            bld.extend_selector(sel.ff_xor, &[rows.p_ff]);
            bld.extend_selector(sel.gg_xor, &[rows.p_gg]);
        }
        bld.extend_selector(sel.tt1, &[rows.p_tt1]);
        bld.extend_selector(sel.tt2, &[rows.p_tt2]);

        let rw = bld.emit_round(
            &sel,
            &rows,
            j,
            &cp,
            &slots_ref,
            &rvj,
            (&ext_pools.w.at(rows.p_w), w_all[j]),
            (&ext_pools.wp.at(rows.p_wp), wp_all[j]),
            &round_pools,
        );
        rounds[j] = Some(rw);

        // e'_{j+1} = P0(TT2_j)：half = TT2 ⊕ rotl9(TT2)，PNXT = half ⊕ rotl17(TT2)。
        // 物理位置 = 块 j 的 **off::TT2 行**（与 TT2 词同点异列）——链值读取统一走
        // `chain.pnxt.at(r.tt2.home)`，两处必须同点（勘误 #12：此前误写 off0，
        // 读写出位、从第 2 轮起全链错读）。
        bld.extend_selector(sel.pnxt, &[rows.p_tt2]);
        let tt2_h = rw.tt2;
        let hhalf = half_pool.at(rows.p_tt2);
        let hout = chain.pnxt.at(rows.p_tt2);
        bld.emit_xor(
            sel.pnxt,
            &SlotRef::view(&tt2_h),
            &SlotRef::rotl(&tt2_h, 9),
            &hhalf,
            rows.p_tt2,
        );
        bld.emit_xor(
            sel.pnxt,
            &SlotRef::view(&hhalf),
            &SlotRef::rotl(&tt2_h, 17),
            &hout,
            rows.p_tt2,
        );
        bld.set_word(&hhalf, rvj.t2 ^ rvj.t2.rotate_left(9));
        bld.set_word(&hout, crate::sm3_native_ref::p0(rvj.t2));
    }

    // ---- 第二遍：消息扩展 W[16..68] 与全部 W'[0..64]。约束完备性关键：
    //      W' 必须覆盖所有轮索引——若只覆盖 j≥16，则前 16 个 TT1 的输入可被
    //      任意伪造（勘误 #10）。本遍只发约束与扩展见证，不触碰布局分配。----
    for j in 0..NUM_BLOCKS {
        if j >= 16 {
            let rows = BlockRows::new(j);
            bld.extend_selector(sel.ext_m1, &[rows.p_xtmp]);
            bld.extend_selector(sel.ext_m2, &[rows.p_xtmp]);
            bld.extend_selector(sel.ext_t, &[rows.p_xtmp]);
            bld.extend_selector(sel.ext_p1, &[rows.p_xtmp]);
            bld.extend_selector(sel.ext_m3, &[rows.p_xtmp]);
            bld.extend_selector(sel.ext_w, &[rows.p_w]);
            bld.emit_extension(&sel, &rows, j, &ext_pools, &w_all);
        }
        if j < NUM_ROUNDS {
            bld.extend_selector(sel.wp_xor, &[row_of(j, off::WP)]);
            bld.emit_wp(sel.wp_xor, j, &ext_pools, wp_all[j]);
        }
    }

    // ---- 输出绑定：V'[k] = 状态[k] ⊕ IV[k]，inst 行 = row_mapping()[k]。
    //      每字母独立选择器（滞后深度 1..4 不同 ⇒ 行→源秩差不共享）。----
    for k in 0..8 {
        let pt = row_mapping()[k];
        bld.extend_selector(out_sels[k], &[pt]);
        let slot = output_letter_slot(k, &rounds, &chain);
        let want = final_state[k] ^ iv_words[k];
        bld.emit_feedforward_pair(out_sels[k], &slot, iv_words[k], o_val, pt, k);
        bld.set_cell_u32(o_val, pt, want);
        bld.set_instance(k, <Fr_ as From<u64>>::from(want as u64));
    }

    let meta = CircuitMeta {
        round_pools,
        ext_pools,
        pnxt: pnxt_cols,
        half: half_pool,
        o_val,
        carries: cp,
    };
    bld.finalize(meta)
}

/// 第 k 个输出字母的物理源槽（依滞后展开回到 TT1/PNXT 池；深度必足——最后
/// 一轮的字母滞后 ≤4 < 64）。旋转与 reg_slots_for_round 同一映射。
fn output_letter_slot(
    k: usize,
    rounds: &[Option<RoundWords>],
    chain: &ChainPools,
) -> SlotRef {
    let r = |lag: usize| -> &RoundWords {
        rounds[NUM_ROUNDS - lag].as_ref().expect("前置轮必已装配")
    };
    match k {
        0 => SlotRef::view(&r(1).tt1),
        1 => SlotRef::view(&r(2).tt1),
        2 => SlotRef::rotl(&r(3).tt1, 9),
        3 => SlotRef::rotl(&r(4).tt1, 9),
        4 => SlotRef::view(&chain.pnxt.at(r(1).tt2.home)),
        5 => SlotRef::view(&chain.pnxt.at(r(2).tt2.home)),
        6 => SlotRef::rotl(&chain.pnxt.at(r(3).tt2.home), 19),
        _ => SlotRef::rotl(&chain.pnxt.at(r(4).tt2.home), 19),
    }
}

/// 各轮字母槽构建（列流；数值由调用方持有的 [`RoundVals`] 承担，此处只管物理视图）。
///
/// 滞后映射（勘误 #7，推导见模块头更新规则）：
///   a_j=T1_{j−1}, b_j=T1_{j−2}, c_j=rotl9(T1_{j−3}), d_j=rotl9(T1_{j−4}),
///   e_j=PNXT_{j−1}, f_j=PNXT_{j−2}, g_j=rotl19(PNXT_{j−3}), h_j=rotl19(PNXT_{j−4})
/// 有符号轮号 t=j−lag 覆盖负号虚拟轮域：[`ChainPools`] 对全部 t 用同一对
/// 池列 + 同一线性家点公式，故字母槽的「行→源」列集合与旋转差对所有
/// 激活行恒定 —— 共享选择器家族全局求值健全的结构前提（勘误 #13）。
fn reg_slots_for_round(j: usize, chain: &ChainPools) -> [SlotRef; 8] {
    let letter = |idx: usize| -> SlotRef {
        let lag = match idx {
            0 | 4 => 1,
            1 | 5 => 2,
            2 | 6 => 3,
            _ => 4,
        };
        let t = j as i64 - lag as i64;
        if idx < 4 {
            let h = chain.t1_at(t);
            match idx {
                2 | 3 => SlotRef::rotl(&h, 9),
                _ => SlotRef::view(&h),
            }
        } else {
            let h = chain.pnxt_at(t);
            match idx {
                6 | 7 => SlotRef::rotl(&h, 19),
                _ => SlotRef::view(&h),
            }
        }
    };
    std::array::from_fn(letter)
}

/// PNXT 的第一连 XOR 中间量列组由 build_compress 局部分配（`half_pool`），
/// 不再使用任何静态注册/桩函数。

// 别名，避免泛型字段名扩散
type FpSM2Type = crate::FpSM2;

// ───────────────────────── 电路对象与 mock-prover ─────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Violation {
    pub constraint: usize,
    pub point: usize,
}

/// 列池/选择器的电路内句柄出口：测试定位篡改点、b4 计时读取证词所用。
/// 负号虚拟轮无独立列——用 [`ChainPools`] 句柄 + [`signed_row`] 负号寻址即可。
#[derive(Clone, Copy, Debug)]
pub struct CircuitMeta {
    pub round_pools: RoundPools,
    pub ext_pools: ExtPools,
    pub pnxt: WordCols,
    pub half: WordCols,
    pub o_val: usize,
    /// 共享 2 位 carry 对（b0/b1）。
    pub carries: CarryPair,
}

#[derive(Clone, Debug)]
pub struct Sm3CompressCircuit<F: PrimeField> {
    pub info: PlonkishCircuitInfo<F>,
    pub advice: Vec<Vec<F>>,
    pub instances: Vec<Vec<F>>,
    pub tags: Vec<(&'static str, usize)>,
    /// 与 info.constraints 平行的家族标签。
    pub ctags: Vec<&'static str>,
    pub num_selectors: usize,
    pub meta: CircuitMeta,
}

impl<F: PrimeField> Sm3CompressCircuit<F> {
    pub fn read_word_bits(&self, h: &WordHandle) -> u32 {
        let pt = h.home;
        let mut out = 0u32;
        for i in 0..32 {
            if self.advice[h.bits[i]][pt] == F::ONE {
                out |= 1 << i;
            }
        }
        out
    }
}

impl<F: PrimeField> PlonkishCircuit<F> for Sm3CompressCircuit<F> {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<F>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<F>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<F>] {
        &self.instances
    }
    fn synthesize(&self, round: usize, challenges: &[F]) -> Result<Vec<Vec<F>>, Error> {
        assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
        Ok(self.advice.clone())
    }
}

/// mock-prover（部件版）：对任意 `(info, advice, instances)` 三元组逐点求值全部
/// 约束。管线化 v2 电路与 v1 共用；注意它**只覆盖位级约束** —— 复制环的
/// 积论证等式在真实协议中由证明方/验证方执行（见 sm3_perm_smoke 的负例）。
///
/// 实现注记：v2 全电路 ~6 万约束 × 2048 点，单线程要十几分钟 —— 按约束分片
/// 多线程求值（各点独立、结果顺序仍按约束号升序拼接，语义与单线程扫描一致）。
pub fn check_parts_violations<F: PrimeField + Sync>(
    info: &PlonkishCircuitInfo<F>,
    advice: &[Vec<F>],
    instances: &[Vec<F>],
) -> Vec<Violation> {
    let cube = bh();
    let np = info.preprocess_polys.len();

    let mut inst_at = vec![F::ZERO; ROWS];
    for (ordinal, v) in instances.iter().flat_map(|c| c.iter()).enumerate() {
        inst_at[row_mapping()[ordinal]] = *v;
    }
    let resolve = |poly_idx: usize, point: usize| -> F {
        if poly_idx == 0 {
            inst_at[point]
        } else if poly_idx <= np {
            info.preprocess_polys[poly_idx - 1][point]
        } else {
            advice[poly_idx - 1 - np][point]
        }
    };

    let cons = &info.constraints;
    let n = cons.len();
    // resolve 按共享引用进入各线程（闭包本体不可 Copy，不能逐线程 move）。
    let resolver = &resolve;
    let nt = std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
        .min(n)
        .max(1);
    let chunk = n.div_ceil(nt);
    let parts: Vec<Vec<Violation>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..nt)
            .map(|t| {
                let lo = t * chunk;
                let hi = ((t + 1) * chunk).min(n);
                scope.spawn(move || {
                    let mut local = Vec::new();
                    for ci in lo..hi {
                        let expr = &cons[ci];
                        for point in cube.iter() {
                            let val = expr.evaluate(
                                &|c| c,
                                &|_| panic!("mock-prover 未用到 CommonPolynomial"),
                                &|q| resolver(q.poly(), cube.rotate(point, q.rotation())),
                                &|_| panic!("单相电路无挑战"),
                                &|v| -v,
                                &|a, b| a + b,
                                &|a, b| a * b,
                                &|v, s| v * s,
                            );
                            if val != F::ZERO {
                                local.push(Violation { constraint: ci, point });
                            }
                        }
                    }
                    local
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mock 求值线程崩溃"))
            .collect()
    });
    parts.into_iter().flatten().collect()
}

/// 子集求值防线（T3/T4 扫描件）：只对 `subset` 列出的约束索引求全部点。
/// 语义与 [`check_parts_violations`] 的对应切片完全一致（同一 resolve/求值
/// 闭包），供"篡改面只影响已知约束子集"的扫描用例把全量求值降为子集求值。
pub fn check_subset_violations<F: PrimeField + Sync>(
    info: &PlonkishCircuitInfo<F>,
    advice: &[Vec<F>],
    instances: &[Vec<F>],
    subset: &[usize],
) -> Vec<Violation> {
    let cube = bh();
    let np = info.preprocess_polys.len();

    let mut inst_at = vec![F::ZERO; ROWS];
    for (ordinal, v) in instances.iter().flat_map(|c| c.iter()).enumerate() {
        inst_at[row_mapping()[ordinal]] = *v;
    }
    let resolve = |poly_idx: usize, point: usize| -> F {
        if poly_idx == 0 {
            inst_at[point]
        } else if poly_idx <= np {
            info.preprocess_polys[poly_idx - 1][point]
        } else {
            advice[poly_idx - 1 - np][point]
        }
    };

    let cons = &info.constraints;
    let nt = std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
        .min(subset.len())
        .max(1);
    let chunk = subset.len().div_ceil(nt);
    let parts: Vec<Vec<Violation>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..nt)
            .map(|t| {
                let lo = (t * chunk).min(subset.len());
                let hi = ((t + 1) * chunk).min(subset.len());
                scope.spawn(move || {
                    let mut local = Vec::new();
                    for &ci in &subset[lo..hi] {
                        let expr = &cons[ci];
                        for point in cube.iter() {
                            let val = expr.evaluate(
                                &|c| c,
                                &|_| panic!("mock-prover 未用到 CommonPolynomial"),
                                &|q| resolve(q.poly(), cube.rotate(point, q.rotation())),
                                &|_| panic!("单相电路无挑战"),
                                &|v| -v,
                                &|a, b| a + b,
                                &|a, b| a * b,
                                &|v, s| v * s,
                            );
                            if val != F::ZERO {
                                local.push(Violation { constraint: ci, point });
                            }
                        }
                    }
                    local
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mock 子集求值线程崩溃"))
            .collect()
    });
    parts.into_iter().flatten().collect()
}

/// mock-prover（v1 电路便捷壳）。
pub fn check_violations<F: PrimeField>(circ: &Sm3CompressCircuit<F>) -> Vec<Violation> {
    check_parts_violations(&circ.info, &circ.advice, &circ.instances)
}

/// 环取值一致性审计（簇E 诊断器，1.1c）：mock 层**不覆盖**的置换论证在装配层
/// 的前置自检 —— 逐环取成员格值判等。返回「存在不等值的环」清单：
/// `(环号, [每组 "值 ×出现次数"])`。积论证闭合失败（prover grand-product
/// sanity assert）时第一个该看这里。
pub fn audit_ring_values<F>(
    info: &PlonkishCircuitInfo<F>,
    advice: &[Vec<F>],
) -> Vec<(usize, Vec<String>)>
where
    F: PrimeField + std::fmt::Debug,
{
    let np = info.preprocess_polys.len();
    let mut bad = Vec::new();
    for (rid, cyc) in info.permutations.iter().enumerate() {
        if cyc.len() < 2 {
            continue;
        }
        let vals: Vec<(F, usize, usize)> = cyc
            .iter()
            .map(|&(p, pt)| {
                debug_assert!(p > np, "环只应含 advice 多项式");
                (advice[p - 1 - np][pt], p - 1 - np, pt)
            })
            .collect();
        let first = vals[0].0;
        if vals.iter().any(|(v, _, _)| *v != first) {
            use std::collections::BTreeMap;
            let mut grp: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (v, col, pt) in &vals {
                grp.entry(format!("{v:?}"))
                    .or_default()
                    .push(format!("adv{col}@pt{pt}"));
            }
            bad.push((
                rid,
                grp.into_iter()
                    .map(|(v, cs)| {
                        // 坐标全打（环长 ≤258，坏环通常 ≤3 条；长环只显示首尾各 4）
                        let shown: Vec<String> = if cs.len() <= 10 {
                            cs.clone()
                        } else {
                            [cs[..4].as_ref(), cs[cs.len() - 4..].as_ref()].concat()
                        };
                        format!("{}×{} [{}]", v, cs.len(), shown.join(", "))
                    })
                    .collect(),
            ));
        }
    }
    bad
}

// ───────────────────────── 测试（b3：全压缩装配器） ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    type Fr = crate::FpSM2;
    use crate::FpSM2;
    use ff::Field;

    /// 把消息填成单个 padding 块（长度 < 56 字节时与 native_ref::hash 的内块一致）。
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

    /// 正例主锚点："abc" 的单块压缩，实例 = 原生参照实现逐字对拍，
    /// mock-prover 零违约。
    #[test]
    fn compress_abc_end_to_end_matches_native() {
        let blk = one_block(b"abc");
        // 注意：native_ref::compress 的返回值已经过 a^v[k] 折叠，即摘要字本身
        // （实例语句正是"输出第 k 个摘要字"，不再叠加 IV）。
        let expect = crate::sm3_native_ref::compress(&crate::sm3_native_ref::IV, &blk);

        let circ = build_compress(&blk);
        assert_eq!(circ.instances[0].len(), 8);
        for k in 0..8 {
            let want = <Fr as From<u64>>::from(expect[k] as u64);
            assert_eq!(circ.instances[0][k], want, "实例 {k} 与原生参照不一致");
        }

        println!(
            "[b3-tally] constraints={} advice_cols={} selectors={} k={K}",
            circ.info.constraints.len(),
            circ.advice.len(),
            circ.num_selectors
        );

        let bad = check_violations(&circ);
        if !bad.is_empty() {
            use std::collections::BTreeMap;
            let mut hist: BTreeMap<&str, usize> = BTreeMap::new();
            for v in &bad {
                *hist.entry(circ.ctags[v.constraint]).or_insert(0) += 1;
            }
            // 秩几何解码：点值→LFSR 秩（用于定位违规行落在窗口哪个块/偏移）
            let inv = rank_inverse();
            let mut pt2rk = vec![usize::MAX; ROWS];
            for (rk, &p) in inv.iter().enumerate() {
                if p < ROWS {
                    pt2rk[p] = rk;
                }
            }
            let decode = |pt: usize| -> String {
                let rk = pt2rk[pt];
                if rk >= RANK_BASE && rk < RANK_BASE + NUM_BLOCKS * ROWS_PER_BLOCK {
                    let t = rk - RANK_BASE;
                    format!("pt{pt}=blk{}off{}", t / ROWS_PER_BLOCK, t % ROWS_PER_BLOCK)
                } else {
                    format!("pt{pt}=rk{rk}")
                }
            };
            let first12: Vec<String> = bad
                .iter()
                .take(12)
                .map(|v| {
                    format!(
                        "#{} {} {}",
                        v.constraint,
                        circ.ctags[v.constraint],
                        decode(v.point)
                    )
                })
                .collect();
            // 深挖：最小违约约束的全部命中点（秩解码）
            let cmin = bad.iter().map(|v| v.constraint).min().unwrap();
            let pts_cmin: Vec<usize> = bad
                .iter()
                .filter(|v| v.constraint == cmin)
                .map(|v| v.point)
                .collect();
            let mut ranks_cmin: Vec<usize> =
                pts_cmin.iter().map(|&p| pt2rk[p]).collect();
            ranks_cmin.sort_unstable();
            println!(
                "[deepdump] 最小违约约束 #{cmin} (tag={}) 命中 {n} 点，秩 = {ranks_cmin:?}",
                circ.ctags[cmin],
                n = pts_cmin.len()
            );
            // 各约束族分布
            let mut by_cons: BTreeMap<usize, usize> = BTreeMap::new();
            for v in &bad {
                *by_cons.entry(v.constraint).or_insert(0) += 1;
            }
            println!("[deepdump] 违约约束个数={} 分布(前20)={:?}",
                by_cons.len(),
                by_cons.iter().take(20).collect::<Vec<_>>()
            );
            panic!(
                "正例出现 {} 处违约；按族直方图 {hist:?}；首 12: {:?}",
                bad.len(),
                first12
            );
        }
    }

    /// 选择器激活点普查——回归网：任何误触发的激活（如 wp 漏 j<16、PNXT 多块）
    /// 都会在这里现形。期望计数由装配路径静态决定。
    #[test]
    fn selector_activation_census() {
        let blk = one_block(b"abc");
        let circ = build_compress(&blk);
        // 装配顺序：SelSet 字段序（16）→ 输出字母私有选择器（8，各 1 点）
        // → 虚拟轮常数选择器（8，各 1 点）。任何多行家族内部的行→源秩差
        // 都必须恒定（勘误 #13），故输出/虚拟轮均为单点家族。
        // 注意：T_j 预处理多项式（内容非 0/1）不计入"激活点"普查，
        // 它不在本列表中 —— 列表仅覆盖 alloc_selector 分配的布尔选择器。
        let mut expected: Vec<usize> = vec![
            64,  // ss1pre
            64,  // tj_prep（预处理多项式，非选择器：非零值恰在各轮 off1 点 ×64）
            64,  // ss2
            48,  // ff_maj   (j>=16)
            16,  // ff_xor   (j<16)
            48,  // gg_choose
            16,  // gg_xor
            64,  // tt1
            64,  // tt2
            52,  // ext_m1   (j∈16..68)
            52,  // ext_m2
            52,  // ext_t
            52,  // ext_p1
            52,  // ext_m3
            52,  // ext_w
            64,  // wp_xor   (j∈0..64)
            64,  // pnxt
        ];
        expected.extend(std::iter::repeat(1).take(8)); // out_sels[k]
        expected.extend(std::iter::repeat(1).take(8)); // vir 常数选择器
        assert_eq!(expected.len(), circ.info.preprocess_polys.len());
        for (i, poly) in circ.info.preprocess_polys.iter().enumerate() {
            let act = poly.iter().filter(|v| **v != FpSM2::ZERO).count();
            assert_eq!(&act, &expected[i], "选择器 #{i} 激活点数不符");
        }
    }

    /// 负例 A（公开侧）：改一个实例位 → ff.bind/ff.out 在对应 ordinal 行被击中。
    #[test]
    fn tampered_instance_rejected_at_its_row() {
        let blk = one_block(b"abc");
        let mut circ = build_compress(&blk);
        circ.instances[0][3] = circ.instances[0][3] + FpSM2::ONE;
        let bad = check_violations(&circ);
        let pt = row_mapping()[3];
        assert!(
            bad.iter().any(|v| v.point == pt),
            "篡改实例 #3 未在其行 {pt} 触发违约"
        );
    }

    /// 负例 B（见证·W 表）：翻 W[5] 一个位 → W'[5] 门在自身行触发违约。
    #[test]
    fn tampered_word_breaks_wp_gate() {
        let blk = one_block(b"abc");
        let mut circ = build_compress(&blk);
        let col = circ.meta.ext_pools.w.bits[7];
        let pt = row_of(5, off::W);
        circ.advice[col][pt] = circ.advice[col][pt] + FpSM2::ONE;
        let bad = check_violations(&circ);
        let wp_pt = row_of(5, off::WP);
        assert!(
            !bad.is_empty(),
            "篡改 W[5] 未被发现"
        );
        assert!(
            bad.iter().any(|v| v.point == wp_pt),
            "违约应击中 W'[5] 行 {wp_pt}（实得首违约 {:?}）",
            bad.first()
        );
    }

    /// 负例 C（见证·PNXT）：翻块 0 half 中间量一个位 → PNXT 发射行（TT2 同点）当场击中。
    #[test]
    fn tampered_pnxt_half_rejected_inline() {
        let blk = one_block(b"abc");
        let mut circ = build_compress(&blk);
        let col = circ.meta.half.bits[0];
        let pt = row_of(0, off::TT2);
        circ.advice[col][pt] = circ.advice[col][pt] + FpSM2::ONE;
        let bad = check_violations(&circ);
        assert!(
            bad.iter().any(|v| v.point == pt),
            "篡改 half@block0 未在发射行触发违约"
        );
    }

    /// 负号虚拟轮读回 = 链前延常数（勘误 #13 存储侧自检）：链值池列在
    /// t=−4..−1 延续秩点的格子必须精确等于 [`vir_values`] 推导值
    /// （TT1 族 [rotr9 IV3, rotr9 IV2, IV1, IV0]，PNXT 族同理 rotr19）。
    #[test]
    fn virtual_rounds_hold_chain_extension() {
        let blk = one_block(b"abc");
        let circ = build_compress(&blk);
        let (vt1, vpn) = vir_values();
        for k in 0..4i64 {
            let t = k - 4;
            let h_t1 = circ.meta.round_pools.tt1.at(signed_row(t, off::TT1));
            assert_eq!(circ.read_word_bits(&h_t1), vt1[k as usize], "t={t} TT1 读回不符");
            let h_pn = circ
                .meta
                .pnxt
                .at(signed_row(t, off::TT2));
            assert_eq!(circ.read_word_bits(&h_pn), vpn[k as usize], "t={t} PNXT 读回不符");
        }
    }

    /// 旋转距离普查——后端协议边界档案（本测试**不做对错断言**，只记录事实）：
    /// HyperPlonk 求和检查的证明方缓冲区按 |Rotation| ≤ num_vars 物化移位副本
    ///（piop/sum_check/classic.rs:42），且验证方为每个 (列，旋转) 对从证明中读入
    /// 2^|d| 个域元素（backend/hyperplonk/verifier.rs:61）——证明大小随旋转距离
    /// 指数增长。本电路按秩窗口布局，跨块读取（扩展 W[j-16]、输出绑定的 4 轮滞后、
    /// 实例行→链尾）的距离由本测试如实打印；数字即「为何端到端首跑被后端拒收」
    /// 的量化证据，进论文诚实边界讨论。
    #[test]
    fn rotation_distance_census() {
        let blk = one_block(b"abc");
        let circ = build_compress(&blk);
        use std::collections::{BTreeMap, BTreeSet};
        // 跨约束去重到 (poly, rot) 级的查询对全集
        let mut pairs: BTreeSet<(usize, i32)> = BTreeSet::new();
        for c in &circ.info.constraints {
            for q in c.used_query() {
                pairs.insert((q.poly(), q.rotation().0));
            }
        }
        let mut per_rot_cols: BTreeMap<i64, usize> = BTreeMap::new();
        for (_, rot) in &pairs {
            *per_rot_cols.entry(*rot as i64).or_insert(0) += 1;
        }
        let distinct_pairs = pairs.len();
        let max_abs = per_rot_cols.keys().map(|r| r.abs()).max().unwrap_or(0);
        // 可支付分类：classic.rs 只放行 |d| ≤ num_vars；verifier 面额 2^|d|
        let kb = K as i64;
        let within_budget: Vec<(i64, usize)> =
            per_rot_cols.iter().filter(|(r, _)| r.abs() <= kb).map(|(r, n)| (*r, *n)).collect();
        let beyond: usize =
            per_rot_cols.iter().filter(|(r, _)| r.abs() > kb).map(|(_, n)| *n).sum();
        let payable_units: usize = within_budget
            .iter()
            .map(|(r, n)| n * (1usize << r.abs() as u32))
            .sum();
        println!("[rot-census] 距离→受影响(去重)列数 = {:?}", per_rot_cols);
        println!(
            "[rot-census] 去重后 (列,旋转) 对数={distinct_pairs} 最大|d|={max_abs} \
             （classic.rs 断言阈 = num_vars={K}）"
        );
        println!(
            "[rot-census] 即使放宽断言：超阈对数={beyond}（面额 ≥2^{max_abs} 域元素/对 ⇒ 协议级不可行）；\
             阈内可支付单元={payable_units}"
        );
    }

    /// 边界字母真值抽查：用虚拟轮直接复算 round 0 的八字输入必须等于 IV。
    /// （a₀..h₀ 经槽视图展开后应还原 IV0..IV7 —— 全局性论证的数值面。）
    #[test]
    fn boundary_round_inputs_reconstruct_iv() {
        // reg_slots_for_round 是模块私有 → 在此重放同一映射做数值核对
        let (vt1, vpn) = vir_values();
        let iv = crate::sm3_native_ref::IV;
        // t=j−lag<0 时格子 k=t+4，槽视图旋转按字母：c/d→rotl9，g/h→rotl19
        let expand = |lag: usize, t1: bool, extra: u32, j: usize| -> u32 {
            if j >= lag {
                return 0; // 真实轮分支不在本测试覆盖内
            }
            let cell = if t1 { vt1[j + 4 - lag] } else { vpn[j + 4 - lag] };
            cell.rotate_left(extra)
        };
        // round 0：真值字母 = IV 本身（装入时无旋转历史）。槽视图展开必须精确还原：
        assert_eq!(expand(1, true, 0, 0), iv[0], "a0");
        assert_eq!(expand(2, true, 0, 0), iv[1], "b0");
        // c₀/d₀/g₀/h₀ 真值都是"平的"IV 值——⟨9⟩/⟨19⟩ 由格子里的 rotr 预折叠抵消
        assert_eq!(expand(3, true, 9, 0), iv[2], "c0");
        assert_eq!(expand(4, true, 9, 0), iv[3], "d0");
        assert_eq!(expand(1, false, 0, 0), iv[4], "e0");
        assert_eq!(expand(2, false, 0, 0), iv[5], "f0");
        assert_eq!(expand(3, false, 19, 0), iv[6], "g0");
        assert_eq!(expand(4, false, 19, 0), iv[7], "h0");
        // round 1：真值 = S₀ 寄存器（C 位首现 rotl9，G 位首现 rotl19；b₁/a 一路平移）
        assert_eq!(expand(2, true, 0, 1), iv[0], "b1");
        assert_eq!(expand(3, true, 9, 1), iv[1].rotate_left(9), "c1");
        assert_eq!(expand(4, true, 9, 1), iv[2], "d1"); // D←C 平移带入（无再旋转）
        assert_eq!(expand(2, false, 0, 1), iv[4], "f1");
        assert_eq!(expand(3, false, 19, 1), iv[5].rotate_left(19), "g1");
        assert_eq!(expand(4, false, 19, 1), iv[6], "h1");
        // round 2 抽查 h₂ = S₁[7] = G(S₀) = IV5⟨19⟩
        assert_eq!(expand(4, false, 19, 2), iv[5].rotate_left(19), "h2");
    }

    // ───────────── 簇A：通用门原语（1.1c；蓝图 §七-簇A）─────────────

    /// 三条通用出口的最小 mock 闭环：正例零违约、篡改必被击中、push 计数逐条对账。
    #[test]
    fn cluster_a_generic_gate_primitives_hold() {
        let mut b = Builder::<Fr>::new(0);
        // 选一个非 0 非实例钉点的普通行点作为唯一激活点。
        let at = point_at_rank(3);
        let sg = b.alloc_selector(&[]);
        b.extend_selector(sg, &[at]);

        let ca = b.alloc_col();
        let cb = b.alloc_col();
        let cc = b.alloc_col();
        let ci = b.alloc_col();
        let truth_a = <Fr as From<u64>>::from(5);
        let truth_b = <Fr as From<u64>>::from(7);
        let truth_inv = truth_a.invert().unwrap();
        // a=5, b=7（cur 同列不同格只演示单格语义），r = a·b 用独立格。
        b.set_cell_f(ca, at, truth_a);
        b.set_cell_f(cb, at, truth_b);
        b.set_cell_u32(cc, at, 35);
        b.set_cell_f(ci, at, truth_inv);

        // bool(ca)：见证已是合法位值 0/1 才能满足 —— ca=5 会违约，因此布尔性
        // 演示改走专用位列。
        let cbit = b.alloc_col();
        // assert.zero 的目标格必须随批预分配（布局冻结纪律：首推后禁 alloc）。
        let cs = b.alloc_col();
        b.set_cell_u32(cbit, at, 1);
        b.emit_bool(sg, cbit);

        // prod.eq: a·b = r
        b.emit_prod_eq(
            sg,
            b.q(ca, Rotation::cur()),
            b.q(cb, Rotation::cur()),
            b.q(cc, Rotation::cur()),
        );
        // neq_zero 形态复用 prod.eq：a·inv(a) = 1
        b.emit_prod_eq(
            sg,
            b.q(ca, Rotation::cur()),
            b.q(ci, Rotation::cur()),
            Expression::<Fr>::one(),
        );
        // assert.zero 线性等式: a + b − (a+b 的目击格) = 0。顺带覆盖 const_pow2
        // 缩放路径（×2^0 = ×1）。
        b.set_cell_u32(cs, at, 12);
        b.emit_assert_zero(
            sg,
            b.q(ca, Rotation::cur())
                + b.q(cb, Rotation::cur())
                - b.const_pow2(0).clone() * b.q(cs, Rotation::cur()),
        );

        assert_eq!(b.n_constraints(), 4, "bool×1 + prod.eq×2（mul+neq_zero 形态）+ assert.zero×1");

        let (info, advice, instances, _tags, _ctags, _nsel) = b.finish_parts();
        // finish_parts 以「单语句」包裹实例向量：outer 恒 1，inner 长度才是语句数。
        assert_eq!(instances.len(), 1);
        assert!(instances[0].is_empty());
        let bad = check_parts_violations(&info, &advice, &instances);
        assert!(bad.is_empty(), "正例必须零违约，首条 {bad:?}");

        // 负例 A：篡改积结果 → prod.eq 击中。
        let mut adv2 = advice.clone();
        adv2[cc][at] += Fr::ONE;
        assert!(!check_parts_violations(&info, &adv2, &instances).is_empty());

        // 负例 B：篡改逆元 → 第二条 prod.eq 击中。
        let mut adv3 = advice.clone();
        adv3[ci][at] += Fr::ONE;
        let bad3 = check_parts_violations(&info, &adv3, &instances);
        assert!(!bad3.is_empty());
    }
}
