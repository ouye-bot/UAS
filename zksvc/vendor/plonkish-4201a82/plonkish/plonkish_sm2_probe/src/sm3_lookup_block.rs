//! SM3 查表化**整块**原型（Phase B，系统线 2026-09-17，分支 `system/sm3-lookup-proto`，
//! 不入论文线）：用"4 位限位 × 查表通道 × 复制接线"重做一整块 SM3 压缩（消息扩展 68 词 +
//! 64 轮 + 前馈异或），与 `sm3_native_ref::compress` 差分对拍，并端到端 prove/verify，
//! 产出立项判据："60,212 约束/1,315 列（现行布尔门 solo）→ X 约束/Y 列/Z 查表；prove 时延对照"。
//!
//! 设计（全部 ≤ K=12 的 4,096 行）：
//! - 词 = 8 个 4 位限位格（limb 0 = 低 4 位）；每个限位格是某条通道某一行的一个见证格；
//! - 查表通道（每条 = 一组见证列 + 一条向量查表论证）：XOR2(a,b,c)、XOR3/MAJ/CH(a,b,c,d)
//!   表 256/4096 项；SPLIT_k(x, hi_k, lo_{4-k}) 16 项，用于位级旋转；RANGE16/RANGE4 用于模加；
//! - 旋转 ROTL r = 限位重标（4 的倍数部分，零成本）+ 位级 ROTL k（k=r mod 4∈{1,3}）：
//!   out_i = lo_{4-k}(x_i)·2^k + hi_k(x_{i-1})——一条线性约束/通道 + 查表；
//! - 模加（≤4 操作数）：x0+x1+x2+x3+cin − s − 16·cout = 0，s∈RANGE16，cout∈RANGE4，cin 接线自
//!   上一限位的 cout（limb 0 接常量 0）；
//! - 接线：消费格与生产格入同一复制环（同一生产格多次消费合并为一条环——置换须为不相交圈）；
//! - 常量（IV、ROTL(T_j, j)）：预处理列 + 同值见证列 + 一条全点相等约束，再接线消费；
//!   消息词：自由输入见证（原型不做实例钉，与形状计数无关）。
//! 非活跃行全零：所有表含全零项、全部约束在零行恒成立。

use ff::Field;
use plonkish_backend::{
    backend::{PlonkishCircuit, PlonkishCircuitInfo},
    util::expression::{Expression, Query, Rotation},
    Error,
};
use std::collections::{BTreeMap, HashSet};

pub type Fr = crate::FpSM2;
pub const K: usize = 12;
pub const ROWS: usize = 1 << K;

// ── 预处理（固定）列 ──
const P_XOR2: usize = 0; // 3
const P_XOR3: usize = 3; // 4
const P_MAJ: usize = 7; // 4
const P_CH: usize = 11; // 4
const P_SPLIT1: usize = 15; // 3: x, hi1, lo3
const P_SPLIT3: usize = 18; // 3: x, hi3, lo1
const P_RANGE16: usize = 21;
const P_RANGE4: usize = 22;
const P_CONST: usize = 23;
pub const NUM_P: usize = 24;
// ── 见证列（相对索引；全局 = NUM_P + i）──
// P2 织入导出（system/sm3-lookup-full）：weave 按同一布局重放到 vendor Builder。
pub const W_XOR2: usize = 0; // a,b,c
pub const W_XOR3: usize = 3; // a,b,c,d
pub const W_MAJ: usize = 7;
pub const W_CH: usize = 11;
pub const W_SPLIT1: usize = 15; // x, hi, lo, prev_hi, out
pub const W_SPLIT3: usize = 20;
pub const W_ADD: usize = 25; // x0,x1,x2,x3,cin,s,cout
pub const W_CONST: usize = 32;
pub const W_INPUT: usize = 33;
pub const NUM_W: usize = 34;

fn gw(i: usize) -> usize {
    NUM_P + i
}
// ── 变异测试体系公开面（列布局/全局号助手；实现细节仍私有）──
pub const W_SPLIT1_PUB: usize = W_SPLIT1;
pub const W_SPLIT3_PUB: usize = W_SPLIT3;
pub const W_ADD_PUB: usize = W_ADD;
pub const W_CONST_PUB: usize = W_CONST;
pub const P_CONST_PUB: usize = P_CONST;
pub fn gw_pub(i: usize) -> usize {
    gw(i)
}
pub fn expr_poly_pub(e: &Expression<Fr>) -> usize {
    expr_poly(e)
}
fn poly(idx: usize) -> Expression<Fr> {
    Expression::Polynomial(Query::new(idx, Rotation::cur()))
}
fn cst(v: u64) -> Expression<Fr> {
    Expression::Constant(Fr::from(v))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cell {
    pub col: usize, // 全局多项式号
    pub row: usize,
}
pub type Word = [Cell; 8];

#[derive(Clone, Copy)]
enum LaneId {
    Xor2,
    Xor3,
    Maj,
    Ch,
    Split1,
    Split3,
    Add,
    Const,
    Input,
}

struct Lane {
    w0: usize, // 首见证列（相对）
    next: usize,
}

pub struct BlockBuilder {
    wit: Vec<Vec<u64>>,
    pconst: Vec<u64>,
    lanes: [Lane; 9],
    /// 生产格 → 消费格列表（收官时合并为不相交环）
    uses: BTreeMap<Cell, Vec<Cell>>,
    zero: Cell,
    /// P2 链式扩展：当前列组基（组 g 的通道列 = NUM_P + g·NUM_W + rel）。
    /// 组切换时 CONST 通道行**全局**不清零（pconst 预处理列单列共享），其余通道行重置。
    group_base: usize,
    started: bool,
    inputs_per_block: Vec<[Word; 16]>,
    const_cache: std::collections::HashMap<u32, Word>,
}

#[derive(Clone, Debug)]
pub struct BlockStats {
    pub rows_used: [(String, usize); 9],
    pub rings: usize,
    pub ring_cells: usize,
    pub num_polys: usize,
    pub constraints: usize,
    pub lookups: usize,
}

#[derive(Clone, Debug)]
pub struct BlockCircuit {
    pub info: PlonkishCircuitInfo<Fr>,
    pub witness: Vec<Vec<Fr>>,
    pub digest: [u32; 8],
    pub digest_cells: [Word; 8],
    pub stats: BlockStats,
    /// P2 织入暴露面：宿主 u64 见证矩阵（组×NUM_W 列）。
    pub wit_u64: Vec<Vec<u64>>,
    /// P2 织入暴露面：pconst 列（共享常量预处理列的宿主值）。
    pub pconst: Vec<u64>,
    /// P2 织入暴露面：每块的 16 个消息输入词（W_INPUT 通道格）。
    pub inputs_per_block: Vec<[Word; 16]>,
}

impl BlockBuilder {
    pub fn new() -> Self {
        let mk = |w0: usize| Lane { w0, next: 1 }; // 点 0 禁用（置换环纪律）
        let mut b = BlockBuilder {
            wit: vec![vec![0u64; ROWS]; NUM_W],
            pconst: vec![0u64; ROWS],
            lanes: [
                mk(W_XOR2),
                mk(W_XOR3),
                mk(W_MAJ),
                mk(W_CH),
                mk(W_SPLIT1),
                mk(W_SPLIT3),
                mk(W_ADD),
                mk(W_CONST),
                mk(W_INPUT),
            ],
            uses: BTreeMap::new(),
            zero: Cell { col: 0, row: 0 },
            group_base: 0,
            const_cache: std::collections::HashMap::new(),
            started: false,
            inputs_per_block: Vec::new(),
        };
        let z = b.const_word(0);
        b.zero = z[0];
        b
    }

    fn alloc(&mut self, lane: LaneId, n: usize) -> (usize, usize) {
        let l = &mut self.lanes[lane as usize];
        let r0 = l.next;
        l.next += n;
        assert!(l.next < ROWS, "通道 {} 溢出 K=12 行预算", lane as usize);
        (self.group_base + l.w0, r0)
    }

    /// set 的 wrel = alloc 返回的**组偏移列**（相对索引，不含 NUM_P）。
    fn set(&mut self, wrel: usize, row: usize, v: u64) -> Cell {
        let col = NUM_P + wrel;
        self.wit[col - NUM_P][row] = v;
        Cell { col, row }
    }

    pub fn val(&self, c: Cell) -> u64 {
        self.wit[c.col - NUM_P][c.row]
    }

    pub fn word_val(&self, w: &Word) -> u32 {
        (0..8).fold(0u32, |acc, i| acc | ((self.val(w[i]) as u32) << (4 * i)))
    }

    /// 消费格 `to` 取生产格 `from` 的值并登记进同一环。
    fn wire(&mut self, from: Cell, to: Cell) {
        let v = self.val(from);
        self.wit[to.col - NUM_P][to.row] = v;
        self.uses.entry(from).or_default().push(to);
    }

    fn limbs(v: u32) -> [u64; 8] {
        std::array::from_fn(|i| ((v >> (4 * i)) & 15) as u64)
    }

    pub fn const_word(&mut self, v: u32) -> Word {
        // B3b（飞证 2026-09-20）：值去重——Tj 每块重复同 64 值，跨块复用同一
        // 生产格（多消费=环合并，合法先例）。否则 CONST lane 64+512G 行
        // G=8 即越 4,096（sm3_lookup_block.rs alloc 断言）——SMT 33 块必炸。
        if let Some(&w) = self.const_cache.get(&v) {
            return w;
        }
        let (w0, r0) = self.alloc(LaneId::Const, 8);
        let l = Self::limbs(v);
        let word: Word = std::array::from_fn(|i| {
            self.pconst[r0 + i] = l[i];
            self.set(w0, r0 + i, l[i])
        });
        self.const_cache.insert(v, word);
        word
    }

    pub fn input_word(&mut self, v: u32) -> Word {
        let (w0, r0) = self.alloc(LaneId::Input, 8);
        let l = Self::limbs(v);
        std::array::from_fn(|i| self.set(w0, r0 + i, l[i]))
    }

    /// B3b（飞证）：绑定输入词——自由落格后把源格 wire 进本格（环合并=等值
    /// 强制）。SMT 内节点链：块 g+1 消息左半 ==块 g 摘要（fresh IV、链在消息）。
    /// B3b（飞证）：绑定输入词——自由落格后把源格 wire 进本格（环合并=等值
    /// 强制）。SMT 内节点链：块 g+1 消息左半 ==块 g 摘要（fresh IV、链在消息）。
    pub fn bind_input_word(&mut self, v: u32, src: &Word) -> Word {
        let (w0, r0) = self.alloc(LaneId::Input, 8);
        let l = Self::limbs(v);
        std::array::from_fn(|i| {
            let cell = self.set(w0, r0 + i, l[i]);
            self.wire(src[i], cell);
            cell
        })
    }

    fn table_op(&mut self, lane: LaneId, ins: &[&Word], f: &dyn Fn(&[u64]) -> u64) -> Word {
        let n_in = ins.len();
        let (w0, r0) = self.alloc(lane, 8);
        std::array::from_fn(|i| {
            let r = r0 + i;
            let vals: Vec<u64> = ins.iter().map(|w| self.val(w[i])).collect();
            for (j, w) in ins.iter().enumerate() {
                let to = Cell { col: gw(w0 + j), row: r };
                self.wire(w[i], to);
            }
            self.set(w0 + n_in, r, f(&vals))
        })
    }

    pub fn xor2(&mut self, a: &Word, b: &Word) -> Word {
        self.table_op(LaneId::Xor2, &[a, b], &|v| v[0] ^ v[1])
    }
    pub fn xor3(&mut self, a: &Word, b: &Word, c: &Word) -> Word {
        self.table_op(LaneId::Xor3, &[a, b, c], &|v| v[0] ^ v[1] ^ v[2])
    }
    pub fn maj(&mut self, a: &Word, b: &Word, c: &Word) -> Word {
        self.table_op(LaneId::Maj, &[a, b, c], &|v| (v[0] & v[1]) | (v[0] & v[2]) | (v[1] & v[2]))
    }
    pub fn ch(&mut self, a: &Word, b: &Word, c: &Word) -> Word {
        self.table_op(LaneId::Ch, &[a, b, c], &|v| (v[0] & v[1]) | ((!v[0] & 15) & v[2]))
    }

    /// ROTL r：限位重标（零成本）+ 位级 ROTL k（k=r mod 4 ∈ {0,1,3}）。
    pub fn rotl(&mut self, w: &Word, r: u32) -> Word {
        let q = (r / 4) as usize;
        let k = r % 4;
        let shifted: Word = std::array::from_fn(|i| w[(i + 8 - q) % 8]);
        if k == 0 {
            return shifted;
        }
        assert!(k == 1 || k == 3, "SM3 旋转量 mod 4 只出现 1/3");
        let lane = if k == 1 { LaneId::Split1 } else { LaneId::Split3 };
        let (w0, r0) = self.alloc(lane, 8);
        let mask_lo = (1u64 << (4 - k)) - 1;
        // 先落 x/hi/lo（hi 是行内生产格，供 prev_hi 接线）
        for i in 0..8 {
            let x = self.val(shifted[i]);
            let to = Cell { col: gw(w0), row: r0 + i };
            self.wire(shifted[i], to);
            self.set(w0 + 1, r0 + i, x >> (4 - k));
            self.set(w0 + 2, r0 + i, x & mask_lo);
        }
        std::array::from_fn(|i| {
            let prev_hi_cell = Cell { col: gw(w0 + 1), row: r0 + (i + 7) % 8 };
            let to = Cell { col: gw(w0 + 3), row: r0 + i };
            self.wire(prev_hi_cell, to);
            let out = (self.wit[w0 + 2][r0 + i] << k) | self.val(prev_hi_cell);
            self.set(w0 + 4, r0 + i, out)
        })
    }

    /// 模 2^32 加（2..4 操作数）。
    pub fn add(&mut self, ins: &[&Word]) -> Word {
        assert!((2..=4).contains(&ins.len()));
        let (w0, r0) = self.alloc(LaneId::Add, 8);
        let zero = self.zero;
        let mut carry_cell: Option<Cell> = None;
        std::array::from_fn(|i| {
            let r = r0 + i;
            let mut sum = 0u64;
            for j in 0..4 {
                let to = Cell { col: gw(w0 + j), row: r };
                match ins.get(j) {
                    Some(w) => {
                        sum += self.val(w[i]);
                        self.wire(w[i], to);
                    }
                    None => self.wire(zero, to),
                }
            }
            let cin_to = Cell { col: gw(w0 + 4), row: r };
            match carry_cell {
                Some(cc) => {
                    sum += self.val(cc);
                    self.wire(cc, cin_to);
                }
                None => self.wire(zero, cin_to),
            }
            let s = self.set(w0 + 5, r, sum & 15);
            carry_cell = Some(self.set(w0 + 6, r, sum >> 4));
            s
        })
    }

    /// P2 链式：新开一个通道列组（表/预处理共享；CONST 行全局）。
    fn new_group(&mut self) {
        for (i, l) in self.lanes.iter_mut().enumerate() {
            if i != LaneId::Const as usize {
                l.next = 1;
            }
        }
        self.wit.extend(vec![vec![0u64; ROWS]; NUM_W]);
        self.group_base = self.wit.len() - NUM_W;
    }

    /// 一整块 SM3 压缩：v ← compress(v, block)。返回摘要词（电路格）与原生值。
    pub fn compress(&mut self, v: &[u32; 8], block: &[u8; 64]) -> ([Word; 8], [u32; 8]) {
        self.compress_entry(None, v, block)
    }

    /// P2 链式入口：prev=上一块的摘要词（非 None 时初始状态字经复制环接线——
    /// 链soundness 在电路内强制，不依赖宿主值一致）。
    pub fn compress_entry(
        &mut self,
        prev: Option<&[Word; 8]>,
        v: &[u32; 8],
        block: &[u8; 64],
    ) -> ([Word; 8], [u32; 8]) {
        self.compress_entry_binds(prev, v, block, &[])
    }

    /// B3b（飞证）：外部词格注入版——消息 16 词已由调用方落格（mux 自由度
    /// 在织入层），本方法只做消息扩展+压缩。words=[左半 8 词, 右半 8 词]。
    /// 🔴 时序契约（dump 定谳 2026-09-20）：调用方须先 [`BlockBuilder::begin_block`]
    /// 切组**再**落词——否则词落在前组 Input lane（块 g 词∈组 g−1，weave 的
    /// 组切片 vcol 全体错位；对齐 compress_entry_binds「先切组后落词」语义）。
    pub fn compress_entry_with_words(
        &mut self,
        prev: Option<&[Word; 8]>,
        v: &[u32; 8],
        words: &[[Word; 8]; 2],
    ) -> ([Word; 8], [u32; 8]) {
        let t0: u32 = 0x79cc_4519;
        let t1: u32 = 0x7a87_9d8a;
        let mut w: Vec<Word> = Vec::with_capacity(68);
        w.extend_from_slice(&words[0]);
        w.extend_from_slice(&words[1]);
        for j in 16..68 {
            let r15 = self.rotl(&w[j - 3], 15);
            let tt = self.xor3(&w[j - 16], &w[j - 9], &r15);
            let t15 = self.rotl(&tt, 15);
            let t23 = self.rotl(&tt, 23);
            let p1 = self.xor3(&tt, &t15, &t23);
            let r7 = self.rotl(&w[j - 13], 7);
            let wj = self.xor3(&p1, &r7, &w[j - 6]);
            w.push(wj);
        }
        self.compress_tail(prev, v, &mut w)
    }

    /// B3b（飞证）：显式开新块（组切换）——外部落词（input_word）前调用，
    /// 使「词与压缩体同组」。幂等语义与 compress_entry_binds 内联段一致。
    pub fn begin_block(&mut self) {
        if self.started {
            self.new_group();
        }
        self.started = true;
    }

    pub fn compress_entry_binds(
        &mut self,
        prev: Option<&[Word; 8]>,
        v: &[u32; 8],
        block: &[u8; 64],
        binds: &[(usize, &Word)],
    ) -> ([Word; 8], [u32; 8]) {
        if self.started {
            self.new_group();
        }
        self.started = true;
        let t0: u32 = 0x79cc_4519;
        let t1: u32 = 0x7a87_9d8a;
        // 消息扩展
        let mut w: Vec<Word> = (0..16)
            .map(|i| {
                let vv = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
                match binds.iter().find(|(idx, _)| *idx == i) {
                    Some((_, src)) => self.bind_input_word(vv, src),
                    None => self.input_word(vv),
                }
            })
            .collect();
        for j in 16..68 {
            let r15 = self.rotl(&w[j - 3], 15);
            let t = self.xor3(&w[j - 16], &w[j - 9], &r15);
            let t15 = self.rotl(&t, 15);
            let t23 = self.rotl(&t, 23);
            let p1 = self.xor3(&t, &t15, &t23);
            let r7 = self.rotl(&w[j - 13], 7);
            let wj = self.xor3(&p1, &r7, &w[j - 6]);
            w.push(wj);
        }
        self.inputs_per_block.push(w[..16].try_into().expect("16 消息词"));
        self.compress_tail(prev, v, &mut w)
    }

    /// 消息扩展后段（wp/64 轮/出口）——compress_entry_binds 与
    /// compress_entry_with_words 共用（B3b 飞证抽取）。
    fn compress_tail(
        &mut self,
        prev: Option<&[Word; 8]>,
        v: &[u32; 8],
        w: &mut Vec<Word>,
    ) -> ([Word; 8], [u32; 8]) {
        let t0: u32 = 0x79cc_4519;
        let t1: u32 = 0x7a87_9d8a;
        let wp: Vec<Word> = (0..64).map(|j| self.xor2(&w[j], &w[j + 4])).collect();
        // 压缩（初始状态：首块=常量；链式=环接上一块摘要）
        let vw: [Word; 8] = match prev {
            None => std::array::from_fn(|i| self.const_word(v[i])),
            Some(p) => {
                // 链式初态=上一块摘要（非常量）——放 INPUT 通道（自由见证），
                // 值经复制环自上一块摘要格接来；放 CONST 通道会违反 const_c
                // （mock 三面当场抓获的教训：约束面按语义选择，不按习惯）
                let (w0, r0) = self.alloc(LaneId::Input, 64);
                std::array::from_fn(|i| {
                    std::array::from_fn(|k| {
                        let to = Cell { col: NUM_P + w0, row: r0 + i * 8 + k };
                        self.wire(p[i][k], to);
                        to
                    })
                })
            }
        };
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (vw[0], vw[1], vw[2], vw[3], vw[4], vw[5], vw[6], vw[7]);
        for j in 0..64usize {
            let tj = if j < 16 { t0 } else { t1 }.rotate_left((j % 32) as u32);
            let tjw = self.const_word(tj);
            let a12 = self.rotl(&a, 12);
            let sum1 = self.add(&[&a12, &e, &tjw]);
            let ss1 = self.rotl(&sum1, 7);
            let ss2 = self.xor2(&ss1, &a12);
            let ff = if j < 16 { self.xor3(&a, &b, &c) } else { self.maj(&a, &b, &c) };
            let gg = if j < 16 { self.xor3(&e, &f, &g) } else { self.ch(&e, &f, &g) };
            let tt1 = self.add(&[&ff, &d, &ss2, &wp[j]]);
            let tt2 = self.add(&[&gg, &h, &ss1, &w[j]]);
            d = c;
            c = self.rotl(&b, 9);
            b = a;
            a = tt1;
            h = g;
            g = self.rotl(&f, 19);
            f = e;
            let t9 = self.rotl(&tt2, 9);
            let t17 = self.rotl(&tt2, 17);
            e = self.xor3(&tt2, &t9, &t17);
        }
        let st = [a, b, c, d, e, f, g, h];
        let out: [Word; 8] = std::array::from_fn(|i| self.xor2(&vw[i], &st[i]));
        let digest: [u32; 8] = std::array::from_fn(|i| self.word_val(&out[i]));
        (out, digest)
    }

    /// P2 织入暴露面：23+1 预处理列宿主值（表列 0..=22 + P_CONST 占位）。
    pub fn lut_tables() -> Vec<Vec<Fr>> {
        Self::tables()
    }

    fn tables() -> Vec<Vec<Fr>> {
        let mut p = vec![vec![Fr::ZERO; ROWS]; NUM_P];
        for i in 0..256usize {
            let (a, b) = ((i >> 4) as u64, (i & 15) as u64);
            p[P_XOR2][i] = Fr::from(a);
            p[P_XOR2 + 1][i] = Fr::from(b);
            p[P_XOR2 + 2][i] = Fr::from(a ^ b);
        }
        for i in 0..4096usize {
            let (a, b, c) = ((i >> 8) as u64, ((i >> 4) & 15) as u64, (i & 15) as u64);
            for (base, f) in [
                (P_XOR3, (a ^ b ^ c)),
                (P_MAJ, ((a & b) | (a & c) | (b & c))),
                (P_CH, ((a & b) | ((!a & 15) & c))),
            ] {
                p[base][i] = Fr::from(a);
                p[base + 1][i] = Fr::from(b);
                p[base + 2][i] = Fr::from(c);
                p[base + 3][i] = Fr::from(f);
            }
        }
        for x in 0..16u64 {
            p[P_SPLIT1][x as usize] = Fr::from(x);
            p[P_SPLIT1 + 1][x as usize] = Fr::from(x >> 3);
            p[P_SPLIT1 + 2][x as usize] = Fr::from(x & 7);
            p[P_SPLIT3][x as usize] = Fr::from(x);
            p[P_SPLIT3 + 1][x as usize] = Fr::from(x >> 1);
            p[P_SPLIT3 + 2][x as usize] = Fr::from(x & 1);
            p[P_RANGE16][x as usize] = Fr::from(x);
        }
        for x in 0..4u64 {
            p[P_RANGE4][x as usize] = Fr::from(x);
        }
        p
    }

    pub fn finalize(self, digest: [u32; 8], digest_cells: [Word; 8]) -> BlockCircuit {
        let groups = self.wit.len() / NUM_W;
        let mut tables = Self::tables();
        tables[P_CONST] = self.pconst.iter().map(|&v| Fr::from(v)).collect();
        // 约束/查表：按列组发射（每组一套；组偏移 = g·NUM_W）
        let mut constraints = Vec::new();
        let mut lookups = Vec::new();
        for g in 0..groups {
            let off = g * NUM_W;
            let split_c = |w0: usize, k: u64| {
                poly(gw(off + w0 + 4))
                    - (cst(1 << k) * poly(gw(off + w0 + 2)) + poly(gw(off + w0 + 3)))
            };
            let add_c = poly(gw(off + W_ADD))
                + poly(gw(off + W_ADD + 1))
                + poly(gw(off + W_ADD + 2))
                + poly(gw(off + W_ADD + 3))
                + poly(gw(off + W_ADD + 4))
                - poly(gw(off + W_ADD + 5))
                - cst(16) * poly(gw(off + W_ADD + 6));
            let const_c = poly(gw(off + W_CONST)) - poly(P_CONST);
            constraints.push(split_c(W_SPLIT1, 1));
            constraints.push(split_c(W_SPLIT3, 3));
            constraints.push(add_c);
            constraints.push(const_c);
            let lk = |w0: usize, p0: usize, n: usize| -> Vec<(Expression<Fr>, Expression<Fr>)> {
                (0..n).map(|j| (poly(gw(off + w0 + j)), poly(p0 + j))).collect()
            };
            lookups.push(lk(W_XOR2, P_XOR2, 3));
            lookups.push(lk(W_XOR3, P_XOR3, 4));
            lookups.push(lk(W_MAJ, P_MAJ, 4));
            lookups.push(lk(W_CH, P_CH, 4));
            lookups.push(lk(W_SPLIT1, P_SPLIT1, 3));
            lookups.push(lk(W_SPLIT3, P_SPLIT3, 3));
            lookups.push(vec![(poly(gw(off + W_ADD + 5)), poly(P_RANGE16))]);
            lookups.push(vec![(poly(gw(off + W_ADD + 6)), poly(P_RANGE4))]);
        }
        // 环：生产格 + 全部消费格（不相交圈）
        let mut permutations: Vec<Vec<(usize, usize)>> = Vec::with_capacity(self.uses.len());
        let mut ring_cells = 0usize;
        for (from, tos) in &self.uses {
            let mut cyc = Vec::with_capacity(tos.len() + 1);
            cyc.push((from.col, from.row));
            cyc.extend(tos.iter().map(|c| (c.col, c.row)));
            ring_cells += cyc.len();
            permutations.push(cyc);
        }
        let info = PlonkishCircuitInfo::<Fr> {
            k: K,
            num_instances: Vec::new(),
            preprocess_polys: tables,
            num_witness_polys: vec![groups * NUM_W],
            num_challenges: vec![0],
            constraints,
            lookups,
            permutations,
            max_degree: Some(4),
        };
        assert!(info.is_well_formed(), "block 原型 info 未通过 well-formed");
        let names = ["XOR2", "XOR3", "MAJ", "CH", "SPLIT1", "SPLIT3", "ADD", "CONST", "INPUT"];
        let rows_used: [(String, usize); 9] =
            std::array::from_fn(|i| (names[i].to_string(), self.lanes[i].next - 1));
        let stats = BlockStats {
            rows_used,
            rings: info.permutations.len(),
            ring_cells,
            num_polys: info.num_poly(),
            constraints: info.constraints.len(),
            lookups: info.lookups.len(),
        };
        // 多组共享一个 P_CONST 预处理列（const_c 为全点约束）：每个组的 W_CONST
        // 见证列整列填充为 pconst——各组的常量格本就写在各自的行上（值相同），
        // 其余行是自由见证值（未被消费，约束=pconst 即满足）。
        let mut wit = self.wit;
        for g in 0..groups {
            wit[g * NUM_W + W_CONST] = self.pconst.clone();
        }
        let pconst_out = self.pconst.clone();
        let inputs_per_block = self.inputs_per_block.clone();
        let witness = wit
            .iter()
            .map(|col| col.iter().map(|&v| Fr::from(v)).collect())
            .collect();
        BlockCircuit {
            info,
            witness,
            digest,
            digest_cells,
            stats,
            wit_u64: wit,
            pconst: pconst_out,
            inputs_per_block,
        }
    }
}

impl Default for BlockBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 一步到位：v + block → 电路。
pub fn build_block(v: &[u32; 8], block: &[u8; 64]) -> BlockCircuit {
    let mut b = BlockBuilder::new();
    let (cells, digest) = b.compress(v, block);
    b.finalize(digest, cells)
}

impl PlonkishCircuit<Fr> for BlockCircuit {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<Fr>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<Fr>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<Fr>] {
        &[]
    }
    fn synthesize(&self, round: usize, challenges: &[Fr]) -> Result<Vec<Vec<Fr>>, Error> {
        assert!(round == 0 && challenges.is_empty());
        Ok(self.witness.clone())
    }
}

/// mock 检查器（测试与负例判据用；协议层的权威=后端 verify）：
/// 查表元组成员资格 / 约束逐行 / 环内等值 三面。返回违约描述列表。
pub fn mock_check(c: &BlockCircuit) -> Vec<String> {
    let mut bad = Vec::new();
    let val = |poly_idx: usize, row: usize| -> Fr {
        if poly_idx < NUM_P {
            c.info.preprocess_polys[poly_idx][row]
        } else {
            c.witness[poly_idx - NUM_P][row]
        }
    };
    for (li, lookup) in c.info.lookups.iter().enumerate() {
        let cols: Vec<(usize, usize)> = lookup
            .iter()
            .map(|(inp, tab)| (expr_poly(inp), expr_poly(tab)))
            .collect();
        let table: HashSet<Vec<Fr>> =
            (0..ROWS).map(|r| cols.iter().map(|&(_, t)| val(t, r)).collect()).collect();
        for r in 0..ROWS {
            let tup: Vec<Fr> = cols.iter().map(|&(i, _)| val(i, r)).collect();
            if !table.contains(&tup) {
                bad.push(format!("lookup#{li} row {r} 元组不在表中"));
                if bad.len() > 20 {
                    return bad;
                }
            }
        }
    }
    for (ci, e) in c.info.constraints.iter().enumerate() {
        for r in 0..ROWS {
            if eval_expr(e, &|p| val(p, r)) != Fr::ZERO {
                bad.push(format!("constraint#{ci} row {r} ≠ 0"));
                if bad.len() > 20 {
                    return bad;
                }
            }
        }
    }
    for (ri, cyc) in c.info.permutations.iter().enumerate() {
        let v0 = val(cyc[0].0, cyc[0].1);
        if cyc.iter().any(|&(p, r)| val(p, r) != v0) {
            bad.push(format!("ring#{ri} 环内值不等"));
            if bad.len() > 20 {
                return bad;
            }
        }
    }
    bad
}

fn expr_poly(e: &Expression<Fr>) -> usize {
    match e {
        Expression::Polynomial(q) => q.poly(),
        _ => panic!("原型查表表达式均为裸多项式"),
    }
}

fn eval_expr(e: &Expression<Fr>, val: &dyn Fn(usize) -> Fr) -> Fr {
    e.evaluate(
        &|c| c,
        &|_| unreachable!("无 common 多项式"),
        &|q| val(q.poly()),
        &|_| unreachable!("无挑战"),
        &|a| -a,
        &|a, b| a + b,
        &|a, b| a * b,
        &|a, s| a * s,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm3_lookup_proto::ProtoSpec;
    use crate::sm3_native_ref;
    use plonkish_backend::{
        backend::{hyperplonk::HyperPlonk, PlonkishBackend},
        pcs::multilinear::Basefold,
        util::{
            hash::Sm3,
            transcript::{InMemoryTranscript, SM3Transcript},
        },
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::io::Cursor;
    use std::time::Instant;

    type Pcs = Basefold<Fr, Sm3, ProtoSpec>;
    type Pb = HyperPlonk<Pcs>;
    type T = SM3Transcript<Cursor<Vec<u8>>>;

    fn rand_block(seed: u64) -> [u8; 64] {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        b
    }

    fn fly<C: PlonkishCircuit<Fr>>(info: &PlonkishCircuitInfo<Fr>, circ: &C, inst: &[Vec<Fr>], tag: &str) -> (bool, f64, f64, usize) {
        let param = Pb::setup(info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = Pb::preprocess(&param, info).unwrap();
        let t = Instant::now();
        let proof = {
            let mut tr = T::new(());
            Pb::prove(&pp, circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let prove_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let ok = {
            let mut tr = T::from_proof((), proof.as_slice());
            Pb::verify(&vp, inst, &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
        };
        let verify_s = t.elapsed().as_secs_f64();
        eprintln!(
            "[sm3-lookup-block] {tag}: polys={} constraints={} lookups={} rings={} prove={prove_s:.2}s verify={verify_s:.3}s proof={}B ok={ok}",
            info.num_poly(), info.constraints.len(), info.lookups.len(), info.permutations.len(), proof.len()
        );
        (ok, prove_s, verify_s, proof.len())
    }

    /// B1 差分：8 随机块 + "abc" 块——电路摘要格 == 原生 compress；mock 三面零违约；形状打印。
    #[test]
    fn b1_block_differential_vs_native() {
        let mut blocks: Vec<[u8; 64]> = (0..8).map(rand_block).collect();
        let mut abc = [0u8; 64];
        abc[..3].copy_from_slice(b"abc");
        abc[3] = 0x80;
        abc[63] = 24;
        blocks.push(abc);
        for (i, blk) in blocks.iter().enumerate() {
            let circ = build_block(&sm3_native_ref::IV, blk);
            let native = sm3_native_ref::compress(&sm3_native_ref::IV, blk);
            assert_eq!(circ.digest, native, "块 {i} 电路摘要 ≠ 原生 SM3");
            let bad = mock_check(&circ);
            assert!(bad.is_empty(), "块 {i} mock 违约: {:?}", &bad[..bad.len().min(5)]);
            if i == 0 {
                let s = &circ.stats;
                eprintln!(
                    "[sm3-lookup-block] B1-shape: polys={} (P={} W={}) constraints={} lookups={} rings={} ring_cells={} rows_used={:?}",
                    s.num_polys, NUM_P, NUM_W, s.constraints, s.lookups, s.rings, s.ring_cells, s.rows_used
                );
            }
        }
        eprintln!("[sm3-lookup-block] B1: 9 块差分对拍全等 + mock 三面零违约 ✓");
    }

    /// B2 端到端 + 基线对照：查表整块 vs 现行布尔门 solo（build_compress_v2，60,212/1,315），同 Spec。
    #[test]
    fn b2_block_prove_verify_vs_boolean_baseline() {
        // 基线 solo 60k 约束的深表达式递归超默认栈（zksvc BIG_STACK 同款护栏）——512MB 工作线程
        std::thread::Builder::new()
            .stack_size(512 * 1024 * 1024)
            .spawn(b2_body)
            .expect("起工作线程失败")
            .join()
            .unwrap();
    }

    fn b2_body() {
        let blk = rand_block(42);
        let circ = build_block(&sm3_native_ref::IV, &blk);
        let (ok, p_lk, v_lk, sz_lk) = fly(&circ.info, &circ, &[], "B2-lookup-block");
        assert!(ok, "查表整块诚实电路 VERIFY FAILED");
        let base = crate::sm3_compress_v2::build_compress_v2(&blk);
        let inst = base.instances.clone();
        let (okb, p_bl, v_bl, sz_bl) = fly(&base.info, &base, &inst, "B2-boolean-solo(v2)");
        assert!(okb, "基线 solo VERIFY FAILED");
        eprintln!(
            "[sm3-lookup-block] B2-RATE: constraints {}→{} | polys {}→{} | lookups 0→{} | prove {:.2}s→{:.2}s ({:.2}x) | verify {:.3}s→{:.3}s | proof {}B→{}B",
            base.info.constraints.len(), circ.info.constraints.len(),
            base.info.num_poly(), circ.info.num_poly(), circ.info.lookups.len(),
            p_bl, p_lk, p_bl / p_lk.max(1e-9), v_bl, v_lk, sz_bl, sz_lk
        );
    }

    /// B3 负例（变异）：① 篡改一个 XOR3 输出限位（元组离表）；② 破一条环（消费格偏离，表仍合法）；
    /// ③ 篡改模加进位（约束违约）——mock 必红，且 ① 走后端 prove 必拒。
    #[test]
    fn b3_negatives_mutation_rejected() {
        let blk = rand_block(7);
        // ① 元组离表
        let mut c1 = build_block(&sm3_native_ref::IV, &blk);
        let r = 100usize;
        let cur = c1.witness[W_XOR3 + 3][r];
        c1.witness[W_XOR3 + 3][r] = if cur == Fr::from(15u64) { Fr::ZERO } else { cur + Fr::ONE };
        let bad1 = mock_check(&c1);
        assert!(bad1.iter().any(|s| s.contains("lookup#1")), "XOR3 输出篡改须被查表捕获: {:?}", &bad1[..bad1.len().min(3)]);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fly(&c1.info, &c1, &[], "B3-neg-lookup")));
        match outcome {
            Ok((ok, ..)) => assert!(!ok, "离表元组被后端静默接受！"),
            Err(_) => eprintln!("[sm3-lookup-block] B3-neg-lookup: prove panic（视为拒绝）"),
        }
        // ② 破环：XOR2 通道某行 a 改成 a⊕1 并同步改 c（元组仍合法），环内不等
        let mut c2 = build_block(&sm3_native_ref::IV, &blk);
        let a = c2.witness[W_XOR2][50];
        let b = c2.witness[W_XOR2 + 1][50];
        let a2 = if a == Fr::from(15u64) { Fr::ZERO } else { a + Fr::ONE };
        c2.witness[W_XOR2][50] = a2;
        // c = a2 ⊕ b（用整数重算）
        let to_u = |f: Fr| (0..16u64).find(|&x| Fr::from(x) == f).unwrap();
        c2.witness[W_XOR2 + 2][50] = Fr::from(to_u(a2) ^ to_u(b));
        let bad2 = mock_check(&c2);
        assert!(bad2.iter().any(|s| s.contains("ring#")), "破环须被环审计捕获: {:?}", &bad2[..bad2.len().min(3)]);
        // ③ 进位篡改
        let mut c3 = build_block(&sm3_native_ref::IV, &blk);
        c3.witness[W_ADD + 6][9] = c3.witness[W_ADD + 6][9] + Fr::ONE;
        let bad3 = mock_check(&c3);
        assert!(bad3.iter().any(|s| s.contains("constraint#2") || s.contains("ring#")), "进位篡改须被约束/环捕获: {:?}", &bad3[..bad3.len().min(3)]);
        eprintln!("[sm3-lookup-block] B3: 三类变异均被捕获 ✓");
    }

    /// P2 验收门 1（solo 链式差分）+ mock 三面 + e2e prove/verify：
    /// 3 块（t1 形态）compress_entry 环接——链 soundness 在电路内（复制环）。
    #[test]
    fn chained_three_blocks_differential_mock_and_e2e() {
        let blocks = [rand_block(11), rand_block(22), rand_block(33)];
        let mut native = sm3_native_ref::IV;
        let mut native_v = vec![native];
        for b in &blocks {
            native = sm3_native_ref::compress(&native, b);
            native_v.push(native);
        }
        let mut bld = BlockBuilder::new();
        let mut v = sm3_native_ref::IV;
        let mut prev: Option<[Word; 8]> = None;
        let mut last: [Word; 8] = std::array::from_fn(|_| std::array::from_fn(|_| Cell { col: 0, row: 0 }));
        for (bi, b) in blocks.iter().enumerate() {
            let (cells, dg) = bld.compress_entry(prev.as_ref(), &v, b);
            // 逐块渐进断言：定位链分歧
            if dg != native_v[bi + 1] {
                eprintln!("[dbg] 块 {bi} dg={dg:08x?}");
                eprintln!("[dbg] 块 {bi} nv={:08x?}", native_v[bi + 1]);
            }
            assert_eq!(dg, native_v[bi + 1], "块 {bi} 摘要漂移");
            v = dg;
            prev = Some(cells);
            last = cells;
        }
        assert_eq!(v, native, "3 块链式电路摘要 ≠ 原生压缩链");
        let circ = bld.finalize(v, last);
        let bad = mock_check(&circ);
        assert!(bad.is_empty(), "mock 违约: {bad:?}");
        eprintln!("[chained-3] witness cols={} stats={:?}", circ.witness.len(), circ.stats);
        let (ok, p, vrf, sz) = fly(&circ.info, &circ, &[], "chained-3");
        assert!(ok, "链式 3 块 VERIFY FAILED");
        let _ = (p, vrf, sz);
    }
}

#[cfg(test)]
mod chained_mutation_tests {
    use super::*;
    use crate::sm3_native_ref;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    fn blk(seed: u64) -> [u8; 64] {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        b
    }

    /// P2 变异抽查（链式体）：篡改见证格（查表输入 limb / ADD 进位）⟹ mock
    /// 三面（表成员/约束逐行/环等值）必红——链式形态约束充分性抽查。
    #[test]
    fn chained_mutations_all_caught() {
        let blocks = [blk(41), blk(42), blk(43)];
        let mut v = crate::sm3_native_ref::IV;
        let mut prev: Option<[Word; 8]> = None;
        let mut last: [Word; 8] =
            std::array::from_fn(|_| std::array::from_fn(|_| Cell { col: 0, row: 0 }));
        let mut bld = BlockBuilder::new();
        for b in &blocks {
            let (cells, dg) = bld.compress_entry(prev.as_ref(), &v, b);
            v = dg;
            prev = Some(cells);
            last = cells;
        }
        let circ = bld.finalize(v, last);
        assert!(mock_check(&circ).is_empty(), "基线 mock 必须干净");

        // 变异一：查表输入 limb（W_INPUT 通道 col，行 65=消息字 8 limb 0）——离表元组
        let mut m1 = circ.clone();
        {
            let col = &mut m1.witness[NUM_P + W_INPUT];
            col[65] = col[65] + Fr::from(1u64);
        }
        assert!(
            !mock_check(&m1).is_empty(),
            "查表输入 limb 篡改未被 mock 击中"
        );

        // 变异二：ADD 进位格（W_ADD+6 通道，行 700）——进位链/约束必红
        let mut m2 = circ.clone();
        {
            let col = &mut m2.witness[NUM_P + W_ADD + 6];
            col[700] = col[700] + Fr::from(1u64);
        }
        assert!(
            !mock_check(&m2).is_empty(),
            "ADD 进位篡改未被 mock 击中"
        );
        eprintln!("[chained-mut] 两变异均被 mock 击中 ✓（链式形态约束充分性保持）");
    }
}
