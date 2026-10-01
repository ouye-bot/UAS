//! A3 · 流式验证器(2026-09-16,TDD 单元 1)
//!
//! 两遍流式设计(文档=`M3_probe/literature_review/A3_流式验证器_两遍设计与地基_2026-09-15.md`)
//! 的第二遍=手动字节解析(绕开 transcript 逐段读入物化)。本模块提供**手动解析器**
//! 并以差分对拍锁定其与 `FiatShamirTranscript` 读序的逐字节一致:
//! - `parse_field_element`:40B wire(=Repr 全长 to_repr 反转后的 wire 形态)→ 域元素;
//! - `parse_hash32`:32B 原样(Merkle 哈希块,无语义转换)。
//! 对拍口径:随机域元素 10^4,三路一致(手动解析 == transcript 读 == 写侧 round-trip),
//! 且 `stream_position` 恰步进 32/元素。e12 禁跑纪律继承。

use plonkish_backend::util::transcript::{
    FieldTranscriptRead, InMemoryTranscript, TranscriptWrite,
};
use plonkish_backend::util::{
    hash::Sm3,
    transcript::{FiatShamirTranscript, SM3Transcript},
};
use std::io::Cursor;

use ff::PrimeField as _;

/// 手动解析:wire → 域元素(=read_field_element 的逐字节等价实现)。
/// **wire 元素宽 = Repr 全长 = 40B(5×8B)**——TDD 差分对拍实测抓得(to_repr
/// 全长 40B 反转上流;32B 假设被本单元当场推翻)。反转还原 LE repr 后
/// from_repr_vartime(≥p 拒绝,与读侧同门)。
pub fn parse_field_element(wire: &[u8]) -> Option<crate::FpSM2> {
    let mut repr = <crate::FpSM2 as ff::PrimeField>::Repr::default();
    if wire.len() != repr.as_ref().len() {
        return None;
    }
    repr.as_mut().copy_from_slice(wire);
    repr.as_mut().reverse();
    crate::FpSM2::from_repr_vartime(repr)
}

/// wire 上单元素宽(字节)。
pub const FE_WIRE_LEN: usize = std::mem::size_of::<<crate::FpSM2 as ff::PrimeField>::Repr>(); // 40(5×8B)

/// 手动解析:Merkle 哈希块 32B 原样(Output<H> 语义,无转换)。
pub fn parse_hash32(wire: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&wire[..32]);
    out
}

// =============================================================================
// A3 尺寸封闭式(2026-09-16,窗口二首件事)
//
// 从 `Basefold::batch_verify`(backend pcs/multilinear/basefold.rs:853)的读序表
// 逐段导出各读段字节长。🔴 wire 常量(逐段核对源码,禁凭直觉一刀切):
// - 域元素 wire 宽 = Repr 全长 = **40B(5×8B)**(read_field_element 读 Repr 全长,
//   TDD 单元 1 差分实测;SM2 域 p<2^256 ⟹ wire 每元素**前 8 字节恒零**=段指纹);
// - 哈希块(Merkle 根/路径/盐)= Output<H> = **32B**(read_commitment)。
//
// 与检查点 v8 续三修正警告的差异(以代码为权威):
// - **final_oracle = 2^(nv−nr+lr) 个域元素(40B),非 32B 哈希**——检查点表格
//   该行与 basefold.rs:1001 read_field_elements 不符,本封闭式予以修正;
// - 补全检查点未列出的段:S5(bh_evals+eq,各 2^(nv−nr) 域元素,nr<nv 才有)。
// =============================================================================

/// wire 上哈希块宽(Output<H> = [u8;32] for Sm3)。
pub const HASH_CHUNK_LEN: usize = 32;

/// batch_verify 读段(按流序;符号:nv=num_vars,lr=log_rate,nr=num_rounds,
/// Q=num_verifier_queries,N=承诺数,E=|evals|(OFF)/n_slots(去重档))。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A3Seg {
    /// S1 头部对齐消耗:每承诺 (盐,根) 成对 = 2·N×32B(不吸收,纯对齐)。
    S1Header,
    /// S2 批量 sumcheck(ClassicSumCheck,degree=2):nv 轮 × 3 域元素 = 120·nv B。
    S2BatchSumcheck,
    /// S3 折叠轮:每轮 (盐,根) 2×32B + 轮 oracle 3×40B = 184·nr B。
    S3FoldRounds,
    /// S4 末轮 fold oracle:3×40B。
    S4FinalFoldOracle,
    /// S5 bh_evals+eq:各 2^(nv−nr) 域元素(仅 nr<nv;A5Spec 下 nr=nv ⟹ 0)。
    S5BhEq,
    /// S6 个体开口叶值:Q·E×2 域元素(两遍流式的回放目标①)。
    S6IndQueries,
    /// S7 个体 Merkle 路径:Q·E×2(nv+lr) 哈希(最大保留段,回放目标②)。
    S7BatchPaths,
    /// S8 联合 eval:1 域元素。
    S8Eval,
    /// S9 final_oracle:2^(nv−nr+lr) **域元素(40B,非哈希——代码为权威)**。
    S9FinalOracle,
    /// S10 all_qs(逐查询线性组合叶值):Q×2(nr+1) 域元素。
    S10AllQs,
    /// S11 查询层 Merkle 路径:每查询每轮 2(nv+lr−1−r) 哈希,Σ=Σ_{r=0}^{nr}。
    S11QueryPaths,
}

/// batch_verify 读段的字节长/偏移封闭式(两遍流式第二遍的纯算术定位器)。
#[derive(Clone, Copy, Debug)]
pub struct A3Sizes {
    pub nv: usize,
    pub lr: usize,
    pub nr: usize,
    pub q: usize,
    pub n_comms: usize,
    /// |evals|(OFF 档)或 n_slots(PCS_BATCH_DEDUP 档,不同 poly 首现数)。
    pub e: usize,
    segs: [usize; 11],
}

impl A3Sizes {
    pub fn new(nv: usize, lr: usize, nr: usize, q: usize, n_comms: usize, e: usize) -> Self {
        let s1 = 2 * n_comms * HASH_CHUNK_LEN;
        let s2 = nv * 3 * FE_WIRE_LEN;
        let s3 = nr * (2 * HASH_CHUNK_LEN + 3 * FE_WIRE_LEN);
        let s4 = 3 * FE_WIRE_LEN;
        let s5 = if nr < nv { 2 * (1 << (nv - nr)) * FE_WIRE_LEN } else { 0 };
        let s6 = q * e * 2 * FE_WIRE_LEN;
        let s7 = q * e * 2 * (nv + lr) * HASH_CHUNK_LEN;
        let s8 = FE_WIRE_LEN;
        let s9 = (1 << (nv - nr + lr)) * FE_WIRE_LEN;
        let s10 = q * 2 * (nr + 1) * FE_WIRE_LEN;
        let s11 = q
            * (0..=nr).map(|r| 2 * (nv + lr - 1 - r)).sum::<usize>()
            * HASH_CHUNK_LEN;
        A3Sizes { nv, lr, nr, q, n_comms, e, segs: [s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11] }
    }

    /// 段字节长。
    pub fn seg_len(&self, seg: A3Seg) -> usize {
        self.segs[seg as usize]
    }

    /// 段在 PCS 段内的起始字节偏移(纯算术;两遍流式第二遍的区间定位)。
    pub fn seg_off(&self, seg: A3Seg) -> usize {
        self.segs[..seg as usize].iter().sum()
    }

    /// PCS 段字节总长。
    pub fn total(&self) -> usize {
        self.segs.iter().sum()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::FpSM2;
    use ff::Field as _;
    use rand::{rngs::StdRng, SeedableRng};

    /// 确定性随机合法域元素(前 4×8B=252bit 随机、Repr 第 5 块(40B)保持零
    /// ⟹ 值 <2^252<p;FpSM2 Repr=5×8B,整块随机会污染第 5 块致 ≥p 被拒)。
    fn rnd_fe(sm: &mut crate::sm2_a7_props::SplitMix) -> FpSM2 {
        crate::FpSM2::from_repr_vartime({
            let mut r = <FpSM2 as ff::PrimeField>::Repr::default();
            for (i, chunk) in r.as_mut().chunks_mut(8).enumerate() {
                if i >= 4 {
                    break; // 第 5 块恒零(320bit 表示的高位清零)
                }
                let v = sm.next() >> 1; // 63 bit
                chunk.copy_from_slice(&v.to_le_bytes());
            }
            r
        })
        .expect("252bit 随机值必 <p")
    }

    /// wire 形态 = to_repr 全长字节反转(write_field_element 同法,40B)。
    fn wire_of(fe: &FpSM2) -> Vec<u8> {
        let mut repr = fe.to_repr();
        repr.as_mut().reverse();
        repr.as_ref().to_vec()
    }

    /// TDD 单元 1:10^4 随机域元素,三路一致(手动解析 == transcript 读 ==
    /// 写侧 round-trip)+ 位置恰步进 32/元素 + 批量读与逐读等价。
    #[test]
    fn a3_parse_cursor_differential() {
        let n = 10_000usize;
        let mut sm = crate::sm2_a7_props::SplitMix(0x00A3_5EED);
        let mut wire = Vec::with_capacity(32 * n);
        let mut elems = Vec::with_capacity(n);
        for _ in 0..n {
            let fe = rnd_fe(&mut sm);
            wire.extend_from_slice(&wire_of(&fe));
            elems.push(fe);
        }

        // 路线一:手动解析器逐元素(第二遍流式的读法)。
        for (i, fe) in elems.iter().enumerate() {
            let w = &wire[FE_WIRE_LEN * i..FE_WIRE_LEN * (i + 1)];
            assert_eq!(
                parse_field_element(w).expect("手动解析拒绝合法域元素"),
                *fe,
                "手动解析 #{i} 值不等"
            );
        }

        // 路线二:零拷贝 transcript(from_proof_ref 地基)逐读,位置恰步进。
        let mut tr = FiatShamirTranscript::<Sm3, Cursor<&[u8]>>::from_proof_ref((), &wire);
        assert_eq!(tr.stream_position(), 0);
        for (i, fe) in elems.iter().enumerate() {
            let v = plonkish_backend::util::transcript::FieldTranscriptRead::<FpSM2>::read_field_element(&mut tr)
                .expect("transcript 读失败");
            assert_eq!(v, *fe, "transcript读 #{i} 值不等");
            assert_eq!(tr.stream_position(), FE_WIRE_LEN * (i + 1), "位置步进漂移 @#{i}");
        }

        // 路线三:批量读与逐读等价(owned 路径交叉验证)。
        let mut tr2 = <SM3Transcript<Cursor<Vec<u8>>> as InMemoryTranscript>::from_proof((), &wire);
        let bulk = plonkish_backend::util::transcript::FieldTranscriptRead::<FpSM2>::read_field_elements(
            &mut tr2,
            512,
        )
        .expect("批量读失败");
        assert_eq!(bulk.len(), 512);
        for (i, v) in bulk.iter().enumerate() {
            assert_eq!(v, &elems[i], "批量读 #{i} 不等");
        }

        // Merkle 哈希块:parse_hash32 恒等(哈希无语义转换)。
        let h = parse_hash32(&wire[..32]);
        assert_eq!(&h[..], &wire[..32]);

        eprintln!(
            "[A3-TDD1] 手动解析器 × {n} 随机域元素:三路一致 + 位置步进精确 ✓(差分对拍绿)"
        );
    }

    /// TDD 单元 2:混排流差分(域元素 40B × 哈希块 32B 交替=真实证明流形态)。
    /// 断言:混排下手动解析与 transcript 读逐块一致、位置算术逐块精确。
    #[test]
    fn a3_mixed_stream_differential() {
        use plonkish_backend::util::transcript::{FieldTranscriptRead, Output, TranscriptRead};

        let pairs = 500usize;
        let mut sm = crate::sm2_a7_props::SplitMix(0x00A3_BEEF);
        let mut wire = Vec::new();
        let mut fes = Vec::new();
        let mut hashes = Vec::new();
        for _ in 0..pairs {
            let fe = rnd_fe(&mut sm);
            wire.extend_from_slice(&wire_of(&fe));
            fes.push(fe);
            let mut h = [0u8; 32];
            for c in h.iter_mut() {
                *c = sm.next() as u8;
            }
            wire.extend_from_slice(&h);
            hashes.push(h);
        }

        // 路线一:手动解析(第二遍流式读法),位置算术逐块精确。
        let mut pos = 0usize;
        for i in 0..pairs {
            let fe = parse_field_element(&wire[pos..pos + FE_WIRE_LEN]).expect("fe 解析失败");
            assert_eq!(fe, fes[i], "混排 fe #{i} 不等");
            pos += FE_WIRE_LEN;
            assert_eq!(
                &parse_hash32(&wire[pos..pos + 32])[..],
                &hashes[i][..],
                "混排 hash #{i} 不等"
            );
            pos += 32;
        }
        assert_eq!(pos, wire.len(), "手动解析末位与流长不等");

        // 路线二:transcript 混排读(域元素+哈希承诺交替)。
        let mut tr = FiatShamirTranscript::<Sm3, Cursor<&[u8]>>::from_proof_ref((), &wire);
        for i in 0..pairs {
            let fe = FieldTranscriptRead::<FpSM2>::read_field_element(&mut tr).expect("tr fe");
            assert_eq!(fe, fes[i]);
            // 具名绑定消 E0283 多候选歧义;值直接与手植哈希比对。
            let h: Output<Sm3> = TranscriptRead::<Output<Sm3>, FpSM2>::read_commitment(&mut tr).expect("tr hash");
            assert_eq!(h.as_slice(), hashes[i].as_slice(), "读值 #{i} 不等");
        }
        assert_eq!(tr.stream_position(), wire.len(), "transcript 末位漂移");

        eprintln!(
            "[A3-TDD2] 混排流 × {pairs} 对(域元素 40B + 哈希 32B):手动==transcript,位置逐块精确 ✓"
        );
    }

    // =====================================================================
    // A3_SIZES(窗口二首件事):尺寸封闭式 × 真实 standalone 证明
    // =====================================================================

    use crate::sm2_a5_route_b::A5Spec;
    use plonkish_backend::{
        backend::{
            hyperplonk::HyperPlonk, PlonkishBackend as A3PlonkishBackend, PlonkishCircuit as A3PlonkishCircuit,
            PlonkishCircuitInfo as A3CircuitInfo,
        },
        pcs::multilinear::{Basefold as A3Basefold, BasefoldExtParams as _},
        util::transcript::{FieldTranscript, Output, Transcript as A3Tr, TranscriptRead as A3TrRead},
        Error as A3Error,
    };

    type A3Pcs = A3Basefold<FpSM2, Sm3, A5Spec>;
    type A3Pb = HyperPlonk<A3Pcs>;
    type A3T = SM3Transcript<Cursor<Vec<u8>>>;

    /// 读调用类别(调用粒度;域元素=40B/个,哈希=32B/个)。
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum CallKind {
        Fe,
        Hash,
    }

    #[derive(Clone, Debug)]
    struct A3Circuit {
        info: A3CircuitInfo<FpSM2>,
        advice: Vec<Vec<FpSM2>>,
        instances: Vec<Vec<FpSM2>>,
    }

    impl A3PlonkishCircuit<FpSM2> for A3Circuit {
        fn circuit_info_without_preprocess(&self) -> Result<A3CircuitInfo<FpSM2>, A3Error> {
            Ok(self.info.clone())
        }
        fn circuit_info(&self) -> Result<A3CircuitInfo<FpSM2>, A3Error> {
            Ok(self.info.clone())
        }
        fn instances(&self) -> &[Vec<FpSM2>] {
            &self.instances
        }
        fn synthesize(&self, round: usize, challenges: &[FpSM2]) -> Result<Vec<Vec<FpSM2>>, A3Error> {
            assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
            Ok(self.advice.clone())
        }
    }

    /// 记录式转录:委托 `FiatShamirTranscript<Sm3, Cursor<&[u8]>>`(零拷贝地基),
    /// 按**调用粒度**记录每次读(域元素/哈希 × n)。零后端改动;HyperPlonk verify
    /// 全程经由本包装 ⟹ 读序表(调用序列)完整可观测,位置由 Cursor 可观测。
    struct LogTranscript<'a> {
        inner: FiatShamirTranscript<Sm3, Cursor<&'a [u8]>>,
        events: Vec<(CallKind, usize)>,
    }

    impl<'a> LogTranscript<'a> {
        fn new(proof: &'a [u8]) -> Self {
            LogTranscript {
                inner: FiatShamirTranscript::<Sm3, Cursor<&'a [u8]>>::from_proof_ref((), proof),
                events: Vec::new(),
            }
        }
        fn pos(&self) -> usize {
            self.inner.stream_position()
        }
    }

    impl FieldTranscript<FpSM2> for LogTranscript<'_> {
        fn squeeze_challenge(&mut self) -> FpSM2 {
            FieldTranscript::<FpSM2>::squeeze_challenge(&mut self.inner)
        }
        fn common_field_element(&mut self, fe: &FpSM2) -> Result<(), A3Error> {
            FieldTranscript::<FpSM2>::common_field_element(&mut self.inner, fe)
        }
    }

    impl FieldTranscriptRead<FpSM2> for LogTranscript<'_> {
        fn read_field_element(&mut self) -> Result<FpSM2, A3Error> {
            let v = FieldTranscriptRead::<FpSM2>::read_field_element(&mut self.inner)?;
            self.events.push((CallKind::Fe, 1));
            Ok(v)
        }
        fn read_field_elements(&mut self, n: usize) -> Result<Vec<FpSM2>, A3Error> {
            let v = FieldTranscriptRead::<FpSM2>::read_field_elements(&mut self.inner, n)?;
            self.events.push((CallKind::Fe, n));
            Ok(v)
        }
    }

    impl A3Tr<Output<Sm3>, FpSM2> for LogTranscript<'_> {
        fn common_commitment(&mut self, c: &Output<Sm3>) -> Result<(), A3Error> {
            A3Tr::<Output<Sm3>, FpSM2>::common_commitment(&mut self.inner, c)
        }
    }

    impl A3TrRead<Output<Sm3>, FpSM2> for LogTranscript<'_> {
        fn read_commitment(&mut self) -> Result<Output<Sm3>, A3Error> {
            let v = A3TrRead::<Output<Sm3>, FpSM2>::read_commitment(&mut self.inner)?;
            self.events.push((CallKind::Hash, 1));
            Ok(v)
        }
        fn read_commitments(&mut self, n: usize) -> Result<Vec<Output<Sm3>>, A3Error> {
            let v = A3TrRead::<Output<Sm3>, FpSM2>::read_commitments(&mut self.inner, n)?;
            self.events.push((CallKind::Hash, n));
            Ok(v)
        }
    }

    fn a3_prove_and_verify(circ: &A3Circuit) -> (Vec<u8>, Vec<(CallKind, usize)>, usize, Result<(), A3Error>) {
        let param = A3Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = A3Pb::preprocess(&param, &circ.circuit_info().unwrap()).unwrap();
        let proof = {
            let mut tr = A3T::new(());
            A3Pb::prove(&pp, circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let (events, pos, verdict) = {
            let mut lt = LogTranscript::new(&proof);
            let verdict = A3Pb::verify(&vp, &circ.instances, &mut lt, StdRng::seed_from_u64(0x5EED + 2));
            let pos = lt.pos();
            (lt.events, pos, verdict)
        };
        (proof, events, pos, verdict)
    }

    /// 逆序消费期望:(类别,n);不匹配即 panic(带段名)。
    fn expect_call(ev: &[(CallKind, usize)], i: &mut usize, k: CallKind, n: usize, what: &str) {
        assert!(*i > 0, "{what}: 事件流提前耗尽(逆序)");
        *i -= 1;
        assert_eq!(ev[*i], (k, n), "{what}: 期望 ({k:?},{n}) 实得 {:?}", ev[*i]);
    }

    /// 逆序走表的拟合与定位结果。
    #[derive(Clone, Copy, Debug)]
    struct A3Fit {
        /// |evals|(OFF)或 n_slots(去重档)。
        e: usize,
        n_comms: usize,
        /// PCS 段在证明字节流中的绝对起点/终点。
        pcs_start: usize,
        pcs_end: usize,
    }

    /// 封闭式 × 真实证明的逆序逐段核对(单独成函数以便 OFF/ON 两档复用)。
    fn a3_analyze(
        tag: &str,
        proof: &[u8],
        ev: &[(CallKind, usize)],
        final_pos: usize,
        nv: usize,
        lr: usize,
        nr: usize,
        q: usize,
    ) -> A3Fit {
        let fe = FE_WIRE_LEN;
        let h = HASH_CHUNK_LEN;

        // 前向位置表:pos[i] = 第 i 个事件前的字节位置。
        let mut pos = Vec::with_capacity(ev.len() + 1);
        let mut p = 0usize;
        pos.push(0);
        for &(k, n) in ev {
            p += match k {
                CallKind::Fe => fe * n,
                CallKind::Hash => h * n,
            };
            pos.push(p);
        }

        let mut i = ev.len();

        // drain(Transcript 尾部消费循环,hyperplonk.rs:464-467):尾部 32B 块连读。
        let end_drain = i;
        while i > 0 && ev[i - 1] == (CallKind::Hash, 1) {
            i -= 1;
        }
        let d = end_drain - i;
        // PCS 段终点 = drain 起点(S11 末事件之后的位置)——须在消费 S11 之前取。
        let pcs_end = pos[i];

        // S11 查询层路径:正向每查询 [Comm(2(nv+lr-1-r))] for r=0..=nr(由大到小);
        // 逆序消费 ⟹ 轮序反转(先 r=nr 的最小块)。
        for _ in 0..q {
            for r in (0..=nr).rev() {
                expect_call(ev, &mut i, CallKind::Hash, 2 * (nv + lr - 1 - r), "S11 查询路径");
            }
        }

        // S10 all_qs:单调用 Fe(Q·2(nr+1))。
        expect_call(ev, &mut i, CallKind::Fe, q * 2 * (nr + 1), "S10 all_qs");
        // S9 final_oracle:**域元素**(40B;检查点表格"32B 哈希"系笔误,代码为权威)。
        expect_call(ev, &mut i, CallKind::Fe, 1 << (nv - nr + lr), "S9 final_oracle");
        // S8 联合 eval:1 域元素。
        expect_call(ev, &mut i, CallKind::Fe, 1, "S8 eval");

        // S7 个体 Merkle 路径连跑:Comm(2(nv+lr)) × q·E;由整除性拟合 E。
        let s7_run_end = i;
        while i > 0 && ev[i - 1] == (CallKind::Hash, 2 * (nv + lr)) {
            i -= 1;
        }
        let l7 = s7_run_end - i;
        assert!(l7 > 0 && l7 % q == 0, "S7 连跑长 {l7} 必须被 q={q} 整除且非零");
        let e_fit = l7 / q;
        for _ in 0..(q * e_fit) {
            expect_call(ev, &mut i, CallKind::Fe, 2, "S6 ind_queries");
        }

        // S5 bh_evals+eq(仅 nr<nv;A5Spec 下 nr=nv ⟹ 无)。
        if nr < nv {
            expect_call(ev, &mut i, CallKind::Fe, 1 << (nv - nr), "S5 bh_evals");
            expect_call(ev, &mut i, CallKind::Fe, 1 << (nv - nr), "S5 eq");
        }
        // S4 末轮 fold oracle。
        expect_call(ev, &mut i, CallKind::Fe, 3, "S4 末轮 oracle");
        // S3 折叠轮(逆序:每轮 Fe(3) 后跟 (盐,根) 两哈希)。
        for _ in 0..nr {
            expect_call(ev, &mut i, CallKind::Fe, 3, "S3 轮 oracle");
            expect_call(ev, &mut i, CallKind::Hash, 1, "S3 轮根");
            expect_call(ev, &mut i, CallKind::Hash, 1, "S3 轮盐");
        }
        // S2 批量 sumcheck:nv 轮 × Fe(3)。
        for _ in 0..nv {
            expect_call(ev, &mut i, CallKind::Fe, 3, "S2 批量 sumcheck 轮");
        }
        // S1 头部对齐:每承诺 (盐,根) 两哈希;前缀最后一读=zero_check 的 m_y Fe(1) ⟹ 连跑有界。
        let s1_run_end = i;
        while i > 0 && ev[i - 1] == (CallKind::Hash, 1) {
            i -= 1;
        }
        let l1 = s1_run_end - i;
        assert!(l1 > 0 && l1 % 2 == 0, "S1 连跑长 {l1} 必须为非零偶数");
        let n_comms = l1 / 2;
        let pcs_start = pos[i];

        // ===== 核心断言:封闭式 == 实测 =====
        let sz = A3Sizes::new(nv, lr, nr, q, n_comms, e_fit);
        assert_eq!(
            pcs_end - pcs_start,
            sz.total(),
            "{tag} PCS 段字节总账({})与封闭式({})不等",
            pcs_end - pcs_start,
            sz.total()
        );
        assert_eq!(final_pos, pos[ev.len()], "{tag} 终值与事件账位置不一致");
        assert_eq!(
            final_pos,
            pcs_end + h * d,
            "{tag} 终值 ≠ PCS 段终点 + drain(32B×{d})"
        );
        assert!(proof.len() >= final_pos && proof.len() - final_pos < 32,
            "{tag} 尾部残留应 <32B(drain 停止条件):尾={} 终值={final_pos}",
            proof.len() - final_pos);

        // ===== 域元素段指纹:前 8B 恒零 + 手动解析器逐元素通过 =====
        let mut fe_check = |off: usize, cnt: usize, name: &str| {
            for k in 0..cnt {
                let o = pcs_start + off + k * fe;
                let w = &proof[o..o + fe];
                assert!(
                    w[..8].iter().all(|&b| b == 0),
                    "{tag} {name} 第 {k} 个域元素 wire 前 8 字节非零(偏移漂移?)"
                );
                assert!(parse_field_element(w).is_some(), "{tag} {name} 第 {k} 个域元素解析被拒");
            }
        };
        fe_check(sz.seg_off(A3Seg::S6IndQueries), q * e_fit * 2, "S6 ind_queries");
        fe_check(sz.seg_off(A3Seg::S9FinalOracle), 1 << (nv - nr + lr), "S9 final_oracle");
        fe_check(sz.seg_off(A3Seg::S2BatchSumcheck), nv * 3, "S2 批量 sumcheck");
        fe_check(sz.seg_off(A3Seg::S4FinalFoldOracle), 3, "S4 末轮 oracle");
        fe_check(sz.seg_off(A3Seg::S8Eval), 1, "S8 eval");
        fe_check(sz.seg_off(A3Seg::S10AllQs), q * 2 * (nr + 1), "S10 all_qs");
        if nr < nv {
            fe_check(sz.seg_off(A3Seg::S5BhEq), 2 * (1 << (nv - nr)), "S5 bh/eq");
        }
        for r in 0..nr {
            let off = sz.seg_off(A3Seg::S3FoldRounds) + r * (2 * h + 3 * fe) + 2 * h;
            fe_check(off, 3, "S3 轮 oracle");
        }

        eprintln!(
            "[A3-SIZES:{tag}] nv={nv} lr={lr} nr={nr} q={q} n_comms={n_comms} evals/slots={e_fit}"
        );
        eprintln!(
            "[A3-SIZES:{tag}] 段字节: S1={} S2={} S3={} S4={} S5={} S6={} S7={} S8={} S9={} S10={} S11={} | 总={}",
            sz.seg_len(A3Seg::S1Header), sz.seg_len(A3Seg::S2BatchSumcheck),
            sz.seg_len(A3Seg::S3FoldRounds), sz.seg_len(A3Seg::S4FinalFoldOracle),
            sz.seg_len(A3Seg::S5BhEq), sz.seg_len(A3Seg::S6IndQueries),
            sz.seg_len(A3Seg::S7BatchPaths), sz.seg_len(A3Seg::S8Eval),
            sz.seg_len(A3Seg::S9FinalOracle), sz.seg_len(A3Seg::S10AllQs),
            sz.seg_len(A3Seg::S11QueryPaths), sz.total()
        );
        eprintln!(
            "[A3-SIZES:{tag}] pcs_start={pcs_start} pcs_end={pcs_end} proof_len={} final_pos={final_pos} drain(32B×{d})={}",
            proof.len(),
            h * d
        );
        A3Fit { e: e_fit, n_comms, pcs_start, pcs_end }
    }

    /// A3_SIZES 主测试:OFF 与 去重(PCS_BATCH_DEDUP)两档,各 prove+verify 一轮,
    /// 封闭式读序表对真实证明逐段核对。单测试独占进程 env(与 A5 同法,勿并行跑 A5)。
    #[test]
    fn a3_sizes_closed_form_real_proof() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_BATCH_DEDUP"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
        let child = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(run_sizes_inner)
            .expect("起 256MB 栈工作线程失败");
        match child.join() {
            Ok(()) => {}
            Err(boxed) => std::panic::resume_unwind(boxed),
        }
    }

    fn run_sizes_inner() {
        let (e, r, s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
        let asm = crate::sm2_verify_assemble::assemble_sm2_verify(e, r, s, pax, pay);
        assert_eq!(asm.info.constraints.len(), 10_424, "standalone 形状漂移（2026-10-01 实测钉：旧钉 16,560 系修复后历史口径，db0bbb3 实测已漂移至 10,489[历史批次 legacy 面未回写]；本次换代 acc.chain 去重 −65=EG 窗 66→1 → 10,424）");
        let nv = asm.info.k;
        let lr = A5Spec::get_rate();
        let q = A5Spec::get_reps();
        assert_eq!(A5Spec::get_basecode_rounds(), 0, "nr=nv 推导依赖 basecode_rounds=0");
        let nr = nv; // setup: num_rounds = num_vars − basecode_rounds(basefold.rs:257)
        let circ = A3Circuit {
            info: asm.info.clone(),
            advice: asm.advice.clone(),
            instances: asm.instances.clone(),
        };

        // ① OFF 档(默认路径=现行字节级行为)。
        std::env::remove_var("PCS_BATCH_DEDUP");
        let (proof_off, ev_off, pos_off, v_off) = a3_prove_and_verify(&circ);
        assert!(v_off.is_ok(), "OFF 档验证失败(基线必须 Ok)");
        let fit_off = a3_analyze("OFF", &proof_off, &ev_off, pos_off, nv, lr, nr, q);
        let (e_off, n_comms) = (fit_off.e, fit_off.n_comms);

        // ② 去重档:期望序列以 n_slots 为 E 变体;槽位数必须严格更少。
        std::env::set_var("PCS_BATCH_DEDUP", "1");
        let (proof_on, ev_on, pos_on, v_on) = a3_prove_and_verify(&circ);
        assert!(v_on.is_ok(), "去重档验证失败");
        let fit_on = a3_analyze("ON ", &proof_on, &ev_on, pos_on, nv, lr, nr, q);
        let (e_slots, n_comms_on) = (fit_on.e, fit_on.n_comms);
        std::env::remove_var("PCS_BATCH_DEDUP");

        assert_eq!(n_comms, n_comms_on, "两档承诺数必须一致");
        assert!(e_slots < e_off, "去重档槽位数({e_slots})应严格小于 OFF 的 |evals|({e_off})");
        eprintln!(
            "[A3-SIZES] 封闭式×真实证明两档全对账:|evals|={e_off} n_slots={e_slots} n_comms={n_comms} \
             proof OFF={} ON={}",
            proof_off.len(),
            proof_on.len()
        );
    }

    // =====================================================================
    // 攻击面探针(2026-09-16):个体开口 Merkle 路径的根链是否被验证
    // =====================================================================

    /// 读侧 batch_verify 对个体开口用 `authenticate_merkle_path`(无根链版:循环在
    /// i+1==len 处 break,从不把"根之两子节点对"哈希后与 root 比对)+ `pop().pop()==root`
    /// 声明式比对。若根链缺失,篡改根子节点对中**非路径侧**的兄弟元素应被接受(缺陷);
    /// 正确实现(如 `_root` 版)必须拒绝。对照组:叶层对篡改(链检必拒)、(root,root)
    /// 声明块篡改(声明比对必拒);末轮折叠路径末字节(verifier_query_phase 循环
    /// 0..num_rounds 不认证末轮 ⟹ 死数据)仅记录现状。
    #[test]
    fn a3_probe_indiv_path_root_link() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_BATCH_DEDUP"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
        let child = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(run_root_link_probe)
            .expect("起 256MB 栈工作线程失败");
        match child.join() {
            Ok(()) => {}
            Err(boxed) => std::panic::resume_unwind(boxed),
        }
    }

    fn run_root_link_probe() {
        let (e, r, s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
        let asm = crate::sm2_verify_assemble::assemble_sm2_verify(e, r, s, pax, pay);
        assert_eq!(asm.info.constraints.len(), 10_424, "standalone 形状漂移（2026-10-01 实测钉：旧钉 16,560 系修复后历史口径，db0bbb3 实测已漂移至 10,489[历史批次 legacy 面未回写]；本次换代 acc.chain 去重 −65=EG 窗 66→1 → 10,424）");
        let nv = asm.info.k;
        let lr = A5Spec::get_rate();
        let q = A5Spec::get_reps();
        assert_eq!(A5Spec::get_basecode_rounds(), 0);
        let nr = nv;
        let circ = A3Circuit {
            info: asm.info.clone(),
            advice: asm.advice.clone(),
            instances: asm.instances.clone(),
        };
        std::env::remove_var("PCS_BATCH_DEDUP");

        let param = A3Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = A3Pb::preprocess(&param, &circ.circuit_info().unwrap()).unwrap();
        let proof = {
            let mut tr = A3T::new(());
            A3Pb::prove(&pp, &circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };

        // 定位:记录式转录一次 → PCS 段起点与拟合参数。
        let (ev, pos, v) = {
            let mut lt = LogTranscript::new(&proof);
            let v = A3Pb::verify(&vp, &circ.instances, &mut lt, StdRng::seed_from_u64(0x5EED + 2));
            let pos = lt.pos();
            (lt.events, pos, v)
        };
        assert!(v.is_ok(), "诚实证明必须 Ok");
        let fit = a3_analyze("PROBE", &proof, &ev, pos, nv, lr, nr, q);
        let sz = A3Sizes::new(nv, lr, nr, q, fit.n_comms, fit.e);

        // 查询 0 / 开口 0 的个体路径:2(nv+lr) 哈希 = (nv+lr) 对;对 k 的元素 j 在
        // path0 + (2k+j)·32。顶端对 (root,root) = 对 nv+lr−1;根之两子节点对 = 对 nv+lr−2。
        let h = HASH_CHUNK_LEN;
        let path0 = fit.pcs_start + sz.seg_off(A3Seg::S7BatchPaths);
        let pairs = nv + lr;
        let at = |pair: usize, elem: usize| path0 + (2 * pair + elem) * h;

        let verify_tampered = |off: usize| -> bool {
            let mut pf = proof.clone();
            pf[off] ^= 0xFF;
            let vp = &vp;
            let circ = &circ;
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut tr = A3T::from_proof((), pf.as_slice());
                A3Pb::verify(vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
            }));
            matches!(r, Ok(true))
        };

        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let acc_child0 = verify_tampered(at(pairs - 2, 0));
        let acc_child1 = verify_tampered(at(pairs - 2, 1));
        let acc_leaf0 = verify_tampered(at(0, 0));
        let acc_rootdecl = verify_tampered(at(pairs - 1, 1));
        let acc_lastbyte = verify_tampered(proof.len() - 1);
        std::panic::set_hook(prev_hook);

        eprintln!(
            "[A3-PROBE 根链] 根子节点对 elem0 接受={acc_child0} elem1 接受={acc_child1} | \
             对照:叶层对 elem0 接受={acc_leaf0} (root,root) 声明块 elem1 接受={acc_rootdecl} | \
             末轮折叠路径末字节 接受={acc_lastbyte}(死数据现状记录)"
        );
        assert!(!acc_leaf0, "对照失败:叶层篡改竟被接受");
        assert!(!acc_rootdecl, "对照失败:(root,root) 声明块篡改竟被接受");
        assert!(
            !acc_child0 && !acc_child1,
            "🔴 根链缺失:根之子节点对篡改被接受(elem0={acc_child0}, elem1={acc_child1})——\
             个体开口路径未与 root 哈希链接(authenticate_merkle_path 无末端校验)"
        );
    }

    // =====================================================================
    // A3 单元 3(2026-09-16):两遍流式验证器——OFF vs STREAM 对照 + 负例族 + 去重×流式
    // =====================================================================

    use plonkish_backend::util::transcript::{a3_stream, SM3StreamTranscript};

    /// 单元 3:PCS_VERIFY_STREAM=1(线程局部回放源 + StreamTranscript + 封闭式区间第二遍)
    /// 与默认档的验证结论逐例相同:诚实证明两档 Ok 且终值一致;五类篡改两档同拒
    /// (S6 叶值/S7 叶层对/S7 根子节点兄弟(P0 守卫)/FS 首字节/去重档错位组合)。
    #[test]
    fn a3_stream_two_pass_standalone() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_BATCH_DEDUP", "PCS_VERIFY_STREAM"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
        let child = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(run_stream_inner)
            .expect("起 256MB 栈工作线程失败");
        match child.join() {
            Ok(()) => {}
            Err(boxed) => std::panic::resume_unwind(boxed),
        }
    }

    fn run_stream_inner() {
        let (e, r, s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
        let asm = crate::sm2_verify_assemble::assemble_sm2_verify(e, r, s, pax, pay);
        assert_eq!(asm.info.constraints.len(), 10_424, "standalone 形状漂移（2026-10-01 实测钉：旧钉 16,560 系修复后历史口径，db0bbb3 实测已漂移至 10,489[历史批次 legacy 面未回写]；本次换代 acc.chain 去重 −65=EG 窗 66→1 → 10,424）");
        let nv = asm.info.k;
        let lr = A5Spec::get_rate();
        let q = A5Spec::get_reps();
        assert_eq!(A5Spec::get_basecode_rounds(), 0);
        let nr = nv;
        let circ = A3Circuit {
            info: asm.info.clone(),
            advice: asm.advice.clone(),
            instances: asm.instances.clone(),
        };
        let h = HASH_CHUNK_LEN;
        let fe = FE_WIRE_LEN;

        let prove = |circ: &A3Circuit| {
            let param = A3Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x5EED)).unwrap();
            let (pp, vp) = A3Pb::preprocess(&param, &circ.circuit_info().unwrap()).unwrap();
            let proof = {
                let mut tr = A3T::new(());
                A3Pb::prove(&pp, circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
                tr.into_proof()
            };
            (vp, proof)
        };

        // 默认档判定(from_proof 复制路径);true = 接受。
        macro_rules! verify_off {
            ($vp:expr, $pf:expr) => {{
                let vp = &$vp;
                let circ = &circ;
                let pf: &[u8] = &$pf;
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut tr = A3T::from_proof((), pf);
                    A3Pb::verify(vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
                }));
                matches!(r, Ok(true))
            }};
        }
        // 流式档判定(注册回放源 + StreamTranscript);返回 (接受?, 终值)。
        macro_rules! verify_stream {
            ($vp:expr, $pf:expr) => {{
                let vp = &$vp;
                let circ = &circ;
                let src = std::sync::Arc::new($pf);
                std::env::set_var("PCS_VERIFY_STREAM", "1");
                a3_stream::register(src.clone());
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut tr = SM3StreamTranscript::new(&src[..]);
                    let ok = A3Pb::verify(vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok();
                    (ok, tr.stream_position())
                }));
                a3_stream::clear();
                std::env::remove_var("PCS_VERIFY_STREAM");
                match r {
                    Ok((ok, pos)) => (ok, pos),
                    Err(_) => (false, 0),
                }
            }};
        }

        // ================= OFF 证明:诚实对照 + 负例族 =================
        std::env::remove_var("PCS_BATCH_DEDUP");
        let (vp_off, proof_off) = prove(&circ);
        let (ev, pos_log, v) = {
            let mut lt = LogTranscript::new(&proof_off);
            let v = A3Pb::verify(&vp_off, &circ.instances, &mut lt, StdRng::seed_from_u64(0x5EED + 2));
            let pos = lt.pos();
            (lt.events, pos, v)
        };
        assert!(v.is_ok(), "诚实证明(记录式)必须 Ok");
        let fit = a3_analyze("S3-OFF", &proof_off, &ev, pos_log, nv, lr, nr, q);
        let sz = A3Sizes::new(nv, lr, nr, q, fit.n_comms, fit.e);

        assert!(verify_off!(vp_off, proof_off), "诚实证明默认档必须 Ok");
        let (ok_s, pos_s) = verify_stream!(vp_off, proof_off.clone());
        assert!(ok_s, "诚实证明流式档必须 Ok");
        assert_eq!(pos_s, pos_log, "流式档终值须与记录式终值一致");
        eprintln!("[A3-S3] 诚实 standalone:OFF Ok / STREAM Ok,终值一致 {pos_s}(proof_len={})", proof_off.len());

        let s6 = fit.pcs_start + sz.seg_off(A3Seg::S6IndQueries);
        let s7 = fit.pcs_start + sz.seg_off(A3Seg::S7BatchPaths);
        let pairs = nv + lr;
        let negatives: [(&str, usize); 4] = [
            ("S6 q0/slot0 叶值字节(偏移8)", s6 + 8),
            ("S7 q0/slot0 叶层对 elem0", s7),
            ("S7 q0/slot0 根子节点对 elem1(P0 守卫)", s7 + (2 * (pairs - 2) + 1) * h),
            ("FS 首字节", 0),
        ];
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        for (name, off) in negatives.iter() {
            let mut pf = proof_off.clone();
            pf[*off] ^= 0xFF;
            let acc_off = verify_off!(vp_off, pf);
            let (acc_stream, _) = verify_stream!(vp_off, pf);
            eprintln!("[A3-S3] 负例 {name}:OFF 接受={acc_off} STREAM 接受={acc_stream}");
            assert!(!acc_off, "负例 {name} 默认档竟接受");
            assert!(!acc_stream, "负例 {name} 流式档竟接受");
        }
        std::panic::set_hook(prev_hook);

        // ================= 去重档 × 流式 + 错位组合负例 =================
        std::env::set_var("PCS_BATCH_DEDUP", "1");
        let (vp_on, proof_on) = prove(&circ);
        let (ev_on, pos_on, v_on) = {
            let mut lt = LogTranscript::new(&proof_on);
            let v = A3Pb::verify(&vp_on, &circ.instances, &mut lt, StdRng::seed_from_u64(0x5EED + 2));
            let pos = lt.pos();
            (lt.events, pos, v)
        };
        assert!(v_on.is_ok(), "去重档诚实证明(记录式)必须 Ok");
        let fit_on = a3_analyze("S3-ON ", &proof_on, &ev_on, pos_on, nv, lr, nr, q);
        let sz_on = A3Sizes::new(nv, lr, nr, q, fit_on.n_comms, fit_on.e);
        assert!(verify_off!(vp_on, proof_on), "去重档默认读法必须 Ok");
        let (ok_on_s, pos_on_s) = verify_stream!(vp_on, proof_on.clone());
        assert!(ok_on_s, "去重档 × 流式必须 Ok");
        assert_eq!(pos_on_s, pos_on, "去重×流式终值须与记录式终值一致");
        eprintln!("[A3-S3] 去重×流式:Ok,终值一致 {pos_on_s}(proof_len={})", proof_on.len());

        // 错位组合(路线 b 负例):交换查询 0 中两个叶值互异槽位的 S6 块 ⟹ 值与树不再对应,两档必拒。
        let s6_on = fit_on.pcs_start + sz_on.seg_off(A3Seg::S6IndQueries);
        let blk = 2 * fe;
        let block = |slot: usize| &proof_on[s6_on + slot * blk..s6_on + (slot + 1) * blk];
        let mut pair = None;
        'outer: for a in 0..fit_on.e {
            for b in (a + 1)..fit_on.e.min(a + 64) {
                if block(a) != block(b) {
                    pair = Some((a, b));
                    break 'outer;
                }
            }
        }
        let (sa, sb) = pair.expect("找不到叶值互异的两个槽位(异常:全部槽位同值)");
        let mut pf = proof_on.clone();
        let (ba, bb) = (block(sa).to_vec(), block(sb).to_vec());
        pf[s6_on + sa * blk..s6_on + (sa + 1) * blk].copy_from_slice(&bb);
        pf[s6_on + sb * blk..s6_on + (sb + 1) * blk].copy_from_slice(&ba);
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let acc_off = verify_off!(vp_on, pf);
        let (acc_stream, _) = verify_stream!(vp_on, pf);
        std::panic::set_hook(prev_hook);
        std::env::remove_var("PCS_BATCH_DEDUP");
        eprintln!("[A3-S3] 负例 错位组合(槽 {sa}↔{sb}):OFF 接受={acc_off} STREAM 接受={acc_stream}");
        assert!(!acc_off && !acc_stream, "错位组合竟被接受(OFF={acc_off} STREAM={acc_stream})");

        eprintln!(
            "[A3-S3] 单元 3 全绿:诚实两档同 Ok+终值一致;负例 5 类两档同拒;去重×流式 Ok(n_slots={} vs |evals|={})",
            fit_on.e, fit.e
        );
    }

    // =====================================================================
    // 分相修复守卫(2026-09-16):公共承诺盐确定性 × 见证承诺盐新鲜性
    // =====================================================================

    /// `batch_commit_public`(预处理/公共参数)同种子两次调用 ⟹ 盐与根逐字节相同(跨进程可复现);
    /// `batch_commit`(见证路径)两次调用 ⟹ 盐与根必异(T1.3b 指纹修复的新鲜盐语义不动);
    /// 同一 setup 下 domain 0/1 两条盐链互异。
    #[test]
    fn a3_public_salt_determinism_and_witness_freshness() {
        use plonkish_backend::pcs::PolynomialCommitmentScheme as _;
        use plonkish_backend::poly::multilinear::MultilinearPolynomial;
        let nv = 6usize;
        let mk = || {
            let param = A3Pcs::setup(1 << nv, 1, StdRng::seed_from_u64(0xA3_5A17)).unwrap();
            A3Pcs::trim(&param, 1 << nv, 1).unwrap()
        };
        let (pp1, _) = mk();
        let (pp2, _) = mk();
        let poly = MultilinearPolynomial::<FpSM2>::rand(nv, StdRng::seed_from_u64(7));
        let polys = [&poly, &poly];
        type A3Comm = <A3Pcs as plonkish_backend::pcs::PolynomialCommitmentScheme<FpSM2>>::Commitment;
        let root_bytes = |c: &A3Comm| -> Vec<u8> { AsRef::<[Output<Sm3>]>::as_ref(c)[0].as_slice().to_vec() };

        let pub_a = A3Pcs::batch_commit_public(&pp1, 0, polys).unwrap();
        let pub_b = A3Pcs::batch_commit_public(&pp2, 0, polys).unwrap();
        for (a, b) in pub_a.iter().zip(pub_b.iter()) {
            assert_eq!(a.salt.as_slice(), b.salt.as_slice(), "公共承诺盐跨 setup 实例不可复现");
            assert_eq!(root_bytes(a), root_bytes(b), "公共承诺根不可复现");
        }
        assert_ne!(pub_a[0].salt.as_slice(), pub_a[1].salt.as_slice(), "同链两多项式盐应互异");
        let pub_d1 = A3Pcs::batch_commit_public(&pp1, 1, polys).unwrap();
        assert_ne!(pub_a[0].salt.as_slice(), pub_d1[0].salt.as_slice(), "domain 0/1 盐链应互异");

        let wit_a = A3Pcs::batch_commit(&pp1, polys).unwrap();
        let wit_b = A3Pcs::batch_commit(&pp1, polys).unwrap();
        assert_ne!(wit_a[0].salt.as_slice(), wit_b[0].salt.as_slice(), "见证承诺盐竟可复现(新鲜性丢失)");
        assert_ne!(root_bytes(&wit_a[0]), root_bytes(&wit_b[0]), "见证承诺根竟相同(指纹通道复活)");
        eprintln!("[A3-SALT] 公共承诺确定性 ✓ / domain 分离 ✓ / 见证承诺新鲜 ✓");
    }
}
