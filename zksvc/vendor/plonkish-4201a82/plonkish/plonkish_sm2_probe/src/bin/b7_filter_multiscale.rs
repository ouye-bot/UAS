// B7 · V₂ 位面多档过滤实验（2026-09-11；十三项方案 item B7）
// 问题：单次出示可读位面（124 个单比特列）对属性候选集的真实过滤率——
// 现行论文启发口径为 |B|·2^−130（130=一次差分的敏感坐标数），但可读位面=124 位，
// 两个数的混同是 D10 修复未覆盖的残余口径问题。本实验逐档实测过滤曲线，
// 回答「过滤率是否与 |B|·2^−m 吻合（m=可读位面宽度）」。
// 布局自检：attrs 在 block1[1..33]（block1 = par(1)‖attrs(32)‖pk_u.x 前 31B）。
// 运行：cargo run --release -p plonkish_sm2_probe --bin b7_filter_multiscale
use plonkish_sm2_probe::sm2_full_statement_assemble::{
    full_statement_host, witness_from, PRED_TARGET,
};
use plonkish_sm2_probe::sm3_native_ref::{compress, IV};
use std::time::Instant;

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

/// v2 = compress(v1, block1)（第二块出口链态）；v1 = compress(IV, block0)。
fn v2_of(v1: &[u32; 8], block1: &[u8; 64]) -> [u32; 8] {
    compress(v1, block1)
}

/// 取 v2 的第 b 位（b∈0..256；word=b/32，word 内位 b%32，MSB-first 与 SM3 词序一致）。
fn bit_of(v2: &[u32; 8], b: usize) -> bool {
    (v2[b / 32] >> (31 - b % 32)) & 1 == 1
}

fn main() {
    let mut sm = SplitMix(0xB7_2026_0911);
    // ── 布局自检：witness_from(PRED_TARGET) 的 blocks 里定位 attrs 模板 ──
    let w = witness_from([0x0A1B_2C3D_4E5F_6071, 0x8293_A4B5_C6D7_E8F9, 0x11, 0x22], [7u8; 32], [0x33; 4]);
    let host = full_statement_host(&w);
    let blocks = host.blocks;
    let mut attrs_off: Option<(usize, usize)> = None; // (block_idx, byte_off)
    for bi in 0..3 {
        for off in 0..=64 - 32 {
            if blocks[bi][off..off + 32] == PRED_TARGET {
                attrs_off = Some((bi, off));
            }
        }
    }
    let (ab_idx, ab_off) = attrs_off.expect("attrs 模板未在 blocks 中定位到");
    assert_eq!((ab_idx, ab_off), (1, 0), "布局自检：attrs 应在 block1[0..32]（par 字节在 block0 尾）");
    println!("[B7] 布局自检 OK：attrs @ block{ab_idx}[{ab_off}..+32]（attrs ‖ pk_u.x；par 在 block0 尾）");

    // ── v1 固定于一个诚实用户；差分斑点对照（attrs A vs B 的 v2 翻转位数）──
    let v1 = compress(&IV, &blocks[0]);
    let v2_base = v2_of(&v1, &blocks[1]);
    let mut block_b = blocks;
    let mut attrs_alt = PRED_TARGET;
    attrs_alt[0] ^= 0xFF;
    block_b[ab_idx][ab_off..ab_off + 32].copy_from_slice(&attrs_alt);
    let v2_alt = v2_of(&v1, &block_b[1]);
    let flip: u32 = (0..256).filter(|&b| bit_of(&v2_base, b) != bit_of(&v2_alt, b)).count() as u32;
    println!("[B7] 差分斑点对照：attrs 单字节翻转 ⟹ v2 翻转 {flip}/256 位（论文差分量级 130/256 一致性参照）");

    // ── 多档过滤实验 ──
    let ms_ladder = [64usize, 124, 130, 256];
    let bs_ladder = [16usize, 20, 24]; // |B| = 2^k
    let mut total_cand = 0u64;
    let t0 = Instant::now();
    println!("[B7] 过滤曲线（survivors/total vs |B|·2^−m；ratio≈1 ⟹ 启发成立）");
    println!("m\tlog2|B|\ttrials\tcandidates\tsurvivors\texpected\t ratio");
    for &m in ms_ladder.iter() {
        // 观测位置：确定性采样 m 个互异位
        let mut pos = Vec::with_capacity(m);
        let mut used = [false; 256];
        while pos.len() < m {
            let b = (sm.next() % 256) as usize;
            if !used[b] {
                used[b] = true;
                pos.push(b);
            }
        }
        for &lb in bs_ladder.iter() {
            let bsize = 1u64 << lb;
            let trials = ((1u64 << 24) / bsize).clamp(4, 65_536) as usize;
            let mut survivors: u64 = 0;
            let mut cands: u64 = 0;
            for tr in 0..trials {
                // 诚实用户（逐 trial 换 id/sk/attrs 真值）
                let w_t = witness_from(
                    [sm.next(), sm.next(), sm.next(), sm.next()],
                    {
                        let mut id = [0u8; 32];
                        for c in id.iter_mut() { *c = sm.next() as u8; }
                        id
                    },
                    [sm.next(), sm.next(), sm.next(), sm.next()],
                );
                let h_t = full_statement_host(&w_t);
                let v1_t = compress(&IV, &h_t.blocks[0]);
                let v2_t = v2_of(&v1_t, &h_t.blocks[1]);
                let observed: Vec<bool> = pos.iter().map(|&b| bit_of(&v2_t, b)).collect();
                // 真值 attrs（供对照；随机候选命中真值概率 2^-256 可忽略）
                let true_attrs = h_t.blocks[1][0..32].to_vec();
                // 候选集：|B| 个随机非真值 attrs
                let mut block_c = h_t.blocks[1];
                for _ in 0..bsize {
                    let mut attrs_c = [0u8; 32];
                    for c in attrs_c.iter_mut() { *c = sm.next() as u8; }
                    if attrs_c == true_attrs[..] { attrs_c[0] ^= 1; }
                    block_c[0..32].copy_from_slice(&attrs_c);
                    let v2_c = v2_of(&v1_t, &block_c);
                    if pos.iter().zip(observed.iter()).all(|(&b, &ob)| bit_of(&v2_c, b) == ob) {
                        survivors += 1;
                    }
                    cands += 1;
                }
            }
            total_cand += cands;
            let expected = (cands as f64) * 2f64.powi(-(m as i32));
            let ratio = if expected >= 1.0 { survivors as f64 / expected } else { f64::NAN };
            println!("{m}\t{lb}\t{trials}\t{cands}\t{survivors}\t{expected:.3}\t{:.3}", ratio);
        }
    }
    println!("[B7] 总候选评测数 {total_cand}，耗时 {:.1}s", t0.elapsed().as_secs_f64());
}
