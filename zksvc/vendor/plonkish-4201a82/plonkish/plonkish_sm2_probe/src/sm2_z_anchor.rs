//! 1.1d 锚点绑定 · 簇F：Z_U 的 native 层（蓝图 `M3_probe/Z_ANCHOR_BLUEPRINT.md`）。
//!
//! `Z_U = SM3(ENTLA ‖ ID_u ‖ a ‖ b ‖ Gx ‖ Gy ‖ x_A ‖ y_A)`，GB/T 32918.2 §5.5
//! 用户身份哈希。序列化纪律（L2 红线）：一切字节只从「域元素 → LE limbs →
//! 每 limb 大端字节」机械导出（[`fe_be32`]），字符串常量仅作测试对拍源，
//! 永不进入电路真值路径。
//!
//! 对拍三层：①本文件自回环（A.2 权威坐标 hex ↔ fe_be32）；②曲线常量
//! 恒等式（a = p−3、P_A 在曲线上——簇C/M1c 已验证的函数直接复用）；
//! ③摘要值与外部实现（python gmssl）一次性比对后**锁定为测试常量**。

use crate::sm2_ec_plonkish::{curve_a, curve_b, g_coords};
use crate::sm2_params::fr_to_limbs;
use crate::FpSM2;

/// 域元素 → 32 字节大端（GB/T 序列化口径）。
///
/// 字节流布局纪律：repr 字节流 = limb 升序 × 每 limb LE（[`fr_to_limbs`] 与
/// m0 `from_limbs` 两源一致）；整数 BE = **最高位 limb 在前** ⟹ 输出第 k 段
/// 放倒数第 k+1 个 limb 的 8 字节 BE 序。与 m0 `f_be`（M2c 已验证先例，
/// be32_to_limbs 注释同款方向约定）语义对齐。
pub fn fe_be32(v: &FpSM2) -> [u8; 32] {
    let limbs = fr_to_limbs(v);
    let mut out = [0u8; 32];
    for k in 0..4 {
        out[k * 8..k * 8 + 8].copy_from_slice(&limbs[3 - k].to_be_bytes());
    }
    out
}

/// 默认用户 ID（GB/T 示例值）：ASCII "1234567812345678"，128 位。
pub const DEFAULT_ID: &[u8; 16] = b"1234567812345678";

/// ENTLA：entlen 的 16 位大端（字节数×8）。
pub fn entla(id_len_bytes: usize) -> [u8; 2] {
    let bits = (id_len_bytes * 8) as u16;
    bits.to_be_bytes()
}

/// Z_U 预像串：ENTLA ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA（**六要素**，默认 ID
/// 时恰 2+16+6×32 = **210 B**；GB/T 32918.2 §5.5 公式逐项展开）。
/// 曲线常量从 [`curve_a`]/[`curve_b`]/[`g_coords`] 直接取——它们是 M1c/
/// 簇C 经 GB/T 标准向量验证过的唯一常量源（勘误 #17 基点同源）。
pub fn z_u_preimage(id: &[u8], pax: &FpSM2, pay: &FpSM2) -> Vec<u8> {
    let mut msg = Vec::with_capacity(2 + id.len() + 6 * 32);
    msg.extend_from_slice(&entla(id.len()));
    msg.extend_from_slice(id);
    msg.extend_from_slice(&fe_be32(&curve_a()));
    msg.extend_from_slice(&fe_be32(&curve_b()));
    msg.extend_from_slice(&fe_be32(&g_coords().0));
    msg.extend_from_slice(&fe_be32(&g_coords().1));
    msg.extend_from_slice(&fe_be32(pax));
    msg.extend_from_slice(&fe_be32(pay));
    msg
}

/// Z_U = SM3(Z_U 预像串)，native 参照真值（电路侧见证唯一来源）。
pub fn z_u_native(id: &[u8], pax: &FpSM2, pay: &FpSM2) -> [u8; 32] {
    crate::sm3_native_ref::hash(&z_u_preimage(id, pax, pay))
}

// ── 决策 #23（蓝图 §三·5）：两体化原语 ──
// 210B 预像 = 常量前缀 146B + 变量尾(xA,yA) 64B；SM3 分块边界恰对齐 ⟹
// B₀/B₁ 全常量。SM3 为确定性级联 ⟹ IV₂ = compress(compress(IV,B₀),B₁)
// 是公开常量，电路只装体A/B 两块（M2c「签发者 Z_A 常量折叠」同先例族）。
// ID 若未来脱离注册面固定值，必须回退展开（R5 接口注记）。

/// 常量前缀：ENTLA ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy（恰 146 B；不含 pax/pay）。
pub fn z_u_const_prefix(id: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(2 + id.len() + 4 * 32);
    msg.extend_from_slice(&entla(id.len()));
    msg.extend_from_slice(id);
    msg.extend_from_slice(&fe_be32(&curve_a()));
    msg.extend_from_slice(&fe_be32(&curve_b()));
    msg.extend_from_slice(&fe_be32(&g_coords().0));
    msg.extend_from_slice(&fe_be32(&g_coords().1));
    msg
}

/// SM3 512-bit 分块（M2b 排布口径：msg + 0x80 + 零 + be64(8·len)）。
/// 210B 预像 ⟹ 恰 4 块；变量切线：B₂ 含常量 18B + xA 32B + yA 前 14B，
/// B₃ 含 yA 后 18B + 填充（长度字 1680 = 0x690）。
pub fn z_u_blocks(id: &[u8], pax: &FpSM2, pay: &FpSM2) -> [[u8; 64]; 4] {
    let pre = z_u_preimage(id, pax, pay);
    let l = pre.len();
    let total = (l + 9).div_ceil(64) * 64;
    let mut padded = pre.clone();
    padded.resize(total, 0);
    padded[l] = 0x80;
    padded[total - 8..total].copy_from_slice(&((l as u64) * 8).to_be_bytes());
    std::array::from_fn(|i| {
        let mut b = [0u8; 64];
        b.copy_from_slice(&padded[i * 64..i * 64 + 64]);
        b
    })
}

/// 前导烘焙状态 IV₂ = compress(compress(IV, B₀), B₁)。仅依赖常量面
/// （ENTLA/ID/a/b/G），pax/pay 不在此路径 —— 只吃 `id`。
pub fn z_u_prelude_state(id: &[u8]) -> [u32; 8] {
    let pre = z_u_const_prefix(id);
    assert!(pre.len() == 146, "常量前缀必须 146B（决策 #23 切线前提）");
    let take = |lo: usize| -> [u8; 64] {
        std::array::from_fn(|k| if lo + k < pre.len() { pre[lo + k] } else { 0 })
    };
    let c = crate::sm3_native_ref::compress;
    c(&c(&crate::sm3_native_ref::IV, &take(0)), &take(64))
}

/// 簇J J-b1：签发者 Z_A 词（全公开 ⟹ 离线常量；蓝图 §四·8 J-1 钉死项 1）。
/// Z_A = SM3(ENTL‖ID_I‖a‖b‖Gx‖Gy‖pk_I.x‖pk_I.y) —— 块排布与 Z_U 同构
/// （z_u_blocks），摘要取 z_u_native 全链（禁手抄）；BE 词 = 烘焙唯一来源。
/// 注意：Z_A（签发者，常量）≠ Z_U（持有人，变量钥派生两体化）——两者不可混抄。
pub fn z_a_words(id: &[u8], pk: &(FpSM2, FpSM2)) -> [u32; 8] {
    let be = z_u_native(id, &pk.0, &pk.1);
    std::array::from_fn(|k| u32::from_be_bytes(be[4 * k..4 * k + 4].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_verify_assemble::a2_inputs;
    use ff::Field;

    /// 簇J J-b1：Z_A（签发者 Z 值）常量面三路互锁（蓝图 §四·8 R8 防线）：
    /// ① `z_a_words`（z_u_native 全链）；② sm3_native_ref 逐块手链（独立路径）；
    /// ③ 词值 BE 重排一致性（勘误 #21 fe_be32 方向教训）。三路必须逐词相同。
    #[test]
    fn z_a_words_three_way_lock() {
        let (_e, _r, _s, pax, pay) = a2_inputs();
        let id: &[u8] = DEFAULT_ID;
        let a = z_a_words(id, &(pax, pay));
        // 路径②：native_ref 手链（独立于 z_u_native 内部实现）
        let blocks = z_u_blocks(id, &pax, &pay);
        let mut v = crate::sm3_native_ref::IV;
        for b in &blocks {
            v = crate::sm3_native_ref::compress(&v, b);
        }
        assert_eq!(a, v, "z_a_words 与 native_ref 手链不一致");
        // 路径③：BE 字节重排一致性
        let be = z_u_native(id, &pax, &pay);
        for k in 0..8 {
            let w = u32::from_be_bytes(be[4 * k..4 * k + 4].try_into().unwrap());
            assert_eq!(a[k], w, "Z_A 词 {k} 与 z_u_native BE 重排不符");
        }
        // J-10 冻结表打印（ID=DEFAULT_ID, pk_I=a2）
        println!(
            "[z_a_words] {}",
            a.iter().map(|w| format!("{w:08X}")).collect::<String>()
        );
    }

    /// 权威 HEX → 32 字节大端（独立字节路径，不复用 fr_to_limbs）。
    fn be32_of_std_hex(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// ① 自回环（外部锚定）：a2_inputs 的坐标经 fe_be32 必须与权威 HEX 的
    /// 字节级 BE 序逐位相同 —— 同时锁住「解析链」与「序列化方向」两端。
    #[test]
    fn fe_be32_matches_authoritative_hex() {
        let (_, _, _, pax, pay) = a2_inputs();
        assert_eq!(
            fe_be32(&pax).to_vec(),
            be32_of_std_hex("09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020")
        );
        assert_eq!(
            fe_be32(&pay).to_vec(),
            be32_of_std_hex("CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13")
        );
    }

    /// ② 曲线常量恒等式：a ≡ −3；P_A 在曲线上（复用簇C 判定）。
    #[test]
    fn curve_constants_identity() {
        let minus3 = FpSM2::ZERO - FpSM2::from(3u64);
        assert_eq!(curve_a(), minus3);
        let (_, _, _, pax, pay) = a2_inputs();
        assert!(crate::sm2_ec_plonkish::on_curve_affine(Some((pax, pay))));
    }

    /// ②′ 预像结构：长度 210（六要素）、ENTLA=[0x00,0x80]、ID 正确内嵌；
    /// 总长公式闭验 + 压缩块数闭验 ceil((210+9)/64)=4（M2b 口径）。
    #[test]
    fn preimage_shape_default_id() {
        let (_, _, _, pax, pay) = a2_inputs();
        let msg = z_u_preimage(DEFAULT_ID, &pax, &pay);
        assert_eq!(msg.len(), 210);
        assert_eq!(msg.len(), 2 + DEFAULT_ID.len() + 6 * 32);
        assert_eq!(&msg[..2], &[0x00, 0x80]);
        assert_eq!(&msg[2..18], DEFAULT_ID.as_ref());
        // SM3 全哈希块数（len+1 字节 0x80 填充、末 8B 长度字，64B/块）：
        assert_eq!((msg.len() + 1 + 8).div_ceil(64), 4);
    }

    /// ⓪ 序列化方向烟雾：ZERO→全零、ONE→末字节 1（BE 的最低位字节），
    /// 与 A.2 向量对拍互补，防单向量巧合通过。
    #[test]
    fn fe_be32_direction_smoke() {
        assert_eq!(fe_be32(&FpSM2::ZERO), [0u8; 32]);
        let one = fe_be32(&FpSM2::ONE);
        assert!(one[..31].iter().all(|b| *b == 0));
        assert_eq!(one[31], 1);
    }

    /// ③ Z_U 摘要锁定：本常数经两步走取得——先 native 打印，再由
    /// `tools/z_u_external_check.py`（python gmssl **盲态**外核：曲线常量
    /// 全部机械解析自源码 + on-curve 自洽）独立复算，两路逐字节一致后才
    /// 钉入（2026-08-27 [实测]）。禁一步编造。
    #[test]
    fn z_u_digest_locked_matches_external_reference() {
        let (_, _, _, pax, pay) = a2_inputs();
        let d = z_u_native(DEFAULT_ID, &pax, &pay);
        expect_hex(
            &d,
            "B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3",
        );
    }

    /// 打印路径保留：改动序列化/哈希后重跑 --nocapture 与外核再比对。
    #[test]
    fn z_u_digest_print_for_external_check() {
        let (_, _, _, pax, pay) = a2_inputs();
        let d = z_u_native(DEFAULT_ID, &pax, &pay);
        println!("Z_U(A.2,default-ID) = {}", d.iter().map(|b| format!("{b:02X}")).collect::<String>());
    }

    fn expect_hex(d: &[u8; 32], hex: &str) {
        let got: String = d.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(got, hex);
    }

    // ── 决策 #23 两体化（簇F′）──

    /// ④ 变量切线钉死：210=192+18。B₂ 含 xA 全部+ yA 前 14B；B₃ 含 yA 后
    /// 18B + 0x80@18 + 长度字 be64(1680)；同时核对 pascal 分块路径与前导
    /// take 路径产出的 B₀/B₁ 完全一致（两条路径不得漂移）。
    #[test]
    fn blocks_variable_boundary_pins() {
        let (_, _, _, pax, pay) = a2_inputs();
        let blocks = z_u_blocks(DEFAULT_ID, &pax, &pay);
        assert_eq!(blocks.len(), 4);
        let xa = fe_be32(&pax);
        let ya = fe_be32(&pay);
        // B₂ = preimage[128..192]：常量 18B + xA@B₂[18..50] + yA 前 14B@B₂[50..64]
        assert_eq!(&blocks[2][18..50], &xa[..], "B₂ 内 xA 切片");
        assert_eq!(&blocks[2][50..64], &ya[..14], "B₂ 内 yA 前 14B");
        // B₃ = preimage[192..256]：yA 后 18B + 0x80 + 零 + 长度字
        assert_eq!(&blocks[3][..18], &ya[14..]);
        assert_eq!(blocks[3][18], 0x80);
        assert!(blocks[3][19..56].iter().all(|b| *b == 0));
        assert_eq!(&blocks[3][56..], &1680u64.to_be_bytes(), "长度字 210×8");
        // 前导 take 路径 vs blocks 路径的 B₀/B₁ 一致性
        let (b0, b1) = {
            let f = |k: usize| {
                let full = z_u_blocks(DEFAULT_ID, &pax, &pay);
                full[k]
            };
            (f(0), f(1))
        };
        let pre = z_u_const_prefix(DEFAULT_ID);
        assert_eq!(pre.len(), 146);
        for i in 0..64 {
            assert_eq!(b0[i], if i < 146 { pre[i] } else { 0 });
            assert_eq!(b1[i], pre[64 + i]); // 128 < 146 恒内
        }
    }

    /// ⑤ 两体等价性夹逼（决策 #23 正确性核心）：IV₂ 链 (→B₂→B₃) 输出
    /// 必须逐字节等于整体 hash。连同已锁定的 Z_U 摘要（gmssl 外核权威），
    /// 数学上把 IV₂ 夹逼唯一 —— 无需库层分步 API。
    #[test]
    fn two_body_chain_equivalence() {
        use crate::sm3_native_ref::{compress, hash};
        let (_, _, _, pax, pay) = a2_inputs();
        let blocks = z_u_blocks(DEFAULT_ID, &pax, &pay);
        let iv2 = z_u_prelude_state(DEFAULT_ID);
        let v = compress(&compress(&iv2, &blocks[2]), &blocks[3]);
        assert_eq!(words_be(&v), hash(&z_u_preimage(DEFAULT_ID, &pax, &pay)).to_vec());
        assert_eq!(words_be(&v), z_u_native(DEFAULT_ID, &pax, &pay).to_vec());
    }

    /// ⑥ IV₂ 打印留档（外核参照：随 #23 备案，不可手抄进断言）。
    #[test]
    fn prelude_state_print() {
        let iv2 = z_u_prelude_state(DEFAULT_ID);
        println!(
            "IV₂(A.2,default-ID) = {}",
            iv2.iter().map(|w| format!("{w:08X}")).collect::<String>()
        );
    }

    /// V 字组 → 32B 大端摘要（compress 输出已含链接 XOR，直接字节化）。
    fn words_be(v: &[u32; 8]) -> Vec<u8> {
        v.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    /// 四块全重放 ≡ 整体 hash（#23 多块层守卫；兼此前 diag 定案收编）。
    /// ⚠️ 契约注意：`sm3_native_ref::compress` 返回**已含链接变量 XOR 的
    /// V′**（CF 完整定义），链条末端不得再 ⊕IV —— 双重异或症状指纹 =
    /// digest 与真值无固定映射的错乱值。
    #[test]
    fn replay_all_four_chain_matches_hash() {
        use crate::sm3_native_ref::{compress, hash, IV};
        let (_, _, _, pax, pay) = a2_inputs();
        let bl = z_u_blocks(DEFAULT_ID, &pax, &pay);
        let mut v = IV;
        for b in bl.iter() {
            v = compress(&v, b);
        }
        assert_eq!(words_be(&v), hash(&z_u_preimage(DEFAULT_ID, &pax, &pay)).to_vec());
        assert_eq!(words_be(&v), z_u_native(DEFAULT_ID, &pax, &pay).to_vec());
    }
}
