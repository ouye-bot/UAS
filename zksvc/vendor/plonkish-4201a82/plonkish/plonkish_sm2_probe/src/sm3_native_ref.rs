//! 原生 SM3 参照实现（GB/T 32905-2016）——1.1b 电路 witness 计算的真值来源。
//!
//! ⚠️ 来源与复制方式（铁律：常量不手抄）：本文件自已验证代码
//! `m0_sm3_circuit/src/sm3_native.rs` **机械复制**（2026-08-27，b1），
//! 算法体与 IV/T 常量逐字节保持一致，仅本头注释为新增。
//! 不直接 path 依赖 m0 crate 的原因：避免把 arkworks R1CS 依赖树拖进探针
//! workspace。正确性由随附 GB/T 向量测试在本 crate 内重新运行锚定；
//! 若上游更新，须重新机械复制并全量重跑对拍（不得凭记忆改写常量）。

/// SM3 初始值 IV（8 个 32 位字）。
pub const IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

// 轮常数以 pub(crate) 暴露，供同 crate 的电路模块（sm3_compress::tj_value）引用，
// 避免第二份常量来源（铁律：常量不手抄）。
pub(crate) const T0: u32 = 0x79cc_4519; // 0 ≤ j ≤ 15
pub(crate) const T1: u32 = 0x7a87_9d8a; // 16 ≤ j ≤ 63

#[inline]
pub(crate) fn ff(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

#[inline]
pub(crate) fn gg(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

#[inline]
pub(crate) fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline]
pub(crate) fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// 消息扩展（自本文件 compress 循环体原样抽出为公共函数，供 1.1b/b3 电路侧复用；
/// 单一真值来源：compress 经由此函数取数，避免两份实现漂移）。
/// 返回 (W[0..68], W'[0..64])，其中 W'[j] = W[j] ^ W[j+4]。
pub fn message_words(block: &[u8; 64]) -> ([u32; 68], Vec<u32>) {
    let mut w = [0u32; 68];
    for j in 0..16 {
        w[j] = u32::from_be_bytes([
            block[4 * j],
            block[4 * j + 1],
            block[4 * j + 2],
            block[4 * j + 3],
        ]);
    }
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }
    let wp: Vec<u32> = (0..64).map(|j| w[j] ^ w[j + 4]).collect();
    (w, wp)
}

/// 单块压缩：V' = CF(V, B)。B 为 64 字节。
pub fn compress(v: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
    // 消息扩展
    let (w, wp) = message_words(block);

    let mut a = v[0];
    let mut b = v[1];
    let mut c = v[2];
    let mut d = v[3];
    let mut e = v[4];
    let mut f = v[5];
    let mut g = v[6];
    let mut h = v[7];

    for j in 0..64 {
        let tj = (if j < 16 { T0 } else { T1 }).rotate_left(j);
        // SM3 全部加法均为 mod 2^32（标准定义），wrapping_add 显式表达；
        // debug 模式裸 `+` 会 panic（release 下 wrap 恰好等价，故语义无变化）。
        let ss1 = (a.rotate_left(12).wrapping_add(e).wrapping_add(tj)).rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = ff(j as usize, a, b, c)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(wp[j as usize]);
        let tt2 = gg(j as usize, e, f, g)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j as usize]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    [
        a ^ v[0],
        b ^ v[1],
        c ^ v[2],
        d ^ v[3],
        e ^ v[4],
        f ^ v[5],
        g ^ v[6],
        h ^ v[7],
    ]
}

/// 完整 SM3 哈希（含 padding 与多块迭代）。
pub fn hash(msg: &[u8]) -> [u8; 32] {
    let mut v = IV;
    let mut padded = Vec::with_capacity(msg.len() + 72);
    padded.extend_from_slice(msg);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    let bitlen = (msg.len() as u64) * 8;
    padded.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        v = compress(&v, &block);
    }
    let mut out = [0u8; 32];
    for (i, word) in v.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// 标准测试向量（GB/T 32905-2016 附录 A 及通用公开向量；随上游一并机械复制，
/// 在本 crate 重跑以锚定复制保真性）。
#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn vector_empty() {
        assert_eq!(hash(b""), hex("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")[..]);
    }

    #[test]
    fn vector_abc() {
        assert_eq!(hash(b"abc"), hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")[..]);
    }

    #[test]
    fn vector_64byte() {
        let msg = b"abcd".repeat(16); // 64 字节 = 1 块
        assert_eq!(hash(&msg), hex("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")[..]);
    }

    #[test]
    fn vector_65byte() {
        let mut msg = b"abcd".repeat(16);
        msg.push(b'a'); // 65 字节 = 2 块
        // OpenSSL 交叉验证值（初版误用 W[j-3]≪7/W[j-13]≪15 组序，产生错误向量已弃）
        assert_eq!(hash(&msg), hex("0d24d8847bb36d29b998d0e191a65e4c39a311303e7b8332fe7fec8341169ad7")[..]);
    }

    #[test]
    fn compress_on_iv_matches_hash_single_block() {
        let msg = b"abcd".repeat(13); // 52 字节 ≤ 55，单块 padding
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
        let mut block = [0u8; 64];
        block.copy_from_slice(&padded[..64]);
        let v = compress(&IV, &block);
        let out = hash(&msg);
        for (i, word) in v.iter().enumerate() {
            assert_eq!(&out[4 * i..4 * i + 4], &word.to_be_bytes());
        }
    }
}
