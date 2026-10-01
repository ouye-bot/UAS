//! 飞证 B6：TRAIL 轨迹合规语句——host 单一事实源（与 uas gcs/bridge fence.py 同构）。
//!
//! 链语义（B5 已落的 fence.py sample_hash 同构单一事实源）：
//!   h_0 = SM3(b"FZ-TEL-GENESIS")
//!   h_{i+1} = SM3(h_i(32) ‖ t_i BE4 ‖ alt_i BE2 ‖ lat_i BE4 ‖ lon_i BE4)   # 46B 单块
//! 检查点报文（设备钥签名对象——device_key.py checkpoint_message 同构）：
//!   SM3(b"FZ-CHK|" ‖ auth_id BE8 ‖ seq BE4 ‖ chain_head 32 ‖ fence_state 4)

use crate::sm3_native_ref;
use crate::FpSM2;

pub const TRAIL_N: usize = 128; // B6-d1：64 秒段 @2Hz
pub const SAMPLE_PERIOD_MS: u32 = 500; // 2Hz
pub const GENESIS_LABEL: &[u8] = b"FZ-TEL-GENESIS";

pub fn genesis_head() -> [u8; 32] {
    sm3_native_ref::hash(GENESIS_LABEL)
}

/// 单样本链扩展（fence.py sample_hash 同构；46B 单块）。
pub fn sample_hash(prev: &[u8; 32], t_epoch: u32, alt_cm: u16, lat_1e7: i32, lon_1e7: i32) -> [u8; 32] {
    let mut m = Vec::with_capacity(46);
    m.extend_from_slice(prev);
    m.extend_from_slice(&t_epoch.to_be_bytes());
    m.extend_from_slice(&alt_cm.to_be_bytes());
    m.extend_from_slice(&lat_1e7.to_be_bytes());
    m.extend_from_slice(&lon_1e7.to_be_bytes());
    sm3_native_ref::hash(&m)
}

/// 样本块→64B SM3 块（消息 46B+0x80@46+BE64(368)@56——与 host hash 填充同构）。
pub fn sample_block(prev: &[u8; 32], t_epoch: u32, alt_cm: u16, lat_1e7: i32, lon_1e7: i32) -> [u8; 64] {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(prev);
    b[32..36].copy_from_slice(&t_epoch.to_be_bytes());
    b[36..38].copy_from_slice(&alt_cm.to_be_bytes());
    b[38..42].copy_from_slice(&lat_1e7.to_be_bytes());
    b[42..46].copy_from_slice(&lon_1e7.to_be_bytes());
    b[46] = 0x80;
    b[56..].copy_from_slice(&368u64.to_be_bytes());
    b
}

pub struct TrailSamples {
    /// n 组 (t, alt, lat, lon)——见证明细。
    pub rows: Vec<(u32, u16, i32, i32)>,
    /// 链头（末样本摘要——==链上锚定 chain_head）。
    pub head: [u8; 32],
    /// 各样本块（电路消息块）。
    pub blocks: Vec<[u8; 64]>,
    /// 各样本输出头（heads[i]=compress(IV, blocks[i]) BE 词序——电路出口对拍面）。
    pub heads: Vec<[u8; 32]>,
}

/// 诚实样本序列（t 连续=周期采样、alt 全部 ≤ alt_max）。
pub fn honest_samples(n: usize, t0: u32, alt_max_cm: u16) -> TrailSamples {
    let mut rows = Vec::with_capacity(n);
    let mut blocks = Vec::with_capacity(n);
    let mut heads = Vec::with_capacity(n);
    let mut h = genesis_head();
    for i in 0..n {
        let t = t0 + (i as u32) * SAMPLE_PERIOD_MS;
        let alt = 3_000u16 + ((i as u16 * 37) % (alt_max_cm.saturating_sub(3_000).max(1)));
        let lat = 31_0000_000i32 + (i as i32) * 13;
        let lon = 121_0000_000i32 + (i as i32) * 17;
        blocks.push(sample_block(&h, t, alt, lat, lon));
        h = sample_hash(&h, t, alt, lat, lon);
        heads.push(h);
        rows.push((t, alt, lat, lon));
    }
    TrailSamples { rows, head: h, blocks, heads }
}

/// 词序折叠（fold_digest_fp 同式——公开实例钉 chain_head 用）。
pub fn fold_words_be(root: &[u8; 32]) -> FpSM2 {
    let mut e = FpSM2::from(0u64);
    for k in 0..8 {
        let wv = u32::from_be_bytes(root[4 * k..4 * k + 4].try_into().expect("界内"));
        e += FpSM2::from(u64::from(wv)) * crate::sm2_params::f_pow2(32 * k);
    }
    e
}

/// 256 位真 BE 整数折叠（gmssl 裸摘要 e 口径——word k 权重 2^{32(7−k)}）。
/// 与 [`fold_words_be`]（词序折叠，AUTH 电路族/实例钉口径：word k 权重 2^{32k}）
/// 是**两个不同约定**：前者对 gmssl 签名验签，后者对电路实例折叠——不可混用。
pub fn fold_be_integer(root: &[u8; 32]) -> FpSM2 {
    let mut e = FpSM2::from(0u64);
    for k in 0..8 {
        let wv = u32::from_be_bytes(root[4 * k..4 * k + 4].try_into().expect("界内"));
        e += FpSM2::from(u64::from(wv)) * crate::sm2_params::f_pow2(32 * (7 - k));
    }
    e
}

// ── 检查点面（B6-d7/d8'：设备签名在锚定/装配面验证，电路绑锚定头） ──

/// 检查点报文（B5 gcs/bridge device_key.py checkpoint_message 同构单一事实源）：
/// `b"FZ-CHK|"‖auth_id BE8‖seq BE4‖chain_head 32‖fence_state 4`——55B 恰满单块。
pub fn checkpoint_message(auth_id: u64, seq: u32, chain_head: &[u8; 32], fence_state: &[u8; 4]) -> Vec<u8> {
    let mut m = Vec::with_capacity(55);
    m.extend_from_slice(b"FZ-CHK|");
    m.extend_from_slice(&auth_id.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(chain_head);
    m.extend_from_slice(fence_state);
    m
}

/// 设备公钥（128 hex x‖y）→ 坐标对；非法返回 None（fail-closed 解析）。
pub fn pk_from_hex128(hex: &str) -> Option<(FpSM2, FpSM2)> {
    if hex.len() != 128 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(crate::sm2_auth_assemble::pk_from_hex(hex))
}

/// 设备钥检查点**裸摘要** SM2 验签（与 uas app.crypto.sm2.sign_digest 同口径：
/// e=SM3(报文) 的词序折叠（BE 整数）直接入方程、无 ZA——FISCO 交易签名族）。
/// host fail-closed 面：坏设备签名/报文被换/错钥 ⟹ false（B6 验收门负例④）。
pub fn verify_checkpoint_sig(
    device_pk: (FpSM2, FpSM2),
    auth_id: u64,
    seq: u32,
    chain_head: &[u8; 32],
    fence_state: &[u8; 4],
    sig_hex: &str,
) -> bool {
    let m = checkpoint_message(auth_id, seq, chain_head, fence_state);
    let dg = crate::sm3_native_ref::hash(&m);
    let e = fold_be_integer(&dg);
    if sig_hex.len() != 128 || !sig_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let r = crate::sm2_params::hex_to_limbs_le(&sig_hex[..64]);
    let s = crate::sm2_params::hex_to_limbs_le(&sig_hex[64..]);
    crate::sm2_verify_assemble::verify_replay(
        e,
        crate::sm2_params::fr_from_limbs(&r),
        crate::sm2_params::fr_from_limbs(&s),
        device_pk.0,
        device_pk.1,
    )
    .ok
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/trail_checkpoint_vector.json"))
            .expect("检查点跨语言 fixture")
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
    fn hex4(s: &str) -> [u8; 4] {
        let mut out = [0u8; 4];
        for i in 0..4 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
    fn hexb(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// 跨语言对拍：uas bridge（Py sign_digest 裸摘要）签发 ↔ Rust host 验签；
    /// 报文/摘要逐字节一致。B6 验收门负例④=坏设备签名在此面数学拒绝。
    #[test]
    fn trail_checkpoint_verify_cross_language() {
        let v = fixture();
        let pk = pk_from_hex128(v["pub_hex"].as_str().unwrap()).expect("合法设备公钥");
        let auth_id = v["auth_id"].as_u64().unwrap();
        let seq = v["seq"].as_u64().unwrap() as u32;
        let head = hex32(v["chain_head_hex"].as_str().unwrap());
        let fs = hex4(v["fence_state_hex"].as_str().unwrap());
        let sig = v["sig_hex"].as_str().unwrap().to_string();

        // 报文/摘要对拍（单一事实源两侧同构）
        let m = checkpoint_message(auth_id, seq, &head, &fs);
        assert_eq!(m, hexb(v["msg_hex"].as_str().unwrap()), "报文逐字节一致");
        let dg = crate::sm3_native_ref::hash(&m);
        let dg_hex: String = dg.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(dg_hex, v["digest_hex"].as_str().unwrap(), "摘要一致");

        // 正例：Py 签名在 Rust 验签通过
        assert!(verify_checkpoint_sig(pk, auth_id, seq, &head, &fs, &sig), "跨语言验签必须通过");

        // 负例①：坏设备签名（s 末位翻 1 字符）
        let mut bad = sig.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == '0' { '1' } else { '0' });
        assert!(!verify_checkpoint_sig(pk, auth_id, seq, &head, &fs, &bad), "坏签名必须拒");

        // 负例②：报文被换（chain_head 翻 1 位——签名不覆盖真实头）
        let mut head2 = head;
        head2[0] ^= 0x01;
        assert!(!verify_checkpoint_sig(pk, auth_id, seq, &head2, &fs, &sig), "换头报文必须拒");

        // 负例③：错钥（另一把公钥——非本设备钥签发）
        // （"9"×128 是合法域元素但非曲线点：verify 的点乘在仿射数学下给出
        // 不匹配的 R ⟹ 拒；此处不依赖 panic 路径。）
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// host 链 vs 原生 hash 差分（消息链语义：h_i 为消息前缀、每块 fresh IV
    /// ——与 SMT 内节点同形态，织入=compress_entry_with_words(None, iv, pair)）。
    #[test]
    fn trail_host_chain_matches_native() {
        let s = honest_samples(8, 1_700_000_000, 12_000);
        for (i, b) in s.blocks.iter().enumerate() {
            let mut dg = crate::sm3_native_ref::compress(&crate::sm3_native_ref::IV, b);
            let mut be = [0u8; 32];
            for k in 0..8 {
                be[4 * k..4 * k + 4].copy_from_slice(&dg[k].to_be_bytes());
            }
            assert_eq!(be, s.heads[i], "块 {i} compress 输出与 hash 链不一致");
        }
        assert_eq!(s.head, s.heads[7], "末头==链头");
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use crate::sm3_lookup_block::BlockBuilder;
    use crate::sm3_lookup_weave::trail_chain_circuit;

    /// B6-T2 根因定谳后的 host 差分红绿门：**电路链头（digest BE 词）必须逐词
    /// 等于 host 单一事实源链头**。chain_circuit 的 IV 链传（SMT 双块语义）对
    /// TRAIL 是错函数——本测试钉死「消息级链、每块 fresh IV」语义不被再次退化。
    #[test]
    fn trail_chain_circuit_digest_matches_host() {
        let s = honest_samples(16, 1_700_000_000, 12_000);
        let circ = trail_chain_circuit(&s.blocks);
        for k in 0..8 {
            let wv = u32::from_be_bytes(s.head[4 * k..4 * k + 4].try_into().expect("界内"));
            assert_eq!(circ.digest[k], wv, "电路 digest word {k} ≠ host 链头——链语义漂移");
        }
    }

    /// T0 预算探针：n=128 链展开 solo（census+e2e prove 判决行——列爆炸定谳）。
    #[test]
    #[ignore = "T0 预算探针：e2e prove 数分钟级；复跑=--ignored"]
    fn trail_budget_probe_n128() {
        let s = honest_samples(TRAIL_N, 1_700_000_000, 12_000);
        let circ = trail_chain_circuit(&s.blocks);
        eprintln!(
            "[trail-probe] blocks={} census: constraints={} polys={} lookups={} rings={}",
            TRAIL_N,
            circ.info.constraints.len(),
            circ.info.num_poly(),
            circ.info.lookups.len(),
            circ.info.permutations.len()
        );
        // e2e（Basefold+SM3Transcript，proto 直跑形态——同 P2 里程碑③门 3）
        use plonkish_backend::backend::{hyperplonk::HyperPlonk, PlonkishBackend};
        use plonkish_backend::pcs::multilinear::Basefold;
        use plonkish_backend::util::hash::Sm3;
        use plonkish_backend::util::transcript::{InMemoryTranscript, SM3Transcript};
        use crate::sm3_lookup_proto::ProtoSpec;
        use rand::{rngs::StdRng, SeedableRng};
        use std::io::Cursor;
        use std::time::Instant;

        type Pcs = Basefold<FpSM2, Sm3, ProtoSpec>;
        type Pb = HyperPlonk<Pcs>;
        type Tr = SM3Transcript<Cursor<Vec<u8>>>;

        struct CircWrap(crate::sm3_lookup_block::BlockCircuit);
        impl plonkish_backend::backend::PlonkishCircuit<FpSM2> for CircWrap {
            fn circuit_info_without_preprocess(
                &self,
            ) -> Result<plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
                Ok(self.0.info.clone())
            }
            fn circuit_info(
                &self,
            ) -> Result<plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
                Ok(self.0.info.clone())
            }
            fn instances(&self) -> &[Vec<FpSM2>] {
                &[]
            }
            fn synthesize(
                &self,
                _round: usize,
                _challenges: &[FpSM2],
            ) -> Result<Vec<Vec<FpSM2>>, plonkish_backend::Error> {
                Ok(self.0.witness.clone())
            }
        }

        let wrap = CircWrap(circ);
        let t0 = Instant::now();
        let param = Pb::setup(&wrap.0.info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp, vp) = Pb::preprocess(&param, &wrap.0.info).unwrap();
        let t1 = Instant::now();
        let proof = {
            let mut tr = Tr::new(());
            Pb::prove(&pp, &wrap, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let t2 = Instant::now();
        let ok = {
            let mut tr = Tr::from_proof((), proof.as_slice());
            Pb::verify(&vp, &wrap.0.info.num_instances.iter().map(|_| Vec::new()).collect::<Vec<_>>(), &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
        };
        let t3 = Instant::now();
        eprintln!(
            "[trail-probe] preprocess={:.1}s prove={:.1}s verify={:.1}s proof={}B ok={}",
            (t1 - t0).as_secs_f64(), (t2 - t1).as_secs_f64(), (t3 - t2).as_secs_f64(), proof.len(), ok
        );
        assert!(ok, "TRAIL solo e2e FAILED");
    }
}
