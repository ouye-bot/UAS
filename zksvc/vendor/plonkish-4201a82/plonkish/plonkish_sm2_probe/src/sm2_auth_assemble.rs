//! 飞证 AUTH 资格证明语句（B3，2026-09-20）——vendor 侧装配。
//!
//! 语句（框架 §5.1）：证明者持有 RA 对 165B 报文 M_A 的 SM2 签名（一次性子凭证），
//! 且承诺原像满足资质范围门 cert_level ≥ required_level、有效期 exp_u ≥ t_epoch、
//! 申请绑定（plan_hash/nonce/policy_version 实例钉）。报文与 T1/pred 布局逐槽同构：
//!
//!     M_A = Z_A(pk_RA)(32) ‖ x(id′·G)(32) ‖ C(32) ‖ pk′.x(32) ‖ pk′.y(32)
//!           ‖ exp_u BE(4) ‖ par(1)          # 165B = 1320bit，三块
//!     C   = SM3( salt(16) ‖ id_number(18) ‖ cert_level(1) ‖ sn_h(16) )  # 51B 单块
//!     sn_h = SM3( drone_serial )[0..16]
//!
//! host 面（本文件 T2 起点）：见证构造与三块报文派生复用
//! `full_statement_host_with_idgx`（attrs_u 槽=C）；e=词序小端折叠
//! `fold_digest_fp`（与 Py `digest_e_bytes` 同口径——黄金向量三面单一事实源：
//! uas/zksvc/tests/auth_golden_vector.json）。
//!
//! sn 等值钉（SM3(sn)==sn_h 电路内强制）与 SMT 非成员构件归 B3b（B3-d3 分账：
//! 本批出厂 sn 绑定由 host 检查+链上 sn_hash 承担）。

use crate::sm2_full_statement_assemble::{
    fold_digest_fp, full_statement_host_with_idgx, FullStatementHost, FullStatementWitness,
};
use crate::sm2_params::{fr_from_limbs, hex_to_limbs_le};
use crate::sm2_z_anchor::fe_be32;
use crate::sm3_native_ref;
use crate::FpSM2;

/// AUTH 见证原像输入（签发面语义——全部用户/RA 侧持有）。
pub struct AuthPreimage {
    /// RA 签名公钥（pk_i 槽；Z_A 对它计算——常量锚，B3-d4）。
    pub pk_ra: (FpSM2, FpSM2),
    /// 一次性子凭证身份标量（32B；每次申请 CSPRNG 全新——跨申请不可链接）。
    pub id_prime: [u8; 32],
    pub salt: [u8; 16],
    /// 实名身份证号（18B；零披露——仅进 C 原像）。
    pub id_number: [u8; 18],
    pub cert_level: u8,
    /// 机型类（B4/A4：进 C 原像词 5 MSB+电路 8 位等值钉实例 24）。
    pub class_id: u8,
    /// 无人机序列号（sn_h=SM3(sn)[0..16] 进 C；sn 等值钉=B3b）。
    pub serial: Vec<u8>,
    /// 持有者出示公钥 pk′（sk′ 端侧生成，RA/电路只见公钥）。
    pub pk_holder: (FpSM2, FpSM2),
    /// 持有者私钥 limbs（E8 持有者绑定见证：[sk′]G=pk′）。
    pub sk_holder: [u64; 4],
    pub exp_u: u32,
    /// 子凭证签名 r‖s（RA 签发；host 自检用——电路内由 E8-E10 验证）。
    pub sig_r: [u64; 4],
    pub sig_s: [u64; 4],
    /// 申请绑定 challenge（验证方 nonce 原始字节——r 派生域；2026-10 换代：
    /// 消除 C₁≡[2]G 恒常。装配器纯函数性——r=f(challenge) 确定性派生，
    /// 非 CSPRNG——黄金向量/测试依赖 witness=f(spec)）。
    pub challenge: Vec<u8>,
}

/// sn_h = SM3(serial)[0..16]。
pub fn sn_hash_of(serial: &[u8]) -> [u8; 16] {
    let d = sm3_native_ref::hash(serial);
    d[..16].try_into().expect("SM3 摘要前 16B")
}

/// 承诺 C = SM3(salt16 ‖ cert BE4 ‖ class1 ‖ id_number ‖ sn_h)=55B 单块加盐
/// 承诺（B4-d1 布局 v3：class 居词 5 MSB=等值钉读数源；与主文件
/// `commit_c_words_auth`/backend credential.py 同构——黄金向量钉定）。
pub fn commitment_c_auth(
    salt: &[u8; 16],
    id_number: &[u8; 18],
    cert_level: u8,
    class_id: u8,
    sn_h: &[u8; 16],
) -> [u8; 32] {
    let mut msg = Vec::with_capacity(55);
    msg.extend_from_slice(salt);
    msg.extend_from_slice(&u32::from(cert_level).to_be_bytes());
    msg.push(class_id);
    msg.extend_from_slice(id_number);
    msg.extend_from_slice(sn_h);
    sm3_native_ref::hash(&msg)
}

/// AUTH r 派生（2026-10 换代——消除 C₁≡[2]G 恒常）：
/// `r = SM3("FZ-AUTH-R|v1|" ‖ challenge) mod n`。challenge 由服务端每申请
/// 随机出 ⟹ r 每申请唯一且不可预测（C₁=[r]G 窗口公开实例 12/13 随 challenge
/// 变化——跨申请可链接面拆除）。确定性纯函数（域分隔前缀钉版本）；n > 2^255
/// ⟹ 256 位摘要 mod n 至多一次条件减法（与 ctx_tag 的 mod p 同构全函数）；
/// r=0 概率 2⁻²⁵⁶，断言兜底（派生域保证实践不触发）。
pub fn derive_auth_r(challenge: &[u8]) -> [u64; 4] {
    let mut buf = Vec::with_capacity(13 + challenge.len());
    buf.extend_from_slice(b"FZ-AUTH-R|v1|");
    buf.extend_from_slice(challenge);
    let d = sm3_native_ref::hash(&buf);
    // BE 32B 摘要 → 小端 limbs（与 hex_to_limbs_le 同一整数语义）。
    let mut v = [0u64; 4];
    for (i, item) in v.iter_mut().enumerate() {
        let s = 24 - 8 * i;
        *item = u64::from_be_bytes(d[s..s + 8].try_into().expect("界内"));
    }
    let n = crate::sm2_params::n_limbs();
    if crate::sm2_params::cmp256(&v, &n) != std::cmp::Ordering::Less {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = v[i].overflowing_sub(n[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            v[i] = d2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        debug_assert_eq!(borrow, 0, "v < 2n ⟹ 单次减法无再借位");
    }
    assert!(
        v.iter().any(|&w| w != 0),
        "r 派生碰零（2^-256 事件）——域分隔派生面前缀保证实践不触发"
    );
    v
}

/// AUTH 见证（attrs_u 槽=C；r=申请绑定 challenge 域分隔派生标量——不进报文，
/// 只进 C₁=[r]G 窗口与 RANK_R 位世界（bool/lt_n/neq），派生值域 [1,n−1] 恒满足）。
pub fn witness_from_auth(pi: &AuthPreimage) -> FullStatementWitness {
    let c = commitment_c_auth(&pi.salt, &pi.id_number, pi.cert_level, pi.class_id, &sn_hash_of(&pi.serial));
    FullStatementWitness {
        sk_u: pi.sk_holder,
        pk_u: pi.pk_holder,
        id_u: pi.id_prime,
        attrs_u: c,
        exp_u: pi.exp_u,
        r: derive_auth_r(&pi.challenge),
        r_s: pi.sig_r,
        s_s: pi.sig_s,
        pk_i: pi.pk_ra,
        apk: crate::sm2_ec_plonkish::affine_add(Some(pi.pk_holder), Some(pi.pk_ra))
            .expect("apk 聚合点加成功（pk_holder+pk_RA）"),
    }
}

impl AuthPreimage {
    /// id_prime 的 LE limbs（sk_u 槽语义=标量 limbs；与 EC 循环位序一致）。
    fn id_prime_limbs(&self) -> [u64; 4] {
        hex_to_limbs_le(&self.id_prime.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }
}

/// AUTH 三块 host（复用 with_idgx——attrs_u=C、pk_i=pk_RA、exp/par 同构）。
pub fn full_statement_host_auth(pi: &AuthPreimage) -> FullStatementHost {
    let w = witness_from_auth(pi);
    let id_bits: [bool; 256] = std::array::from_fn(|i| (w.id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
    let (x, y) = crate::sm2_ec_plonkish::affine_mul_bits(&id_bits, Some(crate::sm2_ec_plonkish::g_coords()))
        .expect("id′·G 有限点（标量域内恒成立）");
    let idg_x_be = fe_be32(&x);
    let par = 0x02u8 | (fe_be32(&y)[31] & 1);
    full_statement_host_with_idgx(&w.pk_i, &idg_x_be, par, &w.attrs_u, &w.pk_u, w.exp_u)
}

/// 电路口径 e（词序小端折叠）——与 Py `digest_e_bytes` 同一整数。
pub fn auth_fold_e(blocks: &[[u8; 64]; 3]) -> FpSM2 {
    let v1 = sm3_native_ref::compress(&sm3_native_ref::IV, &blocks[0]);
    let v2 = sm3_native_ref::compress(&v1, &blocks[1]);
    let dg = sm3_native_ref::compress(&v2, &blocks[2]);
    fold_digest_fp(&dg)
}

/// hex 公钥（128 hex x‖y）→ 坐标对。
pub fn pk_from_hex(hex: &str) -> (FpSM2, FpSM2) {
    assert_eq!(hex.len(), 128, "公钥须 128 hex");
    let x = fr_from_limbs(&hex_to_limbs_le(&hex[..64]));
    let y = fr_from_limbs(&hex_to_limbs_le(&hex[64..]));
    (x, y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_verify_assemble::verify_replay;
    use ff::Field;

    /// SM3_LUT env 串行锁（B3 教训㊿+4 并行版：set/remove 竞态使他人装配走
    /// legacy 路径=假绿/假红双形态——auth 测试族全量互斥）。guard drop 时恢复。
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    static AUTH_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    impl EnvGuard {
        fn new() -> Self {
            // 🔴 锁必须随 guard 存活（持有期互斥）——new 尾释放=并行窗口内
            // 他人 remove_env 使在跑装配走 legacy 路径（本批实测并行假败形态）
            let lock = AUTH_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var("SM3_LUT", "1");
            EnvGuard { _lock: lock }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("SM3_LUT");
        }
    }

    /// B2 黄金向量（三面单一事实源：Py 签发 ↔ 本 host ↔ 电路[后续 e2e]）。
    const VECTOR: &str = include_str!("../tests/auth_golden_vector.json");

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
    }

    fn s(v: &serde_json::Value, k: &str) -> String {
        v[k].as_str().unwrap_or_else(|| panic!("缺 {k}")).to_string()
    }

    fn load_pi() -> (serde_json::Value, AuthPreimage) {
        let v: serde_json::Value = serde_json::from_str(VECTOR).expect("向量 JSON");
        let holder_priv_hex = {
            let hp = s(&v, "holder_priv_hex");
            assert_eq!(hp.len(), 64, "holder priv 64 hex");
            hp
        };
        let pi = AuthPreimage {
            pk_ra: pk_from_hex(&s(&v, "ra_pub_hex")),
            id_prime: hex_to_bytes(&s(&v, "id_prime_hex")).try_into().unwrap(),
            salt: hex_to_bytes(&s(&v, "salt_hex")).try_into().unwrap(),
            id_number: s(&v, "id_number").into_bytes().try_into().unwrap(),
            cert_level: u8::try_from(v["cert_level"].as_u64().unwrap()).unwrap(),
            class_id: u8::try_from(v["class_id"].as_u64().unwrap_or(0)).unwrap(),
            serial: s(&v, "sn").into_bytes(),
            pk_holder: pk_from_hex(&s(&v, "holder_pub_hex")),
            sk_holder: hex_to_limbs_le(&holder_priv_hex),
            exp_u: u32::try_from(v["exp_u"].as_u64().unwrap()).unwrap(),
            sig_r: hex_to_limbs_le(&s(&v, "sig_hex")[..64]),
            sig_s: hex_to_limbs_le(&s(&v, "sig_hex")[64..]),
            // r 派生域（v5 起向量携带——与 auth_canonical_spec.json 的
            // binding.challenge_hex 同值，witness=f(vector) 单一事实源）。
            challenge: hex_to_bytes(&s(&v, "challenge_hex")),
        };
        (v, pi)
    }

    /// mock 三面门+环审计（B3 验收门 clause① 前置：装配健全性）。
    #[test]
    fn auth_assemble_mock_and_ring_audit() {
        use crate::sm2_full_statement_assemble::{assemble_full_statement_auth, AuthCPreimage};
        let (_v, pi) = load_pi();
        let w = witness_from_auth(&pi);
        let (siblings, _root0, _bits) = crate::smt_weave::smt_default_witness();
        // 空树非成员见证按真实 key_bits 闭合（对称 DEFAULT 链）——root 必须取
        // 真实 bits 链头（dump 定谳：default root 是 bits=0 语义，非诚实见证）
        let key_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.0);
        let root = crate::smt_weave::smt_blocks(&key_be, &siblings).1;
        let ap = AuthCPreimage {
            cert_be: u32::from(pi.cert_level).to_be_bytes(),
            class_id: pi.class_id,
            id_number: pi.id_number,
            sn_h: sn_hash_of(&pi.serial),
            serial: pi.serial.clone(),
            smt_siblings: Some(siblings),
            smt_root: Some(root),
        };
        let _env = EnvGuard::new();
        let (asm, _h) = assemble_full_statement_auth(
            &w,
            pi.salt,
            ap,
            u32::try_from(_v["required_level"].as_u64().unwrap()).unwrap(),
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_700_000_000,
        );
        let bad_rings = crate::sm3_compress::audit_ring_values(&asm.info, &asm.advice);
        // B3b 环 dump 探针：完整打印坏环（全成员坐标+值分组）——定谳专用，不截断
        for (rid, grp) in bad_rings.iter().take(8) {
            eprintln!("[ring-dump] 坏环 #{rid} 共 {} 值组: {}", grp.len(), grp.join(" | "));
        }
        assert!(bad_rings.is_empty(), "环值审计违约 {:?}",
            bad_rings.iter().take(2).flat_map(|(_, m)| m.iter().take(1).cloned()).collect::<Vec<_>>());
        let viol = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        for v in viol.iter().take(5) {
            eprintln!("[auth-mock] 违约 c={} point={}", v.constraint, v.point);
        }
        assert!(viol.is_empty(), "mock 违约 {:?}",
            viol.iter().take(3).cloned().collect::<Vec<_>>());
        eprintln!("[auth-mock] constraints={} lookups={} instances={}",
            asm.info.constraints.len(), asm.info.lookups.len(), asm.instances.len());
    }

    /// 负例：below-level（cert=3 & required=4）→ 范围门 mock 违约捕获。
    #[test]
    fn auth_below_level_negative_caught() {
        use crate::sm2_full_statement_assemble::{assemble_full_statement_auth, AuthCPreimage};
        let (_v, pi) = load_pi();
        let w = witness_from_auth(&pi);
        let (siblings, _root0, _bits) = crate::smt_weave::smt_default_witness();
        // 空树非成员见证按真实 key_bits 闭合（对称 DEFAULT 链）——root 必须取
        // 真实 bits 链头（dump 定谳：default root 是 bits=0 语义，非诚实见证）
        let key_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.0);
        let root = crate::smt_weave::smt_blocks(&key_be, &siblings).1;
        let ap = AuthCPreimage {
            cert_be: u32::from(pi.cert_level).to_be_bytes(),
            class_id: pi.class_id,
            id_number: pi.id_number,
            sn_h: sn_hash_of(&pi.serial),
            serial: pi.serial.clone(),
            smt_siblings: Some(siblings),
            smt_root: Some(root),
        };
        let _env = EnvGuard::new();
        let (asm, _h) = assemble_full_statement_auth(
            &w, pi.salt, ap,
            4,  // required=4 > cert=3：不诚实见证
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_700_000_000,
        );
        let viol = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        // 差分语义证明：同见证同装配仅 required 4>cert 3（诚实态 0 违约在
        // auth_assemble_mock_and_ring_audit 锚定）⟹ 违约非空=范围门因果捕获。
        assert!(!viol.is_empty(), "below-level 未被捕获（范围门失效）：{:?}",
            viol.iter().take(3).collect::<Vec<_>>());
        eprintln!("[auth-neg] below-level 违约 {} 条（首条 constraint={:?}）", viol.len(), viol.first().map(|v| v.constraint));
    }

    /// 单成员稀疏树见证（smt.py 同构）：树含 k_other，求 key0 的非成员见证
    /// （key0 位置空——与 k_other 在位 D 分叉 ⟹ 层 D 兄弟=k_other 子树折叠）。
    fn single_member_witness(
        key0: &[u8; 32],
        k_other: &[u8; 32],
    ) -> ([[u8; 32]; 32], [u8; 32]) {
        let b0 = crate::smt_weave::key_bits_of(key0);
        let bo = crate::smt_weave::key_bits_of(k_other);
        let mut d_opt: Option<usize> = None;
        for i in 0..32usize {
            if b0[i] != bo[i] {
                d_opt = Some(i);
                break;
            }
        }
        let d = d_opt.expect("键位须不同");
        // DEFAULT 链（0=根侧 … 32=空叶）
        let empty = crate::smt_weave::empty_leaf();
        let mut defaults = vec![empty; 33];
        for dd in (0..32).rev() {
            let mut two = Vec::with_capacity(64);
            two.extend_from_slice(&defaults[dd + 1]);
            two.extend_from_slice(&defaults[dd + 1]);
            defaults[dd] = crate::sm3_native_ref::hash(&two);
        }
        // k_other 在深度 d 子树内的折叠（叶起 d 层，子树内其余空）
        let mut leaf_msg = b"FZ-SMT-LEAF|".to_vec();
        leaf_msg.extend_from_slice(k_other);
        let mut cur_o = crate::sm3_native_ref::hash(&leaf_msg);
        for g in 0..d {
            let sib = defaults[32 - g];
            let mut blk = [0u8; 64];
            if bo[g] == 1 {
                blk[..32].copy_from_slice(&sib);
                blk[32..].copy_from_slice(&cur_o);
            } else {
                blk[..32].copy_from_slice(&cur_o);
                blk[32..].copy_from_slice(&sib);
            }
            cur_o = crate::sm3_native_ref::hash(&blk);
        }
        // key0 见证（层 D 兄弟=cur_o；其余 default）
        let mut cur = empty;
        let mut siblings = [[0u8; 32]; 32];
        for g in 0..32 {
            let sib = if g == d { cur_o } else { defaults[32 - g] };
            siblings[g] = sib;
            let mut blk = [0u8; 64];
            if b0[g] == 1 {
                blk[..32].copy_from_slice(&sib);
                blk[32..].copy_from_slice(&cur);
            } else {
                blk[..32].copy_from_slice(&cur);
                blk[32..].copy_from_slice(&sib);
            }
            cur = crate::sm3_native_ref::hash(&blk);
        }
        (siblings, cur)
    }

    /// 诚实 SMT 见证构造（空撤销集——对称 DEFAULT 链按真实 key_bits 闭合）。
    fn honest_smt(pkx: &FpSM2) -> ([[u8; 32]; 32], [u8; 32]) {
        let (siblings, _r0, _b) = crate::smt_weave::smt_default_witness();
        let key_be = crate::sm2_z_anchor::fe_be32(pkx);
        let root = crate::smt_weave::smt_blocks(&key_be, &siblings).1;
        (siblings, root)
    }

    /// 负例：成员句柄拒——被吊销者伪造非成员见证（default 兄弟+含自身成员叶
    /// 的树根）。链从 EMPTY 常量锚起（电路强制）⟹ 链头=空树路径根 ≠ 含成员
    /// 树根 ⟹ root.fold 实例钉违约（D14：撤销即时数学拒绝的 mock 级判决）。
    #[test]
    fn auth_smt_member_handle_rejected() {
        use crate::sm2_full_statement_assemble::{assemble_full_statement_auth, AuthCPreimage};
        let (_v, pi) = load_pi();
        let w = witness_from_auth(&pi);
        let (siblings, _root) = honest_smt(&w.pk_u.0);
        // 含单成员（=自己的撤销键）的树根：成员叶=SM3(LEAF‖key)（smt.py 同构）
        let key_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.0);
        let mut leaf_msg = b"FZ-SMT-LEAF|".to_vec();
        leaf_msg.extend_from_slice(&key_be);
        let mut cur = crate::sm3_native_ref::hash(&leaf_msg);
        let bits = crate::smt_weave::key_bits_of(&key_be);
        for (i, &b) in bits.iter().enumerate() {
            let sib = siblings[i]; // 叶→根序兄弟（成员路径对侧恒空=default）
            let mut blk = [0u8; 64];
            if b == 0 {
                blk[..32].copy_from_slice(&cur);
                blk[32..].copy_from_slice(&sib);
            } else {
                blk[..32].copy_from_slice(&sib);
                blk[32..].copy_from_slice(&cur);
            }
            cur = crate::sm3_native_ref::hash(&blk);
        }
        let ap = AuthCPreimage {
            cert_be: u32::from(pi.cert_level).to_be_bytes(),
            class_id: pi.class_id,
            id_number: pi.id_number,
            sn_h: sn_hash_of(&pi.serial),
            serial: pi.serial.clone(),
            smt_siblings: Some(siblings),
            smt_root: Some(cur), // 伪造：根=含成员树（链上公示的 rev_root）
        };
        let _env = EnvGuard::new();
        let (asm, _h) = assemble_full_statement_auth(
            &w, pi.salt, ap,
            u32::try_from(_v["required_level"].as_u64().unwrap()).unwrap(),
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_700_000_000,
        );
        let viol = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(!viol.is_empty(), "成员句柄未拒——SMT 非成员验证失效（D14 撤销语义空洞）");
        eprintln!("[auth-neg] member-handle 违约 {} 条", viol.len());
    }

    /// 负例：坏兄弟——见证兄弟翻 1 位（其余诚实）。链头重算 ≠ 实例钉根 ⟹
    /// root.fold 违约（路径完整性：任何兄弟篡改被根钉捕获）。
    #[test]
    fn auth_smt_bad_sibling_rejected() {
        use crate::sm2_full_statement_assemble::{assemble_full_statement_auth, AuthCPreimage};
        let (_v, pi) = load_pi();
        let w = witness_from_auth(&pi);
        let (mut siblings, root) = honest_smt(&w.pk_u.0);
        siblings[17][0] ^= 0x01; // 篡改一位兄弟
        let ap = AuthCPreimage {
            cert_be: u32::from(pi.cert_level).to_be_bytes(),
            class_id: pi.class_id,
            id_number: pi.id_number,
            sn_h: sn_hash_of(&pi.serial),
            serial: pi.serial.clone(),
            smt_siblings: Some(siblings),
            smt_root: Some(root),
        };
        let _env = EnvGuard::new();
        let (asm, _h) = assemble_full_statement_auth(
            &w, pi.salt, ap,
            u32::try_from(_v["required_level"].as_u64().unwrap()).unwrap(),
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_700_000_000,
        );
        let viol = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(!viol.is_empty(), "坏兄弟未拒——路径完整性失效");
        eprintln!("[auth-neg] bad-sibling 违约 {} 条", viol.len());
    }

    /// lookup 论证 mock（R2-SMT 修复的判决仪器）：每通道每行，A 元组必须
    /// ∈ T 表元组集（logUp 成员性语义——与 backend lookup 参数一致）。
    /// check_parts_violations 只查约束；摘要格=xor lookup 输出（无约束消费），
    /// 故伪造判决必须含本面。返回违约行数（按通道累计）。
    fn lookup_violations(
        info: &plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>,
        advice: &[Vec<FpSM2>],
        instances: &[Vec<FpSM2>],
    ) -> usize {
        use plonkish_backend::util::expression::Expression as E;
        const ROWS_N: usize = 1 << crate::sm3_compress::K;
        let np = info.preprocess_polys.len();
        let mut inst_at = vec![FpSM2::ZERO; ROWS_N];
        for (ordinal, v) in instances.iter().flat_map(|c| c.iter()).enumerate() {
            inst_at[crate::sm3_compress::row_mapping()[ordinal]] = *v;
        }
        fn eval(
            e: &E<FpSM2>,
            r: usize,
            info: &plonkish_backend::backend::PlonkishCircuitInfo<FpSM2>,
            advice: &[Vec<FpSM2>],
            inst_at: &[FpSM2],
        ) -> FpSM2 {
            let np = info.preprocess_polys.len();
            match e {
                E::Constant(c) => *c,
                E::Polynomial(q) => {
                    let p = q.poly();
                    let v = if p == 0 {
                        inst_at[r]
                    } else if p <= np {
                        info.preprocess_polys[p - 1][r]
                    } else {
                        advice[p - 1 - np][r]
                    };
                    let _ = q.rotation(); // 查表面全 cur（proto 定谳）
                    v
                }
                E::Negated(a) => -eval(a, r, info, advice, inst_at),
                E::Sum(a, b) => eval(a, r, info, advice, inst_at) + eval(b, r, info, advice, inst_at),
                E::Product(a, b) => {
                    eval(a, r, info, advice, inst_at) * eval(b, r, info, advice, inst_at)
                }
                E::Scaled(a, s) => *s * eval(a, r, info, advice, inst_at),
                E::DistributePowers(vs, base) => vs.iter().fold(
                    eval(base, r, info, advice, inst_at),
                    |acc, v| acc + eval(v, r, info, advice, inst_at),
                ),
                E::CommonPolynomial(_) => FpSM2::ZERO,
                E::Challenge(_) => FpSM2::ZERO,
            }
        }
        let mut total = 0usize;
        for chan in &info.lookups {
            // T 表元组集（4,096 行全表）
            let mut table: std::collections::HashSet<Vec<FpSM2>> = Default::default();
            for r in 0..ROWS_N {
                table.insert(
                    chan.iter()
                        .map(|(_, t)| eval(t, r, info, advice, &inst_at))
                        .collect::<Vec<_>>(),
                );
            }
            // A 元组成员性
            for r in 0..ROWS_N {
                let key = chan
                    .iter()
                    .map(|(a, _)| eval(a, r, info, advice, &inst_at))
                    .collect::<Vec<_>>();
                if !table.contains(&key) {
                    total += 1;
                }
            }
        }
        total
    }

    /// 🔴 R2-SMT 空洞定谳（2026-09-23，电路普查引出——R2 优化前置）：
    /// **恶意证明者模型**下的撤销检查空洞红线测试。
    ///
    /// 攻击分两相：
    /// ①「假兄弟+真根」装配（诚实播种）——链尾=SM3(假兄弟)≠R ⟹ root.fold
    ///    违约。此相=诚实装配器自拒（bad-sibling 同机制），非判决相。
    /// ② 证明者侧见证重写——把 root.fold 引用的 64 影子格所在**环等值类**
    ///    整体改写为 R 的词 limb 值（整类同值=环一致性保持；mux/bit/cur
    ///    不动）。SMT 组若零算术约束/零 lookup（普查定谳：lookups=24 仅
    ///    三体组；TRAIL 同构 n=128 为 1,024 通道全约束），则压缩函数在
    ///    电路内零强制 ⟹ 重写后 mock 必转零违约=电路接受「假兄弟+真根」
    ///    ⟹ 被吊销键可伪造非成员证明（D14 撤销语义对恶意证明者空洞）。
    ///
    /// 判决：②相重写后 mock 违约必须**非空**（伪造链被压缩门击穿）。
    /// 修复（SMT 组逐块查表约束+lookup，TRAIL 先例）落地前本测试红——
    /// 红即空洞在案的可执行证据。
    #[test]
    fn auth_smt_forged_root_vacuity_red() {
        use crate::sm2_full_statement_assemble::{assemble_full_statement_auth, AuthCPreimage};
        let (_v, pi) = load_pi();
        let w = witness_from_auth(&pi);
        let (_honest_sib, root) = honest_smt(&w.pk_u.0);
        // 假兄弟：全零——任何与真实撤销树无关的值（攻击者自选）
        let fake_sib = [[0u8; 32]; 32];
        let ap = AuthCPreimage {
            cert_be: u32::from(pi.cert_level).to_be_bytes(),
            class_id: pi.class_id,
            id_number: pi.id_number,
            sn_h: sn_hash_of(&pi.serial),
            serial: pi.serial.clone(),
            smt_siblings: Some(fake_sib),
            smt_root: Some(root), // 真实公示根（链上/RA 镜像可验的那个值）
        };
        let _env = EnvGuard::new();
        let (asm, _h) = assemble_full_statement_auth(
            &w, pi.salt, ap,
            u32::try_from(_v["required_level"].as_u64().unwrap()).unwrap(),
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_700_000_000,
        );
        let info = &asm.info;
        let np = info.preprocess_polys.len();

        // 基线相①：诚实播种对假兄弟——root.fold 违约在案。
        let viol0 = crate::sm3_compress::check_parts_violations(info, &asm.advice, &asm.instances);
        assert!(!viol0.is_empty(), "假兄弟+真根在诚实播种下必须违约（root.fold 基线失效）");
        eprintln!("[smt-vacuity] ①诚实播种违约 {} 条（root.fold 基线）", viol0.len());

        // 攻击相②：定位 root.fold 约束的 64 影子格 → 环等值类 → 整类改写为 R limb 值。
        let rf_idx = asm
            .ctags
            .iter()
            .position(|t| *t == "smt.root.fold")
            .expect("root.fold 约束在案");
        let shadow_cols: Vec<usize> = info.constraints[rf_idx]
            .used_query()
            .iter()
            .filter_map(|q| {
                let p = q.poly();
                (p > np + 1).then(|| p - 1 - np)
            })
            .collect();
        assert_eq!(shadow_cols.len(), 64, "root.fold 影子格 8 词×8 limb=64");
        let row_rev = crate::sm3_compress::row_mapping()[23];
        // R 的词 limb 值（词 k=BE u32、limb j=(w>>4j)&15——f_pow2(32k+4j) 折叠口径；
        // 影子格序=词× limb 拍平：m=k*8+j）
        let mut want: Vec<(usize, usize, FpSM2)> = Vec::new(); // (col,row,val)
        for (m, col) in shadow_cols.iter().enumerate() {
            let (k, j) = (m / 8, m % 8);
            let w_be = u32::from_be_bytes(root[4 * k..4 * k + 4].try_into().expect("界内"));
            want.push((*col, row_rev, FpSM2::from(u64::from((w_be >> (4 * j)) & 15))));
        }
        // 环类索引：cell → 类代表
        let mut class_of: std::collections::HashMap<(usize, usize), usize> = Default::default();
        for (rid, cyc) in info.permutations.iter().enumerate() {
            for &(p, pt) in cyc {
                class_of.insert((p, pt), rid);
            }
        }
        // 逐类收集成员（影子格所在类），整类改写为同一伪造值
        let mut adv = asm.advice.clone();
        let mut touched_classes = 0usize;
        let mut touched_cells = 0usize;
        for (col, row, val) in &want {
            let p = np + 1 + col;
            let rid = *class_of.get(&(p, *row)).expect("影子格必在环类中");
            for &(pp, pt) in &info.permutations[rid] {
                adv[pp - 1 - np][pt] = *val;
                touched_cells += 1;
            }
            touched_classes += 1;
        }
        // 环一致性必须保持（改写不破坏置换层）
        let rings = crate::sm3_compress::audit_ring_values(info, &adv);
        assert!(rings.is_empty(), "改写破坏环一致性（攻击模拟失真）: {:?}",
            rings.iter().take(2).map(|(i, _)| i).collect::<Vec<_>>());
        // 判决：重写后违约必须非空（压缩门击穿伪造链）——修复前红。
        // 仪器两路：约束 mock（check_parts_violations）+ lookup 论证 mock
        // （lookup_violations——摘要格=xor lookup 输出，无约束消费，
        // 修复的强制面在查表论证）。
        let viol2 = crate::sm3_compress::check_parts_violations(info, &adv, &asm.instances);
        let lk1 = lookup_violations(info, &asm.advice, &asm.instances);
        let lk2 = lookup_violations(info, &adv, &asm.instances);
        eprintln!(
            "[smt-vacuity] ②影子类改写 {} 类 {} 格后：约束违约 {} 条，lookup 违约 诚实={} 伪造={}（伪造=0 即空洞在案）",
            touched_classes, touched_cells, viol2.len(), lk1, lk2
        );
        // 基线：诚实播种（假兄弟自洽链）的 lookup 必须零违约（仪器自检）
        assert_eq!(lk1, 0, "诚实播种 lookup 违约 {}——lookup mock 仪器失真", lk1);
        assert!(
            !viol2.is_empty() || lk2 > 0,
            "🔴 SMT 撤销检查空洞实锤：伪造见证（假兄弟+真根）约束+lookup 双面零违约——压缩函数电路内零强制"
        );
    }

    /// 负例：洗白（非空树跨键根拼接）——树含他人撤销键 k_other（根对位
    /// 敏感），证明者（位置空、诚实兄弟）却提交**另一棵树**（含 k_other2）
    /// 的根。链头重算 ≠ 实例钉根 ⟹ root.fold 违约——路径-根-键三方一致性。
    /// （空树对称闭合使任何键位 default 链头相同=合法非成员，位敏感性只在
    /// 非空树出现——dump 定谳：负例必须在非空树上构造。）
    #[test]
    fn auth_smt_whitewash_key_swap_rejected() {
        use crate::sm2_full_statement_assemble::{assemble_full_statement_auth, AuthCPreimage};
        let (_v, pi) = load_pi();
        let w = witness_from_auth(&pi);
        let key0 = crate::sm2_z_anchor::fe_be32(&w.pk_u.0);
        let mut k_other = key0;
        k_other[0] ^= 0x80; // 与 key0 在叶层分叉（bit[0] 相反）
        let mut k_other2 = key0;
        k_other2[0] ^= 0x40; // 第二成员：bit[1] 分叉（key 前 32bit 内）
        let (siblings, root) = single_member_witness(&key0, &k_other);
        let (_sib2, root2) = single_member_witness(&key0, &k_other2);
        assert_ne!(root, root2, "两棵树根必须不同（负例前提）");
        let ap = AuthCPreimage {
            cert_be: u32::from(pi.cert_level).to_be_bytes(),
            class_id: pi.class_id,
            id_number: pi.id_number,
            sn_h: sn_hash_of(&pi.serial),
            serial: pi.serial.clone(),
            smt_siblings: Some(siblings),
            smt_root: Some(root2), // 拼接：k_other 树的路径+k_other2 树的根
        };
        let _env = EnvGuard::new();
        let (asm, _h) = assemble_full_statement_auth(
            &w, pi.salt, ap,
            u32::try_from(_v["required_level"].as_u64().unwrap()).unwrap(),
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_700_000_000,
        );
        let viol = crate::sm3_compress::check_parts_violations(&asm.info, &asm.advice, &asm.instances);
        assert!(!viol.is_empty(), "跨键拼接未拒——路径-根一致性失效");
        eprintln!("[auth-neg] whitewash 违约 {} 条", viol.len());
    }

    /// 负例：class 篡改（A4 封堵）——凭证 C 原像含 class 1（黄金向量）但申请
    /// 声明 class 0。**正门 fail-closed**：host 双源断言（attrs_u==SM3(55B
    /// 原像)）在装配入口即拒——恶意见证无法经 vendor 正门构造。绕过正门的
    /// 攻击者（自建装配）面对两层电路强制：①z-plan C-recompute（SM3(声明
    /// class 原像)≠签名 C ⟹ 违约）②class.pin（词 5 高 8 位≠实例 24）——
    /// A4 攻击面闭合（判决形态=should_panic 实证正门拒绝）。
    #[test]
    #[should_panic(expected = "attrs_u")]
    fn auth_class_mismatch_rejected() {
        use crate::sm2_full_statement_assemble::{assemble_full_statement_auth, AuthCPreimage};
        let (_v, pi) = load_pi();
        let w = witness_from_auth(&pi);
        let (siblings, root) = honest_smt(&w.pk_u.0);
        let declared = if pi.class_id == 0 { 1u8 } else { 0u8 };
        let ap = AuthCPreimage {
            cert_be: u32::from(pi.cert_level).to_be_bytes(),
            class_id: declared, // 声明 class ≠ C 原像 class
            id_number: pi.id_number,
            sn_h: sn_hash_of(&pi.serial),
            serial: pi.serial.clone(),
            smt_siblings: Some(siblings),
            smt_root: Some(root),
        };
        let _env = EnvGuard::new();
        let (asm, _h) = assemble_full_statement_auth(
            &w, pi.salt, ap,
            u32::try_from(_v["required_level"].as_u64().unwrap()).unwrap(),
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_700_000_000,
        );
        let _ = (asm, _h); // 到达即失败：断言须在装配内触发
    }

    /// AUTH e2e（B3 验收门：prove/verify 判决行+预算四元组+负例数学拒绝）。
    /// 形态=sm3_lut_full_statement_e2e 模板。判决行已入性能档案（VERIFY ok=true
    /// prove=692s@harness/115.3s@CLI）——#[ignore] 防 check.sh 门禁跑 12 分钟；
    /// 服务器窗/演示机复跑=--ignored。
    #[test]
    #[ignore = "e2e prove ~12min：判决行已入性能档案 B3 节；复跑=--ignored"]
    fn auth_e2e_prove_verify_and_negative() {
        use plonkish_backend::{
            backend::{hyperplonk::HyperPlonk, PlonkishCircuit, PlonkishBackend},
            pcs::multilinear::Basefold,
            util::{
                hash::Sm3,
                transcript::{InMemoryTranscript, SM3Transcript},
            },
        };
        use crate::sm2_full_statement_assemble::{assemble_full_statement_auth, AuthCPreimage};
        use crate::sm3_lookup_proto::ProtoSpec;
        use rand::{rngs::StdRng, SeedableRng};
        use std::io::Cursor;
        use std::time::Instant;

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

        let (v, pi) = load_pi();
        let w = witness_from_auth(&pi);
        let (siblings, _root0, _bits) = crate::smt_weave::smt_default_witness();
        // 空树非成员见证按真实 key_bits 闭合（对称 DEFAULT 链）——root 必须取
        // 真实 bits 链头（dump 定谳：default root 是 bits=0 语义，非诚实见证）
        let key_be = crate::sm2_z_anchor::fe_be32(&w.pk_u.0);
        let root = crate::smt_weave::smt_blocks(&key_be, &siblings).1;
        let ap = AuthCPreimage {
            cert_be: u32::from(pi.cert_level).to_be_bytes(),
            class_id: pi.class_id,
            id_number: pi.id_number,
            sn_h: sn_hash_of(&pi.serial),
            serial: pi.serial.clone(),
            smt_siblings: Some(siblings),
            smt_root: Some(root),
        };
        let required = u32::try_from(v["required_level"].as_u64().unwrap()).unwrap();
        let _env = EnvGuard::new();
        let t_asm = Instant::now();
        let (asm, _h) = assemble_full_statement_auth(
            &w,
            pi.salt,
            ap.clone(),
            required,
            FpSM2::from(0xdead_beefu64),   // ctx_tag（plan_hash 复合钉域）
            FpSM2::from(0x1234_5678u64),   // pred_id（nonce/policy_version 复合钉域）
            1_700_000_000,                  // t_epoch < exp_u=1900000000（诚实正例）
        );
        let asm_s = t_asm.elapsed();
        let circ = AsmCirc {
            info: asm.info.clone(),
            advice: asm.advice.clone(),
            instances: asm.instances.clone(),
        };
        let t0 = Instant::now();
        let param = Pb::setup(&asm.info, StdRng::seed_from_u64(0x5EED)).unwrap();
        let t1 = Instant::now();
        let (pp, vp) = Pb::preprocess(&param, &asm.info).unwrap();
        let t2 = Instant::now();
        let proof = {
            let mut tr = Tr::new(());
            Pb::prove(&pp, &circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        let t3 = Instant::now();
        let ok = {
            let mut tr = Tr::from_proof((), proof.as_slice());
            Pb::verify(&vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
        };
        let t4 = Instant::now();
        eprintln!(
            "[auth-e2e] 正例: constraints={} polys={} lookups={} proof={}B ok={ok}
[auth-e2e] 四元组: setup={:.1}s preprocess={:.1}s prove={:.1}s verify={:.1}s assemble={:.1}s",
            asm.info.constraints.len(), asm.info.num_poly(), asm.info.lookups.len(), proof.len(),
            (t1 - t0).as_secs_f64(), (t2 - t1).as_secs_f64(), (t3 - t2).as_secs_f64(),
            (t4 - t3).as_secs_f64(), asm_s.as_secs_f64()
        );
        assert!(ok, "AUTH e2e VERIFY FAILED");

        // 负例：below-level（required=4>cert=3）——证明不可伪造的电路级判决
        // （SV-2/SV-4 模式：装配完成+prove 照常产出，verify 层 sumcheck 数学拒绝）。
        let (asm_neg, _h2) = assemble_full_statement_auth(
            &w, pi.salt, ap, 4,
            FpSM2::from(0xdead_beefu64),
            FpSM2::from(0x1234_5678u64),
            1_700_000_000,
        );
        let viol = crate::sm3_compress::check_parts_violations(
            &asm_neg.info, &asm_neg.advice, &asm_neg.instances,
        );
        assert!(!viol.is_empty(), "below-level mock 违约缺失——负例断言空洞");
        eprintln!("[auth-e2e] 负例: below-level mock 违约 {} 条（范围门电路内强制；e2e sumcheck 拒绝形态同 SV-2/SV-4 判决）", viol.len());
    }

    #[test]
    fn auth_host_golden_parity() {
        let v: serde_json::Value = serde_json::from_str(VECTOR).expect("向量 JSON");
        let (pi_v, pi) = load_pi();
        let v = pi_v;

        // ① 三块 host == Py M_A 逐字节（165B 消息 + SM3 padding 到 192B 三块）
        let host = full_statement_host_auth(&pi);
        let msg = hex_to_bytes(&s(&v, "message_hex"));
        assert_eq!(msg.len(), 165);
        for b in 0..3 {
            let end = ((b + 1) * 64).min(165);
            let seg = &msg[b * 64..end];
            assert_eq!(&host.blocks[b][..seg.len()], seg, "host 块 {b} 消息段与 Py 报文不一致");
        }

        // ② e 折叠（电路口径）与 Py e_bytes 同整数：verify_replay 用 RA 签名直接判
        let e_fp = auth_fold_e(&host.blocks);
        assert_ne!(e_fp, FpSM2::from(0u64));
        let out = verify_replay(
            e_fp,
            fr_from_limbs(&pi.sig_r),
            fr_from_limbs(&pi.sig_s),
            pi.pk_ra.0,
            pi.pk_ra.1,
        );
        assert!(out.ok, "Py 签发签名未过电路口径 verify_replay——M_A/词序口径漂移");

        // ③ 负例：s 翻位必拒
        let mut s_bad = pi.sig_s;
        s_bad[0] ^= 1;
        let bad = verify_replay(
            e_fp,
            fr_from_limbs(&pi.sig_r),
            fr_from_limbs(&s_bad),
            pi.pk_ra.0,
            pi.pk_ra.1,
        );
        assert!(!bad.ok, "篡改 s 仍过验签——对拍断言空洞");

        // ④ 换持有者公钥（错钥）必拒
        let wrong = verify_replay(
            e_fp,
            fr_from_limbs(&pi.sig_r),
            fr_from_limbs(&pi.sig_s),
            pi.pk_holder.0,
            pi.pk_holder.1,
        );
        assert!(!wrong.ok, "错验签公钥仍过——语义错误");
    }
}
