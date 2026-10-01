//! T2.4 摘要签名加入协议（主机层 spike）——2026-09-02。
//!
//! 论文对应物（设计定案 `literature_review/T2.4_加入协议_设计定案_2026-09-02.md` §三）：
//! - def:pi 的 **Join** 两方协议（替换「签发者明文见 M 的 Issue」——切断陷害
//!   标量来源③：签发者视图=(P, e, attrs, pk_u, PoP, π_link)，**无一通向标量
//!   Id_u**：P 是点（ECDLP 挡）、e 是摘要（SM3 原像挡））。
//! - prem:registry 的 **π_link 承重句**：语句 ∃Id_u: Id_u·G=P（A1″ 起摘要
//!   由签发者按组件拼装 M 后按 GB/T 内算，绑定=签发者本地拼装核对+π_link
//!   知识证明）——没有它，被腐化持有者可拿未注册 Id'' 的签名（G₁a 破）。
//! - thm:frame 恶意签发者版的**机制前提**：签发者按标准接口对 M 签名
//!   （摘要内部计算），EUF-CMA 项退出假设集。
//!
//! ## 结构承诺（类型面）
//! `JoinRequest` **不含 Id_u/M 字段**——M 只在 `HolderSecret`（持有者本地）与
//! `credential` 返回值（持有者装配点）出现。签发者视图的类型面即安全语义。
//!
//! ## 与电路 (S1) 的字节兼容
//! e=SM3(Z_A‖M) 的消息布局**零重实现**：[`join_digest`] 直接复用 T1 真值源
//! [`crate::sm2_full_statement_assemble::full_statement_host`]（A1″ 消息
//! 165B：B₁=Z_A‖x(Id·G) / B₂=attrs‖pk_u.x / B₃=pk_u.y‖exp_u‖parity‖pad
//! (0x80@37+be64(1320))，三块布局与压缩绑定同源，测试 t2 以双见证位差锁定
//! 「该函数只读 id/attrs/pk_u/pk_i/exp_u 五域」+ native hash 独立路径对拍）。
//! 摘要签名 sign(e,d) 与电路 (S2) 验证方程（verify_replay 四步）逐字同式
//! （T1 往返锁定）。
//!
//! ## π_link 分层（设计定案 §3.2/§八）
//! 本模块是主机层：π_link 以 [`PiLink`] 语句占位参与消息流——签发侧检查=
//! 语句重算匹配（e↔P 绑定，T8 跨提交必败）+ `link_ok` 环境门；真实证明对象
//! （第三条语句线：三体 SM3 链 + Id·G 环 + e/P 双钉，~100–105k 门 [估算]）
//! 电路 spike 落地后接管 `verified` 位。

use crate::FpSM2;
use ff::Field;

/// PoP 域分离前缀（持有证明摘要的专属域，与语句摘要 e=SM3(Z_A‖M) 分离；
/// T6 锁定：PoP 签名不可作语句签名重放）。
pub const POP_CHALLENGE: &[u8] = b"SM2-JOIN-POP-CHALLENGE-V1";

/// π_link 域分离前缀（链接证明挑战的专属域，与语句摘要/PoP 摘要分离）。
pub const PILINK_CHALLENGE: &[u8] = b"SM2-JOIN-PILINK-SCHNORR-V1";

/// π_link：注册点离散对数知识的 Schnorr Σ 证明（Fiat--Shamir 非交互，SM3 承载挑战）。
/// 语句 =「∃Id: Id·G = P」；转录 = (R, z)。A1'（2026-09-06）：摘要哈希一致性
/// 移回签发者本地重算（第四道），π_link 的 ZK 语句只剩纯 DL 知识——其
/// 诚实验证者零知识与知识可靠性是标准结果（模拟器只需语句点 P）。
pub struct PiLink {
    /// Σ 承诺：R = k·G（fresh k）
    pub r_pt: (FpSM2, FpSM2),
    /// Σ 应答：z = k + c·Id_u mod n（挑战 c 见 [`pilink_challenge`]）
    pub z: FpSM2,
}

/// 挑战哈希：c = fold(SM3(PILINK_CHALLENGE ‖ R.x ‖ R.y ‖ P.x ‖ P.y))，
/// 再按 mod-n 规约（fold 值 ≥ n 的值域事件 ≈2^{-65}：2^256−n ≈ 2^191），
/// 规约后无歧义；规约偏置量级与 F_p 侧 2^{-32} 同类（sec5 部署口径）。
fn pilink_challenge(r_pt: &(FpSM2, FpSM2), p: &(FpSM2, FpSM2)) -> [u64; 4] {
    let mut msg = PILINK_CHALLENGE.to_vec();
    msg.extend_from_slice(&crate::sm2_z_anchor::fe_be32(&r_pt.0));
    msg.extend_from_slice(&crate::sm2_z_anchor::fe_be32(&r_pt.1));
    msg.extend_from_slice(&crate::sm2_z_anchor::fe_be32(&p.0));
    msg.extend_from_slice(&crate::sm2_z_anchor::fe_be32(&p.1));
    let dg = crate::sm3_native_ref::hash(&msg);
    let mut words = [0u32; 8];
    for k in 0..8 {
        words[k] = u32::from_be_bytes(dg[4 * k..4 * k + 4].try_into().expect("摘要界内"));
    }
    let c = crate::sm2_params::fr_to_limbs(&crate::sm2_full_statement_assemble::fold_digest_fp(&words));
    // mod-n 规约（c < p，与 n 同为 256 位：最多一次减法）
    let n = crate::sm2_params::n_limbs();
    let mut ge = true;
    for i in (0..4).rev() {
        if c[i] != n[i] { ge = c[i] > n[i]; break; }
    }
    if ge {
        let mut d = [0u64; 4];
        let mut borrow = 0u128;
        for i in 0..4 {
            let bi = (c[i] as u128).wrapping_sub(n[i] as u128).wrapping_sub(borrow);
            d[i] = bi as u64;
            borrow = (bi >> 127) & 1;
        }
        d
    } else {
        c
    }
}

/// limbs → 256 位（LSB=0 整数位序——与 EC 循环位消费同源）。
fn limbs_to_bits_le(v: &[u64; 4]) -> [bool; 256] {
    std::array::from_fn(|i| (v[i / 64] >> (i % 64)) & 1 == 1)
}

/// be32 字节 → limbs（大端词序）。
fn be32_to_limbs(b: &[u8; 32]) -> [u64; 4] {
    // BE 字节串 → 小端 limbs（limbs[0]=最低 64 位——与 fr_to_limbs/q_limbs 同约定）。
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&b[i * 8..i * 8 + 8]);
        out[3 - i] = u64::from_be_bytes(chunk);
    }
    out
}

/// limbs 比较（r >= n 判定）。
fn ge_limbs(r: &[u64; 4], n: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if r[i] != n[i] {
            return r[i] > n[i];
        }
    }
    true
}

/// limbs mod-n 加法（wrap 后至多两次条件减 n）。
fn add_mod_n(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let n = crate::sm2_params::n_limbs();
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = (a[i] as u128) + (b[i] as u128) + carry;
        r[i] = s as u64;
        carry = s >> 64;
    }
    for _ in 0..2 {
        let over = carry > 0 || ge_limbs(&r, &n);
        if !over {
            break;
        }
        let mut borrow = 0u128;
        for i in 0..4 {
            let bi = (r[i] as u128).wrapping_sub(n[i] as u128).wrapping_sub(borrow);
            r[i] = bi as u64;
            borrow = (bi >> 127) & 1;
        }
        carry = 0;
    }
    r
}

/// 持有者侧 Schnorr 证明：k fresh → R=kG → c → z=k+c·Id mod n。
pub fn pilink_prove(id_u: &[u8; 32], p: &(FpSM2, FpSM2)) -> PiLink {
    use rand::RngCore;
    let mut kb = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut kb);
    let k = be32_to_limbs(&kb);
    let k_bits = limbs_to_bits_le(&k);
    let r_pt = crate::sm2_ec_plonkish::affine_mul_bits(
        &k_bits,
        Some(crate::sm2_ec_plonkish::g_coords()),
    )
    .expect("k∈[1,n−1] 概率 1−2^{-255}；零事件按 unreachable 处理");
    let c = pilink_challenge(&r_pt, p);
    let id_limbs = be32_to_limbs(id_u);
    let c_id = crate::sm2_full_statement_assemble::sm2_sign_host::mul_mod_n(&c, &id_limbs);
    let z = add_mod_n(&k, &c_id);
    PiLink { r_pt, z: crate::sm2_params::fr_from_limbs(&z) }
}

/// 签发者侧 Schnorr 验证：c'=重算；R' = z·G + (n−c')·P；比对 R'==R。
pub fn pilink_verify(p: &(FpSM2, FpSM2), pi: &PiLink) -> bool {
    let c = pilink_challenge(&pi.r_pt, p);
    let n = crate::sm2_params::n_limbs();
    // n − c（c=0 概率可忽略；保守取 n 自身⟹乘积为 O⟹验证失败方向安全）
    let mut nc = [0u64; 4];
    let mut borrow = 0u128;
    for i in 0..4 {
        let bi = (n[i] as u128).wrapping_sub(c[i] as u128).wrapping_sub(borrow);
        nc[i] = bi as u64;
        borrow = (bi >> 127) & 1;
    }
    let z_bits = limbs_to_bits_le(&crate::sm2_params::fr_to_limbs(&pi.z));
    let nc_bits = limbs_to_bits_le(&nc);
    let zg = crate::sm2_ec_plonkish::affine_mul_bits(
        &z_bits,
        Some(crate::sm2_ec_plonkish::g_coords()),
    );
    let ncp = crate::sm2_ec_plonkish::affine_mul_bits(&nc_bits, Some(*p));
    match crate::sm2_ec_plonkish::affine_add(zg, ncp) {
        Some((rx, ry)) => {
            crate::sm2_z_anchor::fe_be32(&rx) == crate::sm2_z_anchor::fe_be32(&pi.r_pt.0)
                && crate::sm2_z_anchor::fe_be32(&ry) == crate::sm2_z_anchor::fe_be32(&pi.r_pt.1)
        }
        None => false,
    }
}

/// 加入请求（U → I）。**类型面结构承诺：无 Id_u/M 字段。**
pub struct JoinRequest {
    /// P = Id_u·G（注册表点）
    pub p: (FpSM2, FpSM2),
    /// e = SM3(Z_A‖M)（摘要整数，fold_digest_fp 口径）
    pub e: FpSM2,
    /// attrs_u（策略属性，公开）
    pub attrs_u: [u8; 32],
    /// pk_u（持有者公钥，公开）
    pub pk_u: (FpSM2, FpSM2),
    /// 声称到期 epoch（T2.6-C：持有者**声称值**，本身无密码学地位——经
    /// ③′ 与 π_link 实例 stmt_exp 绑定、经 ⑤ 施窗口策略后方承重）
    pub exp_u: u32,
    /// π_link（e↔P 绑定证明，G₁a 承重件）
    pub pi_link: PiLink,
    /// PoP=(r,s)：对 pop_digest(pk_u) 的 SM2 签名（持有证明）
    pub pop: ([u64; 4], [u64; 4]),
}

/// 持有者本地状态（永不出本地；`m` 为凭证消息
/// M=x(P)‖attrs_u‖pk_u(x‖y)‖exp_u‖parity(y(P))，133B——T2.6 有效期 4B 尾段
/// + A1″ 压缩奇偶尾字节（2026-09-09；与电路 full_statement_host_with_idgx
/// 的 b3[36]=0x02|(y LSB) 同口径——M 与 (S1) 消息逐字节同一）。
pub struct HolderSecret {
    pub sk_u: [u64; 4],
    pub pk_u: (FpSM2, FpSM2),
    pub id_u: [u8; 32],
    pub attrs_u: [u8; 32],
    pub m: [u8; 133],
}

/// 签发回复：σ_I=(r_s,s_s)——对摘要 e 的 SM2 签名（limbs 口径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinReply {
    pub r_s: [u64; 4],
    pub s_s: [u64; 4],
}

/// 签发侧六道检查的拒绝分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    /// ① 注册点唯一性（P∈points(REG)）
    DuplicatePoint,
    /// ② PoP 验证失败
    PopFailure,
    /// ③′ π_link 语句不匹配（跨 e/P/exp 提交）/ ④ 证明门未过
    LinkFailure,
    /// ⑤ 到期声明已过（stmt_exp ≤ issuer_now，含 ==now）
    ExpiredClaim,
    /// ⑤ 超出最大有效期窗口（stmt_exp > issuer_now + MAX）
    WindowExceeded,
}

/// 语句摘要三件套（(S1) 同源真值：块布局 + native 链摘要 + 折叠值）。
pub struct JoinDigest {
    /// 三块消息（B₁/B₂/B₃，字节级 = T1 full_statement_host 输出）
    pub blocks: [[u8; 64]; 3],
    /// 三块链摘要 8 词
    pub dg_words: [u32; 8],
    /// e = fold(dg_words)（(S1) 公开语句值口径）
    pub e: FpSM2,
}

/// 语句摘要（幂等纯函数）：**零重实现**——布局委托 T1 真值源
/// `full_statement_host`（该函数只读 id_u/attrs_u/pk_u/pk_i/exp_u 五域；
/// 无关见证位由 t2 双见证锁定），链式压缩 + fold 与 (S1) 装配同式。
/// exp_u 为显式参数（T2.6-C：持有者声明值，经 [`holder_prepare`] 单一真值源注入）。
pub fn join_digest(
    pk_i: &(FpSM2, FpSM2),
    id_u: &[u8; 32],
    attrs_u: &[u8; 32],
    pk_u: &(FpSM2, FpSM2),
    exp_u: u32,
) -> JoinDigest {
    // 持有者口径：有 id_u（经 full_statement_host 内部重算 x(Id·G)）
    join_digest_common(
        &crate::sm2_full_statement_assemble::full_statement_host(&{
            let mut stub = crate::sm2_full_statement_assemble::FullStatementWitness {
                sk_u: [0; 4],
                pk_u: *pk_u,
                id_u: *id_u,
                attrs_u: *attrs_u,
                exp_u,
                r: [0; 4],
                r_s: [0; 4],
                s_s: [0; 4],
                pk_i: *pk_i,
                apk: (FpSM2::ZERO, FpSM2::ZERO),
            };
            stub
        }),
    )
}

/// 签发者重算口径（A1″ 第五道）：点输入——压缩编码（x‖奇偶）由公开点直接
/// 导出，哈希输入全公开。
pub fn join_digest_from_point(
    pk_i: &(FpSM2, FpSM2),
    p: &(FpSM2, FpSM2),
    attrs_u: &[u8; 32],
    pk_u: &(FpSM2, FpSM2),
    exp_u: u32,
) -> JoinDigest {
    let idgx_be = crate::sm2_z_anchor::fe_be32(&p.0);
    // A1″（2026-09-09）：奇偶字节 = 0x02 + (y 规范整数 LSB)——Id↦n−Id 歧义封死。
    let idg_par = 0x02u8 | (crate::sm2_z_anchor::fe_be32(&p.1)[31] & 1);
    join_digest_common(&crate::sm2_full_statement_assemble::full_statement_host_with_idgx(
        pk_i, &idgx_be, idg_par, attrs_u, pk_u, exp_u,
    ))
}

fn join_digest_common(host: &crate::sm2_full_statement_assemble::FullStatementHost) -> JoinDigest {
    let c = crate::sm3_native_ref::compress;
    let v1 = c(&crate::sm3_native_ref::IV, &host.blocks[0]);
    let v2 = c(&v1, &host.blocks[1]);
    let dg_words = c(&v2, &host.blocks[2]);
    let e = crate::sm2_full_statement_assemble::fold_digest_fp(&dg_words);
    JoinDigest { blocks: host.blocks, dg_words, e }
}

/// PoP 域摘要：e_pop = fold(SM3(POP_CHALLENGE ‖ pk_u.x ‖ pk_u.y))。
fn pop_digest(pk_u: &(FpSM2, FpSM2)) -> FpSM2 {
    let mut msg = POP_CHALLENGE.to_vec();
    msg.extend_from_slice(&crate::sm2_z_anchor::fe_be32(&pk_u.0));
    msg.extend_from_slice(&crate::sm2_z_anchor::fe_be32(&pk_u.1));
    let dg = crate::sm3_native_ref::hash(&msg);
    let mut words = [0u32; 8];
    for k in 0..8 {
        words[k] = u32::from_be_bytes(dg[4 * k..4 * k + 4].try_into().expect("摘要界内"));
    }
    crate::sm2_full_statement_assemble::fold_digest_fp(&words)
}

/// 持有者侧 Join_U（全本地）：pk_u ← [sk_u]G；e 与三块语句；P=[Id_u]G（位序
/// = 电路 (S3) 同源：BE 字节 31−i/8 位 i%8）；PoP 签名；π_link 语句装配；
/// M 本地装配。返回 (请求, 持有者秘密)。
pub fn holder_prepare(
    sk_u: &[u64; 4],
    id_u: &[u8; 32],
    attrs_u: &[u8; 32],
    pk_i: &(FpSM2, FpSM2),
    exp_u: u32,
) -> (JoinRequest, HolderSecret) {
    use crate::sm2_full_statement_assemble::sm2_sign_host as sign_host;
    // pk_u = [sk_u]G（宿主真标量乘，与电路 EC 门族同源底层）
    let pk_u = sign_host::pk_from_sk(sk_u);
    // e 与三块语句（(S1) 同源真值；exp_u 单一真值源注入）
    let jd = join_digest(pk_i, id_u, attrs_u, &pk_u, exp_u);
    // P = Id_u·G——位序与 (S3) EC 环见证同源：整数位 i（LSB=0）= 字节 31−i/8 位 i%8
    let id_bits: [bool; 256] =
        std::array::from_fn(|i| (id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
    let p = crate::sm2_ec_plonkish::affine_mul_bits(
        &id_bits,
        Some(crate::sm2_ec_plonkish::g_coords()),
    )
    .expect("[Id_u]G 标量乘成功");
    // PoP：对域分离摘要的 SM2 签名（持有证明，prem:registry 既有要求）
    let e_pop = pop_digest(&pk_u);
    let pop = sign_host::sign(&crate::sm2_params::fr_to_limbs(&e_pop), sk_u);
    // M 永不出本地：凭证消息在此装配（签发者视图=JoinRequest，类型面无 M）。
    // T2.6-C：exp_u 为请求参数——m 尾段、π_link.stmt_exp、JoinRequest.exp_u
    // 三处同源零漂移（单一真值源；策略绑定承重 = π_link 实例钉 + ③′）。
    // A1'：M 的身份分量 = x(Id_u·G)（与消息 B₁ 同源——join_digest 的
    // full_statement_host 已按此口径，M 装配同步）。
    // A1″（2026-09-09）：尾部追加压缩奇偶字节 parity@b3[36] 口径——
    // 0x02|(fe_be32(y)[31]&1)，与电路 full_statement_host_with_idgx 同式
    // （禁手抄：直接从本函数已算出的 P 派生）。
    let idg_par = 0x02u8 | (crate::sm2_z_anchor::fe_be32(&p.1)[31] & 1);
    let mut m = [0u8; 133];
    m[..32].copy_from_slice(&crate::sm2_z_anchor::fe_be32(&p.0));
    m[32..64].copy_from_slice(attrs_u);
    m[64..96].copy_from_slice(&crate::sm2_z_anchor::fe_be32(&pk_u.0));
    m[96..128].copy_from_slice(&crate::sm2_z_anchor::fe_be32(&pk_u.1));
    m[128..132].copy_from_slice(&exp_u.to_be_bytes());
    m[132] = idg_par;
    let pi_link = pilink_prove(id_u, &p);
    let req = JoinRequest {
        p,
        e: jd.e,
        attrs_u: *attrs_u,
        pk_u,
        exp_u,
        pi_link,
        pop,
    };
    let secret = HolderSecret { sk_u: *sk_u, pk_u, id_u: *id_u, attrs_u: *attrs_u, m };
    (req, secret)
}

/// 签发侧 Join_I（六道检查）：①注册点唯一 → ②PoP → ③′π_link 语句三合
/// （e↔P↔exp，跨提交必败处）→ ④π_link 证明门（电路层接管前环境占位）→
/// ⑤有效期窗口策略（对绑定值 stmt_exp 施策）→ ⑥对摘要 e 直接签名
/// （预哈希模式）。检查次序钉死：③′ 先于 ⑤（失配请求按 LinkFailure
/// 分类，不落入窗口类目——t11 语义）。
pub fn issuer_review(
    req: &JoinRequest,
    sk_i: &[u64; 4],
    reg_points: &[(FpSM2, FpSM2)],
    link_ok: bool,
    issuer_now: u32,
    max_validity_window: u32,
) -> Result<JoinReply, JoinError> {
    // 点相等 = 规范 BE 字节相等（ avoids 域 PartialEq 假设，语义等价）
    let fe_eq = |a: &FpSM2, b: &FpSM2| {
        crate::sm2_params::fr_to_limbs(a) == crate::sm2_params::fr_to_limbs(b)
    };
    let pt_eq = |a: &(FpSM2, FpSM2), b: &(FpSM2, FpSM2)| {
        crate::sm2_z_anchor::fe_be32(&a.0) == crate::sm2_z_anchor::fe_be32(&b.0)
            && crate::sm2_z_anchor::fe_be32(&a.1) == crate::sm2_z_anchor::fe_be32(&b.1)
    };
    // ① 注册点唯一（prem:registry 既有流程约束的结构面）
    if reg_points.iter().any(|q| pt_eq(q, &req.p)) {
        return Err(JoinError::DuplicatePoint);
    }
    // ② PoP（持有证明：对域分离摘要的 SM2 签名，(S2) 四步同式重放）
    let e_pop = pop_digest(&req.pk_u);
    let pop_ok = crate::sm2_verify_assemble::verify_replay(
        e_pop,
        crate::sm2_params::fr_from_limbs(&req.pop.0),
        crate::sm2_params::fr_from_limbs(&req.pop.1),
        req.pk_u.0,
        req.pk_u.1,
    )
    .ok;
    if !pop_ok {
        return Err(JoinError::PopFailure);
    }
    // ③′ 摘要本地重算（A1' 第四道，2026-09-06）：e 的哈希输入全部在签发者视图内
    //（含 x(P)——公开点编码），重算核对取代旧「π_link 语句三合」。腐化持有者的
    // 跨提交在此必败（绑定的语义等价且更强：无任何 ZK 绑定需求）。
    let pk_i = crate::sm2_full_statement_assemble::sm2_sign_host::pk_from_sk(sk_i);
    let jd = join_digest_from_point(&pk_i, &req.p, &req.attrs_u, &req.pk_u, req.exp_u);
    if !fe_eq(&jd.e, &req.e) {
        return Err(JoinError::LinkFailure);
    }
    // ④ π_link Schnorr 验证（注册点 DL 知识——标准 Σ 验证；link_ok 参数保留
    // 为环境占位兼容位，真实验证以 pilink_verify 为准）
    if !link_ok || !pilink_verify(&req.p, &req.pi_link) {
        return Err(JoinError::LinkFailure);
    }
    // ⑤ 有效期窗口策略（对请求声称值 exp_u 施策——经第四道重算已绑定进 e；
    // ==now 属拒侧含等号；saturating_add 贴上界时窗口延展到纪元末端）
    if req.exp_u <= issuer_now {
        return Err(JoinError::ExpiredClaim);
    }
    if req.exp_u > issuer_now.saturating_add(max_validity_window) {
        return Err(JoinError::WindowExceeded);
    }
    // ⑥ 对摘要 e 直接签名（预哈希模式；GB/T 32918.2 签名方程以 e 为输入）
    let (r_s, s_s) =
        crate::sm2_full_statement_assemble::sm2_sign_host::sign(&crate::sm2_params::fr_to_limbs(&req.e), sk_i);
    Ok(JoinReply { r_s, s_s })
}

/// 持有者装配凭证 (σ_I, M)。**M 只在此出现且此前永不出本地**——结构承诺
/// 的收口点；后续 Show 路径消费 (σ_I, M)，与 def:pi 凭证结构逐字不变
/// （T2.6+A1″：M=133B 含 exp_u 4B 尾段与压缩奇偶字节）。
pub fn credential(secret: &HolderSecret, reply: &JoinReply) -> ([u64; 4], [u64; 4], [u8; 133]) {
    (reply.r_s, reply.s_s, secret.m)
}

// ───────────────────────────── 测试（TDD 红先行） ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_full_statement_assemble::{
        fold_digest_fp, full_statement_host, sm2_sign_host, FullStatementWitness,
    };
    use crate::sm2_params::{fr_from_limbs, fr_to_limbs};
    use crate::sm2_verify_assemble::verify_replay;
    use crate::sm2_z_anchor::{z_a_words, DEFAULT_ID};

    /// 判决行（TDD 纪律：红绿直接可见）。
    fn judge(name: &str, ok: bool) {
        println!("T2.4-JUDGE {name} = {}", if ok { "PASS" } else { "FAIL" });
        assert!(ok);
    }

    fn issuer_key() -> [u64; 4] {
        sm2_sign_host::test_issuer_key()
    }

    fn issuer_pk() -> (FpSM2, FpSM2) {
        sm2_sign_host::pk_from_sk(&issuer_key())
    }

    /// 确定性测试向量（native hash 派生，无 RNG、无手抄常量）。
    fn test_bytes(seed: &[u8]) -> [u8; 32] {
        crate::sm3_native_ref::hash(seed)
    }

    fn holder_key() -> [u64; 4] {
        [0x0F0E_D0C1, 0x1111_2222, 0, 0x3333_4444]
    }

    fn fe_eq(a: &FpSM2, b: &FpSM2) -> bool {
        fr_to_limbs(a) == fr_to_limbs(b)
    }

    /// (S1) 同构 native 链：v1=compress(IV,B₁)、v2=compress(v1,B₂)、dg=compress(v2,B₃)。
    fn chain(blocks: &[[u8; 64]; 3]) -> [u32; 8] {
        let c = crate::sm3_native_ref::compress;
        let v1 = c(&crate::sm3_native_ref::IV, &blocks[0]);
        let v2 = c(&v1, &blocks[1]);
        c(&v2, &blocks[2])
    }

    /// T1 · happy path：加入全程 + σ_I 对 e 往返 + PoP 往返 + M 重算一致性
    /// （native 全消息 hash 独立路径）+ 篡改 e 必败。
    #[test]
    fn t1_happy_path_end_to_end() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (req, sec) = holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, VALID_EXP);
        let reply =
            issuer_review(&req, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW).expect("诚实加入必成功");
        let (r_s, s_s, m) = credential(&sec, &reply);

        // σ_I 对 e 验证通过（(S2) 四步 native 重放）
        let out = verify_replay(
            req.e,
            fr_from_limbs(&r_s),
            fr_from_limbs(&s_s),
            pk_i.0,
            pk_i.1,
        );
        let sig_ok = out.ok;
        // M 重算一致性：SM3(Z_A ‖ M) 三块链折叠 == req.e（native hash 独立路径；
        // A1″：M=133B ⟹ 语句 165B，三块结构不变 [推得+装配实测]）
        let za_words = z_a_words(DEFAULT_ID, &pk_i);
        let mut msg165 = [0u8; 165];
        for k in 0..8 {
            msg165[4 * k..4 * k + 4].copy_from_slice(&za_words[k].to_be_bytes());
        }
        msg165[32..].copy_from_slice(&m);
        let dg_native = crate::sm3_native_ref::hash(&msg165);
        let mut words = [0u32; 8];
        for k in 0..8 {
            words[k] = u32::from_be_bytes(dg_native[4 * k..4 * k + 4].try_into().expect("界内"));
        }
        let e_re = fold_digest_fp(&words);
        let m_ok = fe_eq(&e_re, &req.e);
        // PoP 往返
        let pop_ok = verify_replay(
            super::pop_digest(&req.pk_u),
            fr_from_limbs(&req.pop.0),
            fr_from_limbs(&req.pop.1),
            req.pk_u.0,
            req.pk_u.1,
        )
        .ok;
        // 篡改 e 必败（签名绑定摘要）
        let e2 = req.e + req.e;
        let tamper_ok = verify_replay(
            e2,
            fr_from_limbs(&r_s),
            fr_from_limbs(&s_s),
            pk_i.0,
            pk_i.1,
        )
        .ok;
        judge("t1_happy_path_end_to_end", sig_ok && m_ok && pop_ok && !tamper_ok);
    }

    /// T2 · 语句布局 crosscheck：join_digest 与 T1 真值源 full_statement_host
    /// 字节级一致（双见证位差锁定「只读 id/attrs/pk_u/pk_i/exp_u 五域」）。
    #[test]
    fn t2_statement_layout_crosscheck() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let pk_u = sm2_sign_host::pk_from_sk(&holder_key());
        let jd = join_digest(&pk_i, &id_u, &attrs, &pk_u, VALID_EXP);

        // 见证甲：无关域填非零；见证乙：无关域换值——blocks 必须逐字节相同
        // （exp_u = 消息域，双见证同值锁定；无关域 = r/r_s/s_s/sk_u/apk）
        let mk = |r: [u64; 4], sk: [u64; 4]| FullStatementWitness {
            sk_u: sk,
            pk_u,
            id_u,
            attrs_u: attrs,
            exp_u: VALID_EXP,
            r,
            r_s: [r[0]; 4],
            s_s: [sk[0]; 4],
            pk_i,
            apk: (FpSM2::ZERO, FpSM2::ZERO),
        };
        let h1 = full_statement_host(&mk([1, 2, 3, 4], holder_key()));
        let h2 = full_statement_host(&mk([9, 9, 9, 9], [0xAAAA_BBBB, 0, 0, 1]));
        let blocks_stable = h1.blocks == h2.blocks;
        let cross = jd.blocks == h1.blocks && jd.dg_words == chain(&h1.blocks) && fe_eq(&jd.e, &fold_digest_fp(&chain(&h1.blocks)));
        judge("t2_statement_layout_crosscheck", blocks_stable && cross);
    }

    /// T3 · 重复注册点拒绝：同 Id_u 二次加入 → DuplicatePoint。
    #[test]
    fn t3_duplicate_point_rejected() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (req, _sec) = holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, VALID_EXP);
        let first = issuer_review(&req, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW);
        let second = issuer_review(&req, &issuer_key(), &[req.p], true, ISSUER_NOW, MAX_WINDOW);
        judge(
            "t3_duplicate_point_rejected",
            first.is_ok() && second == Err(JoinError::DuplicatePoint),
        );
    }

    /// T4 · PoP 错钥拒绝：请求体 pk_u 诚实、PoP 用他钥签 → PopFailure。
    #[test]
    fn t4_wrong_pop_rejected() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (mut req, _sec) = holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, VALID_EXP);
        let e_pop = super::pop_digest(&req.pk_u);
        req.pop = sm2_sign_host::sign(&fr_to_limbs(&e_pop), &[0xDEAD_BEEF, 0, 0, 7]);
        let got = issuer_review(&req, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW);
        judge("t4_wrong_pop_rejected", got == Err(JoinError::PopFailure));
    }

    /// T5 · π_link 证明门拒绝：语句匹配但 link_ok=false → LinkFailure。
    #[test]
    fn t5_link_gate_rejected() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (req, _sec) = holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, VALID_EXP);
        let got = issuer_review(&req, &issuer_key(), &[], false, ISSUER_NOW, MAX_WINDOW);
        judge("t5_link_gate_rejected", got == Err(JoinError::LinkFailure));
    }

    /// T6 · PoP 域分离：e_pop ≠ e（同 pk_u），且 PoP 签名不可作语句签名重放。
    #[test]
    fn t6_pop_domain_separation() {
        let pk_u = sm2_sign_host::pk_from_sk(&holder_key());
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let jd = join_digest(&issuer_pk(), &id_u, &attrs, &pk_u, VALID_EXP);
        let e_pop = super::pop_digest(&pk_u);
        let domains_apart = !fe_eq(&e_pop, &jd.e);
        // PoP 签名对语句摘要 e 验证必败（域分离的签名层面后果）
        let (r_pop, s_pop) = sm2_sign_host::sign(&fr_to_limbs(&e_pop), &holder_key());
        let replay = verify_replay(
            jd.e,
            fr_from_limbs(&r_pop),
            fr_from_limbs(&s_pop),
            pk_u.0,
            pk_u.1,
        )
        .ok;
        judge("t6_pop_domain_separation", domains_apart && !replay);
    }

    /// T8 · 跨 e/P 提交必败（π_link 声音性的签发侧锚）：腐化持有者以诚实
    /// π_link 配对被篡改的 e → LinkFailure（未注册 Id'' 凭证不可得的机制面）。
    #[test]
    fn t8_cross_submission_rejected() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (mut req, _sec) = holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, VALID_EXP);
        req.e = req.e + req.e; // 篡改 e，π_link 仍锚定诚实 (e, P)
        let got = issuer_review(&req, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW);
        judge("t8_cross_submission_rejected", got == Err(JoinError::LinkFailure));
    }

    // ─────────────── T2.6-C 窗口策略（t9–t12；确定性常量，无 RNG） ───────────────

    /// 签发者当前 epoch（测试基准）。
    const ISSUER_NOW: u32 = 500;
    /// 最大有效期窗口。
    const MAX_WINDOW: u32 = 100_000;
    /// 窗口内合法到期声明（>now 且 ≤now+MAX）。
    const VALID_EXP: u32 = 1_000;

    /// T9 · 过期声明拒绝（⑤ 窗口策略下界：==now 属拒侧，含等号语义）→ ExpiredClaim。
    #[test]
    fn t9_expired_request_rejected() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (req, _sec) = holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, ISSUER_NOW);
        let got = issuer_review(&req, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW);
        judge("t9_expired_request_rejected", got == Err(JoinError::ExpiredClaim));
    }

    /// T10 · 超窗拒绝（⑤ 上界外一点：now+MAX+1）→ WindowExceeded。
    #[test]
    fn t10_window_exceeded_rejected() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (req, _sec) =
            holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, ISSUER_NOW + MAX_WINDOW + 1);
        let got = issuer_review(&req, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW);
        judge("t10_window_exceeded_rejected", got == Err(JoinError::WindowExceeded));
    }

    /// T11 · exp 声明失配拒绝（A1' 第四道重算的**缺口本体负例**，2026-09-06
    /// 语义演进）：请求携带的 e 由 exp=VALID_EXP 计算，但声称字段 exp_u 被篡改
    /// 为 10^9（可过窗口策略的谎报）⟹ 签发者以公开输入重算 e' 覆盖篡改值、
    /// 与携带 e 失配 ⟹ LinkFailure——exp 绑定升密码学的承重测试：第四道缺席时
    /// 本请求被接受（有效期窗口整体失效的原始漏洞，T2.6 场景在 A1' 下的等价
    /// 形态——绑定点从 π_link 实例移入哈希输入）。
    #[test]
    fn t11_exp_claim_mismatch_rejected() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (mut req, _sec) = holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, VALID_EXP);
        req.exp_u = 1_000_000_000;
        let got = issuer_review(&req, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW);
        judge("t11_exp_claim_mismatch_rejected", got == Err(JoinError::LinkFailure));
    }

    /// T13 · π_link Schnorr 正确性三探（A1'，2026-09-06）：诚实证明可验证；
    /// 篡改 z 应答 ⟹ 验证失败；换点（他人 P）⟹ 挑战不匹配 ⟹ 验证失败。
    #[test]
    fn t13_pilink_schnorr_probes() {
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let id_bits: [bool; 256] =
            std::array::from_fn(|i| (id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
        let p = crate::sm2_ec_plonkish::affine_mul_bits(
            &id_bits,
            Some(crate::sm2_ec_plonkish::g_coords()),
        )
        .expect("Id·G");
        let pi = pilink_prove(&id_u, &p);
        judge("t13_honest_verifies", pilink_verify(&p, &pi));
        let mut pi2 = PiLink { r_pt: pi.r_pt, z: pi.z + FpSM2::from(7u64) };
        judge("t13_tampered_z_rejected", !pilink_verify(&p, &pi2));
        let other_id = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U2");
        let ob: [bool; 256] =
            std::array::from_fn(|i| (other_id[31 - i / 8] >> (i % 8)) & 1 == 1);
        let p_other = crate::sm2_ec_plonkish::affine_mul_bits(
            &ob,
            Some(crate::sm2_ec_plonkish::g_coords()),
        )
        .expect("Id2·G");
        judge("t13_wrong_point_rejected", !pilink_verify(&p_other, &pi));
    }

    /// T14 · π_link Schnorr 微基准（v5，2026-09-07）：主机层 prove/verify 计时。
    /// prove≈1 次标量乘+1 哈希、verify≈2 次标量乘+1 哈希——实测数供 sec7 升级。
    #[test]
    fn t14_pilink_schnorr_microbench() {
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let id_bits: [bool; 256] =
            std::array::from_fn(|i| (id_u[31 - i / 8] >> (i % 8)) & 1 == 1);
        let p = crate::sm2_ec_plonkish::affine_mul_bits(
            &id_bits,
            Some(crate::sm2_ec_plonkish::g_coords()),
        )
        .expect("Id·G");
        // 预热 3 轮（代码路径/缓存稳定后再计时）
        for _ in 0..3 {
            let pi = pilink_prove(&id_u, &p);
            assert!(pilink_verify(&p, &pi));
        }
        const N: usize = 50;
        let t0 = std::time::Instant::now();
        let mut pis = Vec::with_capacity(N);
        for _ in 0..N {
            pis.push(pilink_prove(&id_u, &p));
        }
        let prove_us = t0.elapsed().as_micros() / N as u128;
        let t1 = std::time::Instant::now();
        for pi in &pis {
            assert!(pilink_verify(&p, pi));
        }
        let verify_us = t1.elapsed().as_micros() / N as u128;
        println!(
            "[pilink-microbench] N={N} prove_mean_us={prove_us} verify_mean_us={verify_us}"
        );
        assert!(prove_us > 0 && verify_us > 0);
    }

    /// T12 · 窗口边界双探正例（⑤ 语义含等号：now+1 与 now+MAX 均须接受）。
    #[test]
    fn t12_window_boundary_pass() {
        let pk_i = issuer_pk();
        let id_u = test_bytes(b"SM2-JOIN-TEST-IDENTITY-U1");
        let attrs = test_bytes(b"SM2-JOIN-TEST-ATTRS-U1");
        let (req_lo, _s1) = holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, ISSUER_NOW + 1);
        let (req_hi, _s2) =
            holder_prepare(&holder_key(), &id_u, &attrs, &pk_i, ISSUER_NOW + MAX_WINDOW);
        let lo = issuer_review(&req_lo, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW);
        let hi = issuer_review(&req_hi, &issuer_key(), &[], true, ISSUER_NOW, MAX_WINDOW);
        judge("t12_window_boundary_pass", lo.is_ok() && hi.is_ok());
    }
}
