//! 装配封装：JobSpec → 论文栈 `Assembled`（飞证 B3 fork——AUTH 单档）。
//!
//! 校验序（全部先于任何装配工作）：① AUTH 准入门禁（FZ_ZK_ALLOW_AUTH=1）
//! → ② 注册表参数校验（reps/log_rate）→ ③ binding 一致性（AUTH=绑定档必携，
//! t_epoch≠0）→ ④ 输入面存在性与档位一致 → ⑤ 分发。
//!
//! 结构五元组（[`StructureTuple`]）是档位锚的载体：结构是锚、时间只是参考档
//! （锚断言一律走五元组）。AUTH 结构锚：104,543 约束 / 11,448 advice /
//! lookups 536 [实测 2026-09-23 R2 换代——B4-T7 104,287+256=SMT 链 64 组×4
//! 查表门（撤销空洞封堵 weave_proto_gates）；13,057−1,609=体B CommitOne
//! 空挂死列清偿 plan_z_parts_single；24+512=SMT 64 组×8 通道]。

use plonkish_sm2_probe::sm2_auth_assemble::{sn_hash_of, AuthPreimage};
use plonkish_sm2_probe::sm2_full_statement_assemble::{
    fold_digest_fp, full_statement_host_auth_of, AuthCPreimage,
};
use plonkish_sm2_probe::sm2_params;
use plonkish_sm2_probe::sm2_verify_assemble::{verify_replay, Assembled};

use crate::ctx_tag::fp_from_be32_hex;
use crate::profile::{
    AssembleError, CheckpointInput, JobSpec, Profile, ProfileInput, ENV_ALLOW_AUTH,
    ENV_ALLOW_TRAIL, SUPPORTED_LOG_RATE, SUPPORTED_REPS, TRAIL_N,
};

/// 装配结构五元组（判决件同口径）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureTuple {
    /// 总约束数 `info.constraints.len()`。
    pub constraints: usize,
    /// advice 列数。
    pub advice_cols: usize,
    /// 复制环数 `info.permutations.len()`。
    pub copy_rings: usize,
    /// 实例数（首实例向量长度）。
    pub instances: usize,
    /// 电路行数对数（规模 = 2^k 行）。
    pub nv: usize,
}

/// `Assembled` 的结构视图扩展（论文栈类型零触碰）。
pub trait AssembledExt {
    fn structure(&self) -> StructureTuple;
}

impl AssembledExt for Assembled {
    fn structure(&self) -> StructureTuple {
        StructureTuple {
            constraints: self.info.constraints.len(),
            advice_cols: self.advice.len(),
            copy_rings: self.info.permutations.len(),
            instances: self.instances.first().map_or(0, |v| v.len()),
            nv: self.info.k,
        }
    }
}

/// AUTH/TRAIL 准入门禁：环境旗标必须恰为 "1"（按档）。
fn allow(profile: Profile) -> bool {
    match profile {
        Profile::Auth => std::env::var(ENV_ALLOW_AUTH).as_deref() == Ok("1"),
        Profile::Trail => std::env::var(ENV_ALLOW_TRAIL).as_deref() == Ok("1"),
    }
}

/// 定长字节 hex 严格解析（2N hex → `[u8; N]`）。
fn fixed_bytes<const N: usize>(name: &'static str, hex: &str) -> Result<[u8; N], AssembleError> {
    if hex.len() != 2 * N || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AssembleError::BadBytes {
            name,
            reason: "hex 长度/字符非法（须定长偶数位 hex）",
        });
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| AssembleError::BadBytes { name, reason: "非法 hex" })?;
    }
    Ok(out)
}

/// 语句域元素严格解析（32B 大端 hex）；失败归一 [`AssembleError::BadFieldElement`]。
fn field_elem(name: &'static str, hex: &str) -> Result<plonkish_sm2_probe::FpSM2, AssembleError> {
    fp_from_be32_hex(hex).ok_or(AssembleError::BadFieldElement {
        name,
        reason: "非法 hex/长度或值 ≥ p（严格解析，无归约）",
    })
}

/// 装配入口：校验序 → 档位分发（AUTH/TRAIL）。
pub fn assemble(spec: &JobSpec) -> Result<Assembled, AssembleError> {
    // ① 准入门禁——先于一切（门禁拒绝不泄露任何后续语义）。
    if !allow(spec.profile) {
        return Err(AssembleError::Forbidden { profile: spec.profile });
    }
    // ② 注册表参数校验。
    if spec.reps != SUPPORTED_REPS {
        return Err(AssembleError::UnsupportedParams {
            field: "reps",
            got: spec.reps,
            want: SUPPORTED_REPS,
        });
    }
    if spec.log_rate != SUPPORTED_LOG_RATE {
        return Err(AssembleError::UnsupportedParams {
            field: "log_rate",
            got: spec.log_rate,
            want: SUPPORTED_LOG_RATE,
        });
    }
    // ③ binding 一致性（AUTH=绑定档必携；TRAIL 非绑定档禁携）。
    match (spec.profile, &spec.binding) {
        (p, None) if p.is_bound() => return Err(AssembleError::MissingBinding),
        (p, Some(_)) if !p.is_bound() => {
            return Err(AssembleError::BindingNotApplicable { profile: p })
        }
        _ => {}
    }
    // ④ 输入面存在性与档位一致。
    let input = spec
        .input
        .as_ref()
        .ok_or(AssembleError::MissingInput { profile: spec.profile })?;
    if input.kind() != spec.profile {
        return Err(AssembleError::InputProfileMismatch {
            input: input.kind(),
            profile: spec.profile,
        });
    }
    // ⑤ 档位分发。
    match input {
        ProfileInput::Auth { .. } => assemble_auth(spec, input),
        ProfileInput::Trail { .. } => assemble_trail(input),
    }
}

/// TRAIL 检查点上限（B6-d5 K=2 起档；服务面容 1..=4——纪元内多锚定形态）。
const TRAIL_CHECKPOINT_MAX: usize = 4;

/// TRAIL 分发：载荷解析 → 检查点 fail-closed 验签 → 链电路+织入 → Assembled。
fn assemble_trail(input: &ProfileInput) -> Result<Assembled, AssembleError> {
    let ProfileInput::Trail {
        rows_hex,
        alt_max_cm,
        t_start,
        chain_head_hex,
        auth_id,
        device_pk_hex,
        checkpoints,
        binding,
    } = input
    else {
        unreachable!("分发前已对齐")
    };
    // 样本面：14B×TRAIL_N 定长（t BE4‖alt BE2‖lat BE4‖lon BE4）。
    if *alt_max_cm == 0 || *alt_max_cm > 0xFFFF {
        return Err(AssembleError::BadBytes {
            name: "alt_max_cm",
            reason: "高度上限域 1..65535（cm）",
        });
    }
    // R4 复验 P0-1 根修：引擎绑定一致性三查（alt_max/auth_id/chain_head——
    // 高度上限不再由证明者自报，见下方引擎签名验签）。
    if binding.alt_max_cm != *alt_max_cm
        || binding.auth_id != *auth_id
        || binding.chain_head_hex.to_ascii_lowercase() != chain_head_hex.to_ascii_lowercase()
    {
        return Err(AssembleError::BadBytes {
            name: "binding",
            reason: "引擎绑定与语句字段不一致（alt_max/auth_id/chain_head）",
        });
    }
    let rows_raw = hex::decode(rows_hex)
        .map_err(|_| AssembleError::BadBytes { name: "rows_hex", reason: "非法 hex" })?;
    if rows_raw.len() != 14 * TRAIL_N {
        return Err(AssembleError::BadBytes {
            name: "rows_hex",
            reason: "样本序列长度错（须 14B×n，n=TRAIL_N 钉定档——见 profile.rs）",
        });
    }
    let mut rows = Vec::with_capacity(TRAIL_N);
    for (i, c) in rows_raw.chunks_exact(14).enumerate() {
        let t = u32::from_be_bytes(c[0..4].try_into().expect("定长切片"));
        let alt = u16::from_be_bytes(c[4..6].try_into().expect("定长切片"));
        let lat = i32::from_be_bytes(c[6..10].try_into().expect("定长切片"));
        let lon = i32::from_be_bytes(c[10..14].try_into().expect("定长切片"));
        let _ = i;
        rows.push((t, alt, lat, lon));
    }
    // 首样本 t 与声明 t_start 一致（fail-fast——电路 t_start 钉的服务面前置）。
    if rows[0].0 != *t_start {
        return Err(AssembleError::BadBytes {
            name: "t_start",
            reason: "声明起始时间≠首样本时间戳",
        });
    }
    let chain_head: [u8; 32] = fixed_bytes("chain_head_hex", chain_head_hex)?;
    // 设备公钥（曲线点校验）。
    let dpk = pk_from_hex_str("device_pk_hex", device_pk_hex)?;
    // 检查点面（B6-d7/d8'）：数量域+逐个验签（报文绑定 auth_id/seq/锚定头/围栏状态）。
    if checkpoints.is_empty() || checkpoints.len() > TRAIL_CHECKPOINT_MAX {
        return Err(AssembleError::BadBytes {
            name: "checkpoints",
            reason: "检查点数量域 1..=4（B6-d5 起档）",
        });
    }
    for (i, cp) in checkpoints.iter().enumerate() {
        verify_one_checkpoint(cp, i, *auth_id, &chain_head, dpk)?;
    }
    // 样本链重算（trail_host 单一事实源）——末头必须==锚定头（TRAIL 语句对象）。
    let mut h = plonkish_sm2_probe::trail_host::genesis_head();
    let mut blocks = Vec::with_capacity(TRAIL_N);
    for (t, alt, lat, lon) in &rows {
        blocks.push(plonkish_sm2_probe::trail_host::sample_block(
            &h, *t, *alt, *lat, *lon,
        ));
        h = plonkish_sm2_probe::trail_host::sample_hash(&h, *t, *alt, *lat, *lon);
    }
    if h != chain_head {
        return Err(AssembleError::BadBytes {
            name: "chain_head_hex",
            reason: "样本链末头≠锚定链头（记录与锚定不一致——fail-closed）",
        });
    }
    // R4 复验 P0-1：引擎绑定签名验签（fold_be_integer 口径，与检查点验签
    // 同族）——引擎钥在证明者域外 ⟹ 高度上限不可自报；第三方经
    // /authz/engine/pub 复核同一签名。
    let epk = pk_from_hex_str("binding.engine_pub_hex", &binding.engine_pub_hex)?;
    let bind_msg = format!(
        "FZ-TRAIL-BIND|{}|{}|{}",
        binding.auth_id,
        binding.alt_max_cm,
        binding.chain_head_hex.to_ascii_lowercase()
    );
    let bind_dg = plonkish_sm2_probe::sm3_native_ref::hash(bind_msg.as_bytes());
    let bind_e = plonkish_sm2_probe::trail_host::fold_be_integer(&bind_dg);
    let bind_sig_ok = if binding.sig_hex.len() == 128
        && binding.sig_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        let r = plonkish_sm2_probe::sm2_params::hex_to_limbs_le(&binding.sig_hex[..64]);
        let s = plonkish_sm2_probe::sm2_params::hex_to_limbs_le(&binding.sig_hex[64..]);
        plonkish_sm2_probe::sm2_verify_assemble::verify_replay(
            bind_e,
            plonkish_sm2_probe::sm2_params::fr_from_limbs(&r),
            plonkish_sm2_probe::sm2_params::fr_from_limbs(&s),
            epk.0,
            epk.1,
        )
        .ok
    } else {
        false
    };
    if !bind_sig_ok {
        return Err(AssembleError::BadBytes {
            name: "binding",
            reason: "引擎绑定签名未通过验签（alt_max 非引擎授权或报文被改）",
        });
    }
    let samples = plonkish_sm2_probe::trail_host::TrailSamples {
        rows,
        head: h,
        blocks,
        heads: Vec::new(),
    };
    let circ = plonkish_sm2_probe::sm3_lookup_weave::trail_chain_circuit(&samples.blocks);
    let woven = plonkish_sm2_probe::trail_weave::weave_trail(
        &circ,
        &plonkish_sm2_probe::trail_weave::TrailWiring {
            samples,
            alt_max_cm: u16::try_from(*alt_max_cm).expect("①已校验域"),
            t_start: *t_start,
            head_fold: plonkish_sm2_probe::trail_host::fold_words_be(&chain_head),
        },
    );
    // TrailCircuit → Assembled 适配（vendor 侧 from_parts 构造器：
    // prove/verify 只消费 info/advice/instances 三件，取证钩子面默认形态）。
    Ok(Assembled::from_parts(woven.info, woven.witness, woven.instances))
}

/// 单检查点验签（fail-closed：坏签名/报文长度错=BadCheckpoint 拒）。
fn verify_one_checkpoint(
    cp: &CheckpointInput,
    index: usize,
    auth_id: u64,
    chain_head: &[u8; 32],
    dpk: (plonkish_sm2_probe::FpSM2, plonkish_sm2_probe::FpSM2),
) -> Result<(), AssembleError> {
    let fs: [u8; 4] = fixed_bytes("fence_state_hex", &cp.fence_state_hex)
        .map_err(|_| AssembleError::BadCheckpoint { index, reason: "围栏状态须 8hex/4B" })?;
    let ok = plonkish_sm2_probe::trail_host::verify_checkpoint_sig(
        dpk, auth_id, cp.seq, chain_head, &fs, &cp.sig_hex,
    );
    if !ok {
        return Err(AssembleError::BadCheckpoint {
            index,
            reason: "设备钥验签失败（坏签名/换头报文/错钥）",
        });
    }
    Ok(())
}

/// AUTH 分发（B3/B4 原路径——逐字保持）。
fn assemble_auth(spec: &JobSpec, input: &ProfileInput) -> Result<Assembled, AssembleError> {
    let ProfileInput::Auth {
        ra_pk_hex,
        id_prime_hex,
        salt_hex,
        id_number_hex,
        cert_level,
        serial_hex,
        holder_sk_hex,
        holder_pk_hex,
        exp_u,
        class_id,
        sig_hex,
        smt_siblings_hex,
        smt_root_hex,
    } = input
    else {
        unreachable!("assemble 分发前已对齐 Auth 档")
    };
    let binding = spec.binding.as_ref().expect("③ 已校验");
    let bp = binding.resolve()?;

    // 字段解析（fail-fast：域/长度/值域逐面校验）。
    let pk_holder = pk_from_hex_str("holder_pk_hex", holder_pk_hex)?;
    let pk_ra = pk_from_hex_str("ra_pk_hex", ra_pk_hex)?;
    let id_prime = fixed_bytes::<32>("id_prime_hex", id_prime_hex)?;
    let salt = fixed_bytes::<16>("salt_hex", salt_hex)?;
    let id_number_raw = fixed_bytes::<18>("id_number_hex", id_number_hex)?;
    let serial = hex::decode(serial_hex)
        .map_err(|_| AssembleError::BadBytes { name: "serial_hex", reason: "非法 hex" })?;
    if serial.is_empty() || serial.len() > 64 {
        return Err(AssembleError::BadBytes {
            name: "serial_hex",
            reason: "序列号 1..64 字节",
        });
    }
    if sig_hex.len() != 128 || !sig_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AssembleError::BadBytes {
            name: "sig_hex",
            reason: "签名须 128 hex（r‖s）",
        });
    }
    let sk_holder = {
        let l = sm2_params::hex_to_limbs_le(holder_sk_hex);
        // R1-1b 数值序修复（2026-09-21）：[u64;4] 的派生比较是**字典序**（从 limbs[0]
        // =最低字比起）——n_limbs 的最低字 ≈0.33×2^64，导致约 2/3 的合法私钥被误拒
        //（黄金向量恰好侥幸通过）。改为从最高字向低字的数值比较。
        let n = sm2_params::n_limbs();
        let mut ge_n = false;
        let mut is_zero = true;
        for i in (0..4).rev() {
            if l[i] != n[i] {
                ge_n = l[i] > n[i];
                break;
            }
        }
        for w in l {
            if w != 0 {
                is_zero = false;
                break;
            }
        }
        if is_zero || ge_n {
            return Err(AssembleError::BadFieldElement {
                name: "holder_sk_hex",
                reason: "标量须 ∈ [1, n-1]",
            });
        }
        l
    };
    // pk′ 与 sk′ 一致性（电路内 [sk′]G=pk′ 的 host 预检——不一致=载荷自相矛盾）。
    {
        let mut bits = [false; 256];
        for ww in 0..4usize {
            for i in 0..64usize {
                bits[64 * ww + i] = (sk_holder[ww] >> i) & 1 == 1;
            }
        }
        let expect = plonkish_sm2_probe::sm2_ec_plonkish::affine_mul_bits(
            &bits,
            Some(plonkish_sm2_probe::sm2_ec_plonkish::g_coords()),
        )
        .expect("真标量乘成功");
        if expect != pk_holder {
            return Err(AssembleError::BadFieldElement {
                name: "holder_pk_hex",
                reason: "pk′ ≠ [sk′]G（出示密钥对不一致）",
            });
        }
    }
    let sig_r = sm2_params::hex_to_limbs_le(&sig_hex[..64]);
    let sig_s = sm2_params::hex_to_limbs_le(&sig_hex[64..]);

    let pi = AuthPreimage {
        pk_ra,
        id_prime,
        salt,
        id_number: id_number_raw,
        cert_level: *cert_level,
        class_id: *class_id,
        serial,
        pk_holder,
        sk_holder,
        exp_u: *exp_u,
        sig_r,
        sig_s,
        // r 派生域（2026-10 换代）：witness r = H("FZ-AUTH-R|v1|"‖challenge)
        // mod n——服务端随机 challenge ⟹ C₁=[r]G 每申请唯一（公开实例 12/13
        // 不再恒 [2]G）。证明方/验证方同 spec 装配 ⟹ 同一确定性 r。
        challenge: bp.challenge_bytes.clone(),
    };
    let w = plonkish_sm2_probe::sm2_auth_assemble::witness_from_auth(&pi);
    // B3b SMT 非成员见证（fail-closed 解析：长度/形态错=BadBytes 拒）
    let smt_siblings_flat: [u8; 1024] = fixed_bytes("smt_siblings_hex", smt_siblings_hex)?;
    let mut smt_siblings: [[u8; 32]; 32] = [[0u8; 32]; 32];
    for (i, chunk) in smt_siblings_flat.chunks_exact(32).enumerate() {
        smt_siblings[i].copy_from_slice(chunk);
    }
    let smt_root: [u8; 32] = fixed_bytes("smt_root_hex", smt_root_hex)?;
    let ap = AuthCPreimage {
        cert_be: u32::from(*cert_level).to_be_bytes(),
        class_id: *class_id,
        id_number: id_number_raw,
        sn_h: plonkish_sm2_probe::sm2_auth_assemble::sn_hash_of(&pi.serial),
        smt_siblings: Some(smt_siblings),
        smt_root: Some(smt_root),
    };
    // host 权威自检：装配前验签（签名被改/错钥=BadFieldElement 拒——与电路内
    // 验签 gadget 同 e 同判，双保险 fail-fast）。
    {
        let host = full_statement_host_auth_of(&w, &salt, &ap);
        let c = plonkish_sm2_probe::sm3_native_ref::compress;
        let v1 = c(&plonkish_sm2_probe::sm3_native_ref::IV, &host.blocks[0]);
        let v2 = c(&v1, &host.blocks[1]);
        let dg = c(&v2, &host.blocks[2]);
        let e_fp = fold_digest_fp(&dg);
        let ok = verify_replay(e_fp, sm2_params::fr_from_limbs(&w.r_s),
            sm2_params::fr_from_limbs(&w.s_s), w.pk_i.0, w.pk_i.1).ok;
        if !ok {
            return Err(AssembleError::BadFieldElement {
                name: "sig_hex",
                reason: "RA 子凭证签名未通过验签（非 RA 签发或报文被改）",
            });
        }
        del_host(host);
    }
    // 装配（电路内全量强制：验签/承诺原像/范围门/有效期/绑定）。
    std::env::set_var("SM3_LUT", "1"); // 飞证部署默认（与生产 pin 口径一致）
    let (asm, _hooks) = plonkish_sm2_probe::sm2_full_statement_assemble::assemble_full_statement_auth(
        &w, salt, ap, bp.required_level, bp.ctx_tag, bp.pred_id, bp.t_epoch,
    );
    Ok(asm)
}

fn del_host(_h: plonkish_sm2_probe::sm2_full_statement_assemble::FullStatementHost) {}

/// 公钥 hex（128 hex x‖y）→ 坐标；非法=BadBytes。
fn pk_from_hex_str(name: &'static str, hex: &str) -> Result<(plonkish_sm2_probe::FpSM2, plonkish_sm2_probe::FpSM2), AssembleError> {
    if hex.len() != 128 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AssembleError::BadBytes {
            name,
            reason: "公钥须 128 hex（x‖y）",
        });
    }
    let x = fp_from_be32_hex(&hex[..64]).ok_or(AssembleError::BadFieldElement {
        name,
        reason: "x 坐标 ≥ p",
    })?;
    let y = fp_from_be32_hex(&hex[64..]).ok_or(AssembleError::BadFieldElement {
        name,
        reason: "y 坐标 ≥ p",
    })?;
    let pt = (x, y);
    if !plonkish_sm2_probe::sm2_ec_plonkish::on_curve_affine(Some(pt)) {
        return Err(AssembleError::BadFieldElement {
            name,
            reason: "公钥不在曲线上",
        });
    }
    Ok(pt)
}

#[cfg(test)]
mod trail_tests {
    use super::*;
    use crate::profile::{CheckpointInput, JobSpec, Profile};

    /// TRAIL 档准入门禁串行锁（AUTH EnvGuard 同法——env set/remove 竞态防线；
    /// 全测试族互斥，allow/deny 双态）。
    struct TrailEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        allow: bool,
    }
    use crate::test_env::ENV_MUTEX as TRAIL_ENV_LOCK;
    impl TrailEnvGuard {
        fn allow() -> Self {
            let g = TRAIL_ENV_LOCK.lock().unwrap();
            std::env::set_var("FZ_ZK_ALLOW_TRAIL", "1");
            TrailEnvGuard { _lock: g, allow: true }
        }
        fn deny() -> Self {
            let g = TRAIL_ENV_LOCK.lock().unwrap();
            std::env::remove_var("FZ_ZK_ALLOW_TRAIL");
            TrailEnvGuard { _lock: g, allow: false }
        }
    }
    impl Drop for TrailEnvGuard {
        fn drop(&mut self) {
            if self.allow {
                std::env::remove_var("FZ_ZK_ALLOW_TRAIL");
            } else {
                std::env::set_var("FZ_ZK_ALLOW_TRAIL", "1");
            }
        }
    }

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/trail_spec_fixture.json"))
            .expect("TRAIL 服务面 fixture")
    }

    fn spec_of(v: &serde_json::Value) -> JobSpec {
        let cps: Vec<CheckpointInput> = v["checkpoints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| CheckpointInput {
                seq: c["seq"].as_u64().unwrap() as u32,
                fence_state_hex: c["fence_state_hex"].as_str().unwrap().to_string(),
                sig_hex: c["sig_hex"].as_str().unwrap().to_string(),
            })
            .collect();
        JobSpec {
            profile: Profile::Trail,
            reps: SUPPORTED_REPS,
            log_rate: SUPPORTED_LOG_RATE,
            binding: None,
            input: Some(ProfileInput::Trail {
                rows_hex: v["rows_hex"].as_str().unwrap().to_string(),
                alt_max_cm: v["alt_max_cm"].as_u64().unwrap() as u32,
                t_start: v["t_start"].as_u64().unwrap() as u32,
                chain_head_hex: v["chain_head_hex"].as_str().unwrap().to_string(),
                auth_id: v["auth_id"].as_u64().unwrap(),
                device_pk_hex: v["device_pk_hex"].as_str().unwrap().to_string(),
                checkpoints: cps,
                binding: serde_json::from_value(v["binding"].clone())
                    .expect("TRAIL binding fixture"),
            }),
        }
    }

    /// 正例：诚实载荷装配成功——结构五元组钉定（B6 判决行：constraints=534/
    /// advice=4454/rings=1,965,044/instances=3/nv=12。2026-10 换代：alt_max/
    /// t_start 迁公开实例——constraints 532+2 钉、advice 4452+2 中继列、
    /// z prep 4+2、实例 1→3、环 +2 中继环(n+1 成员/2 成员)）。
    #[test]
    fn trail_assemble_honest_structure() {
        let _env = TrailEnvGuard::allow();
        let v = fixture();
        let asm = assemble(&spec_of(&v)).expect("诚实 TRAIL 载荷必须装配成功");
        let st = asm.structure();
        assert_eq!(st.constraints, 534, "TRAIL n=128 约束钉定（+2 实例钉）");
        assert_eq!(st.advice_cols, 4454, "TRAIL n=128 advice 列（+2 中继列）");
        assert_eq!(st.instances, 3, "实例面=chain_head‖alt_max‖t_start（2026-10 换代）");
        assert_eq!(st.nv, 12, "行规模 2^12");
        eprintln!("[trail-svc] constraints={} advice={} rings={} inst={} nv={}",
            st.constraints, st.advice_cols, st.copy_rings, st.instances, st.nv);
    }

    /// R4 复验 P0-1：引擎绑定一致性——抬上限（binding≠spec alt_max）必拒。
    #[test]
    fn trail_binding_consistency_tamper_rejected() {
        let _env = TrailEnvGuard::allow();
        let mut v = fixture();
        v["binding"]["alt_max_cm"] = serde_json::Value::from(12_001);
        let spec = spec_of(&v);
        match assemble(&spec) {
            Err(AssembleError::BadBytes { name, .. }) => assert_eq!(name, "binding"),
            other => panic!("抬上限必须被绑定一致性拒绝，实际 {:?}", other.map(|_| ())),
        }
    }

    /// R4 复验 P0-1：绑定签名篡改（非引擎签发）必拒——坏签名在装配面
    /// fail-closed（引擎钥在证明者域外，自签公钥仅自洽不自证）。
    #[test]
    fn trail_binding_sig_tamper_rejected() {
        let _env = TrailEnvGuard::allow();
        let mut v = fixture();
        v["binding"]["sig_hex"] = serde_json::Value::from("00".repeat(128));
        let spec = spec_of(&v);
        match assemble(&spec) {
            Err(AssembleError::BadBytes { name, .. }) => assert_eq!(name, "binding"),
            other => panic!("坏绑定签名必须被拒，实际 {:?}", other.map(|_| ())),
        }
    }

    /// 门禁负例：FZ_ZK_ALLOW_TRAIL 缺失=Forbidden（先于一切校验）。
    #[test]
    fn trail_forbidden_without_env() {
        let _env = TrailEnvGuard::deny();
        let v = fixture();
        let spec = spec_of(&v);
        let r = assemble(&spec);
        assert!(matches!(r, Err(AssembleError::Forbidden { profile: Profile::Trail })), "实得 {:?}", r.err());
    }

    /// 检查点负例（B6 验收门④）：坏设备签名=BadCheckpoint fail-closed。
    #[test]
    fn trail_bad_checkpoint_sig_rejected() {
        let _env = TrailEnvGuard::allow();
        let mut v = fixture();
        v["checkpoints"]
            .as_array_mut()
            .unwrap()[0] = v["bad_checkpoint"].clone();
        let r = assemble(&spec_of(&v));
        match r {
            Err(AssembleError::BadCheckpoint { index: 0, .. }) => {}
            other => panic!("坏检查点必须 BadCheckpoint#0 拒——实得 {:?}", other.map(|a| a.structure())),
        }
    }

    /// 换链头负例：样本链末头≠锚定头=拒（记录与锚定不一致）。R4 P0-1 后
    /// 拒绝点前移——引擎绑定一致性（binding.chain_head≠换后头）先触发，
    /// fail-closed 语义不变。
    #[test]
    fn trail_wrong_anchored_head_rejected() {
        let _env = TrailEnvGuard::allow();
        let mut v = fixture();
        let mut head = v["chain_head_hex"].as_str().unwrap().to_string();
        head.replace_range(0..2, if &head[0..2] == "00" { "01" } else { "00" });
        v["chain_head_hex"] = serde_json::Value::String(head);
        let r = assemble(&spec_of(&v));
        match r {
            Err(AssembleError::BadCheckpoint { .. })
            | Err(AssembleError::BadBytes { name: "chain_head_hex", .. })
            | Err(AssembleError::BadBytes { name: "binding", .. }) => {}
            other => panic!("换锚定头必须拒（检查点报文绑定或链末头比对）——实得 {:?}", other.is_ok()),
        }
    }

    /// t_start 篡改负例：声明起始≠首样本=BadBytes 拒。
    #[test]
    fn trail_tstart_mismatch_rejected() {
        let _env = TrailEnvGuard::allow();
        let mut v = fixture();
        v["t_start"] = serde_json::Value::from(v["t_start"].as_u64().unwrap() + 7);
        let r = assemble(&spec_of(&v));
        match r {
            Err(AssembleError::BadBytes { name: "t_start", .. }) => {}
            other => panic!("t_start 篡改必须拒——实得 {:?}", other.is_ok()),
        }
    }
}
