//! zkc prove 全流程（SP-4 Task 4）：装配→setup→preprocess→prove→proof.bin
//! 落盘 fsync→**盘上字节** from_proof 回读 verify→verdict.json。
//!
//! 纪律（PROBE.md P4 + 计划 Task 4 契约）：
//! - 种子口径（P4 固定种子 + D18 掩蔽换代）：setup/verify 种子公开常数派生=
//!   透明可复现；**证明字节不跨次复现**——D18 掩蔽每证明注入新鲜熵（两次
//!   prove 字节互异实测，MA-4），P4"字节级复现锚"旧口径已被取代；
//! - 回读验证必须消费**盘上字节**（验证侧转录 from_proof——EOF 诊断点教训）；
//! - verify 非 Ok → verdict=FAIL + 退出码 2（不是 panic）；
//! - 电路身份指纹前置（fail-closed）：漂移=PinDrift 拒绝，电路身份不明不出证明；
//! - 后端实例类型级钉定（reps=16/rate=1/random 码，P4 正确性档口径）；
//! - 深表达式递归超默认栈：全链在 256MB 工作线程执行（P4 run2 实测护栏）。

use std::io::Write as _;
use std::panic;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use plonkish_backend::backend::{
    hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit, PlonkishCircuitInfo,
};
use plonkish_backend::pcs::multilinear::{Basefold, BasefoldExtParams};
use plonkish_backend::util::{
    hash::Sm3,
    transcript::{InMemoryTranscript, SM3Transcript},
};
use plonkish_sm2_probe::FpSM2;
use rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use std::io::Cursor;

use crate::assemble::{assemble, AssembledExt, StructureTuple};
use crate::pin_fingerprint::vendor_fingerprint;
use crate::profile::{JobSpec, Profile, ProfileInput};

/// 判决退出码纪律：一切非 OK = 2（计划 Task 4 契约），用法错误 = 1（main 层）。
pub const EXIT_FAIL: i32 = 2;

// ── 后端实例（类型级钉定——与 example/P4 探针逐字一致） ──

#[derive(Debug)]
struct ZkcVerifySpec;
impl BasefoldExtParams for ZkcVerifySpec {
    fn get_reps() -> usize {
        16
    }
    fn get_rate() -> usize {
        1
    }
    fn get_basecode_rounds() -> usize {
        0
    }
    fn get_rs_basecode() -> bool {
        false
    }
    fn get_code_type() -> String {
        "random".to_string()
    }
}

type Pcs = Basefold<FpSM2, Sm3, ZkcVerifySpec>;
type Pb = HyperPlonk<Pcs>;
type T = SM3Transcript<Cursor<Vec<u8>>>;
/// 优化 2 缓存面类型单源：prove 侧参数 / 验证侧参数（zk_cache 工件的内存形态）。
type ProverParam = <Pb as PlonkishBackend<FpSM2>>::ProverParam;
type VerifierParam = <Pb as PlonkishBackend<FpSM2>>::VerifierParam;

/// 种子三件（P4 逐字；证明字节因 D18 掩蔽新鲜熵不跨次复现——非复现锚，
/// 见模块头种子口径）。
const SEED_SETUP: u64 = 0x5317_0001;
const SEED_PROVE: u64 = 0x5317_0002;
const SEED_VERIFY: u64 = 0x5317_0003;

/// 256MB 工作线程栈（P4 run2 实测：setup 深表达式递归超默认 1MB）。
const BIG_STACK: usize = 256 * 1024 * 1024;

// ── PCS 部署开关三件（论文线 D27 / paper-anchor-v3 收口件） ──

pub const ENV_PCS_INTERLEAVE: &str = "PCS_INTERLEAVE";
pub const ENV_PCS_BATCH_DEDUP: &str = "PCS_BATCH_DEDUP";
pub const ENV_PCS_VERIFY_STREAM: &str = "PCS_VERIFY_STREAM";

/// PCS 部署开关状态。vendor 以 env 恰为 "1" 判开（收口默认全关=发布锚字节级历史行为）；
/// prover 与 verifier **必须同值**——zkc 单进程 prove+盘上回读 verify 天然同源，verify-only
/// 须以同一 env 运行。判决件显式记录：同一电路在不同构型下证明尺寸/时延不同，
/// 判决行必须自述"证的是哪种构型"（SV-3 纪律）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PcsSwitches {
    pub interleave: bool,
    pub batch_dedup: bool,
    pub verify_stream: bool,
}

impl PcsSwitches {
    /// 判决行短形态：`il=1/dd=0/st=1`。
    pub fn tag(&self) -> String {
        format!(
            "il={}/dd={}/st={}",
            u8::from(self.interleave),
            u8::from(self.batch_dedup),
            u8::from(self.verify_stream)
        )
    }
}

fn env_is_one(key: &str) -> bool {
    std::env::var(key).as_deref() == Ok("1")
}

/// 读取当前进程的三开关状态（与 vendor 判定同式）。
pub fn pcs_switches() -> PcsSwitches {
    PcsSwitches {
        interleave: env_is_one(ENV_PCS_INTERLEAVE),
        batch_dedup: env_is_one(ENV_PCS_BATCH_DEDUP),
        verify_stream: env_is_one(ENV_PCS_VERIFY_STREAM),
    }
}

/// D18 掩蔽开关（vendor hyperplonk 消费同名 env）——判决件自述消费。
/// 🔴 语义与 vendor 逐字同式：**存在即关**（`var().is_ok()`，置任何值含 "0"
/// 都是关）——自述与消费方分叉=判决件说谎，比不披露更糟。
const ENV_MASK_OFF: &str = "MASK_OFF";

/// 部署档声明 env（信任根收口件4）：production 判定的唯一开关面。
const ENV_DEPLOYMENT: &str = "FZ_DEPLOYMENT";

/// 掩蔽状态自述（评审 P3-2）：verdict.json 必须记录掩蔽态——MASK_OFF 置位时
/// 证明可链接且外观不可检，判决件是唯一披露面（pcs_switches 同纪律）。
pub fn mask_flag() -> &'static str {
    if std::env::var(ENV_MASK_OFF).is_ok() {
        "off"
    } else {
        "on"
    }
}

/// 部署档判定（信任根收口件4）：production = 显式声明 `FZ_DEPLOYMENT=production`
/// （大小写不敏感——与 backend app/deployment.py is_production 的显式声明面同口径）。
///
/// 🔴 为何只认显式声明、不从构型 profile 推断放宽：FZ_ZK_PROFILE 三档
/// （release-demo/dev/pinned）全部是演示/开发/对拍档，没有 production 档——
/// "profile 不含 production" 与 "环回绑定即 demo"（backend 的非环回判定）都
/// 是**可用性启发**；zkc 是单任务独立进程，读不到绑定面。掩蔽关闭=证明可链接
/// 是硬安全属性，判定必须显式、保守、可审计：默认 demo（现状可跑），置
/// production 即收紧。
pub fn deployment_is_production() -> bool {
    std::env::var(ENV_DEPLOYMENT)
        .map(|v| v.trim().eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

/// MASK_OFF 出证准入（信任根收口件4）：production 档 + MASK_OFF 置位 → 拒绝
/// 出证（人话：掩蔽关闭=证明可链接，零知识声明失效——生产环境禁止）。
/// 非 production（demo/dev/pinned）保持现状：仅 stderr 警示+判决件自述，
/// 诊断/对照构型照常可跑。Err=拒绝（调用方 prove_pipeline 在任何装配/IO 前
/// fail-closed 退出，exit 2 判决纪律）。
pub fn mask_off_admission() -> Result<(), ProveError> {
    if mask_flag() != "off" {
        return Ok(());
    }
    if !deployment_is_production() {
        // 现状保持：stderr 警条（评审 P3-2）——判决件自述 mask=off 唯一披露面
        eprintln!(
            "[warn] MASK_OFF 置位：ZK 掩蔽已关闭（证明可链接）——仅限诊断/对照构型，判决件已自述 mask=off"
        );
        return Ok(());
    }
    Err(ProveError::MaskOffInProduction(
        "MASK_OFF 置位于 production 部署档——拒绝出证：掩蔽关闭=证明可链接（零知识声明失效），生产环境禁止；如需诊断构型请在非 production 档执行".to_string(),
    ))
}

/// 部署默认（系统线 SV-3 决策 2026-09-17，论文线授权"SV-3 通过后自行翻默认"）：
/// **叶交织承诺默认开**——未显式设置 `PCS_INTERLEAVE` 时置 "1"；显式 "0" 保留 legacy
/// 构型（发布锚字节级历史行为）。`PCS_BATCH_DEDUP` 保持关（叠加交织零收益：standalone
/// 7,343,792B 同尺寸 [实测]）；`PCS_VERIFY_STREAM` 保持关（zkc 内存 Cursor 转录与流式
/// 两遍验证器的封闭式偏移断言不兼容——"S6 起点偏移 0≠4088" panic 兜底 FAIL [实测]，
/// 且流式仅为验证方内存优化，对 30MB 级证明无意义）。
/// 判决行 [实测 服务器 09-17，RAYON=4]：pred 4,136,532,768→34,211,552B、t1 4,060,954,176→
/// 29,785,472B、merged 350,633,312→12,784,352B、standalone 173,246,256→7,343,792B；负例仍
/// 数学拒绝；prover/verifier 构型错配=验证拒绝（非静默接受）。
pub fn apply_pcs_deployment_defaults() {
    if std::env::var_os(ENV_PCS_INTERLEAVE).is_none() {
        std::env::set_var(ENV_PCS_INTERLEAVE, "1");
    }
}

// ── 错误/报告面 ──

#[derive(Debug)]
pub enum ProveError {
    /// 装配校验拒绝（校验序错误面，含注册表/门禁/输入面）。
    Assemble(crate::profile::AssembleError),
    /// 电路身份漂移——指纹前置 fail-closed。
    PinDrift(String),
    /// 落盘/回读 IO。
    Io(String),
    /// 论文栈后端错误（字符串化：verdict 面只需描述）。
    Backend(String),
    /// 证明工作线程 panic（vendor 校验断言——假见证/非法输入）：结构化
    /// verdict=FAIL/exit 2，不得 panic 逃逸（2026-09-06 假见证 8 任务连炸
    /// exit 101 实证——67e4571 半成品重构的补完面）。
    InvalidStatement(String),
    /// 信任根收口件4：production 部署档 + MASK_OFF（掩蔽关闭=证明可链接）
    /// ——出证拒绝（fail-closed，先于任何装配/IO 零副作用）。
    MaskOffInProduction(String),
}

impl std::fmt::Display for ProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProveError::Assemble(e) => write!(f, "装配拒绝: {e}"),
            ProveError::PinDrift(e) => write!(f, "电路身份漂移（不出证明）: {e}"),
            ProveError::Io(e) => write!(f, "IO: {e}"),
            ProveError::Backend(e) => write!(f, "后端: {e}"),
            ProveError::InvalidStatement(e) => write!(f, "证明输入非法（工作线程断言）: {e}"),
            ProveError::MaskOffInProduction(e) => write!(f, "出证拒绝（掩蔽关闭）: {e}"),
        }
    }
}

impl std::error::Error for ProveError {}

/// 四段耗时 + 总耗时（秒；时间只是参考档——P1R1R2 纪律，锚=结构与字节）。
#[derive(Debug, Clone)]
pub struct Timings {
    pub setup_s: f64,
    pub preprocess_s: f64,
    pub prove_s: f64,
    pub verify_s: f64,
    pub total_s: f64,
}

/// prove 管线报告（verdict.json 的内存形态超集）。
#[derive(Debug, Clone)]
pub struct ProveReport {
    /// "OK" | "FAIL"。
    pub verdict: String,
    /// FAIL 时的验证失败描述。
    pub verify_error: Option<String>,
    pub proof_bytes_len: usize,
    /// 盘上证明字节的 SM3 hex（唯一哈希入口）。
    pub proof_sm3_hex: String,
    pub structure: StructureTuple,
    pub timings: Timings,
    /// 电路身份指纹 `SM3(<pin>|<aggregate>)`（Task 11 上链承诺对象）。
    pub fingerprint: String,
    /// PCS 部署开关状态（判决行自述构型）。
    pub pcs_switches: PcsSwitches,
}

// ── 服务根解析 ──

/// 声明文件目录解析序：`YZT_ZK_ROOT` 环境变量（部署期显式，指向 zksvc 根）
/// → 可执行文件向上搜 `build_manifest.json`（cargo 布局）→ 编译期
/// CARGO_MANIFEST_DIR（dev 兜底）。
/// 🔴 双参照系：build_manifest.json **文件**锚在 zksvc/；其内 `snapshot_dir`
/// 等**字段**相对仓库根（父级）——与 Python 守卫 check_zk_pin.sh 同构
/// （ROOT=仓库根 拼 BM 路径、VENDOR=ROOT+snapshot_dir）。
fn service_bm_dir() -> PathBuf {
    if let Ok(r) = std::env::var("YZT_ZK_ROOT") {
        return PathBuf::from(r);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe
            .ancestors()
            .take(6)
            .find(|p| p.join("build_manifest.json").is_file())
        {
            return dir.to_path_buf();
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// vendor 快照目录（声明字段相对仓库根=声明文件目录的父级——零手抄路径）。
fn service_vendor_dir() -> Result<PathBuf, ProveError> {
    let bm_dir = service_bm_dir();
    let bm_path = bm_dir.join("build_manifest.json");
    let text = std::fs::read_to_string(&bm_path)
        .map_err(|e| ProveError::PinDrift(format!("build_manifest.json 不可读: {e}")))?;
    let bm: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| ProveError::PinDrift(format!("声明面损坏: {e}")))?;
    let rel = bm["snapshot_dir"]
        .as_str()
        .ok_or_else(|| ProveError::PinDrift("声明面缺 snapshot_dir".into()))?;
    let repo_root = bm_dir
        .parent()
        .ok_or_else(|| ProveError::PinDrift("声明文件目录无父级".into()))?;
    Ok(repo_root.join(rel))
}

// ── 电路适配器（probe_sm2_verify::Sm2VerifyCircuit 同款裸部件→PlonkishCircuit）──
// R1 内存优化（2026-09-21 归因表 #1-#3）：advice 经 Mutex<Option> 单次 take 交付
// （synthesize 是单相唯一消费点）——asm.advice 移动进电路、不再三层克隆
// （asm 驻留克隆+JobCircuit 克隆+synthesize 返回克隆各 1.71GB，AUTH 共 −3.42GB）。
#[derive(Debug)]
struct JobCircuit {
    info: PlonkishCircuitInfo<FpSM2>,
    advice: std::sync::Mutex<Option<Vec<Vec<FpSM2>>>>,
    instances: Vec<Vec<FpSM2>>,
}

impl PlonkishCircuit<FpSM2> for JobCircuit {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<FpSM2>, plonkish_backend::Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<FpSM2>] {
        &self.instances
    }
    fn synthesize(&self, round: usize, challenges: &[FpSM2]) -> Result<Vec<Vec<FpSM2>>, plonkish_backend::Error> {
        assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
        Ok(self
            .advice
            .lock()
            .expect("advice 锁中毒")
            .take()
            .expect("单相电路 synthesize 只调用一次（advice 已被取走）"))
    }
}

// ── 管线 ──

/// 256MB 栈工作线程执行体（join 恢复 panic——判决纪律：不吞 panic）。
fn in_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let h = std::thread::Builder::new()
        .stack_size(BIG_STACK)
        .spawn(f)
        .expect("起 256MB 工作线程失败");
    match h.join() {
        Ok(v) => v,
        // 🔴 禁 resume_unwind：工作线程 panic（vendor 校验断言——"四步验签为真"
        // 等，2026-09-06 假见证 8 任务连炸 exit 101 实证）在此收拢为结构化错误，
        // 由 prove 侧映射 verdict=FAIL/exit 2——业务输入错误不得 panic 逃逸。
        Err(_) => panic::panic_any(BigStackPanic),
    }
}

/// 工作线程 panic 的哨兵载荷（catch_unwind 侧识别转结构化 InvalidStatement）。
pub(crate) struct BigStackPanic;

/// 落盘 + fsync（数据落定后返回——进程崩溃后判决件可信的根）。
fn write_fsync(path: &Path, data: &[u8]) -> Result<(), ProveError> {
    let mut f = std::fs::File::create(path).map_err(|e| ProveError::Io(format!("{}: {e}", path.display())))?;
    f.write_all(data)
        .map_err(|e| ProveError::Io(format!("{}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| ProveError::Io(format!("{}: {e}", path.display())))
}

fn sm3_hex(data: &[u8]) -> String {
    use sm3::Digest;
    let mut h = Sm3::new();
    h.update(data);
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

// ── R1 内存归因探针（FZ_PROVE_PHASE_LOG=1）：相位边界打点到 stderr，与外置
// 采样器（backend/scripts/mem_probe.py 的 t_s/rss/commit CSV）按时间轴对齐——
// 纯测量面，零行为差异；默认关。 ──

fn phase_log_enabled() -> bool {
    std::env::var("FZ_PROVE_PHASE_LOG").is_ok()
}

#[macro_export]
macro_rules! phase {
    ($t0:expr, $($arg:tt)*) => {
        if $crate::prove::phase_log_enabled() {
            eprintln!("[PHASE] t={:.2}s {}", $t0.elapsed().as_secs_f64(), format!($($arg)*));
        }
    };
}

/// 出示私钥交付通道自述（批 4-6）：spec 空 holder_sk_hex=env 注入通道（"env"
/// ——私钥字节不落盘）；spec 携带=witness 通道（"witness"——与既有判决件字节
/// 口径一致）。TRAIL/无输入档无发行方私钥面——维持既有值（判决件字节不变）。
fn issuer_key_source(spec: &JobSpec) -> &'static str {
    match &spec.input {
        Some(ProfileInput::Auth { holder_sk_hex, .. }) => {
            if holder_sk_hex.trim().is_empty() {
                "env"
            } else {
                "witness"
            }
        }
        _ => "witness",
    }
}

#[derive(Serialize)]
struct VerdictFile<'a> {
    profile: &'a str,
    reps: u32,
    log_rate: u32,
    proof_sm3: String,
    bytes: usize,
    /// verifier_param.bin 的 SM3 与字节数（判决件第三件的绑定锚）。
    verifier_param_sm3: String,
    verifier_param_bytes: usize,
    setup_s: f64,
    preprocess_s: f64,
    prove_s: f64,
    verify_s: f64,
    total_s: f64,
    verdict: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_error: Option<&'a String>,
    /// SP-20 R-4②：发行方出示私钥交付通道自述（审计面，批 4-6 收口）——
    /// "env"=服务化主路径（spec.json 零私钥字节，私钥经 FZ_ZK_HOLDER_SK_HEX
    /// 注入）；"witness"=spec 明文回落（磁盘明文窗口，判决件可检；
    /// FZ_ZK_FORBID_SPEC_KEY=1 时装配面直接拒绝该通道）。判定与 assemble.rs
    /// resolve_holder_sk 同源同判（权威在装配侧，此处按 spec 形态同式复算）。
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_key_source: Option<&'a str>,
    /// Pred 档公开谓词参数（审计面：判决件自述"证的是哪个阈值/哪个 schema"）。
    /// 非 Pred 档为 None 不序列化——三旧档 verdict.json 字节不变（锚安全）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pred_theta: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pred_schema_seg_hex: Option<&'a str>,
    /// PCS 部署开关三件（interleave / batch_dedup / verify_stream）——同一电路不同构型
    /// 的尺寸/时延不可比，判决件必须自述构型（SV-3 纪律）。
    pcs_switches: PcsSwitches,
    /// D18 掩蔽自述（评审 P3-2）：on=零知识掩蔽启用（默认）；off=MASK_OFF 置位
    /// 的诊断/对照构型（证明可链接——判决件唯一披露面）。
    mask: &'static str,
    zk_pin_fingerprint: String,
    created_unix_ts: u64,
}

/// prove 全流程。verdict.json 无论 OK/FAIL 一律落盘（判决件是产物，
/// 退出码语义由 CLI 层映射：OK=0 / 其余=2）。
pub fn prove_pipeline(spec: &JobSpec, out_dir: &Path) -> Result<ProveReport, ProveError> {
    let t_all = Instant::now();
    // 0) 出证准入（信任根收口件4，fail-closed 最前置）：production + MASK_OFF
    // =拒绝出证——零副作用不建目录不读 vendor（比指纹前置更早，掩蔽关闭=
    // 证明可链接的构型在生产档根本没有出证资格）。
    mask_off_admission()?;
    // 0') 电路身份指纹前置（fail-closed：漂移即拒，零副作用不建目录）
    let fingerprint = vendor_fingerprint(&service_vendor_dir()?).map_err(ProveError::PinDrift)?;

    // 1) 大栈线程全链：装配→setup→preprocess→prove→落盘→盘上回读 verify
    let spec_c = spec.clone();
    let out_c = out_dir.to_path_buf();
    let inner = move || -> Result<ProveReport, ProveError> {
        let t_pipe = Instant::now();
        let asm = assemble(&spec_c).map_err(ProveError::Assemble)?;
        let asm_structure = asm.structure();
        let nv = asm.info.k;
        {
            let info = &asm.info;
            let rings: usize = info.permutations.iter().map(Vec::len).sum();
            phase!(
                t_pipe,
                "assemble_done k={} instances={} prep_polys={} witness_polys={} phases={:?} \
                 challenges={:?} lookups={} perm_cycles={} perm_rings={} constraints={} max_degree={:?}",
                info.k,
                info.num_instances.len(),
                info.preprocess_polys.len(),
                info.num_witness_polys.iter().sum::<usize>(),
                info.num_witness_polys,
                info.num_challenges,
                info.lookups.len(),
                info.permutations.len(),
                rings,
                info.constraints.len(),
                info.max_degree,
            );
        }
        // R1 内存优化（归因表 #1/#2）：info/advice/instances 解构移动进电路——
        // 废除 asm 全程驻留克隆与 JobCircuit 构造克隆（见证 4 份→2 份）。
        // 取证/审计钩子字段（tags/ledger/eg/ep…）随 asm 解构即弃——prove 管线零消费。
        let plonkish_sm2_probe::sm2_verify_assemble::Assembled {
            mut info, advice, instances, ..
        } = asm;
        // 优化 2（跨证明确定性产物复用）：info 规范化（环内排序+环列排序）——
        // 与 ①定谳探针 auth_cross_message_cached_params_e2e（第五版，2026-09-26
        // 手动跑全绿）同构。装配器 HashMap 迭代序使原始 permutations 跨次装配
        // 不可复现；规范化后电路结构=profile 纯函数（auth_structure_canonical_
        // identity_guard 钉死）⟹ setup/preprocess 产物 (pp,vp) 跨消息恒等，
        // 可按指纹键跨证明复用（见下方 zk_cache 集成）。
        for ring in info.permutations.iter_mut() {
            ring.sort();
        }
        info.permutations.sort();
        let circuits = JobCircuit {
            info,
            advice: std::sync::Mutex::new(Some(advice)),
            instances,
        };

        // 优化 2：setup+preprocess 产物 (pp,vp) 磁盘缓存（磁盘工件+惰性加载，
        // 免常驻 daemon——设计定谳见 zk_cache 模块头）。键=指纹键（含电路身份
        // 指纹+规范化 info 结构摘要+档位/构型），指纹换代/结构漂移自动键旋转。
        // 🔴 随机性纪律红线：build 闭包只含 pinned setup（公开常数种子
        // SEED_SETUP）+ preprocess（预处理承诺盐链=ChaCha8(public_salt_seed⊕
        // domain)，公开种子确定性导出）——每证明盲化 λ/m 列/transcript 新鲜熵
        // （OsRng）只在下方 Pb::prove 内现抽，绝不入缓存。
        let structure_digest = {
            use sm3::Digest as _;
            let mut h = sm3::Sm3::new();
            h.update(&bincode::serialize(&circuits.info).unwrap_or_default());
            h.finalize().iter().map(|x| format!("{x:02x}")).collect::<String>()
        };
        let key_src = format!(
            "fz-zk-pp-cache|fmt={}|fp={}|profile={:?}|reps={}|rate={}|k={}|struct={}|pcs={}",
            crate::zk_cache::ARTIFACT_CACHE_FMT,
            fingerprint,
            spec_c.profile,
            spec_c.reps,
            spec_c.log_rate,
            nv,
            structure_digest,
            pcs_switches().tag(),
        );
        let info_ref = &circuits.info;
        let (params, cache_outcome) = crate::zk_cache::cached(
            &key_src,
            &crate::zk_cache::NAMES,
            |blobs| -> Option<((ProverParam, VerifierParam), f64, f64)> {
                let pp: ProverParam = bincode::deserialize(blobs.first()?).ok()?;
                let vp: VerifierParam = bincode::deserialize(blobs.get(1)?).ok()?;
                // (0,0)=占位分段时长；命中时真实耗时=Hit.load_s（下方覆写）
                Some(((pp, vp), 0.0, 0.0))
            },
            || {
                let t0 = Instant::now();
                let param = Pb::setup(info_ref, StdRng::seed_from_u64(SEED_SETUP ^ nv as u64))
                    .map_err(|e| format!("setup: {e:?}"))?;
                let setup_s = t0.elapsed().as_secs_f64();
                let t1 = Instant::now();
                let (pp, vp) = Pb::preprocess(&param, info_ref)
                    .map_err(|e| format!("preprocess: {e:?}"))?;
                let pre_s = t1.elapsed().as_secs_f64();
                let pp_b = bincode::serialize(&pp).map_err(|e| format!("pp 序列化: {e}"))?;
                let vp_b = bincode::serialize(&vp).map_err(|e| format!("vp 序列化: {e}"))?;
                Ok((((pp, vp), setup_s, pre_s), vec![pp_b, vp_b]))
            },
        );
        // build 失败沿既有错误面（Backend）——缓存不吞错不改错
        let ((pp, vp), mut t_setup, mut t_pre) = params.ok_or_else(|| {
            ProveError::Backend(match &cache_outcome {
                crate::zk_cache::Outcome::Miss { reason, .. }
                | crate::zk_cache::Outcome::Off { reason } => reason.clone(),
                crate::zk_cache::Outcome::Hit { .. } => {
                    "不可达（命中必有产物）".to_string()
                }
            })
        })?;
        if let crate::zk_cache::Outcome::Hit { load_s } = &cache_outcome {
            // 判决件耗时口径：命中时 setup=0（全跳过）、preprocess=缓存加载
            // （读盘+SM3 校验+反序列化）——与纯计算口径可区分，收益可对账。
            t_setup = 0.0;
            t_pre = *load_s;
        }
        phase!(t_pipe, "params_ready cache={}", cache_outcome.tag());

        // 2.5) verifier 参数落盘（判决件第三件）。🔴 Task 6 深坑定谳：Basefold
        // commit 内嵌 D18 Phase 2 ZK 掩蔽（fresh mask_seed per commit）⟹
        // preprocess 的 index 承诺每次不可复现 ⟹ verify 侧**不能重做**
        // preprocess（重做=开口不一致，basefold.rs:2807 实证）——独立验证
        // 必须持 prove 侧 verifier 参数。P3 勘误"零参数持久化"仅对 prove
        // 侧成立，verify 侧例外在此落定。
        let vp_bytes =
            bincode::serialize(&vp).map_err(|e| ProveError::Backend(format!("vp 序列化: {e}")))?;
        phase!(t_pipe, "vp_serialized bytes={}", vp_bytes.len());

        let t0 = Instant::now();
        let proof = {
            let mut transcript = T::new(());
            Pb::prove(&pp, &circuits, &mut transcript, StdRng::seed_from_u64(SEED_PROVE))
                .map_err(|e| ProveError::Backend(format!("{e:?}")))?;
            transcript.into_proof()
        };
        let t_prove = t0.elapsed();
        phase!(t_pipe, "prove_done bytes={}", proof.len());

        // 2) 落盘 + fsync（此时装配已成功，允许建目录）
        std::fs::create_dir_all(&out_c).map_err(|e| ProveError::Io(format!("{}: {e}", out_c.display())))?;
        let proof_path = out_c.join("proof.bin");
        write_fsync(&proof_path, &proof)?;
        write_fsync(&out_c.join("verifier_param.bin"), &vp_bytes)?;
        phase!(t_pipe, "artifacts_written");
        // R1-1a：公开实例落盘（fe_be32 hex）——实例驱动验证面的服务端输入。
        // 实例=语句公开面（政策/绑定/纪元根/公开提交），零秘密；
        // 秘密见证（advice）只存在于 prove 进程内存，永不落盘出设备。
        {
            let inst_hex: Vec<String> = circuits
                .instances
                .iter()
                .flatten()
                .map(|v| {
                    plonkish_sm2_probe::sm2_z_anchor::fe_be32(v)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                })
                .collect();
            let inst_json = serde_json::json!({ "instances": inst_hex }).to_string();
            write_fsync(&out_c.join("instances.json"), inst_json.as_bytes())?;
        }
        phase!(t_pipe, "instances_written");

        // 3) 盘上字节回读 verify（纪律：from_proof(盘上字节)，非内存直传）。
        // catch_unwind 兜底：vendor 校验面有 assert panic 路径（实测翻转证明打穿
        // basefold.rs:2807 开口断言）——判决纪律 verdict=FAIL 必须永不 panic 逃逸。
        let proof_disk = std::fs::read(&proof_path)
            .map_err(|e| ProveError::Io(format!("{}: {e}", proof_path.display())))?;
        let t0 = Instant::now();
        let verify_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut transcript = T::from_proof((), proof_disk.as_slice());
            Pb::verify(&vp, &circuits.instances, &mut transcript, StdRng::seed_from_u64(SEED_VERIFY))
        }));
        let t_verify = t0.elapsed();
        phase!(t_pipe, "verify_done");

        let (verdict, verify_error) = match verify_res {
            Ok(Ok(())) => ("OK", None),
            Ok(Err(e)) => ("FAIL", Some(format!("{e:?}"))),
            Err(boxed) => ("FAIL", Some(format!("verify panic 兜底: {}", panic_msg(&boxed)))),
        };

        let report = ProveReport {
            verdict: verdict.to_string(),
            verify_error: verify_error.clone(),
            proof_bytes_len: proof_disk.len(),
            proof_sm3_hex: sm3_hex(&proof_disk),
            structure: asm_structure,
            timings: Timings {
                setup_s: t_setup,
                preprocess_s: t_pre,
                prove_s: t_prove.as_secs_f64(),
                verify_s: t_verify.as_secs_f64(),
                total_s: t_all.elapsed().as_secs_f64(),
            },
            fingerprint: fingerprint.clone(),
            pcs_switches: pcs_switches(),
        };

        // 4) verdict.json 落盘 + fsync（AUTH 档无 pred 面——字段恒 None）
        let (pred_theta, pred_schema_seg_hex): (Option<u32>, Option<&str>) = (None, None);
        let vf = VerdictFile {
            profile: spec_c.profile.as_str(),
            reps: spec_c.reps,
            log_rate: spec_c.log_rate,
            proof_sm3: report.proof_sm3_hex.clone(),
            bytes: report.proof_bytes_len,
            verifier_param_sm3: sm3_hex(&vp_bytes),
            verifier_param_bytes: vp_bytes.len(),
            setup_s: report.timings.setup_s,
            preprocess_s: report.timings.preprocess_s,
            prove_s: report.timings.prove_s,
            verify_s: report.timings.verify_s,
            total_s: report.timings.total_s,
            verdict: report.verdict.as_str(),
            verify_error: report.verify_error.as_ref(),
            // 飞证 AUTH：签名四件交付通道（批 4-6 起双通道可辨——env=主路径
            // 私钥不落盘，witness=spec 明文回落档；TRAIL 无私钥面维持原值）
            issuer_key_source: Some(issuer_key_source(&spec_c)),
            pred_theta,
            pred_schema_seg_hex,
            pcs_switches: report.pcs_switches,
            mask: mask_flag(),
            zk_pin_fingerprint: fingerprint.clone(),
            created_unix_ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let json = serde_json::to_vec_pretty(&vf)
            .map_err(|e| ProveError::Io(format!("verdict 序列化: {e}")))?;
        write_fsync(&out_c.join("verdict.json"), &json)?;

        Ok(report)
    };
    // 67e4571 半成品补完（SP-11.2 过程修复）：in_big_stack 把工作线程 panic
    // 收拢为 BigStackPanic 哨兵，此处 catch_unwind 转结构化 InvalidStatement
    // ——业务输入错误 → verdict=FAIL/exit 2；未知 panic 原样传播不吞。
    let report = match panic::catch_unwind(panic::AssertUnwindSafe(|| in_big_stack(inner))) {
        Ok(r) => r?,
        Err(payload) => {
            if payload.downcast_ref::<BigStackPanic>().is_some() {
                return Err(ProveError::InvalidStatement(
                    "vendor 校验断言触发（见证/输入非法）".into(),
                ));
            }
            std::panic::resume_unwind(payload)
        }
    };
    Ok(report)
}

// ── verify-only 独立验证（Task 6） ──

/// verify-only 判决报告。verdict = "OK" | "FAIL"；FAIL 时 reason 给拒绝原因
/// （SM3 先拒 / 指纹不符 / 判决件非 OK / 后端拒绝 / panic 兜底描述）。
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub verdict: String,
    pub reason: Option<String>,
}

/// 独立验证管线（不重跑 prove）：盘上证明 + prove 侧 verifier 参数 → 判决。
///
/// 关序（任何一关不过即 FAIL、不触后端）：
/// ① 证明文件可读；② 判决件参照（`verdict_path` 提供时）：合法 json /
/// verdict=="OK" / **SM3 摘要先拒**（字节翻转/截断/垃圾在此零后端成本拦下）/
/// 电路指纹对照（prove 后电路漂移 ⟹ 旧判决件不可信）；③ **验证参数关**
/// （fail-closed）：verifier_param.bin 必须存在（`param_path` 显式指定或
/// proof 同目录缺省）——ZK 掩蔽使 index 承诺不可重算，缺参数即拒绝（绝不
/// 重做 preprocess）；判决件参照在场时另对照 verifier_param_sm3 防 vp 篡改。
/// ④ 后端独立验证（verify_proof_bytes，catch_unwind 兜底）。
pub fn verify_pipeline(
    spec: &JobSpec,
    proof_path: &Path,
    verdict_path: Option<&Path>,
    param_path: Option<&Path>,
) -> Result<VerifyReport, ProveError> {
    let fail = |reason: String| {
        Ok(VerifyReport {
            verdict: "FAIL".to_string(),
            reason: Some(reason),
        })
    };

    let proof = match std::fs::read(proof_path) {
        Ok(p) => p,
        Err(e) => return fail(format!("证明文件不可读 {}: {e}", proof_path.display())),
    };

    if let Some(vd_path) = verdict_path {
        let text = std::fs::read_to_string(vd_path)
            .map_err(|e| ProveError::Io(format!("{}: {e}", vd_path.display())))?;
        let vd: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return fail(format!("判决件损坏: {e}")),
        };
        if vd["verdict"].as_str() != Some("OK") {
            return fail("判决件 verdict 非 OK（拒绝复核失败判决件）".to_string());
        }
        let declared_sm3 = match vd["proof_sm3"].as_str() {
            Some(s) => s,
            None => return fail("判决件缺 proof_sm3".to_string()),
        };
        if declared_sm3 != sm3_hex(&proof) {
            return fail("SM3 摘要不匹配（先拒）: 证明字节与判决件声明不符".to_string());
        }
        let declared_fp = match vd["zk_pin_fingerprint"].as_str() {
            Some(s) => s,
            None => return fail("判决件缺 zk_pin_fingerprint".to_string()),
        };
        let current_fp = vendor_fingerprint(&service_vendor_dir()?).map_err(ProveError::PinDrift)?;
        if declared_fp != current_fp {
            return fail("电路指纹与判决件不符（prove 后电路漂移，判决件不可信）".to_string());
        }
    }

    // 验证参数关（fail-closed）：显式路径优先，缺省 = proof 同目录
    let vp_path_owned = proof_path.parent().map(|d| d.join("verifier_param.bin"));
    let vp_path = param_path
        .or(vp_path_owned.as_deref())
        .ok_or_else(|| ProveError::Io("证明路径无父目录".into()))?;
    let vp_bytes = match std::fs::read(vp_path) {
        Ok(v) => v,
        Err(e) => {
            return fail(format!(
                "缺验证参数 {}: {e}（ZK 掩蔽使 index 承诺不可重算——独立验证必须持 prove 侧 verifier_param.bin，禁止重做 preprocess）",
                vp_path.display()
            ))
        }
    };
    if let Some(vd_path) = verdict_path {
        let text = std::fs::read_to_string(vd_path)
            .map_err(|e| ProveError::Io(format!("{}: {e}", vd_path.display())))?;
        let vd: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ProveError::Io(format!("判决件损坏: {e}")))?;
        if let Some(declared) = vd["verifier_param_sm3"].as_str() {
            if declared != sm3_hex(&vp_bytes) {
                return fail("验证参数与判决件不符（verifier_param 被篡改/错配）".to_string());
            }
        }
    }

    // SP-20 R-4①：对齐 prove 面收拢纪律（:371 外层 catch_unwind 的 verify 侧
    // 补齐）——verify_proof_bytes 内层 catch_unwind 覆盖工作线程闭包 panic，
    // 但 in_big_stack 在 join 失败（双重 panic/panic 机制自身故障）时于**调用
    // 线程**重放 BigStackPanic——原实现此处逃逸 ⟹ exit 101 破坏"FAIL=exit 2"
    // 判决纪律。BigStackPanic→结构化 FAIL；未知 panic 原样传播（不吞）。
    let backend_result = match panic::catch_unwind(panic::AssertUnwindSafe(|| {
        verify_proof_bytes(spec, &proof, &vp_bytes)
    })) {
        Ok(r) => r,
        Err(payload) => {
            if payload.downcast_ref::<BigStackPanic>().is_some() {
                Err("verify 工作线程 panic 收拢（BigStackPanic）".to_string())
            } else {
                std::panic::resume_unwind(payload)
            }
        }
    };
    match backend_result {
        Ok(()) => Ok(VerifyReport {
            verdict: "OK".to_string(),
            reason: None,
        }),
        Err(e) => fail(e),
    }
}

/// AUTH 实例索引（B3/B3b/B4 装配定谳——sm2_full_statement_assemble set_instance 序）。
pub mod auth_instances {
    pub const IDX_CTX_TAG: usize = 19;
    pub const IDX_PRED_ID: usize = 20;
    pub const IDX_T: usize = 21;
    pub const IDX_THETA: usize = 22;
    pub const IDX_SMT_ROOT: usize = 23;
    pub const IDX_CLASS: usize = 24;
}

/// 实例驱动验证的期望绑定（服务端从申请体独立重导出——T6 服务侧强制闭环）。
/// TRAIL 档（R1-6 第三方复验）：仅需 chain_head_hex（实例 0）。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BindingExpectations {
    #[serde(default)]
    pub challenge_hex: String,
    #[serde(default)]
    pub pred_id: String,
    #[serde(default)]
    pub t_epoch: u32,
    #[serde(default)]
    pub required_level: u32,
    #[serde(default)]
    pub class_id: u32,
    /// 撤销纪元根（32B hex——实例 23=fold_words_be(root)）。
    #[serde(default)]
    pub smt_root_hex: String,
    /// TRAIL 锚定链头（32B hex——实例 0=fold_words_be(chain_head)）。
    #[serde(default)]
    pub chain_head_hex: String,
    /// AUTH 语句摘要 e（32B hex——实例 0=e_stmt；S5 安全修复[严重1]：钉死
    /// 「电路消息==受理提交报文」，封死自签凭证+真子凭证组合攻击）。
    #[serde(default)]
    pub e_hex: String,
    /// TRAIL 授权高度上限 cm（2026-10 换代：实例 1 钉定必携——0=缺失拒）。
    #[serde(default)]
    pub alt_max_cm: u32,
    /// TRAIL 声明起始时间（2026-10 换代：实例 2 钉定必携）。Option 形态——
    /// 0 是合法段原点（行内 t=段内相对 500ms 网格，t_start=段原点 0），缺失
    /// 哨兵不可用 falsy 值（2026-10-01 终验实弹抓到：合法 t_start=0 被
    /// 「0=缺失拒」误伤）；None（JSON 键缺席/null）才是缺失。
    #[serde(default)]
    pub t_start: Option<u32>,
    /// TRAIL 采样周期 ms（二批换代改动2：实例 3 钉定必携——Option 形态，
    /// 0 是哨兵非法但 None 才是缺失）。声明与记录 Δt 不符会被电路拒绝——
    /// 期望核对钉的是「验证方认哪份周期」。
    #[serde(default)]
    pub sample_period_ms: Option<u32>,
    /// TRAIL 矩形围栏 4 界（二批换代改动1：实例 4..7 钉定必携——期望面
    /// 携带经纬度原值 i32×1e7（负值=南/西半球），核对前按偏置编码折算）。
    #[serde(default)]
    pub fence: Option<TrailFenceExpectations>,
}

/// TRAIL 围栏期望（4 界 i32×1e7——与 PolicyFace FENCE_RECTS/绑定面同口径）。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TrailFenceExpectations {
    pub min_lat: i64,
    pub max_lat: i64,
    pub min_lon: i64,
    pub max_lon: i64,
}

// ── R4 第二批 A-路线#3：canonical 电路 info 指纹键控磁盘缓存 ──

/// 缓存格式版本（结构演进时 +1——键含此值，旧缓存天然失效）。
const INFO_CACHE_FMT: u32 = 1;

fn _hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn info_cache_enabled() -> bool {
    std::env::var("FZ_ZK_INFO_CACHE")
        .map(|v| v != "0")
        .unwrap_or(true)
}

fn info_cache_dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("FZ_ZK_INFO_CACHE_DIR") {
        let p = PathBuf::from(d);
        let _ = std::fs::create_dir_all(&p);
        return Some(p);
    }
    // 缺省=zkc 二进制侧 info-cache/（重建 clean 自然清空；指纹键防陈旧）
    let exe = std::env::current_exe().ok()?;
    let p = exe.parent()?.join("info-cache");
    let _ = std::fs::create_dir_all(&p);
    Some(p)
}

/// MANIFEST **声明面**电路身份（pin_commit|aggregate——cheap 读；重算 146 文件
/// 的慢路径=pin_fingerprint::vendor_fingerprint，prove 前置已做）。键漂移语义：
/// repin 换代 MANIFEST ⟹ 声明值变 ⟹ 缓存键变——旧电路 info 不再命中
/// （无 manifest 场景=独立验证方自建缓存，仍受 spec 摘要与格式版本键控）。
fn declared_circuit_identity() -> String {
    let text = std::env::var("FZ_ZKSVC_DIR")
        .ok()
        .and_then(|d| std::fs::read_to_string(Path::new(&d).join("vendor/MANIFEST.json")).ok())
        .or_else(|| {
            let exe = std::env::current_exe().ok()?;
            let base = exe.parent()?.parent()?.parent()?;
            std::fs::read_to_string(base.join("vendor/MANIFEST.json")).ok()
        });
    match text {
        Some(t) => {
            let v: serde_json::Value = serde_json::from_str(&t).unwrap_or(serde_json::Value::Null);
            format!(
                "{}|{}",
                v["pin_commit"].as_str().unwrap_or("?"),
                v["aggregate_sm3"].as_str().unwrap_or("?")
            )
        }
        None => "no-manifest".to_string(),
    }
}

/// canonical 电路 info 磁盘缓存（verify-instances 专用——证明面需 advice 仍走
/// 全量装配）。verify 每调用重建全电路结构（AUTH 装配 ~8s 为验证时长的大头），
/// 而 canonical spec 同档恒等 ⟹ info 是 spec 的纯函数。
/// 键=SM3(格式版本‖profile‖spec 原文摘要‖MANIFEST 声明身份)——vendor repin/
/// spec 编辑/格式演进任一变化键即变；反序列化失败自愈重建（截断/损坏永不放行）。
/// 默认开（FZ_ZK_INFO_CACHE=0 关——差分测试位）。
fn canonical_info_cached(
    spec: &JobSpec,
    spec_text: &str,
) -> Result<PlonkishCircuitInfo<FpSM2>, ProveError> {
    if !info_cache_enabled() {
        return Ok(assemble(spec).map_err(ProveError::Assemble)?.info);
    }
    let key_src = format!(
        "fz-info-cache|fmt={INFO_CACHE_FMT}|profile={:?}|spec={}|vendor={}",
        spec.profile,
        _hex_of(&crate::sm3_host::sm3_bytes(spec_text.as_bytes())),
        declared_circuit_identity(),
    );
    let key = _hex_of(&crate::sm3_host::sm3_bytes(key_src.as_bytes()));
    let dir = info_cache_dir().ok_or_else(|| ProveError::Io("info 缓存目录不可用".into()))?;
    let path = dir.join(format!("{key}.info.bin"));
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(info) = bincode::deserialize::<PlonkishCircuitInfo<FpSM2>>(&bytes) {
            return Ok(info);
        }
        // 损坏自愈：删除后走重建（fail-closed——不得以坏缓存拒绝验证）
        let _ = std::fs::remove_file(&path);
    }
    let t0 = Instant::now();
    let info = assemble(spec).map_err(ProveError::Assemble)?.info;
    eprintln!(
        "[info-cache] 未命中 {}（装配 {:.1}s，落盘缓存）",
        &key[..16],
        t0.elapsed().as_secs_f64()
    );
    if let Ok(bytes) = bincode::serialize(&info) {
        // 缓存临时名带 pid 防并发互踩；WASI 无 pid（2026-09-28 wasm 尖峰：
        // process::id 在 wasm 恒 panic）——非 x86_64 用固定后缀（单进程面）
        #[cfg(target_arch = "wasm32")]
        let tmp = dir.join(format!("{key}.tmp-wasm"));
        #[cfg(not(target_arch = "wasm32"))]
        let tmp = dir.join(format!("{key}.tmp-{}", std::process::id()));
        if std::fs::File::create(&tmp)
            .and_then(|mut f| {
                f.write_all(&bytes)?;
                f.sync_all()
            })
            .is_ok()
        {
            // 原子落位：Windows rename 不覆盖已存在——先删后移；并发写同内容幂等
            let _ = std::fs::remove_file(&path);
            if std::fs::rename(&tmp, &path).is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
    Ok(info)
}

/// R1-1a：**实例驱动验证**——服务端零秘密验证面。
///
/// canonical spec（服务端自持的电路装配参照）只提供**电路结构 info**（同档语句
/// 恒等，advice 丢弃）；公开实例由证明方交付、服务端按期望绑定逐位核对后再验证明。
/// 秘密见证（身份证号/盐/私钥）全程不出飞手设备。
pub fn verify_instances(
    proof_path: &Path,
    vp_path: &Path,
    instances_path: &Path,
    expected: &BindingExpectations,
) -> Result<VerifyReport, ProveError> {
    let fail = |reason: String| {
        Ok(VerifyReport {
            verdict: "FAIL".to_string(),
            reason: Some(reason),
        })
    };
    // A-P3-2：双 env 并存时按验证形态分派（TRAIL 判据=chain_head_hex 非空）——
    // 旧序 FZ_AUTH_CANONICAL_SPEC 恒遮蔽 FZ_TRAIL_CANONICAL_SPEC，同进程双档
    // 验证必假拒（fail-closed 可用性缺口）
    let want_trail = !expected.chain_head_hex.trim().is_empty();
    let spec_path_auth = std::env::var("FZ_AUTH_CANONICAL_SPEC").ok();
    let spec_path_trail = std::env::var("FZ_TRAIL_CANONICAL_SPEC").ok();
    let canonical_spec_path = if want_trail {
        spec_path_trail.or(spec_path_auth)
    } else {
        spec_path_auth.or(spec_path_trail)
    }
    .or_else(|| {
        // README 流程兜底（2026-10-07 队长实弹 UX 根修）：规范文件随判决件/
        // 分发页同目录发放——未设 env 时从当前目录自动发现同名规范文件，
        // 第三方验证不再因漏设环境变量而 rc=1。
        let name = if want_trail {
            "trail_canonical_spec.json"
        } else {
            "auth_canonical_spec.json"
        };
        std::path::Path::new(name)
            .is_file()
            .then(|| name.to_string())
    })
    .ok_or_else(|| {
        ProveError::Io("canonical 电路参照缺失——请把规范文件（trail_canonical_spec.json / auth_canonical_spec.json）与本包放同一目录，或设置 FZ_TRAIL_CANONICAL_SPEC / FZ_AUTH_CANONICAL_SPEC 环境变量".into())
    })?;
    let text = std::fs::read_to_string(&canonical_spec_path)
        .map_err(|e| ProveError::Io(format!("canonical spec 不可读: {e}")))?;
    let spec: JobSpec = serde_json::from_str(&text)
        .map_err(|e| ProveError::Io(format!("canonical spec 损坏: {e}")))?;
    let spec_is_trail = spec.profile == crate::profile::Profile::Trail;
    if want_trail != spec_is_trail {
        return fail(
            "canonical spec 档位与验证形态不符（TRAIL 判据=chain_head_hex）——拒绝".to_string(),
        );
    }

    let proof = match std::fs::read(proof_path) {
        Ok(p) => p,
        Err(e) => return fail(format!("证明文件不可读: {e}")),
    };
    let vp_bytes = match std::fs::read(vp_path) {
        Ok(v) => v,
        Err(e) => return fail(format!("验证参数不可读: {e}")),
    };
    let inst_text = std::fs::read_to_string(instances_path)
        .map_err(|e| ProveError::Io(format!("实例文件不可读: {e}")))?;
    let inst_doc: serde_json::Value = match serde_json::from_str(&inst_text) {
        Ok(v) => v,
        Err(e) => return fail(format!("实例文件损坏: {e}")),
    };
    let inst_hex = match inst_doc["instances"].as_array() {
        Some(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>(),
        None => return fail("实例文件形态非法".to_string()),
    };

    // TRAIL 档（R1-6 第三方复验）：canonical spec=trail 语句结构（同构 128 样本
    // 电路，advice 丢弃），期望绑定=锚定链头（实例 0=fold_words_be）+ 高度上限/
    // 起始时间（2026-10 换代：实例 1=alt_max、实例 2=t_start 公开实例钉——期望
    // 缺失或不一致一律 fail-closed，上限与时间窗改由验证方实例面钉定）。
    if spec.profile == crate::profile::Profile::Trail {
        let want_hex = expected.chain_head_hex.trim().to_lowercase();
        if want_hex.is_empty() || want_hex.len() != 64 {
            return fail("TRAIL 期望绑定缺 chain_head_hex（64hex）".to_string());
        }
        let got = match inst_hex.first() {
            Some(g) => g.clone(),
            None => return fail("实例 0 缺失（chain_head）".to_string()),
        };
        let got_fe = match crate::ctx_tag::fp_from_be32_hex(&got) {
            Some(f) => f,
            None => return fail("实例 0 非法域元素（chain_head）".to_string()),
        };
        let bytes32 = match fixed_bytes_32(&want_hex) {
            Ok(b) => b,
            Err(e) => return fail(format!("chain_head_hex 非法: {e}")),
        };
        let want = plonkish_sm2_probe::smt_weave::fold_words_be(&bytes32);
        if got_fe != want {
            return fail("实例 0（chain_head）与锚定链头不一致——拒绝".to_string());
        }
        if expected.alt_max_cm == 0 {
            return fail(
                "TRAIL 期望绑定缺 alt_max_cm（高度上限实例 1 钉定必携——fail-closed）".to_string(),
            );
        }
        let got1 = match inst_hex.get(1) {
            Some(g) => g.clone(),
            None => return fail("实例 1 缺失（alt_max）".to_string()),
        };
        let got1_fe = match crate::ctx_tag::fp_from_be32_hex(&got1) {
            Some(f) => f,
            None => return fail("实例 1 非法域元素（alt_max）".to_string()),
        };
        if got1_fe != plonkish_sm2_probe::FpSM2::from(u64::from(expected.alt_max_cm)) {
            return fail("实例 1（alt_max）与授权高度上限不一致——拒绝".to_string());
        }
        let Some(want_t) = expected.t_start else {
            return fail(
                "TRAIL 期望绑定缺 t_start（起始时间实例 2 钉定必携——fail-closed）".to_string(),
            );
        };
        let got2 = match inst_hex.get(2) {
            Some(g) => g.clone(),
            None => return fail("实例 2 缺失（t_start）".to_string()),
        };
        let got2_fe = match crate::ctx_tag::fp_from_be32_hex(&got2) {
            Some(f) => f,
            None => return fail("实例 2 非法域元素（t_start）".to_string()),
        };
        if got2_fe != plonkish_sm2_probe::FpSM2::from(u64::from(want_t)) {
            return fail("实例 2（t_start）与声明起始时间不一致——拒绝".to_string());
        }
        // 二批换代（改动2）：周期实例 3 钉定必携——期望缺失/实例缺失/域元素
        // 非法/值不符四类一律 FAIL（人话报错，与 alt_max/t_start 同法）。
        let Some(want_period) = expected.sample_period_ms else {
            return fail(
                "TRAIL 期望绑定缺 sample_period_ms（采样周期实例 3 钉定必携——fail-closed）"
                    .to_string(),
            );
        };
        if want_period == 0 {
            return fail("TRAIL 期望绑定 sample_period_ms=0 非法（周期域 1..60000）".to_string());
        }
        let got3 = match inst_hex.get(3) {
            Some(g) => g.clone(),
            None => return fail("实例 3 缺失（sample_period_ms）".to_string()),
        };
        let got3_fe = match crate::ctx_tag::fp_from_be32_hex(&got3) {
            Some(f) => f,
            None => return fail("实例 3 非法域元素（sample_period_ms）".to_string()),
        };
        if got3_fe != plonkish_sm2_probe::FpSM2::from(u64::from(want_period)) {
            return fail("实例 3（sample_period_ms）与声明采样周期不一致——拒绝".to_string());
        }
        // 二批换代（改动1）：围栏 4 界实例 4..7 钉定必携（期望携经纬度原值，
        // 偏置编码折算后逐位核对——e=(v+2^31) mod 2^32，与电路 bias_u32 同式）。
        let Some(fence) = &expected.fence else {
            return fail(
                "TRAIL 期望绑定缺 fence（矩形围栏 4 界实例 4..7 钉定必携——fail-closed）"
                    .to_string(),
            );
        };
        let bias = |v: i64| -> Option<u32> {
            let e = v + (1i64 << 31);
            if (0..=0xFFFF_FFFF).contains(&e) {
                Some(e as u32)
            } else {
                None
            }
        };
        let fence_slots: [(&str, i64, usize); 4] = [
            ("min_lat", fence.min_lat, 4),
            ("max_lat", fence.max_lat, 5),
            ("min_lon", fence.min_lon, 6),
            ("max_lon", fence.max_lon, 7),
        ];
        for (name, want_v, idx) in fence_slots {
            let Some(want_b) = bias(want_v) else {
                return fail(format!("TRAIL 围栏期望 {name} 越经纬度值域（|lat|≤90°、|lon|≤180°）"));
            };
            let got = match inst_hex.get(idx) {
                Some(g) => g.clone(),
                None => return fail(format!("实例 {idx} 缺失（{name}）")),
            };
            let got_fe = match crate::ctx_tag::fp_from_be32_hex(&got) {
                Some(f) => f,
                None => return fail(format!("实例 {idx} 非法域元素（{name}）")),
            };
            if got_fe != plonkish_sm2_probe::FpSM2::from(u64::from(want_b)) {
                return fail(format!("实例 {idx}（{name}）与围栏期望不一致——拒绝"));
            }
        }
    } else {
    // 期望实例逐位核对（域元素形态——任何一维不符即 FAIL，先于重验证）
    let expect_field = |idx: usize, want: plonkish_sm2_probe::FpSM2, name: &str| -> Result<(), String> {
        let got = inst_hex
            .get(idx)
            .ok_or_else(|| format!("实例 {idx} 缺失（{name}）"))?;
        let got_fe = crate::ctx_tag::fp_from_be32_hex(got)
            .ok_or_else(|| format!("实例 {idx} 非法域元素（{name}）"))?;
        if got_fe != want {
            Err(format!("实例 {idx}（{name}）与申请绑定不一致——拒绝（T6 服务侧强制）"))
        } else {
            Ok(())
        }
    };
    let check = (|| -> Result<(), String> {
        // 语句摘要钉（S5[严重1]；2026-10 fail-open 封口）：实例 0=e=digest(M_A′)
        // ——服务端从提交报文独立重导出。e_hex 缺失（空串）=期望面残缺，受理
        // 面必须入库 e=digest(M_A′)——缺即拒（人话报错，不再静默放行）。
        if expected.e_hex.trim().is_empty() {
            return Err(
                "AUTH 期望绑定缺 e_hex（语句摘要实例 0 钉定必携——受理面须入库 e=digest(M_A′)，fail-closed）"
                    .to_string(),
            );
        }
        {
            let e_fe = crate::ctx_tag::fp_from_be32_hex(&expected.e_hex)
                .ok_or_else(|| "实例 0 非法域元素（e_hex）".to_string())?;
            let got0 = inst_hex
                .first()
                .ok_or_else(|| "实例 0 缺失（e）".to_string())?;
            let got_fe = crate::ctx_tag::fp_from_be32_hex(got0)
                .ok_or_else(|| "实例 0 非法域元素".to_string())?;
            if got_fe != e_fe {
                return Err("实例 0（语句摘要 e）与提交报文不一致——拒绝".to_string());
            }
        }
        use plonkish_sm2_probe::sm2_z_anchor::fe_be32;
        use plonkish_sm2_probe::smt_weave::fold_words_be;
        let challenge = crate::ctx_tag::hex_decode_bytes(&expected.challenge_hex)
            .ok_or("challenge_hex 非法")?;
        expect_field(
            auth_instances::IDX_CTX_TAG,
            crate::ctx_tag::ctx_tag_from_challenge(&challenge),
            "ctx_tag",
        )?;
        expect_field(auth_instances::IDX_PRED_ID, crate::profile::pred_id_fp(&expected.pred_id), "pred_id")?;
        expect_field(
            auth_instances::IDX_T,
            plonkish_sm2_probe::FpSM2::from(u64::from(expected.t_epoch)),
            "t_epoch",
        )?;
        expect_field(
            auth_instances::IDX_THETA,
            plonkish_sm2_probe::FpSM2::from(u64::from(expected.required_level)),
            "required_level",
        )?;
        expect_field(
            auth_instances::IDX_CLASS,
            plonkish_sm2_probe::FpSM2::from(u64::from(expected.class_id)),
            "class_id",
        )?;
        let root: [u8; 32] = fixed_bytes_32(&expected.smt_root_hex)?;
        expect_field(auth_instances::IDX_SMT_ROOT, fold_words_be(&root), "smt_root")?;
        let _ = fe_be32;
        Ok(())
    })();
    if let Err(reason) = check {
        return fail(reason);
    }
    } // trail/AUTH 分支闭合

    // 结构化实例 → 后端验证（info=canonical 装配结构【指纹键控磁盘缓存】，
    // advice 恒空——验证不需要见证）
    let instances_cols = vec![inst_hex
        .iter()
        .map(|h| {
            fp_from_be32_hex_pub(h).ok_or_else(|| ProveError::Io(format!("非法实例 hex: {h}")))
        })
        .collect::<Result<Vec<_>, _>>()?];
    let info = canonical_info_cached(&spec, &text)?;
    let backend_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let vp = match bincode::deserialize::<<Pb as PlonkishBackend<FpSM2>>::VerifierParam>(&vp_bytes[..]) {
            Ok(v) => v,
            Err(e) => return Err(format!("验证参数反序列化失败: {e}")),
        };
        let mut transcript = T::from_proof((), proof.as_slice());
        match Pb::verify(&vp, &instances_cols, &mut transcript, StdRng::seed_from_u64(SEED_VERIFY)) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("{e:?}")),
        }
    }));
    match backend_result {
        Ok(Ok(())) => Ok(VerifyReport { verdict: "OK".to_string(), reason: None }),
        Ok(Err(e)) => fail(e),
        Err(boxed) => fail(panic_msg(&boxed)),
    }
}

fn fixed_bytes_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("须 64 hex".into());
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| "非法 hex".to_string())?;
    }
    Ok(out)
}

fn fp_from_be32_hex_pub(hex: &str) -> Option<plonkish_sm2_probe::FpSM2> {
    crate::ctx_tag::fp_from_be32_hex(hex)
}

/// panic 载荷消息提取（&str/String 之外的载荷给占位描述）。
fn panic_msg(boxed: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = boxed.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = boxed.downcast_ref::<String>() {
        s.clone()
    } else {
        "非字符串 panic 载荷".to_string()
    }
}

/// 独立验证（Task 6 verify-only 的库面）：盘上证明字节 + **prove 侧 verifier
/// 参数字节** → from_proof verify。
///
/// 🔴 vp 必传（Task 6 深坑）：Basefold commit 的 D18 掩蔽使 index 承诺不可
/// 重算，重做 preprocess 必开口不一致（basefold.rs:2807 实证）——vp 由
/// prove 落盘（verifier_param.bin），verify 侧禁止重做。
/// `Err(描述)` = FAIL（判决语义）。🔴 panic 一律兜底转 `Err`——vendor 校验面
/// 存在 assert panic 路径（实测：翻转证明打穿 basefold.rs:2807 开口断言，
/// 不走 Error 返回），服务边界拒绝任何 panic 逃逸。
pub fn verify_proof_bytes(spec: &JobSpec, proof: &[u8], vp_bytes: &[u8]) -> Result<(), String> {
    let spec_c = spec.clone();
    let proof_c = proof.to_vec();
    let vp_c = vp_bytes.to_vec();
    in_big_stack(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let asm = match assemble(&spec_c) {
                Ok(a) => a,
                Err(e) => return Err(format!("装配拒绝: {e}")),
            };
            // R1 内存优化同款：解构移动（验证面 advice 只被 synthesize 消费一次）。
            let plonkish_sm2_probe::sm2_verify_assemble::Assembled {
                info, advice, instances, ..
            } = asm;
            let circuits = JobCircuit {
                info,
                advice: std::sync::Mutex::new(Some(advice)),
                instances,
            };
            let vp = match bincode::deserialize::<<Pb as PlonkishBackend<FpSM2>>::VerifierParam>(&vp_c) {
                Ok(v) => v,
                Err(e) => return Err(format!("验证参数反序列化失败: {e}")),
            };
            let mut transcript = T::from_proof((), proof_c.as_slice());
            match Pb::verify(
                &vp,
                &circuits.instances,
                &mut transcript,
                StdRng::seed_from_u64(SEED_VERIFY),
            ) {
                Ok(()) => Ok(()),
                Err(e) => Err(format!("verify FAIL: {e:?}")),
            }
        }))
        .unwrap_or_else(|boxed| Err(format!("verify panic 兜底: {}", panic_msg(&boxed))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// env 互斥（同进程并行测试互踩防线——PCS 开关三件为进程级 env）。
    use crate::test_env::ENV_MUTEX as ENV_LOCK;

    fn clear_pcs_env() {
        for k in [ENV_PCS_INTERLEAVE, ENV_PCS_BATCH_DEDUP, ENV_PCS_VERIFY_STREAM] {
            std::env::remove_var(k);
        }
    }

    /// 部署默认：未显式设置 ⟹ 交织开、其余关；显式 "0" ⟹ 保留 legacy（不被覆盖）。
    #[test]
    fn deployment_default_flips_interleave_only_and_respects_explicit_zero() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_pcs_env();
        apply_pcs_deployment_defaults();
        assert_eq!(
            pcs_switches(),
            PcsSwitches { interleave: true, batch_dedup: false, verify_stream: false },
            "未设置 ⟹ 仅交织开（去重/流式保持关）"
        );
        std::env::set_var(ENV_PCS_INTERLEAVE, "0");
        apply_pcs_deployment_defaults();
        assert!(!pcs_switches().interleave, "显式 0 = legacy 构型，部署默认不得覆盖");
        clear_pcs_env();
    }

    /// 2026-10 fail-open 封口负例（改动5）：AUTH 期望缺 e_hex ⟹ verify-instances
    /// 拒绝（实例 0 语句摘要钉必携——期望面残缺不再静默放行）。垃圾 proof/vp
    /// 即可驱动：e_hex 门先于后端验证触发，无需真证明。
    #[test]
    fn verify_instances_missing_e_hex_fail_closed() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");
        let spec = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/auth_canonical_spec.json");
        std::env::set_var("FZ_AUTH_CANONICAL_SPEC", &spec);

        let dir = std::env::temp_dir().join(format!("fz-e-hex-neg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("proof.bin"), b"garbage").unwrap();
        std::fs::write(dir.join("verifier_param.bin"), b"garbage").unwrap();
        std::fs::write(
            dir.join("instances.json"),
            r#"{"instances":["0000000000000000000000000000000000000000000000000000000000000000"]}"#,
        )
        .unwrap();

        let expected = BindingExpectations {
            challenge_hex: "ab".repeat(32),
            pred_id: "plan:p|nonce:n|policy:v".into(),
            t_epoch: 1_700_000_000,
            required_level: 2,
            class_id: 1,
            smt_root_hex: "11".repeat(32),
            chain_head_hex: String::new(), // AUTH 形态（TRAIL 判据=chain_head 非空）
            e_hex: String::new(),          // 🔴 被测面：缺失
            alt_max_cm: 0,
            t_start: None,
            sample_period_ms: None,
            fence: None,
        };
        let report = verify_instances(
            &dir.join("proof.bin"),
            &dir.join("verifier_param.bin"),
            &dir.join("instances.json"),
            &expected,
        )
        .expect("期望面残缺必须走 FAIL 判决（非 IO 错误）");
        assert_eq!(report.verdict, "FAIL", "缺 e_hex 必须 FAIL");
        let reason1 = report.reason.clone().unwrap_or_default();
        assert!(reason1.contains("e_hex"), "拒绝原因必须具名 e_hex：{reason1:?}");

        // 对照：e_hex 在场（合法 hex）⟹ 拒绝原因不再是「缺 e_hex」（封口的是
        // 缺失放行，不是核对语义本身——实例 0 不一致在后续核对面照常抓）。
        let expected_ok = BindingExpectations { e_hex: "12".repeat(32), ..expected };
        let report2 = verify_instances(
            &dir.join("proof.bin"),
            &dir.join("verifier_param.bin"),
            &dir.join("instances.json"),
            &expected_ok,
        )
        .expect("垃圾证明走 FAIL 判决");
        assert_eq!(report2.verdict, "FAIL");
        let r2 = report2.reason.unwrap_or_default();
        assert!(!r2.contains("缺 e_hex"), "e_hex 在场时不得以缺失拒绝：{r2}");

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("FZ_AUTH_CANONICAL_SPEC");
    }

    /// 2026-10 换代负例（改动4）：TRAIL 期望缺 alt_max_cm / t_start ⟹
    /// verify-instances 拒绝（实例 1/2 公开钉必携——期望面残缺 fail-closed）。
    #[test]
    fn verify_instances_trail_missing_altmax_tstart_fail_closed() {
        use plonkish_sm2_probe::sm2_z_anchor::fe_be32;
        use plonkish_sm2_probe::smt_weave::fold_words_be;
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("FZ_ZK_ALLOW_TRAIL", "1");
        let spec = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/trail_canonical_spec.json");
        std::env::set_var("FZ_TRAIL_CANONICAL_SPEC", &spec);

        // 实例 0=合法 chain_head 折叠值（过链头钉核对，专测实例 1/2 期望门）。
        // expected.chain_head_hex=原始 32B（fold 的输入）；instances[0]=折叠值。
        let head_bytes: [u8; 32] = std::array::from_fn(|i| (i as u8) ^ 0x5A);
        let head_fold = fold_words_be(&head_bytes);
        let head_hex: String = head_bytes.iter().map(|b| format!("{b:02x}")).collect();

        let dir = std::env::temp_dir().join(format!("fz-trail-exp-neg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("proof.bin"), b"garbage").unwrap();
        std::fs::write(dir.join("verifier_param.bin"), b"garbage").unwrap();
        let inst0_hex: String =
            fe_be32(&head_fold).iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(
            dir.join("instances.json"),
            format!(r#"{{"instances":["{inst0_hex}"]}}"#),
        )
        .unwrap();
        let mk = |alt: u32, ts: Option<u32>| BindingExpectations {
            challenge_hex: String::new(),
            pred_id: String::new(),
            t_epoch: 0,
            required_level: 0,
            class_id: 0,
            smt_root_hex: String::new(),
            chain_head_hex: head_hex.clone(),
            e_hex: String::new(),
            alt_max_cm: alt,
            t_start: ts,
            sample_period_ms: None,
            fence: None,
        };
        let files = (
            dir.join("proof.bin"),
            dir.join("verifier_param.bin"),
            dir.join("instances.json"),
        );

        // ① 缺 alt_max_cm（=0/缺省）⟹ FAIL 且原因具名（alt_max 期望门先于实例读取）。
        let r1 = verify_instances(&files.0, &files.1, &files.2, &mk(0, Some(1_700_000_000)))
            .expect("期望残缺走 FAIL 判决");
        assert_eq!(r1.verdict, "FAIL");
        let reason2 = r1.reason.clone().unwrap_or_default();
        assert!(reason2.contains("alt_max_cm"), "拒绝原因必须具名 alt_max_cm：{reason2:?}");

        // ② 有 alt_max 缺 t_start ⟹ FAIL 且原因具名。实例 1/2 需在场且与期望
        // 一致（alt/epoch 核对通过）——专测 t_start 期望门。
        let fe = |v: u64| {
            use ff::PrimeField;
            let mut repr = <plonkish_sm2_probe::FpSM2 as PrimeField>::Repr::default();
            repr.as_mut()[..8].copy_from_slice(&v.to_le_bytes());
            let x = plonkish_sm2_probe::FpSM2::from_repr(repr).into_option().expect("u64 域元素");
            fe_be32(&x).iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        let inst3 = format!(
            r#"{{"instances":["{inst0_hex}","{}","{}"]}}"#,
            fe(12_000),
            fe(1_700_000_000)
        );
        std::fs::write(dir.join("instances3.json"), inst3).unwrap();
        let r2 = verify_instances(
            &files.0,
            &files.1,
            &dir.join("instances3.json"),
            &mk(12_000, None),
        )
        .expect("期望残缺走 FAIL 判决");
        assert_eq!(r2.verdict, "FAIL");
        let reason3 = r2.reason.clone().unwrap_or_default();
        assert!(reason3.contains("t_start"), "拒绝原因必须具名 t_start：{reason3:?}");

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("FZ_TRAIL_CANONICAL_SPEC");
    }

    /// 二批换代负例（改动1/改动2）：TRAIL 期望缺 sample_period_ms / fence ⟹
    /// verify-instances 拒绝（实例 3/4..7 公开钉必携——期望面残缺 fail-closed）；
    /// 围栏期望与实例 4..7 值不符 ⟹ 拒绝且原因具名。
    #[test]
    fn verify_instances_trail_missing_period_fence_fail_closed() {
        use plonkish_sm2_probe::sm2_z_anchor::fe_be32;
        use plonkish_sm2_probe::smt_weave::fold_words_be;
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("FZ_ZK_ALLOW_TRAIL", "1");
        let spec = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/trail_canonical_spec.json");
        std::env::set_var("FZ_TRAIL_CANONICAL_SPEC", &spec);

        // 实例 0..3 合法（链头/alt_max/t_start/周期），专测实例 4..7 期望门。
        let head_bytes: [u8; 32] = std::array::from_fn(|i| (i as u8) ^ 0x6B);
        let head_fold = fold_words_be(&head_bytes);
        let head_hex: String = head_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let fe = |v: u64| {
            use ff::PrimeField;
            let mut repr = <plonkish_sm2_probe::FpSM2 as PrimeField>::Repr::default();
            repr.as_mut()[..8].copy_from_slice(&v.to_le_bytes());
            let x = plonkish_sm2_probe::FpSM2::from_repr(repr).into_option().expect("u64 域元素");
            fe_be32(&x).iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        let bias = |v: i64| -> String { fe((v + (1i64 << 31)) as u64) };
        let dir = std::env::temp_dir().join(format!("fz-trail-exp2-neg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("proof.bin"), b"garbage").unwrap();
        std::fs::write(dir.join("verifier_param.bin"), b"garbage").unwrap();
        let inst_head = fe_be32(&head_fold).iter().map(|b| format!("{b:02x}")).collect::<String>();
        let inst8 = format!(
            r#"{{"instances":["{inst_head}","{}","{}","{}","{}","{}","{}","{}"]}}"#,
            fe(12_000),
            fe(1_700_000_000),
            fe(500),
            bias(300_000_000),
            bias(320_000_000),
            bias(1_200_000_000),
            bias(1_220_000_000),
        );
        let files = (
            dir.join("proof.bin"),
            dir.join("verifier_param.bin"),
            dir.join("instances.json"),
        );
        std::fs::write(&files.2, &inst8).unwrap();
        let fence_ok = crate::prove::TrailFenceExpectations {
            min_lat: 300_000_000,
            max_lat: 320_000_000,
            min_lon: 1_200_000_000,
            max_lon: 1_220_000_000,
        };
        let mk = |period: Option<u32>, fence: Option<crate::prove::TrailFenceExpectations>| BindingExpectations {
            challenge_hex: String::new(),
            pred_id: String::new(),
            t_epoch: 0,
            required_level: 0,
            class_id: 0,
            smt_root_hex: String::new(),
            chain_head_hex: head_hex.clone(),
            e_hex: String::new(),
            alt_max_cm: 12_000,
            t_start: Some(1_700_000_000),
            sample_period_ms: period,
            fence,
        };

        // ① 缺 sample_period_ms ⟹ FAIL 且原因具名。
        let r1 = verify_instances(&files.0, &files.1, &files.2, &mk(None, Some(fence_ok.clone())))
            .expect("期望残缺走 FAIL 判决");
        assert_eq!(r1.verdict, "FAIL");
        assert!(
            r1.reason.clone().unwrap_or_default().contains("sample_period_ms"),
            "拒绝原因必须具名 sample_period_ms：{:?}",
            r1.reason
        );

        // ② 有周期缺 fence ⟹ FAIL 且原因具名。
        let r2 = verify_instances(&files.0, &files.1, &files.2, &mk(Some(500), None))
            .expect("期望残缺走 FAIL 判决");
        assert_eq!(r2.verdict, "FAIL");
        assert!(
            r2.reason.clone().unwrap_or_default().contains("fence"),
            "拒绝原因必须具名 fence：{:?}",
            r2.reason
        );

        // ③ 围栏期望与实例不符（东界收窄 1）⟹ FAIL 且原因具名 max_lon。
        let fence_bad = crate::prove::TrailFenceExpectations { max_lon: 1_219_999_999, ..fence_ok.clone() };
        let r3 = verify_instances(&files.0, &files.1, &files.2, &mk(Some(500), Some(fence_bad)))
            .expect("期望不符走 FAIL 判决");
        assert_eq!(r3.verdict, "FAIL");
        assert!(
            r3.reason.clone().unwrap_or_default().contains("max_lon"),
            "拒绝原因必须具名 max_lon：{:?}",
            r3.reason
        );

        // ④ 全期望一致（垃圾证明仍会在后端验证拒绝——但实例核对门必须放行）
        // ⟹ FAIL 原因不再是实例核对（到达后端验证段）。
        let r4 = verify_instances(&files.0, &files.1, &files.2, &mk(Some(500), Some(fence_ok)))
            .expect("垃圾证明走 FAIL 判决");
        assert_eq!(r4.verdict, "FAIL");
        let reason4 = r4.reason.clone().unwrap_or_default();
        assert!(
            !reason4.contains("实例") && !reason4.contains("围栏期望不一致"),
            "全期望一致时不得以实例核对拒绝：{reason4:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("FZ_TRAIL_CANONICAL_SPEC");
    }

    /// SV-3 纪律：判决件必须显式记录 PCS 部署开关三件（同一电路在不同构型下尺寸/时延
    /// 不同，判决行须自述"证的是哪种构型"）。取值与 vendor 判定同式：env 恰为 "1" 才开。
    #[test]
    fn pcs_switches_reflect_env_exactly_one() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_pcs_env();
        assert_eq!(
            pcs_switches(),
            PcsSwitches { interleave: false, batch_dedup: false, verify_stream: false },
            "未设置=全关（收口默认）"
        );
        std::env::set_var(ENV_PCS_INTERLEAVE, "1");
        std::env::set_var(ENV_PCS_VERIFY_STREAM, "true"); // 非 "1" = 关（与 vendor 同式）
        assert_eq!(
            pcs_switches(),
            PcsSwitches { interleave: true, batch_dedup: false, verify_stream: false },
            "仅恰为 \"1\" 的开关为开"
        );
        clear_pcs_env();
    }

    /// 评审 P3-2：掩蔽自述缺省 on；MASK_OFF 置位 ⟹ off（与 vendor 逐字同式：
    /// 存在即关——含 "0" 等任意值；判决件唯一披露面）。
    #[test]
    fn verdict_mask_flag_defaults_on_and_reports_off() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(ENV_MASK_OFF);
        assert_eq!(mask_flag(), "on", "缺省=掩蔽启用");
        std::env::set_var(ENV_MASK_OFF, "1");
        assert_eq!(mask_flag(), "off", "MASK_OFF 置位 ⟹ 诊断构型，判决件须披露");
        std::env::set_var(ENV_MASK_OFF, "0");
        assert_eq!(mask_flag(), "off", "存在即关（与 vendor is_ok() 同式——置 0 也是关）");
        std::env::remove_var(ENV_MASK_OFF);
        assert_eq!(mask_flag(), "on", "取除后恢复缺省（无跨测试泄漏）");
    }

    /// 信任根收口件4：MASK_OFF 出证准入——production 档拒绝（掩蔽关闭=证明
    /// 可链接，生产环境禁止）；demo/dev 档现状不变（仅 stderr 警示+判决件
    /// 自述，诊断/对照构型照常可跑）。判定=FZ_DEPLOYMENT 恰为 production
    /// （大小写不敏感）；其他值/缺省=非 production 不收紧。
    #[test]
    fn mask_off_admission_rejects_production_allows_demo() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(ENV_MASK_OFF);
        std::env::remove_var(ENV_DEPLOYMENT);
        assert!(mask_off_admission().is_ok(), "掩蔽缺省 on=放行（现状）");
        // demo 档 + MASK_OFF → 现状不变（Ok；stderr 警条+判决件自述兜底）
        std::env::set_var(ENV_MASK_OFF, "1");
        assert!(
            mask_off_admission().is_ok(),
            "非 production 档 MASK_OFF=诊断构型现状可跑（不收紧）"
        );
        // production + MASK_OFF → Err（拒绝出证，人话点名）
        std::env::set_var(ENV_DEPLOYMENT, "production");
        let err = mask_off_admission().expect_err("production+MASK_OFF 必须拒绝出证");
        match &err {
            ProveError::MaskOffInProduction(msg) => {
                assert!(msg.contains("证明可链接"), "人话必须点名掩蔽关闭语义: {msg}");
                assert!(msg.contains("生产环境禁止"), "人话必须点名生产禁令: {msg}");
            }
            other => panic!("必须为 MaskOffInProduction 变体: {other:?}"),
        }
        assert!(format!("{err}").contains("出证拒绝"), "Display 面可辨: {err}");
        // 大小写不敏感；非 production 声明不收紧
        std::env::set_var(ENV_DEPLOYMENT, "PRODUCTION");
        assert!(mask_off_admission().is_err(), "判定大小写不敏感");
        std::env::set_var(ENV_DEPLOYMENT, "demo");
        assert!(mask_off_admission().is_ok(), "非 production 声明=不收紧");
        // MASK 取除后恢复（无跨测试泄漏）
        std::env::remove_var(ENV_MASK_OFF);
        std::env::remove_var(ENV_DEPLOYMENT);
        assert!(mask_off_admission().is_ok());
    }

    /// 信任根收口件4 管线面：prove_pipeline 在 production+MASK_OFF 下**最前置**
    /// 拒绝——先于 vendor 指纹/装配/落盘，零副作用不建目录（fail-closed）。
    #[test]
    fn prove_pipeline_refuses_mask_off_in_production_zero_side_effects() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(ENV_DEPLOYMENT, "production");
        std::env::set_var(ENV_MASK_OFF, "1");
        let text = std::fs::read_to_string("tests/auth_canonical_spec.json")
            .expect("auth canonical spec 缺失");
        let spec: JobSpec = serde_json::from_str(&text).unwrap();
        let dir = std::env::temp_dir().join(format!("fz-maskoff-prod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let err = prove_pipeline(&spec, &dir).expect_err("production+MASK_OFF 必须拒绝出证");
        assert!(
            matches!(err, ProveError::MaskOffInProduction(_)),
            "拒绝必须走 MaskOffInProduction 变体: {err:?}"
        );
        assert!(!dir.exists(), "fail-closed 最前置：零副作用不建目录");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var(ENV_MASK_OFF);
        std::env::remove_var(ENV_DEPLOYMENT);
    }

    /// SP-20 R-4①：in_big_stack 主线程重放的 BigStackPanic 必须可被外层
    /// catch_unwind 捕获——prove 面（prove_pipeline :371）与 verify 面
    /// （verify_pipeline 尾段）收拢纪律的共同前提。工作线程 panic →
    /// join Err → 调用线程 panic_any(BigStackPanic)——若此重放不可捕获，
    /// 两管线的结构化收拢全部失效（exit 101 逃逸）。
    #[test]
    fn big_stack_panic_replay_is_catchable() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // 静音 worker 线程 panic 输出
        let caught = std::panic::catch_unwind(|| {
            // 工作线程闭包 panic（catch_unwind 不在场=join 必 Err）
            in_big_stack(|| panic!("worker panic"));
        });
        std::panic::set_hook(prev);
        let payload = caught.expect_err("worker panic 必经 join Err 重放为 BigStackPanic");
        assert!(
            payload.downcast_ref::<BigStackPanic>().is_some(),
            "重放载荷必须是 BigStackPanic 哨兵（收拢识别面）"
        );
    }
    /// R4 第二批 A-路线#3：info 磁盘缓存语义（TRAIL 档——装配快）。四面：
    /// ① 首调落盘恰好一个缓存文件 ② 二调命中且与首调/新鲜装配逐位一致
    /// ③ spec 字节变化（语义不变）→ 键旋转 → 重新装配（键敏感性）
    /// ④ 缓存截断 → 自愈重建（fail-closed——坏缓存不放行不阻塞）。
    #[test]
    fn info_cache_roundtrip_and_key_rotation() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("fz-info-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("FZ_ZK_INFO_CACHE_DIR", &dir);
        std::env::set_var("FZ_ZK_INFO_CACHE", "1");
        std::env::set_var("FZ_ZK_ALLOW_TRAIL", "1");

        let text = std::fs::read_to_string("tests/trail_canonical_spec.json")
            .expect("trail canonical spec 缺失");
        let spec: JobSpec = serde_json::from_str(&text).unwrap();
        let i1 = canonical_info_cached(&spec, &text).expect("首调装配+落盘");
        let n1 = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(n1, 1, "首调落盘恰好一个缓存文件");

        let i2 = canonical_info_cached(&spec, &text).expect("二调命中");
        assert_eq!(
            bincode::serialize(&i1).unwrap(),
            bincode::serialize(&i2).unwrap(),
            "命中值与首调逐位一致"
        );
        let fresh = assemble(&spec).unwrap().info;
        assert_eq!(
            bincode::serialize(&fresh).unwrap(),
            bincode::serialize(&i1).unwrap(),
            "缓存内容与新鲜装配逐位一致（不失真）"
        );

        // 键旋转：尾随空白=字节变化（语义不变）→ 新键 → 重新装配+新文件
        let text2 = format!("{text}
");
        let _i3 = canonical_info_cached(&spec, &text2).unwrap();
        let n2 = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(n2, 2, "spec 字节变化必须键旋转（新缓存文件）");

        // 损坏自愈：截断缓存文件 → 下次调用重建（fail-closed）
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "bin") {
                let bytes = std::fs::read(&p).unwrap();
                std::fs::write(&p, &bytes[..bytes.len() / 2]).unwrap();
            }
        }
        let i4 = canonical_info_cached(&spec, &text).expect("损坏自愈重建");
        assert_eq!(
            bincode::serialize(&i4).unwrap(),
            bincode::serialize(&i1).unwrap(),
            "自愈后与原值一致"
        );

        std::env::remove_var("FZ_ZK_INFO_CACHE_DIR");
        std::env::remove_var("FZ_ZK_INFO_CACHE");
        std::env::remove_var("FZ_ZK_ALLOW_TRAIL");
        let _ = std::fs::remove_dir_all(&dir);
    }





    /// 🔴 常驻守卫（2026-09-26 ①定谳探针转正）：AUTH 电路结构**规范序恒同**——
    /// 环内容与消息无关（原始顺序因装配器 HashMap 迭代序非确定，排序归一后
    /// 跨消息逐位相等）。这是「电路结构=profile 纯函数」的直接判据：
    /// ②③ 电路手术若引入消息条件分支（结构随消息而变），本测试转红。
    /// 注意：原始（未排序）info 字节跨次装配不可复现——依赖结构锚的对拍
    /// 必须走规范序（本测试的 canon 形态）。
    #[test]
    fn auth_structure_canonical_identity_guard() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");

        let text = std::fs::read_to_string("tests/auth_canonical_spec.json")
            .expect("auth canonical spec 缺失");
        let spec_a: JobSpec = serde_json::from_str(&text).unwrap();
        let mut spec_b = spec_a.clone();
        {
            let b = spec_b.binding.as_mut().expect("binding");
            b.challenge_hex = "ab".repeat(32);
            b.t_epoch += 7777;
            b.pred_id = "plan:probe-b|nonce:probe-b|policy:v2026.1".to_string();
        }

        fn canon(mut r: Vec<Vec<(usize, usize)>>) -> Vec<Vec<(usize, usize)>> {
            for ring in r.iter_mut() {
                ring.sort();
            }
            r.sort();
            r
        }
        let ia = canon(assemble(&spec_a).expect("A 装配").info.permutations);
        let ia2 = canon(assemble(&spec_a).expect("A2 装配").info.permutations);
        let ib = canon(assemble(&spec_b).expect("B 装配").info.permutations);
        assert_eq!(ia, ia2, "同 spec 规范序装配不确定（装配器确定性被破坏）");
        assert_eq!(
            ia, ib,
            "AUTH 结构规范序随消息而变——电路结构不再是 profile 纯函数（②③手术回归门）"
        );
    }

    /// ①定谳实证工具（#[ignore]，~18 分钟手动跑）：跨消息复用 (pp,vp) 的
    /// prove→verify 全链——规范化（环排序）语义等价性的实锤记录。2026-09-26
    /// 首跑全绿（proof 校验通过）。注意：prove 段 934s/386MB 是探针未设 PCS
    /// 部署默认的构型噪音（非交织态），非规范化代价；pp 序列化 4.26GB 是
    /// 「prove 侧参数缓存经济性为负」的定谳数据（往返 >20s，超可省 7-20s）。
    /// ①决定性探针（第五版）：规范化（环排序）语义等价 + 跨消息参数复用。
    /// A 装配→规范化→setup/preprocess→(pp,vp) 落盘【模拟缓存】；
    /// B（不同消息）装配→规范化→**复用盘上 (pp,vp)** prove→from_proof verify。
    /// 全绿=规范化语义等价+跨消息参数缓存可行（①的重构路径成立）。
    /// 成本 ~4 分钟（两次 prove）——#[ignore]，手动 --ignored 跑。
    #[test]
    #[ignore]
    fn auth_cross_message_cached_params_e2e() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");

        fn canon_info(info: &mut PlonkishCircuitInfo<FpSM2>) {
            for ring in info.permutations.iter_mut() {
                ring.sort();
            }
            info.permutations.sort();
        }

        let text = std::fs::read_to_string("tests/auth_canonical_spec.json")
            .expect("auth canonical spec 缺失");
        let spec_a: JobSpec = serde_json::from_str(&text).unwrap();
        let mut spec_b = spec_a.clone();
        {
            let b = spec_b.binding.as_mut().expect("binding");
            b.challenge_hex = "ab".repeat(32);
            b.t_epoch += 7777;
            b.pred_id = "plan:probe-b|nonce:probe-b|policy:v2026.1".to_string();
        }

        let dir = std::env::temp_dir().join(format!("fz-xmsg-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // ── A：装配→规范化→setup+preprocess→缓存落盘 ──
        let t0 = Instant::now();
        let mut info_a = assemble(&spec_a).expect("A 装配").info;
        canon_info(&mut info_a);
        let nv = info_a.k;
        let param = Pb::setup(&info_a, StdRng::seed_from_u64(SEED_SETUP ^ nv as u64))
            .map_err(|e| format!("setup: {e:?}"))
            .unwrap();
        let (pp, vp) = Pb::preprocess(&param, &info_a)
            .map_err(|e| format!("preprocess: {e:?}"))
            .unwrap();
        println!("[xmsg] A setup+preprocess {:.1}s", t0.elapsed().as_secs_f64());
        let pp_bytes = bincode::serialize(&pp).unwrap();
        let vp_bytes = bincode::serialize(&vp).unwrap();
        std::fs::write(dir.join("pp.bin"), &pp_bytes).unwrap();
        std::fs::write(dir.join("vp.bin"), &vp_bytes).unwrap();
        println!("[xmsg] 缓存落盘 pp={}B vp={}B", pp_bytes.len(), vp_bytes.len());
        drop(pp);
        drop(param);

        // ── B：不同消息，复用盘上参数 prove→verify ──
        let t1 = Instant::now();
        let plonkish_sm2_probe::sm2_verify_assemble::Assembled {
            info: info_b_raw,
            advice,
            instances,
            ..
        } = assemble(&spec_b).expect("B 装配");
        let mut info_b = info_b_raw;
        canon_info(&mut info_b);
        let pp2: <Pb as PlonkishBackend<FpSM2>>::ProverParam =
            bincode::deserialize(&std::fs::read(dir.join("pp.bin")).unwrap()).unwrap();
        let vp2: <Pb as PlonkishBackend<FpSM2>>::VerifierParam =
            bincode::deserialize(&std::fs::read(dir.join("vp.bin")).unwrap()).unwrap();
        println!("[xmsg] B 装配+规范化+缓存载入 {:.1}s", t1.elapsed().as_secs_f64());

        let circuits = JobCircuit {
            info: info_b,
            advice: std::sync::Mutex::new(Some(advice)),
            instances,
        };
        let t2 = Instant::now();
        let mut transcript = T::new(());
        Pb::prove(&pp2, &circuits, &mut transcript, StdRng::seed_from_u64(SEED_PROVE))
            .map_err(|e| format!("prove: {e:?}"))
            .unwrap();
        let proof = transcript.into_proof();
        println!("[xmsg] B prove（复用缓存参数）{:.1}s proof={}B", t2.elapsed().as_secs_f64(), proof.len());

        let mut tr2 = T::from_proof((), proof.as_slice());
        let v = Pb::verify(&vp2, &circuits.instances, &mut tr2, StdRng::seed_from_u64(SEED_VERIFY));
        assert!(v.is_ok(), "跨消息缓存参数的证明未通过验证：{v:?}");
        println!("[xmsg] ✅ 跨消息复用 (pp,vp) prove→verify 全绿——规范化语义等价实锤");

        let _ = std::fs::remove_dir_all(&dir);
    }

}
