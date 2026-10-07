//! 档位注册表：zkc 可服务的电路档位与任务规格（飞证 B3 fork——单 Auth 档）。
//!
//! [`Profile::Auth`]：起飞资格证明语句（框架 §5.1）——RA 子凭证 SM2 签名
//! （165B M_A 电路口径）+ 承诺原像（54B：salt‖cert‖id‖sn_h）+ 资质范围门
//! cert ≥ required_level + 有效期 exp_u ≥ t_epoch + 申请绑定（ctx_tag/pred_id
//! 实例钉；plan_hash/nonce/policy_version 服务层复合折算——安全论证 T6）。
//! 结构锚 **19,434 约束 / 8,410 advice / lookups 195 / 实例 26 / 2^12 行**
//! [实测 2026-10-06 ⑦代，服务路径 canonical spec 装配产出——
//! `assemble::auth_assemble_honest_structure` 三值 `assert_eq!` 钉定
//! （AUTH_CONSTRAINTS_PIN/AUTH_ADVICE_PIN/AUTH_INSTANCES_PIN），漂移即红]。
//! 演进链：B4-T7 104,287 → R2 换代 104,543（+256 SMT 查表门，撤销空洞封堵；
//! advice 13,057→11,448；lookup 24→536）→ SM3 查表化全量收口 44,383 →
//! 体B 死列清偿等电路手术 ~38.2K → 20,102 → 19,578（advice 11,448→
//! 10,283）→ ⑥代 2026-10-06 SN 绑定+内存优化：19,608 / 10,534 / 556 / 26
//!（第 5 组 SN 单块查表门 digest(sn_witness)==实例 25 sn_hash；组合 A
//! bh 歼灭+掩蔽列惰性化+mimalloc——prove 峰值窗内存换代）→ **⑦代
//! 2026-10-06 SM3 组列共享+查表通道合并：19,434 / 8,410 / 195 / 26**
//!（69 组 34 列独占→lane band 列池 799 列+552 通道→191+msg-limb 桥列
//! packing 704→128+门 276→102；TRAIL 同代 681/4,611/1,024→353/1,743/
//! 357。SPLIT3 2,688 行/组 > 4095/2 ⟹ 每带恰 1 组——通道合并下界由列
//! 角色对齐约束物理钉定，非工程折衷）。proof 归服务器窗（prove 类测试
//! 禁在本机跑）。
//!
//! 🔴 注册表语义：reps/log_rate 是**校验字段而非自由参数**——后端实例类型级
//! 钉定（reps=16/rate=1，论文基线口径），错配 = [`AssembleError::UnsupportedParams`]。
//! 🔴 fail-closed：AUTH 为绑定档——binding 必携（ctx_tag/pred_id/t_epoch 实例钉），
//! t_epoch=0 拒绝（谓词平凡=绑定语义失效）。

use plonkish_sm2_probe::FpSM2;
use serde::{Deserialize, Serialize};

use crate::ctx_tag::{ctx_tag_from_challenge, hex_decode_bytes};

/// 注册表当前钉定的后端实例参数（论文正确性档口径）。
pub const SUPPORTED_REPS: u32 = 16;
pub const SUPPORTED_LOG_RATE: u32 = 1;

/// AUTH 档准入门禁环境旗标（值必须恰为 "1"——大电路档防误触发）。
pub const ENV_ALLOW_AUTH: &str = "FZ_ZK_ALLOW_AUTH";

/// TRAIL 档准入门禁环境旗标（值必须恰为 "1"——大电路档防误触发，与 AUTH 同法）。
pub const ENV_ALLOW_TRAIL: &str = "FZ_ZK_ALLOW_TRAIL";

/// spec 明文私钥回落禁用旗标（批 4-6，SP-20 R-4②收口）：置 "1" 时装配入口
/// 拒绝「出示私钥经 spec 明文携带」的回落档（磁盘明文窗口），人话指路 env
/// 注入。桥/worker 生产拼装缺省置 1；缺省（未置）保留回落——CLI/探针/既有
/// 测试构型兼容不变。
pub const ENV_FORBID_SPEC_KEY: &str = "FZ_ZK_FORBID_SPEC_KEY";

/// 出示私钥 env 注入通道（批 4-6 主路径）：spec 的 holder_sk_hex 为空时自此
/// 取值——私钥字节不落盘（env 主路径零私钥文件）。
pub const ENV_HOLDER_SK: &str = "FZ_ZK_HOLDER_SK_HEX";

/// TRAIL 档钉定样本数（B6-d1：n=128=64 秒段@2Hz；n=16 为电路测试档不入服务）。
pub const TRAIL_N: usize = 128;

/// pred_id 域分隔前缀：`pred_id = FpSM2(SM3(DOMAIN ‖ utf8) mod p)`。
/// 与 challenge 域隔离（同字节两域必不互撞）。
pub const PRED_ID_DOMAIN: &[u8] = b"FZ-ZKSVC-PRED-ID\x01";

/// 电路档位（AUTH B3+；TRAIL B6 增）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Auth,
    Trail,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Auth => "auth",
            Profile::Trail => "trail",
        }
    }

    /// 绑定档判据（AUTH 全语句=绑定档；TRAIL=离线合规语句非绑定）。
    pub fn is_bound(self) -> bool {
        matches!(self, Profile::Auth)
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// AUTH 档载荷（用户秘密面+出示面——见证构造输入）。
/// 域元素/公钥 = 64/128 hex；签名 = 128 hex r‖s（电路口径，RA 签发）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProfileInput {
    Auth {
        /// RA 签名公钥（128 hex x‖y；Z_A 对它计算——电路常量锚）。
        ra_pk_hex: String,
        /// 一次性子凭证身份标量（32B/64hex；每次申请 CSPRNG 全新）。
        id_prime_hex: String,
        salt_hex: String,
        /// 实名身份证号（18 字节 UTF-8 形态 hex——仅进 C 原像，零披露）。
        id_number_hex: String,
        cert_level: u8,
        /// 无人机序列号（UTF-8；sn_h=SM3(serial)[0..16]）。
        serial_hex: String,
        /// 持有者出示密钥对（sk′ 64hex 端侧生成；pk′ 128hex）。批 4-6 起
        /// 可缺省（env FZ_ZK_HOLDER_SK_HEX 注入通道——桥生产拼装空此字段，
        /// 私钥字节不落盘；空值+env 亦空=装配面人话拒绝）。
        #[serde(default)]
        holder_sk_hex: String,
        holder_pk_hex: String,
        exp_u: u32,
        /// 机型类（u8——B4/A4：进 C 原像词 5 MSB+电路等值钉实例 24；与
        /// 申请声明 class_id 一致，证明绑定的机型类=凭证机型类）。
        class_id: u8,
        /// RA 子凭证签名（128hex r‖s，电路口径 e=词序折叠——backend 签发）。
        sig_hex: String,
        /// B3b 撤销累加器非成员见证：32 层兄弟（32×32B=2048hex，叶→根序）。
        smt_siblings_hex: String,
        /// 纪元根（32B/64hex——链上 IdentityRegistry 公示的当前 rev_root）。
        smt_root_hex: String,
    },
    /// TRAIL 轨迹合规证明（B6，框架 §5.2/A5 收窄语义）：
    /// 见证=n 组样本 (t BE4, alt BE2, lat BE4, lon BE4)——「已锚定记录中的
    /// 全部高度样本满足上限 ∧ 全部位置样本落在矩形围栏内 ∧ 采样周期严格
    /// 连续」；公开面=chain_head‖alt_max‖t_start‖周期‖围栏 4 界（实例 0..7，
    /// 2026-10 二批换代）。检查点设备签名在**装配面 fail-closed 验签**
    /// （B6-d7/d8'：msg/sig/设备公钥皆链上公开数据，电路内重验=零密码学
    /// 收益；坏签名/换头=拒）。
    Trail {
        /// 样本序列（14B×n：t‖alt‖lat‖lon BE 拼接 hex——n=TRAIL_N 钉定）。
        rows_hex: String,
        /// 授权高度上限（cm，与令牌 alt_max 同源）。
        alt_max_cm: u32,
        /// 声明起始时间（首样本 t——电路 t_start 钉）。
        t_start: u32,
        /// 采样周期 ms（二批换代改动2：时间门 Δt 实例 3 钉——1Hz=1000/
        /// 2Hz=500/4Hz=250；Δt 语义由电路逐对强制，周期声明被公开面钉定）。
        sample_period_ms: u32,
        /// 锚定链头（32B/64hex——链上 TelemetryAnchor 公示，实例源）。
        chain_head_hex: String,
        /// 授权号（检查点报文绑定）。
        auth_id: u64,
        /// 设备公钥（128hex x‖y——检查点验签锚）。
        device_pk_hex: String,
        /// 矩形围栏 4 界（i32×1e7——负值=南/西半球合法域；二批改动1：
        /// 电路 4 半平面门，实例 4..7 偏置编码）。
        min_lat: i32,
        max_lat: i32,
        min_lon: i32,
        max_lon: i32,
        /// 检查点列表（seq+fence_state(8hex)+sig(128hex r‖s)；1..=4 个）。
        checkpoints: Vec<CheckpointInput>,
        /// 引擎签名轨迹绑定（R4 复验 P0-1 根修 + 二批改动3 扩域）：高度上限/
        /// 围栏 4 界不再由证明者自报——引擎钥对 (auth_id‖alt_max_cm‖chain_head
        /// ‖围栏 4 界) 出具 SM2 签名，装配面 fail-closed 验签；第三方可经
        /// /authz/engine/pub 离线复核。
        binding: TrailBindingInput,
    },
}

/// TRAIL 引擎绑定载荷（R4 复验 P0-1 + 二批改动3 扩域）：绑定报文=
/// `FZ-TRAIL-BIND2|{auth_id}|{alt_max_cm}|{chain_head_hex 小写}|{min_lat}|
/// {max_lat}|{min_lon}|{max_lon}`，SM2 裸摘要签名（fold_be_integer 口径——
/// 与检查点验签同族），引擎钥（/authz/engine/pub 公示）在证明者域外 ⟹
/// 上限与围栏 4 界不可自报。BIND2 域分隔=旧格式签名（FZ-TRAIL-BIND）在
/// 新验证面结构性失效（报文域扩容即版本换代）。采样周期不入绑定签名：
/// 周期由电路 Δt 逐对强制自证（声明与记录不符即电路拒绝），无外部权威
/// 语义可签。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrailBindingInput {
    /// 授权高度上限（cm）——与外层 alt_max_cm 一致性受检。
    pub alt_max_cm: u32,
    /// 授权号——与外层 auth_id 一致性受检。
    pub auth_id: u64,
    /// 锚定链头（小写 64hex）——与外层 chain_head_hex 一致性受检。
    pub chain_head_hex: String,
    /// 矩形围栏 4 界（i32×1e7）——与外层 4 字段逐位一致性受检（二批改动3）。
    pub min_lat: i32,
    pub max_lat: i32,
    pub min_lon: i32,
    pub max_lon: i32,
    /// 引擎公钥（128hex x‖y——验签基准，第三方经 /authz/engine/pub 比对）。
    pub engine_pub_hex: String,
    /// 引擎签名（128hex r‖s，裸摘要口径）。
    pub sig_hex: String,
}

/// 检查点载荷（TRAIL 档）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointInput {
    pub seq: u32,
    /// 围栏状态 4B（FENCE_ENABLE‖FENCE_ALT_MAX BE2‖保留）。
    pub fence_state_hex: String,
    /// 设备钥签名（128hex r‖s，裸摘要口径——与 bridge sign_checkpoint 同构）。
    pub sig_hex: String,
}

impl ProfileInput {
    pub fn kind(&self) -> Profile {
        match self {
            ProfileInput::Auth { .. } => Profile::Auth,
            ProfileInput::Trail { .. } => Profile::Trail,
        }
    }
}

/// 绑定输入（JSON）：验证方挑战 nonce + 申请绑定串 + 验证方时间锚。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingInput {
    /// 验证方挑战 nonce（任意字节 hex——ctx_tag 映射源）。
    pub challenge_hex: String,
    /// 申请绑定串（UTF-8：服务层复合 plan_hash/nonce/policy_version——T6）。
    pub pred_id: String,
    /// 验证方时间锚（epoch 秒；(S6) 实例 21 钉绑）——必填且禁 0。
    pub t_epoch: u32,
    /// 验证方策略：所需资质等级（范围门 θ 实例 22 消费钉）。
    pub required_level: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingParams {
    pub ctx_tag: FpSM2,
    pub pred_id: FpSM2,
    pub t_epoch: u32,
    pub required_level: u32,
    /// challenge 原始字节（2026-10 换代：AUTH r 派生域——
    /// r = SM3("FZ-AUTH-R|v1|"‖challenge) mod n，消除 C₁≡[2]G 恒常）。
    pub challenge_bytes: Vec<u8>,
}

impl BindingInput {
    pub fn resolve(&self) -> Result<BindingParams, AssembleError> {
        if self.t_epoch == 0 {
            return Err(AssembleError::TrivialEpoch);
        }
        let challenge =
            hex_decode_bytes(&self.challenge_hex).ok_or(AssembleError::BadChallengeHex)?;
        if self.required_level == 0 || self.required_level > 255 {
            return Err(AssembleError::BadBytes {
                name: "required_level",
                reason: "资质等级域 1..255",
            });
        }
        Ok(BindingParams {
            ctx_tag: ctx_tag_from_challenge(&challenge),
            pred_id: pred_id_fp(&self.pred_id),
            t_epoch: self.t_epoch,
            required_level: self.required_level,
            challenge_bytes: challenge,
        })
    }
}

/// pred_id 规范映射：域分隔前缀+UTF-8，同一 0D 归约引擎。
pub fn pred_id_fp(pred_id: &str) -> FpSM2 {
    let mut buf = PRED_ID_DOMAIN.to_vec();
    buf.extend_from_slice(pred_id.as_bytes());
    ctx_tag_from_challenge(&buf)
}

/// zkc 任务规格（跨语言 JSON 契约；Python 服务侧产出 → zkc 消费）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    pub profile: Profile,
    #[serde(default = "dflt_reps")]
    pub reps: u32,
    #[serde(default = "dflt_log_rate")]
    pub log_rate: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<BindingInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<ProfileInput>,
}

fn dflt_reps() -> u32 {
    SUPPORTED_REPS
}
fn dflt_log_rate() -> u32 {
    SUPPORTED_LOG_RATE
}

/// 装配错误面（Display 消息面向 CLI 判决件，中文单行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    /// 大电路档准入门禁拒绝（AUTH：非 FZ_ZK_ALLOW_AUTH=1；TRAIL：非 FZ_ZK_ALLOW_TRAIL=1）。
    Forbidden { profile: Profile },
    /// 注册表参数错配（reps/log_rate 非钉定值）。
    UnsupportedParams { field: &'static str, got: u32, want: u32 },
    /// 非绑定档携带 binding（fail-closed）。
    BindingNotApplicable { profile: Profile },
    /// 绑定档缺 binding。
    MissingBinding,
    /// t_epoch=0（(S6) 谓词平凡=绑定语义失效）。
    TrivialEpoch,
    /// 档位缺输入面。
    MissingInput { profile: Profile },
    /// 输入面与档位不符。
    InputProfileMismatch { input: Profile, profile: Profile },
    /// challenge_hex 非法。
    BadChallengeHex,
    /// 语句域元素非法（严格解析无归约）。
    BadFieldElement { name: &'static str, reason: &'static str },
    /// 字节串字段非法（hex/长度）。
    BadBytes { name: &'static str, reason: &'static str },
    /// TRAIL 检查点设备验签失败（坏签名/换头报文/错钥——B6 验收门负例④）。
    BadCheckpoint { index: usize, reason: &'static str },
    /// spec 明文私钥回落被禁（批 4-6）：FZ_ZK_FORBID_SPEC_KEY=1 时装配入口
    /// 拒绝「出示私钥经 spec 明文携带」的磁盘明文窗口档——人话指路 env 注入。
    SpecKeyForbidden,
}

impl std::fmt::Display for AssembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssembleError::Forbidden { profile } => match profile {
                Profile::Auth => {
                    write!(f, "AUTH 档被准入门禁拒绝：需环境 {ENV_ALLOW_AUTH}=1")
                }
                Profile::Trail => {
                    write!(f, "TRAIL 档被准入门禁拒绝：需环境 {ENV_ALLOW_TRAIL}=1")
                }
            },
            AssembleError::UnsupportedParams { field, got, want } => write!(
                f,
                "注册表参数错配：{field}={got}，当前钉定值 {want}（后端实例类型级钉定）"
            ),
            AssembleError::BindingNotApplicable { profile } => {
                write!(f, "档位 {profile} 非绑定档，不得携带 binding（fail-closed）")
            }
            AssembleError::MissingBinding => {
                write!(f, "绑定档（auth）必须携带 binding（ctx_tag/pred_id 实例钉入）")
            }
            AssembleError::TrivialEpoch => write!(
                f,
                "t_epoch=0 使 (S6) 有效期谓词平凡满足，绑定路径禁用（须验证方真实 epoch）"
            ),
            AssembleError::MissingInput { profile } => write!(f, "档位 {profile} 缺输入面"),
            AssembleError::InputProfileMismatch { input, profile } => {
                write!(f, "输入面 kind={input} 与档位 {profile} 不符")
            }
            AssembleError::BadChallengeHex => write!(f, "challenge_hex 非法（需偶数位 hex）"),
            AssembleError::BadFieldElement { name, reason } => {
                write!(f, "语句域元素 {name} 非法：{reason}")
            }
            AssembleError::BadBytes { name, reason } => write!(f, "字节字段 {name} 非法：{reason}"),
            AssembleError::BadCheckpoint { index, reason } => write!(
                f,
                "检查点 #{index} 设备验签失败：{reason}（坏签名/换头报文/错钥——fail-closed）"
            ),
            AssembleError::SpecKeyForbidden => write!(
                f,
                "出示私钥禁止经 spec 明文携带（{ENV_FORBID_SPEC_KEY}=1 已禁用回落档——spec 明文=磁盘明文窗口）：请从 spec 中移除 holder_sk_hex，改经环境变量 {ENV_HOLDER_SK} 注入后重试（env 主路径私钥字节不落盘）"
            ),
        }
    }
}

impl std::error::Error for AssembleError {}
