/** 本机材料绑定指纹（R2-c）：子凭证签发时与「当前登记+表单」绑定——重新登记
 * 后旧子凭证即失配（RA 签名覆盖承诺 C 与出示公钥 pk′，错配必被电路装配拒绝）。
 * 此处把失配检测前移到出证之前，给人话提示而非密码学报错。
 *
 * 一次性出示钥批（2026-10-01）：出示钥对 (sk′,pk′) 改为「签发子凭证」动作
 * 当场生成、与该张子凭证同生命周期——账户长期钥只服务登录/操作签名，不再
 * 进入出示面。故材料指纹不再含账户公钥（换钥不再使子凭证失配——电路本就
 * 不消费账户钥）；指纹=登记承诺+实名/设备表单四元。 */
import { sm3 } from "sm-crypto";

export interface SubBinding {
  cred_hash: string;
  id_number: string;
  sn: string;
  cert_level: number | string;
  sub_pk: string; // 该张子凭证的出示公钥 pk′（随子凭证落盘——公钥可持久）
}

const BOUND_KEY = "fzSubBound";

/** 当前子凭证的出示公钥 pk′（fzSub 内客户端自记字段——签发时写入）。 */
export function storedSubPk(): string {
  try {
    const sub = JSON.parse(localStorage.getItem("fzSub") || "{}");
    return typeof sub.holder_pk_hex === "string" ? sub.holder_pk_hex : "";
  } catch {
    return "";
  }
}

export function currentMaterialFingerprint(): string {
  let form: any = {};
  let cred: any = {};
  try { form = JSON.parse(localStorage.getItem("fzForm") || "{}"); } catch { /* 空 */ }
  try { cred = JSON.parse(localStorage.getItem("fzCred") || "{}"); } catch { /* 空 */ }
  const parts = [
    cred.master_cred_hash_hex ?? "",
    form.id_number ?? "",
    form.sn ?? "",
    String(form.cert_level ?? ""),
  ];
  return sm3(parts.join("|"));
}

export function currentBinding(): SubBinding {
  let form: any = {};
  let cred: any = {};
  try { form = JSON.parse(localStorage.getItem("fzForm") || "{}"); } catch { /* 空 */ }
  try { cred = JSON.parse(localStorage.getItem("fzCred") || "{}"); } catch { /* 空 */ }
  return {
    cred_hash: cred.master_cred_hash_hex ?? "",
    id_number: form.id_number ?? "",
    sn: form.sn ?? "",
    cert_level: form.cert_level ?? "",
    sub_pk: storedSubPk(),
  };
}

export function storeSubBinding(): void {
  localStorage.setItem(BOUND_KEY, JSON.stringify(currentMaterialFingerprint()));
}

/** 子凭证与当前材料是否配套：无绑定记录（旧数据/未记录）=视为失配（引导重签）。 */
export function subMatchesMaterial(): boolean {
  const raw = localStorage.getItem(BOUND_KEY);
  if (!raw) return false;
  try { return JSON.parse(raw) === currentMaterialFingerprint(); } catch { return false; }
}

// ---- 出示私钥 sk′（2026-10-01 一次性出示钥批）----
// 形态=会话域内存态（sessionStorage——标签页关即焚，同 fzSessionSk 纪律）：
// 与该张子凭证生命周期绑定（子凭证本就 24h+一次性），且仅有持有 RA 签名与
// 登记原像的客户端可组合使用——sk′ 单独泄露无长期影响，也不触账户钥。
// 出证消费点唯一（ApplyView→桥 /prove/start）；会话丢失=引导重签（配额 20）。
const SUB_SK_KEY = "fzSubSk";

export function storeSubSk(skHex: string): void {
  sessionStorage.setItem(SUB_SK_KEY, skHex);
}

export function getSubSk(): string | null {
  return sessionStorage.getItem(SUB_SK_KEY);
}

export function clearSubSk(): void {
  sessionStorage.removeItem(SUB_SK_KEY);
}

// ---- 身份清扫（2026-09-25 队长实测：'退出→本机身份登录'不触发登记清理——
// 上一身份的草稿/流程快照/飞行链状态残留在新会话页面。以身份标签为锚：载入时
// 发现换人即清身份域存储；登记路径另有"先清后写"，双保险）。----
const IDENTITY_TAG_KEY = "fzIdTag";
const IDENTITY_SCOPED_KEYS = [
  "fzSub", "fzSubBound", "fzLastReceipt", "fzTokenPayload",
  "fzPlanDraft", "fzPlanStore", "fzLastPlanCommit",
  "fzDevicePub", "fzTrailAuthId", "fzTrailGenesis", "fzTrailHead", "fzTrailRows",
  "fzLastCaseId",
];

/** 会话域清理键（单一事实源——2026-09-28 安全深检 C-P1-1：凡清会话态一律
 * 引本表，禁止手抄键名）。fzSessionSkUnlock 已随「明文钥纯内存」批退役
 * （2026-09-30 口径 E12 对齐），保留键名一行期以防旧页面残留写回。 */
export const SESSION_CLEANUP_KEYS = [
  "fzSessionSk",       // 申请流程会话钥（取件解密用）
  "fzSubSk",           // 出示私钥 sk′（一次性出示钥批——会话域绑定当前子凭证）
  "fzSessionSkUnlock", // 已退役（历史残留清扫）
  "fzApplyFlow",       // 申请流程快照
] as const;

/** 会话域清理（单一入口）。 */
export function clearSessionState(): void {
  for (const k of SESSION_CLEANUP_KEYS) sessionStorage.removeItem(k);
}

export function identityTag(): string {
  try {
    const cred = JSON.parse(localStorage.getItem("fzCred") || "{}");
    return String(cred.master_cred_hash_hex ?? "").slice(0, 16);
  } catch { return ""; }
}

export function storeIdentityTag(): void {
  localStorage.setItem(IDENTITY_TAG_KEY, identityTag());
}

/** 登录/载入时调用：当前身份与上次标签不一致 ⟹ 清身份域存储并落新标签。
 * 返回是否发生过清扫（供 UI 提示"检测到身份切换，已清理上一身份残留"）。 */
export function sweepIfIdentityChanged(): boolean {
  const tag = identityTag();
  if (!tag) return false; // 游客态不动
  const stored = localStorage.getItem(IDENTITY_TAG_KEY);
  if (stored === tag) return false; // 同一身份
  for (const k of IDENTITY_SCOPED_KEYS) localStorage.removeItem(k);
  clearSessionState();
  localStorage.setItem(IDENTITY_TAG_KEY, tag);
  return true;
}

// ---- 账户切换清扫（2026-09-29 账户批）：登录时前后账户不同 ⟹ 上一账户的
// 本机材料全清（含 fzCred/fzForm/本地密钥缓存——账户模型下这些皆为身份域）。
// 服务端会话是真权威，但本机残留会让新账户页面读到旧账户凭证。----
const ACCOUNT_SWITCH_KEYS = [
  ...IDENTITY_SCOPED_KEYS,
  "fzCred",
  "fzForm",
  "fzUserKeypair",
  "fzIdTag",
];

export function sweepForAccountSwitch(prevUser: string | null, newUser: string): boolean {
  if (!prevUser || prevUser === newUser) return false;
  for (const k of ACCOUNT_SWITCH_KEYS) localStorage.removeItem(k);
  clearSessionState();
  return true;
}

/** 登出即清扫（2026-09-30 评审 P1-9 根修）：logout 时当场清全部本机身份材料
 * ——此前只删会话旗标，下一户登录时 prevUser=null → sweepForAccountSwitch
 * 短路，上一户明文身份证号（fzForm）跨户滞留。账户模型下登出=离开工作台，
 * 本地材料无保留价值（服务器密封件可随时恢复），无条件清。 */
export function sweepLocalIdentity(): boolean {
  const had = ACCOUNT_SWITCH_KEYS.some((k) => localStorage.getItem(k) !== null);
  for (const k of ACCOUNT_SWITCH_KEYS) localStorage.removeItem(k);
  clearSessionState();
  return had;
}
