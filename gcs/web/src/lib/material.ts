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
// 档案积累批（2026-10-04）起导出：身份域键面是清扫契约（测试与视图按本表
// 断言「fzLogbook 换人即清」），单源可查，禁止手抄键名清单。
export const IDENTITY_SCOPED_KEYS = [
  "fzSub", "fzSubBound", "fzLastReceipt", "fzTokenPayload",
  "fzPlanDraft", "fzPlanStore", "fzLastPlanCommit",
  "fzDevicePub", "fzTrailAuthId", "fzTrailGenesis", "fzTrailHead", "fzTrailRows",
  "fzLastCaseId",
  "fzLogbook", // 飞手合规档案（本机积累——上一身份的档案不串号）
];

// ---- 飞手合规档案 fzLogbook（L1 链上留痕深化·档案积累批）----
// 链上留痕页的「我的合规档案」数据层：出证受理→取件回填→封链统计→TRAIL
// 判决四步把本机飞行合规事实累积成档案行。纯本机 localStorage——零身份：
// 不请求任何"我的记录"服务端接口；隐私架构=见证不出设备，换设备从新开始。
// 身份域键：换人即清扫（上一身份的档案不串号）。
export interface LogbookTrailVerdict {
  verdict: string;
  sm3: string;
}

export interface LogbookEntry {
  authId: number | null;          // 授权编号（出证时未知留空——取件后回填）
  caseId: string;                 // 出证案卷号（骨架行锚——受理成功时落）
  receiptCode: string;            // 回执码
  tStart: number | null;          // 允许飞行时段·起（Unix 秒——实交值）
  tEnd: number | null;            // 允许飞行时段·止（Unix 秒——clamp 后实交值）
  classId: number | null;         // 机型类（登记绑定档）
  altMax: number | null;          // 高度上限（米——绑定面政策值）
  sealedAt: number | null;        // 封链时刻（未封链=null）
  nSamples: number | null;        // 飞行样本数
  checkpointCount: number | null; // 检查点锚定次数（封链响应权威值）
  breachFlag: boolean;            // 超限记录（如实披露——超限不豁免）
  tripCaseIds: Record<number, string>;                 // TRAIL 窗 → 案卷号
  trailVerdicts: Record<number, LogbookTrailVerdict>; // TRAIL 窗 → 判决
  createdAt: number;              // 骨架行建立时刻（Unix 秒——排序锚）
}

const LOGBOOK_KEY = "fzLogbook";
const LOGBOOK_CAP = 50; // 防膨胀上限：超出裁最旧行（数组尾=最旧）

/** 读单源：JSON 解析容错（坏数据=空档案，不炸页面）+ 行级规范化（缺字段补
 * 默认——旧版/手改数据不致渲染层 undefined 蔓延）。 */
function readLogbook(): LogbookEntry[] {
  let raw: unknown;
  try { raw = JSON.parse(localStorage.getItem(LOGBOOK_KEY) || "[]"); } catch { return []; }
  if (!Array.isArray(raw)) return [];
  const rows: LogbookEntry[] = [];
  for (const r of raw) {
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    rows.push({
      authId: typeof o.authId === "number" ? o.authId : null,
      caseId: typeof o.caseId === "string" ? o.caseId : "",
      receiptCode: typeof o.receiptCode === "string" ? o.receiptCode : "",
      tStart: typeof o.tStart === "number" ? o.tStart : null,
      tEnd: typeof o.tEnd === "number" ? o.tEnd : null,
      classId: typeof o.classId === "number" ? o.classId : null,
      altMax: typeof o.altMax === "number" ? o.altMax : null,
      sealedAt: typeof o.sealedAt === "number" ? o.sealedAt : null,
      nSamples: typeof o.nSamples === "number" ? o.nSamples : null,
      checkpointCount: typeof o.checkpointCount === "number" ? o.checkpointCount : null,
      breachFlag: o.breachFlag === true,
      tripCaseIds: o.tripCaseIds && typeof o.tripCaseIds === "object" ? { ...o.tripCaseIds as Record<number, string> } : {},
      trailVerdicts: o.trailVerdicts && typeof o.trailVerdicts === "object" ? { ...o.trailVerdicts as Record<number, LogbookTrailVerdict> } : {},
      createdAt: typeof o.createdAt === "number" ? o.createdAt : 0,
    });
  }
  return rows;
}

function writeLogbook(rows: LogbookEntry[]): void {
  localStorage.setItem(LOGBOOK_KEY, JSON.stringify(rows.slice(0, LOGBOOK_CAP)));
}

/** 行合并：补丁值有定义即覆盖；tripCaseIds/trailVerdicts 按窗口键累积
 * （多窗口出证跨调用汇入同一行——先 newFlight 后 TrailView 回写仍挂上）。 */
function mergeEntry(base: LogbookEntry, patch: Partial<LogbookEntry>): LogbookEntry {
  const out: LogbookEntry = { ...base, tripCaseIds: { ...base.tripCaseIds }, trailVerdicts: { ...base.trailVerdicts } };
  for (const [k, v] of Object.entries(patch) as [keyof LogbookEntry, unknown][]) {
    if (v === undefined) continue;
    if (k === "tripCaseIds" || k === "trailVerdicts") {
      Object.assign(out[k] as Record<string, unknown>, v as Record<string, unknown>);
    } else {
      (out as unknown as Record<string, unknown>)[k] = v;
    }
  }
  return out;
}

const LOGBOOK_BLANK: LogbookEntry = {
  authId: null, caseId: "", receiptCode: "", tStart: null, tEnd: null,
  classId: null, altMax: null, sealedAt: null, nSamples: null,
  checkpointCount: null, breachFlag: false, tripCaseIds: {}, trailVerdicts: {},
  createdAt: 0,
};

/** 档案追加（按授权编号/案卷号/回执码去重合并）：同一授权的生命周期写入
 * ——申请骨架行→取件回填→封链统计→TRAIL 判决——汇成一行而非多行；
 * 新行插队首（最新在前），超上限裁最旧。 */
export function logbookAppend(entry: Partial<LogbookEntry>): LogbookEntry[] {
  const rows = readLogbook();
  const inc = { ...entry };
  if (typeof inc.createdAt !== "number") inc.createdAt = Math.floor(Date.now() / 1000);
  const at = rows.findIndex((r) =>
    (inc.caseId && r.caseId === inc.caseId) ||
    (inc.receiptCode && r.receiptCode === inc.receiptCode) ||
    (inc.authId != null && r.authId === inc.authId));
  if (at >= 0) rows[at] = mergeEntry(rows[at], inc); // 既有行原位合并（序不变）
  else rows.unshift(mergeEntry(LOGBOOK_BLANK, inc));
  writeLogbook(rows);
  return readLogbook();
}

/** 档案行更新（按授权编号——封链统计/TRAIL 判决回写口）。无匹配行=no-op
 * 返回 null（不虚增行：档案只由受理动作立行，统计晚到挂不上就不挂）。 */
export function logbookUpdate(authId: number, patch: Partial<LogbookEntry>): LogbookEntry | null {
  const rows = readLogbook();
  const at = rows.findIndex((r) => r.authId === authId);
  if (at < 0) return null;
  rows[at] = mergeEntry(rows[at], patch);
  writeLogbook(rows);
  return rows[at];
}

/** 授权编号回填（取件成功处）：把取件令牌的 authId 挂到申请时的骨架行
 * （按案卷号/回执码匹配）。只回填既有 pending 行，绝不新建——取件在非出证
 * 设备发生时（理论不可达——会话钥不出本机）不产生空档案行。 */
export function logbookBackfillAuthId(
  caseId: string | null,
  receiptCode: string,
  authId: number,
): LogbookEntry | null {
  if (!Number.isFinite(authId) || authId <= 0) return null;
  const rows = readLogbook();
  const at = rows.findIndex((r) =>
    !r.authId && ((!!caseId && r.caseId === caseId) || (!!receiptCode && r.receiptCode === receiptCode)));
  if (at < 0) return null;
  rows[at] = mergeEntry(rows[at], { authId });
  writeLogbook(rows);
  return rows[at];
}

/** 全量档案（链上留痕页「我的合规档案」消费——最新在前）。 */
export function logbookAll(): LogbookEntry[] {
  return readLogbook();
}

/** 按授权编号查档案行（授权记录行徽章/本机复验材料定位）。 */
export function logbookFindByAuthId(authId: number): LogbookEntry | null {
  return readLogbook().find((r) => r.authId === authId) ?? null;
}

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
