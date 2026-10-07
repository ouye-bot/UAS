<script setup lang="ts">
/** 屏②起飞申请（说明书 §7.3）：真实出证流程——
 * 绑定面（服务端）→ 桥接本地出证（见证不出设备）→ 自动提交受理 → 回执轮询。
 * 诚实进度，不伪造速度。R2-b 体验修复：
 * ①计划时刻 datetime-local（默认今天，Unix 秒仅内部承诺口径）；
 * ②出证轮询信封双形态解包（/prove/task={code,data}——旧版读顶层 status 恒
 *   undefined=永久卡②的根因）；
 * ③表单草稿 localStorage 持久化 + 出证流程 sessionStorage 恢复（切页/误触
 *   返回不丢）；④逐阶段已用时秒表。 */
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api, bridge, ApiError, randHex } from "../lib/api";
import { initialFlightPlan, planCommitment, newPlanSalt, storePlan, validatePlan, type FlightPlan } from "../lib/plan";
import { sm2 } from "sm-crypto";
import { getSubSk, identityTag, logbookAppend, subMatchesMaterial } from "../lib/material";
import { DEVICE_SERIAL_UNAVAILABLE, getDeviceSerial } from "../lib/device";
import { classLabel } from "../lib/policy";
import HashText from "../components/HashText.vue";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";

const planForm = reactive<FlightPlan>(initialFlightPlan());
const planErr = ref("");
const PLAN_ERR_TEXT: Record<string, string> = {
  region_required: "请填写作业区域",
  purpose_required: "请填写作业用途",
  time_order: "结束时间须晚于开始时间",
  time_past: "计划开始时间已过去——请把开始时刻改为现在或以后再提交",
  alt_range: "作业高度须为 1..500 米",
};
const planCommitted = ref(localStorage.getItem("fzLastPlanCommit") || "");
const busy = ref(false);
const deny = ref<{ code: string; message: string } | null>(null);
const stage = ref(""); // binding / assembling / proving / applying / receipt / ready
// 失败终态（丙-2 M5）：deny 且 stage 未到 ready 时刻度轨切「定格」——停止呼吸、
// 当前段灰红尾、连线不点亮（轨与错误盒说同一句话，不再自相矛盾）
const failed = ref(false);
const receiptCode = ref(localStorage.getItem("fzLastReceipt") || "");
const copied = ref(false);
// 机型类=登记时绑定进承诺 C（B4/A4）——申请页只读展示，不可改（2026-09-25
// 队长实测根修：旧版从草稿恢复+可自由填写，与登记机型不一致 ⟹ 承诺重算不一致
// ⟹ RA 验签必败且报错晦涩）
const registeredClassId = ((): number => {
  try {
    const form = JSON.parse(localStorage.getItem("fzForm") || "{}");
    if (Number.isInteger(form.class_id) && form.class_id >= 0) return form.class_id;
  } catch { /* 走缺省 */ }
  return 1;
})();
const classId = ref(registeredClassId);
// 授权包配额（2026-10-06 多架次拍板）：本申请覆盖架次数 1~5，缺省 1=与
// 令牌一次性历史语义逐字等价。多架次授权=一次出证多次起降（每架次仍独立
// 闸门序+独立消费回报）；配额随授权登记上链（FlightAuthRegistry.remaining）。
const sortieCount = ref(Number(localStorage.getItem("fzSorties") || 1) || 1);
watch(sortieCount, (v) => {
  localStorage.setItem("fzSorties", String(v >= 1 && v <= 5 ? v : 1));
});
const router = useRouter();
const policyAltMax = ref<number | null>(null); // 政策高度上限（绑定面实时返回）

function copyReceipt(): void {
  navigator.clipboard?.writeText(receiptCode.value).then(() => {
    copied.value = true;
    setTimeout(() => (copied.value = false), 1500);
  });
}

const cred = (() => {
  try { return JSON.parse(localStorage.getItem("fzCred") || "null"); } catch { return null; }
})();
const sub = (() => {
  try { return JSON.parse(localStorage.getItem("fzSub") || "null"); } catch { return null; }
})();
const form = (() => {
  try { return JSON.parse(localStorage.getItem("fzForm") || "{}"); } catch { return {}; }
})();
const hasMaterial = computed(() => !!(cred && sub));

// ---- SN 单源（SN 绑定根治 2026-10-07）----
// 出证 sn 唯一读数源=桥 /engine_pub（与桥第 6 查、注册表单同一台设备）。
// 老账户（自由 SN 时代登记）：登记 SN≠本机 SN ⟹ 出证/令牌必 sn_mismatch——
// 申请页就地给出人话指引并阻断，不再让用户撞上密码学报错。
const deviceSn = ref("");
const snMismatch = ref(false);
const registeredSn = String(form.sn ?? "").trim();

// ---- 计划时刻（datetime-local ⟷ Unix 秒内部口径） ----
const startLocal = ref("");
const endLocal = ref("");

function epochToLocal(ts: number): string {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
function localToEpoch(v: string): number {
  if (!v) return 0;
  const t = new Date(v).getTime();
  return Number.isFinite(t) ? Math.floor(t / 1000) : 0;
}
/** 默认窗口：今天（10 分钟后取整 5 分钟）起 2 小时——数小时飞行不跨天。 */
function defaultWindow(): [number, number] {
  const s = Math.ceil((Date.now() + 10 * 60000) / (5 * 60000)) * (5 * 60);
  return [s, s + 2 * 3600];
}
function syncLocals(): void {
  startLocal.value = planForm.start_ts ? epochToLocal(planForm.start_ts) : "";
  endLocal.value = planForm.end_ts ? epochToLocal(planForm.end_ts) : "";
}
watch(startLocal, (v) => { const e = localToEpoch(v); if (e) planForm.start_ts = e; });
watch(endLocal, (v) => { const e = localToEpoch(v); if (e) planForm.end_ts = e; });

// ---- 表单草稿（localStorage——切页/关浏览器不丢） ----
const DRAFT_KEY = "fzPlanDraft";
function loadDraft(): void {
  try {
    const d = JSON.parse(localStorage.getItem(DRAFT_KEY) || "null");
    if (d) {
      planForm.region = d.region ?? "";
      planForm.purpose = d.purpose ?? "";
      planForm.alt_m = d.alt_m ?? 0;
      planForm.start_ts = d.start_ts ?? 0;
      planForm.end_ts = d.end_ts ?? 0;
      // classId 不从草稿恢复——机型=登记绑定（只读），跨身份草稿不再串号
    }
  } catch { /* 草稿损坏即走默认 */ }
  if (!planForm.start_ts || !planForm.end_ts) {
    const [s, e] = defaultWindow();
    planForm.start_ts = s;
    planForm.end_ts = e;
  }
  syncLocals();
}
watch(
  () => [planForm.region, planForm.purpose, planForm.alt_m, planForm.start_ts, planForm.end_ts],
  () => {
    localStorage.setItem(DRAFT_KEY, JSON.stringify({
      region: planForm.region, purpose: planForm.purpose, alt_m: planForm.alt_m,
      start_ts: planForm.start_ts, end_ts: planForm.end_ts,
    }));
  },
);

// ---- 出示钥消费面（2026-10-01 一次性出示钥批）----
// 出证见证 sk′ 来自签发子凭证时生成的会话域钥对（material.getSubSk——
// sessionStorage 内存态，与该张子凭证同生命周期）。账户长期钥自本批起只服务
// 登录/操作签名，出证零接触——本页不再有身份钥解锁/升级门（原解锁面板
// 服务的是「账户钥作出证见证」的旧协议，随批退役；登录路径每次都会以服务器
// v3 密封件回写本地缓存，v1 明文遗留无存活面）。

// ---- 阶段秒表 ----
const stageAt = ref<Record<string, number>>({});
const nowTick = ref(Date.now());
let ticker: number | undefined;
const stageElapsed = computed(() => {
  const t0 = stageAt.value[stage.value];
  return t0 ? Math.max(0, Math.round((nowTick.value - t0) / 1000)) : 0;
});
function setStage(s: string): void {
  stage.value = s;
  if (stageAt.value[s] === undefined) stageAt.value = { ...stageAt.value, [s]: Date.now() };
}

// ---- 出证流程状态机（sessionStorage——切页恢复，关浏览器即焚） ----
type FlowState = {
  stage: "assembling" | "proving" | "applying" | "receipt";
  id_tag?: string; // 身份标签（换人即弃——旧身份流程快照不恢复，2026-09-25）
  task_id?: string;
  case_id?: string;
  binding?: { t_epoch: number; alt_max?: number; required_level?: number };
  nonce_hex?: string;
  plan_hash_hex?: string;
  session_pk?: string;
  receipt_code?: string;
  sorties?: number; // 架次配额（跨切页恢复提交——申请体与档案行同源）
  stage_at?: Record<string, number>; // 各阶段起始时刻（秒表跨切页连续）
};
const FLOW_KEY = "fzApplyFlow";
function saveFlow(f: FlowState): void {
  f.id_tag = identityTag();
  f.stage_at = stageAt.value;
  sessionStorage.setItem(FLOW_KEY, JSON.stringify(f));
}
function clearFlow(): void {
  sessionStorage.removeItem(FLOW_KEY);
}
function restoreFlow(): FlowState | null {
  try {
    const f = JSON.parse(sessionStorage.getItem(FLOW_KEY) || "null") as FlowState | null;
    if (f && f.id_tag !== identityTag()) {
      // 旧身份的流程快照——跨身份残留，弃用（与身份清扫同纪律）
      sessionStorage.removeItem(FLOW_KEY);
      return null;
    }
    return f;
  } catch { return null; }
}

/** 信封双形态单源：bridge 端点 {code,data} 与平铺两态（教训㊿+41）。 */
function envelope(t: any): any {
  return t && typeof t === "object" && "data" in t && t.data ? t.data : t;
}

/** 轮询容错（R3-2，评审 P1-1）：网络瞬断不放弃——连续 5 败才上抛，
 * 避免一次抖动=2 分钟白等+烧一张一次性子凭证。 */
async function pollWithRetry<T>(fn: () => Promise<T>, what: string): Promise<T> {
  let fails = 0;
  for (;;) {
    try {
      return await fn();
    } catch (e) {
      fails += 1;
      if (fails >= 5 || e instanceof ApiError && e.status !== 0 && e.status !== 502 && e.status < 500)
        throw e;
      await new Promise((r) => setTimeout(r, Math.min(2000 * fails, 8000)));
    }
  }
}

async function pollTask(taskId: string): Promise<void> {
  for (;;) {
    const t = envelope(await pollWithRetry(() => bridge(`/prove/task/${taskId}`), "出证进度"));
    const status = t?.status ?? "";
    if (status === "proving") setStage("proving");
    if (status === "done") return;
    // B3 人话化：桥透传后端信封业务码（error_code）——被吊销等专属判词按码
    // 分流；旧桥无此字段回落 prove_failed（通用提示，兼容不破）
    if (status === "failed")
      throw new ApiError(t?.error_code || "prove_failed", t?.error ?? "出证失败", 0);
    await new Promise((r) => setTimeout(r, 2000));
  }
}

async function pollReceipt(code: string): Promise<void> {
  for (;;) {
    const r = await pollWithRetry(
      () => api<Record<string, any>>(`/authz/receipt/${code}`),
      "验证进度",
    );
    if (r.status === "ready") return;
    // B3 人话化：failed 态回执携带 reject_reason/reject_code（worker 判词）——
    // rev_root_moved（验证窗内吊销生效）等不再显示为裸「验证拒绝」
    if (r.status === "failed")
      throw new ApiError(
        r.reject_code || "verify_rejected",
        r.reject_reason || "授权服务验证拒绝该证明",
        0,
      );
    await new Promise((r2) => setTimeout(r2, 2000));
  }
}

/** 受理+取件段（fresh 与 resume 共用——提交受理→回执轮询→ready）。 */
async function applyAndFetch(f: FlowState): Promise<void> {
  setStage("applying");
  f.stage = "applying";
  saveFlow(f);
  const rev = await api<Record<string, any>>("/ra/revocation/snapshot");
  // 授权窗实交值（t_start=出证绑定面时间锚；t_end=计划结束时刻 clamp 到
  // [时间锚+1h, 时间锚+4h]）——请求体与档案骨架行共用同一计算，不出现两套口径
  const tAnchor = f.binding?.t_epoch ?? 0;
  const winEnd = Math.min(Math.max(planForm.end_ts, tAnchor + 3600), tAnchor + 4 * 3600);
  const out = await api<Record<string, any>>("/authz/apply", {
    method: "POST",
    body: JSON.stringify({
      session_pk_hex: f.session_pk,
      sub_cred_message_hex: sub.message_hex,
      sub_sig_hex: sub.sig_hex,
      sub_cred_hash_hex: sub.sub_cred_hash_hex,
      nonce_hex: f.nonce_hex, plan_hash_hex: f.plan_hash_hex, class_id: classId.value,
      case_id: f.case_id,
      // 授权包配额制：架次数 1~5（缺省 1——恢复路径/旧快照无此字段同值）
      sorties: f.sorties ?? 1,
      rev_root_hex: rev.root_hex,
      // 绑定单源纪律：t_start 必须用桥接出证所用的 t_epoch（实例 21 同源）
      t_start: f.binding?.t_epoch,
      // R3-1 收尾（评审 P2-2）：授权窗取计划结束时刻（计划已被承诺——不再装饰）
      // clamp：下限 1h（受理排队余量）/上限 4h（预授权窗政策口径）
      t_end: winEnd,
    }),
  });
  f.receipt_code = out.receipt_code;
  receiptCode.value = out.receipt_code;
  localStorage.setItem("fzLastReceipt", out.receipt_code);
  // 档案骨架行（档案积累批）：受理成功即入档——authId 此时未知留空（回执码
  // 只承诺进度），取件成功后由「令牌与飞行」回填；恢复路径重交=按案卷号/
  // 回执码合并幂等，不产生重复行
  logbookAppend({
    caseId: f.case_id ?? "",
    receiptCode: String(out.receipt_code ?? ""),
    tStart: typeof f.binding?.t_epoch === "number" ? f.binding.t_epoch : null,
    tEnd: winEnd,
    classId: classId.value,
    altMax: policyAltMax.value,
  });
  f.stage = "receipt";
  saveFlow(f);
  setStage("receipt");
  await pollReceipt(out.receipt_code);
  clearFlow();
  setStage("ready");
}

/** 切页/误触返回后的流程恢复：从 sessionStorage 快照继续（诚实幂等——
 * applying 段若首次提交已成功，重交遇 409 即提示用回执码查询）。 */
async function resumeRun(f: FlowState): Promise<void> {
  try {
    if (f.stage === "assembling" || f.stage === "proving") {
      if (f.stage_at) stageAt.value = { ...f.stage_at };
      setStage(f.stage);
      await pollTask(f.task_id!);
      await applyAndFetch(f);
    } else if (f.stage === "applying") {
      await applyAndFetch(f);
    } else if (f.stage === "receipt") {
      setStage("receipt");
      receiptCode.value = f.receipt_code ?? receiptCode.value;
      await pollReceipt(f.receipt_code!);
      clearFlow();
      setStage("ready");
    }
  } catch (e: any) {
    clearFlow();
    fail(e?.code ?? "resume_failed", e?.message ?? String(e));
  } finally {
    // C-P1-1：恢复结束（无论成败）必须复位——旧代码成功分支不复位 ⟹
    // 按钮永远「处理中…」+ 恢复条长驻（队长实测卡死形态）
    busy.value = false;
    resuming.value = false;
  }
}

function commitPlan(): string | null {
  // P1 计划语义重设计：结构化计划+本地盐——对外只有承诺值（防穷举+防跨次关联），
  // 盐与计划全文只存本机（ARM 时地面站按承诺取回，做高度联动）。
  const err = validatePlan(planForm);
  if (err) {
    planErr.value = err;
    return null;
  }
  if (policyAltMax.value && planForm.alt_m > policyAltMax.value) {
    // C-P1-5：政策超限单独文案（此前误映射为 1..500 通用校验——拦对了解释错了）
    planErr.value = `超过政策上限 ${policyAltMax.value} m——请降低计划高度`;
    return null;
  }
  planErr.value = "";
  const salt = newPlanSalt();
  const commit = planCommitment(salt, planForm);
  storePlan(commit, salt, { ...planForm });
  localStorage.setItem("fzLastPlanCommit", commit);
  planCommitted.value = commit;
  return commit;
}

async function apply(): Promise<void> {
  busy.value = true; deny.value = null; stage.value = ""; stageAt.value = {};
  failed.value = false; // 新一次提交——刻度轨解除定格回到进行时形态
  try {
    if (!hasMaterial.value) throw new ApiError("no_material", "先在「我的记录」签发一次性子凭证", 0);
    // SN 单源门（2026-10-07）：桥读数不可达=不猜；登记 SN≠本机 SN=老账户阻断
    // （两态都给人话指引——首次 ARM 必 sn_mismatch 的路径就此封死）
    if (!deviceSn.value) throw new ApiError("device_serial_unavailable", DEVICE_SERIAL_UNAVAILABLE, 0);
    if (snMismatch.value)
      throw new ApiError(
        "sn_mismatch",
        `该账户登记的设备序列号与本机不符（登记 ${registeredSn} ≠ 本机 ${deviceSn.value}）——请重新登记账户`,
        0,
      );
    if (!subMatchesMaterial())
      throw new ApiError("stale_sub_cred", "一次性子凭证与当前登记/密钥不配套（可能重新登记过）——请到「我的记录」点「重新签发一次性子凭证」后再申请", 0);
    if (classId.value !== registeredClassId)
      throw new ApiError("class_mismatch", `机型类与登记时不符（登记为 ${registeredClassId} 类）——机型在登记时已绑定资质，申请须与登记一致`, 0);
    const plan_hash_hex = commitPlan();
    if (!plan_hash_hex) { busy.value = false; return; }  // 计划校验失败——planErr 已显示
    const nonce_hex = randHex(16);
    // ① 绑定面（服务端公示：挑战/政策/时间锚）
    setStage("binding");
    const binfo = await api<Record<string, any>>(
      `/authz/binding?class_id=${classId.value}&plan_hash_hex=${plan_hash_hex}&nonce_hex=${nonce_hex}`,
    );
    if (typeof binfo?.alt_max === "number") policyAltMax.value = binfo.alt_max;
    // ② 会话钥（一次性——取件解密目标，关浏览器即焚）
    const kp = sm2.generateKeyPairHex();
    sessionStorage.setItem("fzSessionSk", kp.privateKey);
    // ③ 桥接本地实时出证（见证不出设备）——出示钥=签发子凭证时生成的
    // 会话域 (sk′,pk′)（一次性出示钥批：跨申请不可链接）
    setStage("assembling");
    const subSk = getSubSk();
    if (!subSk || !sub?.holder_pk_hex)
      throw new ApiError(
        "sub_key_missing",
        "一次性子凭证的出示钥不在本会话（可能换了标签页或已重签）——请到「我的记录」重新签发后再申请",
        0,
      );
    const st = await bridge<{ task_id: string; case_id: string; binding: { t_epoch: number } }>("/prove/start", {
      method: "POST",
      body: JSON.stringify({
        plan_hash_hex, nonce_hex, class_id: classId.value,
        id_number: form.id_number, cert_level: form.cert_level,
        // SN 单源取用（2026-10-07）：sn=桥本机读数（上方单源门保证与登记 SN
        // 同值——ZK 私入/子凭证绑定/令牌 sn_hash/桥第 6 查四处一台设备）
        sn: deviceSn.value,
        salt_hex: cred.salt_hex,
        id_prime_hex: sub.id_prime_hex, sig_hex: sub.sig_hex,
        expires_at: sub.expires_at,
        holder_sk_hex: subSk, holder_pk_hex: sub.holder_pk_hex,
      }),
    });
    // 本机复验材料锚（W-8：流程快照在受理 ready 后清除，case_id 需跨页持久
    // ——身份域键，换人即被清扫；链上留痕页凭它判断"本机保有证明材料"）
    localStorage.setItem("fzLastCaseId", st.case_id);
    const f: FlowState = {
      stage: "assembling", task_id: st.task_id, case_id: st.case_id,
      binding: st.binding, nonce_hex, plan_hash_hex,
      session_pk: kp.publicKey.replace(/^04/, ""),
      sorties: sortieCount.value >= 1 && sortieCount.value <= 5 ? sortieCount.value : 1,
    };
    saveFlow(f);
    await pollTask(st.task_id);
    await applyAndFetch(f);
  } catch (e: any) {
    clearFlow();
    fail(e?.code ?? "apply_failed", e?.message ?? String(e));
    return;
  } finally { busy.value = false; }
}

function fail(code: string, message: string): void {
  deny.value = { code, message };
  // 出证失败且未到 ready——刻度轨定格（轨不再声称「进行中」）
  if (stage.value !== "ready") failed.value = true;
  busy.value = false;
}

const resuming = ref(false);
onMounted(async () => {
  loadDraft();
  nowTick.value = Date.now();
  ticker = window.setInterval(() => (nowTick.value = Date.now()), 1000);
  // SN 单源：读桥本机序列号+老账户失配判定（读数失败=空串，提交面 fail-closed）
  deviceSn.value = await getDeviceSerial();
  snMismatch.value = !!deviceSn.value && !!registeredSn && registeredSn !== deviceSn.value;
  // C-P1-5：政策上限提交前即知（公开公示面，登记机型——无需绑定参数）
  try {
    const d = await api<Record<string, any>>(`/authz/policy/class/${registeredClassId}`);
    const payload = (d as any)?.data ?? d;
    if (typeof payload?.alt_max_m === "number") policyAltMax.value = payload.alt_max_m;
  } catch { /* 未开放类/离线——提交面 fail-closed 兜底 */ }
  const f = restoreFlow();
  if (f) {
    // 半程恢复（提示条 + 续跑）——切页/误触返回不丢出证
    resuming.value = true;
    busy.value = true;
    resumeRun(f);
  }
});
onBeforeUnmount(() => { if (ticker !== undefined) window.clearInterval(ticker); });

function goPickup(): void {
  router.push("/flight");
}

// 阶段文案（视觉 S 批 S4 进度信号收敛：圈号①~⑥退役——六段刻度轨的数字是
// 唯一编号源，StatusTag 只说阶段事实不再复读序号；文案其余逐字保留。
// e2e 冻结面核对：e2e_browser_ui 对本屏只断言「政策/上限」公示文案，无圈号断言）
const stageLabel: Record<string, string> = {
  binding: "获取申请绑定面（服务端公示挑战/政策）…",
  assembling: "见证组装（约 5~10 秒——读取撤销见证、组装本机材料）…",
  proving: "生成零知识证明（本机约 2 分钟，计算不出设备）…",
  applying: "提交授权服务实例核对…",
  receipt: "授权服务验证中（数秒至半分钟，含排队）…",
  ready: "✓ 申请通过——令牌已加密返回",
};

// 刻度轨段序（视觉深化批 D）
const STAGE_ORDER = ["binding", "assembling", "proving", "applying", "receipt", "ready"];
function stageIndex(s: string): number {
  return STAGE_ORDER.indexOf(s);
}

// 密码学报错 → 人话指引（deny 面向飞手）。🔴 真实原因必须保留可见（2026-09-25
// 队长实测教训：hint 覆盖真实报错 ⟹ 排障盲飞）——hint 作第二行提示追加。
// B3 吊销类专属判词：被吊销飞手不再被误导去「重签重试」（必再失败）——
// 判词指向「我的记录」自查与救济面。
const DENY_HINT: Record<string, string> = {
  prove_failed:
    "常见原因：登记材料与子凭证不配套（重新登记后未重签）或机型类与登记不一致——请到「我的记录」重签一次性子凭证后重试。",
  revoked:
    "你已被列入撤销名单——原因与救济见「我的记录」自查。重试或重签子凭证都不会成功（出证将被数学拒绝）。",
  holder_revoked:
    "你的凭证已被列入撤销名单——原因与救济见「我的记录」自查。重签一次性子凭证也无法解除吊销。",
  cred_revoked:
    "你的主凭证已吊销——请在「我的记录」确认吊销原因，按救济流程重新登记后再申请。",
  stale_rev_root:
    "你的子凭证已被一次性消费且凭证已吊销，请重新登记。刷新或反复重试不会成功。",
  rev_root_moved:
    "授权服务在验证窗内检出你已被列入撤销名单（吊销已生效）——该次申请已终局拒绝。原因与救济见「我的记录」自查。",
  sub_cred_used:
    "该一次性子凭证已被使用——请到「我的记录」重新签发一张后再申请。",
  nonce_conflict:
    "申请随机数已被消耗（多为重复提交）——请发起新申请重新出证。",
  // SN 单源（2026-10-07）：两态专属判词（真实原因保留在首行——hint 只补指引）
  sn_mismatch:
    "本机地面站与该账户登记的设备不是同一台——请在本机重新登记账户（或回到登记时所用的地面站操作）。",
  device_serial_unavailable:
    "注册与申请都依赖本机地面站桥读数——请确认地面站桥接已启动后重试。",
};
function denyMessage(code: string, message: string): string {
  const hint = DENY_HINT[code];
  if (hint && message && message !== code) return `${message}\n提示：${hint}`;
  return hint ?? message;
}
</script>

<template>
  <div class="fz-enter">
    <div v-if="resuming && busy" class="note" style="border: var(--hairline); border-left: 3px solid var(--accent); border-radius: 8px; padding: 8px 12px; margin-bottom: 10px">
      检测到未完成的申请——正在恢复出证进度…
    </div>
    <div class="panel">
      <h2>起飞申请</h2>
      <p class="desc">提交后系统在本机生成零知识证明并自动核验飞行资质与合规性，全程不透露您的身份。</p>
      <div v-if="!hasMaterial" class="deny"><span class="code">缺材料</span>请先在「我的记录」签发一次性子凭证。</div>
      <!-- SN 单源（2026-10-07）：老账户失配就地指引（登记 SN≠本机 SN——
           不阻断页面浏览，但提交面 fail-closed；人话指向重登记） -->
      <div v-if="snMismatch" class="deny">
        <span class="code">设备不符</span>
        该账户登记的设备序列号与本机不符（登记 {{ registeredSn }} ≠ 本机 {{ deviceSn }}）——请重新登记账户。
      </div>
      <div class="grid2">
        <div>
          <label>作业区域</label><input v-model="planForm.region" placeholder="例：科技园北侧作业区" />
          <label>用途</label><input v-model="planForm.purpose" placeholder="例：农田巡查" />
          <div class="row2">
            <div>
              <label>开始时刻（现在以后）</label><input v-model="startLocal" type="datetime-local" :min="epochToLocal(Math.floor(Date.now() / 60000) * 60)" />
            </div>
            <div>
              <label>结束时刻（晚于开始）</label><input v-model="endLocal" type="datetime-local" :min="startLocal || epochToLocal(Math.floor(Date.now() / 60000) * 60)" />
            </div>
          </div>
          <label>计划作业高度（米{{ policyAltMax ? `，政策上限 ${policyAltMax} m` : "" }}）</label>
          <input v-model.number="planForm.alt_m" type="number" min="1" :max="policyAltMax ?? 500" />
          <p v-if="policyAltMax && planForm.alt_m > policyAltMax" class="step-err">超过政策上限 {{ policyAltMax }} m——闸门将拒绝</p>
          <label>机型类（登记时绑定，不可更改——{{ classLabel(classId) }}）</label><input v-model.number="classId" type="number" min="0" max="255" readonly class="mono" title="机型在登记时已绑定进资质承诺——申请须与登记一致" />
          <label>设备序列号（地面站桥读数——出证与飞行解锁同一台设备，不可更改）</label>
          <input :value="deviceSn" class="mono" readonly title="序列号单源=本机地面站桥——用户不可修改" />
          <p v-if="!deviceSn" class="step-err">{{ DEVICE_SERIAL_UNAVAILABLE }}</p>
          <label>架次数（授权包配额——一次出证可飞行次数）</label>
          <select v-model.number="sortieCount" :disabled="busy" title="多架次授权：一次出证覆盖多次起降；每次起降仍需独立解锁与消费回报，配额用尽须重新出证">
            <option v-for="n in 5" :key="n" :value="n">{{ n }} 架次{{ n === 1 ? "（单次，缺省）" : "" }}</option>
          </select>
          <p v-if="planErr" class="step-err">{{ PLAN_ERR_TEXT[planErr] ?? planErr }}</p>
          <p v-if="planCommitted" class="note mono">对外承诺值：{{ planCommitted.slice(0, 16) }}…（计划全文与盐不出本机）</p>
          <div style="margin-top:14px">
            <button class="btn" :disabled="busy || !hasMaterial"
              :title="!hasMaterial ? '先在「我的记录」签发一次性子凭证' : ''"
              @click="apply">{{ busy ? "处理中…" : "提交申请（本机出证）" }}</button>
          </div>
          <DenyBox v-if="deny" :code="deny.code" :message="denyMessage(deny.code, deny.message)" />
        </div>
        <div>
          <div class="kv">
            <dt>子凭证签名</dt><dd><HashText v-if="sub" :value="sub.sig_hex" head="10" tail="6" /><span v-else>—</span></dd>
            <dt></dt><dd>
              <div v-if="receiptCode" class="receipt-box">
                <span class="receipt-code">{{ receiptCode }}</span>
                <button class="copy-btn" @click="copyReceipt">{{ copied ? "✓ 已复制" : "复制" }}</button>
              </div>
              <p v-if="receiptCode" class="note">凭此码可在任意设备查询进度；领取令牌请在发起申请的这台设备上完成（会话钥不出本机）——请妥善保存。</p>
            </dd>
          </div>
          <div v-if="stage" class="fz-enter" style="margin-top:16px; border-top: var(--hairline); padding-top: 14px">
            <div style="display:flex; align-items:center; gap:10px">
              <span v-if="busy && stage !== 'ready'" class="spin" />
              <StatusTag :tone="stage === 'ready' ? 'ok' : 'accent'" :label="stageLabel[stage] ?? stage" />
              <span v-if="busy && stage !== 'ready'" class="note mono">已用时 {{ stageElapsed }}s</span>
            </div>
            <!-- 六段刻度轨（视觉深化批 D：申请生命周期仪表化——完成实心/当前
                 呼吸/未来暗，连接线随进度点亮。装饰层：文本语义仍由上方
                 StatusTag 单源承载。） -->
            <div class="fz-track" aria-hidden="true">
              <template v-for="(s, i) in ['binding', 'assembling', 'proving', 'applying', 'receipt', 'ready']" :key="s">
                <span
                  class="fz-track-seg"
                  :class="{
                    done: stageIndex(s) < stageIndex(stage),
                    now: s === stage && stage !== 'ready' && !failed,
                    halt: failed && s === stage && stage !== 'ready',
                    ok: s === 'ready' && stage === 'ready',
                  }"
                >{{ s === 'ready' ? '✓' : i + 1 }}</span>
                <span
                  v-if="i < 5"
                  class="fz-track-line"
                  :class="{ lit: !failed && stageIndex(s) < stageIndex(stage) }"
                />
              </template>
            </div>
            <!-- 条纹 bar 退役（视觉 S 批 S4：与刻度轨双进度信号冗余且常动——
                 进度语义由六段刻度轨单源承载，秒表承担「还活着」信号） -->
            <div v-if="stage === 'ready'" class="fz-enter" style="margin-top:8px; display:flex; gap:10px; align-items:center">
              <button class="btn" @click="goPickup">前往领取令牌 →</button>
              <span class="note">令牌已加密返回，领取后即可解锁飞行。</span>
            </div>
          </div>
          <div v-if="!stage && !busy" class="note">申请提交后此处显示真实进度。</div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* 六段刻度轨（视觉深化批 D：完成=accent 实心/当前=呼吸放大/未来=发丝圈） */
.fz-track { display: flex; align-items: center; gap: 0; margin-top: 12px; }
.fz-track-seg {
  width: 22px; height: 22px; flex: 0 0 22px;
  display: inline-flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 700; font-family: var(--font-mono);
  border-radius: 50%; border: 1px solid var(--line-strong);
  color: var(--ink-3); background: var(--panel-2);
  transition: all var(--t-med);
}
.fz-track-seg.done {
  background: var(--accent); border-color: var(--accent); color: #fff;
}
.fz-track-seg.now {
  border-color: var(--accent); color: var(--accent-ink);
  background: var(--accent-soft);
  animation: fz-pulse 2.4s infinite;
}
.fz-track-seg.ok {
  background: var(--ok); border-color: var(--ok); color: #fff;
}
/* 失败终态定格（丙-2 M5）：当前段灰红尾——呼吸停止、连线退回暗轨；
   灰红=既有 --bad 色相 × 透明度分层（--bad-soft 底+红描边+尾点），零新色相 */
.fz-track-seg.halt {
  border-color: var(--bad); color: var(--bad);
  background: var(--bad-soft);
  animation: none;
  position: relative;
}
.fz-track-seg.halt::after {
  content: "";
  position: absolute;
  right: -2px; bottom: -2px;
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--bad);
  border: 1.5px solid var(--panel);
}
.fz-track-line {
  flex: 1; height: 2px; min-width: 14px;
  background: var(--line); border-radius: 1px;
  transition: background var(--t-med);
}
.fz-track-line.lit { background: var(--accent); }

.receipt-box { display: flex; align-items: center; gap: 8px; }
.receipt-code {
  font-family: ui-monospace, monospace; font-size: 15px; font-weight: 700;
  letter-spacing: 1px; background: var(--accent-soft); border: 1px solid #c9dbfb;
  border-radius: 8px; padding: 6px 10px; word-break: break-all;
}
.copy-btn { font-size: 12px; padding: 4px 10px; border-radius: 8px;
  border: var(--hairline); background: var(--panel); cursor: pointer; }
.copy-btn:hover { box-shadow: var(--shadow-2); }
</style>
