<script setup lang="ts">
/** 审计台（2026-09-29 账户批 B3；批二按队长反馈重设计；2026-10-04 升格批）：
 * - 视觉：KPI 指标带+卡片化收件箱+状态色徽章体系+缓粒子背景（大气、克制）；
 * - 立案自动化：点选违规线索即自动生成案号+带入目标授权+预填依据模板——
 *   一键提交，不再让审计员手填无从下手；
 * - 协同请求生命周期（队长拍板四拍）：待批准→已批准·待执行→已执行·待结案
 *   →已结案（+已驳回/执行失败旁路）；常驻轮询——audit 端留守即可看状态流转，
 *   无需退出重登；executed 后就地查看实名并结案；
 * - 升格批（0018）：结案=结论三判词+说明+签名（FZ-COLLAB-CLOSE|v1）→案卷
 *   指纹回执；核实浮层带设备一致性判词+链上证据时间线；历史签名复验按钮；
 *   历史案卷卡一键追溯；恢复双控复核卡（auditor 第二签）。
 * 敏感操作（立案/发函/结案/复核）以审计员钥签名；刷新后需密码解锁钥。 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { api, ApiError } from "../lib/api";
import { cachedUsername, signMsg, unlockSk } from "../lib/auth";
import { getCachedSk } from "../lib/keystore";
import {
  closeMsg,
  conclusionLabel,
  conclusionTone,
  deviceVerdictMeta,
  restoreCountersignMsg,
  validateCloseForm,
  verdictLabel,
  CHAIN_EVENT_LABEL,
  CONCLUSION_META,
  type CloseConclusion,
  type RestoreRequestRow,
  type TraceOut,
  type VerifySigsOut,
} from "../lib/gov";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";
import ParticleField from "../components/ParticleField.vue";
import FzConfluence from "../components/FzConfluence.vue";
import FzEmpty from "../components/FzEmpty.vue";
import FzWatermark from "../components/FzWatermark.vue";

const username = cachedUsername();
const busy = ref(false);
const deny = ref<{ code: string; message: string } | null>(null);

// ---- 状态徽章体系（四拍主线+两旁路）----
type S = "pending" | "approved" | "executed" | "closed" | "rejected" | "execute_failed";
const S_META: Record<S | "executing", { label: string; tone: string; hint: string }> = {
  pending: { label: "待批准", tone: "amber", hint: "等待机构管理员审阅批准" },
  approved: { label: "已批准 · 待执行", tone: "blue", hint: "系统自动出函与解锁进行中" },
  executing: { label: "执行中", tone: "blue", hint: "出函与解锁执行进行中（租约认领后）" },
  executed: { label: "已执行 · 待结案", tone: "teal", hint: "实名已解锁——请核实并结案" },
  closed: { label: "已结案", tone: "gold", hint: "案件闭环" },
  rejected: { label: "已驳回", tone: "red", hint: "机构驳回——理由可见" },
  execute_failed: { label: "执行失败", tone: "red", hint: "自动执行受阻——机构台可重试" },
};

// ---- 步进器 ----
const step = ref<0 | 1 | 2 | 3>(0);
const STEPS = ["违规收件箱", "立案", "协同解锁请求", "已解锁 · 结案"];

// ---- 数据面 ----
interface Violation { auth_id: number; events: number; last_at: string | null; case_count: number; fileable: boolean }
// unlocked=后端契约的嵌套对象 {ts, master_cred_hash_hex, username, id_number}
// （audit/service._warrant_view 单源——trace 面同构；解锁判定以 ts 在场为准，
// 对象恒真值不能直作布尔——此前恒显「已解锁」的根因）
interface WarrantView {
  warrant_hash_hex: string; case_no: string; target_auth_id: number | null;
  unlocked: { ts: string | null; master_cred_hash_hex: string | null; username: string | null; id_number: string | null };
}
interface ReqView {
  id: number; warrant_hash_hex: string; case_no: string; target_auth_id: number | null;
  legal_basis_text: string | null; note: string; status: S;
  auditor_username: string; auditor_fp: string; admin_username: string | null; admin_fp: string | null;
  reject_reason: string | null; execute_error: string | null;
  fzc2_fingerprint_hex?: string | null; req_fp?: string; req_hash_hex?: string;
  conclusion?: string | null; conclusion_text?: string | null; closed_ts?: string | null;
  case_archive_fp_hex?: string | null;
  created_ts: string | null; decided_ts: string | null; executed_ts: string | null;
}

const violations = ref<Violation[]>([]);
const warrants = ref<WarrantView[]>([]);
const requests = ref<ReqView[]>([]);
// 首拍旗标（视觉 S 批 S2：加载与空态分离——首拍前显示 shimmer 骨架，
// 不显示「收件箱空」这类与事实不符的空态）
const loaded = ref(false);

async function refreshAll(): Promise<void> {
  try {
    violations.value = (await api<{ items: Violation[] }>("/audit/violations?unfiled=1")).items;
  } catch { violations.value = []; }
  try {
    warrants.value = await api<WarrantView[]>("/audit/warrants");
  } catch { warrants.value = []; }
  try {
    requests.value = (await api<{ items: ReqView[] }>("/audit/collab-requests")).items;
  } catch { requests.value = []; }
  await refreshRestores();
  loaded.value = true;
}

// 常驻轮询（5s，任意页步生效）：非终态请求存在即拉取——audit 端在任何页面
// （含第③步发起页）都能"看见"admin 批准后的状态流转
let pollTimer: ReturnType<typeof setInterval> | null = null;
const filedReqId = ref<number | null>(null);
const filedReq = computed<ReqView | null>(
  () => requests.value.find((r) => r.id === filedReqId.value) ?? null,
);

// ---- 状态流转视觉时刻（丙-2 M3 双控双签汇流——单发动画，终了即摘除）----
// pending→approved：原地状态卡一次金色合流脉冲（第二钥落座的可见瞬间）；
// →executed：状态卡与列表行左条各一次 400ms 流光（单发）。
const converged = ref(false);
const sheened = ref(false);
watch(
  () => filedReq.value?.status,
  (s, prev) => {
    if (s === "approved" && prev === "pending") converged.value = true;
    if (s === "executed") sheened.value = true;
  },
);
function onAnimEnd(e: AnimationEvent): void {
  // 按 keyframe 名判定（子元素 fz-enter 等动画结束事件也会冒泡）
  if (e.animationName === "fz-converge") converged.value = false;
  else if (e.animationName === "fz-sheen-run") sheened.value = false;
}
onMounted(() => {
  void refreshAll();
  pollTimer = setInterval(async () => {
    // 无条件轮询（2026-09-30 评审 P1-7 根修：旧条件闸=「有 approved 才拉」
    // 导致新 pending 请求要 F5 才出现）。5s 一次、载荷小——省请求让位于
    // 双控合流可靠。
    try {
      requests.value = (await api<{ items: ReqView[] }>("/audit/collab-requests")).items;
    } catch { /* 下拍再试 */ }
    try { await refreshRestores(); } catch { /* 下拍再试 */ }
  }, 5000);
});
onBeforeUnmount(() => { if (pollTimer) clearInterval(pollTimer); });

// ---- KPI 指标带（count-up：视觉深化批 C——数值变化缓动，纯展示层） ----
import { useCountUp } from "../composables/useCountUp";
const kpiRaw = computed(() => ({
  leads: violations.value.filter((v) => v.fileable).length,
  pending: requests.value.filter((r) => r.status === "pending").length,
  executed: requests.value.filter((r) => r.status === "executed").length,
  closed: requests.value.filter((r) => r.status === "closed").length,
}));
const kpiLeads = useCountUp(computed(() => kpiRaw.value.leads));
const kpiPending = useCountUp(computed(() => kpiRaw.value.pending));
const kpiExecuted = useCountUp(computed(() => kpiRaw.value.executed));
const kpiClosed = useCountUp(computed(() => kpiRaw.value.closed));

// ---- ① 收件箱 → 自动立案 ----
const form = ref({ case_no: "", legal_basis_text: "", target_auth_id: null as number | null });

/** 自动立案（队长反馈根修）：点选线索即自动生成案号（日期+序号）+带入目标
 * 授权+预填依据模板——审计员只需核对/微调依据后一键提交。 */
function pick(v: Violation): void {
  const d = new Date();
  const ymd = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}${String(d.getDate()).padStart(2, "0")}`;
  const seq = warrants.value.length + 1;
  form.value.case_no = `CASE-${ymd}-${String(seq).padStart(3, "0")}`;
  form.value.target_auth_id = v.auth_id;
  form.value.legal_basis_text =
    `授权 #${v.auth_id} 围栏超限违规事件（链上取证 ${v.events} 次，最近 ${v.last_at ?? "—"}）。` +
    `依据《无人驾驶航空器飞行管理暂行条例》相关条款立案，申请协同解锁当事人实名以完成调查。`;
  step.value = 1;
}

async function fileCase(): Promise<void> {
  deny.value = null;
  if (!form.value.legal_basis_text.trim()) { deny.value = { code: "missing_legal_basis", message: "请填写立案依据原文（将哈希+原文双锚落库上链）" }; return; }
  busy.value = true;
  try {
    const r = await api<{ warrant_hash_hex: string }>("/audit/warrants", {
      method: "POST",
      body: JSON.stringify({
        case_no: form.value.case_no.trim(),
        legal_basis_text: form.value.legal_basis_text.trim(),
        target_auth_id: form.value.target_auth_id,
        note: `来源：违规收件箱 authId=${form.value.target_auth_id ?? "—"}`,
      }),
    });
    createdWh.value = r.warrant_hash_hex;
    collabNote.value = `立案依据如上（${form.value.case_no.trim()}）。请求协同解锁授权 #${form.value.target_auth_id} 当事人实名以完成调查。`;
    step.value = 2;
    await refreshAll();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "case_failed", message: err.message ?? String(e) };
  } finally { busy.value = false; }
}
const createdWh = ref("");

// ---- ③ 协同请求（审计员钥签名；发函后停留本页看流转）----
const sk = ref<string | null>(getCachedSk());
const unlockPass = ref("");
const unlockErr = ref("");
const unlockedOnce = ref(!!getCachedSk());
async function doUnlock(): Promise<void> {
  unlockErr.value = "";
  try {
    sk.value = await unlockSk(unlockPass.value);
    unlockedOnce.value = true;
    unlockPass.value = "";
  } catch (e) {
    unlockErr.value = (e as ApiError).message ?? String(e);
  }
}

const collabNote = ref("");

async function fileRequest(): Promise<void> {
  deny.value = null;
  if (!collabNote.value.trim()) { deny.value = { code: "note_required", message: "请填写调查理由——批准人将据此判断" }; return; }
  if (!sk.value) { deny.value = { code: "locked", message: "请先解锁审计员密钥" }; return; }
  const wh = createdWh.value;
  if (!wh) { deny.value = { code: "no_warrant", message: "无可发起的令状——请先立案" }; return; }
  busy.value = true;
  try {
    const sig = signMsg(sk.value, `FZ-COLLAB-REQ|v1|${wh}|${collabNote.value.trim()}`);
    const filed = await api<ReqView>("/audit/collab-requests", {
      method: "POST",
      body: JSON.stringify({ warrant_hash_hex: wh, note: collabNote.value.trim(), sig_hex: sig }),
    });
    filedReqId.value = filed.id; // 第③步原地显示状态流转（常驻轮询驱动）
    await refreshAll();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "request_failed", message: err.message ?? String(e) };
  } finally { busy.value = false; }
}

// ---- ④ 结案（executed→closed，0018 升格）+ 核实浮层（追溯+证据+结案表单）----
// 浮层双入口：请求行「查看实名并结案」（可结案——带 req 上下文）/ 历史案卷卡
// 点击（纯追溯——reqId=null 只读）。浮层内容三段：实名面 / 证据面（设备一致性
// 判词+链上时间线）/ 结案面（表单或已结案回执）。
const trace = ref<TraceOut | null>(null);
const traceError = ref("");
const traceCtx = ref<{ reqId: number | null; reqHashHex: string | null; caseNo: string } | null>(null);
async function openTraceCtx(reqId: number | null, reqHashHex: string | null, wh: string, caseNo: string): Promise<void> {
  traceCtx.value = { reqId, reqHashHex, caseNo };
  trace.value = null;
  traceError.value = "";
  closeForm.value = { conclusion: "", text: "" };
  closeResult.value = null;
  try {
    trace.value = await api<TraceOut>(`/audit/warrants/${wh}/trace`);
  } catch (e) {
    trace.value = null;
    traceError.value = (e as ApiError).message ?? "追溯数据不可得";
  }
}
function openTrace(r: ReqView): Promise<void> {
  return openTraceCtx(r.id, r.req_hash_hex ?? null, r.warrant_hash_hex, r.case_no);
}
function openWarrantTrace(w: WarrantView): Promise<void> {
  // 历史案卷卡入口（A4）：纯追溯——若该令状名下有已结案请求，浮层展示结案回执
  const linked = requests.value.find((r) => r.warrant_hash_hex === w.warrant_hash_hex);
  return openTraceCtx(linked?.id ?? null, linked?.req_hash_hex ?? null, w.warrant_hash_hex, w.case_no);
}
function dismissTrace(): void {
  traceCtx.value = null;
  trace.value = null;
  traceError.value = "";
}
// Esc 关闭（视觉 S 批 S5 可及性三修）：浮层打开时挂窗级监听，关闭即摘
function onModalEsc(e: KeyboardEvent): void {
  if (e.key === "Escape" && traceCtx.value != null) dismissTrace();
}
watch(traceCtx, (v) => {
  if (v != null) window.addEventListener("keydown", onModalEsc);
  else window.removeEventListener("keydown", onModalEsc);
});
onBeforeUnmount(() => window.removeEventListener("keydown", onModalEsc));

// 结案表单（A1）：结论三判词（不预选——属实/误报是终局判词，须显式落座）+
// 说明（verified 必填）+ 解锁钥签名（FZ-COLLAB-CLOSE|v1）→ 成功展示案卷指纹回执
const closeForm = ref<{ conclusion: CloseConclusion | ""; text: string }>({ conclusion: "", text: "" });
const closeResult = ref<{ case_archive_fp_hex: string; closed_ts: string | null } | null>(null);
async function closeCase(): Promise<void> {
  const ctx = traceCtx.value;
  if (ctx == null) return;
  deny.value = null;
  const err = validateCloseForm(closeForm.value.conclusion, closeForm.value.text);
  if (err) { deny.value = { code: "close_invalid", message: err }; return; }
  if (!ctx.reqId || !ctx.reqHashHex) { deny.value = { code: "no_req_ctx", message: "缺少请求上下文——请从「待结案」请求行进入" }; return; }
  if (!sk.value) { deny.value = { code: "locked", message: "请先解锁审计员密钥（结案须签名留痕）" }; return; }
  busy.value = true;
  try {
    const conclusion = closeForm.value.conclusion as CloseConclusion;
    const text = closeForm.value.text.trim();
    const sig = signMsg(sk.value, closeMsg(ctx.reqHashHex, conclusion, text));
    const out = await api<{ case_archive_fp_hex: string; closed_ts: string | null }>(
      `/audit/collab-requests/${ctx.reqId}/close`,
      { method: "POST", body: JSON.stringify({ conclusion, conclusion_text: text, sig_hex: sig }) },
    );
    closeResult.value = { case_archive_fp_hex: out.case_archive_fp_hex, closed_ts: out.closed_ts };
    await refreshAll();
  } catch (e) {
    const err2 = e as ApiError;
    deny.value = { code: err2.code ?? "close_failed", message: err2.message ?? String(e) };
  } finally { busy.value = false; }
}

// 案卷指纹复制（等宽全文+复制回执）
const copied = ref(false);
let copiedTimer: ReturnType<typeof setTimeout> | null = null;
async function copyArchiveFp(): Promise<void> {
  const fp = closeResult.value?.case_archive_fp_hex ?? trace.value?.closure?.case_archive_fp_hex ?? "";
  if (!fp) return;
  let ok = false;
  try { await navigator.clipboard.writeText(fp); ok = true; }
  catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = fp;
      document.body.appendChild(ta);
      ta.select();
      ok = document.execCommand("copy");
      ta.remove();
    } catch { ok = false; }
  }
  if (ok) {
    copied.value = true;
    if (copiedTimer) clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => { copied.value = false; }, 1500);
  }
}

// ---- 历史签名复验（A3）：双端点判词就地展示 ----
const sigs = ref<Record<number, VerifySigsOut>>({});
const sigsBusyId = ref<number | null>(null);
async function checkSigs(r: ReqView): Promise<void> {
  deny.value = null;
  sigsBusyId.value = r.id;
  try {
    sigs.value[r.id] = await api<VerifySigsOut>(`/audit/collab-requests/${r.id}/verify-sigs`);
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "verify_sigs_failed", message: err.message ?? String(e) };
  } finally { sigsBusyId.value = null; }
}

// ---- 恢复双控复核卡（B6·auditor 第二签）：列表端点经角色门放宽（admin+auditor）；
// 后端未就绪（404）或角色不符（403）时整卡优雅隐藏——不谎称「空」----
const restores = ref<RestoreRequestRow[]>([]);
const restoresAvailable = ref(true);
const restoresLoaded = ref(false);
const csBusyId = ref<number | null>(null);
const flash = ref("");
async function refreshRestores(): Promise<void> {
  try {
    restores.value = (await api<{ items: RestoreRequestRow[] }>("/ra/restore/requests")).items;
    restoresAvailable.value = true;
  } catch {
    restoresAvailable.value = false;
  }
  restoresLoaded.value = true;
}
async function countersign(row: RestoreRequestRow): Promise<void> {
  deny.value = null; flash.value = "";
  if (!sk.value) { deny.value = { code: "locked", message: "请先解锁审计员密钥（复核须第二签留痕）" }; return; }
  csBusyId.value = row.id;
  busy.value = true;
  try {
    const sig = signMsg(sk.value, restoreCountersignMsg(row.handle_hex, row.reason));
    await api(`/ra/restore/${row.id}/countersign`, { method: "POST", body: JSON.stringify({ sig_hex: sig }) });
    flash.value = "✓ 复核签名生效——凭证已恢复并推链（新纪元根公示可查）";
    await refreshRestores();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "countersign_failed", message: err.message ?? String(e) };
  } finally { csBusyId.value = null; busy.value = false; }
}

// 浮层结案面分派：已有结案回执（trace.closure 或本次刚结案）→ 只读回执；
// 否则带 req 上下文（reqId+req_hash）→ 结案表单；纯追溯无上下文 → 无结案面
const closureView = computed(() => {
  if (closeResult.value && trace.value) {
    return {
      ...trace.value.closure,
      case_archive_fp_hex: closeResult.value.case_archive_fp_hex,
      closed_ts: closeResult.value.closed_ts,
    } as NonNullable<TraceOut["closure"]>;
  }
  return trace.value?.closure ?? null;
});
const canClose = computed(() => {
  if (closeResult.value) return false;
  const ctx = traceCtx.value;
  if (ctx == null || ctx.reqId == null || !ctx.reqHashHex) return false;
  return !trace.value?.closure;
});

const stepIndex = computed<0 | 1 | 2 | 3>(() => step.value);
</script>

<template>
  <div class="fz-enter audit-root">
    <!-- 头部横幅：渐变+粒子（大气感） -->
    <div class="fz-hero-band fz-ticks">
      <ParticleField />
      <FzWatermark glyph="shield" />
      <div class="fz-hero-inner">
        <div class="fz-hero-title">审计工作台</div>
        <div class="fz-hero-sub">链上取证 → 立案 → 双控协同解锁 → 结案 · 全程留痕可追责</div>
        <div class="fz-kpi-row">
          <div class="fz-kpi"><span class="fz-kpi-n amber">{{ kpiLeads }}</span><span class="fz-kpi-l">未立案线索</span></div>
          <div class="fz-kpi"><span class="fz-kpi-n blue">{{ kpiPending }}</span><span class="fz-kpi-l">待批准请求</span></div>
          <div class="fz-kpi"><span class="fz-kpi-n teal">{{ kpiExecuted }}</span><span class="fz-kpi-l">待结案</span></div>
          <div class="fz-kpi"><span class="fz-kpi-n gold">{{ kpiClosed }}</span><span class="fz-kpi-l">已结案</span></div>
        </div>
      </div>
    </div>

    <!-- 步进器 -->
    <div class="stepper fz-enter" style="margin:14px 0">
      <div v-for="(s, i) in STEPS" :key="s" class="step" :class="{ done: i < stepIndex, active: i === stepIndex }">
        <span class="step-n">{{ i < stepIndex ? "✓" : i + 1 }}</span>
        <span class="step-t">{{ s }}</span>
        <span v-if="i < STEPS.length - 1" class="step-arrow">→</span>
      </div>
    </div>

    <template v-if="step === 0">
      <!-- ① 收件箱（卡片化+色彩标注） -->
      <div class="panel">
        <div class="panel-head">
          <h2>违规事件收件箱</h2>
          <span class="fz-pill amber" v-if="kpiRaw.leads">{{ kpiLeads }} 条待立案</span>
          <span class="fz-pill gray" v-else-if="loaded">收件箱空</span>
        </div>
        <p class="desc">链上围栏违规事件按授权编号聚合（未立案过滤）——点击卡片自动生成立案材料。</p>
        <div class="card-grid" v-if="violations.length">
          <button v-for="v in violations" :key="v.auth_id" class="lead-card" :class="{ dead: !v.fileable }"
                  :disabled="!v.fileable" :title="v.fileable ? '' : '该授权记录不在案——历史线索，立案校验不通过'"
                  @click="pick(v)">
            <span class="lead-dot" :class="{ off: !v.fileable }"></span>
            <div class="lead-main">
              <div class="lead-title">授权 <span class="mono">#{{ v.auth_id }}</span></div>
              <div class="lead-meta">违规 <b>{{ v.events }}</b> 次 · 最近 {{ v.last_at ?? "—" }}</div>
              <div class="lead-meta" v-if="!v.fileable">历史线索——授权记录不在案，不可立案</div>
            </div>
            <span class="lead-cta" v-if="v.fileable">立案 →</span>
          </button>
        </div>
        <div v-else-if="!loaded" class="fz-skelset" aria-hidden="true" style="max-width:420px">
          <div class="fz-skel" style="width:86%"></div>
          <div class="fz-skel" style="width:68%"></div>
          <div class="fz-skel" style="width:50%"></div>
        </div>
        <FzEmpty v-else text="当前没有未立案的围栏违规事件——演示时可让飞手飞越围栏触发取证。" icon="inbox" />

        <div class="panel-head" style="margin-top:20px">
          <h2>历史案卷</h2>
        </div>
        <div class="card-grid" v-if="warrants.length">
          <button v-for="w in warrants" :key="w.warrant_hash_hex" class="case-card"
                  :class="w.unlocked?.ts ? 'ok' : 'open'" @click="openWarrantTrace(w)"
                  title="打开追溯浮层——实名面/证据面/结案回执">
            <div class="case-body">
              <div class="case-no mono">{{ w.case_no }}</div>
              <div class="case-meta">
                目标 <span class="mono">#{{ w.target_auth_id ?? "—" }}</span>
                <StatusTag :tone="w.unlocked?.ts ? 'ok' : 'accent'" :label="w.unlocked?.ts ? '已解锁' : '未解锁'" />
              </div>
              <div class="case-meta" v-if="w.unlocked?.username">实名：{{ w.unlocked.username }}</div>
              <div class="case-meta case-cta">查看追溯 →</div>
            </div>
          </button>
        </div>
        <div v-else-if="!loaded" class="fz-skelset" aria-hidden="true" style="max-width:420px">
          <div class="fz-skel" style="width:74%"></div>
          <div class="fz-skel" style="width:56%"></div>
        </div>
        <FzEmpty v-else text="尚无案卷。" icon="doc" />
      </div>

      <!-- 协同请求列表（常驻可见——状态流转无需离开本页） -->
      <div class="panel" v-if="requests.length">
        <div class="panel-head">
          <h2>协同解锁请求</h2>
          <span class="fz-pill gray">状态自动刷新（5 秒）</span>
        </div>
        <div class="req-list">
          <div v-for="r in requests" :key="r.id" class="req-row"
               :class="[S_META[r.status]?.tone, { 'fz-sheen': sheened && r.id === filedReqId }]"
               @animationend="onAnimEnd($event)">
            <div class="req-main">
              <span class="mono case-mini">{{ r.case_no }}</span>
              <span class="fz-badge" :class="S_META[r.status]?.tone">{{ S_META[r.status]?.label ?? r.status }}</span>
            </div>
            <div class="req-meta">
              目标 <span class="mono">#{{ r.target_auth_id ?? "—" }}</span> · 发起 {{ r.created_ts?.slice(5, 16).replace("T", " ") ?? "—" }}
              <span v-if="r.admin_username"> · 批准人 {{ r.admin_username }}</span>
            </div>
            <div class="req-hint">{{ S_META[r.status]?.hint }}</div>
            <div class="req-err" v-if="r.status === 'execute_failed'">⚠ {{ r.execute_error }}</div>
            <div class="req-err" v-if="r.status === 'rejected'">驳回理由：{{ r.reject_reason }}</div>
            <div class="req-actions">
              <button v-if="r.status === 'executed'" class="btn sm" @click="openTrace(r)">查看实名并结案</button>
              <button class="btn sm ghost" :disabled="sigsBusyId === r.id" @click="checkSigs(r)">
                {{ sigsBusyId === r.id ? "复验中…" : "验签复核" }}
              </button>
            </div>
            <div class="sigs-out" v-if="sigs[r.id]">
              <span class="sigs-line" :class="{ bad: sigs[r.id].auditor.ok === false }">{{ verdictLabel(sigs[r.id].auditor, "审计员签") }}</span>
              <span class="sigs-line" :class="{ bad: sigs[r.id].admin.ok === false }">{{ verdictLabel(sigs[r.id].admin, "管理员签") }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 恢复双控·复核卡（B6·auditor 第二签）：列表端点 admin+auditor 双开；
           后端未就绪（404）时整卡隐藏（restoresAvailable=false）——不谎称空 -->
      <div class="panel" v-if="restoresAvailable">
        <div class="panel-head">
          <h2>恢复复核（双控第二签）</h2>
          <span class="fz-pill blue">机构发起 · 审计复核 · 双签齐才执行</span>
        </div>
        <p class="desc">
          机构管理员可对已吊销凭证发起恢复（单签不执行）；复核以您的密钥签
          FZ-RESTORE-COUNTERSIGN 域——发起人不得自行复核，双签齐即时摘叶推链。
        </p>
        <template v-if="!unlockedOnce">
          <label>解锁审计员密钥（密码——仅在解锁瞬间使用）</label>
          <input v-model="unlockPass" type="password" @keyup.enter="doUnlock" />
          <p v-if="unlockErr" class="step-err">{{ unlockErr }}</p>
          <button class="btn ghost" @click="doUnlock">解锁密钥</button>
        </template>
        <div v-if="!restoresLoaded" class="fz-skelset" aria-hidden="true" style="max-width:420px">
          <div class="fz-skel" style="width:82%"></div>
          <div class="fz-skel" style="width:60%"></div>
        </div>
        <FzEmpty v-else-if="!restores.length" text="暂无待复核的恢复请求。" icon="inbox" />
        <div v-else class="req-list">
          <div v-for="row in restores" :key="row.id" class="req-row"
               :class="row.status === 'pending' ? 'amber' : 'gold'">
            <div class="req-main">
              <span class="mono case-mini">{{ row.handle_hex.slice(0, 16) }}…</span>
              <span class="fz-badge" :class="row.status === 'pending' ? 'amber' : 'gold'">
                {{ row.status === "pending" ? "待复核" : row.status === "executed" ? "已恢复" : row.status }}
              </span>
            </div>
            <div class="req-meta">发起人 <span class="mono">{{ row.requested_by }}</span> · {{ row.created_ts?.slice(5, 16).replace("T", " ") ?? "—" }}</div>
            <div class="req-hint">恢复理由：{{ row.reason }}</div>
            <div class="req-err" v-if="row.execute_error">⚠ {{ row.execute_error }}</div>
            <div class="req-actions" v-if="row.status === 'pending'">
              <button class="btn sm" :disabled="busy || !unlockedOnce || csBusyId === row.id" @click="countersign(row)">
                {{ csBusyId === row.id ? "复核签名中…" : "复核签名并执行恢复" }}
              </button>
            </div>
            <div class="req-meta" v-else-if="row.status === 'executed'">复核人 <span class="mono">{{ row.countersign_by ?? "—" }}</span> · {{ row.executed_ts?.slice(5, 16).replace("T", " ") ?? "—" }}</div>
          </div>
        </div>
        <p v-if="flash" class="flash">{{ flash }}</p>
      </div>
    </template>

    <!-- ② 立案（自动带出） -->
    <div v-if="step === 1" class="panel">
      <div class="panel-head">
        <h2>立案</h2>
        <span class="fz-pill teal">案号与目标已自动生成</span>
      </div>
      <p class="desc">案号与目标授权编号已从所选线索自动带出；依据原文已按模板预填（可修改）——确认后一键立案，原文与哈希双锚上链。</p>
      <div class="kv">
        <dt>案号（自动）</dt><dd class="mono">{{ form.case_no }}</dd>
        <dt>目标授权编号（自动）</dt><dd class="mono">#{{ form.target_auth_id ?? "—" }}</dd>
      </div>
      <label>立案依据原文（预填模板——可修改）</label>
      <textarea v-model="form.legal_basis_text" rows="4"></textarea>
      <div style="display:flex;gap:10px;margin-top:12px">
        <button class="btn ghost" @click="step = 0">返回收件箱</button>
        <button class="btn" :disabled="busy" @click="fileCase">{{ busy ? "立案上链中…" : "确认立案并登记令状" }}</button>
      </div>
      <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
    </div>

    <!-- ③ 协同请求 -->
    <div v-if="step === 2" class="panel">
      <div class="panel-head">
        <h2>发起协同解锁请求</h2>
        <span class="fz-pill blue">双签名 · 缺一不可</span>
      </div>
      <p class="desc">
        请求以您的密钥签名后发往机构管理员——批准人将看到依据原文、您的理由、目标与范围。
        发起后<b>留在本页即可看到状态自动流转</b>（待批准 → 已批准·待执行 → 已执行·待结案 → 已结案）。
      </p>
      <div class="kv">
        <dt>令状哈希</dt><dd class="mono">{{ createdWh.slice(0, 24) }}…</dd>
        <dt>依据原文</dt><dd>{{ form.legal_basis_text || "—" }}</dd>
      </div>
      <template v-if="!unlockedOnce">
        <label>解锁审计员密钥（密码——仅在解锁瞬间使用）</label>
        <input v-model="unlockPass" type="password" @keyup.enter="doUnlock" />
        <p v-if="unlockErr" class="step-err">{{ unlockErr }}</p>
        <button class="btn ghost" @click="doUnlock">解锁密钥</button>
      </template>
      <label>调查理由（批准人可见——已预填）</label>
      <textarea v-model="collabNote" rows="3"></textarea>
      <div style="display:flex;gap:10px;margin-top:12px">
        <button class="btn ghost" @click="step = 0; refreshAll()">返回收件箱</button>
        <button class="btn" :disabled="busy || !unlockedOnce" @click="fileRequest">
          {{ busy ? "签名发函中…" : "签名并发起协同请求" }}
        </button>
      </div>
      <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />

      <!-- 发函后原地状态卡（常驻轮询驱动——批准/执行完成后自动流转） -->
      <div v-if="filedReq" class="filed-status"
           :class="[filedReq.status, { 'fz-converge': converged, 'fz-sheen': sheened }]"
           @animationend="onAnimEnd($event)">
        <div class="req-main">
          <span class="mono case-mini">{{ filedReq.case_no }}</span>
          <span class="fz-badge" :class="S_META[filedReq.status]?.tone">{{ S_META[filedReq.status]?.label ?? filedReq.status }}</span>
        </div>
        <!-- 双钥汇流图（丙-2 M3 装饰层）：审计员钥+管理员钥 → req_fp；
             批准前右钥灰点虚位，批准瞬间本卡一次金色合流脉冲 -->
        <FzConfluence class="filed-cf" :auditor-fp="filedReq.auditor_fp"
          :admin-fp="filedReq.admin_fp ?? filedReq.fzc2_fingerprint_hex" :req-fp="filedReq.req_fp" />
        <div class="req-hint">{{ S_META[filedReq.status]?.hint }}</div>
        <div class="req-err" v-if="filedReq.status === 'execute_failed'">⚠ {{ filedReq.execute_error }}</div>
        <div class="req-err" v-if="filedReq.status === 'rejected'">驳回理由：{{ filedReq.reject_reason }}</div>
        <div class="req-actions" style="margin-top:6px;display:flex;gap:8px">
          <button v-if="filedReq.status === 'executed'" class="btn sm" @click="openTrace(filedReq)">查看实名并结案</button>
          <button class="btn sm ghost" :disabled="sigsBusyId === filedReq.id" @click="checkSigs(filedReq)">
            {{ sigsBusyId === filedReq.id ? "复验中…" : "验签复核" }}
          </button>
        </div>
        <div class="sigs-out" v-if="sigs[filedReq.id]">
          <span class="sigs-line" :class="{ bad: sigs[filedReq.id].auditor.ok === false }">{{ verdictLabel(sigs[filedReq.id].auditor, "审计员签") }}</span>
          <span class="sigs-line" :class="{ bad: sigs[filedReq.id].admin.ok === false }">{{ verdictLabel(sigs[filedReq.id].admin, "管理员签") }}</span>
        </div>
      </div>
    </div>

    <!-- ④ 核实/追溯浮层（请求行「查看实名并结案」或案卷卡点击；Esc 关闭+入场过渡——S5）。
         三段式：实名面 → 证据面（设备一致性判词+链上时间线，A2）→ 结案面
         （表单 A1 / 已结案回执）。 -->
    <Transition name="fz-modal">
      <div v-if="traceCtx != null" class="modal-mask" @click.self="dismissTrace">
        <div class="modal panel">
          <h2>{{ closeResult ? "结案回执" : canClose ? "核实实名并结案" : "案卷追溯" }}</h2>
          <p class="desc" v-if="!closeResult">
            {{ traceCtx.reqId != null
              ? "双签名齐备，系统已自动完成出函与解锁；核实下方实名与链上证据后落终局判词。"
              : "该案卷的实名面与链上证据全程留痕——已结案卷在此展示结案回执。" }}
          </p>

          <!-- 实名面 -->
          <div class="kv" v-if="trace?.warrant?.unlocked?.username">
            <dt>案号</dt><dd class="mono">{{ trace.warrant.case_no }}</dd>
            <dt>解锁实名</dt><dd>{{ trace.warrant.unlocked.username }}（{{ trace.warrant.unlocked.id_number ?? "—" }}）</dd>
            <dt>解锁时间</dt><dd>{{ trace.warrant.unlocked.ts?.slice(5, 16).replace("T", " ") ?? "—" }}</dd>
            <dt>登记 SN 指纹</dt><dd class="mono">{{ trace.chain_trace?.device_check?.registered_sn_fingerprint ?? "—" }}</dd>
          </div>

          <!-- 证据面（A2）：设备一致性判词卡（四判词色彩语义）+链上证据时间线 -->
          <template v-if="trace?.chain_trace?.device_check">
            <div class="panel-head" style="margin-top:14px">
              <h2 style="font-size:14px">设备一致性核验</h2>
              <span class="fz-badge" :class="deviceVerdictMeta(trace.chain_trace.device_check.verdict).tone">
                {{ deviceVerdictMeta(trace.chain_trace.device_check.verdict).label }}
              </span>
            </div>
            <p class="note" style="margin:0 0 6px">
              {{ deviceVerdictMeta(trace.chain_trace.device_check.verdict).hint }}
              <template v-if="trace.chain_trace.device_check.verdict === 'insufficient' && trace.chain_trace.device_check.reason">
                ——{{ trace.chain_trace.device_check.reason }}
              </template>
            </p>
            <div class="kv">
              <dt>核对检查点</dt><dd>{{ trace.chain_trace.device_check.checked ?? 0 }}{{
                trace.chain_trace.device_check.verdict === "mismatch" ? `（其中不一致 ${trace.chain_trace.device_check.mismatch} 处）` : "" }}</dd>
              <dt>登记 SN 指纹</dt><dd class="mono">{{ trace.chain_trace.device_check.registered_sn_fingerprint ?? "—" }}</dd>
            </div>
          </template>

          <!-- 链上证据时间线（checkpoints/events/chain_fingerprint） -->
          <template v-if="trace">
            <div class="panel-head" style="margin-top:14px">
              <h2 style="font-size:14px">链上证据时间线</h2>
              <span class="fz-pill gray">链指纹 <span class="mono">{{ trace.chain_fingerprint ?? "—" }}</span></span>
            </div>
            <div class="tl" v-if="(trace.chain_trace?.checkpoints?.length ?? 0) + (trace.chain_trace?.events?.length ?? 0)">
              <div class="tl-item" v-for="cp in trace.chain_trace?.checkpoints ?? []" :key="`cp-${cp.seq}`">
                <span class="tl-dot blue"></span>
                <div class="tl-body">
                  <div class="tl-title">检查点锚定 <span class="mono">cp{{ cp.seq }}</span></div>
                  <div class="tl-meta mono">链头 {{ (cp.chain_head_hex ?? cp.chain_head ?? "—").slice(0, 18) }}… · {{ cp.ts ?? "—" }}</div>
                </div>
              </div>
              <div class="tl-item" v-for="(ev, i) in trace.chain_trace?.events ?? []" :key="`ev-${i}`">
                <span class="tl-dot amber"></span>
                <div class="tl-body">
                  <div class="tl-title">{{ CHAIN_EVENT_LABEL[ev.event_type] ?? `链上事件 #${ev.event_type}` }}</div>
                  <div class="tl-meta mono">block {{ ev.block }} · {{ ev.event_hash_hex.slice(0, 18) }}… · {{ ev.logged_at?.slice(5, 16).replace("T", " ") ?? "—" }}</div>
                </div>
              </div>
            </div>
            <p v-else class="note">链上暂无该授权的检查点/事件留痕（记录缺失≠无罪——如实呈现）。</p>
          </template>
          <p v-else-if="traceError" class="req-err">追溯数据不可得：{{ traceError }}</p>
          <p v-else class="note">追溯数据加载中…</p>

          <!-- 结案面·已结案回执（A4 只读入口/结案成功态）：结论判词+说明+案卷指纹 -->
          <template v-if="closureView">
            <div class="panel-head" style="margin-top:14px">
              <h2 style="font-size:14px">结案回执</h2>
              <span class="fz-badge" :class="conclusionTone(closureView.conclusion)">{{ conclusionLabel(closureView.conclusion) }}</span>
            </div>
            <div class="kv">
              <dt>结案说明</dt><dd style="font-family:inherit">{{ closureView.conclusion_text ?? "—" }}</dd>
              <dt>结案人</dt><dd class="mono">{{ closureView.auditor_username }} · {{ closureView.closed_ts?.slice(5, 16).replace("T", " ") ?? "—" }}</dd>
            </div>
            <div class="fp-box" v-if="closureView.case_archive_fp_hex">
              <span class="fp-label">案卷指纹（SM3——令状|请求|双签|函|实名|结论|时戳）</span>
              <code class="fp-code">{{ closureView.case_archive_fp_hex }}</code>
              <button class="btn sm ghost" @click="copyArchiveFp">{{ copied ? "已复制" : "复制指纹" }}</button>
            </div>
          </template>

          <!-- 结案面·表单（A1）：结论三判词 radio+说明（属实必填）+签名提交 -->
          <template v-else-if="canClose">
            <div class="panel-head" style="margin-top:14px">
              <h2 style="font-size:14px">终局判词（结案）</h2>
              <span class="fz-pill blue">结案须审计员钥签名留痕</span>
            </div>
            <div class="radio-row" role="radiogroup" aria-label="结案结论">
              <label v-for="c in (Object.keys(CONCLUSION_META) as CloseConclusion[])" :key="c" class="radio-opt"
                     :class="{ on: closeForm.conclusion === c }">
                <input type="radio" name="close-conclusion" :value="c" v-model="closeForm.conclusion" />
                <span class="fz-badge" :class="CONCLUSION_META[c].tone">{{ CONCLUSION_META[c].label }}</span>
                <span class="radio-hint">{{ CONCLUSION_META[c].hint }}</span>
              </label>
            </div>
            <label>结案说明（结论「属实」必填 · ≤500 字——随签名落案卷台账）</label>
            <textarea v-model="closeForm.text" rows="3" maxlength="500"
                      :placeholder="closeForm.conclusion === 'verified' ? '核实认定与依据（必填）——例：链上检查点签名与登记设备一致，违规事实成立。' : '判据与理由（选填）'"></textarea>
            <template v-if="!unlockedOnce">
              <label>解锁审计员密钥（密码——仅在解锁瞬间使用）</label>
              <div style="display:flex;gap:10px;align-items:center">
                <input v-model="unlockPass" type="password" style="flex:1" @keyup.enter="doUnlock" />
                <button class="btn ghost" @click="doUnlock">解锁密钥</button>
              </div>
              <p v-if="unlockErr" class="step-err">{{ unlockErr }}</p>
            </template>
            <div style="display:flex;gap:10px;margin-top:12px">
              <button class="btn ghost" @click="dismissTrace">稍后</button>
              <button class="btn" :disabled="busy || !closeForm.conclusion" @click="closeCase">
                {{ busy ? "签名结案中…" : "签名并结案" }}
              </button>
            </div>
          </template>

          <p v-if="flash" class="flash">{{ flash }}</p>
          <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
        </div>
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.audit-root { position: relative; }

/* 头部横幅：渐变+粒子 */
/* 横幅/KPI/徽章走 ui.css 共享 fz-* 体系（三台统一——禁手抄分叉） */
.panel-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.panel-head h2 { margin: 0; }

/* 收件箱卡片 */
.card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }
.lead-card {
  display: flex; align-items: center; gap: 12px; text-align: left;
  background: var(--panel); border: 1px solid var(--tone-amber-line); border-left: 4px solid #d9963a;
  border-radius: var(--r-md); padding: 14px 16px; cursor: pointer;
  transition: transform var(--t-fast), box-shadow var(--t-fast), border-color var(--t-fast);
}
.lead-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-2); border-color: #d9963a; }
.lead-dot { width: 9px; height: 9px; border-radius: 50%; background: #d96a3a; flex: none; animation: fz-pulse 2.2s infinite; }
.lead-main { flex: 1; }
.lead-title { font-size: 14px; font-weight: 650; color: var(--ink); }
.lead-meta { font-size: 12.5px; color: var(--ink-3); margin-top: 3px; }
.lead-cta { font-size: 12.5px; color: var(--tone-amber-fg); }
.lead-card.dead { opacity: 0.55; border-color: var(--line); border-left-color: var(--line-strong); cursor: not-allowed; }
.lead-card.dead:hover { transform: none; box-shadow: none; }
.lead-dot.off { background: var(--line-strong); animation: none; }

/* 案卷卡（A4：整卡可点开追溯浮层） */
.case-card {
  display: flex; overflow: hidden; background: var(--panel); text-align: left; cursor: pointer;
  border: var(--hairline); border-radius: var(--r-md); padding: 0;
  transition: transform var(--t-fast), box-shadow var(--t-fast);
}
.case-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-2); }
.case-cta { color: var(--tone-blue-fg); font-size: 12px; margin-top: 2px; }
.case-card.ok { border-left: 4px solid var(--tone-teal-fg); }
.case-card.open { border-left: 4px solid var(--tone-blue-fg); }
.case-body { padding: 12px 16px; display: grid; gap: 4px; }
.case-no { font-weight: 700; font-size: 13.5px; }
.case-meta { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--ink-3); }

/* 请求列表 */
.req-list { display: grid; gap: 10px; }
.req-row {
  border: var(--hairline); border-radius: var(--r-md); padding: 12px 16px;
  background: var(--panel); display: grid; gap: 5px;
  border-left-width: 4px;
}
.req-row.amber { border-left-color: #d9963a; }
.req-row.blue { border-left-color: var(--tone-blue-fg); }
.req-row.teal { border-left-color: var(--tone-teal-fg); }
.req-row.gold { border-left-color: #b08d3e; }
.req-row.red { border-left-color: #c0392b; }
.req-main { display: flex; align-items: center; gap: 10px; }
.case-mini { font-weight: 700; font-size: 13.5px; }
.req-meta { font-size: 12.5px; color: var(--ink-3); }
.req-hint { font-size: 12px; color: var(--ink-3); }
.req-err { font-size: 12.5px; color: var(--tone-red-fg); }
.req-actions { margin-top: 4px; }
.btn.sm { padding: 5px 14px; font-size: 12.5px; }

/* 结案浮层 */
.modal-mask {
  position: fixed; inset: 0; background: rgba(30, 34, 40, 0.35);
  display: flex; align-items: center; justify-content: center; z-index: 50;
  backdrop-filter: blur(2px);
}
.modal { width: 520px; max-width: 92vw; margin: 0; }
/* 入场过渡（视觉 S 批 S5：蒙层淡入+卡片上浮 8px/180ms——≤400ms 叙事纪律） */
.fz-modal-enter-active { transition: opacity 180ms var(--ease); }
.fz-modal-enter-active .modal { transition: transform 180ms var(--ease), opacity 180ms var(--ease); }
.fz-modal-enter-from { opacity: 0; }
.fz-modal-enter-from .modal { transform: translateY(8px); opacity: 0; }

.step-err { color: #c0392b; font-size: 12.5px; margin: 6px 0; }
.filed-status {
  border: var(--hairline); border-left: 4px solid var(--line-strong);
  border-radius: var(--r-md); padding: 12px 16px; margin-top: 14px;
  display: grid; gap: 5px; background: var(--panel);
}
.filed-cf { margin: 2px 0 4px; } /* 双钥汇流图落位（丙-2 M3） */
.filed-status.pending { border-left-color: #d9963a; }
.filed-status.approved { border-left-color: var(--tone-blue-fg); }
.filed-status.executed { border-left-color: var(--tone-teal-fg); }
.filed-status.closed { border-left-color: #b08d3e; }
.filed-status.rejected, .filed-status.execute_failed { border-left-color: #c0392b; }
/* （丙-2 M1）此处原有 .req-main/.case-mini/.req-hint/.req-err/.btn.sm 整组
   重复定义——与上方请求列表段完全同值，已删除（单一定义处纪律） */
.note { font-size: 12.5px; color: var(--ink-3); }
.desc { font-size: 12.5px; color: var(--ink-2); line-height: 1.7; margin: 0 0 10px; }

/* 验签判词行（A3） */
.sigs-out { display: grid; gap: 2px; margin-top: 4px; }
.sigs-line { font-size: 12px; color: var(--tone-teal-fg); }
.sigs-line.bad { color: var(--tone-red-fg); }

/* 链上证据时间线（A2）——令牌化细线+彩点，与 fz-badge 同色相 */
.tl { display: grid; gap: 0; margin: 4px 0 2px; }
.tl-item { display: flex; gap: 10px; position: relative; padding: 5px 0 5px 2px; }
.tl-item + .tl-item { border-top: 1px dashed var(--line); }
.tl-dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 5px; flex: none; }
.tl-dot.blue { background: var(--tone-blue-fg); }
.tl-dot.amber { background: var(--tone-amber-fg); }
.tl-body { min-width: 0; }
.tl-title { font-size: 12.5px; font-weight: 650; color: var(--ink); }
.tl-meta { font-size: 11.5px; color: var(--ink-3); overflow-wrap: break-word; }

/* 结案表单（A1）：三判词 radio 落座卡 */
.radio-row { display: grid; gap: 6px; margin: 8px 0 2px; }
.radio-opt {
  display: flex; align-items: center; gap: 8px; margin: 0; cursor: pointer;
  border: var(--hairline); border-radius: var(--r-sm); padding: 8px 10px;
  background: var(--panel-2); transition: border-color var(--t-fast), background var(--t-fast);
}
.radio-opt.on { border-color: var(--accent); background: var(--accent-soft); }
.radio-opt input[type="radio"] { width: auto; margin: 0; }
.radio-hint { font-size: 11.5px; color: var(--ink-3); flex: 1; text-align: right; }

/* 案卷指纹回执（A1/A4）：等宽全文+复制 */
.fp-box {
  margin-top: 10px; padding: 10px 12px; border: var(--hairline);
  border-left: 3px solid var(--tone-gold-fg); border-radius: var(--r-sm);
  background: var(--panel-2); display: grid; gap: 6px;
}
.fp-label { font-size: 11.5px; color: var(--ink-3); }
.fp-code { font-family: var(--font-mono); font-size: 12px; color: var(--ink); overflow-wrap: break-word; }

.flash { color: var(--teal); font-size: 13px; margin-top: 10px; }
</style>
