<script setup lang="ts">
/** 审计台（2026-09-29 账户批 B3；批二按队长反馈重设计）：
 * - 视觉：KPI 指标带+卡片化收件箱+状态色徽章体系+缓粒子背景（大气、克制）；
 * - 立案自动化：点选违规线索即自动生成案号+带入目标授权+预填依据模板——
 *   一键提交，不再让审计员手填无从下手；
 * - 协同请求生命周期（队长拍板四拍）：待批准→已批准·待执行→已执行·待结案
 *   →已结案（+已驳回/执行失败旁路）；常驻轮询——audit 端留守即可看状态流转，
 *   无需退出重登；executed 后就地查看实名并结案。
 * 敏感操作（立案/发函/结案）以审计员钥签名；刷新后需密码解锁钥。 */
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { api, ApiError } from "../lib/api";
import { cachedUsername, signMsg, unlockSk } from "../lib/auth";
import { getCachedSk } from "../lib/keystore";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";
import ParticleField from "../components/ParticleField.vue";

const username = cachedUsername();
const busy = ref(false);
const deny = ref<{ code: string; message: string } | null>(null);

// ---- 状态徽章体系（四拍主线+两旁路）----
type S = "pending" | "approved" | "executed" | "closed" | "rejected" | "execute_failed";
const S_META: Record<S, { label: string; tone: string; hint: string }> = {
  pending: { label: "待批准", tone: "amber", hint: "等待机构管理员审阅批准" },
  approved: { label: "已批准 · 待执行", tone: "blue", hint: "系统自动出函与解锁进行中" },
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
interface WarrantView { warrant_hash_hex: string; case_no: string; target_auth_id: number | null; unlocked: boolean; unlocked_username?: string | null }
interface ReqView {
  id: number; warrant_hash_hex: string; case_no: string; target_auth_id: number | null;
  legal_basis_text: string | null; note: string; status: S;
  auditor_username: string; auditor_fp: string; admin_username: string | null; admin_fp: string | null;
  reject_reason: string | null; execute_error: string | null;
  created_ts: string | null; decided_ts: string | null; executed_ts: string | null;
}

const violations = ref<Violation[]>([]);
const warrants = ref<WarrantView[]>([]);
const requests = ref<ReqView[]>([]);

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
}

// 常驻轮询（5s，任意页步生效）：非终态请求存在即拉取——audit 端在任何页面
// （含第③步发起页）都能"看见"admin 批准后的状态流转
let pollTimer: ReturnType<typeof setInterval> | null = null;
const filedReqId = ref<number | null>(null);
const filedReq = computed<ReqView | null>(
  () => requests.value.find((r) => r.id === filedReqId.value) ?? null,
);
onMounted(() => {
  void refreshAll();
  pollTimer = setInterval(async () => {
    // 无条件轮询（2026-09-30 评审 P1-7 根修：旧条件闸=「有 approved 才拉」
    // 导致新 pending 请求要 F5 才出现）。5s 一次、载荷小——省请求让位于
    // 双控合流可靠。
    try {
      requests.value = (await api<{ items: ReqView[] }>("/audit/collab-requests")).items;
    } catch { /* 下拍再试 */ }
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

// ---- ④ 结案（executed→closed）----
const trace = ref<any>(null);
const closingId = ref<number | null>(null);
async function openTrace(r: ReqView): Promise<void> {
  closingId.value = r.id;
  try {
    trace.value = await api(`/audit/warrants/${r.warrant_hash_hex}/trace`);
  } catch { trace.value = null; }
}
async function closeCase(): Promise<void> {
  if (closingId.value == null) return;
  deny.value = null;
  busy.value = true;
  try {
    await api(`/audit/collab-requests/${closingId.value}/close`, { method: "POST" });
    closingId.value = null;
    trace.value = null;
    await refreshAll();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "close_failed", message: err.message ?? String(e) };
  } finally { busy.value = false; }
}

const stepIndex = computed<0 | 1 | 2 | 3>(() => step.value);
</script>

<template>
  <div class="fz-enter audit-root">
    <!-- 头部横幅：渐变+粒子（大气感） -->
    <div class="fz-hero-band fz-ticks">
      <ParticleField />
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
          <span class="fz-pill gray" v-else>收件箱空</span>
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
        <p v-else class="note">当前没有未立案的围栏违规事件——演示时可让飞手飞越围栏触发取证。</p>

        <div class="panel-head" style="margin-top:20px">
          <h2>历史案卷</h2>
        </div>
        <div class="card-grid" v-if="warrants.length">
          <div v-for="w in warrants" :key="w.warrant_hash_hex" class="case-card" :class="w.unlocked ? 'ok' : 'open'">
            <div class="case-body">
              <div class="case-no mono">{{ w.case_no }}</div>
              <div class="case-meta">
                目标 <span class="mono">#{{ w.target_auth_id ?? "—" }}</span>
                <StatusTag :tone="w.unlocked ? 'ok' : 'accent'" :label="w.unlocked ? '已解锁' : '未解锁'" />
              </div>
              <div class="case-meta" v-if="w.unlocked_username">实名：{{ w.unlocked_username }}</div>
            </div>
          </div>
        </div>
        <p v-else class="note">尚无案卷。</p>
      </div>

      <!-- 协同请求列表（常驻可见——状态流转无需离开本页） -->
      <div class="panel" v-if="requests.length">
        <div class="panel-head">
          <h2>协同解锁请求</h2>
          <span class="fz-pill gray">状态自动刷新（5 秒）</span>
        </div>
        <div class="req-list">
          <div v-for="r in requests" :key="r.id" class="req-row" :class="S_META[r.status]?.tone">
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
            <div class="req-actions" v-if="r.status === 'executed'">
              <button class="btn sm" @click="openTrace(r)">查看实名并结案</button>
            </div>
          </div>
        </div>
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
      <div v-if="filedReq" class="filed-status" :class="filedReq.status">
        <div class="req-main">
          <span class="mono case-mini">{{ filedReq.case_no }}</span>
          <span class="fz-badge" :class="S_META[filedReq.status]?.tone">{{ S_META[filedReq.status]?.label ?? filedReq.status }}</span>
        </div>
        <div class="req-hint">{{ S_META[filedReq.status]?.hint }}</div>
        <div class="req-err" v-if="filedReq.status === 'execute_failed'">⚠ {{ filedReq.execute_error }}</div>
        <div class="req-err" v-if="filedReq.status === 'rejected'">驳回理由：{{ filedReq.reject_reason }}</div>
        <div v-if="filedReq.status === 'executed'" style="margin-top:6px">
          <button class="btn sm" @click="openTrace(filedReq)">查看实名并结案</button>
        </div>
      </div>
    </div>

    <!-- ④ 结案浮层（executed 请求点「查看实名并结案」） -->
    <div v-if="closingId != null" class="modal-mask" @click.self="closingId = null; trace = null">
      <div class="modal panel">
        <h2>核实实名并结案</h2>
        <p class="desc">双签名齐备，系统已自动完成出函与解锁；请核实解锁实名后结案。</p>
        <div class="kv" v-if="trace?.warrant?.unlocked">
          <dt>案号</dt><dd class="mono">{{ trace.warrant.case_no }}</dd>
          <dt>解锁实名</dt><dd>{{ trace.warrant.unlocked?.username }}（{{ trace.warrant.unlocked?.id_number }}）</dd>
          <dt>设备序列号</dt><dd class="mono">{{ trace.warrant.unlocked?.sn ?? "—" }}</dd>
        </div>
        <p v-else class="note">追溯数据加载中…</p>
        <div style="display:flex;gap:10px;margin-top:12px">
          <button class="btn ghost" @click="closingId = null; trace = null">稍后</button>
          <button class="btn" :disabled="busy" @click="closeCase">{{ busy ? "结案中…" : "确认结案" }}</button>
        </div>
        <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
      </div>
    </div>
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
  background: var(--panel); border: 1px solid #ecd9ae; border-left: 4px solid #d9963a;
  border-radius: var(--r-md); padding: 14px 16px; cursor: pointer;
  transition: transform var(--t-fast), box-shadow var(--t-fast), border-color var(--t-fast);
}
.lead-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-2); border-color: #d9963a; }
.lead-dot { width: 9px; height: 9px; border-radius: 50%; background: #d96a3a; flex: none; animation: fz-pulse 2.2s infinite; }
.lead-main { flex: 1; }
.lead-title { font-size: 14px; font-weight: 650; color: var(--ink); }
.lead-meta { font-size: 12.5px; color: var(--ink-3); margin-top: 3px; }
.lead-cta { font-size: 12.5px; color: #b7791f; }
.lead-card.dead { opacity: 0.55; border-color: var(--line); border-left-color: var(--line-strong); cursor: not-allowed; }
.lead-card.dead:hover { transform: none; box-shadow: none; }
.lead-dot.off { background: var(--line-strong); animation: none; }

/* 案卷卡 */
.case-card {
  display: flex; overflow: hidden; background: var(--panel);
  border: var(--hairline); border-radius: var(--r-md);
  transition: transform var(--t-fast), box-shadow var(--t-fast);
}
.case-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-2); }
.case-card.ok { border-left: 4px solid #2e8577; }
.case-card.open { border-left: 4px solid #3b6ea5; }
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
.req-row.blue { border-left-color: #3b6ea5; }
.req-row.teal { border-left-color: #2e8577; }
.req-row.gold { border-left-color: #b08d3e; }
.req-row.red { border-left-color: #c0392b; }
.req-main { display: flex; align-items: center; gap: 10px; }
.case-mini { font-weight: 700; font-size: 13.5px; }
.req-meta { font-size: 12.5px; color: var(--ink-3); }
.req-hint { font-size: 12px; color: var(--ink-3); }
.req-err { font-size: 12.5px; color: #a33; }
.req-actions { margin-top: 4px; }
.btn.sm { padding: 5px 14px; font-size: 12.5px; }

/* 结案浮层 */
.modal-mask {
  position: fixed; inset: 0; background: rgba(30, 34, 40, 0.35);
  display: flex; align-items: center; justify-content: center; z-index: 50;
  backdrop-filter: blur(2px);
}
.modal { width: 520px; max-width: 92vw; margin: 0; }

.step-err { color: #c0392b; font-size: 12.5px; margin: 6px 0; }
.filed-status {
  border: var(--hairline); border-left: 4px solid var(--line-strong);
  border-radius: var(--r-md); padding: 12px 16px; margin-top: 14px;
  display: grid; gap: 5px; background: var(--panel);
}
.filed-status.pending { border-left-color: #d9963a; }
.filed-status.approved { border-left-color: #3b6ea5; }
.filed-status.executed { border-left-color: #2e8577; }
.filed-status.closed { border-left-color: #b08d3e; }
.filed-status.rejected, .filed-status.execute_failed { border-left-color: #c0392b; }
.req-main { display: flex; align-items: center; gap: 10px; }
.case-mini { font-weight: 700; font-size: 13.5px; }
.req-hint { font-size: 12px; color: var(--ink-3); }
.req-err { font-size: 12.5px; color: #a33; }
.btn.sm { padding: 5px 14px; font-size: 12.5px; }
.note { font-size: 12.5px; color: var(--ink-3); }
.desc { font-size: 12.5px; color: var(--ink-2); line-height: 1.7; margin: 0 0 10px; }
</style>
