<script setup lang="ts">
/** 机构台（2026-09-29 账户批 B3；批二异步化；2026-10-04 升格批）：机构管理员工作面
 * ——待批协作/台账/吊销。主线：收函（看明白为什么）→ 批准/驳回（管理员钥签）→ 留痕。
 * 批准即返回（后台自动出函+解锁——真链推链不再卡浏览器请求）；状态轮询
 * 流转：已批准·待执行 → 已执行 | 执行失败（可重试）。
 * 升格批（B1/B6/A5）：吊销=理由+两步式签名（预览句柄→FZ-REVOKE|v1 域）→
 * 联动清单回执；恢复双控发起（FZ-RESTORE|v1）；处置待办卡（后端未就绪隐藏）；
 * 历史签名复验按钮。 */
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import { api, ApiError } from "../lib/api";
import { signMsg, unlockSk } from "../lib/auth";
import { getCachedSk } from "../lib/keystore";
import {
  conclusionLabel,
  conclusionTone,
  restoreMsg,
  revokeMsg,
  verdictLabel,
  type DisposalTodo,
  type RestoreRequestRow,
  type RevokeResult,
  type SnapshotLeaf,
  type VerifySigsOut,
} from "../lib/gov";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";
import ParticleField from "../components/ParticleField.vue";
import FzConfluence from "../components/FzConfluence.vue";
import FzEmpty from "../components/FzEmpty.vue";
import FzWatermark from "../components/FzWatermark.vue";

const busy = ref(false);
const deny = ref<{ code: string; message: string } | null>(null);
const flash = ref("");

// 台账状态 tone（视觉 S 批 S7：对齐审计台 S_META teal 语言——已执行=teal、
// 已结案=gold、已驳回=bad；未知状态兜底 ok；文案原样不动）
const LEDGER_TONE: Record<string, "teal" | "gold" | "bad" | "ok"> = {
  executed: "teal", closed: "gold", rejected: "bad",
};

interface ReqView {
  id: number; warrant_hash_hex: string; case_no: string; target_auth_id: number | null;
  legal_basis_text: string | null; note: string; status: string;
  auditor_username: string; auditor_fp: string; admin_username: string | null; admin_fp: string | null;
  reject_reason: string | null; execute_error: string | null;
  fzc2_fingerprint_hex: string | null; req_fp?: string;
  created_ts: string | null; decided_ts: string | null; executed_ts: string | null;
}
interface Overview {
  warrants: { warrant_hash_hex: string; case_no: string; target_auth_id: number | null; unlocked: boolean; created_ts: string | null }[];
  collab_ledger: { warrant_hash_hex: string; master_cred_hash_hex: string; code_fingerprint_hex: string; issued_at: string | null }[];
  accounts: { username: string; role: string; status: string; created_ts: string | null }[];
  reset_log: { ts: string | null; action: string; username: string; operator: string; detail: string | null }[];
}

const pending = ref<ReqView[]>([]);
const history = ref<ReqView[]>([]);
const overview = ref<Overview | null>(null);
// 首拍旗标（视觉 S 批 S2：加载与空态分离——首拍前 shimmer 骨架，不谎称「空」）
const loaded = ref(false);
const loadedOv = ref(false);

async function refresh(): Promise<void> {
  try {
    const all = (await api<{ items: ReqView[] }>("/admin/collab-requests")).items;
    pending.value = all.filter((x) => ["pending", "approved", "executing", "execute_failed"].includes(x.status));
    history.value = all.filter((x) => ["executed", "closed", "rejected"].includes(x.status));
  } catch { /* 401 由守卫层处理 */ }
  loaded.value = true;
  try { overview.value = await api<Overview>("/admin/overview"); } catch { overview.value = null; }
  loadedOv.value = true;
  void refreshRevocation();
  void refreshRestores();
  void refreshTodos();
}

// KPI 指标带（与审计台同语言——机构视角五数；count-up：视觉深化批 C）
import { computed } from "vue";
import { useCountUp } from "../composables/useCountUp";
const kpiRaw = computed(() => ({
  pending: pending.value.filter((x) => x.status === "pending").length,
  executing: pending.value.filter((x) => ["approved", "executing"].includes(x.status)).length,
  failed: pending.value.filter((x) => x.status === "execute_failed").length,
  done: history.value.filter((x) => x.status === "closed").length,
  accounts: overview.value?.accounts?.length ?? 0,
}));
const kpiPending = useCountUp(computed(() => kpiRaw.value.pending));
const kpiExecuting = useCountUp(computed(() => kpiRaw.value.executing));
const kpiFailed = useCountUp(computed(() => kpiRaw.value.failed));
const kpiDone = useCountUp(computed(() => kpiRaw.value.done));
const kpiAccounts = useCountUp(computed(() => kpiRaw.value.accounts));

// 轮询（4s）：批准后的后台执行态流转自动可见（approved→executed/execute_failed）
let pollTimer: ReturnType<typeof setInterval> | null = null;
onMounted(() => {
  void refresh();
  pollTimer = setInterval(async () => {
    // 无条件轮询（同审计台 P1-7 根修：新 pending 请求自动出现，双控合流不靠 F5）
    try {
      const all = (await api<{ items: ReqView[] }>("/admin/collab-requests")).items;
      pending.value = all.filter((x) => ["pending", "approved", "executing", "execute_failed"].includes(x.status));
      history.value = all.filter((x) => ["executed", "closed", "rejected"].includes(x.status));
    } catch { /* 下拍再试 */ }
  }, 4000);
});
onBeforeUnmount(() => { if (pollTimer) clearInterval(pollTimer); });

// ---- 管理员钥解锁（批准/驳回签名前置）----
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

// ---- 批准 / 驳回 ----
const rejecting = ref<number | null>(null);
const rejectReason = ref("");

// 双钥合流脉冲（丙-2 M3）：批准成功瞬间该卡一次金色合流脉冲（≤400ms 单发，
// animationend 即摘除——头号叙事「双钥汇流成一函」的可见时刻）
const convergedId = ref<number | null>(null);
function onConvergeEnd(id: number, e: AnimationEvent): void {
  // 按 keyframe 名判定（子元素 fz-enter 等动画结束事件也会冒泡到卡片）
  if (e.animationName === "fz-converge" && convergedId.value === id) convergedId.value = null;
}

async function approve(r: ReqView): Promise<void> {
  deny.value = null; flash.value = "";
  if (!sk.value) { deny.value = { code: "locked", message: "请先解锁管理员密钥" }; return; }
  busy.value = true;
  try {
    const sig = signMsg(sk.value, `FZ-COLLAB-REQ|v1|${r.warrant_hash_hex}|${r.note}`);
    await api(`/admin/collab-requests/${r.id}/approve`, {
      method: "POST",
      body: JSON.stringify({ sig_hex: sig }),
    });
    flash.value = "✓ 已批准——自动执行进行中（出函与解锁完成后状态自动流转，本页实时可见）";
    convergedId.value = r.id; // 双钥齐——合流脉冲（视觉叙事与业务事实同拍）
    await refresh();
    // 后台执行态轮询已由 onMounted 计时器接管（approved → executed/execute_failed）
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "approve_failed", message: err.message ?? String(e) };
  } finally { busy.value = false; }
}

async function reject(r: ReqView): Promise<void> {
  deny.value = null; flash.value = "";
  if (!rejectReason.value.trim()) { deny.value = { code: "reason_required", message: "驳回须填写理由（审计员将据此补充材料）" }; return; }
  if (!sk.value) { deny.value = { code: "locked", message: "请先解锁管理员密钥" }; return; }
  busy.value = true;
  try {
    const sig = signMsg(sk.value, `FZ-COLLAB-REJECT|v1|${r.warrant_hash_hex}|${r.note}|${rejectReason.value.trim()}`);
    await api(`/admin/collab-requests/${r.id}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason: rejectReason.value.trim(), sig_hex: sig }),
    });
    flash.value = "✓ 已驳回（理由随请求留痕，审计台可见）";
    rejecting.value = null;
    rejectReason.value = "";
    await refresh();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "reject_failed", message: err.message ?? String(e) };
  } finally { busy.value = false; }
}

// ---- 执行失败重试 ----
async function retry(r: ReqView): Promise<void> {
  deny.value = null; flash.value = "";
  busy.value = true;
  try {
    await api(`/admin/collab-requests/${r.id}/retry`, { method: "POST" });
    flash.value = "✓ 已重新执行（后台进行中）";
    await refresh();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "retry_failed", message: err.message ?? String(e) };
  } finally { busy.value = false; }
}

// ---- 账户管理（删除孤儿账户；密码重置已收回离线——2026-09-30 收紧批）----
const delBusy = ref("");
async function deleteOrphan(username: string): Promise<void> {
  deny.value = null; flash.value = "";
  delBusy.value = username;
  try {
    await api(`/admin/accounts/${username}/delete`, { method: "POST" });
    flash.value = `✓ 已删除孤儿账户 ${username}（用户名已释放）`;
    await refresh();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "delete_failed", message: err.message ?? String(e) };
  } finally { delBusy.value = ""; }
}

// ---- 吊销（B1 升格·两步式签名契约）：理由必填≥4 字+公示纪元+1 绑定+
// FZ-REVOKE|v1|{句柄排序串}|{reason}|{epoch} 域 SM2 签名。句柄集前端无法预知
// ——两步式：先 GET 预览端点取该用户有效凭证句柄与目标纪元，本地拼消息签名
// 后正式提交。成功展示联动撤销授权清单（linked_auth_ids）+台账回执。
const revokeUser = ref("");
const revokeReason = ref("");
const revokeConfirm = ref(false);
const revokeResult = ref<RevokeResult | null>(null);
// 确认态绑定用户名+理由：任一改动即撤回确认（防「看 A 批 B」误伤）
watch([revokeUser, revokeReason], () => { revokeConfirm.value = false; });
function prefillRevoke(username: string, reason: string): void {
  revokeUser.value = username;
  revokeReason.value = reason;
  revokeConfirm.value = false;
  revokeResult.value = null;
}
async function doRevoke(): Promise<void> {
  deny.value = null; flash.value = "";
  const username = revokeUser.value.trim();
  const reason = revokeReason.value.trim();
  if (!username) { deny.value = { code: "username_required", message: "请填写要吊销的用户名" }; return; }
  if (reason.length < 4) { deny.value = { code: "reason_required", message: "撤销理由须 ≥4 字（公示面必填——无理由强制撤销封堵）" }; return; }
  if (!sk.value) { deny.value = { code: "locked", message: "请先解锁管理员密钥（吊销须 SM2 签名留痕）" }; return; }
  if (!revokeConfirm.value) { revokeConfirm.value = true; return; }
  revokeConfirm.value = false;
  busy.value = true;
  try {
    // 两步式第一拍：句柄预览（admin 只读）——句柄集+目标纪元
    const preview = await api<{ username: string; handles: string[]; epoch: number }>(
      `/ra/revoke/by-username/preview?username=${encodeURIComponent(username)}`,
    );
    if (!preview.handles?.length) {
      deny.value = { code: "nothing_to_revoke", message: "该用户无有效凭证（无可吊销项）" };
      return;
    }
    // 第二拍：本地拼 FZ-REVOKE 消息签名后正式提交（epoch=公示纪元+1）
    const msg = revokeMsg(preview.handles, reason, preview.epoch);
    const sig_hex = signMsg(sk.value, msg);
    const out = await api<RevokeResult>("/ra/revoke/by-username", {
      method: "POST",
      body: JSON.stringify({ username, reason, sig_hex, epoch: preview.epoch }),
    });
    revokeResult.value = out;
    flash.value = `✓ 已吊销 ${username} 的 ${out.revoked_handles_hex?.length ?? 0} 项有效凭证——纪元推进至 ${out.epoch}，根已推链公示`;
    revokeUser.value = "";
    revokeReason.value = "";
    await refresh();
  } catch (e) {
    const err = e as ApiError;
    const hint = err.status === 404 ? "（预览端点不可用——后端需部署两步式预览端点）" : "";
    deny.value = { code: err.code ?? "revoke_failed", message: (err.message ?? String(e)) + hint };
  } finally { busy.value = false; }
}

// ---- 恢复双控·发起（B6·admin 第一签）：公示撤销清单逐叶「发起恢复」——
// FZ-RESTORE|v1|{handle}|{reason} 签名→pending 请求落库（单签不执行，
// 审计台复核第二签后才摘叶推链）----
const revokedLeaves = ref<SnapshotLeaf[]>([]);
const snapshotEpoch = ref<number | null>(null);
const snapAvailable = ref(true);
const restores = ref<RestoreRequestRow[]>([]);
const restoresAvailable = ref(true);
const restoreTarget = ref<SnapshotLeaf | null>(null);
const restoreReason = ref("");
const restoreBusyId = ref<string | null>(null);
async function refreshRevocation(): Promise<void> {
  try {
    const snap = await api<{ epoch: number; revoked: SnapshotLeaf[] }>("/ra/revocation/snapshot");
    revokedLeaves.value = snap.revoked ?? [];
    snapshotEpoch.value = snap.epoch ?? null;
    snapAvailable.value = true;
  } catch { snapAvailable.value = false; }
}
async function refreshRestores(): Promise<void> {
  try {
    restores.value = (await api<{ items: RestoreRequestRow[] }>("/ra/restore/requests")).items;
    restoresAvailable.value = true;
  } catch { restoresAvailable.value = false; }
}
function pickRestore(leaf: SnapshotLeaf): void {
  restoreTarget.value = leaf;
  restoreReason.value = "";
  deny.value = null;
}
async function requestRestore(): Promise<void> {
  deny.value = null; flash.value = "";
  const leaf = restoreTarget.value;
  const reason = restoreReason.value.trim();
  if (!leaf) { deny.value = { code: "no_target", message: "请先在公示撤销清单中选择要恢复的凭证" }; return; }
  if (reason.length < 4) { deny.value = { code: "reason_required", message: "恢复理由须 ≥4 字（公示面必填）" }; return; }
  if (!sk.value) { deny.value = { code: "locked", message: "请先解锁管理员密钥（发起恢复须签名留痕）" }; return; }
  restoreBusyId.value = leaf.handle_hex;
  busy.value = true;
  try {
    const sig = signMsg(sk.value, restoreMsg(leaf.handle_hex, reason));
    await api("/ra/restore/request", {
      method: "POST",
      body: JSON.stringify({ handle_hex: leaf.handle_hex, reason, sig_hex: sig }),
    });
    flash.value = "✓ 恢复请求已立案（单签不执行）——待审计台复核第二签后生效";
    restoreTarget.value = null;
    restoreReason.value = "";
    await Promise.all([refreshRestores(), refreshRevocation()]);
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "restore_failed", message: err.message ?? String(e) };
  } finally { restoreBusyId.value = null; busy.value = false; }
}

// ---- 处置待办（A5/B2：结案属实→吊销处置的待办面）——后端并行开发中：
// 404/网络不可达即整卡优雅隐藏，不谎称空 ----
const todos = ref<DisposalTodo[]>([]);
const todosAvailable = ref(true);
const todosLoaded = ref(false);
const resolveBusyId = ref<number | null>(null);
async function refreshTodos(): Promise<void> {
  try {
    todos.value = (await api<{ items: DisposalTodo[] }>("/admin/disposal-todos")).items ?? [];
    todosAvailable.value = true;
  } catch {
    todosAvailable.value = false;
  }
  todosLoaded.value = true;
}
/** 去吊销（预填）：用户名+理由（案号+结论）带入吊销表单——处置闭环第一步。 */
function goRevoke(t: DisposalTodo): void {
  prefillRevoke(
    t.username,
    `案号 ${t.case_no} 审计结案结论「${conclusionLabel(t.conclusion)}」——依终局判词吊销该当事人全部有效凭证`,
  );
  flash.value = `✓ 已按待办 #${t.id} 预填吊销表单（${t.username}）——核对理由后签名执行`;
  document.getElementById("revoke-panel")?.scrollIntoView?.({ behavior: "smooth", block: "start" });
}
async function resolveTodo(t: DisposalTodo): Promise<void> {
  deny.value = null; flash.value = "";
  resolveBusyId.value = t.id;
  try {
    await api(`/admin/disposal-todos/${t.id}/resolve`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    flash.value = `✓ 待办 #${t.id} 已标记处理`;
    await refreshTodos();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "resolve_failed", message: err.message ?? String(e) };
  } finally { resolveBusyId.value = null; }
}

// ---- 历史签名复验（A3）：台账行就地调 /admin/collab-requests/{id}/verify-sigs ----
const sigs = ref<Record<number, VerifySigsOut>>({});
const sigsBusyId = ref<number | null>(null);
async function checkSigs(r: ReqView): Promise<void> {
  deny.value = null;
  sigsBusyId.value = r.id;
  try {
    sigs.value[r.id] = await api<VerifySigsOut>(`/admin/collab-requests/${r.id}/verify-sigs`);
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "verify_sigs_failed", message: err.message ?? String(e) };
  } finally { sigsBusyId.value = null; }
}
</script>

<template>
  <div class="fz-enter">
    <!-- 头部横幅：渐变+粒子（与审计台同语言） -->
    <div class="fz-hero-band fz-ticks">
      <ParticleField />
      <FzWatermark glyph="gov" />
      <div class="fz-hero-inner">
        <div class="fz-hero-title">机构工作台</div>
        <div class="fz-hero-sub">协同审批 · 出函台账 · 凭证吊销 · 每一步签名可追责</div>
        <div class="fz-kpi-row">
          <div class="fz-kpi"><span class="fz-kpi-n amber">{{ kpiPending }}</span><span class="fz-kpi-l">待批准</span></div>
          <div class="fz-kpi"><span class="fz-kpi-n blue">{{ kpiExecuting }}</span><span class="fz-kpi-l">执行中</span></div>
          <div class="fz-kpi"><span class="fz-kpi-n red">{{ kpiFailed }}</span><span class="fz-kpi-l">执行失败</span></div>
          <div class="fz-kpi"><span class="fz-kpi-n gold">{{ kpiDone }}</span><span class="fz-kpi-l">已结案</span></div>
          <div class="fz-kpi"><span class="fz-kpi-n teal">{{ kpiAccounts }}</span><span class="fz-kpi-l">账户数</span></div>
        </div>
      </div>
    </div>

    <!-- ⓪ 处置待办（A5/B2）：审计结案「属实」→ 机构处置的交接面——后端
        并行开发中，404/不可达即整卡隐藏（todosAvailable=false） -->
    <div class="panel" v-if="todosAvailable">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
        <h2 style="margin:0">待处置（审计结案交接）</h2>
        <span class="fz-pill amber" v-if="todos.filter((t) => t.status === 'pending').length">
          {{ todos.filter((t) => t.status === "pending").length }} 项待处置
        </span>
        <span class="fz-pill gray" v-else-if="todosLoaded">暂无待处置</span>
      </div>
      <p class="desc">审计员结案结论「属实」的案件在此汇为处置待办——核对后「去吊销」（已预填用户名与理由）或标记已处理。</p>
      <div v-if="!todosLoaded" class="fz-skelset" aria-hidden="true" style="max-width:420px">
        <div class="fz-skel" style="width:80%"></div>
        <div class="fz-skel" style="width:58%"></div>
      </div>
      <FzEmpty v-else-if="!todos.length" text="暂无待处置案件——审计结案属实后自动汇入。" icon="inbox" />
      <div v-else class="req-list">
        <div v-for="t in todos" :key="t.id" class="todo-row" :class="{ done: t.status === 'done' }">
          <div class="req-main">
            <span class="mono case">{{ t.case_no }}</span>
            <span class="fz-badge" :class="conclusionTone(t.conclusion)">{{ conclusionLabel(t.conclusion) }}</span>
            <span class="fz-badge" :class="t.status === 'pending' ? 'amber' : 'gray'">
              {{ t.status === "pending" ? "待处置" : "已处理" }}
            </span>
          </div>
          <div class="req-meta">当事人 <span class="mono">{{ t.username }}</span> · {{ t.created_ts?.slice(5, 16).replace("T", " ") ?? "—" }}</div>
          <div class="req-meta" v-if="t.resolved_note">处理备注：{{ t.resolved_note }}</div>
          <div class="req-actions" style="display:flex;gap:8px;margin-top:4px" v-if="t.status === 'pending'">
            <button class="btn sm" @click="goRevoke(t)">去吊销</button>
            <button class="btn sm ghost" :disabled="resolveBusyId === t.id" @click="resolveTodo(t)">
              {{ resolveBusyId === t.id ? "提交中…" : "标记已处理" }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- ① 待批协作 -->
    <div class="panel">
      <h2>待批协作请求</h2>
      <p class="desc">
        每张卡是审计员的一次协同解锁申请——依据原文、调查理由、目标与签名指纹完整在列。
        看明白后批准（您签名后系统自动出函+解锁）或驳回（理由必填）。
      </p>
      <template v-if="!unlockedOnce">
        <label>解锁管理员密钥（密码——仅在解锁瞬间使用）</label>
        <input v-model="unlockPass" type="password" @keyup.enter="doUnlock" />
        <p v-if="unlockErr" class="step-err">{{ unlockErr }}</p>
        <button class="btn ghost" @click="doUnlock">解锁密钥</button>
      </template>
      <template v-if="pending.length === 0">
        <div v-if="!loaded" class="fz-skelset" aria-hidden="true" style="max-width:420px">
          <div class="fz-skel" style="width:88%"></div>
          <div class="fz-skel" style="width:70%"></div>
          <div class="fz-skel" style="width:52%"></div>
        </div>
        <FzEmpty v-else text="暂无待批请求。" icon="inbox" />
      </template>
      <div v-for="r in pending" :key="r.id" class="req-card fz-enter" :class="[r.status, { 'fz-converge': convergedId === r.id }]"
           @animationend="onConvergeEnd(r.id, $event)">
        <div class="req-head">
          <span class="case mono">{{ r.case_no }}</span>
          <span class="fz-badge" :class="{
            pending: 'amber', approved: 'blue', executing: 'blue', execute_failed: 'red',
          }[r.status] ?? 'gray'">{{
            { pending: '待批准', approved: '已批准 · 待执行', executing: '执行中', execute_failed: '执行失败' }[r.status] ?? r.status
          }}</span>
        </div>
        <!-- 双钥汇流图（丙-2 M3 装饰层）：审计员钥+管理员钥 → req_fp；
             待批准时右钥灰点虚位——「缺一不可」叙事 -->
        <FzConfluence class="req-cf" :auditor-fp="r.auditor_fp"
          :admin-fp="r.admin_fp ?? r.fzc2_fingerprint_hex" :req-fp="r.req_fp" />
        <div v-if="r.status === 'approved' || r.status === 'executing'" class="exec-hint">系统自动出函与解锁进行中——完成后状态自动流转…</div>
        <div v-if="r.status === 'execute_failed'" class="exec-err">⚠ {{ r.execute_error }}（可重试）</div>
        <div class="kv">
          <dt>立案依据原文</dt><dd>{{ r.legal_basis_text ?? "—（历史案卷无原文）" }}</dd>
          <dt>审计员理由</dt><dd>{{ r.note }}</dd>
          <dt>目标授权编号</dt><dd class="mono">{{ r.target_auth_id ?? "—（未指定——不可自动执行）" }}</dd>
          <dt>令状哈希</dt><dd class="mono">{{ r.warrant_hash_hex.slice(0, 24) }}…</dd>
          <dt>发函人</dt><dd class="mono">{{ r.auditor_username }}（密钥指纹 {{ r.auditor_fp }}…）</dd>
          <dt>请求指纹</dt><dd class="mono">{{ r.req_fp ?? "—" }}</dd>
        </div>
        <div v-if="r.status === 'pending'" style="display:flex;gap:10px;margin-top:10px;align-items:center">
          <button class="btn" :disabled="busy || !unlockedOnce" @click="approve(r)">
            {{ busy ? "签名批准中…" : "批准（签名后自动执行解锁）" }}
          </button>
          <button class="btn ghost" style="border-color:#d98484;color:#a33" @click="rejecting = rejecting === r.id ? null : r.id">
            驳回
          </button>
        </div>
        <div v-if="r.status === 'execute_failed'" style="margin-top:10px">
          <button class="btn" :disabled="busy" @click="retry(r)">重试执行</button>
        </div>
        <div v-if="rejecting === r.id" style="margin-top:8px">
          <label>驳回理由（必填——审计员可见）</label>
          <textarea v-model="rejectReason" rows="2"></textarea>
          <button class="btn" style="border-color:#d98484;color:#a33" :disabled="busy || !unlockedOnce" @click="reject(r)">
            确认驳回
          </button>
        </div>
      </div>
      <p v-if="flash" class="flash">{{ flash }}</p>
      <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
    </div>

    <!-- ② 协作台账 -->
    <div class="panel">
      <h2>协作台账</h2>
      <p class="desc">发函/批准/执行全程带签名指纹——每一步可追责到人。</p>
      <div class="tbl-wrap" v-if="history.length">
        <table class="tbl">
          <thead><tr><th>案号</th><th>状态</th><th>审计员</th><th>批准人</th><th>函指纹</th><th>执行时间</th><th>签名复验</th></tr></thead>
          <tbody>
            <tr v-for="r in history" :key="r.id">
              <td class="mono">{{ r.case_no }}</td>
              <td><StatusTag :tone="LEDGER_TONE[r.status] ?? 'ok'" :label="{ executed: '已执行·待结案', closed: '已结案', rejected: '已驳回' }[r.status] ?? r.status" /></td>
              <td class="mono">{{ r.auditor_username }}</td>
              <td class="mono">{{ r.admin_username ?? "—" }}</td>
              <td class="mono">{{ r.fzc2_fingerprint_hex ?? "—" }}</td>
              <td>{{ r.executed_ts ?? r.decided_ts ?? "—" }}</td>
              <td>
                <button class="btn sm ghost" :disabled="sigsBusyId === r.id" @click="checkSigs(r)">
                  {{ sigsBusyId === r.id ? "复验中…" : "验签复核" }}
                </button>
                <div v-if="sigs[r.id]" class="sigs-out">
                  <span class="sigs-line" :class="{ bad: sigs[r.id].auditor.ok === false }">{{ verdictLabel(sigs[r.id].auditor, "审计员签") }}</span>
                  <span class="sigs-line" :class="{ bad: sigs[r.id].admin.ok === false }">{{ verdictLabel(sigs[r.id].admin, "管理员签") }}</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else-if="!loaded" class="fz-skelset" aria-hidden="true" style="max-width:420px">
        <div class="fz-skel" style="width:80%"></div>
        <div class="fz-skel" style="width:60%"></div>
      </div>
      <FzEmpty v-else text="台账空——尚无已办结的协作请求。" icon="doc" />
    </div>

    <!-- ③ 出函台账（FZC2）——mega-panel 拆分（视觉 S 批 S7）：原③一块大面板
        拆为四个 .panel，全部文本原样保留 -->
    <div class="panel">
      <h2>出函台账（FZC2）</h2>
      <div class="tbl-wrap" v-if="overview?.collab_ledger?.length">
        <table class="tbl">
          <thead><tr><th>令状哈希</th><th>函指纹</th><th>出具时间</th></tr></thead>
          <tbody>
            <tr v-for="(l, i) in overview.collab_ledger" :key="i">
              <td class="mono">{{ l.warrant_hash_hex.slice(0, 24) }}…</td>
              <td class="mono">{{ l.code_fingerprint_hex }}</td>
              <td>{{ l.issued_at ?? "—" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else-if="!loadedOv" class="fz-skelset" aria-hidden="true" style="max-width:420px">
        <div class="fz-skel" style="width:76%"></div>
        <div class="fz-skel" style="width:58%"></div>
      </div>
      <FzEmpty v-else text="尚无出函记录（出函只在批准时自动发生）。" icon="stamp" />
    </div>

    <!-- ④ 凭证吊销（B1 升格·两步式签名契约）+ 恢复双控发起（B6） -->
    <div class="panel" id="revoke-panel">
      <h2>凭证吊销</h2>
      <p class="desc">
        按人级联吊销：该用户全部有效凭证一次撤销（同纪元同根一次推链，即时生效）。
        吊销须理由（≥4 字，公示面必填）+您的密钥签名——签名覆盖该用户全部有效凭证
        句柄串与目标纪元（公示纪元+1），两步式：先预览句柄，签名后正式提交。
      </p>
      <div style="display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap">
        <input v-model="revokeUser" class="mono" placeholder="用户名" style="width:220px" />
      </div>
      <label>撤销理由（必填 ≥4 字——随叶落公示镜像，任何人可查）</label>
      <textarea v-model="revokeReason" rows="2" placeholder="例：审计结案结论属实——围栏违规成立，依规吊销"></textarea>
      <div style="display:flex;gap:10px;margin-top:10px;align-items:center">
        <button class="btn" style="border-color:#d98484;color:var(--tone-red-fg)" :disabled="busy" @click="doRevoke">
          {{ revokeConfirm ? "确认吊销（签名并推链）" : "吊销" }}
        </button>
        <span v-if="snapshotEpoch != null" class="note">当前公示纪元 <b class="mono">{{ snapshotEpoch }}</b>——签名将绑定纪元 {{ snapshotEpoch + 1 }}</span>
      </div>
      <div v-if="revokeConfirm && revokeUser.trim()" class="deny fz-enter">
        <span class="code">二次确认</span>
        将吊销 <b class="mono">{{ revokeUser.trim() }}</b> 的全部有效凭证（含授权轴联动与证件黑名单）——纪元根即时推链、不可撤销。确认执行？
        <button class="btn" style="margin-left:10px" :disabled="busy" @click="doRevoke">确认吊销</button>
        <button class="btn ghost" style="margin-left:8px" @click="revokeConfirm = false">取消</button>
      </div>

      <!-- 吊销回执：联动撤销授权清单+台账指针（B1 升格展示面） -->
      <div v-if="revokeResult" class="fp-box fz-enter">
        <span class="fp-label">吊销回执（append-only 台账 #{{ revokeResult.ledger_id }}）</span>
        <div class="kv" style="margin-top:4px">
          <dt>新纪元 / 根</dt><dd class="mono">epoch {{ revokeResult.epoch }} · {{ revokeResult.root_hex.slice(0, 24) }}…</dd>
          <dt>撤销凭证</dt><dd class="mono">{{ (revokeResult.revoked_handles_hex ?? []).join("  ") }}</dd>
          <dt>联动撤销授权</dt>
          <dd class="mono">{{ revokeResult.linked_auth_ids?.length ? revokeResult.linked_auth_ids.map((a) => `#${a}`).join(" ") : "—（无在案授权）" }}</dd>
        </div>
      </div>

      <div class="panel-head" style="margin-top:20px">
        <h2 style="font-size:15px">公示撤销清单</h2>
        <span class="fz-pill gray" v-if="snapshotEpoch != null">纪元 {{ snapshotEpoch }} · {{ revokedLeaves.length }} 叶</span>
      </div>
      <p class="desc">公示镜像的撤销叶（含子钥传播叶）——主凭证句柄可发起恢复（B6 双控：您发起，审计台复核后才执行）。</p>
      <div v-if="!snapAvailable" class="note">公示镜像不可达——恢复发起暂不可用（下轮自动重试）。</div>
      <FzEmpty v-else-if="!revokedLeaves.length" text="撤销集为空——尚无已吊销凭证。" icon="doc" />
      <div v-else class="tbl-wrap">
        <table class="tbl">
          <thead><tr><th>句柄</th><th>理由</th><th>纪元</th><th>执行人</th><th>时间</th><th></th></tr></thead>
          <tbody>
            <tr v-for="leaf in revokedLeaves" :key="leaf.handle_hex" :class="{ 'row-on': restoreTarget?.handle_hex === leaf.handle_hex }">
              <td class="mono">{{ leaf.handle_hex.slice(0, 16) }}…</td>
              <td>{{ leaf.reason }}</td>
              <td class="mono">{{ leaf.epoch }}</td>
              <td class="mono">{{ leaf.revoked_by }}</td>
              <td>{{ leaf.revoked_at?.slice(5, 16).replace("T", " ") ?? "—" }}</td>
              <td>
                <button class="btn sm ghost" :disabled="restoreBusyId === leaf.handle_hex" @click="pickRestore(leaf)">
                  {{ restoreTarget?.handle_hex === leaf.handle_hex ? "已选中" : "发起恢复" }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <template v-if="restoreTarget">
        <div class="gate fz-enter" style="margin-top:10px">
          <div class="gate-title">发起恢复：<span class="mono">{{ restoreTarget.handle_hex.slice(0, 24) }}…</span></div>
          <p class="desc" style="margin-bottom:6px">
            单签不执行——您签 FZ-RESTORE 域后请求落 pending，审计台复核第二签（FZ-RESTORE-COUNTERSIGN 域）才摘叶推链。
          </p>
          <label>恢复理由（必填 ≥4 字）</label>
          <textarea v-model="restoreReason" rows="2" placeholder="例：误吊销——经复核凭证与设备均无异常"></textarea>
          <div style="display:flex;gap:10px;margin-top:8px">
            <button class="btn" :disabled="busy || !unlockedOnce" @click="requestRestore">
              {{ busy ? "签名发起中…" : "签名并发起恢复请求" }}
            </button>
            <button class="btn ghost" @click="restoreTarget = null">取消</button>
          </div>
        </div>
      </template>

      <div class="panel-head" style="margin-top:20px">
        <h2 style="font-size:15px">恢复请求台账</h2>
        <span class="fz-pill gray" v-if="restoresAvailable">pending 待复核 / executed 已恢复</span>
      </div>
      <div v-if="!restoresAvailable" class="note">恢复台账不可达（后端未就绪时本区自动隐藏）。</div>
      <FzEmpty v-else-if="!restores.length" text="尚无恢复请求。" icon="doc" />
      <div v-else class="req-list">
        <div v-for="row in restores" :key="row.id" class="req-row" :class="row.status === 'pending' ? 'amber' : 'gold'">
          <div class="req-main">
            <span class="mono case-mini">{{ row.handle_hex.slice(0, 16) }}…</span>
            <span class="fz-badge" :class="row.status === 'pending' ? 'amber' : 'gold'">
              {{ row.status === "pending" ? "待复核" : row.status === "executed" ? "已恢复" : row.status }}
            </span>
          </div>
          <div class="req-meta">发起人 <span class="mono">{{ row.requested_by }}</span> · {{ row.created_ts?.slice(5, 16).replace("T", " ") ?? "—" }} · 理由：{{ row.reason }}</div>
          <div class="req-meta" v-if="row.status === 'executed'">复核人 <span class="mono">{{ row.countersign_by ?? "—" }}</span> · {{ row.executed_ts?.slice(5, 16).replace("T", " ") ?? "—" }}</div>
          <div class="req-err" v-if="row.execute_error">⚠ {{ row.execute_error }}</div>
        </div>
      </div>
      <p v-if="flash" class="flash">{{ flash }}</p>
      <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
    </div>

    <!-- ⑤ 账户总览 -->
    <div class="panel">
      <h2>账户总览</h2>
      <p class="desc">机构账户密码重置已收回离线（部署方线下执行 seed 脚本）——线上任何角色（含管理员自己）都不能重置任何机构账户密码；每次重置逐笔记入下方台账。</p>
      <div class="tbl-wrap" v-if="overview?.accounts?.length">
        <table class="tbl">
          <thead><tr><th>用户名</th><th>角色</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="a in overview.accounts" :key="a.username">
              <td class="mono">{{ a.username }}</td>
              <td>{{ { pilot: "飞手", auditor: "审计员", admin: "机构管理员" }[a.role] ?? a.role }}</td>
              <td><StatusTag tone="accent" :label="{ pending_profile: '待补资料', pending_activation: '待激活', active: '已激活' }[a.status] ?? a.status" /></td>
              <td>
                <template v-if="a.status === 'pending_profile'">
                  <button class="btn sm ghost" style="border-color:#d98484;color:var(--tone-red-fg)" :disabled="delBusy === a.username" @click="deleteOrphan(a.username)">
                    {{ delBusy === a.username ? "删除中…" : "删除孤儿户" }}
                  </button>
                </template>
                <template v-else>—</template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else-if="!loadedOv" class="fz-skelset" aria-hidden="true" style="max-width:420px">
        <div class="fz-skel" style="width:64%"></div>
        <div class="fz-skel" style="width:48%"></div>
      </div>
    </div>

    <!-- ⑥ 账户管理台账 -->
    <div class="panel">
      <h2>账户管理台账</h2>
      <p class="desc">密码重置等敏感动作逐笔留痕（append-only）——唯一路径=离线种子脚本，动作/operator 全程可审计。</p>
      <div class="tbl-wrap" v-if="overview?.reset_log?.length">
        <table class="tbl">
          <thead><tr><th>时间</th><th>动作</th><th>账户</th><th>操作者</th><th>明细</th></tr></thead>
          <tbody>
            <tr v-for="(g, i) in overview.reset_log" :key="i">
              <td class="mono">{{ g.ts ?? "—" }}</td>
              <td>{{ { password_reset: "密码重置", reseed_pending: "待激活重设" }[g.action] ?? g.action }}</td>
              <td class="mono">{{ g.username }}</td>
              <td class="mono">{{ g.operator }}</td>
              <td class="mono">{{ g.detail ?? "—" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else-if="!loadedOv" class="fz-skelset" aria-hidden="true" style="max-width:420px">
        <div class="fz-skel" style="width:70%"></div>
        <div class="fz-skel" style="width:52%"></div>
      </div>
      <FzEmpty v-else text="尚无账户管理动作（无重置发生=常态）。" icon="doc" />
    </div>
  </div>
</template>

<style scoped>
.req-card { border: var(--hairline); border-radius: var(--r-md); padding: 14px 16px; margin-top: 12px; background: var(--panel-2, transparent); border-left-width: 4px; }
/* 列表 stagger（视觉深化批 D：依次入场 30ms 递增封顶 8 张——编排引导一次视线） */
.req-card:nth-child(2) { animation-delay: 30ms; }
.req-card:nth-child(3) { animation-delay: 60ms; }
.req-card:nth-child(n+4) { animation-delay: 90ms; }
.req-card.pending { border-left-color: #d9963a; }
.req-card.approved { border-left-color: var(--tone-blue-fg); }
.req-card.execute_failed { border-left-color: #c0392b; }
.exec-hint { font-size: 12.5px; color: var(--tone-blue-fg); }
.exec-err { font-size: 12.5px; color: #a33; }

.req-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.req-head .case { font-weight: 700; }
.req-cf { margin: 2px 0 8px; } /* 双钥汇流图落位（丙-2 M3） */
.tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.btn.sm { padding: 4px 12px; font-size: 12px; margin-right: 6px; }
.tbl th { text-align: left; color: var(--ink-3); font-weight: 600; padding: 6px 10px; border-bottom: var(--hairline); }
.tbl td { padding: 8px 10px; border-bottom: 1px solid var(--line); }
.step-err { color: #c0392b; font-size: 12.5px; margin: 6px 0; }
.flash { color: var(--teal); font-size: 13px; margin-top: 10px; }

/* 待办卡/恢复清单行（升格批：与审计台 req-row 同语言——令牌化细边框+左色条） */
.req-list { display: grid; gap: 10px; }
.req-row {
  border: var(--hairline); border-radius: var(--r-md); padding: 12px 16px;
  background: var(--panel); display: grid; gap: 5px; border-left-width: 4px;
}
.req-row.amber { border-left-color: #d9963a; }
.req-row.gold { border-left-color: #b08d3e; }
.req-main { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.case-mini { font-weight: 700; font-size: 13.5px; }
.todo-row { transition: opacity var(--t-fast); }
.todo-row.done { opacity: 0.55; }
.req-meta { font-size: 12.5px; color: var(--ink-3); }
.req-hint { font-size: 12px; color: var(--ink-3); }
.req-err { font-size: 12.5px; color: var(--tone-red-fg); }
.req-actions { margin-top: 4px; }
.btn.sm { padding: 5px 14px; font-size: 12.5px; }

/* 验签判词行（A3） */
.sigs-out { display: grid; gap: 2px; margin-top: 6px; }
.sigs-line { font-size: 12px; color: var(--tone-teal-fg); }
.sigs-line.bad { color: var(--tone-red-fg); }
.tbl .row-on { background: var(--accent-soft); }

/* 吊销回执（B1）/恢复发起门（B6）——与审计台 fp-box 同语言 */
.fp-box {
  margin-top: 10px; padding: 10px 12px; border: var(--hairline);
  border-left: 3px solid var(--tone-gold-fg); border-radius: var(--r-sm);
  background: var(--panel-2); display: grid; gap: 6px;
}
.fp-label { font-size: 11.5px; color: var(--ink-3); }
</style>
