<script setup lang="ts">
/** 机构台（2026-09-29 账户批 B3；批二异步化）：机构管理员工作面——待批协作/
 * 台账/吊销。主线：收函（看明白为什么）→ 批准/驳回（管理员钥签）→ 留痕。
 * 批准即返回（后台自动出函+解锁——真链推链不再卡浏览器请求）；状态轮询
 * 流转：已批准·待执行 → 已执行 | 执行失败（可重试）。 */
import { onBeforeUnmount, onMounted, ref } from "vue";
import { api, ApiError } from "../lib/api";
import { signMsg, unlockSk } from "../lib/auth";
import { getCachedSk } from "../lib/keystore";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";
import ParticleField from "../components/ParticleField.vue";

const busy = ref(false);
const deny = ref<{ code: string; message: string } | null>(null);
const flash = ref("");

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

// KPI 指标带（与审计台同语言——机构视角五数；count-up：视觉深化批 C）
import { computed } from "vue";
import { useCountUp } from "../composables/useCountUp";
const kpiRaw = computed(() => ({
  pending: pending.value.filter((x) => x.status === "pending").length,
  executing: pending.value.filter((x) => x.status === "approved").length,
  failed: pending.value.filter((x) => x.status === "execute_failed").length,
  done: history.value.filter((x) => x.status === "closed").length,
  accounts: overview.value?.accounts?.length ?? 0,
}));
const kpiPending = useCountUp(computed(() => kpiRaw.value.pending));
const kpiExecuting = useCountUp(computed(() => kpiRaw.value.executing));
const kpiFailed = useCountUp(computed(() => kpiRaw.value.failed));
const kpiDone = useCountUp(computed(() => kpiRaw.value.done));
const kpiAccounts = useCountUp(computed(() => kpiRaw.value.accounts));

async function refresh(): Promise<void> {
  try {
    const all = (await api<{ items: ReqView[] }>("/admin/collab-requests")).items;
    pending.value = all.filter((x) => ["pending", "approved", "execute_failed"].includes(x.status));
    history.value = all.filter((x) => ["executed", "closed", "rejected"].includes(x.status));
  } catch { /* 401 由守卫层处理 */ }
  try { overview.value = await api<Overview>("/admin/overview"); } catch { overview.value = null; }
}

// 轮询（4s）：批准后的后台执行态流转自动可见（approved→executed/execute_failed）
let pollTimer: ReturnType<typeof setInterval> | null = null;
onMounted(() => {
  void refresh();
  pollTimer = setInterval(async () => {
    // 无条件轮询（同审计台 P1-7 根修：新 pending 请求自动出现，双控合流不靠 F5）
    try {
      const all = (await api<{ items: ReqView[] }>("/admin/collab-requests")).items;
      pending.value = all.filter((x) => ["pending", "approved", "execute_failed"].includes(x.status));
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

// ---- 吊销（机构本职——按人级销级联）----
const revokeUser = ref("");
async function doRevoke(): Promise<void> {
  deny.value = null; flash.value = "";
  if (!revokeUser.value.trim()) { deny.value = { code: "username_required", message: "请填写要吊销的用户名" }; return; }
  busy.value = true;
  try {
    await api("/ra/revoke/by-username", {
      method: "POST",
      body: JSON.stringify({ username: revokeUser.value.trim(), reason: "机构管理员吊销（机构台）" }),
    });
    flash.value = `✓ 已吊销 ${revokeUser.value.trim()} 的全部有效凭证（纪元根已推链）`;
    revokeUser.value = "";
    await refresh();
  } catch (e) {
    const err = e as ApiError;
    deny.value = { code: err.code ?? "revoke_failed", message: err.message ?? String(e) };
  } finally { busy.value = false; }
}
</script>

<template>
  <div class="fz-enter">
    <!-- 头部横幅：渐变+粒子（与审计台同语言） -->
    <div class="fz-hero-band fz-ticks">
      <ParticleField />
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
      <div v-if="pending.length === 0" class="note">暂无待批请求。</div>
      <div v-for="r in pending" :key="r.id" class="req-card fz-enter" :class="r.status">
        <div class="req-head">
          <span class="case mono">{{ r.case_no }}</span>
          <span class="fz-badge" :class="{
            pending: 'amber', approved: 'blue', execute_failed: 'red',
          }[r.status] ?? 'gray'">{{
            { pending: '待批准', approved: '已批准 · 待执行', execute_failed: '执行失败' }[r.status] ?? r.status
          }}</span>
        </div>
        <div v-if="r.status === 'approved'" class="exec-hint">系统自动出函与解锁进行中——完成后状态自动流转…</div>
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
      <table class="tbl" v-if="history.length">
        <thead><tr><th>案号</th><th>状态</th><th>审计员</th><th>批准人</th><th>函指纹</th><th>执行时间</th></tr></thead>
        <tbody>
          <tr v-for="r in history" :key="r.id">
            <td class="mono">{{ r.case_no }}</td>
            <td><StatusTag :tone="r.status === 'rejected' ? 'bad' : 'ok'" :label="{ executed: '已执行·待结案', closed: '已结案', rejected: '已驳回' }[r.status] ?? r.status" /></td>
            <td class="mono">{{ r.auditor_username }}</td>
            <td class="mono">{{ r.admin_username ?? "—" }}</td>
            <td class="mono">{{ r.fzc2_fingerprint_hex ?? "—" }}</td>
            <td>{{ r.executed_ts ?? r.decided_ts ?? "—" }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="note">台账空——尚无已办结的协作请求。</p>
    </div>

    <!-- ③ 出函台账 + 账户总览 + 吊销 -->
    <div class="panel">
      <h2>出函台账（FZC2）</h2>
      <table class="tbl" v-if="overview?.collab_ledger?.length">
        <thead><tr><th>令状哈希</th><th>函指纹</th><th>出具时间</th></tr></thead>
        <tbody>
          <tr v-for="(l, i) in overview.collab_ledger" :key="i">
            <td class="mono">{{ l.warrant_hash_hex.slice(0, 24) }}…</td>
            <td class="mono">{{ l.code_fingerprint_hex }}</td>
            <td>{{ l.issued_at ?? "—" }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="note">尚无出函记录（出函只在批准时自动发生）。</p>

      <h2 style="margin-top:18px">凭证吊销</h2>
      <p class="desc">按人级联吊销：该用户全部有效凭证一次撤销（同纪元同根一次推链，即时生效）。</p>
      <div style="display:flex;gap:10px;align-items:center">
        <input v-model="revokeUser" class="mono" placeholder="用户名" style="width:220px" />
        <button class="btn" style="border-color:#d98484;color:#a33" :disabled="busy" @click="doRevoke">吊销</button>
      </div>

      <h2 style="margin-top:18px">账户总览</h2>
      <p class="desc">机构账户密码重置已收回离线（部署方线下执行 seed 脚本）——线上任何角色（含管理员自己）都不能重置任何机构账户密码；每次重置逐笔记入下方台账。</p>
      <table class="tbl" v-if="overview?.accounts?.length">
        <thead><tr><th>用户名</th><th>角色</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="a in overview.accounts" :key="a.username">
            <td class="mono">{{ a.username }}</td>
            <td>{{ { pilot: "飞手", auditor: "审计员", admin: "机构管理员" }[a.role] ?? a.role }}</td>
            <td><StatusTag tone="accent" :label="{ pending_profile: '待补资料', pending_activation: '待激活', active: '已激活' }[a.status] ?? a.status" /></td>
            <td>
              <template v-if="a.status === 'pending_profile'">
                <button class="btn sm ghost" style="border-color:#d98484;color:#a33" :disabled="delBusy === a.username" @click="deleteOrphan(a.username)">
                  {{ delBusy === a.username ? "删除中…" : "删除孤儿户" }}
                </button>
              </template>
              <template v-else>—</template>
            </td>
          </tr>
        </tbody>
      </table>

      <h2 style="margin-top:18px">账户管理台账</h2>
      <p class="desc">密码重置等敏感动作逐笔留痕（append-only）——唯一路径=离线种子脚本，动作/operator 全程可审计。</p>
      <table class="tbl" v-if="overview?.reset_log?.length">
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
      <p v-else class="note">尚无账户管理动作（无重置发生=常态）。</p>
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
.req-card.approved { border-left-color: #3b6ea5; }
.req-card.execute_failed { border-left-color: #c0392b; }
.exec-hint { font-size: 12.5px; color: #3b6ea5; }
.exec-err { font-size: 12.5px; color: #a33; }

.req-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.req-head .case { font-weight: 700; }
.tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.btn.sm { padding: 4px 12px; font-size: 12px; margin-right: 6px; }
.tbl th { text-align: left; color: var(--ink-3); font-weight: 600; padding: 6px 10px; border-bottom: var(--hairline); }
.tbl td { padding: 8px 10px; border-bottom: 1px solid var(--line); }
.step-err { color: #c0392b; font-size: 12.5px; margin: 6px 0; }
.flash { color: var(--teal); font-size: 13px; margin-top: 10px; }
</style>
