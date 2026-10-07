<script setup lang="ts">
/** 屏④留痕与合规证明（说明书 §7.3）：链头/检查点留痕面+TRAIL 出证闭环。
 * R3-2 包2（评审 P0-1）：「生成合规报告」装饰按钮退役——接桥接真出证管线
 * （/prove/trail/start→/prove/task 轮询→判决件三件套下载），把系统最硬的实测成果
 * （TRAIL n=128 服务器 prove 14.77s/verify 0.20s，性能档案 B6）产品化：
 * 出证完成渲染「TRAIL 合规证书卡」（verdict+SM3 摘要+耗时+第三方复验命令）。 */
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { bridge, bridgeBase, apiBase, ApiError } from "../lib/api";
import { logbookFindByAuthId, logbookUpdate } from "../lib/material";
import { runWasmVerify, type WasmVerifyResult } from "../lib/wasmVerify";
import HashText from "../components/HashText.vue";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";

const router = useRouter();
const authId = ref(localStorage.getItem("fzTrailAuthId") || "");
const deny = ref<{ code: string; message: string } | null>(null);

// 飞行屏采样的行数据（同浏览器持久化——留痕单一事实源在本机）
const rows = ref<any[]>([]);
const headHex = ref("");
const genesisHex = ref("");
// ---- 切页/刷新恢复（2026-09-29 切页修复）----
// 出证任务（task_id）与已出证书卡持久化：切页回来凭任务号续接同一任务
// （桥侧 _TASKS 仍在跑——不重跑不重复出证）；证书卡落 localStorage（可复显）。
const JOBS_KEY = "fzTrailJobs";
const CERTS_KEY = "fzTrailCerts";
const CASES_KEY = "fzTrailCaseIds";

function loadPersisted(): void {
  try { caseIds.value = JSON.parse(localStorage.getItem(CASES_KEY) || "{}"); } catch { caseIds.value = {}; }
  try { certs.value = JSON.parse(localStorage.getItem(CERTS_KEY) || "{}"); } catch { certs.value = {}; }
}

function saveCerts(): void {
  localStorage.setItem(CERTS_KEY, JSON.stringify(certs.value));
  localStorage.setItem(CASES_KEY, JSON.stringify(caseIds.value));
}

function loadJobs(): Record<string, string> {
  try { return JSON.parse(sessionStorage.getItem(JOBS_KEY) || "{}"); } catch { return {}; }
}

function saveJob(w: number, taskId: string | null): void {
  const jobs = loadJobs();
  if (taskId) jobs[String(w)] = taskId;
  else delete jobs[String(w)];
  sessionStorage.setItem(JOBS_KEY, JSON.stringify(jobs));
}

onMounted(() => {
  try { rows.value = JSON.parse(localStorage.getItem("fzTrailRows") || "[]"); } catch { rows.value = []; }
  headHex.value = localStorage.getItem("fzTrailHead") || "";
  genesisHex.value = localStorage.getItem("fzTrailGenesis") || "";
  loadPersisted();
  loadAltMax();
  refreshLogbookHit(); // 持久化证书回显形态也如实标注档案命中（非仅新出证）
  void resumeJobs();
});

/** 出证任务续接：切页回来对每个未完任务轮询到终态（done→取判决件；
 * failed→如实报错）——绝不重跑已提交的出证（重复出证=浪费+台账噪音）。 */
async function resumeJobs(): Promise<void> {
  const jobs = loadJobs();
  const ws = Object.keys(jobs).map(Number);
  if (!ws.length) return;
  proving.value = true;
  stage.value = "proving";
  stageAt.value = Date.now();
  ticker = setInterval(() => (elapsed.value = Math.round((Date.now() - stageAt.value) / 1000)), 1000);
  for (const w of ws) {
    const taskId = jobs[String(w)];
    try {
      for (;;) {
        let t: any;
        try {
          t = envelope(await bridge(`/prove/task/${taskId}`));
        } catch {
          await new Promise((r) => setTimeout(r, 2000));
          continue;
        }
        const status = t?.status ?? "";
        if (status === "done") break;
        if (status === "failed") throw new ApiError("prove_failed", t?.error ?? "出证失败", 0);
        await new Promise((r) => setTimeout(r, 2000));
      }
      if (!caseIds.value[w]) {
        try {
          const st = envelope(await bridge(`/prove/task/${taskId}`));
          if (st?.case_id) caseIds.value[w] = st.case_id;
        } catch { /* case_id 从任务详情回填失败——下方 fetchVerdict 会按窗口重查 */ }
      }
      windowSel.value = w;
      await fetchVerdict();
      saveJob(w, null);
    } catch (e: any) {
      deny.value = { code: e?.code ?? "trail_failed", message: e?.message ?? String(e) };
      saveJob(w, null);
    }
  }
  stage.value = "done";
  proving.value = false;
  if (ticker) clearInterval(ticker);
}

// 高度上限（厘米）=取件令牌 alt_max（米）×100——只读带出，杜绝手填错档
const altMaxCm = ref<number | null>(null);
function loadAltMax(): void {
  try {
    const raw = localStorage.getItem("fzTokenPayload") || "";
    if (!raw) return;
    const text = new TextDecoder().decode(hexToBytes(raw));
    const body = JSON.parse(text.slice(0, text.lastIndexOf("|")));
    if (typeof body.alt_max === "number") altMaxCm.value = body.alt_max * 100;
  } catch { /* 未取件——出证按钮引导先取件 */ }
}
function hexToBytes(h: string): Uint8Array {
  const s = h.trim();
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const ready = computed(() => rows.value.length >= 2 && headHex.value.length === 64);

// ---- 行程证书包（2026-09-28）：多窗口出证 ----
// 每 128 样本=一个可出证窗口（B6 定档）；采样超过 128 后窗口 1、2…解锁。
// 各窗口证书独立（自 GENESIS 重放），行程索引 JSON 汇总全部窗口案卷。
const nWindows = computed(() => Math.floor(rows.value.length / 128));
const windowSel = ref(0);
const caseIds = ref<Record<number, string>>({});
// 本飞行含围栏触发记录（FlightView 起链时清除——证书卡披露源）
const flightHadBreach = ref(localStorage.getItem("fzFlightFenceBreached") === "1");
const certs = ref<Record<number, TrailCert>>({});

async function downloadTripIndex(): Promise<void> {
  if (!authId.value) return;
  try {
    const res = await fetch(`${bridgeBase()}/prove/trip/index?auth_id=${authId.value}&download=1`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `trip-index-${authId.value}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e: any) {
    deny.value = { code: "trip_index_failed", message: `行程索引下载失败：${e?.message ?? e}` };
  }
}

// C-P0-1：自组 trail_job 的导出路径已删除——自拼 spec（绝对秒 t+锚链头）与
// 真出证数据面（段相对 500ms 网格+行字节重放链头）是两套口径，拿去 zkc 必被
// 装配器 fail-closed 拒（"换链头"）。第三方复验所需全部文件经下方案卷下载。

function persistAuthId(): void {
  localStorage.setItem("fzTrailAuthId", authId.value);
}
void persistAuthId; // 只读回显（登记绑定）——保留持久化入口供未来授权变更流程

// ---- TRAIL 出证闭环（R3-2 包2） ----
const proving = ref(false);
const stage = ref<"" | "proving" | "done">("");
const stageAt = ref(0);
const elapsed = ref(0);
interface TrailCert { verdict: string; bytes: number; prove_s: number; verify_s: number; sm3: string }
const cert = computed<TrailCert | null>(() => certs.value[windowSel.value] ?? null);
const caseId = computed(() => caseIds.value[windowSel.value] ?? "");
const refetching = ref(false);
let ticker: ReturnType<typeof setInterval> | null = null;

function envelope(t: any): any {
  return t && typeof t === "object" && "data" in t && t.data ? t.data : t;
}

/** 判决件取回（独立于出证）：案卷已在桥侧持久归档，取回失败=重试即可，
 * 无需重新出证。窗口内（Windows 写 ↔ WSL 读可见性延迟）由端点内+此处双
 * 层重试覆盖。取回目标=当前选中窗口的案卷。 */
async function fetchVerdict(): Promise<void> {
  const w = windowSel.value;
  if (!caseIds.value[w]) return;
  refetching.value = true; deny.value = null;
  try {
    let vj: any = null;
    for (let i = 0; i < 5; i++) {
      const v = await fetch(`${bridgeBase()}/prove/case/${caseIds.value[w]}/verdict.json`);
      if (v.ok) { vj = await v.json(); break; }
      if (i < 4) await new Promise((r) => setTimeout(r, 2000));
    }
    if (!vj) throw new ApiError("verdict_unavailable", "判决件暂不可读——案卷已保存，请点击「重新获取判决件」", 0);
    certs.value[w] = {
      verdict: vj.verdict, bytes: vj.bytes,
      prove_s: Math.round((vj.prove_s ?? 0) * 10) / 10,
      verify_s: Math.round((vj.verify_s ?? 0) * 10) / 10,
      sm3: vj.proof_sm3 ?? "",
    };
    // 档案回写（档案积累批）：判决入档——tripCaseIds/trailVerdicts 按窗口键
    // 累积到该授权的档案行（按授权编号合并：出证晚于 newFlight 时仍挂到
    // 已入档的统计行上；无行=no-op 不虚增）
    const aid = Number(authId.value);
    if (Number.isFinite(aid) && aid > 0) {
      logbookUpdate(aid, {
        tripCaseIds: { [w]: caseIds.value[w] },
        trailVerdicts: { [w]: { verdict: String(vj.verdict ?? ""), sm3: String(vj.proof_sm3 ?? "") } },
      });
    }
    refreshLogbookHit();
    deny.value = null;
  } catch (e: any) {
    deny.value = { code: e?.code ?? "verdict_unavailable", message: e?.message ?? String(e) };
  } finally {
    refetching.value = false;
  }
}

async function startTrailProve(): Promise<void> {
  const w = windowSel.value;
  proving.value = true; deny.value = null; delete certs.value[w]; stage.value = "proving";
  stageAt.value = Date.now();
  ticker = setInterval(() => (elapsed.value = Math.round((Date.now() - stageAt.value) / 1000)), 1000);
  try {
    const st = await bridge<{ task_id: string; case_id: string; window: number; n_windows: number }>("/prove/trail/start", {
      method: "POST",
      body: JSON.stringify({ alt_max_cm: altMaxCm.value ?? 12000, window: w }),
    });
    caseIds.value[w] = st.case_id;
    saveJob(w, st.task_id);
    saveCerts();
    let fails = 0;
    for (;;) {
      // C-P2-1：轮询容错（与申请页 pollWithRetry 同纪律）——连续 5 败才放弃
      let t: any;
      try {
        t = envelope(await bridge(`/prove/task/${st.task_id}`));
        fails = 0;
      } catch (e: any) {
        fails += 1;
        if (fails >= 5) throw new ApiError("poll_failed", `轮询连续失败 ${fails} 次——出证任务可能仍在进行，请稍后重试本页`, 0);
        await new Promise((r) => setTimeout(r, 2000));
        continue;
      }
      const status = t?.status ?? "";
      if (status === "done") break;
      if (status === "failed") throw new ApiError("prove_failed", t?.error ?? "出证失败", 0);
      await new Promise((r) => setTimeout(r, 2000));
    }
    stage.value = "done";
    ticker && clearInterval(ticker);
    saveJob(w, null);
    await fetchVerdict();
    saveCerts();
  } catch (e: any) {
    deny.value = { code: e?.code ?? "trail_failed", message: e?.message ?? String(e) };
    stage.value = "";
    saveJob(w, null);
  } finally {
    proving.value = false;
    if (ticker) clearInterval(ticker);
  }
}

function dlUrl(kind: string): string {
  return `${bridgeBase()}/prove/case/${caseId.value}/${kind}`;
}

// ---- 档案命中（档案积累批）：本判决是否已挂进「我的合规档案」——显式 ref
// 而非 computed（依赖 localStorage 非响应式域，fetchVerdict 回写后现查现刷） ----
const inLogbook = ref(false);
function refreshLogbookHit(): void {
  const aid = Number(authId.value);
  inLogbook.value = Number.isFinite(aid) && aid > 0 && !!logbookFindByAuthId(aid);
}
function goLogbook(): void {
  router.push("/chain");
}

// ---- 浏览器内验证（wasm 集成批）：zkc.wasm 经 WASI shim 在 Worker 内跑
// verify-instances——零服务端参与的第三方复验浏览器形态。 ----
const wvBusy = ref(false);
const wvLogs = ref<string[]>([]);
const wvResult = ref<WasmVerifyResult | null>(null);
async function verifyInBrowser(): Promise<void> {
  if (!caseId.value) return;
  wvBusy.value = true; wvLogs.value = []; wvResult.value = null;
  const base = apiBase();
  wvResult.value = await runWasmVerify({
    wasmUrl: `${base}/verify/dist/zkc.wasm`,
    specUrl: `${base}/verify/dist/trail_canonical_spec.json`,
    instancesUrl: dlUrl("instances.json"),
    proofUrl: dlUrl("proof.bin"),
    vpUrl: dlUrl("verifier_param.bin"),
    expectedUrl: dlUrl("expected.json"),
  }, (line) => { wvLogs.value.push(line); wvLogs.value = wvLogs.value.slice(-6); });
  wvBusy.value = false;
}

onBeforeUnmount(() => {
  if (ticker) clearInterval(ticker);
});
</script>

<template>
  <div class="fz-enter">
    <div class="panel">
      <h2>留痕与合规证明</h2>
      <p class="desc">飞行留痕在本机汇总，可对整段航迹生成 TRAIL 合规证书——逐样本高度验证+时间无隙+链头钉，任何第三方可独立复验。轨迹原始数据只存在本机。</p>

      <div class="kv fz-enter">
        <dt>飞行授权编号（取件后自动带出）</dt>
        <dd>
          <template v-if="authId"><input v-model="authId" class="mono" style="width:160px" readonly title="取件令牌的授权编号——出证按本机飞行链自动关联" /></template>
          <template v-else><span class="note">—（领取令牌后自动带出）</span></template>
        </dd>
        <dt>留痕样本</dt><dd>{{ rows.length }} 条 · 可出证窗口 {{ nWindows }}（每窗 128 条，TRAIL 定档）</dd>
        <dt>证书窗口</dt>
        <dd>
          <select v-model.number="windowSel" class="mono" style="width:230px" :disabled="nWindows === 0">
            <option v-if="nWindows === 0" :value="0">—（采样满 128 后可选）</option>
            <option v-for="w in nWindows" :key="w - 1" :value="w - 1">窗口 {{ w - 1 }}（样本 {{ (w - 1) * 128 + 1 }}–{{ w * 128 }}）</option>
          </select>
        </dd>
        <dt>起始锚（飞行链起点）</dt><dd><HashText v-if="genesisHex" :value="genesisHex" head="12" tail="8" /><span v-else>—</span></dd>
        <dt>本段链头</dt><dd><HashText v-if="headHex" :value="headHex" head="12" tail="8" /><span v-else>—</span></dd>
        <dt>高度上限（令牌带出）</dt>
        <dd>
          <template v-if="altMaxCm !== null">{{ altMaxCm }} cm（{{ altMaxCm / 100 }} m）</template>
          <template v-else><StatusTag tone="bad" label="未取件——请先到「令牌与飞行」取件" /></template>
        </dd>
      </div>

      <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:14px">
        <button
          class="btn"
          :disabled="proving || rows.length < 128 || altMaxCm === null"
          :title="rows.length < 128 ? `需 128 样本（当前 ${rows.length}）` : '对本段航迹出证'"
          @click="startTrailProve"
        >{{ proving ? "出证中…" : "生成 TRAIL 合规证书（本机出证）" }}</button>
      </div>
      <p v-if="rows.length < 128" class="note" style="margin-top:8px">
        还差 {{ 128 - rows.length }} 条样本——回「令牌与飞行」继续记录即可。
      </p>
      <p v-else-if="nWindows > 1" class="note" style="margin-top:8px">
        采样已覆盖 {{ nWindows }} 个窗口——每窗口独立出证，全部完成后可下载行程索引（一次飞行=多窗口证书包）。
      </p>
      <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:8px" v-if="authId">
        <button class="btn ghost" @click="downloadTripIndex">下载行程索引 JSON（全部窗口案卷清单）</button>
      </div>
      <p v-if="!authId" class="note" style="margin:6px 0 0">行程索引需授权编号——先完成一次起飞与取件。</p>
      <p style="margin:8px 0 0">
        <a :href="`${apiBase()}/verify/`" target="_blank" rel="noopener" class="note">验证工具分发页（Linux 二进制 / wasm / SHA-256 / 供应链公示）</a>
      </p>
      <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
      <div v-if="deny && caseId" style="margin-top:8px">
        <button class="btn ghost" :disabled="refetching" @click="fetchVerdict">
          {{ refetching ? "获取中…" : "重新获取判决件（无需重新出证）" }}
        </button>
      </div>

      <div v-if="stage === 'proving'" class="fz-enter" style="margin-top:14px; border-top: var(--hairline); padding-top: 14px">
        <div style="display:flex; gap:10px; align-items:center">
          <span class="spin" />
          <StatusTag tone="accent" :label="`TRAIL 出证中（窗口 ${windowSel} · 128 样本，本机约 1 分钟）…`" />
          <span class="note mono">已用时 {{ elapsed }}s</span>
        </div>
      </div>

      <div v-if="cert" class="fz-enter fz-cert-card" style="margin-top:14px; border-top: var(--hairline); padding-top: 14px">
        <div style="display:flex; gap:8px; align-items:center; margin-bottom:10px; flex-wrap:wrap">
          <StatusTag tone="ok" :label="`合规证书 ${cert.verdict}`" />
          <span class="note">窗口 {{ windowSel }} 的 128 样本逐点合规——未超高度上限、时间无空隙、链头未被篡改</span>
        </div>
        <div v-if="flightHadBreach" class="note fz-enter"
             style="margin-bottom:8px; border-left:3px solid #e0a855; padding-left:10px; color:#b7791f">
          ⚠ 本次飞行含围栏触发记录（固件事件已上链，审计台可取证）——本证书仅证明所选窗口 128 样本的合规性，不构成对越线尝试的豁免。
        </div>
        <div class="kv">
          <dt>证明体积</dt><dd>{{ cert.bytes.toLocaleString() }} B</dd>
          <dt>本机出证/验证耗时</dt><dd>{{ cert.prove_s }}s / {{ cert.verify_s }}s（本机实测口径）</dd>
          <dt>证明 SM3 摘要</dt><dd><HashText :value="cert.sm3" head="16" tail="10" /></dd>
          <dt>判决件与复验材料</dt>
          <dd style="display:flex; gap:8px; flex-wrap:wrap">
            <a class="btn ghost" :href="dlUrl('proof.bin')" download>proof.bin</a>
            <a class="btn ghost" :href="dlUrl('verifier_param.bin')" download>verifier_param.bin</a>
            <a class="btn ghost" :href="dlUrl('verdict.json')" download>verdict.json</a>
            <a class="btn ghost" :href="dlUrl('instances.json')" download>instances.json</a>
            <a class="btn ghost" :href="dlUrl('expected.json')" download>expected.json</a>
            <a class="btn ghost" :href="dlUrl('binding.json')" download title="引擎签名的高度授权绑定+链上锚定证据——第三方复核用">binding.json</a>
          </dd>
          <dt>第三方复验（两步，全部文件可下载）</dt>
          <dd>
            <span class="mono note">① expected.json 即上方下载件（已含本窗口链头），无需编辑</span><br />
            <span class="mono note">② zkc verify-instances --instances instances.json --proof proof.bin --vp verifier_param.bin --expected expected.json</span>
            <span class="note" style="display:block; font-size:11px; margin-top:2px">验证器校验的电路指纹与链上公示一致</span>
          </dd>
          <dt>浏览器内验证（零安装）</dt>
          <dd>
            <button class="btn ghost" :disabled="wvBusy" @click="verifyInBrowser">
              {{ wvBusy ? "验证器运行中（约 2 分钟，浏览器 JS 运行时）…" : "在本浏览器运行验证器（zkc.wasm）" }}
            </button>
            <div v-if="wvLogs.length" class="mono note" style="margin-top:6px; white-space:pre-line">{{ wvLogs.join("\n") }}</div>
            <template v-if="wvResult">
              <StatusTag v-if="wvResult.ok" tone="ok" :label="`浏览器内验证 OK（${(wvResult.ms / 1000).toFixed(0)}s）`" />
              <StatusTag v-else tone="bad" :label="`验证未通过（rc=${wvResult.rc}）`" />
            </template>
          </dd>
        </div>
        <p v-if="inLogbook" class="note fz-to-logbook" style="margin:10px 0 0">
          <a href="#/chain" @click.prevent="goLogbook">已入档案 →</a>
        </p>
      </div>
    </div>

    <div class="panel fz-enter">
      <h2>飞行记录明细</h2>
      <p class="desc">飞行明细只保存在本机，不会上传。</p>
      <table v-if="rows.length" class="tbl">
        <thead><tr><th>#</th><th>时间</th><th>高度 (m)</th><th>链头</th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in rows.slice(-8)" :key="i">
            <td class="mono">{{ rows.length - Math.min(rows.length, 8) + i }}</td>
            <td class="mono">{{ new Date(r.t * 1000).toLocaleTimeString() }}</td>
            <td class="mono">{{ (r.alt_cm / 100).toFixed(1) }}</td>
            <td class="mono"><HashText :value="r.head" head="8" tail="4" /></td>
          </tr>
        </tbody>
      </table>
      <p v-else class="note">暂无样本——到「令牌与飞行」起链采样。</p>
    </div>
  </div>
</template>

<style scoped>
.tbl { width: 100%; border-collapse: collapse; font-size: var(--fs-1); }
.tbl th { text-align: left; color: var(--ink-3); font-weight: 600; font-size: var(--fs-0); border-bottom: var(--hairline); padding: 6px 8px; }
.tbl td { padding: 5px 8px; border-bottom: 1px solid #eef2f7; }
.tbl tr { transition: background var(--t-fast); }
.tbl tbody tr:hover { background: var(--accent-soft); }

/* 证书「盖章」金环（视觉深化批 E：verdict 卡出现时一次 600ms 金环扩散——
   仪式感单发不循环） */
.fz-cert-card { position: relative; }
/* 档案链接（档案积累批）：小字导航行——打印形态退场（纸面只留证据本体） */
.fz-to-logbook a { color: var(--accent-ink); text-decoration: none; }
.fz-to-logbook a:hover { text-decoration: underline; }
.fz-cert-card::before {
  content: "";
  position: absolute;
  top: 18px; right: 22px;
  width: 34px; height: 34px;
  border: 2px solid var(--gold);
  border-radius: 50%;
  opacity: 0;
  pointer-events: none;
  animation: fz-stamp 600ms var(--ease) 1 both;
}
@keyframes fz-stamp {
  0% { transform: scale(1.8); opacity: 0; }
  35% { opacity: 0.5; }
  100% { transform: scale(1); opacity: 0.28; }
}

/* 证书卡打印形态（视觉 X 批 X3）：入纸只留证据本体——金环装饰与
   「盖章」动画退场，区块边线充当纸面分隔 */
@media print {
  .fz-cert-card { border-top: 1px solid #bbb; }
  .fz-cert-card::before { display: none; }
  .fz-to-logbook { display: none; }
  .fz-enter { animation: none; }
  .tbl th { color: #555; }
  .tbl td { border-bottom-color: #ddd; }
}
</style>
