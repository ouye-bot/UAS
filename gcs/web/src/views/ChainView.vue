<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from "vue";
import { api, apiBase, bridgeBase, fromHex } from "../lib/api";
import { FZ_CIRCUIT_PIN_DIGEST } from "../lib/circuitPin";
import { logbookFindByAuthId, type LogbookEntry } from "../lib/material";
import { useMaterialStore } from "../stores/material";
import { classLabel } from "../lib/policy";
import {
  bundleTitle as bundleTitleFor,
  bundleUrlFor,
  firstTrailWindow,
  reconVerdict,
  type ReconDetail,
  type ReconState,
} from "../lib/present";
import { runWasmVerify, type WasmVerifyResult } from "../lib/wasmVerify";
import HashText from "../components/HashText.vue";
import StatusTag from "../components/StatusTag.vue";
import FzEmpty from "../components/FzEmpty.vue";

interface PanelData {
  mode: string;
  chain: null | {
    block_height: number;
    rev_epoch: number;
    rev_root_hex: string;
    checkpoints: { auth_id: number; seq: number; chain_head_hex: string; ts: number }[];
  };
  chain_error?: string;
  records: {
    auth_id: number;
    proof_digest_hex: string;
    tx_hash: string;
    status: string;
    class_id: number;
    created_at: string | null;
  }[];
  warrants: {
    warrant_hash_hex: string;
    target_auth_id: number | null;
    created_ts: string | null;
  }[];
}

/** 记录详情（W-8：点击展开按需加载 /chain/record/{id}）。 */
interface RecordDetail {
  auth_id: number;
  status: string;
  class_id: number;
  alt_max_m: number;
  t_start: number;
  t_end: number;
  created_at: string | null;
  proof_digest_hex: string;
  tx_hash: string;
  verify_tail: string | null;
  verify_s: number | null;
  expected: Record<string, unknown> | null;
  archived: boolean;
  chain: null | { proof_digest_hex: string; token_hash_hex: string; match: boolean };
  chain_error?: string;
}

const data = ref<PanelData | null>(null);
const err = ref<string | null>(null);
const loaded = ref(false);

// ---- 我的合规档案（档案积累批·置顶新增——四板块冻结面原样在下方）----
// 数据=fzLogbook 本机积累（material store reload 镜像；写入点=申请受理/
// 取件回填/封链统计/TRAIL 判决，见 lib/material.ts）。零身份：本卡不请求
// 任何"我的记录"服务端接口——档案纯本机，逐行可对链独立核验。
const material = useMaterialStore();
const lbEntries = computed<LogbookEntry[]>(() => material.logbook);
const lbKpi = computed(() => ({
  flights: lbEntries.value.filter((e) => e.sealedAt != null).length,
  certs: lbEntries.value.reduce((n, e) => n + Object.keys(e.trailVerdicts).length, 0),
  anchors: lbEntries.value.reduce((n, e) => n + (e.checkpointCount ?? 0), 0),
}));
const openLb = ref<string | null>(null);
function lbKey(e: LogbookEntry): string {
  return e.caseId || `t${e.createdAt}`;
}
function toggleLb(e: LogbookEntry): void {
  openLb.value = openLb.value === lbKey(e) ? null : lbKey(e);
  if (openLb.value === lbKey(e)) void probeExpected(e); // expected 在场探测（见下）
}
function lbVerdictRows(e: LogbookEntry): { w: number; verdict: string; sm3: string }[] {
  return Object.entries(e.trailVerdicts)
    .map(([w, v]) => ({ w: Number(w), verdict: v.verdict, sm3: v.sm3 }))
    .sort((a, b) => a.w - b.w);
}

// ---- 出示三动作 + 链上对账（L3 接线批·行内瞬时态——操作反馈不出 DenyBox）----
// ① 出示授权档案=出示包（桥 GET /prove/case/{caseId}/bundle，L2 已交付端点）；
// ② 出示合规证书=打印证明页（window.print + 打印聚焦形态——只出该行摘要块）；
// ③ 浏览器内验证=复用 TrailView 的 wasmVerify 流（对第一个有 TRAIL 判决的
//    窗口跑 zkc.wasm verify-instances；无 TRAIL 窗口的行隐藏该按钮——AUTH
//    案卷不适用 TRAIL 验证器，功能不适用≠不可用，不撒谎）。
interface BundleState { busy: boolean; done: boolean; fail: string | null }
const bundleState = ref<Record<string, BundleState>>({});
const expectedKnown = ref<Record<string, boolean>>({}); // 案卷 expected.json 在场（HEAD 探测；未探测键缺省=未知）
const printKey = ref<string | null>(null);
interface RowVerifyState { busy: boolean; logs: string[]; result: WasmVerifyResult | null }
const wv = ref<Record<string, RowVerifyState>>({});

/** expected.json 在场探测（展开时现探一次）：只为出示包按钮的诚实
 * title（AUTH 新案卷可能缺 expected——L2 桥侧 summary.missing 同一事实的
 * 前端侧面）。用 GET 而非 HEAD：桥对 HEAD 回 405（2026-10-04 实弹 curl
 * 判定），expected.json 仅数 KB——只看状态码不读体。探测失败=未知，不出
 * 提示不臆造，不阻塞任何动作。 */
async function probeExpected(e: LogbookEntry): Promise<void> {
  if (!e.caseId) return;
  const k = lbKey(e);
  if (expectedKnown.value[k] !== undefined) return;
  try {
    const res = await fetch(`${bridgeBase()}/prove/case/${e.caseId}/expected.json`);
    expectedKnown.value[k] = res.ok;
  } catch { /* 网络失败=未知 */ }
}

function bundleTitle(e: LogbookEntry): string {
  const k = lbKey(e);
  return bundleTitleFor(e, k in expectedKnown.value ? expectedKnown.value[k] : null);
}

/** ① 生成出示包：fetch+blob 下载（同 TrailView 行程索引下载形态）。成功后
 * 「✓ 已生成」3s 瞬时复位；失败行内红字 5s 复位——不弹拒绝盒（操作反馈）。 */
async function genBundle(e: LogbookEntry): Promise<void> {
  if (!e.caseId) return;
  const k = lbKey(e);
  bundleState.value[k] = { busy: true, done: false, fail: null };
  try {
    const res = await fetch(bundleUrlFor(bridgeBase(), e.caseId));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `fz-proof-${e.caseId.slice(0, 8)}.zip`; // 与桥侧 Content-Disposition 同名
    a.click();
    URL.revokeObjectURL(a.href);
    bundleState.value[k] = { busy: false, done: true, fail: null };
    setTimeout(() => {
      if (bundleState.value[k]?.done) bundleState.value[k] = { busy: false, done: false, fail: null };
    }, 3000);
  } catch (err: any) {
    const msg = err?.message ?? String(err);
    bundleState.value[k] = { busy: false, done: false, fail: msg };
    setTimeout(() => {
      if (bundleState.value[k]?.fail) bundleState.value[k] = { busy: false, done: false, fail: null };
    }, 5000);
  }
}

/** ② 打印证明页：入纸只出该行证明摘要块（.fz-printing 聚焦形态——全局
 * @media print 之上叠加）。摘要含链上交易编号——若该行未对账先尽力拉一次
 * /chain/record（失败如实印「—」，不阻塞打印）。 */
async function printProof(e: LogbookEntry): Promise<void> {
  const k = lbKey(e);
  if (e.authId != null) {
    const cur = recon.value[e.authId];
    if (!cur?.state || cur.state.kind === "unreachable") await reconcile(e);
  }
  printKey.value = k;
  await nextTick();
  try {
    window.print();
  } finally {
    printKey.value = null; // print() 返回即对话框已关（真浏览器阻塞语义）
  }
}

/** 打印摘要块的证明指纹行：TRAIL 存证 SM3 优先（第一个判决窗全文）；
 * 无存证判决时退链上证明摘要（对账已拉到才有）——两者皆无如实印「—」。 */
function printFingerprint(e: LogbookEntry): { label: string; value: string } {
  const hit = firstTrailWindow(e);
  if (hit) {
    const v = e.trailVerdicts[hit.w] ?? (e.trailVerdicts as Record<string, { verdict: string; sm3: string }>)[String(hit.w)];
    return { label: "证明指纹（存证 SM3）", value: v?.sm3 || "—" };
  }
  const d = e.authId != null ? recon.value[e.authId]?.detail : null;
  if (d?.proof_digest_hex) return { label: "证明指纹（链上证明摘要）", value: d.proof_digest_hex };
  return { label: "证明指纹", value: "—（无存证判决）" };
}

/** ③ 浏览器内验证：对该行第一个有 TRAIL 判决的窗口跑 zkc.wasm（Worker 内
 * WASI shim——零服务端参与，同 TrailView 证书卡的复验流）。预期约 105s
 * （浏览器 JS 运行时口径，A7 实测），行内进度+结果如实（OK/FAIL）。 */
async function verifyRow(e: LogbookEntry): Promise<void> {
  const hit = firstTrailWindow(e);
  if (!hit) return;
  const k = lbKey(e);
  wv.value[k] = { busy: true, logs: [], result: null };
  const st = wv.value[k]; // 取 reactive 代理再改（改原始对象不触发重渲染）
  const caseFile = (kind: string) => `${bridgeBase()}/prove/case/${hit.caseId}/${kind}`;
  const base = apiBase();
  st.result = await runWasmVerify({
    wasmUrl: `${base}/verify/dist/zkc.wasm`,
    specUrl: `${base}/verify/dist/trail_canonical_spec.json`,
    instancesUrl: caseFile("instances.json"),
    proofUrl: caseFile("proof.bin"),
    vpUrl: caseFile("verifier_param.bin"),
    expectedUrl: caseFile("expected.json"),
  }, (line) => { st.logs.push(line); st.logs = st.logs.slice(-6); });
  st.busy = false;
}

// ---- 链上对账徽章（L3-2）：GET /chain/record/{authId} 按需对账 ----
// 三态：一致（绿）/不一致（红——不应出现，如实显示）/链不可达（灰·可重试）。
// 结论行内缓存（组件会话内不重复拉；仅链不可达态允许点重试）。行尾徽章位
// 在结论出来后回显到收起行上（非交互 StatusTag——行本体是 button，不能嵌套）。
interface ReconRow { busy: boolean; state: ReconState | null; detail: ReconDetail | null }
const recon = ref<Record<number, ReconRow>>({});

function rowRecon(e: LogbookEntry): ReconState | null {
  if (e.authId == null) return null;
  const r = recon.value[e.authId];
  return r && !r.busy ? r.state : null;
}

/** 对账视图扁平化（模板消费——联合类型跨表达式不窄化，收拢为固定字段面）。 */
interface ReconDone { kind: "match" | "mismatch" | "unreachable"; digest: string; reason: string }
function reconDone(e: LogbookEntry): ReconDone | null {
  const s = rowRecon(e);
  if (!s) return null;
  return s.kind === "match"
    ? { kind: "match", digest: s.digest, reason: "" }
    : { kind: s.kind, digest: "", reason: s.reason };
}

function reconBusy(e: LogbookEntry): boolean {
  return e.authId != null && recon.value[e.authId]?.busy === true;
}

/** 行尾徽章（收起行上回显——非交互 StatusTag，行本体是 button 不能嵌套交互件）。 */
function reconBadge(e: LogbookEntry): { tone: "ok" | "bad" | "accent"; label: string; title: string } | null {
  const s = rowRecon(e);
  if (!s) return null;
  if (s.kind === "match") return { tone: "ok", label: "与链上一致", title: `链上原文指纹一致（${s.digest.slice(0, 12)}…）` };
  if (s.kind === "mismatch") return { tone: "bad", label: "与链上不一致", title: s.reason };
  return { tone: "accent", label: "链不可达", title: s.reason };
}

async function reconcile(e: LogbookEntry): Promise<ReconDetail | null> {
  const aid = e.authId;
  if (aid == null) return null;
  const cur = recon.value[aid];
  if (cur && !cur.busy && cur.state && cur.state.kind !== "unreachable") return cur.detail; // 会话内缓存命中
  if (!cur) recon.value[aid] = { busy: true, state: null, detail: null };
  const row = recon.value[aid]; // 取 reactive 代理再改（改原始对象不触发重渲染）
  row.busy = true;
  // 真链冷读常 >8s（见 load() 注）——10s 超时防白挂，超时=链不可达灰态可重试
  const ctl = new AbortController();
  const kill = setTimeout(() => ctl.abort(), 10000);
  try {
    const d = await api<ReconDetail>(`/chain/record/${aid}`, { signal: ctl.signal });
    row.detail = d;
    row.state = reconVerdict(d, e, null);
  } catch (err: any) {
    row.state = reconVerdict(null, e, err?.name === "AbortError" ? "链响应超时" : err?.message ?? String(err));
  } finally {
    clearTimeout(kill);
    row.busy = false;
  }
  return row.detail;
}

// 授权记录状态 中文+tone 映射（丙-2 M6 表面语言迁移：行内不再裸出英文枚举；
// 形态参照审计台 S_META——未知值兜底原样展示，不编造中文）
type ChainTone = "ok" | "bad" | "gold" | "accent";
const CHAIN_STATUS: Record<string, { label: string; tone: ChainTone }> = {
  pending: { label: "审批中", tone: "accent" },
  approved: { label: "已批准", tone: "ok" },
  rejected: { label: "已驳回", tone: "bad" },
  revoked: { label: "已吊销", tone: "bad" },
};
function chainStatus(s: string): { label: string; tone?: ChainTone } {
  return CHAIN_STATUS[s] ?? { label: s };
}

// 展开态：授权记录 / 检查点 / 令状 三类行各自记录（再次点击收起）
const openRecord = ref<number | null>(null);
const details = ref<Record<number, RecordDetail>>({});
const detailErr = ref<Record<number, string>>({});
const openCp = ref<string | null>(null);
const openWarrant = ref<string | null>(null);

async function load(): Promise<void> {
  loaded.value = false;
  err.value = null;
  // R3-2（评审 P2-1）：超时防无限白挂；2026-09-26 队长实测：真链面板冷读常
  // >8s（全量链回扫）——15s 超时+自动重试一次（慢≠不可达，勿误报）
  for (let attempt = 0; attempt < 2; attempt++) {
    const ctl = new AbortController();
    const kill = setTimeout(() => ctl.abort(), 15000);
    try {
      data.value = await api<PanelData>("/chain/panel", { signal: ctl.signal });
      loaded.value = true;
      return;
    } catch (e: any) {
      if (attempt === 1 || e?.name !== "AbortError") {
        err.value = e?.name === "AbortError"
          ? "链响应超时（链较慢或不可达）——可点下方重试"
          : e?.message ?? String(e);
        loaded.value = true;
        return;
      }
    } finally {
      clearTimeout(kill);
    }
  }
}

async function toggleRecord(authId: number): Promise<void> {
  if (openRecord.value === authId) { openRecord.value = null; return; }
  openRecord.value = authId;
  if (details.value[authId]) return;
  try {
    const d = await api<RecordDetail>(`/chain/record/${authId}`);
    details.value[authId] = d;
  } catch (e: any) {
    detailErr.value[authId] = e?.message ?? String(e);
  }
}

/** 本机当次出证材料检测：本机令牌 authId 匹配 + 档案行（fzLogbook 按授权
 * 编号查询——跨架次仍可定位本机案卷）∥ 旧单值回退（fzLastCaseId=本批之前
 * 的最后一架次，身份域键换人即清——不会误关联他人记录）。 */
function localCaseFor(authId: number): string | null {
  try {
    const hex = localStorage.getItem("fzTokenPayload");
    if (!hex) return null;
    const text = new TextDecoder().decode(fromHex(hex));
    const body = JSON.parse(text.slice(0, text.lastIndexOf("|")));
    if (body.authId !== authId) return null;
    const hit = logbookFindByAuthId(authId);
    if (hit?.caseId) return hit.caseId;
    return localStorage.getItem("fzLastCaseId");
  } catch { return null; }
}

/** 授权记录行徽章判定：该授权在本机档案中（fzLogbook 命中即「我的档案」
 * ——档案身份域单源，不含他人授权，命中无需再校令牌）。 */
function inMyLogbook(authId: number): boolean {
  return !!logbookFindByAuthId(authId);
}

/** expected.json 下载：详情端点的 expected=验证时真实消费的期望绑定
 * （与归档同源）——序列化落盘即第三方复验材料，无需手工重建。 */
function dlExpected(d: RecordDetail): void {
  if (!d.expected) return;
  const blob = new Blob([JSON.stringify(d.expected, null, 1)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "expected.json";
  a.click();
  URL.revokeObjectURL(a.href);
}

function caseUrl(caseId: string, kind: string): string {
  return `${bridgeBase()}/prove/case/${caseId}/${kind}`;
}

function fmtTime(ts: string | number | null): string {
  if (ts === null) return "—";
  const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

onMounted(() => {
  material.reload(); // 档案镜像对账（localStorage 非响应式——挂载时现读）
  load();
});
</script>

<template>
  <section class="wrap" :class="{ 'fz-printing': printKey != null }">
    <h2>链上留痕</h2>
    <p class="sub">
      授权登记、检查点锚定与令状的链上公示面——记录一经上链不可篡改，可独立核验。本页展示的是**全体脱敏公示**：记录不携带任何身份信息，也无法对应到真人（这正是零知识设计的效果）；与本机合规档案命中的授权，会标注「我的档案」徽章。
    </p>

    <!-- 我的合规档案（档案积累批置顶新增——下方四板块冻结面原样不动） -->
    <div class="panel fz-ticks lb-card">
      <h3>我的合规档案</h3>
      <p class="expl">本机积累的飞行合规档案：出证受理入档、封链补全统计、TRAIL 判决自动归档——不依赖任何"我的记录"服务端查询。</p>
      <template v-if="lbEntries.length">
        <div class="lb-kpi">
          累计合规飞行 {{ lbKpi.flights }} 次 · 存证证书 {{ lbKpi.certs }} 张 · 链上锚定 {{ lbKpi.anchors }} 个
        </div>
        <div v-for="e in lbEntries" :key="lbKey(e)" class="rec" :class="{ 'lb-print-rec': printKey === lbKey(e) }">
          <button class="row rowbtn" :aria-expanded="openLb === lbKey(e)" @click="toggleLb(e)">
            <span class="mono">授权 #{{ e.authId ?? "—" }}</span>
            <span>{{ fmtTime(e.tStart) }} ~ {{ fmtTime(e.tEnd) }}</span>
            <span>{{ classLabel(e.classId) }} · 上限 {{ e.altMax ?? "—" }} m</span>
            <span>飞行 {{ e.nSamples ?? "—" }} 样本</span>
            <span>存证 {{ Object.keys(e.trailVerdicts).length }} 窗</span>
            <span>锚定 {{ e.checkpointCount ?? 0 }} 次</span>
            <StatusTag v-if="e.breachFlag" tone="bad" label="含超限记录" />
            <StatusTag :tone="e.sealedAt != null ? 'ok' : 'accent'" :label="e.sealedAt != null ? '已封链' : '未封链'" />
            <!-- 行尾对账徽章位（L3-2）：结论出来后回显收起行（三态如实；title 带原因） -->
            <StatusTag
              v-if="reconBadge(e)"
              :tone="reconBadge(e)!.tone"
              :label="reconBadge(e)!.label"
              :title="reconBadge(e)!.title"
            />
            <span class="caret">{{ openLb === lbKey(e) ? "收起" : "出示与核验" }}</span>
          </button>
          <div v-if="e.breachFlag" class="sub lb-breach">
            ⚠ 本架次含超限记录（固件围栏触发已上链取证）——如实披露，存证证书不构成对越线尝试的豁免。
          </div>
          <div v-if="openLb === lbKey(e)" class="detail">
            <div class="kv"><dt>回执码</dt><dd class="mono">{{ e.receiptCode || "—" }}</dd></div>
            <div class="kv"><dt>封链时刻</dt><dd>{{ e.sealedAt != null ? fmtTime(e.sealedAt) : "—" }}</dd></div>
            <div class="kv"><dt>出证案卷</dt><dd class="mono">{{ e.caseId ? e.caseId.slice(0, 20) + "…" : "—" }}</dd></div>
            <div v-if="lbVerdictRows(e).length" class="kv">
              <dt>存证判决</dt>
              <dd>
                <div v-for="v in lbVerdictRows(e)" :key="v.w" class="mono" style="font-size:11.5px">
                  窗口 {{ v.w }}：{{ v.verdict }}（SM3 {{ v.sm3 ? v.sm3.slice(0, 12) + "…" : "—" }}）
                </div>
              </dd>
            </div>
            <div class="reverify">
              <!-- 链上对账（L3-2）：按需拉 /chain/record/{authId}——三态如实 -->
              <div class="kv">
                <dt>与链上比对</dt>
                <dd class="lb-recon-dd">
                  <span v-if="e.authId == null" class="sub">—（本行未回填授权编号，无对账锚点）</span>
                  <button
                    v-else-if="!reconDone(e)"
                    class="btn ghost"
                    :disabled="reconBusy(e)"
                    title="按需拉取链上记录（/chain/record/{授权编号}），比对链上原文指纹与本行档案参数——结论会话内缓存"
                    @click="reconcile(e)"
                  >{{ reconBusy(e) ? "对账中（链回读可 >8s）…" : "与链上比对" }}</button>
                  <template v-else-if="reconDone(e)!.kind === 'match'">
                    <StatusTag tone="ok" :label="`一致（链上原文指纹=${reconDone(e)!.digest.slice(0, 12)}…）`" />
                  </template>
                  <template v-else-if="reconDone(e)!.kind === 'mismatch'">
                    <StatusTag tone="bad" :label="`不一致：${reconDone(e)!.reason}`" />
                  </template>
                  <button v-else class="btn ghost" :title="`链不可达：${reconDone(e)!.reason}`" @click="reconcile(e)">链不可达 · 点击重试</button>
                </dd>
              </div>
              <!-- 出示三动作（L3-1）：行内瞬时态反馈，不出 DenyBox（操作反馈非拒绝） -->
              <div class="dlrow">
                <button
                  class="btn ghost"
                  :disabled="!e.caseId || bundleState[lbKey(e)]?.busy"
                  :title="bundleTitle(e)"
                  @click="genBundle(e)"
                >{{
                  bundleState[lbKey(e)]?.busy ? "生成中…"
                  : bundleState[lbKey(e)]?.done ? "✓ 已生成"
                  : bundleState[lbKey(e)]?.fail ? "生成失败 · 重试"
                  : "出示授权档案"
                }}</button>
                <button
                  class="btn ghost"
                  :disabled="printKey === lbKey(e)"
                  title="浏览器打印本行证明摘要页（入纸只出该行摘要块；链上交易编号需先对账可得，取不到如实印 —）"
                  @click="printProof(e)"
                >出示合规证书</button>
                <button
                  v-if="firstTrailWindow(e)"
                  class="btn ghost"
                  :disabled="wv[lbKey(e)]?.busy"
                  :title="`在本浏览器运行 zkc.wasm 验证器（窗口 ${firstTrailWindow(e)!.w} 的 TRAIL 证明——零服务端参与）`"
                  @click="verifyRow(e)"
                >浏览器内验证</button>
              </div>
              <p v-if="bundleState[lbKey(e)]?.fail" class="note" style="color: var(--tone-red-fg)">
                出示包生成失败：{{ bundleState[lbKey(e)]!.fail }}（稍后自动复位——可重试）
              </p>
              <div v-if="firstTrailWindow(e) && wv[lbKey(e)]" class="lb-wv">
                <div class="note" style="display:flex; gap:8px; align-items:center; flex-wrap:wrap">
                  <span>窗口 {{ firstTrailWindow(e)!.w }} 浏览器内验证（zkc.wasm，预期约 105s——浏览器 JS 运行时口径）：</span>
                  <span v-if="wv[lbKey(e)]!.busy" class="spin" style="width:12px;height:12px" />
                  <span v-else class="mono">已用时 {{ Math.round(wv[lbKey(e)]!.result!.ms / 1000) }}s</span>
                </div>
                <div v-if="wv[lbKey(e)]!.logs.length" class="mono note" style="white-space: pre-line">{{ wv[lbKey(e)]!.logs.join("\n") }}</div>
                <template v-if="wv[lbKey(e)]!.result">
                  <StatusTag v-if="wv[lbKey(e)]!.result!.ok" tone="ok" :label="`浏览器内验证 OK（${Math.round(wv[lbKey(e)]!.result!.ms / 1000)}s）`" />
                  <StatusTag v-else tone="bad" :label="`验证未通过（rc=${wv[lbKey(e)]!.result!.rc}）`" />
                </template>
              </div>
              <template v-if="e.caseId">
                <p class="sub">本机保有该次出证的完整证明材料（AUTH 五件按案卷挂载），可交付任何第三方独立复验：</p>
                <div class="dlrow">
                  <a class="btn ghost" :href="caseUrl(e.caseId, 'proof.bin')" download>proof.bin</a>
                  <a class="btn ghost" :href="caseUrl(e.caseId, 'verifier_param.bin')" download>verifier_param.bin</a>
                  <a class="btn ghost" :href="caseUrl(e.caseId, 'instances.json')" download>instances.json</a>
                  <a class="btn ghost" :href="caseUrl(e.caseId, 'verdict.json')" download>verdict.json</a>
                  <a class="btn ghost" :href="caseUrl(e.caseId, 'expected.json')" download :title="expectedKnown[lbKey(e)] === false ? '该案卷缺 expected.json（下载将 404）——出示包内 README 有补齐指引' : ''">expected.json</a>
                </div>
                <p class="mono note">zkc verify-instances --instances instances.json --proof proof.bin --vp verifier_param.bin --expected expected.json</p>
              </template>
              <p v-else class="sub">本行无出证案卷号（跨设备领取或本批之前的数据）——证明文件不在本机，无法出示。</p>
            </div>
          </div>
          <!-- 打印证明页摘要块（L3-1 ②）：屏上不显示，打印聚焦态只出本块 -->
          <div class="lb-print-summary" aria-hidden="true">
            <div class="lb-ps-title">飞证 · 合规飞行证明摘要</div>
            <div class="lb-ps-row"><span>授权编号</span><b class="mono">#{{ e.authId ?? "—" }}</b></div>
            <div class="lb-ps-row"><span>授权时间窗</span><b>{{ fmtTime(e.tStart) }} ~ {{ fmtTime(e.tEnd) }}</b></div>
            <div class="lb-ps-row"><span>机型类 / 高度上限</span><b>{{ classLabel(e.classId) }} / {{ e.altMax ?? "—" }} m</b></div>
            <div class="lb-ps-row"><span>出证案卷</span><b class="mono">{{ e.caseId || "—" }}</b></div>
            <div class="lb-ps-row"><span>{{ printFingerprint(e).label }}</span><b class="mono">{{ printFingerprint(e).value }}</b></div>
            <div class="lb-ps-row">
              <span>链上交易编号</span>
              <b class="mono">{{ (e.authId != null && recon[e.authId]?.detail?.tx_hash) || "—（未对账或链不可达）" }}</b>
            </div>
            <div class="lb-ps-row">
              <span>验证指引</span>
              <b class="mono">出示包内 README-验证指引.txt：zkc verify-instances --instances instances.json --proof proof.bin --vp verifier_param.bin --expected expected.json（逐件 sha256 见 summary.json）</b>
            </div>
            <div class="lb-ps-foot">
              本页为本机合规档案的纸面摘要（生成于 {{ new Date().toLocaleString() }}）；密码学核验以出示包（fz-proof-*.zip）与链上记录为准——档案积累在出证设备本机，任何一行均可对链独立核验。
            </div>
          </div>
        </div>
      </template>
      <FzEmpty v-else text="暂无档案——完成一次飞行并封链后自动积累" icon="inbox" />
      <p class="sub lb-foot">档案积累在出证设备本机（隐私架构：见证不出设备）——换设备从新开始，任何一行都能对链独立核验。</p>
    </div>

    <div v-if="err" class="deny">{{ err }}<button class="btn ghost" style="margin-left:10px" @click="load">重试</button></div>
    <div v-else-if="!loaded" class="fz-skelset" aria-hidden="true" style="max-width:520px">
      <div class="fz-skel" style="width:82%"></div>
      <div class="fz-skel" style="width:64%"></div>
      <div class="fz-skel" style="width:46%"></div>
    </div>
    <template v-else-if="data">
      <div class="grid">
        <div class="panel fz-ticks">
          <h3>链状态</h3>
          <p class="expl">撤销名单公示与核验参数。名单版本随吊销即时更新，公示根供第三方校验名单完整性。</p>
          <template v-if="data.chain">
            <div class="kv"><dt>区块高</dt><dd>{{ data.chain.block_height }}</dd></div>
            <div class="kv"><dt>撤销名单版本</dt><dd>{{ data.chain.rev_epoch }}</dd></div>
            <div class="kv">
              <dt>名单公示根</dt>
              <dd><HashText :value="data.chain.rev_root_hex" /></dd>
            </div>
            <div class="kv">
              <dt>电路指纹</dt>
              <dd class="pin-dd">
                <HashText :value="FZ_CIRCUIT_PIN_DIGEST" />
                <span class="fz-pill gold">已公示上链</span>
              </dd>
            </div>
          </template>
          <template v-else>
            <div class="sub">
              当前为{{ data.mode === "fake" ? "演示模式（链下登记在案，链状态面不可用）" : data.mode }}——
              <span v-if="data.chain_error">链回读: {{ data.chain_error }}</span>
            </div>
          </template>
        </div>

        <div class="panel fz-ticks">
          <h3>授权记录</h3>
          <p class="expl">每次飞行授权核验通过后，其证明摘要与授权参数即登记上链。点击记录查看详情与核验材料。</p>
          <FzEmpty v-if="!data.records.length" text="暂无授权记录" icon="doc" />
          <div v-for="r in data.records" :key="r.auth_id" class="rec">
            <button class="row rowbtn" :aria-expanded="openRecord === r.auth_id" @click="toggleRecord(r.auth_id)">
              <span class="mono">#{{ r.auth_id }}</span>
              <HashText :value="r.proof_digest_hex" />
              <span v-if="inMyLogbook(r.auth_id)" class="fz-pill blue">我的档案</span>
              <StatusTag :tone="chainStatus(r.status).tone" :label="chainStatus(r.status).label" />
              <span class="caret">{{ openRecord === r.auth_id ? "收起" : "详情" }}</span>
            </button>

            <div v-if="openRecord === r.auth_id" class="detail">
              <div v-if="detailErr[r.auth_id]" class="sub">详情读取失败：{{ detailErr[r.auth_id] }}</div>
              <template v-else-if="details[r.auth_id]">
                <div v-if="details[r.auth_id].chain" class="kv">
                  <dt>链上原文核验</dt>
                  <dd v-if="details[r.auth_id].chain!.match" class="ok">一致（指纹=链上原文）</dd>
                  <dd v-else class="bad">不一致（链上公示与归档指纹存在差异）</dd>
                </div>
                <div v-else-if="details[r.auth_id].chain_error" class="kv">
                  <dt>链上原文核验</dt><dd class="sub">链暂不可达（{{ details[r.auth_id].chain_error }}）</dd>
                </div>
                <div class="kv"><dt>验证结论</dt>
                  <dd>{{ details[r.auth_id].verify_tail ? details[r.auth_id].verify_tail!.split("\n").pop() : "已归档（该记录无验证日志摘要）" }}</dd>
                </div>
                <div class="kv" v-if="details[r.auth_id].verify_s != null"><dt>验证耗时</dt><dd>{{ details[r.auth_id].verify_s }}s</dd></div>
                <div class="kv"><dt>授权窗</dt><dd class="mono">{{ fmtTime(details[r.auth_id].t_start) }} ~ {{ fmtTime(details[r.auth_id].t_end) }}</dd></div>
                <div class="kv"><dt>高度上限</dt><dd>{{ details[r.auth_id].alt_max_m }} m</dd></div>
                <div class="kv"><dt>登记时间</dt><dd>{{ fmtTime(details[r.auth_id].created_at) }}</dd></div>
                <div class="kv"><dt>链上交易</dt><dd><HashText :value="details[r.auth_id].tx_hash" /></dd></div>
                <div class="kv"><dt>证明摘要（全文）</dt>
                  <dd><code class="fullhash">{{ details[r.auth_id].proof_digest_hex }}</code></dd>
                </div>

                <div class="reverify">
                  <template v-if="localCaseFor(r.auth_id)">
                    <p class="sub">本机保有该次出证的完整证明材料，可交付任何第三方独立复验：</p>
                    <div class="dlrow">
                      <a class="btn ghost" :href="caseUrl(localCaseFor(r.auth_id)!, 'proof.bin')" download>proof.bin</a>
                      <a class="btn ghost" :href="caseUrl(localCaseFor(r.auth_id)!, 'verifier_param.bin')" download>verifier_param.bin</a>
                      <a class="btn ghost" :href="caseUrl(localCaseFor(r.auth_id)!, 'instances.json')" download>instances.json</a>
                      <a class="btn ghost" :href="caseUrl(localCaseFor(r.auth_id)!, 'verdict.json')" download>verdict.json</a>
                      <button v-if="details[r.auth_id].expected" class="btn ghost" @click="dlExpected(details[r.auth_id])">expected.json</button>
                    </div>
                    <p class="mono note">zkc verify-instances --instances instances.json --proof proof.bin --vp verifier_param.bin --expected expected.json</p>
                  </template>
                  <p v-else class="sub">完整证明文件存放于出证设备本机（隐私架构：见证不出设备）。持有证明文件方可执行上述命令独立复验。</p>
                </div>
              </template>
              <div v-else class="sub">详情读取中…</div>
            </div>
          </div>
        </div>

        <div class="panel fz-ticks">
          <h3>检查点锚定</h3>
          <p class="expl">飞行中设备定期将截至当前的飞行记录指纹签名后锚定上链。锚定后的记录不可抵赖。</p>
          <FzEmpty
            v-if="!data.chain || !data.chain.checkpoints.length"
            text="暂无锚定检查点"
            icon="chain"
          />
          <div
            v-for="cp in data.chain?.checkpoints ?? []"
            :key="cp.auth_id + '-' + cp.seq"
            class="rec"
          >
            <button class="row rowbtn" :aria-expanded="openCp === cp.auth_id + '-' + cp.seq" @click="openCp = openCp === cp.auth_id + '-' + cp.seq ? null : cp.auth_id + '-' + cp.seq">
              <span class="mono">#{{ cp.auth_id }}·cp{{ cp.seq }}</span>
              <HashText :value="cp.chain_head_hex" />
              <span class="caret">{{ openCp === cp.auth_id + '-' + cp.seq ? "收起" : "详情" }}</span>
            </button>
            <div v-if="openCp === cp.auth_id + '-' + cp.seq" class="detail">
              <div class="kv"><dt>授权编号</dt><dd class="mono">#{{ cp.auth_id }}</dd></div>
              <div class="kv"><dt>锚定序号</dt><dd class="mono">第 {{ cp.seq }} 次</dd></div>
              <div class="kv"><dt>锚定时间</dt><dd>{{ fmtTime(cp.ts) }}</dd></div>
              <div class="kv"><dt>链头（全文）</dt><dd><code class="fullhash">{{ cp.chain_head_hex }}</code></dd></div>
              <p class="sub">设备对该链头签名后上链；审计方可核验设备签名与链上记录的一致性。</p>
            </div>
          </div>
        </div>

        <div class="panel fz-ticks">
          <h3>令状</h3>
          <p class="expl">审计方调取真实身份的程序留痕。令状登记与实名解锁全程上链，调取行为自身可追溯——公开面仅含令状哈希/目标授权号/时间，立案依据原文与实名不出公开面（核验走审计台权限面）。涉本机档案的令状会标注「涉我的授权」。</p>
          <FzEmpty v-if="!data.warrants.length" text="暂无令状" icon="stamp" />
          <div v-for="w in data.warrants" :key="w.warrant_hash_hex" class="rec">
            <button class="row rowbtn" :aria-expanded="openWarrant === w.warrant_hash_hex" @click="openWarrant = openWarrant === w.warrant_hash_hex ? null : w.warrant_hash_hex">
              <HashText :value="w.warrant_hash_hex" />
              <span v-if="w.target_auth_id" class="mono">授权 #{{ w.target_auth_id }}</span>
              <span v-if="w.target_auth_id && inMyLogbook(w.target_auth_id)" class="badge">涉我的授权</span>
              <span class="caret">{{ openWarrant === w.warrant_hash_hex ? "收起" : "详情" }}</span>
            </button>
            <div v-if="openWarrant === w.warrant_hash_hex" class="detail">
              <div class="kv"><dt>目标授权</dt><dd class="mono">#{{ w.target_auth_id ?? "—" }}</dd></div>
              <div class="kv"><dt>登记时间</dt><dd>{{ fmtTime(w.created_ts) }}</dd></div>
              <div class="kv"><dt>令状哈希（全文）</dt><dd><code class="fullhash">{{ w.warrant_hash_hex }}</code></dd></div>
              <p class="sub">实名解锁须同时持有审计令状与登记机构出具的随案协作函，双重核验全部留痕。</p>
            </div>
          </div>
        </div>
      </div>
    </template>
  </section>
</template>

<style scoped>
/* 丙-2 M6 表面语言迁移：卡片改用全局 .panel（+fz-ticks 角标）、.kv/.deny/.mono
   删除本地重定义（全局单一定义处）；本地只留本页版式微调。 */
.wrap { max-width: 980px; margin: 0 auto; }
h2 { margin: 4px 0 2px; font-size: 20px; }
.sub { color: var(--ink-3); font-size: 13px; margin: 2px 0 14px; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
/* 抵消全局 .panel + .panel 的纵向外距（网格内间距由 gap 单源） */
.grid .panel + .panel { margin-top: 0; }
.panel h3 { font-size: 13px; margin: 0 0 6px; color: var(--ink-2); font-weight: 650; }
.expl { color: var(--ink-3); font-size: 12px; line-height: 1.6; margin: 0 0 10px; }
.row { display: flex; gap: 8px; align-items: center; padding: 4px 0; font-size: 12.5px; flex-wrap: wrap; }
.rec { border-bottom: 1px dashed var(--line); }
.rec:last-child { border-bottom: none; }
.rowbtn {
  background: none; border: none; cursor: pointer; text-align: left;
  color: inherit; font: inherit; width: 100%; padding: 4px 0;
}
.rowbtn:hover { color: var(--accent-ink); }
.caret { margin-left: auto; color: var(--ink-3); font-size: 11px; flex-shrink: 0; }
.detail {
  background: var(--panel-2); border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 12px; margin: 4px 0 10px; animation: fz-enter var(--t-fast) both;
}
.detail .kv { font-size: 12.5px; }
.fullhash {
  font-family: var(--font-mono); font-size: 11px; word-break: break-all;
  color: var(--ink-2); background: var(--panel); padding: 2px 4px; border-radius: 4px;
}
.ok { color: var(--ok); font-weight: 600; }
.bad { color: var(--tone-red-fg); font-weight: 600; }
.pin-dd { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.reverify { border-top: 1px dashed var(--line); margin-top: 8px; padding-top: 8px; }
.dlrow { display: flex; gap: 8px; flex-wrap: wrap; margin: 6px 0; }
.note { color: var(--ink-3); font-size: 11px; word-break: break-word; }
/* 我的合规档案卡（档案积累批）：全宽置顶（.grid 之上）——KPI 行/超限披露
   行/诚实注脚本页微调，四板块冻结面零触碰 */
.lb-card { margin-bottom: 12px; }
.lb-kpi {
  font-size: 13px; font-weight: 650; color: var(--ink-2);
  background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px;
  padding: 8px 12px; margin: 0 0 10px;
}
.lb-breach {
  margin: 2px 0 6px; padding-left: 10px;
  border-left: 3px solid #e0a855; color: #b7791f; font-size: 12px;
}
.lb-foot { margin: 10px 0 0; }
/* ---- 出示三动作 + 链上对账（L3 接线批）---- */
.lb-recon-dd { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.lb-wv { margin: 6px 0; display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
/* 打印证明页摘要块：屏上不显示；打印聚焦态（.fz-printing + 本行 .lb-print-rec）
   下整页只出本块——参照 TrailView 证书卡打印先例（全局 @media print 之上叠加，
   顶栏/按钮等已由全局打印样式退场） */
.lb-print-summary { display: none; }
@media print {
  .fz-printing > :not(.lb-card) { display: none !important; }
  .fz-printing .lb-card > :not(.lb-print-rec) { display: none !important; }
  .fz-printing .lb-print-rec > :not(.lb-print-summary) { display: none !important; }
  .lb-print-summary { display: block; font-size: 12px; }
  .lb-ps-title { font-size: 15px; font-weight: 700; margin-bottom: 10px; }
  .lb-ps-row {
    display: flex; gap: 12px; padding: 4px 0;
    border-bottom: 1px dotted #bbb; break-inside: avoid;
  }
  .lb-ps-row > span { color: #555; min-width: 140px; flex-shrink: 0; }
  .lb-ps-row > b { font-weight: 600; word-break: break-all; }
  .lb-ps-foot { margin-top: 10px; color: #555; font-size: 11px; line-height: 1.6; }
}
</style>
