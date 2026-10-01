<script setup lang="ts">
import { onMounted, ref } from "vue";
import { api, bridgeBase, fromHex } from "../lib/api";
import HashText from "../components/HashText.vue";
import StatusTag from "../components/StatusTag.vue";

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

/** 本机当次出证材料检测：本机令牌 authId 匹配 + 出证时持久化的本机案卷号
 * （fzLastCaseId=身份域 localStorage 键，换人即被身份清扫——不会误关联他人
 * 记录；流程快照在受理 ready 后即清除，故案卷号落持久键而非快照）。 */
function localCaseFor(authId: number): string | null {
  try {
    const hex = localStorage.getItem("fzTokenPayload");
    if (!hex) return null;
    const text = new TextDecoder().decode(fromHex(hex));
    const body = JSON.parse(text.slice(0, text.lastIndexOf("|")));
    if (body.authId !== authId) return null;
    return localStorage.getItem("fzLastCaseId");
  } catch { return null; }
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

onMounted(load);
</script>

<template>
  <section class="wrap">
    <h2>链上留痕</h2>
    <p class="sub">
      授权登记、检查点锚定与令状的链上公示面——记录一经上链不可篡改，可独立核验（零身份字段）。
    </p>

    <div v-if="err" class="deny">{{ err }}<button class="btn ghost" style="margin-left:10px" @click="load">重试</button></div>
    <div v-else-if="!loaded" class="sub">读取中…</div>
    <template v-else-if="data">
      <div class="grid">
        <div class="card">
          <h3>链状态</h3>
          <p class="expl">撤销名单公示与核验参数。名单版本随吊销即时更新，公示根供第三方校验名单完整性。</p>
          <template v-if="data.chain">
            <div class="kv"><span>区块高</span><b>{{ data.chain.block_height }}</b></div>
            <div class="kv"><span>撤销名单版本</span><b>{{ data.chain.rev_epoch }}</b></div>
            <div class="kv">
              <span>名单公示根</span>
              <HashText :value="data.chain.rev_root_hex" />
            </div>
          </template>
          <template v-else>
            <div class="sub">
              当前为{{ data.mode === "fake" ? "演示模式（链下登记在案，链状态面不可用）" : data.mode }}——
              <span v-if="data.chain_error">链回读: {{ data.chain_error }}</span>
            </div>
          </template>
        </div>

        <div class="card">
          <h3>授权记录</h3>
          <p class="expl">每次飞行授权核验通过后，其证明摘要与授权参数即登记上链。点击记录查看详情与核验材料。</p>
          <div v-if="!data.records.length" class="sub">暂无授权记录</div>
          <div v-for="r in data.records" :key="r.auth_id" class="rec">
            <button class="row rowbtn" :aria-expanded="openRecord === r.auth_id" @click="toggleRecord(r.auth_id)">
              <span class="mono">#{{ r.auth_id }}</span>
              <HashText :value="r.proof_digest_hex" />
              <StatusTag :label="r.status" />
              <span class="caret">{{ openRecord === r.auth_id ? "收起" : "详情" }}</span>
            </button>

            <div v-if="openRecord === r.auth_id" class="detail">
              <div v-if="detailErr[r.auth_id]" class="sub">详情读取失败：{{ detailErr[r.auth_id] }}</div>
              <template v-else-if="details[r.auth_id]">
                <div v-if="details[r.auth_id].chain" class="kv">
                  <span>链上原文核验</span>
                  <b v-if="details[r.auth_id].chain!.match" class="ok">一致（指纹=链上原文）</b>
                  <b v-else class="bad">不一致（链上公示与归档指纹存在差异）</b>
                </div>
                <div v-else-if="details[r.auth_id].chain_error" class="kv">
                  <span>链上原文核验</span><span class="sub">链暂不可达（{{ details[r.auth_id].chain_error }}）</span>
                </div>
                <div class="kv"><span>验证结论</span>
                  <b>{{ details[r.auth_id].verify_tail ? details[r.auth_id].verify_tail!.split("\n").pop() : "已归档（该记录无验证日志摘要）" }}</b>
                </div>
                <div class="kv" v-if="details[r.auth_id].verify_s != null"><span>验证耗时</span><b>{{ details[r.auth_id].verify_s }}s</b></div>
                <div class="kv"><span>授权窗</span><b class="mono">{{ fmtTime(details[r.auth_id].t_start) }} ~ {{ fmtTime(details[r.auth_id].t_end) }}</b></div>
                <div class="kv"><span>高度上限</span><b>{{ details[r.auth_id].alt_max_m }} m</b></div>
                <div class="kv"><span>登记时间</span><b>{{ fmtTime(details[r.auth_id].created_at) }}</b></div>
                <div class="kv"><span>链上交易</span><HashText :value="details[r.auth_id].tx_hash" /></div>
                <div class="kv"><span>证明摘要（全文）</span>
                  <code class="fullhash">{{ details[r.auth_id].proof_digest_hex }}</code>
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

        <div class="card">
          <h3>检查点锚定</h3>
          <p class="expl">飞行中设备定期将截至当前的飞行记录指纹签名后锚定上链。锚定后的记录不可抵赖。</p>
          <div
            v-if="!data.chain || !data.chain.checkpoints.length"
            class="sub"
          >
            暂无锚定检查点
          </div>
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
              <div class="kv"><span>授权编号</span><b class="mono">#{{ cp.auth_id }}</b></div>
              <div class="kv"><span>锚定序号</span><b class="mono">第 {{ cp.seq }} 次</b></div>
              <div class="kv"><span>锚定时间</span><b>{{ fmtTime(cp.ts) }}</b></div>
              <div class="kv"><span>链头（全文）</span><code class="fullhash">{{ cp.chain_head_hex }}</code></div>
              <p class="sub">设备对该链头签名后上链；审计方可核验设备签名与链上记录的一致性。</p>
            </div>
          </div>
        </div>

        <div class="card">
          <h3>令状</h3>
          <p class="expl">审计方调取真实身份的程序留痕。令状登记与实名解锁全程上链，调取行为自身可追溯。</p>
          <div v-if="!data.warrants.length" class="sub">暂无令状</div>
          <div v-for="w in data.warrants" :key="w.warrant_hash_hex" class="rec">
            <button class="row rowbtn" :aria-expanded="openWarrant === w.warrant_hash_hex" @click="openWarrant = openWarrant === w.warrant_hash_hex ? null : w.warrant_hash_hex">
              <HashText :value="w.warrant_hash_hex" />
              <span v-if="w.target_auth_id" class="mono">授权 #{{ w.target_auth_id }}</span>
              <span class="caret">{{ openWarrant === w.warrant_hash_hex ? "收起" : "详情" }}</span>
            </button>
            <div v-if="openWarrant === w.warrant_hash_hex" class="detail">
              <div class="kv"><span>目标授权</span><b class="mono">#{{ w.target_auth_id ?? "—" }}</b></div>
              <div class="kv"><span>登记时间</span><b>{{ fmtTime(w.created_ts) }}</b></div>
              <div class="kv"><span>令状哈希（全文）</span><code class="fullhash">{{ w.warrant_hash_hex }}</code></div>
              <p class="sub">实名解锁须同时持有审计令状与登记机构出具的随案协作函，双重核验全部留痕。</p>
            </div>
          </div>
        </div>
      </div>
    </template>
  </section>
</template>

<style scoped>
.wrap { max-width: 980px; margin: 0 auto; }
h2 { margin: 4px 0 2px; font-size: 20px; }
.sub { color: var(--ink-3); font-size: 13px; margin: 2px 0 14px; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.card {
  background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 14px 16px; min-height: 88px;
}
.card h3 { font-size: 13px; margin: 0 0 6px; color: var(--ink-2); }
.expl { color: var(--ink-3); font-size: 12px; line-height: 1.6; margin: 0 0 10px; }
.kv { display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 3px 0; font-size: 13px; }
.kv > span:first-child { color: var(--ink-3); flex-shrink: 0; }
.row { display: flex; gap: 8px; align-items: center; padding: 4px 0; font-size: 12.5px; flex-wrap: wrap; }
.mono { font-family: var(--mono, monospace); color: var(--ink-2); }
.rec { border-bottom: 1px dashed var(--line); }
.rec:last-child { border-bottom: none; }
.rowbtn {
  background: none; border: none; cursor: pointer; text-align: left;
  color: inherit; font: inherit; width: 100%; padding: 4px 0;
}
.rowbtn:hover { color: var(--accent-ink); }
.caret { margin-left: auto; color: var(--ink-3); font-size: 11px; flex-shrink: 0; }
.detail {
  background: var(--bg-2, #f7f9fc); border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 12px; margin: 4px 0 10px; animation: fz-enter var(--t-fast) both;
}
.detail .kv { font-size: 12.5px; }
.fullhash {
  font-family: var(--mono, monospace); font-size: 11px; word-break: break-all;
  color: var(--ink-2); background: var(--panel); padding: 2px 4px; border-radius: 4px;
}
.ok { color: var(--ok, #2e7d32); font-weight: 600; }
.bad { color: #a33; font-weight: 600; }
.reverify { border-top: 1px dashed var(--line); margin-top: 8px; padding-top: 8px; }
.dlrow { display: flex; gap: 8px; flex-wrap: wrap; margin: 6px 0; }
.note { color: var(--ink-3); font-size: 11px; word-break: break-word; }
.deny { border: 1px solid #f3c2c2; background: #fdf3f3; color: #a33; border-radius: 10px; padding: 10px 14px; font-size: 13px; }
@media (prefers-reduced-motion: no-preference) { .card { transition: border-color var(--t-fast); } .card:hover { border-color: #c9dbfb; } }
</style>
