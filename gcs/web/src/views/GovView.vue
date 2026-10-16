<script setup lang="ts">
/** 链上治理公示页（2026-10-12 修整窗口——自机构台拆独立路由 /governance）。
 *
 * admin+auditor 双角色可见（auditor 是三份额域之一——席位变更直接干系其
 * 验签纪元钥；/chain/governance 本就无角色门，双可见只是导航层呈现，零安全
 * 含义）。只读公示：k-of-n 提案全生命周期/席位/时间锁档+份额域失同步红牌+
 * 互认机构名册（⑥站 federation 块——名册/锚纪元/聚合根，只读展示准入结果，
 * 不做机构登记操作动线=修整窗口拍板「砍」项）。
 * 链不可达或 fake 档=整卡诚实空态（不谎称空、不装一致——govAvailable 范式）。
 * 10s 轮询（链上公示节奏——与原机构台治理大屏同拍）。 */
import { onBeforeUnmount, onMounted, ref } from "vue";
import { api } from "../lib/api";
import type {
  FederationOrgRow,
  GovernanceFace,
  GovernanceProposalRow,
} from "../lib/gov";
import FzEmpty from "../components/FzEmpty.vue";
import ParticleField from "../components/ParticleField.vue";
import FzWatermark from "../components/FzWatermark.vue";

const gov = ref<GovernanceFace | null>(null);
const govAvailable = ref(true);
const govLoaded = ref(false);

async function refresh(): Promise<void> {
  try {
    gov.value = await api<GovernanceFace>("/chain/governance");
    govAvailable.value = true;
  } catch {
    govAvailable.value = false;
  }
  govLoaded.value = true;
}
let govTimer: ReturnType<typeof setInterval> | null = null;
onMounted(() => {
  void refresh();
  govTimer = setInterval(() => void refresh(), 10000);
});
onBeforeUnmount(() => {
  if (govTimer) clearInterval(govTimer);
});

function govTone(st: GovernanceProposalRow["status"]): string {
  return { active: "amber", queued: "blue", executed: "teal", cancelled: "gray" }[st] ?? "gray";
}
function govLabel(st: GovernanceProposalRow["status"]): string {
  return (
    { active: "表决中", queued: "时间锁中", executed: "已执行", cancelled: "已取消" }[st] ??
    String(st)
  );
}
function govEta(etaUnixS: number): string {
  if (!etaUnixS) return "—";
  const remain = Math.round(etaUnixS - Date.now() / 1000);
  if (remain <= 0) return "到期可执行";
  const h = Math.floor(remain / 3600);
  const m = Math.floor((remain % 3600) / 60);
  return h > 0 ? `剩余 ${h}h${m}m` : `剩余 ${m}m${remain % 60}s`;
}
function govDelayTag(delayS: number): { text: string; tone: string } {
  return delayS >= 86400
    ? { text: "生产档 24h", tone: "teal" }
    : { text: `演示档 ${delayS}s`, tone: "amber" };
}
function orgStatus(o: FederationOrgRow): { label: string; tone: string } {
  return o.status === 1 ? { label: "在册互认", tone: "teal" } : { label: "已退出（锚冻结保留）", tone: "gray" };
}
function shortRoot(hex: string): string {
  return hex ? `${hex.slice(0, 16)}…` : "—";
}
</script>

<template>
  <div class="fz-enter">
    <!-- 头部横幅（与机构台/审计台同语言） -->
    <div class="fz-hero-band fz-ticks">
      <ParticleField />
      <FzWatermark glyph="gov" />
      <div class="fz-hero-inner">
        <div class="fz-hero-title">链上治理</div>
        <div class="fz-hero-sub">提案 → 多签确认 → 时间锁 → 执行 · 治理面变更不绕过治理面 · 每一步公示可追责</div>
      </div>
    </div>

    <!-- k-of-n 公示大屏（自机构台整体迁入——面板文本原样保留） -->
    <div class="panel" v-if="govAvailable && gov">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;flex-wrap:wrap">
        <h2 style="margin:0">链上治理（多签协同 k-of-n）</h2>
        <template v-if="gov.chain">
          <span class="fz-pill teal">{{ gov.chain.required }}/{{ gov.chain.owner_count }} 多签</span>
          <span class="fz-pill" :class="govDelayTag(gov.chain.delay_s).tone">
            {{ govDelayTag(gov.chain.delay_s).text }}
          </span>
          <span class="fz-pill gray">累计提案 {{ gov.chain.proposal_count }}</span>
        </template>
      </div>
      <FzEmpty
        v-if="!gov.chain"
        :text="gov.mode === 'fake'
          ? '演示链档——治理公示面随真链提供（AdminGovernor k-of-n：提案→多签→时间锁→执行）。'
          : '链不可达——治理公示面暂不可读（恢复后自动填充）。'"
        icon="doc"
      />
      <template v-if="gov.chain">
      <p class="desc">
        政策公示/指纹锚定/治理席位变更——每一条链上治理写入都经
        「提案 → 多签确认 → 时间锁 → 执行」四步，全程事件上链可追责；
        owner 增删与法定票数变更同样走此仪式（治理面变更不绕过治理面）。
        份额刷新（全域钥匙重分割）同为治理域动作——由治理提案仪式触发。
      </p>
      <div class="tbl-wrap" v-if="gov.chain.proposals.length">
        <table class="tbl">
          <thead>
            <tr><th>#</th><th>治理动作</th><th>目标</th><th>确认</th><th>状态</th><th>时间锁</th></tr>
          </thead>
          <tbody>
            <tr v-for="p in gov.chain.proposals" :key="p.proposal_id">
              <td class="mono">{{ p.proposal_id }}</td>
              <td>{{ p.description || "—" }}</td>
              <td class="mono">{{ p.target }}</td>
              <td class="mono">{{ p.confirmations }}/{{ gov!.chain!.required }}</td>
              <td><span class="fz-badge" :class="govTone(p.status)">{{ govLabel(p.status) }}</span></td>
              <td class="mono">{{ p.status === "queued" ? govEta(p.eta_unix_s) : "—" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <FzEmpty v-else text="尚无治理提案记录。" icon="doc" />
      <!-- 1.3 件②：份额域失同步红牌（治理席位变更后未重分割——解锁面
          第④关同步 fail-closed；红牌=漂移检测在案+reshare 提案已自动起草
          （Queued 待确认），confirm/execute 由治理面人工完成） -->
      <p
        v-if="gov.threshold_sync && gov.threshold_sync.synced === false"
        data-test="threshold-sync-flag"
        class="req-meta"
        style="color:#c0392b;border:1px solid #e6b0aa;border-radius:8px;padding:8px 12px;margin-top:10px"
      >
        ⛔ 份额域失同步：治理席位已变更（owner-set 指纹漂移）而份额未重分割
        ——门限解锁已被 fail-closed 拦截。同步 watcher 将自动起草重分割提案
        （待治理多签确认+时间锁执行）；公示落地后系统自动完成份额重分割并
        解除拦截（人工需完成多签确认与执行两步）。
      </p>
      <div class="req-meta" style="margin-top:6px">
        治理席位（{{ gov.chain.owner_count }}）：
        <span v-for="o in gov.chain.owners" :key="o.address" style="margin-right:10px">
          <span class="mono">{{ o.short }}</span>
          <span v-if="o.role" class="fz-badge blue">{{ o.role }}</span>
        </span>
      </div>
      </template>
    </div>
    <div class="panel" v-else-if="govLoaded && !govAvailable">
      <h2>链上治理（多签协同 k-of-n）</h2>
      <FzEmpty text="治理公示面暂不可达（恢复后自动填充）。" icon="doc" />
    </div>

    <!-- 互认机构面板（⑥站 federation 公示——B1 审计件零渲染缺口根修）：
        只读名册+逐域撤销锚+全局聚合根。只读展示准入结果，不做登记操作动线
        （修整窗口拍板：机构登记准入动线砍——准入=部署/种子面事务）。 -->
    <div class="panel" v-if="govAvailable && gov">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;flex-wrap:wrap">
        <h2 style="margin:0">互认机构名册</h2>
        <template v-if="gov.federation">
          <span class="fz-pill teal">在册 {{ gov.federation.org_active }} 域</span>
          <span class="fz-pill gray">聚合纪元 {{ gov.federation.global_rev_epoch }}</span>
        </template>
      </div>
      <FzEmpty
        v-if="!gov.federation"
        :text="gov.mode === 'fake'
          ? '互认注册表随真链提供——演示链档下本面板诚实空缺（跨域互认/聚合根公示在真链档实弹）。'
          : '互认注册表暂不可读（一期前部署或链不可达——恢复后自动填充）。'"
        icon="doc"
      />
      <template v-else>
        <p class="desc">
          各机构域以自身登记权威署名推撤销锚（谁何时推到哪个根——归因公示）；
          全局聚合根=逐机构 (域‖纪元‖锚根) 密码学聚合——任一机构的吊销经聚合
          根被全体互认（退出机构锚冻结保留在聚合：历史吊销永久互认，不得以
          退出换撤销失效）。
        </p>
        <div class="tbl-wrap" v-if="gov.federation.orgs.length">
          <table class="tbl">
            <thead>
              <tr><th>机构域</th><th>准入状态</th><th>锚纪元</th><th>锚根（SM3）</th><th>登记/最近推根</th></tr>
            </thead>
            <tbody>
              <tr v-for="o in gov.federation.orgs" :key="o.org_id">
                <td class="mono">{{ o.org_id }}</td>
                <td><span class="fz-badge" :class="orgStatus(o).tone">{{ orgStatus(o).label }}</span></td>
                <td class="mono">{{ o.rev_epoch }}</td>
                <td class="mono">{{ shortRoot(o.rev_root_hex) }}</td>
                <td class="mono">{{ o.registered_ts ? new Date(o.registered_ts * 1000).toISOString().slice(0, 16).replace("T", " ") : "—" }} / {{ o.anchor_ts ? new Date(o.anchor_ts * 1000).toISOString().slice(0, 16).replace("T", " ") : "—" }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <FzEmpty
          v-else
          text="名册为空——互认随治理准入扩展（机构登记=部署/种子面事务，走治理提案仪式）。"
          icon="doc"
        />
        <p v-if="gov.federation.orgs.length === 1" class="note" data-test="federation-single-org">
          在册 1 域——互认随治理准入扩展（第二机构登记后此处自动呈现双域名册与聚合根更迭）。
        </p>
        <div class="fp-box" style="margin-top:10px">
          <span class="fp-label">全局撤销树聚合根（任何人可独立复算对拍）</span>
          <div class="kv" style="margin-top:4px">
            <dt>聚合纪元</dt><dd class="mono">{{ gov.federation.global_rev_epoch }}</dd>
            <dt>聚合根</dt><dd class="mono">{{ gov.federation.global_rev_root_hex.slice(0, 32) }}…</dd>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<style scoped>
.tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.tbl th { text-align: left; color: var(--ink-3); font-weight: 600; padding: 6px 10px; border-bottom: var(--hairline); }
.tbl td { padding: 8px 10px; border-bottom: 1px solid var(--line); }
.req-meta { font-size: 12.5px; color: var(--ink-3); }
.note { font-size: 12.5px; color: var(--ink-3); }
.fp-box {
  padding: 10px 12px; border: var(--hairline);
  border-left: 3px solid var(--tone-gold-fg); border-radius: var(--r-sm);
  background: var(--panel-2); display: grid; gap: 6px;
}
.fp-label { font-size: 11.5px; color: var(--ink-3); }
.kv { display: grid; grid-template-columns: 90px 1fr; gap: 4px 10px; font-size: 12.5px; margin: 0; }
.kv dt { color: var(--ink-3); }
.kv dd { margin: 0; }
</style>
