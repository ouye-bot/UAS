<script setup lang="ts">
/** 门限解锁仪式留痕（2026-10-12 修整窗口——B3 仪式可视化共享件）。
 * 类型契约单源=lib/gov.ts（两台消费面直接从 lib 导入）。
 *
 * 数据契约（后端案甲响应附带/案乙回放同构）：
 * { k, domains, summoned, granted, not_summoned, rows:[{role, checks, decision}] }
 * checks 四关（真实现四键；替位注入形态三键——缺键不画，不装一致）。
 *
 * 诚实红线（复审洞 4）：只画**应召域**（summoned）——「凑够 k 域即停，第三域
 * 未被征询（少一次份额点出借=正确安全姿态）」must 显性讲出；「三域全列」即
 * 失真。关名用业务语言：请求台账在案/令状链上在案/双控批文在案/份额域同步。 */
import FzEmpty from "./FzEmpty.vue";
import type { CeremonyFace, CeremonyRow } from "../lib/gov";

const ROLE_LABEL: Record<string, string> = {
  admin: "机构管理员域",
  ra: "登记权威域",
  auditor: "审计员域",
};
const CHECK_LABEL: Record<string, string> = {
  request_registered: "解锁请求台账在案",
  warrant_on_chain: "令状链上在案",
  collab_approved: "双控批文在案",
  owner_set_synced: "份额域与治理席位同步",
};
const CHECK_ORDER = ["request_registered", "warrant_on_chain", "collab_approved", "owner_set_synced"];

const props = defineProps<{ ceremony: CeremonyFace | null }>();

function checksOf(row: CeremonyRow): { key: string; ok: boolean }[] {
  return CHECK_ORDER.filter((k) => k in (row.checks ?? {})).map((k) => ({
    key: k,
    ok: !!row.checks[k],
  }));
}
function decisionLabel(d: string): string {
  if (d === "granted") return "已出份额点";
  if (d.startsWith("denied:")) return `拒绝（${d.slice(7).split("+").map((x) => CHECK_LABEL[x] ?? x).join("、")}未过）`;
  return d;
}
</script>

<template>
  <div v-if="ceremony && ceremony.rows?.length" class="ceremony fz-enter" data-test="ceremony-trace">
    <div class="ceremony-head">
      <span class="ceremony-title">门限解锁仪式</span>
      <span class="fz-pill teal">{{ ceremony.threshold ?? `${ceremony.k}-of-${ceremony.domains.length}` }} 门限</span>
      <span class="fz-pill blue">应召 {{ ceremony.summoned.length }}/{{ ceremony.domains.length }} 域</span>
    </div>
    <p class="ceremony-note">
      实名解锁的钥匙层：解密钥拆为 {{ ceremony.domains.length }} 份入各治理角色域，任 {{ ceremony.k }} 域各自过四关校验后各出一份解密份额点、数学合成——
      <b>dᵢ 本身不出域，私钥全程不重组，单域失陷不可单独解实名</b>。每域独立留痕（append-only 审计）。
    </p>
    <div class="ceremony-grid">
      <div v-for="row in ceremony.rows" :key="row.role" class="ceremony-domain" :class="{ ok: row.decision === 'granted', bad: row.decision !== 'granted' }">
        <div class="cd-head">
          <b>{{ ROLE_LABEL[row.role] ?? row.role }}</b>
          <span class="fz-badge" :class="row.decision === 'granted' ? 'teal' : 'red'">{{ decisionLabel(row.decision) }}</span>
        </div>
        <div class="cd-checks">
          <span v-for="c in checksOf(row)" :key="c.key" class="cd-check" :class="{ ok: c.ok }">
            {{ c.ok ? "✓" : "✗" }} {{ CHECK_LABEL[c.key] ?? c.key }}
          </span>
        </div>
      </div>
    </div>
    <p v-if="ceremony.not_summoned?.length" class="ceremony-notsummoned">
      未征询：{{ ceremony.not_summoned.map((d) => ROLE_LABEL[d] ?? d).join("、") }}——已凑足 {{ ceremony.k }} 域即停（未被征询的域不出份额点、无审计行——少一次份额点出借是正确安全姿态）。
    </p>
  </div>
  <FzEmpty v-else text="暂无门限仪式留痕（legacy 信封历史数据无仪式——如实缺省）。" icon="doc" />
</template>

<style scoped>
.ceremony {
  margin-top: 10px; padding: 12px 14px; border: var(--hairline);
  border-left: 3px solid var(--tone-teal-fg, teal); border-radius: var(--r-sm);
  background: var(--panel-2, transparent); display: grid; gap: 8px;
}
.ceremony-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.ceremony-title { font-weight: 700; font-size: 13.5px; }
.ceremony-note { font-size: 12px; color: var(--ink-3); margin: 0; line-height: 1.7; }
.ceremony-grid { display: grid; gap: 8px; }
.ceremony-domain {
  border: var(--hairline); border-radius: var(--r-sm); padding: 8px 12px;
  border-left-width: 3px; background: var(--panel, transparent);
}
.ceremony-domain.ok { border-left-color: var(--ok, teal); }
.ceremony-domain.bad { border-left-color: #c0392b; }
.cd-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 13px; }
.cd-checks { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 4px; }
.cd-check { font-size: 12px; color: var(--ink-3); }
.cd-check.ok { color: var(--tone-teal-fg, teal); }
.ceremony-notsummoned { font-size: 12px; color: var(--ink-3); margin: 0; }
</style>
