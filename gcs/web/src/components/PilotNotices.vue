<script lang="ts">
/** ⑧站触达闭环：飞手提醒条（被动获知面——首页红条/黄条）。
 * 纯展示组件（props 驱动——数据由视图拉 /ra/pilot/notices 后传入）：
 * 三段语义=吊销（红）/围栏违规（红）/子凭证到期（黄）；全空=不渲染
 * （既有可见文本零变化——浏览器 e2e 冻结面纪律）。 */
export interface PilotNoticeData {
  revoked: { master_cred_hash_hex: string; reason: string; epoch: number | null }[];
  violations: { auth_id: number; event_hash_hex: string; logged_at: string }[];
  expiring_subs: { sub_cred_hash_hex: string; expires_at: string; days_left: number }[];
}
export default {};
</script>

<script setup lang="ts">
defineProps<{ notices: PilotNoticeData | null }>();
</script>

<template>
  <div v-if="notices && (notices.revoked.length || notices.violations.length || notices.expiring_subs.length)" class="fz-notices">
    <div v-for="(r, i) in notices.revoked" :key="'rv' + i" class="fz-notice fz-notice-danger" data-test="notice-revoked">
      <b>您的凭证已被吊销</b>——起飞申请将被拒绝。理由：{{ r.reason || "（机构未附理由）" }}
      <template v-if="r.epoch != null">（公示纪元 {{ r.epoch }}）</template>
      。如有疑问请联系签发机构，恢复须机构双控复核。
    </div>
    <div v-if="notices.violations.length" class="fz-notice fz-notice-danger" data-test="notice-violation">
      <b>您的飞行记录中存在 {{ notices.violations.length }} 条围栏违规事件</b>
      ——已按零身份方式上链留证，监管机构可依令状程序追溯。请遵守作业高度与区域围栏。
    </div>
    <div v-for="(s, i) in notices.expiring_subs" :key="'ex' + i" class="fz-notice fz-notice-warn" data-test="notice-expiring">
      <b>一次性子凭证将在 {{ s.days_left }} 天内到期</b>
      （{{ s.expires_at.slice(0, 10) }}）——到期后未使用即作废，请尽快申请起飞或在「我的记录」重新签发。
    </div>
  </div>
</template>

<style scoped>
.fz-notices {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 10px 0;
}
.fz-notice {
  border-radius: 8px;
  padding: 10px 14px;
  font-size: 14px;
  line-height: 1.5;
}
.fz-notice-danger {
  border: var(--hairline);
  border-left: 4px solid #d64545;
  background: rgba(214, 69, 69, 0.08);
}
.fz-notice-warn {
  border: var(--hairline);
  border-left: 4px solid #d9963a;
  background: rgba(217, 150, 58, 0.08);
}
</style>
