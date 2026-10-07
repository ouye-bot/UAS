<script setup lang="ts">
/** 双钥汇流图（丙-2 M3：双控双签的「头号叙事」第一次被看见）——
 * 左=审计员钥签章点，右=机构管理员钥签章点（批准前缺右钥=灰点「虚位以待」），
 * 两条发丝线汇入中央请求指纹 req_fp。数据全部来自既有接口字段
 * （auditor_fp/admin_fp/fzc2_fingerprint_hex/req_fp，backend collab.py 视图层）。
 * 纯装饰层：aria-hidden + pointer-events:none——不进无障碍树、不吃点击；
 * 语义仍由卡片 kv 行单源承载。 */
const props = defineProps<{
  auditorFp?: string | null;
  adminFp?: string | null;
  reqFp?: string | null;
}>();
const short = (v?: string | null): string => (v ? v.slice(0, 8) : "····");
</script>

<template>
  <div class="fz-cf" aria-hidden="true">
    <span class="fz-cf-key">
      <i class="fz-cf-dot" />
      <span class="fz-cf-fp mono">{{ short(props.auditorFp) }}</span>
    </span>
    <span class="fz-cf-line" />
    <span class="fz-cf-core mono">{{ props.reqFp ? short(props.reqFp) : "——" }}</span>
    <span class="fz-cf-line fz-cf-line-rev" />
    <span class="fz-cf-key">
      <span class="fz-cf-fp mono">{{ short(props.adminFp) }}</span>
      <i class="fz-cf-dot" :class="{ off: !props.adminFp }" />
    </span>
  </div>
</template>

<style scoped>
.fz-cf {
  display: flex; align-items: center; gap: 7px;
  pointer-events: none;
  font-size: 10.5px; color: var(--ink-3);
}
.fz-cf-key { display: inline-flex; align-items: center; gap: 5px; flex: none; }
.fz-cf-dot {
  width: 7px; height: 7px; border-radius: 50%; flex: none;
  background: var(--accent);
  box-shadow: 0 0 0 2.5px var(--accent-soft);
}
/* 右钥未落（待批准）=灰点虚位——「缺一不可」的第二钥叙事 */
.fz-cf-dot.off { background: var(--line-strong); box-shadow: none; }
.fz-cf-fp { letter-spacing: 0.4px; }
/* 发丝线：由签章点汇向中央（向心渐深——方向性暗示汇流） */
.fz-cf-line {
  flex: 1 1 24px; min-width: 16px; max-width: 64px; height: 1px;
  background: linear-gradient(90deg, var(--line-strong), var(--ink-3));
  opacity: 0.5;
}
.fz-cf-line-rev { transform: scaleX(-1); }
.fz-cf-core {
  flex: none;
  padding: 1.5px 9px; border-radius: 999px;
  border: 1px dashed var(--line-strong);
  background: var(--panel-2);
  color: var(--ink-2); font-weight: 700; letter-spacing: 0.5px;
  font-variant-numeric: tabular-nums;
}
</style>
