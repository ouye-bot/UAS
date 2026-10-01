<script setup lang="ts">
/** 哈希/长 hex 展示：截断+悬停完整+点击复制（微交互）。 */
import { ref } from "vue";

const props = withDefaults(defineProps<{ value: string; head?: number | string; tail?: number | string }>(), { head: 10, tail: 8 });
const copied = ref(false);

const short = (): string => {
  const v = props.value || "";
  const h = Number(props.head), t = Number(props.tail);
  if (v.length <= h + t + 1) return v;
  return v.slice(0, h) + "…" + v.slice(-t);
};

async function copy(): Promise<void> {
  try {
    await navigator.clipboard.writeText(props.value);
    copied.value = true;
    setTimeout(() => (copied.value = false), 900);
  } catch { /* 剪贴板不可用静默 */ }
}
</script>

<template>
  <span class="hash mono" :title="value" @click="copy">
    {{ short() }}<span v-if="copied" class="copied">已复制</span>
  </span>
</template>

<style scoped>
.hash { cursor: copy; border-bottom: 1px dashed var(--line-strong); transition: color var(--t-fast); }
.hash:hover { color: var(--accent-ink); }
.copied { margin-left: 6px; color: var(--ok); font-size: 11px; animation: fz-enter var(--t-fast) both; }
</style>
