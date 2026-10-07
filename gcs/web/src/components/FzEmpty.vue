<script setup lang="ts">
/** 空态（视觉 S 批 S2）：描边图标+文案——图标与顶栏 icon 同语言（24px 线性
 * 描边），aria-hidden 不进无障碍树、不吃点击；语义由文案单源承载（文案
 * 原样保留=替换前 note/sub 文本零改动）。 */
withDefaults(defineProps<{ text: string; icon?: "inbox" | "doc" | "chain" | "stamp" }>(), { icon: "inbox" });

const PATHS: Record<string, string> = {
  inbox: "M3 13l2.5-7h13L21 13 M3 13v6h18v-6 M3 13h5l1.5 2.5h5L16 13h5",
  doc: "M6 3h9l4 4v14H6z M15 3v4h4 M9 12h6 M9 16h6",
  chain: "M4 7h6v4H4zM14 7h6v4h-6zM9 16h6v4H9z M7 9h8M11 15v-2",
  stamp: "M5 21h14 M7 17.5h10 M8 15h8v-2c0-1.2-2.2-1.7-3.2-2.4a3.4 3.4 0 1 0-1.6 0C10.2 11.3 8 11.8 8 13z",
};
</script>

<template>
  <div class="fz-empty">
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.4"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path :d="PATHS[icon]" />
    </svg>
    <span>{{ text }}</span>
  </div>
</template>

<style scoped>
.fz-empty {
  display: flex; align-items: center; gap: 10px;
  color: var(--ink-3); font-size: 12.5px; padding: 6px 0;
}
.fz-empty svg { width: 24px; height: 24px; flex: none; opacity: 0.75; }
</style>
