<script setup lang="ts">
/** 角色水印 glyph（视觉 X 批 X1）：工作台 hero 带右侧的巨型描边图标——
 * 飞手=craft / 审计=shield / 机构=gov（App.vue 顶栏 icon 库同源路径）。
 * 3% 墨色、aria-hidden、pointer-events:none——不进无障碍树、不吃点击、
 * 零动画（纯静态构图层）。 */
const props = defineProps<{ glyph: "shield" | "gov" | "craft" }>();

const PATHS: Record<string, string> = {
  shield: "M12 3l7 3v5c0 5-3 8.5-7 10-4-1.5-7-5-7-10V6z M9 12l2 2 4-4",
  gov: "M4 21h16 M5 21V10l7-6 7 6v11 M9 21v-6h6v6 M9 12h.01M12 12h.01M15 12h.01",
  craft: "M12 3c2.5 0 4.5 2 4.5 4.5V11l3.5 3v2l-4-1.2V18l1.5 1.5V21L12 19.8 6.5 21v-1.5L8 18v-3.2L4 16v-2l3.5-3V7.5C7.5 5 9.5 3 12 3z",
};

void props;
</script>

<template>
  <svg
    class="fz-wm"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.1"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <path :d="PATHS[glyph]" />
  </svg>
</template>

<style scoped>
.fz-wm {
  position: absolute;
  right: 26px;
  top: 50%;
  transform: translateY(-50%);
  width: 148px;
  height: 148px;
  color: rgba(28, 42, 58, 0.03);
  pointer-events: none;
}
</style>
