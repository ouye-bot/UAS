<script setup lang="ts">
/** 真实拒绝响应展示盒——code+message 原样呈现（禁伪造）。
 * C-P3-5：message 支持 \n 双行（真实原因+提示并存），CSS pre-line 渲染。
 * 视觉深化批 C：拒绝出现瞬间，对最近焦点输入一次性 fz-shake（180ms 抖动+
 * 红边）——纯装饰联动，零校验逻辑改动；焦点不在输入上则跳过。 */
import { onMounted } from "vue";

defineProps<{ code: string; message: string }>();

onMounted(() => {
  const el = document.activeElement;
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    el.classList.remove("fz-shake");
    // 强制重排以重触发动画（连续两次拒绝也可感知）
    void el.offsetWidth;
    el.classList.add("fz-shake");
    window.setTimeout(() => el.classList.remove("fz-shake"), 400);
  }
});
</script>

<template>
  <div class="deny">
    <span class="code">✕ {{ code }}</span><span class="deny-msg">{{ message }}</span>
  </div>
</template>
