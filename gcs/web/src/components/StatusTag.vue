<script setup lang="ts">
/** 状态标签：ok/bad/gold/accent/teal/neutral（teal=S 批 S7 台账对齐审计台语言）。 */
defineProps<{ tone?: "ok" | "bad" | "gold" | "accent" | "teal"; label: string }>();
</script>

<template>
  <span class="tag" :class="tone">{{ label }}</span>
</template>
