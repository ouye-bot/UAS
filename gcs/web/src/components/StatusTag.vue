<script setup lang="ts">
/** 状态标签：ok/bad/gold/accent/neutral。 */
defineProps<{ tone?: "ok" | "bad" | "gold" | "accent"; label: string }>();
</script>

<template>
  <span class="tag" :class="tone">{{ label }}</span>
</template>
