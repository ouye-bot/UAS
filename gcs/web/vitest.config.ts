import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";

// vitest 4 实际吃的是本文件（优先于 vite.config.ts——丙-2 M3 前实测踩坑）。
// ui 挂载测试（tests/ui）需要 .vue 变换——显式挂 vue 插件；环境按文件头
// `@vitest-environment jsdom` 声明（v4 已移除 environmentMatchGlobs）。
export default defineConfig({
  plugins: [vue()],
  test: {
    globals: true,
    environment: "node",
  },
});
