import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";
import { router } from "./router";
import "./styles/tokens.css";
import "./styles/ui.css";

// Pinia（状态收敛批）：渐进式接入——存量视图不强制迁移，新代码走 store
// （stores/session|material|flight，语义单源仍在 lib/*，store 只承载响应式）。
createApp(App).use(createPinia()).use(router).mount("#app");
