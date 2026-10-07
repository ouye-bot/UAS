import { createRouter, createWebHashHistory } from "vue-router";
import LoginView from "./views/LoginView.vue";
import RecordView from "./views/RecordView.vue";
import ApplyView from "./views/ApplyView.vue";
import FlightView from "./views/FlightView.vue";
import TrailView from "./views/TrailView.vue";
import ChainView from "./views/ChainView.vue";
import AuditView from "./views/AuditView.vue";
import AdminView from "./views/AdminView.vue";
import { cachedRole } from "./lib/auth";

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", redirect: "/login" },
    { path: "/login", component: LoginView, meta: { fullscreen: true } },
    // 飞手工作台（账户批：role=pilot 守卫——导航不渲染+守卫双层，真权威在服务端 403）
    { path: "/record", component: RecordView, meta: { title: "我的记录", icon: "id", nav: true, role: "pilot" } },
    { path: "/apply", component: ApplyView, meta: { title: "起飞申请", icon: "send", nav: true, role: "pilot" } },
    { path: "/flight", component: FlightView, meta: { title: "令牌与飞行", icon: "craft", nav: true, role: "pilot" } },
    { path: "/trail", component: TrailView, meta: { title: "留痕与合规证明", icon: "trail", nav: true, role: "pilot" } },
    // 回执查询页已删除（2026-10-04 队长指令）——回执码消费主路径=FlightView
    // 取件；GET /authz/receipt/{code} 零身份公开端点保留（能力不删，删的是页面）
    { path: "/chain", component: ChainView, meta: { title: "链上留痕", icon: "chain", nav: true } },
    // 审计员 / 机构管理员工作台（2026-09-29 账户批 B3：飞手端同风格 Vue 重做）
    { path: "/audit", component: AuditView, meta: { title: "审计台", icon: "shield", nav: true, role: "auditor" } },
    { path: "/admin", component: AdminView, meta: { title: "机构台", icon: "gov", nav: true, role: "admin" } },
  ],
});

// 角色守卫（账户批）：本地角色标签做第一层（切页体验）；服务端会话+角色依赖
// 是真权威（401/403）——本地标签只是缓存，伪造标签在第一个 API 调用即被拒。
router.beforeEach((to) => {
  const need = to.meta?.role as string | undefined;
  if (!need) return true;
  const role = cachedRole();
  if (!role) return "/login";
  if (role !== need) {
    return role === "auditor" ? "/audit" : role === "admin" ? "/admin" : "/record";
  }
  return true;
});
