/** 会话 store（Pinia 收敛批）：会话/角色/清扫的响应式门面。
 *
 * 渐进式纪律：存量视图不强制迁移——auth.ts 的旗标读写函数仍是单一事实源，
 * 本 store 只是把它变成响应式（角色导航/守卫类新代码从这里读，不再各自
 * 手读 localStorage）。既有键名 fzSession 原样保留兼容；清扫语义
 * （material 的四表：身份域/会话域/账户切换/登出清扫）由 store 动作承载，
 * 底层仍引 lib/material 单源函数，禁止手抄键名。
 */
import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { cachedRole, cachedUsername, type Role } from "../lib/auth";
import { sweepLocalIdentity } from "../lib/material";

export const useSessionStore = defineStore("session", () => {
  const username = ref<string | null>(cachedUsername());
  const role = ref<Role | null>(cachedRole());

  const loggedIn = computed(() => !!username.value);

  /** 从本地旗标重读（fzSession 是跨标签页的单一事实源——storage 事件或
   * 路由切换后调用；store 不私藏状态，随时可与旗标对账）。 */
  function refresh(): void {
    username.value = cachedUsername();
    role.value = cachedRole();
  }

  /** 登出清扫（语义同 auth.logout 的本地面）：焚会话旗标+身份域四表清扫。
   * 服务端会话焚毁仍走 lib/auth.logout（网络动作，本 store 不发请求）。 */
  function clearLocal(): boolean {
    localStorage.removeItem("fzSession");
    const swept = sweepLocalIdentity();
    refresh();
    return swept;
  }

  return { username, role, loggedIn, refresh, clearLocal };
});
