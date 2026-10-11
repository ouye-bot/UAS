<script setup lang="ts">
/** 应用壳（B8 队长指令改版；2026-09-29 账户批接手）：顶栏横导航（品牌居左+
 * 导航横排+状态/账户身份居右）。角色导航：按会话角色过滤 nav 项——飞手不见
 * 审计/机构入口（双层隔离的前端层，真权威在服务端 403）。守卫：未登录回门户。 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api, apiBase, bridge } from "./lib/api";
import { cachedRole, cachedUsername, changePassword, logout as authLogout } from "./lib/auth";
import { checkPasswordRules } from "./lib/enroll";

const router = useRouter();
const route = router.currentRoute;

// 角色/用户名响应式（实测教训：挂载时一次性快照=门户登录后导航永不更新——
// 登录前打开的页面 nav 恒空。路由切换时重读本地会话旗标）
const role = ref(cachedRole());
const username = ref(cachedUsername());
watch(
  () => route.value.fullPath,
  () => {
    role.value = cachedRole();
    username.value = cachedUsername();
  },
);
const ROLE_LABEL: Record<string, string> = { pilot: "飞手", auditor: "审计员", admin: "机构管理员" };

const nav = computed(() =>
  router.getRoutes()
    .filter((r) => r.meta?.title && r.meta?.nav)
    .filter((r) => {
      const need = r.meta?.role as string | string[] | undefined;
      if (!need) return true;
      return Array.isArray(need) ? need.includes(role.value ?? "") : need === role.value;
    })
    .map((r) => ({ path: r.path, title: r.meta.title as string, icon: r.meta.icon as string })),
);

// 登录态所属机构域徽标（2026-10-12 修整窗口③——B2 审计件：whoami.org_id
// 前端从未调用，多机构演示时评委无法分辨当前域。零后端：登录后/切页时拉取
// 一次并随路由刷新；拉取失败=徽标不渲染（不装一致）。
const orgId = ref<string | null>(null);
const whoamiTitle = computed(() =>
  orgId.value ? `已登录：${username.value ?? ""}（所属机构域 ${orgId.value}）` : `已登录：${username.value ?? ""}`,
);
async function refreshOrg(): Promise<void> {
  orgId.value = null;
  if (!username.value) return;
  try {
    const out = await api<{ org_id?: string }>("/auth/whoami");
    orgId.value = out.org_id ?? null;
  } catch { /* 徽标不渲染——不装一致 */ }
}
watch(
  () => route.value.fullPath,
  () => void refreshOrg(),
);
onMounted(() => void refreshOrg());

const apiOk = ref<boolean | null>(null);
const bridgeOk = ref<boolean | null>(null);

async function probe(): Promise<void> {
  try { await api("/ra/healthz"); apiOk.value = true; } catch { apiOk.value = false; }
  try { await bridge("/audit"); bridgeOk.value = true; } catch { bridgeOk.value = false; }
}
onMounted(probe);
// 20s 周期重探（P1 批，A-P2-6）：仅挂载时探测一次=「先开页面后起服务」红点
// 常驻到刷新——服务恢复后状态点自动转绿。
let probeTimer: ReturnType<typeof setInterval> | null = setInterval(probe, 20000);
onBeforeUnmount(() => { if (probeTimer) clearInterval(probeTimer); });

const icons: Record<string, string> = {
  id: "M4 5h16v14H4z M8 10a2 2 0 1 0 0.01 0 M12 10h5 M12 13h5 M7 16c.8-1.4 2.2-2 3-2s2.2.6 3 2",
  send: "M3 11 21 4l-7 17-3-7z M11 14 21 4",
  craft: "M12 3c2.5 0 4.5 2 4.5 4.5V11l3.5 3v2l-4-1.2V18l1.5 1.5V21L12 19.8 6.5 21v-1.5L8 18v-3.2L4 16v-2l3.5-3V7.5C7.5 5 9.5 3 12 3z",
  trail: "M5 19c3 0 3-4 6-4s3 4 6 4 M5 12c3 0 3-4 6-4s3 4 6 4 M5 5c3 0 3-2 6-2",
  chain: 'M4 7h6v4H4zM14 7h6v4h-6zM9 16h6v4H9z M7 9h8M11 15v-2',
  shield: "M12 3l7 3v5c0 5-3 8.5-7 10-4-1.5-7-5-7-10V6z M9 12l2 2 4-4",
  gov: "M4 21h16 M5 21V10l7-6 7 6v11 M9 21v-6h6v6 M9 12h.01M12 12h.01M15 12h.01"};

// 滚动浮现顶栏阴影（视觉深化批 C：>8px 挂 .scrolled——内容与顶栏分层感）
const scrolled = ref(false);
function onScroll(): void {
  scrolled.value = window.scrollY > 8;
}
onMounted(() => {
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
});
onBeforeUnmount(() => window.removeEventListener("scroll", onScroll));

function go(p: string): void {
  router.push(p);
}
async function logout(): Promise<void> {
  // 账户批：登出=服务端会话焚毁+本地会话态/内存私钥清零（密封件留服务器——
  // 换设备可再登录；本地 fzCred 等身份域由 sweepIfIdentityChanged 在换人时清扫）
  await authLogout();
  router.push("/login");
}

// ---- 自助修改密码（2026-10-12 修整窗口 P1）：改密码=重封不动钥——
// 私钥不变、会话延续；规范与注册同门槛（checkPasswordRules 单源）。
const pwOpen = ref(false);
const pwCurrent = ref("");
const pwNew = ref("");
const pwConfirm = ref("");
const pwErr = ref("");
const pwOk = ref(false);
const pwBusy = ref(false);
const pwChecks = computed(() => checkPasswordRules(pwNew.value, username.value ?? ""));
async function doChangePassword(): Promise<void> {
  pwErr.value = "";
  pwOk.value = false;
  if (!pwChecks.value.ok) {
    pwErr.value = `新密码未达标：${pwChecks.value.failures.join("、")}`;
    return;
  }
  if (pwNew.value !== pwConfirm.value) {
    pwErr.value = "两次输入的新密码不一致";
    return;
  }
  pwBusy.value = true;
  try {
    await changePassword(pwCurrent.value, pwNew.value);
    pwOk.value = true;
    pwCurrent.value = "";
    pwNew.value = "";
    pwConfirm.value = "";
  } catch (e) {
    const err = e as { message?: string; code?: string };
    pwErr.value = err.message ?? String(e);
  } finally { pwBusy.value = false; }
}
</script>

<template>
  <div class="page">
    <router-view v-if="route.meta?.fullscreen" />
    <template v-else>
    <header class="top" :class="{ scrolled }">
      <div class="brand" @click="go(role === 'pilot' ? '/record' : role === 'auditor' ? '/audit' : role === 'admin' ? '/admin' : '/login')">飞证</div>
      <nav class="hnav">
        <button
          v-for="n in nav"
          :key="n.path"
          class="nav-item"
          :class="{ active: route.path === n.path }"
          @click="go(n.path)"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
            <path :d="icons[n.icon]" />
          </svg>
          <span>{{ n.title }}</span>
        </button>
      </nav>
      <div class="right">
        <span class="svc" title="申请与授权服务"><span class="dot" :class="{ ok: apiOk, bad: apiOk === false }" />服务</span>
        <span class="svc" title="本机飞行桥接服务"><span class="dot" :class="{ ok: bridgeOk, bad: bridgeOk === false }" />桥接</span>
        <span v-if="username" class="whoami" :title="whoamiTitle">{{ ROLE_LABEL[role ?? ""] ?? role }} · {{ username }}<span v-if="orgId" class="org-badge" data-test="org-badge">{{ orgId }}</span></span>
        <button v-if="username" class="exit" title="修改密码（私钥不变——重封密封件，会话延续）" data-test="pw-change-open" @click="pwOpen = true">改密</button>
        <button class="exit" title="焚毁服务端会话并返回门户" @click="logout">退出</button>
      </div>
    </header>
    <!-- 自助修改密码浮层（改密码=重封不动钥——私钥不变、会话延续） -->
    <Transition name="fz-modal">
      <div v-if="pwOpen" class="pw-mask" @click.self="pwOpen = false">
        <div class="pw-modal panel" data-test="pw-change-modal">
          <h2>修改密码</h2>
          <p class="pw-desc">
            改密码=换锁不换钥：您的私钥不变（登录与签名语义不受影响），服务端密封件
            与资料密封件以新密码重封——本会话延续，其他已登录设备不受影响。
          </p>
          <label>当前密码</label>
          <input v-model="pwCurrent" type="password" autocomplete="current-password" />
          <label>新密码</label>
          <input v-model="pwNew" type="password" autocomplete="new-password" />
          <ul class="pw-rules">
            <li v-for="c in pwChecks.checks" :key="c.label" :class="{ pass: c.pass }">{{ c.pass ? "✓" : "·" }} {{ c.label }}</li>
          </ul>
          <label>确认新密码</label>
          <input v-model="pwConfirm" type="password" autocomplete="new-password" />
          <p v-if="pwErr" class="pw-err">{{ pwErr }}</p>
          <p v-if="pwOk" class="pw-done" data-test="pw-change-ok">✓ 密码已更换——密封件与资料已按新密码重封（下次登录用新密码）。</p>
          <div style="display:flex;gap:10px;margin-top:12px">
            <button class="btn" :disabled="pwBusy || !pwCurrent || !pwNew" @click="doChangePassword">
              {{ pwBusy ? "重封中…" : "确认修改（重封密封件）" }}
            </button>
            <button class="btn ghost" @click="pwOpen = false">关闭</button>
          </div>
        </div>
      </div>
    </Transition>
    <main class="main">
      <router-view v-slot="{ Component }">
        <transition name="page" appear>
          <component :is="Component" :key="route.fullPath" />
        </transition>
      </router-view>
    </main>
    </template>
  </div>
</template>

<style scoped>
.page { min-height: 100vh; display: flex; flex-direction: column; }
.top {
  display: flex; align-items: center; gap: 22px;
  padding: 12px 30px;
  border-bottom: var(--hairline);
  background: rgba(255, 255, 255, 0.78);
  backdrop-filter: blur(8px);
  position: sticky; top: 0; z-index: 5;
  transition: box-shadow var(--t-med);
}
.top.scrolled { box-shadow: 0 6px 20px -12px rgba(28, 42, 58, 0.25); }
.brand {
  font-size: 24px; font-weight: 750; letter-spacing: 8px; cursor: pointer;
  background: linear-gradient(120deg, var(--ink) 35%, var(--accent-ink) 75%);
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  position: relative; line-height: 1.2;
}
.brand::after {
  content: ""; position: absolute; left: 2px; bottom: -3px; width: 30px; height: 3px;
  border-radius: 2px; background: linear-gradient(90deg, var(--accent), var(--teal));
}
.hnav { display: flex; gap: 4px; }
.nav-item {
  display: flex; align-items: center; gap: 7px;
  border: 1px solid transparent; background: transparent; color: var(--ink-2);
  font-size: 13.5px; padding: 7px 13px; border-radius: var(--r-md);
  cursor: pointer; transition: all var(--t-fast); position: relative;
}
.nav-item svg { width: 16px; height: 16px; color: var(--ink-3); transition: color var(--t-fast), transform var(--t-fast); }
.nav-item:hover { background: var(--panel); border-color: var(--line); color: var(--ink); }
.nav-item:hover svg { color: var(--accent); transform: translateY(-1px); }
.nav-item.active { background: var(--accent-soft); border-color: #c9dbfb; color: var(--accent-ink); font-weight: 600; }
.nav-item.active svg { color: var(--accent); }
.nav-item.active::after {
  content: ""; position: absolute; left: 14px; right: 14px; bottom: -13px; height: 2px;
  border-radius: 1px; background: linear-gradient(90deg, var(--accent), var(--teal));
}
.right { margin-left: auto; display: flex; align-items: center; gap: 14px; }
.svc { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--ink-2); }
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--line-strong); }
.dot.ok { background: var(--ok); animation: fz-pulse 2.4s infinite; }
.dot.bad { background: var(--bad); }
/* （丙-2 M1）.audit-link 死样式已删除——模板零引用 */
.whoami { font-size: 12.5px; color: var(--ink-2); background: var(--panel); border: var(--hairline); border-radius: 999px; padding: 4px 12px; }
/* 机构域徽标（2026-10-12 修整窗口③）：登录态所属域常显——多机构形态的
   「当前操作者是谁」可见事实；与 whoami 同胶囊，accent 描边区分 */
.org-badge {
  display: inline-block; margin-left: 7px; padding: 0 8px; border-radius: 999px;
  font-size: 11px; font-weight: 650; color: var(--accent-ink);
  background: var(--accent-soft); border: 1px solid #c9dbfb; vertical-align: 1px;
}
.exit {
  border: 1px solid var(--line-strong); background: var(--panel); color: var(--ink-2);
  font-size: 12.5px; padding: 4px 12px; border-radius: var(--r-sm); cursor: pointer;
  transition: all var(--t-fast);
}
.exit:hover { color: var(--ink); border-color: var(--ink-3); }
.main { padding: 26px 34px; max-width: 1120px; width: 100%; margin: 0 auto; flex: 1; }

/* 自助改密浮层（2026-10-12 修整窗口 P1） */
.pw-mask { position: fixed; inset: 0; background: rgba(20, 28, 38, 0.45); backdrop-filter: blur(3px); z-index: 60; display: flex; align-items: center; justify-content: center; }
.pw-modal { width: min(460px, 92vw); max-height: 86vh; overflow: auto; }
.pw-desc { font-size: 12.5px; color: var(--ink-3); line-height: 1.7; margin: 6px 0 10px; }
.pw-rules { list-style: none; margin: 6px 0; padding: 0; display: flex; flex-wrap: wrap; gap: 4px 14px; }
.pw-rules li { font-size: 12px; color: var(--ink-3); }
.pw-rules li.pass { color: var(--ok); }
.pw-err { color: #c0392b; font-size: 12.5px; margin: 8px 0 0; }
.pw-done { color: var(--ok); font-size: 12.5px; margin: 8px 0 0; }
.fz-modal-enter-active { transition: opacity 160ms var(--ease); }
.fz-modal-enter-from { opacity: 0; }
.fz-modal-leave-active { display: none; }

/* 路由过渡（视觉深化批 D：淡入+上浮 8px/180ms——叙事引导一次视线即静止） */
.page-enter-active { transition: opacity 180ms var(--ease), transform 180ms var(--ease); }
.page-enter-from { opacity: 0; transform: translateY(8px); }
.page-leave-active { display: none; } /* 离场直切——新旧同屏会跳动 */
@media (max-width: 960px) {
  .top { flex-wrap: wrap; gap: 10px; }
  .hnav { order: 3; width: 100%; overflow-x: auto; }
  .nav-item.active::after { display: none; }
}
</style>

@media (min-width: 1600px) {
  html { font-size: 112.5%; }
  .main { max-width: 1280px; }
}
