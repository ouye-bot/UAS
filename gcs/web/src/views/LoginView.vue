<script setup lang="ts">
/** 门户（2026-09-29 账户批重写）：登录 / 注册唯一前门。
 * - 登录：用户名+密码 → 本地解封私钥 → SM2 挑战-应答签名 → 会话 → 按角色进入
 *   （预置机构账户首次登录走"激活"分支——初始密码核对后当场生成钥对）。
 * - 注册（飞手）：①建账户（浏览器生成钥对，密码 KEK 密封上传——服务器零明文）
 *   ②补资料（实名+无人机→RA 签发上链，"上链注册"发生时刻）。
 * 密码=密封体系唯一人肉防线：8 位起步+字母+数字+弱密码黑名单（队长拍板）。
 */
import { computed, nextTick, onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { ApiError } from "../lib/api";
import DenyBox from "../components/DenyBox.vue";
import ParticleField from "../components/ParticleField.vue";
import {
  dropPendingRegistration,
  login as authLogin,
  loginWithSk,
  pendingRegistration,
  registerAccount,
  submitProfile,
  type LoginOutcome,
  type PendingRegistration,
} from "../lib/auth";
import { checkPasswordRules, type PasswordCheck } from "../lib/enroll";
import { DEVICE_SERIAL_UNAVAILABLE, getDeviceSerial } from "../lib/device";
import { classLabel } from "../lib/policy";

const router = useRouter();
const tab = ref<"login" | "register">("login");
const busy = ref(false);
const deny = ref<{ code: string; message: string } | null>(null);

// ---- 登录 ----
const liUsername = ref("");
const liPassword = ref("");
const liBusy = ref(false);
const activateHint = ref(false); // 预置机构账户首登激活提示

function homeOf(role: string): string {
  if (role === "auditor") return "/audit";
  if (role === "admin") return "/admin";
  return "/record";
}

async function doLogin(): Promise<void> {
  if (!liUsername.value.trim() || !liPassword.value) {
    deny.value = { code: "input_missing", message: "请输入用户名与密码" };
    return;
  }
  liBusy.value = true; deny.value = null; activateHint.value = false;
  try {
    const out: LoginOutcome = await authLogin(liUsername.value.trim(), liPassword.value);
    liPassword.value = ""; // 密码即焚（解封完成即无用）
    router.push(homeOf(out.role));
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "activation_failed") activateHint.value = true;
    deny.value = { code: err.code ?? "login_failed", message: err.message ?? String(e) };
  } finally {
    liBusy.value = false;
  }
}

// ---- 注册（两步）----
const reg = reactive({ username: "", password: "", password2: "" });
const regStep = ref<1 | 2>(1);
const regBusy = ref(false);
const regDone = ref(false);
const regCredHash = ref("");
const pwCheck = computed<PasswordCheck>(() => checkPasswordRules(reg.password, reg.username));
const pending = ref<PendingRegistration | null>(pendingRegistration());

// 资料（第二步——实名+无人机；签发上链在此发生）
const form = reactive({ id_number: "", cert_level: 3, sn: "", class_id: 1 });
const formErr = ref("");
// SN 单源（SN 绑定根治 2026-10-07）：序列号唯一读数源=桥 /engine_pub——
// 只读预填（用户看得到注册的是哪台设备；登记后 SN 与凭证绑定，换绑须重新
// 登记）。读数失败=空串+人话指引（不回落自由文本——自由 SN 首次 ARM 必
// sn_mismatch）。挂载即取（登录页注册径前置读取——进第二步时缓存已就绪）。
const snReady = ref(false);
onMounted(async () => {
  const sn = await getDeviceSerial();
  if (sn) form.sn = sn;
  snReady.value = true;
});

function fillSample(): void {
  form.id_number = "110101199001011234";
  form.cert_level = 3;
  form.class_id = 1;
}

function nextToProfile(): void {
  deny.value = null;
  if (!/^[A-Za-z0-9._-]{2,32}$/.test(reg.username.trim())) {
    deny.value = { code: "bad_username", message: "用户名仅限字母/数字/._-（2..32 位）" };
    return;
  }
  if (!pwCheck.value.ok) {
    deny.value = { code: "passphrase_weak", message: `密码未达标：${pwCheck.value.failures.join("、")}` };
    return;
  }
  if (reg.password !== reg.password2) {
    deny.value = { code: "passphrase_mismatch", message: "两次密码不一致" };
    return;
  }
  regBusy.value = true;
  registerAccount(reg.username.trim(), reg.password)
    .then(async (p) => {
      // 建户后静默登录（钥已在内存——挑战-应答签名，密码不重输）：
      // 第②步补资料走 /auth/profile 的 pilot 会话守卫
      await loginWithSk(p.username, p.sk);
      pending.value = p;
      regStep.value = 2;
      deny.value = null;
    })
    .catch((e) => {
      const err = e as ApiError;
      deny.value = { code: err.code ?? "register_failed", message: err.message ?? String(e) };
    })
    .finally(() => {
      regBusy.value = false;
    });
}

function submitProfileStep(): void {
  const p = pending.value;
  if (!p) {
    deny.value = { code: "session_lost", message: "注册会话丢失——请返回第一步重新开始" };
    return;
  }
  if (!/^\d{17}[\dXx]$/.test(form.id_number)) {
    formErr.value = "身份证号须为 18 位（末位可 X）";
    return;
  }
  if (!form.sn.trim()) {
    formErr.value = DEVICE_SERIAL_UNAVAILABLE;
    return;
  }
  if (!Number.isInteger(form.cert_level) || form.cert_level < 1 || form.cert_level > 4) {
    formErr.value = "资质等级须为 1..4";
    return;
  }
  if (!Number.isInteger(form.class_id) || form.class_id < 0 || form.class_id > 255) {
    formErr.value = "机型类须为 0..255";
    return;
  }
  formErr.value = "";
  regBusy.value = true; deny.value = null;
  submitProfile(p, {
    id_number: form.id_number,
    cert_level: form.cert_level,
    sn: form.sn.trim(),
    class_id: form.class_id,
  })
    .then((out) => {
      regCredHash.value = String(out.master_cred_hash_hex ?? "");
      regDone.value = true;
      dropPendingRegistration();
    })
    .catch((e) => {
      const err = e as ApiError;
      deny.value = { code: err.code ?? "profile_failed", message: err.message ?? String(e) };
    })
    .finally(() => {
      regBusy.value = false;
    });
}

function enterWorkspace(): void {
  router.push("/record");
}

// 门户页签键盘导航（视觉 S 批 S5 可及性三修）：role=tab + aria-selected +
// 左右方向键切换并把焦点带到新页签（可见文本与点击路径零变化）
const tabLoginBtn = ref<HTMLButtonElement | null>(null);
const tabRegisterBtn = ref<HTMLButtonElement | null>(null);
function onTabArrow(): void {
  const next = tab.value === "login" ? "register" : "login";
  tab.value = next;
  void nextTick(() => {
    (next === "login" ? tabLoginBtn : tabRegisterBtn).value?.focus();
  });
}

function backToAccount(): void {
  // 返回第一步=放弃当前账户（若已建）——如实告知需换用户名
  regStep.value = 1;
}

const keyFingerprint = computed(() => (pending.value?.pk ?? "").slice(0, 16));
</script>

<template>
  <div class="login-wrap">
    <div class="hero fz-enter">
      <ParticleField />
      <div class="brand">飞 证</div>
      <div class="tagline">合规证明解锁起飞 · 身份与轨迹全程零披露</div>
      <div class="chips">
        <span class="chip">国密 SM2 / SM3 / SM4</span>
        <span class="chip">零知识证明</span>
        <span class="chip">联盟链锚定</span>
        <span class="chip">登录零密码存储 · 挑战-应答签名</span>
      </div>
    </div>

    <div class="card fz-enter">
      <div class="tabs" role="tablist">
        <button
          ref="tabLoginBtn"
          class="tab"
          role="tab"
          :aria-selected="tab === 'login'"
          :class="{ on: tab === 'login' }"
          @click="tab = 'login'"
          @keydown.left.prevent="onTabArrow"
          @keydown.right.prevent="onTabArrow"
        >登录</button>
        <button
          ref="tabRegisterBtn"
          class="tab"
          role="tab"
          :aria-selected="tab === 'register'"
          :class="{ on: tab === 'register' }"
          @click="tab = 'register'"
          @keydown.left.prevent="onTabArrow"
          @keydown.right.prevent="onTabArrow"
        >飞手注册</button>
      </div>

      <!-- 登录 -->
      <template v-if="tab === 'login'">
        <p class="desc">密码仅在本机解封您的私钥——服务器不存密码、不存私钥。认证靠 SM2 挑战-应答签名。</p>
        <label>用户名</label>
        <input v-model="liUsername" class="mono" autocomplete="username" @keyup.enter="doLogin" />
        <label>密码</label>
        <input v-model="liPassword" type="password" autocomplete="current-password" @keyup.enter="doLogin" />
        <p v-if="activateHint" class="note">
          检测到该账户为预置机构账户（首次登录）——请核对初始密码；激活将当场生成本账户专属密钥。
        </p>
        <div style="margin-top: 14px">
          <button class="btn" :disabled="liBusy" @click="doLogin">
            {{ liBusy ? "解封与签名中…" : "登录" }}
          </button>
        </div>
        <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
        <p class="foot">审计员 / 机构管理员使用部署方交付的账户；飞手请先注册。</p>
      </template>

      <!-- 注册 -->
      <template v-else>
        <ol class="steps">
          <li :class="{ on: regStep === 1, done: regStep > 1 }">1. 建账户（生成密钥）</li>
          <li :class="{ on: regStep === 2 }">2. 补资料（签发上链）</li>
        </ol>

        <template v-if="regStep === 1">
          <p class="desc">密钥在本机生成，以密码密封后上传——服务器只有密封件，无法登录您的身份。</p>
          <label>用户名（字母/数字/._-，2..32 位）</label>
          <input v-model="reg.username" class="mono" />
          <label>密码（8 位起步，字母+数字——本密码同时用于登录与私钥解封）</label>
          <input v-model="reg.password" type="password" />
          <ul class="pw-rules" v-if="reg.password">
            <li v-for="c in pwCheck.checks" :key="c.label" :class="c.pass ? 'ok' : 'no'">
              {{ c.pass ? "✓" : "✗" }} {{ c.label }}
            </li>
          </ul>
          <label>再次输入密码</label>
          <input v-model="reg.password2" type="password" />
          <div class="wiz-actions">
            <button class="btn" :disabled="regBusy" @click="nextToProfile">
              {{ regBusy ? "生成密钥与密封中…" : "生成密钥并建账户" }}
            </button>
          </div>
          <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
        </template>

        <template v-else-if="regStep === 2">
          <p class="desc">
            账户已建立（密钥指纹 <span class="mono">{{ keyFingerprint }}…</span>）。
            补全实名与无人机资料后，登记权威将<b>自动签发凭证并上链</b>——这是"上链注册"发生的时刻。
          </p>
          <label>身份证号（18 位）</label>
          <input v-model="form.id_number" maxlength="18" />
          <label>无人机序列号（自动读取自本机地面站桥——登记后与凭证绑定，不可手改）</label>
          <input v-model="form.sn" class="mono" readonly
                 title="序列号单源=本机地面站桥读数（与飞行解锁校验同一台设备）——用户不可修改" />
          <p v-if="snReady && !form.sn" class="step-err">{{ DEVICE_SERIAL_UNAVAILABLE }}</p>
          <div class="row2">
            <div>
              <label>资质等级（1..4）</label>
              <input v-model.number="form.cert_level" type="number" min="1" max="4" />
            </div>
            <div>
              <label>机型类（0=微型 1=轻型 2=小型 3=中型）</label>
              <input v-model.number="form.class_id" type="number" min="0" max="255" />
            </div>
          </div>
          <p v-if="formErr" class="step-err">{{ formErr }}</p>
          <dl class="summary" v-if="form.id_number.length === 18">
            <div><dt>身份证号</dt><dd>{{ form.id_number.slice(0, 4) }}********{{ form.id_number.slice(14) }}（脱敏展示）</dd></div>
            <div><dt>机型类</dt><dd>{{ form.class_id }}（{{ classLabel(form.class_id) }}）</dd></div>
          </dl>
          <div class="wiz-actions">
            <button class="btn ghost" :disabled="regBusy" @click="backToAccount">返回</button>
            <button class="btn" :disabled="regBusy || regDone" @click="submitProfileStep">
              {{ regDone ? "✓ 凭证已签发" : regBusy ? "RA 签发与上链中…" : "提交资料并签发上链" }}
            </button>
            <button class="linkish" type="button" @click="fillSample">填入示例数据</button>
          </div>
          <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
          <div v-if="regDone" class="fz-enter done-box">
            <p class="note">✓ 主凭证已签发：承诺哈希 <span class="mono">{{ regCredHash.slice(0, 16) }}…</span> 已入登记权威并锚定上链。资料密文已存档——换设备登录自动恢复。</p>
            <button class="btn" @click="enterWorkspace">进入飞证工作台</button>
          </div>
        </template>
      </template>
    </div>
  </div>
</template>

<style scoped>
.login-wrap {
  min-height: 100vh;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 26px; padding: 40px 18px;
}
.hero { text-align: center; position: relative; }
.brand {
  font-size: 52px; font-weight: 700; letter-spacing: 18px; color: var(--ink);
  text-indent: 18px;
  background: linear-gradient(120deg, var(--ink) 30%, var(--accent-ink) 70%, var(--teal));
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
}
.tagline { margin-top: 10px; color: var(--ink-2); font-size: 15px; letter-spacing: 2px; }
.chips { margin-top: 16px; display: flex; gap: 9px; justify-content: center; flex-wrap: wrap; }
.chip {
  font-size: 12px; color: var(--accent-ink); background: var(--accent-soft);
  border: 1px solid #c9dbfb; border-radius: 999px; padding: 3px 13px;
  transition: transform var(--t-fast), box-shadow var(--t-fast);
}
.chip:hover { transform: translateY(-2px); box-shadow: var(--shadow-2); }
.chip:nth-child(2n) { color: var(--teal); background: #e8f4f7; border-color: #bfe0e8; }
.card {
  width: 480px; max-width: 94vw;
  background: var(--panel); border: var(--hairline); border-radius: var(--r-lg);
  padding: 26px 30px; box-shadow: var(--shadow-2);
}
.tabs { display: flex; gap: 6px; margin-bottom: 16px; border-bottom: var(--hairline); padding-bottom: 10px; }
.tab {
  flex: 1; padding: 8px 0; font-size: 14px; border: 1px solid transparent; border-radius: var(--r-md);
  background: transparent; color: var(--ink-3); cursor: pointer; transition: all var(--t-fast);
}
.tab.on { color: var(--accent-ink); background: var(--accent-soft); border-color: #c9dbfb; font-weight: 600; }
.steps {
  display: flex; gap: 8px; list-style: none; padding: 0; margin: 0 0 16px;
  font-size: 12.5px; color: var(--ink-3);
}
.steps li { padding: 4px 10px; border-radius: 999px; border: 1px solid transparent; }
.steps li.on { color: var(--accent-ink); border-color: #c9dbfb; background: var(--accent-soft); font-weight: 600; }
.steps li.done { color: var(--teal); }
.desc { font-size: 12.5px; color: var(--ink-2); line-height: 1.7; margin: 0 0 10px; }
.pw-rules { list-style: none; margin: 8px 0 0; padding: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 3px 14px; }
.pw-rules li { font-size: 12px; }
.pw-rules li.ok { color: var(--teal); }
.pw-rules li.no { color: var(--tone-amber-fg); }
.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.summary { margin: 12px 0 0; display: grid; gap: 6px; }
.summary div { display: flex; justify-content: space-between; gap: 12px; }
.summary dt { color: var(--ink-3); }
.summary dd { margin: 0; font-family: ui-monospace, monospace; font-size: 12.5px; }
.step-err { color: #c0392b; font-size: 12.5px; margin: 8px 0 0; }
.wiz-actions { display: flex; gap: 10px; margin-top: 14px; align-items: center; }
.linkish {
  background: none; border: none; color: var(--ink-3); font-size: 12px;
  cursor: pointer; padding: 0; margin-left: auto; text-decoration: underline;
}
.foot { font-size: 11.5px; color: var(--ink-3); border-top: var(--hairline); padding-top: 10px; margin: 14px 0 0; }
.done-box { border-top: var(--hairline); padding-top: 12px; margin-top: 12px; }
.note { font-size: 12.5px; color: var(--ink-2); line-height: 1.8; }
@media (prefers-reduced-motion: reduce) { .chip:hover { transform: none; } }
</style>
