<script setup lang="ts">
/** 屏①我的记录（说明书 §7.3）：凭证展示/子凭证签发/撤销快照——真实 RA 面。
 * 登记承诺已前移至入口页（登录/注册）；本屏展示与一次性子凭证管理。 */
import { computed, onMounted, ref } from "vue";
import { sm2 } from "sm-crypto";
import { api, ApiError } from "../lib/api";
import HashText from "../components/HashText.vue";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";
import ParticleField from "../components/ParticleField.vue";
import { storedPk, cacheSk } from "../lib/keystore";
import { storeSubBinding, subMatchesMaterial, storeIdentityTag, storeSubSk, storedSubPk } from "../lib/material";
import { me as authMe, unlockSk } from "../lib/auth";
import { sealProfileSlot } from "../lib/keystore";
import { classLabel } from "../lib/policy";

const busy = ref(false);
const deny = ref<{ code: string; message: string } | null>(null);
const cred = ref<Record<string, any> | null>(null);
const sub = ref<Record<string, any> | null>(null);
const snap = ref<Record<string, any> | null>(null);
const staleSub = ref(false);
const revokeCheck = ref<null | { ok: boolean; message: string; detail?: string }>(null);
const checking = ref(false);

// 子凭证剩余有效期（R3-2：过期态可视化——「不知道自己为什么被拒」清零）
const subRemainText = computed(() => {
  const exp = sub.value?.expires_at;
  if (!exp) return "";
  const ms = new Date(exp.endsWith("Z") ? exp : exp + "Z").getTime() - Date.now();
  if (ms <= 0) return "已过期——请重签";
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `剩余 ${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
});
const subExpired = computed(() => subRemainText.value.startsWith("已过期"));

/** 撤销自查（R3-2，评审 P1-4）：调非成员见证端点——「撤销名单进电路」卖点
 * 的飞手侧可交互验证：ok=不在名单（见证已核）；revoked=已列入（申请将被拒）。 */
async function checkRevocation(): Promise<void> {
  checking.value = true;
  revokeCheck.value = null;
  try {
    const { api } = await import("../lib/api");
    // 核验键=电路实际消费的出示公钥 pk′.x（签发后随子凭证）；未签发时回退
    // 账户公钥（旧协议撤销名单的历史遗留形态——仅提示性）。
    const pk = storedSubPk() || userPk();
    if (!pk) throw new ApiError("no_pk", "本机密钥库缺失", 0);
    const w = await api<Record<string, any>>(
      `/ra/revocation/witness?holder_pk_hex=${pk.toLowerCase()}`,
    );
    revokeCheck.value = {
      ok: true,
      message: "未被吊销——已按最新公示名单核验，可正常申请",
      // 技术核对值收进小字附注（飞手文案说人话纪律——术语不进主标签）
      detail: `技术核对值：名单版本 ${w.epoch} · 公示根 ${String(w.root_hex).slice(0, 12)}…`,
    };
  } catch (e: any) {
    if (e?.code === "revoked")
      revokeCheck.value = { ok: false, message: "已列入吊销名单——提交申请会被自动拒绝，如有疑问请联系管理部门" };
    else revokeCheck.value = { ok: false, message: e?.message ?? String(e) };
  } finally {
    checking.value = false;
  }
}

// P1-A：子凭证签发仅需公钥（私钥零接触——明文生成路径已废除）。
// 2026-10-01 一次性出示钥批：账户公钥仅作「未签发时」的撤销自查回退（旧协议
// 撤销名单可能含账户钥形态的历史遗留）；出证身份以子凭证自带 pk′ 为准。
function userPk(): string {
  return storedPk() ?? "";
}

async function issueSub(): Promise<void> {
  busy.value = true; deny.value = null;
  try {
    // 一次性出示钥（隐私边界收窄）：每次「签发子凭证」动作生成全新 (sk′,pk′)
    // ——RA 对含新 pk′ 的报文签名；sk′ 以会话域内存态绑定该张子凭证
    // （24h+一次性）。账户长期钥只用于登录/操作签名，跨申请不可链接。
    const kp = sm2.generateKeyPairHex();
    // sm-crypto generateKeyPairHex 的 publicKey 确带 "04" 前缀标记（utils.js:47
    // '04'+Px+Py）——此处剥离=取 128 hex X‖Y 服务端口径，非误诊档案的"剥坐标
    // 头"案（那次的错剥对象是无前缀坐标）。勿删：删则 130 hex 被服务端拒。
    const subPk = kp.publicKey.replace(/^04/, "").toLowerCase();
    const form = JSON.parse(localStorage.getItem("fzForm") || "{}");
    const out = await api<Record<string, any>>("/ra/sub-credentials", {
      method: "POST",
      body: JSON.stringify({
        master_cred_hash_hex: cred.value?.master_cred_hash_hex ?? "",
        salt_hex: cred.value?.salt_hex ?? "",
        id_number: form.id_number ?? "",
        cert_level: form.cert_level ?? 3,
        sn: form.sn ?? "",
        holder_pub_hex: subPk,
      }),
    });
    sub.value = { ...out, holder_pk_hex: subPk };
    localStorage.setItem("fzSub", JSON.stringify(sub.value));
    storeSubSk(kp.privateKey); // sk′ 会话域内存态——出证面（申请页）唯一消费点
    storeSubBinding(); // 绑定指纹落盘——换登记后失配可检
    staleSub.value = false;
    await snapshot();
  } catch (e) {
    deny.value = { code: (e as ApiError).code, message: (e as ApiError).message };
  } finally { busy.value = false; }
}

async function snapshot(): Promise<void> {
  try { snap.value = await api("/ra/revocation/snapshot"); } catch { snap.value = null; }
}

async function loadLocal(): Promise<void> {
  const c = localStorage.getItem("fzCred");
  const s = localStorage.getItem("fzSub");
  if (c) cred.value = JSON.parse(c);
  if (s) sub.value = JSON.parse(s);
  // 失配检测：有子凭证但绑定指纹缺失/不等 ⟹ 重新登记或换钥过的旧凭证
  staleSub.value = !!s && !subMatchesMaterial();
  await snapshot();
}
onMounted(loadLocal);

// ---- 孤儿户续办门（2026-09-30 评审 P1-8 根修）：半途注册（已建户未补资料）
// 登录后不再卡死——就地补完资料（密码解锁钥→签发上链→二相回存），用户名不废。----
const orphan = ref<null | { done: boolean; busy: boolean; err: string; pw: string; id_number: string; sn: string; cert_level: number; class_id: number }>(null);

async function checkOrphan(): Promise<void> {
  try {
    const info = await authMe();
    if (info?.role === "pilot" && info.status === "pending_profile") {
      orphan.value = { done: false, busy: false, err: "", pw: "", id_number: "", sn: "", cert_level: 3, class_id: 1 };
    }
  } catch { /* 会话探测失败按无孤儿处理 */ }
}

async function finishOrphan(): Promise<void> {
  const g = orphan.value;
  if (!g) return;
  g.err = "";
  if (!/^\d{17}[\dXx]$/.test(g.id_number)) { g.err = "身份证号须为 18 位（末位可 X）"; return; }
  if (!g.sn.trim()) { g.err = "请填写无人机序列号"; return; }
  if (g.pw.length < 8 || !/[A-Za-z]/.test(g.pw) || !/[0-9]/.test(g.pw)) {
    g.err = "密码须 ≥8 位且含字母与数字（与注册时设置的密码一致）";
    return;
  }
  g.busy = true;
  try {
    // 解锁钥（孤儿户本地无密钥缓存——从服务器密封件解封）
    const sk = await unlockSk(g.pw);
    cacheSk(sk);
    const form = { id_number: g.id_number, cert_level: g.cert_level, sn: g.sn.trim(), class_id: g.class_id };
    const out = await api<Record<string, any>>("/auth/profile", {
      method: "POST",
      body: JSON.stringify(form),
    });
    const sealed = sealProfileSlot({ cred: out, form }, g.pw);
    await api("/auth/profile/keep", {
      method: "POST",
      body: JSON.stringify({ sealed_profile: JSON.stringify(sealed) }),
    });
    localStorage.setItem("fzCred", JSON.stringify(out));
    localStorage.setItem("fzForm", JSON.stringify(form));
    storeIdentityTag();
    g.done = true;
    await loadLocal();
  } catch (e) {
    g.err = (e as ApiError).message ?? String(e);
  } finally { g.busy = false; }
}
void checkOrphan();

// ---- 工作台 KPI 指标带（2026-09-30 三台统一：飞手端同语言）----
const kpi = computed(() => ({
  cred: cred.value ? 1 : 0, // 登记：1=已登记
  sub: sub.value ? (subExpired.value ? -1 : 1) : 0, // 子凭证：1 有效 / -1 过期 / 0 无
  revoke: revokeCheck.value?.ok === true ? 1 : revokeCheck.value && !revokeCheck.value.ok ? -1 : 0,
  epoch: snap.value?.epoch ?? "—",
}));
const KPI_META = {
  cred: { label: "加密登记", tone: () => (kpi.value.cred ? "teal" : "gray"),
          text: () => (kpi.value.cred ? "✓" : "—") },
  sub: { label: "一次性凭证", tone: () => (kpi.value.sub > 0 ? "teal" : kpi.value.sub < 0 ? "red" : "amber"),
         text: () => (kpi.value.sub > 0 ? "有效" : kpi.value.sub < 0 ? "已过期" : "未签发") },
  revoke: { label: "撤销核验", tone: () => (kpi.value.revoke > 0 ? "teal" : kpi.value.revoke < 0 ? "red" : "gray"),
            text: () => (kpi.value.revoke > 0 ? "未吊销" : kpi.value.revoke < 0 ? "已吊销" : "未核验") },
};
</script>

<template>
  <div class="fz-enter">
    <!-- 头部横幅：渐变+粒子（三台统一语言） -->
    <div class="fz-hero-band fz-ticks">
      <ParticleField />
      <div class="fz-hero-inner">
        <div class="fz-hero-title">飞手工作台</div>
        <div class="fz-hero-sub">匿名申请 · 一次性凭证 · 全程零明文——合规证明解锁起飞</div>
        <div class="fz-kpi-row">
          <div class="fz-kpi" v-for="(m, key) in KPI_META" :key="key">
            <span class="fz-kpi-n" :class="m.tone()">{{ m.text() }}</span>
            <span class="fz-kpi-l">{{ m.label }}</span>
          </div>
          <div class="fz-kpi">
            <span class="fz-kpi-n blue">{{ kpi.epoch }}</span>
            <span class="fz-kpi-l">公示名单版本</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 孤儿户续办门（半途注册自救） -->
    <div class="panel" v-if="orphan && !orphan.done" style="border-left: 4px solid #d9963a">
      <h2>⚠ 注册未完成——请补全资料</h2>
      <p class="desc">
        您的账户已建立（密钥已生成并密封），但实名与无人机资料尚未补全——补全后登记权威自动签发凭证并上链，之后即可正常申请起飞。
      </p>
      <label>账户密码（注册时设置——用于解锁您的密钥）</label>
      <input v-model="orphan.pw" type="password" />
      <label>身份证号（18 位）</label>
      <input v-model="orphan.id_number" maxlength="18" />
      <label>无人机序列号</label>
      <input v-model="orphan.sn" class="mono" />
      <div class="grid2">
        <div>
          <label>资质等级（1..4）</label>
          <input v-model.number="orphan.cert_level" type="number" min="1" max="4" />
        </div>
        <div>
          <label>机型类（0=微型 1=轻型 2=小型 3=中型）</label>
          <input v-model.number="orphan.class_id" type="number" min="0" max="255" />
        </div>
      </div>
      <p v-if="orphan.err" class="step-err">{{ orphan.err }}</p>
      <p class="note" v-if="orphan.class_id !== null">机型类 {{ orphan.class_id }}（{{ classLabel(orphan.class_id) }}）</p>
      <button class="btn" :disabled="orphan.busy" @click="finishOrphan">
        {{ orphan.busy ? "RA 签发与上链中…" : "补全资料并签发上链" }}
      </button>
    </div>
    <div class="panel" v-else-if="orphan && orphan.done" style="border-left: 4px solid #2e8577">
      <h2>✓ 资料已补全——凭证已签发上链</h2>
      <p class="note">下方为您的主凭证信息，可正常申请起飞。</p>
    </div>

    <div class="panel" v-if="!orphan || orphan.done">
      <h2>我的凭证 <StatusTag tone="accent" label="已加密登记" /></h2>
      <p class="desc">您的身份已加密登记，任何人都看不到明文。</p>
      <div class="grid2">
        <div>
          <div v-if="staleSub" class="deny" style="margin-bottom:10px">
            <span class="code">子凭证已失配</span>
            当前子凭证与现有登记/密钥不配套（可能重新登记过）——请点左侧「签发一次性子凭证」重新签发后再申请。
          </div>
          <button class="btn" :disabled="busy" @click="issueSub">{{ staleSub ? "重新签发一次性子凭证" : "签发一次性子凭证" }}</button>
          <p class="note" style="margin-top:8px">每次申请会使用一张全新的一次性凭证，他人无法把您的多次申请关联起来。</p>
          <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
        </div>
        <div>
          <div v-if="cred" class="kv fz-enter">
            <dt>登记编号</dt><dd><HashText :value="cred.master_cred_hash_hex" /></dd>
            <dt>身份加密章</dt><dd><HashText :value="cred.commitment_hex" /></dd>
            <dt>加密盐</dt><dd><HashText :value="cred.salt_hex" head="8" tail="6" /></dd>
            <dt>发证签名</dt><dd><HashText :value="cred.sig_hex" head="8" tail="6" /></dd>
            <dt>有效期至</dt><dd>{{ cred.expires_at }}</dd>
          </div>
          <div v-if="sub" class="kv fz-enter" style="margin-top:14px; border-top: var(--hairline); padding-top:12px">
            <dt>子凭证编号</dt><dd><HashText :value="sub.sub_cred_hash_hex" /></dd>
            <dt>一次性凭证身份</dt><dd><HashText :value="sub.id_prime_hex" head="8" tail="6" /></dd>
            <dt>发证签名</dt><dd><HashText :value="sub.sig_hex" head="8" tail="6" /></dd>
            <dt>有效至</dt><dd>{{ sub.expires_at }}<template v-if="sub"><br /><StatusTag :tone="subExpired ? 'bad' : 'ok'" :label="subRemainText" /></template></dd>
          </div>
          <div v-if="revokeCheck" class="fz-enter" style="margin-top:10px">
            <StatusTag :tone="revokeCheck.ok ? 'ok' : 'bad'" :label="revokeCheck.message" />
            <p v-if="revokeCheck.detail" class="note" style="margin-top:6px">{{ revokeCheck.detail }}</p>
          </div>
          <div style="margin-top:10px">
            <button class="btn ghost" :disabled="checking" @click="checkRevocation">
              {{ checking ? "核验中…" : "检查我的撤销状态" }}
            </button>
          </div>
          <div v-if="snap" class="fz-enter" style="margin-top:14px; border-top: var(--hairline); padding-top:12px">
            <div class="note">吊销名单状态（公开可查）</div>
            <div class="kv" style="margin-top:6px">
              <dt>名单版本</dt><dd>{{ snap.epoch }}</dd>
              <dt title="撤销名单的 SM3 校验值——电路用它数学校验「我不在名单上」">校验值</dt><dd><HashText :value="snap.root_hex" head="12" tail="10" /></dd>
              <dt>已吊销数量</dt><dd>{{ snap.revoked_handles_hex.length }}</dd>
            </div>
          </div>
          <p v-if="!cred" class="note">尚无凭证——请从入口页登记。</p>
        </div>
      </div>
    </div>
  </div>
</template>
