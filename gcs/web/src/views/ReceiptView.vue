<script setup lang="ts">
/** 屏⑤回执查询（说明书 §7.3）：128 位回执码跨设备取件（D19）。
 * 演示位=只凭回执码查询状态——零身份列（回执/会话表零身份列模型断言 B4 已钉）。 */
import { computed, ref } from "vue";
import { api, ApiError } from "../lib/api";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";

const code = ref("");
const busy = ref(false);
const deny = ref<{ code: string; message: string } | null>(null);
const statusText = computed(() => {
  const s = result.value?.status;
  if (s === "ready") return "已通过——可领取飞行令牌";
  if (s === "waiting") return "排队核验中（零知识证明核验中）";
  if (s === "failed") return "核验未通过";
  return s ?? "";
});

const result = ref<Record<string, any> | null>(null);
// 切页恢复（2026-09-29 切页修复）：最近一次查询回执码+结果入 sessionStorage
//（关浏览器即焚）——回来不再是空白页。
const RKEY = "fzReceiptLast";

async function query(): Promise<void> {
  busy.value = true; deny.value = null; result.value = null;
  try {
    result.value = await api(`/authz/receipt/${code.value.trim()}`);
    sessionStorage.setItem(RKEY, JSON.stringify({ code: code.value.trim(), result: result.value }));
  } catch (e) {
    deny.value = { code: (e as ApiError).code, message: (e as ApiError).message };
  } finally { busy.value = false; }
}

try {
  const saved = JSON.parse(sessionStorage.getItem(RKEY) || "null");
  if (saved?.code) {
    code.value = saved.code;
    result.value = saved.result ?? null;
  }
} catch { /* 恢复失败=空白页原样 */ }
</script>

<template>
  <div class="fz-enter">
    <div class="panel">
      <h2>回执查询</h2>
      <p class="desc">
凭回执码即可查询申请进度（换设备可查）；领取令牌请在发起申请的设备上完成——会话钥不出本机。
      </p>
      <label>回执码</label>
      <input v-model="code" class="mono" placeholder="仅回执码——不需要任何身份信息" />
      <div style="display:flex; gap:10px; margin-top:14px">
        <button class="btn" :disabled="busy || !code" @click="query">{{ busy ? "查询中…" : "查询回执" }}</button>

      </div>
      <DenyBox v-if="deny" :code="deny.code" :message="deny.message" />
      <div v-if="result" class="fz-enter" style="margin-top:14px; border-top: var(--hairline); padding-top: 12px">
        <div class="kv">
          <dt>状态</dt>
          <dd>
            <StatusTag :tone="result.status === 'ready' ? 'ok' : result.status === 'failed' ? 'bad' : 'accent'"
              :label="statusText" />
          </dd>
          <dt v-if="result.token_cipher_hex">令牌密文</dt>
          <dd v-if="result.token_cipher_hex" class="mono">{{ result.token_cipher_hex.slice(0, 24) }}…（会话钥 ECIES——凭私钥解密）</dd>
        </div>
        <p class="note" style="margin-top:8px">
          申请通过后，凭此回执码到「令牌与飞行」页面取件。该次授权的链上公示可在「链上留痕」页面独立核验。
        </p>
      </div>
    </div>
  </div>
</template>
