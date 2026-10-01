<script setup lang="ts">
/** 屏③令牌与飞行（说明书 §7.3）：回执取件→浏览器端解密+引擎验签（B0 国密基座真实执行）
 * →地面站闸门 arm→遥测链。authId 贯穿键显性呈现（P2）。
 * R3-2 包1（2026-09-24，评审 P0-2/P0-3/P1-7/P1-8/P1-9/P2-1）：
 * ①链路状态徽标（SITL 在线/仿真/未连接——终结「采样+1 伪造数据」观感）；
 * ②ARM 大状态横幅（地面站观感）+围栏触发红告警条；
 * ③SITL 档自动真采样（500ms/2Hz）；未接飞控=明确故障态（零合成遥测——
 * 真实测试策略，③GCS 化退役假链档）；
 * ④令牌时间窗人话+剩余有效期倒计时；
 * ⑤围栏态透传（检查点签名绑定真围栏，替换硬编码 120m）；
 * ⑥「结束飞行并封链」（检查点锚定上链+DISARM——生命周期闭环）；
 * ⑦令牌防篡改自检按钮（负例回归产品面）；三面板错误就地呈现。 */
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import FlightGlobe from "../components/FlightGlobe.vue";
import FlightGauges from "../components/FlightGauges.vue";
import { bridge, ApiError, randInt, fromHex, toHex } from "../lib/api";
import { pickupToken, verifyTokenSig, canonicalTokenBody, checkTokenFields, tokenPayloadHex } from "../lib/token";
import { loadPlan } from "../lib/plan";
import { flightStage, stepperState, windowSubline } from "../lib/flight";
import HashText from "../components/HashText.vue";
import DenyBox from "../components/DenyBox.vue";
import StatusTag from "../components/StatusTag.vue";

const receiptCode = ref(localStorage.getItem("fzLastReceipt") || "");
// 会话钥只在 sessionStorage（关窗即焚）——localStorage 回落读是死代码且构成
// "曾有人写盘就会读到旧值"的回归面（2026-09-28 深检 C 席建议，已删）
const sessionSk = ref(sessionStorage.getItem("fzSessionSk") || "");
const busy = ref(false);
const denyPickup = ref<{ code: string; message: string } | null>(null);
const denyArm = ref<{ code: string; message: string } | null>(null);
const denyLog = ref<{ code: string; message: string } | null>(null);
const info = ref<null | { ok: boolean; tok: any; warnings: string[] }>(null);
const armResult = ref<any>(null);
const chain = ref<any>(null);
// 样本行类型化（2026-09-27 队长实测一根因：any 数组让 FlightGlobe 期望的
// lat_1e7/lon_1e7 与此处推入的 lat/lon 键名错位静默通过 tsc——undefined→NaN
// →3D 跟随/俯视相机位置 NaN 全黑）。键名=桥面原始字段名（单源）。
interface SampleRow {
  t: number;
  alt_cm: number;
  lat_1e7: number;
  lon_1e7: number;
  head: string;
  checkpoint?: { seq?: number } | null;
}
const samples = ref<SampleRow[]>([]);
const att = ref<{ roll: number; pitch: number; yaw: number } | null>(null); // ③GCS 化姿态旁路（UI 面）
// P3 遥测真实感：电池/GPS/HUD（桥 drain 缓存直读——全部 MAVLink 现成字段）
const bat = ref<{ voltage_v: number | null; current_a: number | null; remaining_pct: number | null } | null>(null);
const gps = ref<{ sats: number; fix: number } | null>(null);
const hud = ref<{ speed_ms: number; heading_deg: number; throttle_pct: number } | null>(null);
const fcMode = ref<string | null>(null); // 飞控模式旁路（STABILIZE 等——RTL/HOLD 黄条提示）
const fcArmed = ref<boolean | null>(null); // 飞控侧上锁位旁路（gate armed 但 FC 上锁=重解锁提醒）
const globeFailed = ref(false); // WebGL 降级面（FlightGlobe 初始化失败时 2D 兜底）
interface FlightEvent { t: number; kind: string; text: string; red?: boolean }
const events = ref<FlightEvent[]>([]); // ③GCS 化事件时间线（飞行中实时累积）
const altCmNow = ref<number | null>(null); // 最新高度（仪表/记录单消费）
function pushEvent(kind: string, text: string, red = false) {
  events.value.push({ t: Math.floor(Date.now() / 1000), kind, text, red });
}
// 采样持久化节流（P1 批）：2Hz 全量 JSON.stringify 随样本数线性变贵（256 样本
// ≈40KB/拍×2/s）；5s 节流+窗口满 128 倍数即时落盘+卸载冲刷——正常路径零丢失。
// 空样本不写盘：新架次清空走 removeItem 语义，卸载冲刷写 "[]" 会误清既有
// 留痕（本批回归——seed 后离开本屏即被空冲刷覆盖）。
let lastPersistAt = 0;
function persistTrailRows(force = false): void {
  if (!samples.value.length) return;
  const now = Date.now();
  if (!force && now - lastPersistAt < 5000 && samples.value.length % 128 !== 0) return;
  lastPersistAt = now;
  localStorage.setItem("fzTrailRows", JSON.stringify(samples.value));
}
const link = ref<any>(null);
const anchorResult = ref<any>(null);
const fenceBreached = ref(false);
const breachText = ref("");
const eventSent = ref(false); // 超限事件已补发上链（一次飞行一次）
let sampleTimer: ReturnType<typeof setInterval> | null = null;
let tick: ReturnType<typeof setInterval> | null = null;
const nowTick = ref(Date.now());

// 引擎公钥不落 localStorage（演示钥每场随机——缓存即过期）；取件时现取
const enginePub = ref("");
const tokenPayload = ref(localStorage.getItem("fzTokenPayload") || "");

// ---- 链路状态徽标 ----
async function refreshLink(): Promise<void> {
  try {
    link.value = await bridge("/link_status");
  } catch {
    link.value = { mode: "unknown", conn: null };
  }
}
type Tone = "ok" | "bad" | "gold" | "accent";
const linkState = computed<{ tone: Tone; label: string }>(() => {
  if (!link.value) return { tone: "gold", label: "链路检测中…" };
  if (link.value.mode === "sitl")
    return link.value.conn
      ? { tone: "ok", label: "SITL 链路在线" }
      : { tone: "bad", label: "SITL 链路未连接" };
  return { tone: "gold", label: "仿真链路（无真飞控）" };
});
const sitlReady = computed(() => link.value?.mode === "sitl" && !!link.value?.conn);

// ---- 令牌倒计时 ----
function fmtTs(ts: number): string {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
const remainS = computed(() => {
  if (!info.value) return 0;
  return Math.max(0, (info.value.tok.t_end ?? 0) - Math.floor(nowTick.value / 1000));
});
const remainText = computed(() => {
  const s = remainS.value;
  return `${String(Math.floor(s / 3600)).padStart(2, "0")}:${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
});
const expired = computed(() => !!info.value && remainS.value <= 0);

// ---- ARM / 围栏 ----
const armed = computed(() => !!armResult.value?.ok);
// 令牌消费状态（单一事实源=桥审计库——跨刷新/跨重进同步；此前只存页面内存，
// 刷新后按钮复活⟹再点必撞 token_used，队长大厅实测七）
const tokenConsumed = ref(false);
const canRearm = ref(false);
// 解锁按钮状态机（四态，优先级自上而下）：
//   busy=解锁序列进行中 / 无令牌=不可用 / 重解锁窗口开=可点（同授权延续）/
//   已消费=禁用（一次授权一次解锁）/ 其余=正常可点。
const armButton = computed(() => {
  if (busy.value) return { label: "解锁中…（写入围栏并确认）", disabled: true, title: "围栏三参数写入确认→ARM→上锁位确认" };
  if (canRearm.value) return { label: "重新解锁（同一授权延续）", disabled: false, title: "授权门仍开且飞控已回落上锁——重解锁不重复消费令牌" };
  if (tokenConsumed.value) return { label: "✓ 已解锁过（令牌已消费）", disabled: true, title: "一次授权一次解锁——新飞行请回「起飞申请」申领新令牌" };
  if (!info.value) return { label: "解锁起飞", disabled: true, title: "先领取令牌" };
  return { label: "解锁起飞", disabled: false, title: "写入围栏参数并解锁电机" };
});
async function refreshArmStatus(): Promise<void> {
  if (!tokenPayload.value) { tokenConsumed.value = false; canRearm.value = false; return; }
  try {
    const r = await bridge<{ used: boolean; can_rearm: boolean }>(
      `/arm/status?token_payload_hex=${tokenPayload.value}`);
    tokenConsumed.value = !!r.used;
    canRearm.value = !!r.can_rearm;
  } catch { /* 桥瞬断——保持现值 */ }
}
// 消费状态绑定令牌本体：领取新令牌/换令牌必须重查（此前只在进页面时查一次
// ——旧令牌的"已消费"结论粘到新令牌上=新令牌按钮灰死的混淆根源）。
watch(tokenPayload, () => { void refreshArmStatus(); });
const planAlt = ref<number | null>(null);
const fenceM = computed(() => {
  const cap = info.value?.tok?.alt_max ?? null;
  if (cap === null) return planAlt.value;
  return planAlt.value !== null ? Math.min(cap, planAlt.value) : cap;
});

async function pickup(): Promise<void> {
  busy.value = true; denyPickup.value = null; info.value = null;
  try {
    const { api } = await import("../lib/api");
    const receipt = await api<Record<string, any>>(`/authz/receipt/${receiptCode.value.trim()}`);
    if (receipt.status !== "ready") throw new ApiError("not_ready", `回执状态=${receipt.status}（ready 后可取件）`, 0);
    // 引擎公钥每次现取（不缓存）：演示钥每场随机（S5）——缓存旧钥=取件验签假败
    const ep = await bridge<{ engine_pub_hex: string }>("/engine_pub");
    enginePub.value = ep.engine_pub_hex;
    const p = pickupToken(receipt.token_cipher_hex, sessionSk.value.trim());
    const sigOk = verifyTokenSig(canonicalTokenBody(p.tok), p.sig, enginePub.value);
    // 字段校验真比较（A-P1-1 根修）：plan_hash 与本机计划仓核对——此前传
    // p.tok.plan_hash 自比恒通过=虚标。仓中无此计划（跨设备/已清）给 warning。
    const localPlan = loadPlan(p.tok.plan_hash);
    const warnings = checkTokenFields(
      p.tok,
      localPlan ? p.tok.plan_hash : "",
      Math.floor(Date.now() / 1000),
    );
    if (!localPlan) warnings.push("本机计划仓无此计划记录（跨设备领取或已清）——闸门仍会独立核验");
    info.value = { ok: sigOk, tok: p.tok, warnings };
    tokenPayload.value = tokenPayloadHex(p);
    localStorage.setItem("fzTokenPayload", tokenPayload.value);
  } catch (e: any) {
    denyPickup.value = { code: e?.code ?? "pickup_failed", message: e?.message ?? String(e) };
  } finally { busy.value = false; }
}

async function arm(tamper = false): Promise<void> {
  busy.value = true; denyArm.value = null; armResult.value = null;
  try {
    // payload = token_body|sig；篡改=body 中 alt_max +1（bridge 五查签名必拒）
    const text = new TextDecoder().decode(fromHex(tokenPayload.value));
    const splitAt = text.lastIndexOf("|");
    let bodyText = text.slice(0, splitAt);
    const planHash: string = JSON.parse(bodyText).plan_hash;
    let payloadBytes = fromHex(tokenPayload.value);
    if (tamper) {
      bodyText = bodyText.replace(/"alt_max":(\d+)/, (_m, d) => `"alt_max":${Number(d) + 1}`);
      payloadBytes = new TextEncoder().encode(bodyText + "|" + text.slice(splitAt + 1));
    }
    // 计划高度联动（阶段二）：本机计划仓按承诺取回作业高度→围栏取 min
    const planEntry = loadPlan(planHash);
    planAlt.value = planEntry ? planEntry.plan.alt_m : null;
    armResult.value = await bridge("/arm", {
      method: "POST",
      body: JSON.stringify({
        token_payload_hex: toHex(payloadBytes), plan_hash_hex: planHash,
        plan_altitude_m: planAlt.value,
      }),
    });
    if (armResult.value?.ok) {
      pushEvent("arm", armResult.value.rearmed
        ? "飞控重新解锁（同一授权延续——授权门未重新消费）"
        : "解锁起飞（一次授权一次解锁；围栏参数已随令牌冻结）");
      if (armResult.value.rearmed) fcArmed.value = true;
    }
  } catch (e: any) {
    denyArm.value = { code: e?.code ?? "arm_failed", message: e?.message ?? String(e) };
  } finally {
    busy.value = false;
    void refreshArmStatus(); // 解锁成败后即拉消费状态（按钮真值）
  }
}

// ---- 遥测链（SITL 自动真采样 / fake 手动注入） ----
async function startChain(): Promise<void> {
  busy.value = true; denyLog.value = null;
  try {
    // 围栏态透传（R3-2：检查点签名绑定真围栏——替换硬编码 120m 假值）
    chain.value = await bridge("/telemetry/start", {
      method: "POST",
      body: JSON.stringify({
        auth_id: info.value?.tok?.authId ?? 1,
        fence_state_hex: armResult.value?.fence_state_hex ?? "01007800",
      }),
    });
    // C-P1-2：桥拒绝走 200+ok:false——不检查=静默吞（未 ARM 时界面零反应）
    if (chain.value && chain.value.ok === false) {
      denyLog.value = {
        code: chain.value.code ?? "chain_refused",
        message: chain.value.code === "not_armed"
          ? "请先解锁起飞——没有有效授权就不会开启飞行记录"
          : chain.value.message ?? "记录被拒绝",
      };
      chain.value = null;
      return;
    }
    samples.value = [];
    fenceBreached.value = false;
    breachText.value = "";
    eventSent.value = false;
    anchorResult.value = null;
    pushEvent("chain", "开始记录（遥测链 genesis）");
    chainStartT.value = Math.floor(Date.now() / 1000);
    localStorage.setItem("fzTrailGenesis", chain.value.genesis_head_hex);
    localStorage.setItem("fzDevicePub", chain.value.device_pub_hex);
    // 授权号未知=空串（A-P1-4：缺省 "1" 误导——TrailView 显示 "—"）
    localStorage.setItem("fzTrailAuthId", String(info.value?.tok?.authId ?? ""));
    if (sitlReady.value && armed.value) startAutoSample();
  } catch (e: any) {
    denyLog.value = { code: e?.code ?? "chain_failed", message: e?.message ?? String(e) };
  } finally { busy.value = false; }
}

const telemetryStalled = ref(false);
let sampleMiss = 0;
function startAutoSample(): void {
  if (sampleTimer) clearInterval(sampleTimer);
  sampleMiss = 0;
  sampleTimer = setInterval(async () => {
    if (!chain.value) return;
    try {
      const r = await bridge(`/telemetry/sitl_sample?t_epoch=${Math.floor(Date.now() / 1000)}`);
      if (r?.ok) { recordSample(r); sampleMiss = 0; telemetryStalled.value = false; }
      else { sampleMiss += 1; if (sampleMiss >= 6) telemetryStalled.value = true; }
    } catch {
      sampleMiss += 1;
      if (sampleMiss >= 6) telemetryStalled.value = true; // 连续 3s 无样本=遥测中断显性化（E-15）
    }
  }, 500);
}

function recordSample(r: any): void {
  const t = r.t_epoch ?? r.t ?? Math.floor(Date.now() / 1000);
  const alt = r.alt_cm ?? 0;
  const lat = r.lat_1e7 ?? 0;
  const lon = r.lon_1e7 ?? 0;
  if (r.att) att.value = r.att; // ③GCS 化：姿态旁路（UI 面，不进链）
  if (r.mode) fcMode.value = r.mode;
  if (r.armed !== undefined) fcArmed.value = r.armed; // 飞控上锁位旁路
  if (r.bat) bat.value = r.bat;
  if (r.gps) gps.value = r.gps;
  if (r.hud) hud.value = r.hud;
  samples.value.push({ t, alt_cm: alt, lat_1e7: lat, lon_1e7: lon, head: r.head_hex, checkpoint: r.checkpoint });
  altCmNow.value = alt;
  if (r.checkpoint && (!events.value.length || events.value[events.value.length - 1].kind !== "checkpoint"))
    pushEvent("checkpoint", `检查点锚定 #${r.checkpoint?.seq ?? events.value.filter(e => e.kind === "checkpoint").length + 1}`);
  if (samples.value.length === 1) pushEvent("takeoff", "起飞——首个遥测样本入链");
  persistTrailRows();
  localStorage.setItem("fzTrailHead", r.head_hex);
  if (r.fence_breached && !fenceBreached.value) {
    pushEvent("breach", `固件围栏触发——${r.last_statustext || "Max Alt fence breached"}`, true);
  }
  // 超限事件上链（E-14 根修：桥在采样响应里已生成 event 对象，前端此前从不
  // 调用 /telemetry/event——"超限事件上链取证"宣称在 UI 路径断裂，S1 脚本
  // 路径有调用故 e2e 全绿。存在即补发，幂等由链端 seq/去重语义兜底。）
  if (r.event && !eventSent.value) {
    eventSent.value = true;
    bridge("/telemetry/event", {
      method: "POST",
      body: JSON.stringify({
        auth_id: r.event.auth_id, event_type: r.event.event_type,
        event_hash_hex: r.event.event_hash_hex,
      }),
    }).then((res: any) => {
      if (res?.ok) pushEvent("event", "超限事件已上链取证（EventRecorded）", true);
      else pushEvent("event", `超限事件上链未完成：${res?.code ?? "未知原因"}`, true);
    }).catch(() => pushEvent("event", "超限事件上链请求失败（网络）", true));
  }
  if (r.fence_breached) {
    fenceBreached.value = true;
    breachText.value = r.last_statustext || "Max Alt fence breached";
    localStorage.setItem("fzFlightFenceBreached", "1"); // 证书卡披露源（跨页）
  }
}

// ---- 结束飞行并封链（R3-2：检查点锚定上链+DISARM——生命周期闭环） ----
const sealing = ref(false);
const sealed = ref(false);
// ③GCS 化飞行记录单派生量（封链后卡片消费）
const chainStartT = ref<number | null>(null);
const sealDurText = ref<string | null>(null);
const peakAltM = computed(() => {
  if (!samples.value.length) return 0;
  return Math.max(...samples.value.map((x) => x.alt_cm)) / 100;
});
const flightDuration = computed(() => {
  if (sealDurText.value) return sealDurText.value;
  if (!chainStartT.value) return "—";
  const sec = Math.floor(Date.now() / 1000) - chainStartT.value;
  return `${Math.floor(sec / 60)} 分 ${sec % 60} 秒（进行中）`;
});
const sealConfirm = ref(false); // 封链二次确认（不可撤销动作防误触——队长拍板：弹窗式）
async function endFlight(): Promise<void> {
  if (!sealConfirm.value) { sealConfirm.value = true; return; }
  sealConfirm.value = false;
  sealing.value = true; denyLog.value = null;
  try {
    stopAuto(); // B-P2-7：封链时必须退出自动飞行（disarm 后 climb 仍发的自相矛盾态）
    if (sampleTimer) { clearInterval(sampleTimer); sampleTimer = null; }
    anchorResult.value = await bridge("/telemetry/anchor", { method: "POST" });
    if (anchorResult.value?.ok) {
      sealed.value = true;
      sessionStorage.setItem("fzFlightSealed", "1"); // 切页回来仍是"已封链"（会话域）
    }
    await bridge("/sitl/disarm", { method: "POST" });
    // C-P2-2：停桨后横幅回 DISARMED（否则 ARMED 横幅与已停桨事实自相矛盾）
    armResult.value = null;
    const dur = chainStartT.value ? Math.floor(Date.now() / 1000) - chainStartT.value : 0;
    sealDurText.value = `${Math.floor(dur / 60)} 分 ${dur % 60} 秒`;
    pushEvent("seal", `结束飞行并封链——检查点锚定${anchorResult.value?.ok ? "成功" : "失败"}（${samples.value.length} 样本）`);
  } catch (e: any) {
    denyLog.value = { code: e?.code ?? "seal_failed", message: e?.message ?? String(e) };
  } finally { sealing.value = false; }
}

/** 新架次（2026-09-28 队长拍板）：封链后就地重置飞行状态——旧令牌已消费，
 * 新架次从「领取令牌」重新开始；3D 原点保持（同一场地），链与事件全新。 */
function newFlight(): void {
  sealed.value = false;
  sessionStorage.removeItem("fzFlightSealed");
  chain.value = null;
  anchorResult.value = null;
  armResult.value = null;
  samples.value = [];
  events.value = [];
  fenceBreached.value = false;
  breachText.value = "";
  eventSent.value = false;
  altCmNow.value = null;
  ctrlMode.value = "manual";
  chainStartT.value = 0;
  localStorage.removeItem("fzTrailRows");
  localStorage.removeItem("fzTrailHead");
  localStorage.removeItem("fzLastCaseId");
  localStorage.removeItem("fzFlightFenceBreached");
}

// ---- 飞行控制（SITL 档）——控制源互斥状态机：手动 / 定高悬停 / 自动飞行。
// 任意时刻仅一种控制源生效：点任一控制即切换（自动飞行被手动/悬停打断）。
// 桥端在每次油门指令前切入定高模式（ALT_HOLD）：油门杆=升降率（1500 保持）。
type CtrlMode = "manual" | "hover" | "auto";
const ctrlMode = ref<CtrlMode>("manual");
const targetAltM2 = computed(() => Math.min(targetAltM.value, (fenceM.value ?? 50) - 3));
const ctrlModeLabel = computed(() => {
  if (!armed.value) return "未解锁";
  if (ctrlMode.value === "auto") return `自动飞行中 → ${targetAltM2.value} m`;
  if (ctrlMode.value === "hover") return "定高悬停";
  return "手动";
});
let climbHolding: 0 | 1 | -1 = 0; // 按住方向：0 无 / 1 爬升 / -1 下降
let climbHoldTimer: ReturnType<typeof setTimeout> | null = null;
function climbHoldStop(): void {
  if (!climbHolding) return;
  climbHolding = 0;
  if (climbHoldTimer) { clearTimeout(climbHoldTimer); climbHoldTimer = null; }
  void bridge("/sitl/climb?pwm=1500&hold_s=0.3", { method: "POST" }).catch(() => null); // 松手回中=定高保持
}
async function climbHoldStart(dir: 1 | -1): Promise<void> {
  if (climbHolding !== 0 || !armed.value) return;
  denyLog.value = null;
  stopAuto();
  autoFlying.value = false;
  climbHolding = dir;
  ctrlMode.value = "manual";
  await bridge("/sitl/abort", { method: "POST" }).catch(() => null); // 接管：中止自动段
  const pwm = dir > 0 ? 1850 : 1200; // 爬升/下降对称档（下降带地面保护）
  const pulse = async (): Promise<void> => {
    if (climbHolding !== dir) return;
    try {
      const floor = dir < 0 ? "&min_alt_cm=30" : ""; // 下降地面保护（≤0.3m 停降）
      const r = await bridge<{ ok: boolean; code?: string; message?: string }>(
        `/sitl/climb?pwm=${pwm}&hold_s=0.45${floor}`, { method: "POST" });
      if (r.ok === false && r.code === "fc_disarmed") {
        climbHoldStop();
        denyLog.value = { code: r.code, message: r.message ?? "飞控已上锁——重新解锁后恢复操作" };
        pushEvent("fclock", "飞控已上锁——重新解锁后恢复操作", true);
        return;
      }
      // 下降触地保护：到地面即停降（保持）
      if (dir < 0 && r.ok === true && (r as any).code === "floor_reached") {
        return; // 保持（不继续发下降脉冲）
      }
    } catch { /* 单拍瞬断——按住即续 */ }
    if (climbHolding === dir) climbHoldTimer = setTimeout(pulse, 60);
  };
  void pulse();
}
async function hover(): Promise<void> {
  denyLog.value = null;
  stopAuto();
  ctrlMode.value = "hover";
  try {
    const r = await bridge<{ ok: boolean; code?: string; message?: string }>(
      "/sitl/climb?pwm=1500&hold_s=1.5", { method: "POST" });
    if (r.ok === false) {
      denyLog.value = { code: r.code ?? "hover_failed", message: r.message ?? "悬停指令未生效" };
      ctrlMode.value = "manual";
    }
  } catch (e: any) {
    denyLog.value = { code: e?.code ?? "hover_failed", message: e?.message ?? String(e) };
    ctrlMode.value = "manual";
  }
}
const currentAltM = computed(() => {
  const last = samples.value[samples.value.length - 1];
  return last ? (last.alt_cm / 100).toFixed(1) : null;
});

// ---- ARM 拒绝人话映射（闸门原因直出——2026-09-26 队长实测反馈） ----
const ARM_REJECT_TEXT: Record<string, string> = {
  token_used: "该令牌已使用过——一次授权一次解锁；请回「起飞申请」重新申请并领取新令牌",
  bad_signature: "令牌签名核验未通过（非引擎签发或已被篡改）",
  window_expired: "令牌已过有效期——请重新申请",
  plan_mismatch: "令牌与当前计划不一致——计划在出证后不可改动",
};
const armRejectText = computed(() => {
  const r = armResult.value;
  if (!r || r.ok) return "";
  if (r.code === "token_used") return ARM_REJECT_TEXT.token_used;
  return `${r.message ?? r.code ?? "核验未通过"}${ARM_REJECT_TEXT[r.code] ? "。" + ARM_REJECT_TEXT[r.code] : ""}`;
});

// ---- 飞行可视化（2D 实时高度曲线+航迹俯视——2026-09-26 队长反馈"只有按钮
// 太假"；3D 维持不做拍板：渲染糖衣+重依赖。数据全部本地绘制、不上链） ----
const altCanvas = ref<HTMLCanvasElement | null>(null);
const trackCanvas = ref<HTMLCanvasElement | null>(null);

function drawAltChart(): void {
  const cv = altCanvas.value;
  if (!cv) return;
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth || 600;
  const H = 140;
  cv.width = W * dpr;
  cv.height = H * dpr;
  const ctx = cv.getContext("2d");
  if (!ctx) return;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const pts = samples.value.slice(-160);
  const fence = fenceM.value ?? 50;
  const maxAlt = Math.max(fence + 5, ...pts.map((p) => p.alt_cm / 100), 5);
  const x = (i: number) => (pts.length < 2 ? W / 2 : (i / (pts.length - 1)) * (W - 20) + 10);
  const y = (m: number) => H - 16 - (m / maxAlt) * (H - 30);
  ctx.strokeStyle = "#d7dee8";
  ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(10, y(0)); ctx.lineTo(W - 10, y(0)); ctx.stroke();
  ctx.strokeStyle = "#c0392b";
  ctx.setLineDash([5, 4]);
  ctx.lineWidth = 1.2;
  ctx.beginPath(); ctx.moveTo(10, y(fence)); ctx.lineTo(W - 10, y(fence)); ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = "#c0392b";
  ctx.font = "11px sans-serif";
  ctx.fillText(`围栏 ${fence} m`, W - 88, y(fence) - 4);
  if (pts.length >= 2) {
    ctx.strokeStyle = "#2f6fed";
    ctx.lineWidth = 2;
    ctx.beginPath();
    pts.forEach((p, i) => {
      const px = x(i), py = y(p.alt_cm / 100);
      i ? ctx.lineTo(px, py) : ctx.moveTo(px, py);
    });
    ctx.stroke();
    const last = pts[pts.length - 1];
    // 当前点光晕（视觉深化批 E：随采样重绘刷新——静态光环，零新增动画循环）
    ctx.strokeStyle = "rgba(47, 111, 237, 0.22)";
    ctx.lineWidth = 2;
    ctx.beginPath(); ctx.arc(x(pts.length - 1), y(last.alt_cm / 100), 7, 0, Math.PI * 2); ctx.stroke();
    ctx.fillStyle = "#2f6fed";
    ctx.beginPath(); ctx.arc(x(pts.length - 1), y(last.alt_cm / 100), 3.5, 0, Math.PI * 2); ctx.fill();
  }
}

function drawTrack(): void {
  const cv = trackCanvas.value;
  if (!cv) return;
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth || 280;
  const H = 140;
  cv.width = W * dpr;
  cv.height = H * dpr;
  const ctx = cv.getContext("2d");
  if (!ctx) return;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const pts = samples.value.filter((p) => p.lat_1e7 || p.lon_1e7).slice(-400);
  ctx.fillStyle = "#8496ab";
  ctx.font = "12px sans-serif";
  if (pts.length < 2) {
    ctx.fillText("采样后显示航迹俯视图（本地绘制，不上链）", 14, H / 2);
    return;
  }
  const lats = pts.map((p) => p.lat_1e7);
  const lons = pts.map((p) => p.lon_1e7);
  const spanLat = Math.max(Math.max(...lats) - Math.min(...lats), 1e-4);
  const spanLon = Math.max(Math.max(...lons) - Math.min(...lons), 1e-4);
  const px = (lon: number) => 12 + ((lon - Math.min(...lons)) / spanLon) * (W - 24);
  const py = (lat: number) => H - 12 - ((lat - Math.min(...lats)) / spanLat) * (H - 24);
  ctx.strokeStyle = "#2f6fed";
  ctx.lineWidth = 1.6;
  ctx.beginPath();
  pts.forEach((p, i) => {
    i ? ctx.lineTo(px(p.lon_1e7), py(p.lat_1e7)) : ctx.moveTo(px(p.lon_1e7), py(p.lat_1e7));
  });
  ctx.stroke();
  ctx.fillStyle = "#2a9d5c";
  ctx.beginPath(); ctx.arc(px(pts[0].lon_1e7), py(pts[0].lat_1e7), 4, 0, Math.PI * 2); ctx.fill();
  const last = pts[pts.length - 1];
  ctx.fillStyle = "#c0392b";
  ctx.beginPath(); ctx.arc(px(last.lon_1e7), py(last.lat_1e7), 4, 0, Math.PI * 2); ctx.fill();
}

// ---- 目标高度自动飞行（bang-bang 控制产品化——S1 编舞逻辑回到飞手手里） ----
const targetAltM = ref(18);
let autoPilot: ReturnType<typeof setInterval> | null = null;
const autoFlying = ref(false);
function stopAuto(): void {
  if (autoPilot) { clearInterval(autoPilot); autoPilot = null; }
  autoFlying.value = false;
}async function climbStep(pwm: number, holdS: number): Promise<void> {
  try {
    const r = await bridge<{ ok: boolean; code?: string; message?: string }>(
      `/sitl/climb?pwm=${pwm}&hold_s=${holdS}`, { method: "POST" });
    if (r.ok === false && r.code === "fc_disarmed") {
      stopAuto(); // 飞控已上锁——自动飞行诚实中止（横幅提示重解锁）
      denyLog.value = { code: r.code, message: r.message ?? "飞控已上锁——自动飞行已中止" };
      pushEvent("fclock", "飞控已上锁——自动飞行中止，请重新点击「解锁起飞」", true);
    }
  } catch { /* 控制脉冲瞬断——下一 tick 续 */ }
}
async function flyToTarget(): Promise<void> {
  if (autoFlying.value || !sitlReady.value || !armed.value) return;
  autoFlying.value = true;
  ctrlMode.value = "auto";
  const cap = (fenceM.value ?? 50) - 3; // 目标钳在围栏下 3m（防误触围栏）
  const tgtCm = Math.round(Math.min(targetAltM.value, cap) * 100);
  pushEvent("auto", `自动爬升至 ${Math.min(targetAltM.value, cap)} m（桥侧恒定率）`);
  try {
    const r = await bridge<{ ok: boolean; code?: string; message?: string;
                             reached?: boolean; fence_breached?: boolean; alt_cm?: number }>(
      `/sitl/climb?pwm=2000&until_alt_cm=${tgtCm}&timeout_s=150`, { method: "POST" });
    if (r.ok === false) {
      if (r.code === "fc_disarmed") pushEvent("fclock", "飞控已上锁——自动爬升中止，请重新解锁", true);
      denyLog.value = { code: r.code ?? "auto_failed", message: r.message ?? "自动爬升未完成" };
      ctrlMode.value = "manual";
    } else {
      if (r.fence_breached) pushEvent("breach", "自动爬升途中触发围栏——已刹停", true);
      ctrlMode.value = "hover";
      pushEvent("auto", r.reached ? `到达目标高度 ${Math.min(targetAltM.value, cap)} m——转定高悬停` : "自动爬升结束（未达目标——见事件）");
    }
  } catch (e: any) {
    denyLog.value = { code: e?.code ?? "auto_failed", message: e?.message ?? String(e) };
    ctrlMode.value = "manual";
  } finally {
    autoFlying.value = false;
  }
}

const onResize = () => { drawAltChart(); drawTrack(); };
// ---- 飞行流程状态机（E 席设计批：步进器/引导/窗口卡的单一事实源——纯函数在 lib/flight） ----
const stage = computed(() => flightStage({
  hasToken: !!info.value,
  armed: armed.value,
  chainStarted: !!chain.value,
  sealed: sealed.value,
  sampleCount: samples.value.length,
}));
const stepper = computed(() => stepperState({
  hasToken: !!info.value,
  armed: armed.value,
  chainStarted: !!chain.value,
  sealed: sealed.value,
  sampleCount: samples.value.length,
}));
const checkpointCount = computed(() => events.value.filter((e) => e.kind === "checkpoint").length);
const breachInWindow = computed(() => fenceBreached.value && samples.value.length < 128);
const windowSub = computed(() => windowSubline(samples.value.length, breachInWindow.value));
onMounted(() => {
  refreshLink();
  void refreshArmStatus();
  void reattachFlight();
  nowTick.value = Date.now();
  tick = setInterval(() => (nowTick.value = Date.now()), 1000);
  nextTick(() => { drawAltChart(); drawTrack(); });
  window.addEventListener("resize", onResize);
});

/** 切页/刷新重挂靠（2026-09-29 切页修复）：进页先问桥"现在到底什么状态"，
 * 照实恢复界面——服务器是唯一事实源（链数据从不丢，此前只是界面不认账）。
 * 样本来自本地持久化（5s 节流，尾部最多缺 5 秒——如实标注）。 */
async function reattachFlight(): Promise<void> {
  if (chain.value) { // 本页刚起的链（新架次）——不回放覆盖
    sealed.value = sessionStorage.getItem("fzFlightSealed") === "1";
    return;
  }
  try {
    const st = await bridge<any>("/telemetry/state");
    if (!st?.chain_active) return;
    chain.value = {
      genesis_head_hex: st.genesis_head_hex,
      device_pub_hex: localStorage.getItem("fzDevicePub") || "",
    };
    try { samples.value = JSON.parse(localStorage.getItem("fzTrailRows") || "[]"); } catch { samples.value = []; }
    fenceBreached.value = !!st.breach_seen || localStorage.getItem("fzFlightFenceBreached") === "1";
    breachText.value = fenceBreached.value ? "固件围栏触发（恢复自服务器状态）" : "";
    eventSent.value = !!st.breach_event_filed;
    chainStartT.value = typeof st.started_ts === "number" ? st.started_ts : null;
    sealed.value = sessionStorage.getItem("fzFlightSealed") === "1";
    pushEvent("chain", `已恢复进行中架次显示（服务器回放：${st.n_samples} 样本 · 检查点 ${st.checkpoint_count}）`);
    nextTick(() => { drawAltChart(); drawTrack(); });
    if (!sealed.value && armed.value && sitlReady.value) startAutoSample();
  } catch {
    // 桥不可达——按未开始渲染（顶栏桥接红点已有指示），不伪造状态
  }
}
watch(() => samples.value.length, () => { drawAltChart(); drawTrack(); });
watch(fcArmed, () => { void refreshArmStatus(); }); // 飞控回落/复上锁→重解锁窗口开合
watch(fenceM, () => drawAltChart());
onBeforeUnmount(() => {
  // B-P2-7：卸载必须停自动飞行+自动采样（切屏后无人机仍被驱动=演示事故点）
  stopAuto();
  if (sampleTimer) clearInterval(sampleTimer);
  if (tick) clearInterval(tick);
  window.removeEventListener("resize", onResize);
  persistTrailRows(true); // 节流残量冲刷（离屏前最后一拍落盘）
});
</script>

<template>
  <div class="fz-enter">
    <div class="stepper fz-enter" style="margin-bottom:12px">
      <div v-for="(s, i) in stepper" :key="s.label" class="step" :class="{ done: s.done, active: s.active }">
        <span class="step-n">{{ s.done ? "✓" : i + 1 }}</span>
        <span class="step-t">{{ s.label }}</span>
        <span v-if="i < stepper.length - 1" class="step-arrow">→</span>
      </div>
    </div>
    <div class="panel">
      <h2>领取飞行令牌</h2>
      <p class="desc">申请通过后，飞行授权会加密返回——凭申请页的回执码在此领取，领取后自动核验。</p>
      <div class="grid2">
        <div>
          <label>回执码</label><input v-model="receiptCode" class="mono" />
          <label>会话私钥（本地保存，零上传）</label><input v-model="sessionSk" class="mono" />
          <div style="margin-top:12px">
            <button class="btn" :disabled="busy" @click="pickup">领取令牌</button>
          </div>
          <DenyBox v-if="denyPickup" :code="denyPickup.code" :message="denyPickup.message" />
        </div>
        <div v-if="info" class="fz-enter">
          <div style="display:flex; gap:8px; margin-bottom:10px; flex-wrap:wrap">
            <StatusTag :tone="info.ok ? 'ok' : 'bad'" :label="info.ok ? '引擎验签通过' : '验签失败'" />
            <StatusTag v-if="!info.warnings.length" tone="ok" label="校验通过" />
            <StatusTag v-else tone="bad" :label="info.warnings.join('；')" />
            <StatusTag v-if="expired" tone="bad" label="已过期——闸门将拒绝" />
          </div>
          <div class="kv">
            <dt>授权编号</dt><dd style="color: var(--accent-ink); font-weight:700">{{ info.tok.authId }}</dd>
            <dt>高度上限</dt><dd>{{ info.tok.alt_max }} m</dd>
            <dt>时间窗</dt><dd>{{ fmtTs(info.tok.t_start) }} ~ {{ fmtTs(info.tok.t_end) }}</dd>
            <dt>剩余有效期</dt>
            <dd :style="{ color: expired ? 'var(--bad, #c0392b)' : remainS < 300 ? '#b7791f' : 'inherit', fontWeight: 700 }">
              {{ expired ? "已过期" : remainText }}
            </dd>
            <dt>计划哈希</dt><dd><HashText :value="info.tok.plan_hash" head="12" tail="8" /></dd>
            <dt>一次性随机数（防重放）</dt><dd><HashText :value="info.tok.nonce" head="10" tail="6" /></dd>
            <dt>政策版本</dt><dd>{{ info.tok.policy_version }}</dd>
          </div>
        </div>
        <p v-else class="note">领取后此处显示飞行授权信息。</p>
      </div>
    </div>

    <div class="panel fz-enter">
      <h2>飞行解锁</h2>
      <p class="desc">核验通过后解锁起飞，并自动为飞控设置高度上限（令牌上限与计划高度取小）。</p>
      <div class="gate-banner" :class="armed ? 'armed' : 'disarmed'">
        <span class="gate-state">{{ armed ? "ARMED" : "DISARMED" }}</span>
        <span :class="armed ? 'fz-pulse' : ''" style="width:10px; height:10px; border-radius:50%; display:inline-block; background: var(--accent)" />
        <span class="gate-sub">
          {{ armed
            ? `已解锁 · 授权编号 ${armResult.auth_id ?? "—"} · 围栏 ${fenceM ?? "—"} m`
            : "未解锁——完成领取后点击「解锁起飞」" }}
        </span>
      </div>
      <div style="display:flex; gap:10px; flex-wrap:wrap">
        <button class="btn" :disabled="armButton.disabled" :title="armButton.title"
          @click="arm(false)">{{ armButton.label }}</button>
        <button class="btn ghost" :disabled="busy || !info" title="演示：提交被篡改的令牌——闸门必须拒绝（D1 负例）" @click="arm(true)">令牌防篡改自检</button>
      </div>
      <div v-if="armResult" class="kv fz-enter" style="margin-top:12px">
        <dt>闸门</dt>
        <dd v-if="armResult.ok">已解锁（审计行已记）</dd>
        <dd v-else style="color: var(--bad, #c0392b); font-weight: 700">{{ armRejectText || "拒绝（令牌核验未通过）" }}</dd>
        <dt v-if="armResult.auth_id !== undefined">authId</dt><dd v-if="armResult.auth_id !== undefined">{{ armResult.auth_id }}</dd>
        <dt v-if="armResult.fence_state_hex">围栏态（签名绑定）</dt><dd v-if="armResult.fence_state_hex"><span class="mono">{{ armResult.fence_state_hex }}</span></dd>
      </div>
      <DenyBox v-if="denyArm" :code="denyArm.code" :message="denyArm.message" />
    </div>

    <div class="panel fz-enter">
      <h2>飞行记录</h2>
      <p class="desc">解锁后：①「开始记录」开启遥测链与自动采样 → ②「自动飞到目标高度」或「手动爬升」进入合规高度带（低于围栏即为合规）→ ③ 采满样本后到「留痕与 TRAIL」生成合规证书 → ④「结束飞行并封链」收尾。飞行控制三种来源互斥——手动爬升、定高悬停、自动飞行，任一操作即接管；悬停与自动飞行在定高模式下执行。</p>
      <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px; align-items:center">
        <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center">
          <StatusTag :tone="linkState.tone" :label="linkState.label" />
          <StatusTag v-if="sitlReady && armed && chain" tone="accent" :label="`自动真采样中（2Hz）· ${samples.length}/128 点`" />
          <StatusTag v-if="armed" tone="gold" :label="`飞行控制：${ctrlModeLabel}`" />
        </div>
      </div>
      <!-- 合规记录窗口卡（E 席设计：点数记录的用户化表达——进度/预期/检查点/窗口红线） -->
      <div class="wincard fz-enter" :class="{ full: samples.length >= 128, breach: breachInWindow }" style="margin-bottom:10px">
        <div class="wincard-head">
          <b>合规记录窗口</b>
          <span class="mono">{{ samples.length }}/128 点</span>
          <span v-if="chain && !sealed" class="rec-dot" :class="{ stalled: telemetryStalled }"></span>
          <span v-if="telemetryStalled" class="note" style="color:#b7791f">遥测中断——采样暂停</span>
        </div>
        <div class="winbar"><div class="winbar-fill" :style="{ width: Math.min(100, (samples.length / 128) * 100) + '%' }"></div></div>
        <div class="wincard-sub">{{ windowSub }}</div>
        <div class="wincard-sub">已锚定上链 {{ checkpointCount }} 次（每 60 秒一次——飞行证据随进度固化）</div>
      </div>
      <div v-if="fenceBreached" class="deny fz-enter" style="margin-bottom:10px">
        <span class="code">⚠ 固件围栏触发</span>
        硬拦截已生效（STATUSTEXT：{{ breachText }}）——超限事件将随检查点锚定上链取证。
      </div>
      <div
        v-if="armed && fcMode && !['STABILIZE', 'ALT_HOLD'].includes(fcMode)"
        class="note fz-enter"
        style="margin-bottom: 8px; border-left: 3px solid #e0a855; padding-left: 10px"
      >
        ⚠ 飞控处于自主模式 <b>{{ fcMode }}</b>——下一次爬升/悬停指令会先切回定高模式再执行；若切换失败将被拒绝并提示
      </div>
      <div
        v-if="armed && fcArmed === false"
        class="note fz-enter"
        style="margin-bottom: 8px; border-left: 3px solid #e05555; padding-left: 10px"
      >
        🔴 飞控已上锁（地面怠速自动上锁）——爬升/自动飞行不会生效。请重新点击
        <b>「解锁起飞」</b>（同一授权延续，无需重新出证）
      </div>
      <FlightGauges :att="att" :alt-cm="altCmNow" :fence-m="fenceM" style="margin-bottom: 10px" />
      <div v-if="chain" style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px">
        <span v-if="bat?.voltage_v != null" class="tag" style="padding:3px 10px">🔋 {{ bat.voltage_v.toFixed(2) }} V<span v-if="bat.remaining_pct != null"> · {{ bat.remaining_pct }}%</span></span>
        <span v-if="bat?.current_a != null" class="tag" style="padding:3px 10px">⚡ {{ bat.current_a.toFixed(1) }} A</span>
        <span v-if="gps" class="tag" style="padding:3px 10px">🛰 GPS {{ gps.sats }} 颗{{ gps.fix >= 3 ? " · 已定位" : " · 定位中" }}</span>
        <span v-if="hud" class="tag" style="padding:3px 10px">💨 {{ hud.speed_ms.toFixed(1) }} m/s</span>
        <span v-if="hud" class="tag" style="padding:3px 10px">🧭 航向 {{ hud.heading_deg }}°</span>
        <span v-if="hud" class="tag" style="padding:3px 10px">🎛 油门 {{ hud.throttle_pct }}%</span>
      </div>
      <div class="fz-globe-frame">
      <FlightGlobe
        style="height: 460px; margin-bottom: 0"
        :samples="samples"
        :att="att"
        :fence-m="fenceM"
        :fence-breached="fenceBreached"
        :anchor-count="checkpointCount"
        :armed="armed && fcArmed !== false"
      />
      </div>
      <canvas ref="altCanvas" class="fz-chart"></canvas>
      <canvas v-if="globeFailed" ref="trackCanvas" class="fz-chart" style="margin-top:10px"></canvas>
      <div class="grid2" style="margin-top:10px">
        <div v-if="globeFailed"></div>
        <div>
          <label>目标高度（米，自动飞达后悬停）</label>
          <input v-model.number="targetAltM" type="number" :min="2" :max="Math.max(2, (fenceM ?? 50) - 3)" />
          <p v-if="targetAltM2 < targetAltM" class="note" style="color:#b7791f;margin-top:4px">超出围栏——实际按 {{ targetAltM2 }} m 执行</p>
          <div style="display:flex; gap:8px; margin-top:8px; flex-wrap:wrap">
            <button class="btn" :disabled="!sitlReady || !armed || !chain || autoFlying" @click="flyToTarget">{{ autoFlying ? "自动飞行中…" : "自动飞到目标高度" }}</button>
            <button class="btn ghost" :disabled="!autoFlying" @click="stopAuto">停止自动</button>
          </div>
        </div>
      </div>
      <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top:10px">
        <button class="btn" :class="{ primary: stage === 'record_ready' }" :disabled="!!chain" :title="armed ? '开启遥测链与自动采样（每 0.5 秒记录一点）' : '需先解锁起飞'" @click="startChain">开始记录</button>
        <div v-if="!sitlReady && chain" class="deny fz-enter" style="flex:1 1 100%">
          <span class="code">飞控未连接</span>
          等待 SITL 桥接线（tcp:5760）——真实测试策略：不提供合成遥测。桥接线后本区自动恢复飞控控件。
        </div>
        <button v-if="sitlReady" class="btn ghost" :disabled="!armed || sealing"
        title="按住持续爬升，松开即定高保持；持续按住可强行突破围栏（将触发违规取证）"
        @pointerdown="climbHoldStart(1)" @pointerup="climbHoldStop"
        @pointerleave="climbHoldStop" @pointercancel="climbHoldStop">按住爬升</button>
        <button v-if="sitlReady" class="btn ghost" :disabled="!armed || sealing"
        title="按住持续下降（地面保护：不低于 0.3m），松开即定高保持"
        @pointerdown="climbHoldStart(-1)" @pointerup="climbHoldStop"
        @pointerleave="climbHoldStop" @pointercancel="climbHoldStop">按住下降</button>
        <button v-if="sitlReady" class="btn ghost" :disabled="!armed || sealing" title="保持当前高度（定高模式）" @click="hover()">悬停</button>
        <button v-if="!sealed" class="btn" :disabled="!chain || sealing" style="border-color:#d98484; color:#a33" @click="endFlight">{{ sealing ? "封链中…" : "结束飞行并封链" }}</button>
        <button v-if="sealed" class="btn" @click="newFlight">开始新架次（领取新令牌后可再次飞行）</button>
      </div>
      <div v-if="sealConfirm && !sealed && !sealing && chain" class="deny fz-enter" style="margin-top:8px">
        确认结束飞行？电机将立即停止（DISARM），检查点锚定上链，本架次不可继续。
        <button class="btn" style="margin-left:10px" :disabled="sealing" @click="endFlight">确认封链</button>
        <button class="btn ghost" style="margin-left:8px" @click="sealConfirm = false">取消</button>
      </div>
      <div v-if="fenceBreached && chain && samples.length < 128" class="deny fz-enter" style="margin-top:8px">
        ⚠ 合规记录窗口（前 128 点）内出现超限样本——本窗口的 TRAIL 合规证书将无法生成。
      </div>
      <div v-if="chain && samples.length" class="note fz-enter" style="margin-top:8px">
        当前高度 <b>{{ currentAltM }} m</b><template v-if="fenceM"> · 围栏 {{ fenceM }} m</template>
      </div>
      <div v-if="chain" class="kv fz-enter" style="margin-top:12px">
        <dt>飞行链起始锚</dt><dd><HashText :value="chain.genesis_head_hex" head="14" tail="8" /></dd>
        <dt>设备公钥</dt><dd><HashText :value="chain.device_pub_hex" head="14" tail="8" /></dd>
        <dt v-if="samples.length">最新链头</dt><dd v-if="samples.length"><HashText :value="samples[samples.length - 1].head" head="14" tail="8" /></dd>
      </div>
      <div v-if="events.length" class="kv fz-enter" style="margin-top:12px">
        <dt>事件时间线（飞行中实时）</dt>
        <dd>
          <div
            v-for="(e, i) in events"
            :key="i"
            style="display:flex; gap:8px; align-items:baseline; padding:2px 0"
            :style="e.red ? 'color:#e05555' : ''"
          >
            <span class="mono" style="opacity:0.75">{{ new Date(e.t * 1000).toLocaleTimeString() }}</span>
            <span>{{ e.text }}</span>
          </div>
        </dd>
      </div>
      <div v-if="sealed" class="note fz-enter" style="margin-top:10px; border:1px solid var(--line); border-radius:8px; padding:10px 12px">
        <p style="margin:0 0 6px"><b>飞行记录单</b>（本机留痕——链上证据见判决件与检查点锚定）</p>
        <div class="grid2">
          <div class="kv">
            <dt>飞行时长</dt><dd>{{ flightDuration }}</dd>
            <dt>峰值高度</dt><dd>{{ peakAltM }} m</dd>
            <dt>围栏余量</dt><dd>{{ fenceM != null ? Math.max(fenceM - peakAltM, 0) : "—" }} m{{ fenceBreached ? "（已触发——超限取证见 TRAIL 屏）" : "" }}</dd>
          </div>
          <div class="kv">
            <dt>样本 / 锚定事件</dt><dd>{{ samples.length }} / {{ events.filter(e => e.kind === "checkpoint").length }}</dd>
            <dt>结束电池 / GPS</dt><dd>{{ bat?.remaining_pct != null ? bat.remaining_pct + "%" : "—" }} · {{ gps ? gps.sats + " 颗" : "—" }}</dd>
            <dt>链头终值</dt><dd><HashText v-if="samples.length" :value="samples[samples.length - 1].head" head="12" tail="6" /></dd>
          </div>
        </div>
      </div>
      <div v-if="anchorResult" class="note fz-enter" style="margin-top:8px">
        <template v-if="anchorResult.ok">
          ✓ 封链完成：已锚定 {{ anchorResult.anchored }} 个检查点（anchored_seq={{ anchorResult.anchored_seq }}）——第三方可经链上 verifyHead 复验。
        </template>
        <template v-else>
          封链失败：{{ anchorResult.code }}——检查点未锚定（fail-closed，可重试续锚）。
        </template>
      </div>
      <DenyBox v-if="denyLog" :code="denyLog.code" :message="denyLog.message" />
    </div>
  </div>
</template>

<style scoped>
/* 仪表框（视觉深化批 E：取景器感——发丝边+四角刻度+2% 暗角；
   FlightGlobe 内部零触碰） */
.fz-globe-frame {
  position: relative;
  border: var(--hairline);
  border-radius: 10px;
  overflow: hidden;
  margin-bottom: 10px;
  background: radial-gradient(120% 90% at 50% 40%, transparent 62%, rgba(28, 42, 58, 0.05) 100%);
  box-shadow: var(--shadow-1);
}
.fz-globe-frame::before,
.fz-globe-frame::after {
  content: "";
  position: absolute;
  width: 12px; height: 12px;
  pointer-events: none;
  z-index: 2;
  opacity: 0.55;
}
.fz-globe-frame::before {
  top: 8px; left: 8px;
  border-top: 1.5px solid var(--teal);
  border-left: 1.5px solid var(--teal);
}
.fz-globe-frame::after {
  bottom: 8px; right: 8px;
  border-bottom: 1.5px solid var(--teal);
  border-right: 1.5px solid var(--teal);
}
.fz-chart {
  width: 100%;
  height: 140px;
  background: var(--panel-2, #f4f7fb);
  border: var(--hairline, 1px solid #dbe3ec);
  border-radius: 8px;
  display: block;
}
.gate-banner {
  display: flex; align-items: center; gap: 12px;
  border: var(--hairline); border-left-width: 4px; border-radius: 10px;
  padding: 12px 16px; margin-bottom: 12px; background: var(--panel-2);
}
.gate-banner.armed { border-left-color: var(--accent); }
.gate-banner.disarmed { border-left-color: #9aa7b8; }
.gate-state {
  font-family: ui-monospace, monospace; font-size: 22px; font-weight: 700;
  letter-spacing: 2px; color: var(--ink);
}
.gate-banner.armed .gate-state { color: var(--accent-ink); }
.gate-sub { color: var(--ink-2, var(--ink)); font-size: 13px; }
.stepper { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 10px 14px; }
.step { display: flex; align-items: center; gap: 6px; color: var(--ink-3, #64748b); font-size: 13px; }
.step-n { width: 20px; height: 20px; border-radius: 50%; border: 1.5px solid var(--line-strong, #c9d4e2); display: inline-flex; align-items: center; justify-content: center; font-size: 11px; }
.step.active { color: var(--accent-ink, #1d4ed8); font-weight: 700; }
.step.active .step-n { border-color: var(--accent, #2f6fed); background: var(--accent-soft, #e8f0fe); }
.step.done { color: var(--ok, #2e7d32); }
.step.done .step-n { border-color: var(--ok, #2e7d32); color: var(--ok, #2e7d32); }
.step-arrow { color: var(--ink-3, #94a3b8); margin: 0 2px; }
.wincard { border: 1px solid var(--line, #d8e0ea); border-radius: 10px; padding: 10px 14px; background: var(--panel-2, #f7f9fc); }
.wincard.full { border-color: var(--ok, #2e7d32); }
.wincard.breach { border-color: #d98484; background: #fdf3f3; }
.wincard-head { display: flex; align-items: center; gap: 10px; font-size: 13.5px; }
.wincard-sub { color: var(--ink-3, #64748b); font-size: 12px; margin-top: 4px; }
.winbar { height: 8px; border-radius: 4px; background: var(--line, #e5eaf1); overflow: hidden; margin-top: 6px; }
.winbar-fill { height: 100%; background: linear-gradient(90deg, #2f6fed, #35d07f); border-radius: 4px; transition: width 0.4s; }
.rec-dot { width: 9px; height: 9px; border-radius: 50%; background: #e05555; animation: recblink 1.2s infinite; }
.rec-dot.stalled { background: #b7791f; animation: none; }
@keyframes recblink { 0%, 60% { opacity: 1; } 61%, 100% { opacity: 0.25; } }

</style>
