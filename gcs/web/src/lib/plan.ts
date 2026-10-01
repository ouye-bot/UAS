/** 结构化飞行计划（P1 体验批）：飞手真实声明 + 本地加盐承诺。
 *
 * 隐私语义：计划全文与盐只存本机（按承诺键索引）；对外（绑定面/证明/令牌/受理）
 * 只有承诺值 SM3(盐 ‖ 规范化计划 JSON)——防穷举（无盐不可试）+防跨次关联
 * （每申请新盐→同计划不同承诺）。计划高度经 ARM 请求提交桥接，围栏取
 * min(令牌 alt_max, 计划高度)——地面站层约束（TCB 第①层声明）。
 */
import { sm3 } from "sm-crypto";
import { randHex } from "./api";

export interface FlightPlan {
  region: string;
  start_ts: number;
  end_ts: number;
  alt_m: number;
  purpose: string;
}

export function initialFlightPlan(): FlightPlan {
  return { region: "", start_ts: 0, end_ts: 0, alt_m: 0, purpose: "" };
}

/** 规范化序列（键排序 + 紧凑分隔）——承诺的稳定原像。 */
export function canonicalPlanJson(p: FlightPlan): string {
  const keys = ["alt_m", "end_ts", "purpose", "region", "start_ts"] as const;
  return keys.map((k) => `${k}=${String(p[k])}`).join("|");
}

/** 计划承诺：SM3(盐字节 ‖ 规范化计划字节)——64hex。 */
export function planCommitment(saltHex: string, p: FlightPlan): string {
  const saltBytes = new Uint8Array(saltHex.length / 2);
  for (let i = 0; i < saltBytes.length; i++)
    saltBytes[i] = parseInt(saltHex.slice(i * 2, i * 2 + 2), 16);
  const planBytes = new TextEncoder().encode(canonicalPlanJson(p));
  const msg = new Uint8Array(saltBytes.length + planBytes.length);
  msg.set(saltBytes, 0);
  msg.set(planBytes, saltBytes.length);
  return sm3(Array.from(msg));
}

export function newPlanSalt(): string {
  return randHex(16);
}

/** 计划校验：通过返回 null，否则错误码（组件映射提示）。 */
export function validatePlan(p: FlightPlan): string | null {
  if (!p.region.trim()) return "region_required";
  if (!p.purpose.trim()) return "purpose_required";
  if (!(p.end_ts > p.start_ts)) return "time_order";
  // 计划不可回填过去（60 秒时钟余量防本地钟微差误伤——用户反馈 2026-09-25）
  const now_s = Math.floor(Date.now() / 1000);
  if (p.start_ts < now_s - 60) return "time_past";
  if (!Number.isInteger(p.alt_m) || p.alt_m < 1 || p.alt_m > 500) return "alt_range";
  return null;
}

// ---- 本机计划仓（承诺 → {salt, plan}；ARM 围栏联动与本地核对消费） ----
const PLAN_STORE_KEY = "fzPlanStore";

export function storePlan(commitment: string, salt: string, plan: FlightPlan): void {
  const raw = localStorage.getItem(PLAN_STORE_KEY);
  const store = raw ? JSON.parse(raw) : {};
  store[commitment] = { salt, plan };
  localStorage.setItem(PLAN_STORE_KEY, JSON.stringify(store));
}

export function loadPlan(commitment: string): { salt: string; plan: FlightPlan } | null {
  const raw = localStorage.getItem(PLAN_STORE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw)[commitment] ?? null;
  } catch {
    return null;
  }
}
