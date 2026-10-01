/** 飞行流程状态机（③屏步进器/引导的单一事实源——纯函数可测）。
 * 七态：领取令牌 → 解锁起飞 → 开始记录 →（记录中 / 窗口已满）→ 封链。
 * 全部由既有旁路字段派生，零链语义触碰（2026-09-28 E 席设计批）。 */

export type FlightStage =
  | "pickup" // 未取件
  | "arm" // 已取件未解锁
  | "record_ready" // 已解锁未开始记录
  | "recording" // 记录中·合规窗口未满
  | "window_full" // 合规窗口已满（可出证）
  | "sealed"; // 已封链

export interface StageInput {
  hasToken: boolean;
  armed: boolean;
  chainStarted: boolean;
  sealed: boolean;
  sampleCount: number;
}

export function flightStage(i: StageInput): FlightStage {
  if (i.sealed) return "sealed";
  if (!i.hasToken) return "pickup";
  if (!i.armed) return "arm";
  if (!i.chainStarted) return "record_ready";
  return i.sampleCount >= 128 ? "window_full" : "recording";
}

/** 顶部四格步进器：领取令牌 → 解锁起飞 → 开始记录 → 封链上链。 */
export const STAGE_STEPS = ["领取令牌", "解锁起飞", "开始记录", "封链上链"] as const;

export function stepperState(i: StageInput): { label: string; done: boolean; active: boolean }[] {
  const stage = flightStage(i);
  const done = [i.hasToken, i.armed, i.chainStarted, i.sealed];
  const activeMap: Record<FlightStage, number> = {
    pickup: 0, arm: 1, record_ready: 2, recording: 3, window_full: 3, sealed: 3,
  };
  const active = activeMap[stage];  return STAGE_STEPS.map((label, idx) => ({
    label, done: done[idx], active: idx === active && !done[idx],
  }));
}

/** 合规记录窗口副行文案（128 点 @2Hz——TRAIL 出证窗口）。 */
export function windowSubline(sampleCount: number, breachedInWindow: boolean): string {
  if (breachedInWindow) return "窗口内出现超限样本——本窗口合规证书无法生成";
  if (sampleCount >= 128) return "已满 128 点——可生成合规证书";
  const remainS = Math.ceil(((128 - sampleCount) * 0.5));
  return `约还需 ${remainS} 秒（每 0.5 秒记录一点）`;
}
