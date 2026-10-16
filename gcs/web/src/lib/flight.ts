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

/** 令牌防篡改自检（D1 负例演示）判词——纯函数单源（2026-10-15 根修批）。
 * 语义：自检=提交被篡改的令牌（alt_max+1），**闸门拒绝=自检通过**（防篡改
 * 机制在位），**闸门接受=自检失败**（最重失败，必须显红）；拒绝但原因非
 * 签名核验=自检结论不成立（如实显红，不冒充通过）。此前该负例复用真实
 * 解锁的呈现面——拒绝按真实失败显红（与钥分脑等真故障不可辨）且覆盖解锁
 * 态（横幅 ARMED→DISARMED 翻转）——队长手测实弹报障后分离。 */
export function tamperSelfCheckVerdict(r: { ok?: boolean; code?: string; message?: string }): {
  pass: boolean;
  text: string;
} {
  if (r.ok) {
    return { pass: false, text: "防篡改自检失败：被篡改的令牌被闸门接受——闸门防线失效，请立即停用并上报" };
  }
  if (r.code === "bad_signature") {
    return { pass: true, text: "防篡改自检通过：闸门拒绝了被篡改的令牌（签名核验 bad_signature）——防篡改机制在位" };
  }
  return {
    pass: false,
    text: `防篡改自检未完成：闸门以 ${r.code ?? "未知原因"} 拒绝（${r.message ?? "无详情"}）——拒绝原因非签名核验，自检结论不成立`,
  };
}
