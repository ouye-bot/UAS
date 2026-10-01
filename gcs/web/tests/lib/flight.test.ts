import { describe, expect, it } from "vitest";
import { flightStage, stepperState, windowSubline } from "../../src/lib/flight";

describe("飞行流程状态机（③屏步进器单一事实源）", () => {
  const base = { hasToken: false, armed: false, chainStarted: false, sealed: false, sampleCount: 0 };

  it("七态按序推进", () => {
    expect(flightStage(base)).toBe("pickup");
    expect(flightStage({ ...base, hasToken: true })).toBe("arm");
    expect(flightStage({ ...base, hasToken: true, armed: true })).toBe("record_ready");
    expect(flightStage({ ...base, hasToken: true, armed: true, chainStarted: true, sampleCount: 47 })).toBe("recording");
    expect(flightStage({ ...base, hasToken: true, armed: true, chainStarted: true, sampleCount: 128 })).toBe("window_full");
    expect(flightStage({ ...base, hasToken: true, armed: true, chainStarted: true, sampleCount: 200, sealed: true })).toBe("sealed");
  });

  it("步进器：当前步 active、已完成步 done", () => {
    const s0 = stepperState(base);
    expect(s0[0].active).toBe(true);
    const s2 = stepperState({ ...base, hasToken: true, armed: true, chainStarted: true, sampleCount: 10 });
    expect(s2[0].done && s2[1].done && s2[2].done).toBe(true);
    expect(s2[3].active).toBe(true); // 记录中→下一步动作=封链上链
    const s4 = stepperState({ ...base, hasToken: true, armed: true, chainStarted: true, sampleCount: 130, sealed: true });
    expect(s4[3].done).toBe(true);
    expect(s4.some((x) => x.active)).toBe(false);
  });

  it("窗口副行：剩余秒数/可出证/超限作废", () => {
    expect(windowSubline(0, false)).toContain("64 秒"); // 128 点 × 0.5s
    expect(windowSubline(127, false)).toContain("1 秒");
    expect(windowSubline(128, false)).toContain("可生成合规证书");
    expect(windowSubline(10, true)).toContain("无法生成");
  });

  it("sealed 恒优先（封链后采样数不再影响状态）", () => {
    expect(flightStage({ ...base, hasToken: true, armed: true, chainStarted: true, sampleCount: 130, sealed: true })).toBe("sealed");
  });
});
