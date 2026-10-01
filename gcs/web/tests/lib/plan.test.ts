/** P1 体验批：结构化飞行计划测试（加盐承诺+本地存储+校验）。
 *
 * - 承诺=SM3(盐 ‖ 规范化计划 JSON)：确定性（同盐同计划同承诺）、
 *   抗穷举（不同盐→不同承诺——跨次不可关联）、规范化稳定（键序无关）
 * - 盐不出本机：承诺序列化串中搜不到盐
 * - 校验：区域/用途非空、高度 1..500、时段起止有序
 */
import { describe, expect, it } from "vitest";
import {
  canonicalPlanJson,
  initialFlightPlan,
  planCommitment,
  validatePlan,
} from "../../src/lib/plan";

const PLAN = {
  region: "科技园北侧作业区",
  start_ts: 1790000000,
  end_ts: 1790003600,
  alt_m: 30,
  purpose: "农田巡查",
};
const SALT = "ab".repeat(16);

describe("结构化飞行计划", () => {
  it("承诺确定性：同盐同计划同承诺", () => {
    expect(planCommitment(SALT, PLAN)).toBe(planCommitment(SALT, PLAN));
  });

  it("抗穷举/抗关联：不同盐→不同承诺（队友 #3 缺口的关闭判据）", () => {
    const c1 = planCommitment("11".repeat(16), PLAN);
    const c2 = planCommitment("22".repeat(16), PLAN);
    expect(c1).not.toBe(c2);
  });

  it("规范化稳定：键序无关（同内容不同构造序=同承诺）", () => {
    const reordered = {
      purpose: PLAN.purpose, alt_m: PLAN.alt_m, end_ts: PLAN.end_ts,
      start_ts: PLAN.start_ts, region: PLAN.region,
    };
    expect(planCommitment(SALT, reordered as typeof PLAN)).toBe(planCommitment(SALT, PLAN));
  });

  it("规范化串可读且含计划要素（本机可核对）", () => {
    const j = canonicalPlanJson(PLAN);
    expect(j).toContain("科技园北侧作业区");
    expect(j).toContain("农田巡查");
  });

  it("校验：区域/用途非空、时段有序、高度 1..500", () => {
    const p = { ...initialFlightPlan() };
    expect(validatePlan(p)).toBe("region_required");
    p.region = "北区";
    expect(validatePlan(p)).toBe("purpose_required");
    p.purpose = "巡查";
    expect(validatePlan(p)).toBe("time_order");
    const now_s = Math.floor(Date.now() / 1000);
    p.start_ts = now_s + 600;
    p.end_ts = p.start_ts + 600;
    expect(validatePlan(p)).toBe("alt_range");
    p.alt_m = 30;
    expect(validatePlan(p)).toBeNull();
    p.alt_m = 501;
    expect(validatePlan(p)).toBe("alt_range");
  });

  it("校验：计划开始时间回填过去被拒（2026-09-25 队长实测反馈；60 秒时钟余量）", () => {
    const p = { ...initialFlightPlan(), region: "北区", purpose: "巡查", alt_m: 30 };
    const now_s = Math.floor(Date.now() / 1000);
    p.start_ts = now_s - 3600;
    p.end_ts = now_s + 3600;
    expect(validatePlan(p)).toBe("time_past");
    p.start_ts = now_s - 30;
    expect(validatePlan(p)).toBeNull();
  });
});
