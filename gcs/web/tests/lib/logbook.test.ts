/** 飞手合规档案 fzLogbook（档案积累批）单元测试。
 *
 * 覆盖生命周期四写入点的数据面契约：
 * - append 去重合并：申请骨架行→取件回填→封链统计→TRAIL 判决汇成一行
 *   （含跨架次时序：先 newFlight 清单架次键，后 TrailView 回写仍挂上）
 * - 上限 50 防膨胀裁最旧
 * - 身份域：fzLogbook 在 IDENTITY_SCOPED_KEYS——换人清扫不串号
 * - 回填只挂 pending 行不新建；坏 JSON 容错=空档案
 * node 环境无 DOM storage——内存替身（同 tests/lib/material.test.ts 纪律）。 */
import { beforeEach, describe, expect, it } from "vitest";

class MemStorage {
  private m = new Map<string, string>();
  getItem(k: string): string | null { return this.m.has(k) ? this.m.get(k)! : null; }
  setItem(k: string, v: string): void { this.m.set(k, String(v)); }
  removeItem(k: string): void { this.m.delete(k); }
  clear(): void { this.m.clear(); }
}

beforeEach(() => {
  (globalThis as Record<string, unknown>).localStorage = new MemStorage();
  (globalThis as Record<string, unknown>).sessionStorage = new MemStorage();
});

import {
  IDENTITY_SCOPED_KEYS,
  logbookAll,
  logbookAppend,
  logbookBackfillAuthId,
  logbookFindByAuthId,
  logbookUpdate,
  storeIdentityTag,
  sweepIfIdentityChanged,
} from "../../src/lib/material";

const CRED_A = { master_cred_hash_hex: "aa".repeat(32), salt_hex: "01" };
const CRED_B = { master_cred_hash_hex: "bb".repeat(32), salt_hex: "02" };

/** 完整生命周期种子：受理骨架行→取件回填（ApplyView/FlightView 两写入点）。 */
function seedLifecycle(authId = 7): void {
  logbookAppend({
    caseId: "case-auth-1", receiptCode: "RC-0001",
    tStart: 1790000000, tEnd: 1790007200, classId: 1, altMax: 120,
  });
  logbookBackfillAuthId("case-auth-1", "RC-0001", authId);
}

describe("logbook append 合并语义", () => {
  it("骨架行→取件回填：同案卷号合并成一行（authId 留空再回填）", () => {
    logbookAppend({
      caseId: "case-auth-1", receiptCode: "RC-0001",
      tStart: 1790000000, tEnd: 1790007200, classId: 1, altMax: 120,
    });
    expect(logbookAll()).toHaveLength(1);
    expect(logbookAll()[0].authId).toBeNull();
    const row = logbookBackfillAuthId("case-auth-1", "RC-0001", 7);
    expect(row?.authId).toBe(7);
    expect(logbookAll()).toHaveLength(1); // 回填不新建行
    expect(logbookAll()[0]).toMatchObject({
      authId: 7, caseId: "case-auth-1", receiptCode: "RC-0001",
      tStart: 1790000000, tEnd: 1790007200, classId: 1, altMax: 120,
      sealedAt: null, breachFlag: false,
    });
  });

  it("回退匹配：案卷号丢失时按回执码回填 pending 行；无匹配不新建", () => {
    logbookAppend({ caseId: "case-auth-9", receiptCode: "RC-0009" });
    expect(logbookBackfillAuthId(null, "RC-0009", 12)?.authId).toBe(12);
    // 无 pending 骨架行（如取件在非出证设备）——不产生空档案行
    expect(logbookBackfillAuthId(null, "RC-NONE", 99)).toBeNull();
    expect(logbookAll()).toHaveLength(1);
  });

  it("恢复路径重交幂等：同 caseId/receiptCode 再 append 不产生重复行", () => {
    seedLifecycle();
    logbookAppend({ caseId: "case-auth-1", receiptCode: "RC-0001", altMax: 120 });
    expect(logbookAll()).toHaveLength(1);
  });
});

describe("logbook update 回填（封链统计/TRAIL 判决）", () => {
  it("封链统计回填：sealedAt/nSamples/checkpointCount/breachFlag 落行", () => {
    seedLifecycle(7);
    const row = logbookUpdate(7, {
      sealedAt: 1790003600, nSamples: 256, checkpointCount: 4, breachFlag: true,
    });
    expect(row).toMatchObject({ sealedAt: 1790003600, nSamples: 256, checkpointCount: 4, breachFlag: true });
    expect(logbookFindByAuthId(7)?.createdAt).toBeTruthy(); // 骨架行锚不被覆盖
  });

  it("无匹配行=no-op（统计晚到挂不上就不挂——不虚增行）", () => {
    expect(logbookUpdate(404, { sealedAt: 1 })).toBeNull();
    expect(logbookAll()).toHaveLength(0);
  });

  it("TRAIL 判决按窗口键累积：两次窗口回写汇入同一行的 tripCaseIds/trailVerdicts", () => {
    seedLifecycle(7);
    logbookUpdate(7, {
      tripCaseIds: { 0: "trip-case-0" },
      trailVerdicts: { 0: { verdict: "PASS", sm3: "11".repeat(32) } },
    });
    logbookUpdate(7, {
      tripCaseIds: { 1: "trip-case-1" },
      trailVerdicts: { 1: { verdict: "PASS", sm3: "22".repeat(32) } },
    });
    const row = logbookFindByAuthId(7)!;
    expect(row.tripCaseIds).toEqual({ 0: "trip-case-0", 1: "trip-case-1" });
    expect(Object.keys(row.trailVerdicts).sort()).toEqual(["0", "1"]);
    expect(row.trailVerdicts[1]).toEqual({ verdict: "PASS", sm3: "22".repeat(32) });
  });
});

describe("上限裁剪（防膨胀）", () => {
  it("超过 50 条裁最旧：保最新 50 行", () => {
    for (let i = 0; i < 55; i++) {
      logbookAppend({ caseId: `case-${i}`, receiptCode: `RC-${i}`, createdAt: 1790000000 + i });
    }
    const rows = logbookAll();
    expect(rows).toHaveLength(50);
    expect(rows[0].caseId).toBe("case-54"); // 最新在前
    expect(rows.some((r) => r.caseId === "case-54")).toBe(true);
    expect(rows.some((r) => r.caseId === "case-4")).toBe(false); // 最旧被裁
  });
});

describe("身份域换人清扫", () => {
  it("fzLogbook 在 IDENTITY_SCOPED_KEYS 清单中（清扫契约单源）", () => {
    expect(IDENTITY_SCOPED_KEYS).toContain("fzLogbook");
  });

  it("换人即清：身份标签变化触发清扫，上一身份档案不残留", () => {
    localStorage.setItem("fzCred", JSON.stringify(CRED_A));
    storeIdentityTag(); // 落当前身份标签（同身份不触发清扫）
    expect(sweepIfIdentityChanged()).toBe(false);
    seedLifecycle(7);
    expect(logbookAll()).toHaveLength(1);
    localStorage.setItem("fzCred", JSON.stringify(CRED_B)); // 换人
    expect(sweepIfIdentityChanged()).toBe(true);
    expect(localStorage.getItem("fzLogbook")).toBeNull();
    expect(logbookAll()).toHaveLength(0);
  });
});

describe("跨架次归档时序（先 newFlight 后 TrailView 回写）", () => {
  it("单架次键清空后，判决回写仍挂到已入档的统计行——一行齐备", () => {
    seedLifecycle(7);
    // endFlight：封链统计入档
    logbookUpdate(7, { sealedAt: 1790003600, nSamples: 128, checkpointCount: 2, breachFlag: false });
    // newFlight：清单架次键（fzTrailRows/fzLastCaseId/fzFlightFenceBreached…）
    localStorage.setItem("fzTrailRows", "[{}]"); // 起链后才有——先造出再清
    localStorage.setItem("fzLastCaseId", "case-auth-1");
    localStorage.setItem("fzFlightFenceBreached", "1");
    localStorage.removeItem("fzTrailRows");
    localStorage.removeItem("fzLastCaseId");
    localStorage.removeItem("fzFlightFenceBreached");
    // fzLogbook 不在单架次清理面——统计幸存
    expect(localStorage.getItem("fzLogbook")).not.toBeNull();
    // TrailView：出证/判决晚于 newFlight——按授权编号回写
    logbookUpdate(7, {
      tripCaseIds: { 0: "trip-case-0" },
      trailVerdicts: { 0: { verdict: "PASS", sm3: "33".repeat(32) } },
    });
    expect(logbookAll()).toHaveLength(1);
    expect(logbookFindByAuthId(7)).toMatchObject({
      sealedAt: 1790003600, nSamples: 128, checkpointCount: 2,
      tripCaseIds: { 0: "trip-case-0" },
    });
  });

  it("链路冒烟（两架次完整时序=视图调用序）：受理→取件→封链→newFlight→判决，档案两行齐备", () => {
    // ---- 架次一（authId=7，两窗存证，无超限）----
    logbookAppend({ caseId: "auth-case-1", receiptCode: "RC-1", tStart: 1790000000, tEnd: 1790007200, classId: 1, altMax: 120 });
    logbookBackfillAuthId("auth-case-1", "RC-1", 7); // FlightView 取件成功处
    logbookUpdate(7, { sealedAt: 1790003600, nSamples: 260, checkpointCount: 4, breachFlag: false }); // endFlight 封链成功处
    localStorage.removeItem("fzLastCaseId"); // newFlight 清空（先归档再清空——统计已入档）
    logbookUpdate(7, { tripCaseIds: { 0: "t-7-0" }, trailVerdicts: { 0: { verdict: "PASS", sm3: "aa".repeat(32) } } });
    logbookUpdate(7, { tripCaseIds: { 1: "t-7-1" }, trailVerdicts: { 1: { verdict: "PASS", sm3: "bb".repeat(32) } } });
    // ---- 架次二（authId=8，超限如实披露）----
    logbookAppend({ caseId: "auth-case-2", receiptCode: "RC-2", tStart: 1790100000, tEnd: 1790107200, classId: 0, altMax: 50 });
    logbookBackfillAuthId("auth-case-2", "RC-2", 8);
    logbookUpdate(8, { sealedAt: 1790103600, nSamples: 130, checkpointCount: 2, breachFlag: true });
    logbookUpdate(8, { tripCaseIds: { 0: "t-8-0" }, trailVerdicts: { 0: { verdict: "PASS", sm3: "cc".repeat(32) } } });
    // ---- 档案面聚合（ChainView KPI 消费的数据形状）----
    const rows = logbookAll();
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.authId).sort()).toEqual([7, 8]);
    expect(rows.filter((r) => r.sealedAt != null)).toHaveLength(2); // 累计合规飞行 2 次
    expect(rows.reduce((n, r) => n + Object.keys(r.trailVerdicts).length, 0)).toBe(3); // 存证证书 3 张
    expect(rows.reduce((n, r) => n + (r.checkpointCount ?? 0), 0)).toBe(6); // 链上锚定 6 个
    expect(logbookFindByAuthId(8)?.breachFlag).toBe(true); // 超限披露行数据源
  });
});

describe("空档案与容错", () => {
  it("无数据/坏 JSON=空档案（不炸读取面）", () => {
    expect(logbookAll()).toEqual([]);
    localStorage.setItem("fzLogbook", "{not json");
    expect(logbookAll()).toEqual([]);
    localStorage.setItem("fzLogbook", '{"a":1}'); // 非数组
    expect(logbookAll()).toEqual([]);
  });

  it("行级规范化：缺字段补默认，不致 undefined 蔓延到渲染层", () => {
    localStorage.setItem("fzLogbook", JSON.stringify([{ authId: 9, caseId: "c9" }]));
    const row = logbookFindByAuthId(9)!;
    expect(row.receiptCode).toBe("");
    expect(row.breachFlag).toBe(false);
    expect(row.tripCaseIds).toEqual({});
    expect(row.trailVerdicts).toEqual({});
    expect(row.sealedAt).toBeNull();
  });

  it("findByAuthId 未命中返回 null", () => {
    expect(logbookFindByAuthId(123)).toBeNull();
  });
});
