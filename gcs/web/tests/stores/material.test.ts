/** 材料 store 单测（Pinia 收敛批）：子凭证签发落盘/出示钥轮换/指纹失配/清扫四表。
 * node 环境无 DOM storage——内存替身（同 tests/lib/material.test.ts 纪律）；
 * Pinia 用独立实例（setActivePinia）。 */
import { beforeEach, describe, expect, it } from "vitest";
import { createPinia, setActivePinia } from "pinia";

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
  setActivePinia(createPinia());
});

import { useMaterialStore } from "../../src/stores/material";

const CRED = { master_cred_hash_hex: "aa".repeat(32), salt_hex: "bb".repeat(16) };
const FORM = { id_number: "110101199001011234", sn: "FZ-SN-1", cert_level: 3, class_id: 1 };

function seedMaterial(): void {
  localStorage.setItem("fzCred", JSON.stringify(CRED));
  localStorage.setItem("fzForm", JSON.stringify(FORM));
}

const OUT = { sub_cred_hash_hex: "cc".repeat(32), id_prime_hex: "dd".repeat(32), sig_hex: "ee".repeat(32), expires_at: "2027-01-01" };

describe("material store：签发与轮换", () => {
  it("首签：fzSub 落盘+sk′ 会话域在场+绑定指纹落盘，返回 null（无旧钥不播轮换）", () => {
    seedMaterial();
    const s = useMaterialStore();
    s.reload();
    const flip = s.issueSub({ ...OUT }, "11".repeat(64), "22".repeat(32));
    expect(flip).toBeNull();
    expect(s.sub?.holder_pk_hex).toBe("11".repeat(64));
    expect(JSON.parse(localStorage.getItem("fzSub")!).holder_pk_hex).toBe("11".repeat(64));
    expect(s.hasSubSk).toBe(true);
    expect(sessionStorage.getItem("fzSubSk")).toBe("22".repeat(32));
    // 绑定指纹已落盘（键名兼容：fzSubBound）
    expect(JSON.parse(localStorage.getItem("fzSubBound")!)).toBeTruthy();
    expect(s.isStale()).toBe(false);
  });

  it("轮换：二次签发（新出示钥）返回 {prev,next} 且新钥覆盖会话域旧钥", () => {
    seedMaterial();
    const s = useMaterialStore();
    s.reload();
    s.issueSub({ ...OUT }, "11".repeat(64), "22".repeat(32));
    const flip = s.issueSub({ ...OUT }, "33".repeat(64), "44".repeat(32));
    expect(flip).toEqual({ prev: "11".repeat(64), next: "33".repeat(64) });
    expect(s.sub?.holder_pk_hex).toBe("33".repeat(64));
    expect(sessionStorage.getItem("fzSubSk")).toBe("44".repeat(32));
  });
});

describe("material store：指纹失配与清扫", () => {
  it("失配检测：重新登记（改 fzForm）后 stale=true——重签后回 false", () => {
    seedMaterial();
    const s = useMaterialStore();
    s.reload();
    s.issueSub({ ...OUT }, "11".repeat(64), "22".repeat(32));
    expect(s.isStale()).toBe(false);
    // 换登记（表单四元变化 → 材料指纹变）
    localStorage.setItem("fzForm", JSON.stringify({ ...FORM, sn: "FZ-SN-2" }));
    expect(s.isStale()).toBe(true);
    s.issueSub({ ...OUT }, "55".repeat(64), "66".repeat(32));
    expect(s.isStale()).toBe(false);
  });

  it("登出清扫（sweepAll）：身份域+会话域全清，store 状态归零（键名四表兼容）", () => {
    seedMaterial();
    localStorage.setItem("fzUserKeypair", '{"v":3}');
    localStorage.setItem("fzIdTag", "tag");
    const s = useMaterialStore();
    s.reload();
    s.issueSub({ ...OUT }, "11".repeat(64), "22".repeat(32));
    sessionStorage.setItem("fzSessionSk", "77".repeat(32));
    const had = s.sweepAll();
    expect(had).toBe(true);
    for (const k of ["fzSub", "fzSubBound", "fzCred", "fzForm", "fzUserKeypair", "fzIdTag"]) {
      expect(localStorage.getItem(k)).toBeNull();
    }
    expect(sessionStorage.getItem("fzSubSk")).toBeNull();
    expect(sessionStorage.getItem("fzSessionSk")).toBeNull();
    expect(s.sub).toBeNull();
    expect(s.hasSubSk).toBe(false);
  });

  it("账户切换清扫（sweepAccount）：同名短路、异名清扫", () => {
    seedMaterial();
    const s = useMaterialStore();
    s.reload();
    s.issueSub({ ...OUT }, "11".repeat(64), "22".repeat(32));
    expect(s.sweepAccount("alice", "alice")).toBe(false);
    expect(localStorage.getItem("fzSub")).not.toBeNull();
    expect(s.sweepAccount("alice", "bob")).toBe(true);
    expect(localStorage.getItem("fzSub")).toBeNull();
    expect(s.sub).toBeNull();
  });

  it("档案镜像（档案积累批）：reload 读 fzLogbook，登出清扫归零", () => {
    seedMaterial();
    localStorage.setItem("fzLogbook", JSON.stringify([{
      authId: 7, caseId: "c1", receiptCode: "RC-1", tStart: 1, tEnd: 2,
      classId: 1, altMax: 120, sealedAt: 3, nSamples: 128, checkpointCount: 2,
      breachFlag: false, tripCaseIds: { 0: "t0" }, trailVerdicts: {}, createdAt: 4,
    }]));
    const s = useMaterialStore();
    s.reload();
    expect(s.logbook).toHaveLength(1);
    expect(s.logbook[0].authId).toBe(7);
    const had = s.sweepAll();
    expect(had).toBe(true);
    expect(localStorage.getItem("fzLogbook")).toBeNull();
    expect(s.logbook).toEqual([]);
  });
});
