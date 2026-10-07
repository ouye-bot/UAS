/** 会话/飞行 store 单测（Pinia 收敛批）：跨标签旗标对账/登出清扫/七态状态机。
 * fzSession 旗标是跨标签单一事实源——store 不私藏状态，refresh 随时可对账。 */
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

import { useSessionStore } from "../../src/stores/session";
import { useFlightStore } from "../../src/stores/flight";

describe("session store", () => {
  it("跨标签语义：旗标被（另一标签）直写后 refresh() 状态跟随——store 不私藏", () => {
    const s = useSessionStore();
    expect(s.loggedIn).toBe(false);
    // 模拟另一标签登录写旗标
    localStorage.setItem("fzSession", JSON.stringify({ username: "auditor", role: "auditor" }));
    s.refresh();
    expect(s.loggedIn).toBe(true);
    expect(s.username).toBe("auditor");
    expect(s.role).toBe("auditor");
  });

  it("clearLocal：焚会话旗标+身份域清扫（登出即清扫语义），loggedIn 归 false", () => {
    localStorage.setItem("fzSession", JSON.stringify({ username: "p", role: "pilot" }));
    localStorage.setItem("fzCred", JSON.stringify({ master_cred_hash_hex: "aa" }));
    localStorage.setItem("fzForm", JSON.stringify({ id_number: "x" }));
    const s = useSessionStore();
    s.refresh();
    expect(s.loggedIn).toBe(true);
    const swept = s.clearLocal();
    expect(swept).toBe(true);
    expect(localStorage.getItem("fzSession")).toBeNull();
    expect(localStorage.getItem("fzCred")).toBeNull();
    expect(localStorage.getItem("fzForm")).toBeNull();
    expect(s.loggedIn).toBe(false);
    expect(s.role).toBeNull();
  });
});

describe("flight store（七态状态机单源=lib/flight）", () => {
  it("全生命周期推进：pickup→arm→record_ready→recording→window_full→sealed", () => {
    const f = useFlightStore();
    expect(f.stage).toBe("pickup");
    f.hasToken = true;
    expect(f.stage).toBe("arm");
    f.armed = true;
    expect(f.stage).toBe("record_ready");
    f.chainStarted = true;
    expect(f.stage).toBe("recording");
    f.sampleCount = 128;
    expect(f.stage).toBe("window_full");
    f.sealed = true;
    expect(f.stage).toBe("sealed");
    // 步进器=四格（与 e2e 步进器语义同源——label/done 由 lib 单源派生）
    expect(f.stepper).toHaveLength(4);
    expect(f.stepper.every((x) => x.done)).toBe(true);
  });

  it("reset：新架次复位归 pickup（链上数据语义不在此层）", () => {
    const f = useFlightStore();
    f.hasToken = true;
    f.armed = true;
    f.chainStarted = true;
    f.sampleCount = 30;
    f.reset();
    expect(f.stage).toBe("pickup");
    expect(f.sampleCount).toBe(0);
  });
});
