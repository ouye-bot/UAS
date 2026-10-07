/** SN 单源 lib 测试（SN 绑定根治 2026-10-07）：getDeviceSerial 三态钉定。
 *
 * - 桥可达：/engine_pub.device_serial 读数返回+会话内缓存（第二次调用不重发）
 * - 桥不可达：空串（诚实值——调用方提示检查桥接，不编造不回落）
 * - 响应缺字段：同样空串（形态异常不猜）
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEVICE_SERIAL_UNAVAILABLE,
  cachedDeviceSerial,
  getDeviceSerial,
  resetDeviceSerialCache,
} from "../../src/lib/device";

// node 环境无 DOM storage——最小内存替身（bridgeBase() 读 fzBridgeBase 用）
class MemStorage {
  private m = new Map<string, string>();
  getItem(k: string): string | null { return this.m.has(k) ? this.m.get(k)! : null; }
  setItem(k: string, v: string): void { this.m.set(k, String(v)); }
  removeItem(k: string): void { this.m.delete(k); }
  clear(): void { this.m.clear(); }
}

beforeEach(() => {
  (globalThis as Record<string, unknown>).localStorage = new MemStorage();
  resetDeviceSerialCache();
});

function stubFetchOnce(payload: unknown, status = 200): ReturnType<typeof vi.fn> {
  const f = vi.fn().mockResolvedValueOnce({
    ok: status < 400,
    status,
    statusText: status === 200 ? "OK" : "Service Unavailable",
    json: async () => payload,
  });
  vi.stubGlobal("fetch", f);
  return f;
}

describe("SN 单源 getDeviceSerial", () => {
  it("桥可达：读数返回且会话内缓存（第二次调用零请求）", async () => {
    const f = stubFetchOnce({ engine_pub_hex: "ab".repeat(32), device_serial: "FZ-SN-DEV-01" });
    expect(await getDeviceSerial()).toBe("FZ-SN-DEV-01");
    expect(await getDeviceSerial()).toBe("FZ-SN-DEV-01");
    expect(cachedDeviceSerial()).toBe("FZ-SN-DEV-01");
    expect(f).toHaveBeenCalledTimes(1); // 缓存生效——桥进程生命周期读数不变
  });

  it("桥不可达：空串+缓存（不编造不回落自由文本）", async () => {
    const f = vi.fn().mockRejectedValueOnce(new TypeError("Failed to fetch"));
    vi.stubGlobal("fetch", f);
    expect(await getDeviceSerial()).toBe("");
    expect(await getDeviceSerial()).toBe(""); // 空串同样缓存——不反复打不可达的桥
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("响应缺 device_serial 字段：空串（形态异常不猜）", async () => {
    stubFetchOnce({ engine_pub_hex: "ab".repeat(32) });
    expect(await getDeviceSerial()).toBe("");
    expect(cachedDeviceSerial()).toBe("");
  });

  it("统一人话文案在位（注册/申请两处同一句话）", () => {
    expect(DEVICE_SERIAL_UNAVAILABLE).toContain("无法读取本机设备序列号");
    expect(DEVICE_SERIAL_UNAVAILABLE).toContain("地面站桥接");
  });
});
