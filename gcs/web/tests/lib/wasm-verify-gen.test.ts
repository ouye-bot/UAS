// 分发面现役代查询参（gen）单测（2026-10-15 缓存不可达根修补刀②·前端兜底）。
// 病根：StaticFiles 缺省无 Cache-Control ⟹ 浏览器启发式缓存让旧代 zkc.wasm
// 在存量浏览器长期新鲜（重分发不可达——手测实弹：页面照旧下载 9/28 旧件
// 2.7MB）。服务端 Cache-Control: no-cache（main.py /verify 整域中间件）为第一
// 兜底；本函数从 /verify/api/checks 派生 gen=<sha256 前 12 hex> 拼进分发面
// URL——缓存键随代变必回源，为第二兜底。fail-closed：checks 不可达/信封非法
// =null=退回无参 URL（绝不构造假 gen 冒充换代）。
import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchDistGen, withGen } from "../../src/lib/wasmVerify";

const SHA = "aebe747229d94130df42509eba78da78236a00b47fa2827b0b24c41f9edee2d2";

function checksResponse(artifacts: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => ({ code: "ok", data: { artifacts } }),
  } as unknown as Response;
}

afterEach(() => vi.unstubAllGlobals());

describe("分发面现役代查询参（gen）——缓存键随代变", () => {
  it("checks 信封正常 → gen=sha256 前 12 hex", async () => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      checksResponse([
        { name: "zkc-linux-amd64", sha256: "ab".repeat(32) },
        { name: "zkc.wasm", sha256: SHA },
      ])));
    await expect(fetchDistGen("http://api/verify/api/checks"))
      .resolves.toBe(`gen=${SHA.slice(0, 12)}`);
  });

  it("fail-closed 五态（非 200/信封坏/缺 wasm 件/非 64hex/网络异常）→ null", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => checksResponse([], 503)));
    await expect(fetchDistGen("http://api/verify/api/checks")).resolves.toBeNull();
    vi.stubGlobal("fetch", vi.fn(async () => checksResponse({ unexpected: true })));
    await expect(fetchDistGen("http://api/verify/api/checks")).resolves.toBeNull();
    vi.stubGlobal("fetch", vi.fn(async () =>
      checksResponse([{ name: "zkc.wasm", sha256: undefined }])));
    await expect(fetchDistGen("http://api/verify/api/checks")).resolves.toBeNull();
    vi.stubGlobal("fetch", vi.fn(async () =>
      checksResponse([{ name: "zkc.wasm", sha256: "ZZ-not-hex" }])));
    await expect(fetchDistGen("http://api/verify/api/checks")).resolves.toBeNull();
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("network down");
    }));
    await expect(fetchDistGen("http://api/verify/api/checks")).resolves.toBeNull();
  });

  it("withGen：gen 在位拼接查询串；null 退回原 URL（绝不拼 ?gen=null）", () => {
    expect(withGen("http://api/verify/dist/zkc.wasm", "gen=aebe747229d9"))
      .toBe("http://api/verify/dist/zkc.wasm?gen=aebe747229d9");
    expect(withGen("http://api/verify/dist/trail_canonical_spec.json", null))
      .toBe("http://api/verify/dist/trail_canonical_spec.json");
  });
});
