// 浏览器内 TRAIL 验证 Worker 单测（钥换代根治批）：引擎公钥=运行时参数——
// ① 现役钥拉取失败（网络/HTTP/信封非法）= fail-closed 拒验（不降级、验证器
//    不启动）；② 拉取成功=以 FZ_ENGINE_PUB_HEX env 注入验证器。
// Worker 模块顶层 self.onmessage 挂载——node 环境下先桩 self 再动态导入
// （模块只评估一次：self 用持久桩对象，onmessage 挂上后全用例共享）；
// WASI/WebAssembly 全桩（本批只测编排面，不跑真电路）。
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const ENGINE_PUB = "ab".repeat(64);

interface Posted { type: string; line?: string; rc?: number; ok?: boolean; error?: string }

const posted: Posted[] = [];
let wasiCalls: { argv: string[]; env: string[] }[] = [];

vi.mock("@bjorn3/browser_wasi_shim", () => {
  class FakeWASI {
    argv: string[];
    env: string[];
    constructor(argv: string[], env: string[], _fds: unknown) {
      this.argv = argv;
      this.env = env;
      wasiCalls.push({ argv, env });
    }
    start(_t: unknown): number {
      return 0;
    }
    wasiImport = {};
  }
  return {
    WASI: FakeWASI,
    File: class {},
    OpenFile: class {},
    ConsoleStdout: { lineBuffered: (_f: unknown) => ({}) },
    PreopenDirectory: class {},
  };
});

const selfObj: { postMessage: (m: Posted) => void; onmessage?: (ev: { data: unknown }) => Promise<void> } = {
  postMessage: (m: Posted) => posted.push(m),
};

const RES = (body: unknown, status = 200) =>
  ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(body)).buffer,
  }) as unknown as Response;

function req(overrides: Partial<Record<string, string>> = {}): Record<string, string> {
  return {
    wasmUrl: "http://api/verify/dist/zkc.wasm",
    enginePubUrl: "http://api/authz/engine/pub",
    specUrl: "http://api/verify/dist/trail_canonical_spec.json",
    instancesUrl: "http://bridge/case/instances.json",
    proofUrl: "http://bridge/case/proof.bin",
    vpUrl: "http://bridge/case/verifier_param.bin",
    expectedUrl: "http://bridge/case/expected.json",
    ...overrides,
  };
}

beforeAll(async () => {
  vi.stubGlobal("self", selfObj);
  vi.stubGlobal("WebAssembly", {
    compile: async () => ({}),
    instantiate: async () => ({ exports: {} }),
  });
  await import("../../src/lib/wasmVerifyWorker");
});

beforeEach(() => {
  posted.length = 0;
  wasiCalls = [];
  vi.stubGlobal("self", selfObj);
  vi.stubGlobal("WebAssembly", {
    compile: async () => ({}),
    instantiate: async () => ({ exports: {} }),
  });
});

describe("wasmVerifyWorker 引擎公钥运行时参数（fail-closed 拒验面）", () => {
  it("后端不可达（fetch 抛错）= fail-closed 拒验：验证器不启动，done.ok=false 带人话原因", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("network down")));
    await selfObj.onmessage!({ data: req() });
    const done = posted.find((m) => m.type === "done")!;
    expect(done, "必须以 done 收束").toBeTruthy();
    expect(done.ok).toBe(false);
    expect(done.error).toContain("fail-closed 拒验");
    expect(wasiCalls, "验证器绝不能启动（不降级）").toHaveLength(0);
  });

  it("HTTP 500 / 信封非法 / 公钥非 128hex = 同款拒验", async () => {
    const bad: Response[] = [
      RES({}, 500),
      RES({ ok: true, data: {} }),
      RES({ ok: false, data: { engine_pub_hex: ENGINE_PUB } }),
      RES({ ok: true, data: { engine_pub_hex: "zz".repeat(64) } }),
    ];
    for (const r of bad) {
      posted.length = 0;
      wasiCalls = [];
      vi.stubGlobal("fetch", vi.fn().mockImplementation((u: string | URL) =>
        String(u).includes("/authz/engine/pub") ? Promise.resolve(r) : Promise.reject(new Error("not expected")),
      ));
      await selfObj.onmessage!({ data: req() });
      const done = posted.find((m) => m.type === "done")!;
      expect(done?.ok, `信封 ${r.status < 300 ? "body 非法" : "HTTP " + r.status} 必须拒`).toBe(false);
      expect(done?.error).toContain("fail-closed 拒验");
      expect(wasiCalls).toHaveLength(0);
    }
  });

  it("现役钥就绪 = FZ_ENGINE_PUB_HEX env 注入验证器 + 材料五件照常下载 + 正常收束", async () => {
    const hit = vi.fn();
    vi.stubGlobal("fetch", vi.fn().mockImplementation((u: string | URL) => {
      hit(String(u));
      if (String(u).includes("/authz/engine/pub")) {
        return Promise.resolve(RES({ ok: true, data: { engine_pub_hex: ENGINE_PUB } }));
      }
      return Promise.resolve(RES({})); // 其余材料件（json/二进制桩同形）
    }));
    await selfObj.onmessage!({ data: req() });
    const done = posted.find((m) => m.type === "done")!;
    expect(done?.ok).toBe(true);
    expect(hit).toHaveBeenCalledWith("http://api/authz/engine/pub");
    expect(wasiCalls).toHaveLength(1);
    const env = wasiCalls[0].env.join("\n");
    expect(env).toContain(`FZ_ENGINE_PUB_HEX=${ENGINE_PUB}`);
    expect(env).toContain("FZ_ZK_ALLOW_TRAIL=1");
    expect(wasiCalls[0].argv).toContain("verify-instances");
  });
});
