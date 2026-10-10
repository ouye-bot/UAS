// @vitest-environment jsdom
/** 激活面收紧批③（2026-10-11）：一次性激活码输入面（双因子档位）挂载测试。
 * 档位语义=demo 缺省关（输入面不渲染——浏览器 e2e 冻结面零变化）；
 * production/显式 env 档由服务端 activation_code_required 判词驱动渲染。
 * fetch 打桩（契约形状=accounts/router prelogin 真响应）。 */
import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import LoginView from "../../src/views/LoginView.vue";

function jsonResponse(status: number, payload: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  } as Response;
}

function stubPrelogin(payload: unknown) {
  return vi.fn(async (_url: string, _init?: RequestInit) => {
    if (_url.includes("/auth/prelogin/")) {
      return jsonResponse(200, { code: "ok", message: "", data: payload });
    }
    return jsonResponse(404, { code: "not_found", message: "", data: null });
  });
}

async function mountAndLogin(pre: unknown) {
  const fetchStub = stubPrelogin(pre);
  vi.stubGlobal("fetch", fetchStub);
  const w = mount(LoginView);
  await flushPromises();
  const inputs = w.findAll("input");
  await inputs[0].setValue("auditor_t"); // 用户名
  await inputs[1].setValue("Init-Pass-1"); // 密码
  await w.findAll("button.btn").find((b) => b.text().includes("登录"))!.trigger("click");
  await flushPromises();
  return w;
}

beforeEach(() => {
  localStorage.clear();
  // jsdom 缺口打桩（gov-admin 同款）：ParticleField canvas 探测+matchMedia
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
  window.matchMedia = ((q: string) => ({
    matches: false,
    media: q,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("LoginView 一次性激活码输入面（双因子档位）", () => {
  it("demo 档（require_code 缺省 false）：登录面无激活码输入框（冻结面零变化）", () => {
    const fetchStub = stubPrelogin({ mode: "activation", kdf_salt_hex: "aa".repeat(16), verifier: "v1", rounds: 4096 });
    vi.stubGlobal("fetch", fetchStub);
    const w = mount(LoginView);
    expect(w.find('[data-test="activation-code"]').exists()).toBe(false);
  });

  it("服务端 activation_code_required 判词：渲染激活码输入框+人话判词", async () => {
    const w = await mountAndLogin({
      mode: "activation",
      kdf_salt_hex: "aa".repeat(16),
      verifier: "v1",
      rounds: 4096,
      require_code: true,
    });
    expect(w.find('[data-test="activation-code"]').exists()).toBe(true);
    expect(w.text()).toContain("一次性激活码");
    expect(w.text()).toContain("请向机构管理员索取");
  });
});
