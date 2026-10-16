// @vitest-environment jsdom
/** 令牌防篡改自检（D1 负例演示）结果呈现面（2026-10-15 根修批先红后绿）。
 *
 * 病征（队长手测实弹报障）：自检按钮与真实解锁共用 armResult 状态面——
 * ①负例拒绝按真实失败呈现（红字 bad_signature，与钥分脑等真故障不可辨）；
 * ②拒绝结果覆盖 armResult ⟹ 闸门横幅 ARMED→DISARMED 翻转（飞控实际仍在
 * 解锁态）——自检通过与否在界面上不可辨=演示失效。本组测试钉定新契约：
 * ①自检被拒（bad_signature）=「自检通过」正向判词（data-test=tamper-selfcheck），
 *   真实解锁态（横幅 ARMED/授权信息）零覆盖；
 * ②自检被接受=「自检失败」红判词（闸门放行篡改令牌=最重失败，必须显红）；
 * ③真实解锁拒绝路径（非自检按钮）呈现原样（既有文本零变化——e2e 冻结面）。
 * 取件链路走真 crypto（tests/fixtures/token_fixture.json——ECIES 解密+SM2
 * 验签全真），仅网络面 fetch 路由桩+重型 WebGL 子件桩。 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import fixture from "../fixtures/token_fixture.json";

vi.mock("../../src/components/FlightGlobe.vue", () => ({ default: { template: "<div/>" } }));
vi.mock("../../src/components/FlightGauges.vue", () => ({ default: { template: "<div/>" } }));
import FlightView from "../../src/views/FlightView.vue";

const BRIDGE = "http://127.0.0.1:8100";
const API = "http://127.0.0.1:8000";

type Res = { ok: boolean; status: number; json?: () => Promise<unknown> };
let armResponse: Record<string, unknown> = { ok: true, auth_id: 7, alt_max: 120, fence_state_hex: "01007800" };
const fetchMock = vi.fn((_url: string | URL | RequestInfo, _init?: RequestInit) => Promise.resolve({} as Res));

function route(): Res {
  const url = String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1][0] ?? "");
  const json = (b: unknown, status = 200): Res => ({ ok: status < 300, status, json: async () => b });
  if (url.includes("/authz/receipt/")) return json({ status: "ready", token_cipher_hex: fixture.token_cipher_hex });
  if (url.includes("/engine_pub")) return json({ engine_pub_hex: fixture.engine_pub_hex });
  if (url.includes("/link_status")) return json({ mode: "fake", conn: null });
  if (url.includes("/arm/status")) return json({ used: false, can_rearm: false, remaining: null, sorties: null, local_sorties: null });
  if (url.includes("/telemetry/state")) return json({ chain_active: false });
  if (url.includes("/arm")) return json(armResponse);
  return json({});
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  localStorage.setItem("fzLastReceipt", "RC-FIX");
  sessionStorage.setItem("fzSessionSk", fixture.session_sk_hex);
  armResponse = { ok: true, auth_id: 7, alt_max: 120, fence_state_hex: "01007800" };
  fetchMock.mockImplementation((_u, _i) => {
    const r = route();
    return Promise.resolve(r);
  });
  vi.stubGlobal("fetch", fetchMock);
  // jsdom 无 2d context——FlightView 高度/航迹曲线画布桩（纯呈现面，非被测对象）
  const noop = () => {};
  (HTMLCanvasElement.prototype as unknown as { getContext: () => unknown }).getContext = () =>
    new Proxy({}, { get: () => noop, set: () => true });
});

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
  sessionStorage.clear();
});

async function mountPickedAndArmed(): Promise<ReturnType<typeof mount>> {
  const w = mount(FlightView, { attachTo: document.body });
  await flushPromises();
  const pickupBtn = w.findAll("button").find((b) => b.text().includes("领取令牌"))!;
  expect(pickupBtn, "取件按钮必须在场").toBeTruthy();
  await pickupBtn.trigger("click");
  await flushPromises();
  expect(w.text(), "取件后令牌信息区应显示授权编号").toContain("7");
  const armBtn = w.findAll("button").find((b) => b.text().includes("解锁起飞"))!;
  await armBtn.trigger("click");
  await flushPromises();
  return w;
}

describe("令牌防篡改自检（D1 负例）结果呈现", () => {
  it("自检被拒（bad_signature）=「自检通过」正向判词；真实解锁态零覆盖（横幅仍 ARMED）", async () => {
    const w = await mountPickedAndArmed();
    expect(w.text()).toContain("ARMED");
    armResponse = { ok: false, code: "bad_signature", message: "令牌签名验证失败（非 engine 签发或篡改）" };
    const btn = w.findAll("button").find((b) => b.text().includes("令牌防篡改自检"))!;
    await btn.trigger("click");
    await flushPromises();
    const verdict = w.find('[data-test="tamper-selfcheck"]');
    expect(verdict.exists(), "自检判词块必须在场（负例通过=正向呈现，非红字失败）").toBe(true);
    expect(verdict.text()).toContain("自检通过");
    // 真实解锁态零覆盖：横幅仍 ARMED+授权编号仍在
    expect(w.text(), "自检不得覆盖真实解锁态（横幅仍 ARMED）").toContain("ARMED");
    expect(w.text()).toContain("已解锁");
  });

  it("自检被接受（闸门放行篡改令牌）=「自检失败」红判词——最重失败必须显红", async () => {
    const w = await mountPickedAndArmed();
    armResponse = { ok: true, auth_id: 7, alt_max: 121 };
    const btn = w.findAll("button").find((b) => b.text().includes("令牌防篡改自检"))!;
    await btn.trigger("click");
    await flushPromises();
    const verdict = w.find('[data-test="tamper-selfcheck"]');
    expect(verdict.exists()).toBe(true);
    expect(verdict.text()).toContain("自检失败");
    expect(verdict.text()).toContain("被篡改的令牌被闸门接受");
  });

  it("真实解锁拒绝（非自检按钮）呈现原样——既有红字判词零变化（e2e 冻结面）", async () => {
    const w = await mountPickedAndArmed();
    armResponse = { ok: false, code: "bad_signature", message: "令牌签名验证失败（非 engine 签发或篡改）" };
    const armBtn = w.findAll("button").find((b) => b.text().includes("重新解锁") || b.text().includes("解锁起飞"))!;
    await armBtn.trigger("click");
    await flushPromises();
    expect(w.text()).toContain("令牌签名核验未通过（非引擎签发或已被篡改）");
    expect(w.find('[data-test="tamper-selfcheck"]').exists()).toBe(false);
  });
});
