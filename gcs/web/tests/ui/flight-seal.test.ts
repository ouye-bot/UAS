// @vitest-environment jsdom
/** 封链失败路径不 disarm（缺陷 A2 根修批 2026-10-17，先红后绿）。
 *
 * 病征（手测实弹）：endFlight 在 anchor 失败时仍无条件 /sitl/disarm + 清采样
 * ⟹「已停桨但链未封」僵尸态——链 active 永真、重试封链 0 新样本、UI 承诺
 * 「可重试续锚」实为假。钉定新契约：
 * ①锚定成功 ⟹ /sitl/disarm 恰一次 + 封链完成卡片（飞行记录单）；
 * ②锚定失败（ok:false）⟹ 不发 /sitl/disarm（飞行保持活体）+ 失败判词在场
 *   + 重试封链真实可达（再次点击仍调 /telemetry/anchor，成功后补 disarm）。
 * 取件链路走真 crypto（tests/fixtures/token_fixture.json），网络面 fetch 路由
 * 桩+重型 WebGL 子件桩。 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import fixture from "../fixtures/token_fixture.json";

vi.mock("../../src/components/FlightGlobe.vue", () => ({ default: { template: "<div/>" } }));
vi.mock("../../src/components/FlightGauges.vue", () => ({ default: { template: "<div/>" } }));
import FlightView from "../../src/views/FlightView.vue";

type Res = { ok: boolean; status: number; json?: () => Promise<unknown> };
let anchorResponse: Record<string, unknown>;
const calls: string[] = [];
const fetchMock = vi.fn((_url: string | URL | RequestInfo, _init?: RequestInit) =>
  Promise.resolve({} as Res),
);

function route(): Res {
  const [url, init] = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
  const path = String(url ?? "");
  if (init?.method === "POST") calls.push(path);
  const json = (b: unknown, status = 200): Res => ({ ok: status < 300, status, json: async () => b });
  if (path.includes("/authz/receipt/")) return json({ status: "ready", token_cipher_hex: fixture.token_cipher_hex });
  if (path.includes("/engine_pub")) return json({ engine_pub_hex: fixture.engine_pub_hex });
  if (path.includes("/link_status")) return json({ mode: "fake", conn: null });
  if (path.includes("/arm/status")) return json({ used: false, can_rearm: false, remaining: null, sorties: null, local_sorties: null });
  if (path.includes("/telemetry/state")) return json({ chain_active: false });
  if (path.includes("/telemetry/start"))
    return json({ ok: true, genesis_head_hex: "ab".repeat(32), device_pub_hex: fixture.engine_pub_hex, fence_state_hex: "01007800", checkpoint_seq_base: 0 });
  if (path.includes("/telemetry/anchor")) return json(anchorResponse);
  if (path.includes("/sitl/disarm")) return json({ ok: true });
  if (path.includes("/arm")) return json({ ok: true, auth_id: 7, alt_max: 120, fence_state_hex: "01007800" });
  return json({});
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  localStorage.setItem("fzLastReceipt", "RC-SEAL");
  sessionStorage.setItem("fzSessionSk", fixture.session_sk_hex);
  anchorResponse = { ok: true, anchored: 2, anchored_seq: 2 };
  calls.length = 0;
  fetchMock.mockImplementation((_u, _i) => Promise.resolve(route()));
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

async function mountArmedAndRecording(): Promise<ReturnType<typeof mount>> {
  const w = mount(FlightView, { attachTo: document.body });
  await flushPromises();
  const pickupBtn = w.findAll("button").find((b) => b.text().includes("领取令牌"))!;
  expect(pickupBtn, "取件按钮必须在场").toBeTruthy();
  await pickupBtn.trigger("click");
  await flushPromises();
  const armBtn = w.findAll("button").find((b) => b.text().includes("解锁起飞"))!;
  expect(armBtn, "解锁按钮必须在场").toBeTruthy();
  await armBtn.trigger("click");
  await flushPromises();
  const recBtn = w.findAll("button").find((b) => b.text() === "开始记录")!;
  expect(recBtn, "开始记录按钮必须在场").toBeTruthy();
  await recBtn.trigger("click");
  await flushPromises();
  return w;
}

async function clickSeal(w: ReturnType<typeof mount>): Promise<void> {
  const sealBtn = w.findAll("button").find((b) => b.text().includes("结束飞行并封链"))!;
  expect(sealBtn, "封链按钮必须在场").toBeTruthy();
  await sealBtn.trigger("click"); // 一次点=弹确认
  await flushPromises();
  const confirmBtn = w.findAll("button").find((b) => b.text() === "确认封链")!;
  expect(confirmBtn, "封链确认按钮必须在场").toBeTruthy();
  await confirmBtn.trigger("click");
  await flushPromises();
}

describe("封链失败路径不 disarm（缺陷 A2）", () => {
  it("锚定成功：/sitl/disarm 恰一次 + 封链完成卡片（飞行记录单）", async () => {
    const w = await mountArmedAndRecording();
    await clickSeal(w);
    const disarms = calls.filter((c) => c.includes("/sitl/disarm"));
    expect(disarms.length, "成功封链=停桨恰一次").toBe(1);
    expect(w.text()).toContain("飞行记录单");
    expect(w.text()).toContain("封链完成");
    w.unmount();
  });

  it("锚定失败（ok:false）：不发 /sitl/disarm（飞行保持活体）+ 失败判词在场 + 重试真实可达", async () => {
    const w = await mountArmedAndRecording();
    anchorResponse = { ok: false, code: "anchor_failed", anchored_seq: 0 };
    await clickSeal(w);
    expect(calls.filter((c) => c.includes("/sitl/disarm")).length,
      "锚定失败绝不 disarm——停桨+未封链=僵尸态（病征本体）").toBe(0);
    expect(w.text()).toContain("封链未完成");
    expect(w.text()).toContain("飞行仍在进行");
    // 重试封链=第二次 /telemetry/anchor 调用（真实可达，不被按钮面锁死）
    const anchorsAfterFirst = calls.filter((c) => c.includes("/telemetry/anchor")).length;
    expect(anchorsAfterFirst).toBe(1);
    anchorResponse = { ok: true, anchored: 2, anchored_seq: 2 };
    await clickSeal(w);
    expect(calls.filter((c) => c.includes("/telemetry/anchor")).length,
      "重试封链再次调用锚定面").toBe(2);
    expect(calls.filter((c) => c.includes("/sitl/disarm")).length,
      "重试成功后才补停桨（恰一次）").toBe(1);
    expect(w.text()).toContain("封链完成");
    w.unmount();
  });
});
