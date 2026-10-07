// @vitest-environment jsdom
/** 「我的合规档案」出示三动作 + 链上对账接线测试（L3 接线批）。
 *
 * e2e 夹具不播种 fzLogbook ⟹ 档案卡在浏览器回归里恒空——三按钮与对账徽章
 * 永不渲染。此处挂载 ChainView 补位（localStorage 注入档案行 + fetch 路由
 * mock，同 tests/ui/fz-confluence.test.ts 纪律）：
 * - 出示包：桥 bundle 端点 URL 形态+blob 下载+「✓ 已生成」瞬时态+expected
 *   缺失的诚实 title（HEAD 探测）；
 * - 浏览器内验证：无 TRAIL 窗的行**隐藏**（AUTH 案卷不适用 TRAIL 验证器
 *   ——功能不适用≠不可用）；有窗行以 trip 案卷 URL 调 runWasmVerify；
 * - 对账徽章三态：一致（绿）/不一致（红·点名差异）/链不可达（灰·重试），
 *   结论会话内缓存（打印证明页复用对账不重复拉）。 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";

vi.mock("../../src/lib/wasmVerify", () => ({ runWasmVerify: vi.fn() }));
import { runWasmVerify } from "../../src/lib/wasmVerify";
import ChainView from "../../src/views/ChainView.vue";

const API = "http://api.test";
const BRIDGE = "http://bridge.test";

const TRAIL_ROW = {
  authId: 7, caseId: "aabbccdd00112233", receiptCode: "RC-1",
  tStart: 1790000000, tEnd: 1790007200, classId: 1, altMax: 120,
  sealedAt: 1790003600, nSamples: 260, checkpointCount: 4, breachFlag: false,
  tripCaseIds: { 0: "tripcase07w0" }, trailVerdicts: { 0: { verdict: "OK", sm3: "ff".repeat(32) } },
  createdAt: 1790000500,
};
const AUTH_ROW = {
  ...TRAIL_ROW, authId: 8, caseId: "1122334455667788", receiptCode: "RC-2",
  tripCaseIds: {}, trailVerdicts: {}, createdAt: 1790100500,
};

function recordDetail(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    auth_id: 7, status: "approved", class_id: 1, alt_max_m: 120,
    t_start: 1790000000, t_end: 1790007200, created_at: null,
    proof_digest_hex: "ab".repeat(32), tx_hash: "0xtxhash07",
    verify_tail: null, verify_s: null, expected: null, archived: false,
    chain: { proof_digest_hex: "ab".repeat(32), token_hash_hex: "cd".repeat(32), match: true },
    ...over,
  };
}

type Res = { ok: boolean; status: number; json?: () => Promise<unknown>; blob?: () => Promise<Blob> };
const fetchMock = vi.fn((_url: string | URL | RequestInfo, _init?: RequestInit) => Promise.resolve({} as Res));

function route(responses: { match: (url: string, init?: RequestInit) => boolean; res: Res }[]): void {
  fetchMock.mockImplementation(((url: string | URL | RequestInfo, init?: RequestInit) => {
    const u = String(url);
    for (const r of responses) if (r.match(u, init)) return Promise.resolve(r.res);
    return Promise.resolve({ ok: false, status: 404, json: async () => ({}) } as Res);
  }) as typeof fetch);
}

function panelRes(): Res {
  return { ok: true, status: 200, json: async () => ({ ok: true, data: { mode: "fake", chain: null, records: [], warrants: [] } }) };
}

async function mountView(): Promise<ReturnType<typeof mount>> {
  const w = mount(ChainView);
  await flushPromises();
  return w;
}

beforeEach(() => {
  setActivePinia(createPinia());
  localStorage.clear();
  localStorage.setItem("fzApiBase", API);
  localStorage.setItem("fzBridgeBase", BRIDGE);
  localStorage.setItem("fzLogbook", JSON.stringify([TRAIL_ROW, AUTH_ROW]));
  fetchMock.mockClear(); // 调用计数按用例计（mock 实现由各用例 route() 重设）
  vi.stubGlobal("fetch", fetchMock);
  (URL as unknown as { createObjectURL: unknown }).createObjectURL = vi.fn(() => "blob:mock");
  (URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = vi.fn();
  window.print = vi.fn();
  vi.mocked(runWasmVerify).mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("出示三动作接线（档案行展开区）", () => {
  it("出示包：按钮启用→以桥 bundle 端点 URL fetch+blob 下载→「✓ 已生成」瞬时态；expected 缺失时 title 出补齐提示（不阻塞）", async () => {
    route([
      { match: (u) => u === `${API}/chain/panel`, res: panelRes() },
      { match: (u) => u === `${BRIDGE}/prove/case/aabbccdd00112233/expected.json`, res: { ok: false, status: 404 } as Res },
      { match: (u) => u === `${BRIDGE}/prove/case/aabbccdd00112233/bundle`, res: { ok: true, status: 200, blob: async () => new Blob(["zip-bytes"]) } as Res },
    ]);
    const w = await mountView();
    await w.findAll(".rec")[0].find(".rowbtn").trigger("click"); // 展开档案行
    await flushPromises(); // expected 探测（GET）落定

    // expected 探测（GET 探状态码——桥对 HEAD 回 405）已落定：404 ⟹ title 出补齐提示
    const btn = w.findAll("button").find((b) => b.text() === "出示授权档案")!;
    expect(btn, "三按钮接线后启用在位（不再 disabled+下一批接入）").toBeTruthy();
    expect(btn.attributes("disabled"), "caseId 在场——可生成").toBeUndefined();
    expect(btn.attributes("title"), "expected 缺失（HEAD 404）→ title 补齐提示").toContain("先补齐期望绑定（见下载区）");

    await btn.trigger("click");
    await flushPromises();
    const bundleCalls = fetchMock.mock.calls.filter(([u]) => String(u) === `${BRIDGE}/prove/case/aabbccdd00112233/bundle`);
    expect(bundleCalls, "前端实际调用的 URL=桥 GET /prove/case/{caseId}/bundle").toHaveLength(1);
    expect(URL.createObjectURL, "blob 下载路径走对象 URL").toHaveBeenCalled();
    expect(w.findAll("button").some((b) => b.text() === "✓ 已生成"), "成功瞬时态").toBe(true);
  });

  it("浏览器内验证：无 TRAIL 窗的档案行隐藏按钮（不适用≠禁用）；有窗行以 trip 案卷 URL 调 zkc.wasm 并标注约 105s", async () => {
    route([{ match: (u) => u === `${API}/chain/panel`, res: panelRes() }]);
    vi.mocked(runWasmVerify).mockResolvedValue({ rc: 0, ms: 105123, ok: true });
    const w = await mountView();

    await w.findAll(".rec")[1].find(".rowbtn").trigger("click"); // AUTH-only 行
    await flushPromises();
    expect(w.findAll("button").some((b) => b.text() === "浏览器内验证"), "无 TRAIL 判决的行隐藏该按钮").toBe(false);

    await w.findAll(".rec")[0].find(".rowbtn").trigger("click"); // TRAIL 行（窗口 0）
    await flushPromises();
    const vbtn = w.findAll("button").find((b) => b.text() === "浏览器内验证")!;
    expect(vbtn, "TRAIL 行按钮在位").toBeTruthy();
    expect(vbtn.attributes("title")).toContain("窗口 0");
    await vbtn.trigger("click");
    await flushPromises();
    expect(runWasmVerify).toHaveBeenCalledWith(
      expect.objectContaining({
        instancesUrl: `${BRIDGE}/prove/case/tripcase07w0/instances.json`,
        proofUrl: `${BRIDGE}/prove/case/tripcase07w0/proof.bin`,
        vpUrl: `${BRIDGE}/prove/case/tripcase07w0/verifier_param.bin`,
        expectedUrl: `${BRIDGE}/prove/case/tripcase07w0/expected.json`,
        wasmUrl: `${API}/verify/dist/zkc.wasm`,
      }),
      expect.any(Function),
    );
    expect(w.text(), "结果如实（OK）+运行时预期标注").toContain("浏览器内验证 OK");
    expect(w.text()).toContain("105");
  });
});

describe("链上对账徽章（/chain/record 三态）", () => {
  it("一致：拉 /chain/record/{authId}→行尾徽章+详情绿标签；打印证明页复用对账（会话缓存不重复拉）+摘要块含链上交易编号", async () => {
    route([
      { match: (u) => u === `${API}/chain/panel`, res: panelRes() },
      { match: (u) => u === `${API}/chain/record/7`, res: { ok: true, status: 200, json: async () => ({ ok: true, data: recordDetail() }) } as Res },
      { match: (u) => u === `${BRIDGE}/prove/case/aabbccdd00112233/expected.json`, res: { ok: true, status: 200 } as Res },
    ]);
    const w = await mountView();
    await w.findAll(".rec")[0].find(".rowbtn").trigger("click");
    await flushPromises();

    await w.findAll("button").find((b) => b.text() === "与链上比对")!.trigger("click");
    await flushPromises();
    expect(fetchMock.mock.calls.filter(([u]) => String(u) === `${API}/chain/record/7`)).toHaveLength(1);
    expect(w.text()).toContain("一致（链上原文指纹=");
    expect(w.findAll(".rec")[0].find(".rowbtn").text(), "行尾徽章位回显").toContain("与链上一致");

    await w.findAll("button").find((b) => b.text() === "出示合规证书")!.trigger("click"); // 打印证明页
    await flushPromises();
    expect(window.print).toHaveBeenCalled();
    expect(fetchMock.mock.calls.filter(([u]) => String(u) === `${API}/chain/record/7`), "对账结论缓存——打印复用不重复拉").toHaveLength(1);
    expect(w.find(".lb-print-summary").text(), "纸面摘要含链上交易编号").toContain("0xtxhash07");
    expect(w.find(".lb-print-summary").text(), "纸面摘要含存证 SM3 指纹").toContain("ff".repeat(32));
  });

  it("不一致：链侧参数与本行不符→红标签点名差异（不应出现——出现即如实显示）", async () => {
    route([
      { match: (u) => u === `${API}/chain/panel`, res: panelRes() },
      { match: (u) => u === `${API}/chain/record/7`, res: { ok: true, status: 200, json: async () => ({ ok: true, data: recordDetail({ alt_max_m: 999 }) }) } as Res },
      { match: (u) => u === `${BRIDGE}/prove/case/aabbccdd00112233/expected.json`, res: { ok: true, status: 200 } as Res },
    ]);
    const w = await mountView();
    await w.findAll(".rec")[0].find(".rowbtn").trigger("click");
    await flushPromises();
    await w.findAll("button").find((b) => b.text() === "与链上比对")!.trigger("click");
    await flushPromises();
    expect(w.text()).toContain("不一致：本行档案与链侧登记不一致：高度上限");
    expect(w.findAll(".rec")[0].find(".rowbtn").text()).toContain("与链上不一致");
  });

  it("链不可达：chain_error→灰态重试按钮；重试可达后转一致（灰态不冒充结论）", async () => {
    const recRes = { ok: true, status: 200, json: async () => ({ ok: true, data: recordDetail() }) } as Res;
    const downRes = { ok: true, status: 200, json: async () => ({ ok: true, data: recordDetail({ chain: null, chain_error: "connection refused" }) }) } as Res;
    let down = true;
    route([
      { match: (u) => u === `${API}/chain/panel`, res: panelRes() },
      { match: (u) => u === `${API}/chain/record/7`, res: { get ok() { return down ? downRes.ok : recRes.ok; }, get json() { return down ? downRes.json : recRes.json; }, status: 200 } as unknown as Res },
      { match: (u) => u === `${BRIDGE}/prove/case/aabbccdd00112233/expected.json`, res: { ok: true, status: 200 } as Res },
    ]);
    const w = await mountView();
    await w.findAll(".rec")[0].find(".rowbtn").trigger("click");
    await flushPromises();
    await w.findAll("button").find((b) => b.text() === "与链上比对")!.trigger("click");
    await flushPromises();
    expect(w.text()).toContain("链不可达 · 点击重试");
    expect(w.text(), "灰态不出一致字样").not.toContain("与链上一致");

    down = false;
    await w.findAll("button").find((b) => b.text() === "链不可达 · 点击重试")!.trigger("click");
    await flushPromises();
    expect(fetchMock.mock.calls.filter(([u]) => String(u) === `${API}/chain/record/7`), "灰态允许重试（重拉一次）").toHaveLength(2);
    expect(w.text()).toContain("与链上一致");
  });
});
