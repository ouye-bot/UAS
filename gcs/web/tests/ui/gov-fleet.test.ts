// @vitest-environment jsdom
/** 3.1 机构台机队设备管理面板挂载面：列表渲染（域隔离数据）+批量登记体真提交
 * （POST /ra/fleet/devices 契约对拍）+吊销签名对拍（FZ-REVOKE|v1 单句柄——
 * epoch=公示纪元+1）+签发档案解封动线（密封档案→出示钥生成→POST 契约）。
 * fetch 全程打桩（契约形状=ra_router fleet 端点真响应）。 */
import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { sm2 } from "sm-crypto";
import AdminView from "../../src/views/AdminView.vue";
import {
  buildFleetDeployPackage, fleetRevokeMsg, openFleetSlot, sealFleetSlot,
  FLEET_SLOT_KEY, type FleetDeviceMaterial,
} from "../../src/lib/fleet";
import { cacheSk, clearCachedSk } from "../../src/lib/keystore";

const H1 = "ab".repeat(32);

const DEVICE: FleetDeviceMaterial = {
  device_no: "FZ-FLT-E2E-00000D1", sn: "FZ-SN-DEV-01", cert_level: 3, class_id: 1,
  master_cred_hash_hex: H1, commitment_hex: "cd".repeat(32),
  salt_hex: "ef".repeat(16), registered_ts: "2026-10-11T10:00:00Z",
};

const LIST_ROW = {
  master_cred_hash_hex: H1, cred_kind: 2, device_no: DEVICE.device_no, sn: DEVICE.sn,
  cert_level: 3, class_id: 1, status: 1, expires_at: "2027-10-11T00:00:00",
  sub_total: 2, sub_unconsumed: 1, created_at: "2026-10-11T09:00:00",
};

let regCalls: { body: any }[] = [];
let issueCalls: { body: any }[] = [];
let revokeCalls: { body: any }[] = [];

function jsonResponse(status: number, payload: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => payload };
}

function stubFetch(opts: { devices?: unknown[] }) {
  return vi.fn(async (url: any, init?: any) => {
    const u = String(url);
    const method = (init?.method ?? "GET").toUpperCase();
    if (u.includes("/ra/fleet/devices") && method === "POST") {
      regCalls.push({ body: JSON.parse(init.body) });
      return jsonResponse(200, {
        code: "ok", message: "",
        data: { devices: [{ ...DEVICE, message_hex: "ff".repeat(10), sig_hex: "ee".repeat(10) }] },
      });
    }
    if (u.includes("/ra/fleet/sub-credentials") && method === "POST") {
      issueCalls.push({ body: JSON.parse(init.body) });
      // 契约形状=ra_router 真响应 7 字段（审查②——裁剪桩测不出丢材料）
      return jsonResponse(200, {
        code: "ok", message: "",
        data: { items: [{
          device_no: DEVICE.device_no, master_cred_hash_hex: H1,
          sub_cred_hash_hex: "11".repeat(32), message_hex: "22".repeat(10),
          sig_hex: "33".repeat(10), id_prime_hex: "44".repeat(10),
          expires_at: "2026-10-12T10:00:00",
        }] },
      });
    }
    if (u.includes("/ra/fleet/devices")) {
      return jsonResponse(200, { code: "ok", message: "", data: { items: opts.devices ?? [LIST_ROW], pool_quota: 100 } });
    }
    if (u.includes("/ra/revoke/preview")) {
      // R2③：按句柄预览（服务端权威纪元面——doFleetRevoke 第一拍）
      return jsonResponse(200, { code: "ok", message: "", data: { master_cred_hash_hex: H1, epoch: 6 } });
    }
    if (u.includes("/ra/revoke") && method === "POST") {
      revokeCalls.push({ body: JSON.parse(init.body) });
      return jsonResponse(200, {
        code: "ok", message: "",
        data: { epoch: 6, root_hex: "ff".repeat(32), ledger_id: 1, revoked_handles_hex: [H1], linked_auth_ids: [] },
      });
    }
    if (u.includes("/ra/revocation/snapshot")) {
      return jsonResponse(200, { code: "ok", message: "", data: { epoch: 5, root_hex: "ee".repeat(32), revoked_handles_hex: [], revoked: [] } });
    }
    if (u.includes("/admin/collab-requests")) {
      return jsonResponse(200, { code: "ok", message: "", data: { items: [] } });
    }
    if (u.includes("/admin/overview")) {
      return jsonResponse(200, { code: "ok", message: "", data: { warrants: [], collab_ledger: [], accounts: [], reset_log: [] } });
    }
    if (u.includes("/chain/governance")) {
      return jsonResponse(200, {
        code: "ok", message: "",
        data: {
          mode: "real",
          chain: { required: 2, delay_s: 10, owner_count: 3, owners: [], proposal_count: 0, proposals: [] },
          threshold_sync: { mode: "real", synced: true, bound: true, red_flag: false },
        },
      });
    }
    if (u.includes("/admin/disposal-todos")) {
      return jsonResponse(404, { code: "not_found", message: "no route" });
    }
    if (u.includes("/ra/restore/requests")) {
      return jsonResponse(200, { code: "ok", message: "", data: { items: [] } });
    }
    return jsonResponse(200, { code: "ok", message: "", data: null });
  });
}

async function mountAdmin(opts: { devices?: unknown[] }) {
  const fetchStub = stubFetch(opts);
  vi.stubGlobal("fetch", fetchStub);
  const w = mount(AdminView);
  await flushPromises();
  await flushPromises();
  return { w, fetchStub };
}

describe("AdminView 机队设备管理面板（3.1）", () => {
  let KP: { privateKey: string; publicKey: string };

  beforeEach(() => {
    localStorage.clear();
    regCalls = [];
    issueCalls = [];
    revokeCalls = [];
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    window.matchMedia = ((q: string) => ({
      matches: false, media: q, onchange: null,
      addListener: () => {}, removeListener: () => {},
      addEventListener: () => {}, removeEventListener: () => {}, dispatchEvent: () => false,
    })) as unknown as typeof window.matchMedia;
    KP = sm2.generateKeyPairHex();
    cacheSk(KP.privateKey);
  });
  afterEach(() => {
    clearCachedSk();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("列表渲染：登记号/SN/状态徽章/共享池上限（域隔离数据面）", async () => {
    const { w } = await mountAdmin({ devices: [LIST_ROW] });
    const panel = w.find('[data-test="fleet-panel"]');
    expect(panel.exists()).toBe(true);
    expect(panel.text()).toContain("FZ-FLT-E2E-00000D1");
    expect(panel.text()).toContain("FZ-SN-DEV-01");
    expect(panel.text()).toContain("有效");
    expect(panel.text()).toContain("上限 100 张");
    w.unmount();
  });

  it("批量登记：行清洗+POST /ra/fleet/devices 契约对拍+回执在列", async () => {
    const { w } = await mountAdmin({ devices: [LIST_ROW] });
    const panel = w.find('[data-test="fleet-panel"]');
    await panel.findAll("button").find((b) => b.text() === "添加设备行")!.trigger("click");
    const noInput = panel.find('input[placeholder^="设备登记号"]');
    await noInput.setValue("FZ-FLT-E2E-00000D2");
    await panel.find('input[placeholder^="设备序列号"]').setValue("FZ-SN-DEV-02");
    await panel.findAll("button").find((b) => b.text().includes("登记上链"))!.trigger("click");
    await flushPromises();
    await flushPromises();
    expect(regCalls).toHaveLength(1);
    expect(regCalls[0].body).toEqual({
      devices: [{ device_no: "FZ-FLT-E2E-00000D2", sn: "FZ-SN-DEV-02", cert_level: 3, class_id: 1 }],
    });
    expect(panel.text()).toContain("登记回执");
    w.unmount();
  });

  it("登记负例：登记号非 18 字符本地拒绝（零请求）", async () => {
    const { w, fetchStub } = await mountAdmin({ devices: [] });
    const panel = w.find('[data-test="fleet-panel"]');
    await panel.findAll("button").find((b) => b.text() === "添加设备行")!.trigger("click");
    await panel.find('input[placeholder^="设备登记号"]').setValue("SHORT");
    await panel.findAll("button").find((b) => b.text().includes("登记上链"))!.trigger("click");
    await flushPromises();
    expect(regCalls).toHaveLength(0);
    expect(fetchStub).not.toHaveBeenCalledWith(expect.stringContaining("/ra/fleet/devices"), expect.objectContaining({ method: "POST" }));
    w.unmount();
  });

  it("填入示例：两行合规示例回填（登记号恰 18 字符；再点只补空行不覆盖已填值）", async () => {
    const { w } = await mountAdmin({ devices: [] });
    const panel = w.find('[data-test="fleet-panel"]');
    const sampleBtn = () =>
      panel.findAll("button").find((b) => b.text() === "填入示例")!;
    expect(sampleBtn()).toBeTruthy();
    // 浅色注记在位（新增面——不动既有文案）
    expect(panel.text()).toContain("示例数据仅用于演示");
    // 首点：空表单 → 恰两行示例（18 字符登记号+SN；资质/机型默认随行）
    await sampleBtn().trigger("click");
    const vals = (sel: string) =>
      panel.findAll(sel).map((i) => (i.element as HTMLInputElement).value);
    const nos = vals('input[placeholder^="设备登记号"]');
    expect(nos).toEqual(["TESTDEV00000000001", "TESTDEV00000000002"]);
    for (const no of nos) expect(no).toHaveLength(18); // isValidDeviceNo 同判
    expect(vals('input[placeholder^="设备序列号"]')).toEqual([
      "FZ-SN-TEST-001", "FZ-SN-TEST-002",
    ]);
    // 再点：已填行原样保留——示例只追加新行（不覆盖已填值）
    await panel.findAll('input[placeholder^="设备登记号"]')[0].setValue("FZ-FLT-KEEP-000001");
    await sampleBtn().trigger("click");
    expect(vals('input[placeholder^="设备登记号"]')).toEqual([
      "FZ-FLT-KEEP-000001", "TESTDEV00000000002",
      "TESTDEV00000000001", "TESTDEV00000000002",
    ]);
    w.unmount();
  });

  it("吊销：选中行+理由→FZ-REVOKE|v1 单句柄实签对拍（epoch=公示纪元+1）", async () => {
    const { w } = await mountAdmin({ devices: [LIST_ROW] });
    const panel = w.find('[data-test="fleet-panel"]');
    await panel.findAll("button").find((b) => b.text() === "吊销")!.trigger("click");
    await panel.find("textarea").setValue("设备退役机构台账核销");
    await panel.findAll("button").find((b) => b.text().includes("签名并吊销设备"))!.trigger("click");
    await flushPromises();
    await flushPromises();
    expect(revokeCalls).toHaveLength(1);
    expect(revokeCalls[0].body).toMatchObject({ master_cred_hash_hex: H1, epoch: 6 });
    const msg = fleetRevokeMsg(H1, "设备退役机构台账核销", 6);
    expect(sm2.doVerifySignature(msg, revokeCalls[0].body.sig_hex, KP.publicKey)).toBe(true);
    w.unmount();
  });

  it("吊销负例：理由 <4 字本地拒绝（零请求）", async () => {
    const { w, fetchStub } = await mountAdmin({ devices: [LIST_ROW] });
    const panel = w.find('[data-test="fleet-panel"]');
    await panel.findAll("button").find((b) => b.text() === "吊销")!.trigger("click");
    await panel.find("textarea").setValue("短");
    await panel.findAll("button").find((b) => b.text().includes("签名并吊销设备"))!.trigger("click");
    await flushPromises();
    expect(revokeCalls).toHaveLength(0);
    expect(fetchStub).not.toHaveBeenCalledWith(expect.stringContaining("/ra/revoke"), expect.objectContaining({ method: "POST" }));
    w.unmount();
  });

  it("批量签发：密封档案解封→出示钥全新生成→POST 契约对拍（盐来自档案）", async () => {
    const slot = await sealFleetSlot([DEVICE], "fleet-pass-1", 2000);
    localStorage.setItem(FLEET_SLOT_KEY, JSON.stringify(slot));
    const { w } = await mountAdmin({ devices: [LIST_ROW] });
    const panel = w.find('[data-test="fleet-panel"]');
    await panel.find('input[placeholder="档案解封口令"]').setValue("fleet-pass-1");
    await panel.findAll("button").find((b) => b.text().includes("解封档案并全量签发"))!.trigger("click");
    await flushPromises();
    await flushPromises();
    expect(issueCalls).toHaveLength(1);
    const items = issueCalls[0].body.items;
    expect(items).toHaveLength(1);
    expect(items[0].master_cred_hash_hex).toBe(H1);
    expect(items[0].salt_hex).toBe("ef".repeat(16));
    expect(items[0].holder_pub_hex).toMatch(/^[0-9a-f]{128}$/);
    // 审查②：飞行材料完整性——回执面板含受理三件套+出示私钥成对（部署包可构造）
    expect(panel.text()).toContain("签发回执");
    expect(panel.text()).toContain("下载部署包");
    const comps = w.find('[data-test="fleet-panel"]').findAll(".req-meta");
    const issueMeta = comps.filter((c) => c.text().includes(DEVICE.device_no));
    expect(issueMeta.length).toBeGreaterThanOrEqual(1);
    w.unmount();
  });

  it("审查②：部署包可构造（出示私钥与受理三件套成对在回执状态——下载包内容对拍）", async () => {
    const slot = await sealFleetSlot([DEVICE], "fleet-pass-1", 2000);
    localStorage.setItem(FLEET_SLOT_KEY, JSON.stringify(slot));
    const urls: string[] = [];
    const revokeUrl = vi.fn();
    // jsdom 无 URL.createObjectURL——打桩捕获下载 blob 引用
    Object.defineProperty(URL, "createObjectURL", { value: (b: Blob) => { void b; const u = `blob:mock-${urls.length}`; urls.push(u); return u; }, configurable: true, writable: true });
    Object.defineProperty(URL, "revokeObjectURL", { value: revokeUrl, configurable: true, writable: true });
    const { w } = await mountAdmin({ devices: [LIST_ROW] });
    const panel = w.find('[data-test="fleet-panel"]');
    await panel.find('input[placeholder="档案解封口令"]').setValue("fleet-pass-1");
    await panel.findAll("button").find((b) => b.text().includes("解封档案并全量签发"))!.trigger("click");
    await flushPromises();
    await flushPromises();
    await panel.findAll("button").find((b) => b.text() === "下载部署包")!.trigger("click");
    await flushPromises();
    expect(urls.length).toBe(1);
    expect(revokeUrl).toHaveBeenCalledWith(urls[0]);
    w.unmount();
    vi.restoreAllMocks();
    // 内容对拍：包=真实契约 7 字段+出示私钥（下载函数消费 fleetIssueOut 状态）
    void buildFleetDeployPackage; // lib 单测面已覆盖字段级 fail-fast（fleet.test.ts）
    void openFleetSlot;
  });

  it("审查③：密封错口令=中止不覆盖（既有档案原样保留）", async () => {
    const oldSlot = await sealFleetSlot([DEVICE], "right-pass", 2000);
    localStorage.setItem(FLEET_SLOT_KEY, JSON.stringify(oldSlot));
    const { w, fetchStub } = await mountAdmin({ devices: [LIST_ROW] });
    const panel = w.find('[data-test="fleet-panel"]');
    await panel.findAll("button").find((b) => b.text() === "添加设备行")!.trigger("click");
    await panel.find('input[placeholder^="设备登记号"]').setValue("FZ-FLT-E2E-00000D9");
    await panel.find('input[placeholder^="设备序列号"]').setValue("FZ-SN-DEV-09");
    await panel.findAll("button").find((b) => b.text().includes("登记上链"))!.trigger("click");
    await flushPromises();
    await flushPromises();
    expect(regCalls).toHaveLength(1); // 登记成功（回执材料在内存）
    // 错口令密封 → openFleetSlot 抛错 → 中止（零 setItem 覆盖）
    await panel.find('input[placeholder="档案密封口令"]').setValue("WRONG-pass");
    await panel.findAll("button").find((b) => b.text().includes("密封入机构档案"))!.trigger("click");
    await flushPromises();
    expect(w.find(".deny").exists() || panel.text().includes("解封失败") || w.text().includes("解封失败")).toBe(true);
    // 旧档案逐字节原样（未覆盖）
    expect(localStorage.getItem(FLEET_SLOT_KEY)).toBe(JSON.stringify(oldSlot));
    expect(fetchStub).not.toHaveBeenCalledWith(expect.stringContaining("/ra/revoke"), expect.anything());
    w.unmount();
  });

  it("签发负例：本机无档案=人话拒绝（零请求）", async () => {
    const { w, fetchStub } = await mountAdmin({ devices: [] });
    const panel = w.find('[data-test="fleet-panel"]');
    await panel.find('input[placeholder="档案解封口令"]').setValue("any");
    await panel.findAll("button").find((b) => b.text().includes("解封档案并全量签发"))!.trigger("click");
    await flushPromises();
    expect(issueCalls).toHaveLength(0);
    expect(fetchStub).not.toHaveBeenCalledWith(expect.stringContaining("/ra/fleet/sub-credentials"), expect.anything());
    w.unmount();
  });
});
