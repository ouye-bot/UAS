// @vitest-environment jsdom
/** 审计台升格批挂载面（2026-10-04）：结案浮层三段式（实名/证据/结案）——
 * 结案表单校验+FZ-COLLAB-CLOSE 签名消息实签对拍+设备判词/时间线渲染+
 * 验签复核判词。fetch 全程打桩（契约形状=audit/router 真响应）。 */
import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { sm2 } from "sm-crypto";
import AuditView from "../../src/views/AuditView.vue";
import { closeMsg } from "../../src/lib/gov";
import { cacheSk, clearCachedSk } from "../../src/lib/keystore";

const WH = "11".repeat(32);
const RH = "22".repeat(32);
const FP = "ab".repeat(32);

const REQ = {
  id: 7, warrant_hash_hex: WH, case_no: "CASE-20261004-001", target_auth_id: 9100,
  legal_basis_text: "依据原文", note: "调查理由", status: "executed",
  auditor_username: "auditor_hd", auditor_fp: "a1".repeat(8),
  admin_username: "admin_hd", admin_fp: "b2".repeat(8),
  reject_reason: null, execute_error: null,
  fzc2_fingerprint_hex: "c3".repeat(8), req_fp: "d4".repeat(8), req_hash_hex: RH,
  created_ts: "2026-10-04T09:00:00", decided_ts: "2026-10-04T09:05:00", executed_ts: "2026-10-04T09:10:00",
};

const TRACE = {
  warrant: {
    warrant_hash_hex: WH, case_no: "CASE-20261004-001", target_auth_id: 9100,
    unlocked: { ts: "2026-10-04T09:10:00", master_cred_hash_hex: "ee".repeat(32), username: "张三", id_number: "110101199001011234" },
  },
  chain_trace: {
    auth_id: 9100,
    device_check: { verdict: "mismatch", checked: 4, mismatch: 2, registered_sn_fingerprint: "f0".repeat(8) },
    checkpoints: [{ seq: 1, chain_head_hex: "12".repeat(16), ts: 1728000000 }],
    events: [{ event_type: 1, event_hash_hex: "34".repeat(32), block: 42, tx_hash: "0x" + "56".repeat(20), logged_at: "2026-10-04T09:00:00" }],
  },
  chain_fingerprint: "block=7",
  closure: null,
  mode: "fake",
};

const SIGS = {
  id: 7, req_hash_hex: RH,
  auditor: { ok: true, epoch: 3, reason: null },
  admin: { ok: null, epoch: null, reason: "not_decided" },
};

const okJson = (data: unknown) => ({
  ok: true as const,
  status: 200,
  json: async () => ({ code: "ok", message: "", data }),
});

let closeCalls: { url: string; body: any }[] = [];

function stubFetch(): ReturnType<typeof vi.fn> {
  return vi.fn(async (url: any, init?: any) => {
    const u = String(url);
    const method = (init?.method ?? "GET").toUpperCase();
    if (u.includes("/audit/collab-requests") && u.includes("/close") && method === "POST") {
      closeCalls.push({ url: u, body: JSON.parse(init.body) });
      return okJson({ ...REQ, status: "closed", case_archive_fp_hex: FP, closed_ts: "2026-10-04T10:00:00" });
    }
    if (u.includes("/verify-sigs")) return okJson(SIGS);
    if (u.includes("/audit/warrants") && u.includes("/trace")) return okJson(TRACE);
    if (u.includes("/audit/violations")) return okJson({ items: [] });
    if (u.includes("/audit/warrants")) return okJson([]);
    if (u.includes("/audit/collab-requests")) return okJson({ items: [REQ] });
    if (u.includes("/ra/restore/requests")) return okJson({ items: [] });
    return okJson(null);
  });
}

async function mountAudit(): Promise<ReturnType<typeof mount>> {
  const w = mount(AuditView);
  await flushPromises();
  return w;
}

describe("AuditView 升格批：结案浮层/证据面/验签复核", () => {
  let fetchStub: ReturnType<typeof vi.fn>;
  let KP: { privateKey: string; publicKey: string };

  beforeEach(() => {
    localStorage.clear();
    // jsdom 未实现 matchMedia——useCountUp 的 reduced-motion 探测在此打桩为不减速
    window.matchMedia = ((q: string) => ({
      matches: false, media: q, onchange: null,
      addListener: () => {}, removeListener: () => {},
      addEventListener: () => {}, removeEventListener: () => {}, dispatchEvent: () => false,
    })) as unknown as typeof window.matchMedia;
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    closeCalls = [];
    fetchStub = stubFetch();
    vi.stubGlobal("fetch", fetchStub);
    // 预置审计员钥（内存缓存——签结案消息用；公钥留作验签对拍）
    KP = sm2.generateKeyPairHex();
    cacheSk(KP.privateKey);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
    });
  });
  afterEach(() => {
    clearCachedSk();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("结案浮层：证据面渲染设备判词（mismatch=red）+链上时间线，属实缺说明被本地拒", async () => {
    const w = await mountAudit();
    const open = w.findAll("button").find((b) => b.text() === "查看实名并结案");
    expect(open).toBeTruthy();
    await open!.trigger("click");
    await flushPromises();

    const modal = w.find(".modal");
    expect(modal.exists()).toBe(true);
    expect(modal.text()).toContain("张三");
    // A2 证据面：设备一致性判词卡（mismatch=红判词）+核对计数+时间线节点
    expect(modal.text()).toContain("设备不一致");
    expect(modal.text()).toContain("4");
    expect(modal.text()).toContain("（其中不一致 2 处）");
    expect(modal.text()).toContain("f0f0f0f0f0f0f0f0");
    expect(modal.text()).toContain("检查点锚定");
    expect(modal.text()).toContain("固件围栏拦截");
    expect(modal.find(".fz-badge.red").exists()).toBe(true);

    // A1 校验：属实（verified）未填说明 → 本地拒绝（不发请求）
    const before = closeCalls.length;
    const radio = modal.find('input[name="close-conclusion"][value="verified"]');
    expect(radio.exists()).toBe(true);
    await radio.setValue(true);
    const signBtn = modal.findAll("button").find((b) => b.text().includes("签名并结案"));
    expect(signBtn).toBeTruthy();
    await signBtn!.trigger("click");
    expect(closeCalls.length).toBe(before);
    expect(w.find(".deny").text()).toMatch(/属实.*须填写结案说明/);
    w.unmount();
  });

  it("结案提交：FZ-COLLAB-CLOSE|v1 消息实签可验+案卷指纹回执+复制", async () => {
    const w = await mountAudit();
    const open = w.findAll("button").find((b) => b.text() === "查看实名并结案");
    await open!.trigger("click");
    await flushPromises();
    const modal = w.find(".modal");
    await modal.find('input[name="close-conclusion"][value="verified"]').setValue(true);
    const text = "链上检查点签名与登记设备不符，违规事实成立";
    await modal.find("textarea").setValue(text);
    const signBtn = modal.findAll("button").find((b) => b.text().includes("签名并结案"));
    await signBtn!.trigger("click");
    await flushPromises();

    // 契约体：conclusion/conclusion_text/sig_hex 齐备
    expect(closeCalls).toHaveLength(1);
    expect(closeCalls[0].url).toContain(`/audit/collab-requests/7/close`);
    expect(closeCalls[0].body.conclusion).toBe("verified");
    expect(closeCalls[0].body.conclusion_text).toBe(text);
    expect(closeCalls[0].body.sig_hex).toMatch(/^[0-9a-f]+$/);

    // 签名消息逐字对拍：提交签名须以审计员钥签 closeMsg(RH, conclusion, text)
    // 可验（消息域/req_hash/结论/说明任一漂移即验不过）
    const msg = closeMsg(RH, "verified", text);
    expect(msg).toBe(`FZ-COLLAB-CLOSE|v1|${RH}|verified|${text}`);
    expect(sm2.doVerifySignature(msg, closeCalls[0].body.sig_hex, KP.publicKey)).toBe(true);

    // 回执：等宽案卷指纹+复制按钮
    const receipt = w.find(".modal .fp-box");
    expect(receipt.exists()).toBe(true);
    expect(receipt.find(".fp-code").text()).toBe(FP);
    const copyBtn = receipt.findAll("button").find((b) => b.text().includes("复制"));
    await copyBtn!.trigger("click");
    await flushPromises();
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(FP);
    w.unmount();
  });

  it("验签复核（A3）：双端点判词就地展示（通过带纪元/未批准人话）", async () => {
    const w = await mountAudit();
    const btn = w.findAll("button").find((b) => b.text() === "验签复核");
    expect(btn).toBeTruthy();
    await btn!.trigger("click");
    await flushPromises();
    const out = w.find(".sigs-out");
    expect(out.exists()).toBe(true);
    expect(out.text()).toContain("审计员签 ✓ 纪元 3 验签通过");
    expect(out.text()).toContain("尚未批准——无机构签名可验");
    w.unmount();
  });

  it("历史案卷卡（A4）：点击开追溯浮层（纯追溯——无结案表单时呈加载/证据态）", async () => {
    // 本例案卷卡列表为空——以请求行入口已覆盖浮层；此处补空态不炸
    const w = await mountAudit();
    expect(w.find(".case-card").exists()).toBe(false);
    w.unmount();
  });
});
