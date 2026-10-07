// @vitest-environment jsdom
/** 机构台升格批挂载面（2026-10-04）：处置待办卡空态/404 隐藏+去吊销预填+
 * 吊销两步式签名对拍（FZ-REVOKE|v1）+台账验签判词+恢复发起签名对拍
 * （FZ-RESTORE|v1）。fetch 全程打桩（契约形状=admin_router/ra_router 真响应）。 */
import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { sm2 } from "sm-crypto";
import AdminView from "../../src/views/AdminView.vue";
import { restoreMsg, revokeMsg } from "../../src/lib/gov";
import { cacheSk, clearCachedSk } from "../../src/lib/keystore";

const H1 = "aa".repeat(32);
const RH = "22".repeat(32);
const WH = "11".repeat(32);

const HISTORY_REQ = {
  id: 9, warrant_hash_hex: WH, case_no: "CASE-20261003-002", target_auth_id: 9100,
  legal_basis_text: "依据", note: "理由", status: "closed",
  auditor_username: "auditor_hd", auditor_fp: "a1".repeat(8),
  admin_username: "admin_hd", admin_fp: "b2".repeat(8),
  reject_reason: null, execute_error: null,
  fzc2_fingerprint_hex: "c3".repeat(8), req_fp: "d4".repeat(8), req_hash_hex: RH,
  created_ts: "2026-10-03T09:00:00", decided_ts: "2026-10-03T09:05:00", executed_ts: "2026-10-03T09:10:00",
};

const SIGS = {
  id: 9, req_hash_hex: RH,
  auditor: { ok: true, epoch: 1, reason: null },
  admin: { ok: true, epoch: 2, reason: null },
};

const TODO = {
  id: 3, case_no: "CASE-20261004-007", username: "pilot_bad", conclusion: "verified",
  created_ts: "2026-10-04T10:00:00", status: "pending", resolved_note: null,
};

const LEAF = {
  handle_hex: H1, reason: "违规飞行实弹", revoked_at: "2026-10-01T09:00:00",
  epoch: 5, revoked_by: "admin_hd",
};

let revokeCalls: { body: any }[] = [];
let restoreCalls: { body: any }[] = [];

function jsonResponse(status: number, payload: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}

function stubFetch(opts: { todos: unknown[] | "404" }): ReturnType<typeof vi.fn> {
  return vi.fn(async (url: any, init?: any) => {
    const u = String(url);
    const method = (init?.method ?? "GET").toUpperCase();
    if (u.includes("/admin/disposal-todos") && method === "POST") {
      return jsonResponse(200, { code: "ok", message: "", data: { ok: true } });
    }
    if (u.includes("/admin/disposal-todos")) {
      if (opts.todos === "404") return jsonResponse(404, { code: "not_found", message: "no route" });
      return jsonResponse(200, { code: "ok", message: "", data: { items: opts.todos } });
    }
    if (u.includes("/admin/collab-requests") && u.includes("/verify-sigs")) {
      return jsonResponse(200, { code: "ok", message: "", data: SIGS });
    }
    if (u.includes("/admin/collab-requests")) {
      return jsonResponse(200, { code: "ok", message: "", data: { items: [HISTORY_REQ] } });
    }
    if (u.includes("/admin/overview")) {
      return jsonResponse(200, { code: "ok", message: "", data: { warrants: [], collab_ledger: [], accounts: [], reset_log: [] } });
    }
    if (u.includes("/ra/revoke/by-username/preview")) {
      return jsonResponse(200, { code: "ok", message: "", data: { username: "pilot_bad", handles: [H1], epoch: 6 } });
    }
    if (u.includes("/ra/revoke/by-username") && method === "POST") {
      revokeCalls.push({ body: JSON.parse(init.body) });
      return jsonResponse(200, {
        code: "ok", message: "",
        data: { epoch: 6, root_hex: "ff".repeat(32), ledger_id: 1, revoked_handles_hex: [H1], linked_auth_ids: [9100] },
      });
    }
    if (u.includes("/ra/restore/request") && method === "POST") {
      restoreCalls.push({ body: JSON.parse(init.body) });
      return jsonResponse(200, { code: "ok", message: "", data: { id: 1, status: "pending" } });
    }
    if (u.includes("/ra/revocation/snapshot")) {
      return jsonResponse(200, { code: "ok", message: "", data: { epoch: 5, root_hex: "ee".repeat(32), revoked_handles_hex: [H1], revoked: [LEAF] } });
    }
    if (u.includes("/ra/restore/requests")) {
      return jsonResponse(200, { code: "ok", message: "", data: { items: [] } });
    }
    return jsonResponse(200, { code: "ok", message: "", data: null });
  });
}

async function mountAdmin(opts: { todos: unknown[] | "404" }) {
  const fetchStub = stubFetch(opts);
  vi.stubGlobal("fetch", fetchStub);
  const w = mount(AdminView);
  await flushPromises();
  await flushPromises();
  return { w, fetchStub };
}

describe("AdminView 升格批：待办卡/吊销两步式/验签/恢复发起", () => {
  let KP: { privateKey: string; publicKey: string };

  beforeEach(() => {
    localStorage.clear();
    revokeCalls = [];
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    restoreCalls = [];
    // jsdom 未实现 matchMedia——useCountUp 的 reduced-motion 探测在此打桩为不减速
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

  it("待办卡（A5/B2）：后端 404 时整卡优雅隐藏", async () => {
    const { w } = await mountAdmin({ todos: "404" });
    expect(w.text()).not.toContain("待处置");
    w.unmount();
  });

  it("待办卡：展示案号/用户/结论；去吊销预填用户名与理由（案号+结论）", async () => {
    const { w } = await mountAdmin({ todos: [TODO] });
    expect(w.text()).toContain("CASE-20261004-007");
    expect(w.text()).toContain("pilot_bad");
    expect(w.text()).toContain("属实");
    const go = w.findAll("button").find((b) => b.text() === "去吊销");
    expect(go).toBeTruthy();
    await go!.trigger("click");
    const userInput = w.find('input[placeholder="用户名"]');
    expect((userInput.element as HTMLInputElement).value).toBe("pilot_bad");
    const reason = w.find("textarea").element as HTMLTextAreaElement;
    expect(reason.value).toContain("CASE-20261004-007");
    expect(reason.value).toContain("属实");
    w.unmount();
  });

  it("吊销两步式（B1）：预览句柄→FZ-REVOKE|v1 实签对拍→回执含联动授权清单", async () => {
    const { w, fetchStub } = await mountAdmin({ todos: "404" });
    await w.find('input[placeholder="用户名"]').setValue("pilot_bad");
    await w.find("textarea").setValue("审计结案属实依规吊销");
    const first = w.findAll("button").find((b) => b.text() === "吊销");
    expect(first).toBeTruthy();
    await first!.trigger("click"); // 第一拍：内联二次确认
    const second = w.findAll("button").find((b) => b.text().includes("确认吊销"));
    expect(second).toBeTruthy();
    await second!.trigger("click"); // 第二拍：预览+签名+提交
    await flushPromises();
    await flushPromises();

    expect(fetchStub).toHaveBeenCalledWith(
      expect.stringContaining("/ra/revoke/by-username/preview?username=pilot_bad"),
      expect.anything(),
    );
    expect(revokeCalls).toHaveLength(1);
    expect(revokeCalls[0].body).toMatchObject({
      username: "pilot_bad", reason: "审计结案属实依规吊销", epoch: 6,
    });
    const msg = revokeMsg([H1], "审计结案属实依规吊销", 6);
    expect(sm2.doVerifySignature(msg, revokeCalls[0].body.sig_hex, KP.publicKey)).toBe(true);
    // 回执：联动撤销授权清单+台账指针
    expect(w.text()).toContain("#9100");
    expect(w.text()).toContain("台账 #1");
    w.unmount();
  });

  it("吊销校验：理由 <4 字本地拒绝（不发起任何请求）", async () => {
    const { w, fetchStub } = await mountAdmin({ todos: "404" });
    await w.find('input[placeholder="用户名"]').setValue("pilot_bad");
    await w.find("textarea").setValue("短");
    const first = w.findAll("button").find((b) => b.text() === "吊销");
    await first!.trigger("click");
    expect(w.find(".deny").text()).toMatch(/理由须 ≥4 字/);
    expect(fetchStub).not.toHaveBeenCalledWith(
      expect.stringContaining("/ra/revoke/by-username/preview"),
      expect.anything(),
    );
    w.unmount();
  });

  it("台账行验签复核（A3）：双签判词就地展示", async () => {
    const { w } = await mountAdmin({ todos: "404" });
    const btn = w.findAll("button").find((b) => b.text() === "验签复核");
    expect(btn).toBeTruthy();
    await btn!.trigger("click");
    await flushPromises();
    const out = w.find(".sigs-out");
    expect(out.exists()).toBe(true);
    expect(out.text()).toContain("审计员签 ✓ 纪元 1 验签通过");
    expect(out.text()).toContain("管理员签 ✓ 纪元 2 验签通过");
    w.unmount();
  });

  it("恢复发起（B6）：公示清单选中→FZ-RESTORE|v1 实签→pending 台账刷新", async () => {
    const { w } = await mountAdmin({ todos: "404" });
    expect(w.text()).toContain("aa aa".slice(0, 2)); // 句柄前缀可见
    const pick = w.findAll("button").find((b) => b.text() === "发起恢复");
    expect(pick).toBeTruthy();
    await pick!.trigger("click");
    const gate = w.find(".gate");
    expect(gate.exists()).toBe(true);
    // 理由 <4 字本地拒绝
    await gate.find("textarea").setValue("误");
    const go = gate.findAll("button").find((b) => b.text().includes("签名并发起恢复请求"));
    await go!.trigger("click");
    expect(w.find(".deny").text()).toMatch(/理由须 ≥4 字/);
    expect(restoreCalls).toHaveLength(0);
    // 合规理由→签名提交
    await gate.find("textarea").setValue("误吊销经复核无异常恢复");
    await go!.trigger("click");
    await flushPromises();
    await flushPromises();
    expect(restoreCalls).toHaveLength(1);
    expect(restoreCalls[0].body.handle_hex).toBe(H1);
    const msg = restoreMsg(H1, "误吊销经复核无异常恢复");
    expect(sm2.doVerifySignature(msg, restoreCalls[0].body.sig_hex, KP.publicKey)).toBe(true);
    w.unmount();
  });
});
