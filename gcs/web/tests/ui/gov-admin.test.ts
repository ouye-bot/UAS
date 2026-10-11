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

function stubFetch(opts: {
  todos: unknown[] | "404";
  drift?: boolean;
  /** 修整窗口新增面（默认不提供=既有用例响应零变化）：在途请求行/仪式回放/未解锁令状。 */
  pendingReqs?: unknown[];
  ceremony?: unknown;
  pendingWarrants?: unknown[];
  devices?: unknown[];
}): ReturnType<typeof vi.fn> {
  return vi.fn(async (url: any, init?: any) => {
    const u = String(url);
    const method = (init?.method ?? "GET").toUpperCase();
    if (u.includes("/ra/fleet/devices") && method === "GET") {
      return jsonResponse(200, { code: "ok", message: "", data: { items: opts.devices ?? [], pool_quota: 100 } });
    }
    if (u.includes("/ra/revocation/linkage")) {
      return jsonResponse(200, {
        code: "ok", message: "",
        data: { handle_hex: H1, org_id: "org-a", linked_auth_ids: [9100], link_skipped: [], ledger_rows: [{ ledger_id: 1, epoch: 5, reason: "围栏违规成立", actor: "admin_hd", linked_auth_ids: [9100] }] },
      });
    }
    if (u.includes("/ra/fleet/device/flights")) {
      return jsonResponse(200, {
        code: "ok", message: "",
        data: { master_cred_hash_hex: H1, device_no: "FZ-FLT-E2E-00000D1", flights: [{ auth_id: 9100, status: "approved", class_id: 1, created_at: "2026-10-12T09:00:00", token_consumed_ts: null }] },
      });
    }
    if (u.includes("/ra/threshold/ceremony")) {
      return jsonResponse(200, { code: "ok", message: "", data: opts.ceremony ?? null });
    }
    if (u.includes("/ra/collab/pending")) {
      return jsonResponse(200, { code: "ok", message: "", data: opts.pendingWarrants ?? [] });
    }
    if (u.includes("/auth/whoami")) {
      return jsonResponse(200, { code: "ok", message: "", data: { username: "admin_hd", role: "admin", org_id: "org-a" } });
    }
    if (u.includes("/ra/collab-code") && method === "POST") {
      return jsonResponse(200, { code: "ok", message: "", data: { code: "FZC2-RAW", fingerprint: "fp1234" } });
    }
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
      const items = opts.pendingReqs ?? [HISTORY_REQ];
      return jsonResponse(200, { code: "ok", message: "", data: { items } });
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
          threshold_sync: opts.drift
            ? { mode: "real", synced: false, bound: true, red_flag: true, chain_fp_hex: "bb".repeat(32), domain_fp_hex: "aa".repeat(32) }
            : { mode: "real", synced: true, bound: true, red_flag: false },
        },
      });
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

async function mountAdmin(opts: {
  todos: unknown[] | "404";
  drift?: boolean;
  pendingReqs?: unknown[];
  ceremony?: unknown;
  pendingWarrants?: unknown[];
  devices?: unknown[];
}) {
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
    await first!.trigger("click"); // 第一拍：预览句柄+确认（2026-10-12 D2：预览挪到确认拍）
    await flushPromises();
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

  // 份额域失同步红牌两断言（1.3 件②）已随治理页拆分迁移至 gov-view.test.ts
  // （2026-10-12 修整窗口锚迁移逐条对账：断言原文迁 GovView 挂载面并只增——
  // 红牌 data-test=threshold-sync-flag 现居 /governance 页）。
});

describe("修整窗口：标签工作台+仪式可视化+手工出函卡（2026-10-12）", () => {
  const PENDING_EXEC = {
    ...HISTORY_REQ,
    id: 11, status: "executing",
  };
  const ANON_REQ = {
    ...HISTORY_REQ,
    id: 12, status: "pending", target_auth_id: null,
  };
  const CEREMONY = {
    warrant_hash_hex: WH, k: 2, domains: ["admin", "ra", "auditor"],
    summoned: ["admin", "ra"], granted: ["admin", "ra"], not_summoned: ["auditor"],
    rows: [
      { role: "admin", checks: { request_registered: true, warrant_on_chain: true, collab_approved: true }, decision: "granted" },
      { role: "ra", checks: { request_registered: true, warrant_on_chain: true, collab_approved: true }, decision: "granted" },
    ],
    threshold: "2-of-3",
  };

  let KP2: { privateKey: string; publicKey: string };
  beforeEach(() => {
    localStorage.clear();
    revokeCalls = [];
    restoreCalls = [];
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    window.matchMedia = ((q: string) => ({
      matches: false, media: q, onchange: null,
      addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {}, dispatchEvent: () => false,
    })) as unknown as typeof window.matchMedia;
    KP2 = sm2.generateKeyPairHex();
    cacheSk(KP2.privateKey); // 吊销/出函签名前置（与外层同纪律）
  });

  it("标签工作台：四标签在列+默认待办首屏+台账标签 v-show DOM 可达", async () => {
    const { w } = await mountAdmin({ todos: "404" });
    const tabbar = w.find('[data-test="admin-tabs"]');
    expect(tabbar.exists()).toBe(true);
    const labels = tabbar.findAll("button").map((b) => b.text());
    expect(labels.some((t) => t.startsWith("待办"))).toBe(true);
    expect(labels.some((t) => t.startsWith("吊销与恢复"))).toBe(true);
    expect(labels.some((t) => t.startsWith("机队"))).toBe(true);
    expect(labels.some((t) => t.startsWith("台账与账户"))).toBe(true);
    // 默认首屏=待办（待批协作卡在案可见）
    expect(w.text()).toContain("待批协作请求");
    // v-show 保 DOM 可达：台账文本在 textContent 中（display:none 不裁除）
    expect(w.text()).toContain("协作台账");
    // 切到机队标签后 fleet 面板仍在 DOM
    const fleetTab = tabbar.findAll("button").find((b) => b.text().startsWith("机队"))!;
    await fleetTab.trigger("click");
    expect(w.find('[data-test="fleet-panel"]').exists()).toBe(true);
    w.unmount();
  });

  it("未定域徽标：匿名立案位令状=全域待批（无归属域如实标注）", async () => {
    const { w } = await mountAdmin({ todos: "404", pendingReqs: [ANON_REQ] });
    await flushPromises();
    expect(w.text()).toContain("未定域 · 全域待批");
    w.unmount();
  });

  it("门限仪式可视化（B3）：执行中卡片就地渲染逐域四关+未征询域如实", async () => {
    const { w } = await mountAdmin({ todos: "404", pendingReqs: [PENDING_EXEC], ceremony: CEREMONY });
    await flushPromises();
    await flushPromises();
    const trace = w.find('[data-test="ceremony-trace"]');
    expect(trace.exists()).toBe(true);
    expect(trace.text()).toContain("门限解锁仪式");
    expect(trace.text()).toContain("2-of-3");
    expect(trace.text()).toContain("应召 2/3 域");
    expect(trace.text()).toContain("已出份额点");
    // 复审洞 4 诚实红线：第三域未被征询显性讲出（「三域全列」即失真）
    expect(trace.text()).toContain("未征询：审计员域");
    expect(trace.text()).toContain("凑足 2 域即停");
    w.unmount();
  });

  it("台账行仪式留痕：已执行行按钮回放（案乙）", async () => {
    const { w } = await mountAdmin({ todos: "404", ceremony: CEREMONY });
    const btn = w.findAll("button").find((b) => b.text() === "仪式留痕");
    expect(btn).toBeTruthy();
    await btn!.trigger("click");
    await flushPromises();
    const trace = w.find('[data-test="ceremony-trace"]');
    expect(trace.exists()).toBe(true);
    expect(trace.text()).toContain("门限解锁仪式");
    w.unmount();
  });

  it("未解锁令状卡（B4）：出函动线+FZC2 指纹回显；匿名行不可出函", async () => {
    const warrants = [
      { warrant_hash_hex: WH, case_no: "B4-001", target_auth_id: 9100, org_id: "org-a", legal_basis_text: "依据", created_ts: "2026-10-12T09:00:00" },
      { warrant_hash_hex: "ee".repeat(32), case_no: "B4-ANON", target_auth_id: null, org_id: null, legal_basis_text: null, created_ts: "2026-10-12T09:10:00" },
    ];
    const { w } = await mountAdmin({ todos: "404", pendingWarrants: warrants });
    const panel = w.find('[data-test="pending-warrants-panel"]');
    expect(panel.exists()).toBe(true);
    expect(panel.text()).toContain("B4-001");
    expect(panel.text()).toContain("归属域 org-a");
    expect(panel.text()).toContain("未定域");
    // 匿名行：出函按钮禁用（不提供手输凭证哈希路径——F 席根修语义）
    const buttons = panel.findAll("button").filter((b) => b.text().includes("出具协作函"));
    expect(buttons).toHaveLength(2);
    expect(buttons[1].attributes("disabled")).toBeDefined();
    // 目标行：一键出函→FZC2 指纹回显
    await buttons[0].trigger("click");
    await flushPromises();
    expect(panel.text()).toContain("fp1234");
    w.unmount();
  });

  it("P2 级联视图：公示撤销清单叶反查联动授权（linked_auth_ids 常设化）", async () => {
    const { w } = await mountAdmin({ todos: "404" });
    const btn = w.findAll("button").find((b) => b.text() === "联动授权");
    expect(btn).toBeTruthy();
    await btn!.trigger("click");
    await flushPromises();
    const view = w.find('[data-test="linkage-view"]');
    expect(view.exists()).toBe(true);
    expect(view.text()).toContain("级联视图");
    expect(view.text()).toContain("#9100");
    // 再点收起
    const btn2 = w.findAll("button").find((b) => b.text() === "收起级联");
    await btn2!.trigger("click");
    expect(w.find('[data-test="linkage-view"]').exists()).toBe(false);
    w.unmount();
  });

  it("P2 设备飞行记录：设备行展开授权记录（DB join 面）", async () => {
    const { w } = await mountAdmin({
      todos: "404",
      devices: [{ master_cred_hash_hex: H1, cred_kind: 2, device_no: "FZ-FLT-E2E-00000D1", sn: "FZ-SN-DEV-01", cert_level: 3, class_id: 1, status: 1, expires_at: "2027-10-11T00:00:00", sub_total: 1, sub_unconsumed: 0, created_at: "2026-10-11T09:00:00" }],
    });
    const btn = w.findAll("button").find((b) => b.text() === "飞行记录");
    expect(btn).toBeTruthy();
    await btn!.trigger("click");
    await flushPromises();
    const view = w.find('[data-test="flights-view"]');
    expect(view.exists()).toBe(true);
    expect(view.text()).toContain("飞行记录");
    w.unmount();
  });

  it("D2 预览纪元：确认句亮服务端权威纪元（DB 镜像不作签绑依据）", async () => {
    const { w } = await mountAdmin({ todos: "404" });
    await w.find('input[placeholder="用户名"]').setValue("pilot_bad");
    await w.find("textarea").setValue("审计结案属实依规吊销");
    const first = w.findAll("button").find((b) => b.text() === "吊销");
    await first!.trigger("click"); // 第一拍=预览（权威纪元）
    await flushPromises();
    expect(w.text()).toContain("已取预览：签名将绑定纪元");
    expect(w.text()).toContain("6");
    expect(w.text()).toContain("服务端权威");
    // 旧镜像话术退役（D2 根修——不再自 snapshot+1 推断）
    expect(w.text()).not.toContain("当前公示纪元");
    w.unmount();
  });
});
