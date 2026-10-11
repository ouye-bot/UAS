// @vitest-environment jsdom
/** 治理公示页挂载面（2026-10-12 修整窗口——/governance 拆页）：
 * - 份额域失同步红牌（自 gov-admin.test.ts 锚迁移——断言原文只增不减）；
 * - 互认机构面板（B1 审计件零渲染缺口根修）：真链档名册/单机构诚实文案/
 *   fake 档空态/聚合根；
 * - k-of-n 大屏：提案表+多签 KPI（自 AdminView 整体迁入的公示面）。 */
import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import GovView from "../../src/views/GovView.vue";

function jsonResponse(status: number, payload: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}

const CHAIN = {
  required: 2, delay_s: 10, owner_count: 3, owners: [], proposal_count: 1,
  proposals: [
    { proposal_id: 3, target: "PolicyRegistry", description: "threshold-reshare:epoch-2", confirmations: 1, status: "queued", eta_unix_s: Math.floor(Date.now() / 1000) + 5 },
  ],
};

function stubFetch(opts: {
  drift?: boolean;
  federation?: unknown | "absent";
  mode?: string;
}): ReturnType<typeof vi.fn> {
  return vi.fn(async (url: any) => {
    const u = String(url);
    if (u.includes("/chain/governance")) {
      const data: Record<string, unknown> = {
        mode: opts.mode ?? "real",
        chain: opts.mode === "fake" ? null : CHAIN,
        threshold_sync: opts.drift
          ? { mode: "real", synced: false, bound: true, red_flag: true, chain_fp_hex: "bb".repeat(32), domain_fp_hex: "aa".repeat(32) }
          : { mode: "real", synced: true, bound: true, red_flag: false },
      };
      if (opts.federation !== "absent") data.federation = opts.federation;
      return jsonResponse(200, { code: "ok", message: "", data });
    }
    return jsonResponse(200, { code: "ok", message: "", data: null });
  });
}

async function mountGov(opts: Parameters<typeof stubFetch>[0]) {
  const fetchStub = stubFetch(opts);
  vi.stubGlobal("fetch", fetchStub);
  const w = mount(GovView);
  await flushPromises();
  await flushPromises();
  return { w, fetchStub };
}

beforeEach(() => {
  localStorage.clear();
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
  // jsdom 未实现 matchMedia——ParticleField 的 reduced-motion 探测打桩（gov-admin 同款）
  window.matchMedia = ((q: string) => ({
    matches: false, media: q, onchange: null,
    addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {}, dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("治理页：份额域失同步红牌（1.3 件②——锚迁移自 gov-admin，断言原文）", () => {
  it("漂移态：红牌在案（失同步判词+提案已起草指引）", async () => {
    const { w } = await mountGov({ drift: true });
    const flag = w.find('[data-test="threshold-sync-flag"]');
    expect(flag.exists()).toBe(true);
    expect(flag.text()).toContain("份额域失同步");
    expect(flag.text()).toContain("fail-closed");
    w.unmount();
  });

  it("对齐态：零红牌", async () => {
    const { w } = await mountGov({ drift: false });
    expect(w.find('[data-test="threshold-sync-flag"]').exists()).toBe(false);
    w.unmount();
  });
});

describe("治理页：k-of-n 公示大屏（自 AdminView 整体迁入）", () => {
  it("提案表+多签 KPI 活数据", async () => {
    const { w } = await mountGov({});
    expect(w.text()).toContain("AdminGovernor k-of-n");
    expect(w.text()).toContain("2/3 多签");
    expect(w.text()).toContain("threshold-reshare:epoch-2");
    expect(w.text()).toContain("时间锁中");
    w.unmount();
  });

  it("fake 档：诚实空态（不装一致）", async () => {
    const { w } = await mountGov({ mode: "fake", federation: "absent" });
    expect(w.text()).toContain("演示链档——治理公示面随真链提供");
    w.unmount();
  });
});

describe("治理页：互认机构面板（B1 审计件根修——federation 公示）", () => {
  const FED = {
    orgs: [
      { org_id: "org-a", name: "org-a", status: 1, ra: "0xaaa", rev_epoch: 9, rev_root_hex: "aa".repeat(32), registered_ts: 0, anchor_ts: 0 },
      { org_id: "org-b", name: "org-b", status: 1, ra: "0xbbb", rev_epoch: 3, rev_root_hex: "bb".repeat(32), registered_ts: 0, anchor_ts: 0 },
    ],
    org_active: 2,
    global_rev_root_hex: "cc".repeat(32),
    global_rev_epoch: 14,
  };

  it("双域名册：逐域锚纪元/锚根/准入状态+聚合根", async () => {
    const { w } = await mountGov({ federation: FED });
    expect(w.text()).toContain("互认机构（FedRegistry 名册）");
    expect(w.text()).toContain("org-a");
    expect(w.text()).toContain("org-b");
    expect(w.text()).toContain("在册 2 域");
    expect(w.text()).toContain("在册互认");
    expect(w.text()).toContain("聚合纪元");
    // 单机构诚实文案不出现（双域形态）
    expect(w.text()).not.toContain("在册 1 域——互认随治理准入扩展");
    w.unmount();
  });

  it("单机构形态：名册一行+「在册 1 域」扩展文案（复审洞 5 修法）", async () => {
    const { w } = await mountGov({
      federation: { ...FED, orgs: [FED.orgs[0]], org_active: 1 },
    });
    expect(w.text()).toContain("org-a");
    expect(w.text()).not.toContain("org-b");
    expect(w.find('[data-test="federation-single-org"]').exists()).toBe(true);
    expect(w.text()).toContain("在册 1 域——互认随治理准入扩展");
    w.unmount();
  });

  it("退出机构：锚冻结保留（历史吊销永久互认——诚实徽章）", async () => {
    const { w } = await mountGov({
      federation: { ...FED, orgs: [FED.orgs[0], { ...FED.orgs[1], status: 0 }], org_active: 1 },
    });
    expect(w.text()).toContain("已退出（锚冻结保留）");
    w.unmount();
  });

  it("fake 档/未部署：互认面板诚实空缺（不装一致）", async () => {
    const { w } = await mountGov({ mode: "fake", federation: "absent" });
    expect(w.text()).toContain("互认注册表随真链提供");
    w.unmount();
  });
});
