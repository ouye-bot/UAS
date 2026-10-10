// @vitest-environment jsdom
/** ⑧站触达闭环：飞手提醒条挂载面（吊销红条/违规红条/到期黄条/全空不渲染——
 * 浏览器 e2e 冻结面纪律：既有可见文本零变化，新增面由本测试钉定）。 */
import { describe, expect, it } from "vitest";
import { mount } from "@vue/test-utils";
import PilotNotices from "../../src/components/PilotNotices.vue";

const full = {
  revoked: [{ master_cred_hash_hex: "aa".repeat(32), reason: "围栏违规依判词吊销", epoch: 5 }],
  violations: [{ auth_id: 7, event_hash_hex: "bb".repeat(32), logged_at: "2026-10-10T00:00:00" }],
  expiring_subs: [{ sub_cred_hash_hex: "cc".repeat(32), expires_at: "2026-10-13T00:00:00", days_left: 3 }],
};

describe("PilotNotices 飞手提醒条", () => {
  it("三段齐备：吊销红条（理由+纪元）+违规红条（条数）+到期黄条（天数）", () => {
    const w = mount(PilotNotices, { props: { notices: full } });
    const rv = w.find('[data-test="notice-revoked"]');
    expect(rv.exists()).toBe(true);
    expect(rv.text()).toContain("您的凭证已被吊销");
    expect(rv.text()).toContain("围栏违规依判词吊销");
    expect(rv.text()).toContain("公示纪元 5");
    const vl = w.find('[data-test="notice-violation"]');
    expect(vl.exists()).toBe(true);
    expect(vl.text()).toContain("1 条围栏违规事件");
    const ex = w.find('[data-test="notice-expiring"]');
    expect(ex.exists()).toBe(true);
    expect(ex.text()).toContain("3 天内到期");
  });

  it("全空=不渲染（既有可见文本零变化——e2e 冻结面）", () => {
    const empty = { revoked: [], violations: [], expiring_subs: [] };
    const w = mount(PilotNotices, { props: { notices: empty } });
    expect(w.find(".fz-notices").exists()).toBe(false);
  });

  it("null（拉取失败态）=不渲染——页面形态零变化", () => {
    const w = mount(PilotNotices, { props: { notices: null } });
    expect(w.find(".fz-notices").exists()).toBe(false);
  });

  it("仅到期段：只渲染黄条（吊销/违规红条缺席）", () => {
    const w = mount(PilotNotices, {
      props: { notices: { revoked: [], violations: [], expiring_subs: full.expiring_subs } },
    });
    expect(w.find('[data-test="notice-expiring"]').exists()).toBe(true);
    expect(w.find('[data-test="notice-revoked"]').exists()).toBe(false);
    expect(w.find('[data-test="notice-violation"]').exists()).toBe(false);
  });
});
