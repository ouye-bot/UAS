// @vitest-environment jsdom
/** 双钥汇流图（丙-2 M3）挂载面：e2e 夹具无待批协作请求 ⟹ 组件在浏览器回归
 * 里永不挂载——此处单测补位：三指纹落位/缺右钥灰点/装饰层纪律。 */
import { describe, expect, it } from "vitest";
import { mount } from "@vue/test-utils";
import FzConfluence from "../../src/components/FzConfluence.vue";

describe("FzConfluence 双钥汇流图", () => {
  const auditor = "a".repeat(16);
  const admin = "b".repeat(16);
  const req = "c".repeat(16);

  it("双钥齐备：左右签章指纹+中央 req_fp 各就位", () => {
    const w = mount(FzConfluence, {
      props: { auditorFp: auditor, adminFp: admin, reqFp: req },
    });
    const fps = w.findAll(".fz-cf-fp");
    expect(fps).toHaveLength(2);
    expect(fps[0].text()).toBe("aaaaaaaa");
    expect(fps[1].text()).toBe("bbbbbbbb");
    expect(w.find(".fz-cf-core").text()).toBe("cccccccc");
    // 双钥齐备=右钥实心（无 off 灰点）
    expect(w.find(".fz-cf-dot.off").exists()).toBe(false);
  });

  it("待批准（右钥缺位）：灰点虚位+中央占位，不臆造指纹", () => {
    const w = mount(FzConfluence, {
      props: { auditorFp: auditor, adminFp: null, reqFp: undefined },
    });
    expect(w.find(".fz-cf-dot.off").exists()).toBe(true);
    expect(w.find(".fz-cf-core").text()).toBe("——");
    expect(w.findAll(".fz-cf-fp")[1].text()).toBe("····");
  });

  it("装饰层纪律：根节点 aria-hidden（不进无障碍树；pointer-events:none 由 scoped 样式静态保证）", () => {
    const w = mount(FzConfluence, {
      props: { auditorFp: auditor, adminFp: admin, reqFp: req },
    });
    expect(w.attributes("aria-hidden")).toBe("true");
    expect(w.find(".fz-cf").element.hasAttribute("aria-hidden")).toBe(true);
  });
});
