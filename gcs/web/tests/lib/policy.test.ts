import { describe, expect, it } from "vitest";
import { classLabel } from "../../src/lib/policy";

describe("classLabel 机型类映射（C-P2-7）", () => {
  it("开放档给公共名", () => {
    expect(classLabel(0)).toBe("微型");
    expect(classLabel(1)).toBe("轻型");
  });
  it("未开放档诚实标注", () => {
    expect(classLabel(2)).toBe("小型（暂未开放）");
    expect(classLabel(3)).toBe("中型（暂未开放）");
    expect(classLabel(9)).toBe("9 类（暂未开放）");
  });
  it("缺省形态", () => {
    expect(classLabel(null)).toBe("—");
    expect(classLabel(undefined)).toBe("—");
  });
});
