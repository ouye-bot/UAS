/** P0-3 登记向导状态机测试（纯逻辑层——组件薄封装）。
 *
 * - 无预填：初始表单全空（示例值只能经 SAMPLE 显式填入——演示纪律回归产品面）
 * - 步进：校验不过不出步；三步走完才允许提交
 * - 示例数据与初始态可区分
 */
import { describe, expect, it } from "vitest";
import {
  ENROLL_STEPS,
  SAMPLE_FORM,
  initialEnrollForm,
  validateStep,
} from "../../src/lib/enroll";

describe("登记向导", () => {
  it("初始表单零预填（示例值不进产品面）", () => {
    const f = initialEnrollForm();
    expect(f.username).toBe("");
    expect(f.id_number).toBe("");
    expect(f.sn).toBe("");
    expect(f.cert_level).toBe(0);
    expect(f.class_id).toBe(-1);
    // 示例数据存在且与初始态可区分（"填入示例"按钮的数据源）
    expect(SAMPLE_FORM.username).not.toBe("");
    expect(SAMPLE_FORM.id_number).not.toBe(f.id_number);
  });

  it("第 1 步（身份）校验：不过不出步", () => {
    const f = initialEnrollForm();
    expect(validateStep(1, f)).toBe("username_required");
    f.username = "pilot";
    expect(validateStep(1, f)).toBe("id_number_format");
    f.id_number = "110101199001011234";
    expect(validateStep(1, f)).toBeNull();
  });

  it("身份证 18 位数字格式钉定", () => {
    const f = { ...initialEnrollForm(), username: "pilot" };
    f.id_number = "11010119900101123"; // 17 位
    expect(validateStep(1, f)).toBe("id_number_format");
    f.id_number = "11010119900101123a"; // 含非数字
    expect(validateStep(1, f)).toBe("id_number_format");
  });

  it("第 2 步（设备）校验：序列号/资质/机型范围", () => {
    const f = { ...initialEnrollForm(), username: "pilot", id_number: "110101199001011234" };
    expect(validateStep(2, f)).toBe("sn_required");
    f.sn = "FZ-SN-01";
    expect(validateStep(2, f)).toBe("cert_level_range");
    f.cert_level = 3;
    expect(validateStep(2, f)).toBe("class_id_range");
    f.class_id = 1;
    expect(validateStep(2, f)).toBeNull();
    f.class_id = 256;
    expect(validateStep(2, f)).toBe("class_id_range");
  });

  it("步进状态机：1→2→3，步数不越界", () => {
    const f = { ...SAMPLE_FORM };
    expect(ENROLL_STEPS.length).toBe(3);
    expect(validateStep(3, f)).toBeNull(); // 确认页无额外校验
    expect(validateStep(4, f)).toBe("no_such_step");
  });

  it("填入示例后全步可过（演示位可用）", () => {
    expect(validateStep(1, SAMPLE_FORM)).toBeNull();
    expect(validateStep(2, SAMPLE_FORM)).toBeNull();
    expect(validateStep(3, SAMPLE_FORM)).toBeNull();
  });
});

describe("访问口令强度（P1 体验批）", () => {
  it("分级：空/弱/中/强", async () => {
    const { passphraseStrength } = await import("../../src/lib/enroll");
    expect(passphraseStrength("")).toBe(0);
    expect(passphraseStrength("abcdef")).toBe(1);          // 纯小写短
    expect(passphraseStrength("abcdef1234")).toBe(2);      // 小写+数字 10 位
    expect(passphraseStrength("Abcdef123!@#")).toBe(3);    // 大小写+数字+符号 ≥12
  });
});
