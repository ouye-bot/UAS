/** P1-A1/A2 密钥库测试：私钥静态加密（口令+恢复码双因子解封）。
 *
 * - 密封形态：localStorage 只存 {v:2, pk, enc(口令KEK), rec(恢复码KEK)}——
 *   序列化串中搜不到明文私钥（红线断言）
 * - 双因子各自可解封；错误口令/篡改密文=GCM 认证失败
 * - KDF 确定性：同口令同盐→同 KEK（跨语言对拍可行性的前提）
 * - v1 明文遗留检测（升级迁移入口）
 */
import { describe, expect, it } from "vitest";
import { sm3Hex } from "../../src/lib/keystore";
import {
  KeystoreError,
  deriveKek,
  exportKeystoreBundle,
  generateRecoveryCode,
  importKeystoreBundle,
  isLegacyKeystore,
  openWithPassphrase,
  openWithRecoveryCode,
  parseKeystoreFileText,
  sealKeystore,
} from "../../src/lib/keystore";

const SK = "ab".repeat(32); // 32B 私钥 hex
const PK = "cd".repeat(64);

describe("密钥库（P1-A1/A2）", () => {
  it("KDF 确定性：同口令同盐同输出；异口令异输出", () => {
    const salt = "11".repeat(16);
    const a = deriveKek("口令甲", salt, 200);
    const b = deriveKek("口令甲", salt, 200);
    const c = deriveKek("口令乙", salt, 200);
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toHaveLength(32); // SM4 KEK=16B → 32 hex
  });

  it("sm3Hex 基线（KDF 原语锚）", () => {
    expect(sm3Hex("abc")).toHaveLength(64);
  });

  it("密封后序列化串零明文私钥", () => {
    const env = sealKeystore(SK, PK, "我的口令", "恢复码123");
    const s = JSON.stringify(env);
    expect(s).not.toContain(SK);
    expect(s).not.toContain("ababab");
    expect(env.v).toBe(2);
    expect(env.pk).toBe(PK);
    expect(env.enc.salt).not.toBe(env.rec.salt); // 双密文独立盐
  });

  it("口令解封 roundtrip", () => {
    const env = sealKeystore(SK, PK, "我的口令", "恢复码123");
    expect(openWithPassphrase(env, "我的口令")).toBe(SK);
  });

  it("恢复码独立解封（任一因子即可）", () => {
    const env = sealKeystore(SK, PK, "我的口令", "恢复码123");
    expect(openWithRecoveryCode(env, "恢复码123")).toBe(SK);
  });

  it("错误口令/错误恢复码=KeystoreError（GCM 认证失败）", () => {
    const env = sealKeystore(SK, PK, "我的口令", "恢复码123");
    expect(() => openWithPassphrase(env, "错误口令")).toThrow(KeystoreError);
    expect(() => openWithRecoveryCode(env, "错误码")).toThrow(KeystoreError);
  });

  it("篡改密文=解封拒绝", () => {
    const env = sealKeystore(SK, PK, "我的口令", "恢复码123");
    const tampered = structuredClone(env);
    const ct = tampered.enc.ct;
    tampered.enc.ct = (ct.slice(0, -2) + (ct.endsWith("aa") ? "bb" : "aa")) as string;
    expect(() => openWithPassphrase(tampered, "我的口令")).toThrow(KeystoreError);
  });

  it("恢复码生成：格式与唯一性（CSPRNG）", () => {
    const a = generateRecoveryCode();
    const b = generateRecoveryCode();
    expect(a).toMatch(/^[A-Z2-9]{4}(-[A-Z2-9]{4}){5}$/); // 24 字符分组 6 段
    expect(a).not.toBe(b);
  });

  it("v1 明文遗留检测", () => {
    expect(isLegacyKeystore({ sk: SK, pk: PK })).toBe(true);
    expect(isLegacyKeystore(sealKeystore(SK, PK, "p", "r"))).toBe(false);
  });

  // ---- 跨设备备份（2026-09-28 安全深检 C-P2 演进兑现）----

  const CRED = { master_cred_hash_hex: "ef".repeat(32), commitment_hex: "12".repeat(32), salt_hex: "34".repeat(32), sig_hex: "56".repeat(64), expires_at: "2027-01-01" };
  const FORM = { username: "pilot-x", id_number: "110101199001011234", cert_level: 3, sn: "FZ-SN-X-01", class_id: 1 };
  const RECOVERY = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ";

  it("跨设备备份：导出件零明文 PII，导入恢复身份全量（roundtrip）", () => {
    const env = sealKeystore(SK, PK, "旧口令甲", RECOVERY);
    const file = exportKeystoreBundle(env, CRED, FORM, RECOVERY);
    const text = JSON.stringify(file);
    // 导出件零明文红线：身份证号/用户名/私钥不得以明文出现
    expect(text).not.toContain("110101199001011234");
    expect(text).not.toContain("pilot-x");
    expect(text).not.toContain(SK);
    // 解析（JSON 往返）+导入（换新口令）
    const parsed = parseKeystoreFileText(JSON.stringify(JSON.parse(text)));
    const restored = importKeystoreBundle(parsed, RECOVERY, "新口令乙");
    expect(restored.sk).toBe(SK);
    expect(restored.pk).toBe(PK);
    expect(restored.cred).toEqual(CRED);
    expect(restored.form).toEqual(FORM);
    // 重封后新旧两把钥匙都可用
    expect(openWithPassphrase(restored.env, "新口令乙")).toBe(SK);
    expect(openWithRecoveryCode(restored.env, RECOVERY)).toBe(SK);
  });

  it("跨设备备份：错恢复码导出即拒（防错码封出不可恢复文件）", () => {
    const env = sealKeystore(SK, PK, "口令", RECOVERY);
    expect(() => exportKeystoreBundle(env, CRED, FORM, "XXXX-YYYY-ZZZZ-AAAA-BBBB-CCCC")).toThrow(KeystoreError);
  });

  it("跨设备备份：错恢复码导入拒绝；篡改元数据拒绝；坏文件人话拒绝", () => {
    const env = sealKeystore(SK, PK, "口令", RECOVERY);
    const file = exportKeystoreBundle(env, CRED, FORM, RECOVERY);
    expect(() => importKeystoreBundle(file, "XXXX-YYYY-ZZZZ-AAAA-BBBB-CCCC", "新口令")).toThrow(KeystoreError);
    const tampered = structuredClone(file);
    tampered.meta.ct = tampered.meta.ct.slice(0, -2) + (tampered.meta.ct.endsWith("aa") ? "bb" : "aa");
    expect(() => importKeystoreBundle(tampered, RECOVERY, "新口令")).toThrow(KeystoreError);
    expect(() => parseKeystoreFileText("{not json")).toThrow(KeystoreError);
    expect(() => parseKeystoreFileText(JSON.stringify({ kind: "other" }))).toThrow(/不是飞证密钥库备份/);
  });
});
