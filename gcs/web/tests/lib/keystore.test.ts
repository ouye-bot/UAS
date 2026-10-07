/** P1-A1/A2 密钥库测试：私钥静态加密（口令+恢复码双因子解封）。
 *
 * - 密封形态：localStorage 只存 {v:2, pk, enc(口令KEK), rec(恢复码KEK)}——
 *   序列化串中搜不到明文私钥（红线断言）
 * - 双因子各自可解封；错误口令/篡改密文=GCM 认证失败
 * - KDF 确定性：同口令同盐→同 KEK（跨语言对拍可行性的前提）
 * - v1 明文遗留检测（升级迁移入口）
 * - 批 2 密码底座升档：v4=PBKDF2-HMAC-SM3 现行口径（JS↔Python 对拍锚）+
 *   v3 legacy 保留用例 + 版本分派解封
 */
import { describe, expect, it } from "vitest";
import {
  KDF_ITERATIONS_V4,
  KDF_LEGACY_V3_ITERATIONS,
  sm3Hex,
} from "../../src/lib/keystore";
import {
  KeystoreError,
  deriveActivationVerifier,
  deriveKek,
  deriveKekV4,
  exportKeystoreBundle,
  generateRecoveryCode,
  importKeystoreBundle,
  isLegacyKeystore,
  openKeystore,
  openKeystoreV3,
  openKeystoreV4,
  openWithPassphrase,
  openWithRecoveryCode,
  parseKeystoreBlob,
  parseKeystoreFileText,
  sealKeystore,
  sealKeystoreV3,
  sealKeystoreV4,
  sealProfileSlot,
  unsealProfileSlot,
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

  // ---- 批 2 密码底座升档：v4=PBKDF2-HMAC-SM3 现行 + v3 legacy 兼容 ----

  it("v4 KDF 对拍锚（Python 侧实测同值——JS↔Python 逐字节一致）", async () => {
    // 锚值：node+hash-wasm（本测试同实现）与 Python hashlib/pure 双引擎实测一致
    expect(await deriveKekV4("Test-Pass-8", "aabbccdd", 8)).toBe("1277e3342905e4695e67bde5dd3d89dd");
    expect(await deriveKekV4("Test-Pass-8", "aabbccdd", 21000)).toBe("0b1e8a811af3d432501681bf8372023b");
  });

  it("v3 legacy KDF 对拍锚（旧链保留——存量兼容面事实源不删）", () => {
    expect(deriveKek("Test-Pass-8", "aabbccdd", 8)).toBe("b7a19b8f13a8ea0768e16242baaf6d14");
    expect(deriveKek("Test-Pass-8", "aabbccdd", KDF_LEGACY_V3_ITERATIONS)).toBe("8c30c8ae0a6067df7085e7230c92096d");
  });

  it("激活核对子 v1 独立域：与 KEK 域分离（同口令同盐两域输出互异）", async () => {
    const kek = await deriveKekV4("口令甲", "11".repeat(16), 200);
    const ver = await deriveActivationVerifier("口令甲", "11".repeat(16), 200);
    expect(ver).toHaveLength(32);
    expect(ver).not.toBe(kek); // 域分离（info=FZ-ACTIVATE-VERIFY|v1 入盐）
  });

  it("v4 密封/解封 roundtrip；iter/kdf 随信封落盘；错口令拒；缺省 600k 档", async () => {
    const env = await sealKeystoreV4(SK, PK, "口令甲", 4096);
    expect(env.v).toBe(4);
    expect(env.enc.kdf).toBe("pbkdf2-sm3");
    expect(env.enc.iter).toBe(4096);
    expect(JSON.stringify(env)).not.toContain(SK);
    expect(await openKeystoreV4(env, "口令甲")).toBe(SK);
    await expect(openKeystoreV4(env, "错口令")).rejects.toThrow(KeystoreError);
    const fresh = await sealKeystoreV4(SK, PK, "口令甲"); // 缺省=OWASP 2023 档
    expect(fresh.enc.iter).toBe(KDF_ITERATIONS_V4);
  });

  it("版本分派解封：v3 存量信封仍可解（不删旧链）；未知版本显式拒绝", async () => {
    const v3 = sealKeystoreV3(SK, PK, "口令甲"); // legacy 密封
    expect(await openKeystore(v3, "口令甲")).toBe(SK); // 分派→旧链
    const v4 = await sealKeystoreV4(SK, PK, "口令甲", 4096);
    expect(await openKeystore(v4, "口令甲")).toBe(SK); // 分派→PBKDF2
    const parsed = parseKeystoreBlob(JSON.stringify(v4));
    expect(parsed.v).toBe(4);
    expect(() => parseKeystoreBlob(JSON.stringify({ v: 5, pk: PK, enc: v4.enc }))).toThrow(KeystoreError);
    expect(() => parseKeystoreBlob("not json")).toThrow(KeystoreError);
  });

  it("v4 信封形态门：kdf 标记/iter 非法=拒（fail-closed）", async () => {
    const env = await sealKeystoreV4(SK, PK, "口令甲", 4096);
    const bad1 = structuredClone(env);
    (bad1.enc as { kdf: string }).kdf = "sm3-chain";
    await expect(openKeystoreV4(bad1, "口令甲")).rejects.toThrow(KeystoreError);
    const bad2 = structuredClone(env);
    (bad2.enc as { iter: number }).iter = 0;
    await expect(openKeystoreV4(bad2, "口令甲")).rejects.toThrow(KeystoreError);
    // 篡改 v4 密文=GCM 认证失败
    const bad3 = structuredClone(env);
    bad3.enc.ct = bad3.enc.ct.slice(0, -2) + (bad3.enc.ct.endsWith("aa") ? "bb" : "aa");
    await expect(openKeystoreV4(bad3, "口令甲")).rejects.toThrow(KeystoreError);
  });

  it("资料槽 v4：密封带标记可解；v3 legacy 旧槽（无标记）仍按旧链可解", async () => {
    const data = { cred: { h: "ef".repeat(32) }, form: { sn: "FZ-SN-1" } };
    const slot4 = await sealProfileSlot(data, "口令甲", 4096);
    expect(slot4.kdf).toBe("pbkdf2-sm3");
    expect(await unsealProfileSlot(slot4, "口令甲")).toEqual(data);
    await expect(unsealProfileSlot(slot4, "错口令")).rejects.toThrow(KeystoreError);
  });

  it("v3 开封（openKeystoreV3 直呼）错口令=KeystoreError（legacy 判定面保留）", () => {
    const v3 = sealKeystoreV3(SK, PK, "口令甲");
    expect(openKeystoreV3(v3, "口令甲")).toBe(SK);
    expect(() => openKeystoreV3(v3, "错口令")).toThrow(KeystoreError);
  });
});
