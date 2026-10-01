/** 一次性出示钥批（2026-10-01）：材料绑定与会话域出示钥 sk′ 的单元测试。
 *
 * - sk′ 会话域内存态：storeSubSk/getSubSk/clearSubSk——重签覆盖旧钥（每张
 *   子凭证唯一出示钥）、清除即失（会话域语义）
 * - 材料指纹不含账户公钥（出示钥随子凭证走——换登记/换表单才失配，账户钥
 *   轮换不再使子凭证失配）
 * - 失配检测语义保留：改登记/表单 → subMatchesMaterial=false（引导重签）
 */
import { beforeEach, describe, expect, it } from "vitest";

// node 环境无 DOM storage——最小内存替身（只实现 lib 用到的四面）
class MemStorage {
  private m = new Map<string, string>();
  getItem(k: string): string | null { return this.m.has(k) ? this.m.get(k)! : null; }
  setItem(k: string, v: string): void { this.m.set(k, String(v)); }
  removeItem(k: string): void { this.m.delete(k); }
  clear(): void { this.m.clear(); }
}

beforeEach(() => {
  (globalThis as Record<string, unknown>).localStorage = new MemStorage();
  (globalThis as Record<string, unknown>).sessionStorage = new MemStorage();
});

import {
  clearSubSk,
  currentMaterialFingerprint,
  getSubSk,
  storeSubBinding,
  storeSubSk,
  storedSubPk,
  subMatchesMaterial,
} from "../../src/lib/material";

const CRED = { master_cred_hash_hex: "aa".repeat(32), salt_hex: "bb".repeat(16) };
const FORM = { id_number: "110101199001011234", sn: "FZ-SN-1", cert_level: 3, class_id: 1 };

function seedMaterial(): void {
  localStorage.setItem("fzCred", JSON.stringify(CRED));
  localStorage.setItem("fzForm", JSON.stringify(FORM));
}

describe("出示私钥 sk′（会话域）", () => {
  it("存取回环；清除即失", () => {
    expect(getSubSk()).toBeNull();
    storeSubSk("01".repeat(32));
    expect(getSubSk()).toBe("01".repeat(32));
    clearSubSk();
    expect(getSubSk()).toBeNull();
  });

  it("重签覆盖：同会话只有当前子凭证的 sk′（每张子凭证唯一出示钥）", () => {
    storeSubSk("01".repeat(32));
    storeSubSk("02".repeat(32));
    expect(getSubSk()).toBe("02".repeat(32));
  });
});

describe("材料绑定指纹（不含账户公钥）", () => {
  it("账户钥变化不影响指纹（出示钥随子凭证——换钥不失配）", () => {
    seedMaterial();
    localStorage.setItem("fzUserKeypair", JSON.stringify({ v: 3, pk: "11".repeat(64) }));
    const f1 = currentMaterialFingerprint();
    localStorage.setItem("fzUserKeypair", JSON.stringify({ v: 3, pk: "22".repeat(64) }));
    expect(currentMaterialFingerprint()).toBe(f1);
  });

  it("登记/表单变化 → 指纹变化（失配检测语义保留）", () => {
    seedMaterial();
    storeSubBinding();
    expect(subMatchesMaterial()).toBe(true);
    // 重新登记（新承诺）
    localStorage.setItem("fzCred", JSON.stringify({ ...CRED, master_cred_hash_hex: "cc".repeat(32) }));
    expect(subMatchesMaterial()).toBe(false);
  });

  it("无绑定记录=失配（旧数据/未记录引导重签）", () => {
    seedMaterial();
    expect(subMatchesMaterial()).toBe(false);
  });

  it("指纹不泄露表单原文（单向摘要面）", () => {
    seedMaterial();
    const f = currentMaterialFingerprint();
    expect(f).not.toContain(FORM.id_number);
    expect(f).not.toContain(FORM.sn);
  });
});

describe("出示公钥 pk′ 读取（fzSub 客户端自记字段）", () => {
  it("读 holder_pk_hex；缺失=空串", () => {
    expect(storedSubPk()).toBe("");
    localStorage.setItem("fzSub", JSON.stringify({ sub_cred_hash_hex: "dd".repeat(32), holder_pk_hex: "ab".repeat(64) }));
    expect(storedSubPk()).toBe("ab".repeat(64));
  });
});
