/** 3.1 机队接口前端库单测：登记/签发体构造契约（与后端 RaService 同判）+
 * 档案密封 roundtrip（薄委托 keystore v4 原语）+吊销消息域对拍。 */
import { describe, expect, it } from "vitest";
import { sm2 } from "sm-crypto";
import {
  buildFleetDeployPackage,
  buildIssueBody,
  buildRegisterBody,
  fleetRevokeMsg,
  isValidDeviceNo,
  openFleetSlot,
  sealFleetSlot,
  type FleetDeviceMaterial,
  type FleetDeviceRow,
  type FleetSubCredOut,
} from "../../src/lib/fleet";
import { revokeMsg } from "../../src/lib/gov";

const NO_OK = "FZ-FLT-E2E-00000D1";

function row(over: Partial<FleetDeviceRow> = {}): FleetDeviceRow {
  return { device_no: NO_OK, sn: "FZ-SN-DEV-01", cert_level: 3, class_id: 1, ...over };
}

describe("fleet 登记体构造（后端契约镜像）", () => {
  it("诚实行构造=清洗+全字段在列", () => {
    const body = buildRegisterBody([row({ device_no: "  " + NO_OK + " ", sn: " SN1 " })]);
    expect(body.devices).toHaveLength(1);
    expect(body.devices[0]).toMatchObject({ device_no: NO_OK, sn: "SN1", cert_level: 3, class_id: 1 });
  });

  it("负例：登记号非 18 字符/序列号空/空行集——fail-fast 带行号", () => {
    expect(() => buildRegisterBody([row({ device_no: "SHORT" })])).toThrow(/18 字符/);
    expect(() => buildRegisterBody([row({ sn: "" })])).toThrow(/序列号/);
    expect(() => buildRegisterBody([row({ sn: "a|b" })])).toThrow(/竖线/);
    expect(() => buildRegisterBody([])).toThrow(/设备行/);
  });

  it("isValidDeviceNo 与后端形态门同判（18 字符字母/数字/-/_）", () => {
    expect(isValidDeviceNo(NO_OK)).toBe(true);
    expect(isValidDeviceNo("SHORT")).toBe(false);
    expect(isValidDeviceNo("FZ-FLT-E2E-00000D!")).toBe(false);
    expect(isValidDeviceNo("FZ-FLT-E2E-00000D11")).toBe(false);
  });
});

describe("fleet 签发体构造+吊销消息域", () => {
  it("签发体形态门：句柄 64hex/盐 32hex/出示钥 128hex", () => {
    const kp = sm2.generateKeyPairHex();
    const pk = kp.publicKey.replace(/^04/, "");
    const ok = buildIssueBody([
      { master_cred_hash_hex: "ab".repeat(32), salt_hex: "cd".repeat(16), holder_pub_hex: pk },
    ]);
    expect(ok.items).toHaveLength(1);
    expect(() =>
      buildIssueBody([{ master_cred_hash_hex: "zz", salt_hex: "cd".repeat(16), holder_pub_hex: pk }]),
    ).toThrow(/句柄/);
    expect(() =>
      buildIssueBody([{ master_cred_hash_hex: "ab".repeat(32), salt_hex: "cd".repeat(8), holder_pub_hex: pk }]),
    ).toThrow(/盐/);
    expect(() =>
      buildIssueBody([{ master_cred_hash_hex: "ab".repeat(32), salt_hex: "cd".repeat(16), holder_pub_hex: "12" }]),
    ).toThrow(/出示公钥/);
    expect(() => buildIssueBody([])).toThrow(/勾选/);
  });

  it("fleetRevokeMsg=单句柄 revokeMsg 同域（FZ-REVOKE|v1——逐字对拍）", () => {
    const h = "AA".repeat(32);
    expect(fleetRevokeMsg(h, "设备退役依规吊销", 7)).toBe(revokeMsg([h], "设备退役依规吊销", 7));
    expect(fleetRevokeMsg(h, "设备退役依规吊销", 7)).toMatch(/^FZ-REVOKE\|v1\|/);
  });
});

describe("fleet 设备档案密封（薄委托 keystore v4——SM4-GCM roundtrip）", () => {
  const mats: FleetDeviceMaterial[] = [
    {
      device_no: NO_OK, sn: "FZ-SN-DEV-01", cert_level: 3, class_id: 1,
      master_cred_hash_hex: "ab".repeat(32), commitment_hex: "cd".repeat(32),
      salt_hex: "ef".repeat(16), registered_ts: "2026-10-11T10:00:00Z",
    },
  ];

  it("密封→解封 roundtrip 逐字段同", async () => {
    const slot = await sealFleetSlot(mats, "fleet-pass-1", 2000); // 低迭代注入档（600k 生产档超 vitest 5s 窗——审查④）
    expect(slot.kdf).toBe("pbkdf2-sm3");
    const out = await openFleetSlot(slot, "fleet-pass-1");
    expect(out).toEqual(mats);
  });

  it("负例：错口令解封=人话拒绝（GCM 认证失败面）", async () => {
    const slot = await sealFleetSlot(mats, "fleet-pass-1", 2000);
    await expect(openFleetSlot(slot, "wrong-pass")).rejects.toThrow(/解封失败/);
  });
});

describe("fleet 部署包构造（审查②——受理三件套+出示私钥 fail-fast）", () => {
  const OUT: FleetSubCredOut = {
    device_no: NO_OK, master_cred_hash_hex: "ab".repeat(32), sub_cred_hash_hex: "11".repeat(32),
    message_hex: "22".repeat(10), sig_hex: "33".repeat(10), id_prime_hex: "44".repeat(10),
    expires_at: "2026-10-12T10:00:00", holder_sk_hex: "55".repeat(32),
  };

  it("全字段在列=包构造成功（kind 标记+材料原样）", () => {
    const pkg = buildFleetDeployPackage(OUT) as Record<string, string>;
    expect(pkg.kind).toBe("FZ-FLEET-SUBCRED");
    expect(pkg.message_hex).toBe(OUT.message_hex);
    expect(pkg.holder_sk_hex).toBe(OUT.holder_sk_hex);
  });

  it("负例：缺受理三件套任一/出示私钥=构造拒绝（不产残缺包）", () => {
    for (const field of ["message_hex", "sig_hex", "id_prime_hex", "holder_sk_hex"] as const) {
      const broken = { ...OUT, [field]: "" };
      expect(() => buildFleetDeployPackage(broken)).toThrow(new RegExp(field));
    }
    expect(() => buildFleetDeployPackage({ ...OUT, holder_sk_hex: "zz" })).toThrow(/出示私钥/);
  });
});
