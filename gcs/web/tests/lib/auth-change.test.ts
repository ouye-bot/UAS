// @vitest-environment jsdom
/** 自助改密 v6 形态判定回归（缺陷 B 根修批 2026-10-17，先红后绿）。
 *
 * 病征（手测实弹 final_ui_04）：全新浏览器 v6 账户改密必败 422
 * v6_change_required——changePassword 的 v6 判定只读本地面板（loadKeystore），
 * 全新浏览器本地面板缺失=误判 v4 → 发 v4 信封不携掩码钥 → 服务端（v6 账户）
 * 拒。钉定新契约：本地面板只是快路径，服务端权威判据=me() 回执 sealed_blob
 * 版本（v6 账户服务端存的就是 v6' 信封——keystore 端点 410 的镜像语义）。
 * OPAQUE 解封面（opaqueUnlockSk/opaqueEvaluate）以 importActual 局部替身
 * （OPAQUE 原语已由 tests/lib/opaque.test.ts 黄金向量钉死——本组被测对象=
 * 改密路径选择与报文形态，非 OPAQUE 本体）；v4 密封/解封走真 crypto。 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const SK = "ab".repeat(32);
const PK = "cd".repeat(64);
const USERNAME = "pw_change_ui";

// opaque.test.ts 同源黄金点/r（finalize 黄金钉——替身 evaluate 回执可复算）
const GOLDEN_RT_BETA =
  "94fc9dae4e6934b980939f2eedbacd6c616ab1b1d5d1d5ac7a17ed0d47fcd7d9a" +
  "70ee9da0f70923b35024a0fc26406b074ccab004c8eaaade363c257651c9ac0";
const R_DEMO = "17".repeat(32);

vi.mock("../../src/lib/opaqueClient", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../../src/lib/opaqueClient")>();
  // evaluate 替身回执（黄金点/r——finalize 可复算）；change 材料保留真实实现
  // 逻辑（finalize→rwd 链→v6' 信封），仅把其内部 opaqueEvaluate 调用改道替身
  // （ESM 模块内绑定不被 export mock 改道——须整体替写）。回执常量在闭包内
  // 构造（vi.mock 工厂被提升——顶层 const 在工厂执行时点尚未初始化）。
  const { finalize, deriveRwdChain } = await import("../../src/lib/opaque");
  const { sealEnvelopeV6 } = await import("../../src/lib/keystore");
  const fakeResponse = () => ({
    evaluated_message: GOLDEN_RT_BETA,
    masking_nonce: "00".repeat(32),
    masked_response: "00".repeat(64),
    kdf_salt_hex: "11".repeat(16),
    kdf_iter: 4096,
  });
  return {
    ...mod,
    opaqueUnlockSk: vi.fn(async () => SK),
    opaqueEvaluate: vi.fn(async () => ({ response: fakeResponse(), r: BigInt("0x" + R_DEMO) })),
    opaqueChangeMaterials: vi.fn(
      async (
        _username: string,
        _newPassword: string,
        skHex: string,
        pkHex: string,
        saltHex: string,
        iterations: number,
      ) => {
        const oprfOutput = await finalize(BigInt("0x" + R_DEMO), GOLDEN_RT_BETA);
        const { rwd, maskingKey } = await deriveRwdChain(oprfOutput, saltHex, iterations);
        const env = await sealEnvelopeV6(skHex, pkHex, rwd);
        return {
          sealed_blob: JSON.stringify(env),
          masking_key_hex: Array.from(maskingKey, (b) => b.toString(16).padStart(2, "0")).join(""),
          // 新口令 rwd 随行（v6 账户资料密封槽重封 KEK 源——服务端 _normalize_
          // profile_slot_v6 契约：v6 账户改密回传的资料槽须 v6 profile 形态）
          rwd,
        };
      },
    ),
  };
});

import { changePassword, type MeInfo } from "../../src/lib/auth";
import {
  loadKeystore,
  openProfileSlotV6,
  sealKeystoreV4,
  sealProfileSlot,
  storeKeystore,
} from "../../src/lib/keystore";
import { deriveRwdChain, finalize } from "../../src/lib/opaque";

type Res = { ok: boolean; status: number; json?: () => Promise<unknown> };
let meInfo: Partial<MeInfo>;
const changeBodies: Record<string, unknown>[] = [];
const fetchMock = vi.fn((_url: string | URL | RequestInfo, _init?: RequestInit) =>
  Promise.resolve({} as Res),
);

function route(): Res {
  const [url, init] = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
  const path = String(url ?? "");
  if (init?.method === "POST" && path.includes("/auth/password/change")) {
    changeBodies.push(JSON.parse(String(init.body)));
    return json({ code: "ok", message: "", data: null });
  }
  if (path.includes("/auth/me")) return json({ code: "ok", data: meInfo });
  // 全新浏览器取服务端密封件：v6 账户=410（掩码通道取代——keystore 端点语义）
  return json({ code: "opaque_migrated", message: "该账户已迁移 OPAQUE 通道" }, 410);
}

function json(b: unknown, status = 200): Res {
  return { ok: status < 300, status, json: async () => b };
}

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem("fzSession", JSON.stringify({ role: "pilot", username: USERNAME }));
  changeBodies.length = 0;
  meInfo = {
    username: USERNAME,
    role: "pilot",
    status: "active",
    pubkey_hex: PK,
    sealed_profile: null,
  };
  fetchMock.mockImplementation((_u, _i) => Promise.resolve(route()));
  vi.stubGlobal("fetch", fetchMock);
});

describe("自助改密 v6 形态判定（缺陷 B）", () => {
  it("全新浏览器（零本地面板）+ 服务端 v6 密封件 → v6 路径（携掩码钥的 v6' 信封）——不再误发 v4 信封吃 422", async () => {
    meInfo.sealed_blob = JSON.stringify({ v: 6, pk: PK });
    expect(loadKeystore(), "前置：本地面板缺失（全新浏览器形态）").toBeNull();
    await changePassword("pw-old-口令", "pw-new-口令2");
    expect(changeBodies.length).toBe(1);
    const body = changeBodies[0] as { sealed_blob: string; masking_key_hex?: string };
    expect(JSON.parse(body.sealed_blob).v, "改密报文=v6' 重封件").toBe(6);
    expect(body.masking_key_hex, "新掩码钥必携（原子换新——缺失即服务端 422 的根因面）")
      .toMatch(/^[0-9a-f]{64}$/);
    // 改密成功后本地面板同步换 v6（下次走快路径）
    expect((loadKeystore() as { v?: number }).v).toBe(6);
  }, 60000);

  it("v4 存量（本地面板 v4+服务端 v4）→ v4 路径语义零变化（不携掩码钥）", async () => {
    const env = await sealKeystoreV4(SK, PK, "pw-old-口令", 4096);
    storeKeystore(env); // 本地面板 v4（解锁走本地真解封）
    meInfo.sealed_blob = JSON.stringify(env);
    await changePassword("pw-old-口令", "pw-new-口令2");
    const body = changeBodies[0] as { sealed_blob: string; masking_key_hex?: string };
    expect(JSON.parse(body.sealed_blob).v).toBe(4);
    expect(body.masking_key_hex, "v4 存量不得携带掩码钥（携带即 422 bad_masking_key）").toBeUndefined();
  }, 60000);

  it("本地面板 v4 残留但服务端已换代 v6（他设备迁移形态）→ 服务端权威判 v6 路径", async () => {
    const env = await sealKeystoreV4(SK, PK, "pw-old-口令", 4096);
    storeKeystore(env);
    meInfo.sealed_blob = JSON.stringify({ v: 6, pk: PK });
    await changePassword("pw-old-口令", "pw-new-口令2");
    const body = changeBodies[0] as { sealed_blob: string; masking_key_hex?: string };
    expect(JSON.parse(body.sealed_blob).v, "服务端密封件版本压过本地面板残留").toBe(6);
    expect(body.masking_key_hex).toMatch(/^[0-9a-f]{64}$/);
  }, 60000);

  it("v6 pilot 改密携资料密封件 → 资料槽重封为 v6 profile 形态（缺陷 B 二层：v4 槽=服务端 400 bad_profile_slot）", async () => {
    // 现实形态：注册期资料槽=v4 口令 KEK 槽（sealProfileSlot——keep 端点无形态门
    // 原样入库）；服务端改密对 v6 账户强制 _normalize_profile_slot_v6（v6 profile
    // 槽=rwd 密封）——前端若原样重发 v4 槽=400（活体走查 rt 账户实弹实证）。
    meInfo.sealed_blob = JSON.stringify({ v: 6, pk: PK });
    meInfo.sealed_profile = JSON.stringify(
      await sealProfileSlot({ cred: { h: 1 }, form: { sn: "FZ-SN-DEV-01" } }, "pw-old-口令", 4096),
    );
    await changePassword("pw-old-口令", "pw-new-口令2");
    expect(changeBodies.length).toBe(1);
    const body = changeBodies[0] as { sealed_profile?: string };
    expect(body.sealed_profile, "v6 改密须回传资料槽").toBeTruthy();
    const slot = JSON.parse(body.sealed_profile!);
    expect(slot.v, "资料槽=v6 形态（服务端 _normalize_profile_slot_v6 契约）").toBe(6);
    expect(slot.slot).toBe("profile");
    expect(slot.enc?.kdf).toBe("opaque-rwd-v1");
    // v6 槽可被新 rwd 解开（roundtrip——载荷完整；rwd=替身 change 材料同源复算）
    const oprfOutput = await finalize(BigInt("0x" + R_DEMO), GOLDEN_RT_BETA);
    const { rwd } = await deriveRwdChain(oprfOutput, "11".repeat(16), 4096);
    const opened = await openProfileSlotV6<{ cred: { h: number } }>(body.sealed_profile!, rwd);
    expect(opened.cred).toEqual({ h: 1 });
  }, 60000);
});
