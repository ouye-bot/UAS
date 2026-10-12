/** OPAQUE 客户端原语测试（⑫O-5——设计 §3/§7.2；JS↔PY 对拍锚）。
 *
 * 锚分层（与 backend tests/test_accounts_opaque.py 同向量双端钉死——漂移双向
 * 即红）：独立锚=RFC 9380 K.1 官方 expand_message_xmd(SHA-256) 向量（2026-10-12
 * rfc-editor 拉取）+SSWU 恒等式/例外锚代数性质；自洽钉=SM2 套件黄金向量
 * （后端实现生成——RT 回环/客户端链/v6 信封定长锚）。 */

import { createSHA256 } from "hash-wasm";
import { describe, expect, it } from "vitest";
import { canonicalV6, openEnvelopeV6, sealEnvelopeV6, standardV6EnvelopeLen } from "../../src/lib/keystore";
import {
  credentialResponsePad,
  expandMessageXmd,
  finalize,
  hashToCurve,
  H2C_DST,
  mapToCurveSswu,
  unmaskCredentialResponse,
  xmdCore,
} from "../../src/lib/opaque";
import {
  isOnCurve,
  mulPoint,
  parsePointElement,
  pointToHex,
  randScalar,
} from "../../src/lib/sm2group";

const P_SM2_GROUP = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn;

// 后端 P_SM2（tests/test_crypto_opaque.py 同源）
const P_SM2 = 2n ** 256n - 2n ** 224n - 2n ** 96n + 2n ** 64n - 1n;

// 归约附录 A 锚点（后端 tests/test_crypto_opaque.py 同钉——JS 镜像）
const GOLDEN_H2C =
  "60f589fb5942265c25b2963a69e8dbfd5c75b7e7a59e2dcbba6d55003f324de9" +
  "2bb48167237ffeff262edd48e80f99c72e955e912a75482a38292dfe8b5fccd2";
const GOLDEN_SSWU: Record<number, string> = {
  1: "b8e2fb07009096cb94b7092ebe8202a125bdbc5ffe162b4d283740595eb2fe55685c894241c17539db345e5bf7357770a831e1d39ce8e9f7c99775790eed4169",
  2: "8a773b4a812deb13356fd6ab70bbc7b0eacb45cab3ed72be02cad09bad51278970a436d98d5a3f1d4eb146f03267c023a8355789f922bae2a7530997aa5eaeb8",
};
const GOLDEN_RT_BETA =
  "94fc9dae4e6934b980939f2eedbacd6c616ab1b1d5d1d5ac7a17ed0d47fcd7d9a" +
  "70ee9da0f70923b35024a0fc26406b074ccab004c8eaaade363c257651c9ac0";
const GOLDEN_RT_OUT = "6b0664b3a33c12236efb1a166fd0fa9213e1fc52b9603e004161c98b38167c3c";
const GOLDEN_XMD_96 =
  "2d7b607522ed5a75906be92e0b3df13d0ee0bd515f081439eda2233efe65e9529c42a801e5bce009e629e7086b3e07396e2" +
  "5b14c50b1fa68a65a182cb0fd1d0064582b916652a613364b2794be933315db7afbc48e0143aa866534ec56c39ec3";
const R_DEMO = "17".repeat(32);

// RFC 9380 附录 K.1 官方向量（expand_message_xmd, SHA-256, DST=QUUX-…）
const RFC_DST_QUUX = new TextEncoder().encode("QUUX-V01-CS02-with-expander-SHA256-128");
const RFC_XMD_VECTORS: Array<[Uint8Array, number, string]> = [
  [new Uint8Array(0), 0x20, "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"],
  [new TextEncoder().encode("abc"), 0x20, "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"],
  [
    new Uint8Array(0),
    0x80,
    "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee" +
      "0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda85" +
      "76c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3" +
      "491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
  ],
];

// 客户端链黄金钉（后端 GOLDEN_CHAIN 同钉——双端镜像）
const GOLDEN_RWD = "50f44fea224e94bc7c5f1ede0e946078e4300d27310d84c9710b0c2e9f8cd1b8";
const GOLDEN_MASKING_KEY = "c2dc3b71cf96db31e9a0f31b82921ae5efb69e576c8e9e14fb0c34e2d667d341";
const GOLDEN_MASKED =
  "aa49f8616ea1abebe3cc319d5a1b36d0eaac42c65e0f75fcf6182b8dc12987f557a55890deeefe984aff3659221066e65d3a39f0769e7e18e1315cbf57650a87c6c5defb7c8255f4dc68576b869462e2fb3285d8d1422cde9ba8fb567b36c8d4829411f81c27fa116c53a16e97cfffd696f315763fc1ad923835fc2a5e3fa0ae1214f49170684dd03207bc7025940e9871544a8357c0012db4af2b630588e6e9c5fa8e4c521b2ef08e83b29325cb14ebc887ab1d51c36dc044d76b27e0aa3a2b2560ef3ab03676cf25cb401e01ef88aefd27369a202d4b00e7d3b429851639edf186a0384ed9ee907a031a57a1034e08b7ef7463331bdc3b68b66939f84e99ad23005d3c029e2f2e7639e948aeb049e2623bc7abe2925043df28a8dfbc65798cbdb39762e66fdb759959a8127bd6197753a90161156af1c4092d48bdfecafe36ecbcb39281807b8f74dd9b11d281036b6e643e24176f19513aa48a6c93cae345e60198d23b031f6eb8f1742fbe6d5f69e95c48fcb8bf96c62c14446af4b05e84d9413b6660d59baa492a680301552537cae53fdb9ef55622e2b94aad2a07c2e6a52d6e7c0b90ff05";
const GOLDEN_SERVER_PUB =
  "064bc3ac38298569bffb83e84042ff93389816c2042de5fc1285f3d76e3c458060612430734bff243a00eaa51663e947ed1ed6ee9a0c28007338d99759a7626d";
const GOLDEN_ENV =
  '{"v":6,"pk":"' +
  "11".repeat(64) +
  '","enc":{"kdf":"opaque-rwd-v1","env_nonce":"' +
  "ab".repeat(12) +
  '","nonce":"' +
  "cd".repeat(12) +
  '","ct":"38d4c0b211076ffd88029958d437251bf540c1470ac1d9af4d9073acc9dd7509","tag":"790a853428b159016adb4a834d1e3b5b"}}';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe("OPAQUE 客户端原语（⑫O-5——JS↔PY 对拍锚）", () => {
  it("expand_message_xmd RFC 9380 K.1 官方向量（SHA-256，3 例含多块）", async () => {
    for (const [msg, len, expectHex] of RFC_XMD_VECTORS) {
      const out = await xmdCore(msg, RFC_DST_QUUX, len, async (d) => {
        const h = await createSHA256();
        h.init();
        h.update(d);
        return h.digest("binary") as Uint8Array;
      }, 64);
      expect((out as Uint8Array).length).toBe(len);
      expect(Array.from(out as Uint8Array, (b) => b.toString(16).padStart(2, "0")).join("")).toBe(expectHex);
    }
  });

  it("xmd-SM3 套件黄金钉（96B 定长）+越界拒绝", async () => {
    const out = await expandMessageXmd(new TextEncoder().encode("abc"), H2C_DST, 96);
    expect(out.length).toBe(96);
    expect(Array.from(out, (b) => b.toString(16).padStart(2, "0")).join("")).toBe(GOLDEN_XMD_96);
    await expect(expandMessageXmd(new TextEncoder().encode("abc"), new TextEncoder().encode("D".repeat(256)), 96)).rejects.toThrow();
    await expect(expandMessageXmd(new TextEncoder().encode("abc"), H2C_DST, 65536)).rejects.toThrow();
  });

  it("SSWU 黄金钉（u=1/2）+on-curve+sgn0", () => {
    for (const [u, expectHex] of Object.entries(GOLDEN_SSWU)) {
      const pt = mapToCurveSswu(BigInt(u));
      expect(pointToHex(pt)).toBe(expectHex);
      expect(isOnCurve(pt)).toBe(true);
      expect((pt as { x: bigint; y: bigint }).y % 2n).toBe(BigInt(u) % 2n);
    }
  });

  it("hash_to_curve 黄金钉+确定性", async () => {
    const msg = new TextEncoder().encode("FZ-OPAQUE-OPRF|v1\x00vector-user\x00vector-password");
    const pt = await hashToCurve(msg);
    expect(pointToHex(pt)).toBe(GOLDEN_H2C);
    expect(await hashToCurve(msg)).toEqual(pt);
  });

  it("Client Finalize 黄金钉（固定 r+钉定 β）→oprf_output", async () => {
    const out = await finalize(BigInt("0x" + R_DEMO), GOLDEN_RT_BETA);
    expect(Array.from(out, (b) => b.toString(16).padStart(2, "0")).join("")).toBe(GOLDEN_RT_OUT);
  });

  it("O-2 负例：非曲线点/域外坐标/长度违规=拒", () => {
    const good = parsePointElement(GOLDEN_H2C);
    expect(() => parsePointElement("zz".repeat(64))).toThrow();
    expect(() => parsePointElement("1".repeat(127))).toThrow();
    expect(() => parsePointElement(pointToHex({ x: P_SM2_GROUP, y: good.y }))).toThrow();
    expect(() => parsePointElement(pointToHex({ x: good.x, y: (good.y + 1n) % P_SM2_GROUP }))).toThrow();
  });

  it("盲化因子 CSPRNG：两次 blind 标量互异且在域内", async () => {
    const a = randScalar();
    const b = randScalar();
    expect(a).not.toBe(b);
    expect(a >= 1n && a <= P_SM2_GROUP).toBe(true);
    void mulPoint;
  });

  it("rwd 单链黄金钉（D-8/D-10——600k PBKDF2）", { timeout: 20_000 }, async () => {
    const { rwd, maskingKey } = await deriveRwdChainPinned();
    expect(rwd).toBe(GOLDEN_RWD);
    expect(maskingKey).toBe(GOLDEN_MASKING_KEY);
  });

  it("masked_response 解掩码黄金钉（§6.3 pad 记式）", async () => {
    const maskingKey = hexToBytes(GOLDEN_MASKING_KEY);
    const nonce = hexToBytes("aa".repeat(32));
    const masked = hexToBytes(GOLDEN_MASKED);
    const pad = await credentialResponsePad(maskingKey, nonce, masked.length - 64);
    expect(pad.length).toBe(masked.length);
    const envelope = await unmaskCredentialResponse(maskingKey, nonce, masked);
    const envText = new TextDecoder().decode(envelope);
    expect(envText).toBe(GOLDEN_ENV);
    expect(JSON.parse(envText).enc.kdf).toBe("opaque-rwd-v1");
  });

  it("v6 信封定长锚+规范形态+钉定 nonce 密封/解封回环", async () => {
    expect(standardV6EnvelopeLen()).toBe(GOLDEN_ENV.length);
    expect(canonicalV6("11".repeat(64), "ab".repeat(12), "cd".repeat(12), "22".repeat(32), "33".repeat(16))).toBe(
      canonicalV6("11".repeat(64), "ab".repeat(12), "cd".repeat(12), "22".repeat(32), "33".repeat(16)),
    );
    const rwd = hexToBytes(GOLDEN_RWD);
    const env = await sealEnvelopeV6("ab".repeat(32), "11".repeat(64), rwd, "ab".repeat(12), "cd".repeat(12));
    expect(JSON.stringify(env)).toBe(GOLDEN_ENV);
    const sk = await openEnvelopeV6(JSON.parse(GOLDEN_ENV), rwd);
    expect(sk).toBe("ab".repeat(32));
    // 错 rwd=GCM 认证失败（人话判词源）
    await expect(openEnvelopeV6(JSON.parse(GOLDEN_ENV), hexToBytes("99".repeat(32)))).rejects.toThrow();
  });
});

// deriveRwdChain 的 600k 钉定入口（原函数为纯 Uint8Array 链——此处包 hex 面）
import { deriveRwdChain as deriveRwdChainRaw } from "../../src/lib/opaque";

async function deriveRwdChainPinned(): Promise<{ rwd: string; maskingKey: string }> {
  const oprfOutput = hexToBytes(GOLDEN_RT_OUT);
  const { rwd, maskingKey } = await deriveRwdChainRaw(oprfOutput, "4e".repeat(16), 600_000);
  return {
    rwd: Array.from(rwd, (b) => b.toString(16).padStart(2, "0")).join(""),
    maskingKey: Array.from(maskingKey, (b) => b.toString(16).padStart(2, "0")).join(""),
  };
}
