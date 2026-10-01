/** SM2 TS 面：自洽 roundtrip（跨语言互操作由 Python 侧 ts_parity_fixture 锚——
 * sm-crypto verify 侧与 sign 不同源为旧系统已定谳边界，跨语言方向只测 TS→Py）。 */
import { sm2 } from "sm-crypto";

describe("SM2 自洽 roundtrip", () => {
  it("生成-签名-验证（默认 userId，hash 模式）", () => {
    const keypair = sm2.generateKeyPairHex();
    expect(keypair.privateKey.length).toBe(64);
    // sm-crypto 公钥带 04 未压缩前缀（04‖x‖y=130 hex）
    expect(keypair.publicKey.length).toBe(130);
    expect(keypair.publicKey.startsWith("04")).toBe(true);
    const msg = "feizheng-b0-parity";
    const sig = sm2.doSignature(msg, keypair.privateKey, { hash: true });
    expect(sig.length).toBe(128);
    expect(sm2.doVerifySignature(msg, sig, keypair.publicKey, { hash: true })).toBe(true);
    expect(sm2.doVerifySignature(msg + "x", sig, keypair.publicKey, { hash: true })).toBe(false);
  });
});
