/** 三语言对拍 TS 面：SM4 ECB（GB/T 32907 A）+ SM4-GCM 加解密（RFC 8998 A.1 / GB/T 36624 C.5）。 */
import { sm4 } from "sm-crypto";
import { GcmAuthError, hexToBytes, sm4GcmDecrypt, sm4GcmEncrypt } from "../src/crypto/sm4gcm";
import official from "../../../backend/app/crypto/vectors/sm4_official.json";

const toHex = (u8: Uint8Array) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

describe("SM4-ECB 官方向量（GB/T 32907 附录 A，sm-crypto，字节数组+padding=none 单块）", () => {
  it.each(official.ecb_vectors)("$name", ({ key_hex, pt_hex, ct_hex }) => {
    // sm-crypto 字符串入参按 utf8 原始字节处理（非 hex 解码，探针定谳）——必须传数组
    const out = sm4.encrypt(
      Array.from(hexToBytes(pt_hex.toLowerCase())),
      Array.from(hexToBytes(key_hex.toLowerCase())),
      { padding: "none" },
    );
    expect(out.toUpperCase()).toBe(ct_hex.toUpperCase());
  });
});

describe("SM4-GCM 官方向量（自研 sm4gcm.ts：解密+加密双向）", () => {
  it.each(official.gcm_vectors)("$name", ({ key_hex, iv_hex, aad_hex, pt_hex, ct_hex, tag_hex }) => {
    const pt = sm4GcmDecrypt(
      hexToBytes(key_hex),
      hexToBytes(iv_hex),
      hexToBytes(ct_hex),
      hexToBytes(tag_hex),
      hexToBytes(aad_hex),
    );
    expect(toHex(pt).toUpperCase()).toBe(pt_hex.toUpperCase());

    const enc = sm4GcmEncrypt(hexToBytes(key_hex), hexToBytes(iv_hex), hexToBytes(pt_hex), hexToBytes(aad_hex));
    expect(toHex(enc.ciphertext).toUpperCase()).toBe(ct_hex.toUpperCase());
    expect(toHex(enc.tag).toUpperCase()).toBe(tag_hex.toUpperCase());
  });

  it("负例：篡改 tag 解密必须抛 GcmAuthError", () => {
    const v = official.gcm_vectors[0];
    const badTag = hexToBytes(v.tag_hex);
    badTag[0] ^= 1;
    expect(() =>
      sm4GcmDecrypt(hexToBytes(v.key_hex), hexToBytes(v.iv_hex), hexToBytes(v.ct_hex), badTag, hexToBytes(v.aad_hex)),
    ).toThrow(GcmAuthError);
  });

  it("负例：篡改密文解密必须抛 GcmAuthError", () => {
    const v = official.gcm_vectors[0];
    const badCt = hexToBytes(v.ct_hex);
    badCt[0] ^= 1;
    expect(() =>
      sm4GcmDecrypt(hexToBytes(v.key_hex), hexToBytes(v.iv_hex), badCt, hexToBytes(v.tag_hex), hexToBytes(v.aad_hex)),
    ).toThrow(GcmAuthError);
  });
});
