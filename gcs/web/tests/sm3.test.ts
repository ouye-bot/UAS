/** 三语言对拍 TS 面：SM3 官方向量（sm-crypto）× 事实源 JSON。
 * sm-crypto sm3() 字符串入参按 utf8 处理——此处传字节数组保证字节精确（hex 语义）。 */
import { sm3 } from "sm-crypto";
import official from "../../../backend/app/crypto/vectors/sm3_official.json";

const hexToBytesArr = (hex: string): number[] =>
  (hex.match(/../g) ?? []).map((b) => parseInt(b, 16));

const all = [...official.vectors, ...official.extra_consistency];

describe("SM3 官方向量对拍（GB/T 32905 A.1/A.2 + 一致性）", () => {
  it.each(all)("$name", ({ name, msg_hex, digest_hex }) => {
    expect(sm3(hexToBytesArr(msg_hex))).toBe(digest_hex.toLowerCase());
    void name;
  });

  it("向量数≥3（A.1/A.2/空消息）", () => {
    expect(all.length).toBeGreaterThanOrEqual(3);
  });
});
