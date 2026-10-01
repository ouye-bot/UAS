/** 事实源自检：三份 JSON 结构完整（三语言共享，字段缺失早爆）。 */
import sm2v from "../../../backend/app/crypto/vectors/sm2_official.json";
import sm3v from "../../../backend/app/crypto/vectors/sm3_official.json";
import sm4v from "../../../backend/app/crypto/vectors/sm4_official.json";

describe("向量事实源结构自检", () => {
  it("sm3：≥2 官方向量+1 一致性", () => {
    expect(sm3v.vectors.length).toBeGreaterThanOrEqual(2);
    expect(sm3v.extra_consistency.length).toBeGreaterThanOrEqual(1);
    for (const v of sm3v.vectors) expect(v.digest_hex).toMatch(/^[0-9a-f]{64}$/);
  });
  it("sm2：五元组+TS fixture 在场", () => {
    expect(sm2v.verify_digest_vectors.length).toBeGreaterThanOrEqual(1);
    expect(sm2v.ts_parity_fixture.sig_hex).toHaveLength(128);
  });
  it("sm4：ECB+GCM 向量齐全", () => {
    expect(sm4v.ecb_vectors.length).toBeGreaterThanOrEqual(1);
    expect(sm4v.gcm_vectors.length).toBeGreaterThanOrEqual(3);
  });
});
