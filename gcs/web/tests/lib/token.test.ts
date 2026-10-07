/** 令牌面跨语言测试（B8-T2）：后端 Python 封发 ↔ 浏览器端解密+验签。
 * fixture 由 backend venv 生成（test../fixtures/token_fixture.json）——
 * ECIES C1C3C2（后端 C1 无 04 前缀）+ 裸摘要 SM2 验签 + 规范化 body。 */
import { pickupToken, verifyTokenSig, canonicalTokenBody, quotaExhausted } from "../../src/lib/token";
import fixture from "../fixtures/token_fixture.json";

describe("token 跨语言（Py 封发 ↔ TS 解密验签）", () => {
  it("pickupToken：ECIES 解密出 token_body|sig 并字段齐全", () => {
    const payload = pickupToken(fixture.token_cipher_hex, fixture.session_sk_hex);
    expect(payload.body).toBe(fixture.token_body);
    expect(payload.sig).toBe(fixture.sig_hex);
    expect(payload.tok.authId).toBe(7);
    expect(payload.tok.alt_max).toBe(120);
    expect(payload.tok.nonce).toHaveLength(32);
  });

  it("canonicalTokenBody：与后端 json.dumps(sort_keys,紧凑) 逐字符一致", () => {
    const tok = JSON.parse(fixture.token_body);
    expect(canonicalTokenBody(tok)).toBe(fixture.token_body);
  });

  it("verifyTokenSig：engine 签名通过（e=SM3(规范 body) 裸摘要口径）", () => {
    expect(verifyTokenSig(fixture.token_body, fixture.engine_sig_hex, fixture.engine_pub_hex)).toBe(true);
  });

  it("verifyTokenSig：body 篡改 1 字符必拒（alt_max 改 1）", () => {
    const bad = fixture.token_body.replace('"alt_max":120', '"alt_max":121');
    expect(bad).not.toBe(fixture.token_body);
    expect(verifyTokenSig(bad, fixture.engine_sig_hex, fixture.engine_pub_hex)).toBe(false);
  });
});

describe("授权包配额（2026-10-06 多架次拍板）：quotaExhausted 判定", () => {
  it("remaining 权威在场：>0 未耗尽（多架次续飞按钮可点）", () => {
    expect(quotaExhausted(true, 2)).toBe(false);
    expect(quotaExhausted(true, 1)).toBe(false);
  });
  it("remaining==0 耗尽（最后一次架次回报后的终态）", () => {
    expect(quotaExhausted(true, 0)).toBe(true);
    // 未解锁过=谈不上耗尽
    expect(quotaExhausted(false, 0)).toBe(false);
  });
  it("remaining 缺省（旧桥/查询失败）=used 即耗尽（令牌一次性原语义兼容）", () => {
    expect(quotaExhausted(true, null)).toBe(true);
    expect(quotaExhausted(false, null)).toBe(false);
  });
});
