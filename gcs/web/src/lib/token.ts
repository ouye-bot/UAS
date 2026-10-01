/** 令牌面（B8）：回执取件解密（SM2 ECIES）+ 引擎验签（裸摘要 SM2）。
 *
 * 口径锚（与后端/桥接逐字节同构，tests/lib/token.test.ts 跨语言钉定）：
 * - 封发 payload = token_body + "|" + sig_hex（B4 seal_receipt 同式）
 * - token_body = json.dumps(sort_keys=True, 紧凑)——签名对象
 * - e = SM3(body UTF-8) 直接入 SM2 方程（裸摘要，无 ZA——engine sign_digest 同口径）
 * - ECIES C1C3C2；后端 C1 为 64B 裸 x||y（无 04 前缀）——sm-crypto 需补 "04"
 */
import { sm2, sm3 } from "sm-crypto";
import { ApiError } from "./api";

export interface TokenPayload {
  tok: Record<string, any>;
  sig: string;
  body: string;
}

export interface TokenFields {
  authId: number;
  plan_hash: string;
  alt_max: number;
  t_start: number;
  t_end: number;
  nonce: string;
  policy_version: string;
}

/** 后端 json.dumps(separators=(",",":"), sort_keys=True) 的 TS 等价。
 * 注意 Python 默认 ensure_ascii=True——非 ASCII 字符须转 \uXXXX（跨语言逐字符一致锚定）。 */
export function canonicalTokenBody(tok: Record<string, any>): string {
  const keys = Object.keys(tok).sort();
  const esc = (v: any): string => {
    const s = JSON.stringify(v);
    // JSON.stringify 不转义非 ASCII——补 Python ensure_ascii 形态（代理对按码元逐个转义）
    return s.replace(/[\u0080-\uffff]/g, (ch) =>
      "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"),
    );
  };
  const parts = keys.map((k) => `${esc(k)}:${esc(tok[k])}`);
  return "{" + parts.join(",") + "}";
}

/** 回执取件：ECIES 解密 + 拆分 body|sig。
 * 🔴 sm-crypto doDecrypt 内部自加 "04" 前缀（源码 decodePointHex('04'+C1)）——
 * 后端 C1 本就是裸 64B x||y，原样传 hex，禁再补前缀。 */
export function pickupToken(cipherHex: string, sessionSkHex: string): TokenPayload {
  const data = cipherHex.trim().toLowerCase().replace(/^0x/, "");
  let plain: string | null = null;
  try {
    plain = sm2.doDecrypt(data, sessionSkHex.replace(/^0x/, ""), 1, { output: "string" }) as unknown as string;
  } catch (e) {
    throw new ApiError("decrypt_failed", `会话钥解密失败（密文/私钥不匹配）: ${String(e)}`, 0);
  }
  if (!plain || plain.indexOf("|") < 0) {
    throw new ApiError("decrypt_failed", "解密结果形态非法（缺 body|sig 分隔——密文或私钥不匹配）", 0);
  }
  const idx = plain.lastIndexOf("|");
  const body = plain.slice(0, idx);
  const sig = plain.slice(idx + 1);
  return { tok: JSON.parse(body), sig, body };
}

/** 引擎验签：e=SM3(规范 body)，裸摘要口径。
 * 公钥须带 "04" 非压缩前缀（后端 pubkey 128hex=x‖y 裸形态——decodePointHex 需 04）。 */
export function verifyTokenSig(body: string, sigHex: string, enginePubHex: string): boolean {
  try {
    const pub = enginePubHex.replace(/^0x/, "").toLowerCase();
    const full = pub.startsWith("04") ? pub : "04" + pub;
    const eHex = sm3(body); // string 入参=utf8 原始字节（B0 教训㊻）
    // 🔴 doVerifySignature 对 string 入参会再做 utf8 编码（源码 172 行）——
    // 裸摘要必须以字节数组传入，否则双重编码错 e。
    const eBytes = Array.from(eHex.match(/.{2}/g) ?? [], (h) => Number.parseInt(h, 16));
    return sm2.doVerifySignature(eBytes as any, sigHex.toLowerCase(), full, { hash: false, der: false });
  } catch {
    return false;
  }
}

/** 五查（与 bridge verify_token 同构的浏览器侧预检——展示层先行，链路仍以 bridge 为权威）。 */
export function checkTokenFields(
  tok: Record<string, any>,
  planHashHex: string,
  nowSec: number,
): string[] {
  const errs: string[] = [];
  for (const f of ["authId", "plan_hash", "alt_max", "t_start", "t_end", "nonce", "policy_version"]) {
    if (!(f in tok)) errs.push(`缺字段 ${f}`);
  }
  if (errs.length) return errs;
  const t = tok as unknown as TokenFields;
  if (!(t.t_start <= nowSec && nowSec <= t.t_end)) errs.push(`令牌窗外 [${t.t_start},${t.t_end}] vs ${nowSec}`);
  if (t.plan_hash !== planHashHex) errs.push("plan_hash 与本机计划不一致");
  if (t.nonce.length !== 32) errs.push("nonce 形态非法");
  return errs;
}

/** 令牌 payload bytes（bridge /arm 消费形态）：body|sig 的 UTF-8 hex。 */
export function tokenPayloadHex(p: TokenPayload): string {
  const bytes = new TextEncoder().encode(p.body + "|" + p.sig);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
