/** OPAQUE 客户端原语（⑫O-5——设计合同 §3/§2.4/§7.2 选型 A：纯 JS BigInt 群运算
 * + hash-wasm SM3-XMD；与后端 app/crypto/oprf.py / app/accounts/client.py 逐字节
 * 对拍锚定——tests/lib/opaque.test.ts × backend tests/test_accounts_opaque.py 同
 * 向量双端钉死）。
 *
 * 锚分层：独立锚=RFC 9380 K.1 官方 expand_message_xmd(SHA-256) 向量（结构锚，
 * hashFn 参数化）+归约附录 A 的 Z=−9/SSWU 恒等式代数性质；自洽钉=SM2 套件黄金
 * 向量（后端实现生成、双端共享——回归锁）。
 */

import { createSHA256, createSM3, pbkdf2 } from "hash-wasm";

/** 字节统一别名（TS5.7 泛型标注——外部 WASM 库产流为 ArrayBufferLike）。 */
export type Bytes = Uint8Array<ArrayBufferLike>;
import {
  type Point,
  N,
  OpaqueError,
  isOnCurve,
  mulPoint,
  parsePointElement,
  pointToHex,
  randScalar,
} from "./sm2group";

// ---- 常量（设计 §3.1——与后端 app/crypto/oprf.py 逐字同源） ----

export const Z_SSWU = -9n;
export const FIELD_LEN = 48; // hash_to_field 每元素字节（RFC 9380 §5）
export const H2C_COUNT = 2;
export const SECURITY_K_BITS = 128;
export const SM3_OUT_LEN = 32;
export const SM3_BLOCK_LEN = 64;
export const SUITE_ID = "SM2_P256_XMD:SM3_SSWU_RO_";
export const H2C_DST = new TextEncoder().encode("FZ-OPAQUE-V1-" + SUITE_ID);
export const OPRF_INPUT_PREFIX = "FZ-OPAQUE-OPRF|v1";
export const FINALIZE_PREFIX = new TextEncoder().encode("FZ-OPAQUE-Finalize|v1");
export const MASKING_KEY_INFO = new TextEncoder().encode("FZ-OPAQUE-MaskingKey|v1"); // §1.4 ④
export const ENVELOPE_KEY_INFO = new TextEncoder().encode("FZ-OPAQUE-EnvelopeKey|v1"); // §1.4 ⑤
export const MASKING_NONCE_LEN = 32; // RFC 9807 §6.3.1 记账对齐（Nn）
export const NPK = 64; // server_public_key 槽（engine_pub_hex——D-7）

export function oprfInputBytes(username: string, password: string): Uint8Array {
  /** Blind 输入域串（归约 §2.2 逐字）：前缀‖0x00‖username‖0x00‖password。 */
  const enc = new TextEncoder();
  const u = enc.encode(username);
  const p = enc.encode(password);
  const pre = enc.encode(OPRF_INPUT_PREFIX);
  const out = new Uint8Array(pre.length + 1 + u.length + 1 + p.length);
  let off = 0;
  out.set(pre, off);
  off += pre.length;
  out[off++] = 0;
  out.set(u, off);
  off += u.length;
  out[off++] = 0;
  out.set(p, off);
  return out;
}

// ---- SM3（hash-wasm WASM；实例缓存复用——init() 即重置） ----

export async function sm3Bytes(data: Bytes): Promise<Bytes> {
  const h = await createSM3(); // 每调用独立实例——hash-wasm 实例不重入（共享缓存
  // 实例在 vitest 全量并发面下状态互染：Finalize 对拍锚抓出并根修）
  h.init();
  h.update(data);
  return h.digest("binary") as unknown as Uint8Array<ArrayBuffer>;
}

function concat(...arrs: Bytes[]): Bytes {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function xorBytes(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ---- HMAC-SM3 / HKDF（RFC 2104/5869 标准构造——镜像后端 hmac_sm3.py+kdf.py） ----

export async function hmacSm3(key: Bytes, msg: Bytes): Promise<Bytes> {
  let k = key;
  if (k.length > SM3_BLOCK_LEN) k = await sm3Bytes(k);
  const kk = new Uint8Array(SM3_BLOCK_LEN);
  kk.set(k);
  const ipad = kk.map((b) => b ^ 0x36);
  const opad = kk.map((b) => b ^ 0x5c);
  const inner = await sm3Bytes(concat(ipad, msg));
  return sm3Bytes(concat(opad, inner));
}

export async function hkdfSm3Extract(salt: Bytes, ikm: Bytes): Promise<Bytes> {
  const s = salt.length > 0 ? salt : new Uint8Array(SM3_OUT_LEN); // 空盐=HashLen 零串
  return hmacSm3(s, ikm);
}

export async function hkdfSm3Expand(prk: Bytes, info: Bytes, length: number): Promise<Bytes> {
  if (length < 1 || length > 255 * SM3_OUT_LEN) throw new RangeError("HKDF 长度越界");
  const okm = new Uint8Array(length);
  let t: Bytes = new Uint8Array(0);
  let copied = 0;
  let counter = 1;
  while (copied < length) {
    t = await hmacSm3(prk, concat(t, info, new Uint8Array([counter])));
    okm.set(t.subarray(0, Math.min(t.length, length - copied)), copied);
    copied += t.length;
    counter += 1;
  }
  return okm;
}

// ---- expand_message_xmd（RFC 9380 §5.3.1 逐字——hashFn 参数化供官方向量锚） ----

export async function xmdCore(
  msg: Bytes,
  dst: Bytes,
  lenInBytes: number,
  hashBytes: (data: Bytes) => Promise<Bytes>,
  blockLen: number,
): Promise<Uint8Array> {
  const outLen = (await hashBytes(new Uint8Array(0))).length;
  const ell = Math.ceil(lenInBytes / outLen);
  if (lenInBytes < 1 || ell > 255 || lenInBytes > 65535 || dst.length > 255) {
    throw new RangeError("expand_message_xmd 参数越界（RFC 9380 §5.3.1 边界）");
  }
  const dstPrime = concat(dst, new Uint8Array([dst.length]));
  // 步骤 6 逐字：msg_prime = Z_pad ‖ msg ‖ l_i_b_str ‖ I2OSP(0,1) ‖ DST_prime
  // （l_i_b_str 与 DST_prime 间单 0x00 字节不可省——K.1 官方向量锚定实测在案）
  const msgPrime = concat(
    new Uint8Array(blockLen),
    msg,
    new Uint8Array([lenInBytes >> 8, lenInBytes & 0xff]),
    new Uint8Array([0]),
    dstPrime,
  );
  const b0 = await hashBytes(msgPrime);
  let bi = await hashBytes(concat(b0, new Uint8Array([1]), dstPrime));
  const out = new Uint8Array(lenInBytes);
  out.set(bi.subarray(0, Math.min(bi.length, lenInBytes)), 0);
  let copied = Math.min(bi.length, lenInBytes);
  for (let i = 2; i <= ell && copied < lenInBytes; i++) {
    bi = await hashBytes(concat(xorBytes(b0, bi), new Uint8Array([i]), dstPrime));
    const take = Math.min(bi.length, lenInBytes - copied);
    out.set(bi.subarray(0, take), copied);
    copied += take;
  }
  return out;
}

export function expandMessageXmd(msg: Bytes, dst: Bytes, lenInBytes: number): Promise<Bytes> {
  return xmdCore(msg, dst, lenInBytes, sm3Bytes, SM3_BLOCK_LEN);
}

// ---- hash_to_field / SSWU / hash_to_curve（BigInt 代数——与后端同构） ----

export async function hashToField(msg: Bytes, count = H2C_COUNT): Promise<bigint[]> {
  const uniform = await expandMessageXmd(msg, H2C_DST, count * FIELD_LEN);
  const out: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const chunk = uniform.subarray(i * FIELD_LEN, (i + 1) * FIELD_LEN);
    out.push(BigInt("0x" + Array.from(chunk, (b) => b.toString(16).padStart(2, "0")).join("")));
  }
  return out;
}

const P = (() => {
  // 曲线素数（sm2group 同源——此处独立取用以免导入面扩大：SSWU 域参数）
  return 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn;
})();
const A_ = P - 3n;
const B_ = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n;

function inv0(x: bigint): bigint {
  const v = ((x % P) + P) % P;
  return v === 0n ? 0n : powModP(v, P - 2n);
}

function powModP(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = ((base % P) + P) % P;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

function isSquare(v: bigint): boolean {
  const x = ((v % P) + P) % P;
  return x === 0n || powModP(x, (P - 1n) / 2n) === 1n;
}

function fpSqrt(v: bigint): bigint {
  const r = powModP(v, (P + 1n) / 4n); // p ≡ 3 (mod 4)
  if ((r * r) % P !== ((v % P) + P) % P) throw new OpaqueError("sqrt_not_square", "平方根输入非平方");
  return r;
}

/** SSWU 候选对与 t（RFC 9380 §6.6.2；Z=−9 四准则注释链见后端镜像）。 */
export function sswuXCandidates(u: bigint): {
  t: bigint;
  x1: bigint;
  gx1: bigint;
  x2: bigint;
  gx2: bigint;
} {
  const p = P;
  const uu = ((u % p) + p) % p;
  const tv1 = (((Z_SSWU % p) * uu) % p * uu) % p; // Z·u²
  const t = (tv1 * tv1 + tv1) % p;
  let x1 = inv0(t);
  if (t === 0n) {
    x1 = (-powModP(Z_SSWU, p - 2n) + p) % p; // CMOV：−1/Z ⟹ x1=B/(Z·A)
  } else {
    x1 = (x1 + 1n) % p;
  }
  const c1 = (((-B_) % p) * powModP(A_, p - 2n)) % p; // −B/A
  x1 = (((x1 * c1) % p) + p) % p;
  const gx1 = (x1 * x1 * x1 + A_ * x1 + B_) % p;
  const x2 = (tv1 * x1) % p;
  const gx2 = (x2 * x2 * x2 + A_ * x2 + B_) % p;
  const norm = (v: bigint) => ((v % p) + p) % p;
  return { t: norm(t), x1: norm(x1), gx1: norm(gx1), x2: norm(x2), gx2: norm(gx2) };
}

export function mapToCurveSswu(u: bigint): Point {
  const p = P;
  const uu = ((u % p) + p) % p;
  const { x1, gx1, x2, gx2 } = sswuXCandidates(uu);
  let gv: bigint;
  let x: bigint;
  if (isSquare(gx1)) {
    x = x1;
    gv = gx1;
  } else {
    x = x2;
    gv = gx2;
  }
  let y = fpSqrt(gv);
  if (y % 2n !== uu % 2n) y = p - y; // sgn0(y)=sgn0(u)
  return { x: ((x % p) + p) % p, y: ((y % p) + p) % p };
}

function pointAddP(p1: Point, p2: Point): Point {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const { x: x1, y: y1 } = p1;
  const { x: x2, y: y2 } = p2;
  if (x1 === x2 && (y1 + y2) % P === 0n) return null;
  let lam: bigint;
  if (x1 === x2 && y1 === y2) {
    lam = ((3n * x1 * x1 + A_) * inv0((2n * y1) % P)) % P;
  } else {
    lam = ((y2 - y1) * inv0(x2 - x1)) % P;
  }
  const x3 = (((lam * lam - x1 - x2) % P) + P) % P;
  return { x: x3, y: (((lam * (x1 - x3) - y1) % P) + P) % P };
}

export async function hashToCurve(msg: Bytes): Promise<Point> {
  const [u0, u1] = await hashToField(msg, H2C_COUNT);
  const r = pointAddP(mapToCurveSswu(u0), mapToCurveSswu(u1));
  if (r === null) throw new OpaqueError("h2c_infinity", "hash_to_curve 命中无穷远点");
  return r;
}

// ---- Blind / Finalize（归约 §2.2——r CSPRNG；O-2 校验先行） ----

export async function blind(username: string, password: string): Promise<{ alphaHex: string; r: bigint }> {
  const pt = await hashToCurve(oprfInputBytes(username, password));
  const r = randScalar();
  const alpha = mulPoint(r, pt);
  return { alphaHex: pointToHex(alpha), r };
}

/** 客户端 Finalize：O-2 校验 β → Y=[r⁻¹]β → oprf_output=Extract("", 域串‖Y)。
 * 域串不含 input（归约 §2.2/瑕疵 f 适配注记）。 */
export async function finalize(r: bigint, betaHex: string): Promise<Bytes> {
  const beta = parsePointElement(betaHex); // O-2——对偶面（恶意服务端非曲线点）
  const rInv = powModN(r, N - 2n);
  const y = mulPoint(rInv, { x: beta.x, y: beta.y });
  const yHex = pointToHex(y);
  const yBytes = new Uint8Array(64) as Bytes;
  for (let i = 0; i < 64; i++) yBytes[i] = parseInt(yHex.slice(i * 2, i * 2 + 2), 16);
  const ikm = concat(FINALIZE_PREFIX, yBytes);
  return hkdfSm3Extract(new Uint8Array(0), ikm);
}

function powModN(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = ((base % N) + N) % N;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % N;
    b = (b * b) % N;
    e >>= 1n;
  }
  return result;
}

// ---- rwd 单链（§1.4 ②③④——唯一公式；改链=整体替换+重走评审） ----

export const STRETCHED_LEN = 32; // D-10

export async function deriveRwdChain(
  oprfOutput: Uint8Array,
  saltHex: string,
  iterations: number,
): Promise<{ rwd: Bytes; maskingKey: Bytes }> {
  const stretched = await pbkdf2({
    password: oprfOutput,
    salt: hexToBytesLocal(saltHex),
    iterations,
    hashLength: STRETCHED_LEN,
    hashFunction: createSM3(),
    outputType: "binary",
  });
  const rwd = await hkdfSm3Extract(new Uint8Array(0), concat(oprfOutput, stretched));
  const maskingKey = await hkdfSm3Expand(rwd, MASKING_KEY_INFO, 32);
  return { rwd, maskingKey };
}

export function kekFromRwd(rwd: Bytes, envNonceHex: string): Promise<Bytes> {
  return hkdfSm3Expand(rwd, concat(hexToBytesLocal(envNonceHex), ENVELOPE_KEY_INFO), 16);
}

// ---- masked_response 解掩码（§5.4/§6.3——pad 记式逐字） ----

export async function credentialResponsePad(
  maskingKey: Bytes,
  maskingNonce: Bytes,
  payloadLen: number,
): Promise<Bytes> {
  const info = concat(maskingNonce, new TextEncoder().encode("MaskedResponse"));
  const pad = await hkdfSm3Expand(maskingKey, info, NPK + MASKING_NONCE_LEN + payloadLen);
  return pad.subarray(0, NPK + payloadLen);
}

/** 解掩码取 envelope（JS 档无 server_pub 先验——前缀等式断言省略，错口令判据
 * =信封形态/GCM（与 Python 参考实现的前缀判据同 UX——人话判词在调用层）。 */
export async function unmaskCredentialResponse(
  maskingKey: Bytes,
  maskingNonce: Bytes,
  masked: Bytes,
): Promise<Bytes> {
  if (masked.length <= NPK) throw new OpaqueError("bad_mask", "masked_response 长度非法");
  const pad = await credentialResponsePad(maskingKey, maskingNonce, masked.length - NPK);
  const payload = xorBytes(pad, masked);
  return payload.subarray(NPK);
}

function hexToBytesLocal(hex: string): Bytes {
  if (hex.length % 2) throw new OpaqueError("bad_hex", "hex 长度须为偶数");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
