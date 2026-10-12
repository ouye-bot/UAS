/** SM2 群运算（BigInt——⑫O-5 前端盲化，OPAQUE 实施设计 §7.2 选型 A）。
 *
 * 唯一协议依据：docs/SM2-OPAQUE归约论证-修订版.md（GO，8a10595）§2/§3 +
 * docs/OPAQUE实施设计.md（e1bc5d1）§3/§7.2。曲线常量与后端 gmssl
 * default_ecc_table 同源（GB/T 32918；禁手抄差异——JS 侧以字面量钉定并经
 * JS↔PY 对拍锚验证：tests/lib/opaque.test.ts × backend tests/test_accounts_opaque.py）。
 *
 * 纪律（设计 §2.4/§7.2）：
 * - O-2（客户端）：Finalize 前 β 完整校验（128hex/坐标 ∈ F_p/曲线方程）——
 *   恶意服务端回非曲线点的对偶面（无效曲线防线），fail-closed；
 * - 盲化因子 r ←$ Z_n*（crypto.getRandomValues 拒绝采样——CSPRNG 红线，
 *   Math.random 禁用）；r 为会话一次性随机、用后即焚，浏览器 JS 档非恒时
 *   实现的时序面=同源页面上下文（G6 客户端档注记——设计 §7.2 如实）。
 */

export class OpaqueError extends Error {
  constructor(
    public code: string,
    message = "",
  ) {
    super(message || code);
  }
}

export const P = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn;
export const A = P - 3n; // a=−3 (mod p)——SSWU 直落适用
export const B = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n;
export const N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n; // GB/T n（64 hex——字面量曾多一组 ffffffff=288bit 错值，RT 对拍锚抓出并根修）
const GX = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n;
const GY = 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n;

export type Point = { x: bigint; y: bigint } | null; // null=无穷远

export function modInverse(x: bigint, p: bigint): bigint {
  const r = powMod(((x % p) + p) % p, p - 2n, p);
  return r;
}

export function powMod(base: bigint, exp: bigint, p: bigint): bigint {
  let result = 1n;
  let b = ((base % p) + p) % p;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % p;
    b = (b * b) % p;
    e >>= 1n;
  }
  return result;
}

export function pointAdd(p1: Point, p2: Point): Point {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const { x: x1, y: y1 } = p1;
  const { x: x2, y: y2 } = p2;
  if (x1 === x2 && (y1 + y2) % P === 0n) return null;
  let lam: bigint;
  if (p1 === p2 || (x1 === x2 && y1 === y2)) {
    lam = ((3n * x1 * x1 + A) * modInverse(2n * y1, P)) % P;
  } else {
    lam = ((y2 - y1) * modInverse(x2 - x1, P)) % P;
  }
  // 归一化到 [0, P)——JS BigInt % 保留负号（Python % 恒正——对拍锚必要求）
  const x3 = (((lam * lam - x1 - x2) % P) + P) % P;
  const y3 = (((lam * (x1 - x3) - y1) % P) + P) % P;
  return { x: x3, y: y3 };
}

export function scalarMult(k: bigint, pt: Point): Point {
  let result: Point = null;
  let base = pt;
  let e = k;
  while (e > 0n) {
    if (e & 1n) result = pointAdd(result, base);
    base = pointAdd(base, base);
    e >>= 1n;
  }
  return result;
}

export function isOnCurve(pt: Point): boolean {
  if (pt === null) return false;
  const { x, y } = pt;
  return (y * y - (x * x * x + A * x + B)) % P === 0n;
}

/** 仿射点 → 128 hex（x‖y，各 64 hex 大端）。 */
export function pointToHex(pt: Point): string {
  if (pt === null) throw new OpaqueError("point_infinity", "无穷远点无 128hex 表示");
  const x = ((pt.x % P) + P) % P;
  const y = ((pt.y % P) + P) % P;
  return x.toString(16).padStart(64, "0") + y.toString(16).padStart(64, "0");
}

export function parsePointElement(hex128: string): { x: bigint; y: bigint } {
  /** O-1/O-2 群元素完整校验（归约 §2.3 前置条件——客户端侧 O-2 对偶面）：
   * 128 hex / 坐标 ∈ F_p / 曲线方程；无穷远无表示（长度门即拒）。 */
  if (typeof hex128 !== "string" || !/^[0-9a-fA-F]{128}$/.test(hex128)) {
    throw new OpaqueError("invalid_point", "群元素须 128 hex（x‖y）");
  }
  const x = BigInt("0x" + hex128.slice(0, 64));
  const y = BigInt("0x" + hex128.slice(64));
  if (x >= P || y >= P) throw new OpaqueError("invalid_point", "群元素坐标超出 F_p 域");
  if ((y * y - (x * x * x + A * x + B)) % P !== 0n) {
    throw new OpaqueError("invalid_point", "群元素不在 SM2 曲线上（无效曲线拒绝）");
  }
  return { x, y };
}

/** 标量域校验：∈ Z_n*=[1, n−1]（0/域外——错域拒 fail-closed）。 */
export function validateScalar(d: bigint): bigint {
  if (d < 1n || d > N - 1n) throw new OpaqueError("scalar_domain", "标量不在 Z_n* 域");
  return d;
}

/** CSPRNG 盲化因子：r ←$ Z_n*（crypto.getRandomValues 32B 拒绝采样——
 * RFC 4086 口径；Math.random 禁用红线）。 */
export function randScalar(): bigint {
  const buf = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(buf);
    const v = BigInt("0x" + Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join(""));
    if (v >= 1n && v <= N - 1n) return v;
  }
}

/** [scalar]·point（仿射；标量先域校验）。 */
export function mulPoint(scalar: bigint, pt: Point): Point {
  validateScalar(scalar);
  return scalarMult(scalar, pt);
}

export function generator(): Point {
  return { x: GX, y: GY };
}
