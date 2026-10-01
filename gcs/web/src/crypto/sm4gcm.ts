/**
 * SM4-GCM 解密（TS 自实现，NIST SP 800-38D）——阅后即焚客户端解密面。
 *
 * 为什么自实现：sm-crypto 的 sm4 仅 ECB/CBC，后端数据面为 SM4-GCM（ nonce+ct+tag）。
 * 与后端 sm4.py 纯引擎同算法域；**RFC 8998 A.1 + GB/T 36624 C.5 官方向量
 * 跨语言对拍通过**（tests 侧 node 脚本 + 后端 Python 同锚）——国密第三语言锚（口径：运行主路径密码原语 100% 国密）。
 *
 * 仅实现解密（客户端职责面）；加密在服务端（app/crypto/sm4.py 双引擎）。
 * 位运算全部 >>> 0 保持 32 位无符号语义。
 */

const SBOX = new Uint8Array([
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
  0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
  0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
  0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
  0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
  0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
  0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
  0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
  0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
  0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]);

const FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
const CK = [
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
  0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
  0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function tau(a: number): number {
  return (
    ((SBOX[(a >>> 24) & 0xff] << 24) |
      (SBOX[(a >>> 16) & 0xff] << 16) |
      (SBOX[(a >>> 8) & 0xff] << 8) |
      SBOX[a & 0xff]) >>>
    0
  );
}

function tRound(x: number): number {
  const b = tau(x);
  return (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) >>> 0;
}

function tPrime(x: number): number {
  const b = tau(x);
  return (b ^ rotl(b, 13) ^ rotl(b, 23)) >>> 0;
}

/** SM4 轮密钥（正序；GCM 各面只用正向加密函数——D_K 误用为 GCM 首跑实证教训） */
export function keySchedule(key: Uint8Array): Uint32Array {
  const mk: number[] = [];
  for (let i = 0; i < 4; i++) {
    mk[i] =
      (((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) >>>
        0) ^
      FK[i];
  }
  const rk = new Uint32Array(32);
  let k0 = mk[0], k1 = mk[1], k2 = mk[2], k3 = mk[3];
  for (let i = 0; i < 32; i++) {
    const nk = (k0 ^ tPrime(k1 ^ k2 ^ k3 ^ CK[i])) >>> 0;
    rk[i] = nk;
    k0 = k1; k1 = k2; k2 = k3; k3 = nk;
  }
  return rk;
}

/** SM4 加密单块（正向 32 轮 + 反序变换 R）——GCM 的 H/J0/keystream 全走此函数 */
export function encryptBlock(rk: Uint32Array, block: Uint8Array): Uint8Array {
  let x0 = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) >>> 0;
  let x1 = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) >>> 0;
  let x2 = ((block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]) >>> 0;
  let x3 = ((block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]) >>> 0;
  for (let i = 0; i < 32; i++) {
    const nx = (x0 ^ tRound(x1 ^ x2 ^ x3 ^ rk[i])) >>> 0;
    x0 = x1; x1 = x2; x2 = x3; x3 = nx;
  }
  const out = new Uint8Array(16);
  // 反序变换 R
  const words = [x3, x2, x1, x0];
  for (let i = 0; i < 4; i++) {
    out[4 * i] = (words[i] >>> 24) & 0xff;
    out[4 * i + 1] = (words[i] >>> 16) & 0xff;
    out[4 * i + 2] = (words[i] >>> 8) & 0xff;
    out[4 * i + 3] = words[i] & 0xff;
  }
  return out;
}

// ---- GCM（GF(2^128) 乘法 + GHASH + CTR） ----

export function gf128Mul(x: Uint8Array, y: Uint8Array): Uint8Array<ArrayBuffer> {
  // MSB 序（SP 800-38D 算法 1），与后端 _gf128_mul 同域
  const z = new Uint8Array(16);
  const v = Uint8Array.from(y);
  const r = new Uint8Array(16);
  r[0] = 0xe1;
  for (let i = 0; i < 128; i++) {
    if ((x[i >> 3] >> (7 - (i & 7))) & 1) {
      for (let j = 0; j < 16; j++) z[j] ^= v[j];
    }
    const lsb = v[15] & 1;
    // v >>= 1
    for (let j = 15; j > 0; j--) {
      v[j] = ((v[j] >>> 1) | (v[j - 1] << 7)) & 0xff;
    }
    v[0] >>>= 1;
    if (lsb) for (let j = 0; j < 16; j++) v[j] ^= r[j];
  }
  return z;
}

export function ghash(h: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array<ArrayBuffer> {
  let y = new Uint8Array(16);
  const feed = (buf: Uint8Array) => {
    for (let i = 0; i < buf.length; i += 16) {
      const blk = new Uint8Array(16);
      blk.set(buf.slice(i, i + 16));
      const xored = new Uint8Array(16);
      for (let j = 0; j < 16; j++) xored[j] = y[j] ^ blk[j];
      y = gf128Mul(xored, h);
    }
  };
  feed(aad);
  feed(ct);
  const lens = new Uint8Array(16);
  // 🔴 禁用 >>> 移位（JS 32 位 mod-32 语义：>>>32 静默回绕致字节重复——实测坑）
  const abits = aad.length * 8, cbits = ct.length * 8;
  for (let i = 0; i < 8; i++) {
    lens[7 - i] = Math.floor(abits / 256 ** i) & 0xff;
    lens[15 - i] = Math.floor(cbits / 256 ** i) & 0xff;
  }
  const xored = new Uint8Array(16);
  for (let j = 0; j < 16; j++) xored[j] = y[j] ^ lens[j];
  return gf128Mul(xored, h);
}

function inc32(block: Uint8Array): Uint8Array {
  const out = Uint8Array.from(block);
  let c = 1;
  for (let i = 15; i >= 12 && c; i--) {
    c = out[i] === 0xff ? 1 : 0;
    out[i] = (out[i] + 1) & 0xff;
  }
  return out;
}

function ctr(rk: Uint32Array, icb: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  let cb = icb;
  for (let off = 0; off < data.length; off += 16) {
    const ks = encryptBlock(rk, cb);
    const n = Math.min(16, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
    cb = inc32(cb);
  }
  return out;
}

export class GcmAuthError extends Error {}

/** SM4-GCM 解密：tag 校验失败抛 GcmAuthError；nonce 恒 12B（RFC 8998 口径）。 */
export function sm4GcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (key.length !== 16) throw new GcmAuthError("SM4 密钥必须 16 字节");
  if (nonce.length !== 12) throw new GcmAuthError("GCM nonce 必须 12 字节");
  if (tag.length !== 16) throw new GcmAuthError("tag 必须 16 字节");

  const rk = keySchedule(key);
  const j0 = new Uint8Array(16);
  j0.set(nonce);
  j0[15] = 1;
  const icb = inc32(j0);
  const ct = ciphertext;
  const s = ghash(encryptBlock(rk, new Uint8Array(16)), aad, ct);
  const ekJ0 = encryptBlock(rk, j0);
  const expect = new Uint8Array(16);
  for (let i = 0; i < 16; i++) expect[i] = ekJ0[i] ^ s[i];
  for (let i = 0; i < 16; i++) {
    if (expect[i] !== tag[i]) throw new GcmAuthError("GCM 认证失败");
  }
  return ctr(rk, icb, ct);
}

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** SM4-GCM 加密（阅后即焚端侧加密面）：nonce 12B 由调用方传入（CSPRNG）。 */
export function sm4GcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): { ciphertext: Uint8Array; tag: Uint8Array } {
  if (key.length !== 16) throw new GcmAuthError("SM4 密钥必须 16 字节");
  if (nonce.length !== 12) throw new GcmAuthError("GCM nonce 必须 12 字节");
  const rk = keySchedule(key);
  const j0 = new Uint8Array(16);
  j0.set(nonce);
  j0[15] = 1;
  const ct = ctr(rk, inc32(j0), plaintext);
  const s = ghash(encryptBlock(rk, new Uint8Array(16)), aad, ct);
  const ekJ0 = encryptBlock(rk, j0);
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) tag[i] = ekJ0[i] ^ s[i];
  return { ciphertext: ct, tag };
}
