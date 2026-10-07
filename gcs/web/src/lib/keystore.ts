/** 密钥库（P1-A1/A2；2026-10-04 批 2 密码底座升档）：私钥静态加密——localStorage 零明文私钥。
 *
 * 形态 v2：{v:2, pk, enc(密码KEK 密封), rec(恢复码KEK 密封)}——任一因子解封
 * （本机缓存遗留形态，KDF 保留旧链不动——存量可解）。
 * 形态 v3（legacy）：{v:3, pk, enc}——账户单因子信封旧口径，KDF=SM3 迭代链
 *   21000（保留不删：存量密封件版本分派可解+惰性重封升级）。
 * 形态 v4（现行）：{v:4, pk, enc{kdf,iter,…}}——KDF=PBKDF2-HMAC-SM3
 *   （RFC 8018 标准构造，hash-wasm createSM3 WASM 引擎），迭代数缺省 600000
 *   （OWASP 2023 档；iter 随信封落盘——服务端调档不影响存量可解性）。
 * 加密封装：SM4-GCM（crypto/sm4gcm，RFC 8998 对拍锚），AAD 绑定槽位与版本。
 * 明文私钥仅存在于调用方内存变量（模块缓存），刷新即失——解锁 UX 的依据。
 */
import { createSM3, pbkdf2 } from "hash-wasm";
import { sm3 } from "sm-crypto";
import { randHex } from "./api";
import { GcmAuthError, hexToBytes, sm4GcmDecrypt, sm4GcmEncrypt } from "../crypto/sm4gcm";

export const KDF_ITERATIONS_V4 = 600_000; // OWASP 2023 PBKDF2 口径（与后端 KDF_ITERATIONS_DEFAULT 同源）
export const KDF_LEGACY_V3_ITERATIONS = 21_000; // v3 legacy 旧链固定值（兼容面专用）
export const KDF_NAME_V4 = "pbkdf2-sm3"; // v4 信封 enc.kdf 标记（与后端 accounts/kdf.py 同源）
const KEK_LEN = 16;
const AAD_PASS = new TextEncoder().encode("FZ-KEYSTORE-v2|pass");
const AAD_REC = new TextEncoder().encode("FZ-KEYSTORE-v2|recovery");
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 去易混字符（0/1/I/O）
const ACTIVATE_INFO_V1 = new TextEncoder().encode("FZ-ACTIVATE-VERIFY|v1"); // 激活核对子独立派生域

export class KeystoreError extends Error {}

export function sm3Hex(input: string): string {
  return sm3(input);
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** v3 legacy SM3 迭代链 KDF：返回 16B KEK（hex 32 字符）。确定性：同密码同盐同输出。
 * 批 2 起为兼容面专用（v2 本机信封/存量 v3 密封件/旧种子激活分派）；新密封一律 v4。 */
export function deriveKek(passphrase: string, saltHex: string, iterations: number = KDF_LEGACY_V3_ITERATIONS): string {
  if (iterations < 1) throw new KeystoreError("KDF 迭代数须 ≥1");
  const pass = utf8(passphrase);
  const salt = hexToBytes(saltHex);
  let h = sm3(Array.from(concat(pass, salt)));
  const hBytes = () => hexToBytes(h);
  for (let i = 1; i < iterations; i++) {
    h = sm3(Array.from(concat(hBytes(), pass)));
  }
  return h.slice(0, KEK_LEN * 2);
}

/** v4 现行 KDF（RFC 8018 PBKDF2-HMAC-SM3，WASM 引擎）：返回 16B KEK（hex 32 字符）。
 * 与后端 app/accounts/kdf.py:derive_kek 逐字节一致（JS↔Python 对拍锚）。
 * 盐必须按字节传入（hexToBytes）——hash-wasm 对 string 入参按 UTF-8 解释，
 * hex 串直传会派生出完全不同的 KEK（对拍排障定谳）。 */
export async function deriveKekV4(
  passphrase: string,
  saltHex: string,
  iterations: number = KDF_ITERATIONS_V4,
): Promise<string> {
  if (iterations < 1) throw new KeystoreError("KDF 迭代数须 ≥1");
  return pbkdf2({
    password: utf8(passphrase),
    salt: hexToBytes(saltHex),
    iterations,
    hashLength: KEK_LEN,
    hashFunction: createSM3(),
  });
}

/** 激活核对子（v1 独立派生域——与 KEK 域分离，info 前缀入盐；与后端
 * app/accounts/kdf.py:derive_activation_verifier 逐字节一致）。 */
export async function deriveActivationVerifier(
  passphrase: string,
  saltHex: string,
  iterations: number = KDF_ITERATIONS_V4,
): Promise<string> {
  if (iterations < 1) throw new KeystoreError("KDF 迭代数须 ≥1");
  return pbkdf2({
    password: utf8(passphrase),
    salt: concat(ACTIVATE_INFO_V1, hexToBytes(saltHex)),
    iterations,
    hashLength: KEK_LEN,
    hashFunction: createSM3(),
  });
}

interface SealedSlot {
  salt: string;
  nonce: string;
  ct: string;
  tag: string;
}

export interface KeystoreV2 {
  v: 2;
  pk: string;
  enc: SealedSlot; // 密码因子
  rec: SealedSlot; // 恢复码因子
}

function seal(skHex: string, passphrase: string, aad: Uint8Array): SealedSlot {
  const salt = randHex(16);
  const nonce = randHex(12);
  const kek = hexToBytes(deriveKek(passphrase, salt));
  const { ciphertext, tag } = sm4GcmEncrypt(kek, hexToBytes(nonce), hexToBytes(skHex), aad);
  return { salt, nonce, ct: Array.from(ciphertext, (b) => b.toString(16).padStart(2, "0")).join(""), tag: Array.from(tag, (b) => b.toString(16).padStart(2, "0")).join("") };
}

function unseal(slot: SealedSlot, passphrase: string, aad: Uint8Array): string {
  try {
    const kek = hexToBytes(deriveKek(passphrase, slot.salt));
    const pt = sm4GcmDecrypt(kek, hexToBytes(slot.nonce), hexToBytes(slot.ct), hexToBytes(slot.tag), aad);
    return Array.from(pt, (b) => b.toString(16).padStart(2, "0")).join("");
  } catch (e) {
    if (e instanceof GcmAuthError) throw new KeystoreError("解封失败（密码/恢复码错误或密文被篡改）");
    throw e;
  }
}

/** 密封双密文：密码与恢复码两把独立 KEK——任一因子解封。 */
export function sealKeystore(skHex: string, pkHex: string, passphrase: string, recoveryCode: string): KeystoreV2 {
  if (!passphrase) throw new KeystoreError("密码不可为空");
  if (!recoveryCode) throw new KeystoreError("恢复码不可为空");
  return { v: 2, pk: pkHex, enc: seal(skHex, passphrase, AAD_PASS), rec: seal(skHex, recoveryCode, AAD_REC) };
}

export function openWithPassphrase(env: KeystoreV2, passphrase: string): string {
  return unseal(env.enc, passphrase, AAD_PASS);
}

export function openWithRecoveryCode(env: KeystoreV2, recoveryCode: string): string {
  return unseal(env.rec, recoveryCode, AAD_REC);
}

// ---- 跨设备备份（2026-09-28 安全深检 C-P2 演进兑现：信封导出/导入）----
// 设计要点：①导出件=密钥信封+身份元数据（登记承诺/登记表单），元数据以
// 恢复码 KEK 单独密封（AAD 绑定|meta 槽位）——**导出文件零明文 PII**（身份证
// 号等只在元数据密文内），无恢复码的文件只有公钥可见；②恢复码自此成为真正的
// 跨设备凭证（此前宣称"换设备凭恢复码找回"因信封不随行而落空——深检定谳后
// 以本功能兑现）；③密码学零新增原语：复用 SM3 迭代链 KDF+SM4-GCM，仅新增
// AAD 槽位（与 pass/recovery 槽互斥挪用）。

const AAD_META = new TextEncoder().encode("FZ-KEYSTORE-v2|meta");

function sealRaw(data: Uint8Array, passphrase: string, aad: Uint8Array): SealedSlot {
  const salt = randHex(16);
  const nonce = randHex(12);
  const kek = hexToBytes(deriveKek(passphrase, salt));
  const { ciphertext, tag } = sm4GcmEncrypt(kek, hexToBytes(nonce), data, aad);
  return {
    salt, nonce,
    ct: Array.from(ciphertext, (b) => b.toString(16).padStart(2, "0")).join(""),
    tag: Array.from(tag, (b) => b.toString(16).padStart(2, "0")).join(""),
  };
}

function unsealRaw(slot: SealedSlot, passphrase: string, aad: Uint8Array): Uint8Array {
  try {
    const kek = hexToBytes(deriveKek(passphrase, slot.salt));
    return sm4GcmDecrypt(kek, hexToBytes(slot.nonce), hexToBytes(slot.ct), hexToBytes(slot.tag), aad);
  } catch (e) {
    if (e instanceof GcmAuthError) throw new KeystoreError("恢复码不匹配或备份文件被篡改");
    throw e;
  }
}

/** 跨设备备份文件形态（导出即下载件；内容全部为密文+公钥）。 */
export interface KeystoreExportFile {
  kind: "fz-keystore";
  version: 2;
  exported_at: string;
  keystore: KeystoreV2;
  meta: SealedSlot; // 恢复码 KEK 密封的 {cred, form}（JSON→utf8）
}

/** 导出跨设备备份：恢复码先经解封校验（防错码封出不可恢复文件），元数据
 * （登记承诺+登记表单）以恢复码 KEK 密封。v1 明文遗留不支持导出。 */
export function exportKeystoreBundle(
  ks: KeystoreV2, cred: unknown, form: unknown, recoveryCode: string,
): KeystoreExportFile {
  openWithRecoveryCode(ks, recoveryCode); // 错码在此即拒（KDF 校验）
  const meta = JSON.stringify({ cred, form });
  return {
    kind: "fz-keystore",
    version: 2,
    exported_at: new Date().toISOString(),
    keystore: ks,
    meta: sealRaw(utf8(meta), recoveryCode, AAD_META),
  };
}

/** 解析导出文件文本（严格形态校验——人话拒绝，不静默兼容）。 */
export function parseKeystoreFileText(text: string): KeystoreExportFile {
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new KeystoreError("文件不是有效的 JSON——请确认导出件完整");
  }
  const o = obj as Record<string, unknown>;
  if (o?.kind !== "fz-keystore" || o?.version !== 2) {
    throw new KeystoreError("不是飞证密钥库备份文件（kind/version 不符）");
  }
  const ks = o.keystore as KeystoreV2 | undefined;
  const meta = o.meta as SealedSlot | undefined;
  if (!ks || ks.v !== 2 || typeof ks.pk !== "string" || !ks.enc || !ks.rec) {
    throw new KeystoreError("备份文件缺少密钥信封或形态不符");
  }
  if (!meta || typeof meta.ct !== "string" || typeof meta.tag !== "string") {
    throw new KeystoreError("备份文件缺少身份元数据（无法恢复登记信息）");
  }
  return obj as KeystoreExportFile;
}

/** 导入跨设备备份：恢复码解封信封与元数据，以新密码重封本机密钥库。
 * 返回恢复出的数据由调用方落 localStorage（fzCred/fzForm/密钥库/身份标签）。 */
export function importKeystoreBundle(
  file: KeystoreExportFile, recoveryCode: string, newPassphrase: string,
): { env: KeystoreV2; sk: string; pk: string; cred: unknown; form: unknown } {
  const sk = openWithRecoveryCode(file.keystore, recoveryCode);
  let meta: { cred: unknown; form: unknown };
  try {
    meta = JSON.parse(new TextDecoder().decode(unsealRaw(file.meta, recoveryCode, AAD_META)));
  } catch (e) {
    if (e instanceof KeystoreError) throw e;
    throw new KeystoreError("身份元数据损坏——备份文件不完整");
  }
  if (!meta || typeof meta !== "object" || !("cred" in meta) || !("form" in meta)) {
    throw new KeystoreError("身份元数据形态不符——备份文件不完整");
  }
  const env = sealKeystore(sk, file.keystore.pk, newPassphrase, recoveryCode);
  return { env, sk, pk: file.keystore.pk, cred: meta.cred, form: meta.form };
}

/** 恢复码：24 字符 6 段（120bit，CSPRNG 拒绝采样——Math.random 红线）。 */
export function generateRecoveryCode(): string {
  const groups: string[] = [];
  for (let g = 0; g < 6; g++) {
    let s = "";
    for (let i = 0; i < 4; i++) s += RECOVERY_ALPHABET[randInt32(RECOVERY_ALPHABET.length)];
    groups.push(s);
  }
  return groups.join("-");
}

function randInt32(max: number): number {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / max) * max;
  let v = 0;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return v % max;
}

export interface LegacyKeystore {
  sk: string;
  pk: string;
}

/** v1 明文遗留检测（类型守卫——负分支收窄为 KeystoreV2）。 */
export function isLegacyKeystore(obj: unknown): obj is LegacyKeystore {
  if (typeof obj !== "object" || obj === null) return false;
  const o = obj as Record<string, unknown>;
  return typeof o.sk === "string" && o.v === undefined;
}

// ---- v3 单因子信封（2026-09-29 账户批）：密码=唯一 KEK，密封件存服务器侧 ——
// 账户模型（docs/评审/2026-09-29-账户门户与三角色工作台 §2）：登录任意设备
// 取回密封件本地解封；恢复码/导出导入随服务器存储退役（拍板 #4）。
// AAD 槽位绑定版本域；信封 pk 与账户公钥一致性由服务端注册时校验+解封后
// 指纹核对双层把关。 ----

const AAD_PASS_V3 = new TextEncoder().encode("FZ-KEYSTORE-v3|pass");
const AAD_PROFILE_V3 = new TextEncoder().encode("FZ-KEYSTORE-v3|profile");
const AAD_PASS_V4 = new TextEncoder().encode("FZ-KEYSTORE-v4|pass");
const AAD_PROFILE_V4 = new TextEncoder().encode("FZ-KEYSTORE-v4|profile");

export interface KeystoreV3 {
  v: 3;
  pk: string;
  enc: SealedSlot;
}

/** v4 信封（现行）：enc 槽带 kdf 标记+迭代数落盘（解封按信封内 iter 复算
 * ——服务端 FZ_KDF_ITERATIONS 调档不影响存量可解性）。 */
export interface SealedSlotV4 extends SealedSlot {
  kdf: typeof KDF_NAME_V4;
  iter: number;
}

export interface KeystoreV4 {
  v: 4;
  pk: string;
  enc: SealedSlotV4;
}

export type AccountKeystore = KeystoreV3 | KeystoreV4;

/** v3 密封（legacy 兼容面——仅惰性重封前构造测试/迁移面使用；新密封走 v4）。 */
export function sealKeystoreV3(skHex: string, pkHex: string, passphrase: string): KeystoreV3 {
  if (!passphrase) throw new KeystoreError("密码不可为空");
  return { v: 3, pk: pkHex, enc: seal(skHex, passphrase, AAD_PASS_V3) };
}

/** v3 解封：失败（GCM 认证）=密码错误或信封被篡改——登录 UX 的判定依据。 */
export function openKeystoreV3(env: KeystoreV3, passphrase: string): string {
  if (!env || env.v !== 3 || !env.enc) throw new KeystoreError("密封件形态不符（v3）");
  return unseal(env.enc, passphrase, AAD_PASS_V3);
}

/** v4 密封（现行——PBKDF2-HMAC-SM3，iter 落盘）。 */
export async function sealKeystoreV4(
  skHex: string,
  pkHex: string,
  passphrase: string,
  iterations: number = KDF_ITERATIONS_V4,
): Promise<KeystoreV4> {
  if (!passphrase) throw new KeystoreError("密码不可为空");
  if (iterations < 1) throw new KeystoreError("KDF 迭代数须 ≥1");
  const salt = randHex(16);
  const nonce = randHex(12);
  const kek = hexToBytes(await deriveKekV4(passphrase, salt, iterations));
  const { ciphertext, tag } = sm4GcmEncrypt(kek, hexToBytes(nonce), hexToBytes(skHex), AAD_PASS_V4);
  return {
    v: 4,
    pk: pkHex,
    enc: {
      salt,
      nonce,
      ct: Array.from(ciphertext, (b) => b.toString(16).padStart(2, "0")).join(""),
      tag: Array.from(tag, (b) => b.toString(16).padStart(2, "0")).join(""),
      kdf: KDF_NAME_V4,
      iter: iterations,
    },
  };
}

/** v4 解封（按信封内 iter 复算——形态门 fail-closed：kdf 标记/iter 非法即拒）。 */
export async function openKeystoreV4(env: KeystoreV4, passphrase: string): Promise<string> {
  if (!env || env.v !== 4 || !env.enc) throw new KeystoreError("密封件形态不符（v4）");
  if (env.enc.kdf !== KDF_NAME_V4) throw new KeystoreError("密封件 KDF 标记不符（v4）");
  if (!Number.isInteger(env.enc.iter) || env.enc.iter < 1) throw new KeystoreError("密封件 KDF 迭代数非法");
  return unsealV4(env.enc, passphrase, AAD_PASS_V4, env.enc.iter);
}

/** 版本分派解封（v3→旧链 / v4→PBKDF2）——存量 v3 密封件仍可解，不删旧链。 */
export async function openKeystore(env: AccountKeystore, passphrase: string): Promise<string> {
  if (env?.v === 4) return openKeystoreV4(env, passphrase);
  return openKeystoreV3(env as KeystoreV3, passphrase);
}

/** 密封件解析（严格形态校验 v3/v4——人话拒绝，不静默兼容）。 */
export function parseKeystoreBlob(text: string): AccountKeystore {
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new KeystoreError("密封件不是有效 JSON");
  }
  const o = obj as Record<string, unknown>;
  if ((o?.v !== 3 && o?.v !== 4) || typeof o.pk !== "string" || !o.enc) {
    throw new KeystoreError("密封件形态不符（v3/v4）");
  }
  return o as unknown as AccountKeystore;
}

/** 身份资料密封槽（{cred,form}——零明文 PIII 落服务器，同导出件纪律）。
 * v4 现行：槽带 kdf/iter 标记（unseal 按标记分派——旧槽无标记走旧链）。 */
export async function sealProfileSlot(
  data: unknown,
  passphrase: string,
  iterations: number = KDF_ITERATIONS_V4,
): Promise<SealedSlotV4> {
  const salt = randHex(16);
  const nonce = randHex(12);
  const kek = hexToBytes(await deriveKekV4(passphrase, salt, iterations));
  const { ciphertext, tag } = sm4GcmEncrypt(
    kek, hexToBytes(nonce), utf8(JSON.stringify(data)), AAD_PROFILE_V4,
  );
  return {
    salt,
    nonce,
    ct: Array.from(ciphertext, (b) => b.toString(16).padStart(2, "0")).join(""),
    tag: Array.from(tag, (b) => b.toString(16).padStart(2, "0")).join(""),
    kdf: KDF_NAME_V4,
    iter: iterations,
  };
}

export function unsealProfileSlot<T = unknown>(slot: SealedSlot, passphrase: string): Promise<T> {
  const doUnseal = async (): Promise<T> => {
    const v4 = (slot as SealedSlotV4).kdf === KDF_NAME_V4;
    const raw = await sm4GcmDecryptAsync(
      v4
        ? hexToBytes(await deriveKekV4(passphrase, slot.salt, (slot as SealedSlotV4).iter))
        : hexToBytes(deriveKek(passphrase, slot.salt)),
      hexToBytes(slot.nonce),
      hexToBytes(slot.ct),
      hexToBytes(slot.tag),
      v4 ? AAD_PROFILE_V4 : AAD_PROFILE_V3,
    );
    return JSON.parse(new TextDecoder().decode(raw)) as T;
  };
  return doUnseal().catch((e) => {
    if (e instanceof GcmAuthError || e instanceof KeystoreError) {
      throw new KeystoreError("身份资料解封失败（密码不匹配）");
    }
    throw e;
  });
}

/** sm4GcmDecrypt 的 Promise 化薄壳（同步实现抛异常→rejected，统一 await 面）。 */
function sm4GcmDecryptAsync(
  key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, tag: Uint8Array, aad: Uint8Array,
): Promise<Uint8Array> {
  try {
    return Promise.resolve(sm4GcmDecrypt(key, nonce, ct, tag, aad));
  } catch (e) {
    return Promise.reject(e);
  }
}

/** v4 槽解封内核（AAD+KDF 由调用方按信封版本传入）。 */
async function unsealV4(slot: SealedSlot, passphrase: string, aad: Uint8Array, iterations: number): Promise<string> {
  try {
    const kek = hexToBytes(await deriveKekV4(passphrase, slot.salt, iterations));
    const pt = sm4GcmDecrypt(kek, hexToBytes(slot.nonce), hexToBytes(slot.ct), hexToBytes(slot.tag), aad);
    return Array.from(pt, (b) => b.toString(16).padStart(2, "0")).join("");
  } catch (e) {
    if (e instanceof GcmAuthError) throw new KeystoreError("解封失败（密码错误或密文被篡改）");
    throw e;
  }
}

// ---- 存储与会话缓存（明文私钥只在模块内存——刷新即失，解锁 UX 依据） ----
const STORAGE_KEY = "fzUserKeypair";
let cachedSk: string | null = null;

export function loadKeystore(): KeystoreV2 | AccountKeystore | { sk: string; pk: string } | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** 本地密钥缓存落盘（v2/v3/v4 信封皆可——账户批后新登记一律 v4）。 */
export function storeKeystore(env: KeystoreV2 | AccountKeystore): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(env));
  cachedSk = null; // 旧缓存作废
}

export function storedPk(): string | null {
  const ks = loadKeystore();
  if (!ks) return null;
  return (ks as KeystoreV2).pk ?? (ks as { pk?: string }).pk ?? null;
}

/** 明文私钥缓存=纯内存（2026-09-30 口径 E12 对齐）：刷新即焚，敏感操作前
 * 重新输密码解封（钱包式——拍板接受）。此前的 sessionStorage 缓存与
 * 「刷新后明文钥只在内存」的宣称直接矛盾（评审 C 席证伪），退役。 */
export function getCachedSk(): string | null {
  return cachedSk;
}

/** R3-2（评审 P2-3）：退出即焚——内存明文私钥清零。 */
export function clearCachedSk(): void {
  cachedSk = null;
}

export function cacheSk(sk: string): void {
  cachedSk = sk;
}

/** 会话内一次性生成新钥对并缓存（登记仪式用；密封由调用方 sealKeystore 落盘）。 */
export function newKeypair(skHex: string, pkHex: string): void {
  cachedSk = skHex;
  void pkHex;
}
