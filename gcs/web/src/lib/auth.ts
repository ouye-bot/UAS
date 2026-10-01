/** 账户门户库（2026-09-29 账户批）：登录/注册/激活/资料补全的单一入口。
 *
 * 密码学语义（设计方案 §2）：
 * - 密码只做一件事：本地 KDF 解封私钥/密封资料——明文密码与私钥永不出浏览器；
 * - 登录认证=SM2 挑战-应答签名（uid/摘要口径与后端 app.crypto.sm2 同源——
 *   doSignature{hash:true,userId:"1234567812345678"} ↔ 服务端 verify 实测闭环）；
 * - 资料补全=「上链注册」时点：/auth/profile 服务端调 RA 签发（承诺+主凭证+链锚），
 *   签发响应+表单再以密码 KEK 密封二相回存（零明文 PIII 落库）；
 * - 会话：HttpOnly Cookie——前端只落 fzSession 角色标签（路由守卫展示用，
 *   真权威在服务端会话表）。
 */
import { sm2 } from "sm-crypto";
import { api, ApiError } from "./api";
import {
  KeystoreError,
  clearCachedSk,
  cacheSk,
  deriveKek,
  openKeystoreV3,
  sealKeystoreV3,
  sealProfileSlot,
  storeKeystore,
  unsealProfileSlot,
} from "./keystore";
import { clearSessionState, storeIdentityTag, sweepForAccountSwitch, sweepLocalIdentity } from "./material";

export const SM2_USER_ID = "1234567812345678"; // 全系统统一默认 ID（改动须两端同步）

export type Role = "pilot" | "auditor" | "admin";

export interface MeInfo {
  username: string;
  role: Role;
  status: string;
  pubkey_hex: string | null;
  cred_hash_hex: string | null;
  sealed_blob: string | null;
  sealed_profile: string | null;
}

const SESSION_FLAG = "fzSession";

export function cachedRole(): Role | null {
  try {
    const o = JSON.parse(localStorage.getItem(SESSION_FLAG) || "null");
    return o?.role ?? null;
  } catch {
    return null;
  }
}

export function cachedUsername(): string | null {
  try {
    const o = JSON.parse(localStorage.getItem(SESSION_FLAG) || "null");
    return o?.username ?? null;
  } catch {
    return null;
  }
}

function setSessionFlag(username: string, role: Role): void {
  localStorage.setItem(SESSION_FLAG, JSON.stringify({ username, role }));
}

export function clearSessionFlag(): void {
  localStorage.removeItem(SESSION_FLAG);
}

/** 当前会话探测（401=null——路由守卫与页内诊断共用）。 */
export async function me(): Promise<MeInfo | null> {
  try {
    return await api<MeInfo>("/auth/me");
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}

export async function logout(): Promise<void> {
  const prevUser = cachedUsername(); // 登出清扫要在旗标删除前拿锚（P1-9）
  try {
    await api("/auth/logout", { method: "POST" });
  } finally {
    clearSessionFlag();
    clearSessionState();
    clearCachedSk();
    sweepLocalIdentity(); // 登出即清扫——上一户材料不再等下一户登录时补清
  }
  void prevUser;
}

// ---- 注册（飞手）：两步——①建账户（钥对生成+密封上传）②补资料（RA 签发上链）----

export interface PendingRegistration {
  username: string;
  password: string;
  sk: string;
  pk: string; // 128 hex（无 04 前缀——全系统口径）
}

let pending: PendingRegistration | null = null;

export function pendingRegistration(): PendingRegistration | null {
  return pending;
}

export function dropPendingRegistration(): void {
  pending = null;
}

/** 第①步：建账户。浏览器生成 SM2 钥对→密码 KEK 密封（v3）→只上传密封件。 */
export async function registerAccount(username: string, password: string): Promise<PendingRegistration> {
  const kp = sm2.generateKeyPairHex();
  const sk = kp.privateKey;
  const pk = kp.publicKey.replace(/^04/, "");
  const blob = sealKeystoreV3(sk, pk, password);
  await api("/auth/register", {
    method: "POST",
    body: JSON.stringify({ username, pubkey_hex: pk, sealed_blob: JSON.stringify(blob) }),
  });
  pending = { username, password, sk, pk };
  return pending;
}

export interface ProfileForm {
  id_number: string;
  cert_level: number;
  sn: string;
  class_id: number;
}

export interface ProfileResult {
  master_cred_hash_hex: string;
  [k: string]: unknown;
}

/** 第②步：补资料→RA 签发上链→{cred,form} 密码密封二相回存。 */
export async function submitProfile(reg: PendingRegistration, form: ProfileForm): Promise<ProfileResult> {
  const out = await api<ProfileResult>("/auth/profile", {
    method: "POST",
    body: JSON.stringify(form),
  });
  const sealed = sealProfileSlot({ cred: out, form }, reg.password);
  await api("/auth/profile/keep", {
    method: "POST",
    body: JSON.stringify({ sealed_profile: JSON.stringify(sealed) }),
  });
  finishRegistrationLocal(reg, form, out);
  return out;
}

/** 注册完成后的本机落盘（与旧登记流同键位——下游页面零改动）：fzCred/fzForm/
 * 密钥库本地缓存（v3 信封同步落 localStorage 作解锁 UX 快路径）/身份标签。 */
export function finishRegistrationLocal(
  reg: PendingRegistration,
  form: ProfileForm,
  cred: ProfileResult,
): void {
  localStorage.setItem("fzCred", JSON.stringify(cred));
  localStorage.setItem("fzForm", JSON.stringify(form));
  storeKeystore(sealKeystoreV3(reg.sk, reg.pk, reg.password));
  cacheSk(reg.sk);
  clearSessionState();
  storeIdentityTag();
  pending = null;
}

// ---- 登录：prelogin→(激活)→取密封件→解封→挑战-应答签名→会话----

export interface LoginOutcome {
  username: string;
  role: Role;
  status: string;
}

/** 登录。抛 ApiError（code 区分：activation_failed/密码错=bad_password/限速等）。
 * 密封件解封失败（GCM）=密码错误——本地即判，不猜服务端。 */
export async function login(username: string, password: string): Promise<LoginOutcome> {
  const pre = await api<{ mode: "challenge" | "activation"; kdf_salt_hex?: string }>(
    `/auth/prelogin/${encodeURIComponent(username)}`,
  );
  if (pre.mode === "activation") {
    // 预置机构账户首登激活：初始密码核对子一次性比对→钥对生成+密封上传→焚烧
    const kp = sm2.generateKeyPairHex();
    const sk = kp.privateKey;
    const pk = kp.publicKey.replace(/^04/, "");
    const verifier = deriveKek(password, pre.kdf_salt_hex ?? "");
    const blob = sealKeystoreV3(sk, pk, password);
    await api("/auth/activate", {
      method: "POST",
      body: JSON.stringify({
        username,
        verifier_hex: verifier,
        pubkey_hex: pk,
        sealed_blob: JSON.stringify(blob),
      }),
    });
  }
  const ks = await api<{ sealed_blob: string; pubkey_hex: string }>(
    `/auth/keystore/${encodeURIComponent(username)}`,
  );
  const env = parseV3(ks.sealed_blob);
  let sk: string;
  try {
    sk = openKeystoreV3(env, password);
  } catch (e) {
    if (e instanceof KeystoreError) {
      throw new ApiError("bad_password", "密码错误（密封件解封失败）", 401);
    }
    throw e;
  }
  // 密钥核对：解封私钥须与密封件公钥/账户登记公钥一致（错配=密封件被调包）
  if (!skMatchPub(sk, env.pk) || env.pk.toLowerCase() !== ks.pubkey_hex.toLowerCase()) {
    throw new ApiError("key_mismatch", "密封件与账户公钥不匹配——请与管理员核对", 409);
  }
  // 本地密钥缓存恢复（2026-09-30 批三连带修复：登出即清扫清了 fzUserKeypair
  // ——重登后 storedPk()=空 → 子凭证签发/材料指纹全部断。密封件本来就在
  // 手上，解封成功即回写本地缓存（明文钥仍只驻内存）。
  storeKeystore(env);
  return loginWithSk(username, sk, password);
}

/** 持私钥直登（挑战-应答）：注册第①步建户后静默登录——第②步补资料需要
 * pilot 会话（/auth/profile 角色守卫）；钥已在内存，密码无需重输。 */
export async function loginWithSk(username: string, sk: string, password?: string): Promise<LoginOutcome> {
  const { nonce_hex } = await api<{ nonce_hex: string }>(
    `/auth/challenge/${encodeURIComponent(username)}`,
    { method: "POST" },
  );
  const sig = signMsg(sk, `FZ-AUTH-LOGIN|${nonce_hex}`);
  const out = await api<LoginOutcome>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, nonce_hex, sig_hex: sig }),
  });
  // 账户切换清扫：前后账户不同 ⟹ 清上一账户本机材料（先取 prev 再落新旗标）
  const prevUser = cachedUsername();
  setSessionFlag(out.username, out.role);
  sweepForAccountSwitch(prevUser, out.username);
  cacheSk(sk);
  if (password) await restoreProfileIfMissing(password);
  return out;
}

/** 跨设备恢复：本机无 fzCred 而服务器有密封资料→解封落盘（换设备登录即达）。 */
async function restoreProfileIfMissing(password: string): Promise<void> {
  if (localStorage.getItem("fzCred")) return;
  const info = await me();
  if (!info?.sealed_profile) return;
  try {
    const meta = unsealProfileSlot<{ cred: unknown; form: unknown }>(
      JSON.parse(info.sealed_profile),
      password,
    );
    if (meta?.cred && meta?.form) {
      localStorage.setItem("fzCred", JSON.stringify(meta.cred));
      localStorage.setItem("fzForm", JSON.stringify(meta.form));
    }
  } catch {
    // 资料解封失败不阻断登录——下游页面按"未登记"引导补资料
  }
}

// ---- 角色钥解锁（审计/机构台敏感签名前置）----
// 刷新后内存钥已清：本地缓存密钥（若有）或服务器密封件解封——密码只在
// 解封瞬间使用，解封后钥驻内存（关浏览器即焚）。
export async function unlockSk(password: string): Promise<string> {
  const { loadKeystore, isLegacyKeystore, openKeystoreV3, openWithPassphrase } = await import("./keystore");
  const username = cachedUsername();
  if (!username) throw new ApiError("not_logged_in", "未登录", 401);
  const local = loadKeystore();
  if (local && !isLegacyKeystore(local) && (local as { v?: number }).v === 3) {
    try {
      const sk = openKeystoreV3(local as import("./keystore").KeystoreV3, password);
      if (!skMatchPub(sk, (local as { pk: string }).pk)) throw new KeystoreError("密钥核对失败");
      cacheSk(sk);
      return sk;
    } catch { /* 本地不可用——回落服务器密封件 */ }
  } else if (local && !isLegacyKeystore(local)) {
    const sk = openWithPassphrase(local as never, password);
    cacheSk(sk);
    return sk;
  }
  const ks = await api<{ sealed_blob: string; pubkey_hex: string }>(
    `/auth/keystore/${encodeURIComponent(username)}`,
  );
  const env = parseV3(ks.sealed_blob);
  let sk: string;
  try {
    sk = openKeystoreV3(env, password);
  } catch (e) {
    if (e instanceof KeystoreError) throw new ApiError("bad_password", "密码错误（密封件解封失败）", 401);
    throw e;
  }
  if (!skMatchPub(sk, env.pk) || env.pk.toLowerCase() !== ks.pubkey_hex.toLowerCase()) {
    throw new ApiError("key_mismatch", "密封件与账户公钥不匹配", 409);
  }
  cacheSk(sk);
  return sk;
}

// ---- SM2 工具（与服务端 app.crypto.sm2 口径闭环——node↔python 实测对拍锚）----

/** 敏感操作签名（登录挑战/审计发函/管理员批准——双控双签的客户端侧）。 */
export function signMsg(sk: string, msg: string): string {
  return sm2.doSignature(msg, sk, { hash: true, userId: SM2_USER_ID, der: false });
}

function skMatchPub(sk: string, pkNo04: string): boolean {
  try {
    // 私钥直接派生公钥核对（sm-crypto getPublicKeyFromPrivateKey——同钥必合/异钥必异）
    const sm2Any = sm2 as unknown as { getPublicKeyFromPrivateKey: (sk: string) => string };
    const derived = sm2Any.getPublicKeyFromPrivateKey(sk).replace(/^04/, "").toLowerCase();
    return derived === pkNo04.toLowerCase();
  } catch {
    return false;
  }
}

function parseV3(text: string): import("./keystore").KeystoreV3 {
  const o = JSON.parse(text) as import("./keystore").KeystoreV3;
  if (o?.v !== 3 || typeof o.pk !== "string" || !o.enc) {
    throw new KeystoreError("密封件形态不符（v3）");
  }
  return o;
}
