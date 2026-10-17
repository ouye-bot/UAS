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
  KDF_LEGACY_V3_ITERATIONS,
  type AccountKeystore,
  deriveActivationVerifier,
  deriveKek,
  openKeystore,
  openKeystoreV3,
  parseKeystoreBlob,
  sealKeystoreV4,
  sealProfileSlot,
  storeKeystore,
  unsealProfileSlot,
} from "./keystore";
import { clearSessionState, storeIdentityTag, sweepForAccountSwitch, sweepLocalIdentity } from "./material";
import {
  opaqueChangeMaterials,
  opaqueEvaluate,
  opaqueMigrateMaterials,
  opaqueRegisterMaterials,
  opaqueUnlockSk,
} from "./opaqueClient";

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
  v6env?: import("./keystore").KeystoreV6; // ⑫O-5 v6 本地信封（注册材料回执——finish 落盘）
}

let pending: PendingRegistration | null = null;

export function pendingRegistration(): PendingRegistration | null {
  return pending;
}

export function dropPendingRegistration(): void {
  pending = null;
}

/** 第①步：建账户（⑫O-5 换代——OPAQUE v6 封装）：钥对生成→盲化求值（α→evaluate
 * ——账户未建=服务端 fake 分支仍返真实 β（§6.1 同构计算））→rwd 单链→v6 密封
 * →只上传密文材料（零明文口令出浏览器——设计 §2.2）。 */
export async function registerAccount(username: string, password: string): Promise<PendingRegistration> {
  const kp = sm2.generateKeyPairHex();
  const sk = kp.privateKey;
  const pk = kp.publicKey.replace(/^04/, "");
  const mats = await opaqueRegisterMaterials(username, password, sk, pk);
  await api("/auth/register", {
    method: "POST",
    body: JSON.stringify({
      username,
      pubkey_hex: pk,
      sealed_blob: mats.sealed_blob,
      masking_key_hex: mats.masking_key_hex,
      kdf_salt_hex: mats.kdf_salt_hex,
      kdf_iter: mats.kdf_iter,
    }),
  });
  pending = {
    username,
    password,
    sk,
    pk,
    v6env: JSON.parse(mats.sealed_blob) as import("./keystore").KeystoreV6,
  };
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
  const sealed = await sealProfileSlot({ cred: out, form }, reg.password);
  await api("/auth/profile/keep", {
    method: "POST",
    body: JSON.stringify({ sealed_profile: JSON.stringify(sealed) }),
  });
  await finishRegistrationLocal(reg, form, out);
  return out;
}

/** 注册完成后的本机落盘（与旧登记流同键位——下游页面零改动）：fzCred/fzForm/
 * 密钥库本地缓存（v4 信封同步落 localStorage 作解锁 UX 快路径）/身份标签。 */
export async function finishRegistrationLocal(
  reg: PendingRegistration,
  form: ProfileForm,
  cred: ProfileResult,
): Promise<void> {
  localStorage.setItem("fzCred", JSON.stringify(cred));
  localStorage.setItem("fzForm", JSON.stringify(form));
  // ⑫O-5：本地缓存=注册材料回执的 v6 信封（与服务器密封件同源——解锁走
  // OPAQUE 通道）；v6env 缺失（理论不达）时回退 v4 本地重封（旧语义保底）。
  if (reg.v6env) {
    storeKeystore(reg.v6env);
  } else {
    storeKeystore(await sealKeystoreV4(reg.sk, reg.pk, reg.password));
  }
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
 * 密封件解封失败（GCM）=密码错误——本地即判，不猜服务端。
 * activationCode（2026-10-11 激活面收紧批③）：双因子档位（production/显式
 * env）下预置账户首登激活的一次性激活码——prelogin 下发 require_code=true
 * 而未携带时本地先行拒绝（不烧服务端激活尝试的限速预算）；demo 档缺省关。 */
export async function login(
  username: string,
  password: string,
  activationCode?: string,
): Promise<LoginOutcome> {
  const pre = await api<{
    mode: "challenge" | "activation";
    kdf_salt_hex?: string;
    verifier?: "v1" | "legacy_v3";
    rounds?: number;
    require_code?: boolean;
  }>(`/auth/prelogin/${encodeURIComponent(username)}`);
  if (pre.mode === "activation") {
    if (pre.require_code && !activationCode) {
      throw new ApiError(
        "activation_code_required",
        "该账户须一次性激活码——请向机构管理员索取（种子独立交付件）",
        403,
      );
    }
    // 预置机构账户首登激活：初始密码核对子一次性比对→钥对生成+OPAQUE v6 材料
    // 上传（待激活账户 evaluate=真实 β——§6.1-b）→焚烧核对子。核对子按 prelogin
    // 下发格式分派复算（v1=独立派生域现行 / legacy_v3=旧种子兼容读取）。
    const kp = sm2.generateKeyPairHex();
    const sk = kp.privateKey;
    const pk = kp.publicKey.replace(/^04/, "");
    const verifier =
      pre.verifier === "legacy_v3"
        ? deriveKek(password, pre.kdf_salt_hex ?? "", KDF_LEGACY_V3_ITERATIONS)
        : await deriveActivationVerifier(password, pre.kdf_salt_hex ?? "", pre.rounds);
    const mats = await opaqueRegisterMaterials(username, password, sk, pk, pre.rounds);
    await api("/auth/activate", {
      method: "POST",
      body: JSON.stringify({
        username,
        verifier_hex: verifier,
        pubkey_hex: pk,
        sealed_blob: mats.sealed_blob,
        masking_key_hex: mats.masking_key_hex,
        kdf_salt_hex: mats.kdf_salt_hex,
        kdf_iter: mats.kdf_iter,
        ...(activationCode ? { activation_code: activationCode } : {}),
      }),
    });
  }
  // ⑫O-5 稳态登录（设计 §2.3 两消息协议优先）：OPAQUE 掩码通道（v6 账户）→
  // 失败回落 legacy keystore 通道（v4/v3 过渡存量——鸡-蛋面：解封需先取件；
  // 失败判词两路同人话——体验零变化）。
  try {
    const sk = await opaqueUnlockSk(username, password);
    const out = await loginWithSk(username, sk, password);
    return out;
  } catch (e) {
    if (e instanceof ApiError && e.code === "rate_limited") throw e; // 限速透传
    if (e instanceof ApiError && e.code === "user_not_found") throw e;
    // 其余客户端密码学失败（解掩码/形态/GCM）→回落 legacy 通道复核
  }
  const ks = await api<{ sealed_blob: string; pubkey_hex: string }>(
    `/auth/keystore/${encodeURIComponent(username)}`,
  ).catch((e) => {
    if (e instanceof ApiError && e.status === 410) {
      // ⑫O-4 v6 账户（keystore 410——掩码通道取代）：OPAQUE 已失败=密码错
      throw new ApiError("bad_password", "密码错误（OPAQUE 解封失败）", 401);
    }
    throw e;
  });
  const env = parseKeystoreBlob(ks.sealed_blob);
  if (env.v === 6) {
    // v6 账户走本通道（keystore 不再下发——410 语义镜像）：OPAQUE 已失败=密码错
    throw new ApiError("bad_password", "密码错误（OPAQUE 解封失败）", 401);
  }
  let sk: string;
  try {
    sk = await openKeystore(env, password);
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
  const out = await loginWithSk(username, sk, password);
  await upgradeKeystoreIfNeeded(env, password); // v3 存量→v4 惰性重封（同口令，无感）
  // ⑫O-4 v4→v6 惰性迁移（设计 §5.1-3——v3→v4 同款"解锁成功即升级"语义）：
  // 登录成功+密码在手→会话内注册序（evaluate 携会话=真实 β §6.1-c）→回传换新。
  await opaqueMigrateIfNeeded(username, password, sk, env.pk);
  return out;
}

/** v4→v6 惰性迁移（设计 §5.1-3/§5.4 删除事务）：尽力而为——失败不阻断登录
 * （下次登录自动重试，v3→v4 惰性升级同款 UX）；成功后 keystore 通道对该账户
 * 410（掩码通道取代）。本地缓存同步换 v6 信封。 */
async function opaqueMigrateIfNeeded(
  username: string,
  password: string,
  sk: string,
  pk: string,
): Promise<void> {
  try {
    const mats = await opaqueMigrateMaterials(username, password, sk, pk);
    await api("/auth/opaque/migrate", {
      method: "POST",
      body: JSON.stringify({
        sealed_blob: mats.sealed_blob,
        masking_key_hex: mats.masking_key_hex,
        kdf_salt_hex: mats.kdf_salt_hex,
        kdf_iter: mats.kdf_iter,
      }),
    });
    const v6env = JSON.parse(mats.sealed_blob) as import("./keystore").KeystoreV6;
    storeKeystore(v6env); // 本地缓存换代（后续解锁走 OPAQUE 通道）
  } catch (e) {
    console.warn("[opaque] v6 惰性迁移未完成（下次登录自动重试）", e);
  }
}

/** v4 惰性升级（批 2-2.1）：存量 v3 密封件解封成功后以同口令 v4 重封并回传
 * 服务端换新（本地缓存同步）——迁移语义"解锁成功即升级"。尽力而为：失败
 * 不阻断登录（下次登录自动重试），不打断用户路径。 */
async function upgradeKeystoreIfNeeded(env: AccountKeystore, password: string): Promise<void> {
  if (env.v !== 3) return;
  try {
    const sk = await openKeystoreV3(env, password);
    if (!skMatchPub(sk, env.pk)) return;
    const fresh = await sealKeystoreV4(sk, env.pk, password);
    await api("/auth/keystore/upgrade", {
      method: "POST",
      body: JSON.stringify({ sealed_blob: JSON.stringify(fresh) }),
    });
    storeKeystore(fresh);
    cacheSk(sk); // storeKeystore 清了内存钥缓存——升级路径重挂（同一把钥）
  } catch (e) {
    console.warn("[keystore] v4 惰性升级未完成（下次登录自动重试）", e);
  }
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

/** 跨设备恢复：本机无 fzCred 而服务器有密封资料→解封落盘（换设备登录即达）。
 * 槽形态分派（缺陷 B 二层配套）：v6 槽（rwd 密封——v6 改密后的产物）以当前
 * 口令 rwd 解（opaqueRwdMaterials 同序回程）；v4/v3 槽=口令 KEK 原路径。解封
 * 失败不阻断登录——下游页面按「未登记」引导补资料（catch 兜底不变）。 */
async function restoreProfileIfMissing(password: string): Promise<void> {
  if (localStorage.getItem("fzCred")) return;
  const username = cachedUsername();
  const info = await me();
  if (!info?.sealed_profile) return;
  try {
    const slotObj = JSON.parse(info.sealed_profile) as { v?: number };
    const { openProfileSlotV6 } = await import("./keystore");
    const meta = await (async (): Promise<{ cred: unknown; form: unknown }> => {
      if (slotObj?.v === 6 && username) {
        const { opaqueRwdMaterials } = await import("./opaqueClient");
        const { rwd } = await opaqueRwdMaterials(username, password);
        return openProfileSlotV6<{ cred: unknown; form: unknown }>(info.sealed_profile!, rwd);
      }
      return unsealProfileSlot<{ cred: unknown; form: unknown }>(
        slotObj as never,
        password,
      );
    })();
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
// 解封瞬间使用，解封后钥驻内存（关浏览器即焚）。存量 v3 密封件解封成功
// 即惰性重封 v4（同口令回传服务端——批 2-2.1 无感升级）。
export async function unlockSk(password: string): Promise<string> {
  const { loadKeystore, isLegacyKeystore, openKeystore, openWithPassphrase } = await import("./keystore");
  const username = cachedUsername();
  if (!username) throw new ApiError("not_logged_in", "未登录", 401);
  const local = loadKeystore();
  if (local && !isLegacyKeystore(local)) {
    const v = (local as { v?: number }).v;
    if (v === 6) {
      // ⑫O-5 v6 本地信封：KEK 源=rwd（需 evaluate 回程——服务端无口令材料）
      const sk = await opaqueUnlockSk(username, password);
      cacheSk(sk);
      return sk;
    }
    if (v === 3 || v === 4) {
      let sk = "";
      try {
        sk = await openKeystore(local as import("./keystore").AccountKeystore, password);
        if (!skMatchPub(sk, (local as { pk: string }).pk)) throw new KeystoreError("密钥核对失败");
      } catch { /* 本地不可用——回落服务器密封件 */ }
      if (sk) {
        cacheSk(sk);
        await upgradeKeystoreIfNeeded(local as import("./keystore").AccountKeystore, password);
        return sk;
      }
    } else {
      const sk = openWithPassphrase(local as never, password);
      cacheSk(sk);
      return sk;
    }
  }
  const ks = await api<{ sealed_blob: string; pubkey_hex: string }>(
    `/auth/keystore/${encodeURIComponent(username)}`,
  ).catch((e) => {
    if (e instanceof ApiError && e.status === 410) {
      // ⑫O-4 v6 账户（keystore 410——掩码通道取代）：OPAQUE 解封回程
      return null;
    }
    throw e;
  });
  if (ks === null) {
    const sk = await opaqueUnlockSk(username, password);
    cacheSk(sk);
    return sk;
  }
  const env = parseKeystoreBlob(ks.sealed_blob);
  let sk: string;
  try {
    sk = await openKeystore(env, password);
  } catch (e) {
    if (e instanceof KeystoreError) throw new ApiError("bad_password", "密码错误（密封件解封失败）", 401);
    throw e;
  }
  if (!skMatchPub(sk, env.pk) || env.pk.toLowerCase() !== ks.pubkey_hex.toLowerCase()) {
    throw new ApiError("key_mismatch", "密封件与账户公钥不匹配", 409);
  }
  cacheSk(sk);
  await upgradeKeystoreIfNeeded(env, password);
  return sk;
}

// ---- 自助修改密码（2026-10-12 修整窗口 P1——pm 走查件 Q4-1）----
// 改密码=重封不动钥：私钥 sk 不变（登录挑战-应答/操作签名语义不受影响），
// 新密码 KEK 重封 v4 信封+资料密封件（同一请求原子换新——旧密码不得再解
// 任何密封件）。会话延续（Cookie 会话与密码无涉）；服务端逐笔入台账。

/** 当前密码错=unlockSk 抛 bad_password；新密码规范由调用方以
 * checkPasswordRules（lib/enroll）先行校验（与注册/激活同门槛）。
 * ⑫O-5 v6 感知：v6 账户=v6' 重封+新掩码钥原子换新（盐/迭代取 evaluate 响应
 * 账面值——§5.6 不轮换）；v4 存量保留 v4 语义。v6 判定=本地面板快路径+
 * me() sealed_blob 服务端权威双源（缺陷 B 根修——全新浏览器本地面板缺失时
 * 仍正确选 v6 路径，不再误发 v4 信封吃 422）。缺陷 B 二层：v6 账户的资料
 * 密封槽改密时须重封为 v6 profile 槽（rwd 密封——服务端
 * _normalize_profile_slot_v6 契约；v4 槽原样重发=400 bad_profile_slot）。 */
export async function changePassword(currentPw: string, newPw: string): Promise<void> {
  const username = cachedUsername();
  if (!username) throw new ApiError("not_logged_in", "未登录", 401);
  const sk = await unlockSk(currentPw); // 解封+公钥核对（错密码即拒，不烧服务端）
  const sm2Any = sm2 as unknown as { getPublicKeyFromPrivateKey: (sk: string) => string };
  const pk = sm2Any.getPublicKeyFromPrivateKey(sk).replace(/^04/, "");
  // me() 单源双用（缺陷 B 根修 2026-10-17）：资料密封件重封 + v6 形态权威判定。
  const info = await me();
  // ⑫O-5 v6 感知（缺陷 B 根修）：本地面板版本检测只是快路径——**全新浏览器
  // （本地面板缺失/换设备被清扫）不构成 v4 存量的证据**。权威判据=me() 回执
  // 的 sealed_blob 即服务端现行密封件：v6 账户存的就是 v6' 信封（keystore 端
  // 点对 v6 账户 410——服务端已无 v4 密封件可下发的镜像语义）。判定错档代价
  // 不对称：v6 账户误走 v4 路径=发 v4 信封不携掩码钥 → 422 v6_change_required
  // 改密必败（手测实弹 final_ui_04 全新浏览器实证）；v4 存量维持 v4 路径语义
  // 零变化。sealed_blob 形态不可判（理论不达）=维持本地面板判定——错档仍由
  // 服务端语义人话拒绝（422 原文呈现），不静默吞。
  const { loadKeystore, isLegacyKeystore, openProfileSlotV6, sealProfileSlotV6 } =
    await import("./keystore");
  const local = loadKeystore();
  let isV6 = local !== null && !isLegacyKeystore(local) && (local as { v?: number }).v === 6;
  if (!isV6 && info?.sealed_blob) {
    try {
      isV6 = JSON.parse(info.sealed_blob).v === 6;
    } catch { /* 形态不可判=维持本地面板判定（服务端权威拒绝兜底） */ }
  }
  // 资料密封件重封（pilot 专属——有槽才动）。旧槽解封按形态分派：v6 槽
  // （rwd 密封——上一轮 v6 改密的产物）以当前口令 rwd 解；v4/v3 槽（注册期
  // 口径）以口令 KEK 解。v6 账户的重封形态=v6 profile 槽（新口令 rwd——下方
  // v6 分支取 fresh6.rwd）；v4 存量维持口令 KEK 槽原语义。
  let sealedProfile: string | undefined;
  let v6ProfileMeta: { cred: unknown; form: unknown } | null = null;
  if (info?.sealed_profile) {
    try {
      const slotObj = JSON.parse(info.sealed_profile) as { v?: number };
      const meta = await (async (): Promise<{ cred: unknown; form: unknown }> => {
        if (isV6 && slotObj?.v === 6) {
          const { opaqueRwdMaterials } = await import("./opaqueClient");
          const { rwd } = await opaqueRwdMaterials(username, currentPw);
          return openProfileSlotV6<{ cred: unknown; form: unknown }>(info.sealed_profile!, rwd);
        }
        return unsealProfileSlot<{ cred: unknown; form: unknown }>(
          slotObj as never,
          currentPw,
        );
      })();
      if (isV6) {
        v6ProfileMeta = meta; // 槽体在 v6 分支以新 rwd 重封（fresh6.rwd）
      } else {
        sealedProfile = JSON.stringify(await sealProfileSlot(meta, newPw));
      }
    } catch {
      throw new ApiError(
        "profile_reseal_failed",
        "资料密封件重封失败（已中止改密）——请重试；密封件未被变更",
        500,
      );
    }
  }
  if (isV6) {
    const { response } = await opaqueEvaluate(username, currentPw); // 携会话=真 β+账面盐
    const fresh6 = await opaqueChangeMaterials(
      username, newPw, sk, pk, response.kdf_salt_hex, response.kdf_iter,
    );
    // 缺陷 B 二层：v6 账户资料槽重封=v6 profile 槽（新口令 rwd 密封）——
    // 服务端 _normalize_profile_slot_v6 契约（v4 槽原样重发=400 实弹实证）。
    let profileV6: string | undefined;
    if (v6ProfileMeta !== null) {
      profileV6 = await sealProfileSlotV6(v6ProfileMeta, fresh6.rwd);
    }
    await api("/auth/password/change", {
      method: "POST",
      body: JSON.stringify({
        sealed_blob: fresh6.sealed_blob,
        masking_key_hex: fresh6.masking_key_hex,
        ...(profileV6 ? { sealed_profile: profileV6 } : {}),
      }),
    });
    storeKeystore(JSON.parse(fresh6.sealed_blob) as import("./keystore").KeystoreV6);
    return;
  }
  const fresh = await sealKeystoreV4(sk, pk, newPw);
  await api("/auth/password/change", {
    method: "POST",
    body: JSON.stringify({
      sealed_blob: JSON.stringify(fresh),
      ...(sealedProfile ? { sealed_profile: sealedProfile } : {}),
    }),
  });
  storeKeystore(fresh); // 本地缓存同步换新（明文钥仍只驻内存）
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
