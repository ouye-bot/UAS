/** OPAQUE 客户端编排（⑫O-5——设计 §2.2/§2.3/§5.1-3 线协议组装）：原语
 * lib/opaque（纯函数——零 api 依赖）+本模块（api 编排+信封落地面）。
 * 与后端 app/accounts/client.py 逐字节对拍（tests/lib/opaque.test.ts 同向量
 * 双端钉死）。EvaluateResponse 五键恒形（设计 §2.1）。 */

import { api } from "./api";
import { hexToBytes } from "../crypto/sm4gcm";
import { KeystoreError, openEnvelopeV6, sealEnvelopeV6 } from "./keystore";
import type { ApiError as FzApiError } from "./api";
import { blind, deriveRwdChain, finalize, unmaskCredentialResponse } from "./opaque";

export interface EvaluateResponse {
  evaluated_message: string;
  masking_nonce: string;
  masked_response: string;
  kdf_salt_hex: string;
  kdf_iter: number;
}

export interface OpaqueRegisterMaterials {
  sealed_blob: string; // v6 信封 JSON 串
  masking_key_hex: string;
  kdf_salt_hex: string;
  kdf_iter: number;
}

/** 线协议第 1 步：blind→POST /auth/opaque/evaluate（恒五键）。 */
export async function opaqueEvaluate(
  username: string,
  password: string,
): Promise<{ response: EvaluateResponse; r: bigint }> {
  const { alphaHex, r } = await blind(username, password);
  const response = await api<EvaluateResponse>("/auth/opaque/evaluate", {
    method: "POST",
    body: JSON.stringify({ username, alpha_hex: alphaHex }),
  });
  return { response, r };
}

/** 稳态 OPAQUE 解封（§2.3 全步）：unblind→rwd（响应回传盐/迭代）→解掩码→
 * 解封。错口令=解掩码/信封形态/GCM 败（KeystoreError/ValueError）——人话判词源。 */
export async function opaqueUnlockSk(
  username: string,
  password: string,
): Promise<string> {
  try {
    const { response, r } = await opaqueEvaluate(username, password);
    const oprfOutput = await finalize(r, response.evaluated_message);
    const { rwd, maskingKey } = await deriveRwdChain(
      oprfOutput,
      response.kdf_salt_hex,
      response.kdf_iter,
    );
    const masked = hexToBytes(response.masked_response);
    const nonce = hexToBytes(response.masking_nonce);
    const envelope = await unmaskCredentialResponse(maskingKey, nonce, masked);
    const envObj = JSON.parse(new TextDecoder().decode(envelope)) as import("./keystore").KeystoreV6;
    return openEnvelopeV6(envObj, rwd);
  } catch (e) {
    // UX 纪律（设计 §7.2）：非 ApiError 的密码学失败（解掩码/形态/GCM）统一
    // 人话化——错口令判词与 v4 通道同款
    if (typeof e === "object" && e !== null && "code" in e && "status" in e) throw e;
    throw new KeystoreError("解封失败（密码错误或凭据被篡改）");
  }
}

/** 注册/激活材料四件套（D-8——盐/迭代客户端生成随件上传；k 经 evaluate 回程
 * ——fake 分支同构计算真实 β，§6.1）。 */
export async function opaqueRegisterMaterials(
  username: string,
  password: string,
  skHex: string,
  pkHex: string,
  iterations = 600_000,
): Promise<OpaqueRegisterMaterials> {
  const saltHex = randHexLocal(16);
  const { response, r } = await opaqueEvaluate(username, password);
  const oprfOutput = await finalize(r, response.evaluated_message);
  const { rwd, maskingKey } = await deriveRwdChain(oprfOutput, response.kdf_salt_hex, response.kdf_iter);
  void saltHex;
  void iterations;
  // 盐/迭代以**响应回传的账面值**为准（fake 态=服务端随机盐——注册流不消费
  // 掩码字段；账面值与登录回传一致——D-8 单源）。
  const env = await sealEnvelopeV6(skHex, pkHex, rwd);
  return {
    sealed_blob: JSON.stringify(env),
    masking_key_hex: Array.from(maskingKey, (b) => b.toString(16).padStart(2, "0")).join(""),
    kdf_salt_hex: response.kdf_salt_hex,
    kdf_iter: response.kdf_iter,
  };
}

/** v6' 改密材料（§5.6——盐/迭代取账面值不轮换；evaluate α=新口令派生——β 回程
 * 经解盲得新口令的 oprf_output；会话授权面）。 */
export async function opaqueChangeMaterials(
  username: string,
  newPassword: string,
  skHex: string,
  pkHex: string,
  saltHex: string,
  iterations: number,
): Promise<{ sealed_blob: string; masking_key_hex: string }> {
  const { response, r } = await opaqueEvaluate(username, newPassword);
  const oprfOutput = await finalize(r, response.evaluated_message);
  const { rwd, maskingKey } = await deriveRwdChain(oprfOutput, saltHex, iterations);
  const env = await sealEnvelopeV6(skHex, pkHex, rwd);
  return {
    sealed_blob: JSON.stringify(env),
    masking_key_hex: Array.from(maskingKey, (b) => b.toString(16).padStart(2, "0")).join(""),
  };
}

/** 登录后惰性迁移材料（O-4 §5.1-3——同注册序；须携会话——真 β §6.1-c）。 */
export async function opaqueMigrateMaterials(
  username: string,
  password: string,
  skHex: string,
  pkHex: string,
): Promise<OpaqueRegisterMaterials> {
  return opaqueRegisterMaterials(username, password, skHex, pkHex);
}

function randHexLocal(nBytes: number): string {
  const buf = new Uint8Array(nBytes);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}
