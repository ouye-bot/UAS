/** 后端/桥接 API 客户端（B8）——统一错误规范化：业务拒绝 = {code,message,data:null}。 */

export interface FzError {
  code: string;
  message: string;
  status: number;
}

export class ApiError extends Error implements FzError {
  code: string;
  declare message: string;
  status: number;
  constructor(code: string, message: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function apiBase(): string {
  return alignSameSite(localStorage.getItem("fzApiBase") || "http://127.0.0.1:8000");
}

export function bridgeBase(): string {
  return localStorage.getItem("fzBridgeBase") || "http://127.0.0.1:8100";
}

/** 同站对齐（账户批）：会话 Cookie 受 SameSite 约束——localhost 页面 +
 * 127.0.0.1 API 属跨站（Cookie 不随 fetch 携带）。环回地址与页面主机对齐
 * （两者同为本机），使 API 与页面恒同站；非环回部署地址原样保留。 */
function alignSameSite(base: string): string {
  try {
    const u = new URL(base);
    const host = location.hostname;
    const loop = (h: string) => h === "localhost" || h === "127.0.0.1" || h === "[::1]";
    if (loop(u.hostname) && loop(host) && u.hostname !== host) u.hostname = host;
    return u.toString().replace(/\/+$/, "");
  } catch {
    return base;
  }
}

export function setApiBase(v: string): void {
  localStorage.setItem("fzApiBase", v.replace(/\/+$/, ""));
}

export function setBridgeBase(v: string): void {
  localStorage.setItem("fzBridgeBase", v.replace(/\/+$/, ""));
}

async function parse(res: Response): Promise<any> {
  try {
    return await res.json();
  } catch {
    return { code: `http_${res.status}`, message: res.statusText, data: null };
  }
}

/** 后端调用：返回 data；业务拒绝/HTTP 错误抛 ApiError（真实拒绝原样透传）。
 * credentials=include：会话 Cookie 面（/auth、审计/机构）依赖携带——同站对齐
 * 后 SameSite=Lax 放行。 */
export async function api<T = any>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(apiBase() + path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  const body = await parse(res);
  if (!res.ok) {
    const d = body?.detail ?? body ?? {};
    throw new ApiError(d.code ?? `http_${res.status}`, d.message ?? JSON.stringify(d), res.status);
  }
  if (body && typeof body === "object" && "code" in body && body.code !== "ok") {
    throw new ApiError(body.code, body.message ?? "", res.status);
  }
  return (body?.data ?? body) as T;
}

/** 桥接调用：任意 JSON 直通（bridge 端点语义各异）。 */
export async function bridge<T = any>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(bridgeBase() + path, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  const body = await parse(res);
  if (!res.ok) {
    const d = body?.detail ?? body ?? {};
    throw new ApiError(d.code ?? `http_${res.status}`, d.message ?? JSON.stringify(d), res.status);
  }
  return body as T;
}

/** bytes → hex（小工具）。 */
export function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** hex → bytes。 */
export function fromHex(h: string): Uint8Array {
  const s = h.trim().toLowerCase().replace(/^0x/, "");
  if (s.length % 2) throw new ApiError("bad_hex", "hex 长度须为偶数", 0);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const v = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(v)) throw new ApiError("bad_hex", "非法 hex 字符", 0);
    out[i] = v;
  }
  return out;
}

/** CSPRNG hex（红线：随机性一律 crypto.getRandomValues——Math.random 禁用，B0 门禁扫描）。 */
export function randHex(nBytes: number): string {
  const b = new Uint8Array(nBytes);
  crypto.getRandomValues(b);
  return toHex(b);
}

/** CSPRNG 均匀整数 [0, max)（拒绝采样——无模偏置）。 */
export function randInt(max: number): number {
  if (max <= 0) throw new RangeError("max 须为正");
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  let v = 0;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return v % max;
}
