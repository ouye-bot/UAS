/** 浏览器内 TRAIL 验证入口（主线程侧）——Worker 生命周期与结果面。
 * 尖峰实测（Node 同 shim 0.4.2）：正例 OK / 篡改链头拒绝；浏览器 JS 运行时
 * 全程约 1.5~2.5 分钟（wasmtime 档 8s——快 13×+，慢在 V8 数值面，属运行时
 * 开销非验证语义差异；时长在下单按钮旁如实标注）。
 * enginePubUrl=后端 /authz/engine/pub（现役引擎公钥）——Worker 验证前必拉，
 * 不可达即 fail-closed 拒验（钥换代根治批：验证基准=运行时现役钥）。 */
export interface WasmVerifyResult { rc: number; ms: number; ok: boolean; error?: string }

/** 分发面现役代查询参（2026-10-15 缓存不可达根修补刀②·前端兜底）：从
 * /verify/api/checks 的 artifacts 里 zkc.wasm.sha256 派生 `gen=<前 12 hex>`
 * ——URL 随代变 ⟹ 浏览器缓存键必换代（服务端 Cache-Control: no-cache 整域
 * 中间件为第一兜底；本参为第二兜底：即使响应头缺失/中间层改写，键变也必
 * 回源）。fail-closed：checks 不可达/非 200/信封非法/缺 zkc.wasm 件/非 64hex
 * =返回 null=退回无参 URL（不阻塞验证流程——此时缓存正确性由服务端 no-cache
 * 单兜底；绝不构造假 gen 冒充换代）。 */
export async function fetchDistGen(checksUrl: string): Promise<string | null> {
  try {
    const r = await fetch(checksUrl);
    if (!r.ok) return null;
    const j = (await r.json()) as {
      data?: { artifacts?: { name?: unknown; sha256?: unknown }[] };
    };
    const wasm = j?.data?.artifacts?.find((a) => a?.name === "zkc.wasm");
    const sha = wasm?.sha256;
    if (typeof sha !== "string" || !/^[0-9a-f]{64}$/.test(sha)) return null;
    return `gen=${sha.slice(0, 12)}`;
  } catch {
    return null;
  }
}

/** gen 拼接（null=原样退回——绝不产生 ?gen=null 之类的伪代键）。 */
export function withGen(url: string, gen: string | null): string {
  return gen ? `${url}?${gen}` : url;
}

export function runWasmVerify(
  urls: { wasmUrl: string; enginePubUrl: string; specUrl: string; instancesUrl: string;
          proofUrl: string; vpUrl: string; expectedUrl: string },
  onLog: (line: string) => void,
): Promise<WasmVerifyResult> {
  return new Promise((resolve) => {
    const worker = new Worker(
      new URL("./wasmVerifyWorker.ts", import.meta.url), { type: "module" });
    worker.onmessage = (ev: MessageEvent) => {
      const m = ev.data as { type: string; line?: string } & WasmVerifyResult;
      if (m.type === "log" && m.line) onLog(m.line);
      if (m.type === "done") {
        worker.terminate();
        resolve({ rc: m.rc, ms: m.ms, ok: m.ok, error: (m as { error?: string }).error });
      }
    };
    worker.onerror = (e) => {
      worker.terminate();
      resolve({ rc: -1, ms: 0, ok: false, error: String((e as ErrorEvent).message ?? e) });
    };
    worker.postMessage(urls);
  });
}
