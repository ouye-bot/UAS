/** 浏览器内 TRAIL 验证入口（主线程侧）——Worker 生命周期与结果面。
 * 尖峰实测（Node 同 shim 0.4.2）：正例 OK / 篡改链头拒绝；浏览器 JS 运行时
 * 全程约 1.5~2.5 分钟（wasmtime 档 8s——快 13×+，慢在 V8 数值面，属运行时
 * 开销非验证语义差异；时长在下单按钮旁如实标注）。 */
export interface WasmVerifyResult { rc: number; ms: number; ok: boolean; error?: string }

export function runWasmVerify(
  urls: { wasmUrl: string; specUrl: string; instancesUrl: string; proofUrl: string;
          vpUrl: string; expectedUrl: string },
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
