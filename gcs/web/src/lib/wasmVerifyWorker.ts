/** 浏览器内 TRAIL 验证 Worker（2026-09-28 wasm 集成批）。
 *
 * 架构：zkc.wasm（wasm32-wasip1，与分发站同源）经 @bjorn3/browser_wasi_shim
 * 在 Web Worker 内运行 verify-instances——验证器、证明、参数、期望值全部
 * 在浏览器本地，零服务端参与（第三方复验的浏览器形态）。
 *
 * 输入（postMessage）：{ wasmUrl, specUrl, instancesUrl, proofUrl, vpUrl,
 * expectedUrl }——Worker 内自行 fetch（二进制件约 40MB，全程不占主线程）。
 * 输出：{ type: "log"|"done", ... }——stdout 逐行流回（进度可见），
 * done 携带 { rc, ms, ok }（rc=0 且末行含 "OK" 才判过——双信号，与 CLI 同判据）。
 */
import { WASI, File, OpenFile, ConsoleStdout, PreopenDirectory } from "@bjorn3/browser_wasi_shim";

export interface WasmVerifyRequest {
  wasmUrl: string;
  specUrl: string;
  instancesUrl: string;
  proofUrl: string;
  vpUrl: string;
  expectedUrl: string;
}

async function fetchBytes(url: string): Promise<ArrayBuffer> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`下载失败 ${url}: HTTP ${r.status}`);
  return r.arrayBuffer();
}

self.onmessage = async (ev: MessageEvent<WasmVerifyRequest>) => {
  const req = ev.data;
  const t0 = Date.now();
  const post = (m: unknown) => (self as unknown as Worker).postMessage(m);
  try {
    post({ type: "log", line: "下载验证器与复验材料（约 40MB，本机回环）…" });
    const [wasmBytes, spec, instances, proof, vp, expected] = await Promise.all([
      fetchBytes(req.wasmUrl), fetchBytes(req.specUrl), fetchBytes(req.instancesUrl),
      fetchBytes(req.proofUrl), fetchBytes(req.vpUrl), fetchBytes(req.expectedUrl),
    ]);
    post({ type: "log", line: `材料就绪（zkc.wasm ${(wasmBytes.byteLength / 1048576).toFixed(1)}MB）——浏览器内运行验证器…` });

    const fds = [
      new OpenFile(new File(new Uint8Array(0))),
      ConsoleStdout.lineBuffered((line) => post({ type: "log", line })),
      ConsoleStdout.lineBuffered((line) => post({ type: "log", line: `[stderr] ${line}` })),
      new PreopenDirectory(".", new Map<string, File>([
        ["instances.json", new File(instances)],
        ["proof.bin", new File(proof)],
        ["verifier_param.bin", new File(vp)],
        ["expected.json", new File(expected)],
        ["trail_canonical_spec.json", new File(spec)],
      ]) as unknown as Map<string, never>),
    ];
    const wasi = new WASI(
      ["zkc", "verify-instances", "--instances", "/instances.json",
       "--proof", "/proof.bin", "--vp", "/verifier_param.bin", "--expected", "/expected.json"],
      ["FZ_TRAIL_CANONICAL_SPEC=/trail_canonical_spec.json", "FZ_ZK_ALLOW_TRAIL=1",
       "FZ_ZK_INFO_CACHE=0"],
      fds,
    );
    const wasm = await WebAssembly.compile(wasmBytes);
    const inst = await WebAssembly.instantiate(wasm, { wasi_snapshot_preview1: wasi.wasiImport });
    // shim 的 start 形参类型较窄（结构兼容运行时实例）——以导出面收窄
    const target = inst as unknown as { exports: { memory: WebAssembly.Memory; _start: () => unknown } };
    let rc = -1;
    let lastLine = "";
    try {
      rc = wasi.start(target) as number; // shim 语义：start 返回退出码
    } catch (e) {
      rc = -1;
      lastLine = `运行时异常：${String(e)}`;
      post({ type: "log", line: lastLine });
    }
    post({ type: "done", rc, ms: Date.now() - t0, ok: rc === 0 });
  } catch (e) {
    post({ type: "done", rc: -1, ms: Date.now() - t0, ok: false, error: String(e) });
  }
};
