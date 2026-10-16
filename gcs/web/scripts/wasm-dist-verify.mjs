/** 分发面 zkc.wasm 本机实弹验证器（node + @bjorn3/browser_wasi_shim）。
 *
 * 与浏览器 Worker（src/lib/wasmVerifyWorker.ts）1:1 同路径：同一 shim、同一
 * WASI 预开文件布局、同一 env 注入（FZ_ENGINE_PUB_HEX/FZ_TRAIL_CANONICAL_SPEC/
 * FZ_ZK_ALLOW_TRAIL）——把「浏览器内验证」变成可在任何机器命令行复跑的实弹面。
 *
 * 用途：
 * ① 红绿复现（分发面 wasm 与现役引擎代差 = 本脚本在真链材料上实弹红）；
 * ② backend 门禁测试 test_verify_dist_generation.py 的执行器——分发面与现役
 *    引擎绑定报文代同步检查（binding 探针：装配过门即算同步，后续证明验证
 *    失败与本门无关）。
 *
 * 用法：
 *   node scripts/wasm-dist-verify.mjs --wasm <zkc.wasm> --spec <spec.json> \
 *     --pub <engine_pub_hex> [--instances f] [--proof f] [--vp f] [--expected f] \
 *     [--binding-probe]
 * 退出码：0=verify-instances OK（rc=0）；2=运行完成但验证器拒绝（rc!=0）；
 *        3=环境/参数错误。--binding-probe 档：只要装配面未报「字节字段 binding
 *        非法」即退出 0（引擎绑定代同步探针——不要求完整证明验证通过）。
 */
import { readFileSync } from "node:fs";
import { WASI, File, OpenFile, ConsoleStdout, PreopenDirectory } from "@bjorn3/browser_wasi_shim";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const wasmPath = arg("wasm");
const specPath = arg("spec");
const enginePubHex = arg("pub");
if (!wasmPath || !specPath || !enginePubHex) {
  console.error("用法: node wasm-dist-verify.mjs --wasm <zkc.wasm> --spec <spec.json> --pub <hex> [...]");
  process.exit(3);
}
const bindingProbe = process.argv.includes("--binding-probe");

const lines = [];
const bytes = (p) => new Uint8Array(readFileSync(p));
const fileOrEmpty = (p) => (p ? bytes(p) : new Uint8Array(0));

const fds = [
  new OpenFile(new File(new Uint8Array(0))),
  ConsoleStdout.lineBuffered((line) => { lines.push(line); process.stdout.write(`${line}\n`); }),
  ConsoleStdout.lineBuffered((line) => { lines.push(`[stderr] ${line}`); process.stderr.write(`[stderr] ${line}\n`); }),
  new PreopenDirectory(".", new Map([
    ["instances.json", new File(fileOrEmpty(arg("instances")))],
    ["proof.bin", new File(fileOrEmpty(arg("proof")))],
    ["verifier_param.bin", new File(fileOrEmpty(arg("vp")))],
    ["expected.json", new File(fileOrEmpty(arg("expected")))],
    ["trail_canonical_spec.json", new File(bytes(specPath))],
  ])),
];
const wasi = new WASI(
  ["zkc", "verify-instances", "--instances", "/instances.json",
    "--proof", "/proof.bin", "--vp", "/verifier_param.bin", "--expected", "/expected.json"],
  ["FZ_TRAIL_CANONICAL_SPEC=/trail_canonical_spec.json", "FZ_ZK_ALLOW_TRAIL=1",
    "FZ_ZK_INFO_CACHE=0", `FZ_ENGINE_PUB_HEX=${enginePubHex}`],
  fds,
);
const wasm = await WebAssembly.compile(bytes(wasmPath));
const inst = await WebAssembly.instantiate(wasm, { wasi_snapshot_preview1: wasi.wasiImport });
const target = inst;
let rc = -1;
try {
  rc = wasi.start(target);
} catch (e) {
  console.error(`运行时异常: ${e}`);
  process.exit(2);
}
const all = lines.join("\n");
if (bindingProbe) {
  // 引擎绑定代同步探针（判据三态，fail-closed）：
  //   红=装配面拒绝 binding（报文代差/钥代差的确定性病征「装配拒绝」）；
  //   绿=装配过门——此后因材料缺失的确定性病征（期望绑定损坏/instances 解析
  //       类）在场=验证器已越过 binding 验签门（探针不要求完整证明验证通过）；
  //   其他任何形态=不可判定=红（绝不把意外早退当过门——防假绿）。
  const pastAssembly = /期望绑定|instances|实例|proof|证明/.test(all);
  if (/装配拒绝/.test(all) || /binding 非法/.test(all)) {
    console.error("[binding-probe] 分发面验证器拒绝现役 binding——代差实锤");
    process.exit(2);
  }
  if (rc === 0) {
    console.error("[binding-probe] 验证器完整通过——分发面与现役引擎报文/钥代同步");
    process.exit(0);
  }
  if (pastAssembly) {
    console.error("[binding-probe] 装配面接受现役 binding（材料面后续退出与本探针无关）——代同步");
    process.exit(0);
  }
  console.error("[binding-probe] 运行形态不可判定（既非装配拒绝也无过门病征）——按红处置");
  process.exit(3);
}
process.exit(rc === 0 && /OK/.test(lines[lines.length - 1] ?? "") ? 0 : 2);
