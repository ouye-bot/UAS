/** 出示与对账决策面（L3 链上留痕深化·接线批）。
 *
 * 「我的合规档案」行展开的三个出示动作 + 链上对账徽章里**不碰网络与 DOM**
 * 的决策逻辑收拢于此（视图只做 IO）——浏览器内验证目标窗选择、对账三态
 * 判定、出示包 URL 形态，全部纯函数可单测。
 *
 * 诚实纪律（人话四军规在数据层的落点）：
 * - 浏览器内验证只对有 TRAIL 判决的窗口成立（zkc.wasm 的 verify-instances
 *   是 TRAIL 验证专用——AUTH 案卷不能跑=动作隐藏，功能不适用≠不可用）；
 * - 对账三态如实：一致（绿）/不一致（红——不应出现但如实显示）/链不可达
 *   （灰——可重试），链读不到绝不冒充一致。
 */
import type { LogbookEntry } from "./material";

/** 档案行第一个有 TRAIL 判决且案卷号在场的窗口（浏览器内验证目标）。
 * 无 TRAIL 窗口返回 null——该行动作隐藏。窗口键经 JSON 落盘回读为字符串，
 * 数值化后升序取第一（档案行多窗时验最早一窗）。 */
export function firstTrailWindow(
  e: LogbookEntry,
): { w: number; caseId: string } | null {
  const ws = Object.keys(e.trailVerdicts)
    .map(Number)
    .filter((w) => Number.isFinite(w))
    .sort((a, b) => a - b);
  for (const w of ws) {
    // JSON 落盘回读后窗口键是字符串——两种形态都取（Record<number> 索引串须显式）
    const cid = e.tripCaseIds[w] ?? (e.tripCaseIds as Record<string, string>)[String(w)];
    if (typeof cid === "string" && cid) return { w, caseId: cid };
  }
  return null;
}

/** 出示包下载 URL（桥侧端点形态——与 TrailView 案卷件端点同源：
 * GET {bridge}/prove/case/{case_id}/bundle → application/zip）。 */
export function bundleUrlFor(base: string, caseId: string): string {
  return `${base}/prove/case/${caseId}/bundle`;
}

/** /chain/record/{authId} 响应的消费面（backend app/chain/panel.py 契约的
 * 结构子集——多出的字段不拒收，少关键字段按降级处理）。 */
export interface ReconDetail {
  proof_digest_hex: string;
  tx_hash: string;
  t_start: number;
  t_end: number;
  class_id: number;
  alt_max_m: number;
  chain: { proof_digest_hex: string; token_hash_hex: string; match: boolean } | null;
  chain_error?: string;
}

export type ReconState =
  | { kind: "match"; digest: string; txHash: string }
  | { kind: "mismatch"; reason: string }
  | { kind: "unreachable"; reason: string };

/** 对账判定（三态）：两级比对——
 * ① chain.match：链上原文 proofDigest vs 登记库指纹（backend 机器对账）；
 * ② 本行档案参数 vs 链侧登记参数（时间窗/机型类/上限——本机积累对照）。
 * fetchErr/链不可达=灰态（可重试），绝不冒充一致；参数不一致=红态如实点名。 */
export function reconVerdict(
  d: ReconDetail | null,
  e: LogbookEntry,
  fetchErr: string | null,
): ReconState | null {
  if (fetchErr) return { kind: "unreachable", reason: fetchErr };
  if (!d) return null;
  if (!d.chain) return { kind: "unreachable", reason: d.chain_error || "链暂不可达" };
  if (!d.chain.match) {
    return { kind: "mismatch", reason: "链上公示指纹与登记指纹不一致" };
  }
  const diffs: string[] = [];
  if (e.tStart != null && d.t_start != null && e.tStart !== d.t_start) diffs.push("时间窗起点");
  if (e.tEnd != null && d.t_end != null && e.tEnd !== d.t_end) diffs.push("时间窗止点");
  if (e.classId != null && d.class_id != null && e.classId !== d.class_id) diffs.push("机型类");
  if (e.altMax != null && d.alt_max_m != null && e.altMax !== d.alt_max_m) diffs.push("高度上限");
  if (diffs.length) {
    return { kind: "mismatch", reason: `本行档案与链侧登记不一致：${diffs.join("／")}` };
  }
  return { kind: "match", digest: d.chain.proof_digest_hex, txHash: d.tx_hash };
}

/** 出示包按钮 title（expected 缺失情形的诚实提示——不阻塞下载，只说明
 * 包内验证命令的前置）。expectedKnown=null 表示未知（探测未完成/失败）：
 * 不出提示，不臆造。 */
export function bundleTitle(
  e: LogbookEntry,
  expectedKnown: boolean | null,
): string {
  if (!e.caseId) return "本行无出证案卷号——无法生成出示包";
  const base =
    "把本行出证案卷的全部证明件打包为一个 zip（含 README 人话验证指引与逐件 sha256）——可交付任何第三方独立验证";
  return expectedKnown === false
    ? `${base}；注意：该案卷缺期望绑定 expected.json——包内验证命令需先补齐期望绑定（见下载区）`
    : base;
}
