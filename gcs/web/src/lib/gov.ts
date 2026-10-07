/** 治理台契约库（2026-10-04 审计台/机构台前端升格）——结案/验签复核/吊销/
 * 恢复双控的单一对接面。
 *
 * 纪律：
 * - 签名消息拼装与后端同源镜像（audit/collab.py 的 CLOSE_MSG_PREFIX/
 *   collab.close_msg_of；ra/service.py 的 revoke_msg/restore_msg/
 *   restore_countersign_msg）——改任一侧必须两端同步；
 * - 本库只做纯计算与类型（零 fetch/零 DOM）——签名仍由调用方持钥
 *   （lib/auth.signMsg）完成，便于单测与挂载测试分锁。 */

// ---- 签名消息域（与后端前缀逐字一致）----
export const CLOSE_MSG_PREFIX = "FZ-COLLAB-CLOSE|v1|";
export const REVOKE_MSG_PREFIX = "FZ-REVOKE|v1|";
export const RESTORE_MSG_PREFIX = "FZ-RESTORE|v1|";
export const RESTORE_COUNTERSIGN_MSG_PREFIX = "FZ-RESTORE-COUNTERSIGN|v1|";

/** 结案签名消息：FZ-COLLAB-CLOSE|v1|{req_hash}|{conclusion}|{conclusion_text}。
 * conclusion_text 须为已 trim 的定稿（服务端按 strip 后文本验签）。 */
export function closeMsg(reqHashHex: string, conclusion: string, conclusionText: string): string {
  return `${CLOSE_MSG_PREFIX}${reqHashHex}|${conclusion}|${conclusionText}`;
}

/** 撤销签名消息：FZ-REVOKE|v1|{handles 排序拼接}|{reason}|{epoch}——
 * handles 小写化+字典序排序后 "|" 拼接（后端 revoke_msg 同口径）。 */
export function revokeMsg(handles: string[], reason: string, epoch: number): string {
  return `${REVOKE_MSG_PREFIX}${handles
    .map((h) => h.toLowerCase())
    .sort()
    .join("|")}|${reason}|${epoch}`;
}

/** 恢复发起（admin）签名消息：FZ-RESTORE|v1|{handle}|{reason}。 */
export function restoreMsg(handleHex: string, reason: string): string {
  return `${RESTORE_MSG_PREFIX}${handleHex.toLowerCase()}|${reason}`;
}

/** 恢复读核（auditor）签名消息：FZ-RESTORE-COUNTERSIGN|v1|{handle}|{reason}
 * （handle/reason 取自请求行——复核即绑定同一内容）。 */
export function restoreCountersignMsg(handleHex: string, reason: string): string {
  return `${RESTORE_COUNTERSIGN_MSG_PREFIX}${handleHex.toLowerCase()}|${reason}`;
}

// ---- 结案结论（0018 升格：三判词）----
export const CLOSE_CONCLUSIONS = ["verified", "mistaken", "inconclusive"] as const;
export type CloseConclusion = (typeof CLOSE_CONCLUSIONS)[number];

/** 结论元数据（fz-badge 色彩语义：gold=闭环属实/red=误报/gray=存疑——不引入新色）。 */
export const CONCLUSION_META: Record<CloseConclusion, { label: string; tone: string; hint: string }> = {
  verified: { label: "属实", tone: "gold", hint: "违规事实成立——终局判词须附结案说明" },
  mistaken: { label: "误报", tone: "red", hint: "事实不成立或证据不实——结案说明记录判据" },
  inconclusive: { label: "无法查证", tone: "gray", hint: "证据不足——如实存疑，不留空白结论" },
};

export const CONCLUSION_TEXT_MAX = 500;

/** 结案表单校验（与后端 close_request 同判）：结论必选/属实必填说明/≤500 字。
 * 返回人话错误文案；null=通过。 */
export function validateCloseForm(conclusion: string, text: string): string | null {
  if (!conclusion) return "请先选择结案结论（属实/误报/无法查证）";
  if (!CLOSE_CONCLUSIONS.includes(conclusion as CloseConclusion)) return "结案结论须为 verified/mistaken/inconclusive";
  const t = text.trim();
  if (conclusion === "verified" && !t) return "结论为「属实」须填写结案说明——终局判词不留白";
  if (t.length > CONCLUSION_TEXT_MAX) return `结案说明须 ≤${CONCLUSION_TEXT_MAX} 字（当前 ${t.length} 字）`;
  return null;
}

// ---- verify-sigs 判词（历史签名复验）----
export interface SigVerdict {
  ok: boolean | null;
  epoch: number | null;
  reason: string | null;
}
export interface VerifySigsOut {
  id: number;
  req_hash_hex: string;
  auditor: SigVerdict;
  admin: SigVerdict;
}

const SIG_REASON_TEXT: Record<string, string> = {
  not_decided: "尚未批准——无机构签名可验",
  no_sig: "无签名存证",
  no_epoch_key: "签名时点无纪元公钥可回取——如实不判",
  bad_sig: "验签不过——签名与内容不匹配",
};

/** 判词人话（A3）：ok=true →「✓ 纪元 n 验签通过」；reason → 人话映射。 */
export function verdictLabel(v: SigVerdict, side: string): string {
  if (v.ok === true) return `${side} ✓ 纪元 ${v.epoch ?? "—"} 验签通过`;
  if (v.ok === null) return `${side} ${SIG_REASON_TEXT[v.reason ?? ""] ?? v.reason ?? "未决定"}`;
  return `${side} ✗ ${SIG_REASON_TEXT[v.reason ?? ""] ?? "验签未通过"}`;
}

// ---- trace 证据面（A2：设备一致性判词+链上时间线）----
export type DeviceVerdict = "match" | "mismatch" | "no_evidence" | "insufficient";

/** 设备一致性判词（audit/device_check.py device_consistency 消费面）——
 * 四判词色彩语义：teal=一致/red=不一致（借机飞行）/amber=无检查点留痕（可疑）/
 * gray=材料不足（无法核对）。 */
export const DEVICE_VERDICT_META: Record<DeviceVerdict, { label: string; tone: string; hint: string }> = {
  match: { label: "设备一致", tone: "teal", hint: "全部检查点签名与登记 SN₁ 派生公钥核验一致" },
  mismatch: { label: "设备不一致", tone: "red", hint: "存在与登记设备不符的检查点签名——借机飞行嫌疑" },
  no_evidence: { label: "无检查点留痕", tone: "amber", hint: "授权已消费却零检查点锚定——留痕链可疑" },
  insufficient: { label: "材料不足", tone: "gray", hint: "登记材料缺 SN 密文（旧版）——无法交叉核对" },
};

export function deviceVerdictMeta(v: unknown): { label: string; tone: string; hint: string } {
  const key = (typeof v === "string" ? v : "") as DeviceVerdict;
  return DEVICE_VERDICT_META[key] ?? { label: String(v ?? "—"), tone: "gray", hint: "" };
}

export interface CheckpointRow {
  seq: number;
  chain_head?: string;
  chain_head_hex?: string;
  ts: number | string | null;
  device_sig_hex?: string;
  fence_state_hex?: string;
}
export interface ChainEventRow {
  event_type: number;
  event_hash_hex: string;
  block: number;
  tx_hash: string;
  logged_at: string | null;
}
/** 链上事件类型（telemetry/models.py：1=固件围栏 2=地面站 3=通信中断 4=迫降）。 */
export const CHAIN_EVENT_LABEL: Record<number, string> = {
  1: "固件围栏拦截",
  2: "地面站指令",
  3: "通信中断",
  4: "迫降锚定",
};

export interface ChainTrace {
  auth_id?: number;
  auth_record?: Record<string, unknown> | null;
  auth_record_error?: string;
  checkpoints?: CheckpointRow[];
  events?: ChainEventRow[];
  events_error?: string;
  device_check?: {
    verdict: DeviceVerdict;
    checked: number;
    mismatch: number;
    reason?: string;
    registered_sn_fingerprint?: string;
  };
}
export interface ClosureView {
  req_id: number | null;
  req_hash_hex: string;
  case_no: string;
  action: string;
  conclusion: string | null;
  conclusion_text: string | null;
  auditor_username: string;
  admin_username: string | null;
  fzc2_fingerprint_hex: string | null;
  identity_hash_hex: string | null;
  case_archive_fp_hex: string | null;
  closed_ts: string | null;
  [k: string]: unknown;
}
export interface TraceOut {
  warrant: {
    warrant_hash_hex: string;
    case_no: string;
    target_auth_id: number | null;
    unlocked: {
      ts: string | null;
      master_cred_hash_hex: string | null;
      username: string | null;
      id_number: string | null;
    };
    [k: string]: unknown;
  };
  chain_trace?: ChainTrace;
  chain_fingerprint?: string;
  closure?: ClosureView | null;
  mode?: string;
}

// ---- 吊销/恢复双控（B1/B6）----
/** 两步式第一拍（GET /ra/revoke/by-username/preview）：句柄集+目标纪元。 */
export interface RevokePreview {
  username: string;
  handles: string[];
  epoch: number;
}
export interface RevokeResult {
  epoch: number;
  root_hex: string;
  ledger_id: number;
  revoked_handles_hex: string[];
  linked_auth_ids: number[];
  revoked_credentials?: number;
  link_skipped?: unknown[];
  [k: string]: unknown;
}
/** 公示镜像叶（GET /ra/revocation/snapshot.revoked）。 */
export interface SnapshotLeaf {
  handle_hex: string;
  reason: string;
  revoked_at: string | null;
  epoch: number;
  revoked_by: string;
}
export interface RestoreRequestRow {
  id: number;
  handle_hex: string;
  reason: string;
  status: string;
  requested_by: string;
  countersign_by: string | null;
  execute_error: string | null;
  created_ts: string | null;
  executed_ts: string | null;
}

// ---- 处置待办（A5/B2：并行开发中——404/空时优雅隐藏）----
export interface DisposalTodo {
  id: number;
  case_no: string;
  username: string;
  conclusion: string;
  created_ts: string | null;
  status: "pending" | "done";
  resolved_note: string | null;
}

/** 结论判词徽章文案（待办卡/案卷面共用）。 */
export function conclusionLabel(c: string | null | undefined): string {
  if (!c) return "—";
  return CONCLUSION_META[c as CloseConclusion]?.label ?? c;
}
export function conclusionTone(c: string | null | undefined): string {
  if (!c) return "gray";
  return CONCLUSION_META[c as CloseConclusion]?.tone ?? "gray";
}
