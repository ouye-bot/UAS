/** 治理台契约库单测（2026-10-04 升格批）：签名消息拼装与后端逐字对拍+
 * 结案表单校验+判词人话映射——纯函数面（零 DOM），契约漂移在此击穿。 */
import { describe, expect, it } from "vitest";
import {
  CLOSE_MSG_PREFIX,
  CONCLUSION_TEXT_MAX,
  REVOKE_MSG_PREFIX,
  RESTORE_COUNTERSIGN_MSG_PREFIX,
  RESTORE_MSG_PREFIX,
  closeMsg,
  conclusionLabel,
  conclusionTone,
  deviceVerdictMeta,
  restoreCountersignMsg,
  restoreMsg,
  revokeMsg,
  validateCloseForm,
  verdictLabel,
  type SigVerdict,
} from "../../src/lib/gov";

const RH = "a".repeat(64);
const H1 = "AA".repeat(32); // 大写——拼装须小写化
const H2 = "bb".repeat(32);

describe("gov 签名消息拼装（与后端域前缀逐字一致）", () => {
  it("closeMsg：FZ-COLLAB-CLOSE|v1|{req_hash}|{conclusion}|{text}", () => {
    expect(closeMsg(RH, "verified", "链上检查点签名一致，违规事实成立")).toBe(
      `${CLOSE_MSG_PREFIX}${RH}|verified|链上检查点签名一致，违规事实成立`,
    );
    // 误报/存疑同样过同一域（text 允许空——仅 verified 服务端强制必填）
    expect(closeMsg(RH, "mistaken", "")).toBe(`${CLOSE_MSG_PREFIX}${RH}|mistaken|`);
  });

  it("revokeMsg：句柄小写化+字典序排序后 | 拼接（与 ra/service.revoke_msg 同口径）", () => {
    expect(revokeMsg([H1, H2], "按人级联实弹", 7)).toBe(
      `${REVOKE_MSG_PREFIX}${H1.toLowerCase()}|${H2}|按人级联实弹|7`,
    );
    // 乱序输入 → 输出恒字典序（签名与服务端重排后逐字一致）
    expect(revokeMsg([H2, H1], "r", 1)).toBe(revokeMsg([H1, H2], "r", 1));
  });

  it("restoreMsg / restoreCountersignMsg：同内容不同消息域（跨域挪用即验签失败）", () => {
    expect(restoreMsg(H1, "误吊销恢复实弹")).toBe(`${RESTORE_MSG_PREFIX}${H1.toLowerCase()}|误吊销恢复实弹`);
    expect(restoreCountersignMsg(H1, "误吊销恢复实弹")).toBe(
      `${RESTORE_COUNTERSIGN_MSG_PREFIX}${H1.toLowerCase()}|误吊销恢复实弹`,
    );
  });
});

describe("gov 结案表单校验（与后端 close_request 同判）", () => {
  it("未选结论：拒绝并人话提示", () => {
    expect(validateCloseForm("", "任意说明")).toMatch(/请先选择结案结论/);
    expect(validateCloseForm("bogus", "x")).toMatch(/verified\/mistaken\/inconclusive/);
  });

  it("属实必填说明：空/纯空白均拒绝", () => {
    expect(validateCloseForm("verified", "")).toMatch(/属实.*须填写结案说明/);
    expect(validateCloseForm("verified", "   ")).toMatch(/属实.*须填写结案说明/);
  });

  it("说明 ≤500 字：超长拒绝（含当前字数人话）", () => {
    expect(validateCloseForm("verified", "据".repeat(CONCLUSION_TEXT_MAX + 1))).toMatch(
      new RegExp(`≤${CONCLUSION_TEXT_MAX} 字`),
    );
    expect(validateCloseForm("mistaken", "据".repeat(CONCLUSION_TEXT_MAX + 1))).toMatch(
      new RegExp(`≤${CONCLUSION_TEXT_MAX} 字`),
    );
  });

  it("通过形态：属实+说明 / 误报与存疑可空说明", () => {
    expect(validateCloseForm("verified", "链上证据充分")).toBeNull();
    expect(validateCloseForm("mistaken", "")).toBeNull();
    expect(validateCloseForm("inconclusive", "证据不足如实存疑")).toBeNull();
  });
});

describe("gov 判词人话（A3 验签复核/A2 设备判词）", () => {
  const ok: SigVerdict = { ok: true, epoch: 3, reason: null };
  const bad: SigVerdict = { ok: false, epoch: null, reason: "bad_sig" };
  const undecided: SigVerdict = { ok: null, epoch: null, reason: "not_decided" };
  const honest: SigVerdict = { ok: false, epoch: null, reason: "no_epoch_key" };

  it("验签判词：通过带纪元/失败带人话/未批准如实说", () => {
    expect(verdictLabel(ok, "审计员签")).toBe("审计员签 ✓ 纪元 3 验签通过");
    expect(verdictLabel(bad, "管理员签")).toMatch(/✗/);
    expect(verdictLabel(bad, "管理员签")).toMatch(/签名与内容不匹配/);
    expect(verdictLabel(undecided, "管理员签")).toMatch(/尚未批准/);
    expect(verdictLabel(honest, "审计员签")).toMatch(/无纪元公钥/);
  });

  it("设备一致性判词：四判词色彩语义（teal/red/amber/gray）+未知兜底", () => {
    expect(deviceVerdictMeta("match")).toMatchObject({ tone: "teal" });
    expect(deviceVerdictMeta("mismatch")).toMatchObject({ tone: "red" });
    expect(deviceVerdictMeta("no_evidence")).toMatchObject({ tone: "amber" });
    expect(deviceVerdictMeta("insufficient")).toMatchObject({ tone: "gray" });
    expect(deviceVerdictMeta("whatever")).toMatchObject({ tone: "gray" });
  });

  it("结案结论判词：三判词中文化+灰兜底", () => {
    expect(conclusionLabel("verified")).toBe("属实");
    expect(conclusionLabel("mistaken")).toBe("误报");
    expect(conclusionLabel("inconclusive")).toBe("无法查证");
    expect(conclusionLabel(null)).toBe("—");
    expect(conclusionTone("verified")).toBe("gold");
    expect(conclusionTone(undefined)).toBe("gray");
  });
});
