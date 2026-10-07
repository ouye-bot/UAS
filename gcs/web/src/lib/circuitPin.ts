/** 电路指纹公示面（视觉 S 批 S1）——链上 PolicyRegistry.circuitPin 的展示值。
 *
 * 单一事实源与换算同式（backend/scripts/publish_pin.py local_pin_digest）：
 *   指纹串 = "SM3(" + pin_commit + "|" + aggregate_sm3 + ")"   ← zksvc/vendor/MANIFEST.json
 *   链上公示摘要 = sm3(指纹串)
 *
 * 现行值 = TRAIL 空域围栏换代二批的发布仪式产物（tx=0xb05331dc，2026-10-03/04
 * 主会话执行、幂等复核一致——docs/三大测试汇总报告 三·补3）。
 *
 * 为什么是常量而不是接口取值：现有 HTTP 面没有暴露链上 pin 的端点——
 * /verify/api/checks 只含分发产物 sha256（非电路指纹，不得冒名展示）；
 * /verify/dist/zksvc-build-manifest.json 是尖峰副本构建清单（其 aggregate
 * 落后于 vendor MANIFEST，算出的摘要会与链上公示错位）。backend 线并行作业
 * 禁碰——常量随每次换代仪式（publish_pin 输出）手动更新，与链上 pin 同源
 * 同式，任何漂移在「链上原文核验」面会被独立发现。
 */
export const FZ_CIRCUIT_PIN_STR =
  "SM3(4201a82|5981d449a2cf42a7d77775c62390421361770bfe478c9394cc5ae0edeca9e842)";
export const FZ_CIRCUIT_PIN_DIGEST =
  "632071fa1bb53fe8c4a754918798b31d14ababaa37431a832ce311ce6155e288";
