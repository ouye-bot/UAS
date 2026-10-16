/** 电路指纹公示面（视觉 S 批 S1）——链上 PolicyRegistry.circuitPin 的展示值。
 *
 * 单一事实源与换算同式（backend/scripts/publish_pin.py local_pin_digest）：
 *   指纹串 = "SM3(" + pin_commit + "|" + aggregate_sm3 + ")"   ← zksvc/vendor/MANIFEST.json
 *   链上公示摘要 = sm3(指纹串)
 *
 * 现行值 = 分发面 wasm 重建批的发布仪式产物（tx=0xce091306…，2026-10-15
 * 执行、publish_pin --check 幂等复核一致——vendor 微换代 ef590ba9 重钉随代）。
 *
 * 为什么是常量而不是接口取值：现有 HTTP 面没有暴露链上 pin 的端点——
 * /verify/api/checks 只含分发产物 sha256（非电路指纹，不得冒名展示）；
 * /verify/dist/zksvc-build-manifest.json 是尖峰副本构建清单（其 aggregate
 * 落后于 vendor MANIFEST，算出的摘要会与链上公示错位）。backend 线并行作业
 * 禁碰——常量随每次换代仪式（publish_pin 输出）手动更新，与链上 pin 同源
 * 同式，任何漂移在「链上原文核验」面会被独立发现。
 */
export const FZ_CIRCUIT_PIN_STR =
  "SM3(4201a82|ef590ba955b150c8358ad7b9aa8fd3b85fcf130358acb6c40fa3a77d0857f189)";
export const FZ_CIRCUIT_PIN_DIGEST =
  "bd57fb8039c4e5f8f23df16e4c0d6f5689e9c52e83f7bde884160add2da71387";
