/** 本机设备序列号单源（SN 绑定根治 2026-10-07）：唯一读数源=地面站桥
 * GET /engine_pub 的 device_serial 字段——与桥第 6 查 device_serial()、设备钥
 * 派生为同一读数（demo 档 env FZ_DEVICE_SERIAL/缺省 FZ-SN-DEV-01；生产档=SE
 * 伴飞机读数）。注册表单、申请出证（/prove/start）自此一律取本函数——网页
 * 自由文本 SN 与桥本机读数无对齐 ⟹ 首次 ARM 必 sn_mismatch 的产品缺口封死。
 *
 * 会话内缓存：桥读数在桥进程生命周期内不变（env 或缺省锚），一次读取全程
 * 复用（避免每页面重复回环请求）。桥不可达/字段缺失=空串——调用方显式提示
 * 「无法读取本机设备序列号——请检查地面站桥接」，不静默编造、不回落自由文本。
 */
import { bridge } from "./api";

let cache: string | null = null;

/** 已缓存的读数（null=尚未读取过——测试与视图判定用）。 */
export function cachedDeviceSerial(): string | null {
  return cache;
}

/** 测试隔离口：清会话内缓存（产品路径不调——缓存与桥进程生命周期一致）。 */
export function resetDeviceSerialCache(): void {
  cache = null;
}

/** 读本机序列号：桥 /engine_pub → device_serial；不可达/缺字段=空串（缓存）。 */
export async function getDeviceSerial(): Promise<string> {
  if (cache !== null) return cache;
  try {
    const r = await bridge<{ device_serial?: unknown }>("/engine_pub");
    cache = typeof r?.device_serial === "string" ? r.device_serial : "";
  } catch {
    cache = ""; // 桥不可达——空串是唯一诚实值（调用方提示检查桥接）
  }
  return cache;
}

/** 桥不可达时的统一人话文案（注册/申请两处共用——同一句话不第二种说法）。 */
export const DEVICE_SERIAL_UNAVAILABLE = "无法读取本机设备序列号——请检查地面站桥接";
