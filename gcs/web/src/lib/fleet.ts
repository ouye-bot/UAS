/** 机构机队接口前端库（3.1——credKind=2 机构承诺主凭证动线）。
 *
 * 纪律（与 lib/gov.ts 同款）：
 * - 纯计算与类型+设备档案密封（零视图零 fetch）——登记/签发体构造与后端
 *   RaService.register_fleet_devices / issue_fleet_sub_credentials 契约镜像；
 * - 设备档案（salt 原像=承诺原像机密材料）口令 KEK 密封存 localStorage
 *   （keystore.sealProfileSlot 同族原语薄委托——v4 PBKDF2-HMAC-SM3+SM4-GCM，
 *   单一事实源零逻辑复制），明文材料只在内存与一次性回执，不落明文存储；
 * - 出示钥（holder pk′）每张子凭证当场全新生成（一次性出示钥纪律——
 *   口径卡 C3：出示公钥层跨申请不可链接），生成动作由调用方持 CSPRNG 完成。
 */
import { revokeMsg } from "./gov";
import { sealProfileSlot, unsealProfileSlot } from "./keystore";

export const FLEET_SLOT_KEY = "fzFleetSlot";

/** 登记行（机构台表单行——device_no 恰 18 字符=承诺原像契约）。 */
export interface FleetDeviceRow {
  device_no: string;
  sn: string;
  cert_level: number;
  class_id: number;
}

/** 登记回执单台材料（salt 一次性回传——机构自持原像）。 */
export interface FleetDeviceMaterial {
  device_no: string;
  sn: string;
  cert_level: number;
  class_id: number;
  master_cred_hash_hex: string;
  commitment_hex: string;
  salt_hex: string;
  registered_ts: string;
}

/** 设备档案密封件（localStorage 形态——keystore.SealedSlotV4 同构）。 */
export type FleetSlot = {
  salt: string;
  nonce: string;
  ct: string;
  tag: string;
  kdf: string;
  iter: number;
};

/** 签发行（签发表单行——每行出示钥由调用方生成后填入）。 */
export interface FleetIssueItem {
  master_cred_hash_hex: string;
  salt_hex: string;
  holder_pub_hex: string;
}

/** 设备列表行（GET /ra/fleet/devices 契约——服务端权威面）。 */
export interface FleetDeviceView {
  master_cred_hash_hex: string;
  cred_kind: number;
  device_no: string | null;
  sn: string;
  cert_level: number;
  class_id: number;
  status: number;
  expires_at: string;
  sub_total: number;
  sub_unconsumed: number;
  created_at: string | null;
}

/** 登记号形态校验（与后端 register_fleet_devices 同判——18 字符字母/数字/-/_）。 */
export function isValidDeviceNo(no: string): boolean {
  return no.length === 18 && /^[A-Za-z0-9_-]+$/.test(no);
}

/** 登记请求体构造：行清洗+形态校验（不合法行抛错带行号——fail-fast 于提交前）。 */
export function buildRegisterBody(rows: FleetDeviceRow[]): { devices: FleetDeviceRow[] } {
  if (!rows.length) throw new Error("请先添加设备行");
  return {
    devices: rows.map((r, i) => {
      const device_no = r.device_no.trim();
      const sn = r.sn.trim();
      if (!isValidDeviceNo(device_no))
        throw new Error(`第 ${i + 1} 行设备登记号须 18 字符（字母/数字/-/_）`);
      if (!sn || sn.includes("|")) throw new Error(`第 ${i + 1} 行设备序列号为空或含竖线`);
      return { device_no, sn, cert_level: r.cert_level, class_id: r.class_id };
    }),
  };
}

/** 设备档案密封（salt=承诺原像机密材料——口令 KEK，薄委托 keystore v4 原语；
 * iterations 透传=测试低迭代档，生产缺省 600k）。 */
export function sealFleetSlot(
  materials: FleetDeviceMaterial[],
  passphrase: string,
  iterations?: number,
): Promise<FleetSlot> {
  if (!passphrase) throw new Error("档案密封须口令");
  return (iterations
    ? sealProfileSlot(materials, passphrase, iterations)
    : sealProfileSlot(materials, passphrase)) as Promise<FleetSlot>;
}

/** 设备档案解封（口令错/GCM 认证失败=人话拒绝）。 */
export async function openFleetSlot(slot: FleetSlot, passphrase: string): Promise<FleetDeviceMaterial[]> {
  try {
    return await unsealProfileSlot<FleetDeviceMaterial[]>(slot, passphrase);
  } catch {
    throw new Error("设备档案解封失败（口令不符或档案被篡改）");
  }
}

/** 签发请求体构造：档案行+出示钥→机队端点契约（salt 来自机构自持档案）。 */
export function buildIssueBody(items: FleetIssueItem[]): { items: FleetIssueItem[] } {
  if (!items.length) throw new Error("请先勾选要签发的设备");
  for (const it of items) {
    if (!/^[0-9a-f]{64}$/i.test(it.master_cred_hash_hex)) throw new Error("设备句柄形态非法");
    if (!/^[0-9a-f]{32}$/i.test(it.salt_hex)) throw new Error("原像盐形态非法（16 字节 hex）");
    if (!/^[0-9a-f]{128}$/i.test(it.holder_pub_hex)) throw new Error("出示公钥须 128 hex（SM2 x‖y）");
  }
  return { items };
}

/** 机队吊销签名消息（按句柄——设备无 username，不走 by-username 预览两拍；
 * epoch=公示镜像纪元+1，与个人吊销同一消息域 FZ-REVOKE|v1）。 */
export function fleetRevokeMsg(handleHex: string, reason: string, epoch: number): string {
  return revokeMsg([handleHex], reason, epoch);
}
