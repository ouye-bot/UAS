/** 材料 store（Pinia 收敛批）：子凭证+出示钥+材料指纹的响应式门面。
 *
 * 渐进式纪律：lib/material.ts 仍是单一事实源（键名 fzSub/fzSubBound/fzSubSk
 * 与指纹算法原样）；store 把「签发→落盘→指纹绑定→轮换」收成一个动作，
 * 新代码从 store 走，不再在视图里手拼 localStorage 序列。存量语义：
 * - 出示钥 sk′=会话域（sessionStorage）内存态，与该张子凭证同生命周期；
 * - 材料指纹=登记承诺+实名/设备表单四元（不含账户公钥——一次性出示钥批口径）；
 * - 清扫四表语义由 store 动作承载（身份域/会话域/账户切换/登出），键名兼容。
 */
import { defineStore } from "pinia";
import { computed, ref } from "vue";
import {
  clearSubSk,
  getSubSk,
  logbookAll,
  storeSubBinding,
  storeSubSk,
  subMatchesMaterial,
  sweepForAccountSwitch,
  sweepIfIdentityChanged,
  sweepLocalIdentity,
  type LogbookEntry,
} from "../lib/material";

// 子凭证形态=服务端 /ra/sub-credentials 响应 + 客户端自记 holder_pk_hex——
// 字段面由服务端定义，视图原以 Record<string,any> 消费（宽松口径保持，防
// 服务端加字段时前端类型面变成第二个要维护的契约源）
type SubCred = Record<string, any>;

export const useMaterialStore = defineStore("material", () => {
  const sub = ref<SubCred | null>(null);
  // 飞手合规档案（档案积累批——reload 模式，同 sub 形态：写入走 lib 单源
  // 函数，本状态是视图消费的响应式镜像，reload()/清扫后刷新）
  const logbook = ref<LogbookEntry[]>([]);

  /** 出示钥在场性（响应式镜像——storeSubSk/clearSubSk 后调 touchSk 刷新）。 */
  const skAt = ref(0);
  const hasSubSk = computed(() => {
    void skAt.value;
    return !!getSubSk();
  });
  function touchSk(): void {
    skAt.value++;
  }

  /** 载入本机持久态（fzSub——视图挂载时对账）。 */
  function reload(): void {
    try {
      sub.value = JSON.parse(localStorage.getItem("fzSub") || "null");
    } catch {
      sub.value = null;
    }
    logbook.value = logbookAll();
    touchSk();
  }

  /** 子凭证与当前登记材料是否配套（指纹失配 ⟹ 引导重签）。
   * 刻意是方法而非 computed：失配答案取决于 localStorage 现值（非响应式域
   * ——登记/清扫随时可能改写它），每次询问现算，不喂 Vue 缓存假答案。 */
  function isStale(): boolean {
    return !!sub.value && !subMatchesMaterial();
  }

  /** 签发落盘（RecordView.issueSub 迁移示范——动作内完成四件事：状态、
   * fzSub 落盘、sk′ 会话域、指纹绑定）。返回轮换面：有旧出示钥且不同 ⟹
   * { prev, next } 供视图播轮换时刻；首次签发返回 null。 */
  function issueSub(
    out: Record<string, unknown>,
    subPk: string,
    subSkHex: string,
  ): { prev: string; next: string } | null {
    const prevPk = sub.value?.holder_pk_hex as string | undefined;
    sub.value = { ...out, holder_pk_hex: subPk };
    localStorage.setItem("fzSub", JSON.stringify(sub.value));
    storeSubSk(subSkHex);
    storeSubBinding();
    touchSk();
    return prevPk && prevPk !== subPk ? { prev: prevPk, next: subPk } : null;
  }

  /** 丢弃出示钥（登出/清扫路径——会话域语义）。 */
  function dropSubSk(): void {
    clearSubSk();
    touchSk();
  }

  // ---- 清扫四表（键名单源仍在 lib/material——store 只承载语义）----
  /** 换身份清扫：载入时调用，返回是否发生过清扫。 */
  function sweepIdentity(): boolean {
    const swept = sweepIfIdentityChanged();
    if (swept) reload();
    return swept;
  }
  /** 账户切换清扫：前后账户不同 ⟹ 清上一账户本机材料。 */
  function sweepAccount(prevUser: string | null, newUser: string): boolean {
    const swept = sweepForAccountSwitch(prevUser, newUser);
    if (swept) reload();
    return swept;
  }
  /** 登出清扫：无条件清全部本机身份材料。 */
  function sweepAll(): boolean {
    const had = sweepLocalIdentity();
    sub.value = null;
    logbook.value = [];
    touchSk();
    return had;
  }

  return {
    sub,
    logbook,
    hasSubSk,
    isStale,
    reload,
    issueSub,
    dropSubSk,
    sweepIdentity,
    sweepAccount,
    sweepAll,
  };
});
