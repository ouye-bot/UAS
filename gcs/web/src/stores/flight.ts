/** 飞行态 store（Pinia 收敛批）：飞行屏七态状态机的轻量响应式镜像。
 *
 * 渐进式纪律：FlightView 存量不迁移（其旁路状态仍以桥/服务器为唯一事实源）；
 * 本 store 供新代码消费「当前飞到哪一步」的跨页询问（如导航徽标、引导卡），
 * 状态机单源仍是 lib/flight.flightStage 纯函数——store 只持有输入五元组，
 * 派生全程引单源，杜绝两套状态语义。
 */
import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { flightStage, stepperState, type FlightStage, type StageInput } from "../lib/flight";

export const useFlightStore = defineStore("flight", () => {
  const hasToken = ref(false);
  const armed = ref(false);
  const chainStarted = ref(false);
  const sealed = ref(false);
  const sampleCount = ref(0);

  const input = computed<StageInput>(() => ({
    hasToken: hasToken.value,
    armed: armed.value,
    chainStarted: chainStarted.value,
    sealed: sealed.value,
    sampleCount: sampleCount.value,
  }));
  const stage = computed<FlightStage>(() => flightStage(input.value));
  const stepper = computed(() => stepperState(input.value));

  /** 新架次复位（语义同 FlightView.newFlight 的界面侧——链上数据不动）。 */
  function reset(): void {
    hasToken.value = false;
    armed.value = false;
    chainStarted.value = false;
    sealed.value = false;
    sampleCount.value = 0;
  }

  return {
    hasToken,
    armed,
    chainStarted,
    sealed,
    sampleCount,
    stage,
    stepper,
    reset,
  };
});
