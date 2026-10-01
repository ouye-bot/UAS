/** KPI 数字 count-up（视觉深化批 C）：目标值变化时从当前显示值缓动到目标
 * （一次性 320ms）；prefers-reduced-motion=直显终值。纯展示层——业务
 * computed 原样传入，返回只读显示值。 */
import { onBeforeUnmount, ref, watch, type Ref } from "vue";

export function useCountUp(source: Ref<number>, duration = 320): Ref<number> {
  const shown = ref(source.value);
  let raf = 0;
  const reduced =
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (!reduced) {
    watch(source, (to, from) => {
      cancelAnimationFrame(raf);
      const start = performance.now();
      const a = typeof from === "number" ? from : 0;
      const step = (now: number) => {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
        shown.value = Math.round(a + (to - a) * eased);
        if (t < 1) raf = requestAnimationFrame(step);
      };
      raf = requestAnimationFrame(step);
    });
  } else {
    watch(source, (to) => { shown.value = to; });
  }
  onBeforeUnmount(() => cancelAnimationFrame(raf));
  return shown;
}
