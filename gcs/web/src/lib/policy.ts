/**
 * 机型类公共名映射（C-P2-7 说人话纪律：飞手不看裸数字）。
 * 与后端 CLASS_RULES 对齐：0=微型（真高 50m）/1=轻型（120m）——当前开放档；
 * 2/3=小型/中型（政策表暂未开放，诚实标注而非隐藏）。
 */
export function classLabel(n: number | null | undefined): string {
  const names: Record<number, string> = { 0: "微型", 1: "轻型", 2: "小型", 3: "中型" };
  if (n == null || !Number.isInteger(n)) return "—";
  const base = names[n];
  if (base === undefined) return `${n} 类（暂未开放）`;
  return n <= 1 ? base : `${base}（暂未开放）`;
}
