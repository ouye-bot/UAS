<script setup lang="ts">
/** 信标粒子场 2.0（视觉深化批 B）：三层视差缓漂微粒+偶发信标扩散环+十字
 * 测量节点——大气感/深度感的克制实现。
 * 纪律：粒子仅装饰（低透明度、慢速、暖金/青两色系）；CSPRNG 红线不适用
 * （视觉噪声走种子化 LCG——与 FlightGlobe 草地纹理同款纪律）；
 * prefers-reduced-motion=静态单帧；document.hidden 暂停 rAF；
 * devicePixelRatio 封顶 2（4K 屏粒子数/填充率双控）。 */
import { onBeforeUnmount, onMounted, ref } from "vue";

const canvasRef = ref<HTMLCanvasElement | null>(null);
let raf = 0;
let running = true;
let onVis: (() => void) | null = null;
let onMove: ((e: MouseEvent) => void) | null = null;

interface P { x: number; y: number; vx: number; vy: number; r: number; a: number; hue: 0 | 1; layer: 0 | 1 | 2; cross: boolean }

function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(1664525, s) + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

onMounted(() => {
  const cv = canvasRef.value;
  if (!cv) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const ctx = cv.getContext("2d");
  if (!ctx) return;

  const resize = () => {
    const rect = cv.parentElement?.getBoundingClientRect();
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    cv.width = Math.max(320, rect?.width ?? 640) * dpr;
    cv.height = Math.max(160, rect?.height ?? 240) * dpr;
    cv.style.width = `${Math.max(320, rect?.width ?? 640)}px`;
    cv.style.height = `${Math.max(160, rect?.height ?? 240)}px`;
  };
  resize();
  window.addEventListener("resize", resize);

  const rnd = lcg(0x5a17c0de);
  const N = 56;
  const ps: P[] = Array.from({ length: N }, () => {
    const layer = (rnd() < 0.45 ? 0 : rnd() < 0.75 ? 1 : 2) as 0 | 1 | 2; // 远/中/近
    return {
      x: rnd(), y: rnd(), // 归一化坐标（resize 稳定）
      vx: (rnd() - 0.5) * (0.05 + layer * 0.06),
      vy: -(0.03 + rnd() * 0.08 + layer * 0.05), // 缓慢上浮，近层稍快
      r: (0.7 + rnd() * 1.5) * (1 + layer * 0.55),
      a: (0.09 + rnd() * 0.13) * (1 + layer * 0.35),
      hue: rnd() > 0.5 ? 0 : 1,
      layer,
      cross: rnd() < 0.06, // 十字测量节点（~6%）
    };
  });

  // 鼠标视差：层组位移（近层响应大）——单次记录坐标，绘制时应用
  let mx = 0, my = 0, tx = 0, ty = 0;
  onMove = (e: MouseEvent) => {
    const rect = cv.getBoundingClientRect();
    tx = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
    ty = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
  };
  window.addEventListener("mousemove", onMove, { passive: true });

  // 信标扩散环：同屏至多 1 个，~8s 节奏随机粒子处绽放
  interface Ring { x: number; y: number; r: number; a: number; hue: 0 | 1 }
  let ring: Ring | null = null;
  let ringCd = 2.5;

  const draw = (dt: number, w: number, h: number) => {
    ctx.clearRect(0, 0, w, h);
    // 视差缓动（层组位移量）
    mx += (tx - mx) * Math.min(1, dt * 3);
    my += (ty - my) * Math.min(1, dt * 3);
    for (const p of ps) {
      if (!reduced) {
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        if (p.y < -0.02) { p.y = 1.02; p.x = rnd(); }
        if (p.x < -0.02) p.x = 1.02;
        if (p.x > 1.02) p.x = -0.02;
      }
      const px = (p.x + mx * 0.012 * (p.layer + 1)) * w;
      const py = (p.y + my * 0.012 * (p.layer + 1)) * h;
      if (p.cross) {
        // 十字测量节点（3px 级微标）
        ctx.strokeStyle = p.hue === 0 ? `rgba(178,146,84,${p.a + 0.06})` : `rgba(74,130,140,${p.a + 0.06})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(px - 3, py); ctx.lineTo(px + 3, py);
        ctx.moveTo(px, py - 3); ctx.lineTo(px, py + 3);
        ctx.stroke();
        continue;
      }
      ctx.beginPath();
      ctx.arc(px, py, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.hue === 0
        ? `rgba(197,160,89,${p.a})`   // 暖金（司法感）
        : `rgba(94,148,157,${p.a})`;  // 青（科技感）
      ctx.fill();
    }
    // 信标环（唯一呼吸：绽放 2.4s → 冷却 ~6s）
    if (!reduced) {
      if (ring) {
        ring.r += dt * 26;
        ring.a -= dt * 0.16;
        if (ring.a <= 0) { ring = null; ringCd = 5.5 + rnd() * 3; }
        else {
          ctx.beginPath();
          ctx.arc(ring.x * w, ring.y * h, ring.r, 0, Math.PI * 2);
          ctx.strokeStyle = ring.hue === 0
            ? `rgba(197,160,89,${ring.a * 0.5})`
            : `rgba(94,148,157,${ring.a * 0.5})`;
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      } else {
        ringCd -= dt;
        if (ringCd <= 0) {
          const src = ps[Math.floor(rnd() * ps.length)];
          ring = { x: src.x, y: src.y, r: 2, a: 0.8, hue: src.hue };
        }
      }
    }
  };

  if (reduced) {
    // 静态单帧（尊重系统设置——构图在，动效无）
    draw(0, cv.width, cv.height);
    onBeforeUnmount(() => window.removeEventListener("resize", resize));
    return;
  }

  let last = performance.now();
  const tick = (now: number) => {
    if (!running) return;
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    draw(dt, cv.width, cv.height);
    raf = requestAnimationFrame(tick);
  };
  raf = requestAnimationFrame(tick);

  // 页面隐藏暂停（后台标签零 CPU）
  onVis = () => {
    if (document.hidden) {
      cancelAnimationFrame(raf);
    } else {
      last = performance.now();
      raf = requestAnimationFrame(tick);
    }
  };
  document.addEventListener("visibilitychange", onVis);

  onBeforeUnmount(() => {
    running = false;
    cancelAnimationFrame(raf);
    window.removeEventListener("resize", resize);
    if (onVis) document.removeEventListener("visibilitychange", onVis);
    if (onMove) window.removeEventListener("mousemove", onMove);
  });
});
</script>

<template>
  <canvas ref="canvasRef" class="fz-particles" aria-hidden="true"></canvas>
</template>

<style scoped>
.fz-particles {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
}
</style>
