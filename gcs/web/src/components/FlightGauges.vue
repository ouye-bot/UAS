<script setup lang="ts">
/**
 * FlightGauges——主飞行显示四仪表（③GCS 化批 3，对标 MP/QGC 简化版）。
 * 自绘 canvas 零依赖：姿态球（人工地平仪）/高度带（围栏标尺）/爬升率/航向罗盘。
 * 姿态与爬升率为旁路显示字段（不进链）。
 */
import { onBeforeUnmount, onMounted, ref, watch } from "vue";

const props = defineProps<{
  att: { roll: number; pitch: number; yaw: number } | null;
  altCm: number | null;
  fenceM: number | null;
}>();

const horizonCv = ref<HTMLCanvasElement | null>(null);
const bandCv = ref<HTMLCanvasElement | null>(null);
const compassCv = ref<HTMLCanvasElement | null>(null);
const climb = ref(0);
let raf = 0;
let lastAlt: number | null = null;
let lastT = 0;
let disposed = false;

const DEG = 180 / Math.PI;

function drawHorizon() {
  const cv = horizonCv.value;
  if (!cv) return;
  const ctx = cv.getContext("2d");
  if (!ctx) return;
  const w = cv.width, h = cv.height, cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 4;
  const roll = props.att?.roll ?? 0;
  const pitch = props.att?.pitch ?? 0;
  ctx.clearRect(0, 0, w, h);
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.clip();
  ctx.translate(cx, cy);
  ctx.rotate(-roll);
  const off = (pitch * R) / (Math.PI / 3); // ±60° 满量程
  ctx.fillStyle = "#1c3a66";
  ctx.fillRect(-R * 2, -R * 2 - off, R * 4, R * 4);
  ctx.fillStyle = "#4a5a3a";
  ctx.fillRect(-R * 2, -off, R * 4, R * 4);
  ctx.strokeStyle = "#e8f0ff";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(-R, -off);
  ctx.lineTo(R, -off);
  ctx.stroke();
  // 俯仰刻度
  ctx.lineWidth = 1;
  ctx.fillStyle = "#cfe0f5";
  ctx.font = "9px monospace";
  for (const p of [-30, -20, -10, 10, 20, 30]) {
    const y = -off - (p * R) / 60 * -1;
    const yy = -off - (p * R) / 60;
    ctx.globalAlpha = 0.6;
    ctx.beginPath();
    ctx.moveTo(-18, yy);
    ctx.lineTo(18, yy);
    ctx.stroke();
    ctx.fillText(String(p), 22, yy + 3);
    ctx.globalAlpha = 1;
  }
  ctx.restore();
  // 中央机标
  ctx.strokeStyle = "#ffd060";
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.moveTo(cx - R * 0.55, cy);
  ctx.lineTo(cx - 12, cy);
  ctx.lineTo(cx - 4, cy);
  ctx.stroke();
  ctx.beginPath();
  ctx.moveTo(cx + R * 0.55, cy);
  ctx.lineTo(cx + 12, cy);
  ctx.lineTo(cx + 4, cy);
  ctx.stroke();
  ctx.strokeStyle = "#2a3b5c";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.stroke();
}

function drawBand() {
  const cv = bandCv.value;
  if (!cv) return;
  const ctx = cv.getContext("2d");
  if (!ctx) return;
  const w = cv.width, h = cv.height;
  const fence = Math.max(props.fenceM ?? 50, 10);
  const peak = fence * 1.15; // 标尺顶=围栏×1.15（超限区可见）
  ctx.clearRect(0, 0, w, h);
  const x0 = w - 26, x1 = w - 10;
  // 合规带（0..fence）
  ctx.fillStyle = "rgba(53,208,127,0.16)";
  ctx.fillRect(x0, h - (fence / peak) * h, x1 - x0, (fence / peak) * h);
  // 超限带
  ctx.fillStyle = "rgba(224,85,85,0.20)";
  ctx.fillRect(x0, 0, x1 - x0, h - (fence / peak) * h);
  // 围栏红线
  const fy = h - (fence / peak) * h;
  ctx.strokeStyle = "#e05555";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(x0 - 4, fy);
  ctx.lineTo(x1, fy);
  ctx.stroke();
  ctx.fillStyle = "#e05555";
  ctx.font = "10px monospace";
  ctx.fillText(`围栏 ${props.fenceM ?? "—"}m`, x0 - 62, fy + 3);
  // 刻度（每 10m）
  ctx.fillStyle = "#9db4d6";
  for (let m = 0; m <= peak; m += 10) {
    const y = h - (m / peak) * h;
    ctx.fillRect(x1, y, 5, 1);
    ctx.fillText(String(m), x1 + 7, y + 3);
  }
  // 当前高度游标
  const alt = (props.altCm ?? 0) / 100;
  const ay = h - Math.min(alt / peak, 1) * h;
  ctx.fillStyle = "#ffd060";
  ctx.beginPath();
  ctx.moveTo(x0 - 10, ay);
  ctx.lineTo(x0 - 2, ay - 5);
  ctx.lineTo(x0 - 2, ay + 5);
  ctx.closePath();
  ctx.fill();
  ctx.font = "bold 11px monospace";
  ctx.fillText(`${alt.toFixed(1)}m`, x0 - 66, ay + 4);
}

function drawCompass() {
  const cv = compassCv.value;
  if (!cv) return;
  const ctx = cv.getContext("2d");
  if (!ctx) return;
  const w = cv.width, h = cv.height, cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 6;
  const yaw = props.att?.yaw ?? 0; // 弧度，北=0 东=+90°
  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = "#2a3b5c";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.stroke();
  ctx.fillStyle = "#cfe0f5";
  ctx.font = "10px monospace";
  ctx.textAlign = "center";
  const marks: [string, number][] = [["N", 0], ["E", 90], ["S", 180], ["W", 270]];
  for (const [label, deg] of marks) {
    const a = (deg - yaw * DEG - 90) * (Math.PI / 180);
    ctx.fillText(label, cx + Math.cos(a) * (R - 12), cy + Math.sin(a) * (R - 12) + 3);
  }
  // 机头指针
  const ha = -(yaw * DEG) * (Math.PI / 180) - Math.PI / 2;
  ctx.strokeStyle = "#ffd060";
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(cx + Math.cos(ha + Math.PI / 2) * (R - 16), cy + Math.sin(ha + Math.PI / 2) * (R - 16));
  ctx.stroke();
  ctx.fillStyle = "#ffd060";
  ctx.font = "bold 12px monospace";
  const deg = ((yaw * DEG) % 360 + 360) % 360;
  ctx.fillText(`${deg.toFixed(0)}°`, cx, cy - R + 18);
  ctx.textAlign = "start";
}

function loop() {
  if (disposed) return;
  raf = requestAnimationFrame(loop);
  // 爬升率（alt 差分平滑）
  const alt = props.altCm;
  if (alt != null) {
    const now = performance.now();
    if (lastAlt != null && now > lastT) {
      const inst = ((alt - lastAlt) / 100) / ((now - lastT) / 1000);
      climb.value = climb.value * 0.8 + inst * 0.2;
    }
    lastAlt = alt;
    lastT = now;
  }
  drawHorizon();
  drawBand();
  drawCompass();
}

onMounted(() => {
  raf = requestAnimationFrame(loop);
});
onBeforeUnmount(() => {
  disposed = true;
  cancelAnimationFrame(raf);
});
</script>

<template>
  <div class="gauges">
    <div class="g">
      <canvas ref="horizonCv" width="150" height="150"></canvas>
      <span class="glabel">姿态</span>
    </div>
    <div class="g">
      <canvas ref="bandCv" width="110" height="150"></canvas>
      <span class="glabel">高度带</span>
    </div>
    <div class="g col">
      <canvas ref="compassCv" width="110" height="110"></canvas>
      <span class="glabel">航向</span>
      <div class="climb">
        <span class="num" :style="{ color: climb >= 0 ? '#35d07f' : '#e05555' }">
          {{ climb >= 0 ? "▲" : "▼" }} {{ Math.abs(climb).toFixed(1) }}
        </span>
        <span class="unit">m/s 爬升率</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.gauges {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  flex-wrap: wrap;
}
.g {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}
.glabel {
  color: var(--ink-3, #9db4d6);
  font-size: 11px;
}
.col {
  gap: 6px;
}
.climb {
  text-align: center;
  display: flex;
  flex-direction: column;
}
.num {
  font-family: monospace;
  font-weight: 700;
  font-size: 15px;
}
.unit {
  color: var(--ink-3, #9db4d6);
  font-size: 10px;
}
</style>
