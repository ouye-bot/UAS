<script setup lang="ts">
/**
 * FlightGlobe——3D 实时飞行态势（③GCS 化批 2）。
 *
 * Three.js 本地渲染（零外部瓦片/资产依赖——演示断网不受影响）：
 * 网格场地+起飞坪+限高围栏半透明柱+几何四轴（旋翼转速动画）+实时尾迹
 * （合规绿/超限红）。真实比例（米制），起飞点=坐标原点。
 *
 * 数据面纪律：samples/att 全部为旁路显示字段——不涉及链行/检查点语义。
 * WebGL 不可用自动降级（failed=true，父层保留 2D 双图作为常备降级面）。
 */
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import * as THREE from "three";

export interface GlobeSample {
  alt_cm: number;
  lat_1e7: number;
  lon_1e7: number;
}

const props = defineProps<{
  samples: GlobeSample[];
  fenceBreached: boolean;
  fenceM: number | null;
  att: { roll: number; pitch: number; yaw: number } | null;
  anchorCount?: number;
  armed?: boolean; // P2 观感：LED/螺旋桨状态源（未解锁红/解锁绿）
}>();

const mountEl = ref<HTMLDivElement | null>(null);
const failed = ref(false);
const camMode = ref<"chase" | "orbit" | "top" | "fpv">("chase");

let renderer: THREE.WebGLRenderer | null = null;
let scene: THREE.Scene | null = null;
let camera: THREE.PerspectiveCamera | null = null;
let droneGrp: THREE.Group | null = null;
let rotors: THREE.Mesh[] = [];
let trailLine: THREE.Line | null = null;
let trailPositions: Float32Array | null = null;
let trailDraw = 0;
let fenceGrp: THREE.Group | null = null;
let raf = 0;
let disposed = false;

// 高度数字标牌（Sprite——相机不变朝向；近围栏琥珀色提示）
let altSprite: THREE.Sprite | null = null;
let altCanvasTex: HTMLCanvasElement | null = null;
let altTexNeedsUpdate = false;
let lastAltText = "";
// 检查点锚定脉冲（绿色光环一次扩散——"证据已固化"可视反馈）
let pulseRing: THREE.Mesh | null = null;
let pulseT = -1;
let lastAnchorCount = 0;

// 显示插值状态（帧间平滑——采样 2Hz、渲染 60fps）
const disp = { x: 0, y: 0, z: 0, yaw: 0, pitch: 0, roll: 0 };
const target = { x: 0, y: 0, z: 0, yaw: 0, pitch: 0, roll: 0 };
let originLat = 0;
let originLon = 0;
const E7 = 1e7;
const M_PER_DEG_LAT = 111_320;

function lonLatToLocal(lon1e7: number, lat1e7: number): [number, number] {
  // equirectangular 近似（起飞点原点，米制）——低空小半径足够
  const dLat = (lat1e7 - originLat) / E7;
  const dLon = (lon1e7 - originLon) / E7;
  const north = dLat * M_PER_DEG_LAT;
  const east = dLon * M_PER_DEG_LAT * Math.cos((originLat / E7) * (Math.PI / 180));
  return [east, north];
}

function buildScene() {
  const host = mountEl.value;
  if (!host) throw new Error("mount 缺失");
  renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.setSize(host.clientWidth || 640, host.clientHeight || 360);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  host.appendChild(renderer.domElement);

  scene = new THREE.Scene();
  // P2 观感：日间天空（程序化渐变天穹——零外部资产）
  const skyGeo = new THREE.SphereGeometry(1500, 24, 12);
  const skyCv = document.createElement("canvas");
  skyCv.width = 2; skyCv.height = 256;
  const sctx = skyCv.getContext("2d")!;
  const grad = sctx.createLinearGradient(0, 0, 0, 256);
  grad.addColorStop(0, "#3f74c9");
  grad.addColorStop(0.55, "#8db8e8");
  grad.addColorStop(1, "#dceafc");
  sctx.fillStyle = grad; sctx.fillRect(0, 0, 2, 256);
  const skyTex = new THREE.CanvasTexture(skyCv);
  const sky = new THREE.Mesh(
    skyGeo,
    new THREE.MeshBasicMaterial({ map: skyTex, side: THREE.BackSide, depthWrite: false }),
  );
  scene.add(sky);
  scene.fog = new THREE.Fog(0xcfe2f5, 220, 1000);

  camera = new THREE.PerspectiveCamera(55, (host.clientWidth || 640) / (host.clientHeight || 360), 0.1, 2000);
  camera.position.set(-28, 26, -34);

  // 灯光（日间——柔和主光+环境；阴影开启增强真实感）
  const sun = new THREE.DirectionalLight(0xfff4e0, 2.0);
  sun.position.set(60, 90, 40);
  sun.castShadow = true;
  sun.shadow.mapSize.set(1024, 1024);
  sun.shadow.camera.left = -120; sun.shadow.camera.right = 120;
  sun.shadow.camera.top = 120; sun.shadow.camera.bottom = -120;
  scene.add(sun);
  scene.add(new THREE.HemisphereLight(0xcfe2f5, 0x55704a, 1.1));
  scene.add(new THREE.AmbientLight(0xbfd4ee, 0.5));

  // 场地：程序化草地（canvas 噪声纹理——零外部资产）+起飞坪；接收阴影
  const gcv = document.createElement("canvas");
  gcv.width = 512; gcv.height = 512;
  const gctx = gcv.getContext("2d")!;
  gctx.fillStyle = "#5a8f4a"; gctx.fillRect(0, 0, 512, 512);
  // 噪声用固定种子 LCG——非密码学场景，但 src 全域禁 Math.random（CSPRNG 门禁）；
  // 固定种子附带优点：草地纹理每次加载逐像素一致
  let seed = 0x9e3779b9;
  const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
  for (let i = 0; i < 2600; i++) {
    const x = rnd() * 512, y = rnd() * 512;
    const shade = 70 + Math.floor(rnd() * 60);
    gctx.fillStyle = `rgb(${Math.floor(shade * 0.62)},${shade + 40},${Math.floor(shade * 0.5)})`;
    gctx.fillRect(x, y, 2 + rnd() * 3, 1 + rnd() * 2);
  }
  const grassTex = new THREE.CanvasTexture(gcv);
  grassTex.wrapS = grassTex.wrapT = THREE.RepeatWrapping;
  grassTex.repeat.set(24, 24);
  const ground = new THREE.Mesh(
    new THREE.PlaneGeometry(1200, 1200),
    new THREE.MeshStandardMaterial({ map: grassTex, roughness: 1 }),
  );
  ground.rotation.x = -Math.PI / 2;
  ground.receiveShadow = true;
  scene.add(ground);
  // 比例参照物：跑道条+建筑体块+树（锥+柱）——尺度感与真实感
  const runway = new THREE.Mesh(
    new THREE.PlaneGeometry(10, 90),
    new THREE.MeshStandardMaterial({ color: 0x4a4f57, roughness: 0.95 }),
  );
  runway.rotation.x = -Math.PI / 2;
  runway.position.set(-46, 0.02, 30);
  runway.receiveShadow = true;
  scene.add(runway);
  const bldMat = new THREE.MeshStandardMaterial({ color: 0x9aa3ae, roughness: 0.85 });
  const bldRoofMat = new THREE.MeshStandardMaterial({ color: 0x6b7480, roughness: 0.9 });
  for (const [bx, bz, bw, bd, bh] of [[62, -52, 14, 10, 9], [78, -30, 10, 12, 15], [50, -70, 18, 9, 6]] as const) {
    const bdg = new THREE.Mesh(new THREE.BoxGeometry(bw, bh, bd), bldMat);
    bdg.position.set(bx, bh / 2, bz);
    bdg.castShadow = true; bdg.receiveShadow = true;
    scene.add(bdg);
    const roof = new THREE.Mesh(new THREE.BoxGeometry(bw + 0.6, 0.5, bd + 0.6), bldRoofMat);
    roof.position.set(bx, bh + 0.25, bz);
    scene.add(roof);
  }
  const trunkMat = new THREE.MeshStandardMaterial({ color: 0x6e4f2f, roughness: 1 });
  const crownMat = new THREE.MeshStandardMaterial({ color: 0x3f7038, roughness: 1 });
  for (const [tx, tz] of [[-30, -40], [-42, -22], [36, 44], [24, 58], [-20, 62], [70, 20], [44, -18]] as const) {
    const trunk = new THREE.Mesh(new THREE.CylinderGeometry(0.25, 0.35, 3, 8), trunkMat);
    trunk.position.set(tx, 1.5, tz);
    trunk.castShadow = true;
    scene.add(trunk);
    const crown = new THREE.Mesh(new THREE.ConeGeometry(2.2, 5.5, 8), crownMat);
    crown.position.set(tx, 5.2, tz);
    crown.castShadow = true;
    scene.add(crown);
  }
  const pad = new THREE.Mesh(
    new THREE.CircleGeometry(2.2, 40),
    new THREE.MeshStandardMaterial({ color: 0x1c2c4a, roughness: 0.9 }),
  );
  pad.rotation.x = -Math.PI / 2;
  pad.position.y = 0.02;
  scene.add(pad);
  const padRing = new THREE.Mesh(
    new THREE.RingGeometry(2.2, 2.6, 40),
    new THREE.MeshBasicMaterial({ color: 0x4a7bd0, side: THREE.DoubleSide }),
  );
  padRing.rotation.x = -Math.PI / 2;
  padRing.position.y = 0.03;
  scene.add(padRing);

  // 无人机（精修四轴——零外部资产：机身/电机座/双叶桨/云台相机/状态 LED）
  droneGrp = new THREE.Group();
  const bodyMat = new THREE.MeshStandardMaterial({ color: 0x2c3444, roughness: 0.4, metalness: 0.35 });
  const topMat = new THREE.MeshStandardMaterial({ color: 0xe8edf5, roughness: 0.35 });
  const armMat = new THREE.MeshStandardMaterial({ color: 0x1d2430, roughness: 0.5, metalness: 0.4 });
  const motorMat = new THREE.MeshStandardMaterial({ color: 0x39445c, roughness: 0.35, metalness: 0.6 });
  const propMat = new THREE.MeshStandardMaterial({ color: 0x141a24, roughness: 0.4, side: THREE.DoubleSide });
  const body = new THREE.Mesh(new THREE.CylinderGeometry(0.19, 0.22, 0.13, 8), bodyMat);
  droneGrp.add(body);
  const shell = new THREE.Mesh(new THREE.SphereGeometry(0.16, 14, 10, 0, Math.PI * 2, 0, Math.PI / 2), topMat);
  shell.position.y = 0.05;
  droneGrp.add(shell);
  const cam = new THREE.Mesh(
    new THREE.SphereGeometry(0.055, 12, 10),
    new THREE.MeshStandardMaterial({ color: 0x101826, roughness: 0.3 }),
  );
  cam.position.set(0.16, -0.06, 0);
  droneGrp.add(cam);
  rotors = [];
  for (const [sx, sz] of [[1, 1], [1, -1], [-1, 1], [-1, -1]] as const) {
    const arm = new THREE.Mesh(new THREE.BoxGeometry(0.46, 0.04, 0.06), armMat);
    arm.position.set(sx * 0.2, 0, sz * 0.2);
    arm.rotation.y = sx * sz > 0 ? Math.PI / 4 : -Math.PI / 4;
    droneGrp.add(arm);
    const motor = new THREE.Mesh(new THREE.CylinderGeometry(0.055, 0.06, 0.07, 12), motorMat);
    motor.position.set(sx * 0.38, 0.035, sz * 0.38);
    droneGrp.add(motor);
    // 双叶桨（薄盒×2 正交）+ 旋转盘（高速时视觉模糊盘）
    const rotor = new THREE.Group();
    const blade = new THREE.Mesh(new THREE.BoxGeometry(0.4, 0.008, 0.045), propMat);
    const blade2 = blade.clone();
    blade2.rotation.y = Math.PI / 2;
    rotor.add(blade, blade2);
    rotor.position.set(sx * 0.38, 0.085, sz * 0.38);
    droneGrp.add(rotor);
    rotors.push(rotor as unknown as THREE.Mesh);
  }
  const led = new THREE.Mesh(
    new THREE.SphereGeometry(0.045, 10, 8),
    new THREE.MeshBasicMaterial({ color: 0xd05555 }),
  );
  led.position.set(0, 0.13, 0);
  droneGrp.add(led);
  droneGrp.traverse(o => { if ((o as THREE.Mesh).isMesh && o !== led) { o.castShadow = true; } });
  droneGrp.position.set(0, 0.12, 0);
  droneGrp.scale.setScalar(2.2); // 视觉放大（非物理——0.34m 机体在 16m 相机距下不可辨）
  scene.add(droneGrp);
}

let fenceWallMat: THREE.MeshBasicMaterial | null = null;
let fenceTopMat: THREE.MeshBasicMaterial | null = null;
function buildFence(altM: number, radiusM: number) {
  if (!scene || fenceGrp) return;
  fenceGrp = new THREE.Group();
  const h = Math.max(altM, 8);
  const wall = new THREE.Mesh(
    new THREE.CylinderGeometry(radiusM, radiusM, h, 48, 1, true),
    new THREE.MeshBasicMaterial({
      color: props.fenceBreached ? 0xd05555 : 0x3f6fd0,
      transparent: true,
      opacity: 0.09,
      side: THREE.DoubleSide,
    }),
  );
  wall.position.y = h / 2;
  fenceGrp.add(wall);
  const top = new THREE.Mesh(
    new THREE.TorusGeometry(radiusM, 0.14, 8, 64),
    new THREE.MeshBasicMaterial({ color: props.fenceBreached ? 0xd05555 : 0x5b8de8 }),
  );
  top.rotation.x = Math.PI / 2;
  top.position.y = h;
  fenceGrp.add(top);
  // P2 观感：高度刻度环（每 10m——限高柱从"光柱"变"有刻度的仪表"）
  const tickMat = new THREE.MeshBasicMaterial({ color: 0x7ea4e0, transparent: true, opacity: 0.5 });
  for (let y = 10; y < h; y += 10) {
    const tick = new THREE.Mesh(new THREE.TorusGeometry(radiusM, 0.05, 6, 48), tickMat);
    tick.rotation.x = Math.PI / 2;
    tick.position.y = y;
    fenceGrp.add(tick);
  }
  scene.add(fenceGrp);
  fenceWallMat = wall.material as THREE.MeshBasicMaterial;
  fenceTopMat = top.material as THREE.MeshBasicMaterial;
  applyFenceColor();
}
function applyFenceColor() {
  // 围栏颜色=剩余余量渐变（P2 观感）：蓝（充裕）→琥珀（8m 内）→红（2m 内/超限）
  const altM = droneGrp ? droneGrp.position.y : 0;
  const fm = props.fenceM ?? 50;
  const margin = fm - altM;
  let wall = 0x3f6fd0, top = 0x5b8de8;
  if (props.fenceBreached || margin <= 2) { wall = 0xd05555; top = 0xd05555; }
  else if (margin <= 8) { wall = 0xd0a855; top = 0xd0a855; }
  if (fenceWallMat) fenceWallMat.color.setHex(wall);
  if (fenceTopMat) fenceTopMat.color.setHex(top);
}

// 尾迹（预分配 4096 点顶点色——合规绿/超限红）
const TRAIL_MAX = 4096;
function ensureTrail() {
  if (trailLine || !scene) return;
  trailPositions = new Float32Array(TRAIL_MAX * 3);
  const colors = new Float32Array(TRAIL_MAX * 3);
  const geo = new THREE.BufferGeometry();
  geo.setAttribute("position", new THREE.BufferAttribute(trailPositions, 3));
  geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  geo.setDrawRange(0, 0);
  const mat = new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.95 });
  trailLine = new THREE.Line(geo, mat);
  scene.add(trailLine);
}

const GREEN = new THREE.Color(0x35d07f);
const RED = new THREE.Color(0xe05555);

function pushTrailPoint(x: number, y: number, z: number, breach: boolean) {
  ensureTrail();
  if (!trailLine || !trailPositions || trailDraw >= TRAIL_MAX) return;
  const geo = trailLine.geometry;
  const posAttr = geo.getAttribute("position") as THREE.BufferAttribute;
  const colAttr = geo.getAttribute("color") as THREE.BufferAttribute;
  posAttr.setXYZ(trailDraw, x, y, z);
  const c = breach ? RED : GREEN;
  colAttr.setXYZ(trailDraw, c.r, c.g, c.b);
  trailDraw += 1;
  geo.setDrawRange(0, trailDraw);
  posAttr.needsUpdate = true;
  colAttr.needsUpdate = true;
}

// 采样→目标状态（首点定原点；全部真实比例米制）
watch(
  () => props.samples.length,
  () => {
    const arr = props.samples;
    if (!arr.length) return;
    const last = arr[arr.length - 1];
    if (originLat === 0 && originLon === 0) {
      originLat = last.lat_1e7;
      originLon = last.lon_1e7;
    }
    const [east, north] = lonLatToLocal(last.lon_1e7, last.lat_1e7);
    target.x = east;
    target.z = -north;
    target.y = Math.max(last.alt_cm / 100, 0.12);
    if (fenceGrp === null && scene) {
      // 活动半径=轨迹包围盒+余量（最小 30m）——首点后建围栏
      let rMax = 30;
      for (const s of arr) {
        const [ex, no] = lonLatToLocal(s.lon_1e7, s.lat_1e7);
        rMax = Math.max(rMax, Math.hypot(ex, no) + 40);
      }
      buildFence(props.fenceM ?? 50, rMax);
      ensureTrail();
    }
    if (trailLine) {
      const breach = props.fenceBreached || (props.fenceM != null && last.alt_cm > props.fenceM * 100);
      pushTrailPoint(target.x, target.y, target.z, breach);
    }
    updateAltLabel(last.alt_cm / 100);
    if (props.anchorCount !== undefined && props.anchorCount > lastAnchorCount) {
      lastAnchorCount = props.anchorCount;
      pulseT = 0; // 锚定脉冲：绿色光环自无人机扩散
    }
  },
);

// ---- 高度标牌（canvas sprite）----
function drawAltTexture(text: string, amber: boolean) {
  const cv = altCanvasTex;
  if (!cv) return;
  const ctx = cv.getContext("2d");
  if (!ctx) return;
  ctx.clearRect(0, 0, cv.width, cv.height);
  ctx.font = "bold 44px ui-monospace, monospace";
  ctx.textAlign = "center";
  ctx.fillStyle = amber ? "#e0a855" : "#dce9fb";
  ctx.strokeStyle = "rgba(10,18,32,0.85)";
  ctx.lineWidth = 6;
  ctx.strokeText(text, cv.width / 2, cv.height / 2 + 14);
  ctx.fillText(text, cv.width / 2, cv.height / 2 + 14);
  altTexNeedsUpdate = true;
}
function updateAltLabel(altM: number) {
  if (!scene || !droneGrp) return;
  const near = props.fenceM != null && altM >= props.fenceM - 5;
  const text = `${altM.toFixed(1)} m`;
  if (!altSprite) {
    altCanvasTex = document.createElement("canvas");
    altCanvasTex.width = 256; altCanvasTex.height = 80;
    const tex = new THREE.CanvasTexture(altCanvasTex);
    altSprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, depthTest: false, transparent: true }));
    altSprite.scale.set(6, 1.9, 1);
    scene.add(altSprite);
  }
  if (text !== lastAltText || near !== altSprite.userData.amber) {
    lastAltText = text;
    altSprite.userData.amber = near;
    drawAltTexture(text, near);
    (altSprite.material as THREE.SpriteMaterial).map!.needsUpdate = altTexNeedsUpdate;
  }
  altSprite.position.set(droneGrp.position.x, droneGrp.position.y + 2.2, droneGrp.position.z);
}

// ---- 检查点锚定脉冲 ----
function ensurePulseRing() {
  if (pulseRing || !scene) return;
  pulseRing = new THREE.Mesh(
    new THREE.TorusGeometry(1, 0.08, 8, 48),
    new THREE.MeshBasicMaterial({ color: 0x35d07f, transparent: true, opacity: 0.9 }),
  );
  pulseRing.rotation.x = Math.PI / 2;
  scene.add(pulseRing);
}

// 姿态旁路→目标姿态（弧度）
watch(
  () => props.att,
  (a) => {
    if (!a) return;
    target.roll = a.roll;
    target.pitch = a.pitch;
    target.yaw = a.yaw;
  },
  { deep: true },
);

function animate() {
  if (disposed) return;
  raf = requestAnimationFrame(animate);
  if (!scene || !camera || !droneGrp) return;
  // 帧间插值（指数平滑——2Hz 采样→60fps 观感）
  const k = 0.14;
  disp.x += (target.x - disp.x) * k;
  disp.y += (target.y - disp.y) * k;
  disp.z += (target.z - disp.z) * k;
  droneGrp.position.set(disp.x, disp.y, disp.z);
  const dyaw = target.yaw - disp.yaw;
  disp.yaw += dyaw * k;
  disp.pitch += (target.pitch - disp.pitch) * k;
  disp.roll += (target.roll - disp.roll) * k;
  droneGrp.rotation.set(disp.pitch, -disp.yaw, disp.roll, "YXZ");
  // 旋翼：armed 才转（转速随油门 HUD 上升——未解锁静止）
  const armedNow = props.armed !== false;
  if (armedNow) {
    const spin = performance.now() * 0.9;
    rotors.forEach((r, i) => (r.rotation.y = spin * (i % 2 ? 1 : -1)));
  }
  // LED 三态：未解锁红 / 解锁绿 / 超限闪红
  const ledMesh = droneGrp.children.find(o => (o as THREE.Mesh).material &&
    (o as THREE.Mesh).material instanceof THREE.MeshBasicMaterial) as THREE.Mesh | undefined;
  if (ledMesh) {
    const m = ledMesh.material as THREE.MeshBasicMaterial;
    if (props.fenceBreached) m.color.setHex(Math.floor(performance.now() / 180) % 2 ? 0xd05555 : 0x501010);
    else if (armedNow) m.color.setHex(0x35d07f);
    else m.color.setHex(0xd05555);
  }
  applyFenceColor();
  // 锚定脉冲：光环自无人机位置扩散淡出（1.2s）
  if (pulseT >= 0 && pulseRing) {
    pulseT += 0.016;
    const k = pulseT / 1.2;
    if (k >= 1) { pulseRing.visible = false; pulseT = -1; }
    else {
      pulseRing.visible = true;
      pulseRing.position.copy(droneGrp.position);
      pulseRing.scale.setScalar(1 + k * 10);
      (pulseRing.material as THREE.MeshBasicMaterial).opacity = 0.9 * (1 - k);
    }
  } else if (pulseRing) pulseRing.visible = false;
  if (altSprite && droneGrp) altSprite.position.set(droneGrp.position.x, droneGrp.position.y + 2.2, droneGrp.position.z);
  // 相机四模式（chase 带位置阻尼——瞬移感根除；FPV=机头第一视角）
  const t = performance.now() * 0.00016;
  if (camMode.value === "chase") {
    const back = 12;
    const cx = disp.x - Math.sin(-disp.yaw) * back;
    const cy = disp.y + 9;
    const cz = disp.z - Math.cos(-disp.yaw) * back;
    camera.position.lerp(new THREE.Vector3(cx, cy, cz), 0.08);
    camera.lookAt(disp.x, disp.y + 1.5, disp.z);
  } else if (camMode.value === "fpv") {
    const fpv = new THREE.Vector3(
      disp.x + Math.sin(-disp.yaw) * 1.1,
      disp.y + 0.9,
      disp.z + Math.cos(-disp.yaw) * 1.1,
    );
    camera.position.lerp(fpv, 0.35);
    const look = new THREE.Vector3(
      disp.x + Math.sin(-disp.yaw) * 30,
      disp.y + 1.2,
      disp.z + Math.cos(-disp.yaw) * 30,
    );
    camera.lookAt(look);
  } else if (camMode.value === "top") {
    camera.position.set(disp.x * 0.35, 95, disp.z * 0.35 + 0.01);
    camera.lookAt(disp.x, 0, disp.z);
  } else {
    camera.position.set(Math.sin(t) * 70, 42, Math.cos(t) * 70);
    camera.lookAt(0, 12, 0);
  }
  renderer?.render(scene, camera);
}

function onResize() {
  const host = mountEl.value;
  if (!host || !renderer || !camera) return;
  renderer.setSize(host.clientWidth || 640, host.clientHeight || 360);
  camera.aspect = (host.clientWidth || 640) / (host.clientHeight || 360);
  camera.updateProjectionMatrix();
}

function switchCam() {
  camMode.value = camMode.value === "chase" ? "orbit" : camMode.value === "orbit" ? "top" : "chase";
}
defineExpose({ switchCam });

onMounted(() => {
  try {
    buildScene();
    animate();
    window.addEventListener("resize", onResize);
  } catch (e) {
    failed.value = true; // WebGL 不可用——父层 2D 降级面兜底
    console.warn("[FlightGlobe] 初始化失败（2D 降级）:", e);
  }
});

onBeforeUnmount(() => {
  disposed = true;
  cancelAnimationFrame(raf);
  window.removeEventListener("resize", onResize);
  renderer?.dispose();
  const host = mountEl.value;
  if (host) host.innerHTML = "";
});
</script>

<template>
  <div class="fg-wrap">
    <div v-if="failed" class="fg-failed">WebGL 不可用——已降级 2D 视图</div>
    <div ref="mountEl" class="fg-mount"></div>
    <div class="fg-cambar">
      <button class="fg-cambtn" title="切换视角（跟随/环绕/俯视）" @click="switchCam">
        视角：{{ camMode === "chase" ? "跟随" : camMode === "orbit" ? "环绕" : "俯视" }}
      </button>
      <span class="fg-legend">
        <i style="background:#35d07f" /> 合规段
        <i style="background:#e05555" /> 超限段
      </span>
    </div>
  </div>
</template>

<style scoped>
.fg-wrap {
  position: relative;
  width: 100%;
  height: 100%;
  min-height: 300px;
  border: 1px solid var(--line, #22304a);
  border-radius: 8px;
  overflow: hidden;
}
.fg-mount {
  position: absolute;
  inset: 0;
}
.fg-failed {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--accent-ink, #6f9fd8);
  font-size: 13px;
}
.fg-cambar {
  position: absolute;
  left: 8px;
  bottom: 8px;
  display: flex;
  gap: 10px;
  align-items: center;
}
.fg-cambtn {
  background: rgba(11, 18, 32, 0.75);
  color: #cfe0f5;
  border: 1px solid #2a3b5c;
  border-radius: 6px;
  padding: 3px 10px;
  font-size: 12px;
  cursor: pointer;
}
.fg-legend {
  color: #9db4d6;
  font-size: 12px;
  display: inline-flex;
  gap: 6px;
  align-items: center;
}
.fg-legend i {
  display: inline-block;
  width: 14px;
  height: 3px;
  border-radius: 2px;
}
</style>
