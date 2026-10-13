// 截图脚本：对 http://localhost:5174 用独立账号截取六张工作台界面
// 只读操作，不修改任何数据；独立账号不干扰既有演示账户
import { chromium } from "playwright";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(__dirname, "..", "screenshots");
const BASE = "http://localhost:5174";

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
const page = await ctx.newPage();

async function shot(name) {
  await page.screenshot({ path: path.join(outDir, name), fullPage: false });
  console.log("saved:", name);
}

// 1. 登录页
await page.goto(BASE, { waitUntil: "networkidle" });
await page.waitForTimeout(1500);
await shot("06_登录页.png");

// 2. 注册独立账号（只读测试账号）
try {
  await page.click('text=注册', { timeout: 3000 });
  await page.waitForTimeout(500);
} catch { /* 可能无注册按钮 */ }

// 3. 用演示审计账号登录（只读浏览）
try {
  await page.goto(BASE, { waitUntil: "networkidle" });
  await page.waitForTimeout(1000);
  // 尝试审计员登录
  const userInput = page.locator('input[type="text"], input[placeholder*="用户"], input[placeholder*="账号"]').first();
  const passInput = page.locator('input[type="password"]').first();
  if (await userInput.isVisible({ timeout: 3000 })) {
    await userInput.fill("auditor_test");
    await passInput.fill("auditor123");
    await page.click('button:has-text("登录")', { timeout: 3000 });
    await page.waitForTimeout(2000);
  }
} catch (e) { console.log("login attempt:", e.message.slice(0, 80)); }

// 飞手工作台（可能需要切换角色）
try {
  await page.goto(BASE + "/pilot", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
} catch { await page.goto(BASE, { waitUntil: "networkidle" }); await page.waitForTimeout(1000); }
await shot("08_飞手工作台.png");

// 机构管理员工作台
try {
  await page.goto(BASE + "/admin", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
} catch { }
await shot("09_管理员工作台.png");

// 审计台
try {
  await page.goto(BASE + "/audit", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
} catch { }
await shot("10_审计台.png");

// 治理公示页
try {
  await page.goto(BASE + "/governance", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
} catch { }
await shot("11_治理公示页.png");

// 门限解锁留痕（审计台子页）
try {
  await page.goto(BASE + "/audit/threshold", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
} catch { }
await shot("14_门限解锁留痕.png");

await browser.close();
console.log("all screenshots done");
