/** CSPRNG 纪律：端侧源码 Math.random 零调用（随机性必须 crypto.getRandomValues）。 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const NEEDLE = ["Math", ".random", "("].join("");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist") continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.(ts|vue|js)$/.test(name)) out.push(p);
  }
  return out;
}

it("src 与 tests 中 Math.random 零调用", () => {
  const hits: string[] = [];
  for (const f of walk(join(__dirname, ".."))) {
    if (readFileSync(f, "utf8").includes(NEEDLE)) hits.push(f);
  }
  expect(hits).toEqual([]);
});
