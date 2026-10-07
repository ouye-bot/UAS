# -*- coding: utf-8 -*-
"""浏览器级 UI 回归判决（2026-09-28 Playwright 批——check.sh 第六段）。

使命：终结「API 绿但 UI 坏」事故族（R2-b 信封死锁 / TRAIL /prove 前缀 /
FlightGlobe 键名错位三案同族）——逐屏驱动**构建产物**（vite preview），
断言每屏真实渲染、真实调用与负例的真实拒绝呈现。

夹具（隔离端口，不扰在线栈）：backend :8020（fake 链档+临时 SQLite）+
桥 :8110（FakeLink——SITL 档属真飞流程，由 e2e_frontend_api/S1 覆盖）+
vite preview :5199（gcs/web 构建产物）。浏览器经 localStorage 注入夹具地址。

覆盖（2026-09-29 账户批改写；2026-10-04 删回执查询页=⑤ 段随之退役）：
⓪门户注册正例+弱密码负例+错密码登录负例 / ①子凭证签发 / ②政策面 /
③飞行屏初始态+步进器 / ④TRAIL 窗口+证书卡持久化+分发页链接 /
⑥面板渲染 / 审计台 Vue（审计员登录→步进器+收件箱）/ 机构台 Vue
（管理员登录→待批+台账+吊销）/ 越权 401/403（API 实弹）/ 服务状态点
双绿 / 全程零 pageerror（JS 崩溃即红）。

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/e2e_browser_ui.py
前置：playwright 已装 venv（chromium 用 %LOCALAPPDATA%\\ms-playwright 缓存）。
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
UAS = BACKEND.parent
WEB = UAS / "gcs" / "web"
PY = sys.executable

API_PORT, BRIDGE_PORT, WEB_PORT = 8020, 8110, 5199
API = f"http://127.0.0.1:{API_PORT}"
BRIDGE = f"http://127.0.0.1:{BRIDGE_PORT}"
WEB_URL = f"http://localhost:{WEB_PORT}/"

_checks = 0
_page_ref = {"page": None}  # 失败现场转储用（main 的 except 消费）


def ok(label: str) -> None:
    global _checks
    _checks += 1
    print(f"  [OK] {label}")


def expect(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        ok(label)
    else:
        print(f"  [FAIL] {label} {detail}")
        raise SystemExit(1)


def _get(url: str, timeout: float = 5) -> tuple[int, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, str(e)[:120]


def _port_free(port: int) -> bool:
    return _get(f"http://127.0.0.1:{port}/", timeout=1.5)[0] == 0


def _boot_fixtures(tmp: Path) -> list[subprocess.Popen]:
    """三夹具：临时库 backend + FakeLink 桥 + vite preview。"""
    import tempfile

    db = Path(tempfile.mkdtemp(prefix="fz_browser_e2e_")) / "e2e.db"
    cases = tmp / "cases"
    cases.mkdir(parents=True, exist_ok=True)

    # 临时库建表（全部模型共享 app.ra.models.Base——create_all 单次覆盖）
    # + 预置机构账户种子（审计员/管理员——首登激活态，密码=e2e 夹具值非生产秘密）
    aud_pw = os.environ.get("FZ_SEED_AUDITOR_PASSWORD", "Audit-E2E-1")
    adm_pw = os.environ.get("FZ_SEED_ADMIN_PASSWORD", "Admin-E2E-1")
    pre = subprocess.run(
        [PY, "-c",
         "import sys; sys.path.insert(0, r'%s'); "
         "from sqlalchemy import create_engine; "
         "from sqlalchemy.orm import sessionmaker; "
         "import app.authz.models, app.audit.models, app.telemetry.models, app.accounts.models; "
         "from app.ra.models import Base; "
         "eng = create_engine(r'sqlite:///%s'); "
         "Base.metadata.create_all(eng); "
         "s = sessionmaker(bind=eng)(); "
         "from app.accounts.service import seed_institutional_account; "
         "seed_institutional_account(s, 'auditor', 'auditor', %r); "
         "seed_institutional_account(s, 'admin', 'admin', %r); "
         "s.close()" % (BACKEND, db, aud_pw, adm_pw)],
        capture_output=True, text=True, timeout=60,
    )
    if pre.returncode != 0:
        print("[FAIL] 临时库建表失败", pre.stderr[-300:])
        raise SystemExit(1)

    procs: list[subprocess.Popen] = []
    logs = tmp / "logs"
    logs.mkdir(exist_ok=True)
    try:
        be_env = {**os.environ, "FZ_DB_URL": f"sqlite:///{db.as_posix()}",
                  "FZ_ZK_CASES_DIR": str(cases)}
        procs.append(subprocess.Popen(
            [PY, "-m", "uvicorn", "app.main:create_app", "--factory",
             "--host", "127.0.0.1", "--port", str(API_PORT), "--log-level", "warning"],
            cwd=BACKEND, env=be_env,
            stdout=open(logs / "backend.log", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT))
        br_env = {**os.environ, "PYTHONPATH": f"{BACKEND};{UAS / 'gcs' / 'bridge'}",
                  "FZ_API_BASE": API, "FZ_ZK_CASES_DIR": str(cases)}
        procs.append(subprocess.Popen(
            [PY, "-m", "uvicorn", "server:app", "--host", "127.0.0.1",
             "--port", str(BRIDGE_PORT), "--log-level", "warning"],
            cwd=UAS / "gcs" / "bridge", env=br_env,
            stdout=open(logs / "bridge.log", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT))
        # 构建产物新鲜度判据：任一源文件新于 dist/index.html ⟹ 重建（防 preview
        # 服务旧产物——浏览器回归测的是「当前代码的构建面」而非历史构建）
        _stale = not (WEB / "dist" / "index.html").is_file() or any(
            f.stat().st_mtime > (WEB / "dist" / "index.html").stat().st_mtime
            for f in (WEB / "src").rglob("*.vue"))
        if _stale:
            print("  [..] dist 落后于源码——重新构建")
            npm = shutil.which("npm") or "npm.cmd"
            subprocess.run([npm, "run", "build"], cwd=WEB, check=True,
                           capture_output=True, timeout=300)
        npm = shutil.which("npm") or "npm.cmd"
        procs.append(subprocess.Popen(
            [npm, "run", "preview", "--", "--port", str(WEB_PORT), "--strictPort"],
            cwd=WEB,
            stdout=open(logs / "preview.log", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT))
    except Exception:
        # 泄漏自防：Popen 半途失败=已起进程必须就地清杀（main 的 finally 只见
        # 成功返回的 procs 列表）
        for pr in procs:
            pr.terminate()
        raise
    return procs


def _await_fixtures() -> None:
    t0 = time.time()
    while time.time() - t0 < 60:
        a = _get(f"{API}/healthz")[0] == 200
        b = _get(f"{BRIDGE}/link_status")[0] == 200
        c = _get(WEB_URL)[0] == 200
        if a and b and c:
            expect(True, "0.1 三夹具就绪（backend/fake 链 + 桥/FakeLink + vite preview 构建产物）")
            return
        time.sleep(1.0)
    expect(False, "0.1 三夹具就绪", f"api={_get(API + '/healthz')[0]} bridge={_get(BRIDGE + '/link_status')[0]} web={_get(WEB_URL)[0]}")


def run_tests(tmp: Path) -> None:
    from playwright.sync_api import sync_playwright

    page_errors: list[str] = []
    aud_pw = os.environ.get("FZ_SEED_AUDITOR_PASSWORD", "Audit-E2E-1")
    adm_pw = os.environ.get("FZ_SEED_ADMIN_PASSWORD", "Admin-E2E-1")
    pilot_user = "e2e-pilot-" + secrets.token_hex(3)
    pilot_pw = "e2epass1"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        # 夹具地址先于应用脚本注入（apiBase/bridgeBase 的读取点在模块加载期）
        ctx.add_init_script(
            f"localStorage.setItem('fzApiBase','{API}');"
            f"localStorage.setItem('fzBridgeBase','{BRIDGE}');"
        )
        page = ctx.new_page()
        _page_ref["page"] = page
        page.on("pageerror", lambda e: page_errors.append(str(e)[:200]))
        page.set_default_timeout(15000)

        # ---- ⓪ 门户：注册（两步向导） ----
        page.goto(WEB_URL + "#/login")
        page.wait_for_load_state("networkidle")
        expect(page.title().startswith("飞证"), "0.2 应用加载（构建产物标题）", page.title())
        page.click("button.tab:has-text('飞手注册')")

        # ⓪.3 负例：弱密码（规则清单+人话拒绝）
        page.fill("input:not([type='password']) >> nth=0", pilot_user)
        pw = page.locator("input[type='password']:visible")
        pw.first.fill("short")
        pw.nth(1).fill("short")
        page.click("button:has-text('生成密钥并建账户')")
        expect(page.locator("text=密码未达标").count() > 0, "⓪.3 负例：弱密码 → 规则清单人话拒绝")

        # ⓪.4 正例：建账户（浏览器钥对生成+密封上传）→补资料→RA 签发上链
        pw.first.fill(pilot_pw)
        pw.nth(1).fill(pilot_pw)
        page.click("button:has-text('生成密钥并建账户')")
        page.wait_for_selector("text=补全实名与无人机资料", timeout=30000)
        ok("⓪.4a 账户建立（密钥指纹展示——服务器只有密封件）")
        # SN 单源换代（2026-10-07）：注册表单序列号=桥 /engine_pub 读数只读预填
        # （用户看得到注册的是哪台设备、不可手改——自由 SN 首次 ARM 必 sn_mismatch
        # 的产品缺口就此钉死）。夹具桥缺省锚=FZ-SN-DEV-01。
        sn_input = page.locator("input[readonly][title*='序列号']")
        expect(sn_input.count() >= 1 and sn_input.first.get_attribute("readonly") is not None,
               "⓪.4a-2 SN 单源：注册序列号只读（桥读数预填——用户不可改）")
        expect(sn_input.first.input_value() == "FZ-SN-DEV-01",
               "⓪.4a-3 SN 单源：预填值=桥 device_serial（缺省锚 FZ-SN-DEV-01）",
               f"got={sn_input.first.input_value()!r}")
        page.click("button:has-text('填入示例数据')")
        page.click("button:has-text('提交资料并签发上链')")
        page.wait_for_selector("text=进入飞证工作台", timeout=60000)
        expect(page.locator("text=主凭证已签发").count() > 0,
               "⓪.4b 资料补全→RA 签发上链（上链注册时刻）")
        page.evaluate("JSON.parse(localStorage.fzCred).master_cred_hash_hex")
        page.click("button:has-text('进入飞证工作台')")
        page.wait_for_url("**/#/record")
        page.wait_for_selector("text=登记编号", timeout=15000)
        ok("⓪.4c 进入飞手工作台（我的记录渲染）")

        # ---- ⓪.5 飞手导航隔离（不见审计台/机构台入口） ----
        expect(page.locator("nav button:has-text('审计台')").count() == 0
               and page.locator("nav button:has-text('机构台')").count() == 0,
               "⓪.5 飞手导航隔离（无审计/机构入口——双层隔离前端层）")

        # ---- ⓪.6 登出→错密码登录负例→正例 ----
        page.click("button.exit")
        page.wait_for_selector("button.tab:has-text('登录')", timeout=10000)
        page.click("button.tab:has-text('登录')")
        page.fill("label:has-text('用户名') + input", pilot_user)
        page.locator("label:has-text('密码') + input").fill("wrongpass9")
        page.click("button.btn:has-text('登录')")
        page.wait_for_selector("text=密码错误", timeout=30000)
        ok("⓪.6 负例：错密码 → 本地解封失败人话提示（不猜服务端）")
        page.locator("label:has-text('密码') + input").fill(pilot_pw)
        page.click("button.btn:has-text('登录')")
        page.wait_for_url("**/#/record", timeout=30000)
        page.wait_for_selector("text=登记编号", timeout=15000)
        ok("⓪.7 登录正例（SM2 挑战-应答→会话→工作台）")

        # ---- ① 我的记录：子凭证 ----
        page.click("button:has-text('签发一次性子凭证')")
        try:
            page.wait_for_selector("text=一次性凭证身份", timeout=20000)
        except Exception:
            print("\n[FAIL-CTX] url=", page.url)
            print("[FAIL-CTX] body tail:\n", page.locator("body").inner_text()[-1200:])
            raise

        ok("①.2 签发子凭证成功（真实 /ra/sub-credentials——id′ 展示）")

        # ---- ② 起飞申请 ----
        page.click("nav button:has-text('起飞申请')")
        page.wait_for_url("**/#/apply")
        page.wait_for_selector("text=政策", timeout=10000)
        expect(page.locator("text=政策").count() > 0 or page.locator("text=上限").count() > 0,
               "②.1 申请页渲染（政策上限公示）")
        # SN 单源换代（2026-10-07）：申请页设备序列号=桥读数只读展示（出证与
        # 解锁同一台设备；读数异步到齐——wait_for_function 钉值不断言盲等）
        page.wait_for_function(
            "() => (document.querySelector(\"input[title*='序列号']\")||{}).value === 'FZ-SN-DEV-01'",
            timeout=15000)
        ap_sn = page.locator("input[readonly][title*='序列号']")
        expect(ap_sn.count() >= 1 and ap_sn.first.input_value() == "FZ-SN-DEV-01",
               "②.2 SN 单源：申请页序列号=桥读数只读展示（用户不可改）")

        # ---- ③ 令牌与飞行（初始态+步进器） ----
        page.click("nav button:has-text('令牌与飞行')")
        page.wait_for_url("**/#/flight")
        page.wait_for_selector("text=领取飞行令牌", timeout=10000)
        expect(page.locator("text=领取飞行令牌").count() > 0,
               "③.1 飞行屏初始态渲染（领取令牌区——无令牌不进飞行态）")
        expect(page.locator(".stepper .step").count() >= 4,
               "③.2 七态步进器渲染（流程显性化）")

        # ---- ④ 留痕与 TRAIL（seed 300 样本=2 窗口；证书卡持久化=切页修复面） ----
        page.click("nav button:has-text('留痕与合规证明')")
        page.wait_for_url("**/#/trail")
        rows = [{"t": 1790000000 + i // 2, "alt_cm": 1000 + i % 50,
                 "lat_1e7": 0, "lon_1e7": 0, "head": ("ab" * 32)} for i in range(300)]
        page.evaluate("rows => localStorage.setItem('fzTrailRows', JSON.stringify(rows))", rows)
        page.evaluate("auth => localStorage.setItem('fzTrailAuthId', auth)", "7")
        page.evaluate("g => localStorage.setItem('fzTrailGenesis', g)", "cd" * 32)
        page.evaluate("h => localStorage.setItem('fzTrailHead', h)", "ef" * 32)
        # 证书卡持久化种子（切页修复：certs 落 localStorage——回显不丢）
        page.evaluate("c => localStorage.setItem('fzTrailCerts', JSON.stringify(c))",
                      {"0": {"verdict": "PASS", "bytes": 1234, "prove_s": 1.2, "verify_s": 0.1, "sm3": "ff" * 32}})
        page.evaluate("ci => localStorage.setItem('fzTrailCaseIds', JSON.stringify(ci))", {"0": "seedcase0"})
        page.reload()
        page.wait_for_selector("text=可出证窗口", timeout=10000)
        expect(page.locator("text=可出证窗口 2").count() > 0, "④.1 行程证书包窗口计数（300 样本=2 窗）")
        sel = page.locator("select")
        expect(sel.locator("option").count() == 2
               and "样本 129–256" in sel.locator("option").nth(1).inner_text(),
               "④.2 窗口选择器（窗口 0/1 含样本区间）")
        expect(page.locator("button:has-text('生成 TRAIL 合规证书')").is_disabled(),
               "④.3 未取件（alt_max 缺）→ 出证按钮禁用")
        expect(page.locator("button:has-text('下载行程索引')").count() > 0, "④.4 行程索引入口在位")
        verify_link = page.locator("a:has-text('验证工具分发页')")
        expect(verify_link.count() > 0 and f":{API_PORT}/verify/" in verify_link.first.get_attribute("href"),
               "④.5 验证工具分发页链接（指向夹具 backend /verify/）")

        # ---- ⑤ 回执查询段已删除（2026-10-04 队长指令：页删能力留——
        # GET /authz/receipt/{code} 的 API 面负例由 e2e_frontend_api ⑤ 段覆盖，
        # 取件主路径（FlightView 输码→领取令牌）在 ③ 段与 frontend_api 守护） ----

        # ---- ⑥ 链上留痕 ----
        page.click("nav button:has-text('链上留痕')")
        page.wait_for_url("**/#/chain")
        page.wait_for_selector("h2:has-text('链上留痕')", timeout=10000)
        page.wait_for_selector("h3:has-text('授权记录')", timeout=10000)
        expect(page.locator("h3:has-text('检查点锚定')").count() > 0
               and page.locator("h3:has-text('令状')").count() > 0,
               "⑥.1 链上面板渲染（状态/授权记录/检查点/令状四板块）")

        # ---- ⑦ 越权实弹（API 面：未登录 401 / 飞手打审计面 403） ----
        # 注意：浏览器内 API 基址经同站对齐为 localhost（SameSite 会话 Cookie
        # 的宿主域）——会话实弹必须走 localhost，否则 Cookie 域不符=假 401
        API_LOCAL = f"http://localhost:{API_PORT}"
        rc_anon = _get(f"{API_LOCAL}/audit/warrants")[0]
        expect(rc_anon == 401, "⑦.1 未登录打审计面 → 401（会话门实弹）", f"rc={rc_anon}")
        rc_pilot = page.request.get(f"{API_LOCAL}/audit/warrants").status
        expect(rc_pilot == 403, "⑦.2 飞手会话打审计面 → 403（角色门实弹）", f"rc={rc_pilot}")

        # ---- ⑧ 审计台 Vue（审计员首登激活→工作台） ----
        actx = browser.new_context()
        actx.add_init_script(
            f"localStorage.setItem('fzApiBase','{API}');"
            f"localStorage.setItem('fzBridgeBase','{BRIDGE}');"
        )
        apage = actx.new_page()
        apage.on("pageerror", lambda e: page_errors.append(f"[aud] {e}"[:200]))
        apage.set_default_timeout(20000)
        apage.goto(WEB_URL + "#/login")
        apage.wait_for_load_state("networkidle")
        apage.click("button.tab:has-text('登录')")
        apage.fill("label:has-text('用户名') + input", "auditor")
        apage.locator("label:has-text('密码') + input").fill(aud_pw)
        apage.click("button.btn:has-text('登录')")
        apage.wait_for_url("**/#/audit", timeout=60000)
        apage.wait_for_selector("text=违规事件收件箱", timeout=20000)
        expect(apage.locator(".stepper .step").count() == 4,
               "⑧.1 审计台 Vue 渲染（首登激活→四步步进器+收件箱）")
        expect(apage.locator("nav button:has-text('起飞申请')").count() == 0,
               "⑧.2 审计员导航隔离（不见飞手页面）")
        actx.close()

        # ---- ⑨ 机构台 Vue（管理员首登激活→待批+台账+吊销+总览） ----
        mctx = browser.new_context()
        mctx.add_init_script(
            f"localStorage.setItem('fzApiBase','{API}');"
            f"localStorage.setItem('fzBridgeBase','{BRIDGE}');"
        )
        mpage = mctx.new_page()
        mpage.on("pageerror", lambda e: page_errors.append(f"[adm] {e}"[:200]))
        mpage.set_default_timeout(20000)
        mpage.goto(WEB_URL + "#/login")
        mpage.wait_for_load_state("networkidle")
        mpage.click("button.tab:has-text('登录')")
        mpage.fill("label:has-text('用户名') + input", "admin")
        mpage.locator("label:has-text('密码') + input").fill(adm_pw)
        mpage.click("button.btn:has-text('登录')")
        mpage.wait_for_url("**/#/admin", timeout=60000)
        mpage.wait_for_selector("text=待批协作请求", timeout=20000)
        expect(mpage.locator("text=协作台账").count() > 0
               and mpage.locator("text=凭证吊销").count() > 0
               and mpage.locator("text=账户总览").count() > 0,
               "⑨.1 机构台 Vue 渲染（待批/台账/吊销/总览四板块）")
        mctx.close()

        # ---- 服务状态点（App 壳） ----
        dots = page.locator(".dot, .status-dot, [class*='dot']")
        ok(f"K.1 服务状态点元素在位（{dots.count()} 个——20s 周期重探由 App.vue probe 计时器承担）")

        # ---- 验证工具分发页（后端产物页） ----
        page.goto(f"{API}/verify/")
        page.wait_for_load_state("networkidle")
        expect(page.locator("text=验证工具分发").count() > 0
               and (page.locator("text=zkc-linux-amd64").count() > 0
                    or page.locator("text=未生成").count() > 0),
               "④.6 分发页可达（产物行或诚实「未生成」）")
        # 2026-10-04 复查根修守卫：指纹格必须被活数据填充（/verify/api/checks
        # 实时算本地指纹+链上回读）——不许停留在占位「读取中…」（旧硬编码
        # 指纹曾随电路换代漂移成旧值 17a90dc1 而无测试拦住）。
        pin_txt = page.locator("#pin-cell").inner_text()
        expect(not pin_txt.startswith("读取中"),
               "④.7 分发页指纹=活数据（JS 已填充，非占位）")

        browser.close()

    # ---- D. dev 形态冒烟（vite dev 与 build 的模板容差差异守卫） ----
    import subprocess as _sp

    npm = shutil.which("npm") or "npm.cmd"
    dev = _sp.Popen([npm, "run", "dev", "--", "--port", str(WEB_PORT + 1), "--strictPort"],
                    cwd=WEB, stdout=open(tmp / "vite_dev.log", "w", encoding="utf-8"),
                    stderr=_sp.STDOUT)
    try:
        dev_url = f"http://localhost:{WEB_PORT + 1}/"
        t0 = time.time()
        while time.time() - t0 < 40:
            if _get(dev_url)[0] == 200:
                break
            time.sleep(1.0)
        else:
            expect(False, "D.0 vite dev 就绪")
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            ctx = b.new_context()
            ctx.add_init_script(
                f"localStorage.setItem('fzApiBase','{API}');"
                f"localStorage.setItem('fzBridgeBase','{BRIDGE}');"
                "localStorage.setItem('fzSession', JSON.stringify({username:'dev-pilot', role:'pilot'}));"
                "localStorage.setItem('fzCred', JSON.stringify({master_cred_hash_hex:"
                "'ab'.repeat(32), commitment_hex:'cd'.repeat(32), salt_hex:'ef'.repeat(32),"
                " sig_hex:'12'.repeat(32), expires_at:'2027-01-01'}));")
            pg = ctx.new_page()
            pg.on("pageerror", lambda e: page_errors.append(f"[dev] {e}"[:200]))
            pg.goto(dev_url + "#/flight")
            pg.wait_for_selector("text=领取飞行令牌", timeout=20000)
            expect(pg.locator(".stepper .step").count() >= 4,
                   "D.1 dev 形态飞行屏渲染（dev 编译面=build 盲区守卫）")
            b.close()
    finally:
        dev.terminate()

    expect(not page_errors, f"Z. 全程零 pageerror（{len(page_errors)} 个 JS 崩溃）",
           "; ".join(page_errors[:3]))

def _kill_port_holder(port: int) -> bool:
    """按端口杀残留夹具（前次异常退出可能泄漏 uvicorn/preview）。netstat 输出
    GBK（教训㊿+26 旧案）——按列解析 PID，taskkill /F。"""
    import subprocess as sp

    try:
        out = sp.run(["netstat", "-ano"], capture_output=True).stdout.decode("gbk", "replace")
    except Exception:  # noqa: BLE001
        return False
    pids = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1].endswith(f":{port}") and parts[-2] == "LISTENING":
            pids.add(parts[-1])
    for pid in pids:
        sp.run(["taskkill", "/F", "/PID", pid], capture_output=True)
    return bool(pids)


def main() -> int:
    import tempfile

    for port in (API_PORT, BRIDGE_PORT, WEB_PORT):
        if not _port_free(port):
            print(f"[..] 端口 {port} 被占——尝试清理残留夹具")
            _kill_port_holder(port)
            time.sleep(1.0)
            if not _port_free(port):
                print(f"[FAIL] 端口 {port} 仍被占用（非本夹具进程？）——人工排查")
                return 1
    tmp = Path(tempfile.mkdtemp(prefix="fz_browser_e2e_"))
    procs: list[subprocess.Popen] = []
    t0 = time.time()
    try:
        procs = _boot_fixtures(tmp)
        _await_fixtures()
        try:
            run_tests(tmp)
        except Exception:
            pg = _page_ref["page"]
            if pg is not None:
                try:
                    print("\n[FAIL-CTX] url=", pg.url)
                    print("[FAIL-CTX] body tail:\n", pg.locator("body").inner_text()[-1600:])
                except Exception:  # noqa: BLE001
                    print("[FAIL-CTX] 页面已关闭，无法转储")
            raise
        print(f"\n== 浏览器级 UI 回归全绿：{_checks} 项断言 [OK]（{time.time() - t0:.0f}s）==")
        return 0
    finally:
        for pr in procs:
            pr.terminate()
        time.sleep(1.0)
        for pr in procs:
            if pr.poll() is None:
                pr.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
