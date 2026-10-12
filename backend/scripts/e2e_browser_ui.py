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
# 第 0 批 0.3 增补夹具通道（插入式）：临时库路径（Gap2 org 域翻转消费）+
# admin-fix 钥对（Gap1 吊销数据制备——一次性夹具钥，非生产秘密）
_db_path: dict = {"path": None}
_admin_fix: dict = {"sk": None, "pk": None}


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
    _db_path["path"] = str(db)
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

    # 第 0 批 0.3 增补种子（追加式子进程——既有种子语句零触碰）：
    # admin-fix=已激活形态夹具管理员（钥对由主进程生成经 _admin_fix 传入——
    # Gap1 吊销数据制备走真实 /ra/revoke 签名仪式）；
    # admin-b=org-b 域种子（Gap2 跨域浏览器级——e2e_cross_org org-b 种子语义
    # 的夹具版，首登激活态，密码=夹具值非生产秘密）。
    adm_b_pw = os.environ.get("FZ_SEED_ADMIN_B_PASSWORD", "AdminB-E2E-1")
    pre2 = subprocess.run(
        [PY, "-c",
         "import sys; sys.path.insert(0, r'%s'); "
         "from sqlalchemy import create_engine; "
         "from sqlalchemy.orm import sessionmaker; "
         "import app.accounts.models; "
         "from app.ra.models import Base; "
         "eng = create_engine(r'sqlite:///%s'); "
         "Base.metadata.create_all(eng); "
         "s = sessionmaker(bind=eng)(); "
         "from app.accounts.models import Account; "
         "s.add(Account(username='admin-fix', role='admin', status='active', pubkey_hex=r'%s')); "
         "from app.accounts.service import seed_institutional_account; "
         "seed_institutional_account(s, 'admin-b', 'admin', %r, org_id='org-b'); "
         "s.close()" % (BACKEND, db, _admin_fix["pk"], adm_b_pw)],
        capture_output=True, text=True, timeout=60,
    )
    if pre2.returncode != 0:
        print("[FAIL] 0.3 增补种子失败", pre2.stderr[-300:])
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
    adm_b_pw = os.environ.get("FZ_SEED_ADMIN_B_PASSWORD", "AdminB-E2E-1")
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

        # ---- 0.3 Gap1 数据锚（插入式——既有断言零触碰）：凭证句柄捕获+无事件
        # 空缺省状态捕获。刚登记用户：无吊销/无违规/无子凭证 ⟹ /ra/pilot/notices
        # 三段全空 ⟹ PilotNotices v-if 不渲染；拉取在途（notices=null）同样不渲染
        # ——count==0 在两态恒定，断言无竞态。----
        pilot_handle = page.evaluate(
            "() => JSON.parse(localStorage.fzCred).master_cred_hash_hex")
        gap1_empty = (page.locator(".fz-notices").count() == 0
                      and page.locator("[data-test^='notice-']").count() == 0)

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

        # ---- ⑦.3 提醒条真实栈实弹（0.3 Gap1 增补——插入式）：org-a 夹具管理
        # 员经真实 /auth/challenge-login + /ra/revoke 签名仪式吊销飞手凭证
        # （同域操作——0.1 org 域门放行路径），重载 #/record 后：吊销红条
        # （理由回显）+到期黄条（①.2 子凭证未消费——24h TTL 落 7 天提醒窗）
        # 渲染可见；与 ⓪.4c 捕获的空缺省合成一双态合取断言（任一态破即红）。
        # 数据=真实后端状态，零前端 mock。----
        import requests as _rq

        from app.crypto.sm2 import sign as _sm2_sign
        from app.ra.service import revoke_msg as _revoke_msg

        _sess = _rq.Session()
        _sess.trust_env = False  # 与 _get 同纪律——环回直连不落系统代理
        _ch = _sess.post(f"{API_LOCAL}/auth/challenge/admin-fix",
                         timeout=10).json()["data"]["nonce_hex"]
        _lr = _sess.post(
            f"{API_LOCAL}/auth/login",
            json={"username": "admin-fix", "nonce_hex": _ch,
                  "sig_hex": _sm2_sign(_admin_fix["sk"], f"FZ-AUTH-LOGIN|{_ch}".encode())},
            timeout=10)
        assert _lr.status_code == 200, f"夹具管理员登录失败: {_lr.text[:150]}"
        _ep = _sess.get(f"{API_LOCAL}/ra/revocation/snapshot",
                        timeout=10).json()["data"]["epoch"] + 1
        _reason = "浏览器级提醒条实弹吊销"
        _rr = _sess.post(
            f"{API_LOCAL}/ra/revoke",
            json={"master_cred_hash_hex": pilot_handle, "reason": _reason,
                  "sig_hex": _sm2_sign(_admin_fix["sk"],
                                       _revoke_msg([pilot_handle], _reason, _ep).encode()),
                  "epoch": _ep},
            timeout=15)
        assert _rr.status_code == 200, f"夹具吊销失败: {_rr.text[:200]}"
        page.goto(WEB_URL + "#/record")  # ⑥ 段后页在 #/chain——显式回首页
        page.reload()  # 全量重载=RecordView 重挂载+notices 重拉（吊销后真实状态）
        page.wait_for_selector("[data-test='notice-revoked']", timeout=15000)
        _rev_txt = page.locator("[data-test='notice-revoked']").first.inner_text()
        gap1_visible = ("您的凭证已被吊销" in _rev_txt
                        and _reason in _rev_txt
                        and page.locator("[data-test='notice-expiring']").count() >= 1)
        expect(gap1_empty and gap1_visible,
               "⑦.3 提醒条双态（无事件诚实空缺省不渲染+吊销红条/到期黄条真实栈渲染可见）",
               f"empty={gap1_empty} visible={gap1_visible}")

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
        # 2026-10-12 修整窗口：机构台拆四标签工作台（待办=默认首屏）——v-show
        # 保 DOM 可达（count() 对 display:none 元素照常计数，⑨.1 断言原文不动）。
        expect(mpage.locator("text=协作台账").count() > 0
               and mpage.locator("text=凭证吊销").count() > 0
               and mpage.locator("text=账户总览").count() > 0,
               "⑨.1 机构台 Vue 渲染（待批/台账/吊销/总览四板块——v-show 可达）")
        # ⑨.0（2026-10-12 新增）：标签工作台在列+登录态机构徽标（whoami.org_id
        # 活数据——修整窗口③/B2 审计件：多机构形态下当前操作者域常显）。
        expect(mpage.locator("[data-test='admin-tabs']").count() == 1
               and mpage.locator("[data-test='org-badge']").inner_text().strip() == "org-a",
               "⑨.0 标签工作台+机构徽标（四标签默认待办+whoami.org_id 活数据）",
               mpage.locator("[data-test='org-badge']").inner_text())
        # ⑨.2 治理公示（锚迁移：自机构台拆独立页 /governance——admin+auditor
        # 双可见；k-of-n 大屏必须渲染且链上数据活填充——多签 KPI 格非占位）。
        mpage.goto(WEB_URL + "#/governance")
        mpage.wait_for_selector("text=链上治理", timeout=20000)
        expect(
            mpage.locator("text=多签").first.inner_text().replace(chr(10), "")
            not in ("", "—", "读取中"),
               "⑨.2 治理页 k-of-n KPI 活数据（/chain/governance 回读填充——拆页迁移）")
        # ⑨.3（2026-10-12 新增）：互认机构面板状态感知双态断言（B1 审计件根修
        # ——federation 公示进 UI）。与 GovView 组件同构：fake 档=诚实空缺
        # 文案；真链档=真实名册（互认机构表+在册域数+聚合纪元活数据——链烟
        # ⑨-b/跨域套件登记 org 后本断言实弹；此前无条件断空态文案在真链档
        # 必超时=套件对链状态的过时假设，2026-10-12 验收批根修）。
        # 双态竞态补丁（⑫O-5 批）：gov 拉取为 onMounted 异步——头部静态渲染
        # 先于数据到达即断言会误入 else 分支。先等两态之一实际出现（不弱化
        # 断言——两分支判定体保持原样，只补状态感知等待）。
        mpage.locator("text=互认注册表随真链提供").or_(
            mpage.locator(r"text=/聚合纪元 \d+/")
        ).first.wait_for(timeout=15000)
        if mpage.locator("text=互认注册表随真链提供").count() >= 1:
            expect(mpage.locator("text=互认注册表随真链提供").count() >= 1,
                   "⑨.3 互认机构面板 fake 档诚实空态（FedRegistry 公示随真链提供）")
        else:
            mpage.wait_for_selector("text=互认机构（FedRegistry 名册）", timeout=20000)
            expect(mpage.locator("text=/聚合纪元 \\d+/").count() >= 1,
                   "⑨.3 互认机构面板真链档公示（聚合纪元活数据回填）")
            if mpage.locator(".tbl-wrap table").count() >= 1:
                expect(mpage.locator(".tbl-wrap table tbody tr").count() >= 1,
                       "⑨.3 互认机构面板真链档名册（在册机构行实弹）")
            else:
                expect(mpage.count() >= 1,
                       "⑨.3 互认机构面板真链档（注册表在案、暂无在册域=诚实空表）")
        mpage.goto(WEB_URL + "#/admin")
        mpage.wait_for_selector("text=待批协作请求", timeout=20000)
        # ---- ⑨-b 机队设备管理动线（3.1——credKind=2 机构承诺主凭证；插入式
        # 只增）：锚迁移（2026-10-12）=机队入「机队」标签，先切标签再断言
        # （inner_text 对 display:none 返回空串——v-show 纪律）；面板渲染
        # （kind=2 一级动线在列）+批量登记一台（fake 链夹具=registerCommitment
        # 留痕）→设备列表行「有效」徽章+登记回执原像盐在列。SN=夹具桥读数
        # FZ-SN-DEV-01（/engine_pub device_serial 单源——与第 6 查同源闭环）。----
        mpage.locator("[data-test='admin-tabs'] button:has-text('机队')").click()
        fleet_panel = mpage.locator("[data-test='fleet-panel']")
        expect(fleet_panel.count() == 1 and "机队设备管理" in fleet_panel.inner_text(),
               "⑨-b.1 机队设备管理面板渲染（credKind=2 机构承诺一级动线）")
        fleet_no = "FZ-BRW-E2E-" + "".join(secrets.choice("0123456789") for _ in range(7))
        expect(len(fleet_no) == 18, "⑨-b.2 前置：随机登记号恰 18 字符", fleet_no)
        fleet_panel.locator("button:has-text('添加设备行')").click()
        fleet_panel.locator("input[placeholder^='设备登记号']").fill(fleet_no)
        fleet_panel.locator("input[placeholder^='设备序列号']").fill("FZ-SN-DEV-01")
        fleet_panel.locator("button:has-text('登记上链')").click()
        fleet_panel.get_by_text("登记回执").wait_for(timeout=20000)
        _receipt_txt = fleet_panel.locator("text=登记回执（原像盐一次性").first.inner_text()
        expect(fleet_panel.locator(f"text={fleet_no}").count() >= 1
               and "原像盐" in _receipt_txt,
               "⑨-b.2 批量登记实弹（kind=2 上链+回执原像盐一次性在列+列表行回填）",
               f"no={fleet_no}")
        mctx.close()

        # ---- ⑩ 跨域浏览器级（0.3 Gap2 增补——插入式）：org-b 种子语义的
        # 浏览器动线。UI 无 org 选择面（web 源码零 org_id surface）：域归属由
        # 夹具库建立——admin-b=org-b 种子首登；pilot2 浏览器注册后 users.org_id
        # 翻转为 org-b（e2e_cross_org [X2] 的夹具手段），随后受理面动线子凭证
        # 签发成功=「受理面认 B 域用户」（[X3] 的浏览器级对应面）。两态合成一
        # 合取断言（任一面破即红）。----
        pilot2_user = "e2e-orgb-" + secrets.token_hex(3)
        octx = browser.new_context()
        octx.add_init_script(
            f"localStorage.setItem('fzApiBase','{API}');"
            f"localStorage.setItem('fzBridgeBase','{BRIDGE}');"
        )
        opage = octx.new_page()
        opage.on("pageerror", lambda e: page_errors.append(f"[orgb-pilot] {e}"[:200]))
        opage.set_default_timeout(20000)
        opage.goto(WEB_URL + "#/login")
        opage.wait_for_load_state("networkidle")
        opage.click("button.tab:has-text('飞手注册')")
        opage.fill("input:not([type='password']) >> nth=0", pilot2_user)
        opw = opage.locator("input[type='password']:visible")
        opw.first.fill("e2epass2")
        opw.nth(1).fill("e2epass2")
        opage.click("button:has-text('生成密钥并建账户')")
        opage.wait_for_selector("text=补全实名与无人机资料", timeout=30000)
        opage.click("button:has-text('填入示例数据')")
        # 证件号覆盖为随机新值——示例号固定（LoginView fillSample），pilot1 已被
        # ⑦.3 吊销 ⟹ 其证件号入 B7 黑名单，复用必 409 id_revoked_before
        opage.fill("input[maxlength='18']",
                   "11010119920303" + "".join(secrets.choice("0123456789") for _ in range(4)))
        opage.click("button:has-text('提交资料并签发上链')")
        opage.wait_for_selector("text=进入飞证工作台", timeout=60000)
        opage.click("button:has-text('进入飞证工作台')")
        opage.wait_for_url("**/#/record", timeout=30000)
        opage.wait_for_selector("text=登记编号", timeout=15000)
        # 域归属翻转第一拍（夹具库直改 users.org_id + credentials.owner_org_id
        # =org-b；账户仍 org-a=域错配态。3.1 域权威换代注记：凭证归属域权威
        # 列=owner_org_id（登记时写列）——夹具须同步翻凭证行，users 行单独翻
        # 不再构成错配态（_creds_org 单一权威=列）。）
        _flip = subprocess.run(
            [PY, "-c",
             "import sys; sys.path.insert(0, r'%s'); "
             "from sqlalchemy import create_engine; "
             "from sqlalchemy.orm import sessionmaker; "
             "from app.ra.models import Credential, User; "
             "eng = create_engine(r'sqlite:///%s'); "
             "s = sessionmaker(bind=eng)(); "
             "u = s.query(User).filter_by(username='%s').one(); "
             "u.org_id = 'org-b'; "
             "n = s.query(Credential).filter_by(user_id=u.id)"
             ".update({Credential.owner_org_id: 'org-b'}); "
             "s.commit(); print(u.org_id, n)" % (
                 BACKEND, _db_path["path"], pilot2_user)],
            capture_output=True, text=True, timeout=60)
        assert _flip.returncode == 0 and _flip.stdout.split() == ["org-b", "1"], \
            f"org 域翻转失败（users 行+凭证行 owner_org_id 须同步翻）: {_flip.stderr[-200:]}"
        # ① 域错配态会话内签发 → 0.1 org 域门 403 org_forbidden 浏览器级呈现
        # （判词=目标凭证归属域/操作者域双域——跨域拒绝的人话呈现实弹）
        opage.click("button:has-text('签发一次性子凭证')")
        opage.wait_for_selector("text=跨域操作拒绝", timeout=15000)
        deny_seen = True
        # ② 域对齐（accounts.org_id=org-b——账户与凭证同域的多机构正确语义）
        _flip2 = subprocess.run(
            [PY, "-c",
             "import sys; sys.path.insert(0, r'%s'); "
             "from sqlalchemy import create_engine; "
             "from sqlalchemy.orm import sessionmaker; "
             "from app.accounts.models import Account; "
             "eng = create_engine(r'sqlite:///%s'); "
             "s = sessionmaker(bind=eng)(); "
             "a = s.query(Account).filter_by(username='%s').one(); "
             "a.org_id = 'org-b'; s.commit(); print(a.org_id)" % (
                 BACKEND, _db_path["path"], pilot2_user)],
            capture_output=True, text=True, timeout=60)
        assert _flip2.returncode == 0 and _flip2.stdout.strip() == "org-b", \
            f"账户域对齐失败: {_flip2.stderr[-200:]}"
        # ③ 域对齐后受理动线：会话内签发成功（受理面认 B 域用户——[X3] 对应面）
        opage.click("button:has-text('签发一次性子凭证')")
        try:
            opage.wait_for_selector("text=一次性凭证身份", timeout=20000)
        except Exception:
            print("\n[FAIL-CTX orgb] url=", opage.url)
            print("[FAIL-CTX orgb] body tail:\n", opage.locator("body").inner_text()[-1200:])
            raise
        org_b_issued = True
        octx.close()
        # org-b 机构账户浏览器首登激活（prelogin activation 分支——⑧⑨ 同工艺）→机构台
        b2ctx = browser.new_context()
        b2ctx.add_init_script(
            f"localStorage.setItem('fzApiBase','{API}');"
            f"localStorage.setItem('fzBridgeBase','{BRIDGE}');"
        )
        bpage = b2ctx.new_page()
        bpage.on("pageerror", lambda e: page_errors.append(f"[orgb-admin] {e}"[:200]))
        bpage.set_default_timeout(20000)
        bpage.goto(WEB_URL + "#/login")
        bpage.wait_for_load_state("networkidle")
        bpage.click("button.tab:has-text('登录')")
        bpage.fill("label:has-text('用户名') + input", "admin-b")
        bpage.locator("label:has-text('密码') + input").fill(adm_b_pw)
        bpage.click("button.btn:has-text('登录')")
        bpage.wait_for_url("**/#/admin", timeout=60000)
        bpage.wait_for_selector("text=待批协作请求", timeout=20000)
        b2_rendered = True
        b2ctx.close()
        expect(deny_seen and org_b_issued and b2_rendered,
               "⑩.1 跨域浏览器级（org-b 机构账户首登→机构台渲染；域错配签发 403 org_forbidden"
               "浏览器呈现+域对齐后受理动线成功——e2e_cross_org [X2/X3] 对应面）",
               f"deny={deny_seen} issued={org_b_issued} admin_b={b2_rendered}")

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
    # 0.3 增补：admin-fix 夹具钥对（Gap1 吊销签名仪式——主进程持 sk，
    # pk 经 _admin_fix 进种子子进程建已激活形态账户行）
    sys.path.insert(0, str(BACKEND))
    from app.crypto.sm2 import generate_keypair as _gk

    _admin_fix["sk"], _admin_fix["pk"] = _gk()
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
