"""3 分钟演示动线彩排器（2026-10-12 修整窗口——docs/演示动线3分钟.md 配套）。

对**运行中的演示栈**（backend 8000 / bridge 8100 / web 5174，真链档）做
九拍全走查：预埋（飞手注册/双子凭证/违规飞行取证+四窗预登录）→ 正式九拍
逐步计时（每拍 [OK]/[FAIL] + 判据）。前置：e2e_browser_ui 40/40 全绿后运行；
建议先 `demo_reset --yes --down` + `demo_up`（纯净演示库）。

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/demo_rehearse_3min.py
输出：逐拍 [OK]/[FAIL] + 判决行（X/9 拍全通 + 预埋 Y 项），偏差记入
docs/演示动线3分钟.md「彩排实录」。
"""

from __future__ import annotations

import secrets
import sys
import time

from playwright.sync_api import sync_playwright

API = "http://127.0.0.1:8000"
BRIDGE = "http://127.0.0.1:8100"
WEB = "http://localhost:5174"

PILOT_USER = "pilot3min" + secrets.token_hex(2)
PILOT_PW = "Demo-Pass-1"
AUD_PW = "auditor123"
ADM_PW = "admin123"
ADMB_PW = "adminb123"

_results: list[tuple[bool, str]] = []
_t0 = time.time()


def beat(ok: bool, label: str) -> bool:
    _results.append((ok, label))
    mark = "[OK]  " if ok else "[FAIL]"
    print(f"  {mark} t=+{time.time() - _t0:5.1f}s {label}", flush=True)
    return ok


def pageerror_watch(page, bucket: list):
    page.on("pageerror", lambda e: bucket.append(str(e)[:200]))


def login(page, username: str, password: str, wait_selector: str) -> None:
    """首登激活分支（demo 档无激活码）或挑战登录——统一入口。"""
    page.goto(WEB + "/#/login")
    page.wait_for_load_state("networkidle")
    page.click("button.tab:has-text('登录')")
    page.fill("label:has-text('用户名') + input", username)
    page.locator("label:has-text('密码') + input").fill(password)
    page.click("button.btn:has-text('登录')")
    page.wait_for_selector(wait_selector, timeout=60000)


def register_pilot(page) -> None:
    page.goto(WEB + "/#/login")
    page.wait_for_load_state("networkidle")
    page.click("button.tab:has-text('飞手注册')")
    page.fill("input:not([type='password']) >> nth=0", PILOT_USER)
    page.locator("input[type='password']").nth(0).fill(PILOT_PW)
    page.locator("input[type='password']").nth(1).fill(PILOT_PW)
    page.click("button:has-text('生成密钥并建账户')")
    page.wait_for_selector("text=补全实名与无人机资料", timeout=30000)
    page.click("button:has-text('填入示例数据')")
    page.fill(
        "input[maxlength='18']",
        "11010119920303" + "".join(secrets.choice("0123456789") for _ in range(4)),
    )
    page.click("button:has-text('提交资料并签发上链')")
    page.wait_for_selector("text=进入飞证工作台", timeout=60000)
    page.click("button:has-text('进入飞证工作台')")
    page.wait_for_selector("text=登记编号", timeout=15000)


def issue_sub(page) -> None:
    page.goto(WEB + "/#/record")
    page.wait_for_selector("button:has-text('签发一次性子凭证')", timeout=15000)
    page.click("button:has-text('签发一次性子凭证')")
    page.wait_for_selector("text=一次性凭证身份", timeout=20000)


def _local_dt(offset_min: int) -> str:
    import datetime as dt

    return (dt.datetime.now() + dt.timedelta(minutes=offset_min)).strftime("%Y-%m-%dT%H:%M")


def submit_apply(page) -> None:
    """申请页提交（六段刻度轨开跑）。计划字段按 UI 实际标签填写。"""
    page.goto(WEB + "/#/apply")
    page.wait_for_selector("button:has-text('提交申请（本机出证）')", timeout=15000)
    page.fill("label:has-text('作业区域') + input", "演示区北侧")
    page.fill("label:has-text('用途') + input", "3 分钟演示动线彩排")
    # 计划高度缺省 0=非法（validatePlan alt_range）——必须显式填（低于政策上限）
    page.fill("label:has-text('计划作业高度') + input", "100")
    locs = page.locator("input[type='datetime-local']")
    locs.nth(0).fill(_local_dt(1))
    locs.nth(1).fill(_local_dt(121))
    page.click("button:has-text('提交申请（本机出证）')")


def wait_receipt(page, timeout_s: int = 300) -> bool:
    """出证→受理→回执码（后台并行的等待面）。吊销分支=False。"""
    try:
        page.wait_for_selector(".receipt-code", timeout=timeout_s * 1000)
        return True
    except Exception:
        return False


def breach_via_bridge() -> bool:
    """围栏触发（S1 §4 同款配方——与 UI 按住爬升同一指令通路）：持续爬升直至
    fence_breached。返回是否触发。"""
    import json as _json
    import urllib.request

    def climb(pwm: int, hold_s: float) -> dict:
        req = urllib.request.Request(
            f"{BRIDGE}/sitl/climb?pwm={pwm}&hold_s={hold_s}", method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return _json.loads(r.read().decode())

    climb(1500, 0.5)  # 首包吞（S1 配方：1.5s 重发自愈）
    time.sleep(1.0)
    climb(1500, 0.5)
    t1 = time.time()
    while time.time() - t1 < 240:
        try:
            r = climb(1750, 1.4)
            if r.get("fence_breached"):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        errors: list[str] = []

        # ============ 预埋（不计入 3 分钟） ============
        print("== 预埋：飞手注册/双子凭证/违规飞行/四窗预登录 ==", flush=True)
        pctx = browser.new_context()
        ppage = pctx.new_page()
        pageerror_watch(ppage, errors)
        try:
            register_pilot(ppage)
            beat(True, "预埋.1 飞手注册登记（随机证件号）")
        except Exception as e:
            beat(False, f"预埋.1 飞手注册登记（{str(e)[:120]}）")
            return finish(browser, errors, prep_done=False)

        try:
            issue_sub(ppage)
            beat(True, "预埋.2 子凭证 #1 签发")
        except Exception as e:
            beat(False, f"预埋.2 子凭证 #1 签发（{str(e)[:120]}）")
            return finish(browser, errors, prep_done=False)

        # 申请出证→取件→飞行违规（预埋审计线索）
        try:
            submit_apply(ppage)
            if not wait_receipt(ppage, 300):
                raise RuntimeError("出证 300s 未出回执")
            beat(True, "预埋.3 出证就绪（回执码在列）")
        except Exception as e:
            beat(False, f"预埋.3 出证就绪（{str(e)[:120]}）")
            return finish(browser, errors, prep_done=False)

        try:
            ppage.goto(WEB + "/#/flight")
            ppage.wait_for_selector("button:has-text('领取令牌')", timeout=15000)
            # 回执码在受理即出，取件须等 worker 验证 ready（~60-120s）——重试环
            # （not_ready=waiting 判词期间每 10s 再点，真实演示同款操作）
            deadline = time.time() + 300
            while time.time() < deadline:
                ppage.click("button:has-text('领取令牌')")
                try:
                    ppage.wait_for_selector("text=引擎验签通过", timeout=10000)
                    break
                except Exception:
                    ppage.wait_for_timeout(3000)
            else:
                raise RuntimeError("300s 内回执未 ready（引擎验签未过）")
            ppage.click("button:has-text('解锁起飞')")
            # ARM 完成信号=闸门面板「已解锁（审计行已记）」——解锁进行窗
            # （is_armed 已置/会话字段未落全）内点「开始记录」会撞
            # no_active_session 409（telemetry/start 围栏证词单源核对），
            # 必须等闸门审计行落地再开链（彩排偏差①根修）
            ppage.wait_for_selector("text=已解锁（审计行已记）", timeout=60000)
            ppage.click("button:has-text('开始记录')")
            ppage.wait_for_selector("text=开始记录（遥测链 genesis）", timeout=30000)
            ppage.click("button:has-text('自动飞到目标高度')")
            ppage.wait_for_selector("text=定高悬停", timeout=60000)
            beat(True, "预埋.4 解锁+开始记录+合规高度（悬停）")
        except Exception as e:
            deny_txt = ""
            try:
                if ppage.locator(".deny").count():
                    deny_txt = ppage.locator(".deny").first.inner_text().replace(chr(10), " ")[:300]
            except Exception:
                pass
            body_tail = ""
            try:
                body_tail = " | ".join(ppage.locator("body").inner_text().splitlines())[-600:]
            except Exception:
                pass
            beat(
                False,
                f"预埋.4 解锁+记录+合规高度（{str(e)[:120]}）deny={deny_txt} tail={body_tail}",
            )
            return finish(browser, errors, prep_done=False)

        try:
            if not breach_via_bridge():
                raise RuntimeError("240s 未触发围栏")
            beat(True, "预埋.5 围栏触发（breach 事件上链）")
        except Exception as e:
            beat(False, f"预埋.5 围栏触发（{str(e)[:120]}）")
            return finish(browser, errors, prep_done=False)

        try:
            ppage.click("button:has-text('结束飞行并封链')")
            # 封链二次确认（不可撤销动作防误触——第一拍只弹确认句）
            ppage.click("button:has-text('确认封链')")
            # 封链完成判据=事件时间线锚定行（「已封链」是链上留痕页徽章词——
            # FlightView 无此文案，判据错位=彩排偏差②）
            ppage.wait_for_selector("text=结束飞行并封链——检查点锚定", timeout=90000)
            beat(True, "预埋.6 结束飞行并封链")
        except Exception as e:
            beat(False, f"预埋.6 结束飞行并封链（{str(e)[:120]}）——违规事件已上链，继续")

        try:
            issue_sub(ppage)
            beat(True, "预埋.7 子凭证 #2 签发（正式演示用）")
        except Exception as e:
            beat(False, f"预埋.7 子凭证 #2 签发（{str(e)[:120]}）")
            return finish(browser, errors, prep_done=False)

        # 四窗预登录（管理员/审计/跨域首登激活+密钥解锁在预埋完成——正式拍零输入）
        try:
            actx = browser.new_context()
            apage = actx.new_page()
            pageerror_watch(apage, errors)
            login(apage, "auditor", AUD_PW, "text=违规收件箱")
            beat(True, "预埋.8 审计窗预登录（钥解锁在拍 2 发函步——渐进披露位）")
        except Exception as e:
            beat(False, f"预埋.8 审计窗预登录（{str(e)[:120]}）")
            return finish(browser, errors, prep_done=False)

        try:
            mctx = browser.new_context()
            mpage = mctx.new_page()
            pageerror_watch(mpage, errors)
            login(mpage, "admin", ADM_PW, "text=待批协作请求")
            # 钥状态：登录即回写本地钥缓存（loginWithSk→cacheSk）——
            # unlockedOnce 恒真，批准/吊销签名零额外解锁步（彩排偏差④定谳：
            # 解锁输入 v-if="!unlockedOnce" 不渲染，等它=必超时）
            beat(True, "预埋.9 管理员窗预登录+钥解锁")
        except Exception as e:
            beat(False, f"预埋.9 管理员窗预登录（{str(e)[:120]}）")
            return finish(browser, errors, prep_done=False)

        try:
            bctx = browser.new_context()
            bpage = bctx.new_page()
            pageerror_watch(bpage, errors)
            login(bpage, "admin-b", ADMB_PW, "text=待批协作请求")
            # 钥状态同上（登录即缓存）
            beat(True, "预埋.10 跨域窗预登录+钥解锁")
        except Exception as e:
            beat(False, f"预埋.10 跨域窗预登录（{str(e)[:120]}）")
            return finish(browser, errors, prep_done=False)

        # ============ 正式九拍（3 分钟） ============
        print("== 正式九拍（t 从拍 1 起算）==", flush=True)
        _results.clear()
        global _t0
        _t0 = time.time()

        # 拍 1｜飞手窗：提交申请（后台并行）
        try:
            submit_apply(ppage)
            beat(True, "拍1 提交申请（六段刻度轨开跑——后台并行锚点）")
        except Exception as e:
            beat(False, f"拍1 提交申请（{str(e)[:120]}）")
        pilot_ready = False

        # 拍 2｜审计窗：立案→发函
        try:
            apage.goto(WEB + "/#/audit")
            apage.wait_for_selector("button.lead-card:not(.dead)", timeout=30000)
            apage.locator("button.lead-card").first.click()
            apage.click("button:has-text('确认立案并登记令状')")
            apage.wait_for_selector("button:has-text('签名并发起协同请求')", timeout=30000)
            # 钥状态：审计登录即缓存（unlockedOnce 恒真）——发函直接可签
            apage.click("button:has-text('签名并发起协同请求')")
            apage.wait_for_selector("text=待批准", timeout=30000)
            beat(True, "拍2 违规立案→令状上链→签名发函")
        except Exception as e:
            beat(False, f"拍2 立案发函（{str(e)[:150]}）")

        # 拍 3｜管理员窗：待办批准→仪式 trace
        try:
            mpage.goto(WEB + "/#/admin")
            mpage.wait_for_selector("button:has-text('批准（签名后自动执行解锁）')", timeout=30000)
            mpage.click("button:has-text('批准（签名后自动执行解锁）')")
            # 执行窗内待办卡可就地浮现仪式面板（真链执行 10~20s，一闪而过）
            # ——本拍判据以**台账「仪式留痕」回放**为准（案乙读面，稳定可达）
            mpage.wait_for_selector(
                "button:has-text('批准（签名后自动执行解锁）')", state="detached", timeout=180000
            )
            mpage.locator("[data-test='admin-tabs'] button:has-text('台账与账户')").click()
            mpage.wait_for_selector("button:has-text('仪式留痕')", timeout=30000)
            _resp: dict = {}
            mpage.on(
                "response",
                lambda r: (
                    _resp.update({r.url[-60:]: r.status}) if "threshold/ceremony" in r.url else None
                ),
            )
            mpage.locator("button:has-text('仪式留痕')").first.click()
            mpage.wait_for_timeout(2500)
            trace_n = mpage.locator("[data-test='ceremony-trace']").count()
            toggle_n = mpage.locator("button:has-text('收起仪式')").count()
            print(
                f"    [拍3诊断] ceremony-resp={_resp} trace_n={trace_n} 收起仪式={toggle_n}",
                flush=True,
            )
            mpage.wait_for_selector("[data-test='ceremony-trace']", timeout=30000)
            trace = mpage.locator("[data-test='ceremony-trace']").inner_text()
            assert "门限解锁仪式" in trace and "应召 2/3 域" in trace, trace[:200]
            mpage.locator("[data-test='admin-tabs'] button:has-text('待办')").click()
            beat(True, "拍3 待办批准→双钥汇流→已执行→台账仪式留痕回放（逐域四关可见）")
        except Exception as e:
            dbg = ""
            try:
                n_btn = mpage.get_by_role("button", name="仪式留痕").count()
                n_trace = mpage.locator("[data-test='ceremony-trace']").count()
                n_hist = mpage.locator(".tbl tbody tr").count()
                dbg = f" 仪式留痕btn={n_btn} trace_n={n_trace} 台账行={n_hist}"
            except Exception:
                pass
            body_tail = ""
            try:
                body_tail = " | ".join(mpage.locator("body").inner_text().splitlines())[-400:]
            except Exception:
                pass
            beat(False, f"拍3 批准+仪式（{str(e)[:120]}）{dbg} tail={body_tail}")

        # 拍 4｜审计窗：查看实名并结案（浮层实名+仪式留痕+案卷指纹）
        try:
            apage.goto(WEB + "/#/audit")
            apage.wait_for_selector("button:has-text('查看实名并结案')", timeout=60000)
            apage.click("button:has-text('查看实名并结案')")
            apage.wait_for_selector("[role='radiogroup']", timeout=20000)
            apage.locator(".radio-opt", has_text="属实").click()
            apage.fill(
                "textarea[maxlength='500']", "链上检查点与登记设备一致，违规事实成立（彩排预填）"
            )
            apage.click("button:has-text('签名并结案')")
            apage.wait_for_selector("text=案卷指纹", timeout=60000)
            beat(True, "拍4 结案浮层（实名+仪式留痕+案卷指纹收口）")
        except Exception as e:
            beat(False, f"拍4 结案（{str(e)[:150]}）")

        # 拍 5｜管理员窗：处置待办→去吊销→两步式吊销
        try:
            mpage.goto(WEB + "/#/governance")  # 切页即重挂（待办刷新）——治理一瞥预演
            mpage.wait_for_timeout(800)
            mpage.goto(WEB + "/#/admin")
            mpage.wait_for_selector("button:has-text('去吊销')", timeout=60000)
            mpage.click("button:has-text('去吊销')")
            mpage.wait_for_selector("input[placeholder='用户名']", timeout=15000)
            v = mpage.locator("input[placeholder='用户名']").input_value()
            assert v == PILOT_USER, f"预填用户名 {v} != {PILOT_USER}"
            # 精确定位：#revoke-panel 内第一拍按钮——has-text 子串会命中待办
            # 标签隐藏的「去吊销」（v-show DOM 在场，nth=0 落错元素=彩排偏差⑥）
            mpage.locator("#revoke-panel button").filter(has_text="吊销").first.click()
            mpage.wait_for_selector("text=已取预览：签名将绑定纪元", timeout=20000)
            mpage.locator("#revoke-panel button:has-text('确认吊销（签名并推链）')").click()
            mpage.wait_for_selector("text=吊销回执", timeout=60000)
            beat(True, "拍5 处置待办→去吊销预填→两步式吊销（纪元权威预览+回执联动清单）")
        except Exception as e:
            deny5 = ""
            try:
                if mpage.locator(".deny").count():
                    deny5 = mpage.locator(".deny").first.inner_text().replace(chr(10), " ")[:250]
            except Exception:
                pass
            beat(False, f"拍5 处置吊销（{str(e)[:120]}）deny={deny5}")

        # 拍 6｜飞手窗：红条+申请前置拦截（出证后台态如实两分支）
        try:
            pilot_ready = wait_receipt(ppage, 1)  # 非阻塞探测当前态
            ppage.goto(WEB + "/#/record")
            ppage.wait_for_selector("[data-test='notice-revoked']", timeout=30000)
            ppage.goto(WEB + "/#/apply")
            ppage.wait_for_selector("[data-test='apply-revoked']", timeout=20000)
            state_txt = "就绪" if pilot_ready else "在途/被拦"
            beat(True, f"拍6 吊销红条+申请前置拦截（出证后台态={state_txt}——两分支话术均成立）")
        except Exception as e:
            beat(False, f"拍6 红条（{str(e)[:150]}）")

        # 拍 7｜跨域窗：org-b 管理员对 org-a 用户吊销预览 → 403 双域判词
        try:
            bpage.goto(WEB + "/#/admin")
            # 机构台默认待办标签——吊销表单在「吊销与恢复」标签（先切标签再操作
            # ——fill/wait 默认要求可见，v-show 隐藏元素不可交互）
            bpage.locator("[data-test='admin-tabs'] button:has-text('吊销与恢复')").click()
            bpage.wait_for_selector("input[placeholder='用户名']", timeout=30000)
            bpage.fill("input[placeholder='用户名']", PILOT_USER)
            bpage.locator("textarea").first.fill("跨域吊销企图（彩排负例）")
            bpage.locator("#revoke-panel button").filter(has_text="吊销").first.click()
            bpage.wait_for_selector("#revoke-panel .deny", timeout=45000)
            txt = bpage.locator("#revoke-panel .deny").inner_text()
            assert "跨域操作拒绝" in txt and "org-a" in txt and "org-b" in txt, txt[:200]
            beat(True, "拍7 跨域 403（org_forbidden 双域判词红盒——写面全域隔离）")
        except Exception as e:
            deny7 = ""
            try:
                if bpage.locator(".deny").count():
                    deny7 = bpage.locator(".deny").first.inner_text().replace(chr(10), " ")[:250]
            except Exception:
                pass
            beat(False, f"拍7 跨域 403（{str(e)[:120]}）deny={deny7}")

        # 拍 8｜管理员窗：机队台登记一台
        try:
            mpage.locator("[data-test='admin-tabs'] button:has-text('机队')").click()
            mpage.click("button:has-text('添加设备行')")
            dev_no = "FZ-REHEARS-" + "".join(secrets.choice("0123456789") for _ in range(7))
            assert len(dev_no) == 18
            mpage.fill("input[placeholder^='设备登记号']", dev_no)
            mpage.fill("input[placeholder^='设备序列号']", "FZ-SN-DEV-01")
            mpage.click("button:has-text('登记上链')")
            mpage.wait_for_selector("text=登记回执（原像盐一次性", timeout=60000)
            beat(True, f"拍8 机队台登记上链（kind=2 承诺+回执原像盐——{dev_no}）")
        except Exception as e:
            beat(False, f"拍8 机队台（{str(e)[:150]}）")

        # 拍 9｜治理收束
        try:
            mpage.goto(WEB + "/#/governance")
            mpage.wait_for_selector("text=链上治理", timeout=20000)
            mpage.wait_for_timeout(1500)
            has_fed = mpage.locator("text=互认机构（FedRegistry 名册）").count() >= 1
            assert has_fed, "互认面板未渲染"
            beat(True, "拍9 治理页收束（k-of-n+互认名册/聚合根公示）")
        except Exception as e:
            beat(False, f"拍9 治理收束（{str(e)[:150]}）")

        return finish(browser, errors, prep_done=True)


def finish(browser, errors: list[str], *, prep_done: bool) -> int:
    total = len(_results)
    passed = sum(1 for ok, _ in _results if ok)
    for ok, label in _results:
        if not ok:
            print(f"  ✗ 未过：{label}", flush=True)
    if errors:
        print(f"  ⚠ pageerror {len(errors)} 个：{errors[:3]}", flush=True)
    verdict = "全通" if passed == total and total > 0 and not errors else "存在未过拍"
    scope = "九拍" if prep_done else "含预埋"
    print(
        f"== 彩排判决行：{passed}/{total} 拍 [OK]（{scope}）——{verdict}；"
        f"pageerror={len(errors)} ==",
        flush=True,
    )
    browser.close()
    return 0 if verdict == "全通" else 1


if __name__ == "__main__":
    sys.exit(main())
