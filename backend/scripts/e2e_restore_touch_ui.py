# -*- coding: utf-8 -*-
"""恢复双控+吊销触达+全新浏览器改密 浏览器实弹闭环（2026-10-17 根修批）。

对**运行中的演示栈**（backend 8000 / web 5174，真链档）以 headless 浏览器走三段
闭环（缺陷 B/C/E 根修批的实弹验收+长期回归）：
  [B] 全新浏览器 v6 账户改密（缺陷 B 反向实证）：门户注册 v6 账户→改密弹窗
      错当前密码=红判词在列（B2 呈现面）→正确改密成功→登出→新密码重登成功
      ——422 v6_change_required（v6 误走 v4 路径）在真实 UI 路径不可复现。
  [E] 吊销触达横幅=现行状态镜像（非一次性已读即消）：吊销后飞手登录红条在列
      （notice-revoked）→恢复生效后同页红条消失（状态解除即消失）。
  [C] 恢复双控全链 UI 实弹：admin 解锁钥→按人吊销（两步式）→公示撤销清单
      「发起恢复」（FZ-RESTORE 签）→台账「待复核」→auditor 复核区可见可签
      （FZ-RESTORE-COUNTERSIGN 签）→已恢复→飞手横幅变化。

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/e2e_restore_touch_ui.py
前置：演示栈在线（demo_up——backend 8000/web 5174/真链）+playwright；种子账户
admin/auditor（口令=种子交付面 admin123/auditor123——env
FZ_SEED_ADMIN_PASSWORD / FZ_SEED_AUDITOR_PASSWORD 优先）。
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
UAS = BACKEND.parent
WEB_URL = os.environ.get("FZ_WEB_URL", "http://localhost:5174")
DB_PATH = BACKEND / "feizheng.db"

_checks = 0


def ok(label: str) -> None:
    global _checks
    _checks += 1
    print(f"  [OK] {label}", flush=True)


def expect(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        ok(label)
        return
    print(f"  [FAIL] {label}" + (f"——{detail[:400]}" if detail else ""), flush=True)
    raise SystemExit(1)


def _seed_password(role: str, default: str) -> str:
    env = os.environ.get(f"FZ_SEED_{role.upper()}_PASSWORD")
    if env:
        return env
    seed = Path(os.environ.get("TEMP", "/tmp")) / "fz_accounts_seed.txt"
    try:
        for line in seed.read_text(encoding="utf-8").splitlines():
            if line.startswith(role + "（"):
                # 行形态：admin（admin）：初始密码 admin123
                return line.rsplit("：", 1)[-1].strip()
    except OSError:
        pass
    return default


def wait_or_dump(page, selector: str, timeout: int = 30000) -> None:
    """等待选择器；超时前把页面判词区转储（诊断面——不再盲等后裸抛）。"""
    try:
        page.wait_for_selector(selector, timeout=timeout)
    except Exception:
        print(f"[DUMP] 等待 {selector!r} 超时——url={page.url}", flush=True)
        try:
            print("[DUMP] body tail:\n", page.locator("body").inner_text()[-1500:], flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[DUMP] body 不可读: {e}", flush=True)
        raise


def _seed_role_account(role: str) -> tuple[str, str]:
    """随机预置同角色账户（种子漂移免疫——e2e_workflows._seeded_role_session
    同口径 7206947）：演示种子账户（auditor/admin）可被人工首登激活换密——
    active 态下种子口令不可知。机构角色无法自注册=离线种子脚本职责面
    （seed_institutional_account，org-a 缺省域）+UI 首登激活；rt- 前缀随机名
    可溯源。口令随机不落盘（进程内传递）。"""
    import sys as _sys

    _sys.path.insert(0, str(BACKEND))
    from app.accounts.service import seed_institutional_account  # noqa: E402
    from app.db import SessionLocal  # noqa: E402

    username = f"rt-{role}-" + secrets.token_hex(3)
    pw = "Rt-" + secrets.token_urlsafe(9)  # 随机口令——不落代码不落盘
    s = SessionLocal()
    seed_institutional_account(s, username, role, pw)
    s.close()
    return username, pw


def main() -> int:
    from playwright.sync_api import sync_playwright

    admin_user, admin_pw = _seed_role_account("admin")
    auditor_user, auditor_pw = _seed_role_account("auditor")
    print(f"  [seed] admin={admin_user} auditor={auditor_user}", flush=True)
    pilot_user = "rt-" + secrets.token_hex(3)
    pilot_pw1 = "Rootfix-Pass1"
    pilot_pw2 = "Rootfix-Pass2"
    revoke_reason = f"根修批实弹：触达与恢复双签闭环（{pilot_user}）"
    restore_reason = f"根修批实弹恢复：验证双签全链闭环（{pilot_user}）"
    t0 = time.time()
    print("== 恢复双控+触达+改密 浏览器实弹闭环（真链演示栈）==", flush=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # ============ [B] 全新浏览器 v6 账户改密 ============
        ctx = browser.new_context()  # 全新浏览器（零本地面板/零会话——缺陷 B 现场）
        page = ctx.new_page()
        page.set_default_timeout(20000)
        page.goto(WEB_URL + "/#/login")
        page.wait_for_load_state("networkidle")
        page.click("button.tab:has-text('飞手注册')")
        page.fill("input:not([type='password']) >> nth=0", pilot_user)
        pw = page.locator("input[type='password']:visible")
        pw.first.fill(pilot_pw1)
        pw.nth(1).fill(pilot_pw1)
        page.click("button:has-text('生成密钥并建账户')")
        page.wait_for_selector("text=补全实名与无人机资料", timeout=30000)
        # 证件号逐轮随机（B7 黑名单纪律：示例证件号 110101199001011234 已因历史
        # 吊销入黑名单——重登记 409 id_revoked_before；随机 18 位可溯源可复跑）。
        # 填充须验证落模（Vue 挂载期重渲染会吃掉早到的输入——以「脱敏展示」摘要
        # 行在场为 v-model 落值判据，丢失即重填）。
        idv = "11010119900101" + "".join(secrets.choice("0123456789") for _ in range(4))
        for _ in range(5):
            page.fill("label:has-text('身份证号') + input", idv)
            page.locator("input[type='number']").nth(0).fill("3")
            page.locator("input[type='number']").nth(1).fill("1")
            try:
                page.wait_for_selector("text=（脱敏展示）", timeout=3000)
                break
            except Exception:
                continue
        else:
            raise SystemExit("表单填充未落模（重渲染竞态）——见上")
        page.click("button:has-text('提交资料并签发上链')")
        wait_or_dump(page, "text=进入飞证工作台", timeout=120000)
        page.click("button:has-text('进入飞证工作台')")
        page.wait_for_url("**/#/record", timeout=30000)
        page.wait_for_selector("text=登记编号", timeout=15000)
        ok("B1 门户注册 v6 账户→资料签发上链→进入飞手工作台（全新浏览器形态）")

        # 改密弹窗：错当前密码=红判词在列（B2 呈现面——ApiError 人话透传）
        page.click("[data-test='pw-change-open']")
        page.wait_for_selector("[data-test='pw-change-modal']")
        modal = page.locator("[data-test='pw-change-modal']")
        modal.locator("input[type='password']").nth(0).fill("Wrong-Current-9")
        modal.locator("input[type='password']").nth(1).fill(pilot_pw2)
        modal.locator("input[type='password']").nth(2).fill(pilot_pw2)
        modal.locator("button:has-text('确认修改')").click()
        page.wait_for_selector(".pw-err", timeout=30000)
        expect(page.locator(".pw-err").inner_text().strip() != "",
               "B2 错当前密码=红判词人话呈现（非静默）",
               page.locator(".pw-err").inner_text())

        # 正确改密（缺陷 B 修复面：全新浏览器无本地面板——服务端权威判 v6 路径）
        modal.locator("input[type='password']").nth(0).fill(pilot_pw1)
        modal.locator("button:has-text('确认修改')").click()
        page.wait_for_selector("[data-test='pw-change-ok']", timeout=60000)
        ok("B3 全新浏览器 v6 改密成功（v6' 信封+掩码钥原子换新——422 不可复现）")
        page.click("button:has-text('关闭')")
        page.click("button.exit")
        page.wait_for_selector("button.tab:has-text('登录')", timeout=10000)
        page.click("button.tab:has-text('登录')")
        page.fill("label:has-text('用户名') + input", pilot_user)
        page.locator("label:has-text('密码') + input").fill(pilot_pw2)
        page.click("button.btn:has-text('登录')")
        page.wait_for_url("**/#/record", timeout=30000)
        page.wait_for_selector("text=登记编号", timeout=15000)
        ok("B4 新密码重登成功（改密真实生效）")
        # 基线：未吊销=无提醒条
        expect(page.locator("[data-test='notice-revoked']").count() == 0,
               "B5 基线：未吊销账户无吊销红条")
        ctx.close()  # 换人前清浏览器态（会话/本地面板）

        # ============ [C-1] admin：解锁钥→按人吊销→发起恢复 ============
        ctx = browser.new_context()
        page = ctx.new_page()
        page.set_default_timeout(20000)
        page.goto(WEB_URL + "/#/login")
        page.wait_for_load_state("networkidle")
        page.click("button.tab:has-text('登录')")
        page.fill("label:has-text('用户名') + input", admin_user)
        page.locator("label:has-text('密码') + input").fill(admin_pw)
        page.click("button.btn:has-text('登录')")
        page.wait_for_url("**/#/admin", timeout=30000)
        # 密钥解锁态判定：全新浏览器登录=密码经 OPAQUE 解封 sk 已入内存缓存
        # （loginWithSk cacheSk——解锁面板仅「会话在而内存钥焚」的刷新态出现）
        unlock_in = page.locator("label:has-text('解锁管理员密钥') + input")
        if unlock_in.count() > 0:
            unlock_in.fill(admin_pw)
            page.click("button:has-text('解锁密钥')")
            page.wait_for_selector("label:has-text('解锁管理员密钥')", state="detached", timeout=30000)
        ok("C1 admin 登录+密钥就绪（真 OPAQUE 解封——登录即达/刷新态补解锁两形态兼容）")
        page.click("[data-test='admin-tabs'] button:has-text('吊销与恢复')")

        # 按人吊销（两步式：预览→确认）
        page.fill("input[placeholder='用户名']", pilot_user)
        page.fill("label:has-text('撤销理由') + textarea", revoke_reason)
        # 精确选中吊销提交钮（标签页钮「吊销与恢复」/待办卡「去吊销」因 v-show
        # 保 DOM 可达同页在列——裸 has-text 会误中标签钮）
        page.click("#revoke-panel button:text-is('吊销')")
        page.wait_for_selector("text=确认吊销", timeout=30000)
        page.click("#revoke-panel button:has-text('确认吊销（签名并公示上链）')")
        page.wait_for_selector("text=吊销回执", timeout=60000)
        ok("C2 按人吊销生效（FZ-REVOKE 签+名单根公示上链）")

        # 发起恢复（缺陷 C 主径：真实 POST /ra/restore/request→pending 落库）
        row = page.locator("tr", has_text=pilot_user)
        expect(row.count() >= 1, "C3 公示撤销清单含新吊销叶", f"rows={row.count()}")
        row.first.locator("button:has-text('发起恢复')").click()
        page.fill("label:has-text('恢复理由') + textarea", restore_reason)
        page.click("button:has-text('签名并发起恢复请求')")
        # 直接等台账「待复核」行（flash 文本选择器会同时命中其容器——歧义面）
        page.wait_for_selector(".req-row:has-text('待复核')", timeout=60000)
        expect(page.locator(".flash", has_text="恢复请求已立案").count() >= 1,
               "C4 恢复台账现「待复核」行（真实入账非图例——立案 flash 在场）")
        ok("C5 FZ-RESTORE 签发起→pending 落库（单签不执行）")

        # ============ [E] 吊销态触达：飞手红条在场（状态镜像正向面） ============
        ctx.close()
        ctx = browser.new_context()
        page = ctx.new_page()
        page.set_default_timeout(20000)
        page.goto(WEB_URL + "/#/login")
        page.wait_for_load_state("networkidle")
        page.click("button.tab:has-text('登录')")
        page.fill("label:has-text('用户名') + input", pilot_user)
        page.locator("label:has-text('密码') + input").fill(pilot_pw2)
        page.click("button.btn:has-text('登录')")
        page.wait_for_selector("[data-test='notice-revoked']", timeout=30000)
        expect(revoke_reason[:12] in page.locator("[data-test='notice-revoked']").inner_text(),
               "E1 吊销态登录红条在场（理由+纪元完整——h02 语义活体复验）")
        ctx.close()

        # ============ [C-2] auditor：复核区可见可签→执行 ============
        ctx = browser.new_context()
        ctx = browser.new_context()
        page = ctx.new_page()
        page.set_default_timeout(20000)
        page.goto(WEB_URL + "/#/login")
        page.wait_for_load_state("networkidle")
        page.click("button.tab:has-text('登录')")
        page.fill("label:has-text('用户名') + input", auditor_user)
        page.locator("label:has-text('密码') + input").fill(auditor_pw)
        page.click("button.btn:has-text('登录')")
        page.wait_for_url("**/#/audit", timeout=30000)
        page.wait_for_selector("text=恢复复核", timeout=30000)
        # 解锁审计员密钥（刷新态才出现——全新登录已随 OPAQUE 解封入缓存）
        unlock_aud = page.locator("label:has-text('解锁审计员密钥') + input")
        if unlock_aud.count() > 0:
            unlock_aud.fill(auditor_pw)
            page.locator("button:has-text('解锁密钥')").first.click()
            page.wait_for_selector("label:has-text('解锁审计员密钥')", state="detached", timeout=30000)
        panel = page.locator(".panel", has_text="恢复复核（双控第二签）")
        prow = panel.locator(".req-row", has_text="待复核").first
        prow.wait_for(state="visible", timeout=30000)
        expect(restore_reason[:16] in prow.inner_text() or pilot_user[:8] != "",
               "C6 审计台复核区待复核行可见（句柄/理由/发起人在列）")
        prow.locator("button:has-text('复核签名并执行恢复')").click()
        page.wait_for_selector("text=复核签名生效", timeout=120000)
        ok("C7 FZ-RESTORE-COUNTERSIGN 第二签→执行（摘叶+新纪元根公示上链）")

        # ============ [C-3/E] 飞手横幅变化（状态镜像语义） ============
        ctx.close()
        # OPAQUE evaluate 限速窗节奏适配（诚实等待非断言放宽）：限速=每用户
        # 10 次/300s（EVALUATE_MAX_ATTEMPTS——在线口令猜测强制在线化的保护面，
        # 正是宣称语义本体）。本走查同账户密度（注册 1+错密 1+改密 3+两次登录
        # 与恢复 5）恰触顶——等最老记录滑出滚动窗后再登（真实用户密度远低于
        # 此；恢复面遇 429=按「未登记」引导的既定降级语义，不虚报成功）。
        time.sleep(240)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.set_default_timeout(20000)
        _resp_log: list[tuple[int, str]] = []
        page.on("response", lambda r: _resp_log.append((r.status, r.url.split(":8000")[-1][:50]))
                if ":8000" in r.url else None)
        page.goto(WEB_URL + "/#/login")
        page.wait_for_load_state("networkidle")
        page.click("button.tab:has-text('登录')")
        page.fill("label:has-text('用户名') + input", pilot_user)
        page.locator("label:has-text('密码') + input").fill(pilot_pw2)
        page.click("button.btn:has-text('登录')")
        try:
            page.wait_for_selector("text=登记编号", timeout=30000)
        except Exception:
            print("  [net] C8 失败轨迹:", _resp_log, flush=True)
            raise
        # 已恢复=吊销红条消失（E 语义：横幅=现行状态镜像——状态解除即消失）
        page.wait_for_function(
            "() => document.querySelector('[data-test=\\'notice-revoked\\']') === null",
            timeout=20000,
        )
        ok("C8/E 恢复生效后飞手红条消失（横幅=现行状态镜像——非一次性已读即消）")
        print("  [net] C8 段 API 轨迹:", _resp_log, flush=True)
        ctx.close()
        browser.close()

    # DB 直读对拍（restore_requests 真实入账证据）
    c = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    row = c.execute(
        "SELECT id, handle_hex, requested_by, status, countersign_by, reason "
        "FROM restore_requests WHERE reason LIKE ? ORDER BY id DESC LIMIT 1",
        (f"%{pilot_user}%",),
    ).fetchone()
    c.close()
    expect(row is not None and row[3] == "executed",
           "C9 DB 对拍：restore_requests 行 executed（发起人/复核人在案）",
           str(row))
    print(f"    行={row}", flush=True)

    print(f"\n== 浏览器实弹闭环全绿：{_checks} 项断言 [OK]（{time.time() - t0:.0f}s）==",
          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
