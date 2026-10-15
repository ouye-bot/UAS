"""FastAPI 应用工厂（三服务单体部署形态：ra 已挂载；authz/telemetry/audit 随批次挂载）。"""

from __future__ import annotations

from fastapi import FastAPI

from app.accounts.router import router as accounts_router
from app.audit.router import router as audit_router
from app.authz.router import router as authz_router
from app.ra.router import router as ra_router
from app.telemetry.router import router as telemetry_router


def create_app() -> FastAPI:
    # 批 2-2.3：production 档 KMS 演示钥退出默认——任一 FZ_*_SK 未注入即拒绝
    # 启动（人话列出缺项）。demo（环回）档直接通过，维持现状可跑。
    from app.kms import assert_no_demo_keys_in_production

    assert_no_demo_keys_in_production()

    # 批 4-2：production 档服务形态断言——链锚 fake 缺省/遥测 stub/DB 未配置
    # 三形态逐条人话拒启（demo 环回档零影响）。
    from app.deployment import assert_production_services

    assert_production_services()

    # 3.2 k-of-n 参数化：门限配置启动断言（任务书①——fail-fast 比照 production
    # 拒启工艺）：参数自洽（k≥2/n−k≥1/域形态）全档断言；production 档额外
    # 域集⊆治理席位集对拍（链不可达=拒启）。缺省 env=2-of-3 零变化。
    from app.ra.threshold_shares import assert_threshold_config

    _t_cfg = assert_threshold_config()
    print(
        f"[FZ-STARTUP] threshold k-of-n: k={_t_cfg['k']} n={len(_t_cfg['domains'])} "
        f"domains={','.join(_t_cfg['domains'])}",
        flush=True,
    )

    app = FastAPI(title="feizheng-backend", version="0.1.0")
    # P1-B1 可观测性：JSON 日志+request_id 贯穿+零依赖指标
    import logging
    import time

    from fastapi import Request

    from app.obs import inc, new_request_id, render_metrics, setup_json_logging

    setup_json_logging()

    # R3-0.5（评审 P0-2）：engine 转发面令牌未配置=检查点/事件上链全 401——
    # fail-closed 但必须让人看见（产品路径断裂三天的教训：单测自带头全绿）。
    import os as _os

    if _os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "real" and not _os.environ.get(
        "FZ_ENGINE_TOKEN"
    ):
        print(
            "[FZ-STARTUP][WARN] FZ_CHAIN_ANCHOR=real 但未配置 FZ_ENGINE_TOKEN——"
            "/engine/* 转发面（检查点/事件上链）将全部 401；"
            "请由启动器同源注入（demo_up/S1/sitl_e2e_services 已内置）",
            flush=True,
        )

    # 真链档链上交易钥派生回落 fail-visible（2026-10-15 安全凭据批）：四枚
    # 链上治理/审计/签发交易钥任一未 env 注入即回落 SM3(公开常量) 派生
    # （kms FZ-CHAIN-SMOKE|* 域，kms/__init__.py:101,117,161,173）——读过
    # repo 者可自推私钥直发链上交易，冒充 governor owner/审计方。production
    # 档已由 assert_no_demo_keys_in_production 拒启；真链演示档（环回）保留
    # SMOKE 自洽部署动线（部署钥=运行钥，链写不 revert）故不拒启，但弱钥面
    # 必须让人看见——与 ENGINE_TOKEN 同款 fail-visible 纪律。
    if _os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "real":
        _chain_key_faces = (
            ("FZ_CHAIN_RA_TX_SK", "RA 链上交易（凭证上链/撤销公示）"),
            ("FZ_CHAIN_ENGINE_TX_SK", "engine 链上交易（recordAuth/锚定/事件）"),
            ("FZ_CHAIN_AUDITOR_TX_SK", "审计方链上交易（logWarrant）"),
            ("FZ_CHAIN_ADMIN_TX_SK", "治理 admin 链上交易（governor owner）"),
        )

        def _chain_injected(name: str) -> bool:
            if _os.environ.get(name):
                return True
            # admin 旧名兼容（与 kms/__init__.py 取钥顺序同判）
            return name == "FZ_CHAIN_ADMIN_TX_SK" and bool(_os.environ.get("FZ_CHAIN_ADMIN_SK"))

        _chain_missing = [
            f"{name}（{desc}）" for name, desc in _chain_key_faces if not _chain_injected(name)
        ]
        if _chain_missing:
            print(
                "[FZ-STARTUP][WARN] FZ_CHAIN_ANCHOR=real 但 "
                f"{len(_chain_missing)} 枚链上交易钥未注入（"
                + "；".join(_chain_missing)
                + "）——将回落 SM3(公开常量) 派生钥（FZ-CHAIN-SMOKE 域，读过 "
                "repo 者可自推私钥直发链上交易冒充治理/审计方）。仅限本机环回"
                "演示可接受；评审/生产部署请在 .local_env 注入 CSPRNG 链钥"
                "（scripts/rotate_kms_keys.py 可生成）",
                flush=True,
            )

    # 未处理异常统一转结构化 JSON（2026-09-28 审计台实测：裸 500 非 JSON 响应
    # 让前端只能显示"bad_response: 500"——排障盲飞）。人话+request_id 可追踪；
    # 瞬态类（SQLite 锁/链抖）给出重试指引。
    from fastapi.responses import JSONResponse as _JSONResponse

    @app.exception_handler(Exception)
    async def unhandled_to_json(request: Request, exc: Exception):
        rid = getattr(request.state, "fz_rid", None) or new_request_id(
            request.headers.get("X-Request-ID")
        )
        logging.getLogger("fz.http").error(
            f"unhandled {type(exc).__name__}: {exc} rid={rid} path={request.url.path}"
        )
        msg = str(exc)
        if "database is locked" in msg or "locked" in msg.lower():
            hint = "服务繁忙（数据库短暂锁定）——请稍候重试"
        elif "chain" in msg.lower() or "rpc" in msg.lower():
            hint = "链节点暂不可达——请确认链在线后重试"
        else:
            hint = "服务内部错误——请重试；若复现请携带本提示中的追踪号反馈"
        return _JSONResponse(
            status_code=500,
            content={"code": "internal_error", "message": f"{hint}（追踪号 {rid}）"},
        )

    @app.middleware("http")
    async def obs_middleware(request: Request, call_next):
        rid = new_request_id(request.headers.get("X-Request-ID"))  # 跨程透传（桥/worker 带入）
        request.state.fz_rid = rid  # 异常处理器可引用同一追踪号
        t0 = time.perf_counter()
        response = await call_next(request)
        dur = time.perf_counter() - t0
        path = request.url.path
        # 指标路径模板归一（B-P3-10）：动态段（hex 码/数字 id）折叠 {id}——
        # 标签基数有界（日志行保留原始 path，可观测性不受影响）
        import re as _re

        tpl = _re.sub(r"[0-9a-fA-F]{16,}", "{id}", path)
        tpl = _re.sub(r"/\d+([/.]|$)", r"/{id}\1", tpl)
        inc("fz_requests_total", {"path": tpl, "code": str(response.status_code)})
        response.headers["X-Request-ID"] = rid
        logging.getLogger("fz.http").info(
            f"{request.method} {path} -> {response.status_code} {dur * 1000:.1f}ms rid={rid}"
        )
        return response

    @app.get("/metrics")
    def metrics():
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(content=render_metrics(), media_type="text/plain; version=0.0.4")

    # B8：飞手 Web（vite dev 5173/构建态任意源本地页）跨域白名单——仅 GET/POST。
    # 账户批（2026-09-29）：会话 Cookie 面（/auth、审计/机构端点）需凭据——
    # allow_credentials 开启；2026-09-30 评审清理：旧令牌头自 allow_headers 移除。
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],  # X-Audit-Token 已随账户批退役（2026-09-30 评审清理）
        allow_credentials=True,
    )
    from app.accounts.admin_router import router as admin_router

    app.include_router(accounts_router)
    app.include_router(admin_router)
    app.include_router(ra_router)
    app.include_router(authz_router)
    app.include_router(audit_router)
    app.include_router(telemetry_router)
    # P1-C3：真链档事件索引守护线程（增量回填 chain_events——追溯时间线数据源）
    import os as _os

    if _os.environ.get("FZ_CHAIN_ANCHOR", "fake") != "fake":
        from app.telemetry.indexer import start_background_indexer

        start_background_indexer()
        # 1.3 件②：份额域↔治理席位同步 watcher（漂移→大屏红牌+自动起草
        # reshare 提案——confirm/execute 保持人工，防事件注入 DoS）
        from app.ra.threshold_sync import start_background_watcher

        start_background_watcher()
    from app.chain.panel import router as chain_panel_router

    app.include_router(chain_panel_router)

    # 双控执行启动恢复（2026-09-30 评审 P1-6）：重启杀后台线程 → approved 残留
    # 如实转 execute_failed（僵尸"执行中"卡根修）。表未建（全新库先于迁移）
    # 不阻塞启动——诚实告警。
    import logging as _log

    try:
        from app.accounts.collab import recover_interrupted

        _n = recover_interrupted()
        if _n:
            print(
                f"[FZ-STARTUP] 双控执行恢复：{_n} 条 approved 残留已转 execute_failed（可重试）",
                flush=True,
            )
    except Exception as _e:  # noqa: BLE001
        _log.getLogger("fz.startup").warning(f"双控启动恢复跳过（{_e}）")

    # 过期 Web 会话回收（2026-10-04 worker 扩展前置批）：web_sessions 只进不清
    # =慢性膨胀——启动即清一次（失败不阻断启动——回收面非关键路径）。
    try:
        from app.accounts.service import purge_expired_sessions
        from app.db import SessionLocal as _SessionLocal

        _s = _SessionLocal()
        try:
            _n2 = purge_expired_sessions(_s)
            if _n2:
                print(f"[FZ-STARTUP] 过期 Web 会话回收：{_n2} 行", flush=True)
        finally:
            _s.close()
    except Exception as _e:  # noqa: BLE001
        _log.getLogger("fz.startup").warning(f"过期会话回收跳过（{_e}）")

    # 存量 v3 信封启动扫查（拍板③③）：production 判定档下清点 v3 信封账户，
    # >0 打印显式告警（数量+账户名掩码+处置指引）。不拒启——账户级问题不
    # 阻断服务；库不可达同样只告警（诚实可见）。demo 档零影响（函数内判定）。
    try:
        from app.accounts.service import v3_envelope_stock_report
        from app.db import SessionLocal as _SessionLocal

        _s3 = _SessionLocal()
        try:
            _v3rep = v3_envelope_stock_report(_s3)
            if _v3rep:
                print(_v3rep, flush=True)
        finally:
            _s3.close()
    except Exception as _e:  # noqa: BLE001
        _log.getLogger("fz.startup").warning(f"存量 v3 信封扫查跳过（{_e}）")

    # 存量 v4 信封启动扫查（⑫O-4，设计 §5.2——v3 同构）：production 档清点 v4
    # 信封账户，>0 打印显式告警（处置=登录会话内 /auth/opaque/migrate 惰性迁移
    # 或 FZ_OPAQUE_CUTOFF_TS 截止+机构重置）。不拒启；demo 档零影响。
    try:
        from app.accounts.service import v4_envelope_stock_report
        from app.db import SessionLocal as _SessionLocal4

        _s4 = _SessionLocal4()
        try:
            _v4rep = v4_envelope_stock_report(_s4)
            if _v4rep:
                print(_v4rep, flush=True)
        finally:
            _s4.close()
    except Exception as _e:  # noqa: BLE001
        _log.getLogger("fz.startup").warning(f"存量 v4 信封扫查跳过（{_e}）")

    # 撤销纪元根启动守卫（2026-10-01 批）：真链档启动即自检——链上公示根 vs
    # 本地撤销镜像根，漂移即幂等对齐（复用 align_rev_root 推链核心，epoch+1
    # 单调，本地镜像为权威）；链不可达打 WARNING 不阻塞启动（受理面
    # stale_rev_root 409 仍是兜底）。fake 锚模式不启用（无链面可对）。
    if _os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "real":
        try:
            from app.ra.align import startup_align_guard

            startup_align_guard()
        except Exception as _e:  # noqa: BLE001
            _log.getLogger("fz.startup").warning(
                f"撤销纪元根启动自检失败（不阻塞启动——受理面 stale_rev_root 兜底）: {_e}"
            )

    # （审计台静态单屏已退役——2026-09-29 账户批：审计台由 gcs/web Vue
    # AuditView 承担，X-Audit-Token 粘贴模式随令牌认证一并根除。）

    # 验证工具分发站（2026-09-28 分发批）：页面（git 内）+构建产物（backend/dist，
    # 根 .gitignore 覆盖——二进制不进仓）。dist 挂载在前（前缀更长者先匹配）；
    # check_dir=False——产物未生成时分发页仍可访问（页面如实标「未生成」）。
    from pathlib import Path

    from fastapi.staticfiles import StaticFiles

    class _NoCacheStaticFiles(StaticFiles):
        def file_response(self, *args, **kwargs):  # noqa: ANN002, ANN003
            resp = super().file_response(*args, **kwargs)
            resp.headers["Cache-Control"] = "no-cache"
            return resp

    from app.verify_dist import router as verify_dist_router

    app.include_router(verify_dist_router)
    app.mount(
        "/verify/dist",
        StaticFiles(directory=str(Path(__file__).parents[1] / "dist"), check_dir=False),
        name="verify-dist",
    )
    app.mount(
        "/verify",
        _NoCacheStaticFiles(
            directory=str(Path(__file__).parent / "verify_static"), html=True, check_dir=True
        ),
        name="verify-page",
    )

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "service": "feizheng-backend"}

    return app
