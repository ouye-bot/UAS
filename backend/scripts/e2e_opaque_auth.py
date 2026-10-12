"""⑫O-6 e2e 登录全动线（OPAQUE v6——API 级实弹，零替身）。

动线：v6 注册 → 种子激活（auditor 口径）→ OPAQUE 登录 200 → 错口令连发
→ 429 恰第 11 发+台账 → v4 存量惰性迁移（migrate→keystore 410→OPAQUE 登录）
→ 改密联动（v6'+新掩码钥原子换新→旧口令败/新口令过）→ CUTOFF 403。

自包含夹具：临时 SQLite backend :8033（fake 链档）——零演示库零真链副作用。
用法：cd backend && .venv/Scripts/python.exe scripts/e2e_opaque_auth.py
"""

from __future__ import annotations

import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

API_PORT = 8033
API = f"http://127.0.0.1:{API_PORT}"

_checks = 0


def ok(label: str) -> None:
    global _checks
    _checks += 1
    print(f"  [OK] {label}")


def expect(cond: bool, label: str, detail: str = "") -> None:
    if not cond:
        print(f"  [FAIL] {label} {detail}")
        raise SystemExit(1)
    ok(label)


def _req(method: str, path: str, body: dict | None = None, cookies: dict | None = None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(API + path, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (cookies or {}).items():
        req.add_header("Cookie", f"{k}={v}")
    data = None
    if body is not None:
        import json

        data = json.dumps(body).encode()
    try:
        with opener.open(req, data=data, timeout=30) as r:
            return r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")


def _j(body: str) -> dict:
    import json

    return json.loads(body)


def main() -> int:
    import tempfile

    import uvicorn

    # env 先于 app.* 导入（app.db 读 FZ_DB_URL 于导入期——顺序颠倒会打到开发库）
    tmp = Path(tempfile.mkdtemp(prefix="fz_e2e_opaque_"))
    db = tmp / "e2e.db"
    os.environ["FZ_DB_URL"] = f"sqlite:///{db.as_posix()}"
    os.environ["FZ_ZK_CASES_DIR"] = str(tmp / "cases")
    (tmp / "cases").mkdir(exist_ok=True)

    # 建表+种子（审计员/管理员首登激活态——口径=固定演示口令 auditor123/admin123）
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.accounts.models  # noqa: F401
    from app.accounts.service import seed_institutional_account
    from app.main import create_app
    from app.ra.models import Base

    eng = create_engine(f"sqlite:///{db.as_posix()}")
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    seed_institutional_account(s, "auditor", "auditor", "auditor123")
    seed_institutional_account(s, "admin", "admin", "admin123")
    s.close()

    app = create_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=API_PORT, log_level="warning")
    server = uvicorn.Server(config)
    th = __import__("threading").Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.time() + 20
    while time.time() < deadline and not server.started:
        time.sleep(0.05)
    expect(server.started, "0. 夹具后端启动（:8033 临时库 fake 链档）")

    # ---- 客户端链（app.accounts.client——与浏览器 JS 双端对拍同源） ----
    from app.accounts.client import (
        client_finish_login,
        client_login_blind,
        client_seal_v6,
    )
    from app.accounts.kdf import derive_activation_verifier
    from app.crypto.sm2 import generate_keypair, sign

    def _evaluate(username: str, password: str, cookies: dict | None = None) -> dict:
        alpha, r_scalar = client_login_blind(username, password)
        st, _h, body = _req(
            "POST",
            "/auth/opaque/evaluate",
            {"username": username, "alpha_hex": alpha},
            cookies=cookies,
        )
        expect(st == 200, f"evaluate 200（{username}）", body)
        return r_scalar, _j(body)["data"]

    def _finish(r_scalar: int, response: dict) -> str:
        return client_finish_login(r_scalar, response)

    def _challenge_login(username: str, sk: str):
        st, _h, body = _req("POST", f"/auth/challenge/{username}")
        expect(st == 200, f"挑战 200（{username}）", body)
        nonce = _j(body)["data"]["nonce_hex"]
        st, _h, body = _req(
            "POST",
            "/auth/login",
            {
                "username": username,
                "nonce_hex": nonce,
                "sig_hex": sign(sk, f"FZ-AUTH-LOGIN|{nonce}".encode()),
            },
        )
        return st, body

    _session_cookies: dict = {}

    def _challenge_login_capture(username: str, sk: str):
        """挑战-应答登录并捕获 fz_session Cookie（属主面用——client.cookies）。"""
        st, _h, body = _req("POST", f"/auth/challenge/{username}")
        expect(st == 200, f"挑战 200（{username}）", body)
        nonce = _j(body)["data"]["nonce_hex"]
        st, headers, body = _req(
            "POST",
            "/auth/login",
            {
                "username": username,
                "nonce_hex": nonce,
                "sig_hex": sign(sk, f"FZ-AUTH-LOGIN|{nonce}".encode()),
            },
        )
        setc = headers.get("Set-Cookie", "")
        if "fz_session=" in setc:
            _session_cookies["fz_session"] = setc.split("fz_session=")[1].split(";")[0]
        return st, body

    # ---- ① v6 注册（OPAQUE 材料——fake 态同构真 β §6.1） ----
    sk, pk = generate_keypair()
    mats = client_seal_v6("pilot_e2e", "E2e-Pw-9abc", sk, pk)
    st, _h, body = _req(
        "POST",
        "/auth/register",
        {
            "username": "pilot_e2e",
            "pubkey_hex": pk,
            "sealed_blob": mats["sealed_blob"],
            "masking_key_hex": mats["masking_key_hex"],
            "kdf_salt_hex": mats["kdf_salt_hex"],
            "kdf_iter": mats["kdf_iter"],
        },
    )
    expect(st == 201, "① v6 注册 201（OPRF 记录材料随建）", body)

    # ---- ② 种子激活（auditor——核对子+v6 材料） ----
    st, _h, body = _req("GET", "/auth/prelogin/auditor")
    pre = _j(body)["data"]
    expect(pre["mode"] == "activation", "② prelogin=activation（种子口径）")
    verifier = derive_activation_verifier("auditor123", pre["kdf_salt_hex"], pre["rounds"])
    sk_a, pk_a = generate_keypair()
    mats_a = client_seal_v6("auditor", "auditor123", sk_a, pk_a)
    st, _h, body = _req(
        "POST",
        "/auth/activate",
        {
            "username": "auditor",
            "verifier_hex": verifier,
            "pubkey_hex": pk_a,
            "sealed_blob": mats_a["sealed_blob"],
            "masking_key_hex": mats_a["masking_key_hex"],
            "kdf_salt_hex": mats_a["kdf_salt_hex"],
            "kdf_iter": mats_a["kdf_iter"],
        },
    )
    expect(st == 200, "② 种子激活 200（v6 材料落账）", body)
    st, _h, body = _req("GET", "/auth/prelogin/auditor")
    expect(_j(body)["data"]["mode"] == "challenge", "② 激活后=challenge 稳态")

    # ---- ③ OPAQUE 登录 200（两消息+挑战-应答） ----
    r_scalar, resp = _evaluate("pilot_e2e", "E2e-Pw-9abc")
    sk_un = _finish(r_scalar, resp)
    expect(sk_un == sk, "③ 解封 sk=注册 sk（OPRF 链一致性）")
    st, body = _challenge_login("pilot_e2e", sk)
    expect(st == 200, "③ 登录 200（OPAQUE+挑战-应答）", body)
    ok("③ 登录全动线实弹（注册→登录）")

    # ---- ④ 种子 auditor OPAQUE 登录（auditor123 固定演示口令） ----
    rs_a, resp_a = _evaluate("auditor", "auditor123")
    sk_a2 = _finish(rs_a, resp_a)
    expect(sk_a2 == sk_a, "④ auditor 解封一致")
    st, body = _challenge_login("auditor", sk_a)
    expect(st == 200, "④ auditor 登录 200", body)
    ok("④ 种子 auditor123 全动线实弹")

    # ---- ⑤ 错口令连发 → 429 恰第 11 发（evaluate 限速+审计） ----
    # 清桶（①~④ 动线已消耗部分预算——本段从零计保证 429 恰第 11 发判据）
    from sqlalchemy import delete as _del

    from app.accounts.models import RateLimitBucket

    s_rl = sessionmaker(bind=eng)()
    s_rl.execute(_del(RateLimitBucket))
    s_rl.commit()
    s_rl.close()
    codes = []
    for i in range(11):
        alpha, _r = client_login_blind("pilot_e2e", f"Wrong-Pw-{i:02d}")
        st, _h, body = _req(
            "POST",
            "/auth/opaque/evaluate",
            {"username": "pilot_e2e", "alpha_hex": alpha},
        )
        codes.append(st)
    expect(codes[:10] == [200] * 10, "⑤ 错口令前 10 发=200（服务端零口令知识——无失败差异）")
    expect(codes[10] == 429, "⑤ 第 11 发=429（evaluate 限速——Cheon 纪律）", str(codes))

    # ---- ⑥ v4 存量惰性迁移（migrate→keystore 410→OPAQUE 登录） ----
    from app.accounts.envelope import seal_envelope_v4

    sk_v4, pk_v4 = generate_keypair()
    st, _h, body = _req(
        "POST",
        "/auth/register",
        {
            "username": "pilot_v4mig",
            "pubkey_hex": pk_v4,
            "sealed_blob": seal_envelope_v4(sk_v4, pk_v4, "V4-Mig-Pw-7", iterations=4096),
        },
    )
    expect(st == 422, "⑥ gate on：v4 注册=422 引导 v6（降级拒）", body)
    # 直播行模拟存量 v4（注册面停发前入库形态）
    from sqlalchemy import create_engine as _ce
    from sqlalchemy.orm import sessionmaker as _sm

    from app.accounts.models import Account

    eng2 = _ce(f"sqlite:///{db.as_posix()}")
    s2 = _sm(bind=eng2)()
    s2.add(
        Account(
            username="pilot_v4mig",
            role="pilot",
            status="active",
            pubkey_hex=pk_v4,
            sealed_blob=seal_envelope_v4(sk_v4, pk_v4, "V4-Mig-Pw-7", iterations=4096),
        )
    )
    s2.commit()
    s2.close()
    # v4 登录（现役路径）：keystore 拉取→解封→挑战-应答
    st, _h, body = _req("GET", "/auth/keystore/pilot_v4mig")
    expect(st == 200, "⑥ v4 keystore 200（过渡存量面）")
    from app.accounts.envelope import unseal_envelope

    sk_v4_un = unseal_envelope(_j(body)["data"]["sealed_blob"], "V4-Mig-Pw-7")
    st, body = _challenge_login("pilot_v4mig", sk_v4_un)
    expect(st == 200, "⑥ v4 登录 200（照常）", body)
    # 惰性迁移：会话内 evaluate（携属主会话=真实 β §6.1-c；无会话=fake 态
    # 客户端解掩码诚实失败——先拿会话再取材料）
    _challenge_login_capture("pilot_v4mig", sk_v4_un)
    # 迁移材料：client_seal_v6 内部自算 evaluate（进程内同钥 shortcut——与线协议
    # 盲化回环等价，test_crypto_opaque RT 回环锚定）；未迁移账户的 evaluate
    # 响应为 fake 态（无记录可解掩码）——材料面只取 β 不取掩码字段（§6.1）。
    mats_m = client_seal_v6("pilot_v4mig", "V4-Mig-Pw-7", sk_v4, pk_v4)
    st, _h, body = _req(
        "POST",
        "/auth/opaque/migrate",
        {
            "sealed_blob": mats_m["sealed_blob"],
            "masking_key_hex": mats_m["masking_key_hex"],
            "kdf_salt_hex": mats_m["kdf_salt_hex"],
            "kdf_iter": mats_m["kdf_iter"],
        },
        cookies=dict(_session_cookies),
    )
    expect(st == 200, "⑥ migrate 200（原子换新）", body)
    st, _h, body = _req("GET", "/auth/keystore/pilot_v4mig")
    expect(st == 410, "⑥ 迁移后 keystore=410（v4 路径永久失效）")
    rs_m2, resp_m2 = _evaluate("pilot_v4mig", "V4-Mig-Pw-7")
    sk_m2 = _finish(rs_m2, resp_m2)
    st, body = _challenge_login("pilot_v4mig", sk_m2)
    expect(st == 200, "⑥ 迁移后 OPAQUE 登录 200", body)
    ok("⑥ v4 惰性迁移全动线实弹")

    # ---- ⑦ 改密联动（v6'+新掩码钥原子换新→旧口令败/新口令过） ----
    # 会话：pilot_v4mig 迁移后需重拿（challenge 登录发新 Cookie）
    st_ch, _h_ch = _challenge_login_capture("pilot_v4mig", sk_v4)
    expect(st_ch == 200, "⑦ 改密前登录（属主会话）")
    rs_c, resp_c = _evaluate("pilot_v4mig", "V4-Mig-Pw-7")
    mats_c = client_seal_v6(
        "pilot_v4mig",
        "V4-New-Pw-8",
        sk_v4,
        pk_v4,
        salt_hex=resp_c["kdf_salt_hex"],
        iterations=resp_c["kdf_iter"],
    )
    st, _h, body = _req(
        "POST",
        "/auth/password/change",
        {
            "sealed_blob": mats_c["sealed_blob"],
            "masking_key_hex": mats_c["masking_key_hex"],
        },
        cookies=dict(_session_cookies),
    )
    expect(st == 200, "⑦ v6' 改密 200（信封+掩码钥原子换新）", body)
    # 旧口令败（解掩码/信封 GCM 客户端败=零服务端差异）
    try:
        rs_old, resp_old = _evaluate("pilot_v4mig", "V4-Mig-Pw-7")
        _finish(rs_old, resp_old)
        expect(False, "⑦ 旧口令必须失败")
    except Exception:  # noqa: BLE001
        ok("⑦ 旧口令诚实失败（客户端判词）")
    rs_n, resp_n = _evaluate("pilot_v4mig", "V4-New-Pw-8")
    sk_n = _finish(rs_n, resp_n)
    st, body = _challenge_login("pilot_v4mig", sk_n)
    expect(st == 200, "⑦ 新口令登录 200", body)
    ok("⑦ 改密联动全动线实弹（v6'+掩码钥换新）")

    # ---- ⑧ CUTOFF 403（v4 截止——v6/v3 不受影响） ----
    os.environ["FZ_OPAQUE_CUTOFF_TS"] = str(int(time.time()) - 10)
    # env 注入需后端进程重读——login 读 env 每次调用生效（opaque_cutoff_ts 无缓存）
    sk6, pk6 = generate_keypair()
    mats_cut = client_seal_v6("pilot_cut", "Cut-Pw-12", sk6, pk6)
    st, _h, body = _req(
        "POST",
        "/auth/register",
        {
            "username": "pilot_cut",
            "pubkey_hex": pk6,
            "sealed_blob": mats_cut["sealed_blob"],
            "masking_key_hex": mats_cut["masking_key_hex"],
            "kdf_salt_hex": mats_cut["kdf_salt_hex"],
            "kdf_iter": mats_cut["kdf_iter"],
        },
    )
    expect(st == 201, "⑧ CUTOFF 后 v6 注册照常 201", body)
    # v4 存量（pilot_v4mig 已迁移——播种新 v4 直播行）
    s3 = _sm(bind=eng2)()
    sk_v4b, pk_v4b = generate_keypair()
    s3.add(
        Account(
            username="pilot_cut4",
            role="pilot",
            status="active",
            pubkey_hex=pk_v4b,
            sealed_blob=seal_envelope_v4(sk_v4b, pk_v4b, "Cut4-Pw-123", iterations=4096),
        )
    )
    s3.commit()
    s3.close()
    st, _h, body = _req("POST", "/auth/challenge/pilot_cut4")
    nonce = _j(body)["data"]["nonce_hex"]
    st, _h, body = _req(
        "POST",
        "/auth/login",
        {
            "username": "pilot_cut4",
            "nonce_hex": nonce,
            "sig_hex": sign(sk_v4b, f"FZ-AUTH-LOGIN|{nonce}".encode()),
        },
    )
    expect(st == 403 and _j(body)["code"] == "v4_cutoff", "⑧ CUTOFF 后 v4 登录=403", body)
    os.environ.pop("FZ_OPAQUE_CUTOFF_TS", None)
    ok("⑧ CUTOFF 语义实弹（v4 403/v6 照常）")

    print(
        f"\n== e2e_opaque_auth 全绿：{_checks} 项断言 [OK]（注册→激活→登录→错口令 429→惰性迁移→改密→CUTOFF）=="
    )
    server.should_exit = True
    th.join(timeout=5)
    return 0


_cookie_jar: dict = {}


if __name__ == "__main__":
    raise SystemExit(main())
