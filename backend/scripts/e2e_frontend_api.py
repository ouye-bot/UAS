# -*- coding: utf-8 -*-
"""前端功能接口级端到端判决（P0-3/彩排前置——不驱动浏览器，按屏走真实调用序列）。

逐屏覆盖（每屏=前端实际发出的 API 序列+该屏负例按钮的真实拒绝）：
  [入口] 登记 ok / 坏格式身份证 422
  [①我的记录] 子凭证签发（字段齐）/ 撤销快照 / 坏 master 哈希 404
  [②起飞申请] 绑定面 / 绑定参数非法 400 / 桥接本机出证→受理 / 重放 409
               sub_cred_used / 同 nonce 换新子凭证→409 nonce_used
  [③令牌与飞行] 引擎公钥 / 取件 ECIES / 令牌验签 / ARM（真令牌）/ 篡改 alt_max
               拒 / 错 plan_hash 拒 / 遥测起链 / 采样+检查点 / 真链锚定
  [④留痕与TRAIL] 采样 256 / 双窗口出证（行程证书包）/ 判决件下载 / 双窗第三方
               复验 / 窗口越界拒 / 行程索引 JSON
  [⑤回执查询] 跨屏同码 ready / 随机码 404
  [⑥链上留痕] 面板=真链模式+本屏授权记录在案
  [审计台] 坏令牌 401 / 令状上链 / 列表 / 无令状解锁拒 / 解锁实名 / 追溯闭环
           （含事件时间线——索引器回填）

用法：cd uas/backend && python scripts/e2e_frontend_api.py
前置：backend(8000, 真链档)+bridge(8100)+worker 在线（demo_up 或 sitl_e2e_services）。
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(UAS / "backend"))

API = os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")
BRIDGE = os.environ.get("FZ_BRIDGE_BASE", "http://127.0.0.1:8100")
CASES = UAS / "backend" / "fz-zk-cases"
N_WINDOW = 128  # TRAIL 定档：每窗口样本数（§留痕——128 样本=一窗口）

_checks = 0
ZKC = UAS / "zksvc" / "target" / "release" / "zkc.exe"

_checks = 0

ID_NUMBER = "11010119900101" + secrets.token_hex(2)  # 逐轮随机（B7 黑名单纪律）


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



def _persisted(fname: str) -> str | None:
    """demo_up 随机化令牌的 %TEMP% 持久件回退（2026-09-28 密码评审 P1-4：
    演示钥每场随机后，判决脚本经持久件保持连续性——env > 文件 > 派生）。"""
    import tempfile
    p = Path(tempfile.gettempdir()) / fname
    try:
        v = p.read_text(encoding="utf-8").strip()
        return v or None
    except OSError:
        return None


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _req(url: str, body: dict | None = None, headers: dict | None = None, method: str = "GET", timeout: float = 60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST" if body is not None else method,
    )
    try:
        with opener().open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"_raw": raw[:200]}



# ---- 账户会话（2026-09-29 账户批：X-Audit/X-RA-Token 退役）----
def _account_sessions():
    """按需登录审计员/管理员（env 初始口令；未激活态激活、已注册则跳过）。"""
    import os as _os
    from scripts.script_auth import script_login

    aud_pw = _os.environ.get("FZ_SEED_AUDITOR_PASSWORD")
    adm_pw = _os.environ.get("FZ_SEED_ADMIN_PASSWORD")
    if not aud_pw or not adm_pw:
        raise SystemExit(
            "需要 FZ_SEED_AUDITOR_PASSWORD / FZ_SEED_ADMIN_PASSWORD（部署方交付的"
            "预置账户初始口令——未激活态）。请先运行 scripts/seed_accounts.py 并以"
            "env 注入口令。"
        )
    return script_login(API, "auditor", aud_pw), script_login(API, "admin", adm_pw)


_AUD_SESS = None
_ADM_SESS = None


def _sess_cookie(path: str) -> str:
    """按路径分发会话 Cookie：/audit→审计员；/ra/revoke|/ra/collab|/admin→管理员。"""
    global _AUD_SESS, _ADM_SESS
    if _AUD_SESS is None:
        _AUD_SESS, _ADM_SESS = _account_sessions()
    if path.startswith("/ra/revoke") or path.startswith("/ra/collab") or path.startswith("/admin"):
        s = _ADM_SESS
    elif path.startswith("/audit"):
        s = _AUD_SESS
    else:
        return ""
    return "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items())


def api(path: str, body: dict | None = None, headers: dict | None = None, timeout: float = 60):
    ck = _sess_cookie(path)
    if ck:
        headers = {"Cookie": ck, **(headers or {})}
    return _req(API + path, body, headers, timeout=timeout)


def bridge(path: str, body: dict | None = None, timeout: float = 60):
    return _req(BRIDGE + path, body, timeout=timeout)


def main() -> int:
    from app.crypto.sm2 import decrypt as ecies_decrypt
    from app.crypto.sm2 import generate_keypair
    from app.crypto.sm2 import verify_digest
    from app.crypto.sm3 import sm3_bytes

    t_all = time.time()
    print("== 前端功能接口级端到端（逐屏×真实调用序列×负例按钮）==")

    # 前置探活（W-10 真档适配）：采样段走 SITL 真遥测（/telemetry/sitl_sample
    # ——合成采样已 env 门控默认 403，产品面物理关闭；e2e 与前端同源走真档）。
    rc, link = bridge("/link_status")
    expect(rc == 200 and link.get("mode") == "sitl",
           "0.1 桥=SITL 真档在线（真遥测面——合成采样已退役）",
           f"mode={link.get('mode') if rc == 200 else 'unreachable'}")

    # ============ [入口] 登记承诺 ============
    print("== [入口] 登记承诺 ==")
    holder_sk, holder_pk = generate_keypair()
    sn = os.environ.get("FZ_DEVICE_SERIAL", "FZ-SN-DEV-01")  # ⑥代 SN 绑定：与桥 device_serial 同源单读（一证一机闭环）
    rc, reg = api("/ra/register", {
        "username": "scr-" + secrets.token_hex(3),
        "id_number": ID_NUMBER,
        "cert_level": 3, "sn": sn, "user_pub_hex": holder_pk, "class_id": 1,
    })
    expect(rc == 200 and reg["code"] == "ok" and "master_cred_hash_hex" in reg.get("data", {}),
           "1.1 登记承诺（回执=凭证材料：承诺哈希/盐/签名）")
    cred = reg["data"]
    rc, bad = api("/ra/register", {
        "username": "scr-bad", "id_number": "1101", "cert_level": 3,
        "sn": sn + "-b", "user_pub_hex": holder_pk, "class_id": 1,
    })
    expect(rc == 422, "1.2 坏格式身份证 → 422（'坏格式身份证'负例）", f"rc={rc}")

    # ============ [①我的记录] 子凭证+撤销快照 ============
    print("== [①我的记录] 子凭证+撤销快照 ==")

    def issue_sub() -> tuple[dict, str, str]:
        """签发子凭证（2026-10-01 一次性出示钥批同构——前端 RecordView.issueSub
        同款行为）：每次调用生成全新出示钥对 (sk′,pk′)，RA 对含新 pk′ 的报文
        签名。返回 (签发响应 data, sk′, pk′)。账户钥（holder_pk——登记钥）只
        服务登记面，不再进入出示面。"""
        sub_sk, sub_pk = generate_keypair()
        rc, out = api("/ra/sub-credentials", {
            "master_cred_hash_hex": cred["master_cred_hash_hex"],
            "salt_hex": cred["salt_hex"],
            "id_number": ID_NUMBER,
            "cert_level": 3, "sn": sn, "holder_pub_hex": sub_pk,
        })
        expect(rc == 200 and out["code"] == "ok", "子凭证签发", f"rc={rc}")
        return out["data"], sub_sk, sub_pk

    sub1, sub1_sk, sub1_pk = issue_sub()
    expect(all(k in sub1 for k in ("id_prime_hex", "expires_at", "message_hex", "sig_hex", "sub_cred_hash_hex")),
           "2.1 子凭证字段齐（id′/有效期/报文/签名/哈希——屏①展示面）")
    # 一次性出示钥对拍①（隐私边界收窄判据）：RA 签名报文 M_A′ 的 pk′ 段
    # （165B 布局 Z_A‖idg_x‖C‖pk′.x‖pk′.y‖exp‖par → hex[192:320]）须逐位等于
    # 本次签发生成的新公钥——RA 签的就是客户端当场生成的新钥。
    expect(sub1["message_hex"][192:320] == sub1_pk.lower(),
           "2.1b 子凭证报文绑定本次新出示钥（M_A′ pk′ 段=新钥逐位对拍）")
    rc, snap = api("/ra/revocation/snapshot")
    expect(rc == 200 and "root_hex" in snap.get("data", {}), "2.2 撤销快照（公示根）")
    rc, nf = api("/ra/sub-credentials", {
        "master_cred_hash_hex": "ab" * 32, "salt_hex": "cd" * 16,
        "id_number": ID_NUMBER, "cert_level": 3, "sn": sn, "holder_pub_hex": sub1_pk,
    })
    expect(rc == 404 and nf.get("code") == "not_found", "2.3 坏 master 哈希 → 404 not_found", f"rc={rc}")

    # ============ [②起飞申请] 绑定→出证→受理 ============
    print("== [②起飞申请] 绑定→出证→受理 ==")
    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    rc, binding = api(f"/authz/binding?class_id=1&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}")
    expect(rc == 200 and "challenge_hex" in binding.get("data", {}), "3.1 绑定面（挑战+政策+时间锚）")
    rc, badb = api("/authz/binding?class_id=1&plan_hash_hex=zz&nonce_hex=11")
    expect(rc in (400, 422), "3.2 绑定参数非法 → 400/422", f"rc={rc}")

    rc, start = bridge("/prove/start", {
        "plan_hash_hex": plan_hash_hex, "nonce_hex": nonce_hex, "class_id": 1,
        "id_number": ID_NUMBER, "cert_level": 3, "sn": sn,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub1["id_prime_hex"],
        "sig_hex": sub1["sig_hex"], "expires_at": sub1["expires_at"],
        "holder_sk_hex": sub1_sk, "holder_pk_hex": sub1_pk,
    }, timeout=30)
    expect(rc == 200 and start.get("task_id"), "3.3 桥接出证任务受理")
    task_id, case_id = start["task_id"], start["case_id"]
    prove_t_epoch = start["binding"]["t_epoch"]
    print(f"  [..] 3.4 本机出证中（{task_id[:12]}…，~3 分钟）")
    t0 = time.time()
    status = "assembling"
    while status in ("assembling", "proving"):
        time.sleep(5)
        _, t = bridge(f"/prove/task/{task_id}")
        s = t.get("status") or t.get("data", {}).get("status")
        if s != status:
            status = s
            print(f"  [..] 状态：{status}（{time.time() - t0:.0f}s）")
        if status == "failed":
            print("  [FAIL] 出证失败", str(t)[:200])
            raise SystemExit(1)
        if time.time() - t0 > 1500:
            raise SystemExit(1)
    expect(status == "done", f"3.4 本机出证完成（{time.time() - t0:.0f}s）")

    rc, ap = api("/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub1["message_hex"], "sub_sig_hex": sub1["sig_hex"],
        "sub_cred_hash_hex": sub1["sub_cred_hash_hex"],
        "nonce_hex": nonce_hex, "plan_hash_hex": plan_hash_hex, "class_id": 1,
        "case_id": case_id,
        "rev_root_hex": api("/ra/revocation/snapshot")[1]["data"]["root_hex"],
        "t_start": prove_t_epoch, "t_end": prove_t_epoch + 7200,
    })
    expect(rc == 200 and ap.get("ok"), "3.5 受理通过（回执码签发）")
    receipt_code = ap["data"]["receipt_code"]

    # 3.6 语义换代（批 4 案卷归属门后）：逐字节重放=幂等 200 返原申请（不二次
    # 授权——先证幂等轴）；子凭证一次性负例改真隔离（同子凭证+全新
    # nonce/计划/案卷 ⟹ 除子凭证面全新外全合法 ⟹ 必死于 sub_cred_used）。
    rc2, replay = api("/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub1["message_hex"], "sub_sig_hex": sub1["sig_hex"],
        "sub_cred_hash_hex": sub1["sub_cred_hash_hex"],
        "nonce_hex": nonce_hex, "plan_hash_hex": plan_hash_hex, "class_id": 1,
        "case_id": case_id,
        "rev_root_hex": api("/ra/revocation/snapshot")[1]["data"]["root_hex"],
        "t_start": prove_t_epoch, "t_end": prove_t_epoch + 7200,
    })
    expect(rc2 == 200 and replay["data"]["receipt_code"] == receipt_code,
           "3.6a 逐字节重放=幂等返原件（批 4 语义——无二次授权）", f"rc={rc2}")
    # 3.6b 隔离配套真案卷（门序实证：案卷产物门先于子凭证消费门——随机案卷
    # 号死于 case_incomplete；用 sub1 材料先证一张未绑定案卷〔消费≠吊销，
    # 见证仍可得〕，再以该案卷+同子凭证全新 nonce/计划申请 ⟹ 必死 sub_cred_used）
    # 绑定单源纪律（2026-10-07 门序定谳）：apply 必须消费**该案卷出证所用**的
    # 同一 plan/nonce/t_epoch（与 3.3→3.5 主流程同款）——另取随机 nonce/旧
    # t_epoch 会在门⑤实例一致性被抢先拒成 instance_mismatch，打不到子凭证
    # 一次性独立轴（门序：③链查重→⑤实例核对→库级查重）。新材料仅复用子凭证
    # ⟹ 过全部先序门，唯一复用项=子凭证 ⟹ sub_cred_used（链级③′或库级查重，
    # 同码双保险）。
    _plan36 = secrets.token_bytes(32).hex()
    _nonce36 = secrets.token_bytes(16).hex()
    rc36, start36 = bridge("/prove/start", {
        "plan_hash_hex": _plan36, "nonce_hex": _nonce36,
        "class_id": 1, "id_number": ID_NUMBER, "cert_level": 3, "sn": sn,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub1["id_prime_hex"],
        "sig_hex": sub1["sig_hex"], "expires_at": sub1["expires_at"],
        "holder_sk_hex": sub1_sk, "holder_pk_hex": sub1_pk,
    }, timeout=30)
    _st36 = "assembling"
    _t36 = time.time()
    while _st36 in ("assembling", "proving"):
        time.sleep(5)
        _, _t = bridge(f"/prove/task/{start36['task_id']}")
        _st36 = _t.get("status") or _t.get("data", {}).get("status", _st36)
        if time.time() - _t36 > 1500:
            raise SystemExit(1)
    expect(_st36 == "done", f"3.6b-0 隔离案卷出证（{time.time() - _t36:.0f}s）")
    _t_epoch36 = start36["binding"]["t_epoch"]
    rc2b, replay2 = api("/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub1["message_hex"], "sub_sig_hex": sub1["sig_hex"],
        "sub_cred_hash_hex": sub1["sub_cred_hash_hex"],
        "nonce_hex": _nonce36,
        "plan_hash_hex": _plan36, "class_id": 1,
        "case_id": start36["case_id"],
        "rev_root_hex": api("/ra/revocation/snapshot")[1]["data"]["root_hex"],
        "t_start": _t_epoch36, "t_end": _t_epoch36 + 7200,
    })
    expect(rc2b == 409 and replay2.get("code") == "sub_cred_used",
           "3.6b 子凭证一次性（真隔离：新材料仅子凭证复用）→ 409 sub_cred_used（屏②负例）",
           f"rc={rc2b}")

    sub2, _sub2_sk, sub2_pk = issue_sub()  # 换新子凭证材料（nonce 复用轴）
    # 一次性出示钥对拍②（任务判据）：两次签发=两把不同出示钥——出示公钥层
    # 跨申请不可链接（M_A′ pk′ 段互异）。
    expect(sub1["message_hex"][192:320] != sub2["message_hex"][192:320]
           and sub2["message_hex"][192:320] == sub2_pk.lower(),
           "2.4 新子凭证=新出示钥（两次签发 pk′ 互异且各绑定本报文——跨申请不可链接）")
    # 3.7 隔离配套（同 3.6b 手法）：sub2 新材料+**同 nonce** 先证真案卷，
    # 再申请 ⟹ 材料面全新合法、唯一复用项=nonce ⟹ 必死 nonce_used（链级烧毁）。
    _plan37 = secrets.token_bytes(32).hex()
    rc37, start37 = bridge("/prove/start", {
        "plan_hash_hex": _plan37, "nonce_hex": nonce_hex,
        "class_id": 1, "id_number": ID_NUMBER, "cert_level": 3, "sn": sn,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub2["id_prime_hex"],
        "sig_hex": sub2["sig_hex"], "expires_at": sub2["expires_at"],
        "holder_sk_hex": _sub2_sk, "holder_pk_hex": sub2_pk,
    }, timeout=30)
    _st37 = "assembling"
    _t37 = time.time()
    while _st37 in ("assembling", "proving"):
        time.sleep(5)
        _, _t = bridge(f"/prove/task/{start37['task_id']}")
        _st37 = _t.get("status") or _t.get("data", {}).get("status", _st37)
        if time.time() - _t37 > 1500:
            raise SystemExit(1)
    expect(_st37 == "done", f"3.7-0 隔离案卷出证（同 nonce，{time.time() - _t37:.0f}s）")
    # 绑定单源纪律（同 3.6b）：t_epoch 消费**本案卷**出证绑定——nonce 保持复用
    # （隔离轴本体），其余维度全新合法 ⟹ 唯一复用项=nonce ⟹ nonce_used
    # （链级③烧毁先行，库级查重兜底——worker 排水时序无关，确定性打中）。
    _t_epoch37 = start37["binding"]["t_epoch"]
    rc3, nonce_replay = api("/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub2["message_hex"], "sub_sig_hex": sub2["sig_hex"],
        "sub_cred_hash_hex": sub2["sub_cred_hash_hex"],
        "nonce_hex": nonce_hex, "plan_hash_hex": _plan37, "class_id": 1,
        "case_id": start37["case_id"],
        "rev_root_hex": api("/ra/revocation/snapshot")[1]["data"]["root_hex"],
        "t_start": _t_epoch37, "t_end": _t_epoch37 + 7200,
    })
    expect(rc3 == 409 and nonce_replay.get("code") == "nonce_used",
           "3.7 同 nonce 换新子凭证（真隔离）→ 409 nonce_used（链级重放拒绝）", f"rc={rc3}")

    # ============ [③令牌与飞行] 取件→ARM→遥测→锚定 ============
    print("== [③令牌与飞行] 取件→ARM→遥测→锚定 ==")
    rc, pub = bridge("/engine_pub")
    engine_pub = pub["engine_pub_hex"]
    ok("4.1 引擎公钥获取（验签基准）")
    rr = {"status": "waiting"}
    t1 = time.time()
    while time.time() - t1 < 120:
        _, rr = api(f"/authz/receipt/{receipt_code}")
        rr = rr.get("data", rr)
        if rr["status"] != "waiting":
            break
        time.sleep(2)
    expect(rr["status"] == "ready", f"4.2 worker 验证→回执 ready（{time.time() - t1:.0f}s）")
    payload = ecies_decrypt(holder_sk, bytes.fromhex(rr["token_cipher_hex"]))
    body, sig_hex_b = payload.rsplit(b"|", 1)
    sig_hex = sig_hex_b.decode()
    tok = json.loads(body)
    expect(verify_digest(engine_pub, sm3_bytes(body), sig_hex), "4.3 令牌验签（浏览器端同款 SM2 验证）")
    expect(tok["plan_hash"] == plan_hash_hex and tok["authId"] > 0, "4.4 令牌绑定+authId 贯穿")

    token_payload_hex = payload.hex()
    # 2026-09-30：解锁时延断言（队长实测卡 10s+ 的竞态根修回归门）——
    # 围栏三参数确认+ARM 全序列须 <6s（正常 1~2s；4s×N 超时=竞态复发即红）
    t_arm = time.time()
    rc, arm = bridge("/arm", {"token_payload_hex": token_payload_hex, "plan_hash_hex": plan_hash_hex}, timeout=120)
    arm_s = time.time() - t_arm
    expect(arm.get("ok") is True and arm.get("alt_max") == tok["alt_max"],
           "4.5 ARM 解锁（围栏=令牌 alt_max）", json.dumps(arm, ensure_ascii=False)[:160])
    # 2026-09-30 ARM ACK ~10s 根修完成：真因=attempt_arm 内冗余的 PILOT_SPEED_UP
    # 后台写入持 _lock 跑满 3×4s 超时（本构建该参数无 PARAM_VALUE 响应），主
    # 线程 arm() 等 _lock ~10s——插桩实锤 ARM 命令本身 14ms 即 ACK。根修=该
    # 写入仅在桥启动时一次（server.py），ARM 序列内不再发起。根修前 15.4s →
    # 实测 4.3s（构成：fence 4 参数 ~2s+settle 2s+ARM/DISARM_DELAY/confirm ~0.3s）。
    # 门=6s（余量 1.7s 容 SITL 抖动）；>6s 即锁竞争复发或参数确认退化，红。
    expect(arm_s < 6, f"4.5b ARM 时延 {arm_s:.1f}s < 6s（根修后收紧门）", f"{arm_s:.1f}s")

    tampered_body = json.dumps({**tok, "alt_max": tok["alt_max"] + 1}, separators=(",", ":"), sort_keys=True)
    rc, tamper = bridge("/arm", {
        "token_payload_hex": (tampered_body + "|" + sig_hex).encode().hex(),
        "plan_hash_hex": plan_hash_hex,
    })
    expect(tamper.get("ok") is False, "4.6 篡改 alt_max → ARM 拒（屏③篡改负例）",
           json.dumps(tamper, ensure_ascii=False)[:120])
    # 换设备负例（一次性出示钥批终验）：sk′ 会话域内存态（不随密封件走）——
    # 新"设备"（清本地会话钥）持旧子凭证申请 ⟹ 人话指引重签而非密码学报错。
    # 换设备负例（一次性出示钥批终验）：sk′ 会话域内存态（不随密封件走）——
    # 新"设备"持旧子凭证材料但无 sk′ 申请 AUTH 出证 ⟹ 拒绝（前端形态=
    # sub_key_missing 人话指引重签；API 形态=装配面拒绝，不产生任务）。
    # API 级模拟=同材料 holder_sk_hex 传空。
    rc, nodisk = bridge("/prove/start", {
        "plan_hash_hex": plan_hash_hex, "nonce_hex": nonce_hex, "class_id": 1,
        "id_number": ID_NUMBER, "cert_level": 3, "sn": sn,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub1["id_prime_hex"],
        "sig_hex": sub1["sig_hex"], "expires_at": sub1["expires_at"],
        "holder_sk_hex": "", "holder_pk_hex": sub1_pk,
    }, timeout=30)
    expect(rc in (400, 422, 500) and nodisk.get("task_id") is None,
           "4.9 换设备负例：无 sk′ 旧子凭证申请 → 拒绝且不产生出证任务（引导重签）",
           f"rc={rc} {str(nodisk)[:110]}")
    rc, wrongplan = bridge("/arm", {"token_payload_hex": token_payload_hex, "plan_hash_hex": "ff" * 32})
    expect(wrongplan.get("ok") is False, "4.7 错 plan_hash → ARM 拒（计划一致性）")

    rc, ts = bridge("/telemetry/start", {"auth_id": tok["authId"], "fence_state_hex": arm.get("fence_state_hex", "01780000")})
    expect(ts.get("ok") is True and "genesis_head_hex" in ts, "4.8 遥测链 genesis 起链")

    def sitl_sample() -> dict:
        """真采样（FlightView 同款序列：GET /telemetry/sitl_sample?t_epoch=秒）。"""
        rc_s, s = bridge(f"/telemetry/sitl_sample?t_epoch={int(time.time())}")
        return s

    smp = sitl_sample()
    expect(smp.get("ok") is True and smp.get("checkpoint"), "4.9 真采样+检查点（SITL 真遥测+设备签+围栏态绑定）")
    rc, anch = bridge("/telemetry/anchor", {}, timeout=120)
    expect(anch.get("ok") is True and anch.get("anchored", 0) >= 1, "4.10 检查点真链锚定（anchorCheckpoint）")

    # ============ [④留痕与TRAIL] 采样满→双窗口出证→复验（行程证书包） ============
    print("== [④留痕与TRAIL] 采样满→双窗口出证→复验 ==")
    # 窗口 0=地面基线 128 样本；窗口间真实爬升一次（窗口 1 含升空样本——
    # 静止数据两窗行字节一致⟹链头一致，无法证明切片正确性；爬升后高度分
    # 布不同⟹两窗独立窗口头，行程证书包语义（多窗互异证书）可判）
    while smp.get("n", 0) < 128:
        smp = sitl_sample()
        if not smp.get("ok"):
            break
    expect(smp.get("n", 0) >= 128, f"5.1a 窗口 0 采样满 128（当前 {smp.get('n')}）")
    rc, climb = bridge("/sitl/climb?pwm=1750&hold_s=2.5", {}, timeout=120)
    expect(climb.get("ok") is True, "5.1b 窗口间真实爬升受理（SITL 升空——窗口 1 数据非退化）", str(climb)[:120])
    win1_alt_max = 0
    for _ in range(40):
        smp = sitl_sample()
        if not smp.get("ok"):
            break
        win1_alt_max = max(win1_alt_max, smp.get("alt_cm", 0) or 0)
        if win1_alt_max > 200:
            break
        time.sleep(0.5)
    while smp.get("n", 0) < N_WINDOW * 2:  # 窗口 1 满=256（原误写 128——爬升后 168 即停，窗口 1 永不完整）
        smp = sitl_sample()
        if not smp.get("ok"):
            break
        win1_alt_max = max(win1_alt_max, smp.get("alt_cm", 0) or 0)
    expect(win1_alt_max > 0, "5.1c 窗口 1 含升空样本（高度>0——两窗数据非同型）", f"max_alt={win1_alt_max}")
    expect(smp.get("n", 0) >= N_WINDOW * 2, f"5.1 采样满 {N_WINDOW * 2}（当前 {smp.get('n')}）")
    alt_max_cm = tok["alt_max"] * 100

    def trail_prove_window(w: int):
        """行程证书包窗口出证：start(window=w)→轮询 done→四件下载。
        返回 (case_id, chain_head_hex, out_dir, verdict)。"""
        rc, tr = bridge("/prove/trail/start", {"alt_max_cm": alt_max_cm, "window": w}, timeout=30)
        expect(tr.get("task_id") and tr.get("chain_head_hex") and tr.get("window") == w,
               f"窗口 {w} 出证任务受理")
        tt0 = time.time()
        tstat = "assembling"
        while tstat in ("assembling", "proving"):
            time.sleep(4)
            _, t = bridge(f"/prove/task/{tr['task_id']}")
            tstat = t.get("status") or t.get("data", {}).get("status")
            if tstat == "failed":
                print("  [FAIL] TRAIL 出证失败", str(t)[:200])
                raise SystemExit(1)
            if time.time() - tt0 > 600:
                raise SystemExit(1)
        trail_case = t.get("case_id") or t.get("data", {}).get("case_id")
        expect(tstat == "done", f"窗口 {w} TRAIL 出证完成（{time.time() - tt0:.0f}s）")
        out_dir = UAS / "zksvc" / "target" / "probe" / f"scr_{trail_case[:8]}"
        out_dir.mkdir(parents=True, exist_ok=True)
        verdict = None
        for name in ("proof.bin", "verifier_param.bin", "verdict.json", "instances.json",
                     "expected.json", "binding.json"):
            with opener().open(f"{BRIDGE}/prove/case/{trail_case}/{name}", timeout=60) as resp:
                data = resp.read()
            (out_dir / name).write_bytes(data)
            if name == "verdict.json":
                verdict = json.loads(data)
        return trail_case, tr["chain_head_hex"], out_dir, verdict

    # 窗口越界负例（行程证书包窗口号门）
    rc, wbad = bridge("/prove/trail/start", {"alt_max_cm": alt_max_cm, "window": 99}, timeout=30)
    expect(rc == 409 and wbad.get("code") == "window_out_of_range",
           "5.2 窗口越界 → 409 window_out_of_range", str(wbad)[:120])

    trail_case, head0, out_dir, verdict = trail_prove_window(0)
    expect(verdict and verdict.get("verdict") == "OK", "5.3 判决件三件套下载（verdict=OK）")
    env = {**os.environ, "FZ_ZK_ALLOW_TRAIL": "1",
           "FZ_TRAIL_CANONICAL_SPEC": str(UAS / "zksvc" / "tests" / "trail_canonical_spec.json")}
    # 2026-10 电路换代：alt_max/t_start 迁公开实例 ⟹ 期望绑定必携三字段
    # （chain_head‖alt_max_cm‖t_start——fail-closed）。第三方复验语义=从案卷
    # 拿随卷发放的 expected.json（不再自建旧形态单链头最小期望）。
    exp = out_dir / "expected.json"
    exp_full = json.loads(exp.read_text(encoding="utf-8"))
    assert "alt_max_cm" in exp_full and "t_start" in exp_full, f"案卷期望缺换代字段: {sorted(exp_full)}"
    proc = subprocess.run(
        [str(ZKC), "verify-instances", "--instances", str(out_dir / "instances.json"),
         "--proof", str(out_dir / "proof.bin"), "--vp", str(out_dir / "verifier_param.bin"),
         "--expected", str(exp)], capture_output=True, text=True, env=env)
    expect(proc.returncode == 0, "5.4 第三方独立复验（verify-instances OK，期望绑定三字段随卷）",
           (proc.stdout + proc.stderr)[-160:])
    exp_tampered = {**exp_full, "chain_head_hex": "ab" * 32}
    exp.write_text(json.dumps(exp_tampered), encoding="utf-8")
    proc = subprocess.run(
        [str(ZKC), "verify-instances", "--instances", str(out_dir / "instances.json"),
         "--proof", str(out_dir / "proof.bin"), "--vp", str(out_dir / "verifier_param.bin"),
         "--expected", str(exp)], capture_output=True, text=True, env=env)
    expect(proc.returncode == 2, "5.5 篡改链头 → 复验拒绝 exit 2")
    exp.write_text(json.dumps(exp_full), encoding="utf-8")

    # 窗口 1（samples[128:256] 切片——独立窗口头，与窗口 0 链头互异）
    trail_case1, head1, out_dir1, verdict1 = trail_prove_window(1)
    expect(verdict1 and verdict1.get("verdict") == "OK" and head1 != head0,
           "5.9 窗口 1 判决件（verdict=OK 且链头≠窗口 0——独立窗口头自含重放）")
    exp1 = out_dir1 / "expected.json"
    # 窗口 1 案卷随卷 expected 自含本窗三字段（chain_head=窗口 1 头）——正例
    # 复验直接原文使用（勿借窗口 0 期望：t_start 属窗口，错借即 fail-closed 拒）。
    exp1_full = json.loads(exp1.read_text(encoding="utf-8"))
    assert exp1_full.get("chain_head_hex") == head1, "窗口 1 随卷期望链头与本窗头不一致"
    proc = subprocess.run(
        [str(ZKC), "verify-instances", "--instances", str(out_dir1 / "instances.json"),
         "--proof", str(out_dir1 / "proof.bin"), "--vp", str(out_dir1 / "verifier_param.bin"),
         "--expected", str(exp1)], capture_output=True, text=True, env=env)
    expect(proc.returncode == 0, "5.10 窗口 1 第三方独立复验 OK", (proc.stdout + proc.stderr)[-160:])

    # 行程索引（一次飞行=多窗口证书包的公开清单）
    with opener().open(f"{BRIDGE}/prove/trip/index?auth_id={tok['authId']}", timeout=30) as resp:
        trip = json.loads(resp.read())
    items = trip.get("items", [])
    expect(trip.get("kind") == "fz-trip-index" and trip.get("windows", 0) >= 2
           and {i.get("window") for i in items} >= {0, 1}
           and any(i.get("case_id") == trail_case1 for i in items),
           "5.11 行程索引 JSON（两窗口在册+案卷路径清单）", str(trip)[:160])

    # 锚定对拍实弹（2026-09-28）：binding.json 信封下载+两签离线核验
    # （引擎绑定签 FZ-TRAIL-BIND + 锚定证据签 FZ-ANCHOR-EVID——公示公钥即可验，
    # 语义=证书与链上锚定时间线一致性核对）
    with opener().open(f"{BRIDGE}/prove/case/{trail_case1}/binding.json", timeout=30) as resp:
        bj = json.loads(resp.read())
    (out_dir1 / "binding.json").write_text(json.dumps(bj), encoding="utf-8")
    rc, epub = api("/authz/engine/pub")
    engine_pub_hex = (epub.get("data") or {}).get("engine_pub_hex", "")
    b = bj.get("binding", {})
    ev = bj.get("anchor_evidence") or {}
    from app.crypto.sm2 import verify_digest as _vdig
    # 二批 BIND2 扩域：绑定签名覆盖围栏 4 界（离线复核报文同步换代）
    ok_bind = _vdig(engine_pub_hex, sm3_bytes(
        (f"FZ-TRAIL-BIND2|{b.get('auth_id')}|{b.get('alt_max_cm')}|{b.get('chain_head_hex')}"
         f"|{b.get('min_lat')}|{b.get('max_lat')}|{b.get('min_lon')}|{b.get('max_lon')}").encode()),
        b.get("sig_hex", ""))
    ok_evid = _vdig(engine_pub_hex, sm3_bytes(
        f"FZ-ANCHOR-EVID|{tok['authId']}|{ev.get('seq')}|{ev.get('chain_head_hex')}".encode()),
        bj.get("anchor_evidence_sig_hex", ""))
    expect(bool(b and ok_bind and ok_evid and ev.get("seq", 0) >= 1 and ev.get("chain_head_hex")),
           "5.12 binding.json 锚定证据（两签离线核验 OK+锚定序号在案）",
           f"bind={ok_bind} evid={ok_evid} ev={str(ev)[:120]}")

    # ============ [⑤回执查询] 跨屏同码 ============
    print("== [⑤回执查询] 跨屏同码 ==")
    rc, qr = api(f"/authz/receipt/{receipt_code}")
    expect(rc == 200 and qr.get("data", {}).get("status") == "ready", "6.1 回执查询 ready（跨屏同码）")
    rc, ghost = api(f"/authz/receipt/{secrets.token_hex(16)}")
    expect(rc == 404, "6.2 随机码 → 404（屏⑤负例）", f"rc={rc}")

    # ============ [⑥链上留痕] 面板 ============
    print("== [⑥链上留痕] 面板 ==")
    rc, panel = api("/chain/panel")
    pd = panel["data"]
    expect(pd.get("mode") == "real", "7.1 面板=真链模式")
    proof_digest = sm3_bytes((CASES / case_id / "proof.bin").read_bytes()).hex()
    hit = [r for r in pd.get("records", []) if r["auth_id"] == tok["authId"]]
    expect(bool(hit) and hit[0]["proof_digest_hex"] == proof_digest,
           "7.2 本屏授权记录在面板且 proofDigest=链上（可核验）")
    # W-8 飞手视角详情端点：链上原文对账+复验期望绑定（expected 与验证时同源）
    rc, rd = api(f"/chain/record/{tok['authId']}")
    rdd = rd.get("data", {})
    expect(rc == 200 and rdd.get("chain", {}).get("match") is True,
           "7.3 记录详情：链上原文比对一致（match=True）", str(rd)[:160])
    expect(rdd.get("proof_digest_hex") == proof_digest and rdd.get("expected", {}).get("e_hex"),
           "7.4 详情指纹一致+复验期望绑定在案（e_hex/challenge/θ——第三方复验材料）")

    # ============ [审计台] 令状→解锁→追溯 ============
    print("== [审计台] 令状→解锁→追溯 ==")
    # 账户批：未登录（无会话 Cookie 的真匿名客户端）→ 401（api() 会自动附
    # 审计员会话——匿名负例必须绕开 _sess_cookie 分发，直连无 Cookie 请求）
    import requests as _rq

    anon = _rq.Session()
    _r = anon.get(API + "/audit/warrants", timeout=15)
    expect(_r.status_code == 401, "8.1 未登录（令牌头已退役）→ 401", f"rc={_r.status_code}")
    case_no = "SCR-" + secrets.token_hex(3)
    rc, w = api("/audit/warrants", {
        "case_no": case_no, "legal_basis_hash_hex": sm3_bytes(b"scr-law").hex(),
        "target_auth_id": tok["authId"], "note": "前端接口级 e2e 追溯演示",
    }, timeout=90)
    expect(rc == 200 and w.get("code") == "ok", "8.2 令状创建（logWarrant 上链）")
    wh = w["data"]["warrant_hash_hex"]
    rc, wl = api("/audit/warrants")
    expect(any(x["warrant_hash_hex"] == wh for x in wl.get("data", [])), "8.3 令状列表含新令状")
    ghost = sm3_bytes(b"scr-ghost" + secrets.token_bytes(8)).hex()
    # 批B/C 双控强制：无协作函=400 missing_collab_code（双控第一关前移）
    rc, g = api(f"/audit/warrants/{ghost}/unlock", {"master_cred_hash_hex": cred["master_cred_hash_hex"]}, )
    expect(rc == 400 and g.get("code") == "missing_collab_code", "8.4a 无协作函解锁 → 400（双控第二因素强制）", f"rc={rc} {str(g)[:100]}")
    # RA 操作员出具随案协作函（2026-09-28 F 席根修：FZC2 函-令状绑定——
    # 出具只带令状哈希，凭证由服务端从授权链解析；函不可挪用于其他令状）
    rc, viol = api("/audit/violations", )
    # 2026-09-28 安全修4：响应换代 {items,total,limit,unfiled}（原裸 list）
    expect(rc == 200 and isinstance(viol.get("data", {}).get("items"), list),
           "8.4b-0 违规事件待办列表可达（聚合面+分页契约）")
    rc, cc = api("/ra/collab-code", {"warrant_hash_hex": wh}, )
    expect(rc == 200 and cc.get("data", {}).get("code"), "8.4b RA 协作函出具（FZC2 函-令状绑定）", f"rc={rc} {str(cc)[:100]}")
    collab = cc["data"]["code"]
    rc, g = api(f"/audit/warrants/{ghost}/unlock", {"collab_code": collab}, )
    expect(rc in (400, 403, 404, 409), "8.4 持函解锁无令状 → 拒（流程双控）", f"rc={rc}")
    rc, unl = api(f"/audit/warrants/{wh}/unlock", {"collab_code": collab}, )
    expect(rc == 200 and unl.get("code") == "ok", "8.5 RA 协作解锁（unwrap 实名）", f"rc={rc} {str(unl)[:100]}")
    expect(unl["data"]["unlocked"]["username"].startswith("scr-"), "8.6 解锁面=登记实名")
    rc, tr2 = api(f"/audit/warrants/{wh}/trace", )
    ct = tr2["data"]["chain_trace"]
    expect(ct.get("auth_record") is not None and ct["auth_record"]["proof_digest"],
           "8.7 追溯：授权记录链上回读")
    expect("events" in ct and isinstance(ct["events"], list), "8.8 追溯：事件时间线字段在案（索引器投影）")

    mins = (time.time() - t_all) / 60
    print(f"\n== 前端功能接口级端到端全绿：{_checks} 项断言 [OK] ==")
    print(f"== authId={tok['authId']} 贯穿 | 八屏全走（入口/①-⑥/审计台）| 全程 {mins:.1f} 分钟 ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
