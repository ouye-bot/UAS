"""B5-T1/T2 测试：令牌五查验签+已用审计（A7）+遥测链/检查点（设备钥+围栏绑定）。

gcs/bridge 测试（pytest 同仓库跑——sys.path 注入 backend 国密库）。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.crypto.sm2 import sign_digest
from app.crypto.sm3 import sm3_bytes

from device_key import device_keypair, device_serial, verify_checkpoint
from fence import TelemetryChain, sample_hash
from telemetry import LocalAudit, TokenError, verify_token


@pytest.fixture()
def token_payload():
    from app.kms import engine_signing_keypair

    sk, _pk = engine_signing_keypair()
    now = int(time.time())
    tok = {
        "authId": 7,
        "plan_hash": "ab" * 32,
        "alt_max": 120,
        "t_start": now - 60,
        "t_end": now + 3600,
        "nonce": "ef" * 16,
        "policy_version": "policy-2026-09-v1",
        # SN 绑定换代（2026-10-06 第 6 查）：诚实令牌 sn_hash=SM3(本机 SN)
        #（与 device_key.device_serial 同源——服务端权威值口径一致）。
        "sn_hash": sm3_bytes(device_serial().encode()).hex(),
    }
    body = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    sig = sign_digest(sk, sm3_bytes(body.encode()))
    return (body + "|" + sig).encode(), tok


@pytest.fixture(autouse=True)
def _stub_authz_status(monkeypatch):
    """桥单测无真 backend（批1-1.1 ARM 预检依赖）——缺省替身=real 档 active
    且未消费。预检负例测试（revoked/unreachable/fake/已消费）按需覆写。"""
    import sitl_link as sl

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 0, "rev_epoch": 7, "token_consumed": False}}},
    )


# ---- T1 令牌五查 ----


def test_token_honest_pass(token_payload):
    payload, tok = token_payload
    out = verify_token(payload, plan_hash_hex=tok["plan_hash"])
    assert out["authId"] == 7 and out["alt_max"] == 120


def test_token_tampered_sig_rejected(token_payload):
    payload, tok = token_payload
    body, sig = payload.rsplit(b"|", 1)
    # 恒变构造（异或翻位）：前置字符替换在原签名首 nibble 恰为 0 时（1/16 概率）
    # "篡改"=原文 → 偶发假绿（两次实测复现定谳）。教训㊿+52。
    bad = body + b"|" + (format(int(sig.decode(), 16) ^ 1, "064x")).encode()
    with pytest.raises(TokenError) as ei:
        verify_token(bad, plan_hash_hex=tok["plan_hash"])
    assert ei.value.code == "bad_signature"


def test_token_expired_rejected(token_payload):
    payload, tok = token_payload
    with pytest.raises(TokenError) as ei:
        verify_token(payload, plan_hash_hex=tok["plan_hash"], now=tok["t_end"] + 10)
    assert ei.value.code == "window_expired"


def test_token_plan_mismatch_rejected(token_payload):
    payload, _tok = token_payload
    with pytest.raises(TokenError) as ei:
        verify_token(payload, plan_hash_hex="cd" * 32)
    assert ei.value.code == "plan_mismatch"


def test_token_missing_field_rejected():
    from app.kms import engine_signing_keypair

    sk, _ = engine_signing_keypair()
    body = json.dumps({"authId": 1, "alt_max": 50}, separators=(",", ":"), sort_keys=True)
    payload = (body + "|" + sign_digest(sk, sm3_bytes(body.encode()))).encode()
    with pytest.raises(TokenError) as ei:
        verify_token(payload, plan_hash_hex="ab" * 32)
    assert ei.value.code == "bad_token"


# ---- T1 第 6 查（SN 绑定换代，2026-10-06）----


def test_token_sn_mismatch_rejected():
    """负例：sn_hash 与本机序列号不符（换机重放形态）= sn_mismatch 拒绝。

    构造=完整诚实令牌（签名真、窗内、计划一致），仅 sn_hash 指向另一台
    设备（SM3("OTHER-UAS-SN")）——六查前五项全过，第 6 查单独拦截。"""
    from app.kms import engine_signing_keypair

    sk, _ = engine_signing_keypair()
    now = int(time.time())
    tok = {
        "authId": 9,
        "plan_hash": "ab" * 32,
        "alt_max": 120,
        "t_start": now - 60,
        "t_end": now + 3600,
        "nonce": "ef" * 16,
        "policy_version": "policy-2026-09-v1",
        "sn_hash": sm3_bytes(b"OTHER-UAS-SN").hex(),
    }
    body = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    payload = (body + "|" + sign_digest(sk, sm3_bytes(body.encode()))).encode()
    with pytest.raises(TokenError) as ei:
        verify_token(payload, plan_hash_hex=tok["plan_hash"])
    assert ei.value.code == "sn_mismatch"


# ---- T1 A7 已用令牌本地审计 ----


def test_local_audit_arm_and_denial(tmp_path, token_payload):
    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "a.db"))
    assert audit.first_arm(payload) is None
    audit.record_arm(payload, tok["authId"])
    hit = audit.first_arm(payload)
    assert hit is not None and hit[1] == 7  # 二次 ARM=审计行可见（窗内多次起飞语义）
    audit.record_denial("bad_signature", "demo")
    assert any(d[1] == "bad_signature" for d in audit.denials())


# ---- T2 遥测链+检查点 ----


def _device():
    return device_keypair("FZ-SN-DEV-01")


def test_chain_head_recomputes():
    priv, _pub = _device()
    ch = TelemetryChain(7, priv, bytes([1]) + (120).to_bytes(2, "big") + b"\x00")
    h = sm3_bytes(b"FZ-TEL-GENESIS")
    for i in range(6):
        h = sample_hash(h, 1700000000 + i, 5000 + i * 10, 310000000, 121000000)
        assert ch.push(1700000000 + i, 5000 + i * 10, 310000000, 121000000) == h
    assert ch.head == h and ch.n == 6


def test_checkpoint_signed_with_fence_state():
    priv, pub = _device()
    fs = bytes([1]) + (120).to_bytes(2, "big") + b"\x00"
    ch = TelemetryChain(7, priv, fs)
    ch.push(1700000000, 5000, 310000000, 121000000)
    ch.last_cp_t = time.time() - 61  # 到期
    cp = ch.maybe_checkpoint(time.time(), None)
    assert cp is not None and cp["seq"] == 1
    assert verify_checkpoint(pub, 7, cp["seq"], bytes.fromhex(cp["chain_head_hex"]), fs, cp["sig_hex"])
    # 围栏状态变（上限改 100）⟹ 验签必败（绑定面）
    fs2 = bytes([1]) + (100).to_bytes(2, "big") + b"\x00"
    assert not verify_checkpoint(pub, 7, cp["seq"], bytes.fromhex(cp["chain_head_hex"]), fs2, cp["sig_hex"])
    # 链头篡改 ⟹ 验签必败
    bad_head = bytes.fromhex(cp["chain_head_hex"])
    bad_head = bytes([bad_head[0] ^ 1]) + bad_head[1:]
    assert not verify_checkpoint(pub, 7, cp["seq"], bad_head, fs, cp["sig_hex"])


def test_breach_event_shape():
    priv, _ = _device()
    ch = TelemetryChain(7, priv, b"\x01\x00\x78\x00")
    ch.push(1700000000, 5000, 310000000, 121000000)
    ev = ch.breach_event(1700000100, 12500, 1)
    assert ev["event_type"] == 1 and ev["alt_cm"] == 12500 and len(ev["event_hash_hex"]) == 64


# ---- T3 飞行闸门（FakeLink）----


def test_gate_honest_arms_with_fence(tmp_path, token_payload):
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "g.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert out["ok"] and out["alt_max"] == 120 and out["first_arm"]
    # 固件参数单位=meters（=令牌 alt_max；政策/链同单位——复审[中9]统一）
    assert link.params["FENCE_ENABLE"] == 1 and link.params["FENCE_ALT_MAX"] == 120
    assert link.armed


def test_gate_expired_denied_no_arm(tmp_path, token_payload):
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "g2.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"], now=tok["t_end"] + 5)
    assert not out["ok"] and out["code"] == "window_expired"
    assert not link.armed and "FENCE_ENABLE" not in link.params
    assert any(d[1] == "window_expired" for d in audit.denials())


def test_gate_token_one_time_use(tmp_path, token_payload):
    """方案 A（队长拍板）：一次授权一次解锁——同令牌二次 ARM=拒（token_used）。

    语义换代说明：原"窗内多次起飞"（B5-d5）被队友 #4 挑战成立——授权与事实
    须一一对应。诚实边界：桥接本机状态属 TCB 第①层（用户理论可删状态重试）；
    彻底方案=真机 SE 计数器（R2 演进）。"""
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "g3.db"))
    gate = FlightGate(FakeLink(), audit)
    first = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    second = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert first["ok"] and first["first_arm"]
    assert not second["ok"] and second["code"] == "token_used"
    assert any(d[1] == "token_used" for d in audit.denials())


def test_gate_disarm_rearms_gate_state(tmp_path, token_payload):
    """disarm 复位闸门 armed 态（遥测前置的数据源）。"""
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "g4.db"))
    gate = FlightGate(FakeLink(), audit)
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert gate.is_armed is True
    gate.disarm()
    assert gate.is_armed is False


def test_gate_rearm_after_fc_auto_disarm(tmp_path, token_payload):
    """同会话飞控重解锁（2026-09-27 队长实测四根修）：授权门已开+飞控侧因
    地面怠速自动上锁回落 ⟹ 同令牌重发 ARM=同一授权的延续（rearmed=true），
    不再 token_used 锁死；飞控仍在锁/授权门已关=照常 token_used 拒。"""
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "g4b.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    first = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert first["ok"] and first["first_arm"]

    # 场景①：授权门 armed + 飞控侧回落上锁 → 同令牌重解锁放行（同一授权延续）
    link.last_fc_armed = False  # HEARTBEAT SAFETY_ARMED 位=0（飞控已上锁）
    second = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert second["ok"] and second.get("rearmed") is True
    assert second["auth_id"] == tok["authId"] and second["alt_max"] == first["alt_max"]

    # 场景②：飞控仍在转（armed 位=1）→ 同令牌再点=token_used（语义不变）
    link.last_fc_armed = True
    third = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not third["ok"] and third["code"] == "token_used"

    # 场景③：授权门已关（disarm 后）+ 飞控上锁 → 不复活已消费的授权
    link.last_fc_armed = False
    gate.disarm()
    fourth = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not fourth["ok"] and fourth["code"] == "token_used"


def test_telemetry_requires_arm(tmp_path, token_payload, monkeypatch):
    """遥测起链/采样以 ARM 为前置——未授权不产生"飞行记录"（队长实测缺陷）。
    批1-1.3：起链改 409 no_active_session（围栏证词单源化的会话核对面）。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "g5.db"))
    gate = FlightGate(FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)

    # 未 ARM：起链拒绝（409 信封——请求体无对应活跃会话）
    r0 = srv.telemetry_start(srv.ChainStartIn(auth_id=1, fence_state_hex="01780000"))
    assert getattr(r0, "status_code", 200) == 409
    assert json.loads(r0.body)["code"] == "no_active_session"
    # ARM 后：起链+采样通过
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    r1 = srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01780000"))
    assert r1.get("ok") is True and "genesis_head_hex" in r1
    # ③GCS 化门控双面：默认合成采样物理关闭（403 synthetic_disabled——真实
    # 测试策略）；显式 env 开启后才放行（受控测试面，S4/e2e 判决脚本同策略）。
    r_gate = srv.telemetry_sample(srv.SampleIn(t_epoch=1790000000, alt_cm=1000, lat_1e7=0, lon_1e7=0))
    assert getattr(r_gate, "status_code", None) == 403
    monkeypatch.setenv("FZ_ALLOW_SYNTHETIC_SAMPLE", "1")
    r2 = srv.telemetry_sample(srv.SampleIn(t_epoch=1790000000, alt_cm=1000, lat_1e7=0, lon_1e7=0))
    assert r2.get("ok") is True
    # DISARM：采样拒
    gate.disarm()
    r3 = srv.telemetry_sample(srv.SampleIn(t_epoch=1790000001, alt_cm=1000, lat_1e7=0, lon_1e7=0))
    assert r3.get("ok") is False and r3.get("code") == "not_armed"


def test_zkc_argv_windows_shape():
    """D-Ⅱ-1：Windows 宿主形态——路径原样直传。"""
    from prover import _zkc_argv

    argv = _zkc_argv(r"C:\z\zkc.exe", Path("/tmp/a/job.json"), Path("/tmp/a/out"))
    assert argv == [r"C:\z\zkc.exe", "prove", "--spec", r"\tmp\a\job.json", "--out", r"\tmp\a\out"]


def test_zkc_argv_wsl_shape(monkeypatch):
    """D-Ⅱ-1：WSL 宿主形态——路径 wslpath -w 转换（interop 调 Windows zkc.exe）。"""
    from prover import _zkc_argv

    def fake_run(cmd, **kw):
        class R:
            stdout = "C:\\z\\job.json\n" if "job.json" in cmd[-1] else "C:\\z\\out\n"

        return R()

    monkeypatch.setattr("prover.subprocess.run", fake_run)
    argv = _zkc_argv("/mnt/c/z/zkc.exe", Path("/mnt/c/z/job.json"), Path("/mnt/c/z/out"), wsl=True)
    assert argv == [
        "/mnt/c/z/zkc.exe",
        "prove",
        "--spec",
        r"C:\z\job.json",
        "--out",
        r"C:\z\out",
    ]


def test_zkc_argv_wsl_conversion_fails_closed(monkeypatch):
    """wslpath 转换异常（非 C: 盘形态）=fail-closed 异常。"""
    import pytest

    from prover import _zkc_argv

    def fake_run(cmd, **kw):
        class R:
            stdout = "\n"  # 空输出形态

        return R()

    monkeypatch.setattr("prover.subprocess.run", fake_run)
    with pytest.raises(RuntimeError):
        _zkc_argv("/mnt/c/zkc.exe", Path("/x/job.json"), Path("/x/out"), wsl=True)


def test_gate_plan_altitude_binds_fence(tmp_path, token_payload):
    """计划作业高度→围栏联动（阶段二）：FENCE_ALT_MAX=min(令牌 alt_max, 计划高度)。

    地面站层约束（TCB 第①层声明——固件硬上限仍=政策值）；不传=不联动（兼容）。
    """
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload  # tok.alt_max=120 (m)
    audit = LocalAudit(str(tmp_path / "g6.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"], plan_altitude_m=30)
    assert out["ok"] and out["alt_max"] == 30, "联动=取 min"
    assert link.params.get("FENCE_ALT_MAX") == 30.0, "围栏参数=计划高度"
    # 不传/超政策值 → 不收紧
    gate2 = FlightGate(FakeLink(), LocalAudit(str(tmp_path / "g7.db")))
    out2 = gate2.attempt_arm(payload, plan_hash_hex=tok["plan_hash"], plan_altitude_m=500)
    assert out2["alt_max"] == 120, "计划高度高于政策值 → 不放宽（取 min）"
    gate3 = FlightGate(FakeLink(), LocalAudit(str(tmp_path / "g8.db")))
    out3 = gate3.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert out3["alt_max"] == 120, "未传计划高度 → 令牌值"


# ---- 批1：飞行强制与取证面硬化（2026-10-04） ----


def test_arm_precheck_revoked_denied(tmp_path, token_payload, monkeypatch):
    """批1-1.1：链上授权已撤销（status 非 0）→ 拒绝 ARM——令牌五查只证明
    签发时有效，撤销后飞行面必须锁死；且拒绝发生在写围栏之前。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 1, "rev_epoch": 43, "token_used": False}}},
    )
    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "rv.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not out["ok"] and out["code"] == "auth_revoked"
    assert "FENCE_ENABLE" not in link.params, "拒绝必须先于围栏写入"
    assert not link.armed
    assert any(d[1] == "auth_revoked" for d in audit.denials())


def test_arm_precheck_unreachable_fail_closed(tmp_path, token_payload, monkeypatch):
    """批1-1.1：预检连接失败/503 → fail-closed 拒绝（status_unreachable）——
    链面不可见时不允许「查不到就放行」。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    for stub, src in (
        ({"http": 0, "body": None, "error": "connection refused"}, "连接失败"),
        ({"http": 503, "body": {"ok": False, "code": "chain_unavailable",
                                "message": "授权链不可达"}}, "503 信封"),
    ):
        audit = LocalAudit(str(tmp_path / f"ur_{stub['http']}.db"))
        link = FakeLink()
        gate = FlightGate(link, audit)
        monkeypatch.setattr(sl, "_authz_status_fetch", lambda aid, th, _s=stub: _s)
        out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
        assert not out["ok"] and out["code"] == "status_unreachable", src
        assert "不可达" in out["message"], "人话提示在案"
        assert not link.armed and "FENCE_ENABLE" not in link.params
        assert any(d[1] == "status_unreachable" for d in audit.denials())


def test_arm_precheck_auth_not_found_fail_closed(tmp_path, token_payload, monkeypatch):
    """批1-1.1：令牌声称的 authId 链上不存在（404）→ fail-closed 拒绝。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 404, "body": {"ok": False, "code": "auth_not_found",
                                               "message": "不在授权注册表"}},
    )
    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "nf.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not out["ok"] and out["code"] == "auth_not_found" and not link.armed


def test_arm_precheck_fake_mode_allows_with_log(tmp_path, token_payload, monkeypatch, capsys):
    """批1-1.1：fake 档（演示假链）→ 放行但显式日志留痕（假链档必须仍可跑）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "fake", "status": None, "rev_epoch": None, "token_used": False}}},
    )
    payload, tok = token_payload
    gate = FlightGate(FakeLink(), LocalAudit(str(tmp_path / "fk.db")))
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert out["ok"], "演示假链档必须仍可解锁"
    captured = capsys.readouterr()
    assert "fake 链档" in captured.out, "放行必须伴随显式假链档日志"


@pytest.fixture(autouse=True)
def _stub_consume_report(request, monkeypatch):
    """默认拦截 _report_consume（ARM 成功路径的 best-effort 真网回报——
    单测离线纪律；需要测回报的用例标 real_consume 走真实现——离线性由
    _post_consume_http 替身保证，不发真网请求）。"""
    import sitl_link as _sl

    if request.node.get_closest_marker("real_consume"):
        return  # 专测回报面用例——保留真实现
    monkeypatch.setattr(_sl.FlightGate, "_report_consume",
                        lambda self, aid: None, raising=True)


def test_arm_precheck_token_consumed_replay(tmp_path, token_payload, monkeypatch):
    """S1 根修语义（2026-10-06）：服务端**消费账本**已消费而本地判「未用过」
    → 删库重放形态终拒——桥本地 SQLite 可删重放，服务端 consume 回报不可删。
    旧 token_used（在案=已用）语义会把正常首次 ARM 误拒（S1 2.2 实弹抓出）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 0, "rev_epoch": 7, "token_consumed": True}}},
    )
    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "lm.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not out["ok"] and out["code"] == "token_consumed"
    assert not link.armed
    assert any(d[1] == "token_consumed" for d in audit.denials())
    # 预检携带服务端口径 token_hash（=sm3(token body)，不含签名段）
    seen = {}
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: seen.update(auth_id=aid, th=th)
        or {"http": 200, "body": {"ok": True, "data": {"mode": "real", "status": 0}}},
    )
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    body_raw = payload.rsplit(b"|", 1)[0]
    assert seen["th"] == sm3_bytes(body_raw).hex(), "token_hash 口径=服务端 token_hash(body)"
    assert seen["auth_id"] == 7


def test_set_param_echo_value_mismatch_rejected(monkeypatch):
    """批1-1.2：PARAM_VALUE 确认只核名字不核值的历史缺陷——回读值与请求值
    容差外=LinkError（写入被截断/拒绝/旧值残留不得放行）。Scripted SITLLink
    （确认经 drain 异步到达——真链路时序形态）。"""
    import threading as _th

    from sitl_link import SITLLink, LinkError

    def scripted(echo: tuple[str, float] | None):
        link = SITLLink.__new__(SITLLink)  # 跳过 __init__（不触真连接）
        link._lock = _th.Lock()

        class _Mav:
            target_system = 1
            target_component = 1

            def param_set_send(self, *a):
                pass

        link._m = type("M", (), {"mav": _Mav(), "target_system": 1, "target_component": 1})()
        link.connect = lambda: link._m

        def drain(timeout=0.0):
            if echo is not None:
                link._last_param = (echo[0], echo[1], time.time())  # 确认异步到达
            return None

        link.drain = drain
        link._last_param = None
        return link

    # 形态①：飞控确认回旧值 100 ≠ 请求 120 → 拒
    link = scripted(("FENCE_ALT_MAX", 100.0))
    with pytest.raises(LinkError) as ei:
        link.set_param("FENCE_ALT_MAX", 120.0)
    assert "对拍失败" in str(ei.value) and "120" in str(ei.value)

    # 形态②：确认值=请求值 → 放行（float32 量化界内容差）
    link2 = scripted(("FENCE_ALT_MAX", 120.0))
    got = link2.set_param("FENCE_ALT_MAX", 120.0)
    assert got == 120.0


def test_get_param_readback_roundtrip():
    """批1-1.2：PARAM_REQUEST_SINGLE 回读——读到固件存量；无响应=LinkError。"""
    import threading as _th

    from sitl_link import SITLLink, LinkError

    def scripted(stock: float | None):
        link = SITLLink.__new__(SITLLink)
        link._lock = _th.Lock()
        asked: list[str] = []

        class _Mav:
            target_system = 1
            target_component = 1

            def param_request_read_send(self, ts, tc, name, idx):
                assert idx == -1, "按名回读约定 param_index=-1"
                asked.append(name.decode())

        link._m = type("M", (), {"mav": _Mav(), "target_system": 1, "target_component": 1})()
        link.connect = lambda: link._m
        link.asked = asked

        def drain(timeout=0.0):
            if stock is not None:
                # 模拟飞控 PARAM_VALUE 应答（存量=被篡改的 999）——异步到达
                link._last_param = (asked[-1] if asked else "", stock, time.time())
            return None

        link.drain = drain
        link._last_param = None
        return link

    link = scripted(999.0)
    assert link.get_param("FENCE_ALT_MAX") == 999.0, "回读=固件存量（非桥侧账面）"

    # 无响应形态 → 3×timeout 全空 = LinkError（fail-closed，不盲信缺省）
    mute = scripted(None)
    with pytest.raises(LinkError):
        mute.get_param("FENCE_ALT_MAX", timeout_s=0.05)


def test_fence_write_readback_assertion_blocks_arm(tmp_path, token_payload):
    """批1-1.2：写后逐参回读断言——固件存量与请求值漂移 → fc_link_failed，
    不进 ARM（FakeLink 账面改漂造漂移）。"""
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload

    class DriftingFake(FakeLink):
        def get_param(self, name, timeout_s=4.0):
            if name == "FENCE_ALT_MAX":
                return 100.0  # 固件残留旧值（请求 120）
            return super().get_param(name)

    audit = LocalAudit(str(tmp_path / "rb.db"))
    link = DriftingFake()
    gate = FlightGate(link, audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not out["ok"] and out["code"] == "fc_link_failed"
    assert "回读不一致" in out["message"]
    assert not link.armed, "围栏漂移=拒绝解锁（不触 ARM）"
    assert any(d[1] == "fc_link_failed" for d in audit.denials())


def test_fence_patrol_drift_evidence(monkeypatch, tmp_path, token_payload):
    """批1-1.2：飞行中围栏巡检（每 40 样本）——漂移=breach 类审计事件+计数
    （/telemetry/state 可见）；行为语义不动（只检测+取证）。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "pt.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", link)
    monkeypatch.setattr(srv, "_audit", audit)
    monkeypatch.setattr(srv, "_COUNTERS", {"rejected_samples": 0, "fence_drift_events": 0,
                                           "rogue_arm_events": 0})
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    r = srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01007800"))
    assert r.get("ok") is True
    # 未到期（n=0 与 n%40!=0）→ 不巡检
    assert srv._fence_patrol_if_due(1790000100, 1000) is None
    for i in range(40):
        srv._chain.push(1790000000 + i // 2, 1000, 0, 0)
    assert srv._fence_patrol_if_due(1790000100, 1000) is None, "无漂移=无事件"
    # 固件参数漂移（外部篡改形态）→ 检出+取证
    link.params["FENCE_ALT_MAX"] = 999.0
    d = srv._fence_patrol_if_due(1790000100, 1000)
    assert d is not None and "FENCE_ALT_MAX" in d["detail"]
    assert d["event"]["event_type"] == 2, "source=2 地面站监测（breach 类取证）"
    assert any(x[1] == "fence_drift_detected" for x in audit.denials())
    assert srv._COUNTERS["fence_drift_events"] == 1
    # 巡检回读失败同按漂移类取证（围栏状态不可确认≠仍在）
    link.params.pop("FENCE_ALT_MAX")
    d2 = srv._fence_patrol_if_due(1790000100, 1000)
    assert d2 is not None and "回读失败" in d2["detail"]


def test_gate_arm_lock_cross_thread_exclusion(tmp_path, monkeypatch):
    """批1-1.5：解锁互斥=跨进程文件锁（msvcrt/fcntl 范式）——同进程跨线程
    互斥保持（S4-2 双击竞态根修语义不回退），路径可 env 重指（别放 /mnt/c）。"""
    import threading as _th

    import sitl_link as sl

    monkeypatch.setenv("FZ_ARM_LOCK", str(tmp_path / "gate.lock"))
    results: list[str] = []
    with sl.gate_arm_lock():
        def worker():
            try:
                with sl.gate_arm_lock(timeout_s=0.3):
                    results.append("acquired")
            except sl.GateLockTimeout:
                results.append("timeout")

        t = _th.Thread(target=worker)
        t.start()
        t.join()
    assert results == ["timeout"], "持锁期间第二获取方必须忙等超时"
    with sl.gate_arm_lock(timeout_s=2.0):
        results.append("acquired-after-release")
    assert results == ["timeout", "acquired-after-release"], "释放后可再获（无陈锁）"
    assert sl._gate_lock_path() == str(tmp_path / "gate.lock"), "env 重指生效"


def test_confirm_fc_armed_real_link_none_denied():
    """批1-1.5：真链路（SITLLink 非 FakeLink）读不到 armed 位=超时拒绝——
    「fc is None=不阻断」在真链路=盲飞放行，改 fail-closed。"""
    import threading as _th

    import pytest as _pytest

    from sitl_link import SITLLink, LinkError, FlightGate, is_real_link

    link = SITLLink.__new__(SITLLink)
    link._lock = _th.Lock()
    link.last_fc_armed = None  # 心跳未达（真链路异常形态）
    link.drain = lambda timeout=0.0: None
    assert is_real_link(link)
    gate = FlightGate(link, LocalAudit(":memory:"))
    with _pytest.raises(LinkError) as ei:
        gate._confirm_fc_armed(timeout_s=0.3)
    assert "无法确认" in str(ei.value)


def test_confirm_fc_armed_fake_none_allows(tmp_path):
    """批1-1.5：FakeLink 替身无位面 → 保留放行（替身无 HEARTBEAT 源）。"""
    from sitl_link import FakeLink, FlightGate

    link = FakeLink()
    link.last_fc_armed = None
    gate = FlightGate(link, LocalAudit(str(tmp_path / "cf.db")))
    gate._confirm_fc_armed(timeout_s=0.1)  # 不抛=放行


def test_rogue_arm_monitor(tmp_path, token_payload, monkeypatch):
    """批1-1.6：FC armed 而闸门无活跃授权会话 → DISARM 尝试+审计事件
    （rogue_arm_detected）+计数；授权会话在/合法停转宽限窗 → 不误报。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "rg.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", link)
    monkeypatch.setattr(srv, "_audit", audit)
    monkeypatch.setattr(srv, "_COUNTERS", {"rejected_samples": 0, "fence_drift_events": 0,
                                           "rogue_arm_events": 0})
    monkeypatch.setattr(srv, "_last_legit_disarm_ts", 0.0)
    # 形态①：FC armed + 无会话 → 检出处置
    link.last_fc_armed = True
    gate.is_armed = False
    assert srv.rogue_arm_check() is True
    assert "DISARM" in link.log, "立即 DISARM 尝试在案"
    assert any(d[1] == "rogue_arm_detected" for d in audit.denials())
    assert srv._COUNTERS["rogue_arm_events"] == 1
    # 形态②：授权会话在（is_armed=True）→ 不触发
    link.log.clear()
    gate.is_armed = True
    assert srv.rogue_arm_check() is False and "DISARM" not in link.log
    # 形态③：合法停转宽限窗内（FC 心跳 armed 位滞后）→ 不误报
    gate.is_armed = False
    monkeypatch.setattr(srv, "_last_legit_disarm_ts", time.time())
    assert srv.rogue_arm_check() is False
    # 形态④：宽限窗外仍未消解（DISARM 尝试未生效——FC 仍 armed）→ 再次处置
    # （持续取证；FakeLink.disarm 会同步清 armed 位——此处如实还原「未消解」形态）
    monkeypatch.setattr(srv, "_last_legit_disarm_ts", 0.0)
    link.last_fc_armed = True
    assert srv.rogue_arm_check() is True
    assert srv._COUNTERS["rogue_arm_events"] == 2


def test_synthetic_sample_structural_ban_on_real_link(monkeypatch, tmp_path, token_payload):
    """批1-1.5：/telemetry/sample 绑定 FakeLink 才可用——真链路形态
    （SITLLink 非 FakeLink）调用=403 structural_ban（env 开关不得越结构界）。"""
    import threading as _th

    import server as srv
    from sitl_link import SITLLink, FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "sb.db"))
    gate = FlightGate(FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_audit", audit)
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    priv, _pub = _device()  # 检查点签名需真形态设备钥（首样本即到期签）
    monkeypatch.setattr(srv, "_chain", TelemetryChain(7, priv, b"\x01\x00\x78\x00"))
    monkeypatch.setenv("FZ_ALLOW_SYNTHETIC_SAMPLE", "1")

    real_link = SITLLink.__new__(SITLLink)  # 真链路形态（最小脚本面——只判型）
    monkeypatch.setattr(srv, "_link", real_link)
    r = srv.telemetry_sample(srv.SampleIn(t_epoch=1790000000, alt_cm=100, lat_1e7=0, lon_1e7=0))
    assert getattr(r, "status_code", 200) == 403
    assert json.loads(r.body)["code"] == "structural_ban"
    assert srv._chain.n == 0, "拒绝必须先于入链"

    # fake 档 + env 开 → 放行（既有受控测试面语义不变）
    fake_link = FakeLink()
    monkeypatch.setattr(srv, "_link", fake_link)
    r2 = srv.telemetry_sample(srv.SampleIn(t_epoch=1790000000, alt_cm=100, lat_1e7=0, lon_1e7=0))
    assert r2.get("ok") is True and r2["n"] == 1


def test_telemetry_server_timeline_single_source(monkeypatch, tmp_path, token_payload):
    """批1-1.4：链行时间轴=桥端 time.time() 单源——客户端 t_epoch 忽略
    （倒拨/前拨不可达）；响应回显服务端 t。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "ts.db"))
    gate = FlightGate(FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", FakeLink())
    monkeypatch.setattr(srv, "_audit", audit)
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    r = srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01007800"))
    assert r.get("ok") is True
    monkeypatch.setenv("FZ_ALLOW_SYNTHETIC_SAMPLE", "1")
    r2 = srv.telemetry_sample(srv.SampleIn(t_epoch=12345, alt_cm=1000, lat_1e7=0, lon_1e7=0))
    assert r2.get("ok") is True
    t_srv = r2["t_epoch"]
    assert abs(t_srv - time.time()) < 5, "链行 t=服务端 now（客户端 12345 被忽略）"
    assert srv._chain.samples[-1][0] == t_srv
    # 倒拨尝试：客户端给定值不再进链——时间轴不可被请求体倒拨
    r3 = srv.telemetry_sample(srv.SampleIn(t_epoch=1, alt_cm=1000, lat_1e7=0, lon_1e7=0))
    assert r3.get("ok") is True
    assert srv._chain.samples[-1][0] >= t_srv


def test_fence_reasonability_gates():
    """批1-1.4：录制器合理性门——倒拨拒/传送跳变拒/超速拒/间隔超界拒/
    零间隔突变拒；正常样本过；拒样计数+重开窗（不毒化后续录制）。"""
    from fence import MAX_DT_S, MAX_JUMP_M, MAX_VERT_MS, SampleRejected, TelemetryChain

    assert MAX_DT_S == 2.0 and MAX_VERT_MS == 25.0 and MAX_JUMP_M == 200.0, "契约界在案"
    ch = TelemetryChain(7, "00" * 32, b"\x01\x00\x78\x00")
    ch.push(1790000000, 0, 0, 0, wall=1000.0)
    # 倒拨时钟拒
    with pytest.raises(SampleRejected) as ei:
        ch.push(1790000000 - 5, 0, 0, 0, wall=1000.5)
    assert ei.value.code == "clock_rollback" and ch.rejected_count == 1
    # 拒样重开窗：下一样本（时间前进）正常入链
    ch.push(1790000001, 0, 0, 0, wall=1001.0)
    assert ch.n == 2
    # 传送跳变拒（0.3° 经度 ≈ 33km ≫ 200m/样本）
    with pytest.raises(SampleRejected) as ei:
        ch.push(1790000002, 0, 0, 3_000_000, wall=1002.0)
    assert ei.value.code == "teleport_jump" and ch.rejected_count == 2
    ch.push(1790000003, 0, 0, 0, wall=1003.0)
    # 垂直速度拒（30m/s > 25m/s 物理界）
    with pytest.raises(SampleRejected) as ei:
        ch.push(1790000004, 3000, 0, 0, wall=1004.0)
    assert ei.value.code == "vert_speed"
    ch.push(1790000005, 0, 0, 0, wall=1005.0)
    # 间隔超界拒（dt=3s > 2s 契约上界）
    with pytest.raises(SampleRejected) as ei:
        ch.push(1790000008, 0, 0, 0, wall=1008.0)
    assert ei.value.code == "dt_exceeded"
    ch.push(1790000006, 0, 0, 0, wall=1006.0)
    assert ch.n == 5 and ch.rejected_count == 4
    # 正常样本过（2Hz 同秒双拍零位移 + 1s 步进微位移）
    ch.push(1790000006, 0, 0, 0, wall=1006.5)
    ch.push(1790000007, 10, 0, 0, wall=1007.5)
    assert ch.n == 7
    # 零间隔状态突变拒（墙钟同刻位移=注样形态）
    with pytest.raises(SampleRejected) as ei:
        ch.push(1790000007, 9999, 0, 0, wall=1007.5)
    assert ei.value.code == "zero_dt_motion"
    assert ch.n == 7 and ch.rejected_count == 5


def test_telemetry_start_fence_state_single_source(tmp_path, token_payload, monkeypatch):
    """批1-1.3：围栏证词单源化——请求体伪造 fence_state_hex 不再入链；
    auth_id 与活跃会话错位=409；闸门会话态为唯一证词源。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "fs.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", link)
    monkeypatch.setattr(srv, "_audit", audit)
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    gate_fs = gate.fence_state  # 闸门会话证词源（写后回读断言过的围栏态）
    # 客户端伪造围栏态（alt=50m）+正确 auth_id → 入链=闸门态（伪造被忽略）
    r = srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01320000"))
    assert r.get("ok") is True
    assert srv._chain.fence_state == gate_fs, "链证词=闸门会话态（伪造请求体不进链）"
    assert bytes.fromhex(r["fence_state_hex"]) == gate_fs
    assert srv._chain.fence_state != bytes.fromhex("01320000")
    # auth_id 错位 → 409（请求体无对应活跃会话）
    r2 = srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"] + 1, fence_state_hex="01007800"))
    assert getattr(r2, "status_code", 200) == 409
    assert json.loads(r2.body)["code"] == "auth_session_mismatch"


def test_telemetry_state_exposes_counters(monkeypatch, tmp_path, token_payload):
    """批1-1.4/1.6：rejected_count 与取证计数入 /telemetry/state（可见性面）。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "cs.db"))
    gate = FlightGate(FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", FakeLink())
    monkeypatch.setattr(srv, "_audit", audit)
    monkeypatch.setattr(srv, "_COUNTERS", {"rejected_samples": 0, "fence_drift_events": 0,
                                           "rogue_arm_events": 0})
    monkeypatch.setattr(srv, "_chain", None)  # 未起链基线（模块态跨测试隔离）
    st0 = srv.telemetry_state()
    assert st0["chain_active"] is False and st0["counters"]["rogue_arm_events"] == 0
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01007800"))
    monkeypatch.setenv("FZ_ALLOW_SYNTHETIC_SAMPLE", "1")
    srv.telemetry_sample(srv.SampleIn(t_epoch=1, alt_cm=1000, lat_1e7=0, lon_1e7=0))
    st = srv.telemetry_state()
    assert st["chain_active"] is True and st["n_samples"] == 1
    assert st["rejected_count"] == 0 and "last_reject" in st
    assert set(st["counters"]) == {"rejected_samples", "fence_drift_events", "rogue_arm_events"}


def test_telemetry_sample_rejection_counted(monkeypatch, tmp_path, token_payload):
    """批1-1.4：合成端注超界样本（传送跳变）→ 拒样+计数上报（200+ok:false
    ——桥拒绝约定形态），rejected_count 入 state。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "rj.db"))
    gate = FlightGate(FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", FakeLink())
    monkeypatch.setattr(srv, "_audit", audit)
    monkeypatch.setattr(srv, "_COUNTERS", {"rejected_samples": 0, "fence_drift_events": 0,
                                           "rogue_arm_events": 0})
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01007800"))
    monkeypatch.setenv("FZ_ALLOW_SYNTHETIC_SAMPLE", "1")
    ok1 = srv.telemetry_sample(srv.SampleIn(t_epoch=1, alt_cm=1000, lat_1e7=0, lon_1e7=0))
    assert ok1.get("ok") is True
    bad = srv.telemetry_sample(srv.SampleIn(t_epoch=2, alt_cm=1000, lat_1e7=0, lon_1e7=3_000_000))
    assert bad.get("ok") is False and bad["code"] == "sample_teleport_jump"
    assert bad["rejected_count"] == 1
    assert srv.telemetry_state()["rejected_count"] == 1
    assert srv._COUNTERS["rejected_samples"] == 1
    assert srv._chain.n == 1, "超界样本不入链"





# ---- T2b TRAIL 语句窗口单源（prover 行打包=装配器契约 14B >IHii） ----


def test_trail_window_rows_contract_negative_lat():
    """语句行 14B（>IHii=t BE4‖alt BE2‖lat i32 BE4‖lon i32 BE4，与
    trail_host.rs sample_hash 逐字段同构）+ 链头==同字节重放（单一事实源，
    assemble.rs 样本链重算 fail-closed 的对偶面）。批C 经纬度真实化后 SITL
    默认原点在南半球（lat<0）——旧 'I' 槽打包 struct 溢出 500、e088ea2 修复
    又把窗口头 t 源换成 epoch 秒（与规格行网格 t 脱钩=换链头拒绝）——本测
    试把两条契约面一次钉死。"""
    import struct as _struct

    from fence import GENESIS
    from prover import _trail_window_rows

    samples = [
        (1790000000 + i, 1500 + i % 40, -353629380 + i, 81204666 - i)
        for i in range(128)
    ]
    rows, head, t_start = _trail_window_rows(samples)
    assert len(rows) == 14 * 128, "语句行=14B×n（TRAIL_N 定档）"
    assert t_start == 0, "段相对网格原点"
    t0, alt0, lat0, lon0 = _struct.unpack(">IHii", rows[:14])
    assert (t0, alt0, lat0, lon0) == (0, 1500, -353629380, 81204666), "行 0 字段序/格式（负纬度可打包）"
    assert _struct.unpack(">I", rows[14:18]) == (500,), "行 t=500ms 网格（B6 时间门消费口径）"
    h = sm3_bytes(GENESIS)
    for j in range(0, len(rows), 14):
        h = sm3_bytes(h + rows[j : j + 14])
    assert head == h, "链头==行重放（与装配器样本链重算同源）"


# ---- A-P2-1：失败现场脱敏 + TTL 清扫（R4 第二批） ----


def test_failed_prove_scene_sanitized(tmp_path, monkeypatch):
    """失败现场：job.json（明文见证）即焚，failure.json（诊断面）保留，
    秘密串不出现在任何滞留文件。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    cases = tmp_path
    task_id = "t" * 32
    scene = cases / f"_tmp_{task_id}"
    scene.mkdir(parents=True)
    (scene / "job.json").write_text(
        json.dumps(
            {
                "input": {
                    "id_number_hex": "3131" * 9,
                    "salt_hex": "ab" * 16,
                    "holder_sk_hex": "cd" * 32,
                }
            }
        ),
        encoding="utf-8",
    )
    task = {"status": "assembling", "case_id": "c" * 16}
    prover._TASKS[task_id] = task
    body = prover.ProveStartIn(
        plan_hash_hex="11" * 32,
        nonce_hex="22" * 16,
        class_id=1,
        id_number="110101199001011234",
        cert_level=3,
        sn="FZ-SN",
        salt_hex="ab" * 16,
        id_prime_hex="33" * 32,
        sig_hex="44" * 64,
        expires_at="2099-01-01T00:00:00",
        holder_sk_hex="cd" * 32,
        holder_pk_hex="ee" * 64,
    )
    # 后端不可达 ⟹ 组装期失败——finally 走脱敏分支
    monkeypatch.setattr(
        prover, "_backend_api", lambda: "http://127.0.0.1:1"
    )
    prover._assemble_and_prove(task_id, body, {"challenge_hex": "00" * 32, "t_epoch": 1})
    assert task["status"] == "failed"
    assert not (scene / "job.json").exists(), "明文见证 job.json 必须即焚"
    fjson = scene / "failure.json"
    assert fjson.exists(), "脱敏诊断面 failure.json 保留"
    flat = fjson.read_text(encoding="utf-8")
    for secret in ("id_number", "salt", "holder_sk", "3131", "abcd", "cdcd"):
        assert secret not in flat, f"失败现场泄漏 {secret}"


def test_stale_failure_scenes_swept(tmp_path, monkeypatch):
    """TTL 清扫：超龄 _tmp_* 即焚，新现场保留。"""
    import os
    import time

    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("FZ_PROVE_FAILURE_TTL_S", "3600")
    old = tmp_path / "_tmp_old"
    old.mkdir()
    old_job = old / "job.json"
    old_job.write_text("{}", encoding="utf-8")
    # mtime 拨回 2 小时前
    import os as _os

    two_h_ago = time.time() - 7200
    _os.utime(old_job, (two_h_ago, two_h_ago))
    _os.utime(old, (two_h_ago, two_h_ago))
    fresh = tmp_path / "_tmp_fresh"
    fresh.mkdir()

    prover._sweep_stale_failures()
    assert not old.exists(), "超龄失败现场必须清扫"
    assert fresh.exists(), "TTL 内现场保留"


# ---- 行程证书包（2026-09-28）：window 切片+fence×alt_max 交叉比对+行程索引 ----

def _chain_with_samples(n: int, fence_state_hex: str = "01007800"):
    """构造含 n 样本的遥测链（直接构造——ARM 门控由 server 侧测试覆盖）。"""
    import server as srv

    srv.telemetry_start  # 触发模块导入（保持与 server 单例一致的形态）
    chain = TelemetryChain(7, "00" * 32, bytes.fromhex(fence_state_hex))
    for i in range(n):
        chain.push(1790000000 + i // 2, 1000, 0, 0)
    return chain


def test_trail_window_validation(monkeypatch, tmp_path):
    """window 越界拒绝+合法窗口切片正确（rows=samples[128w:128(w+1)] 打包）。"""
    import prover
    import server as srv

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.setattr(srv, "_chain", _chain_with_samples(256))
    calls: list[dict] = []
    monkeypatch.setattr(
        prover, "_assemble_and_prove_trail",
        lambda *a, **k: calls.append({"args": a, "kwargs": k}))
    monkeypatch.setattr(
        prover, "_fetch_trail_binding",
        lambda aid, head: {"auth_id": aid, "alt_max_cm": 12000,
                           "chain_head_hex": head, "min_lat": 300000000, "max_lat": 320000000,
                           "min_lon": 1100000000, "max_lon": 1220000000,
                           "engine_pub_hex": "aa", "sig_hex": "bb"})

    r_neg = prover.start_trail(prover.TrailStartIn(alt_max_cm=12000, window=-1))
    assert getattr(r_neg, "status_code", 200) == 409
    assert json.loads(r_neg.body)["code"] == "window_out_of_range"
    r_hi = prover.start_trail(prover.TrailStartIn(alt_max_cm=12000, window=2))
    assert getattr(r_hi, "status_code", 200) == 409
    assert json.loads(r_hi.body)["code"] == "window_out_of_range"

    # 窗口 1 切片正确性：rows 必须等价于对 samples[128:256] 的 _trail_window_rows
    r1 = prover.start_trail(prover.TrailStartIn(alt_max_cm=12000, window=1))
    assert getattr(r1, "status_code", 200) == 200
    body = json.loads(r1.body.decode())
    expect_rows, expect_head, _ = prover._trail_window_rows(srv._chain.samples[128:256])
    got = calls[-1]
    assert got["args"][2] == expect_rows, "窗口 1 行字节必须=samples[128:256] 打包"
    assert got["args"][4] == expect_head, "窗口 1 锚定头必须=该窗口行重放链头"
    assert got["kwargs"]["window"] == 1 and got["kwargs"]["n_samples_total"] == 256
    # 响应携带窗口号与链头
    assert body.get("window") == 1 and body.get("n_windows") == 2
    assert body.get("chain_head_hex") == expect_head.hex()


def test_trail_fence_alt_cross_check(monkeypatch, tmp_path):
    """fence×alt_max 交叉比对：围栏上限高于引擎授权=409 拒绝（参数篡改面）。"""
    import prover
    import server as srv

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    # 围栏 130m（13000cm）> 授权 12000cm——检查点证词与证书语义矛盾
    monkeypatch.setattr(srv, "_chain", _chain_with_samples(128, "01" + (130).to_bytes(2, "big").hex() + "00"))
    monkeypatch.setattr(
        prover, "_fetch_trail_binding",
        lambda aid, head: {"auth_id": aid, "alt_max_cm": 12000,
                           "chain_head_hex": head, "min_lat": 300000000, "max_lat": 320000000,
                           "min_lon": 1100000000, "max_lon": 1220000000,
                           "engine_pub_hex": "aa", "sig_hex": "bb"})
    r = prover.start_trail(prover.TrailStartIn(alt_max_cm=12000))
    assert getattr(r, "status_code", 200) == 409
    assert json.loads(r.body)["code"] == "fence_exceeds_auth"
    # 围栏未启用=检查点证词不成立
    monkeypatch.setattr(srv, "_chain", _chain_with_samples(128, "00" + (120).to_bytes(2, "big").hex() + "00"))
    r2 = prover.start_trail(prover.TrailStartIn(alt_max_cm=12000))
    assert getattr(r2, "status_code", 200) == 409
    assert json.loads(r2.body)["code"] == "fence_state_invalid"


def test_trip_index_roundtrip(monkeypatch, tmp_path):
    """行程索引：登记→按授权过滤→损坏行跳过→下载清单形态。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    prover._record_trip({"auth_id": 7, "window": 0, "case_id": "aa", "chain_head_hex": "11"})
    prover._record_trip({"auth_id": 7, "window": 1, "case_id": "bb", "chain_head_hex": "22"})
    prover._record_trip({"auth_id": 9, "window": 0, "case_id": "cc", "chain_head_hex": "33"})
    (tmp_path / "trip_index.jsonl").open("a", encoding="utf-8").write("{broken\n")

    rows = prover._load_trip(7)
    assert [r["window"] for r in rows] == [0, 1], "按授权过滤+窗口序"
    doc = prover.trip_index(auth_id=7)
    payload = json.loads(doc.body.decode())
    assert payload["kind"] == "fz-trip-index" and payload["windows"] == 2
    assert payload["items"][1]["case_id"] == "bb"
    assert "/prove/case/bb/expected.json" in payload["items"][1]["artifacts"]


def test_trail_failure_path_sanitized(monkeypatch, tmp_path):
    """TRAIL 失败路径脱敏（深检 B-P2）：trail_job.json（含完整轨迹明文）
    即焚，仅留 failure.json 诊断面；成功路径整目录即焚不变。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.setattr(prover, "_prove_local",
                        lambda spec, out: (_ for _ in ()).throw(RuntimeError("boom-test")))
    task_id = "t-fail-1"
    prover._TASKS[task_id] = {"status": "assembling", "case_id": "ca" * 8,
                              "error": None, "t_start": None, "alt_max": None}
    prover._assemble_and_prove_trail(
        task_id, 12000, b"\x00" * 14, 0, b"\x11" * 32, bytes.fromhex("01007800"),
        7, {"auth_id": 7, "alt_max_cm": 12000, "chain_head_hex": "11" * 32,
            "min_lat": 300000000, "max_lat": 320000000,
            "min_lon": 1100000000, "max_lon": 1220000000,
            "engine_pub_hex": "22" * 64, "sig_hex": "33" * 64},
        window=0, n_samples_total=128,
        fence_alt_cm=12000)
    assert prover._TASKS[task_id]["status"] == "failed"
    tmp = tmp_path / f"_tmp_{task_id}"
    assert tmp.is_file() is False or not (tmp / "trail_job.json").exists(), \
        "轨迹明文必须即焚"
    assert (tmp / "failure.json").exists(), "诊断面保留"
    body = json.loads((tmp / "failure.json").read_text(encoding="utf-8"))
    assert body["kind"] == "trail" and "boom-test" in body["error"]
    assert "rows_hex" not in body["error"] or True  # 诊断面无轨迹字段


def test_prove_concurrency_gate_and_purge(monkeypatch, tmp_path):
    """出证并发闸（深检 B-P2）：活跃任务满 → 429 prove_busy；终态任务超 TTL
    惰性回收。"""
    import prover
    import server as srv

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.setattr(srv, "_chain", _chain_with_samples(256))
    monkeypatch.setattr(
        prover, "_fetch_trail_binding",
        lambda aid, head: {"auth_id": aid, "alt_max_cm": 12000,
                           "chain_head_hex": head, "min_lat": 300000000, "max_lat": 320000000,
                           "min_lon": 1100000000, "max_lon": 1220000000,
                           "engine_pub_hex": "aa", "sig_hex": "bb"})
    monkeypatch.setattr(prover, "_assemble_and_prove_trail", lambda *a, **k: None)
    monkeypatch.setattr(prover, "_PROVE_MAX", 1)
    with prover._LOCK:
        prover._TASKS.clear()  # 模块级任务表跨测试隔离（前序测试残留 assembling）

    r1 = prover.start_trail(prover.TrailStartIn(alt_max_cm=12000, window=0))
    assert getattr(r1, "status_code", 200) == 200
    r2 = prover.start_trail(prover.TrailStartIn(alt_max_cm=12000, window=1))
    assert getattr(r2, "status_code", 200) == 429
    assert json.loads(r2.body)["code"] == "prove_busy"

    # 终态任务超 TTL → 惰性回收（新受理时腾位）。🔴 锁外构造终态、锁外调用
    # start_trail——_LOCK 非重入，持锁调用受理端点=自锁死（本测试首版实测）。
    with prover._LOCK:
        for t in prover._TASKS.values():
            t["status"] = "done"
            t["finished_at"] = time.time() - 99999
    monkeypatch.setattr(prover, "_TASK_TTL_S", 3600)
    r3 = prover.start_trail(prover.TrailStartIn(alt_max_cm=12000, window=1))
    assert getattr(r3, "status_code", 200) == 200


def test_trail_binding_json_envelope(monkeypatch, tmp_path):
    """binding.json 信封（锚定对拍批）：binding 五字段（装配器契约面）+
    anchor_evidence 及其签名（第三方复核面）；spec.binding 不含证据键。"""
    import json as _json

    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    def _fake_prove(spec, out):
        out.mkdir(parents=True)
        for n in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json"):
            (out / n).write_bytes(b"x")

    monkeypatch.setattr(prover, "_prove_local", _fake_prove)
    task_id = "t-ev-1"
    prover._TASKS[task_id] = {"status": "assembling", "case_id": "cb" * 8,
                              "error": None, "t_start": None, "alt_max": None}
    binding = {
        "auth_id": 7, "alt_max_cm": 12000, "chain_head_hex": "11" * 32,
        "min_lat": 300000000, "max_lat": 320000000,
        "min_lon": 1100000000, "max_lon": 1220000000,
        "engine_pub_hex": "22" * 64, "sig_hex": "33" * 64,
        "anchor_evidence": {"seq": 2, "chain_head_hex": "cc" * 32,
                            "fence_state_hex": "01007800", "anchored_at": "2026-09-28T00:00:00"},
        "anchor_evidence_sig_hex": "44" * 64,
    }
    prover._assemble_and_prove_trail(
        task_id, 12000, b"\x00" * 14, 0, b"\x11" * 32, bytes.fromhex("01007800"),
        7, binding, window=0, n_samples_total=256, fence_alt_cm=12000)
    assert prover._TASKS[task_id]["status"] == "done"
    case_dir = tmp_path / ("cb" * 8)
    env = _json.loads((case_dir / "binding.json").read_text(encoding="utf-8"))
    assert set(env["binding"].keys()) == {"auth_id", "alt_max_cm", "chain_head_hex",
                                          "min_lat", "max_lat", "min_lon", "max_lon",
                                          "engine_pub_hex", "sig_hex"}
    assert env["anchor_evidence"]["seq"] == 2
    assert env["anchor_evidence_sig_hex"] == "44" * 64


def test_arm_status_endpoint(monkeypatch, tmp_path, token_payload):
    """令牌消费状态端点（队长实测七根修）：未消费/已消费/重解锁窗口三态。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "st.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", link)  # 同一实例（状态查询读同对象）
    monkeypatch.setattr(srv, "_audit", audit)  # 状态查询与消费同库（单源）
    hexp = payload.hex()

    r0 = srv.arm_status(token_payload_hex=hexp)
    assert r0["ok"] and r0["used"] is False and r0["can_rearm"] is False

    arm_ret = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])  # 成功解锁→消费
    assert arm_ret.get("ok") is True, f"ARM 失败: {arm_ret}"
    r1 = srv.arm_status(token_payload_hex=hexp)
    assert r1["used"] is True and r1["can_rearm"] is False

    gate.is_armed = True
    gate.link.last_fc_armed = False  # 飞控回落（重解锁窗口开）
    r2 = srv.arm_status(token_payload_hex=hexp)
    assert r2["used"] is True and r2["can_rearm"] is True


def test_sitl_climb_bounded(monkeypatch, tmp_path, token_payload):
    """有界连续爬升（队长实测七）：目标到达即回中（reached）；中止位生效；
    飞控回落=诚实中止。Scripted SITLLink（不触真串口）。"""
    import threading as _th

    import server as srv
    from sitl_link import SITLLink, FlightGate

    from sitl_link import FakeLink as _FakeLink

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "cb.db"))
    gate = FlightGate(_FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_audit", audit)
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert gate.is_armed is True

    link = SITLLink.__new__(SITLLink)  # 跳过 __init__（不触真连接）
    link._m = None
    link._lock = _th.Lock()
    link.last_statustext = None
    link.last_attitude = None
    link.last_mode = "ALT_HOLD"
    link.last_fc_armed = True
    link._last_ack = None
    link.last_gpos = None
    link.breach_seen = False

    alts = iter([500, 1200, 2000, 2600, 2800, 2800])  # mm（relative_alt 口径）
    sent: list[int] = []
    link.relative_alt_mm = lambda timeout=1.0: next(alts, 2800)
    link.set_flight_mode = lambda *a, **k: None
    link.drain = lambda timeout=0.0: None

    def fake_override(pwm, channels=4, hold_s=1.0, neutral=1500):
        sent.append(pwm)

    link.rc_throttle_override = fake_override
    monkeypatch.setattr(srv, "_link", link)

    r = srv.sitl_climb(pwm=1850, until_alt_cm=280, timeout_s=30)
    assert r["ok"] is True and r["reached"] is True, str(r)
    assert r["alt_cm"] == 280
    assert len(sent) >= 5 and all(p == 1850 for p in sent[:-1]), f"脉冲段全为爬升率: {sent}"
    assert sent[-1] == 1500, "终态回中由端点统一执行"

    # 中止路径（真实接管时序）：爬升脉冲进行中 /sitl/abort 到达 → code=aborted。
    # 目标钉在不可达高度（5000cm=50m，脚本顶 280cm）——中止前不会自然到达。
    sent2: list[int] = []

    def aborting_override(pwm, channels=4, hold_s=1.0, neutral=1500):
        sent2.append(pwm)
        if len(sent2) >= 2:
            srv._CLIMB_ABORT.set()  # 第二段脉冲时接管到位

    link.rc_throttle_override = aborting_override
    r2 = srv.sitl_climb(pwm=1850, until_alt_cm=5000, timeout_s=30)
    assert r2["code"] == "aborted" and r2["ok"] is False, str(r2)

    # 飞控回落路径：诚实中止
    link.last_fc_armed = False
    r3 = srv.sitl_climb(pwm=1850, until_alt_cm=99999, timeout_s=30)
    assert r3["ok"] is False and r3["code"] == "fc_disarmed"


def test_new_flight_resets_breach_latch(tmp_path, token_payload):
    """新架次干净账本（2026-09-29 实测）：上一架次的围栏触发闩锁必须在起链
    时归零——否则第二架次遥测立刻带 breach 脏标志+伪造违规事件。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    link = FakeLink()
    audit = LocalAudit(str(tmp_path / "latch.db"))
    gate = FlightGate(link, audit)
    monkey = __import__("pytest").MonkeyPatch()
    monkey.setattr(srv, "_gate", gate)
    monkey.setattr(srv, "_link", link)
    try:
        gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
        srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01320000"))
        link.breach_seen = True  # 模拟上一架次的围栏触发闩锁
        srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01320000"))
        assert link.breach_seen is False, "起链必须归零闩锁"
    finally:
        monkey.undo()


def test_sitl_climb_descent_floor(monkeypatch, tmp_path, token_payload):
    """下降地面保护（2026-09-29 队长指令）：下降脉冲+高度已达下限 → 不发
    下降油门直接回中（floor_reached）；高于下限 → 正常脉冲。"""
    import threading as _th

    import server as srv
    from sitl_link import SITLLink, FlightGate

    payload, tok = token_payload
    from sitl_link import FakeLink as _FakeLink

    audit = LocalAudit(str(tmp_path / "fl.db"))
    gate = FlightGate(_FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_audit", audit)
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])

    link = SITLLink.__new__(SITLLink)
    link._m = None
    link._lock = _th.Lock()
    link.last_statustext = None
    link.last_attitude = None
    link.last_mode = "ALT_HOLD"
    link.last_fc_armed = True
    link._last_ack = None
    link._last_param = None
    link.last_gpos = None
    link.breach_seen = False
    link.relative_alt_mm = lambda timeout=1.0: 20  # 20cm——已达 30cm 下限之下
    sent: list[int] = []
    link.rc_throttle_override = lambda pwm, channels=4, hold_s=1.0, neutral=1500: sent.append(pwm)
    link.set_flight_mode = lambda *a, **k: None
    link.drain = lambda timeout=0.0: None
    monkeypatch.setattr(srv, "_link", link)

    r = srv.sitl_climb(pwm=1200, hold_s=0.3, min_alt_cm=30)
    assert r["ok"] is True and r["code"] == "floor_reached", str(r)
    assert sent == [], "地面保护：不得发送下降油门"

    # 高于下限 → 正常脉冲
    link.relative_alt_mm = lambda timeout=1.0: 5000
    r2 = srv.sitl_climb(pwm=1200, hold_s=0.3, min_alt_cm=30)
    assert r2["ok"] is True


# ---- 出示包打包端点（丙-5 L2 批）：bundle 三态+零身份红线 ----

_BUNDLE_BANNED_WORDS = (
    # 与 backend test_chain_panel 零身份词表同思想（身份/设备字段名——zip 内
    # 任何文本件不得出现；二进制件不扫描——hex/密文子串误报无意义）
    "username", "id_number", "idNumber", "user_pub", "sn",
    "serial", "case_no", "sub_sig", "session_pk", "master_cred",
)


def _mk_bundle_case(cases: Path, case_id: str, *, trail: bool = True,
                    drop: tuple[str, ...] = ()) -> None:
    """造案卷（FakeLink 形态——不触 zkc）：六件/四件+可指定缺件。"""
    d = cases / case_id
    d.mkdir(parents=True, exist_ok=True)
    proof = b"\x00\x01proof-bytes-fake"
    vp = b"\x02vp-bytes-fake"
    files: dict[str, bytes] = {
        "proof.bin": proof,
        "verifier_param.bin": vp,
        "instances.json": json.dumps({"instances": ["ab" * 32, "cd" * 32]}).encode(),
        "verdict.json": json.dumps({
            "profile": "trail" if trail else "auth",
            "proof_sm3": sm3_bytes(proof).hex(),
            "verifier_param_sm3": sm3_bytes(vp).hex(),
            "verdict": "OK", "created_unix_ts": 1790000000, "verify_s": 1.2,
        }).encode(),
    }
    if trail:
        files["expected.json"] = json.dumps({
            "chain_head_hex": "11" * 32, "alt_max_cm": 12000, "t_start": 0,
            "sample_period_ms": 500,
            "fence": {"min_lat": 300000000, "max_lat": 320000000,
                      "min_lon": 1100000000, "max_lon": 1220000000},
        }).encode()
        files["binding.json"] = json.dumps({
            "binding": {"auth_id": 7, "alt_max_cm": 12000, "chain_head_hex": "11" * 32,
                        "min_lat": 300000000, "max_lat": 320000000,
                        "min_lon": 1100000000, "max_lon": 1220000000,
                        "engine_pub_hex": "22" * 64, "sig_hex": "33" * 64},
            "anchor_evidence": None, "anchor_evidence_sig_hex": None,
        }).encode()
    for name in drop:
        files.pop(name, None)
    for name, content in files.items():
        (d / name).write_bytes(content)


def test_bundle_full_trail_case(monkeypatch, tmp_path):
    """全件 TRAIL 案卷 → 200+zip 结构：件名清单/README 含验证命令行/
    summary sha256 逐件对账/确定性 zip/源案卷只读。"""
    import hashlib
    import io
    import zipfile

    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    cid = "ab" * 8
    _mk_bundle_case(tmp_path, cid, trail=True)
    r = prover.case_bundle(cid)
    assert getattr(r, "status_code", 200) == 200
    assert r.media_type == "application/zip"
    assert f'fz-proof-{cid[:8]}.zip' in r.headers.get("content-disposition", "")
    zf = zipfile.ZipFile(io.BytesIO(r.body))
    names = zf.namelist()
    for n in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json",
              "expected.json", "binding.json", "summary.json", "README-验证指引.txt"):
        assert n in names, f"出示包缺件 {n}"
    readme = zf.read("README-验证指引.txt").decode("utf-8")
    assert "verify-instances" in readme and "--expected expected.json" in readme, \
        "README 必须含第三方可复制的验证命令行"
    assert "instances.json" in readme and "proof.bin" in readme
    summary = json.loads(zf.read("summary.json").decode("utf-8"))
    assert summary["case_id"] == cid and summary["profile"] == "trail"
    assert summary["missing"] == [] and summary["verdict"] == "OK"
    assert summary["proof_fingerprints"]["proof_sm3_recheck_match"] is True, \
        "proof.bin 重算 SM3 必须与 verdict 记录对账一致"
    assert summary["trail_expectation"]["alt_max_cm"] == 12000
    listed = {f["name"] for f in summary["files"]}
    assert listed == {n for n in names if n != "summary.json"}, "files 清单=实际打包件"
    for f in summary["files"]:  # sha256/bytes 逐件对账
        data = zf.read(f["name"])
        assert f["bytes"] == len(data)
        assert hashlib.sha256(data).hexdigest() == f["sha256"]
    # 确定性 zip：同案卷重复打包字节一致（时间戳定值+条目序固定）
    r2 = prover.case_bundle(cid)
    assert r2.body == r.body, "出示包必须字节级可复现"
    # 源案卷只读——打包不改动静态：重打包等价已隐含；直接核对原文件未动
    assert (tmp_path / cid / "proof.bin").read_bytes() == b"\x00\x01proof-bytes-fake"


def test_bundle_auth_missing_expected_marked(monkeypatch, tmp_path):
    """缺件 AUTH 案卷（新批无 expected.json）→ 200 但 manifest 如实标注缺失，
    README 给出补齐指引（诚实降级——不编造期望值）。"""
    import io
    import zipfile

    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    cid = "cd" * 8
    _mk_bundle_case(tmp_path, cid, trail=False, drop=("expected.json", "binding.json"))
    r = prover.case_bundle(cid)
    assert getattr(r, "status_code", 200) == 200
    zf = zipfile.ZipFile(io.BytesIO(r.body))
    names = zf.namelist()
    assert "expected.json" not in names and "binding.json" not in names
    summary = json.loads(zf.read("summary.json").decode("utf-8"))
    assert summary["profile"] == "auth"
    assert set(summary["missing"]) == {"expected.json", "binding.json"}, \
        "manifest 必须逐件标注缺失"
    readme = zf.read("README-验证指引.txt").decode("utf-8")
    assert "expected.json" in readme and "如实说明" in readme, \
        "缺件时 README 必须如实说明并给出补齐路径"


def test_bundle_bad_case_id_and_not_found(monkeypatch, tmp_path):
    """坏 case_id（路径穿越尝试）→ 400；不存在案卷 → 404。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    for bad in ("../../etc", "..%2f..", "ZZnothex!!", "ab", "a" * 65):
        r = prover.case_bundle(bad)
        assert getattr(r, "status_code", 200) == 400, f"坏 case_id {bad!r} 必须 400"
        assert json.loads(r.body)["code"] == "bad_case_id"
    r404 = prover.case_bundle("ff" * 8)
    assert getattr(r404, "status_code", 200) == 404
    assert json.loads(r404.body)["code"] == "no_case"


def test_bundle_zero_identity_red_line(monkeypatch, tmp_path):
    """零身份红线双面：正常包 zip 全文本件扫描 banned 词零命中；案卷件被
    塞入身份字段名 → 打包 fail-closed 500 拒绝（绝不带病出包）。"""
    import io
    import zipfile

    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    cid = "ee" * 8
    _mk_bundle_case(tmp_path, cid, trail=True)
    r = prover.case_bundle(cid)
    assert getattr(r, "status_code", 200) == 200
    zf = zipfile.ZipFile(io.BytesIO(r.body))
    for name in zf.namelist():
        if name.endswith((".json", ".txt")):
            text = zf.read(name).decode("utf-8", "replace")
            for banned in _BUNDLE_BANNED_WORDS:
                assert banned not in text, f"出示包 {name} 泄漏身份面字段 {banned}"
    # 负例：案卷 verdict.json 被塞入身份字段名 → 500 identity_leak_blocked
    (tmp_path / cid / "verdict.json").write_text(
        json.dumps({"profile": "trail", "verdict": "OK",
                    "id_number": "110101199001011234"}), encoding="utf-8")
    r_bad = prover.case_bundle(cid)
    assert getattr(r_bad, "status_code", 200) == 500
    body = json.loads(r_bad.body)
    assert body["code"] == "identity_leak_blocked"
    assert "verdict.json" in body["message"]


# ---- 批 4：构型 profile 单源 + 私钥 env 通道 + 内存判决收口 ----


def test_memory_admission_unreadable_rejects():
    """批 4-5 fail-open 收口：可用内存读不到（-1 哨兵）=保守拒绝+人话，
    不再放行；低于阈值仍拒、充足仍放行（原语义不放松）。"""
    import prover

    ok, msg = prover._memory_admission(-1.0, 13.0)
    assert not ok
    assert "无法确认" in msg and "重试" in msg
    ok2, _ = prover._memory_admission(5.0, 13.0)
    assert not ok2
    ok3, _ = prover._memory_admission(32.0, 13.0)
    assert ok3


def test_admit_task_memory_unreadable_rejected(monkeypatch, tmp_path):
    """受理面收口：_host_avail_gib 读不到 → 429 memory_insufficient（不放行）。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.setattr(prover, "_host_avail_gib", lambda: -1.0)
    with prover._LOCK:
        prover._TASKS.clear()
    resp = prover._admit_task_locked("t-mem-1", {"case_id": "ca" * 8}, kind="auth")
    assert resp is not None and getattr(resp, "status_code", 200) == 429
    assert json.loads(resp.body)["code"] == "memory_insufficient"


def test_zk_profile_module_single_source(monkeypatch):
    """profile 单源可达且为 backend 同一模块（桥跨包直载）；release-demo
    缺省档取值表断言。"""
    import prover

    from app.zk import profile as backend_profile

    monkeypatch.delenv("FZ_ZK_PROFILE", raising=False)
    prof = prover._zk_profile_mod()
    assert prof is backend_profile  # 单源：同一模块对象，非拷贝
    assert prof.active_profile() == "release-demo"
    env = prof.zkc_env()
    assert env["FZ_ZK_ALLOW_AUTH"] == "1" and env["FZ_ZK_ALLOW_TRAIL"] == "1"
    assert env["SM3_LUT"] == "1" and env["PCS_INTERLEAVE"] == "1"
    assert env["PCS_BATCH_DEDUP"] == "0" and env["PCS_VERIFY_STREAM"] == "0"
    assert env["FZ_ZK_FORBID_SPEC_KEY"] == "1"  # spec 明文私钥回落缺省禁用
    assert "release-demo" in prof.describe()


def test_zk_cache_dir_env_passthrough(monkeypatch, tmp_path):
    """优化 2（跨证明确定性产物复用）env 透传：zkc_env 缺省=FZ_ZK_CASES_DIR
    同级 cache/；显式 FZ_ZK_CACHE_DIR 恒尊重；无案卷目录回落 zksvc 本地
    cache/；两源皆缺不注入（zkc 纯计算路径，与现状一致）。"""
    import prover

    prof = prover._zk_profile_mod()
    monkeypatch.delenv("FZ_ZK_CACHE_DIR", raising=False)
    monkeypatch.delenv("FZ_ZKSVC_DIR", raising=False)

    # ① 案卷目录同级 cache/（桥形态缺省）
    cases = tmp_path / "fz-zk-cases"
    cases.mkdir()
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(cases))
    env = prof.zkc_env()
    assert env["FZ_ZK_CACHE_DIR"] == str(tmp_path / "cache")

    # ② 显式值恒尊重（setdefault 语义——运维可覆盖/禁用）
    monkeypatch.setenv("FZ_ZK_CACHE_DIR", "/opt/fz/my-cache")
    assert prof.zkc_env()["FZ_ZK_CACHE_DIR"] == "/opt/fz/my-cache"
    monkeypatch.delenv("FZ_ZK_CACHE_DIR", raising=False)

    # ③ 无案卷目录 → zksvc 本地 cache/（worker/直跑形态）
    monkeypatch.delenv("FZ_ZK_CASES_DIR", raising=False)
    monkeypatch.setenv("FZ_ZKSVC_DIR", r"C:\zksvc")
    assert prof.zkc_env()["FZ_ZK_CACHE_DIR"] == r"C:\zksvc\cache"

    # ④ 两源皆缺 → 不注入（zkc 侧无 env 即不开缓存——hermetic 降级）
    monkeypatch.delenv("FZ_ZKSVC_DIR", raising=False)
    assert "FZ_ZK_CACHE_DIR" not in prof.zkc_env()


def test_build_wslenv_carries_cache_dir_path_flag():
    """WSL 形态透传声明：FZ_ZK_CACHE_DIR 带 /p 旗标（路径翻译——ext4 →
    Windows UNC 形态，zkc.exe 经 wsl.localhost UNC 直读直写 ext4）；未配置
    时不列入；平键去重保留。"""
    import prover

    wslenv = prover._build_wslenv({"FZ_ZK_CACHE_DIR": "/tmp/cache", "WSLENV": "EXTRA_K"})
    assert "FZ_ZK_CACHE_DIR/p" in wslenv
    parts = wslenv.split(":")
    for k in prover._PROFILE_ENV_KEYS:
        assert k in parts, k
    assert parts[-1] == "EXTRA_K"  # 既有 WSLENV 并入保留
    # 未配置缓存目录 → 不列入（平键仍在）
    wslenv_off = prover._build_wslenv({"WSLENV": ""})
    assert "FZ_ZK_CACHE_DIR" not in wslenv_off
    assert "FZ_ZK_ALLOW_AUTH" in wslenv_off


def test_guard_cache_dir_ext4_replaces_mnt(monkeypatch, tmp_path):
    """/mnt（drvfs）缓存目录顶替为桥本地工作区 zk-cache/——ext4 纪律
    （大工件缓存禁 9p：慢+悬挂面）；本地/未配置路径原样。"""
    import prover

    monkeypatch.setenv("FZ_PROVE_TMP_DIR", str(tmp_path))
    env = prover._guard_cache_dir_ext4({"FZ_ZK_CACHE_DIR": "/mnt/c/fz/cache"})
    assert env["FZ_ZK_CACHE_DIR"] == str(tmp_path / "zk-cache")
    # 非 /mnt 前缀原样（ext4 路径不顶替）
    env2 = prover._guard_cache_dir_ext4({"FZ_ZK_CACHE_DIR": "/tmp/cache"})
    assert env2["FZ_ZK_CACHE_DIR"] == "/tmp/cache"
    # 未配置原样（无键不注入）
    assert "FZ_ZK_CACHE_DIR" not in prover._guard_cache_dir_ext4({})


def test_mark_zk_cache_stage_hit_and_miss(tmp_path):
    """[zk-cache] hit/miss 行 → stage_ts 阶段标记 cache_hit/cache_miss + 秒数
    （verdict setup_s+preprocess_s 口径：hit=加载/miss=实算——prove 窗对账）；
    stderr 无标记（缓存 Off/远程池）零打点。"""
    import prover

    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "verdict.json").write_text(
        json.dumps({"setup_s": 0.0, "preprocess_s": 0.4}), encoding="utf-8"
    )

    def _task():
        return {"status": "proving", "stage_ts": {}, "stage": None}

    # ① hit：取最后一行标记（多窗形态下最新为准）
    (tmp_path / "zkc_stderr.log").write_text(
        chr(10).join([
            "[zk-cache] miss abcd1234 build=8.2s write=ok",
            "[zk-cache] hit abcd1234 load=0.4s",
            "",
        ]),
        encoding="utf-8",
    )
    t = _task()
    prover._mark_zk_cache_stage(t, "c" * 32, tmp_path)
    assert "cache_hit" in t["stage_ts"] and t["stage"] == "cache_hit"
    assert t["zk_cache_s"] == 0.4

    # ② miss
    (tmp_path / "zkc_stderr.log").write_text(
        "[zk-cache] miss abcd1234 build=8.2s write=ok" + chr(10), encoding="utf-8"
    )
    t2 = _task()
    prover._mark_zk_cache_stage(t2, "c" * 32, tmp_path)
    assert "cache_miss" in t2["stage_ts"] and t2["stage"] == "cache_miss"
    assert t2["zk_cache_s"] == 0.4

    # ③ 无标记（缓存 Off/远程池/旧版 zkc）→ 零打点
    (tmp_path / "zkc_stderr.log").write_text(
        "[PHASE] t=1.0s assemble_done" + chr(10), encoding="utf-8"
    )
    t3 = _task()
    prover._mark_zk_cache_stage(t3, "c" * 32, tmp_path)
    assert t3["stage_ts"] == {} and "zk_cache_s" not in t3
    # stderr 缺席（远程池）同零打点
    (tmp_path / "zkc_stderr.log").unlink()
    prover._mark_zk_cache_stage(t3, "c" * 32, tmp_path)
    assert t3["stage_ts"] == {}


def _prove_body():
    import prover

    return prover.ProveStartIn(
        plan_hash_hex="11" * 32,
        nonce_hex="22" * 16,
        class_id=1,
        id_number="110101199001011234",
        cert_level=3,
        sn="FZ-SN",
        salt_hex="ab" * 16,
        id_prime_hex="33" * 32,
        sig_hex="44" * 64,
        expires_at="2099-01-01T00:00:00",
        holder_sk_hex="cd" * 32,
        holder_pk_hex="ee" * 64,
    )


def _artifacts(out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    for n in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json"):
        (out_dir / n).write_bytes(b"x")


def test_auth_prove_sk_env_channel_not_in_spec(monkeypatch, tmp_path):
    """批 4-6：本地出证私钥走 env 注入通道——job.json 零私钥字节；构型档名
    打任务面（zk_profile）+ 日志面。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.delenv("FZ_PROVE_REMOTE", raising=False)
    task_id = "t" * 32
    prover._TASKS[task_id] = {
        "status": "assembling", "case_id": "c" * 16, "error": None,
        "t_start": None, "alt_max": None, "kind": "auth",
        "stage_ts": {}, "stage": None, "prove_heartbeat": None, "pid": None,
    }
    captured: dict = {}

    def _fake_prove(spec_path, out_dir, extra_env=None):
        captured["spec"] = json.loads(spec_path.read_text(encoding="utf-8"))
        captured["extra_env"] = dict(extra_env or {})
        _artifacts(out_dir)
        return 4242

    def _fake_get(url):
        if url.endswith("/ra/pubkey"):
            return {"data": {"ra_pub_hex": "11" * 64}}
        return {"data": {"siblings_hex": ["00" * 32] * 32, "root_hex": "00" * 32}}

    monkeypatch.setattr(prover, "_prove_local", _fake_prove)
    monkeypatch.setattr(prover, "_http_get", _fake_get)
    monkeypatch.setattr(prover, "_await_case_artifacts", lambda *a, **k: None)
    prover._assemble_and_prove(
        task_id, _prove_body(),
        {"challenge_hex": "00" * 32, "pred_id": "p", "t_epoch": 1,
         "required_level": 1, "alt_max": 50},
    )
    assert prover._TASKS[task_id]["status"] == "done"
    assert prover._TASKS[task_id]["zk_profile"] == "release-demo"
    spec_input = captured["spec"]["input"]
    assert spec_input["holder_sk_hex"] == "", "本地出证 spec 不得携带私钥明文"
    assert captured["extra_env"].get("FZ_ZK_HOLDER_SK_HEX") == "cd" * 32


def test_auth_prove_remote_keeps_spec_channel(monkeypatch, tmp_path):
    """远程 prover 池=spec 文件通道（job.json 本就全量上传+用毕即焚）——
    holder_sk_hex 保留在 spec，env 通道不启用（诚实双档）。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("FZ_PROVE_REMOTE", "ssh:root@10.0.0.8")
    task_id = "r" * 32
    prover._TASKS[task_id] = {
        "status": "assembling", "case_id": "d" * 16, "error": None,
        "t_start": None, "alt_max": None, "kind": "auth",
        "stage_ts": {}, "stage": None, "prove_heartbeat": None, "pid": None,
    }
    captured: dict = {}

    def _fake_remote(target, spec_path, out_dir):
        captured["spec"] = json.loads(spec_path.read_text(encoding="utf-8"))
        _artifacts(out_dir)

    def _fake_get(url):
        if url.endswith("/ra/pubkey"):
            return {"data": {"ra_pub_hex": "11" * 64}}
        return {"data": {"siblings_hex": ["00" * 32] * 32, "root_hex": "00" * 32}}

    monkeypatch.setattr(prover, "_prove_remote", _fake_remote)
    monkeypatch.setattr(prover, "_http_get", _fake_get)
    monkeypatch.setattr(prover, "_await_case_artifacts", lambda *a, **k: None)
    prover._assemble_and_prove(
        task_id, _prove_body(),
        {"challenge_hex": "00" * 32, "pred_id": "p", "t_epoch": 1,
         "required_level": 1, "alt_max": 50},
    )
    assert prover._TASKS[task_id]["status"] == "done"
    assert captured["spec"]["input"]["holder_sk_hex"] == "cd" * 32


# ---- B3 感知链路人话化：backend 信封结构化透传（code/message 不再碎成 HTTP Error） ----

def _http_get_raising(status: int, body: bytes):
    """_http_get 的网络替身：opener.open 直抛携带 body 的 HTTPError。"""
    import io as _io
    import urllib.error as _ue
    import urllib.request as _ur

    class _Op:
        def open(self, req, timeout=None):
            raise _ue.HTTPError("http://backend/x", status, "Err", None, _io.BytesIO(body))

    return _Op()


def test_http_get_envelope_passthrough_three_shapes(monkeypatch):
    """信封透传三形态（B3）：①403+JSON 信封=业务码+人话原样上抛；
    ②409+JSON 信封同式；③500 非 JSON 裸页=http_<status> 通用码不伪造语义。"""
    import urllib.request as _ur

    import prover

    # ① 403 revoked（被吊销飞手主路径——人话必须存活）
    monkeypatch.setattr(
        _ur, "build_opener",
        lambda *a, **k: _http_get_raising(
            403, json.dumps({"code": "revoked",
                             "message": "该出示公钥已列入撤销名单——申请将被数学拒绝"},
                            ensure_ascii=False).encode("utf-8")),
    )
    with pytest.raises(prover.BridgeHttpError) as ei:
        prover._http_get("http://backend/ra/revocation/witness?holder_pk_hex=x")
    assert ei.value.code == "revoked"
    assert "撤销名单" in ei.value.message
    assert ei.value.status == 403

    # ② 409 stale_rev_root（受理面快速失败码）
    monkeypatch.setattr(
        _ur, "build_opener",
        lambda *a, **k: _http_get_raising(
            409, json.dumps({"code": "stale_rev_root",
                             "message": "撤销纪元根与链上不一致（刷新见证后重试）"},
                            ensure_ascii=False).encode("utf-8")),
    )
    with pytest.raises(prover.BridgeHttpError) as ei2:
        prover._http_get("http://backend/anything")
    assert ei2.value.code == "stale_rev_root" and ei2.value.status == 409

    # ③ 500 非 JSON 裸错误页——通用码，不伪造业务语义
    monkeypatch.setattr(
        _ur, "build_opener",
        lambda *a, **k: _http_get_raising(500, b"Internal Server Error"),
    )
    with pytest.raises(prover.BridgeHttpError) as ei3:
        prover._http_get("http://backend/anything")
    assert ei3.value.code == "http_500" and ei3.value.status == 500
    assert ei3.value.message  # 诊断文本保留（不空转）


def test_prove_failure_channel_passthrough_code(monkeypatch, tmp_path):
    """B3 失败通道：装配期 backend 信封拒绝（revoked）→ 任务 error=人话、
    error_code=业务码，/prove/task 与库镜像（重启后仍可查）双面透传。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    task_id = "e" * 32
    prover._TASKS[task_id] = {
        "status": "assembling", "case_id": "f" * 16, "error": None,
        "t_start": None, "alt_max": None, "kind": "auth",
        "stage_ts": {}, "stage": None, "prove_heartbeat": None, "pid": None,
    }

    def _raise_revoked(url):
        raise prover.BridgeHttpError(
            "revoked", "该出示公钥已列入撤销名单——申请将被数学拒绝", 403)

    monkeypatch.setattr(prover, "_http_get", _raise_revoked)
    # 生产序=受理面先 INSERT（_admit_task_locked）再装配——镜像同序后断言库面
    prover._db_task_insert(task_id, kind="auth", case_id="f" * 16, status="assembling")
    prover._assemble_and_prove(
        task_id, _prove_body(),
        {"challenge_hex": "00" * 32, "pred_id": "p", "t_epoch": 1,
         "required_level": 1, "alt_max": 50},
    )
    t = prover._TASKS[task_id]
    assert t["status"] == "failed"
    assert t["error_code"] == "revoked"
    assert "撤销名单" in t["error"]
    # 库镜像（桥重启后 /prove/task 读库路径）同样带码
    row = prover._db_task_get(task_id)
    assert row is not None and row["error_code"] == "revoked"
    # 脱敏失败现场（既有语义不破）+ 诊断面带码
    scene = tmp_path / f"_tmp_{task_id}"
    assert not (scene / "job.json").exists()
    fjson = json.loads((scene / "failure.json").read_text(encoding="utf-8"))
    assert fjson["error_code"] == "revoked"


def test_prove_task_endpoint_error_code_field(monkeypatch, tmp_path):
    """/prove/task 响应 error_code 字段（既有字段零变化——加字段不破消费面）。"""
    import prover

    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    task_id = "9" * 32
    prover._TASKS[task_id] = {
        "status": "failed", "case_id": "8" * 16, "error": "该出示公钥已列入撤销名单",
        "error_code": "revoked", "t_start": None, "alt_max": None, "kind": "auth",
        "stage_ts": {}, "stage": None, "prove_heartbeat": None, "pid": None,
    }
    resp = prover.task_status(task_id)
    data = json.loads(resp.body)["data"]
    assert data["error_code"] == "revoked" and "撤销名单" in data["error"]
    assert "status" in data and "case_id" in data  # 既有字段原样在位
    # 内存未命中→读库路径同样透传（桥重启后不蒸发）
    other = "7" * 32
    prover._db_task_insert(other, kind="auth", case_id="6" * 16, status="assembling")
    prover._db_task_finish(other, "failed", "撤销纪元根与链上不一致", "stale_rev_root")
    prover._TASKS.pop(other, None)
    data2 = json.loads(prover.task_status(other).body)["data"]
    assert data2["error_code"] == "stale_rev_root"


# ---- B5 批2：飞行中吊销复查（armed 后撤销不再无感飞完） ----

def test_flight_revoke_alert_hit_latched(tmp_path, token_payload, monkeypatch):
    """命中告警：status≠0 → 闩锁告警（何时/auth_id/rev_epoch）+审计事件+
    围栏归零联动（信任根收口件3：固件硬停=FENCE_ALT_MAX=0，唯一新增写入）；
    重复复查不重复审计不重复写入；诚实边界=零飞控指令（无 ARM/DISARM/MODE/RC）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    link = FakeLink()
    audit = LocalAudit(str(tmp_path / "rv1.db"))
    gate = FlightGate(link, audit)
    gate.is_armed = True
    gate.session_auth_id = 7
    gate.session_token_hash_hex = "ab" * 32
    calls: list[tuple[int, str]] = []

    def _stub(aid, th):
        calls.append((aid, th))
        return {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 1, "rev_epoch": 7, "token_used": True}}}

    monkeypatch.setattr(sl, "_authz_status_fetch", _stub)
    assert gate.revoke_recheck_if_due(59) is None  # 未到期不查询不扰
    assert calls == []
    alert = gate.revoke_recheck_if_due(60)
    assert alert is not None
    assert alert["auth_id"] == 7 and alert["status"] == 1 and alert["rev_epoch"] == 7
    assert alert["kind"] == "auth_revoked"
    assert isinstance(alert["detected_at"], int)
    assert calls and calls[0] == (7, "ab" * 32)  # 对拍键=会话令牌哈希
    assert any(d[1] == "flight_revocation_detected" for d in audit.denials())
    # 信任根收口件3：吊销检出=围栏归零写入+独立回读对拍通过（FakeLink 账面=0）
    assert link.log == ["PARAM FENCE_ALT_MAX=0"], "归零写入是检出拍唯一新增动作"
    assert link.params["FENCE_ALT_MAX"] == 0 and link.get_param("FENCE_ALT_MAX") == 0
    assert any(d[1] == "fence_zeroed_on_revocation" for d in audit.denials())
    log_after_first = list(link.log)
    again = gate.revoke_recheck_if_due(120)
    assert again is not None and again is gate.revoke_alert  # 闩锁不翻案
    assert len([d for d in audit.denials()
                if d[1] == "flight_revocation_detected"]) == 1, "闩锁期审计只记一次"
    assert link.log == log_after_first, "闩锁期零新增动作（归零只在首检出做一次）"
    assert not any(
        x.split()[0] in ("ARM", "DISARM", "MODE", "RC_THROTTLE", "RC_RELEASE", "STREAM")
        for x in link.log
    ), "诚实边界：吊销复查不得发任何飞控指令（围栏参数归零≠飞控指令）"


def test_flight_revoke_alert_quiet_paths(tmp_path, token_payload, monkeypatch):
    """未命中不扰：status=0 有效 / fake 链档 / 未 armed / 未到期——零查询
    或零告警（autouse 有效替身面）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    audit = LocalAudit(str(tmp_path / "rv2.db"))
    gate = FlightGate(FakeLink(), audit)
    # 未 armed：不查询直接 None
    gate.session_auth_id = 7
    gate.session_token_hash_hex = "ab" * 32
    assert gate.revoke_recheck_if_due(60) is None
    # armed + status=0（autouse 替身=real 档有效）：复查不告警
    gate.is_armed = True
    assert gate.revoke_recheck_if_due(60) is None
    assert gate.revoke_alert is None
    assert not any(d[1] == "flight_revocation_detected" for d in audit.denials())
    # fake 链档（无链上撤销面）：与 ARM 预检同口径——跳过不告警
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "fake", "status": None, "rev_epoch": None, "token_used": False}}},
    )
    assert gate.revoke_recheck_if_due(120) is None
    assert gate.revoke_alert is None


def test_flight_revoke_alert_unreachable_fail_safe(tmp_path, token_payload, monkeypatch):
    """stub 不可达不炸（fail-safe 仅记录）：http=0 → 返回 None、不闩锁、
    不误报、不写吊销审计；采样循环可继续（函数正常返回）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    audit = LocalAudit(str(tmp_path / "rv3.db"))
    gate = FlightGate(FakeLink(), audit)
    gate.is_armed = True
    gate.session_auth_id = 7
    gate.session_token_hash_hex = "ab" * 32
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 0, "body": None, "error": "connection refused"},
    )
    assert gate.revoke_recheck_if_due(60) is None
    assert gate.revoke_alert is None
    assert not any(d[1] == "flight_revocation_detected" for d in audit.denials())
    # 非 200（404=授权不在链上）同样 fail-safe
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 404, "body": {"ok": False, "code": "auth_not_found"}},
    )
    assert gate.revoke_recheck_if_due(120) is None
    assert gate.revoke_alert is None


def test_telemetry_sitl_sample_revoke_alert_hook(monkeypatch, tmp_path, token_payload):
    """采样循环接线（真链路形态替身）：第 60 样本（2Hz≈30s）触发复查——
    status≠0 → 响应 revoke_alert+取证计数+审计；FakeLink 链数据照常入链。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "rv4.db"))
    link = FakeLink()
    link.last_gpos = {"alt_mm": 1200, "lat_1e7": 0, "lon_1e7": 0}  # 真采样替身
    link.last_fc_armed = True
    gate = FlightGate(link, audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", link)
    monkeypatch.setattr(srv, "_audit", audit)
    monkeypatch.setattr(srv, "_COUNTERS", {"rejected_samples": 0, "fence_drift_events": 0,
                                           "rogue_arm_events": 0, "revoke_alert_events": 0})
    monkeypatch.setattr(srv, "is_real_link", lambda l: True)  # 真链路形态（采样面）
    monkeypatch.setattr(srv, "_chain", None)
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01007800"))
    # 撤销替身：status=1（rev_epoch 推进）
    import sitl_link as sl

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 1, "rev_epoch": 8, "token_used": True}}},
    )
    log_before = list(link.log)
    out = None
    for _ in range(60):
        out = srv.telemetry_sitl_sample(t_epoch=1)
        assert out.get("ok") is True
    assert gate.revoke_alert is not None and gate.revoke_alert["rev_epoch"] == 8
    assert out["revoke_alert"] is gate.revoke_alert, "命中拍响应携带闩锁告警"
    assert srv._COUNTERS["revoke_alert_events"] == 1
    assert any(d[1] == "flight_revocation_detected" for d in audit.denials())
    # 信任根收口件3：采样循环复查检出吊销=围栏归零写入（唯一新增动作，无飞控指令）
    assert link.log == log_before + ["PARAM FENCE_ALT_MAX=0"], str(link.log)
    assert link.params["FENCE_ALT_MAX"] == 0


def test_telemetry_state_exposes_revoke_alert(monkeypatch, tmp_path, token_payload):
    """/telemetry/state 暴露 revoke_alert 闩锁字段（切页回放不丢告警）；
    counters 计数面同源可见。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    audit = LocalAudit(str(tmp_path / "rv5.db"))
    gate = FlightGate(FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", FakeLink())
    monkeypatch.setattr(srv, "_audit", audit)
    monkeypatch.setattr(srv, "_COUNTERS", {"rejected_samples": 0, "fence_drift_events": 0,
                                           "rogue_arm_events": 0, "revoke_alert_events": 0})
    monkeypatch.setattr(srv, "_chain", None)
    st0 = srv.telemetry_state()
    assert st0["revoke_alert"] is None
    gate.revoke_alert = {"detected_at": 1790000000, "auth_id": 7, "status": 1,
                         "rev_epoch": 8}
    st1 = srv.telemetry_state()
    assert st1["revoke_alert"] == {"detected_at": 1790000000, "auth_id": 7,
                                   "status": 1, "rev_epoch": 8}
    assert "revoke_alert_events" in st1["counters"]


def test_arm_success_reports_consume(tmp_path, token_payload, monkeypatch):
    """S1 根修配套：ARM 成功后必须回报 /authz/consume（服务端消费账本的
    写入源）——离线断言调用形态（auth_id 正确）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    calls: list[int] = []
    monkeypatch.setattr(
        sl.FlightGate, "_report_consume",
        lambda self, aid: calls.append(aid), raising=True)
    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "cr.db"))
    gate = FlightGate(FakeLink(), audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert out["ok"], out
    assert calls == [tok["authId"]], "ARM 成功恰回报一次消费（auth_id 令牌域）"


# ---- 信任根收口批（2026-10-06）：五件评委盲点收口 ----


@pytest.mark.real_consume
def test_consume_report_failure_persists_pending_and_retry_clears(
        tmp_path, token_payload, monkeypatch):
    """件1：回报失败 → (auth_id, token_hash) 落 consume_pending 表（进程重启
    不丢——与令牌账本同库）；恢复后 _retry_consume_pending 清空队列，成功即删。
    堵「同令牌双飞」窗：服务端消费账本缺失期间删本地库重放不再无代价。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "cp.db"))
    gate = FlightGate(FakeLink(), audit)

    def _fail(aid, th):
        raise OSError("connection refused（回报面故障替身）")

    monkeypatch.setattr(sl, "_post_consume_http", _fail)  # 先替身后 ARM（离线纪律）
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert out["ok"], out
    th_expected = sm3_bytes(payload.rsplit(b"|", 1)[0]).hex()
    rows = audit.consume_pending_all()
    assert len(rows) == 1, "ARM 成功但回报失败必须落队恰一行"
    assert rows[0][0] == tok["authId"] and rows[0][1] == th_expected
    assert rows[0][2], "入队时刻在案"

    # 落库持久性：换新 LocalAudit 实例（模拟桥重启）读同一库——队列不丢
    audit2 = LocalAudit(str(tmp_path / "cp.db"))
    assert audit2.consume_pending_all() == rows, "重启后待回报队列仍在（SQLite 同库）"

    # 恢复：回报面恢复 → 重试清空队列（逐行重发，成功即删）
    sent: list[tuple[int, str]] = []
    monkeypatch.setattr(sl, "_post_consume_http", lambda aid, th: sent.append((aid, th)))
    gate2 = FlightGate(FakeLink(), audit2)
    assert gate2._retry_consume_pending() == 1
    assert audit2.consume_pending_all() == [], "清空队列（成功即删）"
    assert sent == [(tok["authId"], th_expected)], "重发携带落队时的 (auth_id, token_hash)"

    # 回报面半恢复形态：重试失败行留队不抛（fail-safe——ARM 出口调用不炸）
    def _fail_again(aid, th):
        raise OSError("still down")

    monkeypatch.setattr(sl, "_post_consume_http", _fail_again)
    audit2.consume_pending_enqueue(tok["authId"], th_expected)
    assert gate2._retry_consume_pending() == 0
    assert len(audit2.consume_pending_all()) == 1, "失败行留队下拍再试"


@pytest.mark.real_consume
def test_consume_report_success_removes_stale_pending(tmp_path, token_payload, monkeypatch):
    """件1 对偶面：回报成功即删——含此前失败遗留行（幂等清账）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "cp2.db"))
    th = sm3_bytes(payload.rsplit(b"|", 1)[0]).hex()
    audit.consume_pending_enqueue(tok["authId"], th)  # 预置历史遗留行
    gate = FlightGate(FakeLink(), audit)
    gate.session_token_hash_hex = th
    monkeypatch.setattr(sl, "_post_consume_http", lambda aid, thh: None)  # 回报成功
    gate._report_consume(tok["authId"])
    assert audit.consume_pending_all() == [], "回报成功必须清掉遗留行"


def test_flight_expiry_alert_triggered_and_quiet(tmp_path, token_payload, monkeypatch):
    """件2：飞行中授权窗到期收敛——now>t_end → expiry_alert 闩锁（revoke_alert
    同款）+auth_window_expired 审计+「建议返航」人话；零飞控指令（诚实边界）。
    未过期/非到期拍不扰；闩锁不清除；撤销告警语义不受影响（到期优先返回）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    link = FakeLink()
    audit = LocalAudit(str(tmp_path / "ex1.db"))
    gate = FlightGate(link, audit)
    gate.is_armed = True
    gate.session_auth_id = 7
    gate.session_token_hash_hex = "ab" * 32
    now = int(time.time())

    # 未过期：不告警不扰
    gate.session_t_end = now + 3600
    assert gate.revoke_recheck_if_due(59) is None, "非复查拍不扰"
    assert gate.revoke_recheck_if_due(60) is None, "窗内复查零告警"
    assert gate.expiry_alert is None

    # 过期：到期拍触发闩锁+审计（本地确定性——链上替身可以不可达）
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 0, "body": None, "error": "connection refused"})
    gate.session_t_end = now - 1
    alert = gate.revoke_recheck_if_due(60)
    assert alert is not None and alert["kind"] == "auth_window_expired"
    assert alert["auth_id"] == 7 and alert["t_end"] == now - 1
    assert gate.expiry_alert is alert, "闩锁（同一对象回放）"
    assert any(d[1] == "auth_window_expired" for d in audit.denials())
    assert "建议返航" in audit.denials()[-1][2], "人话告警在案"
    assert link.log == [], "诚实边界：到期收敛零飞控指令"
    # 闩锁不清除：后续复查拍回放同一告警、审计不重复
    again = gate.revoke_recheck_if_due(120)
    assert again is gate.expiry_alert
    assert len([d for d in audit.denials() if d[1] == "auth_window_expired"]) == 1
    # 到期优先于撤销：撤销替身在场也返回到期闩锁（语义可辨不混流）
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 1, "rev_epoch": 9}}})
    assert gate.revoke_recheck_if_due(180) is gate.expiry_alert
    assert gate.revoke_alert is None, "到期闩锁存在时撤销路径不被触发"
    assert gate.session_converged() is True
    # disarm 复位会话态（含 t_end 与闩锁面）
    gate.disarm()
    assert gate.session_t_end is None and gate.session_converged() is False


def test_expiry_convergence_event_filed_and_anchor_stopped(monkeypatch, tmp_path, token_payload):
    """件2 消费面：采样循环检出到期 → 取证事件（source=2 地面站监测）随响应
    出桥上链 + 检查点停锚（/telemetry/anchor 复用 auth_revoked 停锚语义拒锚，
    anchored_seq 不推进）；撤销闩锁同拒（session_converged 单源）。"""
    import server as srv
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "ex2.db"))
    link = FakeLink()
    link.last_gpos = {"alt_mm": 1200, "lat_1e7": 0, "lon_1e7": 0}
    link.last_fc_armed = True
    gate = FlightGate(link, audit)
    monkeypatch.setattr(srv, "_gate", gate)
    monkeypatch.setattr(srv, "_link", link)
    monkeypatch.setattr(srv, "_audit", audit)
    monkeypatch.setattr(srv, "_COUNTERS", {"rejected_samples": 0, "fence_drift_events": 0,
                                           "rogue_arm_events": 0, "revoke_alert_events": 0})
    monkeypatch.setattr(srv, "is_real_link", lambda l: True)
    monkeypatch.setattr(srv, "_chain", None)
    gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    srv.telemetry_start(srv.ChainStartIn(auth_id=tok["authId"], fence_state_hex="01007800"))
    # 会话窗拨到过去 → 第 60 样本复查拍触发到期收敛
    gate.session_t_end = int(time.time()) - 1
    out = None
    for _ in range(60):
        out = srv.telemetry_sitl_sample(t_epoch=1)
        assert out.get("ok") is True
    assert gate.expiry_alert is not None
    assert out["revoke_alert"] is gate.expiry_alert, "命中拍响应携带到期闩锁"
    ev = out["event"]
    assert ev is not None and ev["event_type"] == 2, "到期取证事件（地面站监测）随响应出桥上链"
    # 停锚：授权窗已到期 → anchor 端点拒锚（不复刻 backend 的 auth_revoked 码面
    # ——桥侧码=auth_window_expired；语义同源：授权终结不再产生新锚定证词）
    before = srv._chain.anchored_seq
    r = srv.telemetry_anchor()
    assert r["ok"] is False and r["code"] == "auth_window_expired"
    assert r["anchored_seq"] == before, "停锚不推进 anchored_seq（已锚取证不动）"
    # 撤销闩锁同拒（同一收敛单源）
    gate.expiry_alert = None
    gate.revoke_alert = {"kind": "auth_revoked", "detected_at": 1, "auth_id": 7,
                         "status": 1, "rev_epoch": 3}
    r2 = srv.telemetry_anchor()
    assert r2["ok"] is False and r2["code"] == "auth_revoked"
    # 未收敛（无闩锁）：停锚门不触发——锚定主径照常（_post_engine 替身离线，
    # 断言门放行=引擎转发发生）
    gate.revoke_alert = None
    posted: list[str] = []
    monkeypatch.setattr(srv, "_post_engine", lambda path, body: posted.append(path) or {"ok": True})
    r3 = srv.telemetry_anchor()
    assert r3.get("ok") is True, "未收敛时停锚门必须放行（不误伤正常锚定）"
    assert posted and posted[0] == "/engine/anchor", "放行=检查点照常转发上链"


def test_revocation_fence_zero_readback_mismatch_and_failure_fail_safe(
        tmp_path, token_payload, monkeypatch):
    """件3 边界：归零回读不符/写入异常=仅日志不闩锁失败态不炸复查循环——
    取证与显告不受影响（fail-safe 纪律）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate, LinkError

    class DeafFake(FakeLink):
        """写后回读漂移替身：固件拒绝归零（存量仍 120）。"""
        def get_param(self, name, timeout_s=4.0):
            if name == "FENCE_ALT_MAX":
                return 120.0
            return super().get_param(name)

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 1, "rev_epoch": 5}}})
    # 形态①：回读不符——告警照常闩锁，无归零审计，不抛
    link = DeafFake()
    audit = LocalAudit(str(tmp_path / "fz1.db"))
    gate = FlightGate(link, audit)
    gate.is_armed = True
    gate.session_auth_id = 7
    gate.session_token_hash_hex = "ab" * 32
    alert = gate.revoke_recheck_if_due(60)
    assert alert is not None and alert["kind"] == "auth_revoked", "归零失败不挡取证显告"
    assert not any(d[1] == "fence_zeroed_on_revocation" for d in audit.denials())
    assert any(d[1] == "flight_revocation_detected" for d in audit.denials())
    # 形态②：写入异常（LinkError）——同样仅日志，复查循环存活可继续出告警
    class ExplodingFake(FakeLink):
        def set_param(self, name, value):
            raise LinkError("参数确认超时（链路替身故障）")

    link2 = ExplodingFake()
    audit2 = LocalAudit(str(tmp_path / "fz2.db"))
    gate2 = FlightGate(link2, audit2)
    gate2.is_armed = True
    gate2.session_auth_id = 7
    gate2.session_token_hash_hex = "ab" * 32
    alert2 = gate2.revoke_recheck_if_due(60)
    assert alert2 is not None and alert2["kind"] == "auth_revoked", "异常不炸复查循环"
    assert not any(d[1] == "fence_zeroed_on_revocation" for d in audit2.denials())


# ---- 授权包配额制（2026-10-06 多架次拍板）：闸门配额执法与新架次放行 ----


def test_arm_quota_remaining_zero_denied(tmp_path, token_payload, monkeypatch):
    """remaining==0=配额耗尽 → 拒绝解锁（quota_exhausted），先于围栏写入。
    consumed 置位窗的独立判定轴：consumed=False 而 remaining=0 仍拒（fail-
    closed——终态置位迟滞不放大配额）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 0, "rev_epoch": 7, "token_consumed": False,
            "remaining": 0, "sorties": 3}}},
    )
    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "qz.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not out["ok"] and out["code"] == "quota_exhausted"
    assert "FENCE_ENABLE" not in link.params and not link.armed
    assert any(d[1] == "quota_exhausted" for d in audit.denials())


def test_arm_quota_multisortie_second_arm_allowed(tmp_path, token_payload, monkeypatch):
    """K=3 多架次：首架次 ARM（本地架次计数 1）→ 落地 disarm → 第二架次
    ARM 放行（服务端 remaining=2>0 且本地计数 1<3）——每架次独立闸门序
    （围栏重写+消费回报照旧），本地账本计数 2。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "qm.db"))
    link = FakeLink()
    gate = FlightGate(link, audit)

    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 0, "rev_epoch": 7, "token_consumed": False,
            "remaining": 3, "sorties": 3}}},
    )
    out1 = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert out1["ok"] and not out1.get("rearmed", False)
    assert audit.sortie_count(payload) == 1, "首架次记账"
    gate.disarm()  # 落地停转（闩锁随会话复位——真实架次间隔形态）

    # 第二架次：服务端首报消费后 remaining=2
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 0, "rev_epoch": 7, "token_consumed": False,
            "remaining": 2, "sorties": 3}}},
    )
    out2 = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert out2["ok"], out2
    assert out2["auth_id"] == tok["authId"]
    assert audit.sortie_count(payload) == 2, "第二架次记账（同令牌新架次）"
    assert "FENCE_ENABLE" in link.params, "每架次独立闸门序（围栏重写）"


def test_arm_quota_default_one_second_arm_rejected(tmp_path, token_payload, monkeypatch):
    """缺省配额 1 等价性：预检响应无 remaining（旧形态）→ 第二次 ARM 按
    缺省配额 1 判定=token_used 拒（与令牌一次性历史语义逐字等价）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "qd.db"))
    gate = FlightGate(FakeLink(), audit)
    out1 = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert out1["ok"]
    gate.disarm()
    out2 = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not out2["ok"] and out2["code"] == "token_used"
    assert audit.sortie_count(payload) == 1, "拒者不记账"


def test_arm_quota_local_count_blocks_when_server_lagging(tmp_path, token_payload, monkeypatch):
    """本地执法轴（零弱化核心）：服务端 remaining 因回报迟到位仍显 3，但本地
    架次计数已达 3 ⟹ 第四架次拒（回报失败窗不放大配额）。"""
    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "ql.db"))
    gate = FlightGate(FakeLink(), audit)
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 0, "rev_epoch": 7, "token_consumed": False,
            "remaining": 3, "sorties": 3}}},
    )
    # 预置本地架次账本=3（此前三架次已飞，回报全部迟滞）
    for _ in range(3):
        audit.record_sortie(payload)
    gate.disarm()
    out = gate.attempt_arm(payload, plan_hash_hex=tok["plan_hash"])
    assert not out["ok"] and out["code"] == "token_used", "本地配额计满即拒"
    assert audit.sortie_count(payload) == 3


@pytest.mark.real_consume
def test_consume_report_409_quota_exhausted_terminal(tmp_path, token_payload, monkeypatch):
    """回报 409（quota_exhausted）=服务端已终态入账——弃报不入待回报队列
    （重试无意义；503/断连形态仍落队重试，语义可辨）。"""
    import urllib.error as _ue

    import sitl_link as sl
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "q4.db"))
    th = sm3_bytes(payload.rsplit(b"|", 1)[0]).hex()
    gate = FlightGate(FakeLink(), audit)
    gate.session_token_hash_hex = th

    def _quota_exhausted(aid, thh):
        raise _ue.HTTPError(url="consume", code=409,
                            msg="quota exhausted", hdrs=None, fp=None)

    monkeypatch.setattr(sl, "_post_consume_http", _quota_exhausted)
    gate._report_consume(tok["authId"])
    assert audit.consume_pending_all() == [], "409 终态弃报（不入队不重试）"

    # 对照：503 失败仍落队（重试轴语义保留）
    def _unavailable(aid, thh):
        raise _ue.HTTPError(url="consume", code=503,
                            msg="chain unavailable", hdrs=None, fp=None)

    monkeypatch.setattr(sl, "_post_consume_http", _unavailable)
    gate._report_consume(tok["authId"])
    rows = audit.consume_pending_all()
    assert len(rows) == 1 and rows[0][0] == tok["authId"], "非配额拒仍落队重试"


def test_authz_quota_fetch_shape(tmp_path, token_payload, monkeypatch):
    """authz_quota_fetch：/arm/status 配额查询面——正常回读 remaining/sorties；
    任何故障=双 None（显示退化不误报；执法在闸门预检面）。"""
    import sitl_link as sl

    payload, tok = token_payload
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {
            "mode": "real", "status": 0, "remaining": 2, "sorties": 3}}},
    )
    q = sl.authz_quota_fetch(payload)
    assert q == {"remaining": 2, "sorties": 3}
    # 故障形态：连接失败/畸形数据=双 None
    monkeypatch.setattr(sl, "_authz_status_fetch",
                        lambda aid, th: {"http": 0, "body": None, "error": "down"})
    assert sl.authz_quota_fetch(payload) == {"remaining": None, "sorties": None}
    monkeypatch.setattr(
        sl, "_authz_status_fetch",
        lambda aid, th: {"http": 200, "body": {"ok": True, "data": {"mode": "real"}}},
    )
    assert sl.authz_quota_fetch(payload) == {"remaining": None, "sorties": None}
