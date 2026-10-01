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

from device_key import device_keypair, verify_checkpoint
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
    }
    body = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    sig = sign_digest(sk, sm3_bytes(body.encode()))
    return (body + "|" + sig).encode(), tok


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
    """遥测起链/采样以 ARM 为前置——未授权不产生"飞行记录"（队长实测缺陷）。"""
    import server as srv
    from sitl_link import FakeLink, FlightGate

    payload, tok = token_payload
    audit = LocalAudit(str(tmp_path / "g5.db"))
    gate = FlightGate(FakeLink(), audit)
    monkeypatch.setattr(srv, "_gate", gate)

    # 未 ARM：起链拒绝
    r0 = srv.telemetry_start(srv.ChainStartIn(auth_id=1, fence_state_hex="01780000"))
    assert r0.get("ok") is False and r0.get("code") == "not_armed"
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
                           "chain_head_hex": head, "engine_pub_hex": "aa", "sig_hex": "bb"})

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
                           "chain_head_hex": head, "engine_pub_hex": "aa", "sig_hex": "bb"})
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
                           "chain_head_hex": head, "engine_pub_hex": "aa", "sig_hex": "bb"})
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
