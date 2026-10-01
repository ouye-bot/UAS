"""B5 场景脚本（S1 合规全流程/S2 超限取证/S3 负例三连）。

用法（宿主 Python，uas/ 根）：
  backend/.venv/Scripts/python.exe sim/scenarios.py S1 [--fake-chain]
  backend/.venv/Scripts/python.exe sim/scenarios.py S3   （负例三连——不需要 SITL）

判决行：S1 exit 0 全链绿；S3 exit 0=全拒（负例全捕获）、exit 2=有漏拒。
S2 需真 SITL（围栏触发 STATUSTEXT 实锤），--fake 模式跳过飞控面。
桥接连接形态：bridge 为进程内调用（测试同构）；真实部署=uvicorn server:app。
"""

from __future__ import annotations

import json
import secrets
import sys
import time
from pathlib import Path

import pytest

UAS = Path(__file__).resolve().parents[1]
BACKEND = UAS / "backend"
BRIDGE = UAS / "gcs" / "bridge"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BRIDGE))

from fastapi.testclient import TestClient  # noqa: E402

from app.authz.service import build_token, sign_token, token_hash  # noqa: E402
from app.kms import engine_signing_keypair, ra_signing_keypair  # noqa: E402
from app.ra.credential import build_message, sign_credential  # noqa: E402
import server as _server_mod  # noqa: E402
bridge_app = _server_mod.app


def _mk_token(auth_id: int, alt_max: int, plan_hash: str, sn: str, window=(0, 0)) -> bytes:
    now = int(time.time())
    tok = {
        "authId": auth_id,
        "plan_hash": plan_hash,
        "alt_max": alt_max,
        "t_start": window[0] or (now - 10),
        "t_end": window[1] or (now + 1800),
        "nonce": secrets.token_hex(16),
        "policy_version": "policy-2026-09-v1",
    }
    body = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    return (body + "|" + sign_token(body)).encode()


def _mk_token_with_key(sk_hex: str, auth_id: int, alt_max: int, plan_hash: str) -> bytes:
    from app.crypto.sm2 import sign_digest
    from app.crypto.sm3 import sm3_bytes

    now = int(time.time())
    tok = {
        "authId": auth_id, "plan_hash": plan_hash, "alt_max": alt_max,
        "t_start": now - 10, "t_end": now + 1800,
        "nonce": secrets.token_hex(16), "policy_version": "policy-2026-09-v1",
    }
    body = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    sig = sign_digest(sk_hex, sm3_bytes(body.encode()))
    return (body + "|" + sig).encode()


def _mk_sub_credential(session_pk_hex: str):
    _sk, ra_pub = ra_signing_keypair()
    _priv, _pub = ra_signing_keypair()
    msg = build_message(
        ra_pub, secrets.token_bytes(32), secrets.token_bytes(16),
        b"110101199001011234", 3, b"FZ-SN-SCEN", session_pk_hex, 1900000000,
    )
    return msg, sign_credential(_priv, msg)


def scenario_s1() -> int:
    """S1 合规全流程（bridge 面）：arm→telemetry→checkpoint→breach 监测。"""
    c = TestClient(bridge_app)
    plan_hash = secrets.token_hex(32)
    token = _mk_token(11, 120, plan_hash, "FZ-SN-SCEN")
    r = c.post("/arm", json={"token_payload_hex": token.hex(), "plan_hash_hex": plan_hash})
    d = r.json()
    assert d["ok"], f"S1 ARM 失败: {d}"
    assert d["alt_max"] == 120 and d["first_arm"]
    assert d["fence_state_hex"] == "01007800"  # enable‖120 BE16‖rsv
    r = c.post("/telemetry/start", json={"auth_id": 11, "fence_state_hex": "01007800"})
    assert r.json()["ok"]
    now = int(time.time())
    for i in range(8):
        rr = c.post("/telemetry/sample", json={
            "t_epoch": now + i, "alt_cm": 5000 + i * 100,
            "lat_1e7": 310000000, "lon_1e7": 121000000,
        })
        assert rr.json()["ok"]
    ev = c.post("/telemetry/breach", params={"t_epoch": now, "alt_cm": 12500, "source": 2})
    assert ev.json()["event"]["event_type"] == 2
    aud = c.get("/audit").json()
    assert len(aud["arms"]) == 1
    print(f"[S1] 全流程绿：ARM(围栏120m)+8 样本链+违规取证+审计行 authId=11")
    return 0


def scenario_s3() -> int:
    """S3 负例三连（评委可上手）：过期令牌/篡改 alt_max/他人密钥——全拒。"""
    c = TestClient(bridge_app)
    plan_hash = secrets.token_hex(32)
    # ① 过期令牌
    now = int(time.time())
    tok = {
        "authId": 21, "plan_hash": plan_hash, "alt_max": 120,
        "t_start": now - 3600, "t_end": now - 60,
        "nonce": secrets.token_hex(16), "policy_version": "policy-2026-09-v1",
    }
    body = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    expired = (body + "|" + sign_token(body)).encode()
    r = c.post("/arm", json={"token_payload_hex": expired.hex(), "plan_hash_hex": plan_hash})
    assert not r.json()["ok"] and r.json()["code"] == "window_expired", r.json()
    print("[S3-①] 过期令牌 → window_expired 拒绝 ✓")
    # ② 篡改 alt_max（签发后改参数=签名不符）
    token = _mk_token(22, 120, plan_hash, "FZ-SN-SCEN")
    tok2, sig = token.rsplit(b"|", 1)
    d2 = json.loads(tok2)
    d2["alt_max"] = 999  # 评委改高上限
    body2 = json.dumps(d2, separators=(",", ":"), sort_keys=True)
    tampered = (body2 + "|" + sig.decode()).encode()
    r = c.post("/arm", json={"token_payload_hex": tampered.hex(), "plan_hash_hex": plan_hash})
    assert not r.json()["ok"] and r.json()["code"] == "bad_signature", r.json()
    print("[S3-②] 篡改 alt_max → bad_signature 拒绝 ✓")
    # ③ 他人密钥（非 engine 签发）
    _esk, other_pub = engine_signing_keypair()
    rogue = _mk_token_with_key(
        _rogue_key(), 23, 500, plan_hash
    )
    r = c.post("/arm", json={"token_payload_hex": rogue.hex(), "plan_hash_hex": plan_hash})
    assert not r.json()["ok"] and r.json()["code"] == "bad_signature", r.json()
    print("[S3-③] 他人密钥伪造 → bad_signature 拒绝 ✓")
    denials = c.get("/audit").json()["denials"]
    assert len(denials) >= 3, f"审计行缺失: {denials}"
    print(f"[S3] 负例三连全拒+审计行 {len(denials)} 条")
    return 0


_ROGUE_PRIV = None


def _rogue_key() -> str:
    """对抗密钥（评委视角：非 engine 域的 SM2 钥——确定性生成不入库）。"""
    global _ROGUE_PRIV
    if _ROGUE_PRIV is None:
        from app.kms import _derive_priv

        _ROGUE_PRIV = _derive_priv(b"FZ-ATTACKER-ROGUE-KEY")
    return _ROGUE_PRIV


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "S1"
    if which == "S1":
        raise SystemExit(scenario_s1())
    if which == "S3":
        raise SystemExit(scenario_s3())
    print("用法: scenarios.py S1|S3（S2 需真 SITL——sim/scenario_s2_itl.py）")
    raise SystemExit(1)
