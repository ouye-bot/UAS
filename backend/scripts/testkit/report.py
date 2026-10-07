"""统一报告引擎（三套件共用）。

用法：
    from testkit.report import ReportBuilder
    rb = ReportBuilder(suite="crypto")
    m = rb.module("C1_vectors")
    m.pass_("C1-1 SM3 标准向量 'abc'", defense_ref="app/crypto/sm3.py", latency_ms=0.4)
    m.fail("C1-2 SM2 签名向量", expected="MATCH", actual="MISMATCH")
    m.xfail("C1-3 已知边界 B7", reason="电路行 4719")
    ...
    rb.save("reports")   # 落盘 + 打印汇总 + 返回 exit code
"""
from __future__ import annotations

import datetime as dt
import json
import os
import platform
import secrets
import sys
import time

SCHEMA_VERSION = 1
SENSITIVE_KEY_HINTS = ("token", "password", "passwd", "secret", "sk_hex", "private", "cipher_text", "ciphertext")


def _sanitize(detail: dict) -> dict:
    """报告脱敏（铁律 10）：键名疑似敏感物（令牌/口令/私钥/密文）的值替换为摘要形态。"""
    out = {}
    for k, v in (detail or {}).items():
        if any(h in k.lower() for h in SENSITIVE_KEY_HINTS) and isinstance(v, str) and v:
            out[k] = f"<{len(v)} chars, redacted>"
        else:
            out[k] = v
    return out


def env_snapshot(uas_root) -> dict:
    """环境快照（铁律 9）：无快照的报告不可归因。"""
    import subprocess

    def _git():
        try:
            return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(uas_root),
                                  capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            return "unknown"

    snap = {
        "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        "git_commit": _git(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "hostname": platform.node(),
    }
    try:
        import psutil

        vm = psutil.virtual_memory()
        snap["cores"] = psutil.cpu_count(logical=True)
        snap["ram_gb"] = round(vm.total / (1 << 30), 1)
    except Exception:
        pass
    # 电路画像（与 docs/性能档案.md「电路换代批」口径一致）
    snap["circuit"] = {"name": "AUTH@2026-10 换代", "constraints": 19578, "proof_bytes": 22675632}
    snap["prove_max_concurrent"] = os.environ.get("FZ_PROVE_MAX_CONCURRENT", "1")
    snap["chain_mode"] = os.environ.get("FZ_CHAIN_ANCHOR", "")
    return snap


class Module:
    def __init__(self, rb: "ReportBuilder", name: str, display: str = ""):
        self.rb, self.name, self.display = rb, name, display or name
        m = rb.modules.setdefault(name, {"display": display or name, "items": []})
        self.items: list[dict] = m["items"]  # 直接持报告容器引用（注册即生效）

    def _add(self, name: str, verdict: str, *, defense_ref: str = "", expected: str = "",
             actual: str = "", attack_success: bool = False, latency_ms=None, detail=None):
        if self.rb.aborted:
            return
        self.items.append({
            "name": name, "verdict": verdict,
            "expected": expected, "actual": actual,
            "defense_ref": defense_ref, "attack_success": bool(attack_success),
            "latency_ms": latency_ms, "detail": _sanitize(detail),
        })
        self.rb.live(name, verdict, expected, actual)

    def pass_(self, name, *, defense_ref="", latency_ms=None, detail=None):
        self._add(name, "pass", defense_ref=defense_ref, latency_ms=latency_ms, detail=detail)

    def fail(self, name, *, expected="", actual="", defense_ref="", attack_success=False, detail=None):
        self._add(name, "fail", expected=expected, actual=actual, defense_ref=defense_ref,
                  attack_success=attack_success, detail=detail)

    def xfail(self, name, *, reason="", defense_ref=""):
        """已知边界（strict 语义）：计入 xfail 汇总，不进 passed——无软通道。"""
        self._add(name, "xfail", detail={"reason": reason}, defense_ref=defense_ref)

    def env_error(self, name, detail=None):
        """铁律 3：环境错误（404/连接拒绝）——中止整套。"""
        self._add(name, "environment_error", detail=detail)
        self.rb.abort(f"{self.name}/{name}: 环境错误——整套中止（{detail or ''}）")


class ReportBuilder:
    def __init__(self, suite: str, uas_root):
        self.suite = suite
        self.uas_root = str(uas_root)
        self.env = env_snapshot(uas_root)
        self.run_id = secrets.token_hex(6)
        self.started = time.time()
        self.modules: dict[str, dict] = {}
        self.aborted = False
        self.abort_reason = ""

    def module(self, name: str, display: str = "") -> Module:
        self.modules.setdefault(name, {"display": display or name, "items": []})
        return Module(self, name, display)

    def live(self, name, verdict, expected="", actual=""):
        icon = {"pass": "[OK]", "fail": "[FAIL]", "xfail": "[XF]", "environment_error": "[ENV]"}[verdict]
        line = f"  {icon} {name}"
        if verdict == "fail":
            line += f"  期望={expected} 实际={actual}"
        print(line, flush=True)

    def abort(self, reason: str):
        self.aborted, self.abort_reason = True, reason
        print(f"== [中止] {reason} ==", flush=True)

    def build(self) -> dict:
        mods, total = {}, 0
        p = f = x = e = 0
        attack_hits = []
        for name, m in self.modules.items():
            items = m["items"]
            c = {"pass": 0, "fail": 0, "xfail": 0, "environment_error": 0}
            for it in items:
                c[it["verdict"]] = c.get(it["verdict"], 0) + 1
                if it["attack_success"]:
                    attack_hits.append(f"{name}/{it['name']}")
            p += c["pass"]; f += c["fail"]; x += c["xfail"]; e += c["environment_error"]
            total += len(items)
            mods[name] = {"display": m["display"], "passed": c["pass"], "failed": c["fail"],
                          "xfail": c["xfail"], "total": len(items), "items": items}
        verdict = "failed" if (f or attack_hits or self.aborted) else ("empty" if total == 0 else "success")
        return {
            "schema_version": SCHEMA_VERSION, "run_id": self.run_id, "suite": self.suite,
            "env": self.env,
            "summary": {"total": total, "passed": p, "failed": f, "xfail": x,
                        "environment_error": e, "pass_rate": round(p / total, 4) if total else 0,
                        "duration_s": round(time.time() - self.started, 1),
                        "verdict": verdict, "aborted": self.aborted,
                        "abort_reason": self.abort_reason,
                        "attack_success": attack_hits},
            "modules": mods,
        }

    def save(self, out_dir="reports"):
        os.makedirs(out_dir, exist_ok=True)
        rep = self.build()
        path = os.path.join(out_dir, f"{self.suite}-report-{self.run_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
        s = rep["summary"]
        print(f"== {self.suite} 判定: {s['verdict'].upper()} | {s['passed']}/{s['total']} 通过 | "
              f"xfail {s['xfail']} | 失败 {s['failed']} | {s['duration_s']}s ==")
        if s["attack_success"]:
            print("== ⚠ 攻击成功项:", "; ".join(s["attack_success"]))
        if self.aborted:
            print("== 中止原因:", self.abort_reason)
        print(f"== 报告: {path}")
        return path
