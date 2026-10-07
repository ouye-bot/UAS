"""桥侧出证任务落盘+看门狗+准入/限速测试（2026-10-04 并发阻塞根修批）。

被测面（gcs/bridge/prover.py——sys.path 注入同 test_bridge_core）：
- 任务二：prove_tasks 表镜像/读回/重启恢复（如实 failed 可重试）/看门狗
  lease 超时强杀语义（防翻案：终态先到者赢）
- 任务一：内存感知准入纯判决（fail-open/拒绝/放行）+绑定面每 IP 限速窗
  +产物跨卷发布（EXDEV 回落 copyfile+原子 rename）+zkc 看门狗软超时强杀
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND.parent / "gcs" / "bridge"))


@pytest.fixture()
def prover(tmp_path, monkeypatch):
    """隔离的 prover 模块面：cases/工作区/任务库全落 tmp——零污染生产库。"""
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("FZ_PROVE_TMP_DIR", str(tmp_path / "ws"))
    monkeypatch.setenv("FZ_PROVE_TASK_DB", str(tmp_path / "tasks.db"))
    import prover

    prover._TASKS.clear()
    prover._RATE_WINDOWS.clear()  # 限速窗跨测试隔离（真实时间戳残留会污染下一测）
    prover._PROVE_DB_CONN = None  # 单例连接随库路径重置（tmp 隔离）
    prover._MEM_CACHE.update(ts=0.0, gib=-1.0)
    yield prover
    prover._TASKS.clear()
    prover._RATE_WINDOWS.clear()
    prover._PROVE_DB_CONN = None


# ---- 任务二：任务表镜像/读回 ----


def test_task_row_insert_update_get(prover):
    prover._db_task_insert("tid-1", kind="auth", case_id="c1", status="assembling", t_epoch=7)
    prover._db_task_update("tid-1", stage="prove_spawn", stage_ts={"enter": 1.0}, pid=4242)
    row = prover._db_task_get("tid-1")
    assert row is not None
    assert row["kind"] == "auth" and row["case_id"] == "c1" and row["status"] == "assembling"
    assert row["stage"] == "prove_spawn" and row["stage_ts"] == {"enter": 1.0}
    assert row["pid"] == 4242 and row["t_epoch"] == 7
    assert row["lease_until"] is not None, "受理登记即带租约（看门狗判据立即可用）"
    assert prover._db_task_get("nope") is None


def test_task_status_reads_db_fallback(prover):
    """内存未命中→库读回（桥重启后恢复任务仍可查——不蒸发）。"""
    prover._db_task_insert("tid-2", kind="trail", case_id="c2", status="proving")
    prover._db_task_update("tid-2", error="x")
    r = prover.task_status("tid-2")
    body = json.loads(r.body.decode())
    assert r.status_code == 200 and body["code"] == "ok"
    assert body["data"]["status"] == "proving" and body["data"]["kind"] == "trail"
    assert body["data"]["stage_ts"] == {}
    assert prover.task_status("ghost").status_code == 404


def test_task_status_prefers_memory(prover):
    prover._db_task_insert("tid-3", kind="auth", case_id="c3", status="assembling")
    prover._TASKS["tid-3"] = {"status": "proving", "case_id": "c3", "stage": "prove_spawn"}
    body = json.loads(prover.task_status("tid-3").body.decode())
    assert body["data"]["status"] == "proving" and body["data"]["stage"] == "prove_spawn"


def test_db_finish_is_anti_reversal(prover):
    """终态写入仅活跃态可入（防翻案：done 不得覆盖看门狗先判的 failed）。"""
    prover._db_task_insert("tid-4", kind="auth", case_id="c4", status="proving")
    prover._db_task_finish("tid-4", "failed", "watchdog")
    prover._db_task_finish("tid-4", "done")  # 迟到的 done——必须被拒
    assert prover._db_task_get("tid-4")["status"] == "failed"


# ---- 任务二：重启恢复 + 看门狗 ----


def test_recover_marks_active_failed_on_startup(prover):
    prover._db_task_insert("tid-5", kind="auth", case_id="c5", status="proving")
    prover._db_task_insert("tid-6", kind="auth", case_id="c6", status="done")
    n = prover._recover_tasks_on_startup()
    assert n == 1, "仅活跃任务参与恢复"
    row = prover._db_task_get("tid-5")
    assert row["status"] == "failed" and "bridge_restarted" in row["error"]
    assert prover._db_task_get("tid-6")["status"] == "done", "终态不动"
    assert prover._recover_tasks_on_startup() == 0, "恢复幂等"


def test_watchdog_sweep_kills_stale_lease_only(prover):
    prover._db_task_insert("tid-7", kind="auth", case_id="c7", status="proving")
    prover._db_task_insert("tid-8", kind="auth", case_id="c8", status="proving")
    fresh = time.time() + 60
    stale = time.time() - 5
    prover._db_task_update("tid-7", lease_until=stale)
    prover._db_task_update("tid-8", lease_until=fresh)
    prover._TASKS["tid-7"] = {"status": "proving", "case_id": "c7"}
    n = prover._prove_watchdog_sweep()
    assert n == 1
    assert prover._db_task_get("tid-7")["status"] == "failed"
    assert "prove_watchdog" in prover._db_task_get("tid-7")["error"]
    assert prover._TASKS["tid-7"]["status"] == "failed", "内存面同步终态"
    assert prover._db_task_get("tid-8")["status"] == "proving", "租约新鲜不动"


def test_kill_orphan_pid_guard_windows_safe(prover):
    """非 Linux 平台（本测试宿主）=尽力面直接放弃——不误杀。"""
    assert prover._kill_orphan_pid(None) is False
    assert prover._kill_orphan_pid(0) is False


# ---- 任务一：内存感知准入（纯判决面） ----


def test_memory_admission_verdicts(prover):
    # 批 4-5 fail-open 收口：可用内存不可知=保守拒绝（人话指重试/排查），不再 -1 放行
    ok, msg = prover._memory_admission(-1.0, 13.0)
    assert not ok and "无法确认" in msg and "重试" in msg
    ok, msg = prover._memory_admission(8.0, 13.0)
    assert not ok and "内存" in msg and "重试" in msg, "低于峰值需求=人话拒绝"
    ok, _ = prover._memory_admission(13.0, 13.0)
    assert ok, "恰好达标=放行"


def test_admit_gate_memory_insufficient(prover, monkeypatch):
    monkeypatch.setattr(prover, "_PROVE_MAX", 4)
    monkeypatch.setattr(prover, "_host_avail_gib", lambda: 3.0)
    with prover._LOCK:
        resp = prover._admit_task_locked("tid-9", {"case_id": "c9"}, kind="auth")
    assert resp is not None and resp.status_code == 429
    assert json.loads(resp.body)["code"] == "memory_insufficient"
    assert "tid-9" not in prover._TASKS, "拒绝=不登记"


def test_admit_gate_count_first_then_register(prover, monkeypatch):
    monkeypatch.setattr(prover, "_PROVE_MAX", 1)
    monkeypatch.setattr(prover, "_host_avail_gib", lambda: 99.0)
    with prover._LOCK:
        r1 = prover._admit_task_locked(
            "tid-a", {"case_id": "ca", "status": "assembling"}, kind="auth"
        )
        r2 = prover._admit_task_locked("tid-b", {"case_id": "cb"}, kind="auth")
    assert r1 is None and r2 is not None and r2.status_code == 429
    assert json.loads(r2.body)["code"] == "prove_busy"
    assert prover._db_task_get("tid-a") is not None, "受理即落库（任务二）"
    assert prover._db_task_get("tid-b") is None, "拒绝不落库"


# ---- 任务一：绑定面限速（每 IP 30/min 内存窗） ----


class _FakeRequest:
    def __init__(self, host: str = "1.2.3.4"):
        from types import SimpleNamespace

        self.client = SimpleNamespace(host=host)


def test_rate_limit_window(prover):
    for _ in range(30):
        assert prover._rate_limit_ip(_FakeRequest(), max_per_min=30) is None
    r = prover._rate_limit_ip(_FakeRequest(), max_per_min=30)
    assert r is not None and r.status_code == 429, "第 31 次=429"
    assert prover._rate_limit_ip(_FakeRequest(host="other"), max_per_min=30) is None, "按 IP 分窗"
    assert prover._rate_limit_ip(None) is None, "无 request（直调）=不限"


def test_rate_limit_window_expires(prover, monkeypatch):
    now = {"t": 1000.0}
    monkeypatch.setattr(prover.time, "time", lambda: now["t"])
    for _ in range(30):
        assert prover._rate_limit_ip(_FakeRequest(), max_per_min=30) is None
    assert prover._rate_limit_ip(_FakeRequest(), max_per_min=30) is not None
    now["t"] += 61.0  # 窗口滑出
    assert prover._rate_limit_ip(_FakeRequest(), max_per_min=30) is None, "窗过即放行"


# ---- 任务一：产物跨卷发布 + zkc 看门狗 ----


def test_publish_artifact_cross_device_fallback(prover, tmp_path):
    src = tmp_path / "out" / "proof.bin"
    src.parent.mkdir(parents=True)
    src.write_bytes(b"\x01\x02proof")
    dst = tmp_path / "cases" / "c" / "proof.bin"
    dst.parent.mkdir(parents=True)

    calls = {"n": 0}

    def exdev_replace(a, b):
        calls["n"] += 1
        raise OSError(18, "Invalid cross-device link")  # EXDEV

    prover._publish_artifact(src, dst, tries=2, gap=0.0, _replace=exdev_replace)
    assert calls["n"] == 1
    assert dst.read_bytes() == b"\x01\x02proof", "EXDEV→copyfile+.part 原子 rename"
    assert not list(dst.parent.glob("*.part")), ".part 用毕即清"
    # 同卷路径：rename 直迁（src 消失）
    src2 = tmp_path / "out2.bin"
    src2.write_bytes(b"z")
    prover._publish_artifact(src2, tmp_path / "cases" / "c" / "out2.bin", _replace=None)
    assert not src2.exists() and (tmp_path / "cases" / "c" / "out2.bin").exists()


def test_publish_artifact_9p_transient_retry(prover, tmp_path):
    src = tmp_path / "s.bin"
    src.write_bytes(b"d")
    dst = tmp_path / "d.bin"

    flaky = {"n": 0}

    def flaky_replace(a, b):
        flaky["n"] += 1
        if flaky["n"] < 2:
            raise OSError(5, "I/O error")  # 9p 瞬态
        a.replace(b)

    prover._publish_artifact(src, dst, tries=3, gap=0.0, _replace=flaky_replace)
    assert dst.read_bytes() == b"d"


class _FakeProc:
    """永不退出的子进程替身（软超时看门狗裁决面）。"""

    def __init__(self):
        self.killed = False
        self.waited = False

    def poll(self):
        return None

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited = True
        return -9


def test_prove_watchdog_soft_timeout(prover, monkeypatch):
    # 时钟快进：poll 恒 None，每 tick 快进 10s——1500s 软超时必被触发
    t = {"v": time.time()}
    monkeypatch.setattr(prover.time, "time", lambda: t["v"])

    def fake_sleep(s):
        t["v"] += 10.0

    monkeypatch.setattr(prover.time, "sleep", fake_sleep)
    proc = _FakeProc()
    rc = prover._wait_prove_exit(proc, soft_timeout_s=1500, gap_s=1.0)
    assert rc is None, "软超时返回 None（调用方转人话 RuntimeError）"
    assert proc.killed and proc.waited, "强杀+回收"


def test_prove_watchdog_normal_exit(prover, monkeypatch):
    class _OkProc(_FakeProc):
        def __init__(self):
            super().__init__()
            self._polls = 0

        def poll(self):
            self._polls += 1
            return 0 if self._polls >= 2 else None

    t = {"v": time.time()}
    monkeypatch.setattr(prover.time, "time", lambda: t["v"])
    monkeypatch.setattr(prover.time, "sleep", lambda *_: None)
    rc = prover._wait_prove_exit(_OkProc(), soft_timeout_s=1500)
    assert rc == 0


# ---- 工作区分离（9p 规避） ----


def test_workspace_dir_windows_is_cases(prover, monkeypatch):
    """Windows 桥：工作区=cases 目录（NTFS 本地——行为与既有单测同构）。"""
    monkeypatch.delenv("FZ_PROVE_TMP_DIR", raising=False)
    monkeypatch.setattr(prover.sys, "platform", "win32")
    assert prover._workspace_dir() == prover._cases_dir()


def test_sweep_covers_workspace_and_cases(prover, tmp_path, monkeypatch):
    """失败现场清扫双根：工作区与案卷面分离后两侧 _tmp_* 都要扫。"""
    import os
    import time as _t

    monkeypatch.setenv("FZ_PROVE_FAILURE_TTL_S", "3600")
    old = prover._workspace_dir() / "_tmp_old"
    old.mkdir(parents=True, exist_ok=True)
    (old / "failure.json").write_text("{}", encoding="utf-8")
    two_h_ago = _t.time() - 7200
    os.utime(old, (two_h_ago, two_h_ago))
    fresh_ws = prover._workspace_dir() / "_tmp_fresh"
    fresh_ws.mkdir(parents=True, exist_ok=True)
    fresh_cases = prover._cases_dir() / "_tmp_in_cases"
    fresh_cases.mkdir(parents=True, exist_ok=True)
    prover._sweep_stale_failures()
    assert not old.exists(), "工作区超龄现场清扫"
    assert fresh_ws.exists() and fresh_cases.exists(), "TTL 内现场保留（双根）"
