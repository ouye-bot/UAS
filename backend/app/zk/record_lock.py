"""recordAuth 临界区互斥（R4 第二批 B-P2-6 根修形态）。

定谳（2026-09-26，评审建议「按实际 authId 放行」经安全模型审查否决）：
令牌内嵌 authId 必须**先铸后链**——链在 recordAuth 时按 tokenHash 顺序分配
authId，预测与上链之间存在竞窗。多 worker 并发排水时后来者 authId 错位；错位
后若按链上实际值放行，令牌内嵌的仍是预测值（已随 tokenHash 上链不可回铸），
而 ARM 闸门/检查点锚定/TRAIL 绑定均消费**内嵌值**（sitl_link.attempt_arm →
record_arm(tok["authId"]) → fence sign_checkpoint(authId) → 链上 anchorCheckpoint）
——锚定会串号到并发窗内他人的授权行（跨申请数据污染，比烧一张授权更糟）。

唯一正确修法=临界区互斥使预测恒中：
- 同进程组（engine 唯一写面）内 next_auth_id→mint→recordAuth 串行化，
  并发排水全部 approved（评审验收线「双 worker 并发 4 申请全 approved」）；
- 错位仅剩「写面被进程组外写入」形态——保持 fail-closed 拒绝（守卫不动）。

形态：跨进程=OS 文件锁（Windows msvcrt / POSIX fcntl——进程崩溃自动释放，
无陈旧锁）；PostgreSQL 生产档可升 pg_advisory_lock（跨机，env
FZ_RECORD_AUTH_LOCK 指定锁文件路径，缺省临时目录）。
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager


class RecordAuthLockTimeout(RuntimeError):
    """锁忙等超时——调用方按瞬时重试轴处理（链拥堵/持锁 worker 崩溃残留窗）。"""


def _lock_path() -> str:
    import tempfile
    from pathlib import Path

    env = os.environ.get("FZ_RECORD_AUTH_LOCK")
    if env:
        return env
    return str(Path(tempfile.gettempdir()) / "fz_record_auth.lock")


@contextmanager
def record_auth_lock(timeout_s: float | None = None):
    """authId 预测临界区互斥（跨进程/跨线程——文件锁语义见模块 docstring）。"""
    timeout = (
        timeout_s if timeout_s is not None else float(os.environ.get("FZ_RECORD_AUTH_LOCK_S", "90"))
    )
    path = _lock_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR)
    acquired = False
    try:
        deadline = time.monotonic() + timeout
        while True:
            if _try_lock(fd):
                acquired = True
                break
            if time.monotonic() >= deadline:
                raise RecordAuthLockTimeout(f"recordAuth 临界区锁等待超时 {timeout}s（{path}）")
            time.sleep(0.05)
        yield
    finally:
        if acquired:
            _unlock(fd)
        os.close(fd)


def _try_lock(fd: int) -> bool:
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:  # pragma: no cover——句柄关闭时内核已释放
            pass
    else:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:  # pragma: no cover
            pass
