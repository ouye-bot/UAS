"""桥接实时出证服务（R1-1c）：见证不出设备的飞手侧证明生产线。

架构事实：AUTH 见证（身份证号/盐/持有者私钥）只在桥接进程内存组装——
透明 SNARK（零可信设置）使飞手本地 prove 成为自身计算；只有证明、
公开实例与验证参数进入服务端验证面（实例驱动，spec/秘密不上路）。

任务状态机：assembling → proving → done / failed（失败含可读原因）。
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/prove", tags=["prove"])

import struct as _struct


class TrailStartIn(BaseModel):
    """TRAIL 合规证明出证请求（R1-6）：数据面=本机遥测语句窗口（128 样本），
    alt_max_cm=令牌 meters×100（TRAIL 电路口径=cm；转换在调用面）。
    window=行程证书包窗口号（2026-09-28）：samples[128w:128(w+1)] 切片，
    每窗口自 GENESIS 重放独立成证（窗口头自含语义不变）。"""
    alt_max_cm: int
    window: int = 0


def _trip_index_path() -> Path:
    """行程索引（JSONL 追加——桥重启存活；与案卷同目录持久化）。"""
    return _cases_dir() / "trip_index.jsonl"


def _record_trip(rec: dict) -> None:
    import json as _json

    with _LOCK:
        with _trip_index_path().open("a", encoding="utf-8") as f:
            f.write(_json.dumps(rec, ensure_ascii=False) + "\n")


def _load_trip(auth_id: int) -> list[dict]:
    """按授权号过滤的行程窗口清单（损坏行跳过——索引面不阻断出证）。"""
    import json as _json

    out: list[dict] = []
    p = _trip_index_path()
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            r = _json.loads(line)
        except ValueError:
            continue
        if r.get("auth_id") == auth_id:
            out.append(r)
    out.sort(key=lambda r: r.get("window", 0))
    return out

_TASKS: dict[str, dict] = {}
_LOCK = threading.Lock()

# 出证并发闸+任务表回收（2026-09-28 安全深检 B-P2）：AUTH/TRAIL 单次出证
# ~14GB 内存——并发多任务可自伤（内存竞争史复燃条件）；_TASKS 只进不出=
# 慢性泄漏。FZ_PROVE_MAX_CONCURRENT 缺省 1（桥接=单飞手本机，串行即够）；
# 终态任务超 FZ_TASK_TTL_S（缺省 2h——判决件下载走 case_id 不依赖任务表）
# 在新任务受理时惰性回收。
_PROVE_MAX = int(os.environ.get("FZ_PROVE_MAX_CONCURRENT", "1"))
_TASK_TTL_S = int(os.environ.get("FZ_TASK_TTL_S", "7200"))


def _purge_stale_tasks_locked() -> None:
    """终态任务超 TTL 回收（持锁调用）。"""
    now = time.time()
    stale = [
        tid for tid, t in _TASKS.items()
        if t.get("status") in ("done", "failed")
        and now - t.get("finished_at", 0) > _TASK_TTL_S
    ]
    for tid in stale:
        _TASKS.pop(tid, None)


def _active_prove_count_locked() -> int:
    return sum(1 for t in _TASKS.values() if t.get("status") in ("assembling", "proving"))


class ProveStartIn(BaseModel):
    # 申请面（公开）
    plan_hash_hex: str
    nonce_hex: str
    class_id: int
    # 登记材料（本机浏览器持有——仅在飞手侧用于出证，永不上送授权服务）
    id_number: str
    cert_level: int
    sn: str
    salt_hex: str
    # 子凭证材料（RA 签发回执）
    id_prime_hex: str
    sig_hex: str
    expires_at: str
    holder_sk_hex: str
    holder_pk_hex: str


def _zksvc_dir() -> str:
    return os.environ.get("FZ_ZKSVC_DIR", "")


def _cases_dir() -> Path:
    d = Path(os.environ.get("FZ_ZK_CASES_DIR", "/tmp/fz-zk-cases"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _backend_api() -> str:
    return os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")


def _http_get(url: str) -> dict:
    import json as _json
    import urllib.request

    # 回环调用禁系统代理（Windows 常见坑：代理拦 127.0.0.1 致线程挂死）
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=15) as r:
        return _json.loads(r.read().decode())


def _assemble_and_prove(task_id: str, body: ProveStartIn, binding: dict) -> None:
    """工作线程：见证→JobSpec→zkc prove。绑定面由 /prove/start 请求线程单源获取
    并随任务传入（R1 收口定谳：绑定含 t_epoch=now 非确定——客户端与桥接各自取
    必得双值，证明绑 A/申请交 B ⟹ 实例 21 必 mismatch；单源=桥接取、随响应回传、
    申请消费同一值）。失败原因写回任务（可读）。"""
    import json as _json

    task = _TASKS[task_id]
    case_dir = _cases_dir() / task["case_id"]
    tmp = _cases_dir() / f"_tmp_{task_id}"
    try:
        tmp.mkdir(parents=True, exist_ok=True)
        # ② RA 公钥（公开面）
        pk = _http_get(f"{_backend_api()}/ra/pubkey")
        ra_pk_hex = pk["data"]["ra_pub_hex"]
        # ③ 撤销非成员见证（公开镜像）
        w = _http_get(
            f"{_backend_api()}/ra/revocation/witness?holder_pk_hex={body.holder_pk_hex}"
        )
        wd = w["data"]
        # ④ JobSpec 组装（秘密面——只落临时文件，prove 后即焚）
        exp_u = int(datetime.fromisoformat(body.expires_at).timestamp()) & 0xFFFFFFFF
        id_number_hex = body.id_number.encode().hex()
        serial_hex = body.sn.encode().hex()
        spec = {
            "profile": "auth",
            "reps": 16,
            "log_rate": 1,
            "binding": {
                "challenge_hex": binding["challenge_hex"],
                "pred_id": binding["pred_id"],
                "t_epoch": binding["t_epoch"],
                "required_level": binding["required_level"],
            },
            "input": {
                "kind": "auth",
                "ra_pk_hex": ra_pk_hex,
                "id_prime_hex": body.id_prime_hex,
                "salt_hex": body.salt_hex,
                "id_number_hex": id_number_hex,
                "cert_level": body.cert_level,
                "serial_hex": serial_hex,
                "holder_sk_hex": body.holder_sk_hex,
                "holder_pk_hex": body.holder_pk_hex,
                "exp_u": exp_u,
                "class_id": body.class_id,
                "sig_hex": body.sig_hex,
                "smt_siblings_hex": "".join(wd["siblings_hex"]),
                "smt_root_hex": wd["root_hex"],
            },
        }
        spec_path = tmp / "job.json"
        spec_path.write_text(_json.dumps(spec), encoding="utf-8")
        print(f"[prover] holder_sk_hex len={len(spec['input']['holder_sk_hex'])} "
              f"holder_pk_hex len={len(spec['input']['holder_pk_hex'])} "
              f"id_prime len={len(body.id_prime_hex)}", flush=True)
        task["status"] = "proving"
        # ⑤ 出证（双档）：FZ_PROVE_REMOTE=ssh:目标 时走服务器 prover 池（AUTH 内存
        # 密集 ~20GB，本机空闲不足时必需）；否则本地 zkc prove（透明 SNARK，
        # 飞手自身计算）。两档产物同为 proof/vp/instances/verdict 四件。
        remote = os.environ.get("FZ_PROVE_REMOTE", "")
        if remote.startswith("ssh:"):
            _prove_remote(remote[4:], spec_path, tmp / "out")
        else:
            _prove_local(spec_path, tmp / "out")
        out = tmp / "out"
        # ⑥ 产物迁正式 case 目录（供 /authz/apply 与 worker 验证消费）
        case_dir.mkdir(parents=True, exist_ok=True)
        for name in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json"):
            (out / name).replace(case_dir / name)
        # done 语义=按下载/消费路径自读可服务（9p 可见性窗口——同 TRAIL 线程）
        _await_case_artifacts(case_dir, ("proof.bin", "verifier_param.bin",
                                         "instances.json", "verdict.json"))
        task["status"] = "done"
        task["finished_at"] = time.time()
        task["case_id"] = task["case_id"]
        task["t_start"] = binding["t_epoch"]
        task["alt_max"] = binding["alt_max"]
    except Exception as e:  # noqa: BLE001——失败原因可读回传
        task["status"] = "failed"
        task["error"] = str(e)[:400]
        task["finished_at"] = time.time()
    finally:
        # 秘密面即焚（A-P2-1 收口）：成功=整目录删除；失败=保留**脱敏现场**
        # （failure.json=错误+zkc stderr 尾部——诊断面），job.json（含身份证号/
        # 盐/出示私钥明文见证）即焚——隐私系统的磁盘取证面不滞留明文见证。
        import shutil

        if task.get("status") == "failed":
            for secret in ("job.json",):
                (tmp / secret).unlink(missing_ok=True)
            (tmp / "failure.json").write_text(
                _json.dumps(
                    {
                        "task_id": task_id,
                        "error": task.get("error", ""),
                        "at": datetime.now().isoformat(),
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            _sweep_stale_failures()
        else:
            shutil.rmtree(tmp, ignore_errors=True)


def _sweep_stale_failures() -> None:
    """失败现场 TTL 清扫（A-P2-1）：脱敏现场保留 FZ_PROVE_FAILURE_TTL_S
    （缺省 24h）供排障，超时即焚——不再无限期滞留。"""
    ttl_s = int(os.environ.get("FZ_PROVE_FAILURE_TTL_S", "86400"))
    base = _cases_dir()
    now = time.time()
    for d in base.glob("_tmp_*"):
        try:
            if now - d.stat().st_mtime > ttl_s:
                import shutil

                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            continue


def _zkc_argv(exe: str, spec_path: Path, out_dir: Path, wsl: bool = False) -> list[str]:
    """zkc prove 参数构造（两形态单源——D-Ⅱ-1）。

    WSL 形态（桥接进程在 WSL 内、interop 调 Windows zkc.exe）：路径参数必须
    wslpath -w 转 Windows 形态（Windows 进程不识 /mnt/c）；转换失败=fail-closed。
    """
    if not wsl:
        return [exe, "prove", "--spec", str(spec_path), "--out", str(out_dir)]
    conv = lambda p: subprocess.run(  # noqa: E731
        ["wslpath", "-w", str(p)], capture_output=True, text=True, timeout=10
    ).stdout.strip()
    spec_win, out_win = conv(spec_path), conv(out_dir)
    if not spec_win.startswith(("C:\\", "C:/")) or not out_win.startswith(("C:\\", "C:/")):
        raise RuntimeError(f"wslpath 转换异常: spec={spec_win!r} out={out_win!r}")
    return [exe, "prove", "--spec", spec_win, "--out", out_win]


def _prove_local(spec_path: Path, out_dir: Path) -> None:
    """本地出证：zkc prove 子进程（透明 SNARK——飞手自身计算）。

    双宿主形态（D-Ⅱ-1）：Windows 直跑；WSL 内（S1/S2 拓扑——桥接必须与 SITL 同
    侧）经 interop 调 Windows zkc.exe：路径 wslpath 转换+env 经 WSLENV 声明透传
    （WSL→Windows 进程环境默认不透传——[实测 2026-09-22]，见阶段二实施计划）。
    """
    exe = os.path.join(_zksvc_dir(), "target", "release", "zkc.exe")
    env = dict(os.environ)
    env["FZ_ZK_ALLOW_AUTH"] = "1"
    env["FZ_ZK_ALLOW_TRAIL"] = "1"
    # RAYON 扫参判决行 [实测 2026-09-21 8C/16T]：4/8/12/16 线程总墙钟
    # 179.5/138.6/129.6/138.3s（优化后二进制）——12 最优（16=超线程抖动反降）；
    # 见 docs/性能档案.md R1 节。
    env.setdefault("RAYON_NUM_THREADS", "12")
    env.setdefault("RUST_MIN_STACK", "536870912")
    wsl = sys.platform.startswith("linux") and exe.endswith(".exe")
    if wsl:
        env["WSLENV"] = ":".join(
            v
            for v in (
                "FZ_ZK_ALLOW_AUTH",
                "FZ_ZK_ALLOW_TRAIL",
                "RAYON_NUM_THREADS",
                "RUST_MIN_STACK",
                env.get("WSLENV", ""),
            )
            if v
        )
    try:
        proc = subprocess.run(
            _zkc_argv(exe, spec_path, out_dir, wsl=wsl),
            capture_output=True,
            text=True,
            env=env,
            timeout=1800,
        )
    except OSError as e:
        # 2026-09-26 队长实测：WSLInterop binfmt 条目静默消失 ⟹ Exec format
        # error（ENOEXEC）——人话+自愈指引直达调用方（原始 errno 无可操作信息）
        if e.errno == 8:
            raise RuntimeError(
                "WSL 互操作通道失效（无法启动 Windows 版证明器 zkc.exe）——"
                "在仓库根运行 bash scripts/up.sh 自动重注册互操作通道后重试"
            ) from e
        raise
    if proc.returncode != 0:
        raise RuntimeError(f"zkc prove exit {proc.returncode}: {(proc.stdout + proc.stderr)[-300:]}")


def _prove_remote(target: str, spec_path: Path, out_dir: Path) -> None:
    """服务器 prover 池出证（AUTH 内存 ~20GB，本机不足时的加速/可行档）。

    paramiko SSH：上传 spec → 服务器 zkc prove → 回传四件产物。
    秘密面声明：spec 含见证材料，prover 侧=飞手信任域（TCB 扩展，诚实标注）；
    隐私最优路径仍是本地出证（本机内存充足时）。
    """
    import json as _json

    import paramiko

    host = target
    cli = paramiko.SSHClient()
    # 🔴 主机钥 pinning（S5 安全修复——反驳手[重5]）：AutoAddPolicy=盲收任意主机钥
    # ⟹ MITM 可截获含身份证号/私钥的完整见证。必须预置 FZ_PROVE_REMOTE_HOSTKEY
    # （服务器 /etc/ssh/ssh_host_*_key.pub 的 base64 主体），不匹配即拒绝连接。
    hostkey_pin = os.environ.get("FZ_PROVE_REMOTE_HOSTKEY", "")
    if not hostkey_pin:
        raise RuntimeError(
            "远程出证需 FZ_PROVE_REMOTE_HOSTKEY（服务器 SSH 主机钥 base64——"
            "取自 /etc/ssh/ssh_host_ed25519_key.pub 第三字段）；拒绝盲连（MITM 防护）"
        )

    class _PinnedPolicy(paramiko.MissingHostKeyPolicy):
        def __init__(self, key_body: str) -> None:
            self._key_body = key_body

        def missing_host_key(self, client_, hostname, key) -> None:
            import base64 as _b64

            body = _b64.b64encode(key.asbytes()).decode().rstrip("=")
            if body != self._key_body.replace("=", ""):
                raise paramiko.SSHException(
                    "远程主机钥与 FZ_PROVE_REMOTE_HOSTKEY 不符——可能 MITM，拒绝连接"
                )

    cli.set_missing_host_key_policy(_PinnedPolicy(hostkey_pin))
    pw = os.environ.get("FZ_PROVE_REMOTE_PW")
    cli.connect(host.split("@")[-1], username=target.split("@")[0] if "@" in target else "root",
                password=pw, timeout=20) if pw else cli.connect(host.split("@")[-1], timeout=20)
    try:
        remote_dir = "/root/fz-prove/" + spec_path.parent.name
        _exec(cli, f"mkdir -p {remote_dir}")
        sftp = cli.open_sftp()
        sftp.put(str(spec_path), remote_dir + "/job.json")
        rc, out, err = _exec(
            cli,
            f"cd {remote_dir} && FZ_ZK_ALLOW_AUTH=1 FZ_ZKSVC_DIR=/root/zksvc "
            "RUST_MIN_STACK=536870912 /root/zksvc/target/release/zkc "
            "prove --spec job.json --out out",
        )
        if rc != 0:
            raise RuntimeError(f"远程 zkc prove exit {rc}: {(out + err)[-300:]}")
        out_dir.mkdir(parents=True, exist_ok=True)
        for name in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json"):
            sftp.get(f"{remote_dir}/out/{name}", str(out_dir / name))
        sftp.close()
        _exec(cli, f"rm -rf {remote_dir}")
    finally:
        cli.close()


def _exec(cli, cmd):
    """远程命令执行：返回 (rc, stdout, stderr)。"""
    _, stdout, stderr = cli.exec_command(cmd, timeout=1800)
    rc = stdout.channel.recv_exit_status()
    return rc, stdout.read().decode("utf-8", "replace"), stderr.read().decode("utf-8", "replace")


def _sign_trail_cp(auth_id, seq: int, anchor_head, fence_state) -> str:
    """设备钥签署 TRAIL 检查点（绑定语句锚定头=窗口末头+围栏态——与 zksvc
    verify_checkpoint_sig 的 checkpoint_message 同构）。"""
    from device_key import sign_checkpoint

    from server import _DEV_PRIV

    return sign_checkpoint(_DEV_PRIV, auth_id, seq, anchor_head, fence_state)


def _trail_window_rows(samples) -> tuple[bytes, bytes, int]:
    """TRAIL 语句窗口=规格行字节单源（装配器契约的对偶面，S4 雷①单源化）。

    行=14B/样本 `>IHii`（t BE4‖alt_cm BE2‖lat_1e7 i32 BE4‖lon_1e7 i32 BE4
    ——与 trail_host.rs sample_hash/sample_block 逐字段同构；🔴 lat/lon 是
    i32：SITL 默认原点在南半球，'I' 槽打包负纬度=struct 溢出 500）。行 t=
    段相对 500ms 网格（B6 时间门 Δ=500 消费口径；绝对 unix-ms 溢出 u32，
    段原点由链头锚定）。链头=自 GENESIS 对同一 rows 字节重放——assemble.rs
    装配面以 sample_hash 重算样本链并 fail-closed 对账（h≠chain_head 即拒
    「换链头」），头与行任何双源分叉必被拒绝。返回 (rows, chain_head, t_start)。
    """
    from fence import GENESIS
    from telemetry import sm3_bytes

    base_ms = 0  # 段内相对 500ms 网格（u32 域）
    parts: list[bytes] = []
    for i, s in enumerate(samples):
        try:
            parts.append(_struct.pack(">IHii", base_ms + i * 500, s[1], s[2], s[3]))
        except (_struct.error, TypeError) as exc:
            # 诊断面：坏样本的索引/值直达调用方（500 只见溢出不见值=排障
            # 要再飞一轮——遥测面缺陷必须当场定位）
            raise ValueError(f"样本 {i} 字段越界：{s!r}（{exc}）") from exc
    rows = b"".join(parts)
    head = sm3_bytes(GENESIS)
    for j in range(0, len(rows), 14):
        head = sm3_bytes(head + rows[j : j + 14])
    return rows, head, base_ms


def _fetch_trail_binding(auth_id: int, chain_head_hex: str) -> dict:
    """R4-P0-1 引擎签名轨迹绑定：backend /engine/trail/binding（X-Engine-Token
    门禁）以引擎钥签 (auth_id‖alt_max_cm‖chain_head)——高度上限由授权链路权威
    供给，证明者不可自报（zksvc 装配面三查+验签 fail-closed）。"""
    import json as _json
    import urllib.request as _ur

    token = os.environ.get("FZ_ENGINE_TOKEN", "")
    opener = _ur.build_opener(_ur.ProxyHandler({}))  # 回环禁系统代理
    req = _ur.Request(
        f"{_backend_api()}/engine/trail/binding?auth_id={auth_id}&chain_head_hex={chain_head_hex}",
        headers={"X-Engine-Token": token},
    )
    with opener.open(req, timeout=15) as r:
        d = _json.loads(r.read().decode())
    data = d.get("data") or d
    for k in ("auth_id", "alt_max_cm", "chain_head_hex", "engine_pub_hex", "sig_hex"):
        if k not in data:
            raise ValueError(f"引擎绑定响应缺字段 {k}")
    return data


def _await_case_artifacts(case_dir, names, tries: int = 6, gap: float = 1.0) -> None:
    """案卷落盘自证（2026-09-27 队长实测：Windows zkc 写 → WSL 桥经 /mnt/c 读
    存在**非确定**可见性窗口——is_file 通过≠窗口关闭）。done 的诚实语义=
    本端按下载路径**真实读回**全部产物；窗口内重试 ride-out，超时=如实 failed。"""
    import time as _t

    deadline = _t.time() + tries * gap
    while _t.time() < deadline:
        try:
            for n in names:
                with open(case_dir / n, "rb") as f:
                    f.read(1)
            return
        except OSError:
            _t.sleep(gap)
    missing = [n for n in names if not (case_dir / n).is_file()]
    raise RuntimeError(f"案卷产物不可服务（自证 {tries}×{gap}s）: {', '.join(missing)}")


def _assemble_and_prove_trail(task_id: str, alt_max_cm: int, rows: bytes, t_start: int,
                              win_head: bytes, fence_state, auth_id, binding: dict,
                              window: int = 0, n_samples_total: int = 0,
                              fence_alt_cm: int = 0) -> None:
    """TRAIL 出证工作线程（R1-6）：数据面=语句窗口行字节+锚定头（受理端点
    经 _trail_window_rows 单源计算传入——本线程不再二次打包）。检查点=设备钥
    签名绑定锚定头+围栏态；binding=引擎签名轨迹绑定（R4-P0-1 权威 alt_max）。"""
    import json as _json

    task = _TASKS[task_id]
    case_dir = _cases_dir() / task["case_id"]
    tmp = _cases_dir() / f"_tmp_{task_id}"
    # 第三方期望面源（2026-10 换代：实例 1=alt_max/2=t_start——task API 透传
    # 实际授权/窗口参数，scenario 第三方复验经 /prove/task 取期望值，不圆证）。
    task["t_start"] = t_start
    task["alt_max"] = alt_max_cm
    try:
        tmp.mkdir(parents=True, exist_ok=True)
        from server import _DEV_PUB  # 桥接单例（设备公钥）

        n_samples = len(rows) // 14
        # spec.binding=装配器消费面五字段（TrailBindingInput 契约，2026-09-28
        # 锚定对拍批：锚定证据不进 spec——zksvc 零改动；证据随 binding.json
        # 案卷发放供第三方复核）
        spec_binding = {k: binding[k] for k in (
            "auth_id", "alt_max_cm", "chain_head_hex", "engine_pub_hex", "sig_hex")}
        spec = {
            "profile": "trail",
            "reps": 16,
            "log_rate": 1,
            "input": {
                "kind": "trail",
                "rows_hex": rows.hex(),
                "alt_max_cm": alt_max_cm,
                "t_start": t_start,  # 段相对原点（与行内 t 同一网格——t_start 钉）
                "chain_head_hex": win_head.hex(),
                "auth_id": auth_id,
                "device_pk_hex": _DEV_PUB,
                # 检查点=设备钥对【最终链头】的签名（装配器契约：检查点绑定语句
                # 对象=锚定头；飞行中历史锚定走 B5 链上通道，与此正交）。
                # 设备钥在桥接进程（D16 TCB 声明：演示=桥接模拟设备钥）。
                "checkpoints": [
                    {
                        "seq": seq_i,
                        "fence_state_hex": fence_state.hex(),
                        "sig_hex": _sign_trail_cp(auth_id, seq_i, win_head, fence_state),
                    }
                    for seq_i in range(1, min(4, max(2, n_samples // 64)) + 1)
                ],
                # R4-P0-1：引擎绑定（权威 alt_max——装配面三查+引擎钥验签）
                "binding": spec_binding,
            },
        }
        task["status"] = "proving"
        spec_path = tmp / "trail_job.json"
        spec_path.write_text(_json.dumps(spec), encoding="utf-8")
        _prove_local(spec_path, tmp / "out")
        out = tmp / "out"
        case_dir.mkdir(parents=True, exist_ok=True)
        for name in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json"):
            (out / name).replace(case_dir / name)
        # C-P0-1：expected.json 随案卷发放（第三方复验的期望值=本端点公示链头；
        # 2026-10 换代：alt_max/t_start 进公开实例 1/2——期望随链头同发，
        # zkc verify-instances 对实例 1/2 fail-closed 核对）。
        (case_dir / "expected.json").write_text(
            _json.dumps({
                "chain_head_hex": win_head.hex(),
                "alt_max_cm": alt_max_cm,
                "t_start": t_start,
            }), encoding="utf-8"
        )
        # R4-P0-1 第三方复核层落地（2026-09-28 密码评审 P0：安全注记宣称
        # 「binding.json 随案卷发放，凭引擎公示钥离线验签+与实例 0 链头比对」，
        # 但案卷从未落此件=复核层空转）：引擎签名绑定随案卷归档。
        # 2026-09-28 锚定对拍批：binding.json=信封形态（binding 五字段+
        # anchor_evidence 锚定证据+其引擎签名）——第三方可离线验两签并
        # 与链上锚定时间线交叉核对（语义=一致性核对，非真实性证明）。
        binding_envelope = {
            "binding": spec_binding,
            "anchor_evidence": binding.get("anchor_evidence"),
            "anchor_evidence_sig_hex": binding.get("anchor_evidence_sig_hex"),
        }
        (case_dir / "binding.json").write_text(
            _json.dumps(binding_envelope, ensure_ascii=False), encoding="utf-8"
        )
        _await_case_artifacts(case_dir, ("proof.bin", "verifier_param.bin",
                                         "instances.json", "verdict.json",
                                         "expected.json", "binding.json"))
        task["status"] = "done"
        task["finished_at"] = time.time()
        # 行程索引登记（成功路径——失败窗口不进清单，索引零虚报）
        try:
            _record_trip({
                "auth_id": auth_id, "window": window, "case_id": task["case_id"],
                "task_id": task_id, "chain_head_hex": win_head.hex(),
                "alt_max_cm": alt_max_cm, "n_samples_total": n_samples_total,
                "fence_alt_cm": fence_alt_cm, "created_at": datetime.now().isoformat(),
            })
        except OSError:
            pass  # 索引面故障不阻断出证主径
    except Exception as e:  # noqa: BLE001
        task["status"] = "failed"
        task["error"] = str(e)[:400]
        task["finished_at"] = time.time()
        # 失败现场脱敏（2026-09-28 安全深检 B-P2，与 AUTH 路径同纪律）：
        # trail_job.json 含完整轨迹明文（rows_hex）——隐私系统的磁盘取证面
        # 不滞留轨迹；保留 failure.json 诊断面（错误+zkc stderr 无隐私）。
        (tmp / "trail_job.json").unlink(missing_ok=True)
        (tmp / "failure.json").write_text(
            _json.dumps(
                {"task_id": task_id, "kind": "trail",
                 "error": task.get("error", ""), "at": datetime.now().isoformat()},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        _sweep_stale_failures()
    finally:
        if task.get("status") != "failed":
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)


@router.post("/trail/start")
def start_trail(body: TrailStartIn) -> JSONResponse:
    """TRAIL 合规证明出证（R1-6）：本机遥测链→真出证→判决件三件套可下载
    （第三方可复验的合规证书，而非一个 JSON）。window=行程证书包窗口号
    （2026-09-28）：采样 ≥128(w+1) 时窗口 w=samples[128w:128(w+1)] 切片出证，
    每窗口自 GENESIS 重放独立成证（B6 窗口头自含语义不变）。"""
    from server import _chain

    if _chain is None or _chain.n < 128:
        n = _chain.n if _chain else 0
        return JSONResponse(
            status_code=409,
            content={"code": "no_telemetry",
                     "message": f"遥测样本 {n} < 128（TRAIL 定档 n=128，B6-d1）——继续采样"},
        )
    w = body.window
    n_windows = _chain.n // 128
    if w < 0 or w >= n_windows:
        return JSONResponse(
            status_code=409,
            content={"code": "window_out_of_range",
                     "message": f"窗口 {w} 不存在——当前样本 {_chain.n} 可出证窗口 0..{n_windows - 1}"},
        )
    # 语句公开面单源计算：窗口 128 样本行字节+锚定头（第三方复验的期望值
    # 来源=锚定值）。行格式/字段序/链头重放契约集中在 _trail_window_rows
    # （与 trail_host.rs 逐字段同构；此前的双处独立打包+epoch-t 头=换链头
    # 拒绝与 struct 溢出两类缺陷的根）。窗口切片后重放自 GENESIS 起——
    # 各窗口证书独立可验（行程=多证书包，索引见 /prove/trip/index）。
    samples = _chain.samples[128 * w : 128 * (w + 1)]
    try:
        rows, win_head, t_start = _trail_window_rows(samples)
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": "bad_sample", "err": str(exc)[:300]},
        ) from exc
    case_id = secrets.token_hex(8)
    task_id = uuid.uuid4().hex
    # R4-P0-1：引擎绑定获取+权威 alt_max 对拍（链头=本窗口锚定头——绑定对象与
    # 语句对象一字不差）。不一致=任务失败（政策收紧/客户端陈旧值——证明者
    # 不可自报上限的桥侧守门）
    try:
        binding = _fetch_trail_binding(_chain.auth_id, win_head.hex())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail={"code": "binding_unavailable", "err": f"引擎绑定获取失败: {exc}"[:300]},
        ) from exc
    if binding["alt_max_cm"] != body.alt_max_cm:
        return JSONResponse(
            status_code=409,
            content={
                "code": "alt_max_mismatch",
                "message": (
                    f"高度上限与引擎权威绑定不一致（请求 {body.alt_max_cm}cm vs "
                    f"授权 {binding['alt_max_cm']}cm——政策值以引擎绑定为准）"
                ),
            },
        )
    # P1 批（评审 B-P2 尾项）：fence_state×alt_max 交叉比对——链上检查点签名的
    # 围栏态（enable‖alt_max 米 BE16‖rsv）不得高于引擎授权上限：固件围栏被
    # 抬高（>授权）时，检查点证词与证书语义矛盾，拒绝出证。围栏=min(令牌,
    # 计划) 恒 ≤ 授权——正常路径零影响；越界=参数被篡改的诚实拒绝面。
    if len(_chain.fence_state) != 4 or _chain.fence_state[0] != 1:
        return JSONResponse(
            status_code=409,
            content={"code": "fence_state_invalid",
                     "message": "围栏态无效或未启用（fence_state）——检查点证词不成立"},
        )
    fence_alt_cm = int.from_bytes(_chain.fence_state[1:3], "big") * 100
    if fence_alt_cm > binding["alt_max_cm"]:
        return JSONResponse(
            status_code=409,
            content={"code": "fence_exceeds_auth",
                     "message": (f"固件围栏上限 {fence_alt_cm}cm 高于授权 "
                                 f"{binding['alt_max_cm']}cm——围栏参数与授权不符，拒绝出证")},
        )
    with _LOCK:
        _purge_stale_tasks_locked()
        if _active_prove_count_locked() >= _PROVE_MAX:
            return JSONResponse(
                status_code=429,
                content={"code": "prove_busy",
                         "message": ("已有出证任务在进行（本机出证为重计算，串行执行）"
                                     "——请等待当前任务完成后再发起")},
            )
        _TASKS[task_id] = {
            "status": "assembling", "case_id": case_id, "error": None,
            "t_start": None, "alt_max": body.alt_max_cm,
        }
    threading.Thread(
        target=_assemble_and_prove_trail,
        args=(task_id, body.alt_max_cm, rows, t_start, win_head, _chain.fence_state,
              _chain.auth_id, binding), daemon=True,
        kwargs={"window": w, "n_samples_total": _chain.n, "fence_alt_cm": fence_alt_cm},
    ).start()
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok", "task_id": task_id, "case_id": case_id,
            "window": w, "n_windows": n_windows,
            "chain_head_hex": win_head.hex(),  # 锚定链头（复验期望值的公开来源）
        },
    )


@router.get("/trip/index")
def trip_index(auth_id: int, download: int = 0):
    """行程证书包索引（2026-09-28）：按授权号列出全部窗口证书（窗口号/案卷/
    链头/上限），供下载为行程索引 JSON——「一次飞行=多窗口证书包」的公开
    清单。download=1 时以附件形态下发。"""
    import json as _json

    from fastapi import Response

    wins = _load_trip(auth_id)
    doc = {
        "kind": "fz-trip-index", "auth_id": auth_id, "windows": len(wins),
        "items": [
            {
                "window": r.get("window"),
                "case_id": r.get("case_id"),
                "chain_head_hex": r.get("chain_head_hex"),
                "alt_max_cm": r.get("alt_max_cm"),
                "n_samples_total": r.get("n_samples_total"),
                "fence_alt_cm": r.get("fence_alt_cm"),
                "created_at": r.get("created_at"),
                "artifacts": [
                    f"/prove/case/{r.get('case_id')}/{a}"
                    for a in ("proof.bin", "verifier_param.bin", "verdict.json",
                              "instances.json", "expected.json", "binding.json")
                ],
            }
            for r in wins
        ],
    }
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="trip-index-{auth_id}.json"'
    return Response(
        content=_json.dumps(doc, ensure_ascii=False, indent=2),
        media_type="application/json", headers=headers,
    )


@router.get("/case/{case_id}/{artifact}")
def case_artifact(case_id: str, artifact: str):
    """判决件三件套下载（R1-6 合规证书：proof/verifier_param/verdict）。
    ENOENT 短重试（3×0.4s）：Windows zkc 写 ↔ WSL 桥读的 9p 可见性窗口为
    非确定时长 [实测 0.1s~6s+]——重试在端点内 ride-out，对所有消费方生效。"""
    from fastapi import Response

    import re as _re
    import time as _t

    if not _re.fullmatch(r"[0-9a-f]{8,64}", case_id.lower()):
        return JSONResponse(status_code=400, content={"code": "bad_case_id"})
    if artifact not in ("proof.bin", "verifier_param.bin", "verdict.json", "instances.json", "expected.json", "binding.json"):
        return JSONResponse(status_code=404, content={"code": "no_artifact"})
    path = _cases_dir() / case_id.lower() / artifact
    for _ in range(3):
        if path.is_file():
            break
        _t.sleep(0.4)
    if not path.is_file():
        return JSONResponse(status_code=404, content={"code": "no_artifact"})
    media = "application/json" if artifact.endswith(".json") else "application/octet-stream"
    return Response(content=path.read_bytes(), media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{artifact}"'})


@router.post("/start")
def start_prove(body: ProveStartIn) -> JSONResponse:
    case_id = secrets.token_hex(8)
    task_id = uuid.uuid4().hex
    # 出示钥 fail-fast（2026-10-01 一次性出示钥批终验）：空/坏形态的 sk′/pk′
    # 在受理面人话拒绝——放行到装配面只会烧一遍出证流程再 failed（换设备
    # 场景：sk′ 只存签发标签页会话域，新设备无 sk′ 应被指引重签而非空跑）。
    if not body.holder_sk_hex or len(body.holder_sk_hex) != 64:
        return JSONResponse(
            status_code=400,
            content={"code": "sub_key_missing",
                     "message": ("缺少本张子凭证的出示私钥 sk′——它只在签发子凭证的"
                                 "标签页会话中。请回到「我的记录」重新签发子凭证后再申请。")},
        )
    if not body.holder_pk_hex or len(body.holder_pk_hex) != 128:
        return JSONResponse(
            status_code=400,
            content={"code": "bad_input", "message": "出示公钥形态非法（须 128 hex X‖Y）"},
        )
    # 绑定面在请求线程单源获取（fail-fast：服务端不可达即同步报错，不进 assembling）。
    # 响应携带绑定快照（t_epoch/alt_max/required_level）——申请方 apply 必须消费
    # 这里的 t_epoch（与证明实例 21 同源），不得自行再取绑定面。
    try:
        b = _http_get(
            f"{_backend_api()}/authz/binding?class_id={body.class_id}"
            f"&plan_hash_hex={body.plan_hash_hex}&nonce_hex={body.nonce_hex}"
        )
        binding = b["data"]
    except Exception as e:  # noqa: BLE001
        return JSONResponse(
            status_code=502,
            content={"code": "binding_unavailable", "message": f"绑定面获取失败: {e}"},
        )
    with _LOCK:
        _purge_stale_tasks_locked()
        if _active_prove_count_locked() >= _PROVE_MAX:
            return JSONResponse(
                status_code=429,
                content={"code": "prove_busy",
                         "message": ("已有出证任务在进行（本机出证为重计算，串行执行）"
                                     "——请等待当前任务完成后再发起")},
            )
        _TASKS[task_id] = {
            "status": "assembling",
            "case_id": case_id,
            "error": None,
            "t_start": binding.get("t_epoch"),
            "alt_max": binding.get("alt_max"),
        }
    t = threading.Thread(target=_assemble_and_prove, args=(task_id, body, binding), daemon=True)
    t.start()
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "task_id": task_id,
            "case_id": case_id,
            "binding": {
                "t_epoch": binding.get("t_epoch"),
                "alt_max": binding.get("alt_max"),
                "required_level": binding.get("required_level"),
            },
        },
    )


@router.get("/task/{task_id}")
def task_status(task_id: str) -> JSONResponse:
    task = _TASKS.get(task_id)
    if task is None:
        return JSONResponse(status_code=404, content={"code": "task_not_found", "message": "出证任务不存在", "data": None})
    return JSONResponse(status_code=200, content={
        "code": "ok",
        "data": {
            "status": task["status"],
            "case_id": task.get("case_id"),
            "error": task.get("error"),
            "t_start": task.get("t_start"),
            "alt_max": task.get("alt_max"),
        },
    })
