"""测试配置根（B0：锚定 backend 目录为 cwd，保证向量相对路径稳定）。"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _threshold_watcher_isolated():
    """1.3 审查批⑤：threshold watcher daemon 隔离（真链档测试经 create_app
    拉起的 daemon 跨测试存活轮询——[threshold-watcher] unavailable 打印实证
    的潜在测试干扰源）。每测试前：停 daemon+复位进程内幂等标志；测试后同样
    收口（线程在 Event.wait 上退出）。"""
    from app.ra import threshold_sync as _tsw

    _tsw.stop_watcher()
    _tsw._watcher_started = False
    yield
    _tsw.stop_watcher()
    _tsw._watcher_started = False


@pytest.fixture(autouse=True)
def _threshold_root_isolated(tmp_path, monkeypatch):
    """门限根目录全套件强制隔离（⑤站实弹教训，2026-10-10）。

    threshold_root 含 append-only 域审计与密封份额——单测令状行混入=审计可
    信度红线（16:13 污染实锤：无隔离运行把 abababab 标记令状写入生产审计，
    详见 MEMORY ⑤站节）。本 fixture 对全套件 autouse 生效：任何测试无论
    有无模块级隔离，FZ_THRESHOLD_ROOT_DIR 一律重定向 tmp；模块级隔离
    （test_threshold_envelope/_reshare）与此叠加无害。生产目录只由实弹
    （e2e/仪式脚本/运行中的 backend）触碰。"""
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(tmp_path / "threshold_root"))
    yield


def seed_sn_chain(session, msg: bytes, serial: bytes):
    """SN 绑定换代（2026-10-06）测试播种：sub_cred_hash→SubCredential→
    Credential.serial_hex 服务端溯源链（诚实流=RA 签发落库；门控/worker
    测试直插行——server_sn_hash_hex 的解析面）。"""
    import datetime as _dt
    import secrets as _secrets

    from app.crypto.sm3 import sm3_bytes as _sm3b
    from app.ra.models import Credential, SubCredential, User

    user = User(username="sn-" + _secrets.token_hex(6), pub_key_hex="11" * 64)
    session.add(user)
    session.flush()
    cred = Credential(
        user_id=user.id,
        commitment_hex=_secrets.token_bytes(32).hex(),
        master_cred_hash_hex=_secrets.token_bytes(32).hex(),
        sn_hash_hex="00" * 16,
        serial_hex=bytes(serial).hex(),
        id_cipher=b"",
        cert_level=3,
        expires_at=_dt.datetime.utcfromtimestamp(1900000000),
    )
    session.add(cred)
    session.flush()
    session.add(
        SubCredential(
            credential_id=cred.id,
            sub_cred_hash_hex=_sm3b(msg).hex(),
            message_hex=msg.hex(),
            sig_hex="00" * 64,
            holder_pub_hex="11" * 64,
            expires_at=_dt.datetime.utcfromtimestamp(1900000000),
        )
    )
    session.commit()
