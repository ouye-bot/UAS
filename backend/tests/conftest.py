"""测试配置根（B0：锚定 backend 目录为 cwd，保证向量相对路径稳定）。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


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
