"""账户测试共享助手（2026-09-29 账户批；2026-10-04 批 2 密码底座升档）：
测试内建账户+登录会话的单一入口。

令牌退役后，审计/机构端点吃会话 Cookie——本助手提供：
- register_and_login(c, username, role, password)：注册（或种子+激活）→登录
  →TestClient 持有会话 Cookie；返回 sk（后续敏感操作签名用）。
- seed_login(c, username, role, password)：预置机构账户路径（核对子激活）。
- sign_canonical(sk, msg)：与 app.crypto.sm2 口径一致的签名（服务端 verify 验）。
- sealed_blob_v4(pk, sk, passphrase)：v4 信封（envelope 单一事实源）——
  测试内联密封与生产同参数同路径。
"""

from __future__ import annotations

from app.accounts.envelope import seal_envelope_v4
from app.accounts.kdf import derive_activation_verifier
from app.accounts.service import seed_institutional_account
from app.crypto.sm2 import generate_keypair, sign
from app.db import get_session


def _sealed_blob(pk: str, sk: str, passphrase: str) -> str:
    """v4 信封（PBKDF2-HMAC-SM3 现行口径——与浏览器 sealKeystoreV4 同构）。"""
    return seal_envelope_v4(sk, pk, passphrase)


def sign_canonical(sk: str, msg: str) -> str:
    return sign(sk, msg.encode())


def sign_revoke_body(sk: str, handles: list[str], reason: str, epoch: int) -> dict:
    """B1 撤销签名体（FZ-REVOKE|v1|{handles 排序}|{reason}|{epoch} 域）——
    HTTP 测试面共用：/ra/revoke 与 /ra/revoke/by-username 的新契约体片段。"""
    from app.ra.service import revoke_msg

    msg = revoke_msg(handles, reason, epoch)
    return {"reason": reason, "sig_hex": sign(sk, msg.encode()), "epoch": epoch}


def restore_sig(sk: str, handle_hex: str, reason: str, *, countersign: bool = False) -> str:
    """B6 双控恢复签名（FZ-RESTORE|v1 / FZ-RESTORE-COUNTERSIGN|v1 域）。"""
    from app.crypto.sm2 import sign as _sign
    from app.ra.service import restore_countersign_msg, restore_msg

    msg = (
        restore_countersign_msg(handle_hex, reason)
        if countersign
        else restore_msg(handle_hex, reason)
    )
    return _sign(sk, msg.encode())


def _db_session(c):
    """取测试库会话工厂：依赖覆盖优先（标准 fixture）；无覆盖时回落
    app.db.SessionLocal（db_mod 打桩形态的 fixture）。"""
    ov = c.app.dependency_overrides.get(get_session)
    if ov is not None:
        gen = ov()
        return gen, next(gen)
    from app.db import SessionLocal

    s = SessionLocal()
    return None, s


def _close_db_session(gen, sess):
    if gen is not None:
        gen.close()
    else:
        sess.close()


def _login_via_challenge(c, username: str, sk: str) -> None:
    nonce = c.post(f"/auth/challenge/{username}").json()["data"]["nonce_hex"]
    sig = sign_canonical(sk, f"FZ-AUTH-LOGIN|{nonce}")
    r = c.post("/auth/login", json={"username": username, "nonce_hex": nonce, "sig_hex": sig})
    assert r.status_code == 200, r.text


def register_and_login(c, username: str, role: str, password: str) -> str:
    """直注册路径。生产注册口只发 pilot——测试面所需的其他角色在此直设
    （注册后直改库角色列，模拟部署方预置的机构账户已激活形态）。"""
    sk, pk = generate_keypair()
    pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀——误剥致 ~1/256 注册随机失败
    r = c.post(
        "/auth/register",
        json={
            "username": username,
            "pubkey_hex": pk_no04,
            "sealed_blob": _sealed_blob(pk_no04, sk, password),
        },
    )
    if r.status_code == 409:  # 已存在（幂等辅助）——仍需登录
        pass
    else:
        assert r.status_code == 201, r.text
    gen, sess = _db_session(c)
    try:
        from app.accounts.models import Account

        acc = sess.query(Account).filter_by(username=username).one()
        acc.role = role
        acc.status = "active"
        sess.commit()
    finally:
        _close_db_session(gen, sess)
    _login_via_challenge(c, username, sk)
    return sk


def seed_login(c, username: str, role: str, password: str) -> str:
    """预置机构账户路径：种子（激活核对子）→首登激活→挑战登录。核对子按
    prelogin 下发格式分派复算（v1=独立域现行 / legacy_v3=旧种子兼容读取）。"""
    gen, sess = _db_session(c)
    try:
        seed_institutional_account(sess, username, role, password)
        from app.accounts.models import Account

        row = sess.query(Account).filter_by(username=username).one()
        salt, ver_kind = row.init_kdf_salt_hex, row.init_verifier_ver
    finally:
        _close_db_session(gen, sess)
    from app.accounts.kdf import KDF_LEGACY_V3_ITERATIONS, _legacy_v3

    verifier = (
        _legacy_v3(password, salt, KDF_LEGACY_V3_ITERATIONS)
        if ver_kind != "v1"
        else derive_activation_verifier(password, salt)
    )
    sk, pk = generate_keypair()
    pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀——误剥致 ~1/256 注册随机失败
    r = c.post(
        "/auth/activate",
        json={
            "username": username,
            "verifier_hex": verifier,
            "pubkey_hex": pk_no04,
            "sealed_blob": _sealed_blob(pk_no04, sk, password),
        },
    )
    assert r.status_code == 200, r.text
    _login_via_challenge(c, username, sk)
    return sk
