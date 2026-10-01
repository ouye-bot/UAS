"""脚本侧账户会话助手（2026-09-29 账户批）：令牌退役后脚本以账户会话调用
审计/机构端点。直连 HTTP 的脚本（e2e/scenario/redteam）共用本助手。

用法：
    s = script_login(API, "auditor", "演示初始密码")    # 预置账户→首登激活
    s = script_login(API, "pilot_x", "密码")            # 未注册用户名→脚本自注册
之后所有请求自动携带会话 Cookie（requests.Session 持罐）；s.sk 可用于签名。

语义（诚实面）：已激活账户的密封件无法被脚本解封（设计如此）——脚本复用
同一机构账户需部署方以 env FZ_SEED_*_PASSWORD 提供初始密码且账户未激活，
或换未注册用户名自注册。
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests  # noqa: E402

from app.accounts.kdf import derive_kek  # noqa: E402
from app.crypto.sm2 import generate_keypair, sign  # noqa: E402
from app.crypto.sm4 import SM4GCM  # noqa: E402


def _unseal_blob(blob_text: str, passphrase: str) -> str:
    """v3 信封解封（与前端 openKeystoreV3 同构）：KEK=KDF(pass,salt)→SM4-GCM。"""
    env = json.loads(blob_text)
    if env.get("v") != 3:
        raise RuntimeError("密封件形态不符（v3）")
    enc = env["enc"]
    kek = bytes.fromhex(derive_kek(passphrase, enc["salt"]))
    try:
        pt = SM4GCM(kek).decrypt(
            bytes.fromhex(enc["nonce"]), bytes.fromhex(enc["ct"]), bytes.fromhex(enc["tag"]),
            b"FZ-KEYSTORE-v3|pass",
        )
    except Exception as e:  # noqa: BLE001  GCM 认证失败=密码错误（人话化）
        raise RuntimeError("密码错误（密封件解封失败）") from e
    return pt.hex()


def _sealed_blob(pk: str, sk: str, passphrase: str) -> str:
    salt = secrets.token_hex(16)
    nonce = secrets.token_hex(12)
    kek = bytes.fromhex(derive_kek(passphrase, salt))
    ct, tag = SM4GCM(kek).encrypt(bytes.fromhex(nonce), bytes.fromhex(sk), b"FZ-KEYSTORE-v3|pass")
    return json.dumps(
        {"v": 3, "pk": pk, "enc": {"salt": salt, "nonce": nonce, "ct": ct.hex(), "tag": tag.hex()}}
    )


def script_login(api_base: str, username: str, password: str) -> requests.Session:
    """登录（必要时注册/激活）→携带会话 Cookie 的 Session（附 .sk）。"""
    s = requests.Session()
    pre_r = s.get(f"{api_base}/auth/prelogin/{username}", timeout=10)
    if pre_r.status_code == 404:
        # 未注册：脚本自注册（角色=pilot；机构角色请走预置激活路径）
        sk, pk = generate_keypair()
        _remember_sk(sk)
        pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀
        r = s.post(
            f"{api_base}/auth/register",
            json={"username": username, "pubkey_hex": pk_no04, "sealed_blob": _sealed_blob(pk_no04, sk, password)},
            timeout=10,
        )
        r.raise_for_status()
    else:
        pre_r.raise_for_status()
        mode = pre_r.json()["data"]["mode"]
        if mode == "activation":
            # 预置机构账户首登激活：核对子→钥对生成+密封上传（核对子随后即焚）
            sk, pk = generate_keypair()
            _remember_sk(sk)
            pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀
            r = s.post(
                f"{api_base}/auth/activate",
                json={
                    "username": username,
                    "verifier_hex": derive_kek(password, pre_r.json()["data"]["kdf_salt_hex"]),
                    "pubkey_hex": pk_no04,
                    "sealed_blob": _sealed_blob(pk_no04, sk, password),
                },
                timeout=10,
            )
            r.raise_for_status()
        else:
            # 已激活稳态：取密封件→密码本地解封（与浏览器同一密码学路径——
            # 解封失败=GCM 认证失败=密码错误，诚实抛出）
            ks = s.get(f"{api_base}/auth/keystore/{username}", timeout=10).json()["data"]
            sk = _unseal_blob(ks["sealed_blob"], password)
            _remember_sk(sk)
    # 挑战-应答登录
    nonce = s.post(f"{api_base}/auth/challenge/{username}", timeout=10).json()["data"]["nonce_hex"]
    sk = _last_sk
    sig = sign(sk, f"FZ-AUTH-LOGIN|{nonce}".encode())
    r = s.post(
        f"{api_base}/auth/login",
        json={"username": username, "nonce_hex": nonce, "sig_hex": sig},
        timeout=10,
    )
    r.raise_for_status()
    s.sk = sk  # type: ignore[attr-defined]
    return s


_last_sk = ""  # 注册/激活分支产出的私钥（登录签名用——单线程脚本形态）


def _remember_sk(sk: str) -> str:
    global _last_sk
    _last_sk = sk
    return sk
