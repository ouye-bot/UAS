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

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests  # noqa: E402

from app.accounts.client import client_finish_login, client_login_blind, client_seal_v6  # noqa: E402
from app.accounts.envelope import seal_envelope_v4, unseal_envelope  # noqa: E402
from app.accounts.kdf import (  # noqa: E402
    KDF_LEGACY_V3_ITERATIONS,
    _legacy_v3,
    derive_activation_verifier,
)
from app.accounts.service import opaque_enabled  # noqa: E402
from app.crypto.sm2 import generate_keypair, sign  # noqa: E402


def _unseal_blob(blob_text: str, passphrase: str) -> str:
    """信封解封（版本分派：v3 legacy 旧链 / v4 PBKDF2——与前端 openKeystore
    同构）：KEK=按版本分派 KDF→SM4-GCM。"""
    try:
        return unseal_envelope(blob_text, passphrase)
    except Exception as e:  # noqa: BLE001  GCM 认证失败=密码错误（人话化）
        raise RuntimeError("密码错误（密封件解封失败）") from e


def _sealed_blob(pk: str, sk: str, passphrase: str) -> str:
    """v4 密封（keystore.ts sealKeystoreV4 同构——PBKDF2-HMAC-SM3）。"""
    return seal_envelope_v4(sk, pk, passphrase)


def script_login(
    api_base: str, username: str, password: str, activation_code: str | None = None
) -> requests.Session:
    """登录（必要时注册/激活）→携带会话 Cookie 的 Session（附 .sk）。

    activation_code（2026-10-11 批③）：双因子档位（production/显式 env）下
    预置账户首登激活的第二因子（种子脚本独立交付件交付）；demo 档缺省关，
    不传即走纯核对子流。档位开而未传=本地先行拒绝（不烧服务端限速预算）。"""
    s = requests.Session()
    pre_r = s.get(f"{api_base}/auth/prelogin/{username}", timeout=10)
    if pre_r.status_code == 404:
        # 未注册：脚本自注册（角色=pilot；机构角色请走预置激活路径）
        sk, pk = generate_keypair()
        _remember_sk(sk)
        pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀
        payload = {"username": username, "pubkey_hex": pk_no04}
        if opaque_enabled():  # ⑫O-3/4 v6 门：注册走 OPAQUE 材料（client 链同钥 shortcut）
            payload.update(client_seal_v6(username, password, sk, pk_no04))
        else:
            payload["sealed_blob"] = _sealed_blob(pk_no04, sk, password)
        r = s.post(f"{api_base}/auth/register", json=payload, timeout=10)
        r.raise_for_status()
    else:
        pre_r.raise_for_status()
        mode = pre_r.json()["data"]["mode"]
        if mode == "activation":
            # 预置机构账户首登激活：核对子→钥对生成+密封上传（核对子随后即焚）。
            # 核对子按 prelogin 下发格式分派（v1=独立域现行 / legacy_v3=旧种子
            # 兼容读取面——两端同域复算）。
            sk, pk = generate_keypair()
            _remember_sk(sk)
            pk_no04 = pk  # 服务端 sm2 公钥=X‖Y 无 04 前缀
            pre = pre_r.json()["data"]
            if pre.get("require_code") and not activation_code:
                raise RuntimeError(
                    "该账户启用了双因子激活——请以 script_login(..., activation_code=) "
                    "传入种子脚本独立交付件中的一次性激活码"
                )
            if pre.get("verifier", "v1") == "legacy_v3":
                verifier = _legacy_v3(password, pre["kdf_salt_hex"], KDF_LEGACY_V3_ITERATIONS)
            else:
                verifier = derive_activation_verifier(password, pre["kdf_salt_hex"])
            act_body = {
                "username": username,
                "verifier_hex": verifier,
                "pubkey_hex": pk_no04,
            }
            if opaque_enabled():  # ⑫O-3/4 v6 门：激活走 OPAQUE 材料
                act_body.update(client_seal_v6(username, password, sk, pk_no04))
            else:
                act_body["sealed_blob"] = _sealed_blob(pk_no04, sk, password)
            if activation_code:
                act_body["activation_code"] = activation_code
            r = s.post(
                f"{api_base}/auth/activate",
                json=act_body,
                timeout=10,
            )
            r.raise_for_status()
        else:
            ks_r = s.get(f"{api_base}/auth/keystore/{username}", timeout=10)
            if opaque_enabled() and ks_r.status_code == 410:
                # ⑫O-4 v6 稳态登录（设计 §2.3 两消息协议全步）：blind→evaluate→
                # unblind→rwd→解掩码→解封（掩码通道取代 keystore 拉取；解掩码
                # 败=密码错误，诚实抛出）。
                alpha, r_scalar = client_login_blind(username, password)
                ev = s.post(
                    f"{api_base}/auth/opaque/evaluate",
                    json={"username": username, "alpha_hex": alpha},
                    timeout=10,
                )
                ev.raise_for_status()
                sk = client_finish_login(r_scalar, ev.json()["data"])
                _remember_sk(sk)
            else:
                # v4/v3 过渡存量：keystore 拉取→本地解封（与浏览器同一密码学
                # 路径——解封失败=GCM 认证失败=密码错误，诚实抛出）
                ks_r.raise_for_status()
                ks = ks_r.json()["data"]
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
