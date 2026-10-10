"""密码操作 provider 抽象层（1.4——PKCS#11 接口先行，硬件到位即插）。

四原语（任务书钉定）：SM2 签名/SM2-ECIES 解密/SM4-GCM 密封/CSPRNG 随机数
（附 SM2 验签+ECIES 加密镜像面——HSM 侧验签同样不出硬件的对称形态）。

设计纪律（红线逐条）：
- **行为零变化**：SoftwareCryptoProvider=现状实现（app.crypto.sm2/sm4+secrets）
  的**薄委托**（零逻辑复制——单一事实源，杜绝双实现漂移）；等价性由
  tests/test_crypto_provider.py 影子对拍钉死（确定性原语逐字节、含随机 k 的
  SM2 签名/ECIES 互验互换）。
- **零冒充**：HsmPkcs11Provider=骨架——每原语显式 raise HsmNotImplemented
  （绝不返回假数据冒充可用）；未配置 PKCS#11 模块时 get_provider() 拒绝分派
  到 hsm（不可达）。硬件到位+密评通过后填实原语（对接清单见类 docstring）。
- **不放松既有拒启语义**：app.kms.assert_no_demo_keys_in_production
  （production 10 钥注册表）原样——provider 分派不触碰 KMS 钥供给与拒启。

分派：env FZ_CRYPTO_PROVIDER（缺省 software；显式选择即部署决策如实生效）。
宣讲口径止于『provider 架构已备，硬件到位即接入』（口径卡 A3/J8 同步）。
"""

from __future__ import annotations

import os
import secrets
from typing import Protocol, runtime_checkable

_PROVIDER_ENV = "FZ_CRYPTO_PROVIDER"
_HSM_MODULE_ENV = "FZ_HSM_PKCS11_MODULE"


class HsmNotImplemented(NotImplementedError):
    """HSM 原语未填实（骨架态）——显式拒绝而非假返（零冒充红线）。"""


class HsmNotConfigured(RuntimeError):
    """hsm provider 被显式选择但 PKCS#11 模块未配置——分派拒绝（不可达）。"""


@runtime_checkable
class CryptoProvider(Protocol):
    """密码操作原语协议（1.4 件①）：签名/解密/密封/随机数四原语+镜像验签面。

    HSM 实现语义备注（硬件对接时的边界）：sign_sm2/ecies_decrypt 在 HSM 内
    完成（私钥不出硬件）；ecies_encrypt/seal_sm4_gcm/open_sm4_gcm 为公开钥/
    对称密文操作，可留软件侧或按硬件能力下沉。"""

    name: str

    def sign_sm2(self, priv_hex: str, msg: bytes) -> str: ...

    def verify_sm2(self, pub_hex: str, msg: bytes, sig_hex: str) -> bool: ...

    def ecies_encrypt(self, pub_hex: str, plaintext: bytes) -> bytes: ...

    def ecies_decrypt(self, priv_hex: str, ct: bytes) -> bytes: ...

    def seal_sm4_gcm(
        self, key16: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> tuple[bytes, bytes]: ...

    def open_sm4_gcm(
        self, key16: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes
    ) -> bytes: ...

    def random_bytes(self, n: int) -> bytes: ...


class SoftwareCryptoProvider:
    """软件档（1.4 件②）：现状实现的薄委托——零逻辑复制，行为逐字节同
    （影子对拍钉死，tests/test_crypto_provider.py）。**如实标注：本档为软件
    实现，非 HSM 替身**；私钥以 hex 进程内持有（KMS 供给面不变）。"""

    name = "software"

    def sign_sm2(self, priv_hex: str, msg: bytes) -> str:
        from app.crypto.sm2 import sign

        return sign(priv_hex, msg)

    def verify_sm2(self, pub_hex: str, msg: bytes, sig_hex: str) -> bool:
        from app.crypto.sm2 import verify

        return verify(pub_hex, msg, sig_hex)

    def ecies_encrypt(self, pub_hex: str, plaintext: bytes) -> bytes:
        from app.crypto.sm2 import encrypt

        return encrypt(pub_hex, plaintext)

    def ecies_decrypt(self, priv_hex: str, ct: bytes) -> bytes:
        from app.crypto.sm2 import decrypt

        return decrypt(priv_hex, ct)

    def seal_sm4_gcm(
        self, key16: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> tuple[bytes, bytes]:
        from app.crypto.sm4 import SM4GCM

        return SM4GCM(key16).encrypt(nonce, plaintext, aad)

    def open_sm4_gcm(self, key16: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes) -> bytes:
        from app.crypto.sm4 import SM4GCM

        return SM4GCM(key16).decrypt(nonce, ct, tag, aad)

    def random_bytes(self, n: int) -> bytes:
        return secrets.token_bytes(n)


class HsmPkcs11Provider:
    """HSM/PKCS#11 骨架（1.4 件③）：**成文待硬件，零冒充**——每原语显式
    raise HsmNotImplemented；未配置模块时分派层即拒（不可达）。

    硬件到位后的填实清单（密评对接文档——成文在案，非即席发挥）：
    - PKCS#11 模块加载（FZ_HSM_PKCS11_MODULE=.so 路径）+slot/token 选择与
      login 凭据供给（双员管理：操作员卡/管理员卡分离，密评要求）；
    - 算法白名单：SM2 签名（CKM_SM2_SIGN，私钥不出硬件）/SM2-ECIES 解密
      （CKM_SM2 解密面）——非白名单机制一律拒绝；
    - 钥槽策略：密钥 label↔KMS label 映射表、私钥属性 CKA_SENSITIVE=
      CKA_EXTRACTABLE=false、钥到位/轮换走 governance 双签仪式；
    - 随机数：HSM CSPRNG（CKF_SO_GENERATE）优先，软件 CSPRNG 仅兜底并如实
      标注；seal_sm4_gcm 按硬件能力（部分密码卡无 SM4-GCM——留软件侧并
      在密评材料如实分账）。
    上述为**接口契约与流程要求**的成文——本类不含任何可运行替身实现。"""

    name = "hsm"

    def __init__(self, module_path: str) -> None:
        self.module_path = module_path

    def _not_impl(self, primitive: str) -> HsmNotImplemented:
        return HsmNotImplemented(
            f"HSM 原语 {primitive} 未填实（骨架态——硬件到位+密评通过后按本类 "
            "docstring 清单接入；当前不存在任何软件替身路径）"
        )

    def sign_sm2(self, priv_hex: str, msg: bytes) -> str:
        raise self._not_impl("sign_sm2")

    def verify_sm2(self, pub_hex: str, msg: bytes, sig_hex: str) -> bool:
        raise self._not_impl("verify_sm2")

    def ecies_encrypt(self, pub_hex: str, plaintext: bytes) -> bytes:
        raise self._not_impl("ecies_encrypt")

    def ecies_decrypt(self, priv_hex: str, ct: bytes) -> bytes:
        raise self._not_impl("ecies_decrypt")

    def seal_sm4_gcm(
        self, key16: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> tuple[bytes, bytes]:
        raise self._not_impl("seal_sm4_gcm")

    def open_sm4_gcm(self, key16: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes) -> bytes:
        raise self._not_impl("open_sm4_gcm")

    def random_bytes(self, n: int) -> bytes:
        raise self._not_impl("random_bytes")


_software = SoftwareCryptoProvider()
_hsm: HsmPkcs11Provider | None = None


def get_provider() -> CryptoProvider:
    """provider 分派（fail-closed）：缺省 software；显式 hsm 须配置 PKCS#11
    模块（未配置即拒——骨架不可达）；未知名拒（不静默回落）。"""
    raw = (os.environ.get(_PROVIDER_ENV) or "software").strip().lower()
    if raw == "software":
        return _software
    if raw == "hsm":
        module = (os.environ.get(_HSM_MODULE_ENV) or "").strip()
        if not module:
            raise HsmNotConfigured(
                f"{_PROVIDER_ENV}=hsm 已选择但 {_HSM_MODULE_ENV} 未配置——"
                "HSM 骨架不可达（零冒充：不存在软件替身路径）。配置 PKCS#11 "
                "模块路径（硬件到位+密评通过后）或回落 software。"
            )
        global _hsm
        if _hsm is None:
            _hsm = HsmPkcs11Provider(module)
        return _hsm
    raise RuntimeError(f"未知 {_PROVIDER_ENV}={raw!r}（合法值：software/hsm）——分派 fail-closed")
