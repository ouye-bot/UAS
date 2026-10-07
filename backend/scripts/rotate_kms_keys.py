"""KMS 密钥轮换仪式脚本（批 2-2.3）：生成新随机钥→输出 env 行+指纹。

纪律：
- 随机源=CSPRNG（secrets）——零派生自公开常量、零硬编码、零确定性；
- 输出仅 stdout（不落库、不写文件、不入 git）——由部署方把 env 行注入
  其密管渠道（.env/secret manager/启动器）后重启服务；
- 指纹=SM3(公钥/材料)[0:16]——核对注入是否生效的带外面（非机密）；
- 与 app/kms.PRODUCTION_REQUIRED_KEYS 同表同源（缺新域=编译期可见）。

用法：
    cd backend && python scripts/rotate_kms_keys.py [--only FZ_RA_SK,...]
警告（脚本会如实打印）：FZ_RA_SK/FZ_ENGINE_SK 轮换=验签公钥更迭——
链上 setRa/setEngine 换址与历史凭证可验性须按 docs 生产部署演进文档执行。
"""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.crypto.sm2 import pubkey_from_priv  # noqa: E402
from app.crypto.sm3 import sm3_bytes  # noqa: E402
from app.kms import PRODUCTION_REQUIRED_KEYS  # noqa: E402


def _material(kind: str) -> str:
    """按域生成新随机钥材料（hex）。长度与 kms 访问器的形态门一致。"""
    if kind == "sk32":  # SM2 私钥 32B
        return secrets.token_hex(32)
    if kind == "key16":  # SM4 域主钥 16B
        return secrets.token_hex(16)
    if kind == "key32":  # HMAC 服务钥 32B
        return secrets.token_hex(32)
    if kind == "token":  # 不透明令牌 32B
        return secrets.token_hex(32)
    raise ValueError(f"未知密钥材料形态: {kind}")


def _fingerprint(kind: str, value: str) -> str:
    """带外核对指纹（非机密）：非对称钥=SM3(公钥)；对称钥/令牌=SM3(材料)。"""
    ref = pubkey_from_priv(value) if kind == "sk32" else value.encode()
    return sm3_bytes(ref.encode() if isinstance(ref, str) else ref).hex()[:16]


def main() -> int:
    ap = argparse.ArgumentParser(description="KMS 密钥轮换仪式（env 行+指纹，stdout only）")
    ap.add_argument("--only", default="", help="仅轮换指定 env（逗号分隔）；缺省全量")
    args = ap.parse_args()
    only = {x.strip() for x in args.only.split(",") if x.strip()}

    print("# 飞证 KMS 密钥轮换——以下 env 行由部署方注入密管渠道后重启（勿入 git/库）")
    warned = False
    for name, desc, kind in PRODUCTION_REQUIRED_KEYS:
        if only and name not in only:
            continue
        value = _material(kind)
        fp = _fingerprint(kind, value)
        if kind == "sk32":
            warned = True
            print(f"# {name}：{desc}（轮换=验签公钥更迭——链上 set* 换址/历史凭证"
                  "可验性须一并按部署文档执行）")
        print(f"export {name}={value}")
        print(f"# 指纹 {name}: {fp}")
    if not warned:
        print("# 本次未含非对称签名钥——无公钥更迭面")
    print("# 生效自检：重启后 backend 日志无 KMS 拒启断言；指纹可与上方比对（带外渠道）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
