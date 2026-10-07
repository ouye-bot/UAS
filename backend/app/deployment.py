"""部署档判定（批 2 共用底座）：production 判定 = 显式声明 或 非环回绑定。

- env FZ_DEPLOYMENT=production（大小写不敏感）→ production；
- 绑定地址非环回（FZ_BIND_ADDR / FZ_HOST，形如 host[:port]）→ production
  ——绑出环回即面对真实网络，演示缺省（派生钥/非 Secure Cookie）不再成立；
  0.0.0.0/::（全接口）按非环回处理（保守=production）；
- 其余（缺省/127.0.0.1/::1/localhost）→ demo 档，维持现状可跑。

消费面：kms 启动密钥断言（2.3）、会话 Cookie secure 缺省（2.5）。
"""

from __future__ import annotations

import os

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}


def _bind_host() -> str:
    raw = (os.environ.get("FZ_BIND_ADDR") or os.environ.get("FZ_HOST") or "").strip()
    if not raw:
        return ""
    host = raw.split(":", 1)[0].strip("[]").lower()
    return host


def is_production() -> bool:
    if (os.environ.get("FZ_DEPLOYMENT") or "").strip().lower() == "production":
        return True
    host = _bind_host()
    if host and host not in _LOOPBACK_HOSTS:
        return True
    return False


def assert_production_services() -> None:
    """production 档服务形态断言（批 4-2）：三条拒启逐条人话点名——

    ① FZ_CHAIN_ANCHOR 未显式配置（缺省 fake=演示假链档——授权登记/nonce
       烧毁/撤销公示全不落真链，演示替身）；
    ② 链锚 fake 档下遥测锚定为进程内 stub（检查点/违规事件仅内存记录——
       取证时间线无链上留痕，第三方不可回读核验）；
    ③ FZ_DB_URL 未配置（缺省回落本机 SQLite 文件——不满足生产持久化与
       多副本部署语义）。

    demo（环回）档直接返回——演示环回零影响（现状可跑不变）。
    """
    if not is_production():
        return
    anchor_raw = (os.environ.get("FZ_CHAIN_ANCHOR") or "").strip()
    anchor = anchor_raw.lower() or "fake"  # 缺省=本仓各消费面同款 fake 回落
    problems: list[str] = []
    if not anchor_raw:
        problems.append(
            "FZ_CHAIN_ANCHOR 未配置——缺省回落 fake 演示假链档（授权/nonce/撤销"
            "公示全不落真链）：生产须显式 FZ_CHAIN_ANCHOR=real"
        )
    elif anchor != "real":
        problems.append(
            f"FZ_CHAIN_ANCHOR={anchor_raw} 非 real 档——授权链面不生效："
            "生产须显式 FZ_CHAIN_ANCHOR=real"
        )
    if anchor == "fake":
        problems.append(
            "遥测锚定处于 fake 档（检查点/违规事件仅进程内 stub 记录，无链上"
            "留痕可回读）——生产取证链不可用：须 FZ_CHAIN_ANCHOR=real"
        )
    if not (os.environ.get("FZ_DB_URL") or "").strip():
        problems.append(
            "FZ_DB_URL 未配置——缺省回落本机 SQLite 文件（不满足生产持久化/"
            "多副本）：请配置 PostgreSQL 等生产库连接串"
        )
    if problems:
        raise RuntimeError(
            "生产档服务形态断言未通过——拒绝启动（"
            + "；".join(problems)
            + "）"
        )
