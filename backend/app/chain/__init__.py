"""飞证链接入层（B1 自旧系统 fork：RLP/SM2-Z 交易签名/ABI/事件解析，无 SDK）。

治理面（批 3.2）：四合约 onlyAdmin 面（政策/指纹公示+角色授予）链上
admin=AdminGovernor（2/3 多签+时间锁，owners=[admin,RA,auditor]）——治理
操作一律经多签仪式（scripts/publish_pin.py、chain_smoke.py 驱动，
app/chain/governor.py 单源）。运行时 API 不承载治理面：backend 全部链上
写调用均为 onlyRA/onlyEngine/onlyAuditor 业务面（registerCommitment/
setRevocationRoot/recordAuth/anchorCheckpoint/logWarrant 等），读面零变化。
"""
