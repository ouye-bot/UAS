# 合约编译产物 manifest（B1 起）

- 编译器：FISCO solc 国密版（WSL /home/ouye/.fisco/solc/0.4.25/sm3/solc）
- 版本：Gm version: 0.4.25+commit.46d177ad.mod.Linux.g++
- 命令：`solc --bin --abi --overwrite -o build src/<C>.sol`（逐合约显式）；runtime=`--bin-runtime`
- 目标链：FISCO BCOS 2.9.0 国密四节点（sm_crypto=true）

| 文件 | sha256 |
|---|---|
| FlightAuthRegistry.abi | 51bce970034bc82a59499770acbc0f0e124f4225ba7a10e4824fa8061d71bba6 |
| FlightAuthRegistry.bin | 90fff6ca8a2e2f9c03c0f489c0d24a9249559354450d4db79d8e66d7783e5cde |
| FlightAuthRegistry.runtime.bin | 208c0642361a41a073df796c85cfb363f4fbc069070f155455ba2ff83416aa62 |
| IdentityRegistry.abi | 90c4987a60de8f51b3ebcd4cc60e012846f702f3b97ed629b5222756716ca913 |
| IdentityRegistry.bin | 069f79ced5c7416ab5d7d0b95b43709de7603729fee9ac55bda325321ea19cf1 |
| IdentityRegistry.runtime.bin | ccbbf47b4111fa23a896da3f55da575a37fe53f658ac28df00c3bf18cdd75f71 |
| PolicyRegistry.abi | 3a55b5d6a7c10806b1e5f117ac8e1a34984265241e7e212d4d89f0bef12911a2 |
| PolicyRegistry.bin | 1d79c5cb438ed868436b4f019429488719a5361042b7658d10f96f3ad09b3ce8 |
| PolicyRegistry.runtime.bin | 967d2978263c7b1553bc57027c69dbe426f586e51f4a925c14e495b4735a9f8d |
| TelemetryAnchor.abi | f75e1670e0b49368bfcbc4f6a89f0464d75ceb96ae4cc743fb09b90430f8109a |
| TelemetryAnchor.bin | f68343201490e2be4a9c3f10c4a29689722fe72dd676577ecd4e52ce0776a8f6 |
| TelemetryAnchor.runtime.bin | e0dfd9f295e9851905ba73a5b374833cfa899411cd3de2b2c0d0a91682fa6230 |

## 部署对账（chain_smoke --deploy 回填）

| 合约 | 部署地址 | 部署块 | runtime sha256（前 16） |
|---|---|---|---|
|（待部署） | | | |