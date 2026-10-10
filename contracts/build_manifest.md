# 合约编译产物 manifest（B1 起）

- 编译器：FISCO solc 国密版（WSL /home/ouye/.fisco/solc/0.4.25/sm3/solc）
- 版本：Gm version: 0.4.25+commit.46d177ad.mod.Linux.g++
- 命令：`solc --bin --abi --overwrite -o build src/<C>.sol`（逐合约显式）；runtime=`--bin-runtime`
- 目标链：FISCO BCOS 2.9.0 国密四节点（sm_crypto=true）

| 文件 | sha256 |
|---|---|
| AdminGovernor.abi | 46ebf2cb1d8adcb8f48841daf43707ed4d1aa942730132df52692fda9ecf3e4a |
| AdminGovernor.bin | f6e04c86c2f51e7e2df189144369f26ad6c412761c219872b005b6b3b89a6de9 |
| AdminGovernor.runtime.bin | 7deb0b3b2647de9be57eb3dd9ae618194aa3f9b7debb64ab027593fbd80f0ad4 |
| FlightAuthRegistry.abi | f551f2c10e6c2f89bf78b60ef9e8a5a7a26912a96f78228dcf4a7138245ded24 |
| FlightAuthRegistry.bin | 5a52acbd709859cf3c3cd80b9c889499825ba94cdb553eb9759c744ecced1561 |
| FlightAuthRegistry.runtime.bin | 0cfbe9ab98ddef3bc9c2504b37fd88942402a434842c7684a069bb6fd44a93a5 |
| IdentityRegistry.abi | 09d442ddf94cc4332076957a9c26e04b1d73eb7de876eb452a39a0d51c7a5011 |
| IdentityRegistry.bin | e15fd211700ad33152e52aefcd0ecbe39bc8d3711dade6461dd7344fc5f21a66 |
| IdentityRegistry.runtime.bin | 662fa5fe4f313ddedcda3ebef3a715bd413b4690483505554f8c4d1131b6ced6 |
| PolicyRegistry.abi | 584850b8fafe917ffccc26879556d43824818854db16d02ae2a1e179fd50d371 |
| PolicyRegistry.bin | 21d75cfa7b60c35d2660194d8a1720f97fcd59903648bbd93cea4b3054ccd451 |
| PolicyRegistry.runtime.bin | e3692723fc180da78c13975897e8957da01e5ecfc1436138837bc67ceb647057 |
| TelemetryAnchor.abi | 46894173414c018863cca5f72afc0d6902d4854ae3766a76834894bda8ccffc5 |
| TelemetryAnchor.bin | 54abc736e66ec61a5b4f8b8e5960d2cbf08aea43c9fbef5dc351f779447f0c7f |
| TelemetryAnchor.runtime.bin | 1921b270483ab972a34ba244bd2d25c46a6d7545d39fef8785d0d45a34f28e29 |

## 部署对账（chain_smoke --deploy 回填）

| 合约 | 部署地址 | 部署块 | runtime sha256（前 16） |
|---|---|---|---|
|（待部署） | | | |