#!/usr/bin/env bash
# WSL 内部编译脚本（由 compile.sh 调用，工作目录=本脚本目录）。
set -euo pipefail
cd "$(dirname "$0")"
SOLC=/home/ouye/.fisco/solc/0.4.25/sm3/solc
rm -rf build && mkdir -p build
for c in IdentityRegistry PolicyRegistry FlightAuthRegistry TelemetryAnchor AdminGovernor; do
  "$SOLC" --bin --abi --overwrite -o build "src/$c.sol"
done
TMP=$(mktemp -d)
for c in IdentityRegistry PolicyRegistry FlightAuthRegistry TelemetryAnchor AdminGovernor; do
  "$SOLC" --bin-runtime --overwrite -o "$TMP" "src/$c.sol"
  mv "$TMP/$c.bin-runtime" "build/$c.runtime.bin"
done
rm -rf "$TMP"
echo "== solc 编译完成 =="
ls -la build/
