# -*- coding: utf-8 -*-
"""P0-4 mTLS 证书生成（自签 CA+服务端+客户端三件——openssl CLI）。

产物（backend/certs/，已 gitignore——私钥零入库红线）：
  ca.crt/ca.key                    根 CA（10 年，basicConstraints+keyUsage 全扩展）
  server.crt/server.key            服务端证书（SAN: localhost, 127.0.0.1；serverAuth）
  client-{bridge,worker,e2e}.crt/.key  客户端证书（CN=fz-*；clientAuth）
  client-e2e.pfx                   schannel 系工具（Windows curl）便捷包（口令 fz-demo）

🔴 证书卫生（首轮实测红教训）：CA 必须带 basicConstraints=critical,CA:TRUE +
   keyUsage=critical,keyCertSign——无扩展的裸 CA 会被 OpenSSL 3.x 验签方
   "CA cert does not include key usage extension" 直接拒绝。
用法：python scripts/gen_certs.py   （需 PATH 有 openssl；重复运行=全部重签）
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parents[1] / "certs"
CA_CN = "FZ-Demo-CA"
SERVER_CN = "fz-backend.local"
CLIENTS = ("bridge", "worker", "e2e")
DAYS = "3650"

CA_EXT = """basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
"""
SERVER_EXT = """basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
"""
CLIENT_EXT = """basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
"""


def run(cmd: list[str]) -> None:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[FAIL] {' '.join(cmd)}\n{r.stdout}{r.stderr}")
        raise SystemExit(1)


def _extfile(name: str, content: str) -> Path:
    p = CERT_DIR / name
    p.write_text(content, encoding="utf-8")
    return p


def main() -> int:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    ca_crt, ca_key = CERT_DIR / "ca.crt", CERT_DIR / "ca.key"
    ca_ext = _extfile("_ca.ext", CA_EXT)
    srv_ext = _extfile("_server.ext", SERVER_EXT)
    cli_ext = _extfile("_client.ext", CLIENT_EXT)

    # ① 根 CA（自签+全扩展——OpenSSL3/Python3.13 严格验签要求）
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(ca_key), "-out", str(ca_crt), "-days", DAYS,
         "-subj", f"/CN={CA_CN}/O=Feizheng", "-extensions", "v3_ca",
         "-config", str(_ca_conf(ca_ext))])
    print("[certs] CA 就绪（basicConstraints+keyUsage 全扩展）")

    # ② 服务端证书（SAN 双址+serverAuth）
    srv_key, srv_csr, srv_crt = CERT_DIR / "server.key", CERT_DIR / "server.csr", CERT_DIR / "server.crt"
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(srv_key), "-out", str(srv_csr), "-days", str(DAYS),
         "-subj", f"/CN={SERVER_CN}/O=Feizheng"])
    run(["openssl", "x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(srv_crt), "-days", DAYS, "-extfile", str(srv_ext)])
    srv_csr.unlink(missing_ok=True)
    print("[certs] 服务端证书就绪（SAN: localhost, 127.0.0.1）")

    # ③ 客户端证书 ×3（clientAuth——服务互认身份）
    for name in CLIENTS:
        ck, csr, ccrt = CERT_DIR / f"client-{name}.key", CERT_DIR / f"{name}.csr", CERT_DIR / f"client-{name}.crt"
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(ck), "-out", str(csr), "-days", str(DAYS),
             "-subj", f"/CN=fz-{name}/O=Feizheng"])
        run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
             "-CAcreateserial", "-out", str(ccrt), "-days", DAYS, "-extfile", str(cli_ext)])
        csr.unlink(missing_ok=True)
        print(f"[certs] 客户端证书 fz-{name} 就绪")

    # ④ e2e 证书的 PFX 便捷包（Windows schannel 系工具；口令仅演示面）
    run(["openssl", "pkcs12", "-export",
         "-out", str(CERT_DIR / "client-e2e.pfx"),
         "-inkey", str(CERT_DIR / "client-e2e.key"), "-in", str(CERT_DIR / "client-e2e.crt"),
         "-passout", "pass:fz-demo"])
    for ext in ("_ca.ext", "_server.ext", "_client.ext"):
        (CERT_DIR / ext).unlink(missing_ok=True)
    print(f"[certs] 全部产物在 {CERT_DIR}（gitignore——私钥零入库）")
    return 0


def _ca_conf(ca_ext: Path) -> Path:
    """openssl req -x509 -extensions 需要配置文件形态（扩展段名 v3_ca）。"""
    p = CERT_DIR / "_ca.cnf"
    p.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n" + ca_ext.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return p


if __name__ == "__main__":
    sys.exit(main())
