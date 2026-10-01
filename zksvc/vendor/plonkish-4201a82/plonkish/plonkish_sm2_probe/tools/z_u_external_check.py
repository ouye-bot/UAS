# -*- coding: utf-8 -*-
"""Z_U 外核盲检（簇F 两步走第二步）：GM/T 32918.2 §5.5
Z_U = SM3(ENTLA || ID || a || b || Gx || Gy || xA || yA)

纪律：本脚本**零手抄曲线常量** —— b/Gx/Gy/A.2 xA/yA 全部从已验证源码
regex 机械解析；p 取 lib.rs 的 PrimeFieldModulus 十进制串；a = p-3 由
整数推导（与电路 curve_a() 同公式）；最后以 on-curve 恒等式自洽兜底。
脚本不内嵌任何"期望摘要"，输出打印后人工比对。
"""
import re, sys
from pathlib import Path
from gmssl.sm3 import sm3_hash

SRC = Path(__file__).resolve().parents[1] / "src"

def read(p):
    return (SRC / p).read_text(encoding="utf-8")

ec = read("sm2_ec_plonkish.rs")
anchor = read("sm2_z_anchor.rs")
lib = read("lib.rs")

def grab_hex(text, const_name):
    m = re.search(const_name + r'\s*:\s*&str\s*=\s*"([0-9A-Fa-f]+)"', text)
    assert m, f"{const_name} not found"
    return int(m.group(1), 16)

B = grab_hex(ec, "B_HEX")
GX = grab_hex(ec, "GX_HEX")
GY = grab_hex(ec, "GY_HEX")

PMOD = re.search(r'PrimeFieldModulus\s*=\s*"(\d+)"', lib)
assert PMOD, "MODULUS not found"
P = int(PMOD.group(1))
A = (P - 3) % P  # 与电路 curve_a() = ZERO - 3 同公式

# A.2 权威向量：fe_be32_matches_authoritative_hex 内前两个字面量 = (xA, yA)
body = anchor[anchor.index("fn fe_be32_matches_authoritative_hex"):]
hexes = re.findall(r'"([0-9A-Fa-f]{64})"', body)
assert len(hexes) == 2, "expect exactly xA,yA literals"
XA, YA = int(hexes[0], 16), int(hexes[1], 16)

# ── 自洽兜底 ①：域元范围与位长 ──
for nm, v in [("b", B), ("Gx", GX), ("Gy", GY), ("xA", XA), ("yA", YA)]:
    assert 0 <= v < P, f"{nm} out of field"

# ── 自洽兜底 ②：on-curve y² = x³ + ax + b (mod p) ──
assert pow(YA, 2, P) == (pow(XA, 3, P) + A * XA + B) % P, "P_A off-curve"
assert pow(GY, 2, P) == (pow(GX, 3, P) + A * GX + B) % P, "G off-curve"
print("[ok] constants parsed & both points on-curve; bitlen(P) =", P.bit_length())

# ── GB/T §5.5 序列化（ID 与 ENTLA 按规则独立构造）──
ID = b"1234567812345678"          # 默认 ID（GB/T 示例）
# ENTLA = entlen 的 16 位大端（bit 数）
entla = (len(ID) * 8).to_bytes(2, "big")
def be32(v): return v.to_bytes(32, "big")

preimage = (entla + ID + be32(A) + be32(B) + be32(GX) + be32(GY)
            + be32(XA) + be32(YA))
print(f"[info] preimage len = {len(preimage)} (expect 210)")
assert len(preimage) == 210, "preimage length mismatch"

digest = sm3_hash(list(preimage))
print("Z_U(A.2,default-ID)[gmssl external] =", digest.upper())
