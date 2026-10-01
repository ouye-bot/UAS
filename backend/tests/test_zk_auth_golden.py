"""B2↔B3 黄金向量 Py 侧回归：auth_golden_vector.json 内部一致性+签名验证。

三面单一事实源：Py 签发（本测试）↔ Rust host（sm2_auth_assemble.rs 对拍）↔
电路（auth_e2e）。本测试钉 Py 面：重算 M_A/e_bytes 与向量逐字节一致+签名可验。
（zkc CLI 对拍随 T8 fork 接入后以 zk 标记增补。）
"""

import json
from pathlib import Path

from app.crypto.sm2 import verify_digest
from app.crypto.sm3 import sm3_bytes
from app.ra.credential import build_message, digest_e_bytes

_VEC = Path(__file__).resolve().parents[2] / "zksvc" / "tests" / "auth_golden_vector.json"


def test_golden_vector_py_side_recalc():
    data = json.loads(_VEC.read_text(encoding="utf-8"))
    msg = build_message(
        data["ra_pub_hex"],
        bytes.fromhex(data["id_prime_hex"]),
        bytes.fromhex(data["salt_hex"]),
        data["id_number"].encode(),
        data["cert_level"],
        data["sn"].encode(),
        data["holder_pub_hex"],
        data["exp_u"],
        data["class_id"],
    )
    assert msg.hex() == data["message_hex"], "M_A 重算漂移"
    assert digest_e_bytes(msg).hex() == data["e_bytes_hex"], "电路口径 e 漂移"
    assert len(msg) == 165


def test_golden_vector_signature():
    data = json.loads(_VEC.read_text(encoding="utf-8"))
    e = bytes.fromhex(data["e_bytes_hex"])
    assert verify_digest(data["ra_pub_hex"], e, data["sig_hex"]) is True
    bad = "0" + data["sig_hex"][1:]
    assert verify_digest(data["ra_pub_hex"], e, bad) is False


def test_golden_vector_c_layout_55b():
    """C 布局锚 v3：55B（salt16‖cert BE4‖class1‖id18‖sn_h16）——B4-d1 换代防回退。"""
    data = json.loads(_VEC.read_text(encoding="utf-8"))
    from app.ra.credential import commitment_c, sn_hash

    c = commitment_c(
        bytes.fromhex(data["salt_hex"]),
        data["id_number"].encode(),
        data["cert_level"],
        data["sn"].encode(),
        data["class_id"],
    )
    msg = bytes.fromhex(data["message_hex"])
    assert msg[64:96] == c  # M_A 的 C 槽
    assert c == sm3_bytes(
        bytes.fromhex(data["salt_hex"])
        + bytes([data["cert_level"]]).rjust(4, b"\x00")
        + bytes([data["class_id"]])
        + data["id_number"].encode()
        + sn_hash(data["sn"].encode())
    )
    assert data["required_level"] < data["cert_level"], "黄金向量须诚实正例"


def test_golden_vector_smt_witness():
    """B3b SMT 见证锚：键=pk′.x 前 32bit MSB、空树 default 兄弟、真实 bits
    链头（标准 SM3 内节点）——与电路 smt_weave/smt_blocks 同构（对拍判决行：
    Py 链头==Rust mock 实例 23 逐词一致 [实测 2026-09-20]）。"""
    data = json.loads(_VEC.read_text(encoding="utf-8"))
    from app.ra.smt import _DEFAULTS, DEPTH, _path_bits

    pkx = bytes.fromhex(data["holder_pub_hex"][:64])
    bits = _path_bits(pkx)[:DEPTH]
    assert "".join(str(b) for b in bits) == data["smt_key_bits"], "键位漂移"

    siblings = bytes.fromhex(data["smt_siblings_hex"])
    assert len(siblings) == 32 * 32, "兄弟须 32×32B"
    # 逐层兄弟==DEFAULT 链（叶→根序——空撤销集）
    for i in range(DEPTH):
        assert siblings[i * 32 : (i + 1) * 32] == _DEFAULTS[DEPTH - i], f"层 {i} 兄弟漂移"

    # 链头重算（标准 SM3：64B 输入含 padding 的完整哈希）
    cur = sm3_bytes(b"FZ-SMT-EMPTY")
    for g in range(DEPTH):
        sib = siblings[g * 32 : (g + 1) * 32]
        blk = cur + sib if bits[g] == 0 else sib + cur
        cur = sm3_bytes(blk)
    assert cur.hex() == data["smt_root_hex"], "SMT 链头重算漂移"
