"""B2↔B3 黄金向量 Py 侧回归：auth_golden_vector.json 内部一致性+签名验证。

三面单一事实源：Py 签发（本测试）↔ Rust host（sm2_auth_assemble.rs 对拍）↔
电路（auth_e2e）。本测试钉 Py 面：重算 M_A/e_bytes 与向量逐字节一致+签名可验。
（zkc CLI 对拍随 T8 fork 接入后以 zk 标记增补。）
v7（2026-10-06）起向量内嵌证明级期望值（expected_instances_hex/proof_sm3_hex/
zk_pin_fingerprint——确定性钥真实 prove 实测），Py 侧锚测试同步增补。
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

def test_golden_vector_v7_public_instances():
    """v7 证明级期望锚（⑥ SN→⑦ pack→双 vendor 根修 cdc7cec 真实 prove 实测）：
    expected_instances_hex 26 项（⑥代 SN 绑定 25→26）——Py 侧 14 项可重算位
    逐位对拍（实例驱动验证面 R1-1b 同式折叠）。词折叠口径=fold_words_be
    （w0 最低权序列化呈词序倒排——实例 23/25 与真 BE 整数分野，prove 窗实弹定谳）。"""
    data = json.loads(_VEC.read_text(encoding="utf-8"))
    from gmssl.sm2 import default_ecc_table

    from app.authz.service import (
        _fe_be32_hex_from_bytes32,
        _fe_be32_hex_from_digest,
        _fe_be32_hex_from_u64,
    )
    from app.crypto import sm2 as sm2mod
    from app.crypto.sm3 import sm3_bytes

    inst = data["expected_instances_hex"]
    assert len(inst) == 26, "⑦代公开实例面=26（⑥代 SN 绑定第 5 组查表门）"
    # 直读位：e（电路口径词序）/ sig r‖s / Z_A（ra 公钥 x‖y）
    assert inst[0] == data["e_bytes_hex"]
    assert inst[1] + inst[2] == data["sig_hex"]
    assert inst[3] + inst[4] == data["ra_pub_hex"]
    # C₁=[r]G（v5 challenge 派生 r——恒 [2]G 消除：12/13 ≠ 9/10 防回退）
    n = int(default_ecc_table["n"], 16)
    r = int.from_bytes(
        sm3_bytes(b"FZ-AUTH-R|v1|" + bytes.fromhex(data["challenge_hex"])), "big"
    ) % n
    c1 = sm2mod._c(data["ra_priv_hex"], data["ra_pub_hex"])._kg(r, sm2mod._G)
    assert c1[:64] == inst[12] and c1[64:] == inst[13], "C₁=[r]G 重算漂移"
    assert inst[12] != inst[9], "C₁ 恒常回退（[2]G 时代 12/13==9/10）"
    # 绑定/谓词折叠位（真 BE 整数 mod p）：ctx_tag/pred_id/t_epoch/θ/class
    ch = bytes.fromhex(data["challenge_hex"])
    assert _fe_be32_hex_from_digest(sm3_bytes(ch)) == inst[19]
    pred_digest = sm3_bytes((b"FZ-ZKSVC-PRED-ID" + b"") + data["pred_id"].encode())
    assert _fe_be32_hex_from_digest(pred_digest) == inst[20]
    assert _fe_be32_hex_from_u64(data["t_epoch"]) == inst[21]
    assert _fe_be32_hex_from_u64(data["required_level"]) == inst[22]
    assert _fe_be32_hex_from_u64(data["class_id"]) == inst[24]
    # 词折叠位（fold_words_be）：rev_root=实例 23 / sn_hash=实例 25（⑥代核心锚）
    assert _fe_be32_hex_from_bytes32(bytes.fromhex(data["smt_root_hex"])) == inst[23]
    assert _fe_be32_hex_from_bytes32(sm3_bytes(data["sn"].encode())) == inst[25]


def test_golden_vector_v7_proof_digest_pin():
    """v7 proof 摘要+指纹锚：proof_sm3/proof_bytes（⑦代 pack+交织档 16.1MB 级）
    +zk_pin_fingerprint 与 vendor 代（build_manifest pinned_commit_short）互锚——
    指纹换代（vendor 重钉/根修）而向量未换代时此锚红。"""
    import re

    data = json.loads(_VEC.read_text(encoding="utf-8"))
    assert re.fullmatch(r"[0-9a-f]{64}", data["proof_sm3_hex"])
    assert data["proof_bytes"] == 16_063_712, "⑦代交织档 proof 尺寸换代"
    assert re.fullmatch(
        r"SM3\([0-9a-f]{7}\|[0-9a-f]{64}\)", data["zk_pin_fingerprint"]
    )
    manifest = json.loads(
        (_VEC.parents[1] / "build_manifest.json").read_text(encoding="utf-8")
    )
    assert data["zk_pin_fingerprint"].startswith(
        f"SM3({manifest['pinned_commit_short']}|"
    ), "vendor 代与指纹不符（换代未同步）"
