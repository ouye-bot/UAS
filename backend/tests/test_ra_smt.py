"""SM3-SMT 撤销树测试（B3b 电路非成员 gadget 同口径——host 单一事实源）。

设计（B3b-d1 换代）：深度 32；键=撤销键（32B，B3b 起=pk′.x）取前 32bit MSB 优先
为路径；成员叶=SM3("FZ-SMT-LEAF"|key)；空子树按深度预计算默认哈希；内节点=SM3(左‖右)。
"""

from app.crypto.sm3 import sm3_bytes
from app.ra.smt import non_membership_witness, smt_root, verify_non_membership


def _h(b: bytes) -> bytes:
    return sm3_bytes(b)


def test_empty_tree_root_deterministic():
    r1 = smt_root([])
    r2 = smt_root([])
    assert r1 == r2 and len(r1) == 32


def test_member_changes_root():
    h1 = _h(b"handle-1")
    h2 = _h(b"handle-2")
    r_empty = smt_root([])
    r1 = smt_root([h1])
    r12 = smt_root([h1, h2])
    assert len({r_empty, r1, r12}) == 3  # 三态互异


def test_root_order_independent():
    # 集合语义：句柄顺序不影响根
    a, b, c = _h(b"a"), _h(b"b"), _h(b"c")
    assert smt_root([a, b, c]) == smt_root([c, a, b])


def test_non_membership_witness_verifies():
    handle = _h(b"not-revoked")
    revoked = [_h(b"a"), _h(b"b")]
    root = smt_root(revoked)
    w = non_membership_witness(handle, revoked)
    assert verify_non_membership(handle, w, root) is True
    # 成员句柄的非成员证明必须失败
    w_bad = non_membership_witness(revoked[0], revoked)
    assert verify_non_membership(revoked[0], w_bad, root) is False
    # 换根验证失败
    assert verify_non_membership(handle, w, smt_root([])) is False


def test_witness_shape():
    w = non_membership_witness(_h(b"x"), [])
    assert len(w["siblings"]) == 32  # 深度 32：每层一个兄弟子树根
    assert len(w["leaf_index_bits"]) == 32  # 路径位（电路消费同口径）
