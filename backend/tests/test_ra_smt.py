"""SM3-SMT 撤销树测试（B3b 电路非成员 gadget 同口径——host 单一事实源）。

设计（B3b-d1 换代）：深度 32；键=撤销键（32B，B3b 起=pk′.x）取前 32bit MSB 优先
为路径；成员叶=SM3("FZ-SMT-LEAF"|key)；空子树按深度预计算默认哈希；内节点=SM3(左‖右)。
"""

import pytest

from app.crypto.sm3 import sm3_bytes
from app.ra.smt import (
    IncrementalSMT,
    cached_tree,
    non_membership_witness,
    smt_root,
    verify_non_membership,
)


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


# ---- 批 4-7：增量树（脏路径更新，根/见证与全量重算逐字节一致）----


@pytest.fixture()
def _reset_tree_cache():
    """增量缓存进程级单例——用例间重置（零跨用例残留）。"""
    import app.ra.smt as _smt

    _smt._TREE_CACHE["tree"] = None
    _smt._TREE_CACHE["handles"] = set()
    yield
    _smt._TREE_CACHE["tree"] = None
    _smt._TREE_CACHE["handles"] = set()


def test_incremental_root_equals_full_recompute():
    """增量根==全量重算根（逐字节）：多组句柄插入后与 smt_root 全量重算一致。"""
    handles = [_h(f"rev-{i}".encode()) for i in range(37)]
    tree = IncrementalSMT()
    for h in handles:
        tree.root()  # 中途读根不扰脏路径
        tree.insert(h)
    assert tree.root() == smt_root(handles)
    assert len(tree) == len(set(handles))


def test_incremental_remove_matches_full_recompute():
    """摘除后根==全量重算根：删除也是脏路径更新（撤销误登记回收面）。"""
    handles = [_h(f"drv-{i}".encode()) for i in range(19)]
    tree = IncrementalSMT()
    for h in handles:
        tree.insert(h)
    gone = handles[3], handles[11]
    for g in gone:
        tree.remove(g)
    rest = [h for h in handles if h not in gone]
    assert tree.root() == smt_root(rest)
    tree.remove(handles[3])  # 重复摘除=幂等 no-op
    assert tree.root() == smt_root(rest)
    assert handles[3] not in tree and handles[4] in tree


def test_incremental_witness_identical_and_verifies():
    """增量树的见证与模块级全量版逐字节一致，且离线验证通过、成员必拒。"""
    handles = [_h(b"inc-a"), _h(b"inc-b"), _h(b"inc-c")]
    tree = IncrementalSMT()
    for h in handles:
        tree.insert(h)
    outside = _h(b"innocent")
    w_inc = tree.non_membership_witness(outside)
    w_full = non_membership_witness(outside, handles)
    assert w_inc == w_full
    assert verify_non_membership(outside, w_inc, tree.root()) is True
    w_member = tree.non_membership_witness(handles[0])
    assert verify_non_membership(handles[0], w_member, tree.root()) is False
    with pytest.raises(ValueError):
        tree.insert(b"short")


def test_cached_tree_diff_applies_and_reuses(_reset_tree_cache):
    """cached_tree 集合差分：新增/消失句柄增量进出；集合不变=复用（根一致）。
    根每步与全量重算对拍——撤销面热点收口不引入漂移。"""
    base = [_h(b"pool-1"), _h(b"pool-2")]
    t1 = cached_tree(base)
    r1 = t1.root()
    assert r1 == smt_root(base)
    # 新增两笔
    grown = [*base, _h(b"pool-3"), _h(b"pool-4")]
    t2 = cached_tree(grown)
    assert t2 is t1  # 同树增量（非重建）
    assert t2.root() == smt_root(grown)
    # 撤销一笔
    shrunk = [h for h in grown if h != _h(b"pool-2")]
    t3 = cached_tree(shrunk)
    assert t3.root() == smt_root(shrunk)
    # 集合不变=复用且根稳定
    t4 = cached_tree(list(reversed(shrunk)))  # 顺序无关
    assert t4 is t3 and t4.root() == smt_root(shrunk)
