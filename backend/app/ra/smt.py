"""SM3 稀疏 Merkle 树（B2 host 实现；B3b 电路非成员 gadget 同口径单一事实源）。

撤销累加器（D14/B3b）：树键=撤销键（32B，调用方语义：B3b 起=子凭证出示公钥
x 坐标 pk′.x——主凭证吊销经 RA 撤销传播进树，B4 接线），深度 32（B3b-d1 拍板：
健全性与深度无关——伪造需 2^256 碰撞；前缀碰撞=可用性边界，RA 签发期拒收）。
路径=键前 32bit MSB 优先。
- 成员叶哈希 = SM3(b"FZ-SMT-LEAF|" ‖ key)
- 空叶（深度 32）= SM3(b"FZ-SMT-EMPTY")——非成员验证起点（叶层取空叶默认）
- 空子树默认哈希 DEFAULT[d] = SM3(DEFAULT[d+1] ‖ DEFAULT[d+1])，d=31..0
- 内节点 = SM3(左 ‖ 右)（32B 定长无分隔符；左右按路径位——bit=0 走左）
- 非成员证明：键路径上 32 个兄弟子树根（叶→根序）+ 根；
  验证=沿路径重算（叶层取空叶默认）至根比对。

树缺省每次全量重算（演示规模撤销集）；批 4-7 起 [`IncrementalSMT`] 提供增量
维护面：插入/撤销只重算脏路径（O(32) SM3/次），根与全量重算逐字节一致
（单测钉定），消费面见 [`cached_tree`]。
"""

from __future__ import annotations

from app.crypto.sm3 import sm3_bytes

DEPTH = 32
_LEAF_LABEL = b"FZ-SMT-LEAF|"
_EMPTY_LABEL = b"FZ-SMT-EMPTY"


def _leaf_hash(handle: bytes) -> bytes:
    return sm3_bytes(_LEAF_LABEL + handle)


def _parent(left: bytes, right: bytes) -> bytes:
    return sm3_bytes(left + right)


def _default_cache() -> list[bytes]:
    """DEFAULT[0..64]：DEFAULT[64]=空叶；自底向上 DEFAULT[d]=SM3(DEFAULT[d+1]‖DEFAULT[d+1])。"""
    cache = [b""] * (DEPTH + 1)
    cache[DEPTH] = sm3_bytes(_EMPTY_LABEL)
    for d in range(DEPTH - 1, -1, -1):
        cache[d] = _parent(cache[d + 1], cache[d + 1])
    return cache


_DEFAULTS = _default_cache()


def _path_bits(handle: bytes) -> list[int]:
    """句柄前 64bit 的 MSB 优先路径位（每层 1 bit；bit=1 走右）。"""
    v = int.from_bytes(handle[:8], "big")
    return [(v >> (63 - i)) & 1 for i in range(DEPTH)]


def _leaf_pos(handle: bytes) -> int:
    pos = 0
    for bit in _path_bits(handle):
        pos = (pos << 1) | bit
    return pos


def _build_levels(handles: list[bytes]) -> dict[int, dict[int, bytes]]:
    """叶层（DEPTH）→ 根层（0）逐层归约；缺省子树=对应深度 DEFAULT。"""
    leaves: dict[int, bytes] = {}
    for h in handles:
        if len(h) != 32:
            raise ValueError("句柄须 32 字节")
        leaves[_leaf_pos(h)] = _leaf_hash(h)
    levels: dict[int, dict[int, bytes]] = {DEPTH: leaves}
    for d in range(DEPTH - 1, -1, -1):
        child = levels[d + 1]
        parents = {pos >> 1 for pos in child}
        nxt: dict[int, bytes] = {}
        for parent in parents:
            left = child.get(parent << 1, _DEFAULTS[d + 1])
            right = child.get((parent << 1) | 1, _DEFAULTS[d + 1])
            nxt[parent] = _parent(left, right)
        levels[d] = nxt
    return levels


def smt_root(handles: list[bytes]) -> bytes:
    """撤销句柄集合 → SMT 根（集合语义，顺序无关；空集合=DEFAULT[0]）。"""
    return _build_levels(handles)[0].get(0, _DEFAULTS[0])


# ---- 批 4-7：增量维护面（脏路径更新，根==全量重算逐字节一致）----


class IncrementalSMT:
    """增量维护的撤销 SMT：插入/删除只重算脏路径。

    levels[d] 保存非默认节点（位置→哈希；缺省位置取 _DEFAULTS[d]）；插入沿
    键路径写叶并逐层重算父（与默认子树同值的节点即弃——字典只存脏差异）；
    删除=摘叶后沿同路径重算。撤销集演化下每请求全量重算（O(n·32)）改
    O(32) 脏路径更新；根与 [`smt_root`] 全量重算逐字节一致（test_ra_smt 钉定）。
    """

    def __init__(self) -> None:
        self._leaves: dict[int, bytes] = {}
        self._levels: dict[int, dict[int, bytes]] = {d: {} for d in range(DEPTH + 1)}
        self._root: bytes = _DEFAULTS[0]

    def _refresh_path(self, handle_pos: int) -> None:
        """沿 handle_pos 的叶→根路径重算脏节点（叶层已更新后调用）。"""
        pos = handle_pos
        for d in range(DEPTH, 0, -1):
            left = self._levels[d].get(pos & ~1, _DEFAULTS[d])
            right = self._levels[d].get(pos | 1, _DEFAULTS[d])
            parent = pos >> 1
            val = _parent(left, right)
            if val == _DEFAULTS[d - 1]:
                self._levels[d - 1].pop(parent, None)  # 与空子树同值=非脏，即弃
            else:
                self._levels[d - 1][parent] = val
            pos = parent
        self._root = self._levels[0].get(0, _DEFAULTS[0])

    def insert(self, handle: bytes) -> None:
        """插入撤销句柄（32B；已在树中=幂等 no-op）。"""
        if len(handle) != 32:
            raise ValueError("句柄须 32 字节")
        pos = _leaf_pos(handle)
        if pos in self._leaves:
            return
        leaf = _leaf_hash(handle)
        self._leaves[pos] = leaf
        self._levels[DEPTH][pos] = leaf
        self._refresh_path(pos)

    def remove(self, handle: bytes) -> None:
        """移除撤销句柄（32B；不在树中=幂等 no-op）——撤销误登记的回收面。"""
        if len(handle) != 32:
            raise ValueError("句柄须 32 字节")
        pos = _leaf_pos(handle)
        if pos not in self._leaves:
            return
        del self._leaves[pos]
        self._levels[DEPTH].pop(pos, None)
        self._refresh_path(pos)

    def __contains__(self, handle: bytes) -> bool:
        return _leaf_pos(handle) in self._leaves

    def __len__(self) -> int:
        return len(self._leaves)

    def root(self) -> bytes:
        """当前根（== smt_root(全部已插句柄) 逐字节）。"""
        return self._root

    def non_membership_witness(self, handle: bytes) -> dict:
        """非成员证明（与模块级 non_membership_witness 同构同判据）。"""
        if len(handle) != 32:
            raise ValueError("句柄须 32 字节")
        bits = _path_bits(handle)
        leaf_pos = _leaf_pos(handle)
        siblings: list[str] = []
        for d in range(DEPTH, 0, -1):
            node_pos = leaf_pos >> (DEPTH - d)
            sib = self._levels[d].get(node_pos ^ 1, _DEFAULTS[d])
            siblings.append(sib.hex())
        return {"siblings": siblings, "leaf_index_bits": bits}


_TREE_CACHE: dict = {"tree": None, "handles": set()}


def cached_tree(handles: list[bytes]) -> IncrementalSMT:
    """进程级增量缓存访问器：以句柄集合为账本——新增句柄沿脏路径增量插入，
    消失的句柄增量摘除，集合不变=零重算直接复用（每请求全量重算 O(n·32) 的
    撤销面热点收口）。调用方语义=传入当前撤销句柄全集（集合语义顺序无关）。"""
    tree: IncrementalSMT | None = _TREE_CACHE["tree"]
    if tree is None:
        tree = IncrementalSMT()
        _TREE_CACHE["tree"] = tree
        _TREE_CACHE["handles"] = set()
    prev: set[bytes] = _TREE_CACHE["handles"]
    now = set(handles)
    for h in sorted(now - prev):  # 排序保证确定性构建次序（根与次序无关，仅纪律）
        tree.insert(h)
    for h in sorted(prev - now):
        tree.remove(h)
    _TREE_CACHE["handles"] = now
    return tree


def non_membership_witness(handle: bytes, handles: list[bytes]) -> dict:
    """句柄的非成员证明：{siblings: [32×32B hex]（叶→根序）, leaf_index_bits: [32×0/1]}。

    深度 32（R3-0.1 位序统一后 DEPTH=32——旧口径 64 系上轮评审文档残留）。
    兄弟位置序：叶层兄弟=leaf_pos 完整值 LSB 翻转；向上每层右移一位再翻转
    （路径位自 LSB 向 MSB 逐层消费——与位置二进制"MSB=根侧"结构一致）。
    """
    if len(handle) != 32:
        raise ValueError("句柄须 32 字节")
    levels = _build_levels(handles)
    bits = _path_bits(handle)
    leaf_pos = _leaf_pos(handle)
    siblings: list[str] = []
    for d in range(DEPTH, 0, -1):  # d=64（叶层）..1
        node_pos = leaf_pos >> (DEPTH - d)
        sib = levels[d].get(node_pos ^ 1, _DEFAULTS[d])
        siblings.append(sib.hex())
    return {"siblings": siblings, "leaf_index_bits": bits}


def verify_non_membership(handle: bytes, witness: dict, root: bytes) -> bool:
    """离线验非成员证明：叶层取空叶默认，沿 siblings（叶→根序）重算至根比对。

    每层方向位=该层位置最低位（cur 在左=0 → H(cur,sib)；在右=1 → H(sib,cur)）。
    成员句柄的位置叶=成员叶哈希≠空叶默认 ⟹ 重算根必不匹配（成员必拒）。
    """
    if len(handle) != 32:
        return False
    try:
        siblings = [bytes.fromhex(s) for s in witness["siblings"]]
    except (KeyError, ValueError, TypeError):
        return False
    if len(siblings) != DEPTH:
        return False
    leaf_pos = _leaf_pos(handle)
    cur = _DEFAULTS[DEPTH]  # 非成员声称：该位置为空叶
    for d in range(DEPTH, 0, -1):
        sib = siblings[DEPTH - d]
        if (leaf_pos >> (DEPTH - d)) & 1 == 0:  # cur 是左子
            cur = _parent(cur, sib)
        else:
            cur = _parent(sib, cur)
    return cur == root
