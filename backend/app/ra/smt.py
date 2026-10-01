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

树每次全量重算（演示规模吊销集——诚实边界；增量化远期优化挂账）。
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
