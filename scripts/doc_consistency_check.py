#!/usr/bin/env python
"""文档一致性门禁（骨架版，B0 起；规则随批次增）。

禁用短语=口径红线残留（肯定式使用才违例——"禁用'X'"式元引述豁免）；
必须锚=新口径在场。冲突 exit 2，全绿 exit 0。
对象：框架 v2、说明书 v2、docs/性能档案.md（性能档案 B0 Task 10 建立后纳入）。
"""

from __future__ import annotations

import sys
from pathlib import Path

UAS = Path(__file__).resolve().parent.parent
DOCS = UAS / "01_设计文档"
PERF = UAS / "docs" / "性能档案.md"

# (文档, 禁用短语, 理由)
FORBIDDEN: list[tuple[str, str, str]] = [
    ("框架", "全栈国密", "P2-1：必须写'运行主路径密码原语 100% 国密'（构造层 HyperPlonk/Basefold 非商用标准）"),
    ("框架", "替代审批", "D15：令牌=治理层门禁，禁用'替代审批'表述"),
    ("说明书", "全栈国密", "P2-1：同上"),
    ("说明书", "替代审批", "D15：同上"),
    ("性能档案", "TODO", "性能档案禁占位符——每个数字必须 [实测]/[推得]/[估算]+日期"),
]

# (文档, 必须锚, 理由)
REQUIRED: list[tuple[str, str, str]] = [
    ("框架", "D19", "决策记录必须在案"),
    ("说明书", "治理层门禁", "D15 口径锚"),
    ("性能档案", "[实测]", "标记体系在场（每个数字带三标之一）"),
]

FILES = {
    "框架": DOCS / "2026-09-19-系统框架规划-v2.md",
    "说明书": DOCS / "2026-09-19-作品说明书-v2-内部理解版.md",
    "性能档案": PERF,
}

# 引述豁免：短语命中点前 14 字符窗口内含否定式引述标记 = 文档正在"禁用'X'"式元表述，非违例
_QUOTING_MARKS = ("禁用", "禁写", "不用", "不写", "非", "避免", "否")
_WINDOW = 14


def _violating_hits(text: str, phrase: str) -> int:
    """肯定式使用计数（引述豁免后）。"""
    n = 0
    start = 0
    while True:
        i = text.find(phrase, start)
        if i < 0:
            return n
        window = text[max(0, i - _WINDOW) : i]
        if not any(m in window for m in _QUOTING_MARKS):
            n += 1
        start = i + 1


def main() -> int:
    fails: list[str] = []
    if not PERF.exists():
        fails.append(f"性能档案: 尚未建立（{PERF}）——B0 Task 10 建立")
    for doc, path in FILES.items():
        if not path.exists():
            fails.append(f"{doc}: 文件缺失 {path}")
            continue
        text = path.read_text(encoding="utf-8")
        for d, phrase, why in FORBIDDEN:
            if d == doc:
                hits = _violating_hits(text, phrase)
                if hits:
                    fails.append(f"{d}: 禁用短语 '{phrase}' 肯定式在场 ×{hits}（{why}）")
        for d, anchor, why in REQUIRED:
            if d == doc and anchor not in text:
                fails.append(f"{d}: 必须锚 '{anchor}' 缺失（{why}）")
    if fails:
        print("[doc_consistency] FAIL：")
        for f in fails:
            print(f"  - {f}")
        return 2
    print("[doc_consistency] OK：禁用/必须锚全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
