#!/usr/bin/env python
"""文档一致性门禁（骨架版，B0 起；规则随批次增）。

禁用短语=口径红线残留（肯定式使用才违例——"禁用'X'"式元引述豁免）；
必须锚=新口径在场。冲突 exit 2，全绿 exit 0。
对象：框架 v2、说明书 v2、docs/性能档案.md、2026-09-23-作品说明文档.md
（正式提交物，2026-10-04 纳入第四锚——此前在门禁盲区，机制根因见性能档案）。
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
    ("作品说明", "恢复码", "恢复码双因子已随账户批退役（密钥库安全说明 v3 注记）"),
    ("作品说明", "密钥不出设备", "密封件存服务器=任意设备登录取回解封——旧表述失实"),
    ("作品说明", "45 项断言", "S1 现行 46 断言（2026-10-01 复跑，性能档案现行口径总表）"),
    ("作品说明", "100% 拦截", "禁做绝对化安全宣称"),
]

# (文档, 必须锚, 理由)
REQUIRED: list[tuple[str, str, str]] = [
    ("框架", "D19", "决策记录必须在案"),
    ("说明书", "治理层门禁", "D15 口径锚"),
    ("性能档案", "[实测]", "标记体系在场（每个数字带三标之一）"),
    ("作品说明", "挑战-应答", "服务端零口令材料口径（账户批）必须在场"),
    ("作品说明", "一次性出示钥", "出示公钥层跨申请不可链接口径必须在场"),
    ("作品说明", "46 断言", "S1 现行断言数必须在场（性能档案现行口径总表）"),
    ("作品说明", "19,578", "电路现行约束数（⑤代）必须在场"),
]

FILES = {
    "框架": DOCS / "2026-09-19-系统框架规划-v2.md",
    "说明书": DOCS / "2026-09-19-作品说明书-v2-内部理解版.md",
    "性能档案": PERF,
    "作品说明": DOCS / "2026-09-23-作品说明文档.md",
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
