"""EOL 自适应补丁助手（文本手术工具——Windows 混合行尾仓使用）。

用法：python - <<'PY'
import sys, os
sys.path.insert(0, os.path.dirname(__file__) or ".")
sys.path.insert(0, r"C:\\Users\\联想\\Desktop\\Meeting\\uas\\scripts")
from _eol_patch import patch
patch("path/file", [(old, new), ...])
PY
"""

import os


def patch(path, pairs):
    s = open(path, "rb").read().decode("utf-8")
    crlf = "\r\n" in s[:8192]
    applied = 0
    for old, new in pairs:
        o = old.replace("\n", "\r\n") if crlf else old
        n = new.replace("\n", "\r\n") if crlf else new
        if o in s:
            s = s.replace(o, n)
            applied += 1
    open(path, "wb").write(s.encode("utf-8"))
    print(f"{path}: {applied}/{len(pairs)} patches applied (crlf={crlf})")
    return applied
