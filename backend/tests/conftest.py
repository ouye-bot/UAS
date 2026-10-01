"""测试配置根（B0：锚定 backend 目录为 cwd，保证向量相对路径稳定）。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
