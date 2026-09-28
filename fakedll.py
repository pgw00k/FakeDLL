#!/usr/bin/env python3
"""fakedll 入口脚本。

用法示例：
    python fakedll.py all "I:/SteamLibrary/steamapps/common/The Nine Regions/MC_Data/Plugins/steam_api.dll" -o out/
    python fakedll.py header xxx.dll -o xxx.h --renderer renderers/getproc_thunk.py
"""

import os
import sys

# 允许直接从仓库根目录运行（python fakedll.py ...）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakedll.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
