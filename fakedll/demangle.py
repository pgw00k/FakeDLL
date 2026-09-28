"""修饰名解析：从导出名推断调用约定与参数信息。

三层证据源（按可靠性排序）：
  1. MSVC C++ 修饰名（'?' 开头）—— 调用约定、参数个数、甚至完整签名都编码在名字里。
     通过 dbghelp.UnDecorateSymbolName（Windows 自带，零第三方依赖）反修饰，
     再对可读文本做正则抽取。
  2. x86 C 修饰名 —— `_name@N` = __stdcall(N 字节栈参数)；`@name@N` = __fastcall；
     `_name` = __cdecl。x64 C 名不修饰。
  3. （analyze.py）函数字节码分析。

导出的 C++ 修饰名（如 ?SteamAPI_Init@@YAHXZ）里的调用约定字母：
  A = __cdecl   G = __stdcall   I = __fastcall   E = __thiscall(成员)
"""

from __future__ import annotations

import ctypes
import re

# ---------------------------------------------------------------- dbghelp

_undname_flags_complete = 0x0000  # UNDNAME_COMPLETE
_dbghelp = None
_dbghelp_failed = False


def _get_dbghelp():
    global _dbghelp, _dbghelp_failed
    if _dbghelp_failed:
        return None
    if _dbghelp is None:
        try:
            _dbghelp = ctypes.WinDLL("dbghelp")
            _dbghelp.UnDecorateSymbolName.restype = ctypes.c_uint
            _dbghelp.UnDecorateSymbolName.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]
        except OSError:
            _dbghelp_failed = True
            return None
    return _dbghelp


def undecorate(name: str) -> str | None:
    """MSVC 反修饰。返回人类可读签名，失败返回 None。"""
    h = _get_dbghelp()
    if h is None:
        return None
    for enc in ("ascii", "utf-8", "mbcs"):
        try:
            raw = name.encode(enc)
            break
        except (UnicodeEncodeError, LookupError):
            continue
    else:
        return None
    buf = ctypes.create_string_buffer(8192)
    n = h.UnDecorateSymbolName(raw, buf, 8192, _undname_flags_complete)
    if not n:
        return None
    return buf.value.decode("utf-8", "replace")


# ---------------------------------------------------------------- C 修饰名

_RE_STDCALL = re.compile(r"^_(.+?)@(\d+)$")
_RE_FASTCALL = re.compile(r"^@(.+?)@(\d+)$")


def parse_c_decorated(name: str, bits: int):
    """解析 x86 C 修饰名。

    返回 (clean_name, convention, stack_param_count) 或 None。
    fastcall 时 stack_param_count 不含 ECX/EDX 承载的前两个参数。
    """
    if bits != 32:
        return None
    m = _RE_STDCALL.match(name)
    if m:
        return m.group(1), "__stdcall", int(m.group(2)) // 4
    m = _RE_FASTCALL.match(name)
    if m:
        return m.group(1), "__fastcall", int(m.group(2)) // 4
    if name.startswith("_"):
        return name[1:], "__cdecl", None
    return None


# ---------------------------------------------------------------- C++ 修饰名

_CPP_CC_CODES = {
    "A": "__cdecl", "B": "__cdecl",
    "G": "__stdcall", "H": "__stdcall",
    "I": "__fastcall", "J": "__fastcall",
}

_RE_CPP_FUNC = re.compile(r"^(\?[^@].*?)@@Y([A-Z])")


def cpp_decorated_convention(name: str) -> str | None:
    """从 C++ 修饰名 '@@Y<code>' 直接抽调用约定（无需 dbghelp）。"""
    m = _RE_CPP_FUNC.match(name)
    if m:
        return _CPP_CC_CODES.get(m.group(2))
    return None


_RE_CC_TOKEN = re.compile(
    r"\b(__cdecl|__stdcall|__fastcall|__thiscall|__clrcall|__vectorcall|__pascal)\b")


def demangled_info(text: str):
    """从反修饰文本抽调用约定与参数个数。

    返回 (convention, param_count) —— param_count 数不到时为 None。
    """
    if not text:
        return None, None
    m = _RE_CC_TOKEN.search(text)
    conv = m.group(1) if m else None

    # 抽取最外层参数列表：找函数名后的 '(' 与配对 ')'
    depth = 0
    start = -1
    params: str | None = None
    for i, ch in enumerate(text):
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start >= 0:
                params = text[start + 1:i]
                break
    if params is None:
        return conv, None

    stripped = params.strip()
    if not stripped or stripped == "void":
        return conv, 0
    # 模板实参/函数类型中的逗号不算参数分隔符
    count = _count_top_level_commas(stripped) + 1
    return conv, count


def _count_top_level_commas(s: str) -> int:
    depth = 0
    n = 0
    for ch in s:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            n += 1
    return n
