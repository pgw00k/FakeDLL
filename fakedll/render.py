"""渲染层：生成 .h / .def / stub C 源 / JSON 报告，并支持自定义渲染器。

自定义渲染器协议（--renderer path/to/renderer.py）::

    def render(ctx) -> str:
        # ctx.dll_name / ctx.dll_path / ctx.bits / ctx.machine / ctx.timestamp
        # ctx.functions        -> list[fakedll.analyze.FunctionFacts]
        # ctx.options          -> dict（CLI --set k=v 传入）
        # ctx.helper.param_list(fact) -> "void* p1, void* p2"
        return "/* header text */"

返回值即整个输出文件内容。
"""

from __future__ import annotations

import importlib.util
import os
import re
from datetime import datetime

from .pe import PEFile
from .analyze import FunctionFacts

# ------------------------------------------------------------------ 上下文


class RenderContext:
    """传给（内置与自定义）渲染器的全部信息。"""

    def __init__(self, pe: PEFile, facts: list[FunctionFacts], options: dict | None = None):
        self.pe = pe
        self.dll_path = pe.path
        self.dll_name = os.path.splitext(os.path.basename(pe.path))[0]
        self.dll_size = len(pe.data)
        self.bits = pe.bits
        self.machine = pe.machine_name
        self.image_base = pe.image_base
        self.timestamp = pe.timestamp
        self.export_dll_name = pe.export_dll_name()
        self.functions = facts
        self.options = options or {}
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @property
    def count(self) -> int:
        return len(self.functions)

    # 便捷统计
    def stats(self) -> dict:
        s = {"total": self.count,
             "c_exports": 0, "cpp_exports": 0, "forwarders": 0,
             "import_thunks": 0, "data_exports": 0,
             "resolved": 0, "unresolved": 0}
        for f in self.functions:
            if f.export.name and f.export.name.startswith("?"):
                s["cpp_exports"] += 1
            else:
                s["c_exports"] += 1
            if f.export.forwarder:
                s["forwarders"] += 1
            elif f.import_thunk:
                s["import_thunks"] += 1
            if f.is_data:
                s["data_exports"] += 1
            if f.param_count is not None:
                s["resolved"] += 1
            else:
                s["unresolved"] += 1
        return s


class RenderHelper:
    """给自定义渲染器用的工具函数集合。"""

    def __init__(self, ctx: RenderContext):
        self.ctx = ctx

    # -- 参数占位串 --
    def param_list(self, fact: FunctionFacts, style: str | None = None) -> str:
        style = style or self.ctx.options.get("arg_style", "ptr")
        n = fact.param_count
        if n is None:
            return "()" if self.ctx.options.get("empty_unknown", "paren") == "paren" else ""
        if n == 0:
            return "void"
        if style == "int":
            return ", ".join(f"int a{i + 1}" for i in range(n))
        return ", ".join(f"void* p{i + 1}" for i in range(n))

    # -- 调用约定关键字（x64 省略）--
    def cc_keyword(self, fact: FunctionFacts) -> str:
        if self.ctx.bits == 64:
            return ""
        conv = fact.convention or "__cdecl"
        if conv in ("__cdecl", "__stdcall", "__fastcall"):
            return conv + " "
        return ""

    # -- 占位返回类型 --
    def return_type(self, fact: FunctionFacts) -> str:
        return "void*"

    def c_safe_name(self, name: str) -> str:
        return re.sub(r"[^A-Za-z0-9_]", "_", name)


# ------------------------------------------------------------------ C++ 签名直通

_SIG_PREFIXES = ("public: ", "private: ", "protected: ", "static ",
                 "virtual ", "explicit ", "friend ", "inline ")
_CC_RE = re.compile(
    r"\b(__cdecl|__stdcall|__fastcall|__thiscall|__clrcall|__vectorcall)\b")
_PTR64_RE = re.compile(r"\s*\b__ptr64\b|\b__ptr64\b\s*|\b__restrict\b|\b__unaligned\b")
_SCALARS = {
    "void", "bool", "char", "signed char", "unsigned char", "short",
    "unsigned short", "int", "unsigned int", "long", "unsigned long",
    "long long", "unsigned long long", "__int64", "float", "double",
    "long double", "wchar_t", "size_t", "unsigned", "signed",
}  # noqa: F841 —— 文档化用途
_CLASSY_RE = re.compile(r"\b(class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)")


def _split_params(params: str) -> list[str]:
    out, depth, cur = [], 0, []
    for ch in params:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur))
    return out


def _norm_type(t: str) -> str:
    t = _PTR64_RE.sub(" ", t)
    return re.sub(r"\s+", " ", t).strip()


def try_cpp_declaration(fact: FunctionFacts):
    """把 demangled 签名转成可编译的 C++ 声明。

    返回 (declaration, forward_decls) 或 None。
    declaration 形如 "__cdecl bool SteamAPI_Init(void)"（不含分号）。
    失败条件：成员函数、作用域限定名、模板类型、按值类参数、函数指针返回值等。
    """
    sig = fact.cpp_signature
    if not sig:
        return None
    text = sig
    changed = True
    while changed:
        changed = False
        for p in _SIG_PREFIXES:
            if text.startswith(p):
                text = text[len(p):]
                changed = True

    m = _CC_RE.search(text)
    if not m:
        return None
    conv = m.group(1)
    if conv == "__thiscall":
        return None  # C 里无法声明 thiscall 导出
    rettype = _norm_type(text[:m.start()])
    rest = text[m.end():]

    # 名字与参数列表
    ppos = rest.find("(")
    if ppos < 0:
        return None
    name = rest[:ppos].strip()
    if not name or "::" in name or "<" in name or " " in name:
        return None
    # 参数列表：找配对 ')'
    depth = 0
    end = -1
    for i, ch in enumerate(rest):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return None
    params_raw = rest[ppos + 1:end]

    if not rettype or "(" in rettype or "<" in rettype:
        return None
    fwd: list[str] = []

    # 返回类型检查：类/结构只能以指针或引用出现
    if _CLASSY_RE.search(rettype):
        if "*" not in rettype and "&" not in rettype:
            return None
        for cm in _CLASSY_RE.finditer(rettype):
            fwd.append(f"{cm.group(1)} {cm.group(2)};")

    parts = _split_params(params_raw)
    rendered: list[str] = []
    if len(parts) == 1 and _norm_type(parts[0]) == "void":
        rendered.append("void")
    else:
        for p in parts:
            t = _norm_type(p)
            if not t:
                return None
            if "<" in t and ">" in t:
                return None  # 模板类型需要完整定义
            if "(" in t:
                # 函数指针参数（形如 'void (__cdecl *)(int)'）—— 原样保留
                rendered.append(t)
                continue
            cm = _CLASSY_RE.search(t)
            if cm:
                kw, cls = cm.group(1), cm.group(2)
                after = t[cm.end():]
                if "*" not in after and "&" not in after:
                    return None  # 类按值传递，无法安全声明
                fwd.append(f"{kw} {cls};")
            rendered.append(t)
    decl = f"{conv} {rettype} {name}({', '.join(rendered)})"
    # 去重前向声明
    seen, uniq = set(), []
    for d in fwd:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return decl, uniq


# ------------------------------------------------------------------ 内置渲染

def render_header(ctx: RenderContext) -> str:
    opt = ctx.options
    arg_style = opt.get("arg_style", "ptr")
    with_evidence = opt.get("evidence", True) in (True, "1", "true", "yes")
    helper = RenderHelper(ctx)
    st = ctx.stats()

    L: list[str] = []
    ap = L.append
    guard = re.sub(r"[^A-Za-z0-9_]", "_", ctx.dll_name).upper() + "_EXPORTS_H_"

    ap("/*")
    ap(f" * {ctx.dll_name}.dll 导出头文件")
    ap(f" * Generated by fakedll on {ctx.generated_at}")
    ap(f" * Source  : {ctx.dll_path} ({ctx.dll_size} bytes)")
    ap(f" * Target  : {ctx.machine} ({ctx.bits}-bit), image base 0x{ctx.image_base:X}")
    ap(f" * Exports : {st['total']} total"
       f" ({st['c_exports']} C / {st['cpp_exports']} C++ decorated"
       f" / {st['forwarders']} forwarders / {st['import_thunks']} import-thunks"
       f" / {st['data_exports']} data)")
    ap(f" * Params  : {st['resolved']} resolved, {st['unresolved']} unknown")
    ap(" *")
    ap(" * 推断依据优先级: 导出修饰名(MSVC mangled) > x86 C 修饰名 > 函数字节码分析。")
    ap(" * param_kind: exact=ABI 精确 | signature=C++签名 | min=至少 | guess=猜测 | unknown")
    ap(" * 未知参数类型以占位形式给出（void* p1...），请按实际语义修正。")
    ap(" */")
    ap("")
    ap("#pragma once")
    ap(f"#ifndef {guard}")
    ap(f"#define {guard}")
    ap("")
    if ctx.bits == 64:
        ap("#if defined(_M_IX86) && !defined(_M_X64) && !defined(_M_ARM64)")
        ap(f'#error "{ctx.dll_name}.dll is 64-bit; this header matches an x64 build"')
        ap("#endif")
    else:
        ap("#if defined(_M_X64) || defined(_WIN64)")
        ap(f'#error "{ctx.dll_name}.dll is 32-bit; this header matches an x86 build"')
        ap("#endif")
    ap("")

    c_facts, cpp_facts = [], []
    for f in ctx.functions:
        if f.export.name and f.export.name.startswith("?"):
            cpp_facts.append(f)
        else:
            c_facts.append(f)

    # ---------------- extern "C" 段 ----------------
    ap("/* ============================ C 导出 ============================ */")
    ap("#ifdef __cplusplus")
    ap('extern "C" {')
    ap("#endif")
    ap("")
    for f in c_facts:
        _emit_c_export(ap, ctx, f, helper, arg_style, with_evidence)
    ap("")
    ap("#ifdef __cplusplus")
    ap("}")
    ap("#endif")
    ap("")

    # ---------------- C++ 修饰名段 ----------------
    if cpp_facts:
        ap("/* ===================== C++ 修饰名导出 ===================== */")
        ap("/* 这些声明直接复刻 MSVC 修饰名所要求的签名；编译时修饰名自动对上。 */")
        ap("")
        fwd_all: list[str] = []
        n_ok = n_fail = 0
        for f in cpp_facts:
            if with_evidence:
                _emit_evidence(ap, ctx, f)
            got = try_cpp_declaration(f)
            if got:
                decl, fwd = got
                fwd_all.extend(d for d in fwd if d not in fwd_all)
                ap(f"__declspec(dllimport) {decl};")
                n_ok += 1
            else:
                n_fail += 1
                ap(f"/* {f.export.name}")
                if f.cpp_signature:
                    ap(f" * undname: {f.cpp_signature}")
                ap(" * 无法生成可链接声明（成员函数/模板/按值类参数）。")
                ap(" * 请用 GetProcAddress 按原始修饰名获取，或手写匹配签名。 */")
            ap("")
        if fwd_all:
            ap("/* -------- 前向声明（签名直通所需）-------- */")
            for d in fwd_all:
                ap(d)
            ap("")
        ap(f"/* C++ 导出直通: {n_ok} 成功, {n_fail} 回退注释 */")
        ap("")

    ap(f"#endif /* {guard} */")
    ap("")
    return "\n".join(L)


def _emit_evidence(ap, ctx: RenderContext, f: FunctionFacts) -> None:
    ap(f"/* [{f.export.ordinal}] {f.export.name or f'<ordinal-only>'}"
       + (" DATA" if f.is_data else ""))
    ap(f" *   RVA 0x{f.export.rva:X}"
       + (f" -> body 0x{f.body_rva:X}" if f.body_rva and f.body_rva != f.export.rva else ""))
    if f.export.forwarder:
        ap(f" *   forwarder -> {f.export.forwarder}")
    if f.import_thunk:
        ap(f" *   jmp [IAT] -> {f.import_thunk}")
    if f.is_data:
        ap(" *   数据导出（变量），非函数")
    else:
        kind = f.param_kind if f.param_count is not None else "unknown"
        conv = f.convention or ("x64" if ctx.bits == 64 else "?")
        cnt = f.param_count if f.param_count is not None else "?"
        ap(f" *   {conv}, {cnt} param(s) [{kind}]")
    for ev in f.evidence:
        ap(f" *   - {ev}")
    ap(" */")


def _emit_c_export(ap, ctx: RenderContext, f: FunctionFacts, helper: RenderHelper,
                   arg_style: str, with_evidence: bool) -> None:
    if with_evidence:
        _emit_evidence(ap, ctx, f)
    name = f.clean_name or f"ordinal_{f.export.ordinal}"
    if f.is_data:
        # 数据导出：按变量声明（.h 侧需要 dllimport 数据）
        ap(f"__declspec(dllimport) extern void* {name};  /* data export */")
        return
    cc = helper.cc_keyword(f)
    ret = helper.return_type(f)
    if f.param_count is None or f.param_count == 0:
        if f.param_count == 0:
            params = "(void)"
        else:
            params = "(void)" if arg_style != "none" else "()"
    else:
        params = "(" + helper.param_list(f, arg_style) + ")"
    extra = ""
    if f.param_count is None and not f.export.forwarder and not f.import_thunk:
        extra = "  /* 参数个数未知 */"
    ap(f"__declspec(dllimport) {ret} {cc}{name}{params};{extra}")


def render_def(ctx: RenderContext) -> str:
    """生成与原 DLL 导出表一致的 .def（转发导出复刻为转发语法）。"""
    L: list[str] = []
    ap = L.append
    st = ctx.stats()
    ap(f"; {ctx.dll_name}.def — generated by fakedll on {ctx.generated_at}")
    ap(f"; source: {ctx.dll_path} ({ctx.bits}-bit {ctx.machine})")
    ap(f"; {st['total']} exports（含 {st['forwarders']} 个转发导出）")
    ap("")
    ap(f'LIBRARY "{ctx.dll_name}"')
    ap("EXPORTS")
    ap("")
    for f in ctx.functions:
        name = f.export.name
        if name is None:
            ap(f"    ; 原始导出仅有序号 {f.export.ordinal}（无名）")
            ap(f"    fake_ordinal_{f.export.ordinal} @{f.export.ordinal}")
        elif f.export.forwarder:
            ap(f"    ; 原始转发 -> {f.export.forwarder}（此处复刻转发行为）")
            ap(f"    {name} = {f.export.forwarder}")
        elif f.is_data:
            ap(f"    {name} @{f.export.ordinal} DATA")
        else:
            ap(f"    {name} @{f.export.ordinal}")
    return "\n".join(L) + "\n"


def render_stub_def(ctx: RenderContext) -> str:
    """生成与 fake_*.c 桩配套的 .def：原名 -> fake_ 内部名映射。"""
    helper = RenderHelper(ctx)
    L: list[str] = []
    ap = L.append
    ap(f"; {ctx.dll_name}_stub.def — 配套 fake_{ctx.dll_name}.c 使用")
    ap(f"; generated by fakedll on {ctx.generated_at}")
    ap("")
    ap(f'LIBRARY "{ctx.dll_name}"')
    ap("EXPORTS")
    ap("")
    for f in ctx.functions:
        safe = helper.c_safe_name(f.clean_name or f"ordinal_{f.export.ordinal}")
        name = f.export.name
        if f.export.forwarder:
            ap(f"    ; 原始为转发导出 -> {f.export.forwarder}；此处改为占位实现")
            ap(f"    ; 如需复刻转发，改用:  {name} = {f.export.forwarder}")
        if name is None:
            ap(f"    fake_{safe} @{f.export.ordinal}")
        else:
            # C 符号一律带 fake_ 前缀（render_stub），故原名须经 '=' 映射到内部符号；
            # 该语法 MSVC link 与 GNU ld (MinGW) 的 .def 解析器均支持。
            data_kw = " DATA" if f.is_data else ""
            ap(f"    {name} = fake_{safe} @{f.export.ordinal}{data_kw}")
    return "\n".join(L) + "\n"


def render_stub(ctx: RenderContext) -> str:
    """生成 FakeDLL 实现骨架（fake dll.c）—— 与 render_stub_def 的 .def 配套使用。"""
    helper = RenderHelper(ctx)
    L: list[str] = []
    ap = L.append
    ap(f"/* fake_{ctx.dll_name}.c — FakeDLL 桩实现, generated by fakedll on {ctx.generated_at}")
    ap(f" * source: {ctx.dll_path} ({ctx.bits}-bit {ctx.machine})")
    ap(" *")
    ap(" * 编译（MSVC 示例）:")
    ap(f" *   cl /LD fake_{ctx.dll_name}.c /link /def:{ctx.dll_name}_stub.def")
    ap(" *")
    ap(" * 每个 C 导出按推断的调用约定与参数个数生成占位实现；")
    ap(" * 所有导出经配套 .def 以 '原名 = fake_内部名' 映射导出，")
    ap(" * 故编译时内部符号名不与其它模块冲突。")
    ap(" */")
    ap("")
    ap("#include <windows.h>")
    ap("")
    ap("#if defined(_MSC_VER)")
    ap("#pragma warning(disable : 4100) /* unreferenced formal parameter */")
    ap("#endif")
    ap("")
    for f in ctx.functions:
        safe = helper.c_safe_name(f.clean_name or f"ordinal_{f.export.ordinal}")
        ap(f"/* [{f.export.ordinal}] {f.export.name or '<unnamed>'}"
           + (f" | original forwarder: {f.export.forwarder}" if f.export.forwarder else "")
           + (f" | jmp [IAT] -> {f.import_thunk}" if f.import_thunk else "")
           + (" | DATA export" if f.is_data else "")
           + " */")
        if f.is_data:
            # 数据导出：占位全局变量（配合 .def 的 DATA 关键字）
            ap(f"void* fake_{safe} = 0;")
            ap("")
            continue
        cc = helper.cc_keyword(f)
        if f.param_count is None or f.param_count == 0:
            params = "(void)"
            body = []
        else:
            plist = helper.param_list(f)
            params = f"({plist})"
            names = re.findall(r"\b[pi]\d+\b", plist)
            body = [f"    (void){n};" for n in names]
        ap(f"void* {cc}fake_{safe}{params}")
        ap("{")
        for b in body:
            ap(b)
        ap("    return 0;")
        ap("}")
        ap("")
    return "\n".join(L)


def render_json_report(ctx: RenderContext) -> str:
    import json
    obj = {
        "dll": {
            "path": ctx.dll_path,
            "name": ctx.dll_name,
            "bits": ctx.bits,
            "machine": ctx.machine,
            "image_base": f"0x{ctx.image_base:X}",
            "timestamp": ctx.timestamp,
            "export_dll_name": ctx.export_dll_name,
            "size": ctx.dll_size,
        },
        "stats": ctx.stats(),
        "functions": [f.to_dict() for f in ctx.functions],
    }
    return json.dumps(obj, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------ 自定义渲染器


def load_custom_renderer(path: str):
    """加载自定义渲染脚本，返回 render(ctx) -> str 可调用。"""
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"renderer script not found: {path}")
    mod_name = "fakedll_custom_renderer_" + re.sub(r"\W", "_", path)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load renderer module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, "render", None)
    if fn is None and hasattr(mod, "Renderer"):
        inst = mod.Renderer()
        fn = getattr(inst, "render", None)
    if not callable(fn):
        raise AttributeError(
            f"renderer {path} must define render(ctx) or Renderer().render(ctx)")
    return fn


BUILTIN_RENDERERS = {
    "header": render_header,
    "def": render_def,
    "stub-def": render_stub_def,
    "stub": render_stub,
    "json": render_json_report,
}
