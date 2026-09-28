"""fakedll 命令行入口。

用法：
    python fakedll.py analyze  <dll|exe> [-o report.json]
    python fakedll.py header   <dll|exe> [-o out.h] [--renderer my.py] [...]
    python fakedll.py def      <dll|exe> [-o out.def]
    python fakedll.py stub     <dll|exe> [-o fake.c] [--def-output fake.def]
    python fakedll.py build    <dll|exe> [-o fake.dll] [--toolchain msvc|gcc|auto]
    python fakedll.py all      <dll|exe> [-o outdir/]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .pe import PEFile
from .analyze import ExportAnalyzer
from .render import (
    RenderContext,
    BUILTIN_RENDERERS,
    load_custom_renderer,
)
from .build import build as build_dll


def _build_ctx(args) -> RenderContext:
    pe = PEFile(args.pefile)
    analyzer = ExportAnalyzer(pe, max_insn=getattr(args, "max_insn", 1200),
                               jump_hops=getattr(args, "jump_hops", 8))
    facts = analyzer.analyze_all()
    options = dict(getattr(args, "opt", {}) or {})
    options.setdefault("arg_style", args.arg_style)
    options["evidence"] = not args.no_evidence
    return RenderContext(pe, facts, options)


def _write(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    print(f"[+] wrote {path} ({len(content)} chars)")


def _parse_kv(pairs):
    out = {}
    for kv in pairs or []:
        if "=" not in kv:
            raise SystemExit(f"--set expects key=value, got: {kv}")
        k, v = kv.split("=", 1)
        out[k] = v
    return out


def _add_common(p):
    p.add_argument("pefile", help="目标 DLL/EXE 路径")
    p.add_argument("--arg-style", choices=["ptr", "int", "none"], default="ptr",
                   help="未知参数的占位风格 (default: ptr -> void* p1..)")
    p.add_argument("--no-evidence", action="store_true",
                   help="头文件中不输出逐函数证据注释")
    p.add_argument("--max-insn", type=int, default=1200,
                   help="每个函数最多分析的指令数")
    p.add_argument("--jump-hops", type=int, default=8,
                   help="垫片跟随的最大跳数")
    p.add_argument("--set", action="append", metavar="k=v", dest="opt",
                   help="传给（自定义）渲染器的选项，可重复")


def cmd_analyze(args) -> int:
    ctx = _build_ctx(args)
    print(json.dumps(ctx.stats(), indent=2))
    for f in ctx.functions:
        if args.verbose or f.param_count is None:
            print(json.dumps(f.to_dict(), ensure_ascii=False))
    if args.output:
        _write(args.output, BUILTIN_RENDERERS["json"](ctx))
    return 0


def cmd_header(args) -> int:
    ctx = _build_ctx(args)
    if args.renderer:
        fn = load_custom_renderer(args.renderer)
        out = fn(ctx)
    else:
        out = BUILTIN_RENDERERS["header"](ctx)
    if args.output:
        _write(args.output, out)
    else:
        sys.stdout.write(out)
    return 0


def cmd_def(args) -> int:
    ctx = _build_ctx(args)
    out = BUILTIN_RENDERERS["def"](ctx)
    if args.output:
        _write(args.output, out)
    else:
        sys.stdout.write(out)
    return 0


def cmd_stub(args) -> int:
    ctx = _build_ctx(args)
    c_out = args.output or f"fake_{ctx.dll_name}.c"
    _write(c_out, BUILTIN_RENDERERS["stub"](ctx))
    if args.def_output is None:
        base = os.path.splitext(c_out)[0]
        args.def_output = base + ".def"
    _write(args.def_output, BUILTIN_RENDERERS["stub-def"](ctx))
    return 0


def cmd_all(args) -> int:
    ctx = _build_ctx(args)
    outdir = args.output or "fakedll_out"
    _write(os.path.join(outdir, f"{ctx.dll_name}.h"),
           BUILTIN_RENDERERS["header"](ctx))
    _write(os.path.join(outdir, f"{ctx.dll_name}.def"),
           BUILTIN_RENDERERS["def"](ctx))
    _write(os.path.join(outdir, f"fake_{ctx.dll_name}.c"),
           BUILTIN_RENDERERS["stub"](ctx))
    _write(os.path.join(outdir, f"fake_{ctx.dll_name}.def"),
           BUILTIN_RENDERERS["stub-def"](ctx))
    _write(os.path.join(outdir, f"{ctx.dll_name}.report.json"),
           BUILTIN_RENDERERS["json"](ctx))
    return 0


def cmd_build(args) -> int:
    ctx = _build_ctx(args)
    out = args.output or f"fake_{ctx.dll_name}.dll"
    ok, msg = build_dll(args.pefile, ctx, out,
                        toolchain=args.toolchain,
                        keep_sources=args.keep_sources,
                        verbose=args.verbose)
    print(msg)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fakedll",
        description="分析 DLL/EXE 导出函数（调用约定 + 参数），生成匹配的 .h 等文件")
    parser.add_argument("--version", action="version", version="fakedll 1.0.0")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("analyze", help="分析并输出 JSON 报告")
    _add_common(p)
    p.add_argument("-o", "--output", help="JSON 报告输出路径")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="打印全部函数（默认仅打印未解析的）")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("header", help="生成导入头文件 .h")
    _add_common(p)
    p.add_argument("-o", "--output", help="输出 .h 路径（缺省打印到 stdout）")
    p.add_argument("--renderer", metavar="PY",
                   help="自定义渲染脚本（需定义 render(ctx)）")
    p.set_defaults(func=cmd_header)

    p = sub.add_parser("def", help="生成与原 DLL 一致的 .def")
    _add_common(p)
    p.add_argument("-o", "--output", help="输出 .def 路径")
    p.set_defaults(func=cmd_def)

    p = sub.add_parser("stub", help="生成 FakeDLL 桩实现（.c + 配套 .def）")
    _add_common(p)
    p.add_argument("-o", "--output", default=None, help="输出 .c 路径")
    p.add_argument("--def-output", default=None, help="配套 .def 输出路径")
    p.set_defaults(func=cmd_stub)

    p = sub.add_parser("build", help="生成桩并直接编译成 DLL（自动探测 MSVC/gcc）+ 导出表校验")
    _add_common(p)
    p.add_argument("-o", "--output", default=None,
                   help="输出 DLL 路径（默认 fake_<原名>.dll）")
    p.add_argument("--toolchain", choices=["auto", "msvc", "gcc"], default="auto",
                   help="指定编译器（默认自动探测：MSVC 优先，回落 gcc）")
    p.add_argument("--keep-sources", default=None, metavar="DIR",
                   help="同时把生成的 .c/.def 保留到该目录")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="输出编译器原始日志")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("all", help="一键生成全部产物到目录")
    _add_common(p)
    p.add_argument("-o", "--output", default=None, help="输出目录")
    p.set_defaults(func=cmd_all)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
