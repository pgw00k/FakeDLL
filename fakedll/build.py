"""构建：把 stub 源码直接编译成可用的 DLL，并校验导出表。

工具链自动探测顺序：MSVC (cl.exe) → MinGW (gcc)。

MSVC 环境下由本模块**自行拼装** INCLUDE / LIB / PATH，不调用 vcvars*.bat：
后者内部依赖 reg.exe 查询注册表定位 VS 与 Windows SDK，在受限/沙箱环境下
会被拦截而导致 INCLUDE 为空（表现为 "无法打开包括文件: windows.h"）。
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import tempfile

from .pe import PEFile

# ------------------------------------------------------------------ 工具链探测

_VS_ROOTS = (
    r"C:\Program Files\Microsoft Visual Studio",
    r"C:\Program Files (x86)\Microsoft Visual Studio",
    r"C:\Program Files\Microsoft Visual Studio\2022",
)
_VS_EDITIONS = ("Community", "Professional", "Enterprise", "BuildTools", "Preview")
_SDK_ROOTS = (
    r"C:\Program Files (x86)\Windows Kits\10",
    r"C:\Program Files\Windows Kits\10",
)
_MINGW_HINTS = (
    r"C:\ProgramData\mingw64\mingw64\bin\gcc.exe",
    r"C:\mingw64\bin\gcc.exe",
    r"C:\msys64\mingw64\bin\gcc.exe",
)


def _ver_key(s: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", s)]
    return tuple(nums) if nums else (0,)


class MSVC:
    """一套可用的 MSVC 工具链。"""

    def __init__(self, cl: str, msvc_root: str, sdk_inc: str, sdk_lib: str, bits: int):
        self.cl = cl
        self.msvc_root = msvc_root
        self.sdk_inc = sdk_inc
        self.sdk_lib = sdk_lib
        self.bits = bits
        self.arch = "x86" if bits == 32 else "x64"

    @property
    def version(self) -> str:
        m = re.search(r"MSVC[\\/]([\d.]+)[\\/]", self.cl)
        return m.group(1) if m else "?"

    def env(self) -> dict:
        env = dict(os.environ)
        incs = [
            os.path.join(self.msvc_root, "include"),
            os.path.join(self.sdk_inc, "ucrt"),
            os.path.join(self.sdk_inc, "shared"),
            os.path.join(self.sdk_inc, "um"),
        ]
        libs = [
            os.path.join(self.msvc_root, "lib", self.arch),
            os.path.join(self.sdk_lib, "ucrt", self.arch),
            os.path.join(self.sdk_lib, "um", self.arch),
        ]
        env["INCLUDE"] = ";".join(incs)
        env["LIB"] = ";".join(libs)
        env["PATH"] = os.path.dirname(self.cl) + os.pathsep + env.get("PATH", "")
        # 强制英文编译诊断：中文消息经管道传输会因代码页不一致而乱码
        env["VSLANG"] = "1033"
        return env

    def __str__(self) -> str:
        return f"MSVC {self.version} ({self.arch} target)"


def _find_sdk():
    for root in _SDK_ROOTS:
        inc_root = os.path.join(root, "Include")
        if not os.path.isdir(inc_root):
            continue
        vers = [d for d in os.listdir(inc_root) if re.match(r"^10\.\d", d)]
        if not vers:
            continue
        ver = max(vers, key=_ver_key)
        inc = os.path.join(inc_root, ver)
        lib = os.path.join(root, "Lib", ver)
        if os.path.isdir(os.path.join(inc, "um")) and os.path.isdir(lib):
            return inc, lib
    return None


def find_msvc(bits: int) -> MSVC | None:
    arch = "x86" if bits == 32 else "x64"
    cands: list[str] = []
    for root in _VS_ROOTS:
        for ed in _VS_EDITIONS:
            cands += glob.glob(os.path.join(
                root, "*", ed, "VC", "Tools", "MSVC", "*", "bin", "Hostx64", arch, "cl.exe"))
            cands += glob.glob(os.path.join(
                root, ed, "VC", "Tools", "MSVC", "*", "bin", "Hostx64", arch, "cl.exe"))
    cands = [c for c in cands if os.path.isfile(c)]
    if not cands:
        return None
    cl = max(cands, key=lambda p: _ver_key(re.search(r"MSVC[\\/]([^\\/]+)", p).group(1)))
    # cl.exe 位于 ...\<ver>\bin\Hostx64\<arch>\cl.exe，向上 4 层回到 <ver> 根
    msvc_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(cl))))
    sdk = _find_sdk()
    if sdk is None:
        return None
    return MSVC(cl, msvc_root, sdk[0], sdk[1], bits)


def find_gcc(bits: int) -> str | None:
    names = ["gcc"] if bits == 64 else ["i686-w64-mingw32-gcc", "mingw32-gcc"]
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    for hint in _MINGW_HINTS:
        if bits == 64 and os.path.isfile(hint):
            return hint
    return None


# ------------------------------------------------------------------ 编译

def compile_msvc(tc: MSVC, src_c: str, src_def: str, out_dll: str, cwd: str) -> tuple[bool, str]:
    cmd = [
        tc.cl, "/nologo", "/utf-8", "/LD",
        f"/Fo{cwd}{os.sep}",
        "/Fe" + out_dll,
        src_c,
        "/link", f"/def:{src_def}", "/out:" + out_dll,
    ]
    p = subprocess.run(cmd, cwd=cwd, env=tc.env(), capture_output=True, text=True,
                       errors="replace")
    return p.returncode == 0, (p.stdout or "") + (p.stderr or "")


def compile_gcc(gcc: str, src_c: str, src_def: str, out_dll: str, cwd: str) -> tuple[bool, str]:
    cmd = [gcc, "-shared", "-o", out_dll, src_c, src_def, "-Wall"]
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace")
    return p.returncode == 0, (p.stdout or "") + (p.stderr or "")


def try_load_check(dll_path: str, pe: PEFile, sample: int = 5) -> str:
    """若当前进程位数与目标 DLL 一致，则实际 LoadLibrary + 抽查导出。"""
    import ctypes
    import struct

    py_bits = struct.calcsize("P") * 8
    if py_bits != pe.bits:
        return (f"跳过加载验证（当前解释器 {py_bits} 位，目标 DLL {pe.bits} 位；"
                f"请用 {pe.bits} 位加载器验证）")
    try:
        h = ctypes.WinDLL(dll_path)
    except OSError as e:
        return f"加载验证失败: {e}"
    names = [e.name for e in pe.exports() if e.name][:sample]
    got = sum(1 for n in names if getattr(h, n, None) is not None)
    # 64 位句柄超过 C int 范围，必须显式按指针传递
    k32 = ctypes.WinDLL("kernel32")
    k32.FreeLibrary.argtypes = [ctypes.c_void_p]
    k32.FreeLibrary.restype = ctypes.c_int
    k32.FreeLibrary(ctypes.c_void_p(h._handle))
    return f"加载验证通过（LoadLibrary 成功，抽样 {got}/{len(names)} 个导出可解析）"


# ------------------------------------------------------------------ 导出表校验

def compare_exports(orig: PEFile, new: PEFile) -> dict:
    o_exports = orig.exports()
    n_exports = new.exports()
    o = {e.ordinal: e.name for e in o_exports}
    n = {e.ordinal: e.name for e in n_exports}
    missing = sorted(set(o) - set(n))
    extra = sorted(set(n) - set(o))
    renamed = [(k, o[k], n[k]) for k in sorted(set(o) & set(n)) if o[k] != n[k]]
    o_fwd = {e.ordinal for e in o_exports if e.forwarder}
    n_fwd = {e.ordinal for e in n_exports if e.forwarder}
    return {
        "orig_total": len(o), "new_total": len(n),
        "missing": missing, "extra": extra, "renamed": renamed,
        "orig_forwarders": sorted(o_fwd), "new_forwarders": sorted(n_fwd),
        "bits_ok": orig.bits == new.bits,
        "machine": f"{orig.machine_name} -> {new.machine_name}",
        "ok": not missing and not extra and not renamed and orig.bits == new.bits,
    }


def format_report(res: dict, target: str, out_dll: str) -> str:
    L = []
    ap = L.append
    ap(f"[+] 生成 {out_dll}")
    ap(f"    源模块 {target}")
    ap("")
    ap("导出表校验:")
    ap(f"    导出总数   原版 {res['orig_total']}  /  生成 {res['new_total']}")
    ap(f"    架构       {res['machine']}  {'一致' if res['bits_ok'] else '不一致!'}")
    ap(f"    缺失序号   {len(res['missing'])}" + (f"  {res['missing'][:10]}" if res['missing'] else "  (无)"))
    ap(f"    多余序号   {len(res['extra'])}" + (f"  {res['extra'][:10]}" if res['extra'] else "  (无)"))
    ap(f"    名字不符   {len(res['renamed'])}" + (f"  {res['renamed'][:5]}" if res['renamed'] else "  (无)"))
    if res["orig_forwarders"]:
        ap(f"    转发导出   原版 {len(res['orig_forwarders'])} 个 -> 生成为占位实现"
           f"（序号 {res['orig_forwarders'][:10]}）")
    ap("")
    ap("    结论: " + ("导出表完全一致" if res["ok"] else "存在差异，请核对上面的明细"))
    return "\n".join(L)


# ------------------------------------------------------------------ 顶层入口

def build(target_pe: str, ctx, out_dll: str, toolchain: str = "auto",
          keep_sources: str | None = None, verbose: bool = False) -> tuple[bool, str]:
    """生成 stub 源码 -> 编译 -> 校验。返回 (成功?, 消息)。"""
    from .render import BUILTIN_RENDERERS

    pe = PEFile(target_pe)
    stem = ctx.dll_name

    if toolchain in ("auto", "msvc"):
        tc = find_msvc(pe.bits)
        if tc is None and toolchain == "msvc":
            return False, "未找到可用的 MSVC (cl.exe) 或 Windows SDK"
    else:
        tc = None
    gcc = None
    if tc is None:
        gcc = find_gcc(pe.bits)
        if gcc is None:
            hint = ""
            if pe.bits == 32:
                hint = ("\n    32 位目标需要 MSVC 任意版本，或 i686-w64-mingw32-gcc；"
                        "仅有 x64 MinGW (无 multilib) 无法编译 32 位。")
            return False, (
                "未找到可用编译器。请安装 MSVC（Visual Studio / Build Tools）"
                "或 MinGW-w64。" + hint)

    work = tempfile.mkdtemp(prefix="fakedll_build_")
    try:
        src_c = os.path.join(work, f"fake_{stem}.c")
        src_def = os.path.join(work, f"fake_{stem}.def")
        with open(src_c, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(BUILTIN_RENDERERS["stub"](ctx))
        with open(src_def, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(BUILTIN_RENDERERS["stub-def"](ctx))

        # 输出名与 .def 中 LIBRARY 名保持一致，避免 LNK4070
        tmp_dll = os.path.join(work, f"{stem}.dll")
        if tc is not None:
            ok, log = compile_msvc(tc, src_c, src_def, tmp_dll, work)
            who = str(tc)
        else:
            ok, log = compile_gcc(gcc, src_c, src_def, tmp_dll, work)
            who = f"gcc ({gcc})"

        if not ok or not os.path.isfile(tmp_dll):
            return False, f"编译失败（{who}）:\n{log.strip()[:4000]}"

        os.makedirs(os.path.dirname(os.path.abspath(out_dll)) or ".", exist_ok=True)
        shutil.copyfile(tmp_dll, out_dll)

        if keep_sources:
            os.makedirs(keep_sources, exist_ok=True)
            shutil.copyfile(src_c, os.path.join(keep_sources, os.path.basename(src_c)))
            shutil.copyfile(src_def, os.path.join(keep_sources, os.path.basename(src_def)))

        res = compare_exports(pe, PEFile(out_dll))
        load = try_load_check(out_dll, pe)
        msg = f"工具链: {who}\n" + format_report(res, target_pe, out_dll)
        msg += f"\n\n{load}"
        if verbose and log.strip():
            msg += "\n\n编译器输出:\n" + log.strip()
        return res["ok"], msg
    finally:
        shutil.rmtree(work, ignore_errors=True)
