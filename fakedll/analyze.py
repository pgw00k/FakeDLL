"""基于 capstone 的导出函数字节码分析：调用约定与参数推断。

推断手段（按证据强度）：
  x86:
    - ret imm16      : 唯一立即数 N => stdcall/fastcall（ABI 真值，调用者须压 N 字节栈参数）
                       N==0 时 cdecl 与 stdcall(0参) 栈行为等价，默认 cdecl
    - ECX/EDX 首读   : 首条“读未定义”指令 => fastcall 寄存器参数（EDX 读 => 至少 2 个）
    - [ebp+8+4k] 引用: 帧指针下的栈参数使用计数（“至少”语义）
  x64:
    - Microsoft x64 统一调用约定，无需区分
    - mov [rsp+8/0x10/0x18/0x20], reg  => 影子空间保存，精确指出前 4 参数
    - RCX/RDX/R8/R9（含子寄存器）首读未写 => 参数引用
    - 入口块 [rsp+0x28+8k] 读引用 => 第 5+ 个栈参数
  垫片:
    - jmp rel / push imm32; ret / mov reg,[rip+X]; jmp reg => 跟随到真实函数体
    - jmp [IAT] => 转发到导入函数（无本地代码）

所有结论均附带 evidence 字符串，供人工复核（诊断式输出）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_AC_READ, CS_AC_WRITE
from capstone.x86_const import (
    X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
    X86_REG_ECX, X86_REG_CX, X86_REG_CH, X86_REG_CL,
    X86_REG_EDX, X86_REG_DX, X86_REG_DH, X86_REG_DL,
    X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9,
    X86_REG_R8D, X86_REG_R8W, X86_REG_R8B,
    X86_REG_R9D, X86_REG_R9W, X86_REG_R9B,
    X86_REG_RIP, X86_REG_ESP, X86_REG_RSP, X86_REG_EBP, X86_REG_RBP,
)

from .pe import PEFile, ExportFunc
from . import demangle

# ------------------------------------------------------------------ 寄存器族

_X86_FASTCALL_FAM = {}
for _r, _f in [(X86_REG_ECX, "ecx"), (X86_REG_CX, "ecx"), (X86_REG_CH, "ecx"), (X86_REG_CL, "ecx"),
               (X86_REG_EDX, "edx"), (X86_REG_DX, "edx"), (X86_REG_DH, "edx"), (X86_REG_DL, "edx")]:
    _X86_FASTCALL_FAM[_r] = _f

_X64_ARG_FAM = {}
for _r, _f in [(X86_REG_RCX, 0), (X86_REG_ECX, 0), (X86_REG_CX, 0), (X86_REG_CH, 0), (X86_REG_CL, 0),
               (X86_REG_RDX, 1), (X86_REG_EDX, 1), (X86_REG_DX, 1), (X86_REG_DH, 1), (X86_REG_DL, 1),
               (X86_REG_R8, 2), (X86_REG_R8D, 2), (X86_REG_R8W, 2), (X86_REG_R8B, 2),
               (X86_REG_R9, 3), (X86_REG_R9D, 3), (X86_REG_R9W, 3), (X86_REG_R9B, 3)]:
    _X64_ARG_FAM[_r] = _f

_X64_FAM_NAME = {0: "rcx", 1: "rdx", 2: "r8", 3: "r9"}

_TERMINATORS = {"ret", "retf", "iret", "iretd", "iretq", "ud2", "hlt", "int3"}


@dataclass
class FunctionFacts:
    """单个导出函数的分析结论。"""
    export: ExportFunc
    clean_name: str                       # 去修饰后的可读名
    is_data: bool = False                  # 数据导出（变量）而非函数
    cpp_signature: str | None = None       # MSVC demangle 的完整签名（若有）
    convention: str | None = None          # __cdecl / __stdcall / __fastcall / __thiscall / x64
    convention_source: str | None = None   # 结论来源
    param_count: int | None = None
    param_kind: str = "unknown"            # exact / signature / min / guess / unknown / data
    body_rva: int | None = None            # 真实函数体（跟随垫片后）
    import_thunk: str | None = None        # "kernel32!CreateFileA"
    thunk_chain: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    ret_imms: list[int] = field(default_factory=list)
    register_params: int = 0                # fastcall: ECX/EDX 承载的参数数
    stack_param_bytes: int | None = None   # ret N 的 N
    tail_forwarder: bool = False            # 体内含 jmp reg 尾调用（参数转发不可观测）

    def to_dict(self) -> dict:
        return {
            "name": self.export.name,
            "clean_name": self.clean_name,
            "is_data": self.is_data,
            "ordinal": self.export.ordinal,
            "rva": f"0x{self.export.rva:X}",
            "body_rva": f"0x{self.body_rva:X}" if self.body_rva is not None else None,
            "forwarder": self.export.forwarder,
            "import_thunk": self.import_thunk,
            "cpp_signature": self.cpp_signature,
            "convention": self.convention,
            "convention_source": self.convention_source,
            "param_count": self.param_count,
            "param_kind": self.param_kind,
            "register_params": self.register_params,
            "stack_param_bytes": self.stack_param_bytes,
            "tail_forwarder": self.tail_forwarder,
            "thunk_chain": self.thunk_chain,
            "evidence": self.evidence,
        }


_SIG_CC = r"(?:__cdecl|__stdcall|__fastcall|__thiscall|__clrcall|__vectorcall)"
_RE_SIG_NAME = re.compile(rf"{_SIG_CC}\s+([^\s(]+(?:\s*\$?[^\s(])*)\s*\(")


def extract_name_from_signature(sig: str) -> str | None:
    """从 'bool __cdecl Foo::Bar(int)' 里抽 'Foo::Bar'。"""
    if not sig:
        return None
    m = _RE_SIG_NAME.search(sig)
    if not m:
        return None
    return m.group(1).strip()


class ExportAnalyzer:
    def __init__(self, pe: PEFile, max_insn: int = 1200, jump_hops: int = 8):
        self.pe = pe
        self.max_insn = max_insn
        self.jump_hops = jump_hops
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32 if pe.bits == 32 else CS_MODE_64)
        self.cs.detail = True
        self.iat_map = pe.iat_map()
        self._fam = _X86_FASTCALL_FAM if pe.bits == 32 else _X64_ARG_FAM

    # ---------------------------------------------------------- 主入口

    def analyze(self, exp: ExportFunc) -> FunctionFacts:
        f = FunctionFacts(export=exp, clean_name=self._fallback_name(exp))
        if exp.forwarder:
            f.evidence.append(f"forwarder export -> {exp.forwarder}")
            return f

        # --- 证据 0：数据导出检测（RVA 落在非可执行节 => 变量而非函数） ---
        sec = self.pe.section_of_rva(exp.rva)
        if sec is not None and not sec.executable:
            f.is_data = True
            f.param_kind = "data"
            f.evidence.append(
                f"RVA 0x{exp.rva:X} in section '{sec.name}' "
                f"(non-executable) => data export (variable)")
            return f

        # --- 证据 1：导出名 ---
        name_conv = name_params = None
        name_kind = "unknown"
        if exp.name:
            if exp.name.startswith("?"):
                sig = demangle.undecorate(exp.name)
                if sig:
                    f.cpp_signature = sig
                    conv, cnt = demangle.demangled_info(sig)
                    name_conv, name_params, name_kind = conv, cnt, "signature"
                    f.evidence.append(f"C++ decorated '{exp.name}'")
                    f.evidence.append(f"undname: {sig}")
                    f.clean_name = extract_name_from_signature(sig) or f.clean_name
            elif self.pe.bits == 32:
                cinfo = demangle.parse_c_decorated(exp.name, 32)
                if cinfo:
                    clean, conv, stack_params = cinfo
                    f.clean_name = clean
                    if conv == "__stdcall":
                        name_conv, name_params, name_kind = conv, stack_params, "exact"
                        f.evidence.append(
                            f"C decorated '_name@N': __stdcall, {stack_params} stack arg(s)")
                    elif conv == "__fastcall":
                        name_conv = conv
                        f.evidence.append(
                            f"C decorated '@name@N': __fastcall, {stack_params} stack arg(s) beyond ECX/EDX")
                        # 寄存器参数数需字节码确认
                        name_params = None
                        name_kind = "partial"

        # --- 证据 2：字节码 ---
        byte_conv = byte_params = None
        byte_kind = "unknown"
        body_rva, import_thunk = self._resolve_entry(exp.rva, f)
        f.body_rva = body_rva
        if import_thunk:
            f.import_thunk = import_thunk
            f.evidence.append(f"jmp [IAT] -> {import_thunk} (no local body)")
        elif body_rva is not None:
            byte_conv, byte_params, byte_kind = (
                self._analyze_x86(body_rva, f) if self.pe.bits == 32
                else self._analyze_x64(body_rva, f))

        # --- 综合 ---
        if name_conv:
            f.convention, f.convention_source = name_conv, "decorated-name"
        elif import_thunk:
            f.convention, f.convention_source = None, "import-thunk"
        elif byte_conv:
            f.convention, f.convention_source = byte_conv, "bytecode"
        else:
            f.convention = "x64" if self.pe.bits == 64 else "__cdecl"
            f.convention_source = "default-assumption"

        if name_params is not None and name_kind == "signature":
            f.param_count, f.param_kind = name_params, "signature"
        elif name_params is not None and name_kind == "exact":
            f.param_count, f.param_kind = name_params, "exact"
        elif byte_params is not None:
            f.param_count, f.param_kind = byte_params, byte_kind
            if name_params is not None and name_params != byte_params:
                f.evidence.append(
                    f"NOTE: name suggests {name_params} param(s), bytecode says {byte_params}")
        elif name_params is not None:
            f.param_count, f.param_kind = name_params, name_kind

        if import_thunk and f.param_count is None:
            f.evidence.append("parameters unknown: body is an import forwarder")
        return f

    def analyze_all(self) -> list[FunctionFacts]:
        return [self.analyze(e) for e in self.pe.exports()]

    def _fallback_name(self, exp: ExportFunc) -> str:
        if exp.name:
            return exp.name
        return f"ordinal_{exp.ordinal}"

    # ---------------------------------------------------------- 垫片解析

    def _first_insn(self, rva: int, length: int = 32):
        code = self.pe.read_rva(rva, length)
        if not code:
            return None, None
        for insn in self.cs.disasm(code, rva, count=1):
            return insn, code
        return None, code

    def _resolve_entry(self, rva: int, f: FunctionFacts):
        """跟随 jmp/push-ret/mov+jmp 垫片。返回 (body_rva, import_thunk)。"""
        for _ in range(self.jump_hops):
            insn, code = self._first_insn(rva)
            if insn is None:
                return rva, None
            m = insn.mnemonic
            ops = insn.operands

            if m == "jmp":
                if ops and ops[0].type == X86_OP_IMM:
                    tgt = ops[0].imm
                    f.thunk_chain.append(f"jmp 0x{tgt:X} (from 0x{rva:X})")
                    rva = tgt
                    continue
                if ops and ops[0].type == X86_OP_MEM:
                    thunk = self._iat_thunk(insn)
                    if thunk:
                        return None, thunk
                    # 间接 jmp 但非 IAT（switch/虚表）→ 就地分析
                    return rva, None
                return rva, None  # jmp reg

            if m == "push" and ops and ops[0].type == X86_OP_IMM:
                nxt, _ = self._first_insn(rva + insn.size)
                if nxt is not None and nxt.mnemonic == "ret":
                    tgt = ops[0].imm
                    if self.pe.bits == 32:
                        tgt -= self.pe.image_base
                    if tgt > 0 and self.pe.section_of_rva(tgt) is not None:
                        f.thunk_chain.append(
                            f"push 0x{ops[0].imm:X}; ret -> 0x{tgt:X}")
                        rva = tgt
                        continue
                return rva, None

            if m == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                    and ops[1].type == X86_OP_MEM:
                # mov rax, [rip+X]; jmp rax —— 读取 IAT 后跳寄存器
                nxt, _ = self._first_insn(rva + insn.size)
                if nxt is not None and nxt.mnemonic == "jmp" and nxt.operands \
                        and nxt.operands[0].type == X86_OP_REG:
                    thunk = self._iat_thunk(insn)
                    if thunk:
                        return None, thunk
                return rva, None
            return rva, None
        return rva, None

    def _iat_thunk(self, insn):
        """判断一条基于内存的指令是否指向 IAT，返回导入名。"""
        op = insn.operands[0]
        if op.type != X86_OP_MEM:
            return None
        mem = op.mem
        if self.pe.bits == 64:
            if mem.base != X86_REG_RIP:
                return None
            iat_rva = insn.address + insn.size + mem.disp
        else:
            if mem.base not in (0, None):
                return None
            iat_rva = mem.disp - self.pe.image_base
        if iat_rva < 0:
            return None
        ent = self.iat_map.get(iat_rva)
        if ent:
            return f"{ent.dll}!{ent.name}"
        return None

    # ---------------------------------------------------------- 指令收集

    def _collect(self, start_rva: int):
        """递归下降收集指令（条件跳转两路、无条件跳转只跟一次）。"""
        insns: list = []
        seen: set[int] = set()
        stack: list[tuple[int, int]] = [(start_rva, 0)]
        while stack and len(insns) < self.max_insn:
            rva, uncond = stack.pop()
            if rva in seen:
                continue
            code = self.pe.read_rva(rva, 512)
            if not code:
                continue
            block_done = False
            for insn in self.cs.disasm(code, rva):
                if insn.address in seen:
                    block_done = True
                    break
                seen.add(insn.address)
                insns.append(insn)
                m = insn.mnemonic
                if m in _TERMINATORS:
                    block_done = True
                    break
                if m == "jmp":
                    ops = insn.operands
                    if ops and ops[0].type == X86_OP_IMM and uncond < 1:
                        stack.append((ops[0].imm, uncond + 1))
                    block_done = True
                    break
                if m.startswith("j") or m == "loop" or m.startswith("loop"):
                    ops = insn.operands
                    if ops and ops[0].type == X86_OP_IMM:
                        stack.append((ops[0].imm, uncond))
                    continue
            if not block_done:
                pass  # 窗口耗尽，容忍
        return insns

    def _linear_scan(self, start_rva: int, max_count: int = 64):
        """入口块线性反汇编（用于 prologue / rsp 相对引用分析）。"""
        code = self.pe.read_rva(start_rva, 512)
        out = []
        if not code:
            return out
        for insn in self.cs.disasm(code, start_rva):
            out.append(insn)
            if len(out) >= max_count:
                break
            m = insn.mnemonic
            if m in _TERMINATORS or m == "jmp" or m.startswith("j") or m == "call":
                break
        return out

    # ---------------------------------------------------------- x86 分析

    def _analyze_x86(self, rva: int, f: FunctionFacts):
        insns = self._collect(rva)
        if not insns:
            f.evidence.append("no decodable instructions at body")
            return None, None, "unknown"

        # 尾调用垫片检测：块以 jmp reg 结束（参数转发给运行时目标，不可观测）
        for insn in insns:
            if insn.mnemonic == "jmp" and insn.operands \
                    and insn.operands[0].type == X86_OP_REG:
                f.tail_forwarder = True
                break

        # ret imm 统计
        ret_imms: set[int] = set()
        has_bare = False
        for insn in insns:
            if insn.mnemonic == "ret":
                if insn.op_str:
                    try:
                        ret_imms.add(int(insn.op_str, 16))
                    except ValueError:
                        has_bare = True
                else:
                    has_bare = True
        f.ret_imms = sorted(ret_imms)

        # ECX/EDX 首读未写
        first_use = self._first_register_use(insns)
        ecx_read = first_use.get("ecx") == "read"
        edx_read = first_use.get("edx") == "read"

        # [ebp+8+4k] 引用
        ebp_params = self._x86_ebp_params(insns)
        # [esp+4+4k] 引用（无帧指针的叶子函数）
        esp_params = self._x86_esp_params(rva, insns)
        frame_params = None
        for cand in (ebp_params, esp_params):
            if cand is not None:
                frame_params = cand if frame_params is None else max(frame_params, cand)

        conv = params = None
        kind = "unknown"

        if len(ret_imms) == 1:
            n = next(iter(ret_imms))
            f.stack_param_bytes = n
            if has_bare:
                f.evidence.append(
                    "NOTE: mixed 'ret imm' + bare 'ret' — trusting 'ret imm' path")
            if ecx_read or edx_read:
                conv = "__fastcall"
                f.register_params = 2 if edx_read else 1
                params = f.register_params + n // 4
                kind = "exact"
                f.evidence.append(
                    f"ret 0x{n:X}; ECX/EDX first-read => __fastcall: "
                    f"{f.register_params} reg + {n // 4} stack param(s)")
            elif n > 0:
                conv = "__stdcall"
                params = n // 4
                kind = "exact"
                f.evidence.append(
                    f"uniform ret 0x{n:X} => __stdcall with {n // 4} stack param(s)")
            else:
                conv = "__cdecl"
                f.evidence.append(
                    "ret 0 with no ECX/EDX use => __cdecl (ABI-equal to stdcall(void))")
        elif len(ret_imms) > 1:
            # 多个不同的 ret imm：尾调用/变参/不可靠 —— 按最小值猜测
            n = min(ret_imms)
            f.stack_param_bytes = None
            conv = "__stdcall"
            params = n // 4
            kind = "guess"
            f.evidence.append(
                f"mixed ret immediates {[hex(x) for x in sorted(ret_imms)]}; "
                f"guessing __stdcall {n // 4} stack param(s) (tail-call or varargs possible)")
        else:
            # 仅裸 ret（C3）
            if ecx_read or edx_read:
                conv = "__fastcall"
                f.register_params = 2 if edx_read else 1
                params = f.register_params
                kind = "min"
                f.evidence.append(
                    f"bare ret + ECX/EDX first-read => __fastcall with "
                    f"{f.register_params} register arg(s), no stack args")
            else:
                conv = "__cdecl" if has_bare else None
                if has_bare:
                    f.evidence.append(
                        "bare ret(s) only => __cdecl (caller cleans stack)")

        # cdecl/fastcall 下用帧引用补参数个数
        if params is None and frame_params is not None:
            if conv == "__fastcall":
                params = f.register_params + frame_params
                kind = "min"
            else:
                params = frame_params
                kind = "min"
            f.evidence.append(
                f"frame references ([ebp+8]/[esp+4]) => {frame_params} dword slot(s) "
                f"(8-byte args count as 2 slots; slot count is ABI stack-exact)")
        elif params is not None and frame_params is not None and conv == "__fastcall":
            if frame_params > 0:
                f.evidence.append(
                    f"frame references ({frame_params}) beyond reg args")

        # cdecl + 无任何参数引用 => 收敛到 0 参数
        if params is None and conv == "__cdecl" and has_bare:
            params = 0
            kind = "min"
            if f.tail_forwarder:
                f.evidence.append(
                    "no param references observable; body tail-jumps via register "
                    "(lazy forwarder) — arg count forwarded to runtime target, "
                    "assuming 0")
            else:
                f.evidence.append(
                    "no param references found => 0 param(s) (cdecl, caller-cleaned)")

        return conv, params, kind

    @staticmethod
    def _is_zeroing_or_nop(insn) -> bool:
        """清零/空操作习语：寄存器的'读'不代表参数引用。

        - xor/sub reg, reg     : 清零（读的是自身，语义上是纯写）
        - lea reg, [reg]       : 2 字节 NOP
        - mov reg, reg         : 3 字节 NOP
        """
        m = insn.mnemonic
        ops = insn.operands
        if m in ("xor", "sub") and len(ops) == 2:
            return (ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG
                    and ops[0].reg == ops[1].reg)
        if m == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_MEM:
            mem = ops[1].mem
            return (mem.base == ops[0].reg and mem.index == 0
                    and mem.scale == 1 and mem.disp == 0)
        if m == "mov" and len(ops) == 2:
            return (ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG
                    and ops[0].reg == ops[1].reg)
        return False

    def _push_is_param_read(self, insns, i: int) -> bool:
        """push ecx/edx 是参数传递还是局部变量分配？

        MSVC 用 'push ecx' 代替 'sub esp,4' 分配 dword 局部空间 —— 这种 push
        不构成对传入 ECX 值的语义读。判据（x86）：
          - push edx：作局部分配极罕见，算参数读
          - push ecx：同基本块内
              * 后续写入刚压栈槽位（[ebp-4*depth] / [esp]）=> 局部分配
              * 仅隔 push 序列后紧跟 call/jmp（尾调用）=> 参数序列
              * 其余按局部分配处理
        x64 无此分配习语，一律算参数读。
        """
        insn = insns[i]
        fam = self._fam.get(insn.operands[0].reg)
        if self.pe.bits == 64 or fam == "edx":
            return True
        depth = 1
        j = i + 1
        steps = 0
        while j < len(insns) and steps < 3:
            nxt = insns[j]
            m = nxt.mnemonic
            # 写入刚压栈的槽位 => 局部变量初始化
            for op in nxt.operands:
                if op.type == X86_OP_MEM and op.access & CS_AC_WRITE:
                    mem = op.mem
                    if mem.base == X86_REG_EBP and mem.disp == -4 * depth:
                        return False
                    if mem.base == X86_REG_ESP and mem.disp == 4 * (depth - 1):
                        return False
            if m == "call" or m == "jmp":
                return True
            if m == "pop" or m == "leave" or m in _TERMINATORS or m.startswith("j"):
                return False
            if m == "push":
                depth += 1
                j += 1
                steps += 1
                continue
            return False  # 其它指令打断参数序列 => 按局部分配
        return False

    def _first_register_use(self, insns) -> dict[str, str]:
        """ECX/ED(x86) 或 RCX/RDX/R8/R9(x64) 的第一条触碰是读还是写。"""
        fams = self._fam
        defined: set = set()
        first: dict = {}
        for idx, insn in enumerate(insns):
            if insn.mnemonic == "call":
                if self.pe.bits == 32:
                    defined |= {"ecx", "edx"}
                else:
                    defined |= {0, 1, 2, 3}
                continue
            reads, writes = insn.regs_access()
            if self._is_zeroing_or_nop(insn):
                reads = []  # 清零/NOP 的读不构成参数引用
            if (insn.mnemonic == "push" and insn.operands
                    and insn.operands[0].type == X86_OP_REG
                    and not self._push_is_param_read(insns, idx)):
                reads = [r for r in reads
                         if fams.get(r) != self._fam.get(insn.operands[0].reg)]
            for r in reads:
                fam = fams.get(r)
                if fam is not None and fam not in defined and fam not in first:
                    first[fam] = "read"
            for r in writes:
                fam = fams.get(r)
                if fam is not None and fam not in defined and fam not in first:
                    first[fam] = "write"
                    defined.add(fam)
        return first

    def _x86_ebp_params(self, insns) -> int | None:
        max_disp = None
        for insn in insns:
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_EBP:
                    disp = op.mem.disp
                    if disp >= 8 and (op.access & CS_AC_READ):
                        if max_disp is None or disp > max_disp:
                            max_disp = disp
        if max_disp is None:
            return None
        return (max_disp - 8) // 4 + 1

    def _x86_esp_params(self, start_rva: int, insns) -> int | None:
        """入口块内 [esp+4+4k] 读引用（无 ebp 帧的叶子函数）。

        只扫描到第一条 call / 控制转移为止——call 之后 esp 语义受被调方
        清栈行为影响，引用不再可信。push/pop/sub/add 的 esp 增量已折算。
        """
        delta = 0
        max_eff = None
        for insn in insns:
            m = insn.mnemonic
            ops = insn.operands
            if m == "call":
                break
            for op in ops:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP:
                    if op.access & CS_AC_READ:
                        eff = op.mem.disp + delta
                        if eff >= 4:
                            if max_eff is None or eff > max_eff:
                                max_eff = eff
            if m == "push":
                delta -= 4
            elif m == "pop":
                delta += 4
            elif m in ("sub", "add") and len(ops) == 2 \
                    and ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_ESP \
                    and ops[1].type == X86_OP_IMM:
                delta += ops[1].imm if m == "add" else -ops[1].imm
            elif m in _TERMINATORS or m == "jmp" or m.startswith("j"):
                break
        if max_eff is None:
            return None
        return (max_eff - 4) // 4 + 1

    # ---------------------------------------------------------- x64 分析

    def _analyze_x64(self, rva: int, f: FunctionFacts):
        insns = self._collect(rva)
        if not insns:
            f.evidence.append("no decodable instructions at body")
            return "x64", None, "unknown"

        first_use = self._first_register_use(insns)
        used_regs = {k for k, v in first_use.items() if v == "read"}

        # 影子空间保存
        shadow = set()
        for insn in insns:
            ops = insn.operands
            if insn.mnemonic in ("mov",) and len(ops) == 2 and ops[0].type == X86_OP_MEM:
                mem = ops[0].mem
                if mem.base in (X86_REG_RSP, X86_REG_ESP) and 8 <= mem.disp <= 0x20:
                    if ops[1].type == X86_OP_REG:
                        fam = self._fam.get(ops[1].reg)
                        if fam is not None:
                            shadow.add(fam)
        used_regs |= shadow
        if shadow:
            names = ", ".join(_X64_FAM_NAME[i] for i in sorted(shadow))
            f.evidence.append(f"shadow-space spill: {names} => 4 leading args confirmed")

        # 入口块栈参数（第 5+ 个）
        stack_extra = self._x64_stack_params(rva)
        if stack_extra:
            f.evidence.append(
                f"entry-block [rsp+0x28+8k] reads => at least {stack_extra} stack arg(s) beyond 4")

        params = None
        kind = "unknown"
        if used_regs:
            top = max(used_regs)
            params = top + 1
            kind = "min"
            names = ", ".join(_X64_FAM_NAME[i] for i in sorted(used_regs))
            f.evidence.append(f"register args first-read: {names} => at least {top + 1} arg(s)")
        if stack_extra:
            params = max(params or 0, 4) + stack_extra
            kind = "min"
        return "x64", params, kind

    def _x64_stack_params(self, start_rva: int) -> int:
        """入口线性块内 [rsp+0x28+8k] 读引用 => 第 5+ 参数计数。"""
        delta = 0
        max_entry_disp = None
        for insn in self._linear_scan(start_rva):
            # 先按当前 rsp 相对位置解释引用，再更新 delta
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base in (X86_REG_RSP, X86_REG_ESP):
                    if op.access & CS_AC_READ:
                        eff = op.mem.disp + delta
                        if eff >= 0x28:
                            if max_entry_disp is None or eff > max_entry_disp:
                                max_entry_disp = eff
            m = insn.mnemonic
            ops = insn.operands
            touches_rsp = (len(ops) >= 1 and ops[0].type == X86_OP_REG
                           and ops[0].reg in (X86_REG_RSP, X86_REG_ESP))
            if m == "push":
                delta -= 8
            elif m == "pop":
                delta += 8
            elif m == "sub" and len(ops) == 2 and touches_rsp \
                    and ops[1].type == X86_OP_IMM:
                delta -= ops[1].imm
            elif m == "add" and len(ops) == 2 and touches_rsp \
                    and ops[1].type == X86_OP_IMM:
                delta += ops[1].imm
        if max_entry_disp is None:
            return 0
        return (max_entry_disp - 0x28) // 8 + 1
