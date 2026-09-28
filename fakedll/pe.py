"""最小 PE 解析器（零第三方依赖）。

仅覆盖导出函数分析所需的能力：
  - PE32 (i386) / PE32+ (AMD64) 头解析：机器类型、位数、ImageBase、数据目录
  - 节表：RVA <-> 文件偏移
  - 导出表：具名导出、无名(仅序号)导出、转发器(Forwarder)导出
  - 导入表：IAT 槽位 -> "Dll.Func" 映射（用于识别 jmp [IAT] 转发垫片）
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

IMAGE_DOS_SIGNATURE = 0x5A4D          # 'MZ'
IMAGE_NT_SIGNATURE = 0x00004550      # 'PE\0\0'
OPT_MAGIC_PE32 = 0x10B               # 32 位
OPT_MAGIC_PE32P = 0x20B              # 64 位 (PE32+)

MACHINE_NAMES = {
    0x014C: "i386",
    0x8664: "AMD64",
    0x01C4: "ARMNT",
    0xAA64: "ARM64",
    0x0200: "IA64",
}

# 数据目录索引
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_DELAY_IMPORT = 13

# 延迟导入描述符属性：1 = 字段为 RVA
DLATTR_RVA = 1


IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


@dataclass
class Section:
    name: str
    va: int           # VirtualAddress
    vsize: int        # VirtualSize
    raw_ptr: int      # PointerToRawData
    raw_size: int     # SizeOfRawData
    chars: int = 0    # Characteristics

    @property
    def executable(self) -> bool:
        return bool(self.chars & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))

    @property
    def writable(self) -> bool:
        return bool(self.chars & IMAGE_SCN_MEM_WRITE)


@dataclass
class ExportFunc:
    """一个导出项。name 为 None 表示仅按序号导出的无名项。"""
    name: str | None          # 导出名（原样，可能带修饰）
    ordinal: int              # 导出序号（含 Base）
    rva: int                  # 函数 RVA；转发器时指向转发字符串
    forwarder: str | None     # 形如 "OtherDll.Func" 的转发目标
    hint: int | None = None   # 具名导出的 hint


@dataclass
class ImportEntry:
    dll: str                 # 导入所在 DLL（小写）
    name: str                # 函数名，或 "#12"（按序号导入）


class PEFormatError(ValueError):
    pass


class PEFile:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.sections: list[Section] = []
        self._exports: list[ExportFunc] | None = None
        self._iat_map: dict[int, ImportEntry] | None = None
        self._parse_headers()

    # ---------------- 头部 ----------------

    def _parse_headers(self) -> None:
        d = self.data
        if len(d) < 0x40:
            raise PEFormatError("file too small")
        if struct.unpack_from("<H", d, 0)[0] != IMAGE_DOS_SIGNATURE:
            raise PEFormatError("missing MZ signature")

        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if e_lfanew + 24 > len(d):
            raise PEFormatError("bad e_lfanew")
        if struct.unpack_from("<I", d, e_lfanew)[0] != IMAGE_NT_SIGNATURE:
            raise PEFormatError("missing PE\\0\\0 signature")

        fh = e_lfanew + 4
        (self.machine, num_sections, _ts, _ptr_sym, _num_sym,
         opt_size, _chars) = struct.unpack_from("<HHIIIHH", d, fh)
        self.machine_name = MACHINE_NAMES.get(self.machine, f"0x{self.machine:04X}")

        opt = fh + 20
        if opt + 2 > len(d):
            raise PEFormatError("truncated optional header")
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic == OPT_MAGIC_PE32:
            self.bits = 32
            self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
            num_dirs_off = opt + 92
        elif magic == OPT_MAGIC_PE32P:
            self.bits = 64
            self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
            num_dirs_off = opt + 108
        else:
            raise PEFormatError(f"unknown optional header magic 0x{magic:X}")

        self.timestamp = struct.unpack_from("<I", d, fh + 4)[0]
        num_dirs = struct.unpack_from("<I", d, num_dirs_off)[0]
        dd_off = num_dirs_off + 4
        self.data_dirs: list[tuple[int, int]] = []
        for i in range(num_dirs):
            rva, size = struct.unpack_from("<II", d, dd_off + 8 * i)
            self.data_dirs.append((rva, size))

        # 节表
        sec_off = opt + opt_size
        for i in range(num_sections):
            base = sec_off + 40 * i
            raw_name = d[base:base + 8]
            name = raw_name.rstrip(b"\x00").decode("ascii", "replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", d, base + 8)
            chars = struct.unpack_from("<I", d, base + 36)[0]
            self.sections.append(Section(name, va, vsize, raw_ptr, raw_size, chars))

    # ---------------- RVA / 文件偏移 ----------------

    def rva_to_offset(self, rva: int) -> int | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                delta = rva - s.va
                if delta >= s.raw_size:
                    return None  # 位于仅虚拟区（BSS 等）
                return s.raw_ptr + delta
        return None

    def section_of_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s
        return None

    def is_code_rva(self, rva: int) -> bool:
        s = self.section_of_rva(rva)
        return s is not None and s.executable

    def read_rva(self, rva: int, size: int) -> bytes | None:
        off = self.rva_to_offset(rva)
        if off is None:
            return None
        return self.data[off:off + size]

    def read_cstr_rva(self, rva: int, max_len: int = 4096) -> str | None:
        off = self.rva_to_offset(rva)
        if off is None:
            return None
        end = self.data.find(b"\x00", off, min(off + max_len, len(self.data)))
        if end < 0:
            end = min(off + max_len, len(self.data))
        return self.data[off:end].decode("utf-8", "replace")

    # ---------------- 导出表 ----------------

    @property
    def has_exports(self) -> bool:
        return bool(self.data_dirs) and self.data_dirs[DIR_EXPORT][0] != 0

    def export_dll_name(self) -> str | None:
        """导出表里记录的模块内部名。"""
        rva, size = self.data_dirs[DIR_EXPORT]
        if not rva:
            return None
        off = self.rva_to_offset(rva)
        if off is None:
            return None
        name_rva = struct.unpack_from("<I", self.data, off + 12)[0]
        return self.read_cstr_rva(name_rva) if name_rva else None

    def exports(self) -> list[ExportFunc]:
        if self._exports is not None:
            return self._exports
        self._exports = []
        if not self.has_exports:
            return self._exports

        exp_rva, exp_size = self.data_dirs[DIR_EXPORT]
        exp_off = self.rva_to_offset(exp_rva)
        if exp_off is None:
            raise PEFormatError("export directory RVA not mapped to file")

        (_chars, _ts, _majv, _minv, name_rva, base, num_funcs,
         num_names, addr_funcs, addr_names, addr_ords) = struct.unpack_from(
            "<IIHHIIIIIII", self.data, exp_off)

        fwd_lo, fwd_hi = exp_rva, exp_rva + max(exp_size, 1)

        def read_forwarder(func_rva: int) -> str | None:
            """函数 RVA 落在导出目录范围内 => 是转发器字符串。"""
            if fwd_lo <= func_rva < fwd_hi:
                return self.read_cstr_rva(func_rva)
            return None

        funcs: dict[int, int] = {}     # index -> rva
        for i in range(num_funcs):
            off = self.rva_to_offset(addr_funcs)
            if off is None:
                break
            (frva,) = struct.unpack_from("<I", self.data, off + 4 * i)
            if frva:
                funcs[i] = frva

        by_index: dict[int, ExportFunc] = {}
        if num_names:
            names_off = self.rva_to_offset(addr_names)
            ords_off = self.rva_to_offset(addr_ords)
            if names_off is None or ords_off is None:
                raise PEFormatError("export name arrays not mapped")
            for i in range(num_names):
                (n_rva,) = struct.unpack_from("<I", self.data, names_off + 4 * i)
                (idx,) = struct.unpack_from("<H", self.data, ords_off + 2 * i)
                name = self.read_cstr_rva(n_rva) or ""
                frva = funcs.get(idx)
                if frva is None:
                    continue
                hint = self.data[n_rva - 2:n_rva] if n_rva >= 2 else b"\x00\x00"
                by_index[idx] = ExportFunc(
                    name=name,
                    ordinal=base + idx,
                    rva=frva,
                    forwarder=read_forwarder(frva),
                    hint=int.from_bytes(hint, "little"),
                )

        # 无名导出（仅序号）
        for idx, frva in funcs.items():
            if idx not in by_index:
                by_index[idx] = ExportFunc(
                    name=None,
                    ordinal=base + idx,
                    rva=frva,
                    forwarder=read_forwarder(frva),
                    hint=None,
                )

        self._exports = [by_index[k] for k in sorted(by_index)]
        return self._exports

    # ---------------- 导入表 ----------------

    def iat_map(self) -> dict[int, ImportEntry]:
        """IAT 槽位 RVA -> ImportEntry 映射（含普通导入与延迟导入）。"""
        if self._iat_map is not None:
            return self._iat_map
        self._iat_map = {}
        if len(self.data_dirs) <= DIR_IMPORT or not self.data_dirs[DIR_IMPORT][0]:
            pass  # 无普通导入表，仍可尝试延迟导入
        else:
            self._parse_import_descriptors(DIR_IMPORT, is_delay=False)
        if len(self.data_dirs) > DIR_DELAY_IMPORT and self.data_dirs[DIR_DELAY_IMPORT][0]:
            self._parse_import_descriptors(DIR_DELAY_IMPORT, is_delay=True)
        return self._iat_map

    def _parse_import_descriptors(self, dir_index: int, is_delay: bool) -> None:
        imp_rva, _ = self.data_dirs[dir_index]
        desc_off = self.rva_to_offset(imp_rva)
        if desc_off is None:
            return

        thunk_size = 4 if self.bits == 32 else 8
        ordinal_flag = 0x80000000 if self.bits == 32 else 0x8000000000000000

        idx = 0
        while True:
            base = desc_off + 20 * idx if not is_delay else desc_off + 32 * idx
            if base + (32 if is_delay else 20) > len(self.data):
                break
            if not is_delay:
                (oft, _ts, _fwd, name_rva, ft) = struct.unpack_from(
                    "<IIIII", self.data, base)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break  # 结束标记
                lookup = oft or ft
            else:
                # IMAGE_DELAYLOAD_DESCRIPTOR:
                # grAttrs, szName, phmod, pIAT, pINT, pBoundIAT, pUnloadIAT, dwStamp
                (attrs, name_rva, _phmod, ft, int_rva,
                 _bound, _unload, _stamp) = struct.unpack_from("<8I", self.data, base)
                if attrs == 0 and name_rva == 0 and ft == 0:
                    break
                if not (attrs & DLATTR_RVA):
                    idx += 1
                    continue
                lookup = int_rva  # 延迟导入的名字在 INT（IAT 初始为 stub 地址）
            dll_name = (self.read_cstr_rva(name_rva) or "?").lower()
            lookup_off = self.rva_to_offset(lookup)
            ft_off = self.rva_to_offset(ft)
            if lookup_off is None or ft_off is None:
                idx += 1
                continue
            i = 0
            while True:
                if lookup_off + thunk_size * i + thunk_size > len(self.data):
                    break
                if thunk_size == 4:
                    (val,) = struct.unpack_from("<I", self.data, lookup_off + 4 * i)
                else:
                    (val,) = struct.unpack_from("<Q", self.data, lookup_off + 8 * i)
                if val == 0:
                    break
                if val & ordinal_flag:
                    entry = ImportEntry(dll_name, f"#{val & 0xFFFF}")
                else:
                    hint_name = self.read_cstr_rva(val + 2)  # 跳过 WORD hint
                    entry = ImportEntry(dll_name, hint_name or f"#rva{val}")
                iat_rva = ft + thunk_size * i
                self._iat_map.setdefault(iat_rva, entry)
                i += 1
            idx += 1
