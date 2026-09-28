# FakeDLL — DLL/EXE 导出函数分析与 .h 生成工具套件

分析任意 PE 文件（DLL/EXE，32 位与 64 位）的导出函数，推断每个导出的**调用约定**与**参数个数**，
生成与原模块一致的 C/C++ 头文件（`.h`）、模块定义文件（`.def`）、可编译的 Fake DLL 桩（`.c` + `.def`）
以及 JSON 分析报告。生成 `.h` 的逻辑可完全自定义（可插拔渲染器脚本）。

典型用途：写兼容层 / 代理 DLL / 存根时，快速拿到目标模块的完整导出面（export surface），
不必逐个手写函数原型。

## 依赖与安装

- Python 3.10+（仅在 3.13 上测试）
- [Capstone](https://www.capstone-engine.org/) 5.x（字节码反汇编）
- MSVC `dbghelp.dll`（Windows 自带，用于反修饰 MSVC C++ 修饰名；可选，仅影响 `?` 开头导出的精度）

```bash
pip install capstone
```

其余 PE 解析、导入表分析、渲染全部零第三方依赖。

## 快速上手

```bash
# 【推荐】一键生成 DLL：自动探测工具链 -> 生成桩 -> 编译 -> 校验导出表
python fakedll.py build "C:\path\to\target.dll" -o out/fake_target.dll

# 一键生成全部文本产物到 out/（.h / .def / stub .c+def / report.json）
python fakedll.py all "C:\path\to\target.dll" -o out/

# 只生成头文件
python fakedll.py header "target.dll" -o out/target.h

# 只生成与原 DLL 导出表一致的 .def（转发导出复刻为转发语法）
python fakedll.py def "target.dll" -o out/target.def

# 只生成桩源码（.c + 配套 .def），编译与否自行决定
python fakedll.py stub "target.dll" -o out/fake_target.c

# 分析并打印 JSON 报告（默认只打印未能解析参数的函数）
python fakedll.py analyze "target.dll" -o out/report.json -v

# 使用自定义渲染器生成头文件
python fakedll.py header "target.dll" -o out/my.h --renderer renderers/getproc_thunk.py
```

> **注意**：`build` 之外的子命令只产出**文本**（.h / .def / .c）。
> 想拿到可加载的 `.dll` 文件，请用 `build`（自带编译），或自行编译生成的
> `fake_*.c` + `fake_*.def`。也要注意 `stub` 的 `-o` 是 **.c 文件路径**，不是目录。

### 完整生成流程（端到端）

```bash
# 1) 分析：解析 PE 导出表 + 反汇编推断调用约定/参数，落盘 JSON 报告
python fakedll.py analyze "target.dll" -o out/target.report.json

# 2) 生成文本产物：头文件、.def、桩源码（.c + .def）
python fakedll.py all "target.dll" -o out/

# 3) 编译成真实 DLL（自动探测 MSVC / MinGW，自动校验导出表，位数匹配时还会加载验证）
python fakedll.py build "target.dll" -o out/fake_target.dll
```

`build` 一步等效于「`stub` 生成源码 → 调用编译器 → 对比导出表 → 尝试加载」，
并把源码放在临时目录、只把最终 DLL 交付到你指定的路径（需要保留源码时加
`--keep-sources out/`）。

### 常用选项

| 选项 | 适用 | 说明 |
|---|---|---|
| `--arg-style ptr\|int\|none` | 全部 | 未知参数的占位风格，默认 `ptr`（`void* p1, void* p2`） |
| `--no-evidence` | 全部 | 头文件中不输出逐函数的推断证据注释 |
| `--max-insn N` | 全部 | 每函数最多反汇编的指令数（默认 1200） |
| `--jump-hops N` | 全部 | 垫片（jmp/push-ret）跟随的最大跳数（默认 8） |
| `--set k=v` | 全部 | 传给渲染器的自定义选项，可重复 |
| `--renderer PY` | `header` | 自定义渲染脚本 |
| `--toolchain auto\|msvc\|gcc` | `build` | 指定编译器，默认自动探测（MSVC 优先） |
| `--keep-sources DIR` | `build` | 保留生成的 .c/.def |
| `-v` | `analyze`/`build` | 详细输出（build 会额外打印编译器日志） |
| `-o` | 全部 | 输出路径（`all` 为输出目录） |

### 编译工具链要求

`build` 会自动探测：

1. **MSVC**（优先）—— 在 `%ProgramFiles%\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\{x86,x64}\cl.exe`
   中取版本最高者，自动定位 Windows SDK 的 `Include` / `Lib`。
   环境变量（`INCLUDE`/`LIB`/`PATH`）由工具**自行拼装**，不调用 `vcvars*.bat`
   —— 后者依赖 `reg.exe` 查询注册表，在受限环境下会失败（典型症状：
   `无法打开包括文件: windows.h`）。同时设置 `VSLANG=1033` 让编译诊断输出英文，
   避免中文消息经管道传输时乱码。
2. **MinGW gcc**（回落）—— `gcc -shared`。注意：32 位目标需要
   `i686-w64-mingw32-gcc` 或带 multilib 的 gcc；仅有 x64 MinGW 时无法编译 32 位。

| 目标位数 | 可用工具链 |
|---|---|
| 32 位 (x86) | MSVC 任意版本（`Hostx64\x86`）、i686 MinGW |
| 64 位 (x64) | MSVC（`Hostx64\x64`）、x86_64 MinGW |

编译出的 DLL 默认命名 `fake_<原名>.dll`。要直接替换原模块，改成原名即可
（例如 `fake_steam_api.dll` → `steam_api.dll`）。


## 输出物说明

| 产物 | 内容 |
|---|---|
| `target.h` | 每个导出一个声明；带 `__declspec(dllimport)`、推断的调用约定、占位参数、证据注释 |
| `target.def` | 与原 DLL 导出表**一致**的模块定义；序号导出、无名导出、转发导出（`name = other.Func`）均如实复刻 |
| `fake_target.c` + `fake_target.def` | 可直接编译成替换 DLL 的桩实现；所有函数返回 0/NULL；`fake_` 前缀内部符号经 `.def` 映射回原名导出 |
| `fake_target.dll` | （`build` 子命令）编译好的真实 DLL，导出表与原模块逐项一致，可直接被 `LoadLibrary` 加载 |
| `target.report.json` | 全部分析结果的机器可读版本 |

用 MSVC / gcc 手工编译桩（不想用 `build` 时）：

```bat
:: MSVC（需已初始化的 VS 环境）
cl /nologo /utf-8 /LD fake_target.c /link /def:fake_target.def
```

```bash
# MinGW
gcc -shared -o fake_target.dll fake_target.c fake_target.def
```

> `/utf-8` 不能省：生成的源码含中文注释，MSVC 默认按本地代码页（CP936）读取会报 C4819。

### 验证生成的 DLL

- **导出表**：`build` 会自动对比原模块与生成模块的导出表（总数/序号/名字/架构）并打印结论。
- **可加载性**：位数与当前 Python 一致时，`build` 会实际 `LoadLibrary` 并抽查导出；
  位数不一致时（例如 64 位 Python 验 32 位 DLL）需要用对应位数的加载器，
  仓库提供 [`tools/loadtest.c`](tools/loadtest.c)：

```bash
# 编译 32 位加载器（MSVC）
cl /nologo /utf-8 tools\loadtest.c
# 用法：loadtest <dll> [func1 func2 ...]
loadtest out\fake_steam_api.dll SteamAPI_Init SteamAPI_RunCallbacks
```

> 64 位进程加载 32 位 DLL 会报 `WinError 193`（不是有效的 Win32 应用程序），
> 这是位数不匹配而非 DLL 损坏。

## 调用约定与参数是怎么推断的

按可靠性从高到低，逐级回退：

1. **MSVC C++ 修饰名**（`?xxx@@...`）—— 经 `dbghelp.UnDecorateSymbolName` 反修饰得到完整签名
   （返回类型、调用约定、精确参数个数与类型），直接复刻为 C++ 声明。`param_kind: signature`。
2. **x86 C 修饰名**（`_name@N` → `__stdcall`、`@name@N` → `__fastcall`，字节数 N 直接给出栈参数量）。
3. **函数字节码分析**（Capstone 反汇编导出 RVA 处的代码）：
   - **x86**
     - `ret imm16` 的立即数 → stdcall/fastcall 的精确栈参数字节数（`param_kind: exact`）；
     - 入口对 ECX/EDX 的"先读后写" → `__fastcall`（排除清零习语 `xor ecx,ecx` 等）；
     - 帧引用 `[ebp+8+4k]` / `[esp+4+4k]` 的最高 k → cdecl 参数槽位下界；
     - `push ecx` 若紧跟对刚压栈槽位的写入 → 识别为局部分配习语（MSVC 常用来替代 `sub esp,4`），不算参数；
     - 纯 cdecl 且无任何参数引用 → 收敛为 0 参数（调用方清栈，安全）。
   - **x64**（统一调用约定）
     - 影子空间保存 `mov [rsp+8..0x20], reg` / RCX..R9 首读未写 → 前四个参数；
     - 入口块 `[rsp+0x28+8k]` 读引用 → 第 5+ 个参数。
   - **垫片跟随**：`jmp rel32`、`push imm32; ret`、`mov rax,[rip+X]; jmp rax` 逐跳跟随到真实函数体；
     `jmp [IAT]` 识别为**导入转发**（转发到 api-ms-* API set 或其它 DLL，含延迟导入 `.didat`）。
   - **数据导出**：导出 RVA 落在非可执行节（`.data`/`.rdata`）→ 判定为变量而非函数，
     生成 `extern` 变量声明 + `.def` 的 `DATA` 行。

### 参数计数的语义（重要）

x86 帧引用推断给出的是 **dword 槽位数**，不是逻辑参数个数：一个 8 字节参数（如
`SteamAPICall_t`、`LARGE_INTEGER`、双精度浮点）在 32 位栈上占 **2 个槽**。
`SteamAPI_UnregisterCallResult`（2 个逻辑参数，其一为 uint64）报 3 槽就是因此——
槽位计数对 ABI 栈布局是精确的，手写原型时请自行合并。

## 精度与局限

- 参数**类型**不做推断（除 C++ 修饰名直通外），未知类型以 `void*` 占位；
  返回类型同理固定为 `void*`。意图是"贴近可链接"，不是"还原源码级原型"。
- 无名（仅序号）导出在 `.h` 中以 `ordinal_N` 命名。
- 转发导出（forwarder）在 `.h` 中声明为普通导入；`.def` 中如实复刻转发语法。
- 虚函数/成员函数导出（`__thiscall`）无法生成 C 声明，以注释形式给出 undname 签名。
- 高度混淆/VMProtect 保护的模块，字节码分析可能给出 `unknown`——此时诚实输出 `param_count: null`。
- `min`（下界）与 `guess`（猜测）标记的计数请人工核对。

### 实测校验过的目标

| 模块 | 位数 | 结果 |
|---|---|---|
| `steam_api.dll`（The Nine Regions） | x86 | 996 导出：995 `__cdecl` + 1 数据导出，全对 |
| `gdi32.dll` | x86 | BitBlt=9、TextOutA=5、Rectangle=5 等 `exact`；private fastcall API 正确识别 |
| `xlua.dll` | x86 | lua_newstate=2、lua_pushcclosure=3 等全对 |
| `version.dll` | x64 | IAT 转发识别（api-ms-win-core-*） |
| `msvcp140.dll` | x64/x86 | C++ 修饰名直通；`??_7` vtable 数据导出正确落 `.rdata` |

`build` 端到端结果：

| 目标 | 位数 | 生成 DLL | 导出表 | 加载验证 |
|---|---|---|---|---|
| `steam_api.dll` | x86 (i386) | 153,600 B | 996 / 996 逐项一致（含 @996 `DATA`） | 32 位加载器：LoadLibrary + 5 个导出解析 + 真实调用返回 NULL 不崩溃 |
| `version.dll` | x64 (AMD64) | 103,936 B | 17 / 17 一致（2 个转发导出转为占位） | 64 位进程 `LoadLibrary` + 5/5 导出解析 + 调用返回 0 |

## 自定义渲染器

`.h` 的生成逻辑完全可插拔。写一个 Python 文件，定义 `render(ctx) -> str`，返回值即整个输出文件：

```python
# renderers/my_renderer.py
def render(ctx) -> str:
    # 可用信息：
    #   ctx.dll_name / ctx.dll_path / ctx.bits / ctx.machine / ctx.image_base
    #   ctx.functions          -> list[FunctionFacts]（见 fakedll/analyze.py）
    #   ctx.options            -> dict（CLI --set k=v 传入）
    #   ctx.helper.param_list(f)     -> "void* p1, void* p2"
    #   ctx.helper.cc_keyword(f)      -> "__stdcall " / "" (x64)
    #   ctx.helper.c_safe_name(name)  -> C 安全标识符
    #   ctx.stats()                   -> 统计 dict
    L = []
    for f in ctx.functions:
        L.append(f"// {f.export.name}: {f.convention}, {f.param_count}")
    return "\n".join(L)
```

```bash
python fakedll.py header target.dll -o out/my.h --renderer renderers/my_renderer.py --set key=value
```

仓库内置一个完整示例 [`renderers/getproc_thunk.py`](renderers/getproc_thunk.py)：
生成 GetProcAddress 风格的运行时 thunk 表头文件（typedef 函数指针类型 + extern 槽位 +
`dll_init_thunks(HMODULE)` 初始化函数），适合不愿静态链接、运行时手动解析导出的场景。

`FunctionFacts` 关键字段：`export.name/ordinal/rva/forwarder`、`clean_name`、`is_data`、
`convention`（`__cdecl/__stdcall/__fastcall/x64`）、`convention_source`（`mangled/bytecode`）、
`param_count`（可能为 `None`）、`param_kind`（`exact/signature/min/guess/unknown`）、
`import_thunk`、`evidence`（人类可读的推断依据列表）。

## 目录结构

```
FakeDLL/
├── fakedll.py            # CLI 入口
├── fakedll/
│   ├── pe.py             # 零依赖 PE32/PE32+ 解析（节表、导出、导入 + 延迟导入）
│   ├── analyze.py        # Capstone 字节码分析（调用约定/参数推断）
│   ├── demangle.py       # dbghelp 反修饰 + x86 C 修饰名解析
│   ├── render.py         # 内置渲染器 + 自定义渲染器加载器
│   ├── build.py          # 工具链探测 + 编译 + 导出表校验/加载验证
│   └── cli.py            # argparse 子命令
├── renderers/
│   └── getproc_thunk.py  # 自定义渲染器示例
├── tools/
│   └── loadtest.c        # 对应位数的加载验证器（32/64 位均可编）
└── out/                  # 生成产物
```

## 已知问题

- MinGW gcc 编译 32 位目标需要 i686 工具链或 multilib 支持；仅有 x64 MinGW 时会
  提示改用 MSVC。
- `build` 的加载验证只在「解释器位数 == 目标位数」时执行，另一种位数请用
  `tools/loadtest.c` 编出对应位数的加载器。
- 转发导出（forwarder）在桩中被实现为返回 0 的占位函数，原样转发请改用
  `fakedll.py def` 产出的 `.def`（其中 `name = other.Func` 语法会保留转发行为）。
