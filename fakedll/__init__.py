"""fakedll — PE 导出函数分析 + 头文件生成工具套件。

分析一个 DLL/EXE 的导出函数（调用约定、参数个数），生成与之匹配的 .h 文件，
支持 32/64 位，支持自定义渲染逻辑。

子模块：
    pe        — PE32/PE32+ 零依赖解析（导出表 + 导入表）
    demangle  — MSVC 修饰名反修饰（dbghelp）+ C 修饰名解析
    analyze   — capstone 字节码分析：调用约定 / 参数推断
    render    — .h / .def / stub 渲染 + 自定义渲染器
    cli       — 命令行入口
"""

__version__ = "1.0.0"
