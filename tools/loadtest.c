/* loadtest.c — 最小加载验证器（验证 fakedll 生成的桩 DLL 能否被系统加载）
 *
 * 本机 Python 解释器通常只有一种位数，无法加载另一种位数的 DLL
 * （64 位进程加载 32 位 DLL 会报 WinError 193）。此时用本工具编译出对应
 * 位数的加载器来验证：
 *
 *   MSVC x86 : cl /nologo /utf-8 loadtest.c              -> 32 位加载器
 *   MSVC x64 : cl /nologo /utf-8 /DSIXTYFOUR loadtest.c  -> 64 位加载器
 *   MinGW    : gcc -o loadtest.exe loadtest.c
 *
 * 用法:
 *   loadtest <dll> [func1 func2 ...]
 * 不给函数名时只做 LoadLibrary / FreeLibrary 往返。
 */
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    HMODULE h;
    int i, miss = 0;

    if (argc < 2) {
        printf("usage: loadtest <dll> [func ...]\n");
        return 2;
    }

    h = LoadLibraryA(argv[1]);
    if (!h) {
        printf("[FAIL] LoadLibrary error %lu\n", GetLastError());
        return 1;
    }
    printf("[OK] LoadLibrary -> hModule = %p  (%s)\n",
           (void *)h, sizeof(void *) == 8 ? "64-bit loader" : "32-bit loader");

    for (i = 2; i < argc; i++) {
        FARPROC p = GetProcAddress(h, argv[i]);
        if (!p) miss++;
        printf("  GetProcAddress(%-40s) = %p %s\n",
               argv[i], (void *)p, p ? "" : "<MISSING>");
    }

    FreeLibrary(h);
    printf("[OK] FreeLibrary done%s\n", miss ? " (有缺失导出)" : "");
    return miss ? 1 : 0;
}
