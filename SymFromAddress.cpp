#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "dbghelp.lib")

FARPROC SymFromProcAddress(LPCSTR moduleName, LPCSTR procName) {
    HANDLE hProcess = GetCurrentProcess();

    // 初始化符号
    if (!SymInitialize(hProcess, NULL, FALSE)) {
        printf("SymInitialize failed: %lu\n", GetLastError());
        return NULL;
    }

    // 加载模块
    HMODULE hModule = LoadLibraryA(moduleName);
    if (hModule == NULL) {
        printf("LoadLibrary failed: %lu\n", GetLastError());
        SymCleanup(hProcess);
        return NULL;
    }

    // 获取模块基地址
    DWORD64 baseAddress = SymLoadModule64(hProcess, NULL, moduleName, NULL, (DWORD64)hModule, 0);
    if (baseAddress == 0) {
        printf("SymLoadModule64 failed: %lu\n", GetLastError());
        FreeLibrary(hModule);
        SymCleanup(hProcess);
        return NULL;
    }

    // 分配和初始化 SYMBOL_INFO 结构
    PSYMBOL_INFO symbolInfo = (PSYMBOL_INFO)calloc(1, sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR));
    if (symbolInfo == NULL) {
        printf("Memory allocation failed\n");
        FreeLibrary(hModule);
        SymCleanup(hProcess);
        return NULL;
    }
    symbolInfo->MaxNameLen = MAX_SYM_NAME;
    symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);

    // 获取符号地址
    FARPROC procAddress = NULL;
    if (SymFromName(hProcess, procName, symbolInfo)) {
        procAddress = (FARPROC)(symbolInfo->Address);
        printf("Symbol: %s, Address: 0x%llx\n", symbolInfo->Name, symbolInfo->Address);
    }
    else {
        printf("SymFromName failed: %lu\n", GetLastError());
    }

    // 清理资源
    free(symbolInfo);
    FreeLibrary(hModule);
    SymCleanup(hProcess);

    return procAddress;
}

typedef BOOL(WINAPI* GetUserNameFunc)(
    LPSTR   lpBuffer,
    LPDWORD pcbBuffer
    );

int main() {
    LPCSTR moduleName = "advapi32.dll";
    LPCSTR procName = "GetUserNameA";

    FARPROC procAddress = SymFromProcAddress(moduleName, procName);
    if (procAddress != NULL) {
        printf("Address of %s: 0x%p\n", procName, procAddress);

        // 验证符号地址
        HMODULE hModule = LoadLibraryA(moduleName);
        FARPROC VerifyAddress = GetProcAddress(hModule, procName);
        if (VerifyAddress == procAddress) {
            printf("Verified address of %s: 0x%p\n", procName, VerifyAddress);

            // 调用获取到的函数地址
            GetUserNameFunc GetUserNamePtr = (GetUserNameFunc)procAddress;
            char username[256];
            DWORD size = sizeof(username);
            if (GetUserNamePtr(username, &size)) {
                printf("Current username: %s\n", username);
            }
            else {
                printf("GetUserName failed: %lu\n", GetLastError());
            }
        }
        else {
            printf("Address verification failed for %s\n", procName);
        }
        FreeLibrary(hModule);
    }
    else {
        printf("Failed to get the address of %s\n", procName);
    }

    return 0;
}
