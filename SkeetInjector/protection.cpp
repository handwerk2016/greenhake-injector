#include "protection.h"
#include <iostream>

namespace {
    LPVOID ntOpenFile = nullptr;
}

namespace Protection {
    bool Initialize() {
        HMODULE ntdll = LoadLibraryW(L"ntdll");
        if (!ntdll) {
            std::cerr << "[-] Error: Failed to load ntdll.dll\n";
            return false;
        }
        
        ntOpenFile = GetProcAddress(ntdll, "NtOpenFile");
        if (!ntOpenFile) {
            std::cerr << "[-] Error: Failed to get NtOpenFile address\n";
            return false;
        }
        return true;
    }

    void Bypass(HANDLE hProcess) {
        if (ntOpenFile) {
            char originalBytes[5];
            memcpy(originalBytes, ntOpenFile, 5);
            WriteProcessMemory(hProcess, ntOpenFile, originalBytes, 5, NULL);
            std::cout << "[+] Successfully bypassed process protection\n";
        }
    }

    void Restore(HANDLE hProcess) {
        if (ntOpenFile) {
            char originalBytes[5];
            memcpy(originalBytes, ntOpenFile, 5);
            WriteProcessMemory(hProcess, ntOpenFile, originalBytes, 0, NULL);
            std::cout << "[+] Successfully restored process protection\n";
        }
    }

    bool AllocateMemory(HANDLE hProcess) {
        // Allocate required memory regions for the cheat
        if (!VirtualAllocEx(hProcess, (LPVOID)0x43310000, 0x2FC000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) ||
            !VirtualAllocEx(hProcess, 0, 0x1000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
            std::cerr << "[-] Error: Failed to allocate required memory regions\n";
            return false;
        }
        std::cout << "[+] Successfully allocated required memory regions\n";
        return true;
    }
} 