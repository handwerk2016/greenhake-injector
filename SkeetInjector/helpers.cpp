#include "helpers.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>

namespace {
    LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");
}

namespace Helpers {
    bool LaunchCSGO(DWORD& processId) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\cs2", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            std::cerr << "[-] Failed to open registry key\n";
            return false;
        }

        char installPath[MAX_PATH];
        DWORD bufferSize = sizeof(installPath);
        if (RegQueryValueExA(hKey, "installpath", NULL, NULL, (LPBYTE)installPath, &bufferSize) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            std::cerr << "[-] Failed to get CS:GO path\n";
            return false;
        }
        RegCloseKey(hKey);

        std::string csgoExePath = std::string(installPath) + "\\csgo.exe";
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        std::string commandLine = "\"" + csgoExePath + "\" -insecure";

        if (!CreateProcessA(NULL, (LPSTR)commandLine.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            std::cerr << "[-] Failed to launch CS:GO\n";
            return false;
        }

        processId = pi.dwProcessId;
        std::cout << "[+] CS:GO launched (PID: " << processId << ")\n";

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

    DWORD WaitForCSGOWindow() {
        HWND window = nullptr;
        DWORD processId = 0;

        std::cout << "[*] Waiting for CS:GO window...\n";
        while (window == nullptr) {
            window = FindWindowA("Valve001", nullptr);
            if (window != nullptr) {
                GetWindowThreadProcessId(window, &processId);
                std::cout << "[+] Found window. Process ID: " << processId << "\n";
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        return processId;
    }

    void BypassProtection(HANDLE hProcess) {
        if (ntOpenFile) {
            char originalBytes[5];
            memcpy(originalBytes, ntOpenFile, 5);
            WriteProcessMemory(hProcess, ntOpenFile, originalBytes, 5, NULL);
            std::cout << "[+] Protection bypassed\n";
        }
    }

    void RestoreProtection(HANDLE hProcess) {
        if (ntOpenFile) {
            char originalBytes[5];
            memcpy(originalBytes, ntOpenFile, 5);
            WriteProcessMemory(hProcess, ntOpenFile, originalBytes, 0, NULL);
            std::cout << "[+] Protection restored\n";
        }
    }

    bool AllocateRequiredMemory(HANDLE hProcess) {
        // Allocate required memory regions for the cheat
        if (!VirtualAllocEx(hProcess, (LPVOID)0x43310000, 0x2FC000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) ||
            !VirtualAllocEx(hProcess, 0, 0x1000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
            std::cerr << "[-] Failed to allocate required memory\n";
            return false;
        }
        std::cout << "[+] Required memory allocated\n";
        return true;
    }

    bool InjectDLL(HANDLE hProcess, const std::string& dllPath) {
        // Allocate memory for DLL path
        LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!allocatedMem) {
            std::cerr << "[-] Error: Failed to allocate memory for DLL path\n";
            return false;
        }
        std::cout << "[+] Memory allocated at address 0x" << std::hex << (uintptr_t)allocatedMem << std::dec << "\n";

        // Write DLL path to process memory
        if (!WriteProcessMemory(hProcess, allocatedMem, dllPath.c_str(), dllPath.length() + 1, NULL)) {
            std::cerr << "[-] Error: Failed to write DLL path to process memory\n";
            return false;
        }
        std::cout << "[+] Successfully wrote DLL path to process memory\n";

        // Get LoadLibraryA address
        HMODULE hModule = GetModuleHandleA("kernel32.dll");
        if (!hModule) {
            std::cerr << "[-] Error: Failed to get kernel32.dll module handle\n";
            return false;
        }

        FARPROC loadLibraryAddr = GetProcAddress(hModule, "LoadLibraryA");
        if (!loadLibraryAddr) {
            std::cerr << "[-] Error: Failed to locate LoadLibraryA function\n";
            return false;
        }
        std::cout << "[+] Located LoadLibraryA at address 0x" << std::hex << (uintptr_t)loadLibraryAddr << std::dec << "\n";

        // Create remote thread to load DLL
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
            (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMem, 0, nullptr);
        if (!hThread) {
            std::cerr << "[-] Error: Failed to create remote thread\n";
            return false;
        }

        CloseHandle(hThread);
        std::cout << "[+] DLL injection completed successfully\n";
        return true;
    }
}
