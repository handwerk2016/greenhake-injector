#include "csgo.h"
#include <iostream>
#include <thread>
#include <chrono>

namespace CSGO {
    std::string GetInstallPath() {
        HKEY hKey;
        char installPath[MAX_PATH] = {0};
        DWORD bufferSize = sizeof(installPath);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\cs2", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            std::cerr << "[-] Error: Unable to access registry key\n";
            return "";
        }

        if (RegQueryValueExA(hKey, "installpath", NULL, NULL, (LPBYTE)installPath, &bufferSize) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            std::cerr << "[-] Error: Unable to locate CS:GO installation path\n";
            return "";
        }
        
        RegCloseKey(hKey);
        return std::string(installPath);
    }

    bool Launch(DWORD& processId) {
        std::string installPath = GetInstallPath();
        if (installPath.empty()) {
            return false;
        }

        std::string csgoExePath = installPath + "\\csgo.exe";
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        std::string commandLine = "\"" + csgoExePath + "\" -insecure";

        if (!CreateProcessA(NULL, (LPSTR)commandLine.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            std::cerr << "[-] Error: Failed to launch CS:GO process\n";
            return false;
        }

        processId = pi.dwProcessId;
        std::cout << "[+] Successfully launched CS:GO (PID: " << processId << ")\n";

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

    HWND GetWindow() {
        return FindWindowA("Valve001", nullptr);
    }

    bool IsRunning() {
        return GetWindow() != nullptr;
    }

    DWORD WaitForWindow() {
        HWND window = nullptr;
        DWORD processId = 0;

        std::cout << "[*] Waiting for CS:GO window to initialize...\n";
        while (window == nullptr) {
            window = GetWindow();
            if (window != nullptr) {
                GetWindowThreadProcessId(window, &processId);
                std::cout << "[+] CS:GO window detected (Process ID: " << processId << ")\n";
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        return processId;
    }
} 