#include "injector.h"
#include "helpers.h"
#include "csgo.h"
#include "protection.h"
#include <iostream>
#include <thread>

namespace {
    bool FileExists(const std::string& path) {
        DWORD fileAttributes = GetFileAttributesA(path.c_str());
        return (fileAttributes != INVALID_FILE_ATTRIBUTES && 
                !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
    }
}

Injector::Injector()
    : m_processId(0)
    , m_processHandle(nullptr)
    , m_initialized(false)
{
    if (!Protection::Initialize()) {
        std::cerr << "[-] Error: Failed to initialize protection module\n";
    }
}

Injector::~Injector() {
    if (m_processHandle) {
        CloseHandle(m_processHandle);
    }
}

bool Injector::Initialize(const std::string& dllPath) {
    m_dllPath = dllPath;
    return ValidateDllFile();
}

bool Injector::ValidateDllFile() {
    // Check if DLL exists
    if (!FileExists(m_dllPath)) {
        std::cerr << "[-] Error: " << m_dllPath << " not found\n";
        std::cerr << "[-] Please ensure the DLL is in the same directory as the injector\n";
        return false;
    }

    // Get full path
    char fullPath[MAX_PATH];
    if (GetFullPathNameA(m_dllPath.c_str(), MAX_PATH, fullPath, nullptr) == 0) {
        std::cerr << "[-] Error: Failed to resolve full DLL path\n";
        return false;
    }
    
    m_fullDllPath = fullPath;
    m_initialized = true;
    return true;
}

bool Injector::PrepareTargetProcess() {
    if (!m_initialized) {
        std::cerr << "[-] Error: Injector not initialized\n";
        return false;
    }

    // Launch CS:GO if not running
    if (!CSGO::Launch(m_processId)) {
        return false;
    }

    // Wait for CS:GO window
    m_processId = CSGO::WaitForWindow();
    if (m_processId == 0) {
        std::cerr << "[-] Error: Failed to obtain CS:GO process ID\n";
        return false;
    }

    // Open process handle
    m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processId);
    if (!m_processHandle) {
        std::cerr << "[-] Error: Failed to obtain process handle\n";
        return false;
    }

    return true;
}

bool Injector::PerformInjection() {
    if (!m_processHandle) {
        std::cerr << "[-] Error: No valid process handle available\n";
        return false;
    }

    // Bypass protection
    Protection::Bypass(m_processHandle);

    // Allocate memory
    if (!Protection::AllocateMemory(m_processHandle)) {
        return false;
    }

    // Inject main DLL
    if (!Helpers::InjectDLL(m_processHandle, m_fullDllPath)) {
        return false;
    }

    // Optional meme.dll injection
    std::string memeDll = "meme.dll";
    if (FileExists(memeDll)) {
        // Delay 2-3 seconds before injecting meme.dll
        std::cout << "[*] Waiting 8 seconds before injecting meme.dll...\n";
        std::this_thread::sleep_for(std::chrono::seconds(8));
        char memeFullPath[MAX_PATH];
        if (GetFullPathNameA(memeDll.c_str(), MAX_PATH, memeFullPath, nullptr) != 0) {
            std::cout << "[*] meme.dll found, injecting...\n";
            if (!Helpers::InjectDLL(m_processHandle, memeFullPath)) {
                std::cerr << "[-] Error: failed to inject meme.dll\n";
            } else {
                std::cout << "[+] meme.dll injected successfully\n";
            }
        } else {
            std::cerr << "[-] Error: failed to get full path to meme.dll\n";
        }
    } else {
        std::cout << "[*] meme.dll not found, skipping injection of this DLL\n";
    }

    // Restore protection
    Protection::Restore(m_processHandle);
    
    std::cout << "\n[+] Injection process completed successfully\n";
    return true;
}

bool Injector::Run() {
    if (!PrepareTargetProcess()) {
        return false;
    }

    return PerformInjection();
} 