#pragma once
#include <string>
#include <Windows.h>

class Injector {
public:
    Injector();
    ~Injector();

    // Initialize the injector with DLL path
    bool Initialize(const std::string& dllPath);
    
    // Run the injection process
    bool Run();

private:
    // Check if DLL file exists and get its full path
    bool ValidateDllFile();
    
    // Launch and prepare the target process
    bool PrepareTargetProcess();
    
    // Perform the actual injection
    bool PerformInjection();

private:
    std::string m_dllPath;
    std::string m_fullDllPath;
    DWORD m_processId;
    HANDLE m_processHandle;
    bool m_initialized;
}; 