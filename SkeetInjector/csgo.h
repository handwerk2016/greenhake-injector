#pragma once
#include <Windows.h>
#include <string>

namespace CSGO {
    // Get CS:GO installation path from registry
    std::string GetInstallPath();
    
    // Launch CS:GO process
    bool Launch(DWORD& processId);
    
    // Wait for CS:GO window to appear and return process ID
    DWORD WaitForWindow();
    
    // Check if CS:GO is running
    bool IsRunning();
    
    // Get window handle if exists
    HWND GetWindow();
} 