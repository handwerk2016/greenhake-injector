#pragma once
#include <Windows.h>

namespace Protection {
    // Initialize protection module
    bool Initialize();
    
    // Bypass process protection
    void Bypass(HANDLE hProcess);
    
    // Restore process protection
    void Restore(HANDLE hProcess);
    
    // Allocate required memory regions
    bool AllocateMemory(HANDLE hProcess);
} 