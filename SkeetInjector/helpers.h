#pragma once

#include <Windows.h>
#include <string>

namespace Helpers {
    // DLL injection helper functions
    bool InjectDLL(HANDLE hProcess, const std::string& dllPath);
}
