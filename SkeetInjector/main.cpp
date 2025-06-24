#include "injector.h"
#include <iostream>
#include <thread>
#include <cstdio>

int main(int argc, char* argv[]) {
    SetConsoleTitleA("SkeetCrack");

    std::cout << "\nSkeet Crack Injector\n\n";

    Injector injector;

    std::cout << "[*] Initializing injection process...\n";
    if (!injector.Initialize("skeet.dll")) {
        std::cout << "[-] Initialization failed\n";
        std::cout << "\nPress Enter to exit...\n";
        std::cin.get();
        return -1;
    }

    if (!injector.Run()) {
        std::cout << "\n[-] Injection process failed\n";
        std::cout << "\nPress Enter to exit...\n";
        std::cin.get();
        return -1;
    }

    std::cout << "[*] Cleaning up and exiting in 2 seconds...\n";
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}