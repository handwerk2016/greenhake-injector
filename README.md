# greenhake-injector

A simple LoadLibrary injector for sk33t cr4ck by QHide.

Basically, this is the same injector that the crack was supplied with, but there is one cozy feature. This injector automatically launches CS:GO.

The thing is that greenhake (sk33t) requires some memory regions  to work:

```cpp
    bool AllocateMemory(HANDLE hProcess) {
        if (!VirtualAllocEx(hProcess, (LPVOID)0x43310000, 0x2FC000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) ||
            !VirtualAllocEx(hProcess, 0, 0x1000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
            return false; // returning false if we failed to allocate memory
        }
        return true; // returning true if we succeeded to allocate memory
    }
 
```



### Smol FAQ:

Q: *Why there's such complicated csgo launch method and I didn't use ``steam://runappid/730``?*

A: Well, the thing is that if we use ``runnappid`` method, steam ignores your launch options and start CS2 instead of CS:GO.

Q: *Did you again use Claude Sonnet's help?*

A: Yeah I did, why not?

### What code did I ~~stole~~ used. (Actually thanks for these repos)

Memory allocation from this repo: https://github.com/xdcdmaybe/skeetcr4ck-injector 

Loadlibrary injector: https://github.com/adamhlt/DLL-Injector

Loadlibrary injection bypass for vac module: https://github.com/v3ctra/load-lib-injector
