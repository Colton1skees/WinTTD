// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <detours/detours.h>
#include "internal_structures.h"

typedef void(__fastcall* f_RegisterCallbacks)(InstrumentationCallbacks* callbacks);

void __fastcall InstrCallbackPreWriteMemory(VirtualCpu* vCpu, u64 address, u64 dataSize)
{
}

void __fastcall InstrCallbackPostWriteMemory(VirtualCpu* vCpu, u64 address, void* pBuffer, u64 dataSize)
{
}

void __fastcall InstrCallbackReadMemory(VirtualCpu* vCpu, u64 address, void* pBuffer, u64 dataSize)
{
}

void RegisterInstrumentationCallbacks()
{
    // Grab the function for registering callbacks.
    u64 base = (u64)GetModuleHandleA("TTDReplayCPU.dll");
    auto func = (f_RegisterCallbacks)((u64*)(base + 0x1540));

    // Register callbacks
    InstrumentationCallbacks callbacks;
    callbacks.callbackPreWriteMemory = (f_InstrCallbackPreWriteMemory*)InstrCallbackPreWriteMemory;
    callbacks.callbackPostWriteMemory = (f_InstrCallbackPostWriteMemory*)InstrCallbackPostWriteMemory;
    callbacks.callbackReadMemory = (f_InstrCallbackReadMemory*)(InstrCallbackReadMemory);
    func(&callbacks);
}


void Initialize()
{
    // Initialize logging.
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    printf("WinDNA loaded.");

    // Execute boilerplate code for registering callbacks.
    RegisterInstrumentationCallbacks();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        Initialize();
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

