// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <detours/detours.h>
#include "internal_structures.h"
#include <capstone/capstone.h>

void __fastcall InstrCallbackCallRets(Internals::VirtualCpu* vCpu, u64 flowDstAddr)
{
   u64 rip;
   vCpu->GetRegister(Internals::RegisterId::RIP, &rip, 8);
   printf("call or ret destination = %#018llx\n", rip);
}

void __fastcall InstrCallbackPreWriteMemory(Internals::VirtualCpu* vCpu, u64 address, u64 dataSize)
{
}

void __fastcall InstrCallbackPostWriteMemory(Internals::VirtualCpu* vCpu, u64 address, void* pBuffer, u64 dataSize)
{
}

void __fastcall InstrCallbackReadMemory(Internals::VirtualCpu* vCpu, u64 address, void* pBuffer, u64 dataSize)
{
}

void RegisterInstrumentationCallbacks()
{
    // Grab the function for registering callbacks.
    auto func = (Internals::f_RegisterCallbacks)Addresses::Functions::g_register_instrumentation_callbacks;

    // Register callbacks
    Internals::InstrumentationCallbacks callbacks;
    callbacks.callbackCallRets = (Internals::f_InstrCallbackCallRets*)InstrCallbackCallRets;
    callbacks.callbackPreWriteMemory = (Internals::f_InstrCallbackPreWriteMemory*)InstrCallbackPreWriteMemory;
    callbacks.callbackPostWriteMemory = (Internals::f_InstrCallbackPostWriteMemory*)InstrCallbackPostWriteMemory;
    callbacks.callbackReadMemory = (Internals::f_InstrCallbackReadMemory*)(InstrCallbackReadMemory);
    func(&callbacks);
}


void Initialize()
{
    // Initialize logging.
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    printf("WinDNA loaded.");

    // Retrieve various internal addresses.
    Addresses::Initialize();

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

