// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <detours/detours.h>
#include "internal_structures.h"
#include <inttypes.h>
#include <triton_tainter.h>
#include <capstone/capstone.h>

// capstone handle
csh handle;

int globalCount = 0;
void __fastcall InstrCallbackCallRets(Internals::VirtualCpu* vCpu, u64 flowDstAddr)
{
   return;
   u64 rip;
   vCpu->GetRegister(Internals::RegisterId::RIP, &rip, 8);

   unsigned int pageSize = 0x1000 - ((((DWORD)rip)) & 0xFFF);
   if (pageSize > 15)
       pageSize = 15;

   auto isReadingMem = vCpu->bIsReadingMem;
   Internals::VirtualCpu* tempCpu = vCpu;
   vCpu->bIsReadingMem = true;
   if (isReadingMem)
       tempCpu = 0;

   if (tempCpu != nullptr)
       tempCpu->bIsReadingMem = false;

   cs_insn* insn;
   uint8_t disassemblyBuffer[32];
   auto count = cs_disasm(handle, disassemblyBuffer, 15, rip, 1, &insn);
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

typedef void* (__fastcall* fDispatcherLoop)(Internals::VirtualCpu* vCpu, u64 a2);

fDispatcherLoop dispatcherLoop;

void* __fastcall h_DispatcherLoop(Internals::VirtualCpu* vCpu, u64 a2)
{
    Tainter::HandleTaintInstruction(vCpu);
    return dispatcherLoop(vCpu, a2);
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

    dispatcherLoop = (fDispatcherLoop)(Addresses::Modules::g_replay_cpu + 0x9AA00);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)dispatcherLoop, h_DispatcherLoop);
    DetourTransactionCommit();

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

