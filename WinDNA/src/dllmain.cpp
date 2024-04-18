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


   //u64 rip = vCpu->GetPC();
  // rip = flowDstAddr;

   //printf("call or ret destination = %#018llx\n", rip);

   uint8_t disassemblyBuffer[32];

   unsigned int pageSize = 0x1000 - ((((DWORD)rip)) & 0xFFF);
 //  std::cout << "reading page size: " << pageSize << std::endl;
   if (pageSize > 15)
       pageSize = 15;

   auto isReadingMem = vCpu->bIsReadingMem;
   Internals::VirtualCpu* tempCpu = vCpu;
   vCpu->bIsReadingMem = true;
   if (isReadingMem)
       tempCpu = 0;

   bool hasRead = Internals::VirtualCpuHelper::ReadVirtualCpuMemory(vCpu, rip & (u64)0xFFFFFFFFFFFF, &disassemblyBuffer, pageSize);
 //  std::cout << "hasRead: " << hasRead << std::endl;
   if (tempCpu != nullptr)
       tempCpu->bIsReadingMem = false;

   cs_insn* insn;
   auto count = cs_disasm(handle, disassemblyBuffer, 15, rip, 1, &insn);
   globalCount++;

   if (globalCount % 10000 == 0)
   {
       std::cout << "disassembled count: " << globalCount << std::endl;
       printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic,
               insn[0].op_str);
   }
 //  printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic,
   //    insn[0].op_str);
   
}

void __fastcall InstrCallbackPreWriteMemory(Internals::VirtualCpu* vCpu, u64 address, u64 dataSize)
{
  //  std::cout << "pre-write memory rip: 0x" << vCpu->GetPC() << std::endl;
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
   // std::cout << "dispatcher loop at rip: 0x" << std::hex << vCpu->GetPC() << std::endl;
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


    /*
    // Initialize capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        printf("failed to load capstone.");
        return;
    }
    */

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

