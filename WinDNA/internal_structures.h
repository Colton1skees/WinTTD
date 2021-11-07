#pragma once

class VirtualCpu;

// Callback for flow transfer operations. This callback applies to *all* control flow transfer operations.
typedef void* (__fastcall* f_InstrCallbackFlowTransfer)(VirtualCpu* vCpu, u64 flowDstAddr);

// Callback for calls and returns
typedef void*(__fastcall* f_InstrCallbackCallRets)(VirtualCpu* vCpu, u64 flowDstAddr);

// Note: This callback is never executed.
typedef void* (__fastcall* f_InstrCallbackTranslation)();

// Callback prior to memory writes. It may also be some type of memory overwrite callback, or a memory reference callback. I am pretty confident that this is really just a callback that executes before memory write.
typedef void (__fastcall* f_InstrCallbackPreWriteMemory)(VirtualCpu* vCpu, u64 address, u64 dataSize);

// Callback after memory writes
typedef void (__fastcall* f_InstrCallbackPostWriteMemory)(VirtualCpu* vCpu, u64 address, void* pBuffer, u64 dataSize);

// Callback for memory read operations.
typedef void (__fastcall* f_InstrCallbackReadMemory)(VirtualCpu* vCpu, u64 address, void* pBuffer, u64 dataSize);

// Unknown callback, never executed.
typedef void* (__fastcall* f_InstrCallback6)();

// Callback for atomic operations(e.g lock, xcgh)
typedef void* (__fastcall* f_InstrCallbackAtomic)(VirtualCpu* vCpu, void* a2);

// This callback is presumably executed when the code cache is full, but we have no use for it(I've also never encountered a scenario where it gets executed).
typedef void* (__fastcall* f_InstrCallbackCodeCacheFull)();

// Callback for indirect jump operations(e.g jmp rax). It does not apply to indirect calls or other types of indirect control flow.
typedef void* (__fastcall* f_InstrCallbackIndirectJump)(VirtualCpu* vCpu, u64 flowDstAddr);


class InstrumentationCallbacks
{
public:
	f_InstrCallbackFlowTransfer* callbackFlowTransfer = nullptr;
	f_InstrCallbackCallRets* callbackCallRets = nullptr;
	f_InstrCallbackTranslation* callbackTranslation = nullptr;
	f_InstrCallbackPreWriteMemory* callbackPreWriteMemory = nullptr;
	f_InstrCallbackPostWriteMemory* callbackPostWriteMemory = nullptr;
	f_InstrCallbackReadMemory* callbackReadMemory = nullptr;
	f_InstrCallback6* callback6 = nullptr;
	f_InstrCallbackAtomic* callbackAtomicOperation = nullptr;
	f_InstrCallbackCodeCacheFull* callbackCodeCacheFull = nullptr;
	f_InstrCallbackIndirectJump* callbackIndirectJump = nullptr;
};


typedef void(__fastcall* f_RegisterCallbacks)(InstrumentationCallbacks* callbacks);

class Disx86
{
public:
	char pad_0008[616]; //0x0008

	virtual void Function0();
	virtual void Function1();
	virtual void Function2();
	virtual void Function3();
	virtual void Function4();
	virtual void Function5();
	virtual void Function6();
	virtual void Function7();
	virtual void Function8();
	virtual void Function9();
}; //Size: 0x0270

class VirtualCpu
{
public:
	void* clientTls; //0x0008
	char pad_0010[48]; //0x0010
	uint64_t qword1; //0x0040
	void* oPreWriteMem; //0x0048
	void* oPostWriteMem; //0x0050
	void* oReadMem; //0x0058
	void* oTranslation; //0x0060
	void* oMemoryEvict; //0x0068
	void* callbackPreWriteMem; //0x0070
	void* callbackPostWriteMem; //0x0078
	void* callbackReadMem; //0x0080
	void* callbackTranslation; //0x0088
	void* callbackMemoryEvict; //0x0090
	int8_t bFastMemoryPathDisabled; //0x0098
	char pad_0099[7]; //0x0099
	uint64_t qword2; //0x00A0
	int32_t insnCount1; //0x00A8
	char pad_00AC[4]; //0x00AC
	int32_t insnCount2; //0x00B0
	char pad_00B4[4]; //0x00B4
	int64_t insnCountFactor; //0x00B8
	int32_t insnCountLimit; //0x00C0
	int32_t computedLimit; //0x00C4
	int32_t computedLimit2; //0x00C8
	char pad_00CC[1]; //0x00CC
	uint8_t bIsExecutingCallback; //0x00CD
	char pad_00CE[2]; //0x00CE
	void* callbackReplayMemoryFetch; //0x00D0
	void* callbackReplayTimestamp; //0x00D8
	char pad_00E0[32]; //0x00E0
	char registersData[13][8]; //0x0100
	uint64_t pc; //0x0168
	uint64_t teb; //0x0170
	char registersDataExtended[385][8]; //0x0178
	class Disx86 disx86; //0x0D80
	char pad_0FF0[17064]; //0x0FF0
	void* jitHashFunction; //0x5298
	void* jitHashTableMatch; //0x52A0
	char pad_52A8[24]; //0x52A8
	void* stlB; //0x52C0
	char pad_52C8[760]; //0x52C8


	virtual void SetClientTls(u64 tls);
	u64* GetRegistersData(u64* outputDst);
	virtual u64 GetVirtualProcessorState(int unkInt, u64* outputState);
	virtual u64 SetVirtualProcessorState(int stateCode, u64* vState);
	virtual void GetRegister(unsigned __int8 regId, u64* pDst, size_t regSize);
	virtual void SetRegister(unsigned __int8 regId, u64* pSrc, size_t regSize);
	virtual u64 GetPC();
	virtual u64 GetTeb();
	virtual void SetPC(u64 pc);
	virtual void SetTeb(u64 teb);
	virtual u64 GetRegistersHash(char unkBool);
	virtual u64 GetInstructionCount();
	virtual u64 ResetInstructionCount();
	virtual u64 SetInstructionCountLimit(unsigned int limit);

	// Cache related functions have not been reversed or documented. Do not use.
	virtual void EmptyDataCache();
	virtual void QueryDataCacheLineSize();
	virtual void AlignAddrToDataCacheLineSize();
	virtual void RemoveLineFromDataCache();
	virtual void RemoveRangeFromCodeCache();
	virtual void ReadLineFromDataCache();
	virtual void WriteGuestMemory();
	virtual void CreateOrUpdateCacheLine();
	virtual void FindFirstValidDataLine();
	virtual void FindNextValidDataLine();
	virtual void SetMemoryTag();

	virtual u64 RegisterInstrumentationCallbacks(u64* callbackStructure);
	virtual u64 SyncGuestMachineState();

	// More undocumented functions.
	virtual void DisableFastMemoryPath();
	virtual void EnableFastMemoryPath();
	virtual void Delete();
	virtual void RegisterReplayCallbacks();
	virtual void FlushCaches();
	virtual void StopExecution();
	virtual void Execute();
	virtual void Destructor();
}; //Size: 0x0850