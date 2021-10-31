#pragma once


class VirtualCpu
{
public:
	char pad_0008[64]; //0x0008
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
	char pad_0098[56]; //0x0098
	void* callbackReplayMemoryFetch; //0x00D0
	void* callbackReplayTimestamp; //0x00D8
	char pad_00E0[136]; //0x00E0
	uint64_t pc; //0x0168
	uint64_t teb; //0x0170
	char pad_0178[1752]; //0x0178

	virtual void SetClientTls(UINT_PTR tls);
	UINT_PTR* GetRegistersData(UINT_PTR* outputDst);
	virtual UINT_PTR GetVirtualProcessorState(int unkInt, UINT_PTR* outputState);
	virtual UINT_PTR SetVirtualProcessorState(int stateCode, UINT_PTR* vState);
	virtual void GetRegister(unsigned __int8 regId, UINT_PTR* pDst, size_t regSize);
	virtual void SetRegister(unsigned __int8 regId, UINT_PTR* pSrc, size_t regSize);
	virtual UINT_PTR GetPC();
	virtual UINT_PTR GetTeb();
	virtual void SetPC(UINT_PTR pc);
	virtual void SetTeb(UINT_PTR teb);
	virtual UINT_PTR GetRegistersHash(char unkBool);
	virtual UINT_PTR GetInstructionCount();
	virtual UINT_PTR ResetInstructionCount();
	virtual UINT_PTR SetInstructionCountLimit(unsigned int limit);

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

	virtual UINT_PTR RegisterInstrumentationCallbacks(UINT_PTR callbackStructure);
	virtual UINT_PTR SyncGuestMachineState();

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