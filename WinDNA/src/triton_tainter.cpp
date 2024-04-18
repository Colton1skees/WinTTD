#pragma once
#include <pch.h>
#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>
#include <capstone/capstone.h>
#include <internal_structures.h>
#include <triton_tainter.h>

namespace Tainter
{
	// Context for swapping between threads.
	class ThreadContext
	{
	public:
		// Thread ID.
		u64 tid;

		// Concrete registers.
		std::unordered_map<triton::arch::register_e, triton::uint512>* concreteRegisters;

		// Symbolic registers
		std::unordered_map<triton::arch::register_e, triton::engines::symbolic::SharedSymbolicExpression>* symbolicRegisters;

		ThreadContext(u64 tid)
		{
			this->tid = tid;
			concreteRegisters = new std::unordered_map<triton::arch::register_e, triton::uint512>();
			symbolicRegisters = new std::unordered_map<triton::arch::register_e, triton::engines::symbolic::SharedSymbolicExpression>();
		}

		void Save(triton::API* api)
		{
			// Save concrete register values
			for (auto reg : api->getParentRegisters())
			{
				concreteRegisters->insert({ reg->getId(), api->getConcreteRegisterValue(*reg) });
			}

			// Save symbolic registers
			*symbolicRegisters = api->getSymbolicRegisters();
		}

		void Restore(triton::API* api)
		{
			// Restore concrete registers
			for (auto&& pair : *concreteRegisters)
			{
				api->setConcreteRegisterValue(api->getRegister(pair.first), pair.second);
			}

			// Restore symbolic registers
			for (auto&& pair : *symbolicRegisters)
			{
				api->assignSymbolicExpressionToRegister(pair.second, api->getRegister(pair.first));
			}
		}
	};

	triton::API* api;

	std::map<u64, ThreadContext*> contextMap = *new std::map<u64, ThreadContext*>();

	u64 currentTid;

	bool isTainting = false;

	std::mutex taintMutex;

	csh handle;

	int taintCount = 0;

	void LoadThreadContext(Internals::VirtualCpu* vCpu);

	void InitializeTaint(Internals::VirtualCpu* vCpu);

	void TaintCurrentExecutingInstruction(Internals::VirtualCpu* vCpu);
	
	void TaintInstruction(Internals::VirtualCpu* vCpu)
	{
		// Initialize the taint if needed
		if (!isTainting)
			InitializeTaint(vCpu);

		taintMutex.lock();
		LoadThreadContext(vCpu);
		TaintCurrentExecutingInstruction(vCpu);
		taintMutex.unlock();
	}

	void InitializeTaint(Internals::VirtualCpu* vCpu)
	{
		api = new triton::API();
		api->setArchitecture(triton::arch::architecture_e::ARCH_X86_64);

		isTainting = true;
		LoadThreadContext(vCpu);
		api->enableTaintEngine(true);
		api->setMode(triton::modes::TAINT_THROUGH_POINTERS, true);
		api->setMode(triton::modes::ONLY_ON_TAINTED, true);
		api->setMode(triton::modes::ONLY_ON_TAINTED, true);

		// Initialize capstone
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		{
			printf("failed to load capstone. \n");
			return;
		}
	}

	void LoadThreadContext(Internals::VirtualCpu* vCpu)
	{
		// Grab the TEB and use it as a thread ID.
		auto cpuThreadId = vCpu->GetTeb();

		// Return if the provided vCpu's thread context is already loaded.
		if (cpuThreadId == currentTid)
			return;

		// Save the old context, in preparation of loading a new context
		if (contextMap.find(currentTid) != contextMap.end())
		{
			contextMap[currentTid]->Save(api);
		}

		// Set the new current thread ID.
		currentTid = cpuThreadId;

		// Create a context for the current thread if one doesn't exist
		if (contextMap.find(cpuThreadId) == contextMap.end())
		{
			//printf("creating new context");
			ThreadContext* ctx = new ThreadContext(cpuThreadId);
			ctx->Save(api);
			contextMap.insert({ cpuThreadId, ctx });
		}

		// Load the new thread context into triton.
		auto context = contextMap[cpuThreadId];
		context->Restore(api);
	}

	void TaintCurrentExecutingInstruction(Internals::VirtualCpu* vCpu)
	{
		// Retrieve PC
		auto rip = vCpu->GetPC();

		// Compute the size of memory to read
		unsigned int pageSize = 0x1000 - ((((DWORD)rip)) & 0xFFF);
		if (pageSize > 15)
			pageSize = 15;

		// Prepare to read memory
		auto isReadingMem = vCpu->bIsReadingMem;
		Internals::VirtualCpu* tempCpu = vCpu;
		vCpu->bIsReadingMem = true;
		if (isReadingMem)
			tempCpu = 0;

		// Read virtual CPU memory.
		uint8_t disassemblyBuffer[32];
		bool hasRead = Internals::VirtualCpuHelper::ReadVirtualCpuMemory(vCpu, rip & (u64)0xFFFFFFFFFFFF, &disassemblyBuffer, pageSize);
		if (tempCpu != nullptr)
			tempCpu->bIsReadingMem = false;

		// Return if the read failed for some reason.
		if (!hasRead)
		{
			printf("failed to read memory.");
			return;
		}

		// Compute the length of the instruction
		cs_insn* insn;
		auto count = cs_disasm(handle, disassemblyBuffer, 15, rip, 1, &insn);
		
		// Feed the instruction to triton
		triton::arch::Instruction instruction;
		instruction.setOpcode(disassemblyBuffer, insn->size);
		instruction.setAddress(rip);
		bool success = api->processing(instruction);

		if (!success)
		{
			std::cout << "failed to process insn" << std::endl;
			return;
		}
		
		// Log the instruction if it is tainted
		if (instruction.isTainted())
		{
			taintCount++;
			printf("instruction tainted: 0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic,
				insn[0].op_str);
		}

		else 
		{
			printf("Failed to taint instruction: 0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic,
				insn[0].op_str);
		}
	}
}