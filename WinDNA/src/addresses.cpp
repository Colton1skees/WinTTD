#include "pch.h"

namespace Addresses
{
	void Initialize()
	{
		// Locate modules
		Modules::g_replay = (u64)GetModuleHandleA("TTDReplay.dll");
		Modules::g_replay_cpu = (u64)GetModuleHandleA("TTDReplayCPU.dll");

		// Locate functions. TODO: Pattern scan.
		Functions::g_register_instrumentation_callbacks = Modules::g_replay_cpu + 0x1540;
		Functions::g_read_cached_data_internal = Modules::g_replay_cpu + 0x4AD0;
	}
}