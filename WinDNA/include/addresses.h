// WinDbg related addresses which are resolved at runtime
namespace Addresses
{
	void Initialize();

	namespace Modules
	{
		// Base address of TTDReplay.dll.
		inline u64 g_replay;

		// Base address of TTDReplayCPU.dll
		inline u64 g_replay_cpu;
	}

	namespace Functions
	{
		inline u64 g_register_instrumentation_callbacks;

		// Address of VirtualCpu::ReadCachedDataInternal.
		inline u64 g_read_cached_data_internal;
	}
}