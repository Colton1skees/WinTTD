#include "pch.h"
#include "internal_structures.h"

namespace Internals
{
	bool VirtualCpuHelper::ReadVirtualCpuMemory(VirtualCpu* vCpu, u64 addr, void* pDst, u64 dataSize)
	{
		if (VirtualCpuHelper::readCachedDataInternal == nullptr)
			VirtualCpuHelper::readCachedDataInternal = (f_ReadCachedDataInternal)Addresses::Functions::g_read_cached_data_internal;

		return VirtualCpuHelper::readCachedDataInternal(vCpu, addr, pDst, dataSize);
	}
}