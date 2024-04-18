#pragma once

namespace Tainter
{
	// Taints the instruction which is currently being executed by the vCpu.
	void HandleTaintInstruction(Internals::VirtualCpu* vCpu);
}