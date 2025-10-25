#pragma once
#include <string>

namespace Globals
{
	extern std::uintptr_t KernelBase;
	extern std::string WindowsBuild;
	extern void* StackLimitStoreAddress;
	extern void* CurrentStackOffsetAddress;
	extern void* DummyMemoryAllocation;
}
