#include <include/globals.hpp>

namespace Globals
{
	std::uintptr_t KernelBase = NULL;
	std::string WindowsBuild = "";
	void* StackLimitStoreAddress = nullptr;
	void* CurrentStackOffsetAddress = nullptr;
	void* DummyMemoryAllocation = nullptr;
}
