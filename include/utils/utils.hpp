#pragma once
#include <vector>

namespace Utils
{
	bool EnableDebugPrivilege();
	std::vector<std::uintptr_t> FindLegitimateKernelThreadStartAddresses();
	std::uintptr_t FindRandomValidThreadAddress(const int MinimumDuplicates = 2);
}
