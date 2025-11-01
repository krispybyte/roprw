#pragma once
#include <vector>
#include <string>
#include <Windows.h>

namespace Utils
{
	bool EnableDebugPrivilege();
	bool DisableDebugPrivilege();
	std::vector<std::uintptr_t> FindLegitimateKernelThreadStartAddresses();
	std::uintptr_t FindRandomValidThreadAddress(const int MinimumDuplicates = 2);
	std::string GetWindowsDisplayVersion();
	DWORD GetPidByName(const std::string& ProcessName);
	std::uintptr_t GetModuleBaseAddress(DWORD Pid, const std::string& ModuleName);
}
