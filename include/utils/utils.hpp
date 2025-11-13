#pragma once
#include <vector>
#include <string>
#include <Windows.h>

#define WINVER_WIN11_25H2 26200
#define WINVER_WIN11_24H2 26100
#define WINVER_WIN11_23H2 22631
#define WINVER_WIN11_22H2 22621
#define WINVER_WIN11_21H2 22000
#define WINVER_WIN10_22H2 19045

namespace Utils
{
	bool EnableDebugPrivilege();
	bool DisableDebugPrivilege();
	std::vector<std::uintptr_t> FindLegitimateKernelThreadStartAddresses();
	std::uintptr_t FindRandomValidThreadAddress(const int MinimumDuplicates = 2);
	DWORD GetWindowsBuildNumber();
	std::string GetWindowsDisplayVersion();
	DWORD GetPidByName(const std::string& ProcessName);
	std::uintptr_t GetModuleBaseAddress(DWORD Pid, const std::string& ModuleName);
}
