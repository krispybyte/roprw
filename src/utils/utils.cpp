#include <include/utils/utils.hpp>
#include <Windows.h>
#include <winternl.h>
#include <map>
#include <random>

// Required in an administrator ran process (in win build 24h2+) in order to find ntoskrnl.exe base address
bool Utils::EnableDebugPrivilege()
{
	HANDLE Token;
	TOKEN_PRIVILEGES TokenPrivileges;
	LUID UID;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
		return false;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &UID))
	{
		CloseHandle(Token);
		return false;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = UID;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(Token, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		CloseHandle(Token);
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		CloseHandle(Token);
		return false;
	}

	CloseHandle(Token);
	return true;
}

#define SystemProcessInformation 5

std::vector<std::uintptr_t> Utils::FindLegitimateKernelThreadStartAddresses()
{
    // The System Process always has PID 4
    constexpr DWORD SystemPid = 4;

    ULONG BufferSize = 0;
    // Get the required buffer size
    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, NULL, 0, &BufferSize);

    if (BufferSize == 0)
        return {};

    std::vector<BYTE> Buffer(BufferSize);
    PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer.data();

    // Get the actual system information
    NTSTATUS Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, SystemProcessInfo, BufferSize, NULL);

    if (!NT_SUCCESS(Status))
        return {};

    bool FoundSystemProcess = false;

    std::vector<std::uintptr_t> LegitimateStartAddresses;

    while (SystemProcessInfo)
    {
        if (SystemProcessInfo->UniqueProcessId == (HANDLE)SystemPid)
        {
            FoundSystemProcess = true;

            // The Threads array is located right after the SYSTEM_PROCESS_INFORMATION structure
            PSYSTEM_THREAD_INFORMATION SystemThreadInformation = (PSYSTEM_THREAD_INFORMATION)(SystemProcessInfo + 1);

            for (ULONG i = 0; i < SystemProcessInfo->NumberOfThreads; ++i)
            {
                // Thread addresses in the kernel address space are high. A simple check can filter out invalid entries.
                if ((uintptr_t)SystemThreadInformation[i].StartAddress > 0x7FFFFFFFFFFF)
                    LegitimateStartAddresses.push_back(reinterpret_cast<std::uintptr_t>(SystemThreadInformation[i].StartAddress));
            }
            // Found the system process, no need to continue
            break;
        }

        if (SystemProcessInfo->NextEntryOffset == 0)
            break;

        SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)SystemProcessInfo + SystemProcessInfo->NextEntryOffset);
    }

    return LegitimateStartAddresses;
}

std::uintptr_t Utils::FindRandomValidThreadAddress(const int MinimumDuplicates)
{
    // Get the list of all thread start addresses from the System process.
    const auto AllAddresses = FindLegitimateKernelThreadStartAddresses();

    if (AllAddresses.empty())
        return 0;

    // Use a map to count the occurrences of each unique address.
    // Key: The thread start address.
    // Value: The number of times it has appeared.
    std::map<std::uintptr_t, int> AddressCounts;
    for (const auto& Address : AllAddresses)
        AddressCounts[Address]++;

    // Step 3: Create a new list containing only the addresses that meet the minimum duplicate count.
    std::vector<std::uintptr_t> ValidFrequentAddresses;
    for (const auto& Pair : AddressCounts)
    {
        if (Pair.second >= MinimumDuplicates)
            ValidFrequentAddresses.push_back(Pair.first);
    }

    // Check if we found any addresses that met the criteria.
    if (ValidFrequentAddresses.empty())
        return 0;

    // Now we randomly select one address from our list of valid candidates.

    std::random_device RandomDevice;
    std::mt19937 gen(RandomDevice());

    std::uniform_int_distribution<> Distribution(0, ValidFrequentAddresses.size() - 1);

    // Get a random index and return the address at that position.
    const int RandomIndex = Distribution(gen);
    return ValidFrequentAddresses[RandomIndex];
}

std::string Utils::GetWindowsDisplayVersion()
{
    HKEY KeyHandle;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &KeyHandle) != ERROR_SUCCESS)
        return {};

    char DisplayVersion[256];
    DWORD DisplayVersionSize = sizeof(DisplayVersion);

    // Try to get DisplayVersion (used in Windows 11 and newer Windows 10 versions)
    const LONG Result = RegQueryValueEx(KeyHandle, "DisplayVersion", nullptr, nullptr, (LPBYTE)DisplayVersion, &DisplayVersionSize);
    if (Result != ERROR_SUCCESS)
        return {};

    return DisplayVersion;
}
