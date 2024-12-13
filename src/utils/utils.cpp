#include <include/utils/utils.hpp>
#include <Windows.h>

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