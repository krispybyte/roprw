#include <include/driver/arbitrary_call.hpp>

bool Driver::ArbitraryCaller::RedirectCall(void* OriginalFunction, const void* NewFunction)
{
	if (!OriginalFunction || !NewFunction)
		return false;

	// Now we create a buffer which will hold our shellcode, then place it on the target function
	char* RedirectBuffer = new char[sizeof(RedirectShellcode)];
	std::memcpy(RedirectBuffer, RedirectShellcode, sizeof(RedirectShellcode));
	std::memcpy(RedirectBuffer + sizeof(RedirectShellcode) - sizeof(void*),
		&NewFunction,
		sizeof(void*)
	);

	const bool Success = WritePhysicalMemory(OriginalFunction, RedirectBuffer, sizeof(RedirectShellcode));
	delete[] RedirectBuffer;

	return Success;
}

bool Driver::ArbitraryCaller::RedirectCall(void* OriginalFunction, const void* NewFunction, void* Arg1, void* Arg2, void* Arg3)
{
	const std::uint8_t ShellcodeTemplate[] =
	{
		0x48, 0xBB, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,			// mov rbx, Arg1
		0x48, 0x89, 0x5C, 0x24, 0x28,										// mov [rsp+0x28], rbx
		0x48, 0xBB, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,			// mov rbx, Arg2
		0x48, 0x89, 0x5C, 0x24, 0x30,										// mov [rsp+0x30], rbx
		0x48, 0xBB, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,			// mov rbx, Arg3
		0x48, 0x89, 0x5C, 0x24, 0x38,										// mov [rsp+0x38], rbx
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,									// jmp [rip]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	char* ShellcodeBuffer = new char[sizeof(ShellcodeTemplate)];
	std::memcpy(ShellcodeBuffer, ShellcodeTemplate, sizeof(ShellcodeTemplate));
	std::memcpy(ShellcodeBuffer + 2, &Arg1, sizeof(void*));
	std::memcpy(ShellcodeBuffer + 17, &Arg2, sizeof(void*));
	std::memcpy(ShellcodeBuffer + 32, &Arg3, sizeof(void*));
	std::memcpy(ShellcodeBuffer + sizeof(ShellcodeTemplate) - sizeof(void*),
		&NewFunction,
		sizeof(void*)
	);

	const bool Success = WritePhysicalMemory(OriginalFunction, ShellcodeBuffer, sizeof(ShellcodeTemplate));
	delete[] ShellcodeBuffer;

	return Success;
}

bool Driver::ArbitraryCaller::RedirectCallByName(const std::string_view& OriginalFunctionName, const std::string_view& NewFunctionName)
{
	void* OriginalFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(OriginalFunctionName.data()));
	void* NewFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(NewFunctionName.data()));
	if (!OriginalFunctionAddress || !NewFunctionAddress)
		return false;

	const bool Success = RedirectCall(OriginalFunctionAddress, NewFunctionAddress);
	return Success;
}

bool Driver::ArbitraryCaller::RedirectCallByName(const std::string_view& OriginalFunctionName, const std::string_view& NewFunctionName, void* Arg1, void* Arg2, void* Arg3)
{
	void* OriginalFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(OriginalFunctionName.data()));
	void* NewFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(NewFunctionName.data()));
	if (!OriginalFunctionAddress || !NewFunctionAddress)
		return false;

	const bool Success = RedirectCall(OriginalFunctionAddress, NewFunctionAddress, Arg1, Arg2, Arg3);
	return Success;
}

bool Driver::ArbitraryCaller::DisableRedirect(void* OriginalFunction)
{
	if (!OriginalFunction)
		return false;

	const std::uint8_t* UsermodeNtosBase = reinterpret_cast<std::uint8_t*>(GetModuleHandleA("ntoskrnl.exe"));
	const std::uint32_t FunctionOffset = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(OriginalFunction) - NtoskrnlBase);
	const void* FunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + FunctionOffset);

	if (!UsermodeNtosBase || !FunctionOffset || !FunctionAddress)
		return false;

	char* OriginalFunctionBytes = new char[100];
	const std::uint8_t* UsermodeOriginalBytes = reinterpret_cast<const std::uint8_t*>(UsermodeNtosBase + FunctionOffset);
	std::memcpy(OriginalFunctionBytes, UsermodeOriginalBytes, 100);

	const bool Success = WritePhysicalMemory(FunctionAddress, OriginalFunctionBytes, 100);
	delete[] OriginalFunctionBytes;

	return Success;
}

bool Driver::ArbitraryCaller::DisableRedirectByName(const std::string_view& OriginalFunctionName)
{
	void* OriginalFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(OriginalFunctionName.data()));
	if (!OriginalFunctionAddress)
		return false;

	const bool Success = DisableRedirect(OriginalFunctionAddress);

	return Success;
}