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

bool Driver::ArbitraryCaller::RedirectCallByName(const std::string_view& OriginalFunctionName, const std::string_view& NewFunctionName)
{
	void* OriginalFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(OriginalFunctionName.data()));
	void* NewFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(NewFunctionName.data()));
	if (!OriginalFunctionAddress || !NewFunctionAddress)
		return false;

	std::printf("OriginalFunctionAddress:\t0x%p\n", OriginalFunctionAddress);
	std::printf("NewFunctionAddress:\t0x%p\n", NewFunctionAddress);

	const bool Success = RedirectCall(OriginalFunctionAddress, NewFunctionAddress);
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

	char* OriginalFunctionBytes = new char[sizeof(RedirectShellcode)];
	const std::uint8_t* UsermodeOriginalBytes = reinterpret_cast<const std::uint8_t*>(UsermodeNtosBase + FunctionOffset);
	std::memcpy(OriginalFunctionBytes, UsermodeOriginalBytes, sizeof(RedirectShellcode));

	const bool Success = WritePhysicalMemory(FunctionAddress, OriginalFunctionBytes, sizeof(RedirectShellcode));
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