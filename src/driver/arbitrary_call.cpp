#include <include/driver/arbitrary_call.hpp>

bool Driver::ArbitraryCaller::RedirectCall(const void* OriginalFunction, const void* NewFunction)
{
	if (!OriginalFunction || !NewFunction)
		return false;

	// This shellcode performs a jump to the address of NewFunction
	std::uint8_t RedirectShellcode[] =
	{
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,				// jmp [rip]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	// NewFunction arg
	};

	char* RedirectShellcodeBuffer = new char[sizeof(RedirectShellcode)];
	std::memcpy(RedirectShellcodeBuffer, RedirectShellcode, sizeof(RedirectShellcode));
	std::memcpy(RedirectShellcodeBuffer + sizeof(RedirectShellcode) - sizeof(void*),
		&NewFunction,
		sizeof(void*)
	);

	const bool Success = WritePhysicalMemory(OriginalFunction, RedirectShellcodeBuffer, sizeof(RedirectShellcode));
	delete[] RedirectShellcodeBuffer;
	return Success;
}

bool Driver::ArbitraryCaller::RedirectCallByName(const std::string_view& OriginalFunctionName, const std::string_view& NewFunctionName)
{
	const void* OriginalFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(OriginalFunctionName.data()));
	const void* NewFunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(NewFunctionName.data()));
	if (!OriginalFunctionAddress || !NewFunctionAddress)
		return false;

	std::printf("OriginalFunctionAddress:\t0x%p\n", OriginalFunctionAddress);
	std::printf("NewFunctionAddress:\t0x%p\n", NewFunctionAddress);

	const bool Success = RedirectCall(OriginalFunctionAddress, NewFunctionAddress);
	std::printf("Success:\t%d\n", Success);
	return Success;
}