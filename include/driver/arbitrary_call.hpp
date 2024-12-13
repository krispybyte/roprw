#pragma once
#include <include/driver/primitives.hpp>
#include <unordered_map>

namespace Driver
{
	class ArbitraryCaller : public Athpexnt
	{
	private:
		// This shellcode performs a jump to the address of NewFunction
		std::uint8_t RedirectShellcode[14] =
		{
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,				// jmp [rip]
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	// NewFunction arg
		};
	public:
		bool RedirectCall(void* OriginalFunction, const void* NewFunction);
		bool RedirectCallByName(const std::string_view& OriginalFunctionName, const std::string_view& NewFunctionName);
		bool DisableRedirect(void* OriginalFunction);
		bool DisableRedirectByName(const std::string_view& OriginalFunctionName);
		ArbitraryCaller() {}
		~ArbitraryCaller() = default;
	};
}