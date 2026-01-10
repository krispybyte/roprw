#pragma once
#include <include/driver/primitives.hpp>
#include <unordered_map>
#include <include/globals.hpp>
#include <stdexcept>
#include <stdexcept>

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

		std::uintptr_t KmFunctionAddress = NULL;
		std::uintptr_t UmFunctionAddress = NULL;

		bool RedirectCall(void* OriginalFunction, const void* NewFunction);
		bool RedirectCallByName(const std::string_view& OriginalFunctionName, const std::string_view& NewFunctionName);
		bool DisableRedirect(void* OriginalFunction);
		bool DisableRedirectByName(const std::string_view& OriginalFunctionName);
	public:
		ArbitraryCaller(const std::string_view& FunctionToPatch, const std::string_view& FunctionModuleName = "ntdll.dll")
		{
			const HMODULE LibraryAddress = LoadLibraryA(FunctionModuleName.data());
			if (!LibraryAddress)
			{
				throw std::runtime_error("Failed to load library for arbitrary caller");
			}

			this->UmFunctionAddress = reinterpret_cast<std::uintptr_t>(GetProcAddress(LibraryAddress, FunctionToPatch.data()));
			if (!this->UmFunctionAddress)
			{
				throw std::runtime_error("Failed to locate arbitrary caller usermode function address");
			}

			this->KmFunctionAddress = NtoskrnlBase + Driver::GetKernelFunctionOffset(FunctionToPatch.data());
			if (!this->KmFunctionAddress)
			{
				throw std::runtime_error("Failed to locate arbitrary caller kernel function address");
			}
		}
		~ArbitraryCaller() = default;

		template<typename ReturnType, typename... Args>
		ReturnType CallByAddress(void* FunctionAddress, Args... args)
		{
			// Ensure the number of arguments does not exceed 9, since our
			// function which is currently NtReadFileScatter only takes that amount.
			static_assert(sizeof...(args) <= 9, "CallKernelFunction supports up to 9 arguments only");

			this->RedirectCall(reinterpret_cast<void*>(this->KmFunctionAddress), FunctionAddress);

			using FuncPtr = ReturnType(*)(Args...);
			const ReturnType ReturnValue = reinterpret_cast<FuncPtr>(this->UmFunctionAddress)(args...);

			this->DisableRedirect(reinterpret_cast<void*>(this->KmFunctionAddress));

			return ReturnValue;
		}

		template<typename ReturnType, typename... Args>
		ReturnType Call(const std::string_view& FunctionName, Args... args)
		{
			void* FunctionAddress = reinterpret_cast<void*>(NtoskrnlBase + Driver::GetKernelFunctionOffset(FunctionName.data()));
			if (!FunctionAddress)
				return ReturnType();

			ReturnType ReturnValue = this->CallByAddress<ReturnType, Args...>(FunctionAddress, args...);

			return ReturnValue;
		}
	};
}