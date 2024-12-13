#pragma once
#include <include/driver/primitives.hpp>

namespace Driver
{
	class ArbitraryCaller : public Athpexnt
	{
	private:
	public:
		bool RedirectCall(const void* OriginalFunction, const void* NewFunction);
		bool RedirectCallByName(const std::string_view& OriginalFunctionName, const std::string_view& NewFunctionName);
		ArbitraryCaller() {}
		~ArbitraryCaller() = default;
	};
}