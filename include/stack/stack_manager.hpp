#pragma once
#include <vector>

class StackManager
{
private:
	std::vector<std::uint64_t>* Stack = nullptr;
	std::uintptr_t KernelModuleBase = NULL;
	std::uintptr_t StackAddress = NULL;
	std::size_t StackSize = NULL;
public:
	StackManager(const std::uintptr_t _KernelModuleBase, const std::uintptr_t _StackAddress, const size_t _StackSize = 0x3000)
		: KernelModuleBase(_KernelModuleBase), StackAddress(_StackAddress), StackSize(_StackSize)
	{
		Stack = new std::vector<uint64_t>;
		Stack->push_back(StackAddress + StackSize);
	}

	~StackManager()
	{
		delete[] Stack;
	}

	std::uint64_t* GetStackBuffer()
	{
		return Stack->data();
	}

	std::size_t GetStackSize()
	{
		return Stack->size();
	}


};
