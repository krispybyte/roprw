#include <include/stack/stack_manager.hpp>

std::uint64_t* StackManager::GetStackBuffer()
{
	return Stack->data();
}

std::size_t StackManager::GetStackSize()
{
	return Stack->size() * sizeof(std::uint64_t);
}

void StackManager::AddGadget(const std::uint64_t GadgetOffset)
{
	const std::uint64_t GadgetAddress = KernelModuleBase + GadgetOffset;
	Stack->push_back(GadgetAddress);
}

void StackManager::AddValue(const std::uint64_t Value)
{
	Stack->push_back(Value);
}

void StackManager::AddPadding(const std::size_t PaddingSize)
{
	// TODO: Make this a cyclic func.
	// right now it's just hardcoded.
	this->AddValue(0xC0FEBABEC0FEBABE);
}
